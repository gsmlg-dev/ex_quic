defmodule QUIC.HandshakeScheduler do
  @moduledoc """
  Deterministic handshake packet scheduler.

  This module is deliberately socket-free.  TLS emissions become retained
  CRYPTO ranges and protected send effects; local send receipts and peer ACKs
  are applied separately through `QUIC.Recovery`.
  """

  import Bitwise

  alias QUIC.{Codec, Protection, Recovery, TLSDriver}

  @levels [:initial, :handshake, :application]
  @spaces [:initial, :handshake, :application]
  @default_max_packet 1350

  defstruct role: nil,
            dcid: <<>>,
            scid: <<>>,
            tls: nil,
            recovery: nil,
            keys: %{},
            read_keys: %{},
            pending: [],
            pending_acks: %{},
            effects: [],
            max_packet_size: @default_max_packet,
            min_initial_size: 1200,
            max_queue: 64,
            queued: 0

  @type t :: %__MODULE__{}

  @spec new(:client | :server, keyword()) :: {:ok, t(), list()} | {:error, term()}
  def new(role, opts \\ [])

  def new(role, opts) when role in [:client, :server] do
    with {:ok, dcid} <- required_cid(opts, :dcid),
         {:ok, scid} <- required_cid(opts, :scid),
         {:ok, initial} <- initial_keys(opts, dcid, role),
         {:ok, tls, tls_effects} <- TLSDriver.new(role, tls_options(opts)) do
      recovery = Keyword.get(opts, :recovery, Recovery.new())

      state = %__MODULE__{
        role: role,
        dcid: dcid,
        scid: scid,
        tls: tls,
        recovery: recovery,
        keys: Map.put(Keyword.get(opts, :keys, %{}), :initial, initial),
        read_keys: initial_read_keys(opts, dcid, role, initial),
        max_packet_size: Keyword.get(opts, :max_packet_size, @default_max_packet),
        min_initial_size: Keyword.get(opts, :min_initial_size, 1200),
        max_queue: Keyword.get(opts, :max_queue, 64)
      }

      with {:ok, state, sends} <- ingest_tls_effects(state, tls_effects),
           {:ok, state, sends2} <- schedule(state) do
        {:ok, state, sends ++ sends2}
      end
    end
  end

  def new(_, _), do: {:error, :invalid_role}

  @doc "Fold TLS driver effects returned from a CRYPTO receive into the scheduler."
  @spec feed(t(), atom(), non_neg_integer(), binary()) ::
          {:ok, t(), list()} | {:error, term(), t(), list()}
  def feed(%__MODULE__{} = state, level, offset, bytes)
      when level in @levels and is_integer(offset) and offset >= 0 and is_binary(bytes) do
    case TLSDriver.feed(state.tls, level, offset, bytes) do
      {:ok, tls, effects} ->
        state = %{state | tls: tls}

        case ingest_tls_effects(state, effects) do
          {:ok, state, generated} ->
            case schedule(state) do
              {:ok, state, sends} -> {:ok, state, generated ++ sends}
              {:error, reason, state} -> {:error, reason, state, []}
            end

          {:error, reason, state} ->
            {:error, reason, state, []}
        end

      {:error, reason, tls, effects} ->
        state = %{state | tls: tls}

        case ingest_tls_effects(state, effects) do
          {:ok, state, generated} -> {:error, reason, state, generated}
          {:error, fold_error, state} -> {:error, fold_error, state, []}
        end
    end
  end

  def feed(state, _, _, _), do: {:error, :invalid_crypto_input, state, []}

  @doc "Queue an ACK frame for the next packet in a packet-number space."
  def queue_ack(%__MODULE__{} = state, space, ack) when space in @spaces and is_map(ack) do
    %{state | pending_acks: Map.update(state.pending_acks, space, [ack], &(&1 ++ [ack]))}
  end

  def queue_ack(state, _, _), do: state

  @doc "Apply a local writer result; this is distinct from packet admission."
  def local_send(%__MODULE__{} = state, space, number, result, at)
      when space in @spaces and is_integer(number) do
    case Recovery.local_send(state.recovery, space, number, result, at) do
      {:ok, recovery, statuses} ->
        {:ok, %{state | recovery: recovery, queued: max(0, state.queued - 1)}, statuses}

      error ->
        error
    end
  end

  @doc "Apply an authenticated peer ACK to Recovery."
  def receive_ack(%__MODULE__{} = state, space, ack, at) when space in @spaces do
    with {:ok, recovery, result} <- Recovery.receive_ack(state.recovery, space, ack, at) do
      {:ok, %{state | recovery: recovery}, result}
    end
  end

  @doc "Receive one authenticated protected QUIC packet without socket/runtime effects."
  @spec receive_datagram(t(), binary(), non_neg_integer()) ::
          {:ok, t(), [map()]} | {:error, term(), t()}
  def receive_datagram(state, datagram, at \\ 0)

  def receive_datagram(%__MODULE__{} = state, datagram, at)
      when is_binary(datagram) and is_integer(at) and at >= 0 do
    original = state

    with {:ok, packet} <- decode_protected_packet(state, datagram),
         {:ok, recovery} <- Recovery.note_received(state.recovery, packet.space, packet.number),
         {:ok, next, events} <- dispatch_inbound(%{state | recovery: recovery}, packet, at) do
      {:ok, next, events}
    else
      {:error, reason} -> {:error, reason, original}
      {:error, reason, _state} -> {:error, reason, original}
    end
  end

  def receive_datagram(state, _datagram, _at), do: {:error, :invalid_datagram, state}

  @doc "Alias for callers that process one packet rather than a datagram batch."
  def receive_packet(state, packet, at \\ 0), do: receive_datagram(state, packet, at)

  @doc "Return the exact retained datagram for retransmission."
  def retransmit(%__MODULE__{} = state, space, number) when space in @spaces do
    case state.recovery.spaces[space].sent[number] do
      %Recovery.Packet{metadata: %{bytes: bytes, level: level, packet_number: ^number}} ->
        {:ok,
         %{space: space, level: level, packet_number: number, bytes: bytes, retransmit: true}}

      %Recovery.Packet{metadata: %{bytes: bytes, level: level}} when is_binary(bytes) ->
        {:ok,
         %{space: space, level: level, packet_number: number, bytes: bytes, retransmit: true}}

      _ ->
        {:error, :unknown_packet}
    end
  end

  @doc "Schedule all currently pending emissions and queued ACKs."
  @spec schedule(t()) :: {:ok, t(), list()} | {:error, term(), t()}
  def schedule(%__MODULE__{} = state) do
    case state.pending do
      [] ->
        case Enum.find(@spaces, &Map.has_key?(state.pending_acks, &1)) do
          nil ->
            {:ok, state, []}

          space ->
            emission = %{
              level: space,
              offset: state.tls.levels[space].next_send,
              bytes: <<>>,
              ack_only: true
            }

            schedule(%{state | pending: [emission]})
        end

      [emission | rest] ->
        if state.queued >= state.max_queue do
          {:error, :send_queue_limit, state}
        else
          case protect_and_reserve(state, emission) do
            {:ok, state, effect} ->
              case schedule(%{
                     state
                     | pending: rest,
                       effects: [effect | state.effects],
                       queued: state.queued + 1
                   }) do
                {:ok, state, effects} -> {:ok, state, [effect | effects]}
                error -> error
              end

            {:error, reason, state} ->
              {:error, reason, state}
          end
        end
    end
  end

  defp ingest_tls_effects(state, effects) when is_list(effects) do
    Enum.reduce_while(effects, {:ok, state, []}, fn
      {:emit, level, bytes}, {:ok, state, generated} when level in @levels and is_binary(bytes) ->
        offset = emitted_offset(state, level, bytes)
        emission = %{level: level, offset: offset, bytes: bytes}
        {:cont, {:ok, %{state | pending: state.pending ++ [emission]}, generated}}

      {%SSL.QUIC.Secret{}, _}, acc ->
        {:cont, acc}

      %SSL.QUIC.Secret{} = secret, {:ok, state, generated} ->
        case install_secret(state, secret) do
          {:ok, state} -> {:cont, {:ok, state, generated}}
          {:error, reason} -> {:halt, {:error, reason, state}}
        end

      {:handshake_complete, _}, acc ->
        {:cont, acc}

      :handshake_complete, acc ->
        {:cont, acc}

      {:peer_authenticated, _}, acc ->
        {:cont, acc}

      {:peer_transport_parameters, _, _}, acc ->
        {:cont, acc}

      {:negotiated_alpn, _}, acc ->
        {:cont, acc}

      {:error, error}, _ ->
        {:halt, {:error, error, state}}

      _, _ ->
        {:halt, {:error, :invalid_tls_action, state}}
    end)
  end

  defp protect_and_reserve(state, %{level: level, offset: offset, bytes: bytes}) do
    space = level
    key_context = Map.get(state.keys, level)

    with {:ok, packet} <- build_protected(state, level, offset, bytes, key_context),
         :ok <-
           if(byte_size(packet) <= state.max_packet_size,
             do: :ok,
             else: {:error, :packet_size_limit}
           ),
         {:ok, recovery, reserved} <-
           Recovery.reserve(
             state.recovery,
             space,
             %{level: level, crypto: {offset, byte_size(bytes)}, bytes: packet},
             byte_size(packet)
           ),
         {:ok, recovery} <- Recovery.transition(recovery, space, reserved.number, :queued) do
      metadata = Map.put(reserved.metadata, :packet_number, reserved.number)
      recovery = put_in(recovery.spaces[space].sent[reserved.number].metadata, metadata)

      next_state = %{
        state
        | recovery: recovery,
          pending_acks: Map.delete(state.pending_acks, space)
      }

      {:ok, next_state,
       %{type: :send, space: space, level: level, packet_number: reserved.number, bytes: packet}}
    else
      {:error, reason} -> {:error, reason, state}
    end
  end

  defp build_protected(_state, level, _offset, _bytes, nil),
    do: {:error, {:unsupported_level, level}}

  defp build_protected(state, :initial, offset, bytes, keys) do
    ack_frames = Map.get(state.pending_acks, :initial, [])
    crypto = %{type: :crypto, offset: offset, data: bytes}

    with {:ok, ack_bytes} <- Codec.encode_frames(ack_frames),
         {:ok, crypto_bytes} <-
           if(bytes == <<>>, do: {:ok, <<>>}, else: Codec.encode_frames([crypto])),
         plaintext <- crypto_bytes <> ack_bytes,
         plaintext <- pad_initial(state, plaintext, keys),
         pn <- state.recovery.spaces.initial.next,
         pn_len <- packet_number_length(pn),
         {:ok, packet} <- encrypt_initial(state, keys, pn, pn_len, plaintext) do
      {:ok, packet}
    end
  end

  defp build_protected(state, level, offset, bytes, keys)
       when level in [:handshake, :application] and is_map(keys) do
    write_keys = Map.get(keys, :write)

    if is_map(write_keys) do
      ack_frames = Map.get(state.pending_acks, level, [])
      crypto = %{type: :crypto, offset: offset, data: bytes}

      with {:ok, ack_bytes} <- Codec.encode_frames(ack_frames),
           {:ok, crypto_bytes} <-
             if(bytes == <<>>, do: {:ok, <<>>}, else: Codec.encode_frames([crypto])),
           plaintext <- crypto_bytes <> ack_bytes,
           pn <- state.recovery.spaces[level].next,
           pn_len <- packet_number_length(pn),
           {:ok, packet} <- encrypt_protected(state, level, write_keys, pn, pn_len, plaintext) do
        {:ok, packet}
      end
    else
      {:error, {:missing_write_key, level}}
    end
  end

  defp build_protected(_state, level, _offset, _bytes, _keys),
    do: {:error, {:unsupported_level, level}}

  defp encrypt_initial(state, keys, pn, pn_len, plaintext) do
    dummy_cipher = <<0::size((byte_size(plaintext) + 16) * 8)>>

    with {:ok, unprotected} <-
           Codec.build_initial(%{
             dcid: state.dcid,
             scid: state.scid,
             packet_number: pn,
             packet_number_length: pn_len,
             payload: dummy_cipher
           }),
         header_size <- byte_size(unprotected) - byte_size(dummy_cipher),
         aad <- binary_part(unprotected, 0, header_size),
         {:ok, ciphertext} <- Protection.aead_encrypt(keys.key, keys.iv, pn, aad, plaintext),
         packet <- aad <> ciphertext,
         pn_offset <- header_size - pn_len,
         {:ok, mask} <-
           Protection.header_protection_mask(
             keys.hp,
             binary_part(packet, pn_offset + 4, 16),
             :aes_128_gcm
           ),
         prefix_size <- pn_offset - 1,
         <<first, prefix::binary-size(^prefix_size), pn_wire::binary-size(^pn_len), tail::binary>> <-
           packet do
      masked_first = bxor(first, :binary.at(mask, 0) &&& 0x0F)
      masked_pn = mask_packet_number(pn_wire, mask, 1)
      {:ok, <<masked_first, prefix::binary, masked_pn::binary, tail::binary>>}
    else
      {:error, _} = error -> error
      _ -> {:error, :protection_failed}
    end
  end

  defp encrypt_protected(state, :handshake, keys, pn, pn_len, plaintext) do
    encrypt_long(state, keys, 2, pn, pn_len, plaintext)
  end

  defp encrypt_protected(state, :application, keys, pn, pn_len, plaintext) do
    encrypt_short(state, keys, pn, pn_len, plaintext)
  end

  defp encrypt_long(state, keys, packet_type, pn, pn_len, plaintext) do
    dummy_cipher = <<0::size((byte_size(plaintext) + 16) * 8)>>

    with {:ok, length} <- Codec.encode_varint(byte_size(dummy_cipher) + pn_len),
         header <-
           <<0xC0 ||| packet_type <<< 4 ||| pn_len - 1, 1::32, byte_size(state.dcid),
             state.dcid::binary, byte_size(state.scid), state.scid::binary, length::binary>>,
         aad <- header <> <<pn::unsigned-big-integer-size(pn_len * 8)>>,
         {:ok, ciphertext} <- Protection.aead_encrypt(keys.key, keys.iv, pn, aad, plaintext),
         packet <- aad <> ciphertext,
         pn_offset <- byte_size(header),
         {:ok, mask} <-
           Protection.header_protection_mask(
             keys.hp,
             binary_part(packet, pn_offset + 4, 16),
             keys.hp_algorithm
           ),
         prefix_size <- byte_size(header) - 1,
         <<first, prefix::binary-size(^prefix_size), pn_wire::binary-size(^pn_len), tail::binary>> <-
           packet do
      masked_first = bxor(first, :binary.at(mask, 0) &&& 0x0F)
      masked_pn = mask_packet_number(pn_wire, mask, 1)
      {:ok, <<masked_first, prefix::binary, masked_pn::binary, tail::binary>>}
    else
      {:error, _} = error -> error
      _ -> {:error, :protection_failed}
    end
  end

  defp encrypt_short(state, keys, pn, pn_len, plaintext) do
    with header <- <<0x40 ||| pn_len - 1, state.dcid::binary>>,
         aad <- header <> <<pn::unsigned-big-integer-size(pn_len * 8)>>,
         {:ok, ciphertext} <- Protection.aead_encrypt(keys.key, keys.iv, pn, aad, plaintext),
         packet <- aad <> ciphertext,
         pn_offset <- byte_size(header),
         {:ok, mask} <-
           Protection.header_protection_mask(
             keys.hp,
             binary_part(packet, pn_offset + 4, 16),
             keys.hp_algorithm
           ),
         prefix_size <- byte_size(header) - 1,
         <<first, prefix::binary-size(^prefix_size), pn_wire::binary-size(^pn_len), tail::binary>> <-
           packet do
      masked_first = bxor(first, :binary.at(mask, 0) &&& 0x1F)
      masked_pn = mask_packet_number(pn_wire, mask, 1)
      {:ok, <<masked_first, prefix::binary, masked_pn::binary, tail::binary>>}
    else
      {:error, _} = error -> error
      _ -> {:error, :protection_failed}
    end
  end

  defp mask_packet_number(bytes, mask, index) do
    for {byte, i} <- Enum.with_index(:binary.bin_to_list(bytes)), into: <<>> do
      <<bxor(byte, :binary.at(mask, i + index))>>
    end
  end

  defp pad_initial(state, plaintext, _keys) do
    target = max(0, state.min_initial_size)
    overhead = 1 + 4 + 1 + byte_size(state.dcid) + 1 + byte_size(state.scid) + 1 + 1 + 2 + 16
    needed = target - overhead - byte_size(plaintext)
    if needed > 0, do: plaintext <> :binary.copy(<<0>>, needed), else: plaintext
  end

  defp packet_number_length(pn) when pn < 256, do: 1
  defp packet_number_length(pn) when pn < 65_536, do: 2
  defp packet_number_length(pn) when pn < 16_777_216, do: 3
  defp packet_number_length(_), do: 4

  defp emitted_offset(state, level, bytes) do
    existing = Enum.filter(state.pending, &(&1.level == level))

    case Enum.find(Enum.reverse(state.tls.levels[level].sent), fn emission ->
           emission.bytes == bytes and
             not Enum.any?(existing, &(&1.offset == emission.offset))
         end) do
      %{offset: offset} -> offset
      _ -> state.tls.levels[level].next_send - byte_size(bytes)
    end
  end

  defp required_cid(opts, key) do
    case Keyword.get(opts, key) do
      cid when is_binary(cid) and byte_size(cid) <= 20 -> {:ok, cid}
      _ -> {:error, {:missing_or_invalid, key}}
    end
  end

  defp install_secret(state, %SSL.QUIC.Secret{
         level: level,
         direction: direction,
         cipher_suite: cipher_suite,
         aead: aead,
         hkdf: hkdf,
         secret: secret
       })
       when level in [:handshake, :application] and direction in [:read, :write] do
    with {:ok, derived} <- Protection.packet_keys(level, cipher_suite, aead, hkdf, secret) do
      context = Map.put(derived, :direction, direction)
      existing = get_in(state.keys, [level, direction])

      cond do
        is_nil(existing) ->
          keys =
            Map.put(
              state.keys,
              level,
              Map.put(Map.get(state.keys, level, %{}), direction, context)
            )

          {:ok, %{state | keys: keys}}

        existing == context ->
          {:error, {:duplicate_secret, level, direction}}

        true ->
          {:error, {:conflicting_secret, level, direction}}
      end
    end
  end

  defp install_secret(_state, %SSL.QUIC.Secret{level: level}),
    do: {:error, {:unsupported_secret_level, level}}

  defp initial_keys(opts, dcid, role) do
    case Keyword.get(opts, :initial_keys) do
      %{key: _, iv: _, hp: _} = keys -> {:ok, keys}
      nil -> Protection.initial_secrets(dcid, role)
      _ -> {:error, :invalid_initial_context}
    end
  end

  defp initial_read_keys(opts, dcid, role, initial) do
    case Keyword.get(opts, :initial_read_keys) do
      %{key: _, iv: _, hp: _} = keys ->
        keys

      nil ->
        case Protection.initial_secrets(dcid, opposite_role(role)) do
          {:ok, keys} -> keys
          _ -> initial
        end

      _ ->
        initial
    end
  end

  defp opposite_role(:client), do: :server
  defp opposite_role(:server), do: :client

  defp tls_options(opts) do
    opts
    |> Keyword.drop([
      :dcid,
      :scid,
      :initial_keys,
      :keys,
      :recovery,
      :max_packet_size,
      :min_initial_size,
      :max_queue,
      :initial_read_keys
    ])
  end

  defp dispatch_inbound(
         state,
         %{level: level, space: space, number: number, plaintext: plaintext},
         at
       ) do
    case Codec.decode_frames(plaintext) do
      {:ok, frames, <<>>} -> dispatch_frames(state, level, space, number, frames, at, [])
      {:ok, _frames, _tail} -> {:error, :trailing_frame_bytes}
      {:error, reason} -> {:error, {:malformed_frame, reason}}
    end
  end

  defp dispatch_frames(state, _level, _space, _number, [], _at, events),
    do: {:ok, state, Enum.reverse(events)}

  defp dispatch_frames(state, level, space, number, [frame | rest], at, events) do
    case frame do
      %{type: :crypto, offset: offset, data: bytes} when level in [:initial, :handshake] ->
        case feed(state, level, offset, bytes) do
          {:ok, next, generated} ->
            dispatch_frames(next, level, space, number, rest, at, [
              %{type: :crypto, level: level, offset: offset, bytes: bytes, generated: generated}
              | events
            ])

          {:error, reason, _next, _generated} ->
            {:error, reason}
        end

      %{type: :crypto} ->
        {:error, {:wrong_encryption_level, :crypto, level}}

      %{type: :ack} = ack ->
        case receive_ack(state, space, ack, at) do
          {:ok, next, result} ->
            dispatch_frames(next, level, space, number, rest, at, [
              %{type: :ack, result: result} | events
            ])

          {:error, reason} ->
            {:error, {:invalid_ack, reason}}
        end

      %{type: :handshake_done} when level == :application ->
        dispatch_frames(state, level, space, number, rest, at, [%{type: :handshake_done} | events])

      %{type: :handshake_done} ->
        {:error, {:wrong_encryption_level, :handshake_done, level}}

      %{type: type} when type in [:connection_close, :application_close, :ping] ->
        dispatch_frames(state, level, space, number, rest, at, [frame | events])

      _ ->
        dispatch_frames(state, level, space, number, rest, at, [frame | events])
    end
  end

  defp decode_protected_packet(state, datagram) do
    with {:ok, parsed} <- parse_protected_header(state, datagram),
         keys when is_map(keys) <- read_key(state, parsed.level),
         packet <- binary_part(datagram, 0, parsed.packet_length),
         {:ok, unprotected, pn_len} <-
           Protection.remove_header_protection(
             packet,
             parsed.pn_offset,
             keys.hp,
             keys.hp_algorithm
           ),
         pn_offset <- parsed.pn_offset,
         <<_first, _prefix::binary-size(^pn_offset - 1), pn_bytes::binary-size(^pn_len),
           ciphertext::binary>> <- unprotected,
         truncated <- :binary.decode_unsigned(pn_bytes),
         largest <- state.recovery.spaces[parsed.space].largest_received,
         {:ok, number} <- reconstruct_inbound(truncated, largest, pn_len),
         aad_size <- parsed.pn_offset + pn_len,
         aad <- binary_part(unprotected, 0, aad_size),
         {:ok, plaintext} <- Protection.aead_decrypt(keys.key, keys.iv, number, aad, ciphertext) do
      {:ok, Map.merge(parsed, %{number: number, plaintext: plaintext})}
    else
      nil -> {:error, :missing_read_key}
      {:error, reason} -> {:error, reason}
      _ -> {:error, :malformed_protected_packet}
    end
  end

  defp reconstruct_inbound(truncated, -1, _pn_len), do: {:ok, truncated}

  defp reconstruct_inbound(truncated, largest, pn_len)
       when truncated <= largest and largest - truncated < 1 <<< (pn_len * 8 - 1),
       do: {:ok, truncated}

  defp reconstruct_inbound(truncated, largest, pn_len),
    do: Codec.reconstruct_packet_number(truncated, largest, pn_len)

  defp read_key(state, :initial) do
    case state.read_keys[:initial] || state.read_keys do
      %{key: _, iv: _, hp: _} = keys -> Map.put_new(keys, :hp_algorithm, :aes_128_gcm)
      keys -> keys
    end
  end

  defp read_key(state, level), do: get_in(state.keys, [level, :read])

  defp parse_protected_header(state, <<first, version::32, rest::binary>> = packet)
       when (first &&& 0x80) != 0 do
    if version != 1,
      do: {:error, :unsupported_version},
      else: parse_long_header(state, first, rest, packet)
  end

  defp parse_protected_header(state, <<first, _rest::binary>> = packet)
       when (first &&& 0x80) == 0 do
    dcid_len = byte_size(state.dcid)
    pn_offset = 1 + dcid_len

    if byte_size(packet) < pn_offset + 4 + 16,
      do: {:error, :truncated_header},
      else:
        {:ok,
         %{
           level: :application,
           space: :application,
           pn_offset: pn_offset,
           packet_length: byte_size(packet)
         }}
  end

  defp parse_protected_header(_, _), do: {:error, :truncated_header}

  defp parse_long_header(state, first, rest, packet) do
    type = first >>> 4 &&& 0x03

    with {:ok, dcid, rest} <- take_cid(rest),
         {:ok, scid, rest} <- take_cid(rest),
         :ok <- validate_cids(state, dcid, scid),
         {:ok, rest} <- maybe_skip_token(type, rest),
         {:ok, length, after_length} <- Codec.decode_varint(rest),
         true <- length >= 1 and byte_size(after_length) >= length,
         pn_offset <- byte_size(packet) - byte_size(after_length),
         {:ok, level} <- long_level(type) do
      {:ok,
       %{level: level, space: level, pn_offset: pn_offset, packet_length: pn_offset + length}}
    else
      false -> {:error, :truncated_packet}
      {:error, _} = error -> error
    end
  end

  defp take_cid(<<length, rest::binary>>) when length <= 20 and byte_size(rest) >= length,
    do: {:ok, binary_part(rest, 0, length), binary_part(rest, length, byte_size(rest) - length)}

  defp take_cid(_), do: {:error, :malformed_connection_id}

  defp maybe_skip_token(0, rest) do
    with {:ok, length, rest} <- Codec.decode_varint(rest), true <- byte_size(rest) >= length do
      {:ok, binary_part(rest, length, byte_size(rest) - length)}
    else
      false -> {:error, :truncated_token}
      error -> error
    end
  end

  defp maybe_skip_token(2, rest), do: {:ok, rest}
  defp maybe_skip_token(_, _), do: {:error, :unsupported_packet_type}

  defp long_level(0), do: {:ok, :initial}
  defp long_level(2), do: {:ok, :handshake}
  defp long_level(_), do: {:error, :unsupported_packet_type}

  defp validate_cids(state, dcid, scid) do
    if dcid == state.scid or dcid == state.dcid or scid == state.scid or scid == state.dcid,
      do: :ok,
      else: {:error, :wrong_connection_id}
  end
end
