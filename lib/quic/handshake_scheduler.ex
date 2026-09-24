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

      %SSL.QUIC.Secret{}, acc ->
        {:cont, acc}

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

  defp initial_keys(opts, dcid, role) do
    case Keyword.get(opts, :initial_keys) do
      %{key: _, iv: _, hp: _} = keys -> {:ok, keys}
      nil -> Protection.initial_secrets(dcid, role)
      _ -> {:error, :invalid_initial_context}
    end
  end

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
      :max_queue
    ])
  end
end
