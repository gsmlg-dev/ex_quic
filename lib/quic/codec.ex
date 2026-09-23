defmodule QUIC.Codec do
  @moduledoc """
  Bounded QUIC v1 wire helpers.
  """
  import Bitwise

  @max_varint 0x3FFFFFFFFFFFFFFF
  @version 1

  @spec encode_varint(non_neg_integer()) :: {:ok, binary()} | {:error, :varint_overflow}
  def encode_varint(value) when is_integer(value) and value >= 0 and value <= @max_varint do
    cond do
      value < 1 <<< 6 -> {:ok, <<value>>}
      value < 1 <<< 14 -> {:ok, <<1::2, value::14>>}
      value < 1 <<< 30 -> {:ok, <<2::2, value::30>>}
      true -> {:ok, <<3::2, value::62>>}
    end
  end

  def encode_varint(_), do: {:error, :varint_overflow}

  @spec decode_varint(binary()) :: {:ok, non_neg_integer(), binary()} | {:error, atom()}
  def decode_varint(<<prefix, rest::binary>>) do
    bytes = 1 <<< (prefix >>> 6)
    value = prefix &&& 0x3F

    if byte_size(rest) < bytes - 1 do
      {:error, :truncated_varint}
    else
      tail_size = bytes - 1
      <<tail::binary-size(^tail_size), remainder::binary>> = rest
      {:ok, (value <<< (8 * (bytes - 1))) + :binary.decode_unsigned(tail), remainder}
    end
  end

  def decode_varint(_), do: {:error, :truncated_varint}

  @spec reconstruct_packet_number(non_neg_integer(), non_neg_integer(), pos_integer()) ::
          {:ok, non_neg_integer()} | {:error, atom()}
  def reconstruct_packet_number(truncated, largest, pn_len)
      when pn_len in [1, 2, 3, 4] and truncated >= 0 and truncated < 1 <<< (pn_len * 8) and
             largest >= 0 do
    expected = largest + 1
    window = 1 <<< (pn_len * 8)
    half = div(window, 2)
    candidate = (expected &&& window - 1) ||| truncated

    candidate =
      cond do
        candidate + half <= expected -> candidate + window
        candidate > expected + half and candidate >= window -> candidate - window
        true -> candidate
      end

    {:ok, candidate}
  end

  def reconstruct_packet_number(_, _, _), do: {:error, :invalid_packet_number}

  @spec build_initial(map()) :: {:ok, binary()} | {:error, atom()}
  def build_initial(
        %{
          dcid: dcid,
          scid: scid,
          packet_number: pn,
          packet_number_length: pn_len,
          payload: payload
        } = fields
      )
      when is_binary(dcid) and is_binary(scid) and is_binary(payload) and byte_size(dcid) <= 20 and
             byte_size(scid) <= 20 and pn_len in [1, 2, 3, 4] and pn >= 0 and
             pn < 1 <<< (pn_len * 8) do
    token = Map.get(fields, :token, <<>>)
    version = Map.get(fields, :version, @version)

    with :ok <- valid_bytes(token, 0xFFFF),
         :ok <- valid_version(version),
         {:ok, token_len} <- encode_varint(byte_size(token)),
         {:ok, length} <- encode_varint(byte_size(payload) + pn_len),
         true <- byte_size(dcid) <= 255 and byte_size(scid) <= 255 do
      first = 0xC0 ||| 0 <<< 4 ||| pn_len - 1

      {:ok,
       <<first, version::32, byte_size(dcid), dcid::binary, byte_size(scid), scid::binary,
         token_len::binary, token::binary, length::binary,
         pn::unsigned-big-integer-size(pn_len * 8), payload::binary>>}
    else
      false -> {:error, :connection_id_too_long}
      error -> error
    end
  end

  def build_initial(_), do: {:error, :invalid_initial_fields}

  @spec parse_initial(binary()) :: {:ok, map()} | {:error, atom()}
  def parse_initial(<<first, version::32, rest::binary>> = packet) do
    with :ok <- validate_initial_first(first),
         :ok <- valid_version(version),
         {:ok, dcid, rest} <- take_cid(rest),
         {:ok, scid, rest} <- take_cid(rest),
         {:ok, token_len, rest} <- decode_varint(rest),
         :ok <- bound_length(token_len, byte_size(rest)),
         <<token::binary-size(^token_len), rest::binary>> <- rest,
         {:ok, length, rest} <- decode_varint(rest),
         :ok <- bound_length(length, byte_size(rest)),
         true <- length >= 1 do
      <<pn_and_payload::binary-size(^length), trailing::binary>> = rest
      pn_len = (first &&& 3) + 1

      if byte_size(pn_and_payload) < pn_len do
        {:error, :truncated_packet_number}
      else
        <<pn_bytes::binary-size(^pn_len), payload::binary>> = pn_and_payload

        {:ok,
         %{
           type: :initial,
           version: version,
           dcid: dcid,
           scid: scid,
           token: token,
           packet_number_length: pn_len,
           packet_number_bytes: pn_bytes,
           packet_number: :binary.decode_unsigned(pn_bytes),
           payload: payload,
           packet_length: byte_size(packet) - byte_size(trailing),
           trailing: trailing
         }}
      end
    else
      {:error, _} = error -> error
      _ -> {:error, :malformed_initial}
    end
  end

  def parse_initial(_), do: {:error, :truncated_header}

  @spec split_datagram(binary()) :: {:ok, [binary()]} | {:error, atom()}
  def split_datagram(datagram), do: split_datagram(datagram, [])

  defp split_datagram(<<>>, acc), do: {:ok, Enum.reverse(acc)}

  defp split_datagram(data, acc) do
    case parse_initial(data) do
      {:ok, %{packet_length: length}} ->
        <<packet::binary-size(^length), rest::binary>> = data
        split_datagram(rest, [packet | acc])

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec encode_frames([map()]) :: {:ok, binary()} | {:error, atom()}
  def encode_frames(frames) when is_list(frames), do: encode_frames(frames, [])
  def encode_frames(_), do: {:error, :invalid_frames}

  defp encode_frames([], acc), do: {:ok, IO.iodata_to_binary(Enum.reverse(acc))}
  defp encode_frames([%{type: :ping} | rest], acc), do: encode_frames(rest, [<<1>> | acc])

  defp encode_frames([%{type: :crypto, offset: offset, data: data} | rest], acc)
       when is_integer(offset) and offset >= 0 and is_binary(data) do
    with {:ok, o} <- encode_varint(offset), {:ok, l} <- encode_varint(byte_size(data)) do
      encode_frames(rest, [data, l, o, <<6>> | acc])
    end
  end

  defp encode_frames([%{type: :ack, largest: largest, delay: delay, ranges: ranges} | rest], acc)
       when is_integer(largest) and is_integer(delay) and is_list(ranges) do
    with {:ok, a} <- encode_varint(largest),
         {:ok, d} <- encode_varint(delay),
         {:ok, encoded} <- encode_ack_ranges(ranges) do
      encode_frames(rest, [encoded, d, a, <<2>> | acc])
    end
  end

  defp encode_frames([_ | _], _), do: {:error, :unsupported_frame}

  @spec decode_frames(binary(), keyword()) :: {:ok, [map()], binary()} | {:error, atom()}
  def decode_frames(data, opts \\ []) when is_binary(data) do
    max_frames = Keyword.get(opts, :max_frames, 1024)
    decode_frames(data, [], max_frames)
  end

  defp decode_frames(_rest, _acc, 0), do: {:error, :frame_limit}
  defp decode_frames(<<>>, acc, _), do: {:ok, Enum.reverse(acc), <<>>}

  defp decode_frames(<<0, rest::binary>>, acc, limit), do: decode_frames(rest, acc, limit)

  defp decode_frames(<<1, rest::binary>>, acc, limit),
    do: decode_frames(rest, [%{type: :ping} | acc], limit - 1)

  defp decode_frames(<<6, rest::binary>>, acc, limit) do
    with {:ok, offset, rest} <- decode_varint(rest),
         {:ok, length, rest} <- decode_varint(rest),
         :ok <- bound_length(length, byte_size(rest)),
         <<data::binary-size(^length), tail::binary>> <- rest do
      decode_frames(tail, [%{type: :crypto, offset: offset, data: data} | acc], limit - 1)
    else
      _ -> {:error, :malformed_crypto_frame}
    end
  end

  defp decode_frames(<<type, _::binary>>, _acc, _limit) when type >= 0x08 and type <= 0x0F,
    do: {:error, :unsupported_frame}

  defp decode_frames(<<type, _::binary>>, _acc, _limit), do: {:error, {:unknown_frame, type}}
  defp decode_frames(_, _, _), do: {:error, :malformed_frame}

  defp encode_ack_ranges([]), do: {:error, :invalid_ack_ranges}

  defp encode_ack_ranges([{gap, range} | rest]) when gap >= 0 and range >= 0 do
    with {:ok, g} <- encode_varint(gap),
         {:ok, r} <- encode_varint(range),
         {:ok, tail} <- encode_ack_ranges(rest),
         do: {:ok, <<g::binary, r::binary, tail::binary>>}
  end

  defp encode_ack_ranges(_), do: {:error, :invalid_ack_ranges}

  defp take_cid(<<len, rest::binary>>) when len <= 20 and byte_size(rest) >= len,
    do: {:ok, binary_part(rest, 0, len), binary_part(rest, len, byte_size(rest) - len)}

  defp take_cid(_), do: {:error, :invalid_connection_id}

  defp validate_initial_first(first)
       when (first &&& 0x80) != 0 and (first &&& 0x40) != 0 and (first >>> 4 &&& 3) == 0, do: :ok

  defp validate_initial_first(_), do: {:error, :not_initial}
  defp valid_version(@version), do: :ok
  defp valid_version(_), do: {:error, :unsupported_version}
  defp valid_bytes(_, max) when max < 0, do: {:error, :invalid_bound}
  defp valid_bytes(value, max) when is_binary(value) and byte_size(value) <= max, do: :ok
  defp valid_bytes(_, _), do: {:error, :length_exceeded}
  defp bound_length(length, available) when length >= 0 and length <= available, do: :ok
  defp bound_length(_, _), do: {:error, :truncated_payload}
end
