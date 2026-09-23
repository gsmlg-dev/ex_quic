defmodule QUIC.Protection do
  @moduledoc """
  QUIC v1 Initial packet protection primitives.
  """
  import Bitwise

  @salt Base.decode16!("38762c f7f55934 b34d179a e6a4c80c adccbb7f 0a" |> String.replace(" ", ""),
          case: :lower
        )
  @retry_key Base.decode16!("be0c690b 9f66575a 1d766b54 e368c84e" |> String.replace(" ", ""),
               case: :lower
             )
  @retry_nonce Base.decode16!("461599d35d632bf2 23a5b3f0" |> String.replace(" ", ""),
                 case: :lower
               )

  @spec initial_secrets(binary(), :client | :server) :: {:ok, map()} | {:error, atom()}
  def initial_secrets(dcid, role) when is_binary(dcid) and role in [:client, :server] do
    initial = hkdf_extract(@salt, dcid)
    {:ok, client} = hkdf_label(initial, "client in", 32)
    {:ok, server} = hkdf_label(initial, "server in", 32)
    secret = if role == :client, do: client, else: server

    with {:ok, key} <- hkdf_label(secret, "quic key", 16),
         {:ok, iv} <- hkdf_label(secret, "quic iv", 12),
         {:ok, hp} <- hkdf_label(secret, "quic hp", 16) do
      {:ok,
       %{
         client: %{secret: client},
         server: %{secret: server},
         secret: secret,
         key: key,
         iv: iv,
         hp: hp,
         role: role
       }}
    end
  end

  def initial_secrets(_, _), do: {:error, :invalid_initial_context}

  @spec aead_encrypt(binary(), binary(), non_neg_integer(), binary(), binary()) ::
          {:ok, binary()} | {:error, atom()}
  def aead_encrypt(key, iv, packet_number, aad, plaintext),
    do: aead(:encrypt, key, iv, packet_number, aad, plaintext)

  @spec aead_decrypt(binary(), binary(), non_neg_integer(), binary(), binary()) ::
          {:ok, binary()} | {:error, atom()}
  def aead_decrypt(key, iv, packet_number, aad, ciphertext),
    do: aead(:decrypt, key, iv, packet_number, aad, ciphertext)

  @spec header_protection_mask(binary(), binary(), :aes_128_gcm | :chacha20_poly1305) ::
          {:ok, binary()} | {:error, atom()}
  def header_protection_mask(hp, sample, algorithm)
      when is_binary(hp) and byte_size(sample) >= 16 do
    try do
      case algorithm do
        :aes_128_gcm ->
          {:ok, :crypto.crypto_one_time(:aes_128_ecb, hp, sample, true) |> binary_part(0, 5)}

        :chacha20_poly1305 ->
          <<counter::little-32, nonce::binary-size(12)>> = sample

          {:ok,
           :crypto.crypto_one_time(
             :chacha20,
             hp,
             <<nonce::binary, counter::little-32>>,
             <<0, 0, 0, 0, 0>>
           )
           |> binary_part(0, 5)}

        _ ->
          {:error, :unsupported_header_protection}
      end
    rescue
      _ -> {:error, :crypto_unavailable}
    catch
      _, _ -> {:error, :crypto_unavailable}
    end
  end

  def header_protection_mask(_, _, _), do: {:error, :short_sample}

  @doc "Removes QUIC header protection from a packet prefix and packet number bytes."
  @spec remove_header_protection(
          binary(),
          non_neg_integer(),
          binary(),
          :aes_128_gcm | :chacha20_poly1305
        ) ::
          {:ok, binary(), non_neg_integer()} | {:error, atom()}
  def remove_header_protection(packet, pn_offset, hp, algorithm)
      when is_binary(packet) and is_integer(pn_offset) and pn_offset >= 1 and is_binary(hp) do
    if byte_size(packet) < pn_offset + 4 + 16 do
      {:error, :short_sample}
    else
      sample = binary_part(packet, pn_offset + 4, 16)
      header_rest_size = pn_offset - 1

      with {:ok, mask} <- header_protection_mask(hp, sample, algorithm),
           <<first, header_rest::binary-size(^header_rest_size), rest::binary>> <- packet do
        mask_first = :binary.decode_unsigned(binary_part(mask, 0, 1))
        first = bxor(first, mask_first &&& 0x0F)
        pn_len = (first &&& 3) + 1

        if byte_size(rest) < pn_len do
          {:error, :truncated_packet_number}
        else
          <<pn::binary-size(^pn_len), tail::binary>> = rest

          unmasked =
            for {byte, index} <- Enum.with_index(:binary.bin_to_list(pn)), into: <<>> do
              <<bxor(byte, :binary.at(mask, index + 1))>>
            end

          {:ok, <<first, header_rest::binary, unmasked::binary, tail::binary>>, pn_len}
        end
      else
        _ -> {:error, :malformed_header}
      end
    end
  end

  def remove_header_protection(_, _, _, _), do: {:error, :invalid_header_protection_input}

  @spec retry_tag(binary(), binary()) :: {:ok, binary()} | {:error, atom()}
  def retry_tag(original_dcid, retry_packet)
      when is_binary(original_dcid) and is_binary(retry_packet) and byte_size(original_dcid) <= 20 do
    pseudo = <<byte_size(original_dcid), original_dcid::binary, retry_packet::binary>>

    try do
      {_, tag} =
        :crypto.crypto_one_time_aead(
          :aes_128_gcm,
          @retry_key,
          @retry_nonce,
          <<>>,
          pseudo,
          16,
          true
        )

      {:ok, tag}
    rescue
      _ -> {:error, :crypto_unavailable}
    catch
      _, _ -> {:error, :crypto_unavailable}
    end
  end

  def retry_tag(_, _), do: {:error, :invalid_retry_input}

  @spec validate_retry(binary(), binary()) :: :ok | {:error, atom()}
  def validate_retry(original_dcid, packet) when is_binary(packet) and byte_size(packet) >= 16 do
    body_size = byte_size(packet) - 16
    <<body::binary-size(^body_size), tag::binary-size(16)>> = packet

    with {:ok, expected} <- retry_tag(original_dcid, body),
         true <- :crypto.hash_equals(expected, tag) do
      :ok
    else
      false -> {:error, :invalid_retry_tag}
      error -> error
    end
  end

  def validate_retry(_, _), do: {:error, :truncated_retry}

  defp aead(mode, key, iv, pn, aad, data)
       when is_binary(key) and is_binary(iv) and is_integer(pn) and pn >= 0 and is_binary(aad) and
              is_binary(data) do
    if byte_size(iv) != 12 do
      {:error, :invalid_iv}
    else
      try do
        prefix = binary_part(iv, 0, 4)
        suffix = binary_part(iv, 4, 8) |> :binary.decode_unsigned(:big) |> bxor(pn)
        nonce = prefix <> <<suffix::unsigned-big-64>>

        case mode do
          :encrypt ->
            {cipher, tag} =
              :crypto.crypto_one_time_aead(:aes_128_gcm, key, nonce, data, aad, 16, true)

            {:ok, cipher <> tag}

          :decrypt when byte_size(data) >= 16 ->
            cipher = binary_part(data, 0, byte_size(data) - 16)
            tag = binary_part(data, byte_size(data) - 16, 16)

            case :crypto.crypto_one_time_aead(:aes_128_gcm, key, nonce, cipher, aad, tag, false) do
              :error -> {:error, :bad_tag}
              plain -> {:ok, plain}
            end

          :decrypt ->
            {:error, :truncated_ciphertext}
        end
      rescue
        _ -> {:error, :crypto_unavailable}
      catch
        _, _ -> {:error, :crypto_unavailable}
      end
    end
  end

  defp aead(_, _, _, _, _, _), do: {:error, :invalid_aead_input}

  defp hkdf_extract(salt, input), do: :crypto.mac(:hmac, :sha256, salt, input)
  defp hkdf_expand(prk, info, length), do: hkdf_expand_fallback(prk, info, length)

  defp hkdf_expand_fallback(prk, info, length),
    do: hkdf_expand_fallback(prk, info, length, <<>>, <<>>, 1)

  defp hkdf_expand_fallback(_, _, length, _, out, _) when byte_size(out) >= length,
    do: binary_part(out, 0, length)

  defp hkdf_expand_fallback(prk, info, length, previous, out, counter) do
    block = :crypto.mac(:hmac, :sha256, prk, previous <> info <> <<counter>>)
    hkdf_expand_fallback(prk, info, length, block, out <> block, counter + 1)
  end

  defp hkdf_label(secret, label, length) do
    full_label = "tls13 " <> label
    info = <<length::16, byte_size(full_label)::8, full_label::binary, 0>>
    {:ok, hkdf_expand(secret, info, length)}
  end
end
