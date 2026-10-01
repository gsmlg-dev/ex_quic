defmodule SSL.SessionTicket do
  @moduledoc "Bounded, authenticated TLS 1.3 ticket material retained in memory only."

  @derive {Inspect, only: [:hash, :issued_at, :expires_at, :alpn]}
  @enforce_keys [:ticket, :psk, :hash, :age_add, :issued_at, :expires_at, :peer, :alpn]
  defstruct @enforce_keys

  @max_lifetime 604_800_000
  @max_entry_bytes 262_144

  @type t :: %__MODULE__{
          ticket: binary(),
          psk: binary(),
          hash: :sha256 | :sha384,
          age_add: non_neg_integer(),
          issued_at: integer(),
          expires_at: integer(),
          peer: map(),
          alpn: binary() | nil
        }

  @spec validate(term()) :: :ok | {:error, atom()}
  def validate(%__MODULE__{} = ticket) do
    hash_length =
      case ticket.hash do
        :sha256 -> 32
        :sha384 -> 48
        _ -> nil
      end

    cond do
      is_nil(hash_length) ->
        {:error, :invalid_hash}

      not is_binary(ticket.ticket) or byte_size(ticket.ticket) not in 1..16_384 ->
        {:error, :invalid_ticket}

      not is_binary(ticket.psk) or byte_size(ticket.psk) != hash_length ->
        {:error, :invalid_psk}

      not is_integer(ticket.age_add) or ticket.age_add not in 0..0xFFFFFFFF ->
        {:error, :invalid_age_add}

      not is_integer(ticket.issued_at) or not is_integer(ticket.expires_at) or
        ticket.expires_at <= ticket.issued_at or
          ticket.expires_at - ticket.issued_at > @max_lifetime ->
        {:error, :invalid_lifetime}

      not valid_peer?(ticket.peer) ->
        {:error, :invalid_peer}

      not (is_nil(ticket.alpn) or
               (is_binary(ticket.alpn) and byte_size(ticket.alpn) in 1..255)) ->
        {:error, :invalid_alpn}

      :erlang.external_size(ticket) > @max_entry_bytes ->
        {:error, :ticket_too_large}

      true ->
        :ok
    end
  end

  def validate(_), do: {:error, :invalid_ticket}

  defp valid_peer?(%{chain: [_ | _] = chain}) when length(chain) <= 128 do
    Enum.all?(chain, &(is_binary(&1) and byte_size(&1) in 1..1_048_576))
  end

  defp valid_peer?(_), do: false
end
