defmodule QUIC.Streams do
  @moduledoc """
  Connection-owned QUIC stream state.

  Stream values are data references; this module creates no processes. All
  peer-controlled offsets and buffering are checked against the configured
  limits before bytes are retained.
  """
  import Bitwise

  defstruct role: :client,
            streams: %{},
            max_data: 1_048_576,
            data_sent: 0,
            data_received: 0,
            max_stream_data: 65_536,
            max_streams_bidi: 16,
            max_streams_uni: 16,
            max_buffer: 262_144,
            peer_max_data: 1_048_576,
            peer_max_stream_data: 65_536,
            peer_max_streams_bidi: 16,
            peer_max_streams_uni: 16,
            blocked: MapSet.new()

  defmodule Stream do
    defstruct id: 0,
              bidi: true,
              local_initiated: false,
              send_offset: 0,
              send_limit: 0,
              send_final: nil,
              recv_next: 0,
              recv_limit: 0,
              recv_final: nil,
              recv_chunks: %{},
              recv_buffered: 0,
              reset: nil,
              stopped: nil
  end

  @type t :: %__MODULE__{}

  @spec new(:client | :server, keyword()) :: t()
  def new(role, opts \\ [])

  def new(role, opts) when role in [:client, :server] do
    %__MODULE__{
      role: role,
      max_data: positive(opts, :max_data, 1_048_576),
      max_stream_data: positive(opts, :max_stream_data, 65_536),
      max_streams_bidi: nonnegative(opts, :max_streams_bidi, 16),
      max_streams_uni: nonnegative(opts, :max_streams_uni, 16),
      max_buffer: positive(opts, :max_buffer, 262_144),
      peer_max_data: positive(opts, :peer_max_data, 1_048_576),
      peer_max_stream_data: positive(opts, :peer_max_stream_data, 65_536),
      peer_max_streams_bidi: nonnegative(opts, :peer_max_streams_bidi, 16),
      peer_max_streams_uni: nonnegative(opts, :peer_max_streams_uni, 16)
    }
  end

  def new(_, _), do: raise(ArgumentError, "invalid stream role")

  @doc "Open a locally initiated stream and return its stable stream id."
  def open(%__MODULE__{} = state, kind) when kind in [:bidi, :uni] do
    limit = if kind == :bidi, do: state.peer_max_streams_bidi, else: state.peer_max_streams_uni

    count =
      Enum.count(state.streams, fn {_id, s} -> s.local_initiated and s.bidi == (kind == :bidi) end)

    if count >= limit do
      {:blocked, blocked_frame(kind, count)}
    else
      id = 4 * count + role_bit(state.role) + if(kind == :uni, do: 4, else: 0)
      stream = make_stream(state, id, kind == :bidi, true)
      {:ok, %{state | streams: Map.put(state.streams, id, stream)}, id}
    end
  end

  @doc "Admit bytes to a stream send queue; returned frame can be packetized."
  def send(%__MODULE__{} = state, id, data, fin \\ false)
      when is_integer(id) and id >= 0 and is_binary(data) and is_boolean(fin) do
    with {:ok, stream} <- fetch_stream(state, id),
         :ok <- can_send?(stream),
         :ok <- valid_final_send(stream, byte_size(data), fin),
         :ok <- send_credit(state, stream, byte_size(data)) do
      next_offset = stream.send_offset + byte_size(data)

      stream = %{
        stream
        | send_offset: next_offset,
          send_final: if(fin, do: next_offset, else: stream.send_final)
      }

      next = %{
        state
        | streams: Map.put(state.streams, id, stream),
          data_sent: state.data_sent + byte_size(data)
      }

      {:ok, next,
       %{
         type: :stream,
         stream_id: id,
         offset: stream.send_offset - byte_size(data),
         data: data,
         fin: fin
       }}
    else
      {:error, _} = error -> error
      :blocked -> {:blocked, %{type: :data_blocked, value: state.data_sent}}
    end
  end

  @doc "Process one authenticated STREAM frame and emit newly contiguous bytes."
  def receive(%__MODULE__{} = state, %{
        type: :stream,
        stream_id: id,
        offset: offset,
        data: data,
        fin: fin
      })
      when is_integer(id) and id >= 0 and is_integer(offset) and offset >= 0 and is_binary(data) and
             is_boolean(fin) do
    with {:ok, state, stream} <- ensure_peer_stream(state, id),
         :ok <- can_receive?(stream),
         :ok <- receive_bounds(state, stream, offset, data),
         :ok <- consistent_final(stream, offset + byte_size(data), fin),
         stream <- %{
           stream
           | recv_final: if(fin, do: offset + byte_size(data), else: stream.recv_final)
         },
         {:ok, stream} <- insert_chunk(stream, offset, data),
         {:ok, stream, events} <- consume(stream, id) do
      {:ok,
       %{
         state
         | streams: Map.put(state.streams, id, stream),
           data_received: state.data_received + emitted_bytes(events)
       }, events}
    else
      {:error, _} = error -> error
    end
  end

  def receive(_, _), do: {:error, :invalid_stream_frame}

  def reset(%__MODULE__{} = state, id, error_code, final_size)
      when is_integer(error_code) and error_code >= 0 and is_integer(final_size) and
             final_size >= 0 do
    with {:ok, stream} <- fetch_stream(state, id),
         :ok <- can_receive?(stream),
         :ok <- reset_final(stream, final_size) do
      stream = %{
        stream
        | reset: error_code,
          recv_final: final_size,
          recv_chunks: %{},
          recv_buffered: 0
      }

      {:ok, %{state | streams: Map.put(state.streams, id, stream)},
       [{:reset, id, error_code, final_size}]}
    end
  end

  @doc "Apply a peer RESET_STREAM, admitting a previously unseen peer stream."
  def receive_reset(%__MODULE__{} = state, id, error_code, final_size)
      when is_integer(id) and id >= 0 do
    with {:ok, state, stream} <- ensure_peer_stream(state, id),
         :ok <- can_receive?(stream),
         :ok <- reset_final(stream, final_size) do
      stream = %{
        stream
        | reset: error_code,
          recv_final: final_size,
          recv_chunks: %{},
          recv_buffered: 0
      }

      {:ok, %{state | streams: Map.put(state.streams, id, stream)},
       [{:reset, id, error_code, final_size}]}
    end
  end

  def stop_sending(%__MODULE__{} = state, id, error_code)
      when is_integer(error_code) and error_code >= 0 do
    with {:ok, stream} <- fetch_stream(state, id), :ok <- can_receive?(stream) do
      stream = %{stream | stopped: error_code}

      {:ok, %{state | streams: Map.put(state.streams, id, stream)},
       %{type: :stop_sending, stream_id: id, error_code: error_code}}
    end
  end

  @doc "Apply a peer STOP_SENDING to the local send direction."
  def peer_stop_sending(%__MODULE__{} = state, id, error_code)
      when is_integer(error_code) and error_code >= 0 do
    with {:ok, stream} <- fetch_stream(state, id),
         :ok <- can_send?(stream) do
      {:ok, %{state | streams: Map.put(state.streams, id, %{stream | stopped: error_code})}}
    end
  end

  def update_credit(%__MODULE__{} = state, %{type: :max_data, value: value})
      when is_integer(value) and value >= 0,
      do: {:ok, %{state | peer_max_data: max(state.peer_max_data, value)}, :unblocked}

  def update_credit(%__MODULE__{} = state, %{type: :max_stream_data, stream_id: id, value: value})
      when is_integer(id) and is_integer(value) and value >= 0 do
    with {:ok, stream} <- fetch_stream(state, id) do
      stream = %{stream | send_limit: max(stream.send_limit, value)}
      {:ok, %{state | streams: Map.put(state.streams, id, stream)}, :unblocked}
    end
  end

  def update_credit(%__MODULE__{} = state, %{type: :max_streams_bidi, value: value})
      when is_integer(value) and value >= 0,
      do:
        {:ok, %{state | peer_max_streams_bidi: max(state.peer_max_streams_bidi, value)},
         :unblocked}

  def update_credit(%__MODULE__{} = state, %{type: :max_streams_uni, value: value})
      when is_integer(value) and value >= 0,
      do:
        {:ok, %{state | peer_max_streams_uni: max(state.peer_max_streams_uni, value)}, :unblocked}

  def update_credit(_, _), do: {:error, :invalid_credit_frame}

  def stream(%__MODULE__{} = state, id), do: Map.get(state.streams, id)

  defp fetch_stream(state, id) do
    case Map.fetch(state.streams, id) do
      {:ok, stream} -> {:ok, stream}
      :error -> {:error, :unknown_stream}
    end
  end

  defp ensure_peer_stream(state, id) do
    local = (id &&& 1) == role_bit(state.role)

    if local do
      case fetch_stream(state, id) do
        {:ok, stream} -> {:ok, state, stream}
        _ -> {:error, :peer_stream_id_invalid}
      end
    else
      bidi = (id &&& 4) == 0

      count =
        Enum.count(state.streams, fn {_k, s} -> not s.local_initiated and s.bidi == bidi end)

      limit = if bidi, do: state.max_streams_bidi, else: state.max_streams_uni

      if div(id, 4) >= limit or count >= limit do
        {:error, :stream_limit}
      else
        next = put_peer_stream(state, id, bidi)
        {:ok, next, next.streams[id]}
      end
    end
  end

  defp put_peer_stream(state, id, bidi) do
    stream = make_stream(state, id, bidi, false)
    %{state | streams: Map.put(state.streams, id, stream)}
  end

  defp make_stream(state, id, bidi, local) do
    %Stream{
      id: id,
      bidi: bidi,
      local_initiated: local,
      send_limit: state.peer_max_stream_data,
      recv_limit: state.max_stream_data
    }
  end

  defp can_send?(%Stream{stopped: reason}) when not is_nil(reason), do: {:error, :stopped}
  defp can_send?(%Stream{bidi: true}), do: :ok
  defp can_send?(%Stream{local_initiated: true}), do: :ok
  defp can_send?(_), do: {:error, :send_on_receive_only_stream}
  defp can_receive?(%Stream{bidi: true}), do: :ok
  defp can_receive?(%Stream{local_initiated: false}), do: :ok
  defp can_receive?(_), do: {:error, :receive_on_send_only_stream}

  defp send_credit(state, stream, bytes) do
    cond do
      state.data_sent + bytes > state.peer_max_data -> :blocked
      stream.send_offset + bytes > stream.send_limit -> :blocked
      true -> :ok
    end
  end

  defp valid_final_send(%Stream{send_final: nil}, bytes, true), do: if(bytes >= 0, do: :ok)
  defp valid_final_send(%Stream{send_final: nil}, _bytes, false), do: :ok

  defp valid_final_send(%Stream{send_final: final, send_offset: offset}, bytes, fin),
    do: if(offset + bytes == final and fin, do: :ok, else: {:error, :final_size_error})

  defp receive_bounds(state, stream, offset, data) do
    end_offset = offset + byte_size(data)

    cond do
      end_offset > stream.recv_limit -> {:error, :flow_control}
      offset > stream.recv_next + state.max_buffer -> {:error, :buffer_limit}
      stream.recv_buffered + byte_size(data) > state.max_buffer -> {:error, :buffer_limit}
      true -> :ok
    end
  end

  defp consistent_final(%Stream{recv_final: nil}, _end_offset, false), do: :ok
  defp consistent_final(%Stream{recv_final: nil}, _end_offset, true), do: :ok

  defp consistent_final(%Stream{recv_final: final}, end_offset, fin)
       when fin and final != end_offset, do: {:error, :final_size_error}

  defp consistent_final(%Stream{recv_final: final}, end_offset, _fin) when end_offset > final,
    do: {:error, :final_size_error}

  defp consistent_final(_, _, _), do: :ok

  defp insert_chunk(stream, _offset, <<>>), do: {:ok, stream}

  defp insert_chunk(stream, offset, data) do
    case Map.get(stream.recv_chunks, offset) do
      ^data ->
        {:ok, stream}

      existing when is_binary(existing) ->
        {:error, :overlap_conflict}

      nil ->
        case Enum.find(stream.recv_chunks, fn {at, old} ->
               overlap_conflict?(offset, data, at, old)
             end) do
          nil ->
            {:ok,
             %{
               stream
               | recv_chunks: Map.put(stream.recv_chunks, offset, data),
                 recv_buffered: stream.recv_buffered + byte_size(data)
             }}

          _ ->
            {:error, :overlap_conflict}
        end
    end
  end

  defp overlap_conflict?(a, bytes, b, old) do
    left = max(a, b)
    right = min(a + byte_size(bytes), b + byte_size(old))

    right > left and
      binary_part(bytes, left - a, right - left) != binary_part(old, left - b, right - left)
  end

  defp consume(stream, id), do: consume(stream, id, [])

  defp consume(stream, id, events) do
    case Map.pop(stream.recv_chunks, stream.recv_next) do
      {nil, _} ->
        if is_integer(stream.recv_final) and stream.recv_next == stream.recv_final and
             stream.reset == nil,
           do: {:ok, stream, Enum.reverse([{:fin, id} | events])},
           else: {:ok, stream, Enum.reverse(events)}

      {data, chunks} ->
        next = %{
          stream
          | recv_chunks: chunks,
            recv_next: stream.recv_next + byte_size(data),
            recv_buffered: stream.recv_buffered - byte_size(data)
        }

        consume(next, id, [{:data, id, data} | events])
    end
  end

  defp reset_final(%Stream{recv_final: nil}, _), do: :ok
  defp reset_final(%Stream{recv_final: final}, final), do: :ok
  defp reset_final(_, _), do: {:error, :final_size_error}

  defp emitted_bytes(events),
    do:
      Enum.reduce(events, 0, fn
        {:data, _, bytes}, acc -> acc + byte_size(bytes)
        _, acc -> acc
      end)

  defp role_bit(:client), do: 0
  defp role_bit(:server), do: 1
  defp blocked_frame(:bidi, count), do: %{type: :streams_blocked_bidi, value: count}
  defp blocked_frame(:uni, count), do: %{type: :streams_blocked_uni, value: count}
  defp positive(opts, key, default), do: max(1, Keyword.get(opts, key, default))
  defp nonnegative(opts, key, default), do: max(0, Keyword.get(opts, key, default))
end
