defmodule QUIC.Endpoint do
  @moduledoc """
  Bounded standalone UDP endpoint with persistent connection routing.

  A server owns one shared socket; connections only borrow its send capability.
  Reception has one outstanding credit and is rearmed after synchronous routing.
  Current paths remain bound to the original peer address; migration is not yet
  exposed. This internal endpoint is not an independent interoperability claim.
  """
  use GenServer
  alias QUIC.{Codec, Connection, TransportParameters, Retry, Protection}
  alias QUIC.IO.GenUDP

  @cid_length 8
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)
  def local(pid), do: GenServer.call(pid, :local)
  def connections(pid), do: GenServer.call(pid, :connections)
  def stats(pid), do: GenServer.call(pid, :stats)

  @impl true
  def init(opts) do
    role = Keyword.fetch!(opts, :role)
    max = Keyword.get(opts, :max_connections, 128)

    retry = Keyword.get(opts, :retry, false)
    retry_limit = Keyword.get(opts, :retry_limit, 100)
    retry_ttl = Keyword.get(opts, :retry_ttl, 5_000_000)

    if role in [:client, :server] and is_integer(max) and max > 0 and
         is_boolean(retry) and (not retry or role == :server) and
         is_integer(retry_limit) and retry_limit in 1..10_000 and
         is_integer(retry_ttl) and retry_ttl in 1..60_000_000 do
      with {:ok, socket} <-
             GenUDP.open(Keyword.take(opts, [:ip, :port]) ++ [owner: self(), role: role]) do
        data = %{
          role: role,
          retry: retry,
          retry_key: if(retry, do: :crypto.strong_rand_bytes(32)),
          retry_limit: retry_limit,
          retry_ttl: retry_ttl,
          retry_window: GenUDP.monotonic_time(),
          retry_count: 0,
          retry_sent: 0,
          retry_validated: 0,
          socket: socket,
          monitor: Process.monitor(socket),
          opts: opts,
          max: max,
          routes: %{},
          provisional: %{},
          connections: %{},
          admission_drops: 0,
          last_error: nil
        }

        if role == :server do
          {:ok, data}
        else
          case admit(
                 data,
                 Keyword.fetch!(opts, :remote),
                 :crypto.strong_rand_bytes(@cid_length),
                 nil
               ) do
            {:ok, data, _entry} ->
              {:ok, data}

            {:error, reason} ->
              GenUDP.close(socket)
              {:stop, reason}
          end
        end
      end
    else
      {:stop, :invalid_endpoint_options}
    end
  end

  @impl true
  def handle_call(:local, _from, data), do: {:reply, GenUDP.local(data.socket), data}

  def handle_call(:connections, _from, data) do
    entries =
      Enum.map(data.connections, fn {pid, entry} -> %{pid: pid, generation: entry.generation} end)

    {:reply, entries, data}
  end

  def handle_call(:stats, _from, data),
    do:
      {:reply,
       %{
         routes: map_size(data.routes) + map_size(data.provisional),
         admission_drops: data.admission_drops,
         retry_sent: data.retry_sent,
         retry_validated: data.retry_validated,
         last_error: data.last_error
       }, data}

  @impl true
  def handle_info({:quic_udp, generation, credit, remote, bytes, at}, data) do
    next = route(data, remote, bytes, at)

    case GenUDP.consumed(data.socket, generation, credit) do
      :ok -> {:noreply, next}
      {:error, reason} -> {:stop, {:socket_receive, reason}, next}
    end
  end

  def handle_info({:quic_closed, pid, generation, reason}, data) do
    case data.connections[pid] do
      %{generation: ^generation} -> {:noreply, remove(%{data | last_error: reason}, pid)}
      _ -> {:noreply, data}
    end
  end

  def handle_info({:DOWN, monitor, :process, pid, _reason}, data) do
    if monitor == data.monitor do
      {:stop, :normal, data}
    else
      case data.connections[pid] do
        %{monitor: ^monitor} -> {:noreply, remove(data, pid)}
        _ -> {:noreply, data}
      end
    end
  end

  def handle_info({:quic_udp_error, _, _}, data), do: {:stop, :normal, data}
  def handle_info(_, data), do: {:noreply, data}

  defp route(data, remote, bytes, at) do
    with {:ok, dcid} <- destination(bytes) do
      pid = Map.get(data.routes, dcid) || Map.get(data.provisional, {remote, dcid})

      case data.connections[pid] do
        %{remote: ^remote} = entry -> deliver(data, entry, bytes, at)
        nil -> maybe_admit(data, remote, bytes, at)
        _ -> data
      end
    else
      _ -> data
    end
  end

  defp maybe_admit(%{role: :server} = data, remote, bytes, at) when byte_size(bytes) >= 1200 do
    with {:ok, initial} <- Codec.parse_initial(bytes),
         true <- byte_size(initial.dcid) >= 8 do
      if map_size(data.connections) >= data.max do
        %{data | admission_drops: data.admission_drops + 1}
      else
        admit_initial(data, remote, initial, bytes, at)
      end
    else
      _ -> data
    end
  end

  defp maybe_admit(data, _, _, _), do: data

  defp admit_initial(%{retry: true} = data, remote, %{token: <<>>} = initial, _bytes, at) do
    now = GenUDP.monotonic_time()

    data =
      if now - data.retry_window >= 1_000_000,
        do: %{data | retry_window: now, retry_count: 0},
        else: data

    if data.retry_count >= data.retry_limit do
      %{data | admission_drops: data.admission_drops + 1}
    else
      scid = :crypto.strong_rand_bytes(@cid_length)
      token = Retry.issue(data.retry_key, remote, initial.dcid, scid, at)

      body =
        <<0xF0, 1::32, byte_size(initial.scid), initial.scid::binary, byte_size(scid),
          scid::binary, token::binary>>

      {:ok, tag} = Protection.retry_tag(initial.dcid, body)
      data = %{data | retry_count: data.retry_count + 1}

      case GenUDP.send(data.socket, body <> tag, remote) do
        {:ok, _sent_at} -> %{data | retry_sent: data.retry_sent + 1}
        {:error, reason} -> %{data | last_error: {:retry_send, reason}}
      end
    end
  end

  defp admit_initial(%{retry: true} = data, remote, initial, bytes, at) do
    with {:ok, original} <-
           Retry.verify(
             data.retry_key,
             remote,
             initial.dcid,
             initial.token,
             GenUDP.monotonic_time(),
             data.retry_ttl
           ),
         {:ok, next, entry} <- admit(data, remote, original, initial.scid, initial.dcid) do
      deliver(%{next | retry_validated: next.retry_validated + 1}, entry, bytes, at)
    else
      {:error, _} -> %{data | admission_drops: data.admission_drops + 1}
    end
  end

  defp admit_initial(data, remote, initial, bytes, at) do
    case admit(data, remote, initial.dcid, initial.scid) do
      {:ok, next, entry} -> deliver(next, entry, bytes, at)
      {:error, _} -> %{data | admission_drops: data.admission_drops + 1}
    end
  end

  defp admit(data, remote, original_dcid, peer_scid, retry_scid \\ nil) do
    scid = :crypto.strong_rand_bytes(@cid_length)
    dcid = peer_scid || original_dcid

    with false <- Map.has_key?(data.routes, scid),
         {:ok, tls} <-
           materialize(
             Keyword.get(data.opts, :tls, []),
             data.role,
             original_dcid,
             scid,
             retry_scid
           ),
         opts <- [
           role: data.role,
           address_validated: retry_scid != nil,
           owner: self(),
           io: {GenUDP, data.socket},
           remote: remote,
           handshake_timeout: Keyword.get(data.opts, :handshake_timeout, 10_000),
           scheduler:
             [
               dcid: dcid,
               scid: scid,
               original_dcid: original_dcid,
               initial_key_dcid: retry_scid || original_dcid,
               retry_scid: retry_scid
             ] ++ tls
         ],
         {:ok, pid} <- Connection.start(opts),
         {:ok, generation} <- generation(pid) do
      entry = %{pid: pid, remote: remote, generation: generation, monitor: Process.monitor(pid)}

      data = %{
        data
        | connections: Map.put(data.connections, pid, entry),
          routes: Map.put(data.routes, scid, pid)
      }

      data =
        if data.role == :server,
          do: %{
            data
            | provisional: Map.put(data.provisional, {remote, retry_scid || original_dcid}, pid)
          },
          else: data

      {:ok, data, entry}
    else
      true -> {:error, :cid_collision}
      {:error, _} = error -> error
    end
  end

  defp generation(pid) do
    {:ok, Connection.status(pid).generation}
  catch
    :exit, _ -> {:error, :connection_start_failed}
  end

  defp materialize(tls, role, original, scid, retry_scid) do
    entries = [%{id: 0x0F, value: scid}]
    entries = if role == :server, do: [%{id: 0, value: original} | entries], else: entries

    entries = if retry_scid, do: [%{id: 0x10, value: retry_scid} | entries], else: entries

    with {:ok, generated} <- TransportParameters.encode(entries, role: role),
         raw <- Keyword.get(tls, :transport_parameters, generated),
         {:ok, decoded} <- TransportParameters.decode(raw),
         :ok <-
           TransportParameters.validate(decoded,
             role: role,
             initial_source_connection_id: scid,
             retry_source_connection_id: retry_scid,
             original_destination_connection_id: if(role == :server, do: original)
           ) do
      {:ok, Keyword.put(tls, :transport_parameters, raw)}
    end
  end

  defp deliver(data, entry, bytes, at) do
    case Connection.deliver(entry.pid, entry.generation, bytes, at) do
      :ok -> data
      {:error, reason} -> %{data | last_error: reason}
    end
  catch
    :exit, _ -> remove(data, entry.pid)
  end

  defp remove(data, pid) do
    case data.connections[pid] do
      %{monitor: monitor} -> Process.demonitor(monitor, [:flush])
      _ -> :ok
    end

    %{
      data
      | connections: Map.delete(data.connections, pid),
        routes: Map.reject(data.routes, fn {_, target} -> target == pid end),
        provisional: Map.reject(data.provisional, fn {_, target} -> target == pid end)
    }
  end

  defp destination(<<first, _version::32, length, rest::binary>>)
       when Bitwise.band(first, 0x80) != 0 and length <= 20 and byte_size(rest) >= length,
       do: {:ok, binary_part(rest, 0, length)}

  defp destination(<<first, cid::binary-size(@cid_length), _::binary>>)
       when Bitwise.band(first, 0x80) == 0, do: {:ok, cid}

  defp destination(_), do: {:error, :malformed_header}

  @impl true
  def terminate(_, data) do
    Enum.each(data.connections, fn {pid, _} -> Process.exit(pid, :shutdown) end)
    if Process.alive?(data.socket), do: GenUDP.close(data.socket)
    :ok
  end
end
