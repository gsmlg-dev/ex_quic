abyss_root = System.fetch_env!("ABYSS_CHECKOUT")
ex_quic_root = Path.expand("../..", __DIR__)

for path <- Path.wildcard(Path.join(abyss_root, "_build/dev/lib/*/ebin")),
    do: Code.prepend_path(path)

Code.ensure_loaded!(QUIC.AbyssDispatcher)
{:ok, _} = Application.ensure_all_started(:telemetry)

defmodule QUIC.AbyssM5Handler do
  use Abyss.Handler

  @impl true
  def handle_data(_data, state), do: {:continue, state}
end

fixture = Path.join(ex_quic_root, "deps/ex_ssl/test/fixtures/server_flight")

der = fn name ->
  [{:Certificate, bytes, :not_encrypted}] =
    :public_key.pem_decode(File.read!(Path.join(fixture, name)))

  bytes
end

[{key_type, key, :not_encrypted}] =
  :public_key.pem_decode(File.read!(Path.join(fixture, "leaf-key.pem")))

server_tls = [cert: [der.("leaf.pem")], key: {key_type, key}, alpn: ["ex-quic-test"]]

client_tls = [
  cacerts: [der.("root.pem")],
  reference_identity: {:dns_id, "example.test"},
  alpn: ["ex-quic-test"]
]

{:ok, server} =
  Abyss.start_link(
    handler_module: QUIC.AbyssM5Handler,
    port: 0,
    num_listeners: 1,
    transport_options: [ip: {127, 0, 0, 1}],
    datagram_dispatcher: QUIC.AbyssDispatcher,
    dispatcher_options: [tls: server_tls]
  )

pool = Abyss.Server.listener_pool_pid(server)
[listener] = Abyss.ListenerPool.listener_pids(pool)
{:ok, address} = Abyss.Listener.listener_info_cached(listener)
{:ok, client} = QUIC.Endpoint.start_link(role: :client, remote: address, tls: client_tls)

deadline = System.monotonic_time(:millisecond) + 12_000

result =
  Stream.repeatedly(fn ->
    case QUIC.Endpoint.connections(client) do
      [%{pid: pid}] ->
        status = QUIC.Connection.status(pid)
        if status.phase == :established and status.quic_confirmed, do: :ok, else: :pending

      _ ->
        :pending
    end
  end)
  |> Enum.reduce_while(:pending, fn result, _acc ->
    cond do
      result == :ok ->
        {:halt, :ok}

      System.monotonic_time(:millisecond) >= deadline ->
        {:halt, {:error, QUIC.Endpoint.stats(client)}}

      true ->
        Process.sleep(20)
        {:cont, :pending}
    end
  end)

IO.inspect(%{result: result, address: address, client: QUIC.Endpoint.stats(client)},
  label: "M5_ABYSS_RESULT"
)

GenServer.stop(client)
Supervisor.stop(server)
if result == :ok, do: :ok, else: System.halt(1)
