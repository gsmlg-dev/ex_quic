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
{:ok, client_one} = QUIC.Endpoint.start_link(role: :client, remote: address, tls: client_tls)
{:ok, client_two} = QUIC.Endpoint.start_link(role: :client, remote: address, tls: client_tls)

deadline = System.monotonic_time(:millisecond) + 12_000

established? = fn endpoint ->
  case QUIC.Endpoint.connections(endpoint) do
    [%{pid: pid}] ->
      status = QUIC.Connection.status(pid)
      status.phase == :established and status.quic_confirmed

    _ ->
      false
  end
end

wait_until = fn wait_until, predicate, deadline ->
  cond do
    predicate.() ->
      :ok

    System.monotonic_time(:millisecond) >= deadline ->
      :timeout

    true ->
      Process.sleep(20)
      wait_until.(wait_until, predicate, deadline)
  end
end

first_pair =
  wait_until.(
    wait_until,
    fn -> established?.(client_one) and established?.(client_two) end,
    deadline
  )

if first_pair == :ok do
  [%{pid: first_pid}] = QUIC.Endpoint.connections(client_one)
  :ok = QUIC.Connection.close(first_pid)
end

second_survives = wait_until.(wait_until, fn -> established?.(client_two) end, deadline)

:ok = Abyss.suspend(server)
:ok = Abyss.resume(server)
pool = Abyss.Server.listener_pool_pid(server)
[restarted_listener] = Abyss.ListenerPool.listener_pids(pool)
{:ok, restarted_address} = Abyss.Listener.listener_info_cached(restarted_listener)

{:ok, client_three} =
  QUIC.Endpoint.start_link(role: :client, remote: restarted_address, tls: client_tls)

third_ready = wait_until.(wait_until, fn -> established?.(client_three) end, deadline)

result =
  if first_pair == :ok and second_survives == :ok and third_ready == :ok,
    do: :ok,
    else:
      {:error,
       %{first_pair: first_pair, second_survives: second_survives, third_ready: third_ready}}

IO.inspect(%{result: result, address: address, restarted_address: restarted_address},
  label: "M5_ABYSS_RESULT"
)

GenServer.stop(client_one)
GenServer.stop(client_two)
GenServer.stop(client_three)
Supervisor.stop(server)
if result == :ok, do: :ok, else: System.halt(1)
