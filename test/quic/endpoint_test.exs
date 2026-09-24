defmodule QUIC.EndpointTest do
  use ExUnit.Case, async: true
  alias QUIC.{Endpoint, Connection}

  defmodule RecordedTLS do
    def new(:client, _), do: {:ok, :client, [{:emit, :initial, <<1, 2>>}]}
    def new(:server, _), do: {:ok, :server, []}
    def info(_), do: %{receive_level: :initial}
    def feed(:server, :initial, <<1, 2>>), do: {:ok, :done, [{:emit, :initial, <<3, 4>>}]}
    def feed(:client, :initial, <<3, 4>>), do: {:ok, :done, []}
    def feed(state, _, _), do: {:ok, state, []}
    def abort(state, _), do: state
  end

  defmodule LossProxy do
    use GenServer
    def start_link(server, kind), do: GenServer.start_link(__MODULE__, {server, kind})

    def init({server, kind}) do
      {:ok, socket} = :gen_udp.open(0, [:binary, {:ip, {127, 0, 0, 1}}, {:active, :once}])
      {:ok, %{socket: socket, server: server, client: nil, kind: kind, dropped: false}}
    end

    def handle_call(:local, _, state) do
      {:ok, address} = :inet.sockname(state.socket)
      {:reply, address, state}
    end

    def handle_call(:dropped, _, state), do: {:reply, state.dropped, state}

    def handle_info({:udp, socket, ip, port, bytes}, state) do
      from_server = {ip, port} == state.server
      state = if from_server, do: state, else: %{state | client: {ip, port}}
      target = if from_server, do: state.client, else: state.server
      first = :binary.at(bytes, 0)

      drop =
        not state.dropped and
          ((state.kind == :initial and not from_server and Bitwise.band(first, 0xF0) == 0xC0) or
             (state.kind == :handshake and from_server and Bitwise.band(first, 0xF0) == 0xE0))

      if not drop and target, do: :gen_udp.send(socket, elem(target, 0), elem(target, 1), bytes)
      :inet.setopts(socket, active: :once)
      {:noreply, %{state | dropped: state.dropped or drop}}
    end

    def terminate(_, state), do: :gen_udp.close(state.socket)
  end

  test "shared socket admits persistent CID-routed connections and survives one closing" do
    {:ok, server} = Endpoint.start_link(role: :server, tls: [adapter: RecordedTLS])

    {:ok, first} =
      Endpoint.start_link(
        role: :client,
        remote: Endpoint.local(server),
        tls: [adapter: RecordedTLS]
      )

    {:ok, second} =
      Endpoint.start_link(
        role: :client,
        remote: Endpoint.local(server),
        tls: [adapter: RecordedTLS]
      )

    on_exit(fn -> Enum.each([first, second, server], &stop/1) end)
    assert eventually(fn -> length(Endpoint.connections(server)) == 2 end)

    assert eventually(fn ->
             [connection] = Endpoint.connections(first)
             Connection.status(connection.pid).bytes_received > 0
           end)

    [one, two] = Endpoint.connections(server)
    assert one.pid != two.pid
    :ok = Connection.close(one.pid)
    assert eventually(fn -> length(Endpoint.connections(server)) == 1 end)
    assert Process.alive?(two.pid)
    assert Process.alive?(server)
  end

  test "admission limit bounds connections and handshake timeout reclaims routes" do
    {:ok, server} =
      Endpoint.start_link(
        role: :server,
        max_connections: 1,
        handshake_timeout: 300,
        tls: [adapter: RecordedTLS]
      )

    {:ok, first} =
      Endpoint.start_link(
        role: :client,
        remote: Endpoint.local(server),
        tls: [adapter: RecordedTLS]
      )

    on_exit(fn -> Enum.each([first, server], &stop/1) end)
    assert eventually(fn -> length(Endpoint.connections(server)) == 1 end)

    {:ok, second} =
      Endpoint.start_link(
        role: :client,
        remote: Endpoint.local(server),
        tls: [adapter: RecordedTLS]
      )

    on_exit(fn -> stop(second) end)
    assert eventually(fn -> Endpoint.stats(server).admission_drops == 1 end)
    assert length(Endpoint.connections(server)) == 1
    assert eventually(fn -> Endpoint.connections(server) == [] end)
    assert Endpoint.stats(server).routes == 0
  end

  test "real certificate handshake crosses UDP in both roles" do
    {server_tls, client_tls} = certificate_options()
    {:ok, server} = Endpoint.start_link(role: :server, handshake_timeout: 2_000, tls: server_tls)

    {:ok, client} =
      Endpoint.start_link(
        role: :client,
        handshake_timeout: 2_000,
        remote: Endpoint.local(server),
        tls: client_tls
      )

    on_exit(fn -> Enum.each([client, server], &stop/1) end)

    passed =
      eventually(fn ->
        case {Endpoint.connections(client), Endpoint.connections(server)} do
          {[c], [s]} ->
            Connection.status(c.pid).phase == :established and
              Connection.status(s.pid).phase == :established and
              Map.get(Connection.status(c.pid), :quic_confirmed, false)

          _ ->
            false
        end
      end)

    assert passed,
           inspect(%{
             client: Endpoint.stats(client),
             server: Endpoint.stats(server),
             clients: Enum.map(Endpoint.connections(client), &Connection.status(&1.pid)),
             servers: Enum.map(Endpoint.connections(server), &Connection.status(&1.pid))
           })

    [c] = Endpoint.connections(client)
    [s] = Endpoint.connections(server)
    assert Connection.status(c.pid).parameters_valid
    assert Connection.status(s.pid).parameters_valid
    assert Connection.status(c.pid).peer_authenticated
    refute Connection.status(s.pid).peer_authenticated
    assert Connection.status(s.pid).address_validated
    Process.sleep(2_100)
    assert Connection.status(c.pid).phase == :established
    assert Connection.status(s.pid).phase == :established
    assert Connection.status(c.pid).packets.initial.acked >= 1
    assert Connection.status(c.pid).packets.handshake.acked >= 1
    assert Connection.status(s.pid).packets.application.acked >= 1
  end

  test "real UDP handshakes recover a dropped Initial and a dropped Handshake packet" do
    {server_tls, client_tls} = certificate_options()

    for kind <- [:initial, :handshake] do
      {:ok, server} = Endpoint.start_link(role: :server, tls: server_tls)
      {:ok, proxy} = LossProxy.start_link(Endpoint.local(server), kind)

      {:ok, client} =
        Endpoint.start_link(role: :client, remote: GenServer.call(proxy, :local), tls: client_tls)

      on_exit(fn -> Enum.each([client, proxy, server], &stop/1) end)

      passed =
        eventually(
          fn ->
            case {Endpoint.connections(client), Endpoint.connections(server)} do
              {[c], [s]} ->
                Connection.status(c.pid).quic_confirmed and
                  Connection.status(s.pid).quic_confirmed

              _ ->
                false
            end
          end,
          400
        )

      assert passed,
             inspect(%{
               dropped: kind,
               client: Endpoint.stats(client),
               server: Endpoint.stats(server)
             })

      assert GenServer.call(proxy, :dropped)
    end
  end

  test "wrong hostname and incompatible ALPN terminate with explicit TLS errors" do
    {server_tls, client_tls} = certificate_options()

    for {override, failing_role} <- [
          {[reference_identity: {:dns_id, "wrong.example.test"}], :client},
          {[alpn: ["incompatible"]], :server}
        ] do
      {:ok, server} = Endpoint.start_link(role: :server, tls: server_tls)

      {:ok, client} =
        Endpoint.start_link(
          role: :client,
          remote: Endpoint.local(server),
          tls: Keyword.merge(client_tls, override)
        )

      on_exit(fn -> Enum.each([client, server], &stop/1) end)
      failed_endpoint = if failing_role == :client, do: client, else: server

      assert eventually(fn ->
               match?({:tls, :tls, _, _}, Endpoint.stats(failed_endpoint).last_error)
             end)

      assert Endpoint.connections(failed_endpoint) == []
    end
  end

  defp certificate_options do
    # Public disposable credentials from the SHA-pinned ex_ssl test fixtures.
    fixture = Path.expand("../../deps/ex_ssl/test/fixtures/server_flight", __DIR__)

    der = fn name ->
      [{:Certificate, bytes, :not_encrypted}] =
        fixture |> Path.join(name) |> File.read!() |> :public_key.pem_decode()

      bytes
    end

    [{type, key, :not_encrypted}] =
      fixture |> Path.join("leaf-key.pem") |> File.read!() |> :public_key.pem_decode()

    {[cert: [der.("leaf.pem")], key: {type, key}, alpn: ["ex-quic-test"]],
     [
       cacerts: [der.("root.pem")],
       reference_identity: {:dns_id, "example.test"},
       alpn: ["ex-quic-test"]
     ]}
  end

  defp eventually(fun, attempts \\ 100)
  defp eventually(fun, 0), do: fun.()

  defp eventually(fun, attempts) do
    if fun.(),
      do: true,
      else:
        (
          Process.sleep(10)
          eventually(fun, attempts - 1)
        )
  end

  defp stop(pid), do: if(Process.alive?(pid), do: GenServer.stop(pid))
end
