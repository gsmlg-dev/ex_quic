defmodule QUIC.Phase1MetricsTest do
  use ExUnit.Case, async: true

  alias QUIC.Endpoint

  test "public high-water marks persist after event and operation queues drain" do
    {server_tls, client_tls} = credentials()
    {:ok, server} = QUIC.listen(tls: server_tls)
    {:ok, client} = QUIC.client(tls: client_tls)
    on_exit(fn -> for pid <- [server, client], Process.alive?(pid), do: GenServer.stop(pid) end)

    {:ok, connection} = QUIC.connect(client, Endpoint.local(server))
    :ok = QUIC.attach(connection, self())
    assert_receive {:quic_ready, ^connection, _}, 2_000
    assert_receive {:quic_accept, ^server}, 2_000
    {:ok, accepted} = QUIC.accept(server)
    :ok = QUIC.attach(accepted, self())
    assert_receive {:quic_ready, ^accepted, _}, 1_000
    {:ok, _} = QUIC.events(accepted)

    {:ok, stream} = QUIC.open_stream(connection, :bidi)
    {:ok, _} = QUIC.send_stream(stream, "metrics", true)

    assert eventually(fn ->
             match?(
               {:ok, %{resources: %{event_count: count}}} when count > 0,
               QUIC.info(accepted)
             )
           end)

    {:ok, _} = QUIC.events(accepted)

    {:ok, info} = QUIC.info(accepted)
    assert info.resources.event_count == 0
    assert info.highwaters.event_count > 0
    assert info.highwaters.in_flight_sends == 1
    assert info.highwaters.io_queue_entries == 1
    assert info.highwaters.operations >= info.resources.operations
    assert info.highwaters.pending_datagrams >= info.resources.pending_datagrams
    assert info.highwaters.recovery_packets >= info.resources.recovery_packets
  end

  defp credentials do
    fixture = Path.expand("../../deps/ex_ssl/test/fixtures/server_flight", __DIR__)

    cert = fn name ->
      [{:Certificate, der, :not_encrypted}] =
        :public_key.pem_decode(File.read!(Path.join(fixture, name)))

      der
    end

    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf-key.pem")))

    {[cert: [cert.("leaf.pem")], key: {type, key}, alpn: ["ex-quic-phase1"]],
     [
       cacerts: [cert.("root.pem")],
       reference_identity: {:dns_id, "example.test"},
       alpn: ["ex-quic-phase1"]
     ]}
  end

  defp eventually(fun, n \\ 200)
  defp eventually(_, 0), do: false

  defp eventually(fun, n),
    do:
      if(fun.(),
        do: true,
        else:
          (
            Process.sleep(5)
            eventually(fun, n - 1)
          )
      )
end
