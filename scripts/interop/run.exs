# Run with: mix run scripts/interop/run.exs client|server [output-directory]
defmodule QUIC.Interop.Run do
  alias QUIC.{Endpoint, Connection}

  def run(mode, directory) do
    scenario = System.get_env("INTEROP_SCENARIO", "baseline")
    unless scenario in ["baseline", "retry"], do: raise("unsupported scenario")
    if scenario == "retry" and mode != "client", do: raise("server Retry not yet implemented")
    File.mkdir_p!(directory)
    fixture = Path.expand("deps/ex_ssl/test/fixtures/server_flight")

    der = fn name ->
      [{:Certificate, bytes, :not_encrypted}] =
        :public_key.pem_decode(File.read!(Path.join(fixture, name)))

      bytes
    end

    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf-key.pem")))

    client_tls = [
      cacerts: [der.("root.pem")],
      reference_identity: {:dns_id, "example.test"},
      alpn: ["ex-quic-test"]
    ]

    server_tls = [cert: [der.("leaf.pem")], key: {type, key}, alpn: ["ex-quic-test"]]

    endpoint =
      if mode == "server" do
        {:ok, endpoint} = Endpoint.start_link(role: :server, tls: server_tls)
        endpoint
      end

    port = if endpoint, do: elem(Endpoint.local(endpoint), 1), else: 0
    peer_mode = if mode == "client", do: "server", else: "client"

    args = [
      "run",
      "--python",
      "3.12",
      "--with",
      "aioquic==1.2.0",
      "python",
      "scripts/interop/peer.py",
      "--mode",
      peer_mode,
      "--port",
      Integer.to_string(port),
      "--cert",
      Path.join(fixture, "leaf.pem"),
      "--key",
      Path.join(fixture, "leaf-key.pem"),
      "--ca",
      Path.join(fixture, "root.pem"),
      "--capture",
      Path.join(directory, "udp.jsonl")
    ]

    args = if scenario == "retry", do: args ++ ["--retry"], else: args

    peer =
      Port.open(
        {:spawn_executable, System.find_executable("uv")},
        [:binary, :exit_status, :use_stdio, :stderr_to_stdout, {:line, 65_536}, {:args, args}]
      )

    deadline = System.monotonic_time(:millisecond) + 12_000

    {endpoint, messages} =
      if endpoint, do: {endpoint, []}, else: start_client(peer, client_tls, deadline, [])

    result = await(peer, endpoint, mode, deadline, messages, false)
    observed_retry = Enum.any?(result.events, &match?(%{"event" => "retry"}, &1))

    result =
      Map.merge(result, %{
        scenario: scenario,
        passed: result.passed and (scenario != "retry" or observed_retry)
      })

    File.write!(Path.join(directory, "result.json"), JSON.encode!(result))
    IO.puts(JSON.encode!(result))
    if Port.info(peer), do: Port.command(peer, "stop\n")
    GenServer.stop(endpoint)
    if result.passed, do: :ok, else: System.halt(1)
  end

  defp start_client(peer, tls, deadline, messages) do
    if System.monotonic_time(:millisecond) >= deadline, do: raise("peer startup timed out")

    receive do
      {^peer, {:data, {:eol, line}}} ->
        case JSON.decode(line) do
          {:ok, %{"event" => "listening", "port" => port} = message} ->
            {:ok, endpoint} =
              Endpoint.start_link(role: :client, remote: {{127, 0, 0, 1}, port}, tls: tls)

            {endpoint, messages ++ [message]}

          {:ok, message} ->
            start_client(peer, tls, deadline, messages ++ [message])

          _ ->
            start_client(peer, tls, deadline, messages ++ [line])
        end

      {^peer, {:exit_status, code}} ->
        raise("peer exited: #{code}")
    after
      100 -> start_client(peer, tls, deadline, messages)
    end
  end

  defp await(peer, endpoint, mode, deadline, messages, peer_complete) do
    error = Endpoint.stats(endpoint).last_error
    local_error = %{"local_error" => inspect(error)}

    messages =
      if error != nil and local_error not in messages,
        do: messages ++ [local_error],
        else: messages

    states = Enum.map(Endpoint.connections(endpoint), &Connection.status(&1.pid))
    local_complete = Enum.any?(states, &(&1.phase == :established and &1.quic_confirmed))

    if (local_complete and peer_complete) or System.monotonic_time(:millisecond) >= deadline do
      %{
        passed: local_complete and peer_complete,
        role: mode,
        peer: "aioquic 1.2.0",
        runtime: %{elixir: System.version(), otp: to_string(:erlang.system_info(:otp_release))},
        endpoint: sanitize(Endpoint.stats(endpoint)),
        connections: Enum.map(states, &sanitize/1),
        events: messages
      }
    else
      receive do
        {^peer, {:data, {:eol, line}}} ->
          message =
            case JSON.decode(line) do
              {:ok, message} -> message
              _ -> line
            end

          complete = peer_complete or match?(%{"event" => "handshake_complete"}, message)
          await(peer, endpoint, mode, deadline, messages ++ [message], complete)

        {^peer, {:exit_status, code}} ->
          await(peer, endpoint, mode, 0, messages ++ [%{exit_status: code}], peer_complete)
      after
        20 -> await(peer, endpoint, mode, deadline, messages, peer_complete)
      end
    end
  end

  defp sanitize(map),
    do:
      Map.new(map, fn
        {:generation, _} -> {:generation, "redacted"}
        {key, value} when is_tuple(value) -> {key, inspect(value)}
        entry -> entry
      end)
end

case System.argv() do
  [mode | rest] when mode in ["client", "server"] ->
    QUIC.Interop.Run.run(mode, List.first(rest) || "_build/interop/#{mode}")

  _ ->
    raise("usage: mix run scripts/interop/run.exs client|server [output-directory]")
end
