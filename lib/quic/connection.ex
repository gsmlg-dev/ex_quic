defmodule QUIC.Connection do
  @moduledoc """
  Temporary serialized handshake runtime using an externally owned IO capability.

  The endpoint owner calls `deliver/4` synchronously after routing a datagram.
  Only that owner may deliver; it must acquire receive credit before forwarding.
  A connection never closes the shared socket. The IO capability's `send/3`
  must return a local completion timestamp or a bounded failure.

  This is an internal runtime seam, not a network-handshake readiness claim.
  Independent interoperability and full protocol lifecycle coverage are still
  required before exposing a complete endpoint API.
  """
  @behaviour :gen_statem
  alias QUIC.{HandshakeScheduler, TLSDriver, TransportParameters, Recovery}
  alias QUIC.IO.Endpoint

  def start_link(opts) do
    :gen_statem.start_link(__MODULE__, Keyword.put_new(opts, :owner, self()), [])
  end

  def start(opts), do: :gen_statem.start(__MODULE__, Keyword.put_new(opts, :owner, self()), [])

  def child_spec(opts),
    do: %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}, restart: :temporary}

  def status(pid), do: :gen_statem.call(pid, :status)
  def close(pid), do: :gen_statem.call(pid, :close)

  def deliver(pid, generation, bytes, received_at),
    do: :gen_statem.call(pid, {:datagram, generation, bytes, received_at})

  @impl true
  def callback_mode, do: :handle_event_function

  @impl true
  def init(opts) do
    role = Keyword.fetch!(opts, :role)
    {adapter, writer} = Keyword.fetch!(opts, :io)
    timeout = Keyword.get(opts, :handshake_timeout, 10_000)
    owner = Keyword.fetch!(opts, :owner)

    if role in [:client, :server] and is_pid(writer) and is_pid(owner) and
         is_integer(timeout) and timeout > 0 do
      with {:ok, budget} <- Endpoint.new(Keyword.get(opts, :limits, [])) do
        # Clients are not subject to the server's pre-validation amplification limit.
        budget = if role == :client, do: %{budget | address_validated: true}, else: budget
        generation = make_ref()

        data = %{
          role: role,
          adapter: adapter,
          writer: writer,
          owner: owner,
          writer_monitor: Process.monitor(writer),
          owner_monitor: Process.monitor(owner),
          remote: Keyword.fetch!(opts, :remote),
          scheduler_opts: Keyword.fetch!(opts, :scheduler),
          scheduler: nil,
          budget: budget,
          pending: [],
          ready: false,
          parameters_valid: false,
          generation: generation,
          deadline: adapter.monotonic_time() + timeout * 1000,
          reason: :closed
        }

        {:ok, :handshaking, data,
         [{:next_event, :internal, :start}, {{:timeout, :handshake}, timeout, generation}]}
      else
        {:error, reason} -> {:stop, reason}
      end
    else
      {:stop, :invalid_connection_options}
    end
  end

  @impl true
  def handle_event(:internal, :start, :handshaking, data) do
    case HandshakeScheduler.new(data.role, data.scheduler_opts) do
      {:ok, scheduler, effects} ->
        advance(%{data | scheduler: scheduler}, effects, [])

      {:error, reason} ->
        stop(data, {:initialization, reason})

      {:error, reason, scheduler} ->
        stop(%{data | scheduler: scheduler}, {:initialization, reason})
    end
  end

  def handle_event({:call, from}, :status, phase, data) do
    packets =
      Map.new(data.scheduler.recovery.spaces, fn {space, state} ->
        counts = Enum.frequencies_by(Map.values(state.sent), & &1.status)
        {space, Map.merge(%{sent: 0, acked: 0, queued: 0, failed: 0}, counts)}
      end)

    status = %{
      phase: phase,
      cipher_suite: TLSDriver.info(data.scheduler.tls)[:cipher_suite],
      alpn: TLSDriver.info(data.scheduler.tls)[:alpn],
      tls_complete: data.scheduler.tls.facts.tls_complete,
      parameters_valid: data.parameters_valid,
      quic_confirmed: data.scheduler.tls.facts.quic_confirmed,
      peer_authenticated: data.scheduler.tls.facts.peer_authenticated,
      generation: data.generation,
      packets: packets,
      pending_datagrams: length(data.pending),
      bytes_sent: data.budget.bytes_sent,
      bytes_received: data.budget.bytes_received,
      address_validated: data.scheduler.tls.facts.address_validated
    }

    {:keep_state_and_data, [{:reply, from, status}]}
  end

  def handle_event({:call, from}, :close, _phase, data),
    do: {:stop_and_reply, :normal, [{:reply, from, :ok}], %{data | reason: :closed}}

  def handle_event(
        {:call, {caller, _} = from},
        {:datagram, generation, bytes, at},
        phase,
        data
      )
      when phase in [:handshaking, :established] do
    cond do
      caller != data.owner ->
        reply(from, {:error, :not_owner})

      generation != data.generation ->
        reply(from, {:error, :stale_generation})

      not is_binary(bytes) or not is_integer(at) or byte_size(bytes) > 65_527 ->
        reply(from, {:error, :invalid_datagram})

      data.role == :server and initial_packet?(bytes) and byte_size(bytes) < 1200 ->
        reply(from, {:error, :undersized_unvalidated_datagram})

      expired?(data) ->
        {:stop_and_reply, :normal, [{:reply, from, {:error, :handshake_timeout}}],
         %{data | reason: :handshake_timeout}}

      true ->
        receive_packet(data, bytes, at, from)
    end
  end

  def handle_event(
        {:timeout, :handshake},
        generation,
        :handshaking,
        %{generation: generation} = data
      ),
      do: stop(data, :handshake_timeout)

  def handle_event({:timeout, :recovery}, {generation, token}, _phase, data) do
    recovery = data.scheduler.recovery
    now = data.adapter.monotonic_time()

    if generation == data.generation and Recovery.timer_expired?(recovery, token, now) do
      {:ok, recovery, result} = Recovery.on_time(recovery, now)
      scheduler = %{data.scheduler | recovery: recovery}

      case retry_packets(scheduler, result.lost ++ result.probes, []) do
        {:ok, scheduler, effects} -> advance(%{data | scheduler: scheduler}, effects, [])
        {:error, reason} -> stop(data, {:recovery, reason})
      end
    else
      :keep_state_and_data
    end
  end

  def handle_event(:info, {:DOWN, ref, :process, _pid, reason}, _phase, data) do
    cond do
      ref == data.writer_monitor -> stop(data, {:writer_down, reason})
      ref == data.owner_monitor -> stop(data, :owner_down)
      true -> :keep_state_and_data
    end
  end

  def handle_event(_, _, _, _), do: :keep_state_and_data

  defp receive_packet(data, bytes, at, from) do
    case HandshakeScheduler.receive_datagram(data.scheduler, bytes, at) do
      {:ok, scheduler, events} ->
        {:ok, budget} = Endpoint.receive_bytes(data.budget, byte_size(bytes))

        {scheduler, budget} =
          if data.role == :server and handshake_packet?(bytes) do
            {:ok, validated} = Endpoint.validate_address(budget)
            {%{scheduler | tls: TLSDriver.mark_address_validated(scheduler.tls)}, validated}
          else
            {scheduler, budget}
          end

        pending =
          if Enum.any?(events, &(&1.type == :retry)),
            do: Enum.reject(data.pending, &(&1.level == :initial)),
            else: data.pending

        data = %{data | scheduler: scheduler, budget: budget, pending: pending}
        effects = Enum.flat_map(events, &Map.get(&1, :generated, []))

        if Enum.any?(events, &(&1.type in [:connection_close, :application_close])) do
          {:stop_and_reply, :normal, [{:reply, from, :ok}], %{data | reason: :peer_closed}}
        else
          case readiness(data) do
            {:ok, data, extra} ->
              lost =
                Enum.flat_map(events, fn
                  %{type: :ack, result: %{lost: lost}} -> lost
                  _ -> []
                end)

              with {:ok, scheduler, retries} <- retry_packets(data.scheduler, lost, []),
                   {:ok, scheduler, acks} <- HandshakeScheduler.schedule(scheduler) do
                advance(%{data | scheduler: scheduler}, effects ++ extra ++ retries ++ acks, [
                  {:reply, from, :ok}
                ])
              else
                {:error, reason} ->
                  stop_with_replies(data, reason, [{:reply, from, {:error, reason}}])

                {:error, reason, scheduler} ->
                  stop_with_replies(%{data | scheduler: scheduler}, reason, [
                    {:reply, from, {:error, reason}}
                  ])
              end

            {:error, reason} ->
              {:stop_and_reply, :normal, [{:reply, from, {:error, reason}}],
               %{data | reason: reason}}
          end
        end

      {:error, %SSL.QUIC.Error{} = error, _scheduler} ->
        reason = {:tls, error.kind, error.alert, error.reason}
        {:stop_and_reply, :normal, [{:reply, from, {:error, reason}}], %{data | reason: reason}}

      {:error, reason, _scheduler} ->
        reply(from, {:error, reason})
    end
  end

  defp readiness(%{ready: true} = data), do: {:ok, data, []}

  defp readiness(data) do
    facts = data.scheduler.tls.facts

    if facts.tls_complete do
      scheduler = data.scheduler
      peer_role = if data.role == :client, do: :server, else: :client

      with true <- facts.peer_parameters_authenticated,
           true <- data.role == :server or facts.peer_authenticated,
           true <- is_binary(scheduler.peer_initial_scid),
           {:ok, parameters} <- TransportParameters.decode(facts.peer_transport_parameters),
           :ok <-
             TransportParameters.validate(parameters,
               role: peer_role,
               initial_source_connection_id: scheduler.peer_initial_scid,
               retry_source_connection_id: scheduler.retry_scid,
               original_destination_connection_id:
                 if(peer_role == :server, do: scheduler.original_dcid)
             ) do
        if data.role == :server do
          case HandshakeScheduler.handshake_done(scheduler) do
            {:ok, scheduler, effects} ->
              scheduler = %{scheduler | tls: TLSDriver.mark_quic_confirmed(scheduler.tls)}
              {:ok, %{data | scheduler: scheduler, ready: true, parameters_valid: true}, effects}

            {:error, reason, _} ->
              {:error, reason}

            {:error, reason} ->
              {:error, reason}
          end
        else
          {:ok, %{data | ready: true, parameters_valid: true}, []}
        end
      else
        false -> {:error, :incomplete_authentication}
        {:error, reason} -> {:error, {:transport_parameters, reason}}
      end
    else
      {:ok, data, []}
    end
  end

  defp advance(data, effects, replies) do
    pending = data.pending ++ effects

    cond do
      length(pending) > data.budget.max_queue ->
        stop_with_replies(data, :send_queue_limit, replies)

      Enum.reduce(pending, 0, &(byte_size(&1.bytes) + &2)) > data.budget.max_queue_bytes ->
        stop_with_replies(data, :send_queue_bytes_limit, replies)

      true ->
        case flush(%{data | pending: pending}) do
          {:ok, %{ready: true} = data} ->
            {:next_state, :established, data,
             replies ++ [{{:timeout, :handshake}, :cancel}] ++ recovery_timer(data)}

          {:ok, data} ->
            {:keep_state, data, replies ++ recovery_timer(data)}

          {:error, reason, data} ->
            stop_with_replies(data, reason, replies)
        end
    end
  end

  defp flush(%{pending: []} = data), do: {:ok, data}

  defp flush(%{pending: [effect | rest]} = data) do
    if expired?(data) do
      {:error, :handshake_timeout, data}
    else
      case Endpoint.enqueue(data.budget, effect.bytes, data.remote, data.adapter.monotonic_time()) do
        {:error, :anti_amplification} ->
          {:ok, data}

        {:error, reason} ->
          {:error, reason, data}

        {:ok, budget, send} ->
          {:ok, budget, ^send} = Endpoint.dequeue(budget)
          {result, at} = local_send(data, effect.bytes)
          {:ok, budget, _receipt} = Endpoint.local_send(budget, send, result, at)

          case HandshakeScheduler.local_send(
                 data.scheduler,
                 effect.space,
                 effect.packet_number,
                 result,
                 at
               ) do
            {:ok, scheduler, _statuses} ->
              next = %{data | scheduler: scheduler, budget: budget, pending: rest}

              case result do
                :ok -> flush(next)
                {:error, reason} -> {:error, {:local_send, reason}, next}
              end

            {:error, reason} ->
              {:error, {:send_accounting, reason}, data}
          end
      end
    end
  end

  defp recovery_timer(data) do
    recovery = data.scheduler.recovery

    case recovery.deadline do
      nil ->
        [{{:timeout, :recovery}, :cancel}]

      deadline ->
        delay = max(0, div(deadline - data.adapter.monotonic_time() + 999, 1000))
        [{{:timeout, :recovery}, delay, {data.generation, recovery.timer_generation}}]
    end
  end

  defp retry_packets(scheduler, [], effects), do: {:ok, scheduler, effects}

  defp retry_packets(scheduler, [{space, number} | rest], effects) do
    case HandshakeScheduler.retry_crypto(scheduler, space, number) do
      {:ok, next, sends} -> retry_packets(next, rest, effects ++ sends)
      {:error, :not_retransmittable} -> retry_packets(scheduler, rest, effects)
      {:error, reason} -> {:error, reason}
      {:error, reason, _} -> {:error, reason}
    end
  end

  defp local_send(data, bytes) do
    case data.adapter.send(data.writer, bytes, data.remote) do
      {:ok, at} when is_integer(at) -> {:ok, at}
      {:error, reason} -> {{:error, reason}, data.adapter.monotonic_time()}
    end
  catch
    :exit, _ -> {{:error, :writer_unavailable}, data.adapter.monotonic_time()}
  end

  defp initial_packet?(<<first, _::binary>>), do: Bitwise.band(first, 0xF0) == 0xC0
  defp initial_packet?(_), do: false
  defp handshake_packet?(<<first, _::binary>>), do: Bitwise.band(first, 0xF0) == 0xE0
  defp handshake_packet?(_), do: false

  defp expired?(data), do: not data.ready and data.adapter.monotonic_time() >= data.deadline
  defp reply(from, result), do: {:keep_state_and_data, [{:reply, from, result}]}
  defp stop(data, reason), do: {:stop, :normal, %{data | reason: reason}}
  defp stop_with_replies(data, reason, []), do: stop(data, reason)

  defp stop_with_replies(data, reason, replies),
    do: {:stop_and_reply, :normal, replies, %{data | reason: reason}}

  @impl true
  def terminate(_reason, _phase, data) do
    if data.scheduler, do: TLSDriver.abort(data.scheduler.tls, data.reason)
    send(data.owner, {:quic_closed, self(), data.generation, data.reason})
    :ok
  end
end
