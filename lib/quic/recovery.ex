defmodule QUIC.Recovery do
  @moduledoc """
  Explicit-time QUIC packet-number spaces and loss recovery state.

  Packet numbers are allocated by `reserve/4` and are never reused. A packet
  moves through `:reserved`, `:queued`, `:sent`, then `:acked`, `:lost`, or
  `:failed`. ACKs received before a local send receipt are retained as a bounded
  pending acknowledgement and resolved when the receipt arrives.
  """

  alias QUIC.Congestion.NewReno

  @spaces [:initial, :handshake, :application]
  @default_rtt 333_000
  defstruct spaces: %{},
            rtt: nil,
            congestion: nil,
            max_sent_packets: 4096,
            max_ack_ranges: 256,
            max_ack_span: 4096,
            timer_generation: 0,
            deadline: nil

  defmodule Packet do
    @moduledoc false
    defstruct [:number, :space, :status, :bytes, :sent_at, :metadata, :acked_at, :lost_at]
    @type t :: %__MODULE__{}
  end

  defmodule Space do
    @moduledoc false
    defstruct next: 0,
              largest_received: -1,
              largest_acked: -1,
              ack_ranges: [],
              sent: %{},
              pending_acks: MapSet.new()
  end

  defmodule RTT do
    @moduledoc false
    defstruct latest: nil,
              smoothed: nil,
              variance: nil,
              min: nil,
              max_ack_delay: 25_000,
              ack_delay_exponent: 3,
              pto_count: 0
  end

  @spec new(keyword()) :: t()
  def new(opts \\ []) do
    rtt = %RTT{
      max_ack_delay: Keyword.get(opts, :max_ack_delay, 25_000),
      ack_delay_exponent: Keyword.get(opts, :ack_delay_exponent, 3)
    }

    spaces = Map.new(@spaces, &{&1, %Space{}})

    %__MODULE__{
      spaces: spaces,
      rtt: rtt,
      congestion: NewReno.new(opts),
      max_sent_packets: Keyword.get(opts, :max_sent_packets, 4096),
      max_ack_ranges: Keyword.get(opts, :max_ack_ranges, 256),
      max_ack_span: Keyword.get(opts, :max_ack_span, 4096)
    }
  end

  @type t :: %__MODULE__{}

  @spec reserve(t(), atom(), map(), non_neg_integer()) ::
          {:ok, t(), Packet.t()} | {:error, atom()}
  def reserve(state, space, metadata \\ %{}, bytes \\ 0)

  def reserve(state, space, metadata, bytes)
      when space in @spaces and is_map(metadata) and is_integer(bytes) and bytes >= 0 do
    s = state.spaces[space]

    if map_size(s.sent) >= state.max_sent_packets do
      {:error, :sent_history_limit}
    else
      with {:ok, congestion} <- NewReno.reserve(state.congestion, bytes) do
        packet = %Packet{
          number: s.next,
          space: space,
          status: :reserved,
          bytes: bytes,
          metadata: metadata
        }

        state = %{state | congestion: congestion}
        {:ok, put_packet(state, space, packet, %{s | next: s.next + 1}), packet}
      end
    end
  end

  def reserve(_, _, _, _), do: {:error, :invalid_reservation}

  @spec transition(t(), atom(), non_neg_integer(), atom()) :: {:ok, t()} | {:error, atom()}
  def transition(state, space, number, status) when status in [:queued, :sent],
    do: update_status(state, space, number, status)

  def transition(_, _, _, _), do: {:error, :invalid_status}

  @spec local_send(t(), atom(), non_neg_integer(), :ok | {:error, term()}, integer()) ::
          {:ok, t(), [atom()]} | {:error, atom()}
  def local_send(state, space, number, :ok, at) when is_integer(at) do
    with {:ok, packet} <- fetch_packet(state, space, number),
         true <- packet.status in [:reserved, :queued] do
      packet = %{packet | status: :sent, sent_at: at}
      s = state.spaces[space]

      {status, pending} =
        if MapSet.member?(s.pending_acks, number),
          do: {:acked, MapSet.delete(s.pending_acks, number)},
          else: {:sent, s.pending_acks}

      packet = %{packet | status: status, acked_at: if(status == :acked, do: at, else: nil)}
      state = put_packet(state, space, packet, %{s | pending_acks: pending})

      state =
        if status == :acked,
          do: %{state | congestion: NewReno.on_ack(state.congestion, packet.bytes)},
          else: state

      {:ok, arm(state), [status]}
    else
      false -> {:error, :invalid_packet_state}
      error -> error
    end
  end

  def local_send(state, space, number, {:error, _reason}, _at) do
    with {:ok, packet} <- fetch_packet(state, space, number),
         true <- packet.status in [:reserved, :queued] do
      s = state.spaces[space]
      s = %{s | pending_acks: MapSet.delete(s.pending_acks, number)}
      state = put_packet(state, space, %{packet | status: :failed}, s)
      {:ok, %{state | congestion: NewReno.release(state.congestion, packet.bytes)}, [:failed]}
    else
      false -> {:error, :invalid_packet_state}
      error -> error
    end
  end

  @spec receive_ack(t(), atom(), map(), integer()) :: {:ok, t(), map()} | {:error, atom()}
  def receive_ack(state, space, ack, at)
      when space in @spaces and is_map(ack) and is_integer(at) do
    with {:ok, ranges} <-
           normalize_ranges(ack[:ranges] || [], state.max_ack_ranges, state.max_ack_span),
         {:ok, largest} <- validate_largest(ack[:largest], ranges),
         :ok <- known_ack?(state.spaces[space], largest, ranges) do
      {space_state, acked, newly_acked_bytes} = acknowledge(state.spaces[space], ranges, at)

      space_state = %{space_state | largest_acked: max(space_state.largest_acked, largest)}
      state = %{state | spaces: Map.put(state.spaces, space, space_state)}
      {state, sample} = update_rtt(state, space, ack, acked, at)
      state = %{state | congestion: NewReno.on_ack(state.congestion, newly_acked_bytes)}
      {state, threshold_lost} = detect_packet_threshold(state, space, largest)
      {:ok, arm(state), %{acked: acked, lost: threshold_lost, rtt_sample: sample}}
    end
  end

  @doc "Record an authenticated packet number received in a packet-number space."
  @spec note_received(t(), atom(), non_neg_integer()) :: {:ok, t()} | {:error, atom()}
  def note_received(state, space, number)
      when space in @spaces and is_integer(number) and number >= 0 do
    current = state.spaces[space]

    ranges = merge_ranges(current.ack_ranges, [{number, number}])

    if length(ranges) <= state.max_ack_ranges do
      next = %{
        current
        | largest_received: max(number, current.largest_received),
          ack_ranges: ranges
      }

      {:ok, %{state | spaces: Map.put(state.spaces, space, next)}}
    else
      {:error, :ack_range_limit}
    end
  end

  def note_received(_, _, _), do: {:error, :invalid_received_packet}

  @doc "Discard an encryption space's outstanding work while preserving allocated packet numbers."
  def discard_space(state, space) when space in @spaces do
    current = state.spaces[space]

    {sent, released} =
      Enum.reduce(current.sent, {%{}, 0}, fn {number, packet}, {packets, bytes} ->
        if packet.status in [:reserved, :queued, :sent] do
          {Map.put(packets, number, %{packet | status: :discarded}), bytes + packet.bytes}
        else
          {Map.put(packets, number, packet), bytes}
        end
      end)

    next = %{
      current
      | sent: sent,
        pending_acks: MapSet.new(),
        ack_ranges: [],
        largest_received: -1
    }

    arm(%{
      state
      | spaces: Map.put(state.spaces, space, next),
        congestion: NewReno.release(state.congestion, released),
        rtt: %{state.rtt | pto_count: 0}
    })
  end

  @doc "Recompute the next deadline from actual sent packets, without advancing time."
  def arm(state) do
    loss_times =
      for {_space, s} <- state.spaces,
          {number, p} <- s.sent,
          p.status == :sent and is_integer(p.sent_at) and number <= s.largest_acked,
          do: p.sent_at + loss_delay(state)

    deadline =
      case loss_times do
        [] ->
          case pto_candidates(state) do
            [] -> nil
            candidates -> candidates |> Enum.map(&elem(&1, 0)) |> Enum.min()
          end

        times ->
          Enum.min(times)
      end

    %{state | deadline: deadline, timer_generation: state.timer_generation + 1}
  end

  @spec on_time(t(), integer()) :: {:ok, t(), map()}
  def on_time(state, now) when is_integer(now) do
    expired = is_integer(state.deadline) and now >= state.deadline
    {state, lost} = detect_loss(state, now)

    probes =
      if expired and lost == [] do
        case Enum.sort(pto_candidates(state)) do
          [{_deadline, space, number} | _] -> [{space, number}]
          [] -> []
        end
      else
        []
      end

    state =
      if probes == [],
        do: state,
        else: %{state | rtt: %{state.rtt | pto_count: min(16, state.rtt.pto_count + 1)}}

    next = arm(state)

    {:ok, next,
     %{lost: lost, probes: probes, pto: next.deadline, generation: next.timer_generation}}
  end

  @spec timer_expired?(t(), non_neg_integer(), integer()) :: boolean()
  def timer_expired?(%__MODULE__{deadline: deadline, timer_generation: generation}, token, now),
    do: token == generation and is_integer(deadline) and now >= deadline

  defp put_packet(state, space, packet, space_state),
    do: %{
      state
      | spaces:
          Map.put(state.spaces, space, %{
            space_state
            | sent: Map.put(space_state.sent, packet.number, packet)
          })
    }

  defp fetch_packet(state, space, number) do
    case state.spaces[space].sent[number] do
      nil -> {:error, :unknown_packet}
      packet -> {:ok, packet}
    end
  end

  defp update_status(state, space, number, status) do
    with {:ok, packet} <- fetch_packet(state, space, number),
         true <-
           packet.status in [:reserved, :queued] or (status == :sent and packet.status == :sent) do
      {:ok, put_packet(state, space, %{packet | status: status}, state.spaces[space])}
    else
      false -> {:error, :invalid_packet_state}
      error -> error
    end
  end

  defp validate_largest(nil, _), do: {:error, :invalid_ack}

  defp validate_largest(largest, ranges) when is_integer(largest) and largest >= 0 do
    if ranges != [] and Enum.max(Enum.map(ranges, &elem(&1, 1))) == largest,
      do: {:ok, largest},
      else: {:error, :invalid_ack_ranges}
  end

  defp validate_largest(_, _), do: {:error, :invalid_ack}

  defp normalize_ranges(ranges, max, max_span) when is_list(ranges) and length(ranges) <= max do
    result =
      Enum.reduce_while(ranges, {:ok, []}, fn range, {:ok, acc} ->
        case range_bounds(range) do
          {:ok, {lo, hi}} when lo <= hi and hi - lo <= max_span ->
            {:cont, {:ok, [{lo, hi} | acc]}}

          _ ->
            {:halt, {:error, :invalid_ack_ranges}}
        end
      end)

    case result do
      {:ok, xs} -> {:ok, Enum.sort(xs)}
      error -> error
    end
  end

  defp normalize_ranges(_, _, _), do: {:error, :ack_range_limit}

  defp range_bounds({lo, hi}) when is_integer(lo) and is_integer(hi) and lo >= 0 and hi >= 0,
    do: {:ok, {lo, hi}}

  defp range_bounds(%{start: lo, end: hi}), do: range_bounds({lo, hi})
  defp range_bounds(_), do: {:error, :invalid_ack_range}

  defp known_ack?(space, largest, ranges) do
    issued = space.next

    if largest >= issued or Enum.any?(ranges, fn {_lo, hi} -> hi >= issued end),
      do: {:error, :ack_never_issued},
      else: :ok
  end

  defp acknowledge(space, ranges, at) do
    Enum.reduce(ranges, {space, [], 0}, fn {lo, hi}, {s, nums, bytes} ->
      Enum.reduce(lo..hi, {s, nums, bytes}, fn n, {s2, nums2, bytes2} ->
        case s2.sent[n] do
          %Packet{status: :sent} = p ->
            p = %{p | status: :acked, acked_at: at}
            {%{s2 | sent: Map.put(s2.sent, n, p)}, [n | nums2], bytes2 + p.bytes}

          %Packet{status: status} when status in [:reserved, :queued] ->
            {%{s2 | pending_acks: MapSet.put(s2.pending_acks, n)}, nums2, bytes2}

          _ ->
            {s2, nums2, bytes2}
        end
      end)
    end)
  end

  defp merge_ranges(existing, incoming) do
    (existing ++ incoming)
    |> Enum.sort()
    |> Enum.reduce([], fn
      {lo, hi}, [{previous_lo, previous_hi} | rest] when lo <= previous_hi + 1 ->
        [{previous_lo, max(previous_hi, hi)} | rest]

      range, acc ->
        [range | acc]
    end)
    |> Enum.reverse()
  end

  defp update_rtt(state, space, ack, acked, at) do
    sample =
      case Enum.find(acked, fn n -> state.spaces[space].sent[n].sent_at end) do
        nil ->
          nil

        n ->
          max(
            1,
            at - state.spaces[space].sent[n].sent_at -
              min(ack[:delay] || 0, state.rtt.max_ack_delay)
          )
      end

    if sample == nil,
      do: {state, nil},
      else: {%{state | rtt: update_rtt_sample(state.rtt, sample)}, sample}
  end

  defp update_rtt_sample(rtt, sample) do
    min = if rtt.min, do: min(rtt.min, sample), else: sample

    {smoothed, variance} =
      if rtt.smoothed,
        do:
          {div(7 * rtt.smoothed + sample, 8),
           div(3 * rtt.variance + abs(rtt.smoothed - sample), 4)},
        else: {sample, div(sample, 2)}

    %{rtt | latest: sample, min: min, smoothed: smoothed, variance: variance, pto_count: 0}
  end

  defp detect_loss(state, now) do
    threshold = loss_delay(state)

    Enum.reduce(@spaces, {state, []}, fn space, {st, lost} ->
      s = st.spaces[space]

      {s, nums, bytes} =
        Enum.reduce(s.sent, {s, [], 0}, fn {n, p}, {ss, ns, b} ->
          if p.status == :sent and is_integer(p.sent_at) and n <= s.largest_acked and
               now - p.sent_at >= threshold,
             do:
               {%{ss | sent: Map.put(ss.sent, n, %{p | status: :lost, lost_at: now})}, [n | ns],
                b + p.bytes},
             else: {ss, ns, b}
        end)

      {%{
         st
         | spaces: Map.put(st.spaces, space, s),
           congestion:
             if(bytes > 0, do: NewReno.on_loss(st.congestion, bytes), else: st.congestion)
       }, lost ++ Enum.map(nums, &{space, &1})}
    end)
  end

  defp detect_packet_threshold(state, space, largest) do
    threshold = largest - 3
    s = state.spaces[space]

    {s, nums, bytes} =
      Enum.reduce(s.sent, {s, [], 0}, fn {n, p}, {ss, ns, b} ->
        if p.status == :sent and threshold >= 0 and n <= threshold,
          do: {%{ss | sent: Map.put(ss.sent, n, %{p | status: :lost})}, [n | ns], b + p.bytes},
          else: {ss, ns, b}
      end)

    {%{
       state
       | spaces: Map.put(state.spaces, space, s),
         congestion:
           if(bytes > 0, do: NewReno.on_loss(state.congestion, bytes), else: state.congestion)
     }, Enum.map(nums, &{space, &1})}
  end

  defp loss_delay(state),
    do:
      max(
        1000,
        div(max(state.rtt.latest || @default_rtt, state.rtt.smoothed || @default_rtt) * 9 + 7, 8)
      )

  defp pto_candidates(state) do
    Enum.flat_map(@spaces, fn space ->
      sent =
        state.spaces[space].sent
        |> Map.values()
        |> Enum.filter(
          &(&1.status == :sent and is_integer(&1.sent_at) and
              Map.get(&1.metadata, :ack_eliciting, true))
        )

      case sent do
        [] ->
          []

        packets ->
          base =
            (state.rtt.smoothed || @default_rtt) +
              max(1000, 4 * (state.rtt.variance || div(@default_rtt, 2))) +
              if(space == :application, do: state.rtt.max_ack_delay, else: 0)

          latest = packets |> Enum.map(& &1.sent_at) |> Enum.max()
          oldest = Enum.min_by(packets, & &1.sent_at)
          [{latest + base * Integer.pow(2, state.rtt.pto_count), space, oldest.number}]
      end
    end)
  end
end
