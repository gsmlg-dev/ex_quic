defmodule QUIC.RecoveryTest do
  use ExUnit.Case, async: true

  alias QUIC.Recovery

  defp sent(state, space, bytes, at) do
    {:ok, state, packet} = Recovery.reserve(state, space, %{kind: :crypto}, bytes)
    {:ok, state} = Recovery.transition(state, space, packet.number, :queued)
    {:ok, state, _} = Recovery.local_send(state, space, packet.number, :ok, at)
    {state, packet.number}
  end

  test "packet number spaces are independent and numbers are never reused" do
    state = Recovery.new()
    {:ok, state, initial} = Recovery.reserve(state, :initial, %{}, 10)
    {:ok, state, handshake} = Recovery.reserve(state, :handshake, %{}, 10)
    assert initial.number == 0
    assert handshake.number == 0
    {:ok, state, _} = Recovery.local_send(state, :initial, initial.number, {:error, :closed}, 10)
    {:ok, _state, next} = Recovery.reserve(state, :initial, %{}, 10)
    assert next.number == 1
  end

  test "ACK waits for a delayed local send receipt" do
    state = Recovery.new()
    {:ok, state, packet} = Recovery.reserve(state, :application, %{}, 20)
    {:ok, state} = Recovery.transition(state, :application, packet.number, :queued)

    {:ok, state, result} =
      Recovery.receive_ack(state, :application, %{largest: 0, ranges: [{0, 0}]}, 100)

    assert result.acked == []
    assert MapSet.member?(state.spaces.application.pending_acks, 0)
    {:ok, state, [:acked]} = Recovery.local_send(state, :application, 0, :ok, 110)
    assert state.spaces.application.sent[0].status == :acked
  end

  test "duplicate and never-issued ACKs are handled explicitly" do
    {state, number} = sent(Recovery.new(), :initial, 10, 10)

    {:ok, state, %{acked: [0]}} =
      Recovery.receive_ack(state, :initial, %{largest: number, ranges: [{0, 0}]}, 30)

    {:ok, _state, %{acked: []}} =
      Recovery.receive_ack(state, :initial, %{largest: number, ranges: [{0, 0}]}, 31)

    assert {:error, :ack_never_issued} =
             Recovery.receive_ack(state, :initial, %{largest: 4, ranges: [{4, 4}]}, 32)
  end

  test "time-threshold loss and PTO use explicit timestamps" do
    {state, _} = sent(Recovery.new(max_ack_delay: 10_000), :handshake, 100, 0)

    {:ok, state, %{lost: [{:handshake, 0}], generation: generation, pto: pto}} =
      Recovery.on_time(state, 500_000)

    assert state.spaces.handshake.sent[0].status == :lost
    assert pto > 500_000
    assert Recovery.timer_expired?(state, generation, pto)
    {:ok, next, %{generation: next_generation}} = Recovery.on_time(state, pto)
    assert next_generation > generation
    assert next.deadline > pto
    refute Recovery.timer_expired?(next, generation, pto)
  end

  test "packet threshold loss is independent from other spaces" do
    state = Recovery.new()
    {state, _} = sent(state, :initial, 100, 0)
    {state, _} = sent(state, :initial, 100, 1)
    {state, _} = sent(state, :initial, 100, 2)
    {state, _} = sent(state, :initial, 100, 3)
    {state, _} = sent(state, :initial, 100, 4)

    {:ok, state, %{lost: lost}} =
      Recovery.receive_ack(state, :initial, %{largest: 4, ranges: [{4, 4}]}, 5)

    assert {:initial, 0} in lost
    assert state.spaces.initial.sent[0].status == :lost
    assert state.spaces.handshake.sent == %{}
  end

  test "recovery reserves congestion credit and releases failed sends" do
    state = Recovery.new(mss: 100, initial_cwnd: 200)
    assert {:ok, state, _first} = Recovery.reserve(state, :initial, %{}, 200)
    assert {:error, :congestion_limited} = Recovery.reserve(state, :initial, %{}, 1)
    {:ok, state, [:failed]} = Recovery.local_send(state, :initial, 0, {:error, :writer_down}, 10)
    assert state.congestion.bytes_in_flight == 0
    assert {:ok, _state, second} = Recovery.reserve(state, :initial, %{}, 200)
    assert second.number == 1
  end

  test "pending ACK consumes congestion credit once receipt arrives" do
    state = Recovery.new(mss: 100, initial_cwnd: 200)
    {:ok, state, _packet} = Recovery.reserve(state, :application, %{}, 200)

    {:ok, state, _} =
      Recovery.receive_ack(state, :application, %{largest: 0, ranges: [{0, 0}]}, 20)

    assert state.congestion.bytes_in_flight == 200
    {:ok, state, [:acked]} = Recovery.local_send(state, :application, 0, :ok, 25)
    assert state.congestion.bytes_in_flight == 0

    {:ok, state, %{acked: []}} =
      Recovery.receive_ack(state, :application, %{largest: 0, ranges: [{0, 0}]}, 30)

    assert state.congestion.bytes_in_flight == 0
  end

  test "packet threshold includes largest acknowledged minus three" do
    state = Recovery.new()
    {state, _} = sent(state, :initial, 10, 0)
    {state, _} = sent(state, :initial, 10, 1)
    {state, _} = sent(state, :initial, 10, 2)
    {state, _} = sent(state, :initial, 10, 3)

    {:ok, state, %{lost: lost}} =
      Recovery.receive_ack(state, :initial, %{largest: 3, ranges: [{3, 3}]}, 5)

    assert {:initial, 0} in lost
    assert state.spaces.initial.sent[0].status == :lost
  end
end

defmodule QUIC.Congestion.NewRenoTest do
  use ExUnit.Case, async: true

  alias QUIC.Congestion.NewReno

  test "bounded admission, growth and loss reduction" do
    state = NewReno.new(mss: 100, initial_cwnd: 200)
    assert {:ok, state} = NewReno.reserve(state, 200)
    assert {:error, :congestion_limited} = NewReno.reserve(state, 1)
    state = NewReno.on_ack(state, 100)
    assert state.cwnd > 200
    state = NewReno.on_loss(state, 100)
    assert state.cwnd == 200
    assert state.bytes_in_flight == 0
  end
end
