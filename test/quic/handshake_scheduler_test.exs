defmodule QUIC.HandshakeSchedulerTest do
  use ExUnit.Case, async: true

  alias QUIC.{Codec, HandshakeScheduler, Protection}

  defmodule Recorded do
    defstruct [:phase]

    def new(_, _), do: {:ok, %__MODULE__{phase: :initial}, [{:emit, :initial, <<1, 2>>}]}
    def info(%__MODULE__{phase: phase}), do: %{receive_level: phase}
    def abort(state, _), do: state

    def feed(%__MODULE__{phase: :initial} = state, :initial, <<9>>) do
      {:ok, %{state | phase: :handshake}, [{:emit, :initial, <<3>>}]}
    end

    def feed(state, _level, _bytes),
      do: {:error, %{kind: :quic, reason: :unexpected}, state, []}
  end

  defp new(opts \\ []) do
    HandshakeScheduler.new(
      :client,
      [dcid: <<1, 2, 3, 4>>, scid: <<5, 6, 7, 8>>, adapter: Recorded, min_initial_size: 0] ++ opts
    )
  end

  test "TLS Initial emission becomes a protected CRYPTO send effect" do
    assert {:ok, state, [effect]} = new()
    assert %{type: :send, level: :initial, packet_number: 0, bytes: packet} = effect
    assert state.recovery.spaces.initial.sent[0].status == :queued

    assert state.tls.levels.initial.sent == [
             %QUIC.TLSDriver.Emission{offset: 0, level: :initial, bytes: <<1, 2>>}
           ]

    assert {:ok, parsed} = Codec.parse_initial(packet)
    assert {:ok, keys} = Protection.initial_secrets(<<1, 2, 3, 4>>, :client)
    pn_offset = byte_size(packet) - byte_size(parsed.payload) - parsed.packet_number_length

    assert {:ok, unprotected, pn_len} =
             Protection.remove_header_protection(packet, pn_offset, keys.hp, :aes_128_gcm)

    <<aad::binary-size(^pn_offset), pn::binary-size(^pn_len), ciphertext::binary>> = unprotected

    assert {:ok, plaintext} =
             Protection.aead_decrypt(
               keys.key,
               keys.iv,
               :binary.decode_unsigned(pn),
               aad <> pn,
               ciphertext
             )

    assert {:ok, [%{type: :crypto, offset: 0, data: <<1, 2>>}], <<>>} =
             Codec.decode_frames(plaintext)
  end

  test "local send states and exact retransmit are separate from admission" do
    assert {:ok, state, [effect]} = new()
    packet = effect.bytes

    assert {:ok, state, [:failed]} =
             HandshakeScheduler.local_send(state, :initial, 0, {:error, :writer_down}, 10)

    assert {:ok, retransmit} = HandshakeScheduler.retransmit(state, :initial, 0)
    assert retransmit.bytes == packet
    assert retransmit.retransmit

    assert {:ok, state, [next]} = HandshakeScheduler.feed(state, :initial, 0, <<9>>)
    assert next.packet_number == 1
    assert state.recovery.spaces.initial.sent[0].status == :failed
  end

  test "ACK is queued into the next packet and peer accounting remains explicit" do
    assert {:ok, state, [effect]} = new()

    state =
      HandshakeScheduler.queue_ack(state, :initial, %{
        type: :ack,
        largest: 3,
        delay: 0,
        ranges: [{3, 3}]
      })

    assert {:ok, state, [ack_effect]} = HandshakeScheduler.schedule(state)
    assert ack_effect.type == :send
    refute Map.has_key?(state.pending_acks, :initial)

    assert {:ok, state, [:sent]} =
             HandshakeScheduler.local_send(state, :initial, effect.packet_number, :ok, 20)

    assert {:ok, state, result} =
             HandshakeScheduler.receive_ack(state, :initial, %{largest: 0, ranges: [{0, 0}]}, 30)

    assert result.acked == [0]
    assert state.recovery.spaces.initial.sent[0].status == :acked
  end

  test "unsupported handshake level and queue limits are explicit" do
    assert {:ok, state, _} = new()
    state = %{state | pending: [%{level: :handshake, offset: 0, bytes: <<1>>}]}
    assert {:error, {:unsupported_level, :handshake}, ^state} = HandshakeScheduler.schedule(state)

    assert {:error, :send_queue_limit, _limited} = new(max_queue: 0)
  end
end
