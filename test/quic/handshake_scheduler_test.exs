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

  defmodule RecordedSecret do
    defstruct [:phase]

    def new(_, _),
      do:
        {:ok, %__MODULE__{phase: :initial},
         [secret(:handshake, :read), secret(:handshake, :write, :b)]}

    def info(%__MODULE__{phase: phase}), do: %{receive_level: phase}
    def abort(state, _), do: state
    def feed(state, _level, _bytes), do: {:ok, state, []}

    def secret(level, direction, value \\ :a) do
      %SSL.QUIC.Secret{
        level: level,
        direction: direction,
        cipher_suite: 0x1301,
        aead: :aes_128_gcm,
        hkdf: :sha256,
        secret: :binary.copy(if(value == :b, do: <<2>>, else: <<1>>), 32)
      }
    end
  end

  defmodule DuplicateSecret do
    def new(_, _),
      do:
        {:ok, %{},
         [RecordedSecret.secret(:handshake, :read), RecordedSecret.secret(:handshake, :read)]}

    def info(_), do: %{receive_level: :initial}
    def abort(state, _), do: state
    def feed(state, _level, _bytes), do: {:ok, state, []}
  end

  defmodule ConflictingSecret do
    def new(_, _),
      do:
        {:ok, %{},
         [RecordedSecret.secret(:handshake, :read), RecordedSecret.secret(:handshake, :read, :b)]}

    def info(_), do: %{receive_level: :initial}
    def abort(state, _), do: state
    def feed(state, _level, _bytes), do: {:ok, state, []}
  end

  defmodule UnsupportedSecret do
    def new(_, _),
      do:
        {:ok, %{},
         [
           %SSL.QUIC.Secret{
             level: :handshake,
             direction: :write,
             cipher_suite: 0x1301,
             aead: :aes_256_gcm,
             hkdf: :sha256,
             secret: <<0::256>>
           }
         ]}

    def info(_), do: %{receive_level: :initial}
    def abort(state, _), do: state
    def feed(state, _level, _bytes), do: {:ok, state, []}
  end

  defmodule InboundRecorded do
    defstruct [:received]

    def new(_, _), do: {:ok, %__MODULE__{received: []}, []}
    def info(_), do: %{receive_level: :initial}
    def abort(state, _), do: state

    def feed(state, :initial, bytes),
      do: {:ok, %{state | received: state.received ++ [bytes]}, []}

    def feed(state, _level, _bytes),
      do: {:error, %{kind: :quic, reason: :unexpected_level}, state, []}
  end

  defp new(opts \\ []) do
    HandshakeScheduler.new(
      :client,
      [dcid: <<1, 2, 3, 4>>, scid: <<5, 6, 7, 8>>, adapter: Recorded, min_initial_size: 0] ++ opts
    )
  end

  defp new_with(adapter) do
    HandshakeScheduler.new(
      :client,
      dcid: <<1, 2, 3, 4>>,
      scid: <<5, 6, 7, 8>>,
      adapter: adapter,
      min_initial_size: 0
    )
  end

  test "installs directional QUIC keys from recorded TLS secrets" do
    result = new_with(RecordedSecret)
    assert {:ok, state, _effects} = result

    assert %{
             read: %{key: read_key},
             write: %{key: write_key, iv: iv, hp: hp, hp_algorithm: :aes_128_gcm}
           } =
             state.keys.handshake

    refute read_key == write_key
    assert byte_size(read_key) == 16
    assert byte_size(write_key) == 16
    assert byte_size(iv) == 12
    assert byte_size(hp) == 16
  end

  test "rejects duplicate and conflicting directional secret installs" do
    assert {:error, {:duplicate_secret, :handshake, :read}, _state} = new_with(DuplicateSecret)

    assert {:error, {:conflicting_secret, :handshake, :read}, _state} =
             new_with(ConflictingSecret)
  end

  test "rejects unsupported secret algorithm combinations" do
    assert {:error, {:unsupported_cipher_suite, 0x1301}, _state} = new_with(UnsupportedSecret)
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

  test "authenticated Initial datagram dispatches CRYPTO exactly once" do
    {:ok, sender, [effect]} =
      HandshakeScheduler.new(
        :client,
        dcid: <<1, 2, 3, 4>>,
        scid: <<5, 6, 7, 8>>,
        adapter: Recorded,
        min_initial_size: 0
      )

    {:ok, initial_read} = Protection.initial_secrets(<<1, 2, 3, 4>>, :client)

    {:ok, receiver, []} =
      HandshakeScheduler.new(
        :client,
        dcid: <<1, 2, 3, 4>>,
        scid: <<5, 6, 7, 8>>,
        adapter: InboundRecorded,
        initial_read_keys: initial_read,
        min_initial_size: 0
      )

    assert {:ok, receiver, events} =
             HandshakeScheduler.receive_datagram(receiver, effect.bytes, 10)

    assert [%{type: :crypto, offset: 0, bytes: <<1, 2>>}] = events
    assert receiver.tls.tls.received == [<<1, 2>>]

    assert {:ok, duplicate, [_duplicate_event]} =
             HandshakeScheduler.receive_datagram(receiver, effect.bytes, 11)

    assert duplicate.tls.tls.received == [<<1, 2>>]
    assert duplicate.recovery.spaces.initial.largest_received == 0
    assert sender.recovery.spaces.initial.sent[0].status == :queued
  end

  test "bad tags and malformed packets leave scheduler state unchanged" do
    assert {:ok, sender, [effect]} = new()
    {:ok, initial_read} = Protection.initial_secrets(<<1, 2, 3, 4>>, :client)

    assert {:ok, receiver, []} =
             HandshakeScheduler.new(
               :client,
               dcid: <<1, 2, 3, 4>>,
               scid: <<5, 6, 7, 8>>,
               adapter: InboundRecorded,
               initial_read_keys: initial_read,
               min_initial_size: 0
             )

    effect_size = byte_size(effect.bytes)
    prefix_size = effect_size - 1
    <<prefix::binary-size(^prefix_size), last>> = effect.bytes
    tampered = prefix <> <<Bitwise.bxor(last, 1)>>
    assert {:error, :bad_tag, ^receiver} = HandshakeScheduler.receive_datagram(receiver, tampered)

    assert {:error, :truncated_header, ^receiver} =
             HandshakeScheduler.receive_datagram(receiver, <<1>>)

    assert sender.recovery.spaces.initial.sent[0].status == :queued
  end

  test "inbound ACK updates Recovery after authenticated decode" do
    assert {:ok, state, [effect]} = new()
    assert {:ok, state, [:sent]} = HandshakeScheduler.local_send(state, :initial, 0, :ok, 1)

    state =
      HandshakeScheduler.queue_ack(state, :initial, %{
        type: :ack,
        largest: 0,
        delay: 0,
        ranges: [{0, 0}]
      })

    assert {:ok, state, [ack_effect]} = HandshakeScheduler.schedule(state)

    {:ok, read_keys} = Protection.initial_secrets(<<1, 2, 3, 4>>, :client)
    receiver = %{state | read_keys: %{initial: read_keys}}

    assert {:ok, receiver, events} =
             HandshakeScheduler.receive_datagram(receiver, ack_effect.bytes, 20)

    assert Enum.any?(events, &(&1.type == :ack))
    assert receiver.recovery.spaces.initial.sent[0].status == :acked
    assert effect.packet_number == 0
  end
end
