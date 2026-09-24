defmodule QUIC.HandshakeSchedulerLevelsTest do
  use ExUnit.Case, async: true

  alias QUIC.{HandshakeScheduler, Protection}

  defmodule Recorded do
    defstruct []

    def new(_, _),
      do:
        {:ok, %__MODULE__{},
         [
           secret(:handshake, :read, <<1::256>>),
           secret(:handshake, :write, <<2::256>>),
           secret(:application, :read, <<3::256>>),
           secret(:application, :write, <<4::256>>)
         ]}

    def info(_), do: %{receive_level: :initial}
    def abort(state, _), do: state
    def feed(state, _level, _bytes), do: {:ok, state, []}

    def secret(level, direction, bytes) do
      %SSL.QUIC.Secret{
        level: level,
        direction: direction,
        cipher_suite: 0x1301,
        aead: :aes_128_gcm,
        hkdf: :sha256,
        secret: bytes
      }
    end
  end

  defp new do
    HandshakeScheduler.new(
      :client,
      dcid: <<1, 2, 3, 4>>,
      scid: <<5, 6, 7, 8>>,
      adapter: Recorded,
      min_initial_size: 0
    )
  end

  defp decrypt_packet(packet, keys, pn_offset) do
    assert {:ok, unprotected, pn_len} =
             Protection.remove_header_protection(packet, pn_offset, keys.hp, keys.hp_algorithm)

    <<_first, _prefix::binary-size(^pn_offset - 1), pn_bytes::binary-size(^pn_len),
      ciphertext::binary>> =
      unprotected

    pn = :binary.decode_unsigned(pn_bytes)
    aad = binary_part(unprotected, 0, pn_offset + pn_len)
    assert {:ok, plaintext} = Protection.aead_decrypt(keys.key, keys.iv, pn, aad, ciphertext)
    {pn, plaintext}
  end

  test "builds Handshake CRYPTO with write keys and independent packet number" do
    assert {:ok, state, []} = new()
    state = %{state | pending: [%{level: :handshake, offset: 7, bytes: <<8, 9>>}]}

    assert {:ok, state, [effect]} = HandshakeScheduler.schedule(state)
    assert effect.level == :handshake
    assert effect.packet_number == 0
    assert state.recovery.spaces.handshake.sent[0].metadata.crypto == {7, 2}

    {pn, plaintext} =
      decrypt_packet(effect.bytes, state.keys.handshake.write, 1 + 4 + 1 + 4 + 1 + 4 + 1)

    assert pn == 0

    assert {:ok, [%{type: :crypto, offset: 7, data: <<8, 9>>}], <<>>} =
             QUIC.Codec.decode_frames(plaintext)
  end

  test "builds Application packets with independent packet number space" do
    assert {:ok, state, []} = new()

    state = %{
      state
      | pending: [
          %{level: :handshake, offset: 0, bytes: <<1>>},
          %{level: :application, offset: 0, bytes: <<2>>}
        ]
    }

    assert {:ok, state, effects} = HandshakeScheduler.schedule(state)

    assert Enum.map(effects, &{&1.level, &1.packet_number}) == [
             {:handshake, 0},
             {:application, 0}
           ]

    app = Enum.find(effects, &(&1.level == :application))
    {pn, plaintext} = decrypt_packet(app.bytes, state.keys.application.write, 1 + 4)
    assert pn == 0

    assert {:ok, [%{type: :crypto, offset: 0, data: <<2>>}], <<>>} =
             QUIC.Codec.decode_frames(plaintext)
  end

  test "failed local send retains exact packet and next send does not reuse number" do
    assert {:ok, state, []} = new()
    state = %{state | pending: [%{level: :handshake, offset: 0, bytes: <<1>>}]}
    assert {:ok, state, [first]} = HandshakeScheduler.schedule(state)

    assert {:ok, state, [:failed]} =
             HandshakeScheduler.local_send(state, :handshake, 0, {:error, :closed}, 1)

    assert {:ok, retransmit} = HandshakeScheduler.retransmit(state, :handshake, 0)
    assert retransmit.bytes == first.bytes

    state = %{state | pending: [%{level: :handshake, offset: 1, bytes: <<2>>}]}
    assert {:ok, state, [second]} = HandshakeScheduler.schedule(state)
    assert second.packet_number == 1
    assert state.recovery.spaces.handshake.sent[0].status == :failed
  end

  test "ACK updates the matching Handshake recovery space" do
    assert {:ok, state, []} = new()
    state = %{state | pending: [%{level: :handshake, offset: 0, bytes: <<1>>}]}
    assert {:ok, state, [effect]} = HandshakeScheduler.schedule(state)
    assert {:ok, state, [:sent]} = HandshakeScheduler.local_send(state, :handshake, 0, :ok, 2)

    assert {:ok, state, %{acked: [0]}} =
             HandshakeScheduler.receive_ack(
               state,
               :handshake,
               %{largest: 0, ranges: [{0, 0}]},
               3
             )

    assert state.recovery.spaces.handshake.sent[effect.packet_number].status == :acked
  end
end
