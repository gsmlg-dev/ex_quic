defmodule QUIC.CodecTest do
  use ExUnit.Case, async: true

  test "varint boundaries and truncation" do
    for value <- [0, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824, 0x3FFF_FFFF_FFFF_FFFF] do
      assert {:ok, encoded} = QUIC.Codec.encode_varint(value)
      assert {:ok, ^value, <<>>} = QUIC.Codec.decode_varint(encoded)
    end

    assert {:error, :varint_overflow} = QUIC.Codec.encode_varint(0x4000_0000_0000_0000)
    assert {:error, :truncated_varint} = QUIC.Codec.decode_varint(<<0x40>>)
  end

  test "Initial header builds and parses, while unknown versions are rejected" do
    fields = %{
      version: 1,
      dcid: <<1, 2>>,
      scid: <<3, 4>>,
      token: <<5>>,
      packet_number: 0x1234,
      packet_number_length: 2,
      payload: <<1, 2, 3>>
    }

    assert {:ok, packet} = QUIC.Codec.build_initial(fields)
    assert {:ok, parsed} = QUIC.Codec.parse_initial(packet <> <<9, 9>>)
    assert parsed.dcid == fields.dcid
    assert parsed.scid == fields.scid
    assert parsed.token == fields.token
    assert parsed.packet_number == fields.packet_number
    assert parsed.payload == fields.payload
    assert parsed.trailing == <<9, 9>>
    <<first, _version::32, rest::binary>> = packet
    unknown = <<first, 2::32, rest::binary>>
    assert {:error, :unsupported_version} = QUIC.Codec.parse_initial(unknown)
  end

  test "coalesced datagram boundaries are length bounded" do
    fields = %{
      dcid: <<1>>,
      scid: <<2>>,
      packet_number: 1,
      packet_number_length: 1,
      payload: <<7>>
    }

    assert {:ok, one} = QUIC.Codec.build_initial(fields)
    assert {:ok, two} = QUIC.Codec.build_initial(%{fields | packet_number: 2})
    assert {:ok, [^one, ^two]} = QUIC.Codec.split_datagram(one <> two)

    assert {:error, :truncated_payload} =
             QUIC.Codec.split_datagram(binary_part(one, 0, byte_size(one) - 1))
  end

  test "packet number reconstruction selects the closest epoch" do
    assert {:ok, 0x100} = QUIC.Codec.reconstruct_packet_number(0, 0xFF, 1)
    assert {:ok, 0xFF} = QUIC.Codec.reconstruct_packet_number(0xFF, 0x100, 1)
    assert {:error, :invalid_packet_number} = QUIC.Codec.reconstruct_packet_number(256, 0, 1)
  end

  test "encodes and decodes ACK ranges with independent wire bytes" do
    frame = %{type: :ack, largest: 10, delay: 1, ranges: [{8, 10}, {4, 5}]}
    expected = <<2, 10, 1, 1, 2, 1, 1>>

    assert {:ok, ^expected} = QUIC.Codec.encode_frames([frame])
    assert {:ok, [^frame], <<>>} = QUIC.Codec.decode_frames(expected)
    assert {:error, :malformed_ack_frame} = QUIC.Codec.decode_frames(<<2, 10, 1, 1, 2, 1>>)

    assert {:error, :invalid_ack_ranges} =
             QUIC.Codec.encode_frames([%{frame | ranges: [{8, 10}, {7, 7}]}])
  end

  test "encodes and decodes close and handshake control frames" do
    frames = [
      %{type: :connection_close, error_code: 16, frame_type: 6, reason: "bad"},
      %{type: :application_close, error_code: 42, reason: "done"},
      %{type: :handshake_done}
    ]

    expected = <<0x1C, 16, 6, 3, "bad", 0x1D, 42, 4, "done", 0x1E>>
    assert {:ok, ^expected} = QUIC.Codec.encode_frames(frames)
    assert {:ok, ^frames, <<>>} = QUIC.Codec.decode_frames(expected)
    assert {:error, :malformed_connection_close} = QUIC.Codec.decode_frames(<<0x1D, 42, 4, "do">>)

    long_reason = :binary.copy(<<0>>, 1025)

    assert {:error, :reason_too_large} =
             QUIC.Codec.encode_frames([
               %{type: :application_close, error_code: 1, reason: long_reason}
             ])
  end
end
