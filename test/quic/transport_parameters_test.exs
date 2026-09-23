defmodule QUIC.TransportParametersTest do
  use ExUnit.Case, async: true

  alias QUIC.TransportParameters

  test "preserves ordered unknown parameters and exposes known values" do
    ordered = [
      %{id: 0x00, value: <<1, 2>>},
      %{id: 0x20, value: <<0xAA, 0xBB>>},
      %{id: 0x03, value: <<0x44, 0xB0>>}
    ]

    assert {:ok, wire} = TransportParameters.encode(ordered)
    assert wire == <<0x00, 0x02, 1, 2, 0x20, 0x02, 0xAA, 0xBB, 0x03, 0x02, 0x44, 0xB0>>
    assert {:ok, decoded} = TransportParameters.decode(wire)
    assert decoded.ordered == ordered
    assert decoded.unknown == [{0x20, <<0xAA, 0xBB>>}]
    assert decoded.values.original_destination_connection_id == <<1, 2>>
    assert decoded.values.max_udp_payload_size == 1200
  end

  test "rejects duplicate, truncated, and over-bound parameters" do
    duplicate = <<0x03, 0x01, 0x01, 0x03, 0x01, 0x02>>
    assert {:error, :duplicate_transport_parameter} = TransportParameters.decode(duplicate)

    assert {:error, :truncated_transport_parameter} =
             TransportParameters.decode(<<0x03, 0x02, 0x01>>)

    assert {:error, :transport_parameters_too_large} =
             TransportParameters.decode(<<0, 0>>, max_bytes: 1)

    assert {:error, :parameter_count_limit} =
             TransportParameters.decode(<<0, 0, 1, 0>>, max_parameters: 1)
  end

  test "enforces role constraints and numeric bounds" do
    preferred_address = <<0, 0, 0, 0, 0, 53, 0::128, 0, 53, 0, 0::128>>
    client_server_only = [%{id: 0x0D, value: preferred_address}]

    assert {:error, :parameter_forbidden_for_role} =
             TransportParameters.encode(client_server_only, role: :client)

    server_missing_cids = [%{id: 0x0F, value: <<1>>}]

    assert {:error, :missing_original_destination_connection_id} =
             TransportParameters.encode(server_missing_cids, role: :server)

    assert {:error, :invalid_max_udp_payload_size} =
             TransportParameters.encode([%{id: 0x03, value: <<0x44, 0xAF>>}])

    assert {:error, :invalid_max_udp_payload_size} =
             TransportParameters.encode([%{id: 0x03, value: <<0x80, 0x00, 0xFF, 0xF8>>}])

    assert {:error, :invalid_ack_delay_exponent} =
             TransportParameters.encode([%{id: 0x0A, value: <<21>>}])

    assert {:ok, _} =
             TransportParameters.encode([%{id: 0x0D, value: preferred_address}])

    assert {:error, :invalid_preferred_address} =
             TransportParameters.encode([
               %{id: 0x0D, value: binary_part(preferred_address, 0, 23)}
             ])
  end

  test "requires the client initial source connection id" do
    assert {:error, :missing_initial_source_connection_id} =
             TransportParameters.encode([], role: :client)
  end
end
