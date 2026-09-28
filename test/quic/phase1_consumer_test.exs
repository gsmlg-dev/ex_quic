defmodule QUIC.Phase1ConsumerTest do
  use ExUnit.Case, async: true

  alias QUIC.Runtime.{ConnectionHandle, StreamHandle}

  test "public handles retain opaque pid, generation, and stream identity" do
    Code.ensure_loaded!(QUIC)
    connection = %ConnectionHandle{id: self(), generation: make_ref()}
    stream = %StreamHandle{connection: connection, id: 4}

    assert stream.connection == connection
    assert stream.id == 4
    assert function_exported?(QUIC, :events, 2)
    assert function_exported?(QUIC, :operation_status, 2)
  end
end
