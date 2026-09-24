defmodule QUIC.StreamsTest do
  use ExUnit.Case, async: true

  alias QUIC.Streams

  test "stream IDs encode role and direction and enforce local permissions" do
    state = Streams.new(:client, peer_max_streams_bidi: 1, peer_max_streams_uni: 1)
    assert {:ok, state, 0} = Streams.open(state, :bidi)
    assert {:blocked, %{type: :streams_blocked_bidi}} = Streams.open(state, :bidi)
    assert {:ok, state, 4} = Streams.open(state, :uni)

    assert {:ok, state, _} =
             Streams.receive(state, %{
               type: :stream,
               stream_id: 5,
               offset: 0,
               data: <<1>>,
               fin: false
             })

    assert {:error, :send_on_receive_only_stream} = Streams.send(state, 5, <<2>>)
  end

  test "out of order stream data is reassembled and FIN is exact" do
    state = Streams.new(:client, max_buffer: 32)
    assert {:ok, state, 0} = Streams.open(state, :bidi)

    assert {:ok, state, []} =
             Streams.receive(state, %{
               type: :stream,
               stream_id: 0,
               offset: 3,
               data: "def",
               fin: true
             })

    assert {:ok, _state, events} =
             Streams.receive(state, %{
               type: :stream,
               stream_id: 0,
               offset: 0,
               data: "abc",
               fin: false
             })

    assert events == [{:data, 0, "abc"}, {:data, 0, "def"}, {:fin, 0}]
  end

  test "flow control, final-size and overlap violations are explicit" do
    state = Streams.new(:client, peer_max_data: 3, peer_max_stream_data: 3)
    assert {:ok, state, 0} = Streams.open(state, :bidi)
    assert {:blocked, %{type: :data_blocked}} = Streams.send(state, 0, "abcd")
    assert {:ok, state, _} = Streams.send(state, 0, "abc", true)
    assert {:error, :final_size_error} = Streams.send(state, 0, <<>>, false)

    assert {:ok, _state, []} =
             Streams.receive(state, %{
               type: :stream,
               stream_id: 1,
               offset: 1,
               data: "x",
               fin: false
             })
  end

  test "reset and stop sending cancel one stream" do
    state = Streams.new(:client)
    assert {:ok, state, 0} = Streams.open(state, :bidi)
    assert {:ok, state, [{:reset, 0, 9, 0}]} = Streams.reset(state, 0, 9, 0)

    assert {:ok, _state, %{type: :stop_sending, stream_id: 0, error_code: 10}} =
             Streams.stop_sending(state, 0, 10)
  end
end
