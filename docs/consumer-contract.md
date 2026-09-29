# Phase 1 consumer contract

This contract describes the implementation in this worktree, not full QUIC
conformance or HTTP/3 support. Consult [phase1-acceptance.md](phase1-acceptance.md)
for the independently verified subset and outstanding gates. The application
owns DNS, HTTP/3/QPACK, framing, routing and authorization. Negotiated ALPN is
opaque metadata; ex_quic never dispatches an application protocol from it.

## Endpoints, handles and ownership

`Quic.listen(options)` and `Quic.client(options)` return `{:ok, endpoint_pid}`.
The caller is the default acceptor and is monitored. The endpoint owns a
standalone UDP socket unless the server supplies the external capability in
[io-contract.md](io-contract.md). `Quic.local(endpoint)` returns `{ip, port}`.
TLS options are supplied under `:tls`: server certificate chain, signing key and
ALPN; client trust anchors, reference identity and ALPN. Trust/reference checks
belong to `SSL.QUIC`. There is no insecure verification fallback.

`Quic.connect(endpoint, remote, options)` admits a client connection and returns
`{:ok, connection_handle}` before readiness. Server endpoints notify the acceptor
with `{:quic_accept, endpoint}` when their ready accept queue becomes nonempty.
`Quic.accept(endpoint)` dequeues a ready connection or returns
`{:error, :would_block}`. Drain this queue after each notification. There are at
most `:max_connections` connections (default 128).

A connection handle is `%Quic.Runtime.ConnectionHandle{id: pid, generation: ref}`;
a stream handle is `%Quic.Runtime.StreamHandle{connection: handle, id: integer}`.
Treat both as opaque capabilities. Generations prevent stale handles from
addressing a different connection. Stream IDs follow QUIC's initiator/direction
bits, including client uni 2/6/10 and server uni 3/7/11. Streams are data owned by
one connection state machine, not processes.

`Quic.attach(connection, consumer_pid)` assigns the application consumer. I/O
ownership remains at the endpoint. The consumer's death terminates its connection;
endpoint or writer death terminates dependent connections. Applications should
serialize operations through their consumer, with a bounded work queue. The API
does not make arbitrary concurrent local callers' BEAM mailboxes bounded.

## Readiness and pull delivery

`Quic.ready(connection)` returns `:pending` or `:ready`. The attached consumer
receives `{:quic_ready, connection, metadata}` once the ready transition is
observed (or on attachment to a ready connection). `Quic.info(connection)` returns
`{:ok, metadata}` including ALPN, local/remote addresses, TLS completion,
parameter validity, peer authentication and QUIC confirmation as separate facts.
A certificate-based server does not claim client identity authentication without
client authentication. Readiness is not an application authorization decision.

`Quic.events(connection, max \\ 32, options \\ [])` drains up to 128 control notifications for
the attached consumer. Readiness is ordered before buffered stream notifications.
Events are `{:ready, metadata}`, `{:stream_open, stream, :bidi | :uni}`,
`{:readable, stream}`, `{:stopped, stream, application_code}`, and `:writable`.
Readable/writable notifications coalesce. The notification queue defaults to 128;
overflow closes the connection. Stream bytes are retained in bounded connection
data, never copied into an unbounded consumer mailbox. Before attachment the same
limits apply. Poll this public event queue; private process-state enumeration is
unnecessary.

`Quic.read(stream, max_bytes, options \\ [])` consumes at most 16 KiB and returns
`{:ok, items}`, where items are `{:data, stream_id, bytes}`, `{:fin, stream_id}`,
or `{:reset, stream_id, application_code, final_size}`. Small reads split larger
queued data. An empty list means no currently available items. Only the attached
consumer may read or drain events. FIN/reset are delivered once; read FIN closes
only the receive half. Consuming data advances recoverable MAX_DATA and
MAX_STREAM_DATA; duplicates do not grant credit.

## Opening, sending and cancellation

`Quic.open_stream(connection, :bidi | :uni, options)` returns `{:ok, stream}`.
`Quic.send_stream(stream, binary, fin \\ false, options \\ [])` admits at most
16,384 bytes per call and returns `{:ok, operation_ref}`. The engine splits data
into protected packets under the path/profile/peer ceiling, retaining FIN only on
the final range. Admission is neither local writer completion nor peer ACK.
There is no public per-write peer-delivery receipt in this subset.

Temporary credit/queue pressure returns `{:blocked, reason}` without admission;
unknown streams, invalid directions, chunks exceeding 16 KiB and final-size
violations return `{:error, reason}`. Congestion can retain an admitted chunk in
the bounded scheduler queue. Peer credit updates and ACKs resume scheduling and produce coalesced `:writable` events.
Applications may retry a definitely blocked operation when credit changes; do not
blindly retry unknown outcomes.

`Quic.reset_stream(stream, application_code, options \\ [])` cancels the sending half and emits
RESET_STREAM. `Quic.stop_stream(stream, application_code, options \\ [])` stops receiving and
emits STOP_SENDING. Peer STOP_SENDING causes RESET_STREAM when applicable. Neither
operation closes unrelated streams. `Quic.close(connection, code \\ 0,
reason \\ <<>>, options \\ [])` sends an application close. Codes are opaque
62-bit integers and reasons opaque binaries up to 256 bytes. Consumers receive
`{:quic_closed, connection, reason}` on termination. Closing and draining retain
routes until cleanup, so late packets do not admit replacement connections.

## Admission outcomes and resource policy

Connect, accept, reads and event draining also support these operation options.
`Quic.accept(endpoint, options)` accepts a keyword list or legacy integer timeout;
`Quic.operation_status(endpoint, ref)` resolves endpoint admissions. Destructive
pull results are cached as `:completed`, so a timed-out read can recover its exact
bytes using the same reference. Read results retained in the operation cache
consume additional bounded memory (up to 16 KiB per read result); resource byte
counters describe active stream queues, not cached reply binaries.

Mutation options include a caller reference `:ref`, call timeout `:timeout` in
milliseconds (default 5000), and admission deadline duration `:deadline` in
milliseconds measured from the call (default timeout). A deadline is checked
before admission. A timeout returns `{:unknown, ref}`: admission may have occurred.
`Quic.operation_status(connection, ref)` resolves retained results as
`%{status: :admitted | :completed | :rejected, result: result}` or `:unknown`. Reusing a retained
reference with the same request returns its result; changing its request returns
`:operation_ref_conflict`. The bounded cache defaults to the latest 256 operations;
eviction or process death prevents resolution. An unknown outcome is never proof
that retrying a fresh reference is safe.

Public endpoints force manual delivery. Stream receive options live under
`:streams`: `:max_data`, `:max_stream_data`, the three specific bidi-local,
bidi-remote and uni windows, `:max_streams_bidi`, `:max_streams_uni`,
`:max_buffer`, `:max_ready_bytes`, `:max_stream_records`, and `:max_recv_ranges`.
Effective connection credit is clamped to sustainable retained-memory capacity.
Zero transport credit is valid. Authenticated peer defaults and directional
windows replace initial send limits before readiness. Default retained data
budgets are 256 KiB and stream-record capacity 1024; terminal records are bounded
tombstones, so indefinitely opening new streams can exhaust the connection's
record budget. MAX_STREAMS grants stop before exceeding that policy.

`info.resources` exposes pending datagrams, queued application bytes, unread bytes,
reassembly bytes, recovery records, stream records, event count and operation
references. `info.highwaters` retains peaks observed at runtime mutations, including transient
I/O queue/send references. `application_crypto_bytes` counts contiguous accepted
application-level CRYPTO bytes. `operation_result_bytes` is encoded result size,
not total VM heap memory; `tracked_references` counts operation references,
I/O receipt/timer references, generation and owner/writer/consumer monitors.
Mailbox values remain samples at observation points, not a global VM profiler. Application CRYPTO tickets can be parsed/ignored, but resumption/0-RTT,
DATAGRAM, migration, HTTP/3, QPACK and WebTransport are unsupported.

The older PID-oriented `Quic.Connection` and diagnostic `stream_observer` seams
remain for internal tests. Downstream applications should use the generation
handles and consumer operations above.
