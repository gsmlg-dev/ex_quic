# M4 profile and backpressure evidence

`QUIC.Profile.compile/2` exposes two local policy variants: `:ordered` keeps
the supported cipher/group order and uses an 8-byte CID policy; `:compact`
reorders the supported cipher/group lists and uses a 16-byte CID policy. Both
use the QUIC record-free ClientHello policy, ALPN `ex-quic`, and raw transport
parameters supplied by the caller. Validation is delegated to the public
`SSL.ClientHello.Profile` capability contract.

`QUIC.Profile.materialize/2` calls the public ex_ssl materializer. Random and
key-share values are therefore generated per materialization and are not
stored in a reusable profile.

Application sends are bounded by both stream flow control and scheduler queue
bytes (`max_queue_bytes`). `QUIC.Streams` can be configured with
`delivery: :manual` and `max_ready_bytes`; peer data then remains in a
connection-owned ready queue until `consume/3` is called. Queue exhaustion
returns `:receive_queue_limit`; `QUIC.Connection.send_stream/5` returns
`:admission_timeout` when the bounded admission call times out.

Local evidence: `mix format --check-formatted`,
`mix compile --warnings-as-errors`, `git diff --check`, and `mix test` passed
with 138 tests. Independent peer capture comparing ClientHello, JA3/JA4,
transport parameters, and stream transfer was not run in this slice.
