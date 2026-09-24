# M3 runtime evidence and remaining gates

The standalone runtime uses `QUIC.Endpoint` for bounded CID admission/routing,
`QUIC.Connection` as a temporary `:gen_statem` owning Scheduler/TLS state, and
`QUIC.IO.GenUDP` as a separately owned send/receive capability. Closing a
connection does not close the shared socket. Concrete IPv4/IPv6 binds are
required; wildcard binds and ancillary multihoming are unsupported.

Reception forwards one datagram per consumption credit. Queue item and byte
budgets include writes awaiting receipts. The server's amplification budget
includes pending and actually sent bytes. Local receipts carry actual monotonic
microseconds; peer acknowledgements are processed separately in Recovery.
Writer/owner death, generation replacement and handshake deadlines terminate
or invalidate the appropriate work.

TLS completion, authenticated parameters, parameter/CID validity, certificate
verification at the client, address validation and QUIC confirmation remain
separate. HANDSHAKE_DONE confirms the client handshake. The established state
cancels its handshake deadline; it does not imply streams or HTTP/3 support.

## Executable local evidence

- `test/quic/io_endpoint_test.exs`: pending/sent amplification accounting,
  item/byte limits, failed receipts, signed monotonic time, timer and generation
  invalidation. ACK bookkeeping is exclusively in Recovery.
- `test/quic/io_gen_udp_test.exs`: loopback send completion, consumption-credit
  backpressure, concrete binds, malformed input, stale credit and owner death.
- `test/quic/connection_test.exs`: protected Initial transmission, server
  amplification holds, authenticated Handshake address validation, writer
  failure/death, handshake deadline, stale input, parameter authentication and
  CID rejection, fresh-number PTO retransmission.
- `test/quic/endpoint_test.exs`: shared-socket isolation, bounded admission,
  route cleanup, actual both-role certificate handshakes, authenticated ACKs,
  HANDSHAKE_DONE and deadline cancellation, wrong hostname and ALPN rejection.
  A controlled UDP proxy drops one client Initial or one server Handshake packet
  and requires successful confirmation afterward.
- `test/quic/recovery_test.exs`: distinct send/receive histories, packet and time
  threshold loss, PTO without false loss, deadline cancellation, independent
  spaces and delayed receipt/ACK accounting.
- `test/quic/protection_test.exs`: fixed short-header mask regression (five low
  bits for short headers, four for long headers).

Certificate tests read disposable fixtures from the full-SHA pinned ex_ssl
checkout (`test/fixtures/server_flight`), not system/runtime credentials.
The UDP peer on both sides is ex_quic: this is **self-connection evidence**, not
independent QUIC interoperability. The test ALPN is `ex-quic-test`.

## Remaining acceptance work

M3-E is not complete. This document records the earlier local-runtime increment.
See [independent peer evidence](m3-interop.md) for subsequent ordinary dual-role
aioquic results; the complete independent network matrix remains open. Retry/token handling, broader loss/reordering/
duplication/corruption, external certificate/ALPN negatives and independently
verified packet behavior remain to be exercised and corrected as needed.

Before broader endpoint acceptance, also review key retirement, strict packet
header/CID and frame legality, large CRYPTO flight fragmentation, congestion-full
PTO behavior, recovery edge cases, established idle/closing/draining lifetime,
and sent-history reclamation. Current bounded resource limits can terminate a
connection rather than silently extend unsupported behavior. Streams/profiles,
path migration and Abyss integration are not part of this runtime increment.

## Local validation record

2026-09-24, macOS, Elixir 1.20.1 / Erlang OTP 29 (ERTS 17.0.2):
`mix format --check-formatted`, `mix compile --warnings-as-errors`, `mix test`
(91 tests, seed 466101), and staged `git diff --cached --check` exited 0.
Independent-peer tests, CI runtime combinations and packet captures were not run
for this increment.
