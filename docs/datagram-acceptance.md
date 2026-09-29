# Application ALPN and DATAGRAM acceptance

Scope: internal request [#5](https://github.com/gsmlg-dev/ex_quic/issues/5),
2026-09-29. This adds configurable client-profile ALPN and RFC 9221 unreliable
DATAGRAM transport. It does not implement HTTP/3, QPACK, WebTransport or 0-RTT.
The default profile ALPN remains `ex-quic`; DATAGRAM receive support is opt-in.

The separate publication request
[#4](https://github.com/gsmlg-dev/ex_quic/issues/4) was already satisfied by
Hex `elixir_quic 0.2.2`, with `ex_ssl == 0.7.2`. Its GitHub archive SHA-256
matches the Hex release checksum:
`2c73402421edf4156db843bbf11fe26aa5cd78eb1ae7acac863ed41fa47e8c74`.
Tag `v0.2.2` points to `c9ad458add5a496949bd1c89b50128c8ab777da9`.
Release run `36512394283` and released-tag E2E run `36512503737` succeeded.

## Independent network oracle

`scripts/datagram/peer.py` pins `aioquic==1.2.0` through `uv` and Python 3.12.
`scripts/datagram/interop.exs` uses the public generation handles, pull APIs and
events. Both roles negotiate `h3` with certificate verification; the Elixir
client uses a compiled `:ordered` profile. The two implementations exchange
exact empty, duplicate and boundary-sized DATAGRAM payloads alongside a
FIN-terminated stream. The harness requires peer completion, exit status zero
and connection cleanup. These are transport tests, not HTTP/3 request tests.

Reproduce from the repository root:

```sh
direnv exec . mix run scripts/datagram/interop.exs client
direnv exec . mix run scripts/datagram/interop.exs server
```

The released-tag E2E workflow includes both commands. Protocol loss/recovery and
resource-limit assertions are deterministic tests; this network harness does
not claim reliable DATAGRAM delivery under loss.

## Local verification

Executed on Elixir 1.18.5 / OTP 28, 2026-09-29; all commands below exited 0:

| Check | Command / result |
|---|---|
| Formatting | `direnv exec . mix format --check-formatted`; explicit formatting check for `scripts/datagram/interop.exs` and the two Phase 1 Elixir scripts |
| Strict compilation | `direnv exec . env MIX_ENV=test mix compile --warnings-as-errors` |
| Full regression | `direnv exec . mix test --seed 29092026`: **225 tests, 0 failures** |
| Packaging | `direnv exec . env MIX_ENV=prod mix hex.build --output /tmp/elixir-quic-pre-release.tar`; pre-release package build, not publication evidence |
| Independent DATAGRAM | Both commands above: **4 DATAGRAMs and one FIN stream per direction**, including an exact 1197-byte payload boundary |
| Reliable-stream regression | `direnv exec . env PHASE1_INTEROP_RUN=1 PHASE1_SCENARIO=impaired mix run scripts/phase1/interop.exs <role>` for `client` and `server`, plus server with `PHASE1_EXTERNAL=1`: all **PASS**, 2 MiB received application data per arrangement, cleanup true and zero remaining routes |
| Diff | `git diff --check` |

`test/quic/datagram_test.exs` covers profile defaults/ALPN, codec/parameter
boundaries, directional negotiation, idempotent operations, consumer-only pulls,
event rearming and overflow drops. `test/quic/datagram_scheduler_test.exs` covers
authenticated wire-size enforcement, no DATAGRAM retransmission on loss/PTO,
PING probes, congestion bounds, packet/CID growth, and separate ACK scheduling.
The ACK/DATAGRAM regression was observed failing with `:packet_size_limit`
before the repair; the repaired tests decrypt both emitted frames and preserve
the queued payload under a single-send-slot limit.

## Release boundary

See [consumer-contract.md](consumer-contract.md) for API and resource semantics.
The broader experimental limitations in [phase1-acceptance.md](phase1-acceptance.md)
and the unfinished M6 gates still apply. The Phase 1 document records its original
scope; this increment supersedes only its statement that DATAGRAM is unsupported.
