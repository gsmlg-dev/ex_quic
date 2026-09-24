# Implementation progress

This record tracks incremental work against `docs/implement-plan.md`; intermediate runtime tests do not complete the M3 independent-peer gate.

| Area | Current evidence | Status |
|---|---|---|
| Mix app and pinned ex_ssl dependency | `mix.exs`, `mix.lock`, SHA `02eb981f59d4e182d4473e264a9f8b093ec6bf3d` | implemented |
| Runtime ownership contracts | `QUIC.Runtime`, `QUIC.Error` | implemented, pure data contracts only |
| CI checks | `.github/workflows/ci.yml` | implemented |
| TLS public contract checks | `test/ex_ssl_contract_test.exs`; real both-role UDP certificate tests in `test/quic/endpoint_test.exs` | local tests pass; independent peer pending |
| QUIC varints/headers/packet numbers | `QUIC.Codec`, `test/quic/codec_test.exs` | implemented and passing |
| QUIC Initial protection | `QUIC.Protection`, `test/quic/protection_test.exs` | implemented and passing RFC9001 vector checks |
| Bounded Initial inspector | `QUIC.Inspector`, `test/quic/inspector_test.exs` | partial M2: encrypted fixture, fingerprint event, bounded contexts and passive path implemented |
| Transport parameters | `QUIC.TransportParameters`, authenticated parameter/CID readiness checks in `QUIC.Connection` | basic v1 semantic validation implemented |
| UDP runtime | `QUIC.Connection`, `QUIC.Endpoint`, `QUIC.IO.GenUDP`; lifecycle, ACK/PTO, Initial/Handshake loss tests | experimental M3-D runtime; M3-E remains open |
| Initial inspector / fingerprint replay | pinned independent aioquic 1.2.0 Initial replay, duplicate suppression, incomplete completion, expiry/conflict checks and two-ClientHello ordinal lifecycle tests pass; independent HRR peer replay remains pending | M2 |

The endpoint runtime is available for controlled local testing. No independent network-handshake support claim is made before M3-E. Streams, profiles, Abyss integration and full protocol lifecycle acceptance remain later milestones. See [runtime evidence and limits](m3-runtime.md).
