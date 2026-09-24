# Implementation progress

This record tracks incremental work against `docs/implement-plan.md`; intermediate runtime tests do not complete the M3 independent-peer gate.

| Area | Current evidence | Status |
|---|---|---|
| Mix app and pinned ex_ssl dependency | `mix.exs`, `mix.lock`, SHA `02eb981f59d4e182d4473e264a9f8b093ec6bf3d` | implemented |
| Runtime ownership contracts | `QUIC.Runtime`, `QUIC.Error` | implemented, pure data contracts only |
| CI checks | `.github/workflows/ci.yml` | implemented |
| TLS public contract checks | `test/ex_ssl_contract_test.exs`; real both-role UDP certificate tests in `test/quic/endpoint_test.exs` | local tests and independent aioquic both-role handshakes pass |
| QUIC varints/headers/packet numbers | `QUIC.Codec`, `test/quic/codec_test.exs` | implemented and passing |
| QUIC Initial protection | `QUIC.Protection`, `test/quic/protection_test.exs` | implemented and passing RFC9001 vector checks |
| Strict packet/frame validation | `QUIC.Codec.validate_frame_levels/2`, authenticated header/CID checks in `QUIC.HandshakeScheduler`, focused codec/scheduler tests | implemented; 121-test local gate passes; invalid transport-parameter and corrupted-Finished network cases remain pending |
| Bounded Initial inspector | `QUIC.Inspector`, `test/quic/inspector_test.exs` | partial M2: encrypted fixture, fingerprint event, bounded contexts and passive path implemented |
| Transport parameters | `QUIC.TransportParameters`, authenticated parameter/CID readiness checks in `QUIC.Connection` | basic v1 semantic validation implemented |
| UDP runtime | `QUIC.Connection`, `QUIC.Endpoint`, `QUIC.IO.GenUDP`; lifecycle, ACK/PTO, Initial/Handshake loss tests | experimental M3-D runtime; requested M3-E matrix passes |
| M3-C packet keys and protected handshake packets | Recorded Secret actions, independent OTP packet oracle, authenticated level/space errors, retained CRYPTO and fresh-number retransmission | requested C.1/C.2/C.3 checks pass |
| Handshake key retirement | Role-specific receipt/confirmation triggers; bounded buffer/history cleanup; late-event tests; all 20 prior network cases plus both-role HANDSHAKE_DONE loss | implemented; [evidence](m3-key-retirement.md) |
| Large CRYPTO and recovery bounds | Actual protected-packet-size fragmentation, contiguous CRYPTO offsets, fresh packet numbers, PTO/loss boundaries and terminal sent-history reclamation | focused 30-test scheduler/recovery checks and full 124-test local gate pass; independent large-flight network impairment remains pending |
| Connection lifecycle | Idle timeout, closing/draining states, generation-checked timers, old-CID routing retention and terminal route cleanup | focused lifecycle tests and full 127-test local gate pass; independent lifecycle network validation remains pending |
| M4 reliable streams | Connection-owned bounded stream state, application STREAM/control frame codecs, flow-control admission and protected scheduler dispatch | focused stream/codec/scheduler checks and full 133-test local gate pass; independent multi-stream network transfer remains pending |
| M4 backpressure and profiles | Bounded send/receive admission, manual delivery limits, two capability-checked legal WireProfile policies with fresh materialization | focused profile/stream checks and full 138-test local gate pass; independent peer wire/profile comparison remains pending |
| M3-E independent handshake matrix | aioquic 1.2.0; both roles, Retry, Initial/Handshake loss, reorder, duplicate, corruption, wrong CA/hostname/ALPN; archived UDP bytes and results | requested matrix passes; not full QUIC conformance |
| Initial inspector / fingerprint replay | pinned independent aioquic 1.2.0 Initial replay, duplicate suppression, incomplete completion, expiry/conflict checks and two-ClientHello ordinal lifecycle tests pass; independent HRR peer replay remains pending | M2 |

The endpoint runtime supports the controlled independent network-handshake scenarios in [M3 acceptance](m3-acceptance.md). Streams, profiles, Abyss integration and full protocol lifecycle acceptance remain later milestones. See [runtime evidence and limits](m3-runtime.md).
