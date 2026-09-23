# M0/M1 implementation progress

This record tracks the first execution slice from `docs/implement-plan.md`.

| Area | Current evidence | Status |
|---|---|---|
| Mix app and pinned ex_ssl dependency | `mix.exs`, `mix.lock`, SHA `02eb981f59d4e182d4473e264a9f8b093ec6bf3d` | implemented |
| Runtime ownership contracts | `QUIC.Runtime`, `QUIC.Error` | implemented, pure data contracts only |
| CI checks | `.github/workflows/ci.yml` | implemented |
| TLS public contract checks | `test/ex_ssl_contract_test.exs` | implemented and passing (13-test suite) |
| QUIC varints/headers/packet numbers | `QUIC.Codec`, `test/quic/codec_test.exs` | implemented and passing |
| QUIC Initial protection | `QUIC.Protection`, `test/quic/protection_test.exs` | implemented and passing RFC9001 vector checks |
| Transport parameters | no implementation yet | M1 remainder |
| UDP networking / endpoint | intentionally unavailable | M2/M3 |
| Initial inspector / fingerprint replay | intentionally unavailable | M2 |

The first slice does not claim a usable network client or server. Public network
operations remain unavailable until the transport and recovery milestones pass.
