# ex_quic — experimental QUIC v1 library

This repository contains an incremental Elixir QUIC implementation and its revision 3 design. Independent certificate handshakes, Retry, single-fault packet impairment and certificate/ALPN rejection pass in both roles against aioquic 1.2.0. Full protocol lifecycle and product acceptance remain incomplete. It uses `ex_ssl` v0.7.1 at `02eb981f59d4e182d4473e264a9f8b093ec6bf3d` on 2026-09-23.

The project has three mandatory goals: JA3/JA4 observation of visible QUIC ClientHello data, measured profile-controlled client behavior, and opt-in integration with the Abyss UDP server. It is not a client-only plan.

## Start here

Use [CODEX-START.md](CODEX-START.md) in the actual ex_quic workspace. The first execution slice implements M0–M1: engineering/dependency contracts, wire codecs and Initial/Retry protection with tests. It does not claim that UDP networking is complete.

| Document | Purpose |
|---|---|
| [Implementation plan](docs/implement-plan.md) | Ordered M0–M6 tasks, dependencies and concrete exit gates |
| [Architecture](docs/architecture.md) / [Detailed design](docs/design.md) | Functional core, runtime ownership, routing, sending and resource constraints |
| [Actual TLS contract](docs/ex-ssl-quic-contract.md) | Existing public SSL.QUIC API, action order and limitations |
| [Fingerprint design](docs/fingerprint-design.md) | Observation, matching, simulation and fidelity evidence |
| [Abyss integration](docs/abyss-integration.md) | Opt-in pre-handler dispatch and shared-socket lifecycle |
| [Testing](docs/testing.md) / [PRD](docs/prd.md) | Requirements, independent oracles and experimental release acceptance |
| [ex_ssl review](docs/ex-ssl-review.md) | F1 closure and honest scope of current verification |
| [Revision changes](docs/revision-3.md) / [Sources](docs/sources.md) | Supersession rules and pinned evidence |

## Dependency and status

`SSL.QUIC` and `SSL.Fingerprint` are real upstream APIs at the reviewed pin, not work to invent in ex_quic. Use the Git SHA initially; a GitHub release does not establish Hex publication. See [implementation progress](docs/requirements-progress.md) and [runtime evidence](docs/m3-runtime.md) and [independent peer evidence](docs/m3-interop.md) and [M3-C through M3-E acceptance](docs/m3-acceptance.md) for implemented surfaces and remaining gates; design documents also include future modules.

The upstream formatter finding is closed and the inspected supported-runtime compiler/test and TLS-reference jobs pass. Current known upstream limitations, historical macOS TCP integration failures and the absence of a whole-library security audit remain explicit in the review document.

## Adopting this package

Copy/adapt these documents into the workspace while preserving local code and user changes. Replace active v1/v2 planning instructions; move older revisions to an explicitly historical archive rather than leaving conflicting prerequisites. Do not create a remote repository or modify ex_ssl/Abyss during the initial scoped task.

Local tests cover codecs, packet protection, inspection, recovery, and both-role UDP certificate handshakes. These self-connection tests are not independent interoperability or security certification. The full product gate requires observer + measured client profiles + Abyss termination; HTTP/3/QPACK and additional TLS features remain separate work.
