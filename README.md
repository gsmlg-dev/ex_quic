# elixir_quic — experimental QUIC v1 library

[![GitHub Release](https://img.shields.io/github/v/release/gsmlg-dev/ex_quic)](https://github.com/gsmlg-dev/ex_quic/releases)
[![Hex.pm](https://img.shields.io/hexpm/v/elixir_quic.svg)](https://hex.pm/packages/elixir_quic)
[![CI](https://github.com/gsmlg-dev/ex_quic/actions/workflows/ci.yml/badge.svg)](https://github.com/gsmlg-dev/ex_quic/actions/workflows/ci.yml)
[![Test](https://github.com/gsmlg-dev/ex_quic/actions/workflows/test.yml/badge.svg)](https://github.com/gsmlg-dev/ex_quic/actions/workflows/test.yml)
[![Release](https://github.com/gsmlg-dev/ex_quic/actions/workflows/release.yml/badge.svg)](https://github.com/gsmlg-dev/ex_quic/actions/workflows/release.yml)
[![E2E](https://github.com/gsmlg-dev/ex_quic/actions/workflows/e2e.yml/badge.svg)](https://github.com/gsmlg-dev/ex_quic/actions/workflows/e2e.yml)

This repository contains an incremental Elixir QUIC implementation and its revision 3 design. Independent certificate handshakes, Retry, single-fault packet impairment and certificate/ALPN rejection pass in both roles against aioquic 1.2.0. Full protocol lifecycle and product acceptance remain incomplete. The Phase 1 reliable-stream implementation uses the exact Hex dependency `ex_ssl 0.7.2`, whose packaged production source matches the accepted G-S commit `f1327e0bb7fb2093b8dc2b07e72b26233a739963`. See the [Phase 1 acceptance record](docs/phase1-acceptance.md) for current gates, exact evidence and limitations.

The project has three mandatory goals: JA3/JA4 observation of visible QUIC ClientHello data, measured profile-controlled client behavior, and opt-in integration with the Abyss UDP server. It is not a client-only plan.

## Start here

Use [CODEX-START.md](CODEX-START.md) in the actual ex_quic workspace. The first execution slice implements M0–M1: engineering/dependency contracts, wire codecs and Initial/Retry protection with tests. It does not claim that UDP networking is complete.

| Document | Purpose |
|---|---|
| [Phase 1 plan](docs/phase1-implement-plan.md) / [Consumer API](docs/consumer-contract.md) / [I/O contract](docs/io-contract.md) | Reliable streams, public handles, admission outcomes and integration ownership |
| [Implementation plan](docs/implement-plan.md) | Ordered M0–M6 tasks, dependencies and concrete exit gates |
| [Architecture](docs/architecture.md) / [Detailed design](docs/design.md) | Functional core, runtime ownership, routing, sending and resource constraints |
| [Actual TLS contract](docs/ex-ssl-quic-contract.md) | Existing public SSL.QUIC API, action order and limitations |
| [Fingerprint design](docs/fingerprint-design.md) | Observation, matching, simulation and fidelity evidence |
| [Abyss integration](docs/abyss-integration.md) | Opt-in pre-handler dispatch and shared-socket lifecycle |
| [Testing](docs/testing.md) / [PRD](docs/prd.md) | Requirements, independent oracles and experimental release acceptance |
| [ex_ssl review](docs/ex-ssl-review.md) | F1 closure and honest scope of current verification |
| [Revision changes](docs/revision-3.md) / [Sources](docs/sources.md) | Supersession rules and pinned evidence |

## Dependency and status

`SSL.QUIC` and `SSL.Fingerprint` are real upstream APIs at the reviewed pin, not work to invent in ex_quic. The dependency is now resolved from Hex; its immutable source comparison and lockfile checksums are recorded in the [TLS contract](docs/ex-ssl-quic-contract.md). See [implementation progress](docs/requirements-progress.md) and [runtime evidence](docs/m3-runtime.md) and [independent peer evidence](docs/m3-interop.md) and [M3-C through M3-E acceptance](docs/m3-acceptance.md) for implemented surfaces and remaining gates; design documents also include future modules.

The upstream formatter finding is closed and the inspected supported-runtime compiler/test and TLS-reference jobs pass. Current known upstream limitations, historical macOS TCP integration failures and the absence of a whole-library security audit remain explicit in the review document.

## Adopting this package

The Hex package and OTP application are `elixir_quic` / `:elixir_quic`.
The GitHub repository remains `gsmlg-dev/ex_quic`; the public module namespace is `Quic`.
Starting with the first Hex release, depend on:

```elixir
{:elixir_quic, "~> 0.2.2"}
```

Consumers moving from the Git dependency must replace their `:ex_quic`
dependency/application entry with `:elixir_quic`, including application config
or release configuration that names the old app. Rename calls and aliases from
`QUIC` / `QUIC.*` to `Quic` / `Quic.*`; function names and arguments are unchanged.
The unrelated Hex package named `ex_quic` is not this library.

Copy/adapt these documents into the workspace while preserving local code and user changes. Replace active v1/v2 planning instructions; move older revisions to an explicitly historical archive rather than leaving conflicting prerequisites. Do not create a remote repository or modify ex_ssl/Abyss during the initial scoped task.

Local tests cover codecs, packet protection, inspection, recovery, and both-role UDP certificate handshakes. These self-connection tests are not independent interoperability or security certification. The full product gate requires observer + measured client profiles + Abyss termination; HTTP/3/QPACK and additional TLS features remain separate work.


## Publishing

The manual `Release` GitHub Actions workflow validates the source, builds the
Hex package, pushes the verified version commit/tag, publishes it with
`mix hex.publish package --yes`, and creates a GitHub release with the package
attached. A failed publication can be resumed with the same version and branch;
the existing tag is reused, and an existing Hex version is accepted only when
its checksum matches the built archive.
Configure the repository or organization Actions secret `HEX_API_KEY` with Hex
publish permission for `elixir_quic` before dispatching. Missing credentials fail
before any version commit, tag or publication. HexDocs publication is separate;
this workflow publishes the package only.

For the next release, use `version=0.2.2` and `git_ref=main`. Existing `v0.2.1`
and earlier tags remain source-only releases; this change does not republish them.
Validate packaging locally without publishing:

```sh
mix hex.build --output _build/elixir_quic.tar
```

## License

MIT. See [LICENSE](LICENSE). Copied test-only TLS fixtures retain their upstream
Apache-2.0 license in `test/fixtures/tls/LICENSE` and are excluded from the Hex package.
