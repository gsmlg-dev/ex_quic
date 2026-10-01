# elixir_quic — experimental QUIC v1 library

[![GitHub Release](https://img.shields.io/github/v/release/gsmlg-dev/ex_quic)](https://github.com/gsmlg-dev/ex_quic/releases)
[![Hex.pm](https://img.shields.io/hexpm/v/elixir_quic.svg)](https://hex.pm/packages/elixir_quic)
[![CI](https://github.com/gsmlg-dev/ex_quic/actions/workflows/ci.yml/badge.svg)](https://github.com/gsmlg-dev/ex_quic/actions/workflows/ci.yml)
[![Test](https://github.com/gsmlg-dev/ex_quic/actions/workflows/test.yml/badge.svg)](https://github.com/gsmlg-dev/ex_quic/actions/workflows/test.yml)
[![Release](https://github.com/gsmlg-dev/ex_quic/actions/workflows/release.yml/badge.svg)](https://github.com/gsmlg-dev/ex_quic/actions/workflows/release.yml)
[![E2E](https://github.com/gsmlg-dev/ex_quic/actions/workflows/e2e.yml/badge.svg)](https://github.com/gsmlg-dev/ex_quic/actions/workflows/e2e.yml)

This repository is an Elixir umbrella containing an incremental QUIC implementation, its TLS provider, and an experimental HTTP/3 companion. Independent certificate handshakes, Retry, single-fault packet impairment and certificate/ALPN rejection passed in both QUIC roles against aioquic 1.2.0 before the umbrella conversion. Full protocol lifecycle and product acceptance remain incomplete. The QUIC app now uses sibling `ex_ssl 0.7.2` source imported from upstream commit `fb47051355c9d0a29caee046fa060a745ad0ce5b`; the prior Hex package comparison against accepted G-S commit `f1327e0bb7fb2093b8dc2b07e72b26233a739963` remains historical evidence. See the [Phase 1 acceptance record](docs/phase1-acceptance.md) for gates, exact evidence and limitations.

The project has three mandatory goals: JA3/JA4 observation of visible QUIC ClientHello data, measured profile-controlled client behavior, and opt-in integration with the Abyss UDP server. It is not a client-only plan.

## Start here

[CODEX-START.md](CODEX-START.md) records the original M0–M1 execution slice: engineering/dependency contracts, wire codecs and Initial/Retry protection with tests. Current implementation status is tracked in the acceptance records below.

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

## Umbrella layout and commands

| Path | OTP app | Purpose |
|---|---|---|
| `apps/elixir_quic` | `:elixir_quic` (v0.3.0) | QUIC transport and public `Quic` namespace |
| `apps/ex_ssl` | `:ex_ssl` (v0.7.2) | Imported TLS provider source |
| `apps/elixir_quic_http3` | `:elixir_quic_http3` (v0.16.0) | Imported experimental `QuicHttp3` companion; inclusion does not establish complete HTTP/3 support |

From the repository root, `mix deps.get`, `mix format --check-formatted`, `mix compile --warnings-as-errors`, and `mix test` cover the umbrella. Run one app's tests with `mix test apps/elixir_quic/test/`, `mix test apps/ex_ssl/test/`, or `mix test apps/elixir_quic_http3/test/`. The HTTP/3 scoped run passed 30 tests, and the full umbrella suite passed. Root `scripts/` and their `mix run scripts/...` commands remain at the repository root; QUIC test fixtures live under `apps/elixir_quic/test/fixtures/`. The apps share root `_build`, `deps`, `mix.lock`, and `config`.

For local development, the root Mix project sets explicit path and environment overrides for `ex_ssl` and `elixir_quic` to resolve the dependencies used by `http_core`. Mix currently reports duplicate top-level dependency warnings for those apps; these have appeared even when `mix compile --warnings-as-errors` exits successfully.

The CI, Test, and E2E workflows select jobs from directly changed app paths. Root QUIC interop scripts select `elixir_quic`; shared Mix/configuration and workflow selection files select all apps. Changes to unrelated documentation skip the expensive jobs. Each app runs in its own job and executes only its own checks or tests; Mix still compiles the selected app's dependencies. To reproduce a CI test locally, set `EX_QUIC_CI_APP` to `ex_ssl`, `elixir_quic`, or `elixir_quic_http3` and run `mix test apps/$EX_QUIC_CI_APP/test` from the root. Without this variable, the root Mix project keeps its normal full-umbrella behavior.

E2E runs automatically for affected apps on `main` pushes and pull requests. Manual E2E dispatch accepts one app or all apps, with an optional release version. Older single-app QUIC tags can run the QUIC checks; SSL and HTTP/3 require tags containing the modular app sources and workflow support. The SSL job checks its independent QUIC-TLS reference and CI-hosted Caddy fingerprint fixture, the QUIC job runs the existing network interop scripts, and the HTTP/3 job checks its transport adapter over local UDP. The HTTP/3 smoke check does not establish full external HTTP/3 interoperability.

To build the `elixir_quic` Hex archive without publishing, run:

```sh
mkdir -p _build
(cd apps/elixir_quic && mix hex.build --output ../../_build/elixir_quic.tar)
```

The HTTP/3 companion was imported from `gsmlg-dev/http_fetch` at `647ca64ce4aa2818030b036ef6f9df99e8e914ac` (`apps/elixir_quic_http3` in that source repository). It uses the external Hex dependency `http_core 0.16.0`; `elixir_quic` and `ex_ssl` are local umbrella siblings. The shared-version release is currently blocked by [http_fetch#16](https://github.com/gsmlg-dev/http_fetch/issues/16): `http_core 0.16.0` requires incompatible versions of the two sibling packages.

## Dependency and status

`SSL.QUIC` and `SSL.Fingerprint` are real upstream APIs. `apps/ex_ssl` is now an umbrella sibling; its source provenance and historical Hex comparison are recorded in the [TLS contract](docs/ex-ssl-quic-contract.md). See [implementation progress](docs/requirements-progress.md) and [runtime evidence](docs/m3-runtime.md) and [independent peer evidence](docs/m3-interop.md) and [M3-C through M3-E acceptance](docs/m3-acceptance.md) for implemented surfaces and remaining gates; design documents also include future modules.

The upstream formatter finding is closed and the inspected supported-runtime compiler/test and TLS-reference jobs pass. Current known upstream limitations, historical macOS TCP integration failures and the absence of a whole-library security audit remain explicit in the review document.

## Adopting this package

The Hex package and OTP application are `elixir_quic` / `:elixir_quic`.
The GitHub repository remains `gsmlg-dev/ex_quic`; the public module namespace is `Quic`.
Starting with the first Hex release, depend on:

```elixir
{:elixir_quic, "~> 0.3.0"}
```

Consumers moving from the Git dependency must replace their `:ex_quic`
dependency/application entry with `:elixir_quic`, including application config
or release configuration that names the old app. Rename calls and aliases from
`QUIC` / `QUIC.*` to `Quic` / `Quic.*`; function names and arguments are unchanged.
The unrelated Hex package named `ex_quic` is not this library.

Local tests cover codecs, packet protection, inspection, recovery, and both-role UDP certificate handshakes. These self-connection tests are not independent interoperability or security certification. The full product gate requires observer + measured client profiles + Abyss termination; HTTP/3/QPACK and additional TLS features remain separate work.


## Application ALPN and unreliable datagrams

Profiles accept application ALPN, for example
`Quic.Profile.compile(:ordered, alpn: ["h3"])`; the default remains `ex-quic`.
Negotiating `h3` does not implement HTTP/3 or QPACK. Consumers own those protocols.

RFC 9221 DATAGRAM support is opt-in per endpoint with
`datagram: [max_frame_size: 1200, max_items: 64, max_buffer_bytes: 65_536]`.
Use `Quic.send_datagram/3` and `Quic.read_datagrams/3` with a public connection
handle. DATAGRAM payloads are unreliable, message-oriented, congestion-controlled,
and never retransmitted after loss. See the [consumer contract](docs/consumer-contract.md)
for negotiation, size limits, bounded queues and admission semantics.

## Publishing

The manual `Release` GitHub Actions workflow assigns one version to the umbrella
and all three packages, validates external dependency requirements, tests the
source, and builds three Hex archives. It checks existing Hex releases and
GitHub release assets before pushing the version commit/tag, then publishes
`ex_ssl`, `elixir_quic`, and `elixir_quic_http3` in dependency order. Each
package is verified against its archive checksum before the GitHub release is
created with all three archives.
A failed publication can be resumed with the same version and branch from the
immutable tag; matching published packages are skipped. Existing GitHub assets
must also match before missing assets are uploaded. Hex publication across three
packages is not atomic.
Configure the repository or organization Actions secret `HEX_API_KEY` with Hex
publish permission for all three packages before dispatching. Missing credentials fail
before any version commit, tag or publication. HexDocs publication is separate;
this workflow publishes the packages only.

Dispatch with the intended new version and `git_ref=main` after http_fetch#16 is
resolved and the updated `http_core` version is locked here. Older single-package
tags cannot be resumed as shared-version releases; they are not republished.
Validate packaging locally with the child-app command above.

## License

MIT. See [LICENSE](LICENSE). Copied test-only TLS fixtures retain their upstream
Apache-2.0 license in `apps/elixir_quic/test/fixtures/tls/LICENSE` and are excluded from the Hex package.
