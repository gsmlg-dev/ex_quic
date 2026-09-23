# AGENTS.md — ex_quic

## Mission and active documents

Implement an independent Elixir QUIC v1 library: app `:ex_quic`, public namespace `QUIC`. Required products are Initial fingerprint observation, profile-controlled clients and an Abyss-hosted server. Read `CODEX-START.md`, `docs/implement-plan.md`, `docs/architecture.md` and the TLS/Abyss/testing contracts before changes.

This is revision 3. Earlier proposed ex_ssl export APIs are superseded by the actual reviewed v0.7.1 interface. Preserve existing local code/user changes; do not reset a workspace to a planning snapshot.

## Dependency direction

`abyss -> ex_quic -> ex_ssl`. QUIC never imports Abyss modules. Use the full upstream SHA in `docs/ex-ssl-quic-contract.md`; verify any deliberate upgrade. Use only public TLS/fingerprint/profile interfaces in production. Do not copy TLS coordination/transcript/PKIX logic, use OTP :ssl as implementation, or add a native QUIC backend without a separately authorized architecture change.

## Functional architecture

Pure transport transformations use explicit events/time and return state plus effects. Socket/clock/entropy/TLS/telemetry execution lives at the runtime boundary. The actual TLS provider owns fresh entropy and authentication checks, so do not assert strict determinism for real TLS calls.

One temporary :gen_statem owns each connection's current protocol/TLS state. Streams/ranges are data, not mandatory processes. Avoid per-packet processes, unbounded async mailboxes, arbitrary peer-created atoms and macros that hide state transitions.

## Protocol invariants

Never conflate UDP datagrams, QUIC packets, frames, TLS messages or application stream items. Keep packet-number spaces, CRYPTO levels/offsets and stream offsets separate. Bound all peer-driven lengths/counts before allocation/work. Preserve exact handshake bytes; normalization belongs only to fingerprint projections.

Process upstream TLS actions in order. Retain emitted CRYPTO bytes for retransmission without another TLS call. Initial/packet/header-protection keys belong to QUIC; TLS record keys and TLS KeyUpdate do not. Track TLS completion, parameter semantic validity, address validation and QUIC confirmation separately.

A reserved packet number is not recycled. Queue admission is not local-send success; local-send success is not peer ACK. Actual receipts and stale timer/endpoint generations need explicit tests. Congestion/recovery and anti-amplification are correctness requirements, not optional late optimizations.

## Profiles and observations

Use `SSL.Fingerprint` on actual ClientHello bytes, with `:quic` provenance. Do not return configured hashes as observed results. Fingerprint matches are candidate observations, not authentication. Keep unknown/GREASE/raw order in observation; use the analyzer's normalization only for projections.

Profiles describe legal supported behavior. Fresh keys/randomness are never reusable profile data. Unsupported capabilities fail explicitly. Do not label a profile as a complete browser implementation or claim HTTP/3 solely from ALPN. ECH visibility is outer-only unless a separately implemented feature demonstrates otherwise.

Inspect-only code cannot transmit ACKs, Retry, close frames or any other packets. Bound incomplete contexts, bytes, ranges and lifetimes. Raw captures/secrets are not default telemetry.

## Abyss

Abyss retains shared socket ownership. The opt-in dispatcher precedes legacy per-datagram handler creation; connections are CID-routed and persistent. Preserve default ordinary UDP behavior. Egress cannot depend on a call to a blocked receive loop. No cross-repository edits in a task scoped only to ex_quic.

## Verification and reporting

Use standards and independent vectors, differential network tests and deterministic engine tests. Self-connection is not independent interop; TLS-only tests are not network QUIC. Preserve required tests and explicit failure semantics. Never hide failures with retries, weakened assertions or disabled checks.

Record actual commands/runtime/seed/exit status and not-run checks. Do not claim all milestones implemented from scaffolding or unit tests. The experimental acceptance gate is not a production-security audit. No secret/private-key logging or physical BEAM zeroization claims.

## Change control

Keep changes small, functional and typed. Do not automatically create remotes, commit, push, publish, change tags or edit upstream repositories without current explicit authorization. Historical release notes do not grant new task permissions.
