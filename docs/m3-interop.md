# M3-E independent peer evidence (partial)

On 2026-09-24 both ordinary certificate-handshake directions passed against
**aioquic 1.2.0**, using Python 3.12.12 and Elixir 1.20.1 / OTP 29. The ALPN is
`ex-quic-test`. Certificate verification stays enabled with the disposable
`example.test` CA/leaf fixtures from the pinned ex_ssl dependency.

This is independent network handshake evidence for the two ordinary scenarios,
not completion of M3-E or a general QUIC support/security claim. A subsequent
client Retry scenario also passes as recorded below.

| Scenario | Result |
| --- | --- |
| ex_quic client → aioquic server | passed; TLS_AES_256_GCM_SHA384 (0x1302), server certificate authenticated, QUIC confirmed |
| aioquic client → ex_quic server | passed; TLS_AES_128_GCM_SHA256 (0x1301), peer Finished and QUIC confirmation; no client-certificate identity claimed |
| ex_quic client → aioquic Retry server | passed; integrity tag, token echo, preserved ClientHello, increasing packet numbers and authenticated Retry CID |
| aioquic client → ex_quic Retry server | passed; authenticated expiring address-bound token, both handshakes and QUIC confirmation |
| Independent Initial/Handshake loss, reorder, duplicates, corruption | not run; local self-connection loss tests are separate evidence |
| Independent wrong certificate / ALPN cases | not run; existing local negative tests are separate evidence |
| Independent ChaCha negotiation | not run; packet AEAD and RFC 8439 block/header-mask unit tests pass |

## Reproduction

From the repository root, with `uv` and the Mix dependencies available:

```sh
mix run scripts/interop/run.exs client _build/interop/client-final
mix run scripts/interop/run.exs server _build/interop/server-final
```

Both commands exited 0. The runner invokes:

```text
uv run --python 3.12 --with aioquic==1.2.0 python scripts/interop/peer.py ...
```

The exact resolved Python and aioquic versions are emitted into each result.
The aioquic version is fixed; transitive Python packages are not yet locked.
The runner requires both the independent peer's HandshakeCompleted event and
the local endpoint's established/confirmed state. It does not equate a UDP
send, TLS secret export or an open socket with handshake success.

Each run emits `result.json` and `udp.jsonl`. Successful baseline copies are
in `test/fixtures/interop/aioquic-1.2.0/`. Capture records contain exact raw UDP
payloads, peer socket addresses, monotonic timestamps and direction at the
Python transport boundary. They are **not kernel/pcap captures**. No traffic
secret or private key is logged. These are explicit test artifacts, not runtime
telemetry defaults. The captured source is the working tree introducing this
harness, based on parent `f35c8883ce7c96a1507543624769700a6d1484c7`.

## Defects exposed by the independent baseline

- Packet encryption/decryption ignored the installed AEAD and always called
  AES-128-GCM. The algorithm is now passed explicitly; Initial retains AES-128.
- NEW_CONNECTION_ID was an unknown frame, causing rejection of a packet also
  carrying HANDSHAKE_DONE. CID decoding, bounded peer CID state, consistency
  checks and retirement handling now preserve that confirmation path.
- Packet-number reconstruction preserved low epoch bits instead of high bits,
  producing wrong numbers across gaps/windows. Fixed expectations cover both.
- ChaCha header protection used the wrong OTP argument shape and IV order.
  The corrected primitive matches RFC 8439 section 2.3.2's fixed block prefix.

Remaining protocol lifecycle and resource edge cases from `m3-runtime.md` are
not waived by these two passing scenarios. M3-E remains open until its complete
independent network matrix passes.

Local gates on the final baseline increment: `mix format --check-formatted`,
`mix compile --warnings-as-errors`, `mix test` (97 tests, seed 531985), and
`git diff --check` all exited 0. Capture integrity digests are recorded in
`test/fixtures/interop/aioquic-1.2.0/SHA256SUMS`.

## Client Retry increment

```sh
INTEROP_SCENARIO=retry mix run scripts/interop/run.exs client _build/interop/client-retry-fixed
```

This command exited 0 on 2026-09-24 with aioquic 1.2.0 / Python 3.12.12 and
Elixir 1.20.1 / OTP 29. The result requires an observed Retry event in addition
to both peers completing their handshake. Captures/results are archived as
`client-retry-*` beside the ordinary baseline artifacts. Source parent:
`7b3986f27e832780cec8abe303fe20a72a06e78f`, with this Retry increment applied.

The independent test exposed an incorrect v1 Retry nonce. RFC 9001 Appendix
A.4 now supplies an independent fixed integrity vector rather than only a
locally generated round trip. Retry processing preserves original DCID and TLS
state, discards obsolete Initial recovery work without resetting packet-number
allocation, installs fresh Initial packet protection from the Retry SCID, and
echoes the token in the new Initial. Authenticated transport parameters must
match the Retry SCID; a Retry CID is forbidden when no Retry occurred.

The remaining independent impairment and negative-case matrix remains open.
Server-side Retry evidence follows below.

Retry increment local gates: format, warnings-as-errors compilation, all 100
ExUnit tests (seed 619226), and diff checks exited 0. Server Retry, independent
impairment and independent certificate/ALPN negatives were not run here.

## Server Retry increment

```sh
INTEROP_SCENARIO=retry mix run scripts/interop/run.exs server _build/interop/server-retry
```

Exited 0 on 2026-09-24 with aioquic 1.2.0 / Python 3.12.12 and
Elixir 1.20.1 / OTP 29. The aioquic client observed Retry and completed the
verified certificate handshake with ALPN `ex-quic-test`; the local server
reached established/confirmed with valid parameters and a validated address.
One Retry was sent and one token was admitted. Capture/results are archived
as `server-retry-*`, with SHA256SUMS. Source parent: `36bec72771de676213794ce278be4672bce691b8`,
with this server Retry increment applied.

Server endpoints opt in using `retry: true`. Tokens use an endpoint-generation
32-byte random HMAC key, bind the client IP/port, original DCID and Retry SCID,
and expire after `retry_ttl` monotonic microseconds (default 5,000,000; maximum
60,000,000). A restart invalidates them. Tokens are not single-use: retransmitted
Initials route to the existing connection; after connection removal a still-valid
token can admit another bounded connection from the same address. They prove
address reachability, not client identity.

`retry_limit` bounds issuance attempts per endpoint-wide one-second fixed window
(default 100, maximum 10,000); it is not a per-client fairness guarantee.
There is no per-peer token cache. A Retry response is smaller than the required
1200-byte incoming Initial. Nonempty invalid tokens are dropped without a new
Retry, and no connection is allocated before token validation. Original DCID
transport parameters remain separate from the Retry DCID used for Initial keys.

Unit tests mutate every token byte and cover expiry, future time, key replacement,
IPv4/IPv6, address/port/CID mismatch and bounded malformed inputs. UDP tests
cover pre-validation allocation, rate limiting, cross-address replay rejection,
duplicate routing and a real certificate handshake. Independent impairment and
certificate/ALPN negative scenarios are still pending; M3-E remains incomplete.

Server Retry local gates: `mix format --check-formatted`,
`mix compile --warnings-as-errors`, `mix test` (104 tests, seed 184043),
and `git diff --check` passed. The independent server Retry command exited 0.
