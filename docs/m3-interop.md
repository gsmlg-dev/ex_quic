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
| ex_quic Retry server → aioquic client | not run; authenticated expiring server-token policy still pending |
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

Server-side token issuance/validation and the remaining independent impairment
and negative-case matrix remain open.

Retry increment local gates: format, warnings-as-errors compilation, all 100
ExUnit tests (seed 619226), and diff checks exited 0. Server Retry, independent
impairment and independent certificate/ALPN negatives were not run here.
