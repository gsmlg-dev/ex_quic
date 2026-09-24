# M5 Abyss acceptance evidence

The Abyss dispatcher seam is at `gsmlg-dev/abyss@ace6cce`; the external
endpoint and dependency-free adapter are at `ex_quic@9a0308e`.

The real UDP smoke command and its scope are recorded here. It uses a concrete
loopback bind, keeps Abyss as the shared socket owner, routes through the
external `QUIC.Endpoint`, and sends through the dispatcher writer.

```sh
ABYSS_CHECKOUT=/Users/gao/Workspace/gsmlg-dev/ex_quic/.trees/abyss-m5 \
  mix run scripts/interop/abyss_m5.exs
```

Observed result: exit `0`, client phase `:established`, QUIC confirmation true,
one client route, and no admission or endpoint error. This is the first real
QUIC-through-Abyss handshake evidence. Multi-client isolation, stream transfer,
close-one/keep-other, listener restart, writer failure, and ordinary UDP
regression remain open M5 acceptance cells.
