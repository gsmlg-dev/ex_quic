#!/usr/bin/env python3
"""Pinned independent QUIC peer. Never disables certificate verification.

Capture JSONL records exact UDP payloads at the transport boundary, not TLS
secrets. Addresses and monotonic times identify each direction. This is not a
kernel/pcap capture and includes packets before decryption.
"""
import argparse
import asyncio
import base64
import json
import sys
import time

import aioquic
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.asyncio.server import QuicServer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted, ConnectionTerminated


def emit(**fields):
    print(json.dumps(fields), flush=True)


class Capture:
    def __init__(self, path):
        self.file = open(path, "w")

    def packet(self, direction, data, peer):
        if data and data[0] & 0xF0 == 0xF0:
            emit(event="retry", direction=direction)
        self.file.write(json.dumps(dict(time_ns=time.monotonic_ns(), direction=direction,
            peer=peer, payload=base64.b64encode(data).decode())) + "\n")
        self.file.flush()


class Transport:
    def __init__(self, transport, capture):
        self.transport, self.capture = transport, capture

    def sendto(self, data, addr=None):
        self.capture.packet("send", data, addr)
        return self.transport.sendto(data, addr)

    def __getattr__(self, name):
        return getattr(self.transport, name)


class Peer(QuicConnectionProtocol):
    def __init__(self, *args, capture=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.capture = capture

    def connection_made(self, transport):
        super().connection_made(Transport(transport, self.capture) if self.capture else transport)

    def datagram_received(self, data, addr):
        if self.capture:
            self.capture.packet("receive", data, addr)
        super().datagram_received(data, addr)

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            emit(event="handshake_complete", alpn=event.alpn_protocol)
        elif isinstance(event, ConnectionTerminated):
            emit(event="terminated", error_code=event.error_code, reason=event.reason_phrase)
        super().quic_event_received(event)


class Server(QuicServer):
    def __init__(self, *args, capture, **kwargs):
        super().__init__(*args, **kwargs)
        self.capture = capture

    def connection_made(self, transport):
        super().connection_made(Transport(transport, self.capture))

    def datagram_received(self, data, addr):
        self.capture.packet("receive", data, addr)
        super().datagram_received(data, addr)


async def main(args):
    emit(event="version", aioquic=aioquic.__version__, python=sys.version.split()[0])
    capture = Capture(args.capture)
    config = QuicConfiguration(is_client=args.mode == "client", alpn_protocols=[args.alpn])
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    loop.add_reader(sys.stdin.fileno(), lambda: (sys.stdin.readline(), stop.set()))
    loop.call_later(args.timeout, stop.set)
    if args.mode == "server":
        config.load_cert_chain(args.cert, args.key)
        transport, server = await loop.create_datagram_endpoint(
            lambda: Server(configuration=config, create_protocol=Peer,
                           retry=args.retry, capture=capture),
            local_addr=("127.0.0.1", args.port))
        emit(event="listening", port=transport.get_extra_info("sockname")[1])
        await stop.wait()
        server.close()
    else:
        config.server_name = args.hostname
        config.load_verify_locations(cafile=args.ca)
        async with connect("127.0.0.1", args.port, configuration=config,
                           create_protocol=lambda *a, **kw: Peer(*a, capture=capture, **kw),
                           wait_connected=False) as peer:
            peer.transmit()
            emit(event="started")
            await stop.wait()
    capture.file.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["client", "server"], required=True)
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--cert")
    parser.add_argument("--key")
    parser.add_argument("--ca")
    parser.add_argument("--hostname", default="example.test")
    parser.add_argument("--alpn", default="ex-quic-test")
    parser.add_argument("--retry", action="store_true")
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--capture", required=True)
    asyncio.run(main(parser.parse_args()))
