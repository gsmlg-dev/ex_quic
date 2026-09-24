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
from aioquic.buffer import Buffer
from aioquic.quic.packet import pull_quic_header, QuicPacketType
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.asyncio.server import QuicServer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted, ConnectionTerminated


def emit(**fields):
    print(json.dumps(fields), flush=True)


class Capture:
    def __init__(self, path, mode, scenario):
        self.file = open(path, "w")
        self.mode, self.scenario = mode, scenario
        self.applied = False
        self.held = None
        self.hold_timer = None

    def route(self, direction, data, addr, deliver):
        self.packet(direction, data, addr)
        if self.held and direction == self.held[0]:
            _, old, old_addr, old_deliver = self.held
            self.held = None
            self.hold_timer.cancel()
            self.output(direction, data, addr, deliver)
            self.output(direction, old, old_addr, old_deliver)
            emit(event="impairment", action="reorder", direction=direction)
            return
        sender = self.mode if direction == "send" else ("client" if self.mode == "server" else "server")
        packets = []
        try:
            buf = Buffer(data=data)
            while not buf.eof():
                start = buf.tell()
                header = pull_quic_header(buf, host_cid_length=8)
                end = start + header.packet_length
                packets.append((header.packet_type, end))
                buf.seek(end)
        except ValueError:
            pass
        initial = sender == "client" and any(t == QuicPacketType.INITIAL for t, _ in packets)
        handshake = sender == "server" and any(t == QuicPacketType.HANDSHAKE for t, _ in packets)
        target = initial if self.scenario == "drop_initial" else handshake
        if not self.applied and target and self.scenario != "baseline":
            self.applied = True
            action = self.scenario
            if action == "reorder":
                self.held = (direction, data, addr, deliver)
                self.hold_timer = asyncio.get_running_loop().call_later(1.0, self.release)
                return
            emit(event="impairment", action=action, direction=direction,
                 packet_types=[t.name for t, _ in packets])
            if action in ("drop_initial", "drop_handshake"):
                return
            if action == "duplicate":
                self.output(direction, data, addr, deliver)
            if action == "corrupt":
                end = next(end for t, end in packets if t == QuicPacketType.HANDSHAKE)
                data = data[:end-1] + bytes([data[end-1] ^ 1]) + data[end:]
        self.output(direction, data, addr, deliver)

    def output(self, direction, data, addr, deliver):
        self.packet("wire_send" if direction == "send" else "protocol_receive", data, addr)
        deliver(data, addr)

    def release(self):
        if self.held:
            direction, data, addr, deliver = self.held
            self.held = None
            emit(event="reorder_timeout", direction=direction)
            self.output(direction, data, addr, deliver)

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
        return self.capture.route("send", data, addr, self.transport.sendto)

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
            self.capture.route("receive", data, addr, super().datagram_received)
        else:
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
        self.capture.route("receive", data, addr, super().datagram_received)


async def main(args):
    emit(event="version", aioquic=aioquic.__version__, python=sys.version.split()[0])
    capture = Capture(args.capture, args.mode, args.scenario)
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
    parser.add_argument("--scenario", default="baseline", choices=["baseline", "drop_initial", "drop_handshake", "reorder", "duplicate", "corrupt"])
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--capture", required=True)
    asyncio.run(main(parser.parse_args()))
