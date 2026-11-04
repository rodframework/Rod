#!/usr/bin/env python3
"""The bridge acceptance candidate: a per-peer byte pipe (ADR-025).

Python standard library only -- the point is that a listener package ships
in any language. The medium is HTTP: every request's body crosses to the
kernel over the bridge's route-forward carriage, and the answer carries
back as the response. The process parses no rod.v1 grammar, holds no
engagement key, and learns no implant identity; the kernel routes by
path, the bytes are opaque here.
"""

import json
import os
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BRIDGE_SOCKET = os.environ["ROD_BRIDGE_SOCKET"]
PARAMS = json.loads(os.environ.get("ROD_LISTENER_PARAMS") or "{}")

# The carriage byte and method codes of the route-forward contract.
ROUTE_CARRIAGE = 0x52  # 'R'
METHOD_GET = 0
METHOD_POST = 1


def write_varint(value):
    out = bytearray()
    while value >= 0x80:
        out.append((value | 0x80) & 0xFF)
        value >>= 7
    out.append(value)
    return bytes(out)


def read_varint(stream):
    length = 0
    shift = 0
    while True:
        byte = stream.recv(1)
        if not byte:
            raise EOFError("bridge closed mid-varint")
        length |= (byte[0] & 0x7F) << shift
        if not (byte[0] & 0x80):
            return length
        shift += 7
        if shift > 28:
            raise EOFError("malformed varint")


def read_exact(stream, count):
    buffer = bytearray()
    while len(buffer) < count:
        chunk = stream.recv(count - len(buffer))
        if not chunk:
            raise EOFError("bridge closed mid-message")
        buffer.extend(chunk)
    return bytes(buffer)


def encode_string(value):
    encoded = value.encode("utf-8")
    return write_varint(len(encoded)) + encoded


def decode_varint_from(buffer, offset):
    value = 0
    shift = 0
    while True:
        if offset >= len(buffer):
            raise EOFError("truncated varint")
        byte = buffer[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return value, offset
        shift += 7
        if shift > 28:
            raise EOFError("malformed varint")


def decode_string(buffer, offset):
    length, offset = decode_varint_from(buffer, offset)
    if offset + length > len(buffer):
        raise EOFError("truncated string")
    return buffer[offset : offset + length].decode("utf-8"), offset + length


def forward(method, path, peer, user_agent, body):
    """One route-forward exchange: dial the bridge, say 'R', send the
    request unit, read the answer unit, close. One request, one
    connection -- the byte pipe reconnects per medium peer."""
    unit = (
        bytes([method])
        + encode_string(path)
        + encode_string(peer)
        + encode_string(user_agent)
        + body
    )
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as bridge:
        bridge.connect(BRIDGE_SOCKET)
        bridge.sendall(bytes([ROUTE_CARRIAGE]))
        bridge.sendall(write_varint(len(unit)) + unit)
        answer = read_exact(bridge, read_varint(bridge))
    status = int.from_bytes(answer[0:2], "big")
    content_type, offset = decode_string(answer, 2)
    return status, content_type, answer[offset:]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _serve(self, method_code):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        try:
            status, content_type, answer = forward(
                method_code,
                self.path,
                f"{self.client_address[0]}:{self.client_address[1]}",
                self.headers.get("User-Agent") or "",
                body,
            )
        except OSError as failure:
            print(f"bridge exchange failed: {failure}", file=sys.stderr)
            self.send_response(502)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(answer)))
        self.end_headers()
        self.wfile.write(answer)

    def do_GET(self):
        self._serve(METHOD_GET)

    def do_POST(self):
        self._serve(METHOD_POST)

    def log_message(self, format, *args):
        pass


def main():
    if PARAMS.get("pidfile"):
        with open(PARAMS["pidfile"], "w") as pid:
            pid.write(str(os.getpid()))
    server = ThreadingHTTPServer(
        (PARAMS["bind"].rsplit(":", 1)[0], int(PARAMS["bind"].rsplit(":", 1)[1])),
        Handler,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
