#!/usr/bin/env python3
"""The bridge acceptance candidate: a per-peer byte pipe (ADR-025).

Python standard library only -- the point is that a listener package ships
in any language. The medium is HTTP: every request crosses to the kernel
over the bridge's route-forward carriage as a field map (method, path, the
medium's observed peer facts, body), and the answer's status,
content-type, and body carry back as the response. The process parses no
rod.v1 grammar, holds no engagement key, and learns no implant identity;
the kernel routes by path, the bytes are opaque here.
"""

import json
import os
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BRIDGE_SOCKET = os.environ["ROD_BRIDGE_SOCKET"]
PARAMS = json.loads(os.environ.get("ROD_LISTENER_PARAMS") or "{}")

ROUTE_CARRIAGE = 0x52  # 'R'
MAX_FIELDS = 64


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


def encode_unit(fields):
    """One route-forward unit: a counted run of string-keyed fields, every
    value opaque bytes. Unknown keys ride through unheard-of -- the
    kernel's growth rule, and this process's whole protocol surface."""
    out = write_varint(len(fields))
    for key, value in fields:
        if isinstance(value, str):
            value = value.encode("utf-8")
        key_bytes = key.encode("utf-8")
        out += write_varint(len(key_bytes)) + key_bytes
        out += write_varint(len(value)) + value
    return out


def decode_unit(buffer):
    count, offset = decode_varint_from(buffer, 0)
    if count > MAX_FIELDS:
        raise EOFError("field count beyond any honest unit")
    fields = {}
    for _ in range(count):
        key_length, offset = decode_varint_from(buffer, offset)
        key = buffer[offset : offset + key_length].decode("utf-8")
        offset += key_length
        value_length, offset = decode_varint_from(buffer, offset)
        fields[key] = buffer[offset : offset + value_length]
        offset += value_length
    return fields


def forward(method, path, peer, user_agent, body):
    """One route-forward exchange: dial the bridge, say 'R', send the
    request unit, read the answer unit, close. One request, one
    connection -- the byte pipe reconnects per medium peer."""
    unit = encode_unit([
        ("method", method),
        ("path", path),
        ("peer", peer),
        ("ua", user_agent),
        ("body", body),
    ])
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as bridge:
        bridge.connect(BRIDGE_SOCKET)
        bridge.sendall(bytes([ROUTE_CARRIAGE]))
        bridge.sendall(write_varint(len(unit)) + unit)
        answer = decode_unit(read_exact(bridge, read_varint(bridge)))
    status = int(answer["status"])
    content_type = answer["content-type"].decode("utf-8")
    return status, content_type, answer["body"]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _serve(self, method):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        try:
            status, content_type, answer = forward(
                method,
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
        self._serve("GET")

    def do_POST(self):
        self._serve("POST")

    def log_message(self, format, *args):
        pass


def main():
    if PARAMS.get("pidfile"):
        with open(PARAMS["pidfile"], "w") as pid:
            pid.write(str(os.getpid()))
    host, port = PARAMS["bind"].rsplit(":", 1)
    server = ThreadingHTTPServer((host, int(port)), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
