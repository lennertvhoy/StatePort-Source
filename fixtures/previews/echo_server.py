"""Plain-Python preview upstream fixture: HTTP echo and WebSocket echo.

This fixture stands in for a workload development server (the kind a capsule
runs with hot-module reload over a WebSocket). It binds loopback only and is
never published by the product: the preview gateway's authenticated
`/preview/...` route is the only product path to it. Tests use it to prove
HTTP proxying, WebSocket/HMR passthrough, and cookie isolation.
"""

from __future__ import annotations

import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import socket
import struct

_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _read_exact(stream, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = stream.read(size - len(data))
        if not chunk:
            raise EOFError("client closed")
        data += chunk
    return data


def _read_client_frame(stream) -> tuple[int, bytes]:
    head = _read_exact(stream, 2)
    fin = bool(head[0] & 0x80)
    opcode = head[0] & 0x0F
    masked = bool(head[1] & 0x80)
    length = head[1] & 0x7F
    if length == 126:
        length = struct.unpack(">H", _read_exact(stream, 2))[0]
    elif length == 127:
        length = struct.unpack(">Q", _read_exact(stream, 8))[0]
    mask = _read_exact(stream, 4) if masked else b""
    payload = _read_exact(stream, length) if length else b""
    if masked:
        payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return (opcode if fin else -opcode), payload


def _server_frame(opcode: int, payload: bytes) -> bytes:
    head = bytearray([0x80 | opcode])
    if len(payload) < 126:
        head.append(len(payload))
    elif len(payload) <= 0xFFFF:
        head.append(126)
        head += struct.pack(">H", len(payload))
    else:
        head.append(127)
        head += struct.pack(">Q", len(payload))
    return bytes(head) + payload


class PreviewEchoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "PreviewEchoFixture/1"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return

    def _json(self, status: int, value: dict[str, object], *, extra: list[tuple[str, str]] | None = None) -> None:
        body = (json.dumps(value, sort_keys=True) + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for name, header_value in extra or []:
            self.send_header(name, header_value)
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> bytes:
        lengths = self.headers.get_all("Content-Length", failobj=[])
        length = int(lengths[0]) if lengths else 0
        return self.rfile.read(length) if length else b""

    def _handle_websocket(self) -> None:
        key = self.headers.get("Sec-WebSocket-Key", "")
        accept = base64.b64encode(
            hashlib.sha1((key + _WS_GUID).encode(), usedforsecurity=False).digest()
        ).decode("ascii")
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        offered = self.headers.get("Sec-WebSocket-Protocol")
        if offered:
            self.send_header("Sec-WebSocket-Protocol", offered.split(",")[0].strip())
        self.end_headers()
        self.close_connection = True
        while True:
            try:
                opcode, payload = _read_client_frame(self.rfile)
            except (EOFError, OSError):
                return
            if opcode in (0x1, 0x2):
                self.wfile.write(_server_frame(opcode, payload))
                self.wfile.flush()
            elif opcode == 0x9:
                self.wfile.write(_server_frame(0xA, payload))
                self.wfile.flush()
            elif opcode == 0x8:
                self.wfile.write(_server_frame(0x8, payload))
                self.wfile.flush()
                return

    def _dispatch(self, method: str) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/ws" and self.headers.get("Upgrade", "").lower() == "websocket":
            self._handle_websocket()
            return
        if path == "/__headers":
            self._json(
                200,
                {
                    "headers": {name: value for name, value in self.headers.items()},
                    "sawCookie": self.headers.get("Cookie") is not None,
                },
            )
            return
        if path == "/__set-cookie":
            self._json(
                200,
                {"set": True},
                extra=[
                    ("Set-Cookie", "hmr_token=fixture; Domain=example.test; Path=/; Secure; SameSite=None"),
                    ("Set-Cookie", "preview_second=2; HttpOnly; Path=/"),
                ],
            )
            return
        if path == "/__redirect":
            self._json(302, {"redirect": True}, extra=[("Location", "/echo/target")])
            return
        body = self._body()
        self._json(
            200,
            {
                "method": method,
                "path": self.path,
                "bodyLength": len(body),
                "sawCookie": self.headers.get("Cookie") is not None,
                "fixture": "preview-echo",
            },
        )

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")


def make_server(port: int = 0) -> ThreadingHTTPServer:
    """Bind the echo fixture on loopback only; the port is never published."""

    server = ThreadingHTTPServer(("127.0.0.1", port), PreviewEchoHandler)
    bound_host = server.server_address[0]
    if bound_host != "127.0.0.1":
        raise RuntimeError("preview fixtures are loopback-only")
    return server


if __name__ == "__main__":
    import threading

    instance = make_server(int(os.environ.get("PREVIEW_ECHO_PORT", "0")))
    print(f"preview echo fixture on 127.0.0.1:{instance.server_address[1]}", flush=True)
    threading.Thread(target=instance.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    threading.Event().wait()
