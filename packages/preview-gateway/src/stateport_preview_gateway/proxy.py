"""Loopback reverse-proxy plumbing for the preview gateway.

HTTP requests and WebSocket frames are forwarded to the registered loopback
upstream only.  The operator session cookie and StatePort control headers are
never forwarded; upstream ``Set-Cookie`` values are rewritten so they are
scoped to the preview route path and cannot claim the application origin.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import os
import re
import socket
from typing import Any, Mapping

from .errors import PreviewGatewayError


MAX_REQUEST_BODY_BYTES = 16 * 1024 * 1024
MAX_RESPONSE_BODY_BYTES = 32 * 1024 * 1024
MAX_UPSTREAM_HEAD_BYTES = 16 * 1024
# Browser-side reads and the server-frame encoder are the strict terminal
# transport (64 KiB, non-fragmented); upstream frames are capped identically
# so a relayed message always fits one server frame.
MAX_FRAME_BYTES = 64 * 1024
UPSTREAM_TIMEOUT_SECONDS = 30.0

_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)

# Inbound headers that never cross the gateway: the operator session, the
# CSRF token, and the application origin identity stay on the StatePort side.
_REQUEST_STRIP = _HOP_BY_HOP | frozenset(
    {"cookie", "host", "origin", "referer", "x-stateport-csrf"}
)

_RESPONSE_STRIP = _HOP_BY_HOP | frozenset({"content-length", "set-cookie", "location"})

_HTTP_TOKEN = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def preview_base_path(capsule: str, service: str) -> str:
    # Identifier patterns already constrain both values to path-safe
    # characters; the base path must match the raw request path byte-for-byte
    # because browsers path-match Set-Cookie values against it literally.
    return f"/preview/{capsule}/{service}"


def filtered_request_headers(headers: Mapping[str, str], upstream_port: int) -> dict[str, str]:
    """Build the upstream request head: strip StatePort identity, pin the Host."""

    forwarded: dict[str, str] = {}
    for name, value in headers.items():
        lowered = name.lower()
        if lowered in _REQUEST_STRIP:
            continue
        if "\r" in value or "\n" in value:
            continue
        forwarded[name] = value
    forwarded["Host"] = f"127.0.0.1:{upstream_port}"
    # Bodies pass through untransformed; forbid upstream content negotiation
    # that would require decoding at the boundary.
    forwarded["Accept-Encoding"] = "identity"
    return forwarded


def rewrite_set_cookie(value: str, base_path: str) -> str | None:
    """Scope an upstream cookie to the preview route path.

    The upstream Domain, SameSite, Secure, and expiry attributes are dropped:
    preview cookies are host-only session cookies under the route path and may
    never claim the application origin or another capsule's routes.
    """

    first = value.split(";", 1)[0].strip()
    if "=" not in first:
        return None
    name, cookie_value = first.split("=", 1)
    name = name.strip()
    if _HTTP_TOKEN.fullmatch(name) is None:
        return None
    if any(character in cookie_value for character in ';\r\n"'):
        return None
    parts = [f"{name}={cookie_value.strip()}", f"Path={base_path}"]
    if any(part.strip().lower() == "httponly" for part in value.split(";")[1:]):
        parts.append("HttpOnly")
    return "; ".join(parts)


def rewrite_location(value: str, base_path: str) -> str:
    """Keep upstream redirects inside the preview route namespace."""

    if value.startswith("/") and not value.startswith("//"):
        return f"{base_path}{value}"
    return value


def filtered_response_headers(
    headers: list[tuple[str, str]], base_path: str
) -> list[tuple[str, str]]:
    forwarded: list[tuple[str, str]] = []
    for name, value in headers:
        lowered = name.lower()
        if lowered in _RESPONSE_STRIP:
            continue
        if "\r" in value or "\n" in value:
            continue
        forwarded.append((name, value))
    return forwarded


def proxy_http(
    route: Mapping[str, Any],
    *,
    method: str,
    upstream_path: str,
    request_headers: Mapping[str, str],
    body: bytes,
) -> tuple[int, list[tuple[str, str]], bytes]:
    """Forward one HTTP request to the registered loopback upstream."""

    upstream = route["upstream"]
    port = int(upstream["port"])
    base_path = preview_base_path(str(route["capsuleId"]), str(route["serviceId"]))
    connection = http.client.HTTPConnection(
        "127.0.0.1", port, timeout=UPSTREAM_TIMEOUT_SECONDS
    )
    try:
        connection.request(
            method,
            upstream_path,
            body=body if body else None,
            headers=filtered_request_headers(request_headers, port),
        )
        response = connection.getresponse()
        chunks: list[bytes] = []
        remaining = MAX_RESPONSE_BODY_BYTES + 1
        while remaining > 0:
            chunk = response.read(min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > MAX_RESPONSE_BODY_BYTES:
            raise PreviewGatewayError(
                "preview_response_too_large", "the preview upstream response exceeds the boundary limit"
            )
        raw_headers = response.getheaders()
    except PreviewGatewayError:
        raise
    except (OSError, http.client.HTTPException) as exc:
        raise PreviewGatewayError(
            "preview_upstream_unavailable", "the preview upstream is unavailable"
        ) from exc
    finally:
        connection.close()
    forwarded = filtered_response_headers(raw_headers, base_path)
    for name, value in raw_headers:
        lowered = name.lower()
        if lowered == "set-cookie":
            rewritten = rewrite_set_cookie(value, base_path)
            if rewritten is not None:
                forwarded.append(("Set-Cookie", rewritten))
        elif lowered == "location":
            forwarded.append(("Location", rewrite_location(value, base_path)))
    return response.status, forwarded, payload


# ---------------------------------------------------------------------------
# WebSocket client side (gateway -> upstream dev server)
# ---------------------------------------------------------------------------


def upstream_upgrade(
    route: Mapping[str, Any],
    *,
    upstream_path: str,
    subprotocols: tuple[str, ...],
) -> tuple[socket.socket, str | None]:
    """Open a WebSocket client connection to the registered loopback upstream."""

    port = int(route["upstream"]["port"])
    try:
        connection = socket.create_connection(
            ("127.0.0.1", port), timeout=UPSTREAM_TIMEOUT_SECONDS
        )
    except OSError as exc:
        raise PreviewGatewayError(
            "preview_upstream_unavailable", "the preview upstream is unavailable"
        ) from exc
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    lines = [
        f"GET {upstream_path} HTTP/1.1",
        f"Host: 127.0.0.1:{port}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
    ]
    if subprotocols:
        lines.append(f"Sec-WebSocket-Protocol: {', '.join(subprotocols)}")
    request = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")
    try:
        connection.sendall(request)
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = connection.recv(4096)
            if not chunk:
                raise PreviewGatewayError(
                    "preview_upstream_unavailable",
                    "the preview upstream closed during the WebSocket handshake",
                )
            head += chunk
            if len(head) > MAX_UPSTREAM_HEAD_BYTES:
                raise PreviewGatewayError(
                    "preview_upgrade_refused", "the preview upstream handshake head is too large"
                )
        head_text = head.split(b"\r\n\r\n", 1)[0].decode("latin-1")
        head_lines = head_text.split("\r\n")
        status_parts = head_lines[0].split(" ", 2)
        if len(status_parts) < 2 or status_parts[1] != "101":
            raise PreviewGatewayError(
                "preview_upgrade_refused", "the preview upstream refused the WebSocket upgrade"
            )
        headers: dict[str, str] = {}
        for line in head_lines[1:]:
            if ":" not in line:
                raise PreviewGatewayError(
                    "preview_upgrade_refused", "the preview upstream handshake is malformed"
                )
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
        expected_accept = base64.b64encode(
            hashlib.sha1((key + _WS_GUID).encode("ascii"), usedforsecurity=False).digest()
        ).decode("ascii")
        if headers.get("sec-websocket-accept") != expected_accept:
            raise PreviewGatewayError(
                "preview_upgrade_refused", "the preview upstream handshake proof is invalid"
            )
        if headers.get("upgrade", "").lower() != "websocket":
            raise PreviewGatewayError(
                "preview_upgrade_refused", "the preview upstream upgrade header is invalid"
            )
        negotiated = headers.get("sec-websocket-protocol")
        if negotiated is not None and negotiated not in subprotocols:
            raise PreviewGatewayError(
                "preview_upgrade_refused", "the preview upstream selected an unoffered subprotocol"
            )
    except PreviewGatewayError:
        connection.close()
        raise
    except OSError as exc:
        connection.close()
        raise PreviewGatewayError(
            "preview_upstream_unavailable", "the preview upstream is unavailable"
        ) from exc
    connection.settimeout(None)
    return connection, negotiated


class UpstreamFrame:
    __slots__ = ("fin", "opcode", "payload")

    def __init__(self, fin: bool, opcode: int, payload: bytes) -> None:
        self.fin = fin
        self.opcode = opcode
        self.payload = payload


def _read_exact(connection: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise PreviewGatewayError(
                "preview_upstream_detached", "the preview upstream closed the socket"
            )
        data += chunk
    return data


def read_upstream_frame(connection: socket.socket) -> UpstreamFrame:
    """Read one unmasked server frame from the upstream; fragments reassembled."""

    buffer = b""
    opcode: int | None = None
    while True:
        head = _read_exact(connection, 2)
        fin = bool(head[0] & 0x80)
        frame_opcode = head[0] & 0x0F
        if head[0] & 0x70:
            raise PreviewGatewayError(
                "preview_upgrade_refused", "the preview upstream uses unsupported WebSocket extensions"
            )
        masked = bool(head[1] & 0x80)
        length = head[1] & 0x7F
        if masked:
            raise PreviewGatewayError(
                "preview_upgrade_refused", "the preview upstream may not mask server frames"
            )
        if length == 126:
            length = int.from_bytes(_read_exact(connection, 2), "big")
        elif length == 127:
            length = int.from_bytes(_read_exact(connection, 8), "big")
            if length > (1 << 63) - 1:
                raise PreviewGatewayError(
                    "preview_upgrade_refused", "the preview upstream frame length is invalid"
                )
        if length > MAX_FRAME_BYTES:
            raise PreviewGatewayError(
                "preview_upgrade_refused", "the preview upstream frame exceeds the boundary limit"
            )
        payload = _read_exact(connection, length) if length else b""
        if frame_opcode & 0x8:
            if not fin or length > 125:
                raise PreviewGatewayError(
                    "preview_upgrade_refused", "the preview upstream control frame is invalid"
                )
            return UpstreamFrame(True, frame_opcode, payload)
        if opcode is None:
            opcode = frame_opcode
        buffer += payload
        if len(buffer) > MAX_FRAME_BYTES:
            raise PreviewGatewayError(
                "preview_upgrade_refused", "the preview upstream message exceeds the boundary limit"
            )
        if fin:
            return UpstreamFrame(True, opcode, buffer)


def write_client_frame(connection: socket.socket, opcode: int, payload: bytes) -> None:
    """Write one masked client frame toward the upstream (RFC 6455 client duty)."""

    head = bytearray()
    head.append(0x80 | (opcode & 0x0F))
    length = len(payload)
    if length < 126:
        head.append(0x80 | length)
    elif length <= 0xFFFF:
        head.append(0x80 | 126)
        head += length.to_bytes(2, "big")
    else:
        head.append(0x80 | 127)
        head += length.to_bytes(8, "big")
    mask = os.urandom(4)
    head += mask
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    connection.sendall(bytes(head) + masked)


def validate_subprotocol_offer(value: str | None) -> tuple[str, ...]:
    """Bound and validate the browser's subprotocol offer before forwarding."""

    if value is None:
        return ()
    offered = tuple(item.strip() for item in value.split(","))
    if (
        not offered
        or len(offered) > 8
        or any(_HTTP_TOKEN.fullmatch(item) is None for item in offered)
        or len(set(offered)) != len(offered)
    ):
        raise PreviewGatewayError(
            "preview_upgrade_refused", "the preview WebSocket subprotocol offer is invalid"
        )
    return offered


def close_payload(code: int, reason: str) -> bytes:
    return code.to_bytes(2, "big") + reason.encode("utf-8")[:123]


__all__ = [
    "MAX_REQUEST_BODY_BYTES",
    "UpstreamFrame",
    "close_payload",
    "filtered_request_headers",
    "filtered_response_headers",
    "preview_base_path",
    "proxy_http",
    "read_upstream_frame",
    "rewrite_location",
    "rewrite_set_cookie",
    "upstream_upgrade",
    "validate_subprotocol_offer",
    "write_client_frame",
]
