"""Strict RFC 6455 helpers for the loopback terminal adapter.

This module deliberately implements only the small protocol subset used by
StatePort.  Client frames must be masked, unfragmented, bounded, and free of
negotiated extensions.  Terminal payloads are binary; text is reserved for
the versioned authentication and resize/end controls.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import struct
from typing import Any, BinaryIO


TERMINAL_SOCKET_FORMAT = "stateport.terminal-socket/v1"
TERMINAL_SOCKET_PATH = "/v1/terminal/socket"
TERMINAL_SOCKET_SUBPROTOCOL = "stateport.terminal.v1"
MAX_TERMINAL_FRAME_BYTES = 65_536
MAX_TERMINAL_AUTH_BYTES = 2_048
MAX_TERMINAL_CONTROL_BYTES = 1_024


class WebSocketDisconnect(EOFError):
    """The peer closed the transport without a malformed frame."""


class WebSocketProtocolError(ValueError):
    """A bounded client-frame refusal with an RFC 6455 close code."""

    def __init__(self, message: str, close_code: int = 1002) -> None:
        super().__init__(message)
        self.close_code = close_code


@dataclass(frozen=True)
class ClientFrame:
    opcode: int
    payload: bytes


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    value = stream.read(size)
    if value is None or len(value) != size:
        raise WebSocketDisconnect("terminal transport disconnected")
    return value


def read_client_frame(stream: BinaryIO) -> ClientFrame:
    """Read one strict, masked, non-fragmented client frame."""

    first, second = _read_exact(stream, 2)
    if first & 0x70:
        raise WebSocketProtocolError("terminal frames may not use extensions")
    if not first & 0x80:
        raise WebSocketProtocolError("terminal frames may not be fragmented")
    opcode = first & 0x0F
    if opcode not in {0x1, 0x2, 0x8, 0x9, 0xA}:
        raise WebSocketProtocolError("terminal frame opcode is unsupported")
    if not second & 0x80:
        raise WebSocketProtocolError("terminal client frames must be masked")

    encoded_length = second & 0x7F
    if opcode >= 0x8 and encoded_length >= 126:
        raise WebSocketProtocolError("terminal control frames must remain bounded")
    if encoded_length == 126:
        payload_length = struct.unpack("!H", _read_exact(stream, 2))[0]
        if payload_length < 126:
            raise WebSocketProtocolError("terminal frame length is not minimally encoded")
    elif encoded_length == 127:
        encoded = _read_exact(stream, 8)
        if encoded[0] & 0x80:
            raise WebSocketProtocolError("terminal frame length is invalid")
        payload_length = struct.unpack("!Q", encoded)[0]
        if payload_length <= 65_535:
            raise WebSocketProtocolError("terminal frame length is not minimally encoded")
    else:
        payload_length = encoded_length
    if payload_length > MAX_TERMINAL_FRAME_BYTES:
        raise WebSocketProtocolError("terminal frame exceeds 64KiB", 1009)
    if opcode >= 0x8 and payload_length > 125:
        raise WebSocketProtocolError("terminal control frame exceeds 125 bytes")

    mask = _read_exact(stream, 4)
    encoded_payload = _read_exact(stream, payload_length)
    payload = bytes(value ^ mask[index % 4] for index, value in enumerate(encoded_payload))
    if opcode == 0x8:
        validate_close_payload(payload)
    return ClientFrame(opcode, payload)


def server_frame(opcode: int, payload: bytes = b"") -> bytes:
    """Encode one unmasked, final server frame."""

    if opcode not in {0x1, 0x2, 0x8, 0x9, 0xA}:
        raise ValueError("server frame opcode is unsupported")
    if not isinstance(payload, bytes) or len(payload) > MAX_TERMINAL_FRAME_BYTES:
        raise ValueError("server frame payload is invalid")
    if opcode >= 0x8 and len(payload) > 125:
        raise ValueError("server control frame exceeds 125 bytes")
    header = bytearray((0x80 | opcode,))
    if len(payload) < 126:
        header.append(len(payload))
    elif len(payload) <= 65_535:
        header.extend((126,))
        header.extend(struct.pack("!H", len(payload)))
    else:
        header.extend((127,))
        header.extend(struct.pack("!Q", len(payload)))
    return bytes(header) + payload


def close_payload(code: int, reason: str) -> bytes:
    if isinstance(code, bool) or not isinstance(code, int) or not 1000 <= code <= 4999:
        raise ValueError("WebSocket close code is invalid")
    encoded = reason.encode("utf-8")
    if len(encoded) > 123:
        raise ValueError("WebSocket close reason is too large")
    return struct.pack("!H", code) + encoded


def validate_close_payload(payload: bytes) -> None:
    if len(payload) == 1:
        raise WebSocketProtocolError("terminal close frame is malformed")
    if not payload:
        return
    code = struct.unpack("!H", payload[:2])[0]
    if code < 1000 or code in {1004, 1005, 1006, 1015} or 1016 <= code <= 2999 or code >= 5000:
        raise WebSocketProtocolError("terminal close code is invalid")
    try:
        payload[2:].decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise WebSocketProtocolError("terminal close reason is invalid UTF-8", 1007) from exc


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"unsupported JSON constant: {value}")


def strict_json_object(payload: bytes, *, maximum_bytes: int) -> dict[str, Any]:
    if not isinstance(payload, bytes) or len(payload) > maximum_bytes:
        raise WebSocketProtocolError("terminal JSON control is too large", 1009)
    try:
        decoded = payload.decode("utf-8", errors="strict")
        value = json.loads(decoded, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise WebSocketProtocolError("terminal JSON control is invalid", 1007) from exc
    if not isinstance(value, dict):
        raise WebSocketProtocolError("terminal JSON control must be an object", 1007)
    return value


def parse_authentication(payload: bytes) -> dict[str, Any]:
    value = strict_json_object(payload, maximum_bytes=MAX_TERMINAL_AUTH_BYTES)
    required = {
        "formatVersion", "type", "instanceId", "sessionId", "purpose",
        "oneUseToken", "columns", "rows",
    }
    if set(value) != required or value["formatVersion"] != TERMINAL_SOCKET_FORMAT or value["type"] != "authenticate":
        raise WebSocketProtocolError("terminal authentication frame shape is invalid", 1008)
    for name in ("instanceId", "sessionId", "purpose", "oneUseToken"):
        if not isinstance(value[name], str):
            raise WebSocketProtocolError("terminal authentication identity is invalid", 1008)
    if value["purpose"] not in {"create", "reconnect"}:
        raise WebSocketProtocolError("terminal authentication purpose is invalid", 1008)
    token = value["oneUseToken"]
    if not 32 <= len(token) <= 256 or not token.isascii():
        raise WebSocketProtocolError("terminal authentication token is invalid", 1008)
    for name in ("columns", "rows"):
        number = value[name]
        if isinstance(number, bool) or not isinstance(number, int) or not 1 <= number <= 1000:
            raise WebSocketProtocolError("terminal dimensions are invalid", 1008)
    return value


def parse_control(payload: bytes) -> dict[str, Any]:
    value = strict_json_object(payload, maximum_bytes=MAX_TERMINAL_CONTROL_BYTES)
    if value.get("formatVersion") != TERMINAL_SOCKET_FORMAT:
        raise WebSocketProtocolError("terminal control version is invalid", 1008)
    if value.get("type") == "end" and set(value) == {"formatVersion", "type"}:
        return value
    if value.get("type") == "resize" and set(value) == {"formatVersion", "type", "columns", "rows"}:
        for name in ("columns", "rows"):
            number = value[name]
            if isinstance(number, bool) or not isinstance(number, int) or not 1 <= number <= 1000:
                raise WebSocketProtocolError("terminal dimensions are invalid", 1008)
        return value
    raise WebSocketProtocolError("terminal control frame shape is invalid", 1008)


def validate_extension_offer(value: str | None) -> None:
    """Accept only a bounded permessage-deflate offer, but never negotiate it.

    Browsers commonly send this offer and do not expose an API to disable it.
    StatePort omits ``Sec-WebSocket-Extensions`` from its response and still
    rejects every frame with an RSV bit.
    """

    if value is None:
        return
    if not isinstance(value, str) or not value or len(value) > 256 or "," in value:
        raise WebSocketProtocolError("terminal WebSocket extension offer is invalid")
    pieces = [piece.strip() for piece in value.split(";")]
    if not pieces or pieces[0].lower() != "permessage-deflate":
        raise WebSocketProtocolError("terminal WebSocket extension is unsupported")
    permitted = {
        "client_no_context_takeover", "server_no_context_takeover",
        "client_max_window_bits", "server_max_window_bits",
    }
    observed: set[str] = set()
    for parameter in pieces[1:]:
        name, separator, raw = parameter.partition("=")
        name = name.strip().lower()
        raw = raw.strip()
        if not name or name not in permitted or name in observed:
            raise WebSocketProtocolError("terminal WebSocket extension parameter is unsupported")
        observed.add(name)
        if name.endswith("no_context_takeover") and separator:
            raise WebSocketProtocolError("terminal WebSocket extension parameter is invalid")
        if name.endswith("max_window_bits") and separator:
            if raw.startswith('"') and raw.endswith('"'):
                raw = raw[1:-1]
            if raw not in {str(number) for number in range(8, 16)}:
                raise WebSocketProtocolError("terminal WebSocket extension window is invalid")
