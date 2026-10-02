"""Authenticated transport contract used by the loopback WebSocket adapter.

This module does not listen on a socket.  The persistent local service owns
the loopback HTTP/WebSocket listener, authenticates before constructing
``GatewayActor``, and carries one-use values in the first frame, never a URL.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlsplit

from .broker import TerminalAccessDenied, TerminalSessionBroker
from .contracts import (
    TerminalAuditReceipt,
    TerminalExit,
    TerminalInput,
    TerminalOutput,
    TerminalReconnectToken,
    TerminalResize,
    TerminalSession,
)


GATEWAY_FORMAT_VERSION = "stateport.terminal-session-gateway/v1"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SESSION_PATH = "/v1/terminal/socket"
_TOKEN_TRANSPORTS = frozenset({"protected_header", "first_frame"})


@dataclass(frozen=True)
class GatewayActor:
    """Identity result minted by a trusted upstream authenticator."""

    actor_id: str
    instance_ids: frozenset[str]
    authentication_route: str

    def __post_init__(self) -> None:
        if _ID.fullmatch(self.actor_id) is None:
            raise ValueError("gateway actor_id is invalid")
        if not self.instance_ids or len(self.instance_ids) > 128:
            raise ValueError("gateway actor requires a bounded instance grant")
        if any(_ID.fullmatch(item) is None for item in self.instance_ids):
            raise ValueError("gateway instance grant is invalid")
        if self.authentication_route not in {"bearer", "oidc", "operator_session"}:
            raise ValueError("gateway authentication route is unsupported")

    def can_access(self, instance_id: str) -> bool:
        return instance_id in self.instance_ids


@dataclass(frozen=True)
class GatewayHandshake:
    """Authenticated adapter evidence supplied before terminal bytes exist."""

    actor: GatewayActor
    instance_id: str
    origin: str
    request_target: str = _SESSION_PATH
    token_transport: str = "protected_header"

    def __post_init__(self) -> None:
        if not isinstance(self.actor, GatewayActor) or _ID.fullmatch(self.instance_id) is None:
            raise ValueError("terminal handshake identity is invalid")
        parsed = urlsplit(self.request_target)
        if (
            parsed.scheme or parsed.netloc or parsed.path != _SESSION_PATH
            or parsed.query or parsed.fragment or parsed.username or parsed.password
        ):
            raise ValueError("terminal handshake request target may not carry values in its URL")
        if self.token_transport not in _TOKEN_TRANSPORTS:
            raise ValueError("terminal one-use value requires a protected transport")
        if not isinstance(self.origin, str) or not self.origin:
            raise ValueError("terminal handshake origin is required")


@dataclass(frozen=True)
class GatewayFrame:
    """Bounded transport frame; terminal bytes remain ephemeral."""

    frame_type: str
    data: bytes = b""
    columns: int | None = None
    rows: int | None = None
    after_offset: int | None = None

    def __post_init__(self) -> None:
        if self.frame_type not in {"input", "resize", "replay", "disconnect", "close"}:
            raise ValueError("terminal gateway frame type is invalid")
        if not isinstance(self.data, bytes) or len(self.data) > 65_536:
            raise ValueError("terminal gateway data is bounded to 64KiB")
        if self.frame_type == "input" and not self.data:
            raise ValueError("terminal input frame requires data")
        if self.frame_type != "input" and self.data:
            raise ValueError("only terminal input frames may contain data")
        if self.frame_type == "resize":
            if any(isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 1000 for value in (self.columns, self.rows)):
                raise ValueError("terminal resize frame is invalid")
        elif self.columns is not None or self.rows is not None:
            raise ValueError("only terminal resize frames may contain dimensions")
        if self.frame_type == "replay":
            if isinstance(self.after_offset, bool) or not isinstance(self.after_offset, int) or self.after_offset < 0:
                raise ValueError("terminal replay frame offset is invalid")
        elif self.after_offset is not None:
            raise ValueError("only terminal replay frames may contain an offset")


@dataclass(frozen=True)
class WebSocketGatewayCapability:
    """Truthful status of the StatePort-owned loopback adapter."""

    availability: str = "available"
    authentication_required: bool = True
    origin_validation_required: bool = True
    public_listener: bool = False
    reason: str = "authenticated_loopback_adapter"

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": GATEWAY_FORMAT_VERSION,
            "availability": self.availability,
            "authenticationRequired": self.authentication_required,
            "originValidationRequired": self.origin_validation_required,
            "publicListener": self.public_listener,
            "reason": self.reason,
        }


class AuthenticatedTerminalGateway:
    """Narrow adapter-facing boundary with no network listener of its own."""

    capability = WebSocketGatewayCapability()

    def __init__(self, broker: TerminalSessionBroker) -> None:
        if not isinstance(broker, TerminalSessionBroker):
            raise TypeError("gateway requires a TerminalSessionBroker")
        self._broker = broker

    @staticmethod
    def _authorize(actor: GatewayActor, instance_id: str) -> None:
        if not isinstance(actor, GatewayActor) or not actor.can_access(instance_id):
            raise TerminalAccessDenied()

    def prepare(
        self,
        actor: GatewayActor,
        *,
        profile_id: str,
        instance_id: str,
        selected_root: Path | str,
        origin: str,
    ) -> TerminalReconnectToken:
        self._authorize(actor, instance_id)
        return self._broker.prepare_session(
            profile_id,
            actor_id=actor.actor_id,
            instance_id=instance_id,
            selected_root=selected_root,
            origin=origin,
        )

    def accept(
        self,
        actor: GatewayActor,
        *,
        one_use_value: str,
        instance_id: str,
        selected_root: Path | str,
        origin: str,
        columns: int = 80,
        rows: int = 24,
    ) -> tuple[TerminalSession, TerminalAuditReceipt]:
        """Authenticate and create before any terminal output is readable."""

        self._authorize(actor, instance_id)
        return self._broker.open_session(
            one_use_value,
            actor_id=actor.actor_id,
            instance_id=instance_id,
            selected_root=selected_root,
            origin=origin,
            columns=columns,
            rows=rows,
        )

    def accept_reconnect(
        self,
        actor: GatewayActor,
        *,
        one_use_value: str,
        instance_id: str,
        selected_root: Path | str,
        origin: str,
    ) -> tuple[TerminalSession, TerminalAuditReceipt]:
        self._authorize(actor, instance_id)
        return self._broker.reconnect_session(
            one_use_value,
            actor_id=actor.actor_id,
            instance_id=instance_id,
            selected_root=selected_root,
            origin=origin,
        )

    def accept_handshake(
        self,
        handshake: GatewayHandshake,
        *,
        one_use_value: str,
        selected_root: Path | str,
        columns: int = 80,
        rows: int = 24,
    ) -> tuple[TerminalSession, TerminalAuditReceipt]:
        """Accept a URL-clean authenticated handshake through the broker."""

        if not isinstance(handshake, GatewayHandshake):
            raise TerminalAccessDenied()
        return self.accept(
            handshake.actor,
            one_use_value=one_use_value,
            instance_id=handshake.instance_id,
            selected_root=selected_root,
            origin=handshake.origin,
            columns=columns,
            rows=rows,
        )

    def handle_frame(
        self,
        handshake: GatewayHandshake,
        *,
        session_id: str,
        frame: GatewayFrame,
    ) -> TerminalInput | TerminalResize | TerminalOutput | TerminalAuditReceipt | tuple[TerminalExit, TerminalAuditReceipt]:
        """Dispatch one authenticated frame without exposing the broker itself."""

        if not isinstance(handshake, GatewayHandshake) or not isinstance(frame, GatewayFrame):
            raise TerminalAccessDenied()
        self._authorize(handshake.actor, handshake.instance_id)
        identity = {
            "actor_id": handshake.actor.actor_id,
            "instance_id": handshake.instance_id,
            "origin": handshake.origin,
        }
        if frame.frame_type == "input":
            return self._broker.write_input(session_id, frame.data, **identity)
        if frame.frame_type == "resize":
            assert frame.columns is not None and frame.rows is not None
            return self._broker.resize(session_id, frame.columns, frame.rows, **identity)
        if frame.frame_type == "replay":
            assert frame.after_offset is not None
            return self._broker.replay_output(session_id, frame.after_offset, **identity)
        if frame.frame_type == "disconnect":
            return self._broker.disconnect_session(session_id, **identity)
        return self._broker.close_session(session_id, reason="transport_closed", **identity)

    def read_frame(
        self,
        handshake: GatewayHandshake,
        *,
        session_id: str,
        maximum_bytes: int = 65_536,
        timeout_seconds: float = 0.0,
    ) -> TerminalOutput:
        if not isinstance(handshake, GatewayHandshake):
            raise TerminalAccessDenied()
        self._authorize(handshake.actor, handshake.instance_id)
        return self._broker.read_output(
            session_id,
            actor_id=handshake.actor.actor_id,
            instance_id=handshake.instance_id,
            origin=handshake.origin,
            maximum_bytes=maximum_bytes,
            timeout_seconds=timeout_seconds,
        )
