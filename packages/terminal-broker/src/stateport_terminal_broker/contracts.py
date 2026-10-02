"""Versioned, transport-neutral contracts for the governed terminal boundary.

The contracts intentionally separate terminal bytes from audit metadata.  A
``TerminalOutput`` is an ephemeral transport value; ``TerminalAuditReceipt``
never contains commands, terminal bytes, reconnect values, or environment
contents.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Any


TERMINAL_FORMAT_VERSION = "stateport.terminal/v1"
TARGET_CLASSES = frozenset({"local_pty", "ssh", "herdr_attach", "capsule"})
TARGET_AVAILABILITY = frozenset({"available", "environment_gated", "unavailable"})
SESSION_STATES = frozenset({"reserved", "connected", "disconnected", "closed", "quarantined"})
_ACTIONS = frozenset({"created", "reconnected", "disconnected", "closed", "timed_out", "recovered"})
_OUTCOMES = frozenset({"accepted", "completed", "refused", "cleanup_failed"})
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _bounded_id(value: str, name: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ValueError(f"{name} must be a bounded contract identifier")
    return value


def _bounded_text(value: str, name: str, *, limit: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > limit
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError(f"{name} must be bounded printable text")
    return value


def _positive(value: int, name: str, *, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= maximum:
        raise ValueError(f"{name} must be between 1 and {maximum}")
    return value


def _nonnegative(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _format(payload: dict[str, Any]) -> dict[str, Any]:
    return {"formatVersion": TERMINAL_FORMAT_VERSION, **payload}


@dataclass(frozen=True)
class TerminalCapabilities:
    """Capabilities actually available for one configured target."""

    target_class: str
    input: bool
    output: bool
    resize: bool
    reconnect: bool
    replay: bool
    server_side_authentication: bool
    transcript_capture: bool = False
    reconnect_scope: str = "same_actor_instance_origin_generation_until_process_exit"

    def __post_init__(self) -> None:
        if self.target_class not in TARGET_CLASSES:
            raise ValueError("target_class is invalid")
        for name in (
            "input", "output", "resize", "reconnect", "replay",
            "server_side_authentication", "transcript_capture",
        ):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"{name} must be boolean")
        if self.transcript_capture:
            raise ValueError("terminal transcript capture is unavailable in v1")
        _bounded_text(self.reconnect_scope, "reconnect_scope", limit=128)

    def to_dict(self) -> dict[str, Any]:
        return _format({
            "targetClass": self.target_class,
            "input": self.input,
            "output": self.output,
            "resize": self.resize,
            "reconnect": self.reconnect,
            "replay": self.replay,
            "serverSideAuthentication": self.server_side_authentication,
            "transcriptCapture": False,
            "reconnectScope": self.reconnect_scope if self.reconnect else "none",
        })


@dataclass(frozen=True)
class TerminalTarget:
    """Public description of a configured terminal target."""

    target_id: str
    target_class: str
    display_name: str
    availability: str
    capabilities: TerminalCapabilities
    unavailable_reason: str | None = None

    def __post_init__(self) -> None:
        _bounded_id(self.target_id, "target_id")
        _bounded_text(self.display_name, "display_name")
        if self.target_class not in TARGET_CLASSES:
            raise ValueError("target_class is invalid")
        if self.availability not in TARGET_AVAILABILITY:
            raise ValueError("target availability is invalid")
        if self.capabilities.target_class != self.target_class:
            raise ValueError("target capabilities do not match its class")
        if self.availability == "available" and self.unavailable_reason is not None:
            raise ValueError("available targets may not have an unavailable reason")
        if self.availability != "available":
            _bounded_text(self.unavailable_reason or "", "unavailable_reason", limit=512)

    def to_dict(self) -> dict[str, Any]:
        result = _format({
            "targetId": self.target_id,
            "targetClass": self.target_class,
            "displayName": self.display_name,
            "availability": self.availability,
            "capabilities": self.capabilities.to_dict(),
        })
        if self.unavailable_reason is not None:
            result["unavailableReason"] = self.unavailable_reason
        return result


@dataclass(frozen=True)
class TerminalConnectionProfile:
    """Server-owned launch policy; never accepted from a browser request."""

    profile_id: str
    target: TerminalTarget
    instance_ids: tuple[str, ...]
    working_root: Path | None
    command: tuple[str, ...] = ()
    environment_allowlist: tuple[str, ...] = ("PATH", "LANG", "LC_ALL", "LC_CTYPE")
    idle_timeout_seconds: int = 900
    maximum_lifetime_seconds: int = 3600
    replay_limit_bytes: int = 65_536
    output_limit_bytes: int = 16_777_216
    elevated: bool = False

    def __post_init__(self) -> None:
        _bounded_id(self.profile_id, "profile_id")
        if not self.instance_ids or len(self.instance_ids) > 128:
            raise ValueError("instance_ids must be a non-empty bounded tuple")
        for instance_id in self.instance_ids:
            _bounded_id(instance_id, "instance_id")
        if len(set(self.instance_ids)) != len(self.instance_ids):
            raise ValueError("instance_ids must be unique")
        _positive(self.idle_timeout_seconds, "idle_timeout_seconds", maximum=86_400)
        _positive(self.maximum_lifetime_seconds, "maximum_lifetime_seconds", maximum=86_400)
        if self.idle_timeout_seconds > self.maximum_lifetime_seconds:
            raise ValueError("idle timeout may not exceed maximum lifetime")
        _positive(self.replay_limit_bytes, "replay_limit_bytes", maximum=1_048_576)
        _positive(self.output_limit_bytes, "output_limit_bytes", maximum=1_073_741_824)
        if self.replay_limit_bytes > self.output_limit_bytes:
            raise ValueError("replay limit may not exceed output limit")
        if not isinstance(self.elevated, bool):
            raise ValueError("elevated must be boolean")
        if not isinstance(self.environment_allowlist, tuple) or len(self.environment_allowlist) > 32:
            raise ValueError("environment_allowlist must be a bounded tuple")
        for name in self.environment_allowlist:
            if not isinstance(name, str) or re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", name) is None:
                raise ValueError("environment_allowlist contains an invalid name")
        if len(set(self.environment_allowlist)) != len(self.environment_allowlist):
            raise ValueError("environment_allowlist must be unique")
        if self.target.target_class == "local_pty":
            if self.target.availability != "available":
                raise ValueError("a local PTY profile requires an available target")
            if self.working_root is None or not isinstance(self.working_root, Path):
                raise ValueError("a local PTY profile requires an explicit working_root")
            if not self.command or len(self.command) > 32:
                raise ValueError("a local PTY profile requires a bounded command")
            if any(not isinstance(item, str) or not item or "\x00" in item for item in self.command):
                raise ValueError("command arguments must be non-empty strings")
        elif self.working_root is not None or self.command:
            raise ValueError("environment-gated target profiles may not define a local command or root")

    def to_dict(self, *, working_root_digest: str | None = None) -> dict[str, Any]:
        if working_root_digest is not None and _DIGEST.fullmatch(working_root_digest) is None:
            raise ValueError("working_root_digest must be sha256")
        result = _format({
            "profileId": self.profile_id,
            "target": self.target.to_dict(),
            "instanceIds": list(self.instance_ids),
            "idleTimeoutSeconds": self.idle_timeout_seconds,
            "maximumLifetimeSeconds": self.maximum_lifetime_seconds,
            "replayLimitBytes": self.replay_limit_bytes,
            "outputLimitBytes": self.output_limit_bytes,
            "elevated": self.elevated,
            "filesystemScope": "host" if self.elevated else "project_root",
            "networkAccess": self.elevated,
        })
        if working_root_digest is not None:
            result["workingRootDigest"] = working_root_digest
        return result


@dataclass(frozen=True)
class TerminalSession:
    session_id: str
    target_id: str
    target_class: str
    actor_id: str
    instance_id: str
    state: str
    created_at: str
    expires_at: str
    last_activity_at: str
    generation_digest: str
    working_root_digest: str
    connected: bool

    def __post_init__(self) -> None:
        for value, name in (
            (self.session_id, "session_id"), (self.target_id, "target_id"),
            (self.actor_id, "actor_id"), (self.instance_id, "instance_id"),
        ):
            _bounded_id(value, name)
        if self.target_class not in TARGET_CLASSES:
            raise ValueError("target_class is invalid")
        if self.state not in SESSION_STATES:
            raise ValueError("session state is invalid")
        if not isinstance(self.connected, bool) or self.connected != (self.state == "connected"):
            raise ValueError("connected must match session state")
        for value, name in (
            (self.created_at, "created_at"), (self.expires_at, "expires_at"),
            (self.last_activity_at, "last_activity_at"),
        ):
            _bounded_text(value, name, limit=64)
        for value, name in (
            (self.generation_digest, "generation_digest"),
            (self.working_root_digest, "working_root_digest"),
        ):
            if _DIGEST.fullmatch(value) is None:
                raise ValueError(f"{name} must be sha256")

    def to_dict(self) -> dict[str, Any]:
        return _format({
            "sessionId": self.session_id,
            "targetId": self.target_id,
            "targetClass": self.target_class,
            "actorId": self.actor_id,
            "instanceId": self.instance_id,
            "state": self.state,
            "createdAt": self.created_at,
            "expiresAt": self.expires_at,
            "lastActivityAt": self.last_activity_at,
            "generationDigest": self.generation_digest,
            "workingRootDigest": self.working_root_digest,
            "connected": self.connected,
        })


@dataclass(frozen=True)
class TerminalResize:
    session_id: str
    columns: int
    rows: int
    sequence: int

    def __post_init__(self) -> None:
        _bounded_id(self.session_id, "session_id")
        _positive(self.columns, "columns", maximum=1000)
        _positive(self.rows, "rows", maximum=1000)
        _nonnegative(self.sequence, "sequence")

    def to_dict(self) -> dict[str, Any]:
        return _format({"sessionId": self.session_id, "columns": self.columns, "rows": self.rows, "sequence": self.sequence})


@dataclass(frozen=True)
class TerminalInput:
    """Input acknowledgement containing size only, never terminal content."""

    session_id: str
    byte_count: int
    sequence: int

    def __post_init__(self) -> None:
        _bounded_id(self.session_id, "session_id")
        _positive(self.byte_count, "byte_count", maximum=65_536)
        _nonnegative(self.sequence, "sequence")

    def to_dict(self) -> dict[str, Any]:
        return _format({"sessionId": self.session_id, "byteCount": self.byte_count, "sequence": self.sequence})


@dataclass(frozen=True)
class TerminalOutput:
    """Ephemeral output frame.  Callers must not persist it as audit data."""

    session_id: str
    data: bytes = field(repr=False)
    start_offset: int
    end_offset: int
    replayed: bool
    dropped_before_offset: int
    eof: bool

    def __post_init__(self) -> None:
        _bounded_id(self.session_id, "session_id")
        if not isinstance(self.data, bytes) or len(self.data) > 65_536:
            raise ValueError("terminal output data must be bytes bounded to 64KiB")
        for value, name in (
            (self.start_offset, "start_offset"), (self.end_offset, "end_offset"),
            (self.dropped_before_offset, "dropped_before_offset"),
        ):
            _nonnegative(value, name)
        if self.end_offset - self.start_offset != len(self.data):
            raise ValueError("terminal output offsets do not match its data")
        if not isinstance(self.replayed, bool) or not isinstance(self.eof, bool):
            raise ValueError("terminal output flags must be boolean")

    def to_dict(self) -> dict[str, Any]:
        return _format({
            "sessionId": self.session_id,
            "encoding": "base64",
            "data": base64.b64encode(self.data).decode("ascii"),
            "startOffset": self.start_offset,
            "endOffset": self.end_offset,
            "replayed": self.replayed,
            "droppedBeforeOffset": self.dropped_before_offset,
            "eof": self.eof,
        })


@dataclass(frozen=True)
class TerminalExit:
    session_id: str
    reason: str
    return_code: int | None
    cleanup: str
    exited_at: str

    def __post_init__(self) -> None:
        _bounded_id(self.session_id, "session_id")
        _bounded_text(self.reason, "reason")
        _bounded_text(self.cleanup, "cleanup")
        _bounded_text(self.exited_at, "exited_at", limit=64)
        if self.return_code is not None and (isinstance(self.return_code, bool) or not isinstance(self.return_code, int)):
            raise ValueError("return_code must be an integer or null")

    def to_dict(self) -> dict[str, Any]:
        return _format({
            "sessionId": self.session_id,
            "reason": self.reason,
            "returnCode": self.return_code,
            "cleanup": self.cleanup,
            "exitedAt": self.exited_at,
        })


@dataclass(frozen=True)
class TerminalReconnectToken:
    """Short-lived, opaque, one-use value; its representation is redacted."""

    value: str = field(repr=False)
    session_id: str
    purpose: str
    expires_at: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or not 32 <= len(self.value) <= 256:
            raise ValueError("terminal token must be an opaque bounded value")
        _bounded_id(self.session_id, "session_id")
        if self.purpose not in {"create", "reconnect"}:
            raise ValueError("terminal token purpose is invalid")
        _bounded_text(self.expires_at, "expires_at", limit=64)

    def __repr__(self) -> str:
        return f"TerminalReconnectToken(value='[REDACTED]', session_id={self.session_id!r}, purpose={self.purpose!r}, expires_at={self.expires_at!r})"

    def to_dict(self) -> dict[str, Any]:
        return _format({
            "value": self.value,
            "sessionId": self.session_id,
            "purpose": self.purpose,
            "expiresAt": self.expires_at,
        })


@dataclass(frozen=True)
class TerminalAuditReceipt:
    """Bounded audit metadata with no terminal transcript or credentials."""

    receipt_id: str
    session_id: str
    target_id: str
    actor_id: str
    instance_id: str
    action: str
    outcome: str
    occurred_at: str
    working_root_digest: str
    generation_digest: str
    input_bytes: int
    output_bytes: int
    replay_dropped_bytes: int
    cleanup: str

    def __post_init__(self) -> None:
        for value, name in (
            (self.receipt_id, "receipt_id"), (self.session_id, "session_id"),
            (self.target_id, "target_id"), (self.actor_id, "actor_id"),
            (self.instance_id, "instance_id"),
        ):
            _bounded_id(value, name)
        if self.action not in _ACTIONS:
            raise ValueError("audit action is invalid")
        if self.outcome not in _OUTCOMES:
            raise ValueError("audit outcome is invalid")
        _bounded_text(self.occurred_at, "occurred_at", limit=64)
        _bounded_text(self.cleanup, "cleanup")
        for value, name in (
            (self.working_root_digest, "working_root_digest"),
            (self.generation_digest, "generation_digest"),
        ):
            if _DIGEST.fullmatch(value) is None:
                raise ValueError(f"{name} must be sha256")
        for value, name in (
            (self.input_bytes, "input_bytes"), (self.output_bytes, "output_bytes"),
            (self.replay_dropped_bytes, "replay_dropped_bytes"),
        ):
            _nonnegative(value, name)

    def to_dict(self) -> dict[str, Any]:
        reconnect_scope = (
            "same_actor_instance_origin_generation_until_process_exit"
            if self.action in {"created", "reconnected", "disconnected"}
            else "none"
        )
        return _format({
            "receiptId": self.receipt_id,
            "sessionId": self.session_id,
            "targetId": self.target_id,
            "actorId": self.actor_id,
            "instanceId": self.instance_id,
            "action": self.action,
            "outcome": self.outcome,
            "occurredAt": self.occurred_at,
            "workingRootDigest": self.working_root_digest,
            "generationDigest": self.generation_digest,
            "inputBytes": self.input_bytes,
            "outputBytes": self.output_bytes,
            "replayDroppedBytes": self.replay_dropped_bytes,
            "cleanup": self.cleanup,
            "localAdapterCleanup": self.cleanup,
            "remoteProcessCleanup": "not_applicable",
            "reconnectScope": reconnect_scope,
        })
