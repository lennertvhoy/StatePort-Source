from __future__ import annotations

import argparse
import base64
import binascii
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import http.cookies
import ipaddress
import json
import mimetypes
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import secrets
import signal
import subprocess
import socket
import stat
import sys
import threading
import time
import uuid
from urllib.parse import parse_qs, unquote, urlsplit
from typing import Any, Mapping

import yaml

from stateport_persistent_app import AppError, LocalLayout, PersistentApp
try:
    from stateport_persistent_app import platform_surface
except ModuleNotFoundError:  # Source-tree consumers may not pre-install sibling packages.
    for _sibling in ("deployment", "governed-runner", "release-contracts", "updater"):
        _sibling_src = Path(__file__).resolve().parents[3] / _sibling / "src"
        if _sibling_src.is_dir():
            sys.path.insert(0, str(_sibling_src))
    from stateport_persistent_app import platform_surface
try:
    from stateport_preview_gateway import PreviewGatewayError, PreviewRouteRegistry
    from stateport_preview_gateway import proxy as preview_proxy
except ModuleNotFoundError:  # Source-tree consumers may not pre-install sibling packages.
    _preview_src = Path(__file__).resolve().parents[3] / "preview-gateway" / "src"
    if _preview_src.is_dir():
        sys.path.insert(0, str(_preview_src))
    from stateport_preview_gateway import PreviewGatewayError, PreviewRouteRegistry
    from stateport_preview_gateway import proxy as preview_proxy
from stateport_persistent_app.activity_receipts import ActivityReceiptError, ActivityReceiptStore
from stateport_persistent_app.conversation_attachments import ConversationAttachmentError, ConversationAttachmentStore
from stateport_persistent_app.execution_host_proxy import ExecutionHostProxy, ExecutionHostProxyError
from stateport_persistent_app.settings import SettingsError, SettingsStore
from stateport_persistent_app.repository_import import RepositoryImportError, RepositoryInspector, RepositorySourcePolicy
from stateport_persistent_app.infrastructure import InfrastructureError, LocalLibvirtAdapter
from stateport_portable_execution import EnvironmentGatedExecution, PortableExecutionError, PortableExecutionService, PortableImportError
try:
    from governed_api import GovernedAPI
except ModuleNotFoundError:  # Source-tree consumers may not pre-install sibling packages.
    for sibling in ("governed-api", "approval-gate", "audit-log", "quota-engine"):
        governed_api_src = Path(__file__).resolve().parents[3] / sibling / "src"
        if governed_api_src.is_dir():
            sys.path.insert(0, str(governed_api_src))
    from governed_api import GovernedAPI
from stateport_context_lifecycle import (
    ContextLifecycleError,
    ContextLifecycleService,
    ContinuityState,
    TokenUsage,
    canonical_digest as context_digest,
)
try:
    from stateport_goal_execution import GoalContractError, GoalExecutionCoordinator, GovernanceRefusal
except ModuleNotFoundError:  # Source-tree consumers may not pre-install sibling packages.
    goal_src = Path(__file__).resolve().parents[3] / "goal-execution" / "src"
    if goal_src.is_dir():
        sys.path.insert(0, str(goal_src))
    from stateport_goal_execution import GoalContractError, GoalExecutionCoordinator, GovernanceRefusal
from stateport_persistent_app.terminal_transport import (
    TERMINAL_SOCKET_FORMAT,
    TERMINAL_SOCKET_PATH,
    TERMINAL_SOCKET_SUBPROTOCOL,
    WebSocketDisconnect,
    WebSocketProtocolError,
    close_payload,
    parse_authentication,
    parse_control,
    read_client_frame,
    server_frame,
    validate_extension_offer,
)


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


_WEB_BUILD_IDENTITY_FILE = "stateport-build.json"
_EXECUTION_HOST_RECEIPT_SCOPE = "execution-host"
_TEMPLATE_UPGRADE_REQUESTER = "persistent-app-upgrade-requester"
_TEMPLATE_UPGRADE_OPERATOR = "persistent-app-upgrade-operator"
_WEB_BUILD_IDENTITY_KEYS = {
    "formatVersion",
    "adapter",
    "mode",
    "sourceCommit",
    "sourceTree",
    "sourceRef",
    "sourceDirty",
    "builtAt",
}
_WEB_BUILD_SOURCE_REF = re.compile(r"[A-Za-z0-9._/@:+-]{1,200}")
_HTTP_TOKEN = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
_WEB_BUILD_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z"
)


class TemplateUpgradeError(ValueError):
    """A safe refusal from the instance-scoped template-upgrade facade."""

    def __init__(self, status: int, code: str, message: str):
        self.status = status
        self.code = code
        super().__init__(message)


def _is_stateport_product_web_root(source_web_root: Path) -> bool:
    """Distinguish the real product frontend from disposable static fixtures."""

    try:
        product_root = source_web_root.parents[1]
    except IndexError:
        return False
    if source_web_root != product_root / "apps" / "web":
        return False
    package_path = source_web_root / "package.json"
    if not package_path.is_file() or package_path.is_symlink():
        return False
    try:
        package = json.loads(package_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("StatePort frontend package identity is unreadable") from exc
    if not isinstance(package, dict) or package.get("name") != "stateport-frontend":
        raise ValueError("StatePort frontend package identity is invalid")
    return True


def _require_production_web_build_identity(built_web_root: Path) -> dict[str, object]:
    marker = built_web_root / _WEB_BUILD_IDENTITY_FILE
    if not marker.is_file() or marker.is_symlink():
        raise ValueError("StatePort production web build identity is missing")
    try:
        if marker.stat().st_size > 1024:
            raise ValueError("StatePort production web build identity is invalid")
        identity = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("StatePort production web build identity is unreadable") from exc
    valid_timestamp = False
    if isinstance(identity, dict):
        built_at = identity.get("builtAt")
        if built_at == "unknown":
            valid_timestamp = True
        elif isinstance(built_at, str) and _WEB_BUILD_TIMESTAMP.fullmatch(built_at):
            try:
                parsed = datetime.fromisoformat(built_at[:-1] + "+00:00")
                valid_timestamp = (
                    parsed.tzinfo is not None
                    and parsed.utcoffset() == timedelta(0)
                    and parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z") == built_at
                )
            except ValueError:
                valid_timestamp = False
    if (
        not isinstance(identity, dict)
        or set(identity) != _WEB_BUILD_IDENTITY_KEYS
        or identity.get("formatVersion") != "stateport.web-build/v3"
        or identity.get("adapter") != "http"
        or identity.get("mode") != "production"
        or not isinstance(identity.get("sourceCommit"), str)
        or (
            identity["sourceCommit"] != "unknown"
            and re.fullmatch(r"[0-9a-f]{40}", identity["sourceCommit"]) is None
        )
        or not isinstance(identity.get("sourceTree"), str)
        or (
            identity["sourceTree"] != "unknown"
            and re.fullmatch(r"[0-9a-f]{40}", identity["sourceTree"]) is None
        )
        or ((identity["sourceCommit"] == "unknown") != (identity["sourceTree"] == "unknown"))
        or not isinstance(identity.get("sourceRef"), str)
        or (
            identity["sourceRef"] != "unknown"
            and _WEB_BUILD_SOURCE_REF.fullmatch(identity["sourceRef"]) is None
        )
        or not isinstance(identity.get("sourceDirty"), bool)
        or (identity["sourceCommit"] == "unknown" and identity["sourceDirty"] is not True)
        or not valid_timestamp
    ):
        raise ValueError(
            "StatePort production web build must identify the HTTP adapter with valid provenance"
        )
    return dict(identity)


def _select_web_root(
    source_web_root: Path,
    *,
    expected_source_commit: str | None = None,
    expected_source_tree: str | None = None,
) -> Path:
    """Select a built root and fail closed for a mislabeled product artifact."""

    if (expected_source_commit is None) != (expected_source_tree is None):
        raise ValueError("expected StatePort web source commit and tree must be supplied together")
    source_web_root = source_web_root.resolve()
    built_web_root = source_web_root / "dist"
    if not (built_web_root / "index.html").is_file():
        if _is_stateport_product_web_root(source_web_root):
            raise ValueError("StatePort production web build is missing")
        return source_web_root
    if _is_stateport_product_web_root(source_web_root):
        identity = _require_production_web_build_identity(built_web_root)
        if expected_source_commit is not None and (
            identity["sourceCommit"] != expected_source_commit
            or identity["sourceTree"] != expected_source_tree
        ):
            raise ValueError(
                "StatePort production web build does not match the configured product commit/tree; "
                "rebuild apps/web before starting the service"
            )
    return built_web_root


def _expected_web_source_identity(repo_root: Mapping[str, str]) -> tuple[str, str]:
    """Bind the production web build marker to the identity that proves it.

    A source checkout binds the marker to the mounted product root's exact
    Git head/tree. A packaged no-checkout image carries a synthesized
    packaged-content commit as its product-root identity instead, so the
    marker is bound to the exact source identity baked into the image
    environment at build time. Both values follow the same exact-or-unknown
    contract as the build marker itself.
    """
    if os.environ.get("STATEPORT_PACKAGED_PRODUCT") != "1":
        return repo_root["gitHead"], repo_root["gitTree"]
    commit = os.environ.get("STATEPORT_BUILD_SOURCE_COMMIT", "unknown")
    tree = os.environ.get("STATEPORT_BUILD_SOURCE_TREE", "unknown")
    if (commit == "unknown") != (tree == "unknown"):
        raise ValueError(
            "packaged StatePort build source commit and tree must both be exact or both be unknown"
        )
    for value in (commit, tree):
        if value != "unknown" and re.fullmatch(r"[0-9a-f]{40}", value) is None:
            raise ValueError("packaged StatePort build source identity is not exact")
    return commit, tree


PREVIEW_DISABLED_CODE = "preview_disabled_same_origin"
PREVIEW_DISABLED_MESSAGE = (
    "Preview execution is disabled for security: preview content is served "
    "from the StatePort origin, where hostile preview JavaScript could reach "
    "the operator session, cookies, storage, and the /v1 control API. "
    "Previews stay off until they are served from a credential-isolated "
    "origin; header filtering is not sufficient. Test and development "
    "fixtures may opt in explicitly through dependency injection."
)
PREVIEW_DISABLED_NEXT_ACTION = (
    "No operator action enables previews. Wait for a StatePort release that "
    "serves previews from a credential-isolated origin."
)


def _preview_enabled(server: object) -> bool:
    """Same-origin previews are disabled unless a test/dev fixture opts in.

    Production and release services never set ``_preview_gateway_enabled``;
    only test fixtures may inject it (see scripts/test_preview_gateway.py).
    """

    return getattr(server, "_preview_gateway_enabled", False) is True


def _preview_availability(server: object) -> dict[str, object]:
    """Typed availability projection for the preview gateway surface."""

    if _preview_enabled(server):
        return {"status": "enabled"}
    return {
        "status": "disabled",
        "code": PREVIEW_DISABLED_CODE,
        "message": PREVIEW_DISABLED_MESSAGE,
        "nextAction": PREVIEW_DISABLED_NEXT_ACTION,
    }


def _preview_registry(server: object) -> PreviewRouteRegistry:
    """Resolve the preview route registry, creating only private state directories.

    The operator-facing registry lives under the persistent layout state root;
    tests may redirect it with STATEPORT_PREVIEW_GATEWAY_STATE_ROOT or inject
    ``server._preview_route_registry`` directly.
    """

    registry = getattr(server, "_preview_route_registry", None)
    if registry is None:
        override = os.environ.get("STATEPORT_PREVIEW_GATEWAY_STATE_ROOT", "").strip()
        root = Path(override) if override else server.layout.state_root / "preview-gateway"
        if not root.is_absolute():
            raise PreviewGatewayError(
                "preview_gateway_unavailable", "preview gateway state root must be absolute"
            )
        registry = PreviewRouteRegistry(root)
        server._preview_route_registry = registry
    return registry


def _preview_mutation_result(mutation: Mapping[str, object]) -> dict[str, object]:
    """Flatten the route and receipt returned by one locked registry mutation."""

    route = mutation.get("route")
    receipt = mutation.get("receipt")
    if not isinstance(route, Mapping) or not isinstance(receipt, Mapping):
        raise PreviewGatewayError("receipt_chain_invalid", "preview mutation returned incomplete evidence")
    return {**dict(route), "receipt": dict(receipt)}


class _WebSocketWriter:
    """Serialize server frames from the input and PTY-output threads."""

    def __init__(self, stream: object) -> None:
        self._stream = stream
        self._mutex = threading.Lock()
        self._closed = False

    def send(self, opcode: int, payload: bytes = b"") -> None:
        with self._mutex:
            if self._closed:
                raise OSError("terminal WebSocket writer is closed")
            self._stream.write(server_frame(opcode, payload))
            self._stream.flush()

    def json(self, value: object) -> None:
        payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        self.send(0x1, payload)

    def close(self, code: int, reason: str) -> None:
        with self._mutex:
            if self._closed:
                return
            self._closed = True
            try:
                self._stream.write(server_frame(0x8, close_payload(code, reason)))
                self._stream.flush()
            except OSError:
                pass


def _is_loopback_service_authority(
    host_header: str,
    expected_port: int,
    external_loopback_port: int | None = None,
) -> bool:
    """Return whether a Host header names this loopback service on an allowed port."""
    try:
        parsed = urlsplit(f"//{host_header}")
        hostname = parsed.hostname
        port = parsed.port
    except (ValueError, AttributeError):
        return False
    allowed_ports = {expected_port}
    if external_loopback_port is not None:
        allowed_ports.add(external_loopback_port)
    if hostname is None or port not in allowed_ports:
        return False
    normalized = hostname.strip().lower()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


class Handler(BaseHTTPRequestHandler):
    server_version = "StatePortLocal/1"
    # RFC 6455 requires the WebSocket handshake response to be HTTP/1.1.
    # BaseHTTPRequestHandler otherwise defaults to HTTP/1.0, which Chromium
    # tolerates but Firefox rejects before it emits the socket open event.
    protocol_version = "HTTP/1.1"

    def _session(self) -> bool:
        try:
            cookie = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
        except http.cookies.CookieError:
            return False
        supplied = cookie.get("stateport_session")
        return bool(supplied and secrets.compare_digest(supplied.value, self.server.session))

    def _send(self, status: int, payload: object, *, content_type: str = "application/json; charset=utf-8", extra: dict[str, str] | None = None) -> None:
        body = payload if isinstance(payload, bytes) else _json_bytes(payload)
        # The WebSocket handshake needs an HTTP/1.1 status line, but ordinary
        # requests deliberately remain one-response-per-connection. Closing
        # prevents rejected or unread request bodies from being reparsed as a
        # second request and lets shutdown join request threads deterministically.
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            # xterm and CodeMirror create runtime <style> elements for measured
            # glyph geometry and editor layout. They remain trusted,
            # same-origin components; scripts, frames, and connections retain
            # their strict directives.
            "style-src-elem 'self' 'unsafe-inline'; style-src-attr 'unsafe-inline'; worker-src 'self' blob:; "
            "font-src 'self' data:; img-src 'self' blob:; connect-src 'self'; "
            "object-src 'none'; frame-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Permissions-Policy",
            "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
        )
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        try:
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            # A browser may cancel a navigation after the operation has already
            # completed. The response is no longer deliverable, and retrying an
            # error response would misclassify the completed operation as 400.
            self.close_connection = True

    def _error(self, status: int, message: str, code: str = "request_failed") -> None:
        request_id = self.headers.get("X-Request-ID") or f"req-{uuid.uuid4().hex[:16]}"
        self._send(status, {"ok": False, "error": {"code": code, "message": message, "diagnostic": {"requestId": request_id}}}, extra={"X-Request-ID": request_id})

    def _body(self, *, maximum_bytes: int = 64 * 1024) -> dict[str, object]:
        if self.headers.get_all("Transfer-Encoding", failobj=[]):
            raise ValueError("request transfer encoding is unsupported")
        lengths = self.headers.get_all("Content-Length", failobj=[])
        if len(lengths) > 1:
            raise ValueError("request content length is ambiguous")
        raw_length = lengths[0] if lengths else "0"
        if len(raw_length) > 20 or re.fullmatch(r"[0-9]+", raw_length) is None:
            raise ValueError("request content length is invalid")
        length = int(raw_length)
        if length > maximum_bytes:
            raise ValueError("request body is too large")
        if length == 0:
            return {}
        value = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("request body must be a JSON object")
        return value

    @staticmethod
    def _local_child(value: str, root: Path, label: str) -> Path:
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            raise ValueError(f"{label} must be an absolute local path")
        if any(part in {"", ".", ".."} for part in candidate.parts):
            raise ValueError(f"{label} must not contain traversal")
        root = root.resolve()
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"{label} must remain under the StatePort local boundary") from exc
        if candidate.exists() and candidate.is_symlink():
            raise ValueError(f"{label} must not be a symlink")
        parent = candidate.parent
        while parent != root and parent != parent.parent:
            if parent.is_symlink():
                raise ValueError(f"{label} has a symlinked parent")
            parent = parent.parent
        resolved = candidate.resolve(strict=False)
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"{label} must remain under the StatePort local boundary") from exc
        return candidate

    def _execution(self, app: PersistentApp) -> PortableExecutionService:
        return self.server.execution

    def _expected_origin(self) -> str:
        port = self.server.external_loopback_port or self.server.server_address[1]
        return f"http://127.0.0.1:{port}"

    def _valid_request_host(self) -> bool:
        """Reject DNS-rebinding aliases before serving session or API data.

        Every loopback alias (``127.0.0.1``, ``localhost``, ``[::1]``) on the
        bound port names this same service; an explicitly configured loopback
        port is additionally allowed for a container's host port mapping.
        """

        values = self.headers.get_all("Host", failobj=[])
        return len(values) == 1 and _is_loopback_service_authority(
            values[0],
            self.server.server_address[1],
            self.server.external_loopback_port,
        )

    def _valid_loopback_origin(self, origin: str) -> bool:
        """Return whether an Origin value names this loopback service.

        Any loopback alias on the bound port is accepted; everything else,
        including non-http schemes, credentials, paths, or missing ports,
        fails closed.
        """
        try:
            parts = urlsplit(origin)
            port = parts.port
        except ValueError:
            return False
        if (
            parts.scheme != "http"
            or parts.path not in ("", "/")
            or parts.query
            or parts.fragment
            or parts.username is not None
            or parts.password is not None
            or parts.hostname is None
            or port
            != (self.server.external_loopback_port or self.server.server_address[1])
        ):
            return False
        return _is_loopback_bind_host(parts.hostname)

    def _mutation_security(self, label: str) -> None:
        origin_values = self.headers.get_all("Origin", failobj=[])
        token_values = self.headers.get_all("X-StatePort-CSRF", failobj=[])
        if len(origin_values) != 1 or len(token_values) != 1:
            raise PermissionError(f"{label} mutation authorization failed")
        supplied_origin = origin_values[0]
        supplied_token = token_values[0]
        if not self._valid_loopback_origin(supplied_origin) or not secrets.compare_digest(supplied_token, self.server.csrf_token):
            raise PermissionError(f"{label} mutation authorization failed")

    def _file_request_security(self) -> None:
        self._mutation_security("file workspace")

    def _attachment_request_security(self) -> None:
        self._mutation_security("conversation attachment")

    def _attachment_scope(self, instance_id: str):
        thread, participant_id, binding = self.server.conversation_for_instance(instance_id)
        return thread, participant_id, binding

    def _single_header(self, name: str, *, required: bool = True) -> str | None:
        values = self.headers.get_all(name, failobj=[])
        if len(values) != 1:
            if not values and not required:
                return None
            raise WebSocketProtocolError(f"terminal WebSocket {name} header is invalid")
        value = values[0]
        if not isinstance(value, str) or not value or "\r" in value or "\n" in value:
            raise WebSocketProtocolError(f"terminal WebSocket {name} header is invalid")
        return value

    def _terminal_upgrade_key(self) -> str:
        if self.path != TERMINAL_SOCKET_PATH or self.request_version != "HTTP/1.1":
            raise WebSocketProtocolError("terminal WebSocket request target is invalid")
        host = self._single_header("Host")
        assert host is not None
        if not _is_loopback_service_authority(host, self.server.server_address[1], self.server.external_loopback_port):
            raise WebSocketProtocolError("terminal WebSocket host is invalid")
        origin = self._single_header("Origin")
        assert origin is not None
        if not self._valid_loopback_origin(origin):
            raise WebSocketProtocolError("terminal WebSocket origin is invalid")
        if self._single_header("Upgrade").lower() != "websocket":
            raise WebSocketProtocolError("terminal WebSocket upgrade is invalid")
        connection = self._single_header("Connection")
        assert connection is not None
        tokens = [item.strip().lower() for item in connection.split(",")]
        if (
            any(_HTTP_TOKEN.fullmatch(item) is None for item in tokens)
            or len(set(tokens)) != len(tokens)
            or "upgrade" not in tokens
            or "close" in tokens
        ):
            raise WebSocketProtocolError("terminal WebSocket connection header is invalid")
        if self._single_header("Sec-WebSocket-Version") != "13":
            raise WebSocketProtocolError("terminal WebSocket version is unsupported")
        if self._single_header("Sec-WebSocket-Protocol") != TERMINAL_SOCKET_SUBPROTOCOL:
            raise WebSocketProtocolError("terminal WebSocket subprotocol is invalid")
        extension = self._single_header("Sec-WebSocket-Extensions", required=False)
        validate_extension_offer(extension)
        if self.headers.get_all("Transfer-Encoding", failobj=[]) or self.headers.get_all("Content-Length", failobj=[]):
            raise WebSocketProtocolError("terminal WebSocket upgrade may not carry a request body")
        supplied_key = self._single_header("Sec-WebSocket-Key")
        assert supplied_key is not None
        try:
            decoded_key = base64.b64decode(supplied_key, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise WebSocketProtocolError("terminal WebSocket key is invalid") from exc
        if len(decoded_key) != 16 or base64.b64encode(decoded_key).decode("ascii") != supplied_key:
            raise WebSocketProtocolError("terminal WebSocket key is invalid")
        return base64.b64encode(
            hashlib.sha1((supplied_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii"), usedforsecurity=False).digest()
        ).decode("ascii")

    def _handle_terminal_socket(self) -> None:
        if not self._session():
            self._error(401, "local browser session is required", "session_required")
            return
        try:
            accept_key = self._terminal_upgrade_key()
        except WebSocketProtocolError:
            self._error(400, "terminal WebSocket upgrade was refused", "terminal_upgrade_refused")
            return

        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept_key)
        self.send_header("Sec-WebSocket-Protocol", TERMINAL_SOCKET_SUBPROTOCOL)
        self.end_headers()
        self.close_connection = True
        writer = _WebSocketWriter(self.wfile)
        registered = False
        connection: dict[str, object] | None = None
        output_thread: threading.Thread | None = None
        output_stop = threading.Event()
        explicit_end = False
        protocol_failure = False
        transport_detached = False

        try:
            self.server.register_terminal_socket(self.connection)
            registered = True
            self.connection.settimeout(5.0)
            first_frame = read_client_frame(self.rfile)
            if first_frame.opcode != 0x1:
                raise WebSocketProtocolError("terminal authentication must be the first text frame", 1008)
            authentication = parse_authentication(first_frame.payload)
            connection = self.server.accept_terminal_socket(authentication, self._expected_origin())
            self.connection.settimeout(None)
            session = connection["session"]
            writer.json({
                "formatVersion": TERMINAL_SOCKET_FORMAT,
                "type": "ready",
                "sessionId": session.session_id,
                "purpose": authentication["purpose"],
                "targetClass": session.target_class,
                "reconnect": session.target_class == "local_pty",
            })

            def pump_output() -> None:
                try:
                    while not output_stop.is_set():
                        output = connection["gateway"].read_frame(
                            connection["handshake"], session_id=session.session_id,
                            maximum_bytes=65_536, timeout_seconds=0.2,
                        )
                        if output.data:
                            writer.send(0x2, output.data)
                        if output.eof:
                            writer.close(1000, "process_exit")
                            try:
                                self.connection.shutdown(socket.SHUT_RDWR)
                            except OSError:
                                pass
                            return
                except Exception:  # noqa: BLE001 - transport closes without exposing broker details
                    if not output_stop.is_set():
                        writer.close(1011, "terminal_output_refused")
                        try:
                            self.connection.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass

            output_thread = threading.Thread(target=pump_output, name="stateport-terminal-output", daemon=True)
            output_thread.start()

            from stateport_terminal_broker import GatewayFrame

            while True:
                frame = read_client_frame(self.rfile)
                if frame.opcode == 0x2:
                    if not frame.payload:
                        raise WebSocketProtocolError("terminal input frame may not be empty", 1008)
                    connection["gateway"].handle_frame(
                        connection["handshake"], session_id=session.session_id,
                        frame=GatewayFrame("input", frame.payload),
                    )
                    continue
                if frame.opcode == 0x1:
                    control = parse_control(frame.payload)
                    if control["type"] == "resize":
                        connection["gateway"].handle_frame(
                            connection["handshake"], session_id=session.session_id,
                            frame=GatewayFrame("resize", columns=control["columns"], rows=control["rows"]),
                        )
                        continue
                    connection["gateway"].handle_frame(
                        connection["handshake"], session_id=session.session_id,
                        frame=GatewayFrame("close"),
                    )
                    explicit_end = True
                    writer.close(1000, "operator_closed")
                    break
                if frame.opcode == 0x8:
                    transport_detached = True
                    break
                if frame.opcode == 0x9:
                    writer.send(0xA, frame.payload)
                    continue
                if frame.opcode == 0xA:
                    continue
        except WebSocketDisconnect:
            pass
        except (socket.timeout, TimeoutError):
            protocol_failure = True
            writer.close(1008, "terminal_authentication_timeout")
        except WebSocketProtocolError as exc:
            protocol_failure = True
            writer.close(exc.close_code, "terminal_protocol_refused")
        except Exception:  # noqa: BLE001 - authenticated boundary redacts broker and ticket details
            protocol_failure = True
            writer.close(1008, "terminal_access_refused")
        finally:
            output_stop.set()
            cleanup_confirmed = True
            if connection is not None and not explicit_end:
                try:
                    from stateport_terminal_broker import GatewayFrame

                    cleanup_result = connection["gateway"].handle_frame(
                        connection["handshake"], session_id=connection["session"].session_id,
                        frame=GatewayFrame("close" if protocol_failure else "disconnect"),
                    )
                    receipt = cleanup_result[1] if isinstance(cleanup_result, tuple) else cleanup_result
                    cleanup_confirmed = getattr(receipt, "cleanup", None) in {"terminated", "not_required"}
                except Exception:  # noqa: BLE001 - session may already have exited or broker may be closing
                    cleanup_confirmed = False
            if transport_detached:
                writer.close(
                    1000 if cleanup_confirmed else 1011,
                    "transport_detached" if cleanup_confirmed else "terminal_cleanup_unverified",
                )
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            if output_thread is not None:
                output_thread.join(timeout=1.0)
            if registered:
                self.server.unregister_terminal_socket(self.connection)

    # ------------------------------------------------------------------
    # Preview gateway: authenticated loopback reverse proxy (HTTP + WS)
    # ------------------------------------------------------------------

    def _preview_target(self) -> tuple[dict[str, object], str]:
        split = urlsplit(self.path)
        segments = split.path.split("/")
        if len(segments) < 4 or segments[0] != "" or segments[1] != "preview":
            raise PreviewGatewayError("preview_route_not_found", "preview route not found")
        rest = segments[4:]
        if rest == [""]:
            rest = []
        for segment in rest:
            decoded = unquote(segment)
            if (
                decoded in {"", ".", ".."}
                or "/" in decoded
                or "\\" in decoded
                or len(decoded) > 256
                or any(ord(character) < 32 or ord(character) == 127 for character in decoded)
            ):
                raise PreviewGatewayError(
                    "preview_path_refused", "the preview upstream path is refused"
                )
        upstream_path = "/" + "/".join(unquote(segment) for segment in rest)
        if split.query:
            if len(split.query) > 4096 or "\r" in split.query or "\n" in split.query:
                raise PreviewGatewayError(
                    "preview_path_refused", "the preview upstream query is refused"
                )
            upstream_path = f"{upstream_path}?{split.query}"
        route = _preview_registry(self.server).resolve(unquote(segments[2]), unquote(segments[3]))
        return route, upstream_path

    def _preview_request_body(self) -> bytes:
        if self.headers.get_all("Transfer-Encoding", failobj=[]):
            raise PreviewGatewayError(
                "preview_request_refused", "preview request transfer encoding is unsupported"
            )
        lengths = self.headers.get_all("Content-Length", failobj=[])
        if len(lengths) > 1:
            raise PreviewGatewayError(
                "preview_request_refused", "preview request content length is ambiguous"
            )
        raw_length = lengths[0] if lengths else "0"
        if len(raw_length) > 20 or re.fullmatch(r"[0-9]+", raw_length) is None:
            raise PreviewGatewayError(
                "preview_request_refused", "preview request content length is invalid"
            )
        length = int(raw_length)
        if length > preview_proxy.MAX_REQUEST_BODY_BYTES:
            raise PreviewGatewayError(
                "preview_request_refused", "preview request body is too large"
            )
        return self.rfile.read(length) if length else b""

    def _preview_upgrade_key(self) -> tuple[str, tuple[str, ...]]:
        if self.request_version != "HTTP/1.1":
            raise WebSocketProtocolError("preview WebSocket request target is invalid")
        host = self._single_header("Host")
        assert host is not None
        if not _is_loopback_service_authority(host, self.server.server_address[1], self.server.external_loopback_port):
            raise WebSocketProtocolError("preview WebSocket host is invalid")
        origin = self._single_header("Origin")
        assert origin is not None
        if not self._valid_loopback_origin(origin):
            raise WebSocketProtocolError("preview WebSocket origin is invalid")
        if self._single_header("Upgrade").lower() != "websocket":
            raise WebSocketProtocolError("preview WebSocket upgrade is invalid")
        connection = self._single_header("Connection")
        assert connection is not None
        tokens = [item.strip().lower() for item in connection.split(",")]
        if (
            any(_HTTP_TOKEN.fullmatch(item) is None for item in tokens)
            or len(set(tokens)) != len(tokens)
            or "upgrade" not in tokens
            or "close" in tokens
        ):
            raise WebSocketProtocolError("preview WebSocket connection header is invalid")
        if self._single_header("Sec-WebSocket-Version") != "13":
            raise WebSocketProtocolError("preview WebSocket version is unsupported")
        extension = self._single_header("Sec-WebSocket-Extensions", required=False)
        validate_extension_offer(extension)
        if self.headers.get_all("Transfer-Encoding", failobj=[]) or self.headers.get_all("Content-Length", failobj=[]):
            raise WebSocketProtocolError("preview WebSocket upgrade may not carry a request body")
        supplied_key = self._single_header("Sec-WebSocket-Key")
        assert supplied_key is not None
        try:
            decoded_key = base64.b64decode(supplied_key, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise WebSocketProtocolError("preview WebSocket key is invalid") from exc
        if len(decoded_key) != 16 or base64.b64encode(decoded_key).decode("ascii") != supplied_key:
            raise WebSocketProtocolError("preview WebSocket key is invalid")
        subprotocols = preview_proxy.validate_subprotocol_offer(
            self._single_header("Sec-WebSocket-Protocol", required=False)
        )
        accept_key = base64.b64encode(
            hashlib.sha1((supplied_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii"), usedforsecurity=False).digest()
        ).decode("ascii")
        return accept_key, subprotocols

    def _handle_preview(self) -> None:
        if not _preview_enabled(self.server):
            self._error(403, PREVIEW_DISABLED_MESSAGE, PREVIEW_DISABLED_CODE)
            return
        if self.command not in {"GET", "HEAD"}:
            self._mutation_security("preview proxy")
        if not self._session():
            self._error(401, "local browser session is required", "session_required")
            return
        if (self.headers.get("Upgrade") or "").lower() == "websocket":
            if self.command != "GET":
                self._error(405, "preview WebSocket upgrade requires GET", "preview_upgrade_refused")
                return
            self._handle_preview_socket()
            return
        self._handle_preview_http()

    def _handle_preview_http(self) -> None:
        try:
            route, upstream_path = self._preview_target()
            status, headers, payload = preview_proxy.proxy_http(
                route,
                method=self.command,
                upstream_path=upstream_path,
                request_headers={name: value for name, value in self.headers.items()},
                body=self._preview_request_body(),
            )
        except PreviewGatewayError as exc:
            status_code = 404 if exc.code == "preview_route_not_found" else (502 if exc.code == "preview_upstream_unavailable" else 409)
            self._error(status_code, str(exc)[:512], exc.code)
            return
        self.close_connection = True
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _handle_preview_socket(self) -> None:
        try:
            accept_key, subprotocols = self._preview_upgrade_key()
            route, upstream_path = self._preview_target()
            upstream, negotiated = preview_proxy.upstream_upgrade(
                route, upstream_path=upstream_path, subprotocols=subprotocols
            )
        except WebSocketProtocolError:
            self._error(400, "preview WebSocket upgrade was refused", "preview_upgrade_refused")
            return
        except PreviewGatewayError as exc:
            status_code = 404 if exc.code == "preview_route_not_found" else (502 if exc.code in {"preview_upstream_unavailable", "preview_upgrade_refused"} else 409)
            self._error(status_code, str(exc)[:512], exc.code)
            return

        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept_key)
        if negotiated is not None:
            self.send_header("Sec-WebSocket-Protocol", negotiated)
        self.end_headers()
        self.close_connection = True
        writer = _WebSocketWriter(self.wfile)
        stop = threading.Event()

        def pump_upstream() -> None:
            try:
                while not stop.is_set():
                    frame = preview_proxy.read_upstream_frame(upstream)
                    writer.send(frame.opcode, frame.payload)
                    if frame.opcode == 0x8:
                        try:
                            self.connection.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                        return
            except Exception:  # noqa: BLE001 - transport closes without exposing upstream details
                if not stop.is_set():
                    writer.close(1011, "preview_upstream_detached")
                    try:
                        self.connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

        pump = threading.Thread(target=pump_upstream, name="stateport-preview-upstream", daemon=True)
        pump.start()
        try:
            while True:
                frame = read_client_frame(self.rfile)
                if frame.opcode in (0x1, 0x2, 0x9, 0xA):
                    preview_proxy.write_client_frame(upstream, frame.opcode, frame.payload)
                    continue
                if frame.opcode == 0x8:
                    try:
                        preview_proxy.write_client_frame(upstream, 0x8, frame.payload)
                    except OSError:
                        pass
                    writer.close(1000, "operator_closed")
                    break
        except WebSocketDisconnect:
            pass
        except (socket.timeout, TimeoutError):
            writer.close(1008, "preview_transport_timeout")
        except WebSocketProtocolError as exc:
            writer.close(exc.close_code, "preview_protocol_refused")
        except Exception:  # noqa: BLE001 - authenticated boundary redacts upstream details
            writer.close(1011, "preview_relay_refused")
        finally:
            stop.set()
            try:
                upstream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            upstream.close()
            pump.join(timeout=1.0)
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    @staticmethod
    def _query_path(raw_query: str) -> str:
        values = parse_qs(raw_query, keep_blank_values=True, strict_parsing=True)
        if set(values) != {"path"} or len(values["path"]) != 1:
            raise ValueError("file workspace read requires exactly one path")
        return values["path"][0]

    @staticmethod
    def _strict_body(body: dict[str, object], required: set[str]) -> None:
        if set(body) != required:
            raise ValueError("request shape is invalid")

    @staticmethod
    def _bounded_static(root: Path, relative: str) -> Path | None:
        if not relative or relative.startswith("/") or relative.endswith("/") or "//" in relative or "\\" in relative or "%" in relative:
            return None
        current = root
        for component in relative.split("/"):
            if component in {"", ".", ".."} or component != component.strip() or current.is_symlink():
                return None
            current = current / component
        return current if current.is_file() and not current.is_symlink() else None

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if not self._valid_request_host():
            self._error(421, "request host does not match the loopback service", "invalid_host")
            return
        try:
            if path == TERMINAL_SOCKET_PATH:
                self._handle_terminal_socket()
                return
            if path.startswith("/preview/"):
                self._handle_preview()
                return
            if path == "/session":
                self._send(200, {"ok": True, "result": {"session": "local", "csrfToken": self.server.csrf_token}}, extra={"Set-Cookie": f"stateport_session={self.server.session}; HttpOnly; SameSite=Strict; Path=/"})
                return
            if path == "/health":
                self._send(200, {"ok": True, "result": {"status": "ok", "service": "stateport", "identity": "local-operator"}})
                return
            if path == "/favicon.ico":
                self._send(204, b"", content_type="image/x-icon")
                return
            vite_asset = path.lstrip("/") if path.startswith("/") else ""
            if vite_asset in self.server.vite_asset_paths:
                target = self._bounded_static(self.server.web_root, vite_asset)
                if target is None:
                    self._error(404, "application asset not found", "not_found")
                    return
                guessed = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
                content_type = "text/javascript; charset=utf-8" if target.suffix == ".js" else guessed
                if target.suffix in {".css", ".json"}:
                    content_type = f"{guessed}; charset=utf-8"
                self._send(200, target.read_bytes(), content_type=content_type)
                return
            if path in {"/", "/index.html"}:
                filename = "index.html"
                target = self.server.web_root / filename
                if not target.is_file():
                    self._error(404, "dashboard asset not found", "not_found")
                    return
                content_type = "text/html; charset=utf-8"
                self._send(200, target.read_bytes(), content_type=content_type)
                return
            if not self._session():
                self._error(401, "local browser session is required", "session_required")
                return
            platform_surface.require_platform_operator_for_path(self.server, path)
            app = self.server.source_app()
            if path == "/v1/provider/status":
                status = self.server.provider_setup.status()
                if not self.server._provider_execution_allowed:
                    status["connected"] = False
                    status["detail"] = "Provider execution is disabled in the validation release profile. Inspect status in the accepted installed runtime before enabling provider work."
                self._send(200, {"ok": True, "result": status})
                return
            if path == "/v1/settings":
                self._send(200, {"ok": True, "result": self.server.settings_store().projection()})
                return
            if path == "/v1/status":
                self._send(200, {"ok": True, "result": {**self.server.source_app().product_status(), "actor": self.server.actor_projection()}})
                return
            if path == "/v1/operations":
                from .operations import operation_projection
                self._send(200, {"ok": True, "result": operation_projection(app, self._execution(app))})
                return
            if path == "/v1/instances":
                self._send(200, {"ok": True, "result": {"instances": app.instance_list_public()}})
                return
            if path == "/v1/applications":
                self._send(200, {"ok": True, "result": {"applications": self.server.application_catalog()}})
                return
            if path == "/v1/sources":
                self._send(200, {"ok": True, "result": {"sources": self.server.source_app().canonical_source_registry()}})
                return
            if path == "/v1/repository-import/local-candidates":
                self._send(200, {"ok": True, "result": {"candidates": self.server.repository_inspector.local_candidates(), "policy": self.server.repository_inspector.policy.to_dict()}})
                return
            if path.startswith("/v1/sources/"):
                parts = [unquote(part) for part in path.split("/") if part]
                source_id = parts[2] if len(parts) == 3 and parts[:2] == ["v1", "sources"] else ""
                if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,159}", source_id):
                    self._error(404, "application source was not found", "source_not_found")
                    return
                self.server.require_actor_permission("platform.source.inspect")
                try:
                    result = self.server.source_app().canonical_source_operator_projection(source_id)
                except AppError:
                    self._error(404, "application source was not found", "source_not_found")
                    return
                self._send(200, {"ok": True, "result": result})
                return
            if path == "/v1/application-experiences":
                self._send(200, {"ok": True, "result": {"experiences": self.server.application_experiences()}})
                return
            if path == "/v1/platform/statebench":
                self.server.require_actor_permission("platform.statebench.read")
                self._send(200, {"ok": True, "result": self._execution(app).statebench_matrix()})
                return
            if path == "/v1/execution/engines":
                self._send(200, {"ok": True, "result": {"engines": self._execution(app).engines()}})
                return
            parts = [unquote(part) for part in path.split("/") if part]
            if len(parts) == 5 and parts[:3] == ["v1", "execution-host", "workspaces"] and parts[4] == "authority":
                if self.server.actor_role != "platform_operator":
                    raise PermissionError("platform operator authorization is required")
                self.server.require_actor_permission("platform.authority.mutate")
                self._send(200, {"ok": True, "result": self.server.execution_host.workspace_authority(parts[3])})
                return
            if len(parts) == 6 and parts[:3] == ["v1", "execution-host", "workspaces"] and parts[4:] == ["terminal", "target"]:
                with self.server._terminal_mutex:
                    target = self.server._terminal_binding_locked(parts[3], workspace_only=True)[5]
                    self._send(200, {"ok": True, "result": {"target": target.to_dict()}})
                return
            if path == "/v1/execution-host":
                self._send(200, {"ok": True, "result": {"executionHost": self.server.execution_host.status()}})
                return
            if path == "/v1/execution-host/receipts":
                self._send(200, {"ok": True, "result": self.server.execution_host_receipts()})
                return
            if path == "/v1/execution-host/workloads":
                self._send(200, {"ok": True, "result": self.server.execution_host.list()})
                return
            if path.startswith("/v1/execution-host/workloads/") and path.endswith("/logs"):
                workload_id = unquote(path[len("/v1/execution-host/workloads/"):-len("/logs")])
                self._send(200, {"ok": True, "result": self.server.execution_host.logs(workload_id)})
                return
            if path.startswith("/v1/execution-host/workloads/"):
                workload_id = unquote(path[len("/v1/execution-host/workloads/"):])
                self._send(200, {"ok": True, "result": self.server.execution_host.status_of(workload_id)})
                return
            if path.startswith("/v1/runs/") and path.endswith("/bundle"):
                run_id = unquote(path[len("/v1/runs/"):-len("/bundle")])
                self._send(200, {"ok": True, "result": self._execution(app).bundle(run_id)})
                return
            if path.startswith("/v1/runs/") and path.endswith("/statebench"):
                run_id = unquote(path[len("/v1/runs/"):-len("/statebench")])
                self._send(200, {"ok": True, "result": self._execution(app).statebench(run_id)})
                return
            if path.startswith("/v1/runs/"):
                run_id = unquote(path.split("/", 3)[3])
                self._send(200, {"ok": True, "result": self._execution(app).inspect(run_id)})
                return
            if path.startswith("/v1/instances/"):
                parts = [unquote(part) for part in path.split("/") if part]
                if len(parts) < 3:
                    self._error(404, "instance route not found", "not_found")
                    return
                instance_id = parts[2]
                if len(parts) == 5 and parts[3] == "file-workspace":
                    operation = parts[4]
                    if operation not in {"listDirectory", "readFile", "readFileMetadata"}:
                        self._error(404, "file workspace operation not found", "not_found")
                        return
                    selected_path = self._query_path(urlsplit(self.path).query)
                    broker = self.server.file_workspace(instance_id)
                    identity = self.server.file_workspace_identity(broker)
                    if operation == "listDirectory":
                        result = broker.list_directory(selected_path, **identity).to_dict()
                    elif operation == "readFile":
                        result = broker.read_file(selected_path, **identity).to_dict()
                    else:
                        result = broker.read_file_metadata(selected_path, **identity).to_dict()
                    self._send(200, {"ok": True, "result": result})
                    return
                if len(parts) == 3:
                    self._send(200, {"ok": True, "result": app.inspect(instance_id)})
                    return
                if parts[3] == "experience":
                    entry = app.catalog.get(instance_id)
                    result = self.server.application_experience(str(entry.get("applicationId", "")), instance_id)
                    if result is None:
                        self._error(404, "application experience is not registered", "experience_unavailable")
                        return
                    result = dict(result)
                    result["instanceBinding"] = {
                        "instanceId": instance_id,
                        "applicationId": str(entry.get("applicationId", "")),
                        "descriptorDigest": result["descriptorIdentity"]["descriptorDigest"],
                    }
                    self._send(200, {"ok": True, "result": result})
                    return
                if parts[3] == "conversation" and len(parts) == 4:
                    self._send(200, {"ok": True, "result": self.server.conversation_presentation(instance_id)})
                    return
                if parts[3:5] == ["conversation", "retention"] and len(parts) == 5:
                    self._send(200, {"ok": True, "result": self.server.conversation_retention(instance_id)})
                    return
                if len(parts) == 5 and parts[3:] == ["conversation", "attachments"]:
                    self._attachment_request_security()
                    thread, _participant_id, _binding = self._attachment_scope(instance_id)
                    self._send(200, {"ok": True, "result": self.server.attachments.list_metadata(instance_id=instance_id, conversation_id=thread.conversation_id)})
                    return
                if len(parts) == 6 and parts[3:5] == ["conversation", "attachments"]:
                    self._attachment_request_security()
                    thread, _participant_id, _binding = self._attachment_scope(instance_id)
                    self._send(200, {"ok": True, "result": self.server.attachments.detail(instance_id=instance_id, conversation_id=thread.conversation_id, attachment_id=parts[5])})
                    return
                if parts[3] == "activity" and len(parts) == 4:
                    self._send(200, {"ok": True, "result": self.server.activity_projection(instance_id)})
                    return
                if parts[3] == "receipts" and len(parts) == 4:
                    self._send(200, {"ok": True, "result": self.server.receipt_index_projection(instance_id)})
                    return
                if parts[3] == "receipts" and len(parts) == 5:
                    self._send(200, {"ok": True, "result": self.server.receipt_detail_projection(instance_id, parts[4])})
                    return
                if parts[3] == "settings" and len(parts) == 4:
                    self._send(200, {"ok": True, "result": self.server.settings_store(instance_id).projection()})
                    return
                if parts[3] == "context-lifecycle" and len(parts) == 4:
                    _entry, root = app._entry(instance_id)
                    self._send(200, {"ok": True, "result": self.server.context_lifecycle_view(instance_id, root)})
                    return
                if parts[3] == "goal-execution" and len(parts) == 4:
                    self._send(200, {"ok": True, "result": self.server.goal_execution_view(instance_id)})
                    return
                if parts[3] == "infrastructure" and len(parts) == 4:
                    self._send(200, {"ok": True, "result": self.server.infrastructure_projection(instance_id)})
                    return
                if parts[3:] == ["infrastructure", "grant"]:
                    self._send(200, {"ok": True, "result": self.server.infrastructure_adapter(instance_id).daily_driver_grant()})
                    return
                if parts[3] == "actions":
                    entry = app.catalog.get(instance_id)
                    if isinstance(entry.get("metadata"), Mapping) and entry["metadata"].get("externalRepository") is True:
                        self._send(200, {"ok": True, "result": {"actions": [], "availability": "environment_gated", "reason": "infrastructure_operations_not_connected"}})
                        return
                    allow_development_candidate = app.development_candidate_testing_allowed(instance_id)
                    self._send(200, {"ok": True, "result": {"actions": self._execution(app).action_list(instance_id, allow_development_candidate=allow_development_candidate)}})
                    return
                if parts[3] == "execution" and len(parts) == 5 and parts[4] == "engines":
                    self._send(200, {"ok": True, "result": {"engines": self._execution(app).engines()}})
                    return
                if parts[3] == "execution" and len(parts) == 5 and parts[4] == "history":
                    self._send(200, {"ok": True, "result": {"runs": self._execution(app).history(instance_id)}})
                    return
                data = app.inspect(instance_id)
                field = parts[3]
                if field == "health": result = {"health": data["health"]}
                elif field == "source": result = data["source"]
                elif field == "ownership": result = data["ownership"]
                elif field == "recovery": result = app.recovery_status(instance_id)
                elif field == "runs": result = {"runs": data["runs"]}
                elif field == "approvals": result = {"approvals": data["approvals"]}
                else:
                    self._error(404, "instance route not found", "not_found")
                    return
                self._send(200, {"ok": True, "result": result})
                return
            if path == "/v1/approvals":
                self._send(200, {"ok": True, "result": self.server.approvals_projection()})
                return
            if path == "/v1/privacy/export":
                self.server.require_actor_permission("platform.privacy.export")
                self._send(200, {"ok": True, "result": self.server.privacy_export()})
                return
            if path == "/v1/deployments":
                self._send(200, {"ok": True, "result": platform_surface.deployments_index(self.server)})
                return
            if path.startswith("/v1/deployments/"):
                parts = [unquote(part) for part in path.split("/") if part]
                if len(parts) != 3:
                    self._error(404, "deployment route not found", "not_found")
                    return
                self._send(200, {"ok": True, "result": platform_surface.deployment_detail(self.server, parts[2])})
                return
            if path == "/v1/authority/profiles":
                platform_surface.require_platform_operator(self.server)
                self._send(200, {"ok": True, "result": platform_surface.authority_profiles(self.server)})
                return
            if path == "/v1/authority/index":
                platform_surface.require_platform_operator(self.server)
                self._send(200, {"ok": True, "result": platform_surface.authority_index(self.server)})
                return
            if path == "/v1/authority/grants":
                platform_surface.require_platform_operator(self.server)
                self._send(200, {"ok": True, "result": platform_surface.authority_grants(self.server)})
                return
            if path.startswith("/v1/authority/grants/"):
                parts = [unquote(part) for part in path.split("/") if part]
                if len(parts) != 4:
                    self._error(404, "authority grant route not found", "not_found")
                    return
                platform_surface.require_platform_operator(self.server)
                self._send(200, {"ok": True, "result": platform_surface.authority_grant_detail(self.server, parts[3])})
                return
            if path == "/v1/updater/status":
                self._send(200, {"ok": True, "result": platform_surface.updater_status(self.server)})
                return
            if path == "/v1/updater/policy":
                self._send(200, {"ok": True, "result": platform_surface.updater_policy(self.server)})
                return
            if path == "/v1/updater/rollback":
                self._send(200, {"ok": True, "result": platform_surface.updater_rollback(self.server)})
                return
            if path == "/v1/preview-routes":
                if not _preview_enabled(self.server):
                    self._send(200, {"ok": True, "result": {"availability": _preview_availability(self.server), "routes": []}})
                    return
                self._send(200, {"ok": True, "result": {"availability": _preview_availability(self.server), "routes": _preview_registry(self.server).list_routes()}})
                return
            self._error(404, "route not found", "not_found")
        except EnvironmentGatedExecution as exc:
            self._send(200, {"ok": True, "result": exc.payload})
        except ContextLifecycleError as exc:
            self._error(409, "the context lifecycle request was refused", exc.reason_code)
        except GovernanceRefusal as exc:
            self._error(409, "the governed goal operation was refused", exc.code)
        except GoalContractError:
            self._error(409, "the governed goal contract was refused", "goal_contract_refused")
        except SettingsError as exc:
            self._error(409, str(exc), "settings_request_refused")
        except platform_surface.PlatformSurfaceError as exc:
            status = 404 if exc.code.endswith("_not_found") else 409
            self._error(status, str(exc)[:512], exc.code)
        except ActivityReceiptError as exc:
            self._error(409, str(exc), "activity_receipts_refused")
        except ConversationAttachmentError as exc:
            self._error(409, str(exc), "conversation_attachment_refused")
        except TemplateUpgradeError as exc:
            self._error(exc.status, str(exc)[:512], exc.code)
        except PermissionError:
            if path == "/v1/settings" or "/settings" in path:
                self._error(403, "settings access denied", "settings_access_denied")
            elif "/terminal/" in path:
                self._error(403, "terminal access denied", "terminal_access_denied")
            elif "/goal-execution" in path:
                self._error(403, "goal execution access denied", "goal_execution_access_denied")
            elif path == "/v1/platform/statebench":
                self._error(403, "platform StateBench access denied", "platform_operation_denied")
            elif path.startswith("/v1/deployments"):
                self._error(403, "deployment access denied", "deployment_access_denied")
            elif path.startswith("/v1/authority"):
                self._error(403, "authority access denied", "authority_access_denied")
            elif path.startswith("/v1/updater"):
                self._error(403, "updater access denied", "updater_access_denied")
            elif path.startswith("/v1/preview-routes"):
                self._error(403, "preview route access denied", "preview_route_access_denied")
            elif path.startswith("/v1/deployments"):
                self._error(403, "deployment access denied", "deployment_access_denied")
            elif path.startswith("/v1/authority"):
                self._error(403, "authority access denied", "authority_access_denied")
            elif path.startswith("/v1/updater"):
                self._error(403, "updater access denied", "updater_access_denied")
            elif path.startswith("/v1/preview-routes"):
                self._error(403, "preview route access denied", "preview_route_access_denied")
            elif path.startswith("/v1/sources/"):
                self._error(403, "application source inspection is operator-only", "source_inspection_denied")
            else:
                self._error(403, "file workspace access denied", "file_workspace_access_denied")
        except Exception as exc:  # noqa: BLE001 - local boundary redacts non-broker details
            if exc.__class__.__module__.startswith("stateport_file_workspace."):
                self._error(409, str(exc), "file_workspace_refused")
            elif exc.__class__.__module__.startswith("stateport_terminal_broker."):
                self._error(409, "the terminal request was refused", "terminal_refused")
            elif exc.__class__.__module__.startswith("stateport_deployment."):
                code = platform_surface.public_error_code(exc, "deployment_refused")
                self._error(404 if code == "deployment_not_found" else 409, str(exc)[:512], code)
            elif exc.__class__.__module__.startswith("governed_runner."):
                self._error(409, str(exc)[:512], platform_surface.public_error_code(exc, "authority_refused"))
            elif exc.__class__.__module__.startswith("stateport_updater."):
                self._error(409, str(exc)[:512], platform_surface.public_error_code(exc, "updater_refused"))
            elif exc.__class__.__module__.startswith("stateport_preview_gateway."):
                code = platform_surface.public_error_code(exc, "preview_refused")
                self._error(404 if code == "preview_route_not_found" else 409, str(exc)[:512], code)
            elif exc.__class__.__module__.startswith("stateport_portable_execution."):
                # Governed run preparation/execution failures must surface
                # their typed refusal instead of a generic operation_failed.
                code = platform_surface.public_error_code(exc, "execution_refused")
                self._error(409, str(exc)[:512], code)
            else:
                self._error(400, "the local operation failed", "operation_failed")

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if not self._valid_request_host():
            self._error(421, "request host does not match the loopback service", "invalid_host")
            return
        if path == "/session":
            self._send(200, {"ok": True, "result": {"session": "local", "csrfToken": self.server.csrf_token}}, extra={"Set-Cookie": f"stateport_session={self.server.session}; HttpOnly; SameSite=Strict; Path=/"})
            return
        try:
            if path.startswith("/preview/"):
                # The preview proxy performs its own session check and never
                # forwards StatePort identity; proxied dev-server posts do not
                # cross the StatePort mutation boundary.
                self._handle_preview()
                return
            if not self._session():
                self._error(401, "local browser session is required", "session_required")
                return
            # `/session` is the sole unauthenticated POST because it establishes
            # the browser session and supplies the CSRF token. Every other POST
            # crosses the mutation boundary before dispatch or body parsing.
            # Route-local checks below remain as defense in depth, while this
            # guard makes newly added POST routes fail closed by default.
            self._mutation_security("authenticated POST")
            platform_surface.require_platform_operator_for_path(self.server, path)
            app = self.server.source_app()
            parts = [unquote(part) for part in path.split("/") if part]
            attachment_upload = len(parts) == 5 and parts[:2] == ["v1", "instances"] and parts[3:] == ["conversation", "attachments"]
            body = self._body(maximum_bytes=ConversationAttachmentStore.MAX_BYTES * 2 if attachment_upload else 64 * 1024)
            if path in {"/v1/provider/configure", "/v1/provider/verify", "/v1/provider/disconnect"}:
                platform_surface.require_platform_operator(self.server)
                self._strict_body(body, ({"model", "providerId"} if "providerId" in body else {"model"}) if path.endswith("/configure") else set())
                self._send(200, {"ok": True, "result": self.server.provider_action(path.rsplit("/", 1)[1], body)})
                return
            if path == "/v1/repository-import/inspect":
                self._mutation_security("repository inspection")
                self._strict_body(body, {"candidateId"} if "candidateId" in body else {"url", "revision"})
                if "candidateId" in body:
                    result = self.server.repository_inspector.inspect_candidate(body["candidateId"])
                else:
                    result = self.server.repository_inspector.inspect_public_url(body["url"], body["revision"])
                self._send(200, {"ok": True, "result": result})
                return
            if path == "/v1/template-import/plan":
                self._mutation_security("template import planning")
                self._strict_body(
                    body,
                    {"candidateId", "inspectionDigest", "instanceId", "name"},
                )
                candidate_id = body.get("candidateId")
                inspection_digest = body.get("inspectionDigest")
                instance_id = body.get("instanceId")
                name = body.get("name")
                if not all(
                    isinstance(value, str) and value
                    for value in (
                        candidate_id,
                        inspection_digest,
                        instance_id,
                        name,
                    )
                ):
                    raise RepositoryImportError(
                        "template_import_invalid",
                        "template import planning details are invalid",
                    )
                inspection = self.server.repository_inspector.inspect_candidate(
                    candidate_id
                )
                if inspection.get("inspectionDigest") != inspection_digest:
                    raise RepositoryImportError(
                        "repository_inspection_stale",
                        "repository identity changed; inspect it again",
                    )
                result = app.plan_template_import(
                    inspection,
                    candidate_id=candidate_id,
                    instance_id=instance_id,
                    name=name,
                )
                self._send(200, {"ok": True, "result": result})
                return
            if path == "/v1/template-import/install":
                self._mutation_security("template import installation")
                self._strict_body(body, {"plan", "approval"})
                plan = body.get("plan")
                approval = body.get("approval")
                if not isinstance(plan, dict) or not isinstance(approval, dict):
                    raise RepositoryImportError(
                        "template_import_invalid",
                        "template import plan and approval are required",
                    )
                candidate_id = plan.get("candidateId")
                if not isinstance(candidate_id, str):
                    raise RepositoryImportError(
                        "template_import_invalid",
                        "template import candidate identity is invalid",
                    )
                inspection = self.server.repository_inspector.inspect_candidate(
                    candidate_id
                )
                source_path = (
                    self.server.repository_inspector.policy.resolve_candidate(
                        candidate_id
                    )
                )
                result = app.install_template(
                    plan,
                    approval,
                    source_root=source_path,
                    current_inspection=inspection,
                    actor_id=self.server.actor_id,
                )
                instance_id = str(result["instanceId"])
                grant = self.server.ensure_instance_capability_grant(instance_id)
                thread, _participant_id, _binding = (
                    self.server.conversation_for_instance(instance_id)
                )
                activity_receipt = {
                    "formatVersion": "stateport.template-import-activity/v1",
                    "receiptId": "template-import-"
                    + str(result["receiptDigest"])[7:31],
                    "receiptType": "stateport.template-import-activity/v1",
                    "action": "template.import",
                    "status": "completed",
                    "sourceKind": "managed_template_import",
                    "createdAt": datetime.now(timezone.utc)
                    .replace(microsecond=0)
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "instanceId": instance_id,
                    "applicationId": result["applicationId"],
                    "templateAdapterId": result["template"]["adapterId"],
                    "source": result["source"],
                    "installReceiptDigest": result["receiptDigest"],
                    "capabilityGrantDigest": grant.get("grantDigest"),
                    "conversationId": thread.conversation_id,
                    "ownership": "StatePort-managed isolated copy; source repository unchanged",
                }
                self.server.activity_receipts.record_receipt(
                    instance_id=instance_id,
                    receipt=activity_receipt,
                )
                self._send(
                    200,
                    {
                        "ok": True,
                        "result": {
                            **result,
                            "grant": grant,
                            "conversationId": thread.conversation_id,
                            "receiptId": activity_receipt["receiptId"],
                        },
                    },
                )
                return
            if path == "/v1/repository-import/register":
                self._mutation_security("repository registration")
                self._strict_body(body, {"candidateId", "inspectionDigest", "instanceId", "name", "approval"})
                candidate_id = body.get("candidateId")
                instance_id = body.get("instanceId")
                name = body.get("name")
                approval = body.get("approval")
                if not isinstance(candidate_id, str) or not isinstance(instance_id, str) or not isinstance(name, str) or not isinstance(approval, dict):
                    raise RepositoryImportError("repository_registration_invalid", "repository registration details are invalid")
                if set(approval) != {"decision", "actorId", "proposalDigest"} or approval.get("decision") != "approve" or approval.get("actorId") != self.server.actor_id:
                    raise RepositoryImportError("repository_approval_required", "exact local-operator approval is required")
                if approval.get("proposalDigest") != body.get("inspectionDigest"):
                    raise RepositoryImportError("repository_approval_invalid", "approval does not match the inspected repository")
                inspection = self.server.repository_inspector.inspect_candidate(candidate_id)
                inspection_digest = inspection.get("inspectionDigest")
                if inspection_digest != body.get("inspectionDigest") or approval.get("proposalDigest") != inspection_digest:
                    raise RepositoryImportError("repository_inspection_stale", "repository identity changed; inspect it again")
                template = inspection.get("template")
                if isinstance(template, dict) and isinstance(template.get("validation"), dict) and template["validation"].get("status") == "failed":
                    raise RepositoryImportError("template_contract_invalid", "The template contract failed validation; correct it before importing")
                if inspection.get("sourceKind") == "public_https":
                    raise RepositoryImportError("repository_registration_refused", "public templates require the reviewed managed-copy import flow")
                source_identity = inspection.get("sourceIdentity")
                if not isinstance(source_identity, dict):
                    raise RepositoryImportError("repository_identity_missing", "repository identity is unavailable")
                path_value = self.server.repository_inspector.policy.resolve_candidate(candidate_id)
                registered = app.register_external_repository(
                    path_value,
                    instance_id=instance_id,
                    name=name,
                    application_id="nixos-infrastructure",
                    source=source_identity,
                )
                try:
                    grant = self.server.ensure_instance_capability_grant(instance_id)
                    thread, _participant_id, _binding = self.server.conversation_for_instance(instance_id)
                    receipt_seed = {"instanceId": instance_id, "inspectionDigest": inspection_digest, "source": source_identity}
                    receipt_id = "repository-import-" + hashlib.sha256(json.dumps(receipt_seed, sort_keys=True).encode("utf-8")).hexdigest()[:24]
                    receipt = {
                        "formatVersion": "stateport.repository-import-receipt/v1",
                        "receiptId": receipt_id,
                        "receiptType": "stateport.repository-import-receipt/v1",
                        "action": "repository.import",
                        "status": "completed",
                        "sourceKind": "repository_import",
                        "createdAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                        "instanceId": instance_id,
                        "applicationId": "nixos-infrastructure",
                        "sourceIdentity": source_identity,
                        "inspectionDigest": inspection_digest,
                        "approval": {"actorId": approval["actorId"], "proposalDigest": approval["proposalDigest"]},
                        "capabilityGrantDigest": grant.get("grantDigest"),
                        "conversationId": thread.conversation_id,
                        "ownership": "user-owned source registered in place; StatePort owns operational metadata",
                    }
                    self.server.activity_receipts.record_receipt(instance_id=instance_id, receipt=receipt)
                except Exception:
                    app.catalog.forget(instance_id)
                    raise
                self._send(200, {"ok": True, "result": {"entry": registered, "inspection": inspection, "grant": grant, "conversationId": thread.conversation_id, "receipt": receipt}})
                return
            if len(parts) == 5 and parts[:2] == ["v1", "instances"] and parts[3] == "infrastructure" and parts[4] in {"plan", "approve", "run"}:
                self._mutation_security("infrastructure operation")
                instance_id = str(parts[2])
                adapter = self.server.infrastructure_adapter(instance_id)
                operation = parts[4]
                if operation == "plan":
                    self._strict_body(body, {"operation"})
                    result = adapter.plan(body.get("operation"))
                elif operation == "approve":
                    self._strict_body(body, {"planDigest"})
                    result = adapter.approve(body.get("planDigest"), self.server.actor_id)
                else:
                    self._strict_body(body, {"planDigest"})
                    try:
                        result = adapter.run(body.get("planDigest"))
                    except InfrastructureError:
                        self.server.infrastructure_record_receipt(instance_id, adapter.latest_run())
                        raise
                    self.server.infrastructure_record_receipt(instance_id, result)
                self._send(200, {"ok": True, "result": result})
                return
            if len(parts) == 6 and parts[:2] == ["v1", "instances"] and parts[3:5] == ["infrastructure", "grant"] and parts[5] in {"prepare", "approve"}:
                self._mutation_security("infrastructure grant")
                instance_id = str(parts[2])
                adapter = self.server.infrastructure_adapter(instance_id)
                if parts[5] == "prepare":
                    self._strict_body(body, set())
                    result = adapter.prepare_daily_driver_grant()
                else:
                    self._strict_body(body, {"proposalDigest"})
                    result = adapter.approve_daily_driver_grant(body.get("proposalDigest"), self.server.actor_id)
                    receipt = adapter.daily_driver_grant_receipt(result)
                    self.server.activity_receipts.record_receipt(instance_id=instance_id, receipt=receipt)
                    result = {**result, "receipt": receipt}
                self._send(200, {"ok": True, "result": result})
                return
            if path in {"/v1/settings", "/v1/settings/preview", "/v1/settings/rollback"}:
                self._mutation_security("settings")
                store = self.server.settings_store()
                if path.endswith("/preview"):
                    self._strict_body(body, {"expectedRevision", "changes"})
                    result = store.preview(expected_revision=body["expectedRevision"], changes=body["changes"])
                elif path.endswith("/rollback"):
                    self._strict_body(body, {"expectedRevision", "receiptId"})
                    result = store.rollback(expected_revision=body["expectedRevision"], receipt_id=body["receiptId"])
                else:
                    self._strict_body(body, {"expectedRevision", "changes"})
                    result = store.patch(expected_revision=body["expectedRevision"], changes=body["changes"])
                self._send(200, {"ok": True, "result": result})
                return
            if len(parts) == 4 and parts[:2] == ["v1", "instances"] and parts[3] in {"settings", "settings-preview", "settings-rollback"}:
                self._mutation_security("application settings")
                instance_id = str(parts[2])
                store = self.server.settings_store(instance_id)
                if parts[3] == "settings-preview":
                    self._strict_body(body, {"expectedRevision", "changes"})
                    result = store.preview(expected_revision=body["expectedRevision"], changes=body["changes"])
                elif parts[3] == "settings-rollback":
                    self._strict_body(body, {"expectedRevision", "receiptId"})
                    result = store.rollback(expected_revision=body["expectedRevision"], receipt_id=body["receiptId"])
                else:
                    self._strict_body(body, {"expectedRevision", "changes"})
                    result = store.patch(expected_revision=body["expectedRevision"], changes=body["changes"])
                self._send(200, {"ok": True, "result": result})
                return
            if len(parts) == 6 and parts[:2] == ["v1", "instances"] and parts[3] == "activity" and parts[5] in {"read", "acknowledge"}:
                self._mutation_security("application activity")
                self._strict_body(body, {"expectedVersion"})
                result = self.server.transition_activity_attention(
                    instance_id=str(parts[2]), attention_id=str(parts[4]), action=str(parts[5]),
                    expected_version=body["expectedVersion"],
                )
                self._send(200, {"ok": True, "result": result})
                return
            if (
                len(parts) == 4
                and parts[:2] == ["v1", "sources"]
                and parts[3] == "development-resolve"
            ):
                self._mutation_security("development source verification")
                self.server.require_actor_permission("platform.source.development.verify")
                source_id = str(parts[2])
                if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,159}", source_id):
                    self._error(404, "application source was not found", "source_not_found")
                    return
                self._strict_body(body, {
                    "sourceId", "sourceClass", "expectedCommit", "expectedTree",
                    "expectedManifestDigest", "expectedSourceDigest", "acknowledgement",
                })
                try:
                    source_app = self.server.source_app()
                    projection = source_app.canonical_source_operator_projection(source_id)
                    candidate = projection.get("developmentCandidate")
                    identity = candidate.get("identity") if isinstance(candidate, dict) else None
                    verification = candidate.get("verificationAction") if isinstance(candidate, dict) else None
                    expected = {
                        "sourceId": projection["sourceId"],
                        "sourceClass": candidate.get("sourceClass") if isinstance(candidate, dict) else None,
                        "expectedCommit": identity.get("commit") if isinstance(identity, dict) else None,
                        "expectedTree": identity.get("tree") if isinstance(identity, dict) else None,
                        "expectedManifestDigest": identity.get("manifestDigest") if isinstance(identity, dict) else None,
                        "expectedSourceDigest": identity.get("sourceDigest") if isinstance(identity, dict) else None,
                        "acknowledgement": verification.get("acknowledgement") if isinstance(verification, dict) else None,
                    }
                    if any(
                        not isinstance(body.get(key), str)
                        or not isinstance(value, str)
                        or not secrets.compare_digest(body[key], value)
                        for key, value in expected.items()
                    ):
                        self._error(409, "development source identity changed; inspect it again", "source_candidate_stale")
                        return
                    result = source_app.resolve_development_candidate(
                        source_id=source_id,
                        operator_acknowledged=True,
                    )
                except AppError:
                    self._error(
                        409,
                        "Development candidate verification could not be completed.",
                        "source_candidate_verification_failed",
                    )
                    return
                self._send(200, {"ok": True, "result": result})
                return
            if len(parts) == 6 and parts[:3] == ["v1", "execution-host", "workspaces"] and parts[4:] == ["authority", "prepare"]:
                self._mutation_security("workspace authority request preparation")
                if self.server.actor_role != "platform_operator":
                    raise PermissionError("platform operator authorization is required")
                self.server.require_actor_permission("platform.authority.mutate")
                self._strict_body(body, {"profileDigest", "sourceMode", "grantExpiresAt"})
                result = self.server.execution_host.prepare_workspace_authority(parts[3], profile_digest=body["profileDigest"], source_mode=body["sourceMode"], grant_expires_at=body["grantExpiresAt"])
                self._send(200, {"ok": True, "result": result})
                return
            if len(parts) == 6 and parts[:3] == ["v1", "execution-host", "workspaces"] and parts[4:] == ["terminal", "prepare"]:
                self._mutation_security("workspace terminal")
                self._strict_body(body, {"expectedInstanceId", "expectedTargetId", "columns", "rows"})
                if body["expectedInstanceId"] != parts[3]:
                    raise PermissionError("workspace terminal instance identity changed")
                result = self.server.prepare_terminal(parts[3], columns=body["columns"], rows=body["rows"], workspace_only=True, expected_target_id=body["expectedTargetId"])
                self._send(200, {"ok": True, "result": result})
                return
            if len(parts) == 5 and parts[:2] == ["v1", "instances"] and parts[3:] == ["terminal", "prepare"]:
                self._mutation_security("terminal")
                self._strict_body(body, {"expectedInstanceId", "columns", "rows"})
                instance_id = str(parts[2])
                if body["expectedInstanceId"] != instance_id:
                    raise PermissionError("terminal instance identity changed")
                result = self.server.prepare_terminal(
                    instance_id,
                    columns=body["columns"],
                    rows=body["rows"],
                )
                self._send(200, {"ok": True, "result": result})
                return
            if len(parts) == 5 and parts[:2] == ["v1", "instances"] and parts[3] == "file-workspace":
                self._file_request_security()
                instance_id, operation = parts[2], parts[4]
                catalog_entry = app.catalog.get(instance_id)
                content_identity = catalog_entry.get("contentIdentity")
                broker = self.server.file_workspace(instance_id)
                identity = self.server.file_workspace_identity(broker)
                if operation == "prepareWrite":
                    self._strict_body(body, {"path", "content", "expectedContentHash", "expectedBaseSha"})
                    result = broker.prepare_write(
                        body["path"], body["content"],
                        expected_content_hash=body["expectedContentHash"],
                        expected_base_sha=body["expectedBaseSha"], **identity,
                    ).to_dict()
                elif operation == "createFile":
                    self._strict_body(body, {"path", "content", "expectedBaseSha"})
                    result = broker.create_file(
                        body["path"], body["content"],
                        expected_base_sha=body["expectedBaseSha"], **identity,
                    ).to_dict()
                elif operation == "previewDiff":
                    self._strict_body(body, {"preparedWriteId"})
                    result = broker.preview_diff(body["preparedWriteId"], **identity).to_dict()
                elif operation == "commitWrite":
                    self._strict_body(body, {"preparedWriteId", "confirmedDiffDigest"})
                    result = broker.commit_write(
                        body["preparedWriteId"],
                        confirmed_diff_digest=body["confirmedDiffDigest"], **identity,
                    ).to_dict()
                elif operation == "discardWrite":
                    self._strict_body(body, {"preparedWriteId"})
                    result = broker.discard_write(body["preparedWriteId"], **identity)
                elif operation == "renamePath":
                    self._strict_body(body, {"sourcePath", "destinationPath", "expectedContentHash", "expectedBaseSha"})
                    result = broker.rename_path(
                        body["sourcePath"], body["destinationPath"],
                        expected_content_hash=body["expectedContentHash"],
                        expected_base_sha=body["expectedBaseSha"], **identity,
                    ).to_dict()
                elif operation == "deletePath":
                    self._strict_body(body, {"path", "expectedContentHash", "expectedBaseSha"})
                    result = broker.delete_path(
                        body["path"], expected_content_hash=body["expectedContentHash"],
                        expected_base_sha=body["expectedBaseSha"], **identity,
                    ).to_dict()
                else:
                    self._error(404, "file workspace operation not found", "not_found")
                    return
                if operation in {"commitWrite", "renamePath", "deletePath"}:
                    self.server.record_file_workspace_receipt(
                        instance_id=instance_id,
                        application_id=identity["application_id"],
                        expected_operation=str(result.get("operation", "")),
                        receipt=result,
                    )
                    if isinstance(content_identity, Mapping):
                        app.catalog.rebind_external_content(
                            instance_id,
                            expected_content_identity=content_identity,
                        )
                self._send(200, {"ok": True, "result": result})
                return
            if path == "/v1/catalog/refresh":
                self._mutation_security("catalog refresh")
                self._strict_body(body, set())
                self._send(200, {"ok": True, "result": {"instances": app.instance_list_public(), "refreshed": True}})
                return
            if path == "/v1/privacy/purge":
                self._mutation_security("privacy purge")
                self.server.require_actor_permission("platform.privacy.purge")
                self._strict_body(body, set())
                self._send(200, {"ok": True, "result": self.server.privacy_purge()})
                return
            if (
                len(parts) == 6
                and parts[:2] == ["v1", "instances"]
                and parts[3:5] == ["recovery", "restore"]
            ):
                self._mutation_security("governed instance restore")
                self.server.require_actor_permission("platform.recovery.restore")
                source_instance_id, operation = str(parts[2]), str(parts[5])
                if operation == "plan":
                    self._strict_body(
                        body,
                        {"backupReceiptId", "destinationInstanceId", "destinationName"},
                    )
                    if not all(
                        isinstance(body.get(field), str)
                        for field in ("backupReceiptId", "destinationInstanceId")
                    ) or body.get("destinationName") is not None and not isinstance(
                        body.get("destinationName"), str
                    ):
                        raise ValueError("restore plan request identity is invalid")
                    result = app.restore_plan(
                        source_instance_id,
                        backup_receipt_id=str(body["backupReceiptId"]),
                        destination_instance_id=str(body["destinationInstanceId"]),
                        destination_name=(
                            str(body["destinationName"])
                            if body.get("destinationName") is not None
                            else None
                        ),
                    )
                elif operation == "approve":
                    self._strict_body(body, {"planDigest"})
                    if not isinstance(body.get("planDigest"), str):
                        raise ValueError("restore approval plan identity is invalid")
                    result = app.approve_restore(
                        source_instance_id,
                        plan_digest=str(body["planDigest"]),
                        actor_id=self.server.actor_id,
                        actor_role=self.server.actor_role,
                    )
                elif operation == "apply":
                    self._strict_body(body, {"planDigest", "approvalDigest"})
                    if not all(
                        isinstance(body.get(field), str)
                        for field in ("planDigest", "approvalDigest")
                    ):
                        raise ValueError("restore apply identity is invalid")
                    result = app.apply_restore(
                        source_instance_id,
                        plan_digest=str(body["planDigest"]),
                        approval_digest=str(body["approvalDigest"]),
                    )
                else:
                    self._error(404, "restore operation not found", "not_found")
                    return
                self._send(200, {"ok": True, "result": result})
                return
            if len(parts) == 4 and parts[:2] == ["v1", "instances"] and parts[3] == "rename":
                from stateport_persistent_app.app import ApplicationRenameError
                self._mutation_security("application rename")
                self._strict_body(body, {"name", "expectedName"})
                try:
                    result = self.server.source_app().rename_instance(
                        parts[2], name=body["name"], expected_name=body["expectedName"],
                        actor_id=self.server.actor_id, actor_role=self.server.actor_role,
                    )
                except ApplicationRenameError as exc:
                    self._error({"rename_conflict": 409, "rename_invalid": 400, "rename_forbidden": 403}.get(exc.code, 409), str(exc), exc.code)
                    return
                self._send(200, {"ok": True, "result": result})
                return
            if len(parts) == 4 and parts[:2] == ["v1", "instances"]:
                instance_id, operation = parts[2], parts[3]
                if operation == "portable-export":
                    self._mutation_security("portable export")
                    self._strict_body(body, set())
                    result = self._execution(app).export_instance(str(instance_id))
                elif operation == "backup":
                    self._mutation_security("application backup")
                    self._strict_body(body, set())
                    result = app.backup(instance_id)
                elif operation == "synthetic-run":
                    self._mutation_security("synthetic contract inspection")
                    self._strict_body(body, set())
                    result = app.synthetic_run(instance_id)
                else:
                    self._error(404, "instance operation not found", "not_found")
                    return
                self._send(200, {"ok": True, "result": result})
                return
            if len(parts) == 5 and parts[:2] == ["v1", "instances"] and parts[3:] == ["conversation", "messages"]:
                self._mutation_security("conversation")
                self._strict_body(body, {"clientMessageId", "text", "replyToExternalMessageId", "attachments"})
                instance_id = str(parts[2])
                client_message_id = body.get("clientMessageId")
                text = body.get("text")
                reply_to = body.get("replyToExternalMessageId")
                attachments = body.get("attachments", [])
                if not isinstance(client_message_id, str) or not isinstance(text, str):
                    raise ValueError("clientMessageId and text are required")
                if reply_to is not None and not isinstance(reply_to, str):
                    raise ValueError("replyToExternalMessageId must be a string or null")
                if not isinstance(attachments, list):
                    raise ValueError("attachments must be an array")
                thread, participant_id, binding = self.server.conversation_for_instance(instance_id)
                attachment_references = []
                for attachment in attachments:
                    if not isinstance(attachment, dict) or set(attachment) != {"attachmentId", "name", "mediaType", "sizeBytes", "digest"}:
                        raise ValueError("conversation attachment reference is invalid")
                    reference = self.server.attachments.conversation_reference(
                        instance_id=instance_id, conversation_id=thread.conversation_id,
                        attachment_id=attachment.get("attachmentId"),
                    )
                    if _json_bytes(reference) != _json_bytes(attachment):
                        raise ValueError("conversation attachment reference changed or is not authorized")
                    attachment_references.append(reference)
                inbound = self.server.web_conversation_adapter.normalize(
                    binding,
                    {
                        "formatVersion": self.server.web_conversation_adapter.FORMAT,
                        "bindingId": binding.binding_id,
                        "clientMessageId": client_message_id,
                        "sentAt": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                        "text": text,
                        "replyToExternalMessageId": reply_to,
                        "attachments": attachment_references,
                        "echoGuard": None,
                    },
                )
                accepted = self.server.conversations.ingest(participant_id=participant_id, inbound=inbound)
                self._send(
                    200,
                    {
                        "ok": True,
                        "result": {
                            "ingest": accepted.to_dict(),
                            "presentation": self.server.conversation_presentation(instance_id, expected_conversation_id=thread.conversation_id),
                        },
                    },
                )
                return
            if len(parts) == 5 and parts[:2] == ["v1", "instances"] and parts[3:] == ["conversation", "export"]:
                self._mutation_security("conversation export")
                self._strict_body(body, {"expectedConversationId", "requestId"})
                instance_id = str(parts[2])
                result = self.server.conversation_export(
                    instance_id,
                    expected_conversation_id=str(body.get("expectedConversationId", "")),
                    request_id=str(body.get("requestId", "")),
                )
                self._send(200, {"ok": True, "result": result})
                return
            if len(parts) == 5 and parts[:2] == ["v1", "instances"] and parts[3:] == ["conversation", "clear"]:
                self._mutation_security("conversation clear")
                self._strict_body(body, {"expectedConversationId", "requestId", "confirmation"})
                if body.get("confirmation") != "CLEAR_CONVERSATION":
                    raise ValueError("conversation clear requires explicit confirmation")
                instance_id = str(parts[2])
                result = self.server.conversation_clear(
                    instance_id,
                    expected_conversation_id=str(body.get("expectedConversationId", "")),
                    request_id=str(body.get("requestId", "")),
                )
                self._send(200, {"ok": True, "result": result})
                return
            if attachment_upload:
                self._attachment_request_security()
                self._strict_body(body, {"name", "mediaType", "dataBase64", "sensitivityLabel", "retentionClass"})
                thread, _participant_id, _binding = self._attachment_scope(str(parts[2]))
                result = self.server.attachments.upload(
                    instance_id=str(parts[2]), conversation_id=thread.conversation_id,
                    name=body["name"], media_type=body["mediaType"], data_base64=body["dataBase64"],
                    sensitivity_label=body["sensitivityLabel"], retention_class=body["retentionClass"],
                )
                self._send(200, {"ok": True, "result": result})
                return
            if len(parts) == 7 and parts[:2] == ["v1", "instances"] and parts[3:5] == ["conversation", "attachments"] and parts[6] in {"delete", "export"}:
                self._attachment_request_security()
                self._strict_body(body, set())
                thread, _participant_id, _binding = self._attachment_scope(str(parts[2]))
                operation = parts[6]
                if operation == "delete":
                    result = self.server.attachments.delete(instance_id=str(parts[2]), conversation_id=thread.conversation_id, attachment_id=parts[5])
                else:
                    result = self.server.attachments.export(instance_id=str(parts[2]), conversation_id=thread.conversation_id, attachment_id=parts[5])
                self._send(200, {"ok": True, "result": result})
                return
            if len(parts) == 5 and parts[:2] == ["v1", "instances"] and parts[3] == "context-lifecycle":
                self._mutation_security("context lifecycle")
                instance_id, operation = str(parts[2]), str(parts[4])
                _entry, root = app._entry(instance_id)
                lifecycle = self.server.context_lifecycle
                if operation == "preference":
                    self._strict_body(body, {"expectedInstanceId", "expectedPolicyDigest", "mode"})
                    result = lifecycle.set_preference(
                        instance_id,
                        root,
                        expected_instance_id=str(body.get("expectedInstanceId", "")),
                        expected_policy_digest=str(body.get("expectedPolicyDigest", "")),
                        mode=str(body.get("mode", "")),
                    )
                    result = self.server.context_lifecycle_view(instance_id, root)
                elif operation == "compact":
                    request = self.server.current_context_lifecycle_request(instance_id, root, body)
                    result = lifecycle.compress(instance_id, root, request)
                elif operation == "handoff":
                    request = self.server.current_context_lifecycle_request(instance_id, root, body)
                    result = lifecycle.handoff(instance_id, root, request)
                else:
                    self._error(404, "context lifecycle operation not found", "not_found")
                    return
                self._send(200, {"ok": True, "result": result})
                return
            if len(parts) == 5 and parts[:2] == ["v1", "instances"] and parts[3] == "goal-execution":
                self._mutation_security("goal execution")
                instance_id, operation = str(parts[2]), str(parts[4])
                application_id, root = self.server.goal_execution_binding(instance_id)
                coordinator = self.server.goal_execution
                if operation == "prepare":
                    required = {"expectedInstanceId", "expectedRevision", "expectedBaseCommit", "mode", "intent"}
                    optional = {"backendId"}
                    if not set(body).issubset(required | optional) or not required.issubset(set(body)):
                        raise ValueError("goal execution prepare request shape is invalid")
                    if body["expectedInstanceId"] != instance_id:
                        raise PermissionError("goal execution instance identity changed")
                    result = coordinator.prepare(
                        application_id=application_id,
                        instance_id=instance_id,
                        instance_root=root,
                        requested_by=self.server.actor_id,
                        text=body["intent"],
                        mode=body["mode"],
                        expected_revision=body["expectedRevision"],
                        expected_base_commit=body["expectedBaseCommit"],
                        backend_id=body.get("backendId"),
                    )
                elif operation == "approve":
                    self._strict_body(body, {"expectedInstanceId", "expectedRevision", "expectedPlanDigest"})
                    if body["expectedInstanceId"] != instance_id:
                        raise PermissionError("goal execution instance identity changed")
                    result = coordinator.approve(
                        instance_id,
                        root,
                        expected_revision=body["expectedRevision"],
                        expected_plan_digest=body["expectedPlanDigest"],
                        actor=f"authenticated-{self.server.actor_role}-approver",
                    )
                elif operation == "execute":
                    self._strict_body(body, {"expectedInstanceId", "expectedRevision", "expectedPlanDigest"})
                    if body["expectedInstanceId"] != instance_id:
                        raise PermissionError("goal execution instance identity changed")
                    result = coordinator.execute(
                        instance_id,
                        root,
                        expected_revision=body["expectedRevision"],
                        expected_plan_digest=body["expectedPlanDigest"],
                    )
                elif operation == "review":
                    self._strict_body(body, {"expectedInstanceId", "expectedRevision", "expectedExecutionResultDigest"})
                    if body["expectedInstanceId"] != instance_id:
                        raise PermissionError("goal execution instance identity changed")
                    result = coordinator.review(
                        instance_id,
                        root,
                        expected_revision=body["expectedRevision"],
                        expected_result_digest=body["expectedExecutionResultDigest"],
                    )
                elif operation == "close":
                    self._strict_body(body, {"expectedInstanceId", "expectedRevision", "expectedReviewDigest"})
                    if body["expectedInstanceId"] != instance_id:
                        raise PermissionError("goal execution instance identity changed")
                    result = coordinator.close(
                        instance_id,
                        root,
                        expected_revision=body["expectedRevision"],
                        expected_review_digest=body["expectedReviewDigest"],
                        actor="stateport-governor",
                    )
                else:
                    self._error(404, "goal execution operation not found", "not_found")
                    return
                response_result = {
                    **result,
                    "currentIdentity": coordinator.current_identity(root),
                }
                if operation == "close":
                    self.server.record_goal_execution_receipt(
                        instance_id=instance_id,
                        application_id=application_id,
                        closed_projection=result,
                    )
                self._send(200, {"ok": True, "result": response_result})
                return
            if path in {"/v1/portable-import/preview", "/v1/portable-import/apply"}:
                self._mutation_security("portable import")
                expected_fields = {"archive", "destination", "identityPolicy"} if path.endswith("/preview") else {"archive", "destination", "identityPolicy", "expectedPlanDigest", "approval"}
                if set(body) != expected_fields:
                    raise PortableImportError("portable_import_request_invalid", "portable import request shape is invalid")
                archive = body.get("archive")
                destination = body.get("destination")
                if not isinstance(archive, dict) or set(archive) != {"path", "archiveDigest", "archiveFileDigest"}:
                    raise PortableImportError("portable_import_request_invalid", "portable import archive request is invalid")
                if not isinstance(destination, dict) or set(destination) != {"path", "instanceId"}:
                    raise PortableImportError("portable_import_request_invalid", "portable import destination request is invalid")
                if not all(isinstance(archive.get(key), str) for key in ("path", "archiveDigest", "archiveFileDigest")) or not all(isinstance(destination.get(key), str) for key in ("path", "instanceId")) or not isinstance(body.get("identityPolicy"), str):
                    raise PortableImportError("portable_import_request_invalid", "portable import request identities are invalid")
                try:
                    archive_path = self._local_child(str(archive["path"]), app.layout.operations_root / "portable", "archive path")
                    destination_path = self._local_child(str(destination["path"]), app.layout.instances_root, "destination path")
                except ValueError as exc:
                    raise PortableImportError("portable_import_path_refused", "portable import path is outside the local boundary") from exc
                execution = self._execution(app)
                if path.endswith("/preview"):
                    result = execution.preview_portable_import(
                        archive_path, destination_path,
                        expected_archive_digest=archive["archiveDigest"], expected_archive_file_digest=archive["archiveFileDigest"],
                        destination_instance_id=destination["instanceId"], identity_policy=body["identityPolicy"],
                    )
                else:
                    approval = body.get("approval")
                    if not isinstance(approval, dict) or set(approval) != {"decision", "actorId", "actorRole"}:
                        raise PortableImportError("portable_import_request_invalid", "portable import approval is invalid")
                    expected_approval = {"decision": "approve", "actorId": self.server.actor_id, "actorRole": self.server.actor_role}
                    if any(not isinstance(approval.get(key), str) or not secrets.compare_digest(approval[key], value) for key, value in expected_approval.items()):
                        raise PermissionError("portable import approval identity is invalid")
                    result = execution.apply_portable_import(
                        archive_path, destination_path,
                        expected_archive_digest=archive["archiveDigest"], expected_archive_file_digest=archive["archiveFileDigest"],
                        destination_instance_id=destination["instanceId"], identity_policy=body["identityPolicy"],
                        expected_plan_digest=body["expectedPlanDigest"], approval=expected_approval,
                    )
                self._send(200, {"ok": True, "result": result})
                return
            if (
                len(parts) == 5
                and parts[:2] == ["v1", "instances"]
                and parts[3] == "template-upgrade"
            ):
                instance_id, operation = parts[2], parts[4]
                if operation == "request":
                    self._strict_body(body, {"expectedInstanceId", "targetRevision"})
                    if body.get("expectedInstanceId") != instance_id or not isinstance(body.get("targetRevision"), str):
                        raise ValueError("template upgrade requires exact instance and revision identities")
                    result = self.server.request_template_upgrade(instance_id, body["targetRevision"])
                elif operation in {"approve", "reject", "apply"}:
                    required = {"expectedInstanceId", "approvalId", "expectedPlanDigest"}
                    allowed = required | ({"reason"} if operation == "reject" else set())
                    if set(body) != required and set(body) != allowed:
                        raise ValueError("template upgrade transition request shape is invalid")
                    if body.get("expectedInstanceId") != instance_id or not all(
                        isinstance(body.get(key), str) and body.get(key)
                        for key in ("approvalId", "expectedPlanDigest")
                    ):
                        raise ValueError("template upgrade transition identities are invalid")
                    if operation == "apply":
                        result = self.server.apply_template_upgrade(
                            instance_id=instance_id,
                            approval_id=body["approvalId"],
                            expected_plan_digest=body["expectedPlanDigest"],
                        )
                    else:
                        reason = body.get("reason", "")
                        if not isinstance(reason, str) or len(reason) > 512:
                            raise ValueError("template upgrade decision reason is invalid")
                        result = self.server.decide_template_upgrade(
                            instance_id=instance_id,
                            approval_id=body["approvalId"],
                            expected_plan_digest=body["expectedPlanDigest"],
                            status="approved" if operation == "approve" else "rejected",
                            reason=reason,
                        )
                else:
                    self._error(404, "template upgrade operation not found", "not_found")
                    return
                self._send(200, {"ok": True, "result": result})
                return
            if path == "/v1/application-fixtures/install":
                try:
                    self._mutation_security("application fixture install")
                except PermissionError:
                    self._error(403, "application installation authorization failed", "application_install_denied")
                    return
                self._strict_body(body, {"applicationId", "instanceId", "name", "applicationDescriptorDigest", "applicationPackageDigest", "experienceDescriptorDigest"})
                application_id = body.get("applicationId")
                instance_id = body.get("instanceId")
                name = body.get("name")
                application_digest = body.get("applicationDescriptorDigest")
                package_digest = body.get("applicationPackageDigest")
                experience_digest = body.get("experienceDescriptorDigest")
                if not all(isinstance(value, str) and value for value in (application_id, instance_id, name, application_digest, package_digest, experience_digest)):
                    raise ValueError("application installation identities are required")
                catalog_entry = next(
                    (item for item in self.server.application_catalog() if item["applicationId"] == application_id),
                    None,
                )
                if catalog_entry is None or catalog_entry["install"]["status"] != "available":
                    self._error(403, "application is not available for browser installation", "application_install_denied")
                    return
                if not secrets.compare_digest(application_digest, catalog_entry["applicationIdentity"]["descriptorDigest"]):
                    self._error(409, "application package changed; review it again", "application_install_stale")
                    return
                if not secrets.compare_digest(package_digest, catalog_entry["applicationIdentity"]["packageDigest"]):
                    self._error(409, "application package changed; review it again", "application_install_stale")
                    return
                if not secrets.compare_digest(experience_digest, catalog_entry["experienceIdentity"]["descriptorDigest"]):
                    self._error(409, "application experience changed; review it again", "application_install_stale")
                    return
                result = self._execution(app).install_fixture_instance(
                    application_id,
                    instance_id,
                    name,
                    expected_descriptor_digest=application_digest,
                    expected_package_digest=package_digest,
                    experience_descriptor_digest=experience_digest,
                    consent="explicit_browser_confirmation",
                    actor_id=self.server.actor_id,
                )
                self.server.ensure_instance_capability_grant(instance_id)
                self._send(200, {"ok": True, "result": result})
                return
            if len(parts) == 5 and parts[:2] == ["v1", "instances"] and parts[3] == "execution" and parts[4] == "prepare":
                self._mutation_security("governed run preparation")
                self._strict_body(body, {"expectedInstanceId", "actionId", "engineId", "inputs"})
                if body.get("expectedInstanceId") != parts[2]:
                    raise ValueError("execution preparation requires the exact selected instance identity")
                instance_id = str(parts[2])
                allow_development_candidate = app.development_candidate_testing_allowed(instance_id)
                result = self._execution(app).prepare(instance_id, str(body.get("actionId", "")), str(body.get("engineId", "synthetic")), body.get("inputs") if isinstance(body.get("inputs"), dict) else {}, allow_development_candidate=allow_development_candidate)
                self._send(200, {"ok": True, "result": result})
                return
            if len(parts) == 4 and parts[:2] == ["v1", "runs"]:
                run_id, operation = str(parts[2]), str(parts[3])
                self._mutation_security("governed run transition")
                self._strict_body(body, {"expectedInstanceId", "expectedRevision"})
                execution = self._execution(app)
                expected_instance_id = body.get("expectedInstanceId")
                expected_revision = body.get("expectedRevision")
                if not isinstance(expected_instance_id, str) or isinstance(expected_revision, bool) or not isinstance(expected_revision, int) or expected_revision < 0:
                    raise ValueError("run mutations require exact instance and revision identities")
                binding = {"expected_instance_id": expected_instance_id, "expected_revision": expected_revision}
                if operation == "approve": result = execution.approve_run(run_id, **binding)
                elif operation == "execute": result = execution.execute(run_id, **binding)
                elif operation == "cancel": result = execution.cancel(run_id, **binding)
                elif operation == "proposal-approve": result = execution.approve_proposal(run_id, **binding)
                elif operation == "proposal-reject": result = execution.reject_proposal(run_id, **binding)
                elif operation == "apply": result = execution.apply_proposal(run_id, **binding)
                else:
                    self._error(404, "run operation not found", "not_found")
                    return
                self._send(200, {"ok": True, "result": result})
                return
            if path == "/v1/deployments/plan":
                self._mutation_security("deployment plan")
                required = {"project", "deploymentId", "grantId"}
                optional = required | {"sliceId", "rollbackOf"}
                if not required <= set(body) <= optional:
                    raise ValueError("deployment plan request shape is invalid")
                result = platform_surface.plan_deployment(
                    self.server,
                    project=body.get("project"),
                    identity=body.get("deploymentId"),
                    grant=body.get("grantId"),
                    slice_identity=body.get("sliceId"),
                    rollback_of=body.get("rollbackOf"),
                )
                self._send(200, {"ok": True, "result": result})
                return
            if len(parts) == 4 and parts[:2] == ["v1", "deployments"] and parts[3] == "apply":
                self._mutation_security("deployment apply")
                required = {"acceptPlanDigest", "grantId", "approval"}
                if not required <= set(body) <= required | {"sliceId"}:
                    raise ValueError("deployment apply request shape is invalid")
                digest = platform_surface.digest_text(body.get("acceptPlanDigest"), "accepted plan digest")
                platform_surface.require_digest_approval(self.server, body, digest)
                result = platform_surface.apply_plan(
                    self.server,
                    identity=parts[2],
                    accept_plan_digest=digest,
                    grant=body.get("grantId"),
                    slice_identity=body.get("sliceId"),
                )
                self._send(200, {"ok": True, "result": result})
                return
            if len(parts) == 5 and parts[:2] == ["v1", "deployments"] and parts[3:] == ["backup", "plan"]:
                self._mutation_security("deployment backup plan")
                if not {"grantId"} <= set(body) <= {"grantId", "sliceId"}:
                    raise ValueError("deployment backup plan request shape is invalid")
                result = platform_surface.plan_backup(
                    self.server,
                    identity=parts[2],
                    grant=body.get("grantId"),
                    slice_identity=body.get("sliceId"),
                )
                self._send(200, {"ok": True, "result": result})
                return
            if len(parts) == 5 and parts[:2] == ["v1", "deployments"] and parts[3:] == ["restore", "plan"]:
                self._mutation_security("deployment restore plan")
                required = {"backupId", "grantId"}
                if not required <= set(body) <= required | {"sliceId"}:
                    raise ValueError("deployment restore plan request shape is invalid")
                result = platform_surface.plan_restore(
                    self.server,
                    identity=parts[2],
                    backup=body.get("backupId"),
                    grant=body.get("grantId"),
                    slice_identity=body.get("sliceId"),
                )
                self._send(200, {"ok": True, "result": result})
                return
            if len(parts) == 4 and parts[:2] == ["v1", "deployments"] and parts[3] == "reject":
                self._mutation_security("deployment proposal rejection")
                required = {"planDigest", "grantId"}
                if not required <= set(body) <= required | {"sliceId"}:
                    raise ValueError("deployment rejection request shape is invalid")
                result = platform_surface.reject_plan(
                    self.server,
                    identity=parts[2],
                    plan_digest=body.get("planDigest"),
                    grant=body.get("grantId"),
                    slice_identity=body.get("sliceId"),
                )
                self._send(200, {"ok": True, "result": result})
                return
            if len(parts) == 4 and parts[:2] == ["v1", "deployments"] and parts[3] in {"status", "logs", "restart", "remove"}:
                operation = parts[3]
                self._mutation_security(f"deployment {operation}")
                required = {"grantId"}
                optional = required | {"sliceId"} | ({"serviceId", "tail"} if operation == "logs" else set()) | ({"approval"} if operation in {"restart", "remove"} else set())
                if not required <= set(body) <= optional:
                    raise ValueError(f"deployment {operation} request shape is invalid")
                if operation == "status":
                    result = platform_surface.observe_deployment(
                        self.server, identity=parts[2], grant=body.get("grantId"), slice_identity=body.get("sliceId"),
                    )
                elif operation == "logs":
                    result = platform_surface.deployment_logs(
                        self.server, identity=parts[2], grant=body.get("grantId"), slice_identity=body.get("sliceId"),
                        service_id=body.get("serviceId"), tail=body.get("tail"),
                    )
                else:
                    service = platform_surface.deployment_service(self.server)
                    action = "restart_deployment" if operation == "restart" else "remove_deployment_runtime"
                    expected = service.peek_authority_run_id(platform_surface.deployment_id(parts[2]), action)
                    platform_surface.require_digest_approval(self.server, body, expected)
                    governed = (
                        platform_surface.restart_deployment if operation == "restart" else platform_surface.remove_deployment
                    )
                    result = governed(
                        self.server, identity=parts[2], grant=body.get("grantId"), slice_identity=body.get("sliceId"),
                    )
                self._send(200, {"ok": True, "result": result})
                return
            if len(parts) == 5 and parts[:2] == ["v1", "deployments"] and parts[3:] == ["purge", "plan"]:
                self._mutation_security("deployment purge plan")
                if not {"grantId"} <= set(body) <= {"grantId", "sliceId"}:
                    raise ValueError("deployment purge plan request shape is invalid")
                result = platform_surface.plan_purge(
                    self.server, identity=parts[2], grant=body.get("grantId"), slice_identity=body.get("sliceId"),
                )
                self._send(200, {"ok": True, "result": result})
                return
            if len(parts) == 5 and parts[:3] == ["v1", "authority", "grants"] and parts[4] == "revoke":
                self._mutation_security("authority grant revocation")
                platform_surface.require_platform_operator(self.server)
                required = {"ownerDirectiveId", "reason", "grantDigest", "approval"}
                if set(body) != required:
                    raise ValueError("authority grant revocation request shape is invalid")
                detail = platform_surface.authority_grant_detail(self.server, parts[3])
                grant_digest = detail["grant"].get("grantDigest")
                if not isinstance(grant_digest, str):
                    raise platform_surface.PlatformSurfaceError("invalid_authority_state", "authority grant digest is unavailable")
                reviewed_digest = platform_surface.digest_text(body.get("grantDigest"), "authority grant digest")
                if reviewed_digest != grant_digest:
                    raise platform_surface.PlatformSurfaceError(
                        "authority_digest_mismatch",
                        "authority grant changed since it was reviewed",
                    )
                platform_surface.require_digest_approval(self.server, body, grant_digest)
                result = platform_surface.revoke_grant(
                    self.server,
                    identity=parts[3],
                    owner_directive_id=body.get("ownerDirectiveId"),
                    reason=body.get("reason"),
                    expected_grant_digest=reviewed_digest,
                )
                self._send(200, {"ok": True, "result": result})
                return
            if path == "/v1/authority/pause":
                self._mutation_security("authority pause")
                platform_surface.require_platform_operator(self.server)
                paused = body.get("paused")
                required = {"paused", "ownerDirectiveId", "reason", "controlDigest", "approval"}
                if set(body) != required:
                    raise ValueError("authority pause request shape is invalid")
                control = platform_surface.authority_manager(self.server).inspect()["control"]
                control_digest = control.get("controlDigest")
                if not isinstance(control_digest, str):
                    raise platform_surface.PlatformSurfaceError("invalid_authority_state", "authority control digest is unavailable")
                reviewed_digest = platform_surface.digest_text(body.get("controlDigest"), "authority control digest")
                if reviewed_digest != control_digest:
                    raise platform_surface.PlatformSurfaceError(
                        "authority_digest_mismatch",
                        "authority control changed since it was reviewed",
                    )
                platform_surface.require_digest_approval(self.server, body, control_digest)
                result = platform_surface.set_authority_paused(
                    self.server,
                    paused=paused,
                    owner_directive_id=body.get("ownerDirectiveId"),
                    reason=body.get("reason"),
                    expected_control_digest=reviewed_digest,
                )
                self._send(200, {"ok": True, "result": result})
                return
            if path == "/v1/updater/policy":
                self._mutation_security("updater policy")
                self._strict_body(body, {"policy", "expectedStatusDigest", "approval"})
                digest = platform_surface.digest_text(body.get("expectedStatusDigest"), "expected status digest")
                platform_surface.require_digest_approval(self.server, body, digest)
                result = platform_surface.set_updater_policy(
                    self.server,
                    policy=body.get("policy"),
                    expected_status_digest=digest,
                )
                self._send(200, {"ok": True, "result": result})
                return
            if path == "/v1/updater/rollback":
                self._mutation_security("updater rollback plan")
                self._strict_body(body, {"expectedStatusDigest", "approval"})
                digest = platform_surface.digest_text(body.get("expectedStatusDigest"), "expected status digest")
                platform_surface.require_digest_approval(self.server, body, digest)
                result = platform_surface.plan_updater_rollback(
                    self.server, expected_status_digest=digest
                )
                self._send(200, {"ok": True, "result": result})
                return
            if path == "/v1/preview-routes":
                self._mutation_security("preview route registration")
                if not _preview_enabled(self.server):
                    self._error(409, PREVIEW_DISABLED_MESSAGE, PREVIEW_DISABLED_CODE)
                    return
                required = {"capsuleId", "serviceId", "revisionDigest", "upstreamPort", "ttlSeconds"}
                if set(body) != required:
                    raise ValueError("preview route registration request shape is invalid")
                registry = _preview_registry(self.server)
                result = _preview_mutation_result(registry.register(
                    capsule_id=body.get("capsuleId"),
                    service_id=body.get("serviceId"),
                    revision_digest=body.get("revisionDigest"),
                    upstream_port=body.get("upstreamPort"),
                    ttl_seconds=body.get("ttlSeconds"),
                    actor=self.server.actor_id,
                ))
                self._send(200, {"ok": True, "result": result})
                return
            if len(parts) == 4 and parts[:2] == ["v1", "preview-routes"] and parts[3] in {"revoke", "rewrite"}:
                operation = parts[3]
                self._mutation_security(f"preview route {operation}")
                if not _preview_enabled(self.server):
                    self._error(409, PREVIEW_DISABLED_MESSAGE, PREVIEW_DISABLED_CODE)
                    return
                registry = _preview_registry(self.server)
                if operation == "revoke":
                    self._strict_body(body, {"reason", "expectedRouteDigest"})
                    result = _preview_mutation_result(
                        registry.revoke(parts[2], reason=body.get("reason"), expected_route_digest=body.get("expectedRouteDigest"), actor=self.server.actor_id)
                    )
                else:
                    self._strict_body(body, {"revisionDigest", "upstreamPort", "expectedRouteDigest"})
                    result = _preview_mutation_result(
                        registry.rewrite(
                            parts[2],
                            revision_digest=body.get("revisionDigest"),
                            upstream_port=body.get("upstreamPort"),
                            expected_route_digest=body.get("expectedRouteDigest"),
                            actor=self.server.actor_id,
                        )
                    )
                self._send(200, {"ok": True, "result": result})
                return
            if path == "/v1/execution-host/workloads":
                self._mutation_security("execution host create")
                self._strict_body(body, ({"instanceId", "sourceReviewDigest"} if "sourceReviewDigest" in body else {"instanceId"}) if body else set())
                result = self.server.record_execution_host_result(
                    self.server.create_application_workspace(body["instanceId"], source_review_digest=body.get("sourceReviewDigest")) if body else self.server.execution_host.create_default()
                )
                self._send(200, {"ok": True, "result": result})
                return
            if path == "/v1/execution-host/workloads/start":
                self._mutation_security("execution host start")
                self._strict_body(body, {"workloadId"})
                result = self.server.record_execution_host_result(
                    self.server.execution_host.start(body.get("workloadId"))
                )
                self._send(200, {"ok": True, "result": result})
                return
            if path == "/v1/execution-host/workloads/stop":
                self._mutation_security("execution host stop")
                self._strict_body(body, {"workloadId"})
                result = self.server.record_execution_host_result(
                    self.server.execution_host.stop(body.get("workloadId"))
                )
                self._send(200, {"ok": True, "result": result})
                return
            if path == "/v1/execution-host/workloads/cancel":
                self._mutation_security("execution host cancel")
                self._strict_body(body, {"workloadId"})
                result = self.server.record_execution_host_result(
                    self.server.execution_host.cancel(body.get("workloadId"))
                )
                self._send(200, {"ok": True, "result": result})
                return
            if path == "/v1/execution-host/workloads/remove":
                self._mutation_security("execution host remove")
                self._strict_body(body, {"workloadId"})
                result = self.server.record_execution_host_result(
                    self.server.execution_host.remove(body.get("workloadId"))
                )
                self._send(200, {"ok": True, "result": result})
                return
            if path == "/v1/execution-host/workloads/exec":
                self._mutation_security("execution host exec")
                self._strict_body(body, {"workloadId", "argv"})
                result = self.server.record_execution_host_result(
                    self.server.execution_host.exec(body.get("workloadId"), body.get("argv"))
                )
                self._send(200, {"ok": True, "result": result})
                return
            self._error(404, "route not found", "not_found")
        except ExecutionHostProxyError as exc:
            self._error(exc.status, str(exc), exc.code)
        except PortableImportError as exc:
            self._error(409, str(exc), exc.code)
        except RepositoryImportError as exc:
            self._error(409, str(exc), exc.code)
        except InfrastructureError as exc:
            self._error(409, str(exc), exc.code)
        except EnvironmentGatedExecution as exc:
            self._send(200, {"ok": True, "result": exc.payload})
        except ContextLifecycleError as exc:
            self._error(409, "the context lifecycle request was refused", exc.reason_code)
        except GovernanceRefusal as exc:
            self._error(409, "the governed goal operation was refused", exc.code)
        except GoalContractError:
            self._error(409, "the governed goal contract was refused", "goal_contract_refused")
        except SettingsError as exc:
            self._error(409, str(exc), "settings_request_refused")
        except platform_surface.PlatformSurfaceError as exc:
            status = 404 if exc.code.endswith("_not_found") else 409
            self._error(status, str(exc)[:512], exc.code)
        except PermissionError:
            if path == "/v1/settings" or "/settings" in path:
                self._error(403, "settings access denied", "settings_access_denied")
            elif "/terminal/" in path:
                self._error(403, "terminal access denied", "terminal_access_denied")
            elif "/conversation/" in path:
                self._error(403, "conversation access denied", "conversation_access_denied")
            elif "/context-lifecycle/" in path:
                self._error(403, "context lifecycle access denied", "context_lifecycle_access_denied")
            elif "/goal-execution/" in path:
                self._error(403, "goal execution access denied", "goal_execution_access_denied")
            elif path.startswith("/v1/deployments"):
                self._error(403, "deployment access denied", "deployment_access_denied")
            elif path.startswith("/v1/authority"):
                self._error(403, "authority access denied", "authority_access_denied")
            elif path.startswith("/v1/updater"):
                self._error(403, "updater access denied", "updater_access_denied")
            elif path.startswith("/v1/preview-routes"):
                self._error(403, "preview route access denied", "preview_route_access_denied")
            elif path.startswith("/v1/execution-host"):
                self._error(403, "execution host access denied", "execution_host_access_denied")
            elif path == "/v1/application-fixtures/install":
                self._error(403, "application installation authorization failed", "application_install_denied")
            elif "/template-upgrade/" in path:
                self._error(403, "template upgrade authorization failed", "template_upgrade_denied")
            elif path == "/v1/catalog/refresh":
                self._error(403, "catalog refresh authorization failed", "catalog_refresh_denied")
            elif path.endswith("/portable-export"):
                self._error(403, "portable export authorization failed", "portable_export_denied")
            elif path.endswith("/backup"):
                self._error(403, "application backup authorization failed", "backup_access_denied")
            elif "/recovery/restore/" in path:
                self._error(403, "application restore authorization failed", "restore_access_denied")
            elif path.endswith("/synthetic-run"):
                self._error(403, "synthetic contract inspection authorization failed", "synthetic_validation_denied")
            elif path.startswith("/v1/runs/") or path.endswith("/execution/prepare"):
                self._error(403, "governed run authorization failed", "execution_access_denied")
            elif path.startswith("/v1/portable-import/"):
                self._error(403, "portable import authorization failed", "portable_import_denied")
            elif path.startswith("/v1/sources/"):
                self._error(403, "development source verification is operator-only", "source_verification_denied")
            else:
                self._error(403, "file workspace access denied", "file_workspace_access_denied")
        except ActivityReceiptError as exc:
            self._error(409, str(exc), "activity_receipts_refused")
        except ConversationAttachmentError as exc:
            self._error(409, str(exc), "conversation_attachment_refused")
        except TemplateUpgradeError as exc:
            self._error(exc.status, str(exc)[:512], exc.code)
        except Exception as exc:  # noqa: BLE001 - local boundary redacts non-broker details
            if exc.__class__.__module__.startswith("stateport_file_workspace."):
                self._error(409, str(exc), "file_workspace_refused")
            elif exc.__class__.__module__.startswith("stateport_terminal_broker."):
                self._error(409, "the terminal request was refused", "terminal_refused")
            elif exc.__class__.__module__.startswith("stateport_deployment."):
                code = platform_surface.public_error_code(exc, "deployment_refused")
                self._error(404 if code == "deployment_not_found" else 409, str(exc)[:512], code)
            elif exc.__class__.__module__.startswith("governed_runner."):
                self._error(409, str(exc)[:512], platform_surface.public_error_code(exc, "authority_refused"))
            elif exc.__class__.__module__.startswith("stateport_updater."):
                self._error(409, str(exc)[:512], platform_surface.public_error_code(exc, "updater_refused"))
            elif exc.__class__.__module__.startswith("stateport_preview_gateway."):
                code = platform_surface.public_error_code(exc, "preview_refused")
                self._error(404 if code == "preview_route_not_found" else 409, str(exc)[:512], code)
            elif exc.__class__.__module__.startswith("stateport_portable_execution."):
                # Governed run preparation/execution failures must surface
                # their typed refusal instead of a generic operation_failed.
                code = platform_surface.public_error_code(exc, "execution_refused")
                self._error(409, str(exc)[:512], code)
            else:
                self._error(400, "the local operation failed", "operation_failed")

    def log_message(self, fmt: str, *args: object) -> None:
        self.server.log.write((fmt % args) + "\n")
        self.server.log.flush()

    def log_request(self, code: int | str = "-", size: int | str = "-") -> None:
        """Log only the fixed path, never query values or request bodies."""

        path = urlsplit(self.path).path
        self.log_message("method=%s path=%s status=%s bytes=%s", self.command, path, code, size)


class AppServer(ThreadingHTTPServer):
    # Permit a clean local restart after the previous listener has closed.
    # A live listener still produces the normal address-in-use diagnostic.
    allow_reuse_address = True
    # Long-lived assistant SSE and terminal handlers are explicitly managed
    # by processor/socket shutdown. They must never keep interpreter teardown
    # alive after the bounded server cleanup has completed.
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        layout: LocalLayout,
        web_root: Path,
        *,
        actor_role: str = "local_user",
        canonical_source_catalog: Path | str | None = None,
        expected_source_catalog_digest: str | None = None,
        allow_public_bind: bool = False,
        external_loopback_port: int | None = None,
        expected_source_commit: str | None = None,
        expected_source_tree: str | None = None,
    ):
        from stateport_application_experience import ExperienceRegistry, load_experience_policy
        from stateport_conversation import ConversationService, ParticipantIdentity, WebFixtureAdapter, canonical_digest

        if address[0] != "127.0.0.1" and not allow_public_bind:
            raise ValueError("the persistent StatePort service is loopback-only")
        if external_loopback_port is not None and (
            not allow_public_bind
            or isinstance(external_loopback_port, bool)
            or not isinstance(external_loopback_port, int)
            or not 1 <= external_loopback_port <= 65535
        ):
            raise ValueError(
                "external loopback port requires an allowed public bind and a valid port"
            )
        source_web_root = web_root.resolve()
        product_root = source_web_root.parents[1]
        selected_web_root = _select_web_root(
            source_web_root,
            expected_source_commit=expected_source_commit,
            expected_source_tree=expected_source_tree,
        )
        self.layout = layout
        if actor_role == "platform_operator":
            operator_boundary = layout.config_root / "platform-operator-authority"
            try:
                boundary_stat = operator_boundary.stat()
            except OSError as exc:
                raise ValueError(
                    "platform_operator requires an OS-owned platform-operator-authority file"
                ) from exc
            if (
                not operator_boundary.is_file()
                or boundary_stat.st_uid != os.geteuid()
                or boundary_stat.st_mode & 0o077
            ):
                raise ValueError(
                    "platform_operator requires a private OS-owned platform-operator-authority file"
                )
        self.web_root = selected_web_root
        self.product_root = product_root
        self.vite_asset_paths = self._vite_assets(self.web_root)
        self.app = PersistentApp(
            layout,
            canonical_source_catalog=canonical_source_catalog,
        )
        source_catalog_identity = self.app._service_source_catalog_identity()
        if (
            expected_source_catalog_digest is not None
            and source_catalog_identity["canonicalSourceCatalogDigest"]
            != expected_source_catalog_digest
        ):
            raise ValueError("configured source catalog does not match its expected digest")
        self.canonical_source_catalog = Path(
            source_catalog_identity["canonicalSourceCatalog"]
        )
        self.canonical_source_catalog_digest = source_catalog_identity[
            "canonicalSourceCatalogDigest"
        ]
        self.log = open(layout.logs_root / "service.log", "a", encoding="utf-8")
        self.execution = PortableExecutionService(self.app, product_root)
        self.execution_host = ExecutionHostProxy(catalog_entry=self.workspace_catalog_entry, catalog_entries=lambda: self.source_app().catalog.list(), instance_runs=self.execution.history)
        self.repository_inspector = RepositoryInspector(RepositorySourcePolicy(layout))
        self.context_lifecycle = ContextLifecycleService(
            policy_path=(product_root / "config" / "context-lifecycle.v1.yaml").resolve(),
            preference_file=(layout.config_root / "context-lifecycle-preferences.json").resolve(),
            record_root=(layout.state_root / "context-lifecycle" / "records").resolve(),
        )
        self.experience_registry = ExperienceRegistry(product_root)
        self.experience_policy = load_experience_policy(product_root / "config" / "application-experience-policy.yaml")
        if actor_role not in {"local_user", "platform_operator"} or actor_role not in self.experience_policy.actor_permissions:
            raise ValueError("persistent service actor role is unsupported")
        self.conversations = ConversationService(store_path=layout.state_root / "conversation.sqlite3")
        self.activity_receipts = ActivityReceiptStore(layout.state_root / "activity-receipts.sqlite3")
        self.attachments = ConversationAttachmentStore(layout.data_root / "attachments")
        self.web_conversation_adapter = WebFixtureAdapter()
        self._participant_contract = ParticipantIdentity
        self._conversation_digest = canonical_digest
        self._conversation_scopes: dict[str, tuple[str, str, str]] = {}
        self._context_continuities: dict[str, tuple[str, ContinuityState, TokenUsage]] = {}
        self.actor_role = actor_role
        self.actor_id = "platform-operator" if actor_role == "platform_operator" else "local-user"
        self.template_upgrade_approver = f"authenticated-{actor_role}-approver"
        self.external_loopback_port = external_loopback_port
        self._ensure_registered_instance_capability_grants()
        self.template_upgrades = GovernedAPI(
            layout.data_root,
            identities={
                _TEMPLATE_UPGRADE_REQUESTER: {"roles": ["requester"], "instances": ["*"]},
                self.template_upgrade_approver: {"roles": ["approver"], "instances": ["*"]},
                _TEMPLATE_UPGRADE_OPERATOR: {"roles": ["operator"], "instances": ["*"]},
            },
            operator_allowed_capabilities=["write_state"],
            instance_capability_resolver=self._template_upgrade_capabilities,
            template_capability_resolver=self._template_upgrade_template_capabilities,
            upgrade_target_binding_resolver=self._template_upgrade_target_binding,
            lease_root=layout.operations_root / "leases",
        )
        self.goal_execution = GoalExecutionCoordinator(record_root=(layout.state_root / "goal-execution").resolve())
        self.session = secrets.token_urlsafe(24)
        self.csrf_token = secrets.token_urlsafe(32)
        self._file_workspace_mutex = threading.RLock()
        self.file_workspaces: dict[str, tuple[str, object]] = {}
        self._terminal_mutex = threading.RLock()
        self.terminal_brokers: dict[str, tuple[str, object, object, Path, str, object]] = {}
        self.terminal_tickets: dict[str, dict[str, object]] = {}
        self._terminal_sockets_mutex = threading.Condition(threading.Lock())
        self._terminal_sockets: set[socket.socket] = set()
        self._terminal_closing = False
        from .provider_setup import ProviderSetup
        self.provider_setup = ProviderSetup(layout.config_root, layout.state_root)
        self._assistant_processor: object = None
        self._provider_execution_allowed = os.environ.get("STATEPORT_RELEASE_PROFILE", "").strip().lower() != "validation"
        if self._provider_execution_allowed and self.provider_setup.startup_allowed() and (self.provider_setup.profile_path.exists() or os.environ.get("STATEPORT_ASSISTANT_PROCESSOR_ENABLED", "").strip().lower() in {"1", "true", "yes"}):
            from stateport_persistent_app.assistant_processor import AssistantProcessor
            self._assistant_processor = AssistantProcessor(
                self.conversations,
                log_writer=lambda msg: (self.log.write(msg), self.log.flush()),
            )
        try:
            self.telegram_launcher = self._construct_telegram_launcher(layout)
            self._eager_telegram_setup()
            super().__init__(address, Handler)
        except Exception:
            self.log.close()
            raise
        if self._assistant_processor is not None:
            self._assistant_processor.start()

    def _stop_provider_processor(self):
        processor = self._assistant_processor
        if processor is None:
            return
        processor.shutdown()
        if not processor.shutdown_complete:
            raise RuntimeError("provider processor is still stopping; retry after it stops")
        processor.work_store.cancel_queued_for_disconnect()
        self._assistant_processor = None

    def provider_action(self, action, body):
        from .provider_router import ProviderRouter, PROVIDERS
        from .assistant_processor import AssistantProcessor
        with self.provider_setup.lock:
            if not self._provider_execution_allowed and action in {"configure", "verify"}:
                raise PermissionError("provider execution is disabled in the validation release profile")
            if action == "verify":
                return self.provider_setup.verify()
            if action == "disconnect":
                result = self.provider_setup.disconnect()
                self._stop_provider_processor()
                return result
            # Validate before interrupting active work.
            model = body.get("model")
            provider_id = body["providerId"] if "providerId" in body else self.provider_setup.selected_provider()
            if not isinstance(provider_id, str) or provider_id not in PROVIDERS:
                raise ValueError("provider identity is invalid")
            if not isinstance(model, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}", model):
                raise ValueError("provider configuration is invalid")
            candidate = None
            try:
                # Keep the durable refusal marker throughout preparation. A
                # failed constructor or cursor write must not enable replay on
                # the next service restart.
                self.provider_setup.disconnect()
                self._stop_provider_processor()
                ProviderRouter.configure(
                    self.provider_setup.profile_path, provider_id=provider_id,
                    model_identifier=model, time_seconds=30, steps=2,
                )
                self.provider_setup.probe(provider_id)
                if provider_id == 'opencode':
                    self.provider_setup.authentication = self.provider_setup.request = "unverified"
                    return self.provider_setup.status()
                candidate = AssistantProcessor(
                    self.conversations,
                    router=ProviderRouter(self.provider_setup.profile_path),
                    log_writer=lambda msg: (self.log.write(msg), self.log.flush()),
                )
                candidate.work_store.cancel_queued_for_disconnect()
                candidate.activate_current_messages()
                self._assistant_processor = candidate
                self.provider_setup.disabled_path.unlink()
                candidate.start()
                self.provider_setup.authentication = self.provider_setup.request = "unverified"
                self.provider_setup.detail = "Model saved. Authenticate using Codex in this runtime, then verify. StatePort never reads or copies credentials."
                return self.provider_setup.status()
            except Exception:
                # A start can fail after creating its thread. Restore durable
                # refusal first, then retain any processor whose shutdown has
                # not completed so a retry cannot create a competing owner.
                self.provider_setup.disconnect()
                if candidate is not None:
                    self._assistant_processor = candidate
                    self._stop_provider_processor()
                raise RuntimeError("provider setup failed; StatePort provider work remains disabled") from None

    @staticmethod
    def _vite_assets(web_root: Path) -> frozenset[str]:
        """Load only reviewed Vite outputs; never expose the manifest or maps."""

        manifest_path = web_root / ".vite" / "manifest.json"
        if not manifest_path.is_file() or manifest_path.is_symlink():
            return frozenset()
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return frozenset()
        if not isinstance(manifest, dict):
            return frozenset()
        assets: set[str] = set()
        for entry in manifest.values():
            if not isinstance(entry, dict):
                return frozenset()
            values = [entry.get("file"), *(entry.get("css") or []), *(entry.get("assets") or [])]
            for value in values:
                if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9._/-]+", value):
                    return frozenset()
                if value.startswith("/") or ".." in value.split("/") or value.endswith(".map"):
                    return frozenset()
                target = Handler._bounded_static(web_root, value)
                if target is None or target.suffix not in {".js", ".css", ".svg", ".png", ".webp", ".woff", ".woff2"}:
                    return frozenset()
                assets.add(value)
        return frozenset(assets)

    def actor_projection(self) -> dict[str, object]:
        permissions = self.experience_policy.permissions_for(self.actor_role)
        statebench = "platform.statebench.read" in permissions
        return {
            "role": self.actor_role,
            "actorId": self.actor_id,
            "platformOperationsAllowed": statebench,
            "statebenchInspectionAllowed": statebench,
        }

    def settings_store(self, instance_id: str | None = None) -> SettingsStore:
        """Return the typed operational settings store for the requested scope."""

        if instance_id is None:
            return SettingsStore(self.layout.settings_root / "global.json", scope="global")
        if not re.fullmatch(r"[a-z][a-z0-9._-]{1,127}", instance_id):
            raise SettingsError("settings instance identity is invalid")
        self.source_app().catalog.get(instance_id)
        store = SettingsStore(
            self.layout.settings_root / "instances" / f"{instance_id}.json",
            scope="application",
            instance_id=instance_id,
        )
        # Context mode has one authority: ContextLifecycleService. Reflect its
        # current effective preference without creating a second writable state
        # machine in the general settings store.
        store.values["context.mode"] = self.context_lifecycle.preference_mode(instance_id)
        return store

    def _refresh_activity_projection(self, instance_id: str) -> None:
        """Synchronize the operational index from already-persisted local facts."""

        app = self.source_app()
        inspection = app.inspect(instance_id)
        settings = self.settings_store(instance_id).projection()
        receipts = settings.get("recentReceipts") if isinstance(settings, dict) else None
        self.activity_receipts.refresh(
            instance_id=instance_id,
            inspection=inspection,
            settings_receipts=receipts if isinstance(receipts, list) else [],
            application_install_receipt=app.application_install_receipt(instance_id),
            application_rename_receipts=app.application_rename_receipts(instance_id),
        )
        for receipt in self.execution.closure_receipts(instance_id):
            self.activity_receipts.record_receipt(
                instance_id=instance_id,
                receipt=receipt,
            )

    def activity_projection(self, instance_id: str) -> dict[str, object]:
        self._refresh_activity_projection(instance_id)
        global_projection = self.settings_store().projection()
        notification_level = "important"
        for section in global_projection.get("sections", []):
            for field in section.get("fields", []) if isinstance(section, dict) else []:
                if isinstance(field, dict) and field.get("key") == "notifications.level":
                    notification_level = str(field.get("value", notification_level))
        return self.activity_receipts.activity(instance_id, notification_level=notification_level)

    def receipt_index_projection(self, instance_id: str) -> dict[str, object]:
        self._refresh_activity_projection(instance_id)
        return self.activity_receipts.receipt_index(instance_id)

    def receipt_detail_projection(self, instance_id: str, receipt_id: str) -> dict[str, object]:
        self._refresh_activity_projection(instance_id)
        return self.activity_receipts.receipt_detail(instance_id, receipt_id)

    def record_execution_host_result(
        self, result: Mapping[str, object]
    ) -> dict[str, object]:
        """Persist the bounded daemon receipt before returning a mutation."""

        receipt = result.get("receipt")
        if not isinstance(receipt, Mapping):
            raise ExecutionHostProxyError(
                "execution_receipt_missing",
                "execution host mutation returned no persistable receipt",
                status=502,
            )
        projected = dict(receipt)
        projected["actorId"] = self.actor_id
        self.activity_receipts.record_receipt(
            instance_id=_EXECUTION_HOST_RECEIPT_SCOPE,
            receipt=projected,
        )
        owned_instance = projected.get("instanceId")
        if isinstance(owned_instance, str) and owned_instance != _EXECUTION_HOST_RECEIPT_SCOPE:
            self.activity_receipts.record_receipt(instance_id=owned_instance, receipt=projected)
        response = dict(result)
        response["receipt"] = projected
        return response

    def execution_host_receipts(self) -> dict[str, object]:
        return self.activity_receipts.receipt_index(_EXECUTION_HOST_RECEIPT_SCOPE)

    def transition_activity_attention(self, *, instance_id: str, attention_id: str, action: str, expected_version: object) -> dict[str, object]:
        self._refresh_activity_projection(instance_id)
        return self.activity_receipts.transition_attention(
            instance_id=instance_id, attention_id=attention_id, action=action,
            expected_version=expected_version,
        )

    def source_app(self) -> PersistentApp:
        return self.app

    def require_actor_permission(self, permission: str) -> None:
        if permission not in self.experience_policy.permissions_for(self.actor_role):
            raise PermissionError("actor permission is unavailable")

    def approvals_projection(self) -> dict[str, object]:
        """Derive the global inbox from the existing decision authorities."""

        approvals: list[dict[str, object]] = []
        for request in self.pending_template_upgrade_approvals():
            metadata = request.get("metadata")
            plan = metadata.get("planBinding") if isinstance(metadata, Mapping) else None
            target = metadata.get("targetBinding") if isinstance(metadata, Mapping) else None
            if not isinstance(plan, Mapping) or not isinstance(target, Mapping):
                continue
            approval_id = request.get("id")
            instance_id = request.get("instanceId")
            plan_digest = plan.get("planDigest")
            requested_at = target.get("requestedAt")
            if not all(
                isinstance(value, str) and value
                for value in (approval_id, instance_id, plan_digest, requested_at)
            ):
                continue
            target_revision = str(target.get("targetRevision") or "unknown")
            target_version = str(plan.get("targetVersion") or "unknown")
            approvals.append({
                "id": f"template_upgrade:{approval_id}",
                "instanceId": instance_id,
                "kind": "template_upgrade",
                "title": f"Approve template upgrade to {target_version}",
                "operationType": "template_upgrade",
                "risk": "medium",
                "status": "pending",
                "scope": [
                    f"Application: {target.get('applicationId', 'unknown')}",
                    f"Instance: {instance_id}",
                    f"Target revision: {target_revision}",
                    f"Target version: {target_version}",
                    f"Template digest: {target.get('templateDigest', 'unknown')}",
                ],
                "beforeSummary": "The installed application instance remains on its current template revision.",
                "afterSummary": f"Apply only the exact reviewed upgrade plan for descriptor revision {target_revision}; execution remains separate.",
                "planDigest": plan_digest,
                "targetId": approval_id,
                "whyRequired": "Template upgrades can modify canonical application files and require an independent exact-plan approval.",
                "requestedAt": requested_at,
                "decision": {
                    "kind": "template_upgrade",
                    "expectedInstanceId": instance_id,
                    "expectedDigest": plan_digest,
                },
            })
        for run in self.execution.pending_approval_sources():
            status = str(run["status"])
            run_id = str(run["runId"])
            instance_id = str(run["instanceId"])
            revision = int(run["revision"])
            requested_at = run.get("requestedAt")
            action_id = str(run.get("actionId") or "governed action")
            action_display = run.get("actionDisplayName")
            action_label = (
                action_display
                if isinstance(action_display, str) and action_display
                else action_id.replace("_", " ")
            )
            if not isinstance(requested_at, str):
                continue
            if status == "awaiting_approval":
                digest_value = str(run["runSpecDigest"])
                decision_kind = "run_approval"
                title = f"Approve {action_label}"
                before = "The governed run is prepared and has not executed."
                after = "Record exact run approval; execution remains a separate governed step."
                scope = [
                    f"Run: {run_id}",
                    f"Action: {action_id}",
                    f"Revision: {revision}",
                ]
            else:
                digest_value = str(run["proposalDigest"])
                decision_kind = "run_proposal"
                title = f"Approve changes proposed by {action_label}"
                before = "The governed run completed without changing canonical application state."
                after = "Approve the exact proposed file changes; applying them remains a separate governed step."
                scope = [
                    f"Run: {run_id}",
                    f"Action: {action_id}",
                    f"Revision: {revision}",
                    *[
                        f"Path: {path}"
                        for path in (run.get("proposalPaths") or [])[:20]
                        if isinstance(path, str)
                    ],
                ]
            source_revision = (
                (run.get("runSpec") or {}).get("instance", {}).get("sourceRevision")
                if isinstance(run.get("runSpec"), Mapping)
                and isinstance((run.get("runSpec") or {}).get("instance"), Mapping)
                else None
            )
            if isinstance(source_revision, str):
                scope.append(f"Source revision: {source_revision}")
            approvals.append({
                "id": f"{decision_kind}:{run_id}",
                "instanceId": instance_id,
                "kind": "orchestration_run",
                "title": title,
                "operationType": decision_kind,
                "risk": "medium" if status == "state_change_proposed" or run.get("mutationPolicy") == "propose_only" else "low",
                "status": "pending",
                "scope": scope,
                "beforeSummary": before,
                "afterSummary": after,
                "planDigest": digest_value,
                "targetId": run_id,
                "runId": run_id,
                "whyRequired": "This decision is bound to the persisted run revision and exact content digest.",
                "requestedAt": requested_at,
                "decision": {
                    "kind": decision_kind,
                    "expectedInstanceId": instance_id,
                    "expectedRevision": revision,
                    "expectedDigest": digest_value,
                },
            })

        app = self.source_app()
        entries = app.instance_list()
        for entry in entries:
            instance_id = entry.get("instanceId")
            if not isinstance(instance_id, str):
                continue
            if (
                self.actor_id == "local-user"
                and entry.get("applicationId") == "nixos-infrastructure"
                and isinstance(entry.get("metadata"), Mapping)
                and entry["metadata"].get("externalRepository") is True
            ):
                try:
                    infrastructure_sources = self.infrastructure_adapter(instance_id).pending_approval_sources()
                except (InfrastructureError, OSError, ValueError):
                    infrastructure_sources = []
                for source in infrastructure_sources:
                    if source.get("type") == "infrastructure_plan" and isinstance(source.get("plan"), Mapping):
                        plan = source["plan"]
                        digest_value = plan.get("planDigest")
                        created_at = plan.get("createdAt")
                        expires_at = plan.get("expiresAt")
                        operation = plan.get("operation")
                        target = plan.get("target")
                        repository = plan.get("repository")
                        if not all(isinstance(value, str) for value in (digest_value, created_at, expires_at, operation)):
                            continue
                        if not isinstance(target, Mapping) or not isinstance(repository, Mapping):
                            continue
                        target_id = str(target.get("targetId") or "libvirt-persistent")
                        domain = str(target.get("domain") or target_id)
                        approvals.append({
                            "id": f"infrastructure_plan:{digest_value}",
                            "instanceId": instance_id,
                            "kind": "infrastructure_plan",
                            "title": f"Approve {str(operation).replace('_', ' ')}",
                            "operationType": str(operation),
                            "risk": "high" if operation == "destroy" else "medium",
                            "status": "pending",
                            "scope": [
                                f"Target: {domain}",
                                f"Target ID: {target_id}",
                                f"Repository branch: {repository.get('branch', 'unknown')}",
                                f"Repository commit: {repository.get('headCommit', 'unknown')}",
                                f"Repository tree: {repository.get('headTree', 'unknown')}",
                            ],
                            "beforeSummary": f"The target was observed as {(plan.get('domainBefore') or {}).get('state', 'unknown')}.",
                            "afterSummary": f"Authorize only this exact {str(operation).replace('_', ' ')} plan; running it remains separate.",
                            "planDigest": digest_value,
                            "planId": digest_value,
                            "targetId": target_id,
                            "whyRequired": "This infrastructure mutation is not covered by an active authorization grant.",
                            "requestedAt": created_at,
                            "expiresAt": expires_at,
                            "decision": {
                                "kind": "infrastructure_plan",
                                "expectedInstanceId": instance_id,
                                "expectedDigest": digest_value,
                            },
                        })
                    elif source.get("type") == "authorization_grant" and isinstance(source.get("grant"), Mapping):
                        grant = source["grant"]
                        digest_value = grant.get("proposalDigest")
                        created_at = grant.get("createdAt")
                        target = grant.get("target")
                        if not isinstance(digest_value, str) or not isinstance(created_at, str) or not isinstance(target, Mapping):
                            continue
                        grant_id = str(grant.get("grantId") or "local-nix-daily-driver")
                        target_id = str(target.get("targetId") or "libvirt-persistent")
                        allowed = [
                            str(item).replace("_", " ")
                            for item in grant.get("allowedOperations", [])
                            if isinstance(item, str)
                        ]
                        approvals.append({
                            "id": f"authorization_grant:{grant_id}:{digest_value}",
                            "instanceId": instance_id,
                            "kind": "authorization_grant",
                            "title": "Activate daily-driver authorization",
                            "operationType": "authorization_grant",
                            "risk": "medium",
                            "status": "pending",
                            "scope": [
                                f"Target: {target.get('domain', target_id)}",
                                f"Target ID: {target_id}",
                                *[f"Allow: {item}" for item in allowed],
                            ],
                            "beforeSummary": "Routine infrastructure mutations require approval of each exact plan.",
                            "afterSummary": "Authorize only the listed operations while the repository and VM target identities remain unchanged.",
                            "planDigest": digest_value,
                            "targetId": target_id,
                            "whyRequired": "A template may request this scope, but only the authenticated local user can grant it.",
                            "requestedAt": created_at,
                            "decision": {
                                "kind": "authorization_grant",
                                "expectedInstanceId": instance_id,
                                "expectedDigest": digest_value,
                            },
                        })

            try:
                _application_id, root = self.goal_execution_binding(instance_id)
                goal = self.goal_execution.pending_approval_source(instance_id, root)
            except (PermissionError, GovernanceRefusal, GoalContractError, AppError, OSError, ValueError):
                goal = None
            if not isinstance(goal, Mapping):
                continue
            revision = goal.get("revision")
            recorded_at = goal.get("recordedAt")
            plan = goal.get("slice")
            selected = goal.get("selectedItem")
            if (
                isinstance(revision, bool)
                or not isinstance(revision, int)
                or revision < 0
                or not isinstance(recorded_at, str)
                or not isinstance(plan, Mapping)
                or not isinstance(selected, Mapping)
                or not isinstance(plan.get("planDigest"), str)
            ):
                continue
            digest_value = str(plan["planDigest"])
            objective = str(selected.get("objective") or selected.get("itemId") or "governed goal slice")
            approvals.append({
                "id": f"goal_execution:{instance_id}:{digest_value}",
                "instanceId": instance_id,
                "kind": "goal_execution",
                "title": f"Approve goal slice: {objective}",
                "operationType": "goal_execution",
                "risk": "medium",
                "status": "pending",
                "scope": [
                    f"Item: {plan.get('itemId', 'unknown')}",
                    f"Revision: {revision}",
                    f"Base commit: {plan.get('baseCommit', 'unknown')}",
                    f"Base tree: {plan.get('baseTree', 'unknown')}",
                    f"State snapshot: {plan.get('stateSnapshotDigest', 'unknown')}",
                    f"Mode: {goal.get('mode', 'unknown')}",
                ],
                "beforeSummary": "The bounded goal slice is prepared and has not executed.",
                "afterSummary": "Approve this exact slice; execution and independent review remain separate governed steps.",
                "planDigest": digest_value,
                "targetId": str(plan.get("itemId") or instance_id),
                "whyRequired": "Assisted and managed goal execution require an independent exact-plan approval.",
                "requestedAt": recorded_at,
                "decision": {
                    "kind": "goal_execution",
                    "expectedInstanceId": instance_id,
                    "expectedRevision": revision,
                    "expectedDigest": digest_value,
                },
            })

        approvals.sort(key=lambda item: (str(item.get("requestedAt", "")), str(item.get("id", ""))), reverse=True)
        return {
            "formatVersion": "stateport.approval-index/v1",
            "identity": self.actor_id,
            "approvals": approvals[:250],
        }

    def infrastructure_adapter(self, instance_id: str) -> LocalLibvirtAdapter:
        """Resolve the one supported infrastructure adapter from the app catalog."""

        entry, root = self.source_app()._entry(instance_id)
        metadata = entry.get("metadata") if isinstance(entry, Mapping) else None
        if not isinstance(metadata, Mapping) or metadata.get("externalRepository") is not True:
            raise InfrastructureError("infrastructure_unavailable", "this application is not a registered infrastructure repository")
        if entry.get("applicationId") != "nixos-infrastructure":
            raise InfrastructureError("infrastructure_unavailable", "the registered application does not expose the local infrastructure adapter")
        return LocalLibvirtAdapter(
            root,
            instance_id=instance_id,
            state_root=self.layout.state_root / "infrastructure" / instance_id,
            product_root=self.product_root,
        )

    def infrastructure_projection(self, instance_id: str) -> dict[str, object]:
        return self.infrastructure_adapter(instance_id).inspect()

    def infrastructure_record_receipt(self, instance_id: str, run: Mapping[str, object] | None) -> None:
        receipt = run.get("receipt") if isinstance(run, Mapping) else None
        if isinstance(receipt, Mapping):
            self.activity_receipts.record_receipt(instance_id=instance_id, receipt=receipt)

    @staticmethod
    def _capability_grant_digest(value: Mapping[str, object]) -> str:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return "sha256:" + hashlib.sha256(encoded).hexdigest()

    def _experience_policy_digest(self) -> str:
        path = self.product_root / "config" / "application-experience-policy.yaml"
        return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

    def _remember_application_workspace(self, instance_id: str, binding: Mapping[str, Any]) -> None:
        """Remember isolation selection, never authority; removal cannot enable host PTY."""
        entry = self.workspace_catalog_entry(instance_id)
        owner = binding["workload"]["parameters"]["ownership"]
        marker = {"workloadId": binding["workload"]["workloadId"], "catalogIdentityDigest": owner["catalogIdentityDigest"]}
        if (entry.get("metadata") or {}).get("executionWorkspaceBinding") != marker:
            self.source_app().catalog.update(instance_id, executionWorkspaceBinding=marker)

    def create_application_workspace(self, instance_id: Any, *, source_review_digest: Any = None) -> dict[str, Any]:
        iid = self.execution_host._validate_workload_id(instance_id)
        binding = self.execution_host.application_binding(iid, operation="createWorkload")
        if binding is None:
            raise ExecutionHostProxyError("workspace_authority_missing", "An operator must provision exact application workspace authority")
        self._remember_application_workspace(iid, binding)
        return self.execution_host.create_application(iid, source_review_digest=source_review_digest)

    def workspace_catalog_entry(self, instance_id: str) -> Mapping[str, Any]:
        """Resolve a live catalog incarnation before using operator authority."""
        entry = self.source_app().catalog.get(instance_id)
        root = Path(str(entry.get("path", "")))
        identity = entry.get("filesystem")
        if entry.get("pathState") != "present" or entry.get("status") != "active" or not isinstance(identity, Mapping) or not root.is_absolute():
            raise PermissionError("application catalog entry is unavailable")
        info = root.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != (identity.get("device"), identity.get("inode")):
            raise PermissionError("application filesystem identity changed")
        return entry

    def ensure_instance_capability_grant(self, instance_id: str) -> dict[str, object]:
        """Bind effective capability policy to one catalog identity.

        Application IDs are descriptors, not authority.  The manifest is
        stored in catalog metadata and is accepted only when its instance ID,
        descriptor digest, policy digest, and self-digest still match.
        Imported instances intentionally receive no capabilities through this
        migration path.
        """

        app = self.source_app()
        entry = app.catalog.get(instance_id)
        application_id = str(entry.get("applicationId", ""))
        descriptor = self.experience_registry.get(application_id)
        if descriptor is None:
            requested: list[str] = []
            descriptor_digest = None
        else:
            requested = sorted(item.value for item in descriptor.capabilities)
            descriptor_digest = descriptor.descriptor_digest()
        mode = entry.get("adoption", {}).get("mode") if isinstance(entry.get("adoption"), Mapping) else None
        existing = entry.get("metadata", {}).get("capabilityGrant") if isinstance(entry.get("metadata"), Mapping) else None
        if isinstance(existing, Mapping) and existing.get("policyDigest") == self._experience_policy_digest() and existing.get("descriptorDigest") == descriptor_digest:
            return dict(existing)
        granted = sorted(set(requested) & set(self.experience_policy.grants_for(application_id))) if mode == "registered" else []
        body: dict[str, object] = {
            "formatVersion": "stateport.instance-capability-grant/v1",
            "instanceId": instance_id,
            "applicationId": application_id,
            "descriptorDigest": descriptor_digest,
            "requestedCapabilities": requested,
            "grantedCapabilities": granted,
            "adoptionMode": mode or "unknown",
            "policyDigest": self._experience_policy_digest(),
            "grantReason": "stateport_registered_instance" if mode == "registered" else "imported_instance_requires_explicit_review",
            "createdAt": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        }
        body["grantDigest"] = self._capability_grant_digest(body)
        app.catalog.update(instance_id, capabilityGrant=body)
        return body

    def _ensure_registered_instance_capability_grants(self) -> None:
        app = self.source_app()
        for entry in app.catalog.list():
            mode = entry.get("adoption", {}).get("mode") if isinstance(entry.get("adoption"), Mapping) else None
            metadata = entry.get("metadata") if isinstance(entry.get("metadata"), Mapping) else {}
            grant = metadata.get("capabilityGrant")
            if mode == "registered":
                application_id = str(entry.get("applicationId", ""))
                descriptor = self.experience_registry.get(application_id)
                descriptor_digest = descriptor.descriptor_digest() if descriptor is not None else None
                if (
                    not isinstance(grant, Mapping)
                    or grant.get("policyDigest") != self._experience_policy_digest()
                    or grant.get("descriptorDigest") != descriptor_digest
                ):
                    self.ensure_instance_capability_grant(str(entry.get("instanceId", "")))

    def _instance_capabilities(self, instance_id: str, application_id: str, descriptor_digest: str) -> frozenset[str]:
        try:
            entry = self.source_app().catalog.get(instance_id)
        except Exception:  # noqa: BLE001 - fail closed behind the capability boundary
            return frozenset()
        if entry.get("pathState") != "present":
            return frozenset()
        metadata = entry.get("metadata") if isinstance(entry.get("metadata"), Mapping) else {}
        grant = metadata.get("capabilityGrant") if isinstance(metadata, Mapping) else None
        if not isinstance(grant, Mapping):
            return frozenset()
        base = {key: value for key, value in grant.items() if key != "grantDigest"}
        if (
            grant.get("formatVersion") != "stateport.instance-capability-grant/v1"
            or grant.get("instanceId") != instance_id
            or grant.get("applicationId") != application_id
            or grant.get("descriptorDigest") != descriptor_digest
            or grant.get("policyDigest") != self._experience_policy_digest()
            or grant.get("grantDigest") != self._capability_grant_digest(base)
            or not isinstance(grant.get("requestedCapabilities"), list)
            or not isinstance(grant.get("grantedCapabilities"), list)
        ):
            return frozenset()
        requested = set(grant["requestedCapabilities"])
        granted = set(grant["grantedCapabilities"])
        known = {item.value for item in self.experience_registry.get(application_id).capabilities} if self.experience_registry.get(application_id) else set()
        if not granted <= requested or not granted <= known or any(not isinstance(item, str) for item in (*grant["requestedCapabilities"], *grant["grantedCapabilities"])):
            return frozenset()
        return frozenset(granted)

    def _template_upgrade_capabilities(
        self, instance_path: Path, instance_id: str
    ) -> frozenset[str]:
        """Resolve upgrade authority from the installed catalog grant."""

        try:
            entry, registered_root = self.source_app()._entry(instance_id)
            application_id = str(entry.get("applicationId", ""))
            experience = self.experience_registry.get(application_id)
            application, _identity, _profile, _source_root, _package_digest = (
                self.execution._browser_fixture_contract(application_id)
            )
            if (
                registered_root != instance_path.resolve(strict=True)
                or experience is None
                or not isinstance(application.get("lifecycleTemplate"), Mapping)
            ):
                return frozenset()
            granted = self._instance_capabilities(
                instance_id,
                application_id,
                experience.descriptor_digest(),
            )
            return frozenset((*granted, "write_state")) if granted else frozenset()
        except (AppError, OSError, RuntimeError, ValueError):
            return frozenset()

    def _template_upgrade_template_capabilities(
        self, template_path: Path
    ) -> frozenset[str]:
        """Authorize only an exact digest-addressed descriptor revision."""

        try:
            relative = template_path.relative_to(
                self.layout.data_root / "upgrade-templates"
            )
            if len(relative.parts) != 3:
                return frozenset()
            application_id, revision_id, digest_name = relative.parts
            descriptor, _identity, _profile, source_root, _package_digest = (
                self.execution._browser_fixture_contract(application_id)
            )
            lifecycle_template = descriptor.get("lifecycleTemplate")
            if not isinstance(lifecycle_template, Mapping):
                return frozenset()
            (
                _source_root,
                _revision_root,
                resolved_revision,
                _template_id,
                revision_digest,
            ) = self.execution._fixture_revision_contract(
                application_id,
                source_root,
                lifecycle_template,
                revision_id=revision_id,
            )
            if (
                resolved_revision != revision_id
                or revision_digest != f"sha256:{digest_name}"
                or not secrets.compare_digest(
                    revision_digest,
                    self.execution._fixture_tree_digest(template_path),
                )
            ):
                return frozenset()
            return frozenset({"write_state"})
        except (OSError, RuntimeError, ValueError):
            return frozenset()

    def _template_upgrade_target_binding(
        self,
        instance_id: str,
        instance_path: Path,
        template_path: Path,
        _supplied: Mapping[str, str],
    ) -> dict[str, str]:
        """Derive approval labels from the exact catalog and staged target."""

        entry, registered_root = self.source_app()._entry(instance_id)
        application_id = entry.get("applicationId")
        relative = template_path.relative_to(
            self.layout.data_root / "upgrade-templates"
        )
        if (
            not isinstance(application_id, str)
            or registered_root != instance_path.resolve(strict=True)
            or len(relative.parts) != 3
            or relative.parts[0] != application_id
            or self._template_upgrade_template_capabilities(template_path)
            != frozenset({"write_state"})
        ):
            raise ValueError("template upgrade target binding is not canonical")
        _application_id, target_revision, digest_name = relative.parts
        return {
            "applicationId": application_id,
            "targetRevision": target_revision,
            "templateDigest": f"sha256:{digest_name}",
        }

    def _template_upgrade_call(
        self, route: str, body: Mapping[str, object]
    ) -> dict[str, object]:
        response = self.template_upgrades.dispatch("POST", route, body)
        result = response.body.get("result")
        if response.status == 200 and isinstance(result, Mapping):
            return dict(result)
        error = response.body.get("error")
        code = error.get("code") if isinstance(error, Mapping) else None
        message = error.get("message") if isinstance(error, Mapping) else None
        raise TemplateUpgradeError(
            response.status,
            str(code or "template_upgrade_refused"),
            str(message or "the template upgrade was refused"),
        )

    def request_template_upgrade(
        self, instance_id: str, target_revision: str
    ) -> dict[str, object]:
        binding = self.execution.stage_fixture_upgrade_revision(instance_id, target_revision)
        instance_path = binding["instancePath"]
        template_path = binding["templatePath"]
        if not isinstance(instance_path, Path) or not isinstance(template_path, Path):
            raise TemplateUpgradeError(500, "template_upgrade_binding_invalid", "the template upgrade binding is invalid")
        target_binding = {
            "applicationId": str(binding["applicationId"]),
            "targetRevision": str(binding["targetRevision"]),
            "templateDigest": str(binding["templateDigest"]),
        }
        result = self._template_upgrade_call(
            "/v1/mutations/request",
            {
                "operation": "apply-upgrade",
                "actor": _TEMPLATE_UPGRADE_REQUESTER,
                "instancePath": instance_path.relative_to(self.layout.data_root).as_posix(),
                "templatePath": template_path.relative_to(self.layout.data_root).as_posix(),
                "reason": f"Upgrade {binding['applicationId']} to descriptor revision {binding['targetRevision']}",
                "targetBinding": target_binding,
            },
        )
        approval = result.get("approval")
        metadata = approval.get("metadata") if isinstance(approval, Mapping) else None
        verified_binding = (
            metadata.get("targetBinding") if isinstance(metadata, Mapping) else None
        )
        if not isinstance(verified_binding, Mapping):
            raise TemplateUpgradeError(
                500,
                "template_upgrade_binding_invalid",
                "the verified template upgrade binding is missing",
            )
        return {**result, "targetBinding": dict(verified_binding)}

    def _template_upgrade_request(
        self, *, instance_id: str, approval_id: str, expected_plan_digest: str
    ) -> dict[str, object]:
        listed = self._template_upgrade_call(
            "/v1/approvals/list", {"actor": self.template_upgrade_approver}
        )
        approvals = listed.get("approvals")
        request = next(
            (
                dict(item)
                for item in approvals
                if isinstance(item, Mapping) and item.get("id") == approval_id
            ),
            None,
        ) if isinstance(approvals, list) else None
        if request is None:
            raise TemplateUpgradeError(404, "approval_not_found", "the template upgrade approval was not found")
        plan_binding = request.get("metadata", {}).get("planBinding") if isinstance(request.get("metadata"), Mapping) else None
        plan_digest = plan_binding.get("planDigest") if isinstance(plan_binding, Mapping) else None
        if request.get("operation") != "apply-upgrade" or request.get("instanceId") != instance_id:
            raise TemplateUpgradeError(409, "approval_mismatch", "the template upgrade approval identity changed")
        if not isinstance(plan_digest, str) or not secrets.compare_digest(plan_digest, expected_plan_digest):
            raise TemplateUpgradeError(409, "approval_mismatch", "the template upgrade plan digest changed")
        return request

    def decide_template_upgrade(
        self,
        *,
        instance_id: str,
        approval_id: str,
        expected_plan_digest: str,
        status: str,
        reason: str = "",
    ) -> dict[str, object]:
        self._template_upgrade_request(
            instance_id=instance_id,
            approval_id=approval_id,
            expected_plan_digest=expected_plan_digest,
        )
        return self._template_upgrade_call(
            "/v1/approvals/decide",
            {
                "actor": self.template_upgrade_approver,
                "approvalId": approval_id,
                "status": status,
                "reason": reason,
            },
        )

    def apply_template_upgrade(
        self, *, instance_id: str, approval_id: str, expected_plan_digest: str
    ) -> dict[str, object]:
        approval_request = self._template_upgrade_request(
            instance_id=instance_id,
            approval_id=approval_id,
            expected_plan_digest=expected_plan_digest,
        )
        app = self.source_app()
        catalog_entry = app.catalog.get(instance_id)
        result = self._template_upgrade_call(
            "/v1/mutations/apply",
            {"actor": _TEMPLATE_UPGRADE_OPERATOR, "approvalId": approval_id},
        )
        receipt = result.get("receipt")
        if not isinstance(receipt, Mapping) and result.get("idempotent") is True:
            _entry, instance_root = self.source_app()._entry(
                instance_id,
                allow_stale_replacement=True,
            )
            receipt_path = instance_root / ".statedd" / "upgrade-receipt.yaml"
            if (
                receipt_path.is_symlink()
                or not receipt_path.is_file()
                or receipt_path.stat().st_size > 256 * 1024
            ):
                raise TemplateUpgradeError(500, "upgrade_receipt_missing", "the applied upgrade receipt is unavailable")
            loaded = yaml.safe_load(receipt_path.read_text(encoding="utf-8")) or {}
            receipt = loaded if isinstance(loaded, Mapping) else None
        if not isinstance(receipt, Mapping):
            raise TemplateUpgradeError(500, "upgrade_receipt_missing", "the applied upgrade returned no receipt")
        receipt_plan_digest = receipt.get("planDigest")
        if not isinstance(receipt_plan_digest, str) or not secrets.compare_digest(
            receipt_plan_digest, expected_plan_digest
        ):
            raise TemplateUpgradeError(500, "upgrade_receipt_invalid", "the applied upgrade receipt changed")
        applied_at = receipt.get("appliedAt")
        if not isinstance(applied_at, str):
            raise TemplateUpgradeError(500, "upgrade_receipt_invalid", "the applied upgrade receipt is invalid")
        current = receipt.get("current")
        root_identity = current.get("rootIdentity") if isinstance(current, Mapping) else None
        if (
            not isinstance(root_identity, Mapping)
            or set(root_identity) != {"path", "device", "inode"}
            or root_identity.get("path") != catalog_entry.get("path")
        ):
            raise TemplateUpgradeError(500, "upgrade_receipt_invalid", "the applied upgrade root identity is invalid")
        try:
            rebound = app.catalog.rebind_replaced_directory(
                catalog_entry,
                {
                    "device": root_identity["device"],
                    "inode": root_identity["inode"],
                    "kind": "directory",
                },
            )
        except AppError as exc:
            raise TemplateUpgradeError(409, "catalog_rebind_refused", "the upgraded catalog identity could not be rebound") from exc
        if rebound.get("pathState") != "present":
            raise TemplateUpgradeError(500, "catalog_rebind_invalid", "the upgraded catalog identity is unavailable")
        operational_receipt = {
            "receiptId": f"template-upgrade:{approval_id}",
            "receiptType": str(receipt.get("formatVersion") or "statedd.upgrade-receipt/v1"),
            "action": "template_upgrade",
            "status": str(receipt.get("status") or "applied"),
            "createdAt": applied_at,
            "sourceKind": "statedd_lifecycle",
            "relatedApprovalId": f"template_upgrade:{approval_id}",
            "authority": {
                "requestedBy": approval_request.get("actor"),
                "approvedBy": (
                    approval_request.get("metadata", {}).get("decision", {}).get("actor")
                    if isinstance(approval_request.get("metadata"), Mapping)
                    and isinstance(approval_request.get("metadata", {}).get("decision"), Mapping)
                    else None
                ),
                "appliedBy": _TEMPLATE_UPGRADE_OPERATOR,
            },
            "authorityModel": "authenticated_session_with_internal_service_roles/v1",
            "authorityBindings": {
                "requestedBy": {
                    "id": _TEMPLATE_UPGRADE_REQUESTER,
                    "principalType": "internal_service_role",
                },
                "approvedBy": {
                    "id": self.template_upgrade_approver,
                    "principalType": "authenticated_operator_session",
                    "sessionActorId": self.actor_id,
                    "sessionActorRole": self.actor_role,
                },
                "appliedBy": {
                    "id": _TEMPLATE_UPGRADE_OPERATOR,
                    "principalType": "internal_service_role",
                },
            },
            "upgrade": dict(receipt),
        }
        self.activity_receipts.record_receipt(
            instance_id=instance_id, receipt=operational_receipt
        )
        return {
            **result,
            "receipt": dict(receipt),
            "activityReceiptId": operational_receipt["receiptId"],
            "authority": dict(operational_receipt["authority"]),
            "authorityModel": operational_receipt["authorityModel"],
            "authorityBindings": dict(operational_receipt["authorityBindings"]),
        }

    def pending_template_upgrade_approvals(self) -> list[dict[str, object]]:
        result = self._template_upgrade_call(
            "/v1/approvals/list", {"actor": self.template_upgrade_approver}
        )
        approvals = result.get("approvals")
        return [
            dict(item)
            for item in approvals
            if isinstance(item, Mapping)
            and item.get("operation") == "apply-upgrade"
            and item.get("status") == "pending"
        ] if isinstance(approvals, list) else []

    def goal_execution_binding(self, instance_id: str) -> tuple[str, Path]:
        self.require_actor_permission("application.cto.use")
        app = self.source_app()
        try:
            entry = app.catalog.get(instance_id)
        except Exception as exc:  # noqa: BLE001 - catalog failures stay behind the local boundary
            raise PermissionError("catalog identity is unavailable") from exc
        filesystem = entry.get("filesystem")
        if (
            entry.get("pathState") != "present"
            or entry.get("status") != "active"
            or not isinstance(filesystem, dict)
            or set(filesystem) != {"device", "inode", "kind"}
            or filesystem.get("kind") != "directory"
        ):
            raise PermissionError("cataloged project path is unavailable")
        application_id = str(entry.get("applicationId", ""))
        experience = self.application_experience(application_id, instance_id)
        statuses = {
            str(item.get("id")): str(item.get("status"))
            for item in (experience or {}).get("capabilities", [])
            if isinstance(item, dict)
        }
        if not all(statuses.get(item) in {"available", "degraded"} for item in ("goal_execution", "cto_orchestration")):
            raise PermissionError("application does not have an effective CTO capability")
        root = Path(str(entry.get("path", "")))
        try:
            metadata = os.lstat(root)
        except OSError as exc:
            raise PermissionError("cataloged project path is unavailable") from exc
        if (
            not root.is_absolute()
            or stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino) != (filesystem.get("device"), filesystem.get("inode"))
        ):
            raise PermissionError("cataloged project filesystem identity changed")
        return application_id, root.resolve(strict=True)

    def goal_execution_view(self, instance_id: str) -> dict[str, object]:
        _application_id, root = self.goal_execution_binding(instance_id)
        view = self.goal_execution.inspect(instance_id)
        identity = self.goal_execution.current_identity(root)
        stop = view.get("stop")
        if (
            identity.get("repositoryClean") is False
            and view.get("state") == "stopped"
            and isinstance(stop, Mapping)
            and stop.get("code") == "base_drift"
        ):
            # Preserve the terminal lifecycle reason while currentIdentity
            # continues to describe the repository observed now.  The exact
            # approved basis remains separately bound in ``slice``.
            identity = {**identity, "reasonCode": "base_drift"}
        return {
            **view,
            "currentIdentity": identity,
            # Typed backend availability lets the frontend show an honest
            # unavailable state instead of active orchestration that the
            # production backend would always refuse.
            "backendAvailability": self.goal_execution.backend_availability(),
        }

    @staticmethod
    def _operational_receipt_timestamp(value: object, label: str) -> str:
        if not isinstance(value, str) or len(value) > 64 or not value.endswith("Z"):
            raise ActivityReceiptError(f"{label} is invalid")
        try:
            parsed = datetime.fromisoformat(value[:-1] + "+00:00")
        except ValueError as exc:
            raise ActivityReceiptError(f"{label} is invalid") from exc
        if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
            raise ActivityReceiptError(f"{label} is invalid")
        return value

    @staticmethod
    def _goal_contract_digest(value: Mapping[str, object]) -> str:
        try:
            encoded = json.dumps(
                dict(value),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ActivityReceiptError("goal execution receipt evidence is not JSON-safe") from exc
        return "sha256:" + hashlib.sha256(encoded).hexdigest()

    def record_goal_execution_receipt(
        self,
        *,
        instance_id: str,
        application_id: str,
        closed_projection: Mapping[str, object],
    ) -> None:
        """Index one exact coordinator-owned noncanonical closure receipt."""

        receipt = closed_projection.get("receipt")
        if not isinstance(receipt, Mapping) or set(receipt) != {
            "formatVersion",
            "receiptId",
            "applicationId",
            "instanceId",
            "itemId",
            "approvalDigest",
            "executionResultDigest",
            "reviewDigest",
            "closureDecisionDigest",
            "routingDeviationRetained",
            "nextItemStatus",
            "canonicalStateEffect",
        }:
            raise ActivityReceiptError("goal execution closure receipt shape is invalid")
        if (
            closed_projection.get("formatVersion") != "stateport.goal-execution-view/v1"
            or closed_projection.get("state") != "closed"
            or closed_projection.get("instanceId") != instance_id
            or closed_projection.get("applicationId") != application_id
            or closed_projection.get("canonicalStateEffect") != "none"
            or closed_projection.get("nextItemAutoStart") is not False
            or receipt.get("formatVersion") != "stateport.goal-execution-receipt/v1"
            or receipt.get("instanceId") != instance_id
            or receipt.get("applicationId") != application_id
            or receipt.get("canonicalStateEffect") != "none"
            or receipt.get("nextItemStatus") != "stopped_unapproved"
            or not isinstance(receipt.get("routingDeviationRetained"), bool)
        ):
            raise ActivityReceiptError("goal execution closure receipt authority is invalid")
        receipt_id = receipt.get("receiptId")
        item_id = receipt.get("itemId")
        recorded_at = self._operational_receipt_timestamp(
            closed_projection.get("recordedAt"),
            "goal execution receipt timestamp",
        )
        # The durable receipt retains the exact backend identity behind the
        # closure: a fabricated provider execution can never be recorded as
        # real, and a test-only backend stays labelled as one.
        backend_id = closed_projection.get("backendId")
        provider_execution = closed_projection.get("providerExecution")
        if (
            not isinstance(provider_execution, bool)
            or (backend_id is not None and not isinstance(backend_id, str))
            or (provider_execution is True and backend_id in (None, "fake"))
        ):
            raise ActivityReceiptError("goal execution closure receipt backend identity is invalid")
        if not all(isinstance(value, str) and value for value in (receipt_id, item_id)):
            raise ActivityReceiptError("goal execution closure receipt identity is invalid")
        for field in (
            "approvalDigest",
            "executionResultDigest",
            "reviewDigest",
            "closureDecisionDigest",
        ):
            if not isinstance(receipt.get(field), str) or not re.fullmatch(
                r"sha256:[0-9a-f]{64}",
                str(receipt.get(field)),
            ):
                raise ActivityReceiptError("goal execution closure receipt digest is invalid")
        approval = closed_projection.get("approval")
        execution_result = closed_projection.get("executionResult")
        review = closed_projection.get("review")
        closure = closed_projection.get("closure")
        selected_item = closed_projection.get("selectedItem")
        delegation = closed_projection.get("delegation")
        if not all(
            isinstance(value, Mapping)
            for value in (approval, execution_result, review, closure, selected_item, delegation)
        ):
            raise ActivityReceiptError("goal execution closure evidence is incomplete")
        assert isinstance(approval, Mapping)
        assert isinstance(execution_result, Mapping)
        assert isinstance(review, Mapping)
        assert isinstance(closure, Mapping)
        assert isinstance(selected_item, Mapping)
        assert isinstance(delegation, Mapping)
        routing = delegation.get("routingDeviation")
        if (
            receipt["approvalDigest"] != self._goal_contract_digest(approval)
            or receipt["executionResultDigest"] != execution_result.get("executionResultDigest")
            or receipt["reviewDigest"] != review.get("reviewDigest")
            or receipt["closureDecisionDigest"] != self._goal_contract_digest(closure)
            or receipt["itemId"] != selected_item.get("itemId")
            or not isinstance(routing, Mapping)
            or receipt["routingDeviationRetained"] != routing.get("occurred")
        ):
            raise ActivityReceiptError("goal execution closure receipt digest binding is invalid")
        self.activity_receipts.record_receipt(
            instance_id=instance_id,
            receipt={
                "receiptId": receipt_id,
                "receiptType": receipt["formatVersion"],
                "action": "goal_execution.close",
                "status": "completed_without_change",
                "createdAt": recorded_at,
                "sourceKind": "goal_execution",
                "instanceId": instance_id,
                "applicationId": application_id,
                "backendId": backend_id,
                "providerExecution": provider_execution,
                "goalExecutionReceipt": dict(receipt),
            },
        )

    def application_experience(self, application_id: str, instance_id: str | None = None) -> dict[str, object] | None:
        descriptor = self.experience_registry.get(application_id)
        if descriptor is None:
            return None
        policy = self.experience_policy
        grants = policy.grants_for(descriptor.application_id)
        if instance_id is not None:
            grants = self._instance_capabilities(instance_id, application_id, descriptor.descriptor_digest())
        resolved = self.experience_registry.resolve(
            application_id,
            instance_grants=grants,
            operator_permits=policy.operator_permits,
            runtime_capabilities=policy.runtime_capabilities,
            actor_permissions=policy.permissions_for(self.actor_role),
        )
        if resolved is not None and descriptor.application_id == "studydd":
            return {
                **resolved,
                "sourceStatus": self.source_app().canonical_source_registry()[0],
            }
        return resolved

    def application_experiences(self) -> list[dict[str, object]]:
        values: list[dict[str, object]] = []
        for descriptor in self.experience_registry.list():
            resolved = self.application_experience(str(descriptor["applicationId"]))
            if resolved is not None:
                values.append(resolved)
        return values

    def application_catalog(self) -> list[dict[str, object]]:
        """Project safe install choices without exposing package file paths."""

        results: list[dict[str, object]] = []
        actor_permissions = self.experience_policy.permissions_for(self.actor_role)
        canonical_source = self.source_app().canonical_source_registry()[0]
        for descriptor in self.execution.applications():
            if descriptor.get("catalogVisible") is False:
                continue
            application_id = str(descriptor.get("applicationId", ""))
            eligibility = self.execution.browser_fixture_install_eligibility(application_id)
            application_identity = self.execution.application_identity(application_id)
            if eligibility["eligible"]:
                application_identity = {
                    **application_identity,
                    "packageDigest": eligibility["packageDigest"],
                }
            experience = self.application_experience(application_id)
            experience_identity = experience.get("descriptorIdentity") if experience is not None else None
            reasons = list(eligibility["reasons"])
            if experience_identity is None:
                reasons.append("application_experience_unavailable")
            if "application.install.fixture" not in actor_permissions:
                reasons.append("actor_permission_missing")
            source_status = canonical_source if application_id == "studydd" else None
            if source_status is not None and source_status.get("installable") is not True:
                reasons.append("canonical_source_unresolved")
            requested_capabilities = sorted(
                str(item) for item in (experience or {}).get("installProjection", {}).get("requestedCapabilities", [])
            )
            entry: dict[str, object] = {
                "formatVersion": "stateport.application-catalog-entry/v1",
                "applicationId": application_id,
                "displayName": str(descriptor.get("displayName", application_id)),
                "description": str(descriptor.get("description", "")),
                "privacyClassification": str(descriptor.get("privacyClassification", "unknown")),
                "productionEligible": descriptor.get("productionEligible") is True,
                "applicationIdentity": application_identity,
                "experienceIdentity": experience_identity,
                "install": {
                    "status": "available" if not reasons else "unavailable",
                    "reasons": reasons,
                    "confirmationRequired": True,
                    "sourceKind": "bundled_public_fixture" if not reasons else "not_installable_from_browser",
                    "requestedCapabilities": requested_capabilities,
                    "networkPolicy": eligibility["networkPolicy"],
                    "receiptFormat": "stateport.application-install-receipt/v1",
                },
            }
            if source_status is not None:
                entry["sourceStatus"] = source_status
            results.append(entry)
        return results

    def conversation_for_instance(self, instance_id: str):
        from stateport_conversation import ConversationConflictError

        current = self._conversation_scopes.get(instance_id)
        if current is not None:
            conversation_id, participant_id, binding_id = current
            return (
                self.conversations.thread(participant_id=participant_id, conversation_id=conversation_id),
                participant_id,
                self.conversations.binding(participant_id=participant_id, binding_id=binding_id),
            )
        app = self.source_app()
        entry = app.catalog.get(instance_id)
        application_id = str(entry.get("applicationId", ""))
        participant_id = f"local-operator:{instance_id}"
        participant = self._participant_contract.from_dict(
            {
                "formatVersion": self._participant_contract.FORMAT,
                "participantId": participant_id,
                "actorId": "local-operator",
                "displayName": "Local operator",
                "kind": "human",
                "applicationIds": [application_id],
                "instanceIds": [instance_id],
                "permissions": [
                    "conversation.create", "conversation.bind", "conversation.read", "conversation.send",
                    "conversation.respond", "conversation.deliver", "conversation.propose", "conversation.delete",
                ],
            }
        )
        try:
            self.conversations.register_participant(participant)
        except ConversationConflictError:
            # A store created before transcript clear existed may have the
            # fixed operator participant without the new service permission.
            # Upgrade only that exact service-owned identity.
            self.conversations.ensure_service_participant_permission(
                participant_id=participant_id,
                permission="conversation.delete",
            )
        self.conversations.ensure_service_participant_permission(
            participant_id=participant_id,
            permission="conversation.delete",
        )
        thread = self.conversations.create_thread(
            participant_id=participant_id,
            application_id=application_id,
            instance_id=instance_id,
            title=f"{entry.get('name', instance_id)} conversation",
            delivery_policy="mirror_to_all",
        )
        binding = self.conversations.bind_channel(
            participant_id=participant_id,
            conversation_id=thread.conversation_id,
            channel="web",
            external_identity_digest=self._conversation_digest({"actor": "local-operator", "instanceId": instance_id}),
            external_conversation_digest=self._conversation_digest({"channel": "web", "instanceId": instance_id}),
        )
        self._conversation_scopes[instance_id] = (thread.conversation_id, participant_id, binding.binding_id)
        self._maybe_attach_telegram(thread.conversation_id, participant_id, instance_id=instance_id)
        return thread, participant_id, binding

    def _construct_telegram_launcher(self, layout: LocalLayout) -> object | None:
        """Load the sanctioned launcher, or None if the package is unavailable."""

        try:
            from stateport_telegram_adapter.launcher import TelegramLiveLauncher
        except ImportError:
            return None
        return TelegramLiveLauncher(
            config_root=layout.config_root,
            runtime_root=layout.runtime_root,
            conversation_service=self.conversations,
            auto_reply=os.environ.get("STATEPORT_TELEGRAM_AUTO_REPLY") == "1",
        )

    def _eager_telegram_setup(self) -> None:
        """Eagerly create the configured Telegram conversation at startup."""

        launcher = self.telegram_launcher
        if launcher is None or not launcher.enabled:
            return
        configured_instance = launcher.instance_id
        if not configured_instance:
            self.log.write("telegram eager setup: no configured instance\n")
            self.log.flush()
            return
        try:
            self.conversation_for_instance(configured_instance)
        except Exception as exc:  # noqa: BLE001 - telegram wiring is non-critical
            # Never write provider exception text to the plaintext log: it can
            # embed URLs or tokens. The class name is sufficient to diagnose.
            self.log.write(f"telegram eager setup failed for {configured_instance}: {type(exc).__name__}\n")
            self.log.flush()

    def _maybe_attach_telegram(self, conversation_id: str, participant_id: str, *, instance_id: str | None = None) -> None:
        """Attach the exclusive Telegram binding to the configured conversation.

        The bot is exclusive to the single allowlisted operator user id from
        ``operator.yaml`` and the configured application and instance.  Only
        the exact configured conversation receives the Telegram binding.
        Telegram wiring must never regress conversation availability.
        """

        launcher = self.telegram_launcher
        if launcher is None or not launcher.enabled or launcher.attached:
            return
        configured_instance = launcher.instance_id
        if configured_instance is not None and instance_id is not None and configured_instance != instance_id:
            return
        try:
            launcher.attach(participant_id=participant_id, conversation_id=conversation_id)
            launcher.start()
        except Exception:  # noqa: BLE001 - telegram wiring is non-critical
            reason = launcher.status().reason
            self.log.write(f"telegram wiring failed; reason={reason}\n")
            self.log.flush()

    def conversation_presentation(self, instance_id: str, *, expected_conversation_id: str | None = None) -> dict[str, object]:
        thread, participant_id, _binding = self.conversation_for_instance(instance_id)
        if expected_conversation_id is not None and expected_conversation_id != thread.conversation_id:
            raise ValueError("conversation identity changed during the request")
        try:
            inspected = self.source_app().inspect(instance_id)
        except ValueError:
            # Conversation continuity is operational and may remain available
            # while an instance needs repair. Never invent approval or receipt
            # references when the canonical inspection cannot be established.
            inspected = {}
        approval_references = tuple(
            str(item.get("approvalId") or item.get("id"))
            for item in inspected.get("approvals", [])
            if isinstance(item, dict) and (item.get("approvalId") or item.get("id"))
        )
        receipt_references = tuple(
            str(item.get("receiptId") or item.get("runId"))
            for item in inspected.get("runs", [])
            if isinstance(item, dict) and (item.get("receiptId") or item.get("runId"))
        )
        return self.conversations.presentation(
            participant_id=participant_id,
            conversation_id=thread.conversation_id,
            pending_approval_references=approval_references,
            run_receipt_references=receipt_references,
        )

    def conversation_retention(self, instance_id: str) -> dict[str, object]:
        thread, participant_id, _binding = self.conversation_for_instance(instance_id)
        return self.conversations.retention_status(
            participant_id=participant_id,
            conversation_id=thread.conversation_id,
        ).to_dict()

    def privacy_purge(self) -> dict[str, object]:
        """Purge soft-deleted blobs and expired attachments."""
        deleted_purge = self.attachments.purge_deleted()
        expired_purge = self.attachments.purge_expired()
        return {
            "formatVersion": "stateport.privacy-purge/v1",
            "deletedBlobPurge": deleted_purge,
            "expiredAttachmentPurge": expired_purge,
        }

    def privacy_export(self) -> dict[str, object]:
        """Export all user data across conversations and attachments."""
        app = self.source_app()
        instances = app.instance_list()
        conversations: list[dict[str, object]] = []
        for entry in instances:
            instance_id = entry.get("instanceId")
            if not isinstance(instance_id, str):
                continue
            try:
                thread, participant_id, _binding = self.conversation_for_instance(instance_id)
                export, _receipt = self.conversations.export_transcript(
                    participant_id=participant_id,
                    conversation_id=thread.conversation_id,
                    request_id=f"privacy-export-{instance_id}",
                )
                conversations.append(export.to_dict())
            except Exception:
                continue
        attachments = self.attachments.export_all()
        return {
            "formatVersion": "stateport.privacy-export/v1",
            "exportedAt": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "conversations": conversations,
            "attachments": attachments,
        }

    def conversation_export(
        self,
        instance_id: str,
        *,
        expected_conversation_id: str,
        request_id: str,
    ) -> dict[str, object]:
        thread, participant_id, _binding = self.conversation_for_instance(instance_id)
        if expected_conversation_id != thread.conversation_id:
            raise ValueError("conversation identity changed during the request")
        export, receipt = self.conversations.export_transcript(
            participant_id=participant_id,
            conversation_id=thread.conversation_id,
            request_id=request_id,
        )
        receipt_value = receipt.to_dict()
        self._record_conversation_lifecycle_receipt(instance_id, receipt_value)
        return {"export": export.to_dict(), "receipt": receipt_value}

    def conversation_clear(
        self,
        instance_id: str,
        *,
        expected_conversation_id: str,
        request_id: str,
    ) -> dict[str, object]:
        thread, participant_id, _binding = self.conversation_for_instance(instance_id)
        if expected_conversation_id != thread.conversation_id:
            raise ValueError("conversation identity changed during the request")
        receipt = self.conversations.clear_transcript(
            participant_id=participant_id,
            conversation_id=thread.conversation_id,
            request_id=request_id,
        )
        receipt_value = receipt.to_dict()
        self._record_conversation_lifecycle_receipt(instance_id, receipt_value)
        return {"receipt": receipt_value, "canonicalStateEffect": "none"}

    def _record_conversation_lifecycle_receipt(
        self,
        instance_id: str,
        receipt: Mapping[str, object],
    ) -> None:
        """Index an exact conversation-service receipt without replacing it.

        Transcript export and clear are operational, noncanonical lifecycle
        actions.  The conversation service owns their durable exact receipt;
        the activity store receives only a bounded projection wrapper so the
        application-scoped receipt index can discover that evidence.
        """

        if (
            receipt.get("formatVersion") != "stateport.transcript-lifecycle-receipt/v1"
            or receipt.get("instanceId") != instance_id
            or receipt.get("operation") not in {"export", "clear"}
            or receipt.get("authority") != "operational_noncanonical"
            or receipt.get("canonicalStateEffect") != "none"
            or receipt.get("threadIdentity") != "preserved"
            or receipt.get("bindingPolicy") != "preserved"
        ):
            raise ActivityReceiptError("conversation lifecycle receipt authority is invalid")
        receipt_id = receipt.get("receiptId")
        occurred_at = receipt.get("occurredAt")
        conversation_id = receipt.get("conversationId")
        application_id = receipt.get("applicationId")
        operation = receipt.get("operation")
        if not all(
            isinstance(value, str) and value
            for value in (
                receipt_id,
                occurred_at,
                conversation_id,
                application_id,
                operation,
            )
        ):
            raise ActivityReceiptError("conversation lifecycle receipt identity is invalid")
        projection = {
            "receiptId": receipt_id,
            "receiptType": receipt["formatVersion"],
            "action": f"conversation.{operation}",
            "status": "completed_without_change",
            "createdAt": occurred_at,
            "sourceKind": "conversation_lifecycle",
            "instanceId": instance_id,
            "applicationId": application_id,
            "relatedConversationId": conversation_id,
            "canonicalStateEffect": "none",
            "lifecycleReceipt": dict(receipt),
        }
        self.activity_receipts.record_receipt(
            instance_id=instance_id,
            receipt=projection,
        )

    def current_context_continuity(self, instance_id: str, instance_root: Path) -> tuple[ContinuityState, TokenUsage]:
        """Compile bounded operational continuity from the shared application conversation."""

        presentation = self.conversation_presentation(instance_id)
        app = self.source_app()
        try:
            inspected = app.inspect(instance_id)
        except ValueError:
            entry = app.catalog.get(instance_id)
            inspected = {
                "health": "unavailable",
                "approvals": [],
                "runs": [],
                "source": entry.get("observedSource", {}),
            }
        git = self.context_lifecycle.git_identity(instance_root)
        messages = [item for item in presentation.get("messages", []) if isinstance(item, dict)]
        approvals = [item for item in inspected.get("approvals", []) if isinstance(item, dict)][:32]
        runs = [item for item in inspected.get("runs", []) if isinstance(item, dict)][:32]
        signature_value = {
            "conversationId": presentation["thread"]["conversationId"],
            "messages": [
                {
                    "messageId": item.get("messageId"),
                    "sequence": item.get("sequence"),
                    "kind": item.get("kind"),
                    "bodyDigest": context_digest({"body": item.get("body", "")}),
                }
                for item in messages
            ],
            "approvals": approvals,
            "runs": runs,
            "git": git,
        }
        signature = context_digest(signature_value)
        cached = self._context_continuities.get(instance_id)
        now = datetime.now(timezone.utc)
        if cached is not None and secrets.compare_digest(cached[0], signature):
            fresh_until = datetime.fromisoformat(
                str(cached[1].to_dict()["contextManifest"]["freshUntil"]).replace("Z", "+00:00")
            )
            if now < fresh_until:
                return cached[1], cached[2]

        user_messages = [item for item in messages if item.get("kind") == "user_message"]
        if not user_messages:
            raise ContextLifecycleError("conversation_active_task_not_available")
        latest = user_messages[-1].get("body")
        if not isinstance(latest, str) or not latest.strip():
            raise ContextLifecycleError("conversation_active_task_not_available")
        active_task = latest.strip()[:4096]
        approval_references = [
            str(item.get("approvalId") or item.get("id"))
            for item in approvals
            if item.get("approvalId") or item.get("id")
        ]
        completed = [
            f"Run {str(item.get('runId'))[:128]} reached {str(item.get('status', 'unknown'))[:64]}."
            for item in runs
            if item.get("runId") and item.get("status") in {"applied", "completed", "closed"}
        ]
        pending = [f"Approval {value[:256]} remains pending." for value in approval_references]
        receipt_digests = [
            context_digest({"receiptReference": str(item.get("receiptId") or item.get("runId"))})
            for item in runs
            if item.get("receiptId") or item.get("runId")
        ]
        source = inspected.get("source", {}) if isinstance(inspected.get("source"), dict) else {}
        source_digest = source.get("manifestDigest")
        state_references = []
        if isinstance(source_digest, str) and len(source_digest) == 71 and source_digest.startswith("sha256:"):
            state_references.append({"id": "application.source", "digest": source_digest, "authority": "external"})
        compiled_at = now.replace(microsecond=0)
        fresh_until = compiled_at + timedelta(minutes=30)
        runtime_digest = context_digest({
            "applicationId": presentation["applicationBinding"]["applicationId"],
            "actorRole": self.actor_role,
            "channel": "web",
        })
        manifest_value = {
            "conversationSignature": signature,
            "messageCount": len(messages),
            "git": git,
            "applicationId": presentation["applicationBinding"]["applicationId"],
        }
        manifest_digest = context_digest(manifest_value)
        suffix = signature.removeprefix("sha256:")[:24]
        workstream_suffix = context_digest({
            "applicationId": presentation["applicationBinding"]["applicationId"],
            "instanceId": instance_id,
            "conversationId": presentation["thread"]["conversationId"],
        }).removeprefix("sha256:")[:24]
        continuity = ContinuityState.from_dict({
            "formatVersion": "stateport.context-continuity/v1",
            "conversationId": presentation["thread"]["conversationId"],
            "workstreamId": f"workstream.{workstream_suffix}",
            "instanceId": instance_id,
            "runtimeProfile": {"id": "runtime.stateport-local-web", "digest": runtime_digest},
            "baseSha": git["baseSha"],
            "contextManifest": {
                "contextId": f"context.{suffix}",
                "digest": manifest_digest,
                "compiledAt": compiled_at.isoformat().replace("+00:00", "Z"),
                "freshUntil": fresh_until.isoformat().replace("+00:00", "Z"),
                "provenanceDigest": signature,
            },
            "activeTask": active_task,
            "requirements": [
                "Keep the shared conversation operational and noncanonical.",
                "Preserve exact application and Git identity across a fresh provider session.",
            ],
            "completedWork": completed,
            "pendingWork": pending,
            "decisions": ["Use one logical application conversation across bound channels."],
            "approvals": approval_references,
            "unresolvedRisks": ["Provider token accounting is unavailable; StatePort reports an estimate only."],
            "exactGitIdentity": git,
            "acceptanceCriteria": ["Compression or handoff preserves the active task and exact Git identity without mutating canonical state."],
            "validationState": [f"Application health is {str(inspected.get('health', 'unavailable'))[:64]}."],
            "relevantStateReferences": state_references,
            "recentReceipts": receipt_digests,
            "nextAction": "Continue the active application task in the same logical conversation.",
        })
        estimated_tokens = max(1, sum(len(str(item.get("body", ""))) for item in messages) // 4) if messages else 0
        usage = TokenUsage(estimated_tokens, "estimated", "stateport_estimator")
        self._context_continuities[instance_id] = (signature, continuity, usage)
        return continuity, usage

    def context_lifecycle_view(self, instance_id: str, instance_root: Path) -> dict[str, object]:
        try:
            continuity, usage = self.current_context_continuity(instance_id, instance_root)
        except ContextLifecycleError:
            return self.context_lifecycle.inspect(instance_id, instance_root)
        return self.context_lifecycle.inspect(instance_id, instance_root, continuity=continuity, usage=usage)

    def current_context_lifecycle_request(
        self,
        instance_id: str,
        instance_root: Path,
        binding: dict[str, object],
    ) -> dict[str, object]:
        required = {"expectedInstanceId", "expectedBaseSha", "expectedPolicyDigest", "expectedContinuityDigest"}
        if set(binding) != required or binding.get("expectedInstanceId") != instance_id:
            raise ContextLifecycleError("invalid_context_lifecycle_binding")
        continuity, usage = self.current_context_continuity(instance_id, instance_root)
        policy_digest = self.context_lifecycle.effective_policy(instance_id).to_dict()["effectivePolicyDigest"]
        expected = (
            secrets.compare_digest(str(binding.get("expectedBaseSha", "")), continuity.to_dict()["baseSha"]),
            secrets.compare_digest(str(binding.get("expectedPolicyDigest", "")), str(policy_digest)),
            secrets.compare_digest(str(binding.get("expectedContinuityDigest", "")), continuity.digest),
        )
        if not all(expected):
            raise ContextLifecycleError("context_lifecycle_binding_changed")
        return {
            "expectedInstanceId": instance_id,
            "expectedBaseSha": continuity.to_dict()["baseSha"],
            "expectedPolicyDigest": policy_digest,
            "actorId": self.actor_id,
            "trigger": "manual",
            "usage": usage.to_dict(),
            "continuity": continuity.to_dict(),
        }

    def _drop_terminal_broker(self, instance_id: str) -> None:
        cached = self.terminal_brokers.pop(instance_id, None)
        if cached is not None:
            cached[1].close()

    def _terminal_binding_locked(self, instance_id: str, *, workspace_only: bool = False) -> tuple[str, object, object, Path, str, object]:
        from stateport_terminal_broker import (
            AuthenticatedTerminalGateway,
            TerminalCapabilities,
            TerminalConnectionProfile,
            TerminalSessionBroker,
            TerminalTarget,
        )

        if workspace_only:
            if self.actor_role != "platform_operator":
                self._drop_terminal_broker(instance_id)
                raise PermissionError("platform operator authorization is required")
            self.require_actor_permission("platform.authority.mutate")
        if "application.terminal.use" not in self.experience_policy.permissions_for(self.actor_role):
            self._drop_terminal_broker(instance_id)
            raise PermissionError("actor is not permitted to use application terminals")

        # Authenticate untrusted workspace transport before catalog/root reads,
        # durable isolation markers, target/session creation or PTY effects.
        try:
            application_workspace = self.execution_host.application_client(instance_id)
            if workspace_only and application_workspace is not None and self.execution_host._bindings_format == "stateport.application-workspace-bindings/v2" and "status" not in application_workspace[0]["grant"]["operations"]:
                raise ExecutionHostProxyError("workspace_operation_not_granted", "Workspace status permission is required")
        except ExecutionHostProxyError as exc:
            self._drop_terminal_broker(instance_id)
            raise PermissionError("application workspace authority is unavailable; operator approval is required") from exc

        app = self.source_app()
        try:
            entry = app.catalog.get(instance_id)
        except Exception as exc:  # noqa: BLE001 - catalog internals stay behind the local service
            self._drop_terminal_broker(instance_id)
            raise PermissionError("catalog identity is unavailable") from exc
        filesystem = entry.get("filesystem")
        if (
            entry.get("pathState") != "present"
            or entry.get("status") != "active"
            or not isinstance(filesystem, dict)
            or set(filesystem) != {"device", "inode", "kind"}
            or filesystem.get("kind") != "directory"
            or any(
                isinstance(filesystem.get(key), bool)
                or not isinstance(filesystem.get(key), int)
                or filesystem.get(key) < 0
                for key in ("device", "inode")
            )
        ):
            self._drop_terminal_broker(instance_id)
            raise PermissionError("cataloged project path is not present with a verified identity")
        application_id = str(entry.get("applicationId", ""))
        if workspace_only:
            if self.actor_role != "platform_operator":
                self._drop_terminal_broker(instance_id)
                raise PermissionError("platform operator authorization is required")
            self.require_actor_permission("platform.authority.mutate")
        else:
            experience = self.application_experience(application_id, instance_id)
            if experience is None:
                self._drop_terminal_broker(instance_id)
                raise PermissionError("application experience is unavailable")
            statuses = {
                str(item.get("id")): str(item.get("status"))
                for item in experience.get("capabilities", [])
                if isinstance(item, dict)
            }
            if not all(statuses.get(item) in {"available", "degraded"} for item in ("workbench", "terminal")):
                self._drop_terminal_broker(instance_id)
                raise PermissionError("application does not have an effective terminal Workbench")
        if "application.terminal.use" not in self.experience_policy.permissions_for(self.actor_role):
            self._drop_terminal_broker(instance_id)
            raise PermissionError("actor is not permitted to use application terminals")
        root = Path(str(entry.get("path", "")))
        if not root.is_absolute():
            self._drop_terminal_broker(instance_id)
            raise PermissionError("cataloged project path must be absolute")
        try:
            root_info = os.lstat(root)
        except OSError as exc:
            self._drop_terminal_broker(instance_id)
            raise PermissionError("cataloged project path is unavailable") from exc
        expected_root_identity = (filesystem["device"], filesystem["inode"])
        if (
            not stat.S_ISDIR(root_info.st_mode)
            or stat.S_ISLNK(root_info.st_mode)
            or (root_info.st_dev, root_info.st_ino) != expected_root_identity
        ):
            self._drop_terminal_broker(instance_id)
            raise PermissionError("cataloged project filesystem identity changed")
        incarnation = ""
        if workspace_only:
            if application_workspace is None:
                self._drop_terminal_broker(instance_id)
                raise PermissionError("an exact application workspace binding is required")
            binding, execution_client = application_workspace
            try:
                observed = execution_client.status(binding["workload"]["workloadId"])["result"]
                owner = binding["workload"]["parameters"]["ownership"]
                expected_owner = {"grantId": binding["grantId"], "applicationId": None, "runId": None, **owner}
                incarnation = observed.get("containerIdentityDigest", "")
                if observed.get("workloadId") != binding["workload"]["workloadId"] or observed.get("kind") != "workspace" or observed.get("state") != "running" or observed.get("engineStatus") != "running" or observed.get("ownership") != expected_owner or not isinstance(incarnation, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", incarnation):
                    raise ValueError("workspace must be running with exact owner and container identity")
            except Exception as exc:
                self._drop_terminal_broker(instance_id)
                raise PermissionError("workspace terminal authority or running identity is unavailable") from exc
        if application_workspace is None and (entry.get("metadata") or {}).get("executionWorkspaceBinding"):
            self._drop_terminal_broker(instance_id)
            raise PermissionError("application workspace authority was removed; host terminal fallback is refused")
        if application_workspace is not None:
            self._remember_application_workspace(instance_id, application_workspace[0])
        workspace_digest = hashlib.sha256(json.dumps(application_workspace[0], sort_keys=True).encode()).hexdigest() if application_workspace else "local"
        cache_identity = f"{application_id}:{root.as_posix()}:{root_info.st_dev}:{root_info.st_ino}:{workspace_digest}:{'platform' if workspace_only else 'application'}:{incarnation}"
        cached = self.terminal_brokers.get(instance_id)
        if cached is not None and secrets.compare_digest(cached[0], cache_identity):
            return cached
        if cached is not None:
            cached[1].close()

        opaque = hashlib.sha256(cache_identity.encode("utf-8")).hexdigest()[:32]
        if application_workspace is not None:
            from stateport_terminal_broker.execution_host_gateway import ExecutionHostTerminalGateway
            binding, execution_client = application_workspace
            target = TerminalTarget(f"terminal.workspace.{opaque}", "capsule", "Application workspace terminal", "available", TerminalCapabilities("capsule", True, True, True, False, False, True))
            profile_id = f"terminal.profile.{opaque}"
            gateway = ExecutionHostTerminalGateway(execution_client, expected_container_identity_digest=incarnation if workspace_only else None, require_container_identity=workspace_only, workspace_id=binding["workload"]["workloadId"], instance_id=instance_id, profile_id=profile_id, target=target, allowed_origins=(f"http://127.0.0.1:{self.server_address[1]}",))
            value = (cache_identity, gateway, gateway, Path("/workspace"), profile_id, target)
            self.terminal_brokers[instance_id] = value
            return value
        target = TerminalTarget(
            f"terminal.local.{opaque}",
            "local_pty",
            "Project terminal",
            "available",
            TerminalCapabilities("local_pty", True, True, True, True, True, True),
        )
        profile_id = f"terminal.profile.{opaque}"
        profile = TerminalConnectionProfile(
            profile_id,
            target,
            (instance_id,),
            root,
            ("/bin/sh",),
        )
        state_directory = self.layout.runtime_root / f"terminal-broker-{opaque}"
        broker = TerminalSessionBroker(
            (profile,),
            state_directory=state_directory,
            allowed_origins=(f"http://127.0.0.1:{self.server_address[1]}",),
        )
        gateway = AuthenticatedTerminalGateway(broker)
        value = (cache_identity, broker, gateway, root, profile_id, target)
        self.terminal_brokers[instance_id] = value
        return value

    @staticmethod
    def _terminal_dimensions(columns: object, rows: object) -> tuple[int, int]:
        for name, value in (("columns", columns), ("rows", rows)):
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 1000:
                raise ValueError(f"terminal {name} must be between 1 and 1000")
        return columns, rows

    def _cleanup_terminal_tickets_locked(self) -> None:
        now = time.monotonic()
        for digest in tuple(self.terminal_tickets):
            if float(self.terminal_tickets[digest]["expiresMonotonic"]) <= now:
                self.terminal_tickets.pop(digest, None)

    def prepare_terminal(self, instance_id: str, *, columns: object, rows: object, workspace_only: bool = False, expected_target_id: object = None) -> dict[str, object]:
        from stateport_terminal_broker import GatewayActor, TerminalBrokerError

        columns, rows = self._terminal_dimensions(columns, rows)
        origin = f"http://127.0.0.1:{self.server_address[1]}"
        with self._terminal_mutex:
            cache_identity, broker, gateway, root, profile_id, target = self._terminal_binding_locked(instance_id, workspace_only=workspace_only)
            if workspace_only and (not isinstance(expected_target_id, str) or not secrets.compare_digest(expected_target_id, target.target_id)):
                raise PermissionError("workspace terminal target changed; review the running workspace again")
            broker.sweep_expired()
            self._cleanup_terminal_tickets_locked()
            if any(ticket["instanceId"] == instance_id for ticket in self.terminal_tickets.values()):
                raise TerminalBrokerError("the selected application already has a pending terminal connection")
            if len(self.terminal_tickets) >= 256:
                raise TerminalBrokerError("terminal ticket capacity is exhausted")
            actor = GatewayActor(self.actor_id, frozenset({instance_id}), "operator_session")
            sessions = (broker.list_sessions(actor, instance_id=instance_id, origin=origin)
                        if target.target_class == "capsule"
                        else broker.list_sessions(actor_id=self.actor_id, instance_id=instance_id, origin=origin))
            if any(session.connected for session in sessions):
                raise TerminalBrokerError("the selected application already has a connected terminal")
            disconnected = [session for session in sessions if not session.connected]
            if len(disconnected) > 1:
                raise TerminalBrokerError("terminal reconnect is ambiguous")
            if disconnected:
                token = broker.prepare_reconnect(
                    disconnected[0].session_id,
                    actor_id=self.actor_id,
                    instance_id=instance_id,
                    origin=origin,
                )
            else:
                token = gateway.prepare(
                    actor,
                    profile_id=profile_id,
                    instance_id=instance_id,
                    selected_root=root,
                    origin=origin,
                )
            digest = hashlib.sha256(token.value.encode("ascii")).hexdigest()
            self.terminal_tickets[digest] = {
                "cacheIdentity": cache_identity,
                "workspaceOnly": workspace_only,
                "instanceId": instance_id,
                "sessionId": token.session_id,
                "purpose": token.purpose,
                "columns": columns,
                "rows": rows,
                "expiresMonotonic": time.monotonic() + 30.0,
            }
            return {
                "formatVersion": TERMINAL_SOCKET_FORMAT,
                "socketPath": TERMINAL_SOCKET_PATH,
                "subprotocol": TERMINAL_SOCKET_SUBPROTOCOL,
                "oneUseToken": token.value,
                "sessionId": token.session_id,
                "purpose": token.purpose,
                "expiresAt": token.expires_at,
                "target": target.to_dict(),
            }

    def accept_terminal_socket(self, authentication: dict[str, object], origin: str) -> dict[str, object]:
        from stateport_terminal_broker import GatewayActor, GatewayFrame, GatewayHandshake, TerminalAccessDenied

        token = authentication["oneUseToken"]
        assert isinstance(token, str)
        digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        with self._terminal_mutex:
            self._cleanup_terminal_tickets_locked()
            ticket = self.terminal_tickets.pop(digest, None)
            if ticket is None or float(ticket["expiresMonotonic"]) <= time.monotonic():
                raise TerminalAccessDenied()
            exact = (
                secrets.compare_digest(str(authentication["instanceId"]), str(ticket["instanceId"])),
                secrets.compare_digest(str(authentication["sessionId"]), str(ticket["sessionId"])),
                secrets.compare_digest(str(authentication["purpose"]), str(ticket["purpose"])),
                authentication["columns"] == ticket["columns"],
                authentication["rows"] == ticket["rows"],
                secrets.compare_digest(origin, f"http://127.0.0.1:{self.server_address[1]}"),
            )
            if not all(exact):
                raise TerminalAccessDenied()
            instance_id = str(ticket["instanceId"])
            cache_identity, _broker, gateway, root, _profile_id, _target = self._terminal_binding_locked(instance_id, workspace_only=ticket.get("workspaceOnly") is True)
            if not secrets.compare_digest(cache_identity, str(ticket["cacheIdentity"])):
                raise TerminalAccessDenied()
            actor = GatewayActor(self.actor_id, frozenset({instance_id}), "operator_session")
            handshake = GatewayHandshake(
                actor,
                instance_id,
                origin,
                request_target=TERMINAL_SOCKET_PATH,
                token_transport="first_frame",
            )
            if ticket["purpose"] == "create":
                session, receipt = gateway.accept_handshake(
                    handshake,
                    one_use_value=token,
                    selected_root=root,
                    columns=int(ticket["columns"]),
                    rows=int(ticket["rows"]),
                )
            else:
                session, receipt = gateway.accept_reconnect(
                    actor,
                    one_use_value=token,
                    instance_id=instance_id,
                    selected_root=root,
                    origin=origin,
                )
                gateway.handle_frame(
                    handshake,
                    session_id=session.session_id,
                    frame=GatewayFrame("resize", columns=int(ticket["columns"]), rows=int(ticket["rows"])),
                )
            return {
                "gateway": gateway,
                "handshake": handshake,
                "session": session,
                "receipt": receipt,
            }

    def register_terminal_socket(self, connection: socket.socket) -> None:
        with self._terminal_sockets_mutex:
            if self._terminal_closing:
                raise OSError("terminal service is closing")
            self._terminal_sockets.add(connection)

    def unregister_terminal_socket(self, connection: socket.socket) -> None:
        with self._terminal_sockets_mutex:
            self._terminal_sockets.discard(connection)
            self._terminal_sockets_mutex.notify_all()

    def service_actions(self) -> None:
        """Enforce terminal ticket and process lifetimes while the service runs.

        ``serve_forever`` invokes this hook once per poll.  Expiry therefore
        does not depend on a later operator request.  A broker whose sweep
        cannot be completed is closed fail-safe rather than left supervising
        a process with an unenforced lifetime.
        """

        with self._terminal_mutex:
            if self._terminal_closing:
                return
            self._cleanup_terminal_tickets_locked()
            failed: list[str] = []
            for instance_id, (_, broker, *_) in tuple(self.terminal_brokers.items()):
                try:
                    broker.sweep_expired()
                except Exception:  # noqa: BLE001 - close the opaque broker without logging process details
                    failed.append(instance_id)
            for instance_id in failed:
                self._drop_terminal_broker(instance_id)
                self.log.write("terminal lifetime sweep failed; broker closed\n")
                self.log.flush()

    def _drop_file_workspace(self, instance_id: str) -> None:
        cached = self.file_workspaces.pop(instance_id, None)
        if cached is not None:
            cached[1].close()

    def file_workspace(self, instance_id: str):
        with self._file_workspace_mutex:
            return self._file_workspace_locked(instance_id)

    def _file_workspace_locked(self, instance_id: str):
        from stateport_file_workspace import FileWorkspaceBroker, FileWorkspaceProfile, PathPolicyRule

        app = self.source_app()
        try:
            entry = app.catalog.get(instance_id)
        except Exception as exc:  # noqa: BLE001 - catalog failures are redacted at this boundary
            self._drop_file_workspace(instance_id)
            raise PermissionError("catalog identity is unavailable") from exc
        filesystem = entry.get("filesystem")
        if (
            entry.get("pathState") != "present"
            or entry.get("status") != "active"
            or not isinstance(filesystem, dict)
            or set(filesystem) != {"device", "inode", "kind"}
            or filesystem.get("kind") != "directory"
            or any(
                isinstance(filesystem.get(key), bool)
                or not isinstance(filesystem.get(key), int)
                or filesystem.get(key) < 0
                for key in ("device", "inode")
            )
        ):
            self._drop_file_workspace(instance_id)
            raise PermissionError("cataloged project path is not present with a verified identity")
        application_id = str(entry.get("applicationId", ""))
        experience = self.application_experience(application_id, instance_id)
        if experience is None:
            raise PermissionError("application experience is unavailable")
        statuses = {str(item.get("id")): str(item.get("status")) for item in experience.get("capabilities", []) if isinstance(item, dict)}
        if not all(statuses.get(item) in {"available", "degraded"} for item in ("workbench", "file_viewer", "editor")):
            raise PermissionError("application does not have an effective file Workbench")
        root = Path(str(entry.get("path", "")))
        if not root.is_absolute():
            self._drop_file_workspace(instance_id)
            raise PermissionError("cataloged project path must be absolute")
        expected_root_identity = (filesystem["device"], filesystem["inode"])
        try:
            root_info = os.lstat(root)
        except OSError as exc:
            self._drop_file_workspace(instance_id)
            raise PermissionError("cataloged project path is unavailable") from exc
        if (
            not stat.S_ISDIR(root_info.st_mode)
            or stat.S_ISLNK(root_info.st_mode)
            or (root_info.st_dev, root_info.st_ino) != expected_root_identity
        ):
            self._drop_file_workspace(instance_id)
            raise PermissionError("cataloged project filesystem identity changed")
        cache_identity = f"{application_id}:{root.as_posix()}:{root_info.st_dev}:{root_info.st_ino}"
        cached = self.file_workspaces.get(instance_id)
        if cached is not None and cached[0] == cache_identity:
            return cached[1]
        if cached is not None:
            cached[1].close()

        rules = [
            PathPolicyRule("project.lifecycle", ".statedd", "subtree", "canonical", True, False, False, False, False),
            PathPolicyRule("project.generated.build", "build", "subtree", "generated", True, False, False, False, False),
            PathPolicyRule("project.generated.dist", "dist", "subtree", "generated", True, False, False, False, False),
            PathPolicyRule("project.disposable.tmp", "tmp", "subtree", "disposable", True, True, True, True, True),
        ]
        application_subtrees = (
            ".github", "apps", "config", "docs", "fixtures", "packages", "public",
            "schemas", "scripts", "src", "static", "templates", "test", "tests",
            "hosts", "modules", "home",
        )
        rules.extend(
            PathPolicyRule(
                f"project.application.subtree.{index}", path, "subtree", "application_owned",
                True, True, True, True, True,
            )
            for index, path in enumerate(application_subtrees, start=1)
        )
        application_root_files = (
            "CHANGELOG", "Dockerfile", "LICENSE", "Makefile", "README", "README.md",
            "Cargo.toml", "compose.yaml", "compose.yml", "go.mod", "go.sum", "package-lock.json",
            "package.json", "pyproject.toml", "requirements.txt", "flake.nix", "flake.lock",
            "PROJECT_ADAPTER.yaml", "shell.nix", "configuration.nix",
        )
        rules.extend(
            PathPolicyRule(
                f"project.application.root.{index}", path, "exact", "application_owned",
                True, True, False, False, False,
            )
            for index, path in enumerate(application_root_files, start=1)
        )
        canonical_paths = (
            "AGENTS.md", "BACKLOG.md", "NEXT_ACTIONS.md", "PROJECT_DNA.yaml",
            "PROJECT_STATE.yaml", "STATUS.md", "WORKLOG.md", "docs/EVIDENCE_LOG.md",
        )
        rules.extend(
            PathPolicyRule(f"project.canonical.{index}", path, "exact", "canonical", True, False, False, False, False)
            for index, path in enumerate(canonical_paths, start=1)
        )
        profile = FileWorkspaceProfile(
            profile_id=f"file-workspace.{instance_id}",
            application_id=application_id,
            application_kind="development",
            instance_id=instance_id,
            project_root=root,
            expected_root_identity=expected_root_identity,
            effective_capabilities=frozenset(item for item in ("workbench", "file_viewer", "editor") if statuses.get(item) in {"available", "degraded"}),
            actor_permissions={self.actor_id: frozenset({"file.read", "file.write"})},
            path_rules=tuple(rules),
        )
        broker = FileWorkspaceBroker(
            profile,
            lease_directory=self.layout.runtime_root / "file-workspace-leases",
        )
        self.file_workspaces[instance_id] = (cache_identity, broker)
        return broker

    def file_workspace_identity(self, broker: object) -> dict[str, str]:
        return {
            "actor_id": self.actor_id,
            "application_id": broker.profile.application_id,
            "instance_id": broker.profile.instance_id,
        }

    def record_file_workspace_receipt(
        self,
        *,
        instance_id: str,
        application_id: str,
        expected_operation: str,
        receipt: Mapping[str, object],
    ) -> None:
        """Index one exact broker-owned mutation receipt after it succeeds."""

        if set(receipt) != {
            "formatVersion",
            "operation",
            "receiptId",
            "actorId",
            "applicationId",
            "instanceId",
            "sourcePath",
            "destinationPath",
            "baseSha",
            "preHash",
            "postHash",
            "ownershipClass",
            "diffDigest",
            "validation",
            "completedAt",
            "contentRetained",
        }:
            raise ActivityReceiptError("file workspace mutation receipt shape is invalid")
        if (
            expected_operation not in {"commitWrite", "createFile", "renamePath", "deletePath"}
            or receipt.get("formatVersion") != "stateport.file-workspace/v1"
            or receipt.get("operation") != expected_operation
            or receipt.get("actorId") != self.actor_id
            or receipt.get("applicationId") != application_id
            or receipt.get("instanceId") != instance_id
            or receipt.get("contentRetained") is not False
            or receipt.get("ownershipClass") not in {
                "application_owned",
                "canonical",
                "generated",
                "disposable",
            }
            or receipt.get("validation") not in {"passed", "not_required"}
        ):
            raise ActivityReceiptError("file workspace mutation receipt authority is invalid")
        receipt_id = receipt.get("receiptId")
        source_path = receipt.get("sourcePath")
        completed_at = self._operational_receipt_timestamp(
            receipt.get("completedAt"),
            "file workspace receipt timestamp",
        )
        if not all(isinstance(value, str) and value for value in (receipt_id, source_path)):
            raise ActivityReceiptError("file workspace mutation receipt identity is invalid")
        if (
            not isinstance(receipt.get("baseSha"), str)
            or not re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", str(receipt["baseSha"]))
        ):
            raise ActivityReceiptError("file workspace mutation receipt base identity is invalid")
        for field in ("preHash", "postHash", "diffDigest"):
            value = receipt.get(field)
            if value is not None and (
                not isinstance(value, str)
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", value)
            ):
                raise ActivityReceiptError("file workspace mutation receipt digest is invalid")
        destination_path = receipt.get("destinationPath")
        if destination_path is not None and (
            not isinstance(destination_path, str) or not destination_path
        ):
            raise ActivityReceiptError("file workspace mutation receipt destination is invalid")
        pre_hash = receipt.get("preHash")
        post_hash = receipt.get("postHash")
        diff_digest = receipt.get("diffDigest")
        if expected_operation == "commitWrite":
            operation_shape_is_valid = (
                destination_path is None
                and isinstance(pre_hash, str)
                and isinstance(post_hash, str)
                and isinstance(diff_digest, str)
            )
        elif expected_operation == "createFile":
            operation_shape_is_valid = (
                destination_path is None
                and pre_hash is None
                and isinstance(post_hash, str)
                and isinstance(diff_digest, str)
            )
        elif expected_operation == "renamePath":
            operation_shape_is_valid = (
                isinstance(destination_path, str)
                and isinstance(pre_hash, str)
                and post_hash == pre_hash
                and diff_digest is None
            )
        else:
            operation_shape_is_valid = (
                destination_path is None
                and isinstance(pre_hash, str)
                and post_hash is None
                and diff_digest is None
            )
        if not operation_shape_is_valid:
            raise ActivityReceiptError("file workspace mutation receipt operation binding is invalid")
        self.activity_receipts.record_receipt(
            instance_id=instance_id,
            receipt={
                "receiptId": receipt_id,
                "receiptType": receipt["formatVersion"],
                "action": f"file_workspace.{expected_operation}",
                "status": "applied",
                "createdAt": completed_at,
                "sourceKind": "file_workspace",
                "instanceId": instance_id,
                "applicationId": application_id,
                "fileMutationReceipt": dict(receipt),
            },
        )

    def server_close(self) -> None:
        try:
            if self._assistant_processor is not None:
                self._assistant_processor.shutdown()
            with self._terminal_sockets_mutex:
                self._terminal_closing = True
                active_sockets = tuple(self._terminal_sockets)
            for connection in active_sockets:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    connection.close()
                except OSError:
                    pass
            deadline = time.monotonic() + 1.0
            with self._terminal_sockets_mutex:
                while self._terminal_sockets and time.monotonic() < deadline:
                    self._terminal_sockets_mutex.wait(timeout=max(0.0, deadline - time.monotonic()))
            with self._terminal_mutex:
                for _, broker, *_ in self.terminal_brokers.values():
                    broker.close()
                self.terminal_brokers.clear()
                self.terminal_tickets.clear()
            with self._file_workspace_mutex:
                for _, broker in self.file_workspaces.values():
                    broker.close()
                self.file_workspaces.clear()
            if self.telegram_launcher is not None:
                self.telegram_launcher.stop()
            self.log.close()
        finally:
            super().server_close()


_REQUIRED_PRODUCT_PATHS = (
    "packages/persistent-app/src",
    "packages/goal-execution/src",
    "packages/execution-host/src",
    "packages/release-contracts/src",
    "packages/opencode-adapter/src",
    "packages/container-opencode/src",
    "apps/telegram-adapter/src",
    "config/functionality-preservation.v1.yaml",
)


def _validate_product_root(raw_root: Path) -> dict[str, str]:
    root = raw_root.expanduser().resolve()
    git_marker = root / ".git"
    if not root.is_dir() or not (git_marker.is_dir() or git_marker.is_file()):
        raise ValueError("StatePort product root must be a Git clone or worktree")
    configured = os.environ.get("STATEPORT_PRODUCT_ROOT")
    if configured and Path(configured).expanduser().resolve() != root:
        raise ValueError("configured product root does not match the service root")
    missing = [relative for relative in _REQUIRED_PRODUCT_PATHS if not (root / relative).exists()]
    if missing:
        raise ValueError("configured product root is missing required capabilities: " + ", ".join(missing))
    try:
        identity = {}
        for key, arguments in (
            ("top", ("--show-toplevel",)),
            ("gitDir", ("--git-dir",)),
            ("branch", ("--abbrev-ref", "HEAD")),
            ("head", ("HEAD",)),
        ):
            value = subprocess.run(
                ("git", "-C", str(root), "rev-parse", *arguments),
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            ).stdout.strip()
            identity[key] = value
        identity["tree"] = subprocess.run(
            ("git", "-C", str(root), "rev-parse", f"{identity['head']}^{{tree}}"),
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("configured product root has no readable Git identity") from exc
    if Path(identity["top"]).resolve() != root:
        raise ValueError("Git identity does not belong to the configured product root")
    return {
        "repoRoot": root.as_posix(),
        "gitDir": identity["gitDir"],
        "gitBranch": identity["branch"],
        "gitHead": identity["head"],
        "gitTree": identity["tree"],
    }


def _is_loopback_bind_host(host: str) -> bool:
    normalized = host.strip()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        # Hostname resolution is intentionally not performed here.  An unknown
        # name could resolve to a public address between validation and bind.
        return False


def _validate_bind_host(host: str, allow_public_bind: bool) -> None:
    if not isinstance(host, str) or not host.strip():
        raise ValueError("host must be an explicit loopback address unless public bind is enabled")
    if not _is_loopback_bind_host(host) and not allow_public_bind:
        raise ValueError(
            "refusing non-loopback bind; pass --allow-public-bind only for an intentional "
            "public bind behind an external trust boundary"
        )


def _unlink_runtime_if_owned(runtime: Path, pid: int, process_start_ticks: int) -> None:
    """Remove only this daemon's runtime record, never a successor's record."""

    try:
        current = json.loads(runtime.read_text(encoding="utf-8"))
        if int(current.get("pid", -1)) != pid or int(current.get("processStartTicks", -1)) != process_start_ticks:
            return
        runtime.unlink()
    except (FileNotFoundError, OSError, TypeError, ValueError, json.JSONDecodeError):
        return


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--actor-role", choices=("local_user", "platform_operator"), default="local_user")
    parser.add_argument("--canonical-source-catalog", type=Path)
    parser.add_argument("--expected-source-catalog-digest")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument(
        "--external-loopback-port",
        type=int,
        default=os.environ.get("STATEPORT_EXTERNAL_LOOPBACK_PORT"),
        help="explicit host loopback port for a container port mapping",
    )
    parser.add_argument(
        "--allow-public-bind",
        action="store_true",
        help="allow binding beyond loopback; unsafe unless an external trust boundary exists",
    )
    args = parser.parse_args(argv)
    try:
        _validate_bind_host(args.host, args.allow_public_bind)
    except ValueError as exc:
        parser.error(str(exc))
    repo_root = _validate_product_root(args.repo_root)
    layout = LocalLayout.from_environment()
    layout.initialize()
    daemon_lock_path = layout.runtime_root / "service-daemon.lock"
    daemon_lock = daemon_lock_path.open("a+", encoding="utf-8")
    os.chmod(daemon_lock_path, 0o600)
    try:
        fcntl.flock(daemon_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        daemon_lock.close()
        parser.error("another local StatePort service process is already active")

    product_root = Path(repo_root["repoRoot"])
    expected_commit, expected_tree = _expected_web_source_identity(repo_root)
    runtime = layout.runtime_root / "service.json"
    server: AppServer | None = None
    process_start_ticks = PersistentApp._process_start_ticks(os.getpid())
    try:
        runtime_fingerprint = PersistentApp._service_runtime_fingerprint(product_root)
        server = AppServer(
            (args.host, args.port),
            layout,
            product_root / "apps" / "web",
            actor_role=args.actor_role,
            canonical_source_catalog=args.canonical_source_catalog,
            expected_source_catalog_digest=args.expected_source_catalog_digest,
            allow_public_bind=args.allow_public_bind,
            external_loopback_port=args.external_loopback_port,
            expected_source_commit=expected_commit,
            expected_source_tree=expected_tree,
        )
        runtime_data = {
            "formatVersion": "stateport.service-runtime/v1",
            "pid": os.getpid(),
            "processStartTicks": process_start_ticks,
            "port": server.server_address[1],
            "actorRole": args.actor_role,
            "runtimeFingerprint": runtime_fingerprint,
            **server.source_app()._service_source_catalog_identity(),
            "startedAt": datetime.now(timezone.utc).isoformat(),
            **repo_root,
        }
        temporary_runtime = runtime.with_name(f".{runtime.name}.{os.getpid()}.tmp")
        temporary_runtime.write_text(json.dumps(runtime_data, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(temporary_runtime, 0o600)
        os.replace(temporary_runtime, runtime)

        def stop(_signum: int, _frame: object) -> None:
            assert server is not None
            threading.Thread(target=server.shutdown, daemon=True).start()

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        server.serve_forever(poll_interval=0.2)
    finally:
        if server is not None:
            server.server_close()
        _unlink_runtime_if_owned(runtime, os.getpid(), process_start_ticks)
        try:
            fcntl.flock(daemon_lock.fileno(), fcntl.LOCK_UN)
        finally:
            daemon_lock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
