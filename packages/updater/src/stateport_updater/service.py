"""Loopback-only health/readiness/status surface for the updater service."""

from __future__ import annotations

from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
from pathlib import Path
import re
import socket
from threading import BoundedSemaphore
from typing import Any, Mapping
from urllib.parse import urlsplit
import uuid

from stateport_release import canonical_json_bytes, validate_update_status

from .store import StoreError, UpdateStore, project_update_status


LOOPBACK_ADDRESSES = {"127.0.0.1", "::1"}
REQUEST_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
PUBLIC_ERROR_CODE = re.compile(r"[a-z][a-z0-9_]{0,127}\Z")
MAX_RESPONSE_BYTES = 256 * 1024
HOST_PUBLIC_CLASSIFICATION = "host-public"


class UpdaterServiceError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ServiceStatus:
    http_status: int
    payload: Mapping[str, Any]
    headers: Mapping[str, str] | None = None


def health_status(service_version: str) -> ServiceStatus:
    """Pure process liveness; it does not touch or create durable state."""

    return ServiceStatus(
        HTTPStatus.OK,
        {
            "schema": "stateport.updater-health/v1",
            "service": "stateport-updater",
            "version": service_version,
            "status": "alive",
        },
    )


def _diagnostic_code(exc: Exception, default: str) -> str:
    """Expose only bounded typed codes, never exception messages."""

    code = (
        getattr(exc, "code", None) if isinstance(exc, (StoreError, UpdaterServiceError)) else None
    )
    return str(code) if isinstance(code, str) and PUBLIC_ERROR_CODE.fullmatch(code) else default


class UpdaterDiagnostics:
    """Read-only diagnostics backed by canonical durable updater status."""

    def __init__(self, store: UpdateStore, *, service_version: str) -> None:
        self.store = store
        self.service_version = service_version

    def health(self) -> ServiceStatus:
        return health_status(self.service_version)

    def readiness(self) -> ServiceStatus:
        try:
            status, pending = self.store.snapshot()
            validated = validate_update_status(project_update_status(status, pending))
        except (StoreError, ValueError) as exc:
            return ServiceStatus(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {
                    "schema": "stateport.updater-readiness/v1",
                    "service": "stateport-updater",
                    "version": self.service_version,
                    "status": "not_ready",
                    "code": _diagnostic_code(exc, "status_unavailable"),
                },
                (
                    {"Retry-After": "1"}
                    if _diagnostic_code(exc, "status_unavailable") == "update_state_busy"
                    else None
                ),
            )
        except Exception:
            return ServiceStatus(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {
                    "schema": "stateport.updater-readiness/v1",
                    "service": "stateport-updater",
                    "version": self.service_version,
                    "status": "not_ready",
                    "code": "diagnostics_failed",
                },
            )
        pending_phase = None if pending is None else str(pending["phase"])
        return ServiceStatus(
            HTTPStatus.OK,
            {
                "schema": "stateport.updater-readiness/v1",
                "service": "stateport-updater",
                "version": self.service_version,
                "status": "ready",
                "updatePhase": validated.document["phase"],
                "pendingPhase": pending_phase,
                "actionRequired": pending_phase
                in {
                    "reconciliation_required",
                    "rollback_reconciliation_required",
                    "retention_reconciliation_required",
                    "cleanup_reconciliation_required",
                    "authority_finalization_pending",
                },
                "statusDigest": validated.digest,
            },
        )

    def status(self) -> ServiceStatus:
        try:
            status, _pending = self.store.snapshot()
            validated = validate_update_status(project_update_status(status, _pending))
        except (StoreError, ValueError) as exc:
            return ServiceStatus(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {
                    "schema": "stateport.updater-error/v1",
                    "service": "stateport-updater",
                    "version": self.service_version,
                    "status": "unavailable",
                    "code": _diagnostic_code(exc, "status_unavailable"),
                },
                {"Retry-After": "1"},
            )
        except Exception:
            return ServiceStatus(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {
                    "schema": "stateport.updater-error/v1",
                    "service": "stateport-updater",
                    "version": self.service_version,
                    "status": "unavailable",
                    "code": "diagnostics_failed",
                },
                {"Retry-After": "1"},
            )
        return ServiceStatus(HTTPStatus.OK, validated.as_dict())


class _UpdaterServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(
        self,
        address: tuple[str, int],
        diagnostics: UpdaterDiagnostics,
        logger: logging.Logger,
        *,
        maximum_concurrency: int,
        read_timeout_seconds: float,
    ) -> None:
        self.diagnostics = diagnostics
        self.logger = logger
        self._capacity = BoundedSemaphore(maximum_concurrency)
        self.read_timeout_seconds = read_timeout_seconds
        super().__init__(address, _UpdaterHandler)

    def get_request(self) -> tuple[socket.socket, Any]:
        request, address = super().get_request()
        request.settimeout(self.read_timeout_seconds)
        return request, address

    def process_request(self, request: socket.socket, client_address: Any) -> None:
        if not self._capacity.acquire(blocking=False):
            request_id = f"req-{uuid.uuid4().hex}"
            payload = canonical_json_bytes(
                {
                    "schema": "stateport.updater-error/v1",
                    "code": "service_busy",
                    "status": "not_executed",
                }
            )
            response = (
                b"HTTP/1.1 503 Service Unavailable\r\n"
                b"Content-Type: application/json; charset=utf-8\r\n"
                + f"Content-Length: {len(payload)}\r\n".encode("ascii")
                + b"Cache-Control: no-store\r\n"
                + b"X-Content-Type-Options: nosniff\r\n"
                + b"Content-Security-Policy: default-src 'none'\r\n"
                + b"X-StatePort-Data-Classification: host-public\r\n"
                + f"X-Request-Id: {request_id}\r\n".encode("ascii")
                + b"Retry-After: 1\r\nConnection: close\r\n\r\n"
                + payload
            )
            try:
                request.sendall(response)
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._capacity.release()
            raise

    def process_request_thread(self, request: socket.socket, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._capacity.release()


class _UpdaterServerV6(_UpdaterServer):
    address_family = socket.AF_INET6

    def server_bind(self) -> None:
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()


class _UpdaterHandler(BaseHTTPRequestHandler):
    server: _UpdaterServer
    protocol_version = "HTTP/1.1"

    def send_response(self, code: int, message: str | None = None) -> None:
        """Send status and date without disclosing Python's server banner."""

        self.log_request(code)
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())

    def _request_id(self) -> str:
        supplied = self.headers.get("X-Request-Id", "")
        return supplied if REQUEST_ID.fullmatch(supplied) else f"req-{uuid.uuid4().hex}"

    def _write(
        self,
        status: ServiceStatus,
        request_id: str,
        *,
        include_body: bool = True,
    ) -> None:
        try:
            payload = canonical_json_bytes(status.payload)
        except Exception:
            status = ServiceStatus(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {
                    "schema": "stateport.updater-error/v1",
                    "code": "response_serialization_failed",
                    "status": "failed",
                },
            )
            payload = canonical_json_bytes(status.payload)
        if len(payload) > MAX_RESPONSE_BYTES:
            status = ServiceStatus(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {
                    "schema": "stateport.updater-error/v1",
                    "code": "response_bounds_exceeded",
                    "status": "failed",
                },
            )
            payload = canonical_json_bytes(status.payload)
        self.send_response(int(status.http_status))
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Request-Id", request_id)
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.send_header("X-StatePort-Data-Classification", HOST_PUBLIC_CLASSIFICATION)
        for key, value in (status.headers or {}).items():
            self.send_header(key, value)
        self.send_header("Connection", "close")
        self.end_headers()
        if include_body:
            self.wfile.write(payload)

    def _log_result(self, request_id: str, result: ServiceStatus, route_path: str) -> None:
        self.server.logger.info(
            json.dumps(
                {
                    "event": "updater_http_request",
                    "requestId": request_id,
                    "method": self.command,
                    "path": route_path,
                    "status": int(result.http_status),
                    "service": "stateport-updater",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )

    @staticmethod
    def _error(status: HTTPStatus, code: str, result: str) -> ServiceStatus:
        return ServiceStatus(
            status,
            {
                "schema": "stateport.updater-error/v1",
                "code": code,
                "status": result,
            },
        )

    def _request_route(
        self,
        *,
        reject_body: bool = True,
    ) -> tuple[str | None, ServiceStatus | None, str]:
        try:
            parsed = urlsplit(self.path)
        except (UnicodeError, ValueError):
            return (
                None,
                self._error(
                    HTTPStatus.BAD_REQUEST,
                    "request_target_invalid",
                    "not_executed",
                ),
                "invalid-request-target",
            )
        if (
            not self.path.startswith("/")
            or parsed.scheme
            or parsed.netloc
            or parsed.fragment
            or "\\" in parsed.path
        ):
            return (
                None,
                self._error(
                    HTTPStatus.BAD_REQUEST,
                    "request_target_invalid",
                    "not_executed",
                ),
                "invalid-request-target",
            )
        route_path = parsed.path
        header_sizes = [
            len(str(key).encode("utf-8")) + len(str(value).encode("utf-8")) + 4
            for key, value in self.headers.items()
        ]
        if (
            len(self.path.encode("utf-8")) > 2048
            or len(self.headers) > 32
            or any(size > 8192 for size in header_sizes)
            or sum(header_sizes) > 32768
        ):
            return (
                None,
                self._error(
                    HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE,
                    "request_bounds_exceeded",
                    "not_executed",
                ),
                "request-bounds-exceeded",
            )
        content_length = self.headers.get("Content-Length")
        if reject_body and content_length not in {None, "0"}:
            return (
                None,
                self._error(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    "request_body_refused",
                    "not_executed",
                ),
                "request-body-refused",
            )
        return route_path, None, route_path

    def _handle_read(self, *, include_body: bool) -> None:
        request_id = self._request_id()
        route_path, refusal, log_path = self._request_route()
        if refusal is not None:
            self._write(refusal, request_id, include_body=include_body)
            self._log_result(request_id, refusal, log_path)
            return
        routes = {
            "/healthz": self.server.diagnostics.health,
            "/readyz": self.server.diagnostics.readiness,
            "/v1/status": self.server.diagnostics.status,
        }
        operation = routes.get(route_path)
        if operation is None:
            result = self._error(HTTPStatus.NOT_FOUND, "route_not_found", "not_found")
            log_path = "unmatched-route"
        else:
            try:
                result = operation()
            except Exception:
                result = self._error(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    "diagnostics_failed",
                    "failed",
                )
        self._write(result, request_id, include_body=include_body)
        self._log_result(request_id, result, log_path)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._handle_read(include_body=True)

    def _reject_mutation(self) -> None:
        request_id = self._request_id()
        _route_path, refusal, log_path = self._request_route(reject_body=False)
        if refusal is not None:
            self._write(refusal, request_id)
            self._log_result(request_id, refusal, log_path)
            return
        result = self._error(
            HTTPStatus.METHOD_NOT_ALLOWED,
            "read_only_service",
            "method_not_allowed",
        )
        self._write(
            ServiceStatus(result.http_status, result.payload, {"Allow": "GET, HEAD"}),
            request_id,
        )
        self._log_result(
            request_id,
            result,
            log_path if log_path in {"/healthz", "/readyz", "/v1/status"} else "unmatched-route",
        )

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._reject_mutation()

    def do_PUT(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._reject_mutation()

    def do_PATCH(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._reject_mutation()

    def do_DELETE(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._reject_mutation()

    def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._handle_read(include_body=False)

    def do_OPTIONS(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._reject_mutation()

    def send_error(
        self,
        code: int,
        message: str | None = None,
        explain: str | None = None,
    ) -> None:
        """Replace base-class HTML/error echoes with one bounded JSON shape."""

        del message, explain
        request_id = self._request_id()
        try:
            status = HTTPStatus(code)
        except ValueError:
            status = HTTPStatus.BAD_REQUEST
        result = self._error(status, "request_invalid", "not_executed")
        self._write(result, request_id, include_body=self.command != "HEAD")
        self._log_result(request_id, result, "invalid-request")

    def log_message(self, format: str, *args: object) -> None:
        # The structured event above is the sole access log; the base class
        # includes untrusted request text in an unstructured line.
        del format, args


def build_server(
    *,
    listen: str,
    port: int,
    state_root: Path,
    service_version: str,
    logger: logging.Logger | None = None,
    maximum_concurrency: int = 16,
    read_timeout_seconds: float = 5.0,
) -> ThreadingHTTPServer:
    if listen not in LOOPBACK_ADDRESSES:
        raise UpdaterServiceError(
            "public_bind_refused", "updater diagnostics may bind only to loopback"
        )
    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
        raise UpdaterServiceError("port_invalid", "updater service port is invalid")
    if not state_root.is_absolute():
        raise UpdaterServiceError("state_root_invalid", "updater state root must be absolute")
    if (
        isinstance(maximum_concurrency, bool)
        or not isinstance(maximum_concurrency, int)
        or not 1 <= maximum_concurrency <= 128
    ):
        raise UpdaterServiceError("concurrency_invalid", "updater concurrency limit is invalid")
    if (
        isinstance(read_timeout_seconds, bool)
        or not isinstance(read_timeout_seconds, (int, float))
        or not 0.1 <= float(read_timeout_seconds) <= 60
    ):
        raise UpdaterServiceError("timeout_invalid", "updater read timeout is invalid")
    selected_logger = logger or logging.getLogger("stateport_updater.service")
    diagnostics = UpdaterDiagnostics(
        UpdateStore.open_existing(state_root),
        service_version=service_version,
    )
    server_type = _UpdaterServerV6 if listen == "::1" else _UpdaterServer
    try:
        return server_type(
            (listen, port),
            diagnostics,
            selected_logger,
            maximum_concurrency=maximum_concurrency,
            read_timeout_seconds=float(read_timeout_seconds),
        )
    except OSError as exc:
        raise UpdaterServiceError(
            "bind_failed",
            f"updater loopback bind failed ({type(exc).__name__})",
        ) from exc
