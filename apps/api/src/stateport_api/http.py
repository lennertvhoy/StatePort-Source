"""Small stdlib HTTP adapter for :mod:`governed_api`."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from time import perf_counter
from typing import Any, Protocol
from urllib.parse import urlsplit

from governed_api import API_VERSION, GovernedAPI, Response
from stateport_auth import AuthError, BearerAuthenticator, OIDCAuthenticator
from stateport_observability import NullObserver, OperationalObserver, observer_from_environment


class Authenticator(Protocol):
    @property
    def configured(self) -> bool: ...

    def authenticate(self, authorization: Any) -> Any: ...


MAX_REQUEST_BYTES = 1_048_576
DEFAULT_POLL_INTERVAL = 0.5
MIN_POLL_INTERVAL = 0.05
MAX_POLL_INTERVAL = 5.0
TRANSPORT_VERSION = "1"
READ_ONLY_BROWSER_POSTS = frozenset({
    "/v1/context/build",
    "/v1/context/inspect",
    "/v1/approvals/list",
})


def _bounded_poll_interval(value: float) -> float:
    """Validate the small polling interval used by the stdlib server."""

    try:
        interval = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("poll_interval must be a finite number") from exc
    if not MIN_POLL_INTERVAL <= interval <= MAX_POLL_INTERVAL:
        raise ValueError(
            f"poll_interval must be between {MIN_POLL_INTERVAL} and {MAX_POLL_INTERVAL} seconds"
        )
    return interval


def _is_loopback_host(host: str) -> bool:
    normalized = host.strip().lower().rstrip(".")
    if normalized == "localhost":
        return True
    if normalized.startswith("[") and normalized.endswith("]"):
        normalized = normalized[1:-1]
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        # Hostname resolution is intentionally not performed here.  An unknown
        # name could resolve to a public address between validation and bind.
        return False


def _validate_bind_host(host: str, allow_public_bind: bool) -> None:
    if not isinstance(host, str) or not host.strip():
        raise ValueError("host must be an explicit loopback address unless public bind is enabled")
    if not _is_loopback_host(host) and not allow_public_bind:
        raise ValueError(
            "refusing non-loopback bind; pass allow_public_bind=True only for an intentional public bind"
        )


def _json_constant(value: str) -> Any:
    del value
    raise ValueError("JSON constants such as NaN and Infinity are not valid")


def _require_authenticated_authorization_config(
    identities: dict[str, Any] | None,
    operator_allowed_capabilities: list[str] | None,
    authenticator: Authenticator,
) -> None:
    """Reject authorization configuration without a trusted HTTP identity."""

    if (identities or operator_allowed_capabilities) and not authenticator.configured:
        raise ValueError(
            "configured identities or operator capabilities require bearer authentication"
        )


class _Handler(BaseHTTPRequestHandler):
    server_version = "StatePortAPI/1"
    sys_version = ""

    def handle_one_request(self) -> None:
        # One handler can serve several keep-alive requests.  Correlation and
        # duration therefore reset at the transport request boundary.
        self._stateport_request_id = None
        self._stateport_request_started = perf_counter()
        self._stateport_request_observed = False
        super().handle_one_request()

    def _api(self) -> GovernedAPI:
        return self.server.governed_api  # type: ignore[attr-defined]

    def _authenticator(self) -> Authenticator:
        return self.server.authenticator  # type: ignore[attr-defined]

    def _observer(self) -> OperationalObserver:
        return getattr(self.server, "operational_observer", NullObserver("stateport-api"))

    def _request_id(self) -> str:
        # Never reflect a caller-controlled trace value: request IDs are
        # diagnostics only and must not become a covert header/body echo.
        request_id = getattr(self, "_stateport_request_id", None)
        if request_id is None:
            request_id = f"sp-{os.urandom(8).hex()}"
            self._stateport_request_id = request_id
        return request_id

    def _observe_completed(
        self,
        status: int,
        payload: dict[str, Any],
        *,
        response_bytes: int,
    ) -> None:
        if getattr(self, "_stateport_request_observed", False):
            return
        self._stateport_request_observed = True
        result_code = "ok"
        if payload.get("ok") is False:
            error = payload.get("error")
            if isinstance(error, dict) and isinstance(error.get("code"), str):
                result_code = error["code"]
            else:
                result_code = "request_failed"
        route = self._path()
        level = "debug" if route in {"/health", "/livez", "/readyz"} and status < 400 else (
            "warning" if status >= 400 else "info"
        )
        started = getattr(self, "_stateport_request_started", perf_counter())
        self._observer().emit(
            "http.request.completed",
            level=level,
            requestId=self._request_id(),
            method=getattr(self, "command", None) or "unknown",
            route=route,
            status=status,
            responseBytes=response_bytes,
            durationMs=max(0.0, (perf_counter() - started) * 1000.0),
            resultCode=result_code,
        )

    def _path(self) -> str:
        # urlsplit also handles absolute-form HTTP targets and drops queries,
        # keeping routing independent of the caller's base URL.
        return urlsplit(self.path).path or "/"

    def _loopback_origin(self) -> str | None:
        """Return a safe local browser origin, if the caller supplied one."""

        headers = getattr(self, "headers", None)
        if headers is None:
            return None
        origin = headers.get("origin")
        if not origin:
            return None
        try:
            parsed = urlsplit(origin)
        except ValueError:
            return None
        if (
            parsed.scheme != "http"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path
            or parsed.query
            or parsed.fragment
            or not _is_loopback_host(parsed.hostname)
        ):
            return None
        return origin

    def _local_read_only_browser_post(self) -> bool:
        return bool(
            self._loopback_origin()
            and self._path() in READ_ONLY_BROWSER_POSTS
            and not self.headers.get("cookie")
        )

    def _send(
        self,
        status: int,
        payload: dict[str, Any],
        *,
        request_id: str | None = None,
        headers: dict[str, str] | None = None,
        include_body: bool = True,
    ) -> None:
        data = (json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        self.send_response(status)
        for name, value in (headers or {}).items():
            if name.lower() not in {"content-length", "content-type", "server", "date"}:
                self.send_header(name, value)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(data)))
        self.send_header("cache-control", "no-store")
        self.send_header("x-content-type-options", "nosniff")
        self.send_header("x-stateport-api-version", API_VERSION)
        self.send_header("x-stateport-transport-version", TRANSPORT_VERSION)
        self.send_header("x-request-id", request_id or self._request_id())
        origin = self._loopback_origin()
        if origin:
            self.send_header("access-control-allow-origin", origin)
            self.send_header("vary", "Origin")
        self.end_headers()
        if include_body and self.command != "HEAD":
            self.wfile.write(data)
        self._observe_completed(status, payload, response_bytes=len(data))

    def _send_error(
        self,
        status: int,
        code: str,
        message: str,
        *,
        request_id: str,
        allow: str | None = None,
    ) -> None:
        diagnostic = {
            "requestId": request_id,
            "status": status,
            "method": getattr(self, "command", None) or "unknown",
        }
        headers = {"allow": allow} if allow else None
        self._send(
            status,
            {"ok": False, "error": {"code": code, "message": message, "diagnostic": diagnostic}},
            request_id=request_id,
            headers=headers,
        )

    def _reject_request(
        self,
        status: int,
        code: str,
        message: str,
        *,
        request_id: str,
    ) -> None:
        # Do not leave an unread or malformed body on a persistent connection
        # where it could be interpreted as the next request.
        self.close_connection = True
        self._send_error(status, code, message, request_id=request_id)

    def _send_response(self, response: Response, *, request_id: str) -> None:
        payload = response.body
        if not payload.get("ok", True):
            raw_error = payload.get("error")
            error = raw_error if isinstance(raw_error, dict) else {}
            code = error.get("code") if isinstance(error.get("code"), str) else "request_failed"
            # Core operation failures are deliberately generic at the transport
            # boundary.  In particular, exception text can contain local paths,
            # credentials supplied to an embedding, or other sensitive detail.
            message = error.get("message") if isinstance(error.get("message"), str) else "request failed"
            if code in {"internal_error", "operation_failed"}:
                message = "the operation failed"
            self._send_error(response.status, code, message, request_id=request_id)
            return
        self._send(response.status, payload, request_id=request_id, headers=response.headers)

    def _read_json(self, *, request_id: str) -> dict[str, Any] | None:
        content_types = self.headers.get_all("content-type") or []
        content_type = content_types[0] if len(content_types) == 1 else ""
        content_type_parts = [part.strip() for part in content_type.split(";")]
        media_type = content_type_parts[0].lower()
        parameters = content_type_parts[1:]
        seen_parameters: set[str] = set()
        valid_parameters = True
        for parameter in parameters:
            name, separator, value = parameter.partition("=")
            name = name.strip().lower()
            value = value.strip()
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            if (
                not separator
                or name != "charset"
                or name in seen_parameters
                or value.lower() != "utf-8"
            ):
                valid_parameters = False
                break
            seen_parameters.add(name)
        if media_type != "application/json" or not valid_parameters:
            self._reject_request(
                415,
                "unsupported_media_type",
                "content-type must be application/json with UTF-8 or no charset",
                request_id=request_id,
            )
            return None
        transfer_encoding = self.headers.get("transfer-encoding")
        if transfer_encoding:
            self._reject_request(
                400,
                "unsupported_transfer_encoding",
                "transfer-encoding is not supported; send a content-length",
                request_id=request_id,
            )
            return None
        lengths = self.headers.get_all("content-length") or []
        raw_length = lengths[0] if len(lengths) == 1 else ""
        if not raw_length:
            self._reject_request(
                411,
                "length_required",
                "content-length is required",
                request_id=request_id,
            )
            return None
        if not all("0" <= character <= "9" for character in raw_length):
            self._reject_request(
                400,
                "invalid_content_length",
                "content-length must be a non-negative decimal integer",
                request_id=request_id,
            )
            return None
        normalized_length = raw_length.lstrip("0") or "0"
        if len(normalized_length) > len(str(MAX_REQUEST_BYTES)):
            self._reject_request(
                413,
                "request_too_large",
                "request body exceeds 1 MiB",
                request_id=request_id,
            )
            return None
        length = int(normalized_length)
        if length > MAX_REQUEST_BYTES:
            self._reject_request(
                413,
                "request_too_large",
                "request body exceeds 1 MiB",
                request_id=request_id,
            )
            return None
        raw_body = self.rfile.read(length)
        if len(raw_body) != length:
            self._reject_request(
                400,
                "incomplete_request",
                "request body is incomplete",
                request_id=request_id,
            )
            return None
        try:
            decoded = json.loads(
                raw_body.decode("utf-8"),
                parse_constant=_json_constant,
            )
        except (RecursionError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            self._reject_request(
                400,
                "invalid_json",
                "request body must be valid JSON",
                request_id=request_id,
            )
            return None
        if not isinstance(decoded, dict):
            self._send_error(
                400,
                "invalid_request",
                "request body must be a JSON object",
                request_id=request_id,
            )
            return None
        return decoded

    def _same_origin(self, value: str) -> bool:
        try:
            parsed = urlsplit(value)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username:
                return False
            host_header = self.headers.get("host")
            if host_header:
                expected = urlsplit(f"//{host_header}")
                expected_host = expected.hostname
                expected_port = expected.port
            else:
                address = self.server.server_address
                expected_host = str(address[0]).strip("[]")
                expected_port = int(address[1])
            parsed_port = parsed.port
        except ValueError:
            return False
        if not expected_host:
            return False
        if parsed_port is None:
            parsed_port = 443 if parsed.scheme == "https" else 80
        if expected_port is None:
            expected_port = 80
        return parsed.hostname.lower() == expected_host.lower() and parsed_port == expected_port

    def _csrf_allowed(self) -> bool:
        """Reject browser-signalled cross-origin mutation requests."""

        origin = self.headers.get("origin")
        referer = self.headers.get("referer")
        fetch_site = (self.headers.get("sec-fetch-site") or "").lower()
        browser_signal = bool(origin or referer or fetch_site or self.headers.get("cookie"))
        if not browser_signal:
            return True
        if self._local_read_only_browser_post():
            return True
        if fetch_site and fetch_site not in {"same-origin", "none"}:
            return False
        if origin and not self._same_origin(origin):
            return False
        if referer and not self._same_origin(referer):
            return False
        if self.headers.get("cookie") and not (origin or referer):
            return False
        return True

    def do_OPTIONS(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if not self._loopback_origin():
            self._send_error(
                405,
                "method_not_allowed",
                "method is not supported for this transport",
                request_id=self._request_id(),
                allow="GET, POST",
            )
            return
        self._send(
            200,
            {"ok": True, "result": {"cors": "loopback-only"}},
            request_id=self._request_id(),
            headers={
                "access-control-allow-methods": "GET, POST, OPTIONS",
                "access-control-allow-headers": "Content-Type, Authorization",
                "access-control-max-age": "300",
            },
        )

    def _dispatch(self, method: str, body: dict[str, Any] | None = None) -> None:
        request_id = self._request_id()
        response = self._api().dispatch(method, self._path(), body)
        self._send_response(response, request_id=request_id)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        try:
            if self._path() == "/livez":
                self._send(
                    200,
                    {"ok": True, "result": {"service": "stateport-api", "status": "live"}},
                    request_id=self._request_id(),
                )
                return
            if self._path() == "/readyz":
                self._send(
                    200,
                    {
                        "ok": True,
                        "result": {
                            "service": "stateport-api",
                            "status": "ready",
                            "ready": True,
                            "authenticationConfigured": self._authenticator().configured,
                        },
                    },
                    request_id=self._request_id(),
                )
                return
            self._dispatch("GET")
        except Exception:  # noqa: BLE001 - never expose transport internals
            self._send_error(500, "internal_error", "the operation failed", request_id=self._request_id())

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        request_id = self._request_id()
        if not self._csrf_allowed():
            self._send_error(
                403,
                "csrf_failed",
                "browser mutation request must be same-origin",
                request_id=request_id,
            )
            return
        body = self._read_json(request_id=request_id)
        if body is None:
            return
        authenticator = self._authenticator()
        if authenticator.configured:
            try:
                authenticated = authenticator.authenticate(self.headers.get("authorization"))
            except AuthError as exc:
                del exc
                self._send_error(
                    401,
                    "authentication_required",
                    "authentication is required",
                    request_id=request_id,
                )
                return
            supplied_actor = body.get("actor")
            if supplied_actor is not None and supplied_actor != authenticated.actor:
                self._send_error(
                    403,
                    "identity_mismatch",
                    "request actor does not match bearer identity",
                    request_id=request_id,
                )
                return
            body = dict(body)
            body["actor"] = authenticated.actor
        try:
            response = self._api().dispatch("POST", self._path(), body)
            self._send_response(response, request_id=request_id)
        except Exception:  # noqa: BLE001 - never expose transport internals
            self._send_error(500, "internal_error", "the operation failed", request_id=request_id)

    def _do_unsupported(self) -> None:
        self._send_error(
            405,
            "method_not_allowed",
            "method is not supported for this transport",
            request_id=self._request_id(),
            allow="GET, POST",
        )

    do_DELETE = _do_unsupported
    do_HEAD = _do_unsupported
    do_PATCH = _do_unsupported
    do_PUT = _do_unsupported
    do_TRACE = _do_unsupported
    do_CONNECT = _do_unsupported

    def send_error(  # noqa: D401 - BaseHTTPRequestHandler hook
        self,
        code: int,
        message: str | None = None,
        explain: str | None = None,
    ) -> None:
        """Keep even unknown HTTP verbs/errors in the JSON contract."""

        del message, explain
        if code == 501:
            self._send_error(
                405,
                "method_not_allowed",
                "method is not supported for this transport",
                request_id=self._request_id(),
                allow="GET, POST",
            )
            return
        self._send_error(
            code,
            "invalid_request",
            "the HTTP request could not be parsed",
            request_id=self._request_id(),
        )

    def log_message(self, fmt: str, *args: object) -> None:
        # Keep the adapter quiet for embedders and deterministic smoke tests.
        del fmt, args


def serve(
    workspace: Path | str,
    host: str = "127.0.0.1",
    port: int = 8790,
    *,
    identities: dict[str, Any] | None = None,
    operator_allowed_capabilities: list[str] | None = None,
    authenticator: Authenticator | None = None,
    container_engine: str = "podman",
    runner_image: str = "stateport/runner:local",
    allow_public_bind: bool = False,
    poll_interval: float = DEFAULT_POLL_INTERVAL,
    observer: OperationalObserver | None = None,
) -> None:
    """Serve the local governed API until interrupted."""
    interval = _bounded_poll_interval(poll_interval)
    server = create_server(
        workspace,
        host,
        port,
        identities=identities,
        operator_allowed_capabilities=operator_allowed_capabilities,
        authenticator=authenticator,
        container_engine=container_engine,
        runner_image=runner_image,
        allow_public_bind=allow_public_bind,
        observer=observer,
    )
    try:
        server.serve_forever(poll_interval=interval)
    finally:
        server.server_close()


def create_server(
    workspace: Path | str,
    host: str = "127.0.0.1",
    port: int = 8790,
    *,
    identities: dict[str, Any] | None = None,
    operator_allowed_capabilities: list[str] | None = None,
    authenticator: Authenticator | None = None,
    container_engine: str = "podman",
    runner_image: str = "stateport/runner:local",
    allow_public_bind: bool = False,
    observer: OperationalObserver | None = None,
) -> ThreadingHTTPServer:
    """Build the one local API server without starting a second service."""

    _validate_bind_host(host, allow_public_bind)
    resolved_authenticator = authenticator if authenticator is not None else BearerAuthenticator()
    _require_authenticated_authorization_config(
        identities,
        operator_allowed_capabilities,
        resolved_authenticator,
    )
    api = GovernedAPI(
        workspace,
        identities=identities,
        operator_allowed_capabilities=operator_allowed_capabilities,
        container_engine=container_engine,
        runner_image=runner_image,
    )
    server = ThreadingHTTPServer((host, port), _Handler)
    server.daemon_threads = True
    server.governed_api = api  # type: ignore[attr-defined]
    server.authenticator = resolved_authenticator  # type: ignore[attr-defined]
    server.operational_observer = observer or NullObserver("stateport-api")  # type: ignore[attr-defined]
    return server


def start_server(
    workspace: Path | str,
    host: str = "127.0.0.1",
    port: int = 8790,
    *,
    identities: dict[str, Any] | None = None,
    operator_allowed_capabilities: list[str] | None = None,
    authenticator: Authenticator | None = None,
    container_engine: str = "podman",
    runner_image: str = "stateport/runner:local",
    allow_public_bind: bool = False,
    poll_interval: float = DEFAULT_POLL_INTERVAL,
    observer: OperationalObserver | None = None,
) -> ThreadingHTTPServer:
    """Start the API in one daemon thread and return its server handle."""

    interval = _bounded_poll_interval(poll_interval)
    server = create_server(
        workspace,
        host,
        port,
        identities=identities,
        operator_allowed_capabilities=operator_allowed_capabilities,
        authenticator=authenticator,
        container_engine=container_engine,
        runner_image=runner_image,
        allow_public_bind=allow_public_bind,
        observer=observer,
    )
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": interval},
        name="stateport-api",
        daemon=True,
    )
    server._stateport_thread = thread  # type: ignore[attr-defined]
    thread.start()
    return server


def shutdown_server(server: ThreadingHTTPServer, *, timeout: float = 5.0) -> None:
    """Stop a server and boundedly join a thread started by ``start_server``."""

    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or timeout != timeout
        or timeout < 0
        or timeout > 30
    ):
        raise ValueError("shutdown timeout must be between 0 and 30 seconds")
    thread = getattr(server, "_stateport_thread", None)
    if thread is not None and thread is threading.current_thread():
        server.server_close()
        return
    if isinstance(thread, threading.Thread) and not thread.is_alive():
        server.server_close()
        return
    if thread is None:
        shutdown_event = getattr(server, "_BaseServer__is_shut_down", None)
        if shutdown_event is not None and shutdown_event.is_set():
            server.server_close()
            return
    server.shutdown()
    server.server_close()
    if isinstance(thread, threading.Thread):
        thread.join(timeout=timeout)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="stateport-api")
    parser.add_argument("--workspace", default=".")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8790, type=int)
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
    identities: dict[str, Any] | None = None
    raw_identities = os.environ.get("STATEPORT_IDENTITIES_JSON")
    if raw_identities:
        try:
            decoded = json.loads(raw_identities)
        except json.JSONDecodeError as exc:
            parser.error(f"STATEPORT_IDENTITIES_JSON must be valid JSON: {exc}")
        if not isinstance(decoded, dict):
            parser.error("STATEPORT_IDENTITIES_JSON must be a JSON object")
        identities = decoded
    raw_capabilities = os.environ.get("STATEPORT_OPERATOR_CAPABILITIES", "")
    capabilities = [item.strip() for item in raw_capabilities.split(",") if item.strip()]
    raw_tokens = os.environ.get("STATEPORT_AUTH_TOKENS_JSON")
    raw_oidc = os.environ.get("STATEPORT_OIDC_CONFIG_JSON")
    if raw_tokens and raw_oidc:
        parser.error(
            "STATEPORT_AUTH_TOKENS_JSON and STATEPORT_OIDC_CONFIG_JSON are mutually exclusive"
        )
    authenticator: Authenticator = BearerAuthenticator()
    if raw_tokens:
        try:
            authenticator = BearerAuthenticator.from_json_mapping(json.loads(raw_tokens))
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            parser.error(f"STATEPORT_AUTH_TOKENS_JSON is invalid: {exc}")
    elif raw_oidc:
        try:
            authenticator = OIDCAuthenticator.from_mapping(json.loads(raw_oidc))
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            parser.error(f"STATEPORT_OIDC_CONFIG_JSON is invalid: {exc}")
    try:
        _require_authenticated_authorization_config(
            identities,
            capabilities,
            authenticator,
        )
    except ValueError as exc:
        parser.error(str(exc))
    try:
        observer = observer_from_environment("stateport-api")
    except ValueError as exc:
        parser.error(str(exc))
    serve(
        args.workspace,
        args.host,
        args.port,
        identities=identities,
        operator_allowed_capabilities=capabilities,
        authenticator=authenticator,
        container_engine=os.environ.get("STATEPORT_CONTAINER_ENGINE", "podman"),
        runner_image=os.environ.get("STATEPORT_RUNNER_IMAGE", "stateport/runner:local"),
        allow_public_bind=args.allow_public_bind,
        observer=observer,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
