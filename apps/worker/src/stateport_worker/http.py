"""Health surface and optional local queue-consumer loop for StatePort."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from time import perf_counter
from typing import Any

from container_runner import ContainerExecutor
from stateport_observability import (
    NullObserver,
    OperationalObserver,
    observer_from_environment,
)
from stateport_observability.events import exception_digest
from stateport_worker.service import WorkerService


def _execution_enabled(value: str | None) -> bool:
    normalized = (value or "").strip().lower()
    if normalized in {"", "0", "false", "no"}:
        return False
    if normalized in {"1", "true", "yes"}:
        return True
    raise ValueError("STATEPORT_WORKER_EXECUTION_ENABLED must be true or false")


def _is_loopback_host(host: str) -> bool:
    normalized = host.strip().lower().rstrip(".")
    if normalized == "localhost":
        return True
    if normalized.startswith("[") and normalized.endswith("]"):
        normalized = normalized[1:-1]
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _validate_bind_host(host: str, allow_public_bind: bool) -> None:
    if not isinstance(host, str) or not host.strip():
        raise ValueError("worker host must be an explicit loopback address")
    if not _is_loopback_host(host) and not allow_public_bind:
        raise ValueError(
            "refusing non-loopback worker bind; pass --allow-public-bind only for an intentional container or host boundary"
        )


def _payload(
    *,
    execution_enabled: bool = False,
    last_job_status: str | None = None,
    consecutive_errors: int = 0,
    last_error_code: str | None = None,
    last_error_digest: str | None = None,
    ready: bool = True,
) -> dict[str, Any]:
    if not execution_enabled:
        status = "standby"
    elif consecutive_errors > 0:
        status = "degraded"
    else:
        status = "ready"
    return {
        "ok": True,
        "result": {
            "service": "stateport-worker",
            "status": status,
            "mode": "queue",
            "executionEnabled": execution_enabled,
            "containerExecutor": "enabled" if execution_enabled else "disabled",
            "queueClaiming": execution_enabled,
            "networkEnabled": False,
            "lastJobStatus": last_job_status,
            "consecutiveErrors": consecutive_errors,
            "lastErrorCode": last_error_code,
            "lastErrorDigest": last_error_digest,
            "ready": ready,
        },
    }


class _WorkerLoop:
    def __init__(
        self,
        service: WorkerService,
        poll_seconds: float,
        *,
        observer: OperationalObserver | None = None,
    ):
        self.service = service
        self.poll_seconds = poll_seconds
        self.stop_event = threading.Event()
        self.last_job_status: str | None = None
        self.consecutive_errors: int = 0
        self.last_error_code: str | None = None
        self.last_error_digest: str | None = None
        self.observer = observer or NullObserver("stateport-worker")
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=max(3.0, self.poll_seconds + 1.0))

    def _run(self) -> None:
        while not self.stop_event.is_set():
            try:
                job = self.service.run_once()
                if job is None:
                    self.stop_event.wait(self.poll_seconds)
                else:
                    self.last_job_status = str(job.get("status", "unknown"))
                    job_id = job.get("jobId") or job.get("id")
                    self.observer.emit(
                        "worker.job.completed",
                        level="warning" if self.last_job_status == "failed" else "info",
                        jobId=job_id if isinstance(job_id, str) else None,
                        workerId=getattr(self.service, "worker_id", None),
                        resultCode=self.last_job_status,
                    )
                    if job.get("status") == "queued":
                        self.stop_event.wait(self.poll_seconds)
                self.consecutive_errors = 0
                self.last_error_code = None
                self.last_error_digest = None
            except Exception as exc:  # noqa: BLE001 - keep health available, fail job service-side
                self.last_job_status = "worker_error"
                self.consecutive_errors += 1
                self.last_error_code = "worker_loop_exception"
                self.last_error_digest = exception_digest(exc)
                self.observer.emit(
                    "worker.loop.failed",
                    level="error",
                    resultCode=self.last_error_code,
                    errorDigest=self.last_error_digest,
                    workerId=getattr(self.service, "worker_id", None),
                )
                self.stop_event.wait(self.poll_seconds)


class _Handler(BaseHTTPRequestHandler):
    server_version = "StatePortWorker/1"

    def handle_one_request(self) -> None:
        self._stateport_request_id = None
        self._stateport_request_started = perf_counter()
        self._stateport_request_observed = False
        super().handle_one_request()

    def _observer(self) -> OperationalObserver:
        return getattr(self.server, "operational_observer", NullObserver("stateport-worker"))

    def _request_id(self) -> str:
        request_id = getattr(self, "_stateport_request_id", None)
        if request_id is None:
            request_id = f"sp-{os.urandom(8).hex()}"
            self._stateport_request_id = request_id
        return request_id

    def _ready(self) -> bool:
        if not bool(getattr(self.server, "execution_enabled", False)):
            return True
        loop = getattr(self.server, "worker_loop", None)
        return isinstance(loop, _WorkerLoop) and loop.thread.is_alive()

    def do_GET(self) -> None:  # noqa: N802
        route = self.path.split("?", 1)[0]
        if route == "/livez":
            self._send(200, {"ok": True, "result": {"service": "stateport-worker", "status": "live"}})
            return
        if route not in {"/health", "/readyz", "/v1/capabilities"}:
            self._send(404, {"ok": False, "error": {"code": "not_found", "message": "route was not found"}})
            return
        loop = getattr(self.server, "worker_loop", None)
        ready = self._ready()
        self._send(
            200 if route != "/readyz" or ready else 503,
            _payload(
                execution_enabled=bool(getattr(self.server, "execution_enabled", False)),
                last_job_status=getattr(loop, "last_job_status", None),
                consecutive_errors=getattr(loop, "consecutive_errors", 0),
                last_error_code=getattr(loop, "last_error_code", None),
                last_error_digest=getattr(loop, "last_error_digest", None),
                ready=ready,
            ),
        )

    def do_POST(self) -> None:  # noqa: N802
        self._send(405, {"ok": False, "error": {"code": "method_not_allowed", "message": "worker control is queue-only"}})

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        data = (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(data)))
        self.send_header("cache-control", "no-store")
        self.send_header("x-content-type-options", "nosniff")
        self.send_header("x-request-id", self._request_id())
        self.end_headers()
        self.wfile.write(data)
        if not getattr(self, "_stateport_request_observed", False):
            self._stateport_request_observed = True
            error = payload.get("error")
            result_code = (
                error.get("code", "request_failed")
                if isinstance(error, dict)
                else "ok"
            )
            route = self.path.split("?", 1)[0] or "/"
            self._observer().emit(
                "http.request.completed",
                level="debug" if route in {"/health", "/livez", "/readyz"} and status < 400 else (
                    "warning" if status >= 400 else "info"
                ),
                requestId=self._request_id(),
                method=getattr(self, "command", None) or "unknown",
                route=route,
                status=status,
                responseBytes=len(data),
                durationMs=max(
                    0.0,
                    (perf_counter() - getattr(self, "_stateport_request_started", perf_counter())) * 1000.0,
                ),
                resultCode=result_code,
            )

    def log_message(self, fmt: str, *args: object) -> None:
        del fmt, args


def _capabilities(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="stateport-worker")
    parser.add_argument("--workspace", default=os.environ.get("STATEPORT_WORKSPACE", "/workspace"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--allow-public-bind", action="store_true")
    parser.add_argument("--port", type=int, default=8791)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--worker-id", default=os.environ.get("STATEPORT_WORKER_ID", f"local-{os.getpid()}"))
    args = parser.parse_args(argv)
    try:
        _validate_bind_host(args.host, args.allow_public_bind)
    except ValueError as exc:
        parser.error(str(exc))
    try:
        enabled = _execution_enabled(os.environ.get("STATEPORT_WORKER_EXECUTION_ENABLED"))
    except ValueError as exc:
        parser.error(str(exc))
    try:
        observer = observer_from_environment("stateport-worker")
    except ValueError as exc:
        parser.error(str(exc))
    service: WorkerService | None = None
    if enabled:
        capabilities = _capabilities(os.environ.get("STATEPORT_OPERATOR_CAPABILITIES", ""))
        if "execute_container" not in capabilities:
            parser.error("enabled worker requires execute_container in STATEPORT_OPERATOR_CAPABILITIES")
        try:
            timeout_seconds = int(os.environ.get("STATEPORT_EXECUTOR_TIMEOUT_SECONDS", "300"))
            executor = ContainerExecutor(
                engine=os.environ.get("STATEPORT_CONTAINER_ENGINE", "podman"),
                image=os.environ.get("STATEPORT_RUNNER_IMAGE", "stateport/runner:local"),
                allow_execution=True,
                timeout_seconds=timeout_seconds,
            )
            service = WorkerService(
                Path(args.workspace),
                executor=executor,
                worker_id=args.worker_id,
                operator_allowed_capabilities=capabilities,
            )
        except (TypeError, ValueError) as exc:
            parser.error(str(exc))
    if args.once:
        if service is None:
            parser.error("--once requires STATEPORT_WORKER_EXECUTION_ENABLED=true")
        result = service.run_once()
        print(json.dumps({"ok": True, "job": result}, sort_keys=True))
        return 0 if result is None or result.get("status") == "succeeded" else 1

    worker_loop = (
        _WorkerLoop(service, poll_seconds=1.0, observer=observer)
        if service is not None
        else None
    )
    server = ThreadingHTTPServer((args.host, args.port), _Handler)
    server.execution_enabled = enabled  # type: ignore[attr-defined]
    server.worker_loop = worker_loop  # type: ignore[attr-defined]
    server.operational_observer = observer  # type: ignore[attr-defined]
    if worker_loop is not None:
        worker_loop.start()
    try:
        server.serve_forever()
    finally:
        server.server_close()
        if worker_loop is not None:
            worker_loop.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
