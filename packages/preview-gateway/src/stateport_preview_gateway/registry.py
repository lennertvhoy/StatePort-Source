"""Authenticated preview route registry with receipted mutations.

Every mutation runs under a single-writer lock, rewrites the route document
through an atomic replace, and appends a chained
``stateport.preview-route-receipt/v1`` receipt.  A revision rollback rewrites
the route atomically: concurrent proxied requests observe either the old or
the new binding, never a partial one.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import fcntl
import json
import os
from pathlib import Path
import secrets
import stat
import tempfile
from typing import Any, Callable, Iterator, Mapping

from .contracts import (
    MAX_ACTIVE_ROUTES,
    RECOVERY_SCHEMA,
    RECOVERY_STATUS,
    ROUTE_SCHEMA,
    RECEIPT_SCHEMA,
    UPSTREAM_HOST,
    actor_id as _actor_id,
    bounded_text,
    canonical_bytes,
    capsule_id as _capsule_id,
    parse_timestamp,
    receipt_digest,
    revision_digest as _revision_digest,
    route_digest,
    service_id as _service_id,
    ttl_seconds as _ttl_seconds,
    upstream_port as _upstream_port,
    utc_timestamp,
    validate_receipt_document,
    validate_recovery_document,
    validate_receipt_route_binding,
    validate_route_document,
)
from .errors import PreviewGatewayError


MAX_DOCUMENT_BYTES = 256 * 1024


def _ensure_private_directory(path: Path) -> Path:
    if path.is_symlink():
        raise PreviewGatewayError("unsafe_state_root", "preview gateway state root may not be a symlink")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, stat.S_IRWXU)
    return path


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    _ensure_private_directory(path.parent)
    if path.is_symlink():
        raise PreviewGatewayError("unsafe_state_file", "preview route file may not be a symlink")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.write(canonical_bytes(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        temporary = None
        _fsync_directory(path.parent)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _read_json(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise PreviewGatewayError("preview_route_not_found", f"{label} is missing or unsafe")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise PreviewGatewayError("preview_route_invalid", f"{label} could not be read safely") from exc
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise PreviewGatewayError("preview_route_invalid", f"{label} exceeds the document size limit")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PreviewGatewayError("preview_route_invalid", f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise PreviewGatewayError("preview_route_invalid", f"{label} must be a JSON object")
    return value


@contextmanager
def _exclusive_lock(path: Path) -> Iterator[None]:
    _ensure_private_directory(path.parent)
    if path.is_symlink():
        raise PreviewGatewayError("unsafe_lock", "preview gateway lock may not be a symlink")
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise PreviewGatewayError(
                "preview_gateway_busy", "another writer owns the preview gateway registry"
            ) from exc
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


class PreviewRouteRegistry:
    """Single-writer registry of authenticated preview routes."""

    def __init__(
        self,
        root: Path | str,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.root = _ensure_private_directory(Path(root))
        self.routes_root = _ensure_private_directory(self.root / "routes")
        self.receipts_root = _ensure_private_directory(self.root / "receipts")
        self.recovery_root = _ensure_private_directory(self.root / "recovery")
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    # ------------------------------------------------------------------
    # Paths and loading
    # ------------------------------------------------------------------

    def _lock_path(self) -> Path:
        return self.root / ".registry.lock"

    def _route_path(self, route_id: str) -> Path:
        return self.routes_root / f"{route_id}.json"

    def _receipt_dir(self, route_id: str) -> Path:
        return self.receipts_root / route_id

    def _recovery_path(self, route_id: str) -> Path:
        return self.recovery_root / f"{route_id}.json"

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise PreviewGatewayError("preview_clock_invalid", "preview gateway clock must be UTC-aware")
        return value.astimezone(timezone.utc).replace(microsecond=0)

    def _load_route(self, route_id: str) -> dict[str, Any]:
        return validate_route_document(_read_json(self._route_path(route_id), "preview route"))

    def _route_has_receipt_unlocked(self, route: Mapping[str, Any]) -> bool:
        try:
            chain = self.receipts(route["routeId"])
        except PreviewGatewayError:
            return False
        if not chain:
            return False
        validate_receipt_route_binding(route, chain[-1])
        return True

    def _mark_recovery_unlocked(
        self, route_id: str, *, route_digest_value: str | None, reason: str
    ) -> dict[str, Any]:
        record = validate_recovery_document(
            {
                "schema": RECOVERY_SCHEMA,
                "routeId": route_id,
                "routeDigest": route_digest_value,
                "status": RECOVERY_STATUS,
                "reason": reason[:1024],
                "detectedAt": utc_timestamp(self._now()),
            }
        )
        _atomic_json(self._recovery_path(route_id), record)
        return record

    def _recover_unlocked(self) -> list[dict[str, Any]]:
        recovered: list[dict[str, Any]] = []
        for path in sorted(self.routes_root.glob("route_*.json")):
            route_id = path.stem
            try:
                route = self._load_route(route_id)
            except PreviewGatewayError:
                continue
            if self._route_has_receipt_unlocked(route):
                continue
            marker = self._mark_recovery_unlocked(
                route_id,
                route_digest_value=route["routeDigest"],
                reason="route exists without a matching durable receipt",
            )
            recovered.append(marker)
        for directory in sorted(self.receipts_root.glob("route_*")):
            route_id = directory.name
            if self._route_path(route_id).exists():
                continue
            try:
                chain = self.receipts(route_id)
                route_digest_value = chain[-1]["data"].get("routeDigest") if chain else None
            except PreviewGatewayError:
                route_digest_value = None
            marker = self._mark_recovery_unlocked(
                route_id,
                route_digest_value=route_digest_value,
                reason="receipt exists without a durable route",
            )
            recovered.append(marker)
        return recovered

    def _all_routes(self) -> list[dict[str, Any]]:
        routes: list[dict[str, Any]] = []
        for path in sorted(self.routes_root.glob("route_*.json")):
            route = validate_route_document(_read_json(path, "preview route"))
            if self._recovery_path(route["routeId"]).exists() or not self._route_has_receipt_unlocked(route):
                continue
            routes.append(route)
        return routes

    def _status(self, route: Mapping[str, Any], now: datetime) -> str:
        if route["revokedAt"] is not None:
            return "revoked"
        if parse_timestamp(route["expiresAt"], "preview route expiry timestamp") <= now:
            return "expired"
        return "active"

    # ------------------------------------------------------------------
    # Receipts
    # ------------------------------------------------------------------

    def _append_receipt_unlocked(
        self,
        route_id: str,
        *,
        event: str,
        actor: str,
        route_digest_value: str,
        data: Mapping[str, Any],
    ) -> dict[str, Any]:
        existing = self.receipts(route_id)
        receipt: dict[str, Any] = {
            "schema": RECEIPT_SCHEMA,
            "receiptId": f"receipt_{secrets.token_hex(12)}",
            "routeId": route_id,
            "sequence": len(existing) + 1,
            "event": event,
            "actor": actor,
            "createdAt": utc_timestamp(self._now()),
            "data": {**dict(data), "routeDigest": route_digest_value},
            "previousReceiptDigest": None if not existing else existing[-1]["receiptDigest"],
        }
        receipt["receiptDigest"] = receipt_digest(receipt)
        validated = validate_receipt_document(receipt)
        _atomic_json(self._receipt_dir(route_id) / f"{validated['receiptId']}.json", validated)
        return validated

    def receipts(self, route_id: str) -> list[dict[str, Any]]:
        directory = self._receipt_dir(route_id)
        if directory.is_symlink() or not directory.is_dir():
            return []
        chain: list[dict[str, Any]] = []
        for path in sorted(directory.glob("receipt_*.json")):
            chain.append(validate_receipt_document(_read_json(path, "preview receipt")))
        chain.sort(key=lambda receipt: receipt["sequence"])
        previous: str | None = None
        for index, receipt in enumerate(chain, start=1):
            if receipt["sequence"] != index or receipt["previousReceiptDigest"] != previous:
                raise PreviewGatewayError(
                    "receipt_chain_invalid", "preview receipt chain is broken"
                )
            previous = receipt["receiptDigest"]
        return chain

    def recover(self) -> list[dict[str, Any]]:
        with _exclusive_lock(self._lock_path()):
            return self._recover_unlocked()

    def recovery_status(self, route_id: object) -> dict[str, Any] | None:
        with _exclusive_lock(self._lock_path()):
            path = self._recovery_path(str(route_id))
            if not path.exists():
                return None
            return validate_recovery_document(_read_json(path, "preview recovery record"))

    def _mutation_result_unlocked(
        self, route: Mapping[str, Any], receipt: Mapping[str, Any], now: datetime
    ) -> dict[str, Any]:
        return {
            "route": {**dict(route), "status": self._status(route, now)},
            "receipt": dict(receipt),
        }

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------

    def register(
        self,
        *,
        capsule_id: object,
        service_id: object,
        revision_digest: object,
        upstream_port: object,
        ttl_seconds: object,
        actor: object,
    ) -> dict[str, Any]:
        selected_capsule = _capsule_id(capsule_id)
        selected_service = _service_id(service_id)
        selected_revision = _revision_digest(revision_digest)
        selected_port = _upstream_port(upstream_port)
        selected_ttl = _ttl_seconds(ttl_seconds)
        selected_actor = _actor_id(actor)
        now = self._now()
        with _exclusive_lock(self._lock_path()):
            self._recover_unlocked()
            routes = self._all_routes()
            active = [route for route in routes if self._status(route, now) == "active"]
            if any(
                route["capsuleId"] == selected_capsule and route["serviceId"] == selected_service
                for route in active
            ):
                raise PreviewGatewayError(
                    "preview_route_conflict",
                    "an active preview route already binds this capsule and service",
                )
            if len(active) >= MAX_ACTIVE_ROUTES:
                raise PreviewGatewayError(
                    "preview_route_budget_exceeded", "the active preview route budget is exhausted"
                )
            route: dict[str, Any] = {
                "schema": ROUTE_SCHEMA,
                "routeId": f"route_{secrets.token_hex(12)}",
                "capsuleId": selected_capsule,
                "serviceId": selected_service,
                "revisionDigest": selected_revision,
                "upstream": {"host": UPSTREAM_HOST, "port": selected_port},
                "createdAt": utc_timestamp(now),
                "expiresAt": utc_timestamp(now + timedelta(seconds=selected_ttl)),
                "revokedAt": None,
                "revocationReason": None,
            }
            route["routeDigest"] = route_digest(route)
            validated = validate_route_document(route)
            _atomic_json(self._route_path(validated["routeId"]), validated)
            receipt = self._append_receipt_unlocked(
                validated["routeId"],
                event="registered",
                actor=selected_actor,
                route_digest_value=validated["routeDigest"],
                data={
                    "capsuleId": selected_capsule,
                    "serviceId": selected_service,
                    "revisionDigest": selected_revision,
                    "upstream": dict(validated["upstream"]),
                    "expiresAt": validated["expiresAt"],
                },
            )
            return self._mutation_result_unlocked(validated, receipt, now)

    def rewrite(
        self,
        route_id: object,
        *,
        revision_digest: object,
        upstream_port: object,
        actor: object,
    ) -> dict[str, Any]:
        """Atomically rebind a route to a new revision and loopback upstream.

        This is the rollback path: when a deployment rolls a capsule back to
        an exact predecessor revision, the preview route is rewritten in one
        locked, atomic replace so in-flight proxy requests never observe a
        partial binding.
        """

        selected_revision = _revision_digest(revision_digest)
        selected_port = _upstream_port(upstream_port)
        selected_actor = _actor_id(actor)
        now = self._now()
        with _exclusive_lock(self._lock_path()):
            self._recover_unlocked()
            current = self._load_route(str(route_id))
            if not self._route_has_receipt_unlocked(current):
                raise PreviewGatewayError("preview_route_recovery_required", "preview route requires receipt recovery")
            status = self._status(current, now)
            if status == "revoked":
                raise PreviewGatewayError(
                    "preview_route_revoked", "a revoked preview route cannot be rewritten"
                )
            if status == "expired":
                raise PreviewGatewayError(
                    "preview_route_expired", "an expired preview route cannot be rewritten"
                )
            rewritten = dict(current)
            rewritten["revisionDigest"] = selected_revision
            rewritten["upstream"] = {"host": UPSTREAM_HOST, "port": selected_port}
            rewritten["routeDigest"] = route_digest(rewritten)
            validated = validate_route_document(rewritten)
            _atomic_json(self._route_path(validated["routeId"]), validated)
            receipt = self._append_receipt_unlocked(
                validated["routeId"],
                event="rewritten",
                actor=selected_actor,
                route_digest_value=validated["routeDigest"],
                data={
                    "previousRevisionDigest": current["revisionDigest"],
                    "previousUpstream": dict(current["upstream"]),
                    "previousRouteDigest": current["routeDigest"],
                    "revisionDigest": selected_revision,
                    "upstream": dict(validated["upstream"]),
                },
            )
            return self._mutation_result_unlocked(validated, receipt, now)

    def revoke(self, route_id: object, *, reason: object, actor: object) -> dict[str, Any]:
        selected_reason = bounded_text(reason, "preview revocation reason")
        selected_actor = _actor_id(actor)
        with _exclusive_lock(self._lock_path()):
            self._recover_unlocked()
            current = self._load_route(str(route_id))
            if not self._route_has_receipt_unlocked(current):
                raise PreviewGatewayError("preview_route_recovery_required", "preview route requires receipt recovery")
            if current["revokedAt"] is not None:
                raise PreviewGatewayError(
                    "preview_route_revoked", "the preview route is already revoked"
                )
            revoked = dict(current)
            revoked["revokedAt"] = utc_timestamp(self._now())
            revoked["revocationReason"] = selected_reason
            revoked["routeDigest"] = route_digest(revoked)
            validated = validate_route_document(revoked)
            _atomic_json(self._route_path(validated["routeId"]), validated)
            receipt = self._append_receipt_unlocked(
                validated["routeId"],
                event="revoked",
                actor=selected_actor,
                route_digest_value=validated["routeDigest"],
                data={"reason": selected_reason},
            )
            return self._mutation_result_unlocked(validated, receipt, self._now())

    # ------------------------------------------------------------------
    # Resolution and projections
    # ------------------------------------------------------------------

    def resolve(self, capsule: object, service: object) -> dict[str, Any]:
        """Resolve the active route for a capsule/service pair, typed otherwise."""

        selected_capsule = _capsule_id(capsule)
        selected_service = _service_id(service)
        with _exclusive_lock(self._lock_path()):
            self._recover_unlocked()
            now = self._now()
            matches = [
                route
                for route in self._all_routes()
                if route["capsuleId"] == selected_capsule and route["serviceId"] == selected_service
            ]
            if not matches:
                raise PreviewGatewayError(
                    "preview_route_not_found", "no preview route binds this capsule and service"
                )
            route = matches[-1]
            status = self._status(route, now)
            if status == "revoked":
                raise PreviewGatewayError(
                    "preview_route_revoked", "the preview route for this destination was revoked"
                )
            if status == "expired":
                raise PreviewGatewayError(
                    "preview_route_expired", "the preview route for this destination expired"
                )
            return route

    def get(self, route_id: object) -> dict[str, Any]:
        with _exclusive_lock(self._lock_path()):
            self._recover_unlocked()
            route = self._load_route(str(route_id))
            if not self._route_has_receipt_unlocked(route):
                raise PreviewGatewayError("preview_route_recovery_required", "preview route requires receipt recovery")
            return {**route, "status": self._status(route, self._now())}

    def list_routes(self) -> list[dict[str, Any]]:
        with _exclusive_lock(self._lock_path()):
            self._recover_unlocked()
            now = self._now()
            return [
                {**route, "status": self._status(route, now)} for route in self._all_routes()
            ]
