"""Strict preview route and receipt contracts.

The preview gateway binds an opaque ``(capsuleId, serviceId, revisionDigest)``
triple to one loopback upstream.  ``capsuleId`` stays an opaque namespaced
binding owned by the deployment record; the gateway never interprets it.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Mapping

from .errors import PreviewGatewayError


ROUTE_SCHEMA = "stateport.preview-route/v1"
RECEIPT_SCHEMA = "stateport.preview-route-receipt/v1"
RECOVERY_SCHEMA = "stateport.preview-route-recovery/v1"

ROUTE_ID = re.compile(r"route_[0-9a-f]{24}\Z")
RECEIPT_ID = re.compile(r"receipt_[0-9a-f]{24}\Z")
CAPSULE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{1,127}\Z")
SERVICE_ID = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
ACTOR = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")

RECEIPT_EVENTS = frozenset({"registered", "rewritten", "revoked"})
RECOVERY_STATUS = "recovery_required"

# The preview namespace may never shadow or reach StatePort's own engine,
# metadata, or control-plane surfaces.  These names fail closed at route
# registration and again at proxy resolution.
RESERVED_DESTINATIONS = frozenset(
    {
        "api",
        "control-plane",
        "engine",
        "engine-socket",
        "health",
        "metadata",
        "session",
        "v1",
    }
)

MAX_ACTIVE_ROUTES = 64
MAX_TTL_SECONDS = 30 * 86_400
UPSTREAM_HOST = "127.0.0.1"


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest_value(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def utc_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_timestamp(value: object, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise PreviewGatewayError("preview_route_invalid", f"{label} is invalid") from exc
    if (
        not isinstance(value, str)
        or parsed.tzinfo is None
        or parsed.utcoffset() != timezone.utc.utcoffset(parsed)
        or parsed.microsecond
        or value != parsed.isoformat().replace("+00:00", "Z")
    ):
        raise PreviewGatewayError("preview_route_invalid", f"{label} is invalid")
    return parsed


def bounded_text(value: object, label: str, *, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\n" in value or "\r" in value:
        raise PreviewGatewayError("preview_route_invalid", f"{label} is invalid")
    return value


def _identifier(value: object, label: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise PreviewGatewayError("preview_route_invalid", f"{label} is invalid")
    return value


def capsule_id(value: object) -> str:
    selected = _identifier(value, "preview capsule id", CAPSULE_ID)
    if selected.lower() in RESERVED_DESTINATIONS:
        raise PreviewGatewayError(
            "preview_destination_refused",
            "preview destinations may not name StatePort engine, metadata, or control-plane surfaces",
        )
    return selected


def service_id(value: object) -> str:
    selected = _identifier(value, "preview service id", SERVICE_ID)
    if selected.lower() in RESERVED_DESTINATIONS:
        raise PreviewGatewayError(
            "preview_destination_refused",
            "preview destinations may not name StatePort engine, metadata, or control-plane surfaces",
        )
    return selected


def revision_digest(value: object) -> str:
    return _identifier(value, "preview revision digest", DIGEST)


def upstream_port(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65_535:
        raise PreviewGatewayError("preview_route_invalid", "preview upstream port is invalid")
    return value


def ttl_seconds(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_TTL_SECONDS:
        raise PreviewGatewayError("preview_route_invalid", "preview route ttl is invalid")
    return value


def actor_id(value: object) -> str:
    return _identifier(value, "preview receipt actor", ACTOR)


def route_digest(route: Mapping[str, Any]) -> str:
    return digest_value({key: value for key, value in route.items() if key != "routeDigest"})


def receipt_digest(receipt: Mapping[str, Any]) -> str:
    return digest_value({key: value for key, value in receipt.items() if key != "receiptDigest"})


def validate_route_document(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise PreviewGatewayError("preview_route_invalid", "preview route must be an object")
    expected = {
        "schema",
        "routeId",
        "capsuleId",
        "serviceId",
        "revisionDigest",
        "upstream",
        "createdAt",
        "expiresAt",
        "revokedAt",
        "revocationReason",
        "routeDigest",
    }
    if set(value) != expected:
        raise PreviewGatewayError("preview_route_invalid", "preview route has unknown or missing fields")
    if value["schema"] != ROUTE_SCHEMA:
        raise PreviewGatewayError("preview_route_invalid", "preview route schema is unsupported")
    _identifier(value["routeId"], "preview route id", ROUTE_ID)
    capsule_id(value["capsuleId"])
    service_id(value["serviceId"])
    revision_digest(value["revisionDigest"])
    upstream = value["upstream"]
    if not isinstance(upstream, Mapping) or set(upstream) != {"host", "port"}:
        raise PreviewGatewayError("preview_route_invalid", "preview upstream is malformed")
    if upstream["host"] != UPSTREAM_HOST:
        raise PreviewGatewayError(
            "preview_upstream_refused", "preview upstreams are loopback-only"
        )
    upstream_port(upstream["port"])
    parse_timestamp(value["createdAt"], "preview route creation timestamp")
    parse_timestamp(value["expiresAt"], "preview route expiry timestamp")
    revoked_at = value["revokedAt"]
    reason = value["revocationReason"]
    if revoked_at is None:
        if reason is not None:
            raise PreviewGatewayError("preview_route_invalid", "preview revocation state is inconsistent")
    else:
        parse_timestamp(revoked_at, "preview revocation timestamp")
        bounded_text(reason, "preview revocation reason")
    if value["routeDigest"] != route_digest(value):
        raise PreviewGatewayError("preview_route_invalid", "preview route digest does not match")
    return dict(value)


def validate_receipt_document(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise PreviewGatewayError("receipt_chain_invalid", "preview receipt must be an object")
    expected = {
        "schema",
        "receiptId",
        "routeId",
        "sequence",
        "event",
        "actor",
        "createdAt",
        "data",
        "previousReceiptDigest",
        "receiptDigest",
    }
    if set(value) != expected:
        raise PreviewGatewayError("receipt_chain_invalid", "preview receipt has unknown or missing fields")
    if value["schema"] != RECEIPT_SCHEMA:
        raise PreviewGatewayError("receipt_chain_invalid", "preview receipt schema is unsupported")
    _identifier(value["receiptId"], "preview receipt id", RECEIPT_ID)
    _identifier(value["routeId"], "preview route id", ROUTE_ID)
    sequence = value["sequence"]
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise PreviewGatewayError("receipt_chain_invalid", "preview receipt sequence is invalid")
    if value["event"] not in RECEIPT_EVENTS:
        raise PreviewGatewayError("receipt_chain_invalid", "preview receipt event is unsupported")
    actor_id(value["actor"])
    parse_timestamp(value["createdAt"], "preview receipt timestamp")
    if not isinstance(value["data"], Mapping):
        raise PreviewGatewayError("receipt_chain_invalid", "preview receipt data is malformed")
    previous = value["previousReceiptDigest"]
    if previous is not None:
        _identifier(previous, "preview previous receipt digest", DIGEST)
    if value["receiptDigest"] != receipt_digest(value):
        raise PreviewGatewayError("receipt_chain_invalid", "preview receipt digest does not match")
    return dict(value)


def validate_recovery_document(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise PreviewGatewayError("receipt_chain_invalid", "preview recovery record must be an object")
    expected = {"schema", "routeId", "routeDigest", "status", "reason", "detectedAt"}
    if set(value) != expected or value["schema"] != RECOVERY_SCHEMA:
        raise PreviewGatewayError("receipt_chain_invalid", "preview recovery record is malformed")
    _identifier(value["routeId"], "preview recovery route id", ROUTE_ID)
    route_digest_value = value["routeDigest"]
    if route_digest_value is not None:
        _identifier(route_digest_value, "preview recovery route digest", DIGEST)
    if value["status"] != RECOVERY_STATUS:
        raise PreviewGatewayError("receipt_chain_invalid", "preview recovery status is unsupported")
    bounded_text(value["reason"], "preview recovery reason", maximum=1024)
    parse_timestamp(value["detectedAt"], "preview recovery timestamp")
    return dict(value)


def validate_receipt_route_binding(
    route: Mapping[str, Any], receipt: Mapping[str, Any]
) -> None:
    if receipt.get("routeId") != route.get("routeId"):
        raise PreviewGatewayError("receipt_chain_invalid", "preview receipt route binding is invalid")
    data = receipt.get("data")
    if not isinstance(data, Mapping) or data.get("routeDigest") != route.get("routeDigest"):
        raise PreviewGatewayError("receipt_chain_invalid", "preview receipt route digest is not bound")
    event = receipt.get("event")
    if event in {"registered", "rewritten"}:
        if data.get("revisionDigest") != route.get("revisionDigest"):
            raise PreviewGatewayError("receipt_chain_invalid", "preview receipt revision is not bound")
        upstream = data.get("upstream")
        if upstream != route.get("upstream"):
            raise PreviewGatewayError("receipt_chain_invalid", "preview receipt upstream is not bound")
    if event == "registered":
        if (
            data.get("capsuleId") != route.get("capsuleId")
            or data.get("serviceId") != route.get("serviceId")
            or data.get("expiresAt") != route.get("expiresAt")
        ):
            raise PreviewGatewayError("receipt_chain_invalid", "preview registration receipt fields are not bound")
    elif event == "revoked":
        if route.get("revokedAt") is None or data.get("reason") != route.get("revocationReason"):
            raise PreviewGatewayError("receipt_chain_invalid", "preview revocation receipt fields are not bound")
