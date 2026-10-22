"""HTTP surface of the keep-up loop: ``/v1/models`` (docs/API_CONTRACT_WEB.md, "Model routes").

The AppServer handler has already checked the Host header and the session
cookie, and (for POST and DELETE) the same-origin + CSRF mutation guard,
before any function here runs. Mutations additionally need the
``application.provider.manage`` actor permission and are refused in the
validation release profile, like every provider action.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import unquote

from .model_routes import ModelRoutesError

_MANAGE = "application.provider.manage"


def is_models_path(path: str) -> bool:
    return path == "/v1/models" or path.startswith("/v1/models/")


def _parts(path: str) -> list[str]:
    return [unquote(part) for part in path.split("/") if part]


def _shape(body: dict[str, object], required: set[str], optional: frozenset[str] | set[str] = frozenset()) -> None:
    keys = set(body)
    if not required <= keys or keys - required - set(optional):
        raise ModelRoutesError("request_shape_invalid", "request shape is invalid", 400)


def _authorize_mutation(handler: Any) -> None:
    server = handler.server
    try:
        server.require_actor_permission(_MANAGE)
    except PermissionError:
        raise ModelRoutesError("model_routes_access_denied", "model route changes are not permitted for this actor", 403) from None
    if not getattr(server, "_provider_execution_allowed", True):
        raise ModelRoutesError(
            "model_routes_disabled", "model routes are disabled in the validation release profile", 403
        )


def _send_projection(handler: Any) -> None:
    handler._send(200, {"ok": True, "result": handler.server.model_routes.projection()})


def handle_get(handler: Any, path: str) -> None:
    routes = handler.server.model_routes
    try:
        if path == "/v1/models":
            _send_projection(handler)
            return
        parts = _parts(path)
        if len(parts) == 4 and parts[:3] == ["v1", "models", "runs"]:
            handler._send(200, {"ok": True, "result": routes.run_status(parts[3])})
            return
        handler._error(404, "model route not found", "not_found")
    except ModelRoutesError as exc:
        handler._error(exc.status, exc.message[:512], exc.code)


def handle_post(handler: Any, path: str, body: dict[str, object]) -> None:
    server = handler.server
    routes = server.model_routes
    by = str(getattr(server, "actor_id", "owner"))
    try:
        _authorize_mutation(handler)
        parts = _parts(path)
        if path == "/v1/models/consent":
            _shape(body, {"destination", "termsSha256"})
            routes.grant_consent(body["destination"], body["termsSha256"], by=by)
            _after_route_change(server)
            _send_projection(handler)
            return
        if path == "/v1/models/observe":
            _shape(body, set())
            routes.observe(by=by)
            _send_projection(handler)
            return
        if path == "/v1/models/evaluate":
            _shape(body, {"models"})
            started = routes.start_evaluation(body["models"], by=by, trigger="owner")
            handler._send(200, {"ok": True, "result": started})
            return
        if path == "/v1/models/route":
            _shape(body, {"actionClass", "model", "pin"})
            routes.set_route(body["actionClass"], body["model"], body["pin"], by=by)
            _after_route_change(server)
            _send_projection(handler)
            return
        if path == "/v1/models/lease":
            _shape(body, {"enabled"}, {"days"})
            routes.set_lease(body["enabled"], body.get("days"), by=by)
            _send_projection(handler)
            return
        if len(parts) == 4 and parts[:3] == ["v1", "models", "proposal"]:
            _shape(body, {"decision"})
            routes.decide_proposal(parts[3], body["decision"], by=by)
            _after_route_change(server)
            _send_projection(handler)
            return
        handler._error(404, "model route not found", "not_found")
    except ModelRoutesError as exc:
        handler._error(exc.status, exc.message[:512], exc.code)


def handle_delete(handler: Any, path: str, body: dict[str, object]) -> None:
    server = handler.server
    try:
        _authorize_mutation(handler)
        if path != "/v1/models/consent":
            handler._error(404, "model route not found", "not_found")
            return
        _shape(body, set(), {"destination"})
        server.model_routes.withdraw_consent(body.get("destination", "opencode-free"), by=str(getattr(server, "actor_id", "owner")))
        _after_route_change(server)
        _send_projection(handler)
    except ModelRoutesError as exc:
        handler._error(exc.status, exc.message[:512], exc.code)


def _after_route_change(server: Any) -> None:
    ensure = getattr(server, "ensure_routed_assistant", None)
    if callable(ensure):
        try:
            ensure()
        except Exception:  # noqa: BLE001 - chat start-up never fails the route mutation
            pass


__all__ = ["handle_delete", "handle_get", "handle_post", "is_models_path"]
