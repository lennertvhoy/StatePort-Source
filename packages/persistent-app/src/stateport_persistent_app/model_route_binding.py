"""Bind the keep-up loop's routes to their callers (agent actions and chat).

``resolve_agent_route(action_class)`` is the one call agent actions (WP2) make
before running anything: it returns the exact ``SandboxRoute`` to pass to
``agent_sandbox.run_in_sandbox`` or a typed ``RouteRefusal`` whose message the
UI can show as is. Refusal codes:

- ``route_not_consented``: the opencode-free destination has no current consent;
- ``no_measured_route``: consented, no route, and no measured free model;
- ``route_not_configured``: consented and measured, but no route is chosen
  (or no ``ModelRoutes`` is bound in this process);
- ``harness_unavailable``: the pinned OpenCode executable is missing.

``chat_routing`` gives the chat path its route selection only. The chat
subprocess environment (all tools denied) is owned by the sandbox work (WP1),
not by this module.

AppServer calls ``bind(model_routes)`` once at startup.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import threading
from typing import Any

from .model_routes import (
    ACTION_CLASSES,
    FREE_ROUTE_ALLOW_HOSTS,
    HARNESS,
    ModelRoutes,
    ResolvedRoute,
    RouteRefusal,
    destination_of,
    is_free_model,
)

_bound: ModelRoutes | None = None
_bound_lock = threading.Lock()

#: Tool profile per action class (agent-sandbox.md: "none" for chat, "edit" for agent actions).
TOOLS_BY_CLASS = {"chat": "none", "agent.edit-state": "edit"}


def bind(routes: ModelRoutes | None) -> None:
    """Make ``routes`` the process-wide authority for route resolution (None unbinds)."""
    global _bound
    with _bound_lock:
        _bound = routes


def bound() -> ModelRoutes | None:
    with _bound_lock:
        return _bound


def resolve_agent_route(action_class: str, *, routes: ModelRoutes | None = None) -> Any:
    """Return a ``SandboxRoute`` for ``action_class`` or a ``RouteRefusal``.

    Never raises for an ordinary refusal; the caller checks
    ``isinstance(result, RouteRefusal)`` (or ``result.status == "refused"``).
    """
    from .agent_sandbox import SandboxRoute

    authority = routes if routes is not None else bound()
    if authority is None:
        return RouteRefusal("route_not_configured", "Model routes are not available in this service.")
    if action_class not in ACTION_CLASSES:
        return RouteRefusal("route_not_configured", "No route is defined for this kind of action.")
    resolved = authority.resolve(action_class)
    if isinstance(resolved, RouteRefusal):
        return resolved
    assert isinstance(resolved, ResolvedRoute)
    return SandboxRoute(
        harness=HARNESS,
        harness_binary=resolved.harness_binary,
        model=resolved.model,
        allow_hosts=FREE_ROUTE_ALLOW_HOSTS,
        credential_file=None,
        tools=TOOLS_BY_CLASS[action_class],
    )


@dataclass(frozen=True)
class ChatRouting:
    """Route selection for one chat invocation."""

    model: str | None          # the consented chat route's model, or None (use the provider profile)
    free_consented: bool       # whether the opencode-free destination has current consent
    refusal: str | None        # the chat route's refusal code when model is None
    policy_digest: str | None

    def route_record(self) -> dict[str, Any] | None:
        if self.model is None:
            return None
        return {
            "actionClass": "chat",
            "model": self.model,
            "destination": destination_of(self.model),
            "policyDigest": self.policy_digest,
        }


def chat_routing(routes: ModelRoutes | None = None) -> ChatRouting:
    authority = routes if routes is not None else bound()
    if authority is None:
        return ChatRouting(None, False, "route_not_configured", None)
    consented = authority.consented()
    resolved = authority.resolve("chat")
    if isinstance(resolved, ResolvedRoute):
        return ChatRouting(resolved.model, consented, None, resolved.policy_digest)
    return ChatRouting(None, consented, resolved.code, None)


def catalogue_cache_path(routes: ModelRoutes | None = None) -> Path | None:
    """The service-refreshed raw ``models.json`` (read-only for the sandbox), or None.

    The sandbox pre-seeds each fresh per-run OpenCode HOME with it
    (``$XDG_CACHE_HOME/opencode/models.json``) so a cold HOME does not fall
    back to the binary's stale bundled catalogue snapshot.
    """
    authority = routes if routes is not None else bound()
    return authority.catalogue_cache_path() if authority is not None else None


def chat_route_resolver(routes: ModelRoutes) -> Any:
    """A zero-argument callable for ProviderRouter (bound to one ModelRoutes)."""
    return lambda: chat_routing(routes)


def free_model_requires_consent(model_id: str, routing: ChatRouting | None) -> bool:
    """True when a call to ``model_id`` would use the free route without consent."""
    return routing is not None and is_free_model(model_id) and not routing.free_consented


__all__ = [
    "ChatRouting",
    "RouteRefusal",
    "TOOLS_BY_CLASS",
    "bind",
    "bound",
    "catalogue_cache_path",
    "chat_route_resolver",
    "chat_routing",
    "free_model_requires_consent",
    "resolve_agent_route",
]
