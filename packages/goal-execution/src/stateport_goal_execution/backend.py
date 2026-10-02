from __future__ import annotations

from typing import Any

from .sandbox import SANDBOX_BACKEND_ID


_BACKEND_REGISTRY: dict[str, Any] = {}


def _init_backends() -> None:
    if _BACKEND_REGISTRY:
        return
    # This provider cannot execute managed work until the sealed runtime and
    # separate validator qualify. Listing that fact must not probe the operator's
    # CLI, launch Podman, or pull a mutable image on an ordinary UI request.
    _BACKEND_REGISTRY["opencode_container"] = {
        "backend": None,
        "ready": False,
        "readiness": None,
        "capabilities": None,
        # Honest reason: the rootless-container OpenCode agent backend exists in
        # execution-host but is self-declared not production eligible and has no
        # separate confined validator integrated, so it is never offered.
        "error": "container_agent_backend_not_production_eligible",
    }
    # The bubblewrap-sandboxed backend is the only offered governed backend. Its
    # readiness is a real smoke run (sandbox.probe), made on demand and cached,
    # never at registry initialisation or when merely listing.
    _BACKEND_REGISTRY[SANDBOX_BACKEND_ID] = {
        "backend": None,
        "ready": False,
        "readiness": "probed_on_demand",
        "capabilities": None,
        "error": "readiness_not_probed",
    }


def register_synthetic_test_backend() -> None:
    """Register the test-only synthetic backend; tests must call this explicitly.

    The "fake" backend fabricates provider-free contract-inspection results
    without executing anything. It is never registered by default: production
    and release services must observe a typed ``goal_backend_unavailable``
    refusal instead of a fabricated success.
    """

    _init_backends()
    _BACKEND_REGISTRY["fake"] = {
        "backend": None,
        "ready": True,
        "readiness": None,
        "capabilities": None,
    }


def get_backend(backend_id: str) -> dict[str, Any] | None:
    _init_backends()
    return _BACKEND_REGISTRY.get(backend_id)


def list_backends() -> dict[str, Any]:
    _init_backends()
    return {
        bid: {
            "ready": info.get("ready", False),
            "testOnly": bid == "fake",
            "error": info.get("error"),
        }
        for bid, info in _BACKEND_REGISTRY.items()
    }


def sandbox_readiness() -> tuple[bool, str]:
    """Probe (cached) whether the bubblewrap sandbox is usable on this host."""

    from .sandbox import probe

    return probe()


def backend_effective_profile(backend_id: str) -> str:
    if backend_id == "fake":
        return "provider-free-inspection"
    if backend_id == SANDBOX_BACKEND_ID:
        return "sandboxed-validation"
    return "opencode-container-execution"


def backend_effective_read_scope(backend_id: str) -> tuple[str, ...]:
    if backend_id == "fake":
        return ("application.yaml", "actions.yaml")
    return ("staging_workspace",)


def backend_effective_write_scope(backend_id: str) -> tuple[str, ...]:
    if backend_id == "fake":
        return ("stateport-operational-records",)
    return ("staging_workspace",)
