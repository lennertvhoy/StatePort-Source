from __future__ import annotations

from pathlib import Path
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "packages" / "execution-host" / "src"))
_source_root = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(_source_root / "packages" / "opencode-adapter" / "src"))
sys.path.insert(0, str(_source_root / "packages" / "container-opencode" / "src"))

from execution_host.opencode_backend import OpenCodeContainerBackend
from execution_host.contracts import BackendCapabilities


_BACKEND_REGISTRY: dict[str, Any] = {}


def _init_backends() -> None:
    if _BACKEND_REGISTRY:
        return
    try:
        opencode = OpenCodeContainerBackend()
        readiness = opencode.container_readiness()
        # Container escape checks prove the agent's staging boundary only.
        # Closure also requires running the exact validation contract without
        # executing agent-owned staging content on the host.  Until that
        # isolated validator exists, keep the managed backend capability-gated.
        _BACKEND_REGISTRY["opencode_container"] = {
            "backend": opencode,
            "ready": False,
            "readiness": readiness,
            "capabilities": opencode.capabilities(),
            "error": (
                "sandboxed_validation_not_implemented"
                if readiness is not None and readiness.passed()
                else "container_enforcement_unavailable"
            ),
        }
    except Exception as exc:
        _BACKEND_REGISTRY["opencode_container"] = {
            "backend": None,
            "ready": False,
            "readiness": None,
            "error": str(exc),
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


def backend_effective_profile(backend_id: str) -> str:
    if backend_id == "fake":
        return "provider-free-inspection"
    return "opencode-container-execution"


def backend_effective_read_scope(backend_id: str) -> tuple[str, ...]:
    if backend_id == "fake":
        return ("application.yaml", "actions.yaml")
    return ("staging_workspace",)


def backend_effective_write_scope(backend_id: str) -> tuple[str, ...]:
    if backend_id == "fake":
        return ("stateport-operational-records",)
    return ("staging_workspace",)
