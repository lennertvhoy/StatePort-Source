"""Persistent local StatePort application services.

The package root exposes the established public product API lazily. Importing a
narrow operational module such as ``assistant_work`` must not initialize the
complete application, service launcher, catalog, backup, or infrastructure
dependency graph. This keeps package boundaries reviewable without changing the
public names used by the CLI and browser fixtures.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from .app import (
        ApprovalError,
        AppError,
        BootstrapError,
        ImportPlan,
        LocalLayout,
        ServiceError,
        initialize_instance_repository,
    )
    from .service_launcher import PersistentApp

_APP_EXPORTS = frozenset(
    {
        "ApprovalError",
        "AppError",
        "BootstrapError",
        "ImportPlan",
        "LocalLayout",
        "ServiceError",
        "initialize_instance_repository",
    }
)

__all__ = [
    "ApprovalError",
    "AppError",
    "BootstrapError",
    "ImportPlan",
    "LocalLayout",
    "PersistentApp",
    "ServiceError",
    "initialize_instance_repository",
]


def __getattr__(name: str) -> Any:
    if name == "PersistentApp":
        value = getattr(import_module(".service_launcher", __name__), name)
    elif name in _APP_EXPORTS:
        value = getattr(import_module(".app", __name__), name)
    else:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted({*globals(), *__all__})
