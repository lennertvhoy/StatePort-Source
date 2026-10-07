"""Application descriptor discovery independent of any application domain."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def discover_application_descriptors(root: Path) -> list[dict[str, Any]]:
    """Load public-safe application descriptors from a fixture registry.

    The registry deliberately reads descriptors as data.  It never imports an
    application package or dispatches on an application name.
    """

    fixture_root = root / "fixtures" / "apps"
    adapter_root = root / "fixtures" / "template-adapters"
    descriptors: list[dict[str, Any]] = []
    if not fixture_root.is_dir():
        return descriptors
    paths = list(fixture_root.glob("*/application.yaml"))
    if adapter_root.is_dir() and not adapter_root.is_symlink():
        paths.extend(adapter_root.glob("*.application.yaml"))
    for path in sorted(paths):
        value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(value, dict) or value.get("formatVersion") != "stateport.application/v1":
            raise ValueError(f"invalid application descriptor: {path}")
        if not isinstance(value.get("applicationId"), str) or not value["applicationId"]:
            raise ValueError(f"application descriptor lacks applicationId: {path}")
        value["descriptorPath"] = path.relative_to(root).as_posix()
        descriptors.append(value)
    identities = [str(item["applicationId"]) for item in descriptors]
    if len(identities) != len(set(identities)):
        raise ValueError("application descriptor identities are ambiguous")
    return descriptors
