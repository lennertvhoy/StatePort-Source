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
    descriptors: list[dict[str, Any]] = []
    if not fixture_root.is_dir():
        return descriptors
    for path in sorted(fixture_root.glob("*/application.yaml")):
        value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(value, dict) or value.get("formatVersion") != "stateport.application/v1":
            raise ValueError(f"invalid application descriptor: {path}")
        if not isinstance(value.get("applicationId"), str) or not value["applicationId"]:
            raise ValueError(f"application descriptor lacks applicationId: {path}")
        value["descriptorPath"] = path.relative_to(root).as_posix()
        descriptors.append(value)
    return descriptors
