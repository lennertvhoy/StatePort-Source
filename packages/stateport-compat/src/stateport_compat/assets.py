"""Pure compatibility mapping for StateDD v5 ``STATEDD_ASSETS.json``.

This adapter reads the historical contract without importing or executing the
StateDD updater.  It produces a normalized, StatePort-owned view that callers
can bind to a new immutable lock; it never mutates the historical manifest.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class CompatibilityError(ValueError):
    """Raised when an accepted StateDD v5 payload cannot be mapped safely."""


def _path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or value.startswith("/") or "\\" in value:
        raise CompatibilityError(f"{label} must be a relative POSIX path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise CompatibilityError(f"{label} contains an unsafe path component")
    return value


def _digest(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise CompatibilityError(f"{label} must be a lowercase SHA-256 digest")
    return "sha256:" + value


@dataclass(frozen=True)
class StateDDAssets:
    schema: str
    template_version: str
    template_commit: str | None
    profile: str
    managed_assets: tuple[dict[str, Any], ...]
    retired_assets: tuple[dict[str, Any], ...]
    source_digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "templateVersion": self.template_version,
            "templateCommit": self.template_commit,
            "profile": self.profile,
            "managedAssets": copy.deepcopy(list(self.managed_assets)),
            "retiredAssets": copy.deepcopy(list(self.retired_assets)),
            "sourceDigest": self.source_digest,
        }


def load_statedd_assets(path: Path | str) -> StateDDAssets:
    manifest_path = Path(path)
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise CompatibilityError("STATEDD_ASSETS.json must be a regular file")
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CompatibilityError(f"could not read STATEDD_ASSETS.json: {exc}") from exc
    if not isinstance(raw, dict):
        raise CompatibilityError("STATEDD_ASSETS.json must contain an object")
    schema = raw.get("schema")
    if schema not in {"statedd.runtime_assets.v1", "statedd.runtime_assets.v2"}:
        raise CompatibilityError(f"unsupported StateDD assets schema: {schema!r}")
    version = raw.get("template_version")
    profile = raw.get("profile")
    if not isinstance(version, str) or not version or not isinstance(profile, str) or not profile:
        raise CompatibilityError("template_version and profile are required")
    if schema == "statedd.runtime_assets.v1":
        assets = raw.get("assets")
        if not isinstance(assets, list) or not assets or any(not isinstance(item, str) for item in assets):
            raise CompatibilityError("v1 assets must be a non-empty string list")
        managed = tuple(
            {
                "path": _path(item, "assets path"),
                "owner": "instance" if item in {"PROJECT_STATE.yaml", "PROJECT_DNA.yaml", "PROJECT_ADAPTER.yaml"} else "template",
                "merge": "append_only" if item in {"WORKLOG.md", "EVIDENCE_LOG.md"} else "replace",
                "sensitivity": "internal",
                "source": item,
                "legacy": True,
            }
            for item in assets
        )
        retired: tuple[dict[str, Any], ...] = ()
    else:
        records = raw.get("managed_assets")
        if not isinstance(records, list) or not records:
            raise CompatibilityError("v2 managed_assets must be a non-empty list")
        seen: set[str] = set()
        normalized: list[dict[str, Any]] = []
        for index, item in enumerate(records):
            if not isinstance(item, dict):
                raise CompatibilityError(f"managed_assets[{index}] must be an object")
            required = {"path", "owner", "merge_strategy", "sensitivity", "append_only"}
            if not required.issubset(item):
                raise CompatibilityError(f"managed_assets[{index}] is missing required lifecycle fields")
            rel = _path(item["path"], f"managed_assets[{index}].path")
            if rel in seen:
                raise CompatibilityError(f"duplicate managed asset: {rel}")
            seen.add(rel)
            if item["owner"] not in {"template", "project"}:
                raise CompatibilityError(f"managed_assets[{index}].owner is invalid")
            if not isinstance(item["append_only"], bool):
                raise CompatibilityError(f"managed_assets[{index}].append_only must be boolean")
            normalized.append(
                {
                    "path": rel,
                    "owner": "instance" if item["owner"] == "project" else "template",
                    "merge": "append_only" if item["append_only"] else item["merge_strategy"],
                    "sensitivity": item["sensitivity"],
                    "source": rel,
                    "legacy": False,
                }
            )
        managed = tuple(sorted(normalized, key=lambda item: item["path"]))
        raw_retired = raw.get("retired_assets", [])
        if not isinstance(raw_retired, list):
            raise CompatibilityError("retired_assets must be a list")
        retired = tuple(
            {"path": _path(item.get("path"), "retired asset path"), "reason": item.get("reason", "historical retirement")}
            for item in raw_retired
            if isinstance(item, dict)
        )
    payload = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    import hashlib
    source_digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    commit = raw.get("template_commit")
    if commit is not None and (not isinstance(commit, str) or len(commit) != 40 or any(c not in "0123456789abcdef" for c in commit)):
        raise CompatibilityError("template_commit must be a full lowercase Git commit")
    return StateDDAssets(schema, version, commit, profile, managed, retired, source_digest)


def map_assets_to_stateport(assets: StateDDAssets) -> dict[str, Any]:
    """Produce a deterministic StatePort-native manifest projection."""
    files = []
    for item in assets.managed_assets:
        files.append(
            {
                "path": item["path"],
                "source": item["source"],
                "owner": item["owner"],
                "provision": "copy",
                "merge": item["merge"],
                "generation": "none",
                "required": True,
                "schema": None,
                "sensitivity": item["sensitivity"] if item["sensitivity"] in {"public", "internal", "private", "secret"} else "internal",
                "retirementPolicy": "retain",
            }
        )
    return {
        "formatVersion": "stateport.compatibility-view/v1",
        "adapter": "stateport.statedd-v5-assets/1",
        "sourceSchema": assets.schema,
        "templateVersion": assets.template_version,
        "templateCommit": assets.template_commit,
        "profile": assets.profile,
        "files": sorted(files, key=lambda item: item["path"]),
        "retired": sorted(assets.retired_assets, key=lambda item: item["path"]),
        "sourceDigest": assets.source_digest,
    }
