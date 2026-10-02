from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Iterable

from statedd_core.lifecycle import load_template_manifest


def _hash(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def build_bundle(base_template: Path | str, candidate_template: Path | str, *, evidence: Iterable[str], version_bump: str) -> dict[str, Any]:
    base = Path(base_template).resolve()
    candidate = Path(candidate_template).resolve()
    evidence_values = tuple(item for item in evidence if isinstance(item, str) and item.strip())
    if not evidence_values:
        raise ValueError("deterministic evidence is required")
    if not isinstance(version_bump, str) or not version_bump.strip():
        raise ValueError("version_bump is required")
    manifest = load_template_manifest(candidate)
    changed: list[dict[str, Any]] = []
    files: list[str] = []
    for item in manifest["files"]:
        path = item["path"]
        if item["owner"] != "template" or item["sensitivity"] not in {"public", "internal"}:
            continue
        if item["provision"] != "copy" or not item.get("source"):
            continue
        if path.startswith((".env", "instance", "state/", "audit/", "evidence/")):
            raise ValueError(f"private or operational path is not contribution eligible: {path}")
        source = candidate / item["source"]
        old = base / item["source"]
        if not source.is_file():
            raise ValueError(f"candidate source missing: {item['source']}")
        new_hash = _hash(source)
        old_hash = _hash(old) if old.is_file() else None
        if old_hash != new_hash:
            changed.append({"path": path, "sourceHash": new_hash, "baseHash": old_hash, "sensitivity": item["sensitivity"]})
            files.append(path)
    if not changed:
        raise ValueError("bundle must contain at least one changed eligible file")
    return {"formatVersion": "statedd.contribution-bundle/v1", "status": "needs_review",
            "templateId": manifest["templateId"], "fromVersion": "base", "versionBump": version_bump,
            "changedFiles": changed, "evidence": list(evidence_values), "files": files,
            "secretScan": "required_before_merge", "privateContentIncluded": False,
            "automaticApply": False}
