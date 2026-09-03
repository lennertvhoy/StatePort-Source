from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CompiledContext:
    manifest: dict[str, Any]
    digest: str
    text: str


_CATEGORIES = {
    "instance_descriptor": ("instance.yaml",),
    "credentials": (),
    "engine_sessions": (),
}


def compile_context(root: Path, action_id: str, policy: dict[str, Any], budget_tokens: int) -> CompiledContext:
    include = list(policy.get("includeCategories", ()))
    exclude = list(policy.get("excludeCategories", ()))
    included: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    chunks: list[str] = []
    category_paths = dict(_CATEGORIES)
    for category, raw_paths in (policy.get("categoryPaths") or {}).items():
        if isinstance(category, str) and isinstance(raw_paths, (list, tuple)):
            category_paths[category] = tuple(str(path) for path in raw_paths if isinstance(path, str))
    for category in sorted(category_paths):
        paths = category_paths[category]
        for relative in paths:
            path = root / relative
            if category in include and category not in exclude and path.is_file() and not path.is_symlink():
                content = path.read_text(encoding="utf-8", errors="replace")
                included.append({"category": category, "path": relative, "bytes": len(content.encode())})
                chunks.append(f"[{relative}]\n{content.strip()}\n")
            elif category in exclude or category not in include:
                excluded.append({"category": category, "path": relative, "reason": "policy" if category in exclude else "not_declared"})
            elif not path.is_file():
                excluded.append({"category": category, "path": relative, "reason": "missing"})
    text = "\n".join(chunks)
    token_estimate = max(1, (len(text) + 3) // 4) if text else 0
    truncated = token_estimate > budget_tokens
    if truncated:
        text = text[: budget_tokens * 4]
        token_estimate = max(1, (len(text) + 3) // 4)
    manifest = {"formatVersion": "stateport.state-pack/v1", "actionId": action_id, "policyId": policy.get("id", "unknown"), "included": included, "excluded": excluded, "sensitivity": policy.get("sensitivity", "unknown"), "budgetTokens": budget_tokens, "tokenEstimate": token_estimate, "truncated": truncated, "pathPolicy": "repository-relative"}
    payload = {"manifest": manifest, "contentDigests": [{"path": item["path"], "digest": "sha256:" + hashlib.sha256((root / item["path"]).read_bytes()).hexdigest()} for item in included]}
    digest = "sha256:" + hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    manifest["digest"] = digest
    return CompiledContext(manifest, digest, text)
