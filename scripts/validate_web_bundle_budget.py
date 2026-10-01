#!/usr/bin/env python3
"""Fail when a production web build exceeds the reviewed alpha size budget."""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
from typing import Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / "config" / "web-bundle-budget.v1.json"
POLICY_SCHEMA = "stateport.web-bundle-budget/v1"


class BundleBudgetError(RuntimeError):
    """The size policy or production bundle is absent, unsafe, or oversized."""


def _positive_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise BundleBudgetError(f"{label} must be a positive integer")
    return value


def load_policy(path: Path = DEFAULT_POLICY) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BundleBudgetError("web bundle budget could not be parsed") from exc
    expected = {
        "schema",
        "distRoot",
        "maximumTotalBytes",
        "maximumJavaScriptAssetBytes",
        "maximumStylesheetAssetBytes",
        "maximumFontAssetBytes",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise BundleBudgetError("web bundle budget has unexpected fields")
    if value["schema"] != POLICY_SCHEMA:
        raise BundleBudgetError("web bundle budget schema is unsupported")
    raw_root = value["distRoot"]
    if not isinstance(raw_root, str) or not raw_root:
        raise BundleBudgetError("distRoot must be a repository-relative path")
    dist_root = PurePosixPath(raw_root)
    if dist_root.is_absolute() or dist_root.as_posix() != raw_root or ".." in dist_root.parts:
        raise BundleBudgetError("distRoot must be a normalized repository-relative path")
    result = dict(value)
    for field in expected - {"schema", "distRoot"}:
        result[field] = _positive_int(value[field], field)
    return result


def inspect_bundle(repository: Path = ROOT, policy_path: Path = DEFAULT_POLICY) -> dict[str, object]:
    policy = load_policy(policy_path)
    dist = (repository / str(policy["distRoot"])).resolve()
    repository = repository.resolve()
    if repository not in dist.parents or not dist.is_dir() or dist.is_symlink():
        raise BundleBudgetError("production dist root is absent or unsafe")
    files = sorted(path for path in dist.rglob("*") if path.is_file() and not path.is_symlink())
    if not files or not (dist / "stateport-build.json").is_file():
        raise BundleBudgetError("production bundle is incomplete")
    total = sum(path.stat().st_size for path in files)
    limits = {
        ".js": int(policy["maximumJavaScriptAssetBytes"]),
        ".css": int(policy["maximumStylesheetAssetBytes"]),
        ".woff": int(policy["maximumFontAssetBytes"]),
        ".woff2": int(policy["maximumFontAssetBytes"]),
    }
    violations: list[dict[str, object]] = []
    if total > int(policy["maximumTotalBytes"]):
        violations.append({"kind": "total", "observedBytes": total, "limitBytes": policy["maximumTotalBytes"]})
    largest: dict[str, int] = {suffix: 0 for suffix in limits}
    for path in files:
        suffix = path.suffix.lower()
        if suffix not in limits:
            continue
        size = path.stat().st_size
        largest[suffix] = max(largest[suffix], size)
        if size > limits[suffix]:
            violations.append(
                {
                    "kind": suffix.removeprefix("."),
                    "asset": path.relative_to(dist).as_posix(),
                    "observedBytes": size,
                    "limitBytes": limits[suffix],
                }
            )
    return {
        "schema": POLICY_SCHEMA,
        "totalBytes": total,
        "fileCount": len(files),
        "largestBySuffix": largest,
        "violations": violations,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=ROOT)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    args = parser.parse_args(argv)
    try:
        report = inspect_bundle(args.repository, args.policy)
    except BundleBudgetError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1
    ok = not report["violations"]
    print(json.dumps({"ok": ok, "report": report}, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
