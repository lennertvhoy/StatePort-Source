#!/usr/bin/env python3
"""Separate committed-source safety from owner-local and generated artifacts.

The public exporter operates only on an exact committed tree.  This validator
therefore treats tracked classification, staged-content safety, and untracked
owner material as distinct concerns.  Local artifacts never become public
source merely because they exist beside a checkout, while source-like
untracked files remain visible to operators instead of being silently lost.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path, PurePosixPath
import subprocess
from typing import Any, Iterable, Mapping, Sequence


POLICY_SCHEMA = "stateport.local-artifact-policy/v1"
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / "config" / "local-artifact-policy.v1.json"


class LocalArtifactPolicyError(RuntimeError):
    """The local-artifact contract is malformed or could not be evaluated."""


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    path: str
    classification: str | None = None


@dataclass(frozen=True)
class Policy:
    local_roots: tuple[tuple[str, str], ...]
    source_suffixes: tuple[str, ...]
    prohibited_suffixes: tuple[str, ...]
    prohibited_basenames: tuple[str, ...]


def _strings(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or any(not isinstance(item, str) or not item for item in value):
        raise LocalArtifactPolicyError(f"{label} must be a non-empty string list")
    values = tuple(value)
    if len(values) != len(set(values)) or list(values) != sorted(values):
        raise LocalArtifactPolicyError(f"{label} must be unique and sorted")
    return values


def _safe_relative(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise LocalArtifactPolicyError(f"{label} is required")
    path = PurePosixPath(value)
    if path.is_absolute() or value != path.as_posix() or any(part in {"", ".", ".."} for part in path.parts):
        raise LocalArtifactPolicyError(f"{label} must be a normalized repository-relative path")
    return value.rstrip("/")


def load_policy(path: Path = DEFAULT_POLICY) -> Policy:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LocalArtifactPolicyError("local-artifact policy could not be parsed") from exc
    if not isinstance(value, Mapping) or set(value) != {
        "schema",
        "localRoots",
        "sourceLikeSuffixes",
        "prohibitedTrackedSuffixes",
        "prohibitedTrackedBasenames",
    }:
        raise LocalArtifactPolicyError("local-artifact policy has unexpected fields")
    if value["schema"] != POLICY_SCHEMA:
        raise LocalArtifactPolicyError("local-artifact policy schema is unsupported")
    roots_value = value["localRoots"]
    if not isinstance(roots_value, list) or not roots_value:
        raise LocalArtifactPolicyError("localRoots must be a non-empty list")
    roots: list[tuple[str, str]] = []
    for index, raw in enumerate(roots_value):
        if not isinstance(raw, Mapping) or set(raw) != {"path", "classification"}:
            raise LocalArtifactPolicyError(f"localRoots[{index}] has unexpected fields")
        root = _safe_relative(raw["path"], f"localRoots[{index}].path")
        classification = raw["classification"]
        if not isinstance(classification, str) or not classification:
            raise LocalArtifactPolicyError(f"localRoots[{index}].classification is required")
        roots.append((root, classification))
    if roots != sorted(roots) or len({root for root, _ in roots}) != len(roots):
        raise LocalArtifactPolicyError("localRoots must be unique and sorted")
    return Policy(
        local_roots=tuple(roots),
        source_suffixes=_strings(value["sourceLikeSuffixes"], "sourceLikeSuffixes"),
        prohibited_suffixes=_strings(value["prohibitedTrackedSuffixes"], "prohibitedTrackedSuffixes"),
        prohibited_basenames=_strings(value["prohibitedTrackedBasenames"], "prohibitedTrackedBasenames"),
    )


def _git_paths(repository: Path, args: Sequence[str]) -> tuple[str, ...]:
    try:
        output = subprocess.run(
            ["git", "-C", str(repository), *args],
            check=True,
            capture_output=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise LocalArtifactPolicyError("Git path inventory failed") from exc
    try:
        paths = tuple(item.decode("utf-8") for item in output.split(b"\0") if item)
    except UnicodeDecodeError as exc:
        raise LocalArtifactPolicyError("Git path inventory contains a non-UTF-8 path") from exc
    return paths


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


def _local_classification(path: str, policy: Policy) -> str | None:
    matches = [classification for root, classification in policy.local_roots if _under(path, root)]
    if len(matches) > 1:
        raise LocalArtifactPolicyError("localRoots overlap")
    return matches[0] if matches else None


def _prohibited(path: str, policy: Policy) -> bool:
    name = PurePosixPath(path).name
    return name in policy.prohibited_basenames or any(path.endswith(suffix) for suffix in policy.prohibited_suffixes)


def inspect(repository: Path = ROOT, policy_path: Path = DEFAULT_POLICY) -> tuple[Finding, ...]:
    repository = repository.resolve()
    policy = load_policy(policy_path)
    tracked = _git_paths(repository, ("ls-files", "--cached", "-z"))
    staged = _git_paths(repository, ("diff", "--cached", "--name-only", "--diff-filter=ACMRTUXB", "-z"))
    untracked = _git_paths(repository, ("ls-files", "--others", "--exclude-standard", "-z"))
    findings: list[Finding] = []
    for path in sorted(set(tracked) | set(staged)):
        classification = _local_classification(path, policy)
        if classification is not None:
            findings.append(Finding("local_artifact_tracked", "error", path, classification))
        elif _prohibited(path, policy):
            findings.append(Finding("generated_or_sensitive_artifact_tracked", "error", path))
    for path in sorted(set(untracked)):
        classification = _local_classification(path, policy)
        if classification is not None:
            findings.append(Finding("local_artifact_observed", "info", path, classification))
        elif _prohibited(path, policy):
            findings.append(Finding("generated_or_sensitive_artifact_untracked", "error", path))
        elif any(path.endswith(suffix) for suffix in policy.source_suffixes):
            findings.append(Finding("untracked_source_like_path", "error", path))
        else:
            findings.append(Finding("untracked_unclassified_path", "warning", path))
    return tuple(findings)


def validate_ignore_contract(repository: Path = ROOT, policy_path: Path = DEFAULT_POLICY) -> None:
    policy = load_policy(policy_path)
    gitignore = (repository / ".gitignore").read_text(encoding="utf-8").splitlines()
    dockerignore = (repository / ".dockerignore").read_text(encoding="utf-8").splitlines()
    for root, _ in policy.local_roots:
        if f"/{root}/" not in gitignore:
            raise LocalArtifactPolicyError(f".gitignore does not bind local root {root}")
        if root not in dockerignore:
            raise LocalArtifactPolicyError(f".dockerignore does not bind local root {root}")


def _json(findings: Iterable[Finding]) -> list[dict[str, Any]]:
    return [
        {
            "code": item.code,
            "severity": item.severity,
            "path": item.path,
            "classification": item.classification,
        }
        for item in findings
    ]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=ROOT)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        validate_ignore_contract(args.repository, args.policy)
        findings = inspect(args.repository, args.policy)
    except LocalArtifactPolicyError as exc:
        if args.json:
            print(json.dumps({"ok": False, "error": str(exc), "findings": []}, sort_keys=True))
        else:
            print(f"FAIL: {exc}")
        return 1
    errors = [item for item in findings if item.severity == "error"]
    if args.json:
        print(json.dumps({"ok": not errors, "findings": _json(findings)}, sort_keys=True))
    else:
        for finding in findings:
            print(f"{finding.severity.upper()}: {finding.code}: {finding.path}")
        print("PASS: local artifacts are separated from committed-source authority" if not errors else "FAIL: unsafe local or staged artifacts found")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
