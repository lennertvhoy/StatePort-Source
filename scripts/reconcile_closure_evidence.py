#!/usr/bin/env python3
"""Reconcile a StatePort closure evidence bundle with one exact Git candidate.

This tool is deliberately StatePort-local and read-only with respect to the
repository.  It records evidence gaps instead of filling them with inferred
upstream or runtime facts.  A report can therefore be useful even when the
underlying proof is not closure-grade.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


DEFAULT_COMMIT = "a60fdf2d7599c148bd377852df0b71cfe2906bf5"
DEFAULT_EVIDENCE = Path("docs/evidence/2026-07-13-studydd-011-closure-proof")
ACTION_NAMES = ("added", "modified", "removed", "renamed")


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=root, text=True, capture_output=True, check=False
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout.strip()


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _finding(
    finding_id: str,
    classification: str,
    message: str,
    *,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": finding_id,
        "classification": classification,
        "message": message,
    }
    if evidence is not None:
        result["evidence"] = evidence
    return result


def _path_action_counts(actions: list[dict[str, Any]]) -> dict[str, int]:
    counts = {name: 0 for name in ACTION_NAMES}
    for index, entry in enumerate(actions):
        if not isinstance(entry, dict):
            raise ValueError(f"path action {index} must be an object")
        action = entry.get("action")
        if action not in counts:
            raise ValueError(f"path action {index} has unsupported action {action!r}")
        counts[action] += 1
    return counts


def _reconcile_path_actions(matrix: dict[str, Any]) -> dict[str, Any]:
    counts = matrix.get("counts")
    if not isinstance(counts, dict):
        return {
            "status": "incomplete",
            "reason": "path-action matrix has no machine-readable counts",
        }
    declared = {name: counts.get(name) for name in ACTION_NAMES}
    actions = matrix.get("actions")
    if isinstance(actions, list):
        derived = _path_action_counts(actions)
        return {
            "status": "pass" if declared == derived else "disagreement",
            "declared": declared,
            "derived": derived,
            "actionCount": len(actions),
        }

    categories = matrix.get("categories")
    if not isinstance(categories, dict):
        return {
            "status": "incomplete",
            "reason": "path-action matrix has no actions or categories",
            "declared": declared,
        }
    category_totals = {
        name: len(categories.get(f"exact-file-{name}", []))
        + len(categories.get(f"tree-{name}", []))
        for name in ACTION_NAMES
    }
    return {
        "status": "disagreement",
        "declared": declared,
        "categoryEntryTotals": category_totals,
        "reason": "stored counts cannot be derived because the action list is absent",
    }


def _pytest_counts(root: Path) -> dict[str, Any]:
    collect_command = [sys.executable, "-m", "pytest", "scripts/", "--collect-only", "-q"]
    collected = subprocess.run(
        collect_command, cwd=root, text=True, capture_output=True, check=False
    )
    collected_match = re.search(r"(\d+) tests collected", collected.stdout)
    run_command = [sys.executable, "-m", "pytest", "scripts/", "-q"]
    run = subprocess.run(run_command, cwd=root, text=True, capture_output=True, check=False)
    passed_match = re.search(r"(\d+) passed(?:,| in|$)", run.stdout)
    return {
        "collectCommand": " ".join(collect_command),
        "collected": int(collected_match.group(1)) if collected_match else None,
        "runCommand": " ".join(run_command),
        "returnCode": run.returncode,
        "passed": int(passed_match.group(1)) if passed_match else None,
        "summary": run.stdout.strip().splitlines()[-1] if run.stdout.strip() else run.stderr.strip(),
    }


def _candidate_status_test_claims(root: Path, candidate_commit: str) -> list[int]:
    """Read historical count claims from the exact candidate, without editing it."""
    result = subprocess.run(
        ["git", "show", f"{candidate_commit}:STATUS.md"],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        return []
    values = re.findall(r"\b(\d+) passed\b", result.stdout)
    values.extend(re.findall(r"\bplus\s+`?(\d+)`?\s+supplementary closure tests\b", result.stdout))
    return sorted({int(value) for value in values})


def reconcile(
    root: Path,
    evidence_dir: Path,
    *,
    candidate_commit: str = DEFAULT_COMMIT,
    run_tests: bool = True,
) -> dict[str, Any]:
    root = root.resolve()
    evidence_dir = evidence_dir.resolve()
    commit = _git(root, "rev-parse", "--verify", f"{candidate_commit}^{{commit}}")
    tree = _git(root, "rev-parse", "--verify", f"{commit}^{{tree}}")
    branch = _git(root, "branch", "--show-current")
    repository = _git(root, "remote", "get-url", "origin")
    manifest_path = evidence_dir / "evidence_manifest.json"
    identities_path = evidence_dir / "proof-identities.json"
    matrix_path = evidence_dir / "path-action-matrix.json"
    manifest = _read_json(manifest_path)
    identities = _read_json(identities_path)
    matrix = _read_json(matrix_path)

    findings: list[dict[str, Any]] = []
    required_source_keys = {"repository", "manifestDigest", "sourceDigest"}
    source_binding: dict[str, Any] = {}
    for label in ("baseline", "target"):
        source = identities.get(label)
        if isinstance(source, dict):
            missing = sorted(
                required_source_keys
                - set(source)
                | ({"commit"} if not {"commit", "resolvedCommit"}.intersection(source) else set())
                | ({"tree"} if not {"tree", "resolvedTree"}.intersection(source) else set())
            )
        else:
            missing = sorted(required_source_keys | {"commit", "tree"})
        source_binding[label] = {
            "present": isinstance(source, dict),
            "missing": missing,
        }
    if any(item["missing"] for item in source_binding.values()):
        findings.append(
            _finding(
                "canonical-source-binding",
                "incomplete",
                "canonical source identities do not bind repository, commit, tree, manifest, and content together",
                evidence=source_binding,
            )
        )

    stateport_candidate = manifest.get("stateportCandidate")
    expected_candidate = {"repository": repository, "commit": commit, "tree": tree}
    if stateport_candidate != expected_candidate:
        findings.append(
            _finding(
                "functional-evidence-identity",
                "wrong-or-missing",
                "evidence manifest is not bound to the exact StatePort candidate commit and tree",
                evidence={"expected": expected_candidate, "recorded": stateport_candidate},
            )
        )

    instance_binding = manifest.get("instanceBinding")
    if not isinstance(instance_binding, dict) or not {
        "instanceId", "lockDigest", "sourceDigest"
    }.issubset(instance_binding):
        findings.append(
            _finding(
                "instance-lock-source-binding",
                "incomplete",
                "closure evidence does not bind an instance identity, exact lock digest, and locked source digest",
                evidence={"recorded": instance_binding},
            )
        )

    audit_path = next(
        (evidence_dir / name for name in ("audit.jsonl", "audit-records.jsonl") if (evidence_dir / name).is_file()),
        None,
    )
    audit = {"status": "missing", "path": None}
    if audit_path is not None:
        # Importing the package here keeps the validator tied to the existing
        # StatePort hash-chain implementation without duplicating its rules.
        sys.path.insert(0, str(root / "packages" / "audit-log" / "src"))
        from audit_log import AuditLog  # type: ignore[import-not-found]

        loaded = AuditLog(audit_path)
        audit = {"status": "pass" if loaded.verify() else "invalid", "path": audit_path.name, "events": len(loaded.events)}
    if audit["status"] != "pass":
        findings.append(
            _finding(
                "audit-records",
                "incomplete" if audit["status"] == "missing" else "invalid",
                "closure evidence has no verified hash-chained audit record for the proof",
                evidence=audit,
            )
        )

    path_actions = _reconcile_path_actions(matrix)
    if path_actions["status"] != "pass":
        findings.append(
            _finding(
                "path-action-counts",
                path_actions["status"],
                "path-action counts are not reproducibly derived from machine-readable actions",
                evidence=path_actions,
            )
        )

    status_text = (root / "STATUS.md").read_text(encoding="utf-8")
    project_state_text = (root / "PROJECT_STATE.yaml").read_text(encoding="utf-8")
    status_branches = re.findall(r"\*\*Repository:\*\*[^\n]*\bbranch\s+`?([A-Za-z0-9_./-]+)", status_text)
    state_branches = re.findall(r"^\s+branch:\s*([A-Za-z0-9_./-]+)\s*$", project_state_text, re.MULTILINE)
    stale_branches = sorted({value for value in [*status_branches, *state_branches] if value != branch})
    if stale_branches:
        findings.append(
            _finding(
                "live-status-identity",
                "stale",
                "live status/project state contains branch identity from another checkout",
                evidence={"currentBranch": branch, "staleValues": stale_branches},
            )
        )

    test_counts = _pytest_counts(root) if run_tests else {"status": "not-run"}
    test_counts["candidateStatusClaims"] = _candidate_status_test_claims(root, commit)
    recorded_closure_counts = sorted({int(value) for value in re.findall(r"\b(\d+) passed\b", (evidence_dir / "validation.md").read_text(encoding="utf-8"))})
    if run_tests and (
        test_counts.get("returnCode") != 0
        or test_counts.get("passed") != test_counts.get("collected")
        or any(value != test_counts.get("passed") for value in recorded_closure_counts)
    ):
        findings.append(
            _finding(
                "test-count-recording",
                "inconsistent",
                "recorded closure test counts do not match the StatePort machine-readable test result",
                evidence={"observed": test_counts, "recordedClosureCounts": recorded_closure_counts},
            )
        )

    resolved: list[dict[str, Any]] = []
    if stateport_candidate == expected_candidate:
        resolved.append({"id": "functional-evidence-identity", "classification": "resolved"})
    if not stale_branches:
        resolved.append({"id": "live-status-identity", "classification": "resolved"})
    if run_tests and test_counts.get("returnCode") == 0 and test_counts.get("passed") == test_counts.get("collected") and all(
        value == test_counts.get("passed") for value in recorded_closure_counts
    ):
        resolved.append({"id": "test-count-recording", "classification": "resolved"})

    return {
        "formatVersion": "stateport.closure-reconciliation/v1",
        "candidate": {
            "repository": repository,
            "commit": commit,
            "tree": tree,
            "branch": branch,
        },
        "evidence": {
            "directory": evidence_dir.relative_to(root).as_posix() if evidence_dir.is_relative_to(root) else evidence_dir.as_posix(),
            "manifestDigest": _file_digest(manifest_path),
            "manifestFiles": manifest.get("files", []),
        },
        "sourceBinding": source_binding,
        "instanceBinding": instance_binding,
        "audit": audit,
        "pathActions": path_actions,
        "testCounts": test_counts,
        "resolved": resolved,
        "findings": findings,
        "status": "findings-recorded" if findings else "reconciled",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--evidence-dir", type=Path, default=DEFAULT_EVIDENCE)
    parser.add_argument("--candidate", default=DEFAULT_COMMIT)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--skip-tests", action="store_true")
    args = parser.parse_args(argv)
    report = reconcile(
        args.root,
        args.evidence_dir,
        candidate_commit=args.candidate,
        run_tests=not args.skip_tests,
    )
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 1 if report["findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
