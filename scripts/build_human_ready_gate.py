#!/usr/bin/env python3
"""Assemble a strict, false-by-default StatePort human-ready gate."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Mapping, Sequence


FORMAT_VERSION = "stateport.human-ready-gate/v1"
REQUIRED_CHECKS = (
    "fullSuitePassed",
    "focusedSourceTestsPassed",
    "browserAutomationPassed",
    "noUnexpectedConsoleErrors",
    "noUnexpectedFailedRequests",
    "terminalRegressionsPassed",
    "editorRegressionsPassed",
    "conversationRegressionsPassed",
    "ctoRegressionsPassed",
    "stateBenchRegressionsPassed",
    "gitWorktreeClean",
    "allMachineTestableAcceptanceJourneysPassed",
    "credentialsNotExposed",
    "noUnresolvedCriticalSecurityReviewFindings",
)
_GIT_IDENTITY = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


class HumanReadyGateError(ValueError):
    """Raised for evidence that cannot support a human-ready claim."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_artifact(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise HumanReadyGateError("evidence artifact must be a non-empty portable relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or any(part in ("", ".") for part in path.parts):
        raise HumanReadyGateError("evidence artifact must be a safe relative path")
    return value


def assemble_human_ready_gate(
    source: Mapping[str, object], *, generated_at: str | None = None
) -> dict[str, object]:
    """Normalize evidence; omitted checks are false and true checks need hashes."""

    unknown_root = set(source) - {"functionalCommit", "functionalTree", "checks"}
    if unknown_root:
        raise HumanReadyGateError(f"unknown root fields: {sorted(unknown_root)}")
    commit = source.get("functionalCommit")
    tree = source.get("functionalTree")
    if not isinstance(commit, str) or not _GIT_IDENTITY.fullmatch(commit):
        raise HumanReadyGateError("functionalCommit must be an exact 40-character Git identity")
    if not isinstance(tree, str) or not _GIT_IDENTITY.fullmatch(tree):
        raise HumanReadyGateError("functionalTree must be an exact 40-character Git tree identity")
    raw_checks = source.get("checks", {})
    if not isinstance(raw_checks, Mapping):
        raise HumanReadyGateError("checks must be an object")
    unknown_checks = set(raw_checks) - set(REQUIRED_CHECKS)
    if unknown_checks:
        raise HumanReadyGateError(f"unknown checks: {sorted(unknown_checks)}")

    checks: dict[str, object] = {}
    blockers: list[str] = []
    for name in REQUIRED_CHECKS:
        raw = raw_checks.get(name)
        if raw is None:
            passed = False
            evidence: list[dict[str, str]] = []
        else:
            if not isinstance(raw, Mapping) or set(raw) - {"passed", "evidence"}:
                raise HumanReadyGateError(f"{name} must contain only passed and evidence")
            passed_value = raw.get("passed", False)
            if not isinstance(passed_value, bool):
                raise HumanReadyGateError(f"{name}.passed must be boolean")
            passed = passed_value
            raw_evidence = raw.get("evidence", [])
            if not isinstance(raw_evidence, list):
                raise HumanReadyGateError(f"{name}.evidence must be an array")
            evidence = []
            for item in raw_evidence:
                if not isinstance(item, Mapping) or set(item) != {"artifact", "sha256"}:
                    raise HumanReadyGateError(f"{name} evidence must contain artifact and sha256")
                digest = item.get("sha256")
                if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
                    raise HumanReadyGateError(f"{name} evidence sha256 is invalid")
                evidence.append({"artifact": _safe_artifact(item.get("artifact")), "sha256": digest})
            if passed and not evidence:
                raise HumanReadyGateError(f"{name} cannot pass without hashed evidence")
        checks[name] = {"passed": passed, "evidence": evidence}
        if not passed:
            blockers.append(name)

    ready = not blockers
    return {
        "formatVersion": FORMAT_VERSION,
        "generatedAt": generated_at or _now(),
        "functionalCommit": commit,
        "functionalTree": tree,
        "readyForHumanAcceptance": ready,
        "classification": "machine_ready_for_subjective_human_acceptance" if ready else "machine_gate_incomplete",
        "checks": checks,
        "blockers": blockers,
        "humanSession": {
            "permitted": ready,
            "maximumMinutes": 20,
            "scope": "subjective clarity, control, trust, and acceptance only",
        },
        "privacy": {"credentialsRecorded": False, "privateContentRecorded": False},
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="Machine evidence JSON")
    parser.add_argument("--output", required=True, type=Path, help="human_ready_gate.json destination")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        source = json.loads(args.input.read_text(encoding="utf-8"))
        if not isinstance(source, dict):
            raise HumanReadyGateError("input must be a JSON object")
        gate = assemble_human_ready_gate(source)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(gate, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (HumanReadyGateError, json.JSONDecodeError, OSError) as exc:
        print(f"human-ready gate rejected evidence: {exc}", file=sys.stderr)
        return 2
    print("human-ready gate written")
    return 0 if gate["readyForHumanAcceptance"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
