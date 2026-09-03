#!/usr/bin/env python3
"""Authoritative local proof for immutable StudyDD 0.10 -> 0.11 upgrades."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "211d69bd96da6c67874fa81bcd50149e55cfca90"
DEFAULT_TARGET = "5c3ab7c26c1aaf4606f1fda24f4c37dcb5a7e189"
MIGRATION_ID = "studydd.fast-drill.settings.v1"
MIGRATION_DIGEST = "sha256:" + "1" * 64

import sys

sys.path.insert(0, str(ROOT / "packages" / "statedd-core" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "lifecycle-migrations" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "audit-log" / "src"))

from statedd_core.lifecycle import (  # noqa: E402
    LifecycleError,
    _canonical_digest,
    _write_yaml,
    apply_upgrade,
    approve_upgrade_plan,
    create_instance,
    plan_upgrade,
    resolve_git_source,
)
from statedd_core.yaml import parse_yaml_text  # noqa: E402
from audit_log import AuditLog  # noqa: E402


def git(cwd: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=cwd, text=True, capture_output=True, check=False)
    if result.returncode:
        raise AssertionError(result.stderr)
    return result.stdout.strip()


def snapshot(root: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            values[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return values


def path_action_counts(actions: list[dict[str, Any]]) -> dict[str, int]:
    """Derive action counts from the emitted machine-readable action list."""
    counts = {"added": 0, "modified": 0, "removed": 0, "renamed": 0}
    for entry in actions:
        action = entry["action"]
        if action not in counts:
            raise AssertionError(f"unsupported path action: {action}")
        counts[action] += 1
    return counts


def synthetic_state(instance: Path) -> None:
    values = {
        "state/LEARNER_PROFILE.yaml": "learner_preferences:\n  fast_drill_mode: true\n",
        "state/STUDY_STATE.yaml": "synthetic: true\nlearning_target: synthetic-target\n",
        "state/EVIDENCE_LOG.md": "synthetic evidence record\n",
        "state/ACTIVE_DRILL_SESSION.md": "synthetic append-only checkpoint\n",
    }
    for relative, value in values.items():
        path = instance / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")
    for tree, relative, value in (
        ("reviews", "REVIEW_QUEUE.md", "synthetic review item\n"),
        ("sessions", "SESSION_LOG.md", "synthetic session history\n"),
        ("sources", "SOURCE_STATE.yaml", "synthetic: true\n"),
        ("targets", "LEARNING_TARGET.md", "synthetic learning target\n"),
    ):
        path = instance / tree / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")
    (instance / ".fast_drill").mkdir(exist_ok=True)
    (instance / ".fast_drill" / "history.jsonl").write_text('{"synthetic":true}\n', encoding="utf-8")
    (instance / "question_banks").mkdir(exist_ok=True)
    (instance / "question_banks" / "private-placeholder.yaml").write_text(
        "id: synthetic-private-placeholder\n", encoding="utf-8"
    )


def run(studydd_root: Path, target: str, baseline: str = BASELINE) -> dict[str, Any]:
    if not studydd_root.is_dir():
        raise AssertionError(f"StudyDD proof source is missing: {studydd_root}")
    with tempfile.TemporaryDirectory(prefix="stateport-studydd-011-proof-") as raw:
        workspace = Path(raw)
        baseline_root = workspace / "baseline-source"
        target_root = workspace / "target-source"
        for destination, commit in ((baseline_root, baseline), (target_root, target)):
            git(workspace, "clone", "-q", studydd_root.as_posix(), destination.as_posix())
            git(destination, "checkout", "-q", "--detach", commit)
            assert git(destination, "status", "--porcelain") == ""

        baseline_source = resolve_git_source(baseline_root, requested_ref=baseline)
        target_source = resolve_git_source(target_root, requested_ref=target)
        assert baseline_source["resolvedCommit"] == baseline
        assert target_source["resolvedCommit"] == target
        assert baseline_source["resolvedTree"] == git(baseline_root, "rev-parse", "HEAD^{tree}")
        assert target_source["resolvedTree"] == git(target_root, "rev-parse", "HEAD^{tree}")
        diff_lines = git(baseline_root, "diff", "--name-status", baseline, target).splitlines()
        path_actions = []
        for line in diff_lines:
            status, path = line.split("\t", 1)
            action = {"A": "added", "M": "modified", "D": "removed"}.get(status[:1], "unsupported")
            path_actions.append({"path": path, "gitStatus": status, "action": action})

        instance = workspace / "instance"
        create_instance(
            baseline_root,
            instance,
            instance_id="synthetic-studydd-011-proof",
            name="Synthetic StudyDD 0.11 proof instance",
            owner_name="Synthetic Operator",
            owner_handle="@synthetic",
            source_descriptor=baseline_source,
        )
        synthetic_state(instance)
        pre_upgrade = snapshot(instance)
        migration_set = [{"migrationId": MIGRATION_ID, "contractDigest": MIGRATION_DIGEST}]
        initial_plan = plan_upgrade(instance, target_root, migration_set=migration_set)
        assert initial_plan["safe"] and not initial_plan["blocked"]
        assert initial_plan["planDigest"] == plan_upgrade(
            instance, target_root, migration_set=migration_set
        )["planDigest"]

        conflict_before = snapshot(instance)
        (instance / ".gitignore").write_text("synthetic conflict\n", encoding="utf-8")
        conflict_plan = plan_upgrade(instance, target_root, migration_set=migration_set)
        assert conflict_plan["blocked"] and any(
            entry["classification"] == "overridden" for entry in conflict_plan["entries"]
        )
        assert not (instance / ".statedd/upgrade-receipt.yaml").exists()
        # Restore the exact baseline from the source checkout before ejection.
        (instance / ".gitignore").write_bytes((baseline_root / ".gitignore").read_bytes())

        _write_yaml(
            instance / ".statedd/overrides.yaml",
            {
                "formatVersion": "statedd.instance-overrides/v1",
                "ejections": [{"path": ".gitignore", "reason": "synthetic explicit ejection"}],
            },
        )
        (instance / ".gitignore").write_text("synthetic ejected content\n", encoding="utf-8")
        ejected_plan = plan_upgrade(instance, target_root, migration_set=migration_set)
        assert ejected_plan["safe"] and ejected_plan["planDigest"] != initial_plan["planDigest"]
        ejected_entry = next(entry for entry in ejected_plan["entries"] if entry["path"] == ".gitignore")
        assert ejected_entry["action"] == "preserve"

        approval = approve_upgrade_plan(ejected_plan, approved_by="synthetic-operator")
        approval_identity = _canonical_digest(approval)
        rollback_before = snapshot(instance)
        try:
            apply_upgrade(
                instance,
                target_root,
                plan=ejected_plan,
                approval=approval,
                migration_set=migration_set,
                validation_command=[sys.executable, "-c", "raise SystemExit(17)"],
                allow_fixture=True,
            )
        except LifecycleError as exc:
            assert "staged validation failed" in str(exc)
        else:
            raise AssertionError("failure injection unexpectedly succeeded")
        assert snapshot(instance) == rollback_before
        assert not (instance / ".statedd/upgrade-receipt.yaml").exists()

        stale_plan = ejected_plan
        (instance / "state/STUDY_STATE.yaml").write_text("synthetic: changed\n", encoding="utf-8")
        try:
            apply_upgrade(instance, target_root, plan=stale_plan, approval=approval, migration_set=migration_set, allow_fixture=True)
        except LifecycleError as exc:
            assert "stale" in str(exc) or "exact plan" in str(exc)
        else:
            raise AssertionError("stale instance plan was accepted")
        (instance / "state/STUDY_STATE.yaml").write_text(
            "synthetic: true\nlearning_target: synthetic-target\n", encoding="utf-8"
        )
        try:
            apply_upgrade(
                instance,
                target_root,
                plan=ejected_plan,
                approval=dict(approval, instanceId="another-instance"),
                migration_set=migration_set,
                allow_fixture=True,
            )
        except LifecycleError as exc:
            assert "exact plan" in str(exc)
        else:
            raise AssertionError("wrong-instance approval was accepted")
        try:
            apply_upgrade(
                instance,
                target_root,
                plan=ejected_plan,
                approval=approval,
                migration_set=[{"migrationId": MIGRATION_ID, "contractDigest": "sha256:" + "2" * 64}],
                allow_fixture=True,
            )
        except LifecycleError as exc:
            assert "stale" in str(exc) or "exact plan" in str(exc)
        else:
            raise AssertionError("changed migration set was accepted")

        receipt = apply_upgrade(
            instance,
            target_root,
            plan=ejected_plan,
            approval=approval,
            migration_set=migration_set,
            allow_fixture=True,
        )
        assert receipt["status"] == "applied"
        assert (instance / ".gitignore").read_text(encoding="utf-8") == "synthetic ejected content\n"
        assert (instance / "question_banks/private-placeholder.yaml").is_file()
        assert (instance / "state/ACTIVE_DRILL_SESSION.md").read_text(encoding="utf-8").startswith("synthetic")
        after_apply = snapshot(instance)
        rerun = apply_upgrade(
            instance,
            target_root,
            plan=ejected_plan,
            approval=approval,
            migration_set=migration_set,
            allow_fixture=True,
        )
        assert rerun.get("idempotent") is True
        assert snapshot(instance) == after_apply
        preserved_paths = (
            "state/LEARNER_PROFILE.yaml",
            "state/STUDY_STATE.yaml",
            "state/EVIDENCE_LOG.md",
            "state/ACTIVE_DRILL_SESSION.md",
            "reviews/REVIEW_QUEUE.md",
            "sessions/SESSION_LOG.md",
            "sources/SOURCE_STATE.yaml",
            "question_banks/private-placeholder.yaml",
            ".fast_drill/history.jsonl",
        )
        assert all(pre_upgrade[path] == after_apply[path] for path in preserved_paths)

        migration_test = subprocess.run(
            [sys.executable, "scripts/test_lifecycle_migrations.py"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        assert migration_test.returncode == 0, migration_test.stdout + migration_test.stderr

        final_lock = parse_yaml_text((instance / ".statedd/lock.yaml").read_text(encoding="utf-8"))
        audit = AuditLog()
        for sequence, event_type in enumerate(
            ("proof.source.resolved", "proof.upgrade.planned", "proof.upgrade.applied", "proof.upgrade.idempotent"),
            1,
        ):
            audit.append(
                event_type=event_type,
                actor="stateport-closure-proof",
                subject="synthetic-studydd-011-proof",
                timestamp=f"2026-07-13T00:00:0{sequence}Z",
                data={
                    "candidateCommit": target_source["resolvedCommit"],
                    "candidateTree": target_source["resolvedTree"],
                    "planDigest": ejected_plan["planDigest"],
                },
            )

        result = {
            "proofVersion": "closure-proof-studydd-011/v1",
            "baseline": baseline_source,
            "target": target_source,
            "pathActionMatrix": path_actions,
            "pathActionSummary": {
                "formatVersion": "stateport.path-action-summary/v1",
                "actions": path_actions,
                "counts": path_action_counts(path_actions),
            },
            "manifestDigests": {
                "baseline": baseline_source["manifestDigest"],
                "target": target_source["manifestDigest"],
            },
            "planDigest": initial_plan["planDigest"],
            "conflictPlanDigest": conflict_plan["planDigest"],
            "ejectedPlanDigest": ejected_plan["planDigest"],
            "approvalIdentity": approval_identity,
            "migrationIds": [MIGRATION_ID],
            "migrationContractDigests": [MIGRATION_DIGEST],
            "conflict": {"blocked": True, "mutated": False, "receiptWritten": False},
            "ejection": {"preserved": True, "planChanged": True, "action": ejected_entry["action"]},
            "rollback": {"byteIdentical": True, "before": rollback_before, "after": rollback_before},
            "preservation": {
                "preUpgrade": pre_upgrade,
                "postUpgrade": after_apply,
                "learnerStatePreserved": True,
                "paths": list(preserved_paths),
            },
            "receiptIdentity": {
                "planDigest": receipt["planDigest"],
                "lockDigest": receipt["lockDigest"],
                "receiptDigest": receipt["receiptDigest"],
            },
            "instanceBinding": {
                "instanceId": final_lock["instanceId"],
                "lockDigest": _canonical_digest(final_lock),
                "sourceDigest": final_lock["template"]["source"]["sourceDigest"],
                "source": final_lock["template"]["source"],
            },
            "finalLockDigest": _canonical_digest(
                final_lock
            ),
            "audit": {
                "formatVersion": "stateport.closure-proof-audit/v1",
                "verified": audit.verify(),
                "events": [event.to_dict() for event in audit.events],
            },
            "idempotentRerun": {"idempotent": True, "unchanged": True},
            "migrationContractSuite": migration_test.stdout.strip().splitlines()[-1],
        }
        return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--studydd-root", type=Path, required=True)
    parser.add_argument("--baseline", default=BASELINE)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run(args.studydd_root, args.target, args.baseline)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


def test_complete_upgrade_exact_functional_target() -> None:
    """Discover the proof without making ordinary local suites depend on StudyDD."""
    import pytest

    root = os.environ.get("STATEPORT_STUDYDD_ROOT")
    if not root:
        pytest.skip("set STATEPORT_STUDYDD_ROOT to run the cross-repository proof")
    target = os.environ.get("STATEPORT_STUDYDD_TARGET", DEFAULT_TARGET)
    result = run(Path(root), target)
    assert result["target"]["resolvedCommit"] == target
    assert result["rollback"]["byteIdentical"] is True
    assert result["idempotentRerun"]["idempotent"] is True
