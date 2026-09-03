#!/usr/bin/env python3
"""Acceptance tests for the headless governed API boundary."""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for relative in (
    "packages/governed-api/src",
    "packages/statedd-core/src",
    "packages/template-validator/src",
    "packages/approval-gate/src",
    "packages/quota-engine/src",
    "packages/audit-log/src",
    "packages/governed-runner/src",
    "packages/container-runner/src",
    "apps/runner/src",
):
    path = ROOT / relative
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from governed_api import GovernedAPI
from statedd_core import create_instance


CLASSDD = ROOT / "templates" / "classdd"


def _fixture(workspace: Path) -> tuple[GovernedAPI, Path, Path]:
    template = workspace / "template"
    shutil.copytree(CLASSDD, template)
    instance = workspace / "instance"
    create_instance(
        template,
        instance,
        instance_id="api-demo",
        name="API demo",
        owner_name="Tester",
        owner_handle="@tester",
    )
    return GovernedAPI(workspace), template, instance


def test_health_and_capabilities_are_explicitly_read_only() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        api = GovernedAPI(tmpdir)
        health = api.dispatch("GET", "/health")
        assert health.status == 200
        assert health.body["result"]["readOnly"] is True
        capabilities = api.dispatch("GET", "/v1/capabilities")
        assert capabilities.status == 200
        assert capabilities.body["result"]["mutations"] == []
        assert "plan-upgrade" in capabilities.body["result"]["operations"]


def test_validation_and_lifecycle_routes_return_structured_results() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        api, template, instance = _fixture(Path(tmpdir))
        template_result = api.dispatch("POST", "/v1/validate/template", {"path": "template"})
        instance_result = api.dispatch("POST", "/v1/validate/instance", {"path": "instance"})
        overrides = api.dispatch(
            "POST",
            "/v1/lifecycle/overrides",
            {"instancePath": "instance", "templatePath": "template"},
        )
        plan = api.dispatch(
            "POST",
            "/v1/lifecycle/upgrade-plan",
            {"instancePath": "instance", "templatePath": "template"},
        )
        assert template_result.status == instance_result.status == 200
        assert template_result.body["result"]["valid"] is True
        assert instance_result.body["result"]["valid"] is True
        assert overrides.body["result"]["formatVersion"] == "statedd.override-report/v1"
        assert plan.body["result"]["dryRun"] is True
        assert plan.body["result"]["applied"] is False
        assert template.exists() and instance.exists()


def test_context_routes_build_inspect_and_compare_without_persisting_pack() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        api, _, instance = _fixture(Path(tmpdir))
        before = {
            path.relative_to(instance).as_posix(): path.read_bytes()
            for path in instance.rglob("*")
            if path.is_file()
        }
        built = api.dispatch(
            "POST",
            "/v1/context/build",
            {
                "instancePath": "instance",
                "task": "class students status",
                "model": "test-model",
                "budgetTokens": 200,
                "profile": "compact",
                "selection": "eager",
            },
        )
        assert built.status == 200
        pack = built.body["result"]
        assert pack["manifest"]["formatVersion"] == "statepack/v1"
        inspected = api.dispatch("POST", "/v1/context/inspect", {"pack": pack})
        compared = api.dispatch(
            "POST", "/v1/context/compare", {"left": pack, "right": pack}
        )
        assert inspected.body["result"]["valid"] is True
        assert compared.body["result"]["equal"] is True
        after = {
            path.relative_to(instance).as_posix(): path.read_bytes()
            for path in instance.rglob("*")
            if path.is_file()
        }
        assert before == after


def test_paths_methods_and_malformed_requests_fail_closed() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        api, _, _ = _fixture(Path(tmpdir))
        assert api.dispatch("DELETE", "/v1/context/build").status == 405
        assert api.dispatch("POST", "/v1/unknown", {}).status == 404
        missing = api.dispatch("POST", "/v1/validate/template", {})
        assert missing.status == 400
        assert missing.body["ok"] is False
        outside = api.dispatch(
            "POST", "/v1/validate/template", {"path": "../outside"}
        )
        assert outside.status == 403
        assert outside.body["error"]["code"] == "path_forbidden"


def test_context_inspect_invalid_pack_uses_successful_transport_and_invalid_result() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        api = GovernedAPI(tmpdir)
        response = api.dispatch("POST", "/v1/context/inspect", {"pack": {"manifest": {}, "text": ""}})
        assert response.status == 200
        assert response.body["result"]["valid"] is False


def test_governance_routes_apply_intersection_and_quota_checks() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        api = GovernedAPI(tmpdir)
        policy = api.dispatch(
            "POST",
            "/v1/policy/check",
            {"operation": "write", "capability": "write", "templateRequested": ["write"], "instanceGranted": ["write"], "operatorAllowed": ["read"]},
        )
        quota = api.dispatch(
            "POST",
            "/v1/quota/check",
            {"runsPerDay": 1, "runsToday": 1, "estimatedCost": 0},
        )
        assert policy.body["result"]["allowed"] is False
        assert quota.body["result"]["allowed"] is False


def test_mutation_snapshot_restore_preserves_modes_and_removes_added_directories() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir) / "instance"
        nested = root / "scripts"
        nested.mkdir(parents=True)
        executable = nested / "run.py"
        executable.write_text("print('safe')\n", encoding="utf-8")
        os.chmod(root, 0o750)
        os.chmod(nested, 0o711)
        os.chmod(executable, 0o755)
        api = GovernedAPI(tmpdir)
        snapshot = api._snapshot(root)  # noqa: SLF001

        executable.write_text("print('changed')\n", encoding="utf-8")
        os.chmod(executable, 0o600)
        added = root / "added" / "nested"
        added.mkdir(parents=True)
        (added / "file.txt").write_text("remove me\n", encoding="utf-8")
        api._restore(root, snapshot)  # noqa: SLF001

        assert executable.read_text(encoding="utf-8") == "print('safe')\n"
        assert executable.stat().st_mode & 0o777 == 0o755
        assert nested.stat().st_mode & 0o777 == 0o711
        assert root.stat().st_mode & 0o777 == 0o750
        assert not (root / "added").exists()


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("PASS")
