#!/usr/bin/env python3
"""Unit tests for the StatePort local runner."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
for _src in [
    ROOT / "packages" / "statedd-core" / "src",
    ROOT / "packages" / "template-validator" / "src",
    ROOT / "apps" / "runner" / "src",
    ROOT / "apps" / "admin-cli" / "src",
]:
    if str(_src) not in sys.path:
        sys.path.insert(0, str(_src))

from runner import run_instance


def _copy_instance_to(destination: Path) -> Path:
    """Copy the demo instance and its template into a mirrored temp repo layout.

    Preserves the relative ``../../templates/classdd`` reference from the demo
    instance so that template resolution succeeds and missing-state-file errors
    are surfaced as intended.
    """
    instance_source = ROOT / "instances" / "demo-classdd"
    template_source = ROOT / "templates" / "classdd"
    instance_dest = destination / "instances" / "demo-classdd"
    template_dest = destination / "templates" / "classdd"
    shutil.copytree(instance_source, instance_dest)
    shutil.copytree(template_source, template_dest)
    return instance_dest


def test_demo_instance_runs() -> None:
    result = run_instance(ROOT / "instances" / "demo-classdd")
    assert result.ok, result.errors
    assert result.status == "active"
    assert any("instance loaded: demo-classdd" in log for log in result.logs)
    assert any("template loaded: classdd" in log for log in result.logs)
    assert any("state files present" in log for log in result.logs)


def test_missing_state_file_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        instance_path = _copy_instance_to(Path(tmpdir))
        (instance_path / "state" / "topics.yaml").unlink()
        result = run_instance(instance_path)
        assert not result.ok
        assert any("state/topics.yaml" in err for err in result.errors)


def test_invalid_instance_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        instance_path = _copy_instance_to(Path(tmpdir))
        (instance_path / "instance.yaml").write_text(
            "not-a-mapping", encoding="utf-8"
        )
        result = run_instance(instance_path)
        assert not result.ok


def test_inactive_instance_reports_status() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        instance_path = _copy_instance_to(Path(tmpdir))
        text = (instance_path / "instance.yaml").read_text(encoding="utf-8")
        text = text.replace("status: active", "status: archived")
        (instance_path / "instance.yaml").write_text(text, encoding="utf-8")
        result = run_instance(instance_path)
        assert result.ok, result.errors
        assert result.status == "archived"


def test_draft_status_allowed() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        instance_path = _copy_instance_to(Path(tmpdir))
        text = (instance_path / "instance.yaml").read_text(encoding="utf-8")
        text = text.replace("status: active", "status: draft")
        (instance_path / "instance.yaml").write_text(text, encoding="utf-8")
        result = run_instance(instance_path)
        assert result.ok, result.errors
        assert result.status == "draft"


def test_unknown_status_fails() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        instance_path = _copy_instance_to(Path(tmpdir))
        text = (instance_path / "instance.yaml").read_text(encoding="utf-8")
        text = text.replace("status: active", "status: pending")
        (instance_path / "instance.yaml").write_text(text, encoding="utf-8")
        result = run_instance(instance_path)
        assert not result.ok
        assert result.status == "pending"
        assert any(
            "invalid instance status 'pending'" in err for err in result.errors
        )
        assert any("active, archived, draft" in err for err in result.errors)


def test_unexpected_exception_caught_as_run_result_error() -> None:
    """Malformed inputs that slip past the validator must not leak tracebacks."""
    with tempfile.TemporaryDirectory() as tmpdir:
        instance_path = _copy_instance_to(Path(tmpdir))
        with patch(
            "runner.runner.check_template_ref_resolves",
            side_effect=RuntimeError("simulated unexpected failure"),
        ):
            result = run_instance(instance_path)
        assert not result.ok
        assert result.status == "active"
        assert any(
            "unexpected runner error: simulated unexpected failure" in err
            for err in result.errors
        )


def _copy_repo_to(destination: Path) -> Path:
    """Copy the demo template and instance into a mirrored repo layout."""
    repo = destination / "repo"
    repo.mkdir()
    (repo / "instances").mkdir()
    (repo / "templates").mkdir()
    shutil.copytree(ROOT / "instances" / "demo-classdd", repo / "instances" / "demo-classdd")
    shutil.copytree(ROOT / "templates" / "classdd", repo / "templates" / "classdd")
    return repo / "instances" / "demo-classdd"


def test_schema_path_traversal_fails_in_runner() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        instance_path = _copy_repo_to(Path(tmpdir))
        template_path = instance_path.parents[1] / "templates" / "classdd"
        text = (template_path / "template.yaml").read_text(encoding="utf-8")
        text = text.replace("state/class.yaml", "../etc/passwd")
        (template_path / "template.yaml").write_text(text, encoding="utf-8")
        result = run_instance(instance_path)
        assert not result.ok
        assert any("traversal" in err.lower() for err in result.errors)


def test_template_ref_id_mismatch_fails_in_runner() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        instance_path = _copy_repo_to(Path(tmpdir))
        text = (instance_path / "instance.yaml").read_text(encoding="utf-8")
        text = text.replace("id: classdd", "id: wrong-id")
        (instance_path / "instance.yaml").write_text(text, encoding="utf-8")
        result = run_instance(instance_path)
        assert not result.ok
        assert any("id" in err.lower() for err in result.errors)


def test_output_determinism() -> None:
    instance_path = ROOT / "instances" / "demo-classdd"
    result_a = run_instance(instance_path)
    result_b = run_instance(instance_path)
    assert result_a == result_b


def test_wrapper_run_instance_smoke() -> None:
    result = subprocess.run(
        [
            str(ROOT / "stateport"),
            "run-instance",
            str(ROOT / "instances" / "demo-classdd"),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "active"
    assert payload["errors"] == []


def test_wrapper_run_instance_fails_on_missing_state() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        instance_path = _copy_instance_to(Path(tmpdir))
        (instance_path / "state" / "topics.yaml").unlink()
        result = subprocess.run(
            [
                str(ROOT / "stateport"),
                "run-instance",
                str(instance_path),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 1, result.stdout + result.stderr
        payload = json.loads(result.stdout)
        assert any("state/topics.yaml" in err for err in payload["errors"])


def test_container_runner_module_cli_emits_structured_result() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "runner",
            str(ROOT / "instances" / "demo-classdd"),
        ],
        cwd=ROOT,
        env={
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": os.pathsep.join(
                (
                    str(ROOT / "packages" / "statedd-core" / "src"),
                    str(ROOT / "packages" / "template-validator" / "src"),
                    str(ROOT / "apps" / "runner" / "src"),
                )
            ),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["status"] == "active"
    assert payload["errors"] == []


def test_trusted_template_override_supports_flat_container_mounts() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        instance = root / "instance"
        template = root / "template"
        shutil.copytree(ROOT / "instances" / "demo-classdd", instance)
        shutil.copytree(ROOT / "templates" / "classdd", template)
        direct = run_instance(instance, template_path_override=template)
        assert direct.ok, direct.errors
        result = subprocess.run(
            [sys.executable, "-m", "runner", str(instance)],
            cwd=ROOT,
            env={
                "PATH": os.environ.get("PATH", ""),
                "PYTHONPATH": os.pathsep.join(
                    (
                        str(ROOT / "packages" / "statedd-core" / "src"),
                        str(ROOT / "packages" / "template-validator" / "src"),
                        str(ROOT / "apps" / "runner" / "src"),
                    )
                ),
                "STATEPORT_TEMPLATE_PATH": str(template),
            },
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert json.loads(result.stdout)["ok"] is True
if __name__ == "__main__":
    test_demo_instance_runs()
    test_missing_state_file_fails()
    test_invalid_instance_fails()
    test_inactive_instance_reports_status()
    test_draft_status_allowed()
    test_unknown_status_fails()
    test_unexpected_exception_caught_as_run_result_error()
    test_schema_path_traversal_fails_in_runner()
    test_template_ref_id_mismatch_fails_in_runner()
    test_output_determinism()
    test_wrapper_run_instance_smoke()
    test_wrapper_run_instance_fails_on_missing_state()
    test_container_runner_module_cli_emits_structured_result()
    test_trusted_template_override_supports_flat_container_mounts()
    print("PASS")
