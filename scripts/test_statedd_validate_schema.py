#!/usr/bin/env python3
"""Regression tests for StatePort schema validation and admin CLI/scripts."""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "statedd_validate_schema.py"

# Make in-process imports of the scripts and local packages possible.
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "packages" / "statedd-core" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "template-validator" / "src"))
for package_source in sorted((ROOT / "packages").glob("*/src")):
    sys.path.insert(0, str(package_source))
sys.path.insert(0, str(ROOT / "apps" / "runner" / "src"))
sys.path.insert(0, str(ROOT / "apps" / "admin-cli" / "src"))


def run(
    args: list[str], *, cwd: Path = ROOT, expect_success: bool
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        [sys.executable, str(VALIDATOR), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    output = f"{completed.stdout}\n{completed.stderr}"
    if expect_success and completed.returncode != 0:
        raise AssertionError(f"Expected success, got {completed.returncode}\n{output}")
    if not expect_success and completed.returncode == 0:
        raise AssertionError(f"Expected failure, got success\n{output}")
    return completed


def test_root_passes() -> None:
    run([str(ROOT)], expect_success=True)


def test_missing_product_contracts_fail() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        run([tmpdir], expect_success=False)


_REPO_COPY_IGNORE = shutil.ignore_patterns(
    ".git", "__pycache__", ".venv", "node_modules", ".terraform", ".tmp"
)


def _copy_repo_to(destination: Path, *, source: Path = ROOT) -> None:
    """Copy the repository without the scratch dir or the destination itself.

    ``TMPDIR`` may point inside the repository (``.tmp``); without these
    exclusions the copy would descend into the destination it is writing
    and nest recursively without bound.
    """
    resolved_destination = destination.resolve()

    def ignore(directory: str, names: list[str]) -> set[str]:
        ignored = set(_REPO_COPY_IGNORE(directory, names))
        for name in names:
            candidate = Path(directory, name).resolve()
            if candidate == resolved_destination or candidate in resolved_destination.parents:
                ignored.add(name)
        return ignored

    shutil.copytree(source, destination, ignore=ignore, dirs_exist_ok=True)


def test_copy_repo_to_excludes_scratch_and_destination() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        source = Path(tmpdir) / "source"
        scratch = source / "scratch"
        scratch.mkdir(parents=True)
        (source / "marker.txt").write_text("marker\n", encoding="utf-8")
        leftover = source / ".tmp"
        leftover.mkdir()
        (leftover / "leftover.txt").write_text("leftover\n", encoding="utf-8")
        destination = scratch / "repo"
        _copy_repo_to(destination, source=source)
        assert (destination / "marker.txt").is_file()
        assert not (destination / ".tmp").exists()
        assert not (destination / "scratch").exists()
        assert list(destination.rglob("repo")) == []


def test_coordination_files_are_not_product_schema_inputs() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_copy = Path(tmpdir) / "repo"
        _copy_repo_to(repo_copy)
        (repo_copy / "AGENTS.md").unlink()
        for name in (
            "PROJECT_STATE.yaml",
            "PROJECT_DNA.yaml",
            "PROJECT_ADAPTER.yaml",
            "STATUS.md",
            "NEXT_ACTIONS.md",
        ):
            path = repo_copy / name
            if path.exists():
                path.unlink()
        run([str(repo_copy)], cwd=repo_copy, expect_success=True)


# ---------------------------------------------------------------------------
# JSON Schema subset regression tests
# ---------------------------------------------------------------------------


def test_additional_properties_false_without_properties() -> None:
    from statedd_validate_schema import validate_json_schema

    schema: dict[str, object] = {"type": "object", "additionalProperties": False}
    issues = validate_json_schema({"unexpected": 1}, schema)
    assert any(
        "additional property is not allowed" in issue.message for issue in issues
    ), issues


# ---------------------------------------------------------------------------
# admin-cli regression tests
# ---------------------------------------------------------------------------


def test_main_py_does_not_mutate_sys_path_on_import() -> None:
    """Importing admin_cli.main must not insert local src paths into sys.path."""
    src_paths = [
        ROOT / "packages" / "statedd-core" / "src",
        ROOT / "packages" / "template-validator" / "src",
        ROOT / "apps" / "runner" / "src",
        ROOT / "apps" / "admin-cli" / "src",
    ]
    path_list = ", ".join(f"r'{p}'" for p in src_paths)
    code = (
        "import json, sys\n"
        "before = set(sys.path)\n"
        "from admin_cli import main\n"
        "after = set(sys.path)\n"
        f"inserted = {{str(p) for p in [{path_list}]}}\n"
        "extra = inserted & (after - before)\n"
        "print(json.dumps({'extra': sorted(extra)}))\n"
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(str(p) for p in src_paths)
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=env,
    )
    if completed.returncode != 0:
        raise AssertionError(f"Import failed: {completed.stderr}")
    data = json.loads(completed.stdout.strip())
    assert data["extra"] == [], f"sys.path mutated on import: {data['extra']}"


def test_run_instance_cmd_catches_unexpected_exception() -> None:
    """run_instance_cmd must catch unexpected exceptions and emit JSON errors."""
    from admin_cli import commands

    original = commands.run_instance

    def boom(path: Path) -> None:
        raise RuntimeError("simulated runner failure")

    commands.run_instance = boom  # type: ignore[assignment]
    try:
        with mock.patch("sys.stdout", new_callable=io.StringIO) as captured:
            rc = commands.run_instance_cmd("/tmp/fake-instance")
    finally:
        commands.run_instance = original
    payload = json.loads(captured.getvalue())
    assert rc == 1
    assert payload["status"] == "error"
    assert any("simulated runner failure" in err for err in payload["errors"])


def test_lifecycle_preview_commands_are_read_only_and_return_success() -> None:
    """The CLI exposes override and upgrade previews without applying changes."""
    from admin_cli import commands
    from statedd_core import create_instance

    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        template = workspace / "template"
        instance = workspace / "instance"
        shutil.copytree(ROOT / "templates" / "classdd", template)
        create_instance(
            template,
            instance,
            instance_id="cli-demo",
            name="CLI demo",
            owner_name="Alice",
            owner_handle="@alice",
        )
        before = {
            path.relative_to(instance).as_posix(): path.read_bytes()
            for path in instance.rglob("*")
            if path.is_file()
        }

        with mock.patch("sys.stdout", new_callable=io.StringIO) as captured:
            inspect_rc = commands.inspect_overrides_cmd(
                str(instance), str(template)
            )
        inspect_payload = json.loads(captured.getvalue())
        assert inspect_rc == 0
        assert inspect_payload["safe"] is True

        with mock.patch("sys.stdout", new_callable=io.StringIO) as captured:
            plan_rc = commands.plan_upgrade_cmd(str(instance), str(template))
        plan_payload = json.loads(captured.getvalue())
        assert plan_rc == 0
        assert plan_payload["dryRun"] is True
        assert plan_payload["applied"] is False

        after = {
            path.relative_to(instance).as_posix(): path.read_bytes()
            for path in instance.rglob("*")
            if path.is_file()
        }
        assert after == before


# ---------------------------------------------------------------------------
# validate_repo.py regression tests
# ---------------------------------------------------------------------------


def test_check_templates_uses_statedd_core_yaml() -> None:
    """check_templates must always validate YAML using the project's parser."""
    import validate_repo

    with tempfile.TemporaryDirectory() as tmpdir:
        repo = Path(tmpdir) / "repo"
        template_dir = repo / "templates" / "classdd"
        template_dir.mkdir(parents=True)
        template_path = template_dir / "template.yaml"
        template_path.write_text("name: example\n", encoding="utf-8")

        original_root = validate_repo.REPO_ROOT
        original_required = validate_repo.REQUIRED_TEMPLATES
        validate_repo.REPO_ROOT = repo
        validate_repo.REQUIRED_TEMPLATES = ["templates/classdd/template.yaml"]
        try:
            assert validate_repo.check_templates() is True

            template_path.write_text(
                "name: example\nname: duplicate\n", encoding="utf-8"
            )
            assert validate_repo.check_templates() is False
        finally:
            validate_repo.REPO_ROOT = original_root
            validate_repo.REQUIRED_TEMPLATES = original_required


def test_check_templates_accepts_v2_source_without_compatibility_yaml() -> None:
    import validate_repo

    with tempfile.TemporaryDirectory() as tmpdir:
        repo = Path(tmpdir) / "repo"
        template_dir = repo / "fixtures" / "templates" / "v2"
        shutil.copytree(ROOT / "fixtures" / "templates" / "lifecycle-v2-minimal", template_dir)
        (template_dir / "template.yaml").unlink()

        original_root = validate_repo.REPO_ROOT
        original_required = validate_repo.REQUIRED_TEMPLATES
        validate_repo.REPO_ROOT = repo
        validate_repo.REQUIRED_TEMPLATES = ["fixtures/templates/v2/template.yaml"]
        try:
            assert validate_repo.check_templates() is True
        finally:
            validate_repo.REPO_ROOT = original_root
            validate_repo.REQUIRED_TEMPLATES = original_required


def test_check_secrets_env_and_extensionless() -> None:
    """check_secrets must scan .env and extensionless files for token-like values."""
    import validate_repo

    with tempfile.TemporaryDirectory() as tmpdir:
        repo = Path(tmpdir) / "repo"
        repo.mkdir()
        # Build token-like values at runtime so the test source itself does not
        # trigger the secret scanner while still exercising the broader patterns.
        (repo / ".env").write_text(
            "API_KEY=" + "A" * 32 + "\n", encoding="utf-8"
        )
        (repo / "credentials").write_text(
            "token=" + "A" * 16 + "/" + "B" * 16 + "==\n", encoding="utf-8"
        )

        original_root = validate_repo.REPO_ROOT
        validate_repo.REPO_ROOT = repo
        try:
            with mock.patch("sys.stdout", new_callable=io.StringIO) as captured:
                result = validate_repo.check_secrets()
            output = captured.getvalue()
            assert result is True
            assert ".env" in output
            assert "credentials" in output
        finally:
            validate_repo.REPO_ROOT = original_root


if __name__ == "__main__":
    test_root_passes()
    test_missing_product_contracts_fail()
    test_coordination_files_are_not_product_schema_inputs()
    test_additional_properties_false_without_properties()
    test_main_py_does_not_mutate_sys_path_on_import()
    test_run_instance_cmd_catches_unexpected_exception()
    test_lifecycle_preview_commands_are_read_only_and_return_success()
    test_check_templates_uses_statedd_core_yaml()
    test_check_secrets_env_and_extensionless()
    print("PASS")
