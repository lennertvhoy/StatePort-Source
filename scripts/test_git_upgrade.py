#!/usr/bin/env python3
"""Focused proof for immutable Git resolution and transactional upgrades."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "statedd-core" / "src"))

from statedd_core import (  # noqa: E402
    LifecycleError,
    apply_upgrade,
    approve_upgrade_plan,
    create_instance,
    plan_upgrade,
    resolve_git_source,
)
from statedd_core.lifecycle import _write_yaml  # noqa: E402
from statedd_core.yaml import parse_yaml_text  # noqa: E402


FIXTURE = ROOT / "fixtures" / "templates" / "lifecycle-v2-minimal"


def _git(cwd: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=cwd, text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def _canonical_repo(parent: Path, name: str) -> Path:
    root = parent / name
    shutil.copytree(FIXTURE, root)
    template = root / "template.yaml"
    template.write_text(
        template.read_text(encoding="utf-8").replace(
            "stateport.fixture.lifecycle-v2-minimal", "git-fixture"
        ),
        encoding="utf-8",
    )
    manifest_path = root / ".statedd" / "manifest.yaml"
    manifest = parse_yaml_text(manifest_path.read_text(encoding="utf-8"))
    manifest["template"]["id"] = "git-fixture"
    manifest["source"] = {"class": "canonical_source", "productionEligible": True}
    _write_yaml(manifest_path, manifest)
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "StatePort test")
    _git(root, "config", "user.email", "stateport-test@example.invalid")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "baseline")
    return root


def test_git_resolution_is_immutable_and_lock_bound() -> None:
    with tempfile.TemporaryDirectory(prefix="stateport-git-source-") as raw:
        parent = Path(raw)
        source = _canonical_repo(parent, "source")
        descriptor = resolve_git_source(source)
        assert len(descriptor["resolvedCommit"]) == 40
        assert len(descriptor["resolvedTree"]) == 40
        instance = parent / "instance"
        lock = create_instance(
            source,
            instance,
            instance_id="demo",
            name="Demo",
            owner_name="Operator",
            owner_handle="@operator",
            source_descriptor=descriptor,
        )
        assert lock["template"]["source"] == descriptor
        assert lock["template"]["sourceRevision"] == descriptor["sourceDigest"]


def test_upgrade_requires_exact_approval_and_is_idempotent() -> None:
    with tempfile.TemporaryDirectory(prefix="stateport-git-upgrade-") as raw:
        parent = Path(raw)
        source = _canonical_repo(parent, "source")
        target = parent / "target"
        _git(parent, "clone", "-q", source.as_posix(), target.as_posix())
        (target / "README.md").write_text("release candidate\n", encoding="utf-8")
        template = target / "template.yaml"
        template.write_text(template.read_text(encoding="utf-8").replace("version: 0.0.1", "version: 0.0.2"), encoding="utf-8")
        manifest_path = target / ".statedd" / "manifest.yaml"
        manifest = parse_yaml_text(manifest_path.read_text(encoding="utf-8"))
        manifest["template"]["releaseVersion"] = "0.0.2"
        _write_yaml(manifest_path, manifest)
        _git(target, "add", ".")
        _git(target, "commit", "-qm", "release candidate")

        instance = parent / "instance"
        descriptor = resolve_git_source(source)
        create_instance(
            source,
            instance,
            instance_id="demo",
            name="Demo",
            owner_name="Operator",
            owner_handle="@operator",
            source_descriptor=descriptor,
        )
        plan = plan_upgrade(instance, target)
        assert plan["safe"] is True
        approval = approve_upgrade_plan(plan, approved_by="operator")
        bad = dict(approval, planDigest="sha256:" + "0" * 64)
        try:
            apply_upgrade(instance, target, plan=plan, approval=bad)
        except LifecycleError as exc:
            assert "exact plan digest" in str(exc)
        else:
            raise AssertionError("mismatched approval was accepted")
        before = {
            path.relative_to(instance).as_posix(): path.read_bytes()
            for path in instance.rglob("*")
            if path.is_file()
        }
        try:
            apply_upgrade(
                instance,
                target,
                plan=plan,
                approval=approval,
                validation_command=[sys.executable, "-c", "raise SystemExit(7)"],
                allow_fixture=True,
            )
        except LifecycleError as exc:
            assert "staged validation failed" in str(exc)
        else:
            raise AssertionError("failed staged validation was accepted")
        after = {
            path.relative_to(instance).as_posix(): path.read_bytes()
            for path in instance.rglob("*")
            if path.is_file()
        }
        assert after == before
        assert not (instance / ".statedd" / "upgrade-receipt.yaml").exists()
        receipt = apply_upgrade(instance, target, plan=plan, approval=approval)
        assert receipt["status"] == "applied"
        assert apply_upgrade(instance, target, plan=plan, approval=approval)["idempotent"] is True


def test_override_blocks_plan_before_transaction() -> None:
    with tempfile.TemporaryDirectory(prefix="stateport-git-conflict-") as raw:
        parent = Path(raw)
        source = _canonical_repo(parent, "source")
        target = parent / "target"
        _git(parent, "clone", "-q", source.as_posix(), target.as_posix())
        (target / "README.md").write_text("new template\n", encoding="utf-8")
        template = target / "template.yaml"
        template.write_text(template.read_text(encoding="utf-8").replace("version: 0.0.1", "version: 0.0.2"), encoding="utf-8")
        manifest_path = target / ".statedd" / "manifest.yaml"
        manifest = parse_yaml_text(manifest_path.read_text(encoding="utf-8"))
        manifest["template"]["releaseVersion"] = "0.0.2"
        _write_yaml(manifest_path, manifest)
        _git(target, "add", ".")
        _git(target, "commit", "-qm", "release candidate")
        instance = parent / "instance"
        create_instance(
            source,
            instance,
            instance_id="demo",
            name="Demo",
            owner_name="Operator",
            owner_handle="@operator",
            source_descriptor=resolve_git_source(source),
        )
        (instance / "README.md").write_text("local override\n", encoding="utf-8")
        plan = plan_upgrade(instance, target)
        assert plan["blocked"] is True
        assert any(item["classification"] == "overridden" for item in plan["entries"])


def test_upgrade_refreshes_checked_in_generated_baseline() -> None:
    with tempfile.TemporaryDirectory(prefix="stateport-generated-upgrade-") as raw:
        parent = Path(raw)
        source = _canonical_repo(parent, "source")
        manifest_path = source / ".statedd" / "manifest.yaml"
        manifest = parse_yaml_text(manifest_path.read_text(encoding="utf-8"))
        manifest["modules"][0]["assets"].append("generated-view")
        manifest["assets"].append(
            {
                "id": "generated-view",
                "path": "generated-view.yaml",
                "kind": "file",
                "owner": "generated",
                "role": "compatibility_view",
                "provisionPolicy": "generated_output",
                "updatePolicy": "generated",
                "required": True,
                "schema": "fixture.view/v1",
                "sensitivity": "internal",
                "generator": "fixture-generator",
                "selectingModules": ["core"],
            }
        )
        _write_yaml(manifest_path, manifest)
        (source / "state").mkdir(exist_ok=True)
        (source / "generated-view.yaml").write_text("baseline\n", encoding="utf-8")
        _git(source, "add", ".")
        _git(source, "commit", "-qm", "add generated compatibility baseline")

        target = parent / "target"
        _git(parent, "clone", "-q", source.as_posix(), target.as_posix())
        target_manifest = parse_yaml_text((target / ".statedd" / "manifest.yaml").read_text(encoding="utf-8"))
        target_manifest["template"]["releaseVersion"] = "0.0.2"
        _write_yaml(target / ".statedd" / "manifest.yaml", target_manifest)
        (target / "template.yaml").write_text(
            (target / "template.yaml").read_text(encoding="utf-8").replace(
                "version: 0.0.1", "version: 0.0.2"
            ),
            encoding="utf-8",
        )
        (target / "generated-view.yaml").write_text("target\n", encoding="utf-8")
        _git(target, "add", ".")
        _git(target, "commit", "-qm", "refresh generated compatibility baseline")

        instance = parent / "instance"
        create_instance(
            source,
            instance,
            instance_id="generated-demo",
            name="Generated Demo",
            owner_name="Operator",
            owner_handle="@operator",
        )
        assert (instance / "generated-view.yaml").read_text(encoding="utf-8") == "baseline\n"
        plan = plan_upgrade(instance, target)
        receipt = apply_upgrade(
            instance,
            target,
            plan=plan,
            approval=approve_upgrade_plan(plan, approved_by="operator"),
        )
        assert receipt["status"] == "applied"
        assert (instance / "generated-view.yaml").read_text(encoding="utf-8") == "target\n"
