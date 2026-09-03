#!/usr/bin/env python3
"""Tests for the StateDD manifest, materialisation, and lockfile slice."""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for source in [
    ROOT / "packages" / "statedd-core" / "src",
    ROOT / "packages" / "template-validator" / "src",
]:
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from statedd_core import (
    LifecycleError,
    MANIFEST_V2_FORMAT,
    apply_upgrade,
    approve_upgrade_plan,
    assert_production_eligible,
    create_instance,
    detect_overrides,
    load_template_manifest,
    materialize_instance,
    plan_upgrade,
    plan_digest,
)
from statedd_core.lifecycle import _write_yaml, describe_template_source, resolve_template_source
from statedd_core.yaml import parse_yaml_text


CLASSDD = ROOT / "templates" / "classdd"
V2_FIXTURE = ROOT / "fixtures" / "templates" / "lifecycle-v2-minimal"
STUDYDD_FIXTURE = ROOT / "fixtures" / "templates" / "studydd-minimal"


def _make_template(parent: Path, *, name: str = "template") -> Path:
    template = parent / name
    shutil.copytree(CLASSDD, template)
    return template


def _make_instance(
    template: Path,
    parent: Path,
    *,
    name: str = "instance",
    allow_fixture: bool = False,
) -> Path:
    destination = parent / name
    create_instance(
        template,
        destination,
        instance_id="demo",
        name="Demo",
        owner_name="Alice",
        owner_handle="@alice",
        allow_fixture=allow_fixture,
    )
    return destination


def _expect_lifecycle_error(action, message: str) -> None:
    try:
        action()
    except LifecycleError as exc:
        assert message in str(exc), str(exc)
    else:
        raise AssertionError(f"expected LifecycleError containing {message!r}")


def _snapshot_tree(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _bump_template_version(template: Path, version: str) -> None:
    template_yaml = (template / "template.yaml").read_text(encoding="utf-8")
    (template / "template.yaml").write_text(
        template_yaml.replace("version: 0.1.0", f"version: {version}"),
        encoding="utf-8",
    )
    manifest_path = template / ".statedd" / "manifest.yaml"
    manifest_yaml = manifest_path.read_text(encoding="utf-8")
    manifest_path.write_text(
        manifest_yaml.replace("templateVersion: 0.1.0", f"templateVersion: {version}"),
        encoding="utf-8",
    )


def _write_v2_manifest(template: Path, data: dict) -> None:
    _write_yaml(template / ".statedd" / "manifest.yaml", data)


def _v2_template(parent: Path, *, name: str = "v2-template") -> Path:
    template = parent / name
    shutil.copytree(V2_FIXTURE, template)
    return template


def _v1_target_without_file(
    parent: Path, source: Path, path: str, *, name: str = "template-target"
) -> Path:
    target = parent / name
    shutil.copytree(source, target)
    manifest_path = target / ".statedd" / "manifest.yaml"
    data = parse_yaml_text(manifest_path.read_text(encoding="utf-8"))
    data["templateVersion"] = "0.2.0"
    data["files"] = [item for item in data["files"] if item["path"] != path]
    _write_yaml(manifest_path, data)
    template_yaml = target / "template.yaml"
    template_yaml.write_text(
        template_yaml.read_text(encoding="utf-8").replace(
            "version: 0.1.0", "version: 0.2.0"
        ),
        encoding="utf-8",
    )
    source_path = target / path
    if source_path.is_file():
        source_path.unlink()
    return target


def _generated_retirement_template(parent: Path, *, name: str) -> Path:
    template = _make_template(parent, name=name)
    generated = template / "generated-view.txt"
    generated.write_text("generated baseline\n", encoding="utf-8")
    manifest_path = template / ".statedd" / "manifest.yaml"
    data = parse_yaml_text(manifest_path.read_text(encoding="utf-8"))
    data["files"].append(
        {
            "path": "generated-view.txt",
            "source": "generated-view.txt",
            "owner": "generated",
            "provision": "generate",
            "merge": "replace",
            "generation": "materializer",
            "retirementPolicy": "remove_if_unmodified",
            "required": True,
            "schema": None,
            "sensitivity": "internal",
        }
    )
    _write_yaml(manifest_path, data)
    return template


def test_all_legacy_bundled_templates_have_matching_manifests() -> None:
    for template_path in sorted((ROOT / "templates").iterdir()):
        if template_path.is_dir():
            manifest = load_template_manifest(template_path)
            assert manifest["templateId"]
            assert manifest["files"]


def test_create_instance_materializes_and_locks_deterministically() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        destination = Path(tmpdir) / "instances" / "demo"
        lock = create_instance(
            CLASSDD,
            destination,
            instance_id="demo",
            name="Demo",
            owner_name="Alice",
            owner_handle="@alice",
        )
        lock_path = destination / ".statedd" / "lock.yaml"
        first_bytes = lock_path.read_bytes()
        assert lock["formatVersion"] == "statedd.lock/v1"
        assert (destination / ".statedd" / "contract.md").read_bytes() == (
            CLASSDD / ".statedd" / "contract.md"
        ).read_bytes()
        assert (destination / "state" / "class.yaml").is_file()
        assert parse_yaml_text(first_bytes.decode("utf-8")) == lock

        second = materialize_instance(CLASSDD, destination)
        assert second == lock
        assert lock_path.read_bytes() == first_bytes


def test_instance_owned_state_is_preserved_on_repeat() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        destination = Path(tmpdir) / "instance"
        create_instance(
            CLASSDD,
            destination,
            instance_id="demo",
            name="Demo",
            owner_name="Alice",
            owner_handle="@alice",
        )
        state_path = destination / "state" / "class.yaml"
        state_path.write_text("class:\n  id: changed\n", encoding="utf-8")
        materialize_instance(CLASSDD, destination)
        assert "changed" in state_path.read_text(encoding="utf-8")


def test_template_owned_change_is_rejected() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        destination = Path(tmpdir) / "instance"
        create_instance(
            CLASSDD,
            destination,
            instance_id="demo",
            name="Demo",
            owner_name="Alice",
            owner_handle="@alice",
        )
        (destination / "README.md").write_text("local override\n", encoding="utf-8")
        _expect_lifecycle_error(
            lambda: materialize_instance(CLASSDD, destination),
            "template-owned file changed",
        )


def test_detect_overrides_classifies_template_and_instance_drift() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        destination = _make_instance(CLASSDD, workspace)
        (destination / "README.md").write_text("local template override\n", encoding="utf-8")
        (destination / "state" / "class.yaml").write_text(
            "class:\n  id: local-state\n", encoding="utf-8"
        )

        report = detect_overrides(destination, CLASSDD)
        entries = {entry["path"]: entry for entry in report["files"]}
        assert report["formatVersion"] == "statedd.override-report/v1"
        assert report["dryRun"] is True
        assert report["blocked"] is True
        assert report["safe"] is False
        assert entries["README.md"]["classification"] == "overridden"
        assert entries["README.md"]["owner"] == "template"
        assert entries["state/class.yaml"]["classification"] == "changed"
        assert entries["state/class.yaml"]["owner"] == "instance"
        assert report["summary"]["overridden"] == 1
        assert report["summary"]["changed"] == 1


def test_detect_overrides_treats_generated_lock_as_non_override() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        destination = _make_instance(CLASSDD, workspace)
        report = detect_overrides(destination, CLASSDD)
        entries = {entry["path"]: entry for entry in report["files"]}
        generated = entries[".statedd/lock.yaml"]

        assert generated["owner"] == "generated"
        assert generated["classification"] == "unchanged"
        assert generated["lockedHash"] is None
        assert report["blocked"] is False
        assert report["safe"] is True


def test_detect_overrides_classifies_missing_required_files_and_blocks() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        destination = _make_instance(CLASSDD, workspace)
        (destination / "README.md").unlink()
        (destination / "state" / "class.yaml").unlink()

        report = detect_overrides(destination, CLASSDD)
        entries = {entry["path"]: entry for entry in report["files"]}
        assert entries["README.md"]["classification"] == "removed"
        assert entries["state/class.yaml"]["classification"] == "removed"
        assert entries["README.md"]["reason"] == "required manifest file is missing"
        assert entries["state/class.yaml"]["reason"] == "required manifest file is missing"
        assert report["summary"]["removed"] == 2
        assert report["blocked"] is True
        assert report["safe"] is False


def test_detect_overrides_reports_unknown_added_files_as_blocked() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        destination = _make_instance(CLASSDD, workspace)
        (destination / "local-not-in-manifest.txt").write_text("local\n", encoding="utf-8")

        report = detect_overrides(destination, CLASSDD)
        entries = {entry["path"]: entry for entry in report["files"]}
        assert entries["local-not-in-manifest.txt"]["classification"] == "added"
        assert entries["local-not-in-manifest.txt"]["owner"] is None
        assert report["summary"]["added"] == 1
        assert report["blocked"] is True
        assert report["safe"] is False


def test_detect_overrides_is_deterministic_and_non_mutating() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        destination = _make_instance(CLASSDD, workspace)
        (destination / "README.md").write_text("override\n", encoding="utf-8")
        before = _snapshot_tree(destination)

        first = detect_overrides(destination, CLASSDD)
        second = detect_overrides(destination, CLASSDD)

        assert first == second
        assert _snapshot_tree(destination) == before


def test_detect_overrides_blocks_symlinked_instance_paths() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        destination = _make_instance(CLASSDD, workspace)
        outside = workspace / "outside.txt"
        outside.write_text("outside\n", encoding="utf-8")
        (destination / "unknown-link.txt").symlink_to(outside)

        _expect_lifecycle_error(
            lambda: detect_overrides(destination, CLASSDD),
            "symlinked instance path is not safe",
        )


def test_plan_upgrade_same_template_version_is_blocked_and_non_mutating() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        old_template = _make_template(workspace, name="template-old")
        destination = _make_instance(old_template, workspace)
        new_template = _make_template(workspace, name="template-same-version")
        (new_template / "README.md").write_text("same-version change\n", encoding="utf-8")
        before = _snapshot_tree(destination)

        plan = plan_upgrade(destination, new_template)

        assert plan["formatVersion"] == "statedd.upgrade-plan/v1"
        assert plan["dryRun"] is True
        assert plan["current"]["version"] == "0.1.0"
        assert plan["target"]["version"] == "0.1.0"
        assert plan["blocked"] is True
        assert plan["safe"] is False
        assert any("higher numeric version" in reason for reason in plan["reasons"])
        assert _snapshot_tree(destination) == before


def test_plan_upgrade_new_version_preserves_unchanged_files() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        old_template = _make_template(workspace, name="template-old")
        destination = _make_instance(old_template, workspace)
        new_template = _make_template(workspace, name="template-new")
        _bump_template_version(new_template, "0.2.0")
        before = _snapshot_tree(destination)

        plan = plan_upgrade(destination, new_template)
        entries = {entry["path"]: entry for entry in plan["files"]}

        assert plan["current"]["version"] == "0.1.0"
        assert plan["target"]["version"] == "0.2.0"
        assert plan["blocked"] is False
        assert plan["safe"] is True
        assert entries["README.md"]["classification"] == "unchanged"
        assert entries["README.md"]["action"] == "preserve"
        assert entries["state/class.yaml"]["classification"] == "unchanged"
        assert entries["state/class.yaml"]["action"] == "preserve"
        assert _snapshot_tree(destination) == before


def test_plan_upgrade_new_template_change_replaces_unoverridden_template_file() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        old_template = _make_template(workspace, name="template-old")
        destination = _make_instance(old_template, workspace)
        new_template = _make_template(workspace, name="template-new")
        _bump_template_version(new_template, "0.2.0")
        (new_template / "README.md").write_text("new upstream README\n", encoding="utf-8")
        before = _snapshot_tree(destination)

        plan = plan_upgrade(destination, new_template)
        entries = {entry["path"]: entry for entry in plan["files"]}

        assert plan["blocked"] is False
        assert plan["safe"] is True
        assert entries["README.md"]["classification"] == "changed"
        assert entries["README.md"]["action"] == "replace"
        assert entries["state/class.yaml"]["action"] == "preserve"
        assert _snapshot_tree(destination) == before


def test_upgrade_plan_actions_are_typed_and_target_hash_bound() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        old_template = _make_template(workspace, name="typed-old")
        instance = _make_instance(old_template, workspace, name="typed-instance")
        target = _make_template(workspace, name="typed-target")
        _bump_template_version(target, "0.2.0")
        (target / "README.md").write_text("target bytes\n", encoding="utf-8")
        plan = plan_upgrade(instance, target)
        readme = {item["path"]: item for item in plan["entries"]}["README.md"]
        assert readme["action"] == "replace"
        assert readme["targetHash"].startswith("sha256:")

        forged = dict(plan)
        forged["files"] = [dict(item) for item in plan["files"]]
        forged["entries"] = forged["files"]
        forged["files"][0]["action"] = "delete"
        forged["planDigest"] = plan_digest(forged)
        _expect_lifecycle_error(
            lambda: approve_upgrade_plan(forged, approved_by="operator"),
            "invalid action",
        )

        approval = approve_upgrade_plan(plan, approved_by="operator")
        (target / "README.md").write_text("changed after approval\n", encoding="utf-8")
        _expect_lifecycle_error(
            lambda: apply_upgrade(instance, target, plan=plan, approval=approval),
            "target source is stale",
        )

        # Restore the target and change durable instance state instead: the
        # plan must bind both sides of the transaction before staging.
        (target / "README.md").write_text("target bytes\n", encoding="utf-8")
        instance_state = instance / "state" / "class.yaml"
        instance_state.write_text("class:\n  id: changed-after-plan\n", encoding="utf-8")
        _expect_lifecycle_error(
            lambda: apply_upgrade(instance, target, plan=plan, approval=approval),
            "stale or does not match current state",
        )


def test_idempotent_upgrade_still_requires_exact_approval() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        old_template = _make_template(workspace, name="approval-old")
        instance = _make_instance(old_template, workspace, name="approval-instance")
        target = _make_template(workspace, name="approval-target")
        _bump_template_version(target, "0.2.0")
        plan = plan_upgrade(instance, target)
        approval = approve_upgrade_plan(plan, approved_by="operator")
        apply_upgrade(instance, target, plan=plan, approval=approval)
        bad = dict(approval, planDigest="sha256:" + "0" * 64)
        _expect_lifecycle_error(
            lambda: apply_upgrade(instance, target, plan=plan, approval=bad),
            "exact plan digest",
        )


def test_swap_failure_restores_instance_and_releases_upgrade_lease() -> None:
    import statedd_core.lifecycle as lifecycle

    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        old_template = _make_template(workspace, name="rollback-old")
        instance = _make_instance(old_template, workspace, name="rollback-instance")
        target = _make_template(workspace, name="rollback-target")
        _bump_template_version(target, "0.2.0")
        plan = plan_upgrade(instance, target)
        approval = approve_upgrade_plan(plan, approved_by="operator")
        before = _snapshot_tree(instance)
        original_replace = lifecycle.os.replace
        calls = 0

        def fail_second_swap(source, destination):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected swap failure")
            return original_replace(source, destination)

        lifecycle.os.replace = fail_second_swap
        try:
            try:
                apply_upgrade(instance, target, plan=plan, approval=approval)
            except OSError as exc:
                assert "injected swap failure" in str(exc)
            else:
                raise AssertionError("injected swap failure was swallowed")
        finally:
            lifecycle.os.replace = original_replace
        assert _snapshot_tree(instance) == before
        assert not (workspace / ".rollback-instance.upgrade-in-progress").exists()
        assert not (workspace / ".rollback-instance.upgrade-backup").exists()
        assert not list(workspace.glob(".statedd-upgrade-*"))


def test_interrupted_upgrade_recovers_from_parent_journal_on_next_apply() -> None:
    import statedd_core.lifecycle as lifecycle

    class SimulatedProcessExit(BaseException):
        pass

    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        old_template = _make_template(workspace, name="interrupted-old")
        instance = _make_instance(old_template, workspace, name="interrupted-instance")
        target = _make_template(workspace, name="interrupted-target")
        _bump_template_version(target, "0.2.0")
        plan = plan_upgrade(instance, target)
        approval = approve_upgrade_plan(plan, approved_by="operator")
        original_replace = lifecycle.os.replace

        def exit_after_original_move(source, destination):
            result = original_replace(source, destination)
            if Path(source) == instance and Path(destination).name == ".interrupted-instance.upgrade-backup":
                raise SimulatedProcessExit()
            return result

        lifecycle.os.replace = exit_after_original_move
        try:
            try:
                apply_upgrade(instance, target, plan=plan, approval=approval)
            except SimulatedProcessExit:
                pass
            else:
                raise AssertionError("simulated process exit was swallowed")
        finally:
            lifecycle.os.replace = original_replace

        assert not instance.exists()
        assert (workspace / ".interrupted-instance.upgrade-backup").is_dir()
        assert (workspace / ".interrupted-instance.upgrade-stage").is_dir()
        assert (workspace / ".interrupted-instance.upgrade-transaction.yaml").is_file()

        applied = apply_upgrade(instance, target, plan=plan, approval=approval)
        assert applied["status"] == "applied"
        assert instance.is_dir()
        assert not (workspace / ".interrupted-instance.upgrade-backup").exists()
        assert not (workspace / ".interrupted-instance.upgrade-stage").exists()
        assert not (workspace / ".interrupted-instance.upgrade-transaction.yaml").exists()
        assert not (workspace / ".interrupted-instance.upgrade-in-progress").exists()


def test_committed_upgrade_survives_backup_cleanup_failure() -> None:
    import statedd_core.lifecycle as lifecycle

    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        old_template = _make_template(workspace, name="cleanup-old")
        instance = _make_instance(old_template, workspace, name="cleanup-instance")
        target = _make_template(workspace, name="cleanup-target")
        _bump_template_version(target, "0.2.0")
        plan = plan_upgrade(instance, target)
        approval = approve_upgrade_plan(plan, approved_by="operator")
        backup = workspace / ".cleanup-instance.upgrade-backup"
        original_rmtree = lifecycle.shutil.rmtree

        def fail_committed_backup_cleanup(path, *args, **kwargs):
            if Path(path) == backup and (instance / ".statedd" / "upgrade-receipt.yaml").is_file():
                raise OSError("injected committed cleanup failure")
            return original_rmtree(path, *args, **kwargs)

        lifecycle.shutil.rmtree = fail_committed_backup_cleanup
        try:
            applied = apply_upgrade(instance, target, plan=plan, approval=approval)
        finally:
            lifecycle.shutil.rmtree = original_rmtree

        assert applied["status"] == "applied"
        assert backup.is_dir()
        assert (workspace / ".cleanup-instance.upgrade-transaction.yaml").is_file()
        assert parse_yaml_text((instance / ".statedd" / "lock.yaml").read_text())["template"]["version"] == "0.2.0"

        repeated = apply_upgrade(instance, target, plan=plan, approval=approval)
        assert repeated["idempotent"] is True
        assert not backup.exists()
        assert not (workspace / ".cleanup-instance.upgrade-transaction.yaml").exists()
        assert not (workspace / ".cleanup-instance.upgrade-in-progress").exists()


def test_plan_upgrade_blocks_template_change_when_local_template_file_is_overridden() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        old_template = _make_template(workspace, name="template-old")
        destination = _make_instance(old_template, workspace)
        (destination / "README.md").write_text("local override\n", encoding="utf-8")
        new_template = _make_template(workspace, name="template-new")
        _bump_template_version(new_template, "0.2.0")
        (new_template / "README.md").write_text("new upstream README\n", encoding="utf-8")
        before = _snapshot_tree(destination)

        plan = plan_upgrade(destination, new_template)
        entries = {entry["path"]: entry for entry in plan["files"]}

        assert plan["blocked"] is True
        assert plan["safe"] is False
        assert entries["README.md"]["classification"] == "overridden"
        assert entries["README.md"]["action"] == "block"
        assert _snapshot_tree(destination) == before


def test_plan_upgrade_blocks_template_identity_change() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        old_template = _make_template(workspace, name="template-old")
        destination = _make_instance(old_template, workspace)
        new_template = workspace / "project-template"
        shutil.copytree(ROOT / "templates" / "projectdd", new_template)
        _bump_template_version(new_template, "0.2.0")

        plan = plan_upgrade(destination, new_template)

        assert plan["blocked"] is True
        assert plan["safe"] is False
        assert "template ids differ" in plan["reasons"]


def test_removed_template_file_is_retained_and_recorded_idempotently() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        old_template = _make_template(workspace, name="template-old")
        instance = _make_instance(old_template, workspace)
        target = _v1_target_without_file(workspace, old_template, "README.md")

        plan = plan_upgrade(instance, target)
        entry = {item["path"]: item for item in plan["entries"]}["README.md"]
        assert plan["safe"] is True
        assert entry["classification"] == "retained_unmodified"
        assert entry["action"] == "retain"
        assert plan["retirement"]["entries"] == [entry]

        approval = approve_upgrade_plan(plan, approved_by="operator")
        before = _snapshot_tree(instance)
        try:
            apply_upgrade(
                instance,
                target,
                plan=plan,
                approval=approval,
                validation_command=[sys.executable, "-c", "raise SystemExit(9)"],
                allow_fixture=True,
            )
        except LifecycleError as exc:
            assert "staged validation failed" in str(exc)
        else:
            raise AssertionError("failed retirement transaction was accepted")
        assert _snapshot_tree(instance) == before
        assert not (instance / ".statedd" / "upgrade-receipt.yaml").exists()

        receipt = apply_upgrade(instance, target, plan=plan, approval=approval)
        assert (instance / "README.md").read_text(encoding="utf-8") == (
            old_template / "README.md"
        ).read_text(encoding="utf-8")
        assert receipt["retirements"][0]["classification"] == "retained_unmodified"
        lock = parse_yaml_text((instance / ".statedd" / "lock.yaml").read_text())
        assert lock["retired"][0]["path"] == "README.md"
        assert lock["retired"][0]["disposition"] == "retained"
        assert len(lock["history"]) == 1
        report = detect_overrides(instance, target)
        retained = {item["path"]: item for item in report["files"]}["README.md"]
        assert retained["classification"] == "retained_unmodified"
        assert report["safe"] is True

        repeated = apply_upgrade(instance, target, plan=plan, approval=approval)
        assert repeated["idempotent"] is True
        assert repeated["history"] == receipt["history"]


def test_removed_template_and_instance_files_are_retained_when_modified() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        old_template = _make_template(workspace, name="template-old")
        template_instance = _make_instance(old_template, workspace, name="template-instance")
        (template_instance / "README.md").write_text("local README\n", encoding="utf-8")
        template_target = _v1_target_without_file(
            workspace, old_template, "README.md", name="template-target"
        )
        template_plan = plan_upgrade(template_instance, template_target)
        template_entry = {
            item["path"]: item for item in template_plan["entries"]
        }["README.md"]
        assert template_plan["blocked"] is True
        assert template_entry["classification"] == "retained_modified"
        assert template_entry["action"] == "retain"

        instance = _make_instance(old_template, workspace, name="instance-owned")
        state_path = instance / "state" / "class.yaml"
        state_path.write_text("class:\n  id: local\n", encoding="utf-8")
        target = _v1_target_without_file(
            workspace, old_template, "state/class.yaml", name="instance-target"
        )
        plan = plan_upgrade(instance, target)
        state_entry = {item["path"]: item for item in plan["entries"]}["state/class.yaml"]
        assert plan["safe"] is True
        assert state_entry["classification"] == "retained_modified"
        assert state_entry["action"] == "retain"
        approval = approve_upgrade_plan(plan, approved_by="operator")
        apply_upgrade(instance, target, plan=plan, approval=approval)
        assert state_path.read_text(encoding="utf-8") == "class:\n  id: local\n"


def test_only_explicit_unmodified_generated_output_can_be_removed() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        old_template = _generated_retirement_template(workspace, name="generated-old")
        instance = _make_instance(old_template, workspace)
        target = _generated_retirement_template(workspace, name="generated-target")
        manifest_path = target / ".statedd" / "manifest.yaml"
        data = parse_yaml_text(manifest_path.read_text(encoding="utf-8"))
        data["templateVersion"] = "0.2.0"
        data["files"] = [item for item in data["files"] if item["path"] != "generated-view.txt"]
        _write_yaml(manifest_path, data)
        template_yaml = target / "template.yaml"
        if template_yaml.exists():
            template_yaml.write_text(
                template_yaml.read_text(encoding="utf-8").replace(
                    "version: 0.1.0", "version: 0.2.0"
                ),
                encoding="utf-8",
            )

        plan = plan_upgrade(instance, target)
        entry = {item["path"]: item for item in plan["entries"]}["generated-view.txt"]
        assert plan["safe"] is True
        assert entry["classification"] == "retired"
        assert entry["action"] == "remove"
        approval = approve_upgrade_plan(plan, approved_by="operator")
        receipt = apply_upgrade(instance, target, plan=plan, approval=approval)
        assert not (instance / "generated-view.txt").exists()
        assert receipt["retirements"][0]["action"] == "remove"
        lock = parse_yaml_text((instance / ".statedd" / "lock.yaml").read_text())
        retired = {item["path"]: item for item in lock["retired"]}["generated-view.txt"]
        assert retired["disposition"] == "removed"
        assert detect_overrides(instance, target)["safe"] is True


def test_lock_records_exact_template_identity_and_source_revision() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        destination = _make_instance(CLASSDD, workspace)
        lock = parse_yaml_text(
            (destination / ".statedd" / "lock.yaml").read_text(encoding="utf-8")
        )

        assert lock["template"]["id"] == "classdd"
        assert lock["template"]["version"] == "0.1.0"
        assert lock["template"]["sourcePath"] == CLASSDD.as_posix()
        assert lock["template"]["sourceRevision"].startswith("sha256:")
        assert len(lock["template"]["sourceRevision"]) == len("sha256:") + 64
        assert lock["template"]["source"] == {
            "formatVersion": "statedd.source/v1",
            "kind": "local",
            "path": CLASSDD.resolve().as_posix(),
            "identity": lock["template"]["sourceRevision"],
        }

        # A second read is stable and the persisted lock is the exact value
        # returned by the materialiser.
        assert materialize_instance(CLASSDD, destination) == lock


def test_source_descriptor_identity_is_path_independent_and_deterministic() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        first_template = _make_template(workspace, name="first-template")
        second_template = _make_template(workspace, name="second-template")

        first = describe_template_source(first_template)
        second = describe_template_source(second_template)
        assert first["formatVersion"] == "statedd.source/v1"
        assert first["kind"] == "local"
        assert first["path"] == first_template.resolve().as_posix()
        assert first["identity"].startswith("sha256:")
        assert first["identity"] == second["identity"]
        assert first["path"] != second["path"]
        assert resolve_template_source(first_template) == first


def test_source_descriptor_identity_changes_when_template_contract_changes() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        template = _make_template(Path(tmpdir))
        before = describe_template_source(template)
        (template / ".statedd" / "contract.md").write_text(
            "changed contract\n", encoding="utf-8"
        )
        after = describe_template_source(template)
        assert after["path"] == before["path"]
        assert after["identity"] != before["identity"]


def test_source_descriptor_requires_a_template_directory() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        missing = Path(tmpdir) / "missing-template"
        _expect_lifecycle_error(
            lambda: describe_template_source(missing),
            "not a directory",
        )


def test_identical_template_content_has_identical_source_revision() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        first_template = _make_template(workspace, name="first-template")
        second_template = _make_template(workspace, name="second-template")
        first = _make_instance(first_template, workspace, name="first-instance")
        second = _make_instance(second_template, workspace, name="second-instance")

        first_lock = parse_yaml_text(
            (first / ".statedd" / "lock.yaml").read_text(encoding="utf-8")
        )
        second_lock = parse_yaml_text(
            (second / ".statedd" / "lock.yaml").read_text(encoding="utf-8")
        )
        assert first_lock["template"]["sourceRevision"] == second_lock["template"][
            "sourceRevision"
        ]
        assert first_lock["template"]["sourcePath"] == first_template.as_posix()
        assert second_lock["template"]["sourcePath"] == second_template.as_posix()


def test_template_revision_drift_is_rejected_before_materialization() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        template = _make_template(workspace)
        destination = _make_instance(template, workspace)
        (template / "README.md").write_text("new upstream content\n", encoding="utf-8")

        _expect_lifecycle_error(
            lambda: materialize_instance(template, destination),
            "source revision does not match template",
        )


def test_template_owned_missing_materialized_file_is_rejected() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        template = _make_template(workspace)
        destination = _make_instance(template, workspace)
        (destination / "README.md").unlink()

        _expect_lifecycle_error(
            lambda: materialize_instance(template, destination),
            "template-owned file changed",
        )


def test_missing_template_source_is_rejected() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        template = _make_template(workspace)
        (template / "README.md").unlink()

        _expect_lifecycle_error(
            lambda: load_template_manifest(template),
            "manifest source file is missing",
        )


def test_generated_lock_can_be_recreated_without_overwriting_instance_state() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        template = _make_template(workspace)
        destination = _make_instance(template, workspace)
        state_path = destination / "state" / "class.yaml"
        state_path.write_text("class:\n  id: retained\n", encoding="utf-8")
        lock_path = destination / ".statedd" / "lock.yaml"
        original_lock = lock_path.read_bytes()
        lock_path.unlink()

        recreated = materialize_instance(template, destination)
        recreated_lock = parse_yaml_text(lock_path.read_text(encoding="utf-8"))
        original_lock_data = parse_yaml_text(original_lock.decode("utf-8"))
        assert recreated_lock["template"] == original_lock_data["template"]
        assert recreated_lock["formatVersion"] == "statedd.lock/v1"
        assert state_path.read_text(encoding="utf-8") == "class:\n  id: retained\n"
        assert recreated == recreated_lock


def test_new_template_version_is_materializable_but_cannot_replace_existing_lock() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        old_template = _make_template(workspace, name="template-v1")
        old_instance = _make_instance(old_template, workspace, name="old-instance")

        new_template = _make_template(workspace, name="template-v2")
        template_yaml = (new_template / "template.yaml").read_text(encoding="utf-8")
        (new_template / "template.yaml").write_text(
            template_yaml.replace("version: 0.1.0", "version: 0.2.0"),
            encoding="utf-8",
        )
        manifest_yaml = (new_template / ".statedd" / "manifest.yaml").read_text(
            encoding="utf-8"
        )
        (new_template / ".statedd" / "manifest.yaml").write_text(
            manifest_yaml.replace("templateVersion: 0.1.0", "templateVersion: 0.2.0"),
            encoding="utf-8",
        )

        new_instance = _make_instance(new_template, workspace, name="new-instance")
        new_lock = parse_yaml_text(
            (new_instance / ".statedd" / "lock.yaml").read_text(encoding="utf-8")
        )
        assert new_lock["template"]["version"] == "0.2.0"
        assert new_lock["template"]["sourceRevision"] != parse_yaml_text(
            (old_instance / ".statedd" / "lock.yaml").read_text(encoding="utf-8")
        )["template"]["sourceRevision"]

        # The current API only materialises and locks; it must fail closed if
        # asked to use a new source against an already locked instance.
        _expect_lifecycle_error(
            lambda: materialize_instance(new_template, old_instance),
            "source revision does not match template",
        )


def test_same_template_version_with_changed_source_is_not_treated_as_safe_upgrade() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        template = _make_template(workspace)
        destination = _make_instance(template, workspace)
        (template / ".statedd" / "contract.md").write_text(
            "changed upstream contract\n", encoding="utf-8"
        )

        _expect_lifecycle_error(
            lambda: materialize_instance(template, destination),
            "source revision does not match template",
        )


def test_materialization_is_byte_for_byte_deterministic_for_same_inputs() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        first = _make_instance(CLASSDD, workspace, name="first")
        second = _make_instance(CLASSDD, workspace, name="second")
        first_lock = (first / ".statedd" / "lock.yaml").read_bytes()
        second_lock = (second / ".statedd" / "lock.yaml").read_bytes()
        assert first_lock == second_lock

        first_state = sorted(
            path.relative_to(first).as_posix()
            for path in first.rglob("*")
            if path.is_file() and ".statedd/lock.yaml" not in path.as_posix()
        )
        second_state = sorted(
            path.relative_to(second).as_posix()
            for path in second.rglob("*")
            if path.is_file() and ".statedd/lock.yaml" not in path.as_posix()
        )
        assert first_state == second_state


def test_manifest_absolute_paths_are_rejected() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        template = _make_template(Path(tmpdir))
        manifest_path = template / ".statedd" / "manifest.yaml"
        manifest = manifest_path.read_text(encoding="utf-8").replace(
            "path: README.md", "path: /tmp/README.md", 1
        )
        manifest_path.write_text(manifest, encoding="utf-8")

        _expect_lifecycle_error(
            lambda: load_template_manifest(template),
            "must be a relative path",
        )


def test_manifest_source_traversal_is_rejected() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        template = _make_template(Path(tmpdir))
        manifest_path = template / ".statedd" / "manifest.yaml"
        manifest = manifest_path.read_text(encoding="utf-8").replace(
            "source: README.md", "source: ../README.md", 1
        )
        manifest_path.write_text(manifest, encoding="utf-8")

        _expect_lifecycle_error(
            lambda: load_template_manifest(template),
            "parent",
        )


def test_manifest_source_symlink_cannot_escape_template_root() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        template = _make_template(workspace)
        outside = workspace / "outside.md"
        outside.write_text("outside\n", encoding="utf-8")
        source_link = template / "outside-link.md"
        source_link.symlink_to(outside)
        manifest_path = template / ".statedd" / "manifest.yaml"
        manifest = manifest_path.read_text(encoding="utf-8").replace(
            "source: README.md", "source: outside-link.md", 1
        )
        manifest_path.write_text(manifest, encoding="utf-8")

        _expect_lifecycle_error(
            lambda: load_template_manifest(template),
            "escapes its root",
        )


def test_manifest_traversal_is_rejected() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        template = Path(tmpdir) / "template"
        shutil.copytree(ROOT / "templates" / "classdd", template)
        manifest_path = template / ".statedd" / "manifest.yaml"
        manifest = manifest_path.read_text(encoding="utf-8").replace(
            "path: README.md", "path: ../README.md", 1
        )
        manifest_path.write_text(manifest, encoding="utf-8")
        try:
            load_template_manifest(template)
        except LifecycleError as exc:
            assert "parent" in str(exc)
        else:
            raise AssertionError("expected manifest traversal to be rejected")


def test_v2_fixture_validates_with_modules_owned_tree_and_source_class() -> None:
    manifest = load_template_manifest(V2_FIXTURE)
    assert manifest["formatVersion"] == MANIFEST_V2_FORMAT
    assert manifest["templateId"] == "stateport.fixture.lifecycle-v2-minimal"
    assert manifest["selectedModules"] == ["core"]
    assert manifest["trees"][0]["path"] == "state"
    assert manifest["sourceClass"] == "synthetic_fixture"
    assert manifest["productionEligible"] is False
    with tempfile.TemporaryDirectory() as tmpdir:
        destination = _make_instance(V2_FIXTURE, Path(tmpdir), allow_fixture=True)
        lock = parse_yaml_text((destination / ".statedd" / "lock.yaml").read_text())
        source = lock["template"]["source"]
        assert source["formatVersion"] == "statedd.source/v2"
        assert source["checkoutLocation"] == V2_FIXTURE.resolve().as_posix()
        assert source["sourceDigest"] == lock["template"]["sourceRevision"]
        assert source["resolvedCommit"] is None
        assert lock["template"]["selectedModules"] == ["core"]


def test_v2_template_owned_tree_materializes_without_recursive_merge() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        template = _v2_template(workspace, name="v2-template-tree")
        public_tree = template / "public"
        public_tree.mkdir()
        (public_tree / "guide.txt").write_text("synthetic public guide\n", encoding="utf-8")
        raw = parse_yaml_text((template / ".statedd" / "manifest.yaml").read_text())
        raw["modules"][0]["assets"].append("public-tree")
        raw["assets"].append(
            {
                "id": "public-tree",
                "path": "public",
                "kind": "tree",
                "owner": "template",
                "role": "public_tree",
                "provisionPolicy": "create_if_missing",
                "updatePolicy": "preserve",
                "required": True,
                "schema": None,
                "sensitivity": "public",
                "selectingModules": ["core"],
            }
        )
        _write_v2_manifest(template, raw)
        destination = _make_instance(template, workspace, allow_fixture=True)
        assert (destination / "public/guide.txt").read_text(encoding="utf-8") == "synthetic public guide\n"


def test_v2_manifest_is_authoritative_without_template_yaml() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        template = _v2_template(workspace)
        (template / "template.yaml").unlink()

        manifest = load_template_manifest(template)
        assert manifest["templateId"] == "stateport.fixture.lifecycle-v2-minimal"
        descriptor = describe_template_source(template)
        assert descriptor["sourceDigest"]
        assert not (template / "template.yaml").exists()

        destination = _make_instance(template, workspace, allow_fixture=True)
        assert not (destination / "template.yaml").exists()
        assert detect_overrides(destination, template)["blocked"] is False

        target = _v2_template(workspace, name="v2-target")
        (target / "template.yaml").unlink()
        target_data = parse_yaml_text((target / ".statedd" / "manifest.yaml").read_text())
        target_data["template"]["releaseVersion"] = "0.0.2"
        _write_v2_manifest(target, target_data)
        plan = plan_upgrade(destination, target)
        assert plan["safe"] is True
        assert plan["target"]["version"] == "0.0.2"


def test_v2_matching_optional_template_yaml_is_accepted_and_disagreement_rejected() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        matching = _v2_template(workspace)
        assert load_template_manifest(matching)["templateId"]

        disagreement = _v2_template(workspace, name="v2-disagreement")
        template_yaml = disagreement / "template.yaml"
        template_yaml.write_text(
            template_yaml.read_text(encoding="utf-8").replace(
                "version: 0.0.1", "version: 0.0.2"
            ),
            encoding="utf-8",
        )
        _expect_lifecycle_error(
            lambda: load_template_manifest(disagreement), "does not match"
        )


def test_v1_template_yaml_remains_required_and_must_match_manifest() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        missing = _make_template(Path(tmpdir), name="v1-missing")
        (missing / "template.yaml").unlink()
        _expect_lifecycle_error(lambda: load_template_manifest(missing), "template.yaml")

        disagreement = _make_template(Path(tmpdir), name="v1-disagreement")
        template_yaml = disagreement / "template.yaml"
        template_yaml.write_text(
            template_yaml.read_text(encoding="utf-8").replace(
                "version: 0.1.0", "version: 0.2.0"
            ),
            encoding="utf-8",
        )
        _expect_lifecycle_error(
            lambda: load_template_manifest(disagreement), "does not match"
        )


def test_v1_normalization_is_compatible_and_exposes_v2_limits() -> None:
    manifest = load_template_manifest(CLASSDD)
    assert manifest["formatVersion"] == "statedd.template-manifest/v1"
    assert manifest["normalizedFrom"] == "statedd.template-manifest/v1"
    assert manifest["template"]["id"] == "classdd"
    assert manifest["sourceClass"] == "legacy_local_development"
    assert manifest["v2Limitations"]


def test_v2_module_resolution_is_deterministic() -> None:
    first = load_template_manifest(V2_FIXTURE)
    second = load_template_manifest(V2_FIXTURE)
    assert first == second
    assert first["modules"] == [
        {
            "id": "core",
            "contractVersion": "1.0",
            "dependencies": [],
            "conflicts": [],
            "capabilities": ["read_state"],
            "assets": ["durable-state", "guide", "instance-definition", "lifecycle-lock"],
            "selfTests": [{"id": "lifecycle-v2-contract"}],
            "order": 10,
        }
    ]


def test_v2_module_dependency_cycle_is_rejected() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        template = _v2_template(Path(tmpdir))
        data = parse_yaml_text((template / ".statedd" / "manifest.yaml").read_text())
        data["modules"][0]["dependencies"] = ["core"]
        _write_v2_manifest(template, data)
        _expect_lifecycle_error(lambda: load_template_manifest(template), "dependency cycle")


def test_v2_module_conflict_is_rejected() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        template = _v2_template(Path(tmpdir))
        data = parse_yaml_text((template / ".statedd" / "manifest.yaml").read_text())
        data["modules"][0]["conflicts"] = ["extra"]
        data["modules"].append(
            {
                "id": "extra",
                "contractVersion": "1.0",
                "dependencies": [],
                "conflicts": [],
                "capabilities": [],
                "assets": [],
                "selfTests": [],
                "order": 20,
            }
        )
        data["selectedModules"].append("extra")
        _write_v2_manifest(template, data)
        _expect_lifecycle_error(lambda: load_template_manifest(template), "selected modules conflict")


def test_v2_duplicate_overlapping_and_conflicting_paths_are_rejected() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        template = _v2_template(Path(tmpdir))
        data = parse_yaml_text((template / ".statedd" / "manifest.yaml").read_text())
        duplicate = dict(data["assets"][0])
        duplicate["id"] = "duplicate-guide"
        data["assets"].append(duplicate)
        data["modules"][0]["assets"].append("duplicate-guide")
        _write_v2_manifest(template, data)
        _expect_lifecycle_error(lambda: load_template_manifest(template), "duplicate exact path")

        data["assets"].pop()
        data["modules"][0]["assets"].pop()
        conflict = dict(data["assets"][0])
        conflict["id"] = "instance-guide"
        conflict["owner"] = "instance"
        data["assets"].append(conflict)
        data["modules"][0]["assets"].append("instance-guide")
        _write_v2_manifest(template, data)
        _expect_lifecycle_error(lambda: load_template_manifest(template), "conflicting owners")

        data["assets"].pop()
        data["modules"][0]["assets"].pop()
        data["assets"][0]["path"] = "state/nested"
        _write_v2_manifest(template, data)
        _expect_lifecycle_error(lambda: load_template_manifest(template), "overlaps declared tree")

        data["assets"][0]["path"] = "README.md"
        data["assets"][0]["selectingModules"] = []
        _write_v2_manifest(template, data)
        _expect_lifecycle_error(lambda: load_template_manifest(template), "no owning module")


def test_v2_rejects_unsafe_source_and_symlinks() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        template = _v2_template(workspace)
        data = parse_yaml_text((template / ".statedd" / "manifest.yaml").read_text())
        data["assets"][0]["source"] = "../README.md"
        _write_v2_manifest(template, data)
        _expect_lifecycle_error(lambda: load_template_manifest(template), "parent directories")

        template = _v2_template(workspace, name="linked-template")
        outside = workspace / "outside.md"
        outside.write_text("outside\n", encoding="utf-8")
        (template / "README.md").unlink()
        (template / "README.md").symlink_to(outside)
        _expect_lifecycle_error(lambda: load_template_manifest(template), "uses a symlink")


def test_v2_instance_tree_is_preserved_and_symlink_destination_is_rejected() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        destination = _make_instance(V2_FIXTURE, workspace, allow_fixture=True)
        state_file = destination / "state" / "session.md"
        state_file.write_text("retained\n", encoding="utf-8")
        materialize_instance(V2_FIXTURE, destination, allow_fixture=True)
        assert state_file.read_text(encoding="utf-8") == "retained\n"
        assert detect_overrides(destination, V2_FIXTURE)["blocked"] is False

        (destination / ".statedd" / "lock.yaml").unlink()
        state_file.unlink()
        (destination / "state").rmdir()
        outside = workspace / "outside-state"
        outside.mkdir()
        (destination / "state").symlink_to(outside, target_is_directory=True)
        _expect_lifecycle_error(
            lambda: materialize_instance(V2_FIXTURE, destination, allow_fixture=True), "uses a symlink"
        )


def test_v2_ejection_makes_a_template_file_instance_owned() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        destination = _make_instance(V2_FIXTURE, workspace, allow_fixture=True)
        (destination / "README.md").write_text("local ejection\n", encoding="utf-8")
        _write_yaml(
            destination / ".statedd" / "overrides.yaml",
            {
                "formatVersion": "statedd.instance-overrides/v1",
                "ejections": [{"path": "README.md", "reason": "local policy"}],
            },
        )
        materialize_instance(V2_FIXTURE, destination, allow_fixture=True)
        report = detect_overrides(destination, V2_FIXTURE)
        entry = {item["path"]: item for item in report["files"]}["README.md"]
        assert entry["owner"] == "instance"
        assert entry["classification"] == "changed"
        assert report["blocked"] is False


def test_v2_ejection_validation_and_unsupported_strategies_fail_closed() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        destination = _make_instance(V2_FIXTURE, workspace, allow_fixture=True)
        _write_yaml(
            destination / ".statedd" / "overrides.yaml",
            {
                "formatVersion": "statedd.instance-overrides/v1",
                "ejections": [{"path": "state", "reason": "not a file"}],
            },
        )
        _expect_lifecycle_error(
            lambda: materialize_instance(V2_FIXTURE, destination, allow_fixture=True), "template-owned exact file"
        )

        template = _v2_template(workspace)
        data = parse_yaml_text((template / ".statedd" / "manifest.yaml").read_text())
        data["assets"][0]["provisionPolicy"] = "composed_output"
        data["assets"][0].pop("source")
        data["assets"][0]["updatePolicy"] = "compose"
        data["assets"][0]["composer"] = "named-fragment-slot"
        _write_v2_manifest(template, data)
        _expect_lifecycle_error(
            lambda: _make_instance(template, workspace, name="unsupported", allow_fixture=True), "declared but not materializable"
        )


def test_v2_synthetic_fixture_cannot_be_selected_as_a_production_source() -> None:
    manifest = load_template_manifest(V2_FIXTURE)
    _expect_lifecycle_error(
        lambda: assert_production_eligible(manifest), "not eligible for canonical production"
    )


def test_studydd_fixture_is_explicit_only_and_cannot_impersonate_canonical_content() -> None:
    manifest = load_template_manifest(STUDYDD_FIXTURE)
    assert manifest["templateId"] == "stateport.fixture.studydd-minimal"
    assert manifest["sourceClass"] == "synthetic_fixture"
    assert manifest["productionEligible"] is False
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        _expect_lifecycle_error(
            lambda: _make_instance(STUDYDD_FIXTURE, workspace), "explicit test/development opt-in"
        )
        destination = _make_instance(
            STUDYDD_FIXTURE, workspace, name="fixture-instance", allow_fixture=True
        )
        assert (destination / "state").is_dir()
    _expect_lifecycle_error(
        lambda: assert_production_eligible(manifest), "not eligible for canonical production"
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        fixture_copy = Path(tmpdir) / "fixture-copy"
        shutil.copytree(STUDYDD_FIXTURE, fixture_copy)
        for path in [fixture_copy / "template.yaml", fixture_copy / ".statedd" / "manifest.yaml"]:
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "stateport.fixture.studydd-minimal", "studydd"
                ),
                encoding="utf-8",
            )
        _expect_lifecycle_error(
            lambda: load_template_manifest(fixture_copy), "synthetic fixtures must use"
        )


def test_template_discovery_excludes_migrated_synthetic_fixture_and_old_path() -> None:
    bundled_ids = {
        load_template_manifest(path)["templateId"]
        for path in (ROOT / "templates").iterdir()
        if path.is_dir()
    }
    assert bundled_ids == {"classdd", "projectdd"}
    assert not (ROOT / "templates" / "studydD").exists()
    assert STUDYDD_FIXTURE.is_dir()


if __name__ == "__main__":
    for name, test in sorted(globals().items()):
        if name.startswith("test_") and callable(test):
            test()
    print("PASS")
