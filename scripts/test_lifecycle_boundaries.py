"""Regression tests for lifecycle path, provenance, and apply boundaries."""

from __future__ import annotations

import os
import shutil
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
    materialize_instance,
    plan_upgrade,
)
from statedd_core.lifecycle import _write_yaml  # noqa: E402
from statedd_core.lifecycle_v2 import _path  # noqa: E402
from statedd_core.yaml import parse_yaml_text  # noqa: E402


CLASSDD = ROOT / "templates" / "classdd"
V2_FIXTURE = ROOT / "fixtures" / "templates" / "lifecycle-v2-minimal"


def _bump_v1(template: Path) -> None:
    (template / "template.yaml").write_text(
        (template / "template.yaml").read_text(encoding="utf-8").replace(
            "version: 0.1.0", "version: 0.2.0"
        ),
        encoding="utf-8",
    )
    manifest_path = template / ".statedd" / "manifest.yaml"
    manifest = parse_yaml_text(manifest_path.read_text(encoding="utf-8"))
    manifest["templateVersion"] = "0.2.0"
    _write_yaml(manifest_path, manifest)


def _expect_code(code: str, action) -> None:
    try:
        action()
    except LifecycleError as exc:
        assert exc.code == code, exc.diagnostic
        assert exc.diagnostic["code"] == code
    else:
        raise AssertionError(f"expected lifecycle diagnostic {code!r}")


def _v1_case(workspace: Path) -> tuple[Path, Path, Path]:
    old = workspace / "old"
    target = workspace / "target"
    instance = workspace / "instance"
    shutil.copytree(CLASSDD, old)
    shutil.copytree(CLASSDD, target)
    _bump_v1(target)
    create_instance(
        old,
        instance,
        instance_id="boundary-demo",
        name="Boundary demo",
        owner_name="Operator",
        owner_handle="@operator",
    )
    return old, target, instance


def test_symlinked_instance_ancestor_is_rejected_by_plan_and_apply() -> None:
    with tempfile.TemporaryDirectory(prefix="stateport-boundary-path-") as raw:
        workspace = Path(raw)
        _, target, instance = _v1_case(workspace)
        alias = workspace / "alias"
        alias.symlink_to(workspace, target_is_directory=True)
        aliased_instance = alias / instance.name
        _expect_code("unsafe_path", lambda: plan_upgrade(aliased_instance, target))
        plan = plan_upgrade(instance, target)
        _expect_code(
            "unsafe_path",
            lambda: apply_upgrade(
                aliased_instance,
                target,
                plan=plan,
                approval=approve_upgrade_plan(plan, approved_by="operator"),
            ),
        )


def test_plan_binds_instance_root_against_replacement_and_move() -> None:
    with tempfile.TemporaryDirectory(prefix="stateport-boundary-root-") as raw:
        workspace = Path(raw)
        _, target, instance = _v1_case(workspace)
        plan = plan_upgrade(instance, target)
        approval = approve_upgrade_plan(plan, approved_by="operator")
        moved = workspace / "moved"
        os.replace(instance, moved)
        shutil.copytree(moved, instance)
        _expect_code(
            "stale_instance_root",
            lambda: apply_upgrade(instance, target, plan=plan, approval=approval),
        )

        _, target2, instance2 = _v1_case(workspace / "second")
        plan2 = plan_upgrade(instance2, target2)
        approval2 = approve_upgrade_plan(plan2, approved_by="operator")
        moved2 = workspace / "moved-instance"
        os.replace(instance2, moved2)
        _expect_code(
            "stale_instance_root",
            lambda: apply_upgrade(moved2, target2, plan=plan2, approval=approval2),
        )


def test_existing_lock_requires_instance_and_source_provenance_identity() -> None:
    with tempfile.TemporaryDirectory(prefix="stateport-boundary-lock-") as raw:
        workspace = Path(raw)
        old, _, instance = _v1_case(workspace)
        lock_path = instance / ".statedd" / "lock.yaml"
        lock = parse_yaml_text(lock_path.read_text(encoding="utf-8"))
        lock["instanceId"] = "copied-from-another-instance"
        _write_yaml(lock_path, lock)
        _expect_code("instance_identity_mismatch", lambda: materialize_instance(old, instance))

        instance2 = workspace / "instance-provenance"
        create_instance(
            old,
            instance2,
            instance_id="provenance-demo",
            name="Provenance demo",
            owner_name="Operator",
            owner_handle="@operator",
        )
        lock_path = instance2 / ".statedd" / "lock.yaml"
        lock = parse_yaml_text(lock_path.read_text(encoding="utf-8"))
        lock["template"]["sourcePath"] = (workspace / "wrong-source-root").as_posix()
        _write_yaml(lock_path, lock)
        _expect_code(
            "source_provenance_mismatch",
            lambda: materialize_instance(old, instance2),
        )


def test_v2_lock_requires_complete_local_source_identity() -> None:
    with tempfile.TemporaryDirectory(prefix="stateport-boundary-source-") as raw:
        workspace = Path(raw)
        source = workspace / "source"
        instance = workspace / "instance"
        shutil.copytree(V2_FIXTURE, source)
        create_instance(
            source,
            instance,
            instance_id="source-demo",
            name="Source demo",
            owner_name="Operator",
            owner_handle="@operator",
            allow_fixture=True,
        )
        lock_path = instance / ".statedd" / "lock.yaml"
        lock = parse_yaml_text(lock_path.read_text(encoding="utf-8"))
        del lock["template"]["source"]["resolvedCommit"]
        _write_yaml(lock_path, lock)
        _expect_code(
            "incomplete_source_identity",
            lambda: materialize_instance(source, instance, allow_fixture=True),
        )


def test_unsupported_target_strategy_is_rejected_during_planning() -> None:
    with tempfile.TemporaryDirectory(prefix="stateport-boundary-strategy-") as raw:
        workspace = Path(raw)
        old = workspace / "old"
        target = workspace / "target"
        instance = workspace / "instance"
        shutil.copytree(V2_FIXTURE, old)
        shutil.copytree(V2_FIXTURE, target)
        target_manifest_path = target / ".statedd" / "manifest.yaml"
        target_manifest = parse_yaml_text(target_manifest_path.read_text(encoding="utf-8"))
        target_manifest["template"]["releaseVersion"] = "0.0.2"
        asset = target_manifest["assets"][0]
        asset["provisionPolicy"] = "composed_output"
        asset["updatePolicy"] = "compose"
        asset.pop("source", None)
        asset["composer"] = "unsupported-composer"
        _write_yaml(target_manifest_path, target_manifest)
        (target / "template.yaml").write_text(
            (target / "template.yaml").read_text(encoding="utf-8").replace(
                "version: 0.0.1", "version: 0.0.2"
            ),
            encoding="utf-8",
        )
        create_instance(
            old,
            instance,
            instance_id="strategy-demo",
            name="Strategy demo",
            owner_name="Operator",
            owner_handle="@operator",
            allow_fixture=True,
        )
        _expect_code("unsupported_strategy", lambda: plan_upgrade(instance, target))


def test_v2_backslash_separator_is_rejected_portably() -> None:
    _expect_code("unsafe_path", lambda: _path("state\\evil.yaml", "assets[0].path"))
