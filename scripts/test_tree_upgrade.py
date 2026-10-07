#!/usr/bin/env python3
"""Synthetic tree ownership and immutable upgrade proof."""

from __future__ import annotations

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
    plan_upgrade,
)
from statedd_core.lifecycle import _write_yaml  # noqa: E402
from statedd_core.yaml import parse_yaml_text  # noqa: E402


FIXTURE = ROOT / "fixtures" / "templates" / "lifecycle-v2-minimal"


def _tree_template(parent: Path, name: str, version: str = "0.1.0") -> Path:
    root = parent / name
    shutil.copytree(FIXTURE, root)
    (root / "state" / "nested").mkdir(parents=True)
    (root / "state" / "managed.txt").write_text("baseline\n", encoding="utf-8")
    (root / "state" / "nested" / "old.txt").write_text("old\n", encoding="utf-8")
    manifest_path = root / ".statedd" / "manifest.yaml"
    manifest = parse_yaml_text(manifest_path.read_text(encoding="utf-8"))
    manifest["template"]["releaseVersion"] = version
    manifest["assets"] = [
        asset
        for asset in manifest["assets"]
        if asset["id"] not in {"durable-state"}
    ]
    manifest["modules"][0]["assets"].remove("durable-state")
    manifest["modules"][0]["assets"].append("managed-tree")
    manifest["assets"].append(
        {
            "id": "managed-tree",
            "path": "state",
            "kind": "tree",
            "owner": "template",
            "role": "managed_tree",
            "provisionPolicy": "create_if_missing",
            "updatePolicy": "preserve",
            "required": True,
            "schema": None,
            "sensitivity": "public",
            "selectingModules": ["core"],
        }
    )
    _write_yaml(manifest_path, manifest)
    template = root / "template.yaml"
    text = template.read_text(encoding="utf-8")
    template.write_text(text.replace("version: 0.0.1", f"version: {version}"), encoding="utf-8")
    return root


def test_tree_add_modify_preserve_and_idempotence() -> None:
    with tempfile.TemporaryDirectory(prefix="stateport-tree-") as raw:
        parent = Path(raw)
        old = _tree_template(parent, "old")
        instance = parent / "instance"
        create_instance(
            old,
            instance,
            instance_id="tree-demo",
            name="Tree Demo",
            owner_name="Operator",
            owner_handle="@operator",
            allow_fixture=True,
        )
        target = _tree_template(parent, "target", "0.2.0")
        (target / "state" / "managed.txt").write_text("changed\n", encoding="utf-8")
        (target / "state" / "nested" / "new.txt").write_text("new\n", encoding="utf-8")
        plan = plan_upgrade(instance, target)
        assert plan["safe"] is True
        entries = {item["path"]: item for item in plan["entries"]}
        assert entries["state/managed.txt"]["classification"] == "changed"
        assert entries["state/nested/new.txt"]["classification"] == "added"
        receipt = apply_upgrade(
            instance,
            target,
            plan=plan,
            approval=approve_upgrade_plan(plan, approved_by="operator"),
            allow_fixture=True,
        )
        assert receipt["status"] == "applied"
        assert (instance / "state" / "managed.txt").read_text() == "changed\n"
        assert (instance / "state" / "nested" / "new.txt").read_text() == "new\n"
        assert apply_upgrade(
            instance,
            target,
            plan=plan,
            approval=approve_upgrade_plan(plan, approved_by="operator"),
            allow_fixture=True,
        )["idempotent"] is True


def test_tree_conflict_symlink_and_case_collision_fail_closed() -> None:
    with tempfile.TemporaryDirectory(prefix="stateport-tree-safety-") as raw:
        parent = Path(raw)
        old = _tree_template(parent, "old")
        instance = parent / "instance"
        create_instance(
            old,
            instance,
            instance_id="tree-conflict",
            name="Tree Conflict",
            owner_name="Operator",
            owner_handle="@operator",
            allow_fixture=True,
        )
        (instance / "state" / "managed.txt").write_text("local\n", encoding="utf-8")
        target = _tree_template(parent, "target", "0.2.0")
        (target / "state" / "managed.txt").write_text("upstream\n", encoding="utf-8")
        plan = plan_upgrade(instance, target)
        assert plan["blocked"] is True
        assert any(item["classification"] == "overridden" for item in plan["entries"])

        symlinked = _tree_template(parent, "symlinked", "0.3.0")
        (symlinked / "state" / "unsafe").symlink_to(symlinked / "README.md")
        try:
            plan_upgrade(instance, symlinked)
        except LifecycleError as exc:
            assert "symlink" in str(exc)
        else:
            raise AssertionError("tree symlink was accepted")

        collision = _tree_template(parent, "collision", "0.3.0")
        (collision / "state" / "MANAGED.txt").write_text("collision\n", encoding="utf-8")
        try:
            plan_upgrade(instance, collision)
        except LifecycleError as exc:
            assert "case-colliding" in str(exc)
        else:
            raise AssertionError("case-colliding tree paths were accepted")


if __name__ == "__main__":
    test_tree_add_modify_preserve_and_idempotence()
    test_tree_conflict_symlink_and_case_collision_fail_closed()
    print("PASS")
