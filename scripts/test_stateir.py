#!/usr/bin/env python3
"""Focused tests for source-linked StateIR normalization."""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORE_SRC = ROOT / "packages" / "statedd-core" / "src"
if str(CORE_SRC) not in sys.path:
    sys.path.insert(0, str(CORE_SRC))

from statedd_core import build_state_ir, create_instance


CLASSDD = ROOT / "templates" / "classdd"
V2_FIXTURE = ROOT / "fixtures" / "templates" / "lifecycle-v2-minimal"


def _make_instance(workspace: Path) -> tuple[Path, Path]:
    template = workspace / "template"
    shutil.copytree(CLASSDD, template)
    instance = workspace / "instance"
    create_instance(
        template,
        instance,
        instance_id="demo",
        name="Demo",
        owner_name="Alice",
        owner_handle="@alice",
    )
    return template, instance


def test_stateir_is_deterministic_and_source_linked() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        _, instance = _make_instance(Path(tmpdir))
        (instance / "state" / "class.yaml").write_text(
            "class:\n  students:\n    - id: s1\n", encoding="utf-8"
        )
        first = build_state_ir(instance)
        second = build_state_ir(instance)
        assert first == second
        assert first.format_version == "statedd.state-ir/v1"
        assert first.facts
        assert all(fact.source is not None for fact in first.facts)
        assert all(fact.source.sha256.startswith("sha256:") for fact in first.facts)
        assert any(fact.path == "state/class.yaml#/class/students/0/id" for fact in first.facts)
        assert first.to_dict()["facts"][0]["source"]["path"]


def test_stateir_filters_secret_files_before_fact_generation() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        template, instance = _make_instance(Path(tmpdir))
        manifest = template / ".statedd" / "manifest.yaml"
        text = manifest.read_text(encoding="utf-8")
        text = text.replace("    sensitivity: private\n", "    sensitivity: secret\n")
        manifest.write_text(text, encoding="utf-8")
        lock = instance / ".statedd" / "lock.yaml"
        lock_text = lock.read_text(encoding="utf-8")
        lock.write_text(
            lock_text.replace('    sensitivity: "private"\n', '    sensitivity: "secret"\n'),
            encoding="utf-8",
        )
        ir = build_state_ir(instance, template_path=template)
        assert "instance.yaml" in ir.excluded_files
        assert not any(fact.source_file == "instance.yaml" for fact in ir.facts)
        assert ir.stale is True


def test_stateir_exposes_intersection_of_access_policies() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        template, instance = _make_instance(Path(tmpdir))
        ir = build_state_ir(
            instance,
            template_path=template,
            template_sensitivities={"public", "private"},
            instance_granted_sensitivities={"private"},
            operator_allowed_sensitivities={"public", "private"},
        )
        assert ir.included_files == (
            "instance.yaml",
            "state/class.yaml",
            "state/students.yaml",
            "state/topics.yaml",
        )
        assert ".statedd/contract.md" in ir.excluded_files


def test_stateir_marks_changed_template_source_stale_without_mutating_instance() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        template, instance = _make_instance(Path(tmpdir))
        before = (instance / "state" / "class.yaml").read_bytes()
        (template / "README.md").write_text("changed template\n", encoding="utf-8")
        ir = build_state_ir(instance, template_path=template)
        assert ir.stale is True
        assert (instance / "state" / "class.yaml").read_bytes() == before


def test_stateir_rejects_symlinked_canonical_source() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        template, instance = _make_instance(Path(tmpdir))
        state = instance / "state" / "class.yaml"
        original = state.read_bytes()
        state.unlink()
        state.symlink_to(instance / "instance.yaml")
        try:
            build_state_ir(instance, template_path=template)
        except ValueError as exc:
            assert "symlink" in str(exc)
        else:
            raise AssertionError("expected symlinked source to be rejected")
        state.unlink()
        state.write_bytes(original)


def test_stateir_supports_v2_source_without_template_yaml() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        template = workspace / "template"
        shutil.copytree(V2_FIXTURE, template)
        (template / "template.yaml").unlink()
        instance = workspace / "instance"
        create_instance(
            template,
            instance,
            instance_id="demo-v2",
            name="Demo v2",
            owner_name="Alice",
            owner_handle="@alice",
            allow_fixture=True,
        )
        ir = build_state_ir(instance)
        assert ir.source_revision.startswith("sha256:")
        assert ir.included_files == ("README.md", "instance.yaml")


def test_stateir_accepts_expanded_template_owned_tree_files() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        template = workspace / "template"
        shutil.copytree(V2_FIXTURE, template)
        manifest = template / ".statedd" / "manifest.yaml"
        text = manifest.read_text(encoding="utf-8")
        text = text.replace("path: state\n    kind: tree\n    owner: instance", "path: state\n    kind: tree\n    owner: template")
        manifest.write_text(text, encoding="utf-8")
        (template / "state").mkdir(exist_ok=True)
        (template / "state" / "guide.md").write_text("synthetic tree source\n", encoding="utf-8")
        (template / "state" / "metadata.yaml").write_text(
            "---\nlast_updated: 2026-07-13\n", encoding="utf-8"
        )
        instance = workspace / "instance"
        create_instance(
            template,
            instance,
            instance_id="tree-demo",
            name="Tree demo",
            owner_name="Synthetic",
            owner_handle="synthetic",
            allow_fixture=True,
        )
        ir = build_state_ir(instance)
        assert "state/guide.md" in ir.included_files
        assert "state/metadata.yaml" in ir.included_files


if __name__ == "__main__":
    test_stateir_is_deterministic_and_source_linked()
    test_stateir_filters_secret_files_before_fact_generation()
    test_stateir_exposes_intersection_of_access_policies()
    test_stateir_marks_changed_template_source_stale_without_mutating_instance()
    test_stateir_rejects_symlinked_canonical_source()
    test_stateir_supports_v2_source_without_template_yaml()
    test_stateir_accepts_expanded_template_owned_tree_files()
    print("PASS")
