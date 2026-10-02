#!/usr/bin/env python3
"""Focused tests for explicit immutable source selection in the local alpha."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
for relative in (
    "packages/statedd-core/src",
    "packages/diagnostics/src",
    "packages/execution-host/src",
    "packages/synthetic-executor/src",
    "apps/runner/src",
    "apps/admin-cli/src",
):
    path = ROOT / relative
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from diagnostics import DiagnosticCode  # noqa: E402
from statedd_core import (  # noqa: E402
    LifecycleError,
    SourceContract,
    SourceSelectionError,
    create_instance,
    load_builtin_source_contract,
    resolve_source_contract,
)
from statedd_core.lifecycle import _write_yaml  # noqa: E402
from statedd_core.yaml import parse_yaml_text  # noqa: E402


FIXTURE = ROOT / "fixtures" / "templates" / "lifecycle-v2-minimal"
DEMO = ROOT / "scripts" / "demo_local_alpha.py"


def _git(cwd: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=cwd, text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def _canonical_repo(tmp_path: Path, name: str = "source") -> tuple[Path, str, str]:
    root = tmp_path / name
    shutil.copytree(FIXTURE, root)
    template = root / "template.yaml"
    template.write_text(
        template.read_text(encoding="utf-8").replace(
            "stateport.fixture.lifecycle-v2-minimal", "studydd"
        ),
        encoding="utf-8",
    )
    manifest_path = root / ".statedd" / "manifest.yaml"
    manifest = parse_yaml_text(manifest_path.read_text(encoding="utf-8"))
    manifest["template"]["id"] = "studydd"
    manifest["source"] = {"class": "canonical_source", "productionEligible": True}
    _write_yaml(manifest_path, manifest)
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "StatePort test")
    _git(root, "config", "user.email", "stateport-test@example.invalid")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "baseline")
    commit = _git(root, "rev-parse", "HEAD")
    tree = _git(root, "rev-parse", "HEAD^{tree}")
    return root, commit, tree


def _contract(root: Path, commit: str, *, expected_tree: str | None = None, template_id: str = "studydd") -> SourceContract:
    return SourceContract(
        "stateport.source-contract/v1",
        template_id,
        root.as_posix(),
        commit,
        ".statedd/manifest.yaml",
        expected_tree,
        None,
    )


def _assert_code(callable_: object, code: DiagnosticCode) -> None:
    with pytest.raises(SourceSelectionError) as raised:
        callable_()
    assert raised.value.diagnostic.code is code
    assert raised.value.diagnostic.component.value == "source"
    assert "Traceback" not in raised.value.diagnostic.to_json()


def test_builtin_profile_binds_functional_studydd_identity() -> None:
    contract = load_builtin_source_contract("builtin:studydd-local-alpha")
    assert contract.template_id == "studydd"
    assert contract.repository == "https://github.com/lennertvhoy/StudyDD_Template.git"
    assert contract.commit == "cffc45a2f69f8719b950abce37988667b1712830"
    assert contract.expected_tree == "e518c185fab3dbd1624cf76d017f566e4aad317f"


def test_explicit_local_git_mirror_resolves_and_records_identity(tmp_path: Path) -> None:
    root, commit, tree = _canonical_repo(tmp_path)
    resolved = resolve_source_contract(_contract(root, commit, expected_tree=tree))
    assert resolved.descriptor["resolvedCommit"] == commit
    assert resolved.descriptor["resolvedTree"] == tree
    assert resolved.descriptor["manifestDigest"].startswith("sha256:")
    assert resolved.manifest["templateId"] == "studydd"


def test_unrelated_ambient_studydd_checkout_is_ignored(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    valid, commit, tree = _canonical_repo(tmp_path, "explicit-mirror")
    unrelated = tmp_path / "StudyDD"
    unrelated.mkdir()
    (unrelated / "README.md").write_text("unrelated ambient checkout\n", encoding="utf-8")
    monkeypatch.setenv("STATEPORT_STUDYDD_ROOT", unrelated.as_posix())
    resolved = resolve_source_contract(_contract(valid, commit, expected_tree=tree))
    assert resolved.root == valid.resolve()
    assert resolved.root != unrelated


def test_shared_checkout_without_manifest_is_rejected(tmp_path: Path) -> None:
    root, commit, _tree = _canonical_repo(tmp_path, "shared-StudyDD-main")
    (root / ".statedd" / "manifest.yaml").unlink()
    _git(root, "add", "-u")
    _git(root, "commit", "-qm", "remove lifecycle manifest")
    missing_commit = _git(root, "rev-parse", "HEAD")
    _assert_code(
        lambda: resolve_source_contract(_contract(root, missing_commit)),
        DiagnosticCode.SOURCE_MANIFEST_NOT_FOUND,
    )


def test_source_path_does_not_exist_is_structured(tmp_path: Path) -> None:
    missing = tmp_path / "missing-source"
    _assert_code(
        lambda: resolve_source_contract(_contract(missing, "0" * 40)),
        DiagnosticCode.SOURCE_REPOSITORY_NOT_FOUND,
    )


def test_plain_copied_directory_is_not_accepted(tmp_path: Path) -> None:
    root, commit, _tree = _canonical_repo(tmp_path)
    shutil.rmtree(root / ".git")
    _assert_code(
        lambda: resolve_source_contract(_contract(root, commit)),
        DiagnosticCode.SOURCE_REPOSITORY_NOT_FOUND,
    )


def test_wrong_template_id_is_rejected(tmp_path: Path) -> None:
    root, commit, tree = _canonical_repo(tmp_path)
    _assert_code(
        lambda: resolve_source_contract(_contract(root, commit, expected_tree=tree, template_id="not-studydd")),
        DiagnosticCode.SOURCE_TEMPLATE_ID_MISMATCH,
    )


def test_absent_commit_is_rejected(tmp_path: Path) -> None:
    root, _commit, _tree = _canonical_repo(tmp_path)
    _assert_code(
        lambda: resolve_source_contract(_contract(root, "f" * 40)),
        DiagnosticCode.SOURCE_COMMIT_NOT_FOUND,
    )


def test_expected_tree_mismatch_is_rejected(tmp_path: Path) -> None:
    root, commit, _tree = _canonical_repo(tmp_path)
    _assert_code(
        lambda: resolve_source_contract(_contract(root, commit, expected_tree="e" * 40)),
        DiagnosticCode.SOURCE_IDENTITY_MISMATCH,
    )


def test_branch_movement_cannot_change_exact_commit(tmp_path: Path) -> None:
    root, commit, tree = _canonical_repo(tmp_path)
    _git(root, "checkout", "--detach", commit)
    resolved = resolve_source_contract(_contract(root, commit, expected_tree=tree))
    (root / "README.md").write_text("branch successor\n", encoding="utf-8")
    _git(root, "add", "README.md")
    _git(root, "commit", "-qm", "branch successor")
    successor = _git(root, "rev-parse", "HEAD")
    _git(root, "update-ref", "refs/heads/master", successor)
    _git(root, "checkout", "--detach", commit)
    instance = tmp_path / "instance"
    create_instance(
        root,
        instance,
        instance_id="exact-source",
        name="Exact source",
        owner_name="Test",
        owner_handle="test",
        source_descriptor=resolved.descriptor,
    )
    lock = parse_yaml_text((instance / ".statedd" / "lock.yaml").read_text(encoding="utf-8"))
    assert lock["template"]["source"]["resolvedCommit"] == commit
    assert lock["template"]["source"]["resolvedTree"] == tree


def test_source_validation_happens_before_instance_creation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import demo_local_alpha

    calls: list[list[str]] = []

    def fail_if_create(command: list[str], *, cwd: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        raise AssertionError("instance command ran before source validation")

    monkeypatch.setattr(demo_local_alpha, "_run", fail_if_create)
    with pytest.raises(SourceSelectionError):
        demo_local_alpha.run_demo(
            source_repository=(tmp_path / "missing").as_posix(),
            source_commit="0" * 40,
            source_template_id="studydd",
        )
    assert calls == []


def test_missing_explicit_source_human_and_json_errors_are_traceback_free() -> None:
    for extra in ((), ("--json",)):
        result = subprocess.run(
            [sys.executable, str(DEMO), *extra],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 2
        assert result.stderr == ""
        assert "Traceback" not in result.stdout
        assert "SP-SOURCE-EXPLICIT-REQUIRED" in result.stdout
        assert "repository" in result.stdout
        assert "requestedRef" in result.stdout
        if extra:
            payload = json.loads(result.stdout)
            assert payload["error"]["severity"] == "error"
            assert payload["error"]["component"] == "source"
            assert payload["exitCode"] == 2


@pytest.mark.skipif(not os.environ.get("STATEPORT_STUDYDD_MIRROR"), reason="functional StudyDD mirror not supplied")
def test_complete_demo_records_source_identity() -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(DEMO),
            "--source-profile",
            "builtin:studydd-local-alpha",
            "--source-repository",
            os.environ["STATEPORT_STUDYDD_MIRROR"],
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report["source"]["repository"] == "https://github.com/lennertvhoy/StudyDD_Template.git"
    assert report["source"]["commit"] == "cffc45a2f69f8719b950abce37988667b1712830"
    assert report["source"]["tree"] == "e518c185fab3dbd1624cf76d017f566e4aad317f"
    assert report["source"]["manifestDigest"] == "sha256:425008e382cc87076e05a3ae02a6915167107bcbb74dc2ffe7236650c0591671"
    assert report["source"]["matchesContract"] is True
