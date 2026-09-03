#!/usr/bin/env python3
"""Focused tests for StatePort diagnostics and the read-only doctor."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "packages" / "diagnostics" / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from diagnostics import Diagnostic, DiagnosticCode, Doctor, DoctorConfig, DoctorReport, Severity  # noqa: E402


def test_diagnostic_codes_are_stable_and_json_safe() -> None:
    assert [code.value for code in DiagnosticCode] == [
        "SP-ENV", "SP-SOURCE", "SP-INSTANCE", "SP-LOCK", "SP-LIFECYCLE",
        "SP-RUN", "SP-APPROVAL", "SP-BACKUP", "SP-HOST", "SP-CI",
        "SP-INSTANCE-ROOT-NOT-FOUND", "SP-INSTANCE-ROOT-NOT-DIRECTORY",
        "SP-INSTANCE-ROOT-INACCESSIBLE", "SP-SOURCE-EXPLICIT-REQUIRED",
        "SP-SOURCE-REPOSITORY-NOT-FOUND", "SP-SOURCE-MANIFEST-NOT-FOUND",
        "SP-SOURCE-COMMIT-NOT-FOUND", "SP-SOURCE-TEMPLATE-ID-MISMATCH",
        "SP-SOURCE-IDENTITY-MISMATCH",
    ]
    item = Diagnostic(
        "SP-ENV", "info", "environment", "runtime is available",
        {"nested": {"token": "do-not-store", "value": 3}},
        "continue",
        ("sys.version_info",),
    )
    encoded = item.to_json()
    assert json.loads(encoded) == item.to_dict()
    assert "do-not-store" not in encoded
    assert item.to_dict()["details"] == {"nested": {"token": "<redacted>", "value": 3}}


def test_report_order_is_independent_of_construction_order() -> None:
    report = DoctorReport(
        (
            Diagnostic("SP-CI", "info", "ci", "git ok", {}, "No action required.", ("git",)),
            Diagnostic("SP-ENV", "warning", "environment", "runtime warning", {}, "fix", ("runtime",)),
            Diagnostic("SP-SOURCE", "error", "source", "unsafe path", {}, "fix", ("path",)),
        )
    )
    assert [item.code.value for item in report.diagnostics] == ["SP-ENV", "SP-SOURCE", "SP-CI"]
    assert not report.ok


def test_doctor_passes_repo_fixture_and_is_read_only() -> None:
    doctor = Doctor(DoctorConfig(ROOT))
    report = doctor.run()
    assert doctor.read_only
    assert report.ok, report.to_json()
    assert {item.code.value for item in report.diagnostics} == {"SP-ENV", "SP-SOURCE", "SP-INSTANCE", "SP-HOST", "SP-CI"}


def test_doctor_reports_escaping_path_without_following_it(tmp_path: Path) -> None:
    outside = tmp_path / "outside.yaml"
    outside.write_text("safe: true\n", encoding="utf-8")
    config = DoctorConfig(ROOT, config_paths=(outside,))
    report = Doctor(config).check_paths()[0]
    assert report.code is DiagnosticCode.SOURCE
    assert report.severity is Severity.ERROR
    assert "outside-repository" in json.dumps(report.to_dict())


def test_doctor_optional_readiness_uses_injected_read_only_probe() -> None:
    calls: list[tuple[str, float]] = []

    def probe(url: str, timeout: float) -> int:
        calls.append((url, timeout))
        return 204

    doctor = Doctor(
        DoctorConfig(ROOT, ui_url="http://127.0.0.1:8080/ready", api_url="http://127.0.0.1:8790/ready"),
        readiness_probe=probe,
    )
    diagnostics = doctor.check_readiness()
    assert len(diagnostics) == 2
    assert all(item.severity is Severity.INFO for item in diagnostics)
    assert calls == [("http://127.0.0.1:8080/ready", 1.0), ("http://127.0.0.1:8790/ready", 1.0)]


def test_doctor_rejects_non_fixture_adapter(tmp_path: Path) -> None:
    fixture = tmp_path / "adapter.json"
    fixture.write_text(
        json.dumps({"formatVersion": "stateport.backend-capabilities/v1", "adapter": {"testOnly": False, "productionEligible": True}}),
        encoding="utf-8",
    )
    diagnostic = Doctor(DoctorConfig(ROOT, adapter_fixture=fixture)).check_adapter_fixture()[0]
    assert diagnostic.code is DiagnosticCode.HOST
    assert diagnostic.severity is Severity.ERROR


_REPO_COPY_IGNORE = shutil.ignore_patterns(".git", "__pycache__", ".tmp")


def _copy_repo(destination: Path, *, source: Path = ROOT) -> None:
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

    shutil.copytree(source, destination, ignore=ignore)


def test_copy_repo_excludes_scratch_and_destination(tmp_path: Path) -> None:
    source = tmp_path / "source"
    scratch = source / "scratch"
    scratch.mkdir(parents=True)
    (source / "marker.txt").write_text("marker\n", encoding="utf-8")
    leftover = source / ".tmp"
    leftover.mkdir()
    (leftover / "leftover.txt").write_text("leftover\n", encoding="utf-8")
    destination = scratch / "repo"
    _copy_repo(destination, source=source)
    assert (destination / "marker.txt").is_file()
    assert not (destination / ".tmp").exists()
    assert not (destination / "scratch").exists()
    assert list(destination.rglob("repo")) == []


def test_doctor_does_not_write_during_run(tmp_path: Path) -> None:
    destination = tmp_path / "repo"
    _copy_repo(destination)
    before = sorted(path.relative_to(destination).as_posix() for path in destination.rglob("*") if path.is_file())
    Doctor(DoctorConfig(destination)).run()
    after = sorted(path.relative_to(destination).as_posix() for path in destination.rglob("*") if path.is_file())
    assert before == after


def _doctor_cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(ROOT / "stateport"), "doctor", *arguments],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def _root_diagnostic(report: DoctorReport) -> Diagnostic:
    root_codes = {
        DiagnosticCode.INSTANCE_ROOT_NOT_FOUND,
        DiagnosticCode.INSTANCE_ROOT_NOT_DIRECTORY,
        DiagnosticCode.INSTANCE_ROOT_INACCESSIBLE,
    }
    return next(item for item in report.diagnostics if item.code in root_codes)


def test_doctor_reports_nonexistent_absolute_root_without_mutation(tmp_path: Path) -> None:
    root = tmp_path / "missing-root"
    report = Doctor(DoctorConfig(root)).run()
    diagnostic = _root_diagnostic(report)
    assert diagnostic.code is DiagnosticCode.INSTANCE_ROOT_NOT_FOUND
    assert diagnostic.severity is Severity.ERROR
    assert diagnostic.component.value == "instance"
    assert diagnostic.details["suppliedRoot"] == str(root)
    assert not root.exists()


def test_doctor_reports_nonexistent_relative_root_without_mutation() -> None:
    relative = Path(".stateport-test-missing-root")
    try:
        assert not (ROOT / relative).exists()
        report = Doctor(DoctorConfig(relative)).run()
        diagnostic = _root_diagnostic(report)
        assert diagnostic.code is DiagnosticCode.INSTANCE_ROOT_NOT_FOUND
        assert diagnostic.details["suppliedRoot"] == relative.as_posix()
    finally:
        assert not (ROOT / relative).exists()


def test_doctor_reports_regular_file_root(tmp_path: Path) -> None:
    root = tmp_path / "not-a-directory"
    root.write_text("not a directory\n", encoding="utf-8")
    diagnostic = _root_diagnostic(Doctor(DoctorConfig(root)).run())
    assert diagnostic.code is DiagnosticCode.INSTANCE_ROOT_NOT_DIRECTORY
    assert diagnostic.details["rootKind"] == "file"


def test_doctor_reports_inaccessible_root_when_permission_bits_reproduce_it(tmp_path: Path) -> None:
    root = tmp_path / "inaccessible"
    root.mkdir()
    original_mode = root.stat().st_mode & 0o777
    try:
        root.chmod(0)
        diagnostic = _root_diagnostic(Doctor(DoctorConfig(root)).run())
        assert diagnostic.code is DiagnosticCode.INSTANCE_ROOT_INACCESSIBLE
        assert diagnostic.details["rootKind"] == "inaccessible-directory"
    finally:
        root.chmod(original_mode)


def test_doctor_cli_human_and_json_root_failures_are_traceback_free(tmp_path: Path) -> None:
    root = tmp_path / "missing-root"
    human = _doctor_cli("--root", str(root))
    assert human.returncode == 2
    assert human.stderr == ""
    assert "Traceback" not in human.stdout
    assert "SP-INSTANCE-ROOT-NOT-FOUND" in human.stdout
    assert str(root) in human.stdout
    assert "doctor: issues found" in human.stdout

    encoded = _doctor_cli("--root", str(root), "--json")
    assert encoded.returncode == 2
    assert encoded.stderr == ""
    assert "Traceback" not in encoded.stdout
    payload = json.loads(encoded.stdout)
    diagnostic = next(item for item in payload["diagnostics"] if item["code"] == "SP-INSTANCE-ROOT-NOT-FOUND")
    assert diagnostic["severity"] == "error"
    assert diagnostic["component"] == "instance"
    assert diagnostic["details"]["suppliedRoot"] == str(root)
    assert "remediation" in diagnostic
    assert not root.exists()


def test_doctor_cli_accepts_valid_root_in_both_modes() -> None:
    for arguments in ((), ("--json",)):
        result = _doctor_cli("--root", ".", *arguments)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "Traceback" not in result.stdout
        if "--json" in arguments:
            assert json.loads(result.stdout)["ok"] is True


def test_doctor_does_not_hide_unexpected_internal_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(_self: Doctor) -> tuple[Diagnostic, ...]:
        raise RuntimeError("unexpected doctor failure")

    monkeypatch.setattr(Doctor, "check_paths", explode)
    with pytest.raises(RuntimeError, match="unexpected doctor failure"):
        Doctor(DoctorConfig(ROOT)).run()
