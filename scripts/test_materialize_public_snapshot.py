#!/usr/bin/env python3
"""Synthetic integration tests for sanitized snapshot materialization."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

from export_public_candidate import DETECTOR_FORMAT, audit_fresh_git  # noqa: E402
from materialize_public_snapshot import (  # noqa: E402
    NO_AUTO_MAINTENANCE_ARGS,
    SnapshotBuildError,
    _gateway_receipt,
    _init_candidate_git,
    materialize_snapshot,
)


POLICY_PATH = "config/public-export.yaml"


def _write(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _policy(*, include_unreviewed: bool = False) -> dict[str, object]:
    private = ["internal/notes.txt", POLICY_PATH]
    if include_unreviewed:
        private.append("future.txt")
    return {
        "formatVersion": "stateport.public-export-allowlist/v1",
        "default": {
            "id": "future-path-blocked",
            "classification": "unresolved-blocking",
            "license": "NOASSERTION",
            "provenanceRationale": "Synthetic paths require an explicit decision.",
        },
        "rules": [
            {
                "id": "synthetic-code",
                "classification": "public-source",
                "license": "AGPL-3.0-or-later",
                "provenanceRationale": "Invented test source.",
                "paths": ["src/app.py"],
            },
            {
                "id": "synthetic-docs",
                "classification": "public-documentation",
                "license": "CC-BY-4.0",
                "provenanceRationale": "Invented test documentation.",
                "paths": ["docs/README.md"],
            },
            {
                "id": "synthetic-license",
                "classification": "third-party-reviewed",
                "license": "AGPL-3.0-only",
                "provenanceRationale": "Invented canonical test licence text.",
                "paths": ["LICENSE"],
            },
            {
                "id": "synthetic-private",
                "classification": "private-internal",
                "license": "NOASSERTION",
                "provenanceRationale": "Invented private test control.",
                "paths": private,
            },
        ],
    }


def _source(tmp_path: Path, *, unresolved: bool = False) -> tuple[Path, str]:
    source = tmp_path / "private-source"
    source.mkdir()
    _git(source, "init", "--quiet", "--initial-branch=private-work")
    _write(source / "src/app.py", "print('public snapshot fixture')\n")
    _write(source / "docs/README.md", "# Public snapshot fixture\n")
    _write(source / "LICENSE", "Synthetic canonical licence fixture.\n")
    _write(source / "internal/notes.txt", "Private fixture control.\n")
    _write(source / POLICY_PATH, yaml.safe_dump(_policy(), sort_keys=False))
    if unresolved:
        _write(source / "future.txt", "Unreviewed fixture.\n")
    _git(source, "add", "--all")
    _git(
        source,
        "-c",
        "user.name=Snapshot Fixture Builder",
        "-c",
        "user.email=snapshot-fixture@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "synthetic private source",
    )
    return source, _git(source, "rev-parse", "HEAD")


def _detectors(tmp_path: Path) -> Path:
    path = tmp_path / "private-detectors.json"
    path.write_text(
        json.dumps(
            {
                "formatVersion": DETECTOR_FORMAT,
                "forbiddenLiterals": [
                    {"id": "synthetic-private-sentinel", "value": "never-copy-private-sentinel"}
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    os.chmod(path, 0o600)
    return path


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_materializes_one_clean_self_contained_candidate_and_external_receipts(
    tmp_path: Path,
) -> None:
    source, commit = _source(tmp_path)
    candidate = tmp_path / "candidate"
    evidence = tmp_path / "evidence"

    result = materialize_snapshot(
        source,
        commit,
        POLICY_PATH,
        _detectors(tmp_path),
        candidate,
        evidence,
    )

    assert result["status"] == "passed"
    assert result["sourceCommit"] == commit
    assert _git(candidate, "rev-parse", "HEAD") == result["candidateHead"]
    assert _git(candidate, "status", "--porcelain=v1") == ""
    assert _git(candidate, "remote") == ""
    assert _git(candidate, "for-each-ref", "--format=%(refname)") == "refs/heads/public-main"
    assert audit_fresh_git(candidate) == []
    assert not (candidate / ".git/logs").exists()
    assert sorted(
        path.relative_to(candidate).as_posix()
        for path in candidate.rglob("*")
        if path.is_file() and ".git" not in path.relative_to(candidate).parts
    ) == ["LICENSE", "docs/README.md", "src/app.py"]
    assert not (candidate / "internal").exists()
    assert not (candidate / "config").exists()

    assert _load(evidence / "gateway-receipt.json")["status"] == "passed"
    assert _load(evidence / "snapshot-audit.json")["status"] == "passed"
    assert _load(evidence / "exclusion-receipt.json")["defaultMatchedFileCount"] == 0
    assert _load(evidence / "licensing-receipt.json")["candidateFileCount"] == 3
    assert _load(evidence / "materialization-receipt.json") == result
    rights = yaml.safe_load((evidence / "rights-inventory.yaml").read_text(encoding="utf-8"))
    assert {item["path"] for item in rights["files"]} == {"LICENSE", "docs/README.md", "src/app.py"}
    assert (evidence / "private-export-inventory.json").stat().st_mode & 0o777 == 0o600

    with pytest.raises(SnapshotBuildError, match="already exists"):
        materialize_snapshot(source, commit, POLICY_PATH, _detectors(tmp_path), candidate, evidence)


def test_candidate_git_writes_disable_detached_auto_maintenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    candidate = tmp_path / "candidate"
    source.mkdir()
    candidate.mkdir()
    calls: list[tuple[str, ...]] = []

    def fake_git(
        _repository: Path,
        arguments: list[str],
        *,
        environment: dict[str, str] | None = None,
    ) -> str:
        del environment
        call = tuple(arguments)
        calls.append(call)
        if call[:3] == ("show", "-s", "--format=%ct"):
            return "1760000000"
        if call == ("rev-parse", "HEAD"):
            return "a" * 40
        if call == ("for-each-ref", "--format=%(refname)"):
            return "refs/heads/public-main"
        return ""

    monkeypatch.setattr("materialize_public_snapshot._git", fake_git)
    monkeypatch.setattr("materialize_public_snapshot.audit_fresh_git", lambda _candidate: [])

    assert _init_candidate_git(candidate, source, "b" * 40) == "a" * 40
    assert (*NO_AUTO_MAINTENANCE_ARGS, "add", "--all") in calls
    assert (
        *NO_AUTO_MAINTENANCE_ARGS,
        "commit",
        "--quiet",
        "-m",
        "StatePort sanitized public snapshot",
    ) in calls


def test_unreviewed_future_path_blocks_before_candidate_git_materialization(tmp_path: Path) -> None:
    source, commit = _source(tmp_path, unresolved=True)
    candidate = tmp_path / "blocked-candidate"
    evidence = tmp_path / "blocked-evidence"

    with pytest.raises(SnapshotBuildError, match="export was blocked"):
        materialize_snapshot(
            source,
            commit,
            POLICY_PATH,
            _detectors(tmp_path),
            candidate,
            evidence,
        )

    assert not candidate.exists()
    manifest = _load(evidence / "public-export-manifest.json")
    assert manifest["status"] == "blocked"
    assert {item["code"] for item in manifest["blockingIssueCounts"]} == {
        "unresolved_classification"
    }


def test_gateway_allows_reserved_fixture_email_but_blocks_other_email_domains(
    tmp_path: Path,
) -> None:
    safe = tmp_path / "safe-candidate"
    safe.mkdir()
    _write(safe / "fixture.txt", "Contact: support@example.invalid\n")

    receipt = _gateway_receipt(safe)

    assert receipt["status"] == "passed"
    assert receipt["reviewedFixtureEmailCount"] == 1
    assert receipt["highRiskFindingCount"] == 0

    _write(safe / "private-use.txt", "Contact: operator@stateport.internal\n")
    private_use_receipt = _gateway_receipt(safe)
    assert private_use_receipt["status"] == "passed"
    assert private_use_receipt["reviewedFixtureEmailCount"] == 2

    unsafe = tmp_path / "unsafe-candidate"
    unsafe.mkdir()
    _write(unsafe / "contact.txt", "Contact: person@" + "company.be\n")

    with pytest.raises(SnapshotBuildError, match="requiring transformation or review"):
        _gateway_receipt(unsafe)


def test_gateway_disposes_npm_specifiers_only_inside_lockfiles(tmp_path: Path) -> None:
    candidate = tmp_path / "lockfile-candidate"
    candidate.mkdir()
    _write(
        candidate / "package-lock.json",
        '"resolved": "openai/codex@' + '0.146.0-darwin-arm64"\n',
    )

    receipt = _gateway_receipt(candidate)

    assert receipt["status"] == "passed"
    assert receipt["reviewedNpmSpecifierCount"] == 1
    assert receipt["reviewedFixtureEmailCount"] == 0
    assert receipt["highRiskFindingCount"] == 0

    _write(candidate / "not-a-lockfile.txt", "specifier: openai/codex@" + "0.146.0-darwin-arm64\n")
    with pytest.raises(SnapshotBuildError, match="requiring transformation or review"):
        _gateway_receipt(candidate)

    _write(candidate / "package-lock.json", "contact: person@" + "company.be\n")
    with pytest.raises(SnapshotBuildError, match="requiring transformation or review"):
        _gateway_receipt(candidate)
