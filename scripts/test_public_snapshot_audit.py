#!/usr/bin/env python3
"""Synthetic regression tests for the fail-closed public-snapshot audit."""

from __future__ import annotations

from hashlib import sha256
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

from public_snapshot_audit import (  # noqa: E402
    INPUT_FORMAT,
    RIGHTS_FORMAT,
    audit_public_snapshot,
    main,
)


def _write(path: Path, value: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(value, bytes):
        path.write_bytes(value)
    else:
        path.write_text(value, encoding="utf-8")


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        capture_output=True,
        check=True,
        text=True,
    )
    return result.stdout.strip()


def _commit(repository: Path) -> str:
    _git(repository, "add", "--all")
    _git(
        repository,
        "-c",
        "user.name=Public Fixture Builder",
        "-c",
        "user.email=public-fixture@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "synthetic public root",
    )
    return _git(repository, "rev-parse", "HEAD")


def _candidate(tmp_path: Path, extra: dict[str, str | bytes] | None = None) -> tuple[Path, str]:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    _git(candidate, "init", "--quiet", "--initial-branch", "public-main")
    _write(candidate / "README.md", "# Fictional public candidate\n")
    _write(candidate / "src/app.py", "print('fictional public candidate')\n")
    for relative, content in (extra or {}).items():
        _write(candidate / relative, content)
    return candidate, _commit(candidate)


def _rights(
    candidate: Path, *, overrides: dict[str, dict[str, object]] | None = None
) -> dict[str, object]:
    entries: list[dict[str, object]] = []
    for path in sorted(
        item.relative_to(candidate).as_posix()
        for item in candidate.rglob("*")
        if item.is_file()
        and not item.is_symlink()
        and ".git" not in item.relative_to(candidate).parts
    ):
        entry: dict[str, object] = {
            "path": path,
            "category": "owned_documentation" if path.endswith(".md") else "owned_code",
            "proposedLicence": "CC-BY-4.0" if path.endswith(".md") else "AGPL-3.0-or-later",
            "source": "Invented synthetic fixture authored for this regression test.",
            "attribution": "Public Fixture Builder",
            "redistributable": True,
            "publicExportDecision": "include",
            "evidence": "Synthetic fixture ownership and licence were reviewed in-test.",
            "reviewerStatus": "reviewed_internal",
        }
        entry.update((overrides or {}).get(path, {}))
        entries.append(entry)
    return {
        "formatVersion": RIGHTS_FORMAT,
        "metadata": {
            "created": "2026-07-29",
            "scope": "Every regular file in the invented candidate tree.",
            "completeness": "Exact path coverage is verified by the audit.",
            "notes": "Synthetic test inventory only; no legal certification claim.",
        },
        "files": entries,
    }


def _metadata(
    tmp_path: Path,
    candidate: Path,
    head: str,
    *,
    rights: dict[str, object] | None = None,
    expected_head: str | None = None,
    expected_branch: str = "public-main",
) -> tuple[Path, Path]:
    controls = tmp_path / "external-audit-inputs"
    controls.mkdir(exist_ok=True)
    inventory_path = controls / "rights.yaml"
    inventory_bytes = yaml.safe_dump(rights or _rights(candidate), sort_keys=True).encode("utf-8")
    inventory_path.write_bytes(inventory_bytes)
    descriptor = {
        "formatVersion": INPUT_FORMAT,
        "git": {"expectedBranch": expected_branch, "expectedHead": expected_head or head},
        "rightsInventory": {
            "digest": "sha256:" + sha256(inventory_bytes).hexdigest(),
            "path": inventory_path.name,
        },
    }
    metadata_path = controls / "audit-input.json"
    metadata_path.write_text(json.dumps(descriptor, sort_keys=True) + "\n", encoding="utf-8")
    return metadata_path, inventory_path


def _codes(result: object) -> set[str]:
    report = getattr(result, "report")
    return {str(item["code"]) for item in report["findingCounts"]}


def test_clean_exact_candidate_passes_without_mutation(tmp_path: Path) -> None:
    candidate, head = _candidate(tmp_path)
    metadata, inventory = _metadata(tmp_path, candidate, head)
    visible_before = {
        item.relative_to(candidate).as_posix(): item.read_bytes()
        for item in candidate.rglob("*")
        if item.is_file() and ".git" not in item.relative_to(candidate).parts
    }
    controls_before = (metadata.read_bytes(), inventory.read_bytes())

    result = audit_public_snapshot(candidate, metadata)

    assert result.passed
    assert result.report["findingCounts"] == []
    assert result.report["gitIdentity"] == {"verifiedHead": head}
    assert result.report["summary"] == {
        "auditedByteCount": sum(len(value) for value in visible_before.values()),
        "auditedFileCount": 2,
        "rightsInventoryEntryCount": 2,
    }
    visible_after = {
        item.relative_to(candidate).as_posix(): item.read_bytes()
        for item in candidate.rglob("*")
        if item.is_file() and ".git" not in item.relative_to(candidate).parts
    }
    assert visible_after == visible_before
    assert (metadata.read_bytes(), inventory.read_bytes()) == controls_before
    assert _git(candidate, "status", "--porcelain=v1") == ""


def test_privacy_guidance_and_source_expressions_do_not_look_like_leaked_values(
    tmp_path: Path,
) -> None:
    candidate, head = _candidate(
        tmp_path,
        {
            "PRIVACY.md": "Never publish learner data or private conversations.\n",
            "src/security.py": (
                "import secrets\n"
                "token = secrets.token_urlsafe(32)\n"
                "credential = validate_required_string(token)\n"
            ),
            "src/navigation.ts": "export const keys = 'Home/End'\n",
        },
    )
    metadata, _inventory = _metadata(tmp_path, candidate, head)

    result = audit_public_snapshot(candidate, metadata)

    assert result.passed


def test_literal_secret_assignment_still_blocks(tmp_path: Path) -> None:
    candidate, head = _candidate(
        tmp_path,
        {"src/config.txt": "password = '" + "fixture-secret-value-1234'\n"},
    )
    metadata, _inventory = _metadata(tmp_path, candidate, head)

    result = audit_public_snapshot(candidate, metadata)

    assert not result.passed
    assert "assigned_secret_content" in _codes(result)


def test_secret_private_path_learner_internal_symlink_and_rights_fail_closed_without_values(
    tmp_path: Path,
) -> None:
    credential = "gh" + "p_" + ("A" * 24)
    private_path = "/" + "home" + "/fixture-user/private-work"
    learner_marker = "Study" + "_Lenny"
    candidate, head = _candidate(
        tmp_path,
        {
            "src/unsafe.txt": f"token={credential}\npath={private_path}\nmarker={learner_marker}\n",
            "STATE.yaml": "Internal synthetic state fixture.\n",
        },
    )
    outside = tmp_path / "outside.txt"
    outside.write_text("outside synthetic value\n", encoding="utf-8")
    os.symlink(outside, candidate / "linked.txt")
    rights = _rights(
        candidate,
        overrides={
            "src/unsafe.txt": {
                "proposedLicence": "NOASSERTION",
                "source": "",
                "reviewerStatus": "unreviewed",
            }
        },
    )
    metadata, _inventory = _metadata(tmp_path, candidate, head, rights=rights)

    result = audit_public_snapshot(candidate, metadata)

    assert not result.passed
    assert {
        "assigned_secret_content",
        "high_risk_credential_content",
        "internal_only_artifact",
        "learner_data_marker_content",
        "local_private_path_content",
        "rights_entry_not_publicly_cleared",
        "rights_license_or_provenance_invalid",
        "symlink_entry",
    } <= _codes(result)
    serialized = json.dumps(result.report, sort_keys=True)
    for forbidden in (credential, private_path, learner_marker, "src/unsafe.txt", "linked.txt"):
        assert forbidden not in serialized


def test_git_identity_and_rights_digest_mismatches_are_structured(tmp_path: Path) -> None:
    candidate, head = _candidate(tmp_path)
    metadata, inventory = _metadata(
        tmp_path,
        candidate,
        head,
        expected_head="f" * 40,
        expected_branch="public-other",
    )
    inventory.write_text(inventory.read_text(encoding="utf-8") + "# changed\n", encoding="utf-8")

    result = audit_public_snapshot(candidate, metadata)

    assert not result.passed
    assert {
        "git_branch_mismatch",
        "git_head_mismatch",
        "rights_inventory_digest_mismatch",
    } <= _codes(result)
    assert result.report["gitIdentity"] == {"verifiedHead": None}


@pytest.mark.parametrize("kind", ["missing", "symlink", "path_escape"])
def test_missing_or_unsafe_rights_inventory_fails_closed(tmp_path: Path, kind: str) -> None:
    candidate, head = _candidate(tmp_path)
    metadata, inventory = _metadata(tmp_path, candidate, head)
    document = json.loads(metadata.read_text(encoding="utf-8"))
    if kind == "missing":
        inventory.unlink()
    elif kind == "symlink":
        inventory.unlink()
        inventory.symlink_to(tmp_path / "not-present")
    else:
        document["rightsInventory"]["path"] = "../rights.yaml"
        metadata.write_text(json.dumps(document), encoding="utf-8")

    result = audit_public_snapshot(candidate, metadata)

    assert not result.passed
    assert _codes(result) & {
        "audit_metadata_invalid",
        "rights_inventory_metadata_missing",
        "rights_inventory_missing_or_unsafe",
    }


def test_cli_returns_two_and_emits_only_json_for_a_blocked_candidate(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    candidate, head = _candidate(tmp_path)
    metadata, _inventory = _metadata(tmp_path, candidate, head, expected_head="e" * 40)

    assert main(["--candidate", str(candidate), "--metadata", str(metadata)]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "blocked"
    assert {item["code"] for item in report["findingCounts"]} >= {"git_head_mismatch"}


def test_missing_audit_metadata_is_reported_without_skipping_candidate_scan(tmp_path: Path) -> None:
    candidate, _head = _candidate(tmp_path, {"src/private.txt": "marker=" + "Study" + "_Lenny\n"})

    result = audit_public_snapshot(candidate, tmp_path / "absent-audit-input.json")

    assert not result.passed
    assert {
        "audit_metadata_missing",
        "git_identity_metadata_missing",
        "learner_data_marker_content",
        "rights_inventory_metadata_missing",
    } <= _codes(result)
    assert result.report["gitIdentity"] == {"verifiedHead": None}


def test_public_home_accounts_pass_but_other_home_paths_block(tmp_path: Path) -> None:
    public_paths = (
        "brew=/home/linuxbrew/.linuxbrew/bin/syft\n"
        "service=/home/stateport/.codex\n"
        "qualification=/home/stateport-qualification/.local/state/stateport\n"
        "fixture=/home/operator/private\n"
    )
    candidate, head = _candidate(tmp_path, {"src/paths.txt": public_paths})
    metadata, _inventory = _metadata(tmp_path, candidate, head)

    result = audit_public_snapshot(candidate, metadata)

    assert result.passed
    assert "local_private_path_content" not in _codes(result)

    private_path = "/" + "home" + "/fixture-owner/private-work"
    (tmp_path / "second").mkdir()
    candidate, head = _candidate(tmp_path / "second", {"src/paths.txt": f"path={private_path}\n"})
    metadata, _inventory = _metadata(tmp_path / "second", candidate, head)

    result = audit_public_snapshot(candidate, metadata)

    assert not result.passed
    assert "local_private_path_content" in _codes(result)
