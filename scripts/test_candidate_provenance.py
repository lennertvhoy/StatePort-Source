from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess

import pytest
import yaml

from validate_candidate_provenance import (
    CandidateProvenanceError,
    main,
    validate_all,
    validate_contract,
    validate_repository_relationship,
    verify_bundle,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = (
    ROOT / "config" / "candidate-provenance" / "stateport-public-snapshot-20260730-dcfd4b8c.yaml"
)
SCHEMA_PATH = ROOT / "schemas" / "candidate-provenance.v1.schema.json"


def _values() -> tuple[dict, dict]:
    return (
        yaml.safe_load(CONTRACT_PATH.read_text(encoding="utf-8")),
        json.loads(SCHEMA_PATH.read_text(encoding="utf-8")),
    )


def test_tracked_contract_is_exact_and_primary_namespace_is_explicit() -> None:
    value, schema = _values()
    validated = validate_contract(value, schema)
    assert validated["repository"]["commit"] == "7dc32e44177c3577bfa8577e5d9cc24d8d3641aa"
    assert validated["repository"]["primaryRepositoryResolvable"] is False
    assert validated["retention"]["status"] == "durably_reconciled"
    assert validated["verification"]["contract"]["argv"] == [
        "python3",
        "scripts/validate_candidate_provenance.py",
    ]
    assert validated["verification"]["recovery"]["argvPrefix"][-1] == "--bundle"
    assert validate_all(ROOT) == ("stateport-public-snapshot-20260730-dcfd4b8c",)


def test_absolute_operator_path_is_rejected() -> None:
    value, schema = _values()
    value = deepcopy(value)
    value["storage"]["repositoryLocator"] = "/home/operator/private-candidate"
    with pytest.raises(CandidateProvenanceError, match="schema validation|absolute host path"):
        validate_contract(value, schema)


def test_bare_or_missing_bundle_identity_is_rejected() -> None:
    value, schema = _values()
    value = deepcopy(value)
    value["artifacts"]["gitBundle"]["sha256"] = None
    with pytest.raises(CandidateProvenanceError, match="schema validation"):
        validate_contract(value, schema)


def test_verification_commands_are_required() -> None:
    value, schema = _values()
    value = deepcopy(value)
    del value["verification"]
    with pytest.raises(CandidateProvenanceError, match="schema validation"):
        validate_contract(value, schema)


def test_source_tree_and_retained_tool_bytes_are_verified() -> None:
    value, _schema = _values()
    wrong_tree = deepcopy(value)
    wrong_tree["materialization"]["sourceTree"] = "0" * 40
    with pytest.raises(CandidateProvenanceError, match="source tree"):
        validate_repository_relationship(wrong_tree, ROOT)

    wrong_tool = deepcopy(value)
    wrong_tool["materialization"]["exporter"]["sha256"] = "0" * 64
    with pytest.raises(CandidateProvenanceError, match="exporter blob digest"):
        validate_repository_relationship(wrong_tool, ROOT)


def test_default_cli_does_not_claim_bundle_recovery(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--root", str(ROOT)]) == 0
    output = capsys.readouterr().out
    assert "external recovery bundle not inspected" in output
    assert "exact recovery bundle was verified" not in output


def test_archive_commit_must_match_candidate() -> None:
    value, schema = _values()
    value = deepcopy(value)
    value["artifacts"]["auditedSourceArchive"]["embeddedCommit"] = "0" * 40
    with pytest.raises(CandidateProvenanceError, match="embedded commit"):
        validate_contract(value, schema)


def test_bundle_recovery_is_explicit_and_quiet(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "source"
    subprocess.run(
        ["git", "init", "--quiet", "--initial-branch=public-main", str(source)],
        check=True,
    )
    (source / "README.md").write_text("recoverable candidate\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(source), "add", "README.md"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(source),
            "-c",
            "user.name=StatePort test",
            "-c",
            "user.email=stateport-test@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        ],
        check=True,
    )
    commit = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    tree = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD^{tree}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    bundle = tmp_path / "candidate.bundle"
    subprocess.run(
        ["git", "-C", str(source), "bundle", "create", str(bundle), "public-main"],
        check=True,
    )
    payload = bundle.read_bytes()
    verify_bundle(
        {
            "repository": {
                "commit": commit,
                "tree": tree,
                "ref": "refs/heads/public-main",
            },
            "artifacts": {
                "gitBundle": {
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "bytes": len(payload),
                    "ref": "refs/heads/public-main",
                }
            },
        },
        bundle,
    )
    captured = capfd.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_tool_issued_receipts_must_match_content_derivation() -> None:
    from validate_candidate_provenance import _derive_tool_receipt

    value, schema = _values()
    tool_issued = deepcopy(value)
    receipt = tool_issued["materialization"]["receipt"]
    bundle = tool_issued["artifacts"]["gitBundle"]
    archive = tool_issued["artifacts"]["auditedSourceArchive"]
    receipt["id"] = _derive_tool_receipt("materialization", receipt["digest"])
    bundle["recoveryReceipt"] = _derive_tool_receipt("recovery", bundle["sha256"])
    tool_issued["retention"]["preservationReceipt"] = _derive_tool_receipt(
        "preservation", bundle["sha256"], archive["sha256"]
    )
    validate_contract(tool_issued, schema)

    forged = deepcopy(tool_issued)
    forged["retention"]["preservationReceipt"] = "snapshot_receipt_" + "0" * 32
    with pytest.raises(CandidateProvenanceError, match="content derivation"):
        validate_contract(forged, schema)

    broker_issued = deepcopy(value)
    validate_contract(broker_issued, schema)
