from __future__ import annotations

import json
from pathlib import Path
import sys

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from infra.qualification import runner  # noqa: E402


def _candidate() -> dict[str, object]:
    return {
        "releaseId": "stateport-alpha4-test",
        "version": "0.1.0-alpha.4",
        "targetId": runner.TARGET_ID,
        "releaseIndexUri": "https://example.invalid/release-index.json",
        "releaseIndexDigest": "sha256:" + "0" * 64,
        "signedPayloadDigest": "sha256:" + "1" * 64,
        "sourceCommit": "2" * 40,
        "sourceTree": "3" * 40,
        "imageDigests": ["sha256:" + "4" * 64],
    }


def _missing(guest_id: str, distribution: str, candidate: dict[str, object]) -> dict[str, object]:
    return runner._missing_guest(
        {"guestId": guest_id, "distribution": distribution, "version": "24.04"},
        candidate,
        "SSH guest is unavailable",
    )


def test_probe_script_is_valid_guest_python() -> None:
    compile(runner._probe_script(), "guest_probe.py", "exec")


def test_missing_guest_evidence_never_becomes_support() -> None:
    candidate = _candidate()
    result = _missing("ubuntu-2404", "ubuntu", candidate)
    assert result["evidenceClass"] == "missing_real_guest"
    assert result["supportTier"] == "missing_real_guest_evidence"
    assert result["receiptDigest"] is None
    assert all(stage["status"] == "missing" for stage in result["stages"])


def test_stage_receipt_binds_release_and_image_verification_to_candidate() -> None:
    candidate = _candidate()
    receipt = runner._stage_receipt(
        guest_id="ubuntu-2404",
        stage_id="release_verification",
        candidate=candidate,
        evidence_class="real_guest",
        result="passed",
        facts={
            "releaseIndexDigest": candidate["releaseIndexDigest"],
            "signedPayloadDigest": candidate["signedPayloadDigest"],
            "sourceCommit": candidate["sourceCommit"],
            "sourceTree": candidate["sourceTree"],
            "imageDigests": candidate["imageDigests"],
            "indexVerified": True,
            "imagesVerified": True,
        },
        observed_at="2026-08-09T00:00:00Z",
    )
    assert runner._validate_stage_receipt(
        receipt, guest_id="ubuntu-2404", stage_id="release_verification", candidate=candidate
    ) == receipt
    changed = dict(receipt)
    changed["candidate"] = {**candidate, "sourceTree": "5" * 40}
    with pytest.raises(runner.QualificationError, match="different candidate"):
        runner._validate_stage_receipt(
            changed,
            guest_id="ubuntu-2404",
            stage_id="release_verification",
            candidate=candidate,
        )


def test_manifest_digest_and_missing_matrix_are_explicit() -> None:
    candidate = _candidate()
    guests = [
        _missing("ubuntu-2404", "ubuntu", candidate),
        _missing("debian", "debian", candidate),
        _missing("fedora-44", "fedora", candidate),
        _missing("arch-rolling", "rolling", candidate),
    ]
    body: dict[str, object] = {
        "schema": runner.FORMAT,
        "runId": "run_" + "a" * 32,
        "startedAt": "2026-08-09T00:00:00Z",
        "finishedAt": "2026-08-09T00:01:00Z",
        "harness": {"version": runner.HARNESS_VERSION, "runnerDigest": "sha256:" + "6" * 64},
        "candidate": candidate,
        "acceptedReceiptDigests": [],
        "guests": guests,
        "claims": {"validatedBaselineGuestIds": [], "compatibleUnvalidatedGuestIds": [], "missingEvidenceGuestIds": [item["guestId"] for item in guests]},
    }
    manifest = {**body, "manifestDigest": runner.canonical_digest(body)}
    runner.validate_manifest(manifest)
    assert manifest["claims"]["validatedBaselineGuestIds"] == []


def test_qualification_schemas_are_well_formed() -> None:
    schema_root = ROOT / "infra" / "qualification" / "schemas"
    for path in sorted(schema_root.glob("*.schema.json")):
        schema = json.loads(path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
