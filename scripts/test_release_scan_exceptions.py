from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from collect_release_evidence import (  # noqa: E402
    EvidenceError,
    evaluate_scan,
    load_scan_exceptions,
)


TODAY = "2026-08-02"


def _exceptions_config(records: list[dict]) -> dict:
    return {
        "formatVersion": "stateport.release-scan-exceptions/v1",
        "resolvedOn": TODAY,
        "exceptions": records,
    }


def _record(**overrides: object) -> dict:
    record = {
        "id": "RX-2026-001",
        "advisory": "CVE-2026-11940",
        "package": "python",
        "images": ["stateport-api"],
        "severity": "High",
        "surface": "CPython standard library in the control-plane runtime image.",
        "reachability": "No fixed CPython 3.13 release exists at the pin date; the defect is documented as unreachable through the service surface.",
        "evidence": "Grype scan retained under the release evidence root; upstream fix only in 3.15.0b4.",
        "remediation": "Rebase to the first fixed CPython 3.13.x or 3.15 base image when published.",
        "expiresOn": "2026-09-15",
    }
    record.update(overrides)
    return record


def _write_scan(tmp_path: Path, matches: list[dict]) -> Path:
    path = tmp_path / "scan.json"
    path.write_text(json.dumps({"matches": matches}), encoding="utf-8")
    return path


def _match(
    advisory: str = "CVE-2026-11940",
    package: str = "python",
    version: str = "3.13.14",
    severity: str = "High",
    path: str | None = None,
) -> dict:
    match = {
        "vulnerability": {
            "id": advisory,
            "severity": severity,
            "fix": {"state": "wont-fix", "versions": []},
        },
        "artifact": {"name": package, "version": version},
    }
    if path is not None:
        match["artifact"]["locations"] = [{"path": path}]
    return match


def test_repository_exception_contract_is_schema_valid_and_empty_by_default() -> None:
    config, digest = load_scan_exceptions()
    assert config["formatVersion"] == "stateport.release-scan-exceptions/v1"
    assert isinstance(config["exceptions"], list)
    assert digest.startswith("sha256:")


def test_podman_remote_archive_exception_requires_candidate_bound_evidence() -> None:
    config, _digest = load_scan_exceptions()
    record = next(item for item in config["exceptions"] if item["id"] == "RX-2026-050")
    evidence = record["evidence"]
    assert "candidate receipt binds the exact source commit" in evidence
    assert "create-only release evidence root" in evidence
    assert "Alpha.9" not in evidence
    assert "release/alpha8" not in evidence


def test_historical_chrome_exceptions_cannot_mask_the_current_payload() -> None:
    config, _ = load_scan_exceptions()
    chrome = [record for record in config["exceptions"] if record["package"] == "chrome"]
    historical = [
        record for record in chrome if record["packageVersion"] == "152.0.7977.64"
    ]
    build_inputs = yaml.safe_load(
        (ROOT / "config/container-build-inputs.yaml").read_text(encoding="utf-8")
    )
    current_version = build_inputs["browserAssets"]["chrome-for-testing"]["version"]

    assert current_version == "152.0.7977.65"
    assert not [record for record in chrome if record.get("packageVersion") == current_version]
    assert len(historical) == 57
    assert [record["id"] for record in historical] == [
        f"RX-2026-{number:03d}" for number in range(107, 164)
    ]
    assert all(record["images"] == ["stateport-playwright"] for record in historical)
    assert all(record["expiresOn"] == "2026-09-15" for record in historical)


def test_gh_module_exceptions_are_exact_and_do_not_mask_xcrypto() -> None:
    config, _ = load_scan_exceptions()
    gh_modules = [
        record
        for record in config["exceptions"]
        if record["images"] == ["stateport-dev-workspace"]
        and record["package"] in {"golang.org/x/mod", "golang.org/x/crypto"}
    ]

    assert [
        (
            record["id"],
            record["advisory"],
            record["packageVersion"],
            record.get("artifactPath"),
        )
        for record in gh_modules
        if record["package"] == "golang.org/x/mod"
    ] == [
        ("RX-2026-047", "GO-2026-6179", "v0.37.0", None),
        ("RX-2026-048", "GO-2026-6180", "v0.37.0", None),
        ("RX-2026-164", "GO-2026-6179", "v0.38.0", "/usr/local/bin/gh"),
        ("RX-2026-165", "GO-2026-6180", "v0.38.0", "/usr/local/bin/gh"),
    ]
    assert not [
        record
        for record in config["exceptions"]
        if record["advisory"] == "GO-2026-6303"
        and record["images"] == ["stateport-dev-workspace"]
    ]


def test_podman_remote_go6303_exception_is_exact_and_path_bound() -> None:
    config, _ = load_scan_exceptions()
    records = [
        record
        for record in config["exceptions"]
        if record["advisory"] == "GO-2026-6303"
    ]

    assert [
        (
            record["id"],
            record["package"],
            record["packageVersion"],
            record["images"],
            record.get("artifactPath"),
            record["severity"],
        )
        for record in records
    ] == [
        (
            "RX-2026-166",
            "golang.org/x/crypto",
            "v0.50.0",
            ["stateport-execution-host"],
            "/usr/bin/podman-remote",
            "High",
        )
    ]


def test_artifact_path_exception_refuses_a_different_binary(tmp_path: Path) -> None:
    record = _record(
        advisory="GO-2026-6179",
        package="golang.org/x/mod",
        packageVersion="v0.38.0",
        artifactPath="/usr/local/bin/gh",
        images=["stateport-dev-workspace"],
    )
    wrong_path = _write_scan(
        tmp_path,
        [
            _match(
                advisory="GO-2026-6179",
                package="golang.org/x/mod",
                version="v0.38.0",
                path="/usr/local/bin/other",
            )
        ],
    )
    result = evaluate_scan(
        scan_path=wrong_path,
        image_id="stateport-dev-workspace",
        exceptions_config=_exceptions_config([record]),
        today=TODAY,
    )
    assert len(result["unexplainedFindings"]) == 1

    exact_path = _write_scan(
        tmp_path,
        [
            _match(
                advisory="GO-2026-6179",
                package="golang.org/x/mod",
                version="v0.38.0",
                path="/usr/local/bin/gh",
            )
        ],
    )
    result = evaluate_scan(
        scan_path=exact_path,
        image_id="stateport-dev-workspace",
        exceptions_config=_exceptions_config([record]),
        today=TODAY,
    )
    assert result["unexplainedFindings"] == []


def test_exact_unexpired_exception_explains_a_finding(tmp_path: Path) -> None:
    scan = _write_scan(tmp_path, [_match()])
    result = evaluate_scan(
        scan_path=scan,
        image_id="stateport-api",
        exceptions_config=_exceptions_config([_record()]),
        today=TODAY,
    )
    assert result["unexplainedFindings"] == []
    assert [item["exceptionId"] for item in result["appliedExceptions"]] == ["RX-2026-001"]


def test_expired_exception_refuses_the_finding(tmp_path: Path) -> None:
    scan = _write_scan(tmp_path, [_match()])
    result = evaluate_scan(
        scan_path=scan,
        image_id="stateport-api",
        exceptions_config=_exceptions_config([_record(expiresOn="2026-08-01")]),
        today=TODAY,
    )
    assert len(result["unexplainedFindings"]) == 1
    assert result["appliedExceptions"] == []


def test_exception_for_another_image_refuses_the_finding(tmp_path: Path) -> None:
    scan = _write_scan(tmp_path, [_match()])
    result = evaluate_scan(
        scan_path=scan,
        image_id="stateport-web",
        exceptions_config=_exceptions_config([_record()]),
        today=TODAY,
    )
    assert len(result["unexplainedFindings"]) == 1


def test_advisory_mismatch_refuses_the_finding(tmp_path: Path) -> None:
    scan = _write_scan(tmp_path, [_match(advisory="CVE-2026-99999")])
    result = evaluate_scan(
        scan_path=scan,
        image_id="stateport-api",
        exceptions_config=_exceptions_config([_record()]),
        today=TODAY,
    )
    assert len(result["unexplainedFindings"]) == 1


def test_package_mismatch_refuses_the_finding(tmp_path: Path) -> None:
    scan = _write_scan(tmp_path, [_match(package="libssl3")])
    result = evaluate_scan(
        scan_path=scan,
        image_id="stateport-api",
        exceptions_config=_exceptions_config([_record()]),
        today=TODAY,
    )
    assert len(result["unexplainedFindings"]) == 1


def test_package_version_pin_refuses_drifted_version(tmp_path: Path) -> None:
    scan = _write_scan(tmp_path, [_match(version="3.13.15")])
    result = evaluate_scan(
        scan_path=scan,
        image_id="stateport-api",
        exceptions_config=_exceptions_config([_record(packageVersion="3.13.14")]),
        today=TODAY,
    )
    assert len(result["unexplainedFindings"]) == 1


def test_below_threshold_findings_do_not_gate(tmp_path: Path) -> None:
    scan = _write_scan(tmp_path, [_match(severity="Medium"), _match(severity="Low")])
    result = evaluate_scan(
        scan_path=scan,
        image_id="stateport-api",
        exceptions_config=_exceptions_config([]),
        today=TODAY,
    )
    assert result["unexplainedFindings"] == []
    assert result["findingsBySeverity"] == {"Medium": 1, "Low": 1}


def test_empty_exception_contract_refuses_every_gated_finding(tmp_path: Path) -> None:
    scan = _write_scan(tmp_path, [_match(), _match(severity="Critical")])
    result = evaluate_scan(
        scan_path=scan,
        image_id="stateport-api",
        exceptions_config=_exceptions_config([]),
        today=TODAY,
    )
    assert len(result["unexplainedFindings"]) == 2


def test_schema_rejects_exception_without_remediation(tmp_path: Path) -> None:
    from collect_release_evidence import SCAN_EXCEPTIONS

    record = _record()
    del record["remediation"]
    config = _exceptions_config([record])
    original = SCAN_EXCEPTIONS.read_bytes()
    try:
        SCAN_EXCEPTIONS.write_text(yaml.safe_dump(config), encoding="utf-8")
        with pytest.raises(EvidenceError):
            load_scan_exceptions()
    finally:
        SCAN_EXCEPTIONS.write_bytes(original)
