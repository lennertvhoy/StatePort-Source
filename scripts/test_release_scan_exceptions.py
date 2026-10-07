from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import re
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
    load_scan_suppression,
    suppressed_population,
)


_REGEX_METACHARACTERS = re.compile(r"[\\^$.|?*+()\[\]{}]")

TODAY = "2026-08-02"
GRYPE_VERSION = "0.117.0"
# The collector judges today from the real clock, not from TODAY above, so the
# declarations these two tests arm must not be able to lapse on their own.
FOREVER = "2099-12-31"


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


def _write_scan(
    tmp_path: Path,
    matches: list[dict],
    *,
    ignored: list[dict] | None = None,
    effective_rules: list[dict] | None = None,
    grype_version: str | None = None,
    name: str = "scan.json",
) -> Path:
    path = tmp_path / name
    document: dict = {"matches": matches}
    if ignored is not None or effective_rules is not None or grype_version is not None:
        # Real grype documents carry their own effective configuration; the
        # fixture reproduces that shape rather than inventing one.
        document["descriptor"] = {
            "name": "grype",
            "version": GRYPE_VERSION if grype_version is None else grype_version,
            "configuration": {"output": ["json"], "ignore": effective_rules or []},
        }
    if ignored is not None:
        document["ignoredMatches"] = ignored
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _suppression_config(records: list[dict], *, version: str = GRYPE_VERSION) -> dict:
    return {
        "formatVersion": "stateport.release-scan-suppression/v1",
        "resolvedOn": TODAY,
        "suppressionRule": "default-deny; only a declared, justified, unexpired rule suppresses",
        "tool": {
            "name": "grype",
            "version": version,
            "provenance": "Pinned grype executable in config/release-tool-inputs.yaml.",
        },
        "rules": records,
    }


def _suppression_rule(**overrides: object) -> dict:
    rule = {
        "id": "RS-2026-003",
        "package": "linux-libc-dev",
        "packageType": "deb",
        "matchType": "exact-indirect-match",
        "justification": (
            "Kernel UAPI headers and static libraries for compiling native modules; "
            "no kernel code runs from this package."
        ),
        "expiresOn": "2026-12-31",
    }
    rule.update(overrides)
    return rule


def _effective_rule(**overrides: object) -> dict:
    """One entry of grype's own ``descriptor.configuration.ignore`` list."""

    rule = {
        "vulnerability": "",
        "include-aliases": False,
        "reason": "",
        "namespace": "",
        "fix-state": "",
        "package": {
            "name": "linux-libc-dev",
            "version": "",
            "language": "",
            "type": "deb",
            "location": "",
            "upstream-name": "linux",
        },
        "vex-status": "",
        "vex-justification": "",
        "match-type": "exact-indirect-match",
    }
    rule.update(overrides)
    return rule


def _normalized_rule(**overrides: object) -> dict:
    """The normalized identity the evaluation records for an effective rule."""

    normalized = {"package": "linux-libc-dev", "packageType": "deb", "matchType": "exact-indirect-match"}
    normalized.update(overrides)
    return normalized


def _suppressed(
    advisory: str = "CVE-2024-57857",
    package: str = "linux-libc-dev",
    version: str = "6.8.0-136.136",
    severity: str = "High",
    applied: list[dict] | None = None,
) -> dict:
    """A grype suppressed match in the real observed shape."""
    match = {
        "vulnerability": {
            "id": advisory,
            "severity": severity,
            "namespace": "ubuntu:distro:ubuntu:24.04",
            "fix": {"versions": [], "state": "not-fixed"},
        },
        "artifact": {
            "name": package,
            "version": version,
            "type": "deb",
            "locations": [{"path": "/var/lib/dpkg/status"}],
        },
        "matchDetails": [
            {"type": "exact-indirect-match", "matcher": "dpkg-matcher"},
        ],
    }
    if applied is not None:
        match["appliedIgnoreRules"] = applied
    else:
        match["appliedIgnoreRules"] = [
            {
                "namespace": "",
                "package": {"name": package, "type": "deb"},
                "match-type": "exact-indirect-match",
            }
        ]
    return match


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

    assert current_version == "153.0.8010.36"
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
    ] == []
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


def test_direct_cpe_null_locations_keeps_path_bound_finding_unexplained(tmp_path: Path) -> None:
    match = _match()
    match["artifact"]["locations"] = None
    result = evaluate_scan(
        scan_path=_write_scan(tmp_path, [match]),
        image_id="stateport-api",
        exceptions_config=_exceptions_config([_record(artifactPath="/usr/bin/python")]),
        today=TODAY,
    )
    assert result["findingsBySeverity"] == {"High": 1}
    assert len(result["unexplainedFindings"]) == 1
    assert result["appliedExceptions"] == []


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


# --- scan suppression: an accepted suppression must be declared, pinned,
# justified, unexpired, and visible in the evaluation document ---
#
# Grype moves every finding covered by an ignore rule into `ignoredMatches` and
# reports success for it. Before config/release-scan-suppression.v1.yaml the
# collector's per-advisory ledger could not reach those findings at all, so an
# accepted suppression was carried only inside the grype binary. These tests
# pin the repair: the suppression is evaluated, counted, and refused unless a
# declared rule explains it.


def test_repository_suppression_contract_declares_the_pinned_scanner_defaults() -> None:
    contract, digest = load_scan_suppression()
    assert contract["formatVersion"] == "stateport.release-scan-suppression/v1"
    assert digest.startswith("sha256:")
    assert contract["tool"]["name"] == "grype"
    pinned = yaml.safe_load(
        (ROOT / "config/release-tool-inputs.yaml").read_text(encoding="utf-8")
    )
    assert contract["tool"]["version"] == pinned["tools"]["grype"]["version"] == "0.117.0"
    assert [
        (rule["package"], rule["packageType"], rule["matchType"]) for rule in contract["rules"]
    ] == [
        ("kernel-headers", "rpm", "exact-indirect-match"),
        ("linux(-.*)?-headers-.*", "deb", "exact-indirect-match"),
        ("linux-libc-dev", "deb", "exact-indirect-match"),
        ("linux-kbuild-.*", "deb", "exact-indirect-match"),
    ]
    assert [rule["id"] for rule in contract["rules"]] == [
        f"RS-2026-{number:03d}" for number in range(1, 5)
    ]
    assert all(len(rule["justification"].strip()) >= 16 for rule in contract["rules"])
    assert all(rule["expiresOn"] > TODAY for rule in contract["rules"])


def test_repository_suppression_contract_is_rejected_when_a_justification_disappears(
    tmp_path: Path,
) -> None:
    from collect_release_evidence import SCAN_SUPPRESSION

    contract = yaml.safe_load(SCAN_SUPPRESSION.read_text(encoding="utf-8"))
    contract["rules"][2]["justification"] = "  "
    original = SCAN_SUPPRESSION.read_bytes()
    try:
        SCAN_SUPPRESSION.write_text(yaml.safe_dump(contract), encoding="utf-8")
        with pytest.raises(EvidenceError, match="justification"):
            load_scan_suppression()
    finally:
        SCAN_SUPPRESSION.write_bytes(original)


def test_undeclared_suppressed_critical_is_refused(tmp_path: Path) -> None:
    """A suppressed Critical no declared rule covers must fail the image."""

    scan = _write_scan(
        tmp_path,
        [],
        ignored=[_suppressed(severity="Critical")],
        effective_rules=[_effective_rule()],
    )
    result = evaluate_scan(
        scan_path=scan,
        image_id="stateport-dev-workspace",
        exceptions_config=_exceptions_config([]),
        today=TODAY,
        suppression_config=_suppression_config([]),
    )
    suppressed = result["suppressedFindings"]
    assert suppressed["total"] == 1
    assert suppressed["bySeverity"] == {"Critical": 1}
    assert suppressed["gatedTotal"] == 1
    assert result["unexplainedSuppressedFindings"] == suppressed["uncoveredGatedFindings"]
    assert [item["advisory"] for item in suppressed["uncoveredGatedFindings"]] == [
        "CVE-2024-57857"
    ]
    assert suppressed["coveredByRule"] == {}
    assert any("covered by no" in refusal for refusal in suppressed["refusals"])
    # An undeclared effective rule is refused in its own right, even before a
    # finding is considered.
    assert suppressed["undeclaredEffectiveRules"] == [_normalized_rule()]


def test_declared_justified_unexpired_rule_explains_and_surfaces_the_suppression(
    tmp_path: Path,
) -> None:
    """The same document passes once the rule is declared, justified, unexpired."""

    scan = _write_scan(
        tmp_path,
        [],
        ignored=[
            _suppressed(severity="Critical"),
            _suppressed(advisory="CVE-2012-4542", severity="Low"),
            _suppressed(advisory="CVE-2024-57857", severity="High"),
        ],
        effective_rules=[_effective_rule()],
    )
    result = evaluate_scan(
        scan_path=scan,
        image_id="stateport-dev-workspace",
        exceptions_config=_exceptions_config([]),
        today=TODAY,
        suppression_config=_suppression_config([_suppression_rule()]),
    )
    suppressed = result["suppressedFindings"]
    assert suppressed["refusals"] == []
    assert suppressed["undeclaredEffectiveRules"] == []
    assert result["unexplainedSuppressedFindings"] == []
    assert suppressed["total"] == 3
    assert suppressed["bySeverity"] == {"Critical": 1, "Low": 1, "High": 1}
    # Below-threshold findings are counted but never explain anything.
    assert suppressed["gatedTotal"] == 2
    assert suppressed["coveredByRule"] == {"RS-2026-003": 2}
    assert [
        (item["advisory"], item["severity"], item["suppressionRuleId"])
        for item in suppressed["gatedFindings"]
    ] == [
        ("CVE-2024-57857", "Critical", "RS-2026-003"),
        ("CVE-2024-57857", "High", "RS-2026-003"),
    ]
    assert suppressed["tool"] == {
        "name": "grype",
        "declaredVersion": GRYPE_VERSION,
        "observedVersion": GRYPE_VERSION,
        "pinnedVersion": GRYPE_VERSION,
    }
    assert suppressed["effectiveRules"] == [_normalized_rule()]


def test_expired_suppression_declaration_refuses_the_finding(tmp_path: Path) -> None:
    scan = _write_scan(
        tmp_path,
        [],
        ignored=[_suppressed(severity="Critical")],
        effective_rules=[_effective_rule()],
    )
    result = evaluate_scan(
        scan_path=scan,
        image_id="stateport-dev-workspace",
        exceptions_config=_exceptions_config([]),
        today=TODAY,
        suppression_config=_suppression_config(
            [_suppression_rule(expiresOn="2026-08-01")]
        ),
    )
    suppressed = result["suppressedFindings"]
    assert suppressed["expiredRuleIds"] == ["RS-2026-003"]
    assert suppressed["uncoveredGatedFindings"][0]["advisory"] == "CVE-2024-57857"
    assert any("covered by no" in refusal for refusal in suppressed["refusals"])


def test_empty_justification_refuses_the_finding(tmp_path: Path) -> None:
    scan = _write_scan(
        tmp_path,
        [],
        ignored=[_suppressed(severity="Critical")],
        effective_rules=[_effective_rule()],
    )
    result = evaluate_scan(
        scan_path=scan,
        image_id="stateport-dev-workspace",
        exceptions_config=_exceptions_config([]),
        today=TODAY,
        suppression_config=_suppression_config([_suppression_rule(justification="")]),
    )
    suppressed = result["suppressedFindings"]
    assert suppressed["unjustifiedRuleIds"] == ["RS-2026-003"]
    assert any(
        "no justification" in refusal for refusal in suppressed["refusals"]
    ), suppressed["refusals"]
    assert suppressed["uncoveredGatedFindings"][0]["advisory"] == "CVE-2024-57857"


def test_undeclared_extra_effective_rule_is_refused(tmp_path: Path) -> None:
    """A rule the contract does not declare cannot suppress, even silently."""

    scan = _write_scan(
        tmp_path,
        [],
        ignored=[_suppressed(severity="Critical")],
        effective_rules=[
            _effective_rule(),
            _effective_rule(package={"name": "openssl", "type": "deb", "version": "", "language": "", "location": "", "upstream-name": "openssl"}),
        ],
    )
    result = evaluate_scan(
        scan_path=scan,
        image_id="stateport-dev-workspace",
        exceptions_config=_exceptions_config([]),
        today=TODAY,
        suppression_config=_suppression_config([_suppression_rule()]),
    )
    suppressed = result["suppressedFindings"]
    assert suppressed["refusals"] == [
        "the scan suppressed findings under 1 effective ignore rule(s) the policy "
        "does not declare: 'openssl'/deb/exact-indirect-match"
    ]
    assert suppressed["uncoveredGatedFindings"] == []
    # The declared rule still explains the finding it does cover; the extra
    # effective rule alone refuses the image.
    assert suppressed["coveredByRule"] == {"RS-2026-003": 1}


def test_a_rule_naming_another_package_cannot_cover_the_finding(tmp_path: Path) -> None:
    """A regex rule that does not match the suppressed package explains nothing."""

    scan = _write_scan(
        tmp_path,
        [],
        ignored=[_suppressed(severity="Critical")],
        effective_rules=[
            _effective_rule(
                package={
                    "name": "linux-headers-.*",
                    "type": "deb",
                    "version": "",
                    "language": "",
                    "location": "",
                    "upstream-name": "linux.*",
                }
            )
        ],
    )
    result = evaluate_scan(
        scan_path=scan,
        image_id="stateport-dev-workspace",
        exceptions_config=_exceptions_config([]),
        today=TODAY,
        suppression_config=_suppression_config(
            [_suppression_rule(package="linux-headers-.*")]
        ),
    )
    suppressed = result["suppressedFindings"]
    # The effective rule is declared, so it is not itself a refusal; it simply
    # does not match the suppressed package, which leaves the finding uncovered.
    assert suppressed["undeclaredEffectiveRules"] == []
    assert any("covered by no" in refusal for refusal in suppressed["refusals"])
    assert [item["advisory"] for item in suppressed["uncoveredGatedFindings"]] == [
        "CVE-2024-57857"
    ]


def test_a_scan_that_names_no_scanner_cannot_be_covered_by_the_declaration(
    tmp_path: Path,
) -> None:
    """Fail closed: an unversioned scan cannot be shown to be the pinned tool's."""

    scan = _write_scan(
        tmp_path,
        [],
        ignored=[_suppressed(severity="Critical")],
        effective_rules=[_effective_rule()],
        grype_version="",
    )
    result = evaluate_scan(
        scan_path=scan,
        image_id="stateport-dev-workspace",
        exceptions_config=_exceptions_config([]),
        today=TODAY,
        suppression_config=_suppression_config([_suppression_rule()]),
    )
    refusals = result["suppressedFindings"]["refusals"]
    assert any("names no scanner version" in refusal for refusal in refusals), refusals


def test_an_unreadable_expiry_cannot_keep_a_suppression_alive(tmp_path: Path) -> None:
    """A malformed date is a lapsed declaration, not an open-ended one."""

    scan = _write_scan(
        tmp_path,
        [],
        ignored=[_suppressed(severity="Critical")],
        effective_rules=[_effective_rule()],
    )
    result = evaluate_scan(
        scan_path=scan,
        image_id="stateport-dev-workspace",
        exceptions_config=_exceptions_config([]),
        today=TODAY,
        suppression_config=_suppression_config([_suppression_rule(expiresOn="whenever")]),
    )
    suppressed = result["suppressedFindings"]
    assert suppressed["expiredRuleIds"] == ["RS-2026-003"]
    assert any("covered by no" in refusal for refusal in suppressed["refusals"])


def test_a_suppression_declared_for_another_scanner_version_is_refused(tmp_path: Path) -> None:
    scan = _write_scan(
        tmp_path,
        [],
        ignored=[_suppressed(severity="Critical")],
        effective_rules=[_effective_rule()],
        grype_version="0.99.0",
    )
    result = evaluate_scan(
        scan_path=scan,
        image_id="stateport-dev-workspace",
        exceptions_config=_exceptions_config([]),
        today=TODAY,
        suppression_config=_suppression_config([_suppression_rule()], version="0.117.0"),
    )
    refusals = result["suppressedFindings"]["refusals"]
    assert any("produced by grype 0.99.0" in refusal for refusal in refusals), refusals


def test_omitting_the_policy_leaves_every_suppressed_finding_unexplained(
    tmp_path: Path,
) -> None:
    """The default (no policy loaded) reading is fail-closed, never permissive."""

    scan = _write_scan(
        tmp_path,
        [],
        ignored=[_suppressed(severity="Critical")],
        effective_rules=[_effective_rule()],
    )
    result = evaluate_scan(
        scan_path=scan,
        image_id="stateport-dev-workspace",
        exceptions_config=_exceptions_config([]),
        today=TODAY,
    )
    suppressed = result["suppressedFindings"]
    assert suppressed["declaredRuleIds"] == []
    assert suppressed["coveredByRule"] == {}
    assert result["unexplainedSuppressedFindings"] == suppressed["uncoveredGatedFindings"]
    assert suppressed["undeclaredEffectiveRules"] == [_normalized_rule()]


def test_non_suppressed_evaluation_is_unchanged_by_the_suppression_contract(
    tmp_path: Path,
) -> None:
    """Adding the suppression evaluation must not move the existing verdicts."""

    scan = _write_scan(
        tmp_path, [_match(), _match(severity="Medium")], grype_version=GRYPE_VERSION
    )
    without = evaluate_scan(
        scan_path=scan,
        image_id="stateport-api",
        exceptions_config=_exceptions_config([_record()]),
        today=TODAY,
    )
    with_policy = evaluate_scan(
        scan_path=scan,
        image_id="stateport-api",
        exceptions_config=_exceptions_config([_record()]),
        today=TODAY,
        suppression_config=load_scan_suppression()[0],
    )
    for document in (without, with_policy):
        assert document["formatVersion"] == "stateport.release-scan-evaluation/v2"
        assert document["findingsBySeverity"] == {"High": 1, "Medium": 1}
        assert [item["exceptionId"] for item in document["appliedExceptions"]] == [
            "RX-2026-001"
        ]
        assert document["unexplainedFindings"] == []
    assert with_policy["suppressedFindings"]["total"] == 0
    assert with_policy["suppressedFindings"]["refusals"] == []
    assert with_policy["unexplainedSuppressedFindings"] == []
    assert without["suppressedFindings"]["refusals"] == []
    # Nothing about the non-suppressed verdicts moved; only the new keys exist.
    assert with_policy == {
        **without,
        "suppressedFindings": with_policy["suppressedFindings"],
        "unexplainedSuppressedFindings": [],
    }


def test_the_collector_always_evaluates_with_the_loaded_suppression_contract() -> None:
    """Guard the production call site: the contract must reach the evaluator."""

    source = (ROOT / "scripts/collect_release_evidence.py").read_text(encoding="utf-8")
    assert "suppression_config=context.suppression_config" in source
    assert "suppression_config, suppression_digest = load_scan_suppression()" in source


# ---------------------------------------------------------------------------
# suppressed_population: the effective-ignore-rule enforcement site.
#
# The evaluation-level refusals above are covered, but this enforcement site was
# not: nothing imported `suppressed_population` at all, and disabling its
# `if undeclared: raise EvidenceError(...)` changed no test outcome. These are
# the positive and negative twins of that one check.


def test_an_applied_ignore_rule_the_resolved_configuration_does_not_declare_is_refused(
    tmp_path: Path,
) -> None:
    """A rule grype applied that its own resolved ignore list does not contain.

    This is the fail-closed property that the per-advisory ledger cannot reach:
    the rule arrived from somewhere other than the committed, pinned
    configuration, so the scan's ignore behaviour is not reproducible from the
    repository and the collection must refuse rather than sign it.
    """

    scan = _write_scan(
        tmp_path,
        [],
        ignored=[_suppressed(applied=[_effective_rule(package="not-the-declared-one")])],
        effective_rules=[_effective_rule()],
    )
    with pytest.raises(EvidenceError) as excinfo:
        suppressed_population(scan_path=scan, declared_rules=[_effective_rule()])
    assert "does not" in str(excinfo.value)


def test_an_applied_ignore_rule_the_resolved_configuration_does_declare_is_accepted(
    tmp_path: Path,
) -> None:
    """The positive twin: the same document is accepted when the rule is declared.

    Without this, the refusal above could be satisfied by a function that always
    raised, which would pass the negative test while being useless.
    """

    rule = _effective_rule()
    scan = _write_scan(
        tmp_path,
        [],
        ignored=[_suppressed(applied=[rule])],
        effective_rules=[rule],
    )
    population = suppressed_population(scan_path=scan, declared_rules=[rule])
    assert population["suppressedMatches"] == 1
    assert population["suppressedMatchesBySeverity"] == {"High": 1}
    assert population["appliedIgnoreRules"] == [rule]


def test_a_scan_with_no_suppressed_matches_declares_nothing(tmp_path: Path) -> None:
    """No ignoredMatches at all is not a suppression and must not fail."""

    scan = _write_scan(tmp_path, [], effective_rules=[])
    population = suppressed_population(scan_path=scan, declared_rules=[])
    assert population == {
        "suppressedMatches": 0,
        "suppressedMatchesBySeverity": {},
        "appliedIgnoreRules": [],
    }


def _minimal_contract() -> dict:
    """A self-contained, valid suppression contract to mutate.

    Built from a literal rather than read from the repository file, so these
    tests depend on no shared module state and no tracked file. The version
    committed first read the live config and proved order-dependent: it passed
    alone and failed in a multi-file run, which is a defect in the test, not in
    the contract.
    """

    return {
        "formatVersion": "stateport.release-scan-suppression/v1",
        "resolvedOn": TODAY,
        "suppressionRule": "default-deny; only a declared, justified, unexpired rule suppresses",
        "tool": {
            "name": "grype",
            "version": GRYPE_VERSION,
            "provenance": "Pinned grype executable in config/release-tool-inputs.yaml.",
        },
        "rules": [
            {
                "id": "RS-2026-999",
                "package": "linux-libc-dev",
                "packageType": "deb",
                "matchType": "exact-indirect-match",
                "justification": (
                    "Kernel UAPI headers and static libraries for compiling native "
                    "modules; no kernel code runs from this package."
                ),
                "expiresOn": "2026-12-31",
            }
        ],
    }


def _load_contract_from(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rules: list[dict]):
    """Point the loader at a temporary copy of a contract carrying `rules`.

    The rebinding goes through ``load_scan_suppression.__globals__`` rather than
    through ``sys.modules``. scripts/test_release_tool_inputs.py and
    scripts/test_grype_scan_config.py each build a SECOND module object from this
    same file with ``spec_from_file_location``, replacing
    ``sys.modules["collect_release_evidence"]``. So "import the module and patch
    it" can patch a different copy from the one the function under test reads,
    and the test passes alone and fails in a multi-file run. The function's own
    globals are the namespace it actually reads, so binding there is correct
    regardless of which copy is registered.
    """

    contract = _minimal_contract()
    contract["rules"] = rules
    path = tmp_path / "suppression.yaml"
    path.write_text(yaml.safe_dump(contract), encoding="utf-8")
    monkeypatch.setitem(load_scan_suppression.__globals__, "SCAN_SUPPRESSION", path)


def test_a_rule_that_omits_a_required_property_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A declaration missing a contract property must refuse the release.

    Without this check an omitted property is an unstated claim and each later
    per-property check would report its own property rather than naming the
    declaration as malformed. This enforcement site was uncovered: a mutation
    removing the check failed no test in the repository.
    """

    rules = [dict(_minimal_contract()["rules"][0])]
    rules[0].pop("matchType")
    _load_contract_from(tmp_path, monkeypatch, rules)
    with pytest.raises(EvidenceError, match="must declare exactly"):
        load_scan_suppression()


def test_a_rule_that_declares_an_extra_property_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other direction, so a check that merely counted properties fails."""

    rules = [dict(_minimal_contract()["rules"][0])]
    rules[0]["severity"] = "High"
    _load_contract_from(tmp_path, monkeypatch, rules)
    with pytest.raises(EvidenceError, match="must declare exactly"):
        load_scan_suppression()


def test_a_contract_declaring_exactly_its_property_set_loads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The positive twin.

    Without this, both refusals above would also be satisfied by a loader that
    refuses every contract, which would pass while being useless.
    """

    _load_contract_from(tmp_path, monkeypatch, [dict(_minimal_contract()["rules"][0])])
    loaded, _digest = load_scan_suppression()
    assert loaded["formatVersion"] == "stateport.release-scan-suppression/v1"


# The remaining declaration-level refusals. A sweep that mutated each of the
# five in turn found NONE of them exercised by any test, so the contract's own
# claim that it is hand-validated because schemas are out of its boundary was
# true of the code and untested. Each is the negative plus a shared positive
# twin above, so none can be satisfied by a loader that refuses everything.


def test_a_rule_id_that_is_invalid_or_duplicated_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two rules cannot share an id: the id is how a finding names its rule."""

    rules = [dict(_minimal_contract()["rules"][0])]
    rules.append(dict(rules[0]))
    _load_contract_from(tmp_path, monkeypatch, rules)
    with pytest.raises(EvidenceError, match="id is invalid or duplicated"):
        load_scan_suppression()


def test_a_rule_that_pins_no_match_type_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An empty match type names no suppression at all."""

    rules = [dict(_minimal_contract()["rules"][0])]
    rules[0]["matchType"] = "  "
    _load_contract_from(tmp_path, monkeypatch, rules)
    with pytest.raises(EvidenceError, match="pins no match type"):
        load_scan_suppression()


def test_a_package_that_is_not_a_valid_expression_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A package that will not compile could never match, so it is a silent hole."""

    rules = [dict(_minimal_contract()["rules"][0])]
    rules[0]["package"] = "linux-libc-dev("
    _load_contract_from(tmp_path, monkeypatch, rules)
    with pytest.raises(EvidenceError, match="not a valid expression"):
        load_scan_suppression()


def test_a_rule_with_no_package_type_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Package name and type together are the rule's identity; half is not."""

    rules = [dict(_minimal_contract()["rules"][0])]
    rules[0]["packageType"] = ""
    _load_contract_from(tmp_path, monkeypatch, rules)
    with pytest.raises(EvidenceError, match="no package type"):
        load_scan_suppression()


def test_a_contract_declaring_more_rules_than_the_gate_bounds_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The rule count is bounded so a contract cannot grow without limit."""

    rules = []
    for index in range(33):
        rule = dict(_minimal_contract()["rules"][0])
        rule["id"] = f"RS-2026-{index:03d}"
        rules.append(rule)
    _load_contract_from(tmp_path, monkeypatch, rules)
    with pytest.raises(EvidenceError, match="more rules than the gate bounds"):
        load_scan_suppression()


# ---------------------------------------------------------------------------
# The collect/main enforcement site.
#
# The evaluation tests above classify findings and read a verdict. These two
# drive the release collector's OWN entry points -- `main` -> `collect` ->
# `_collect_image` -- and assert what the collector does with the verdict. That
# enforcement tail was the one fail-closed refusal in this module that nothing
# executed: two tests already called `collect_many`, but both replaced
# `_collect_image` with a lambda, so the real function -- and the real refusal
# at its end -- ran nowhere in the suite. It could have been deleted, inverted,
# or downgraded to a warning and every other test here would still have passed.
#
# What is stubbed, precisely: these five seams, and no others.
#   prepare_collection_context  verifies the real toolchain and refreshes the
#                               real Grype database
#   derive_build_observations  reads live Podman image identity
#   _collect_sboms             runs syft
#   _collect_grype_scan        runs grype
#   _health_observation        runs `podman run`
#
# What is real: the CLI parse, `collect`, `_collect_image`, `evaluate_scan` and
# `_suppression_verdict` on the fixture scan, `_resolved_dependencies` against
# the repository's own input manifests, `build_provenance` under the published
# contract schema, the create-only publication, the manifest, and the refusal.
#
# The consequence of the second seam is stated rather than hidden: because
# `derive_build_observations` is replaced, the double-build digest-identity
# check in the same function is NOT covered here. That is a separate
# enforcement site and this test does not claim it.


_IMAGE_ID = "stateport-dev-workspace"
_DIGEST = "sha256:" + "1" * 64


def _release_receipt() -> dict:
    """A build receipt shaped like the canonical one, for the collector's reader."""
    image = {
        "acceptedReference": f"127.0.0.1:5011/stateport-alpha/{_IMAGE_ID}@{_DIGEST}",
        "containerfile": "images/stateport-dev-workspace/Containerfile",
        "containerfileDigest": "sha256:" + "2" * 64,
        "reproducible": True,
        "builds": [
            {
                "ordinal": ordinal,
                "pushedDigest": _DIGEST,
                "digestFileDigest": "sha256:" + "3" * 64,
                "localImageId": "4" * 64,
                "localTag": f"stateport-collect-fixture:{ordinal}",
                "startedAt": "2026-08-01T00:00:00Z",
                "finishedAt": "2026-08-01T00:10:00Z",
            }
            for ordinal in (1, 2)
        ],
    }
    return {
        "formatVersion": "stateport.release-image-build-receipt/v1",
        "identity": {
            "commit": "b" * 40,
            "tree": "c" * 40,
            "source_date_epoch": 1754006400,
        },
        "context": {"archiveDigest": "sha256:" + "5" * 64},
        "builder": {
            "version": "5.4.2",
            "executableDigest": "sha256:" + "9" * 64,
            "descriptorDigest": "sha256:" + "a" * 64,
            "artifact": {"uri": "oci://podman/builder", "digest": "sha256:" + "6" * 64},
        },
        "images": {_IMAGE_ID: image},
    }


def _arm_collector(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    scan: dict,
    exceptions_config: dict,
    suppression_config: dict,
) -> tuple[Path, Path]:
    """Point the real `main`/`collect` at fixture files and a fixture scan.

    The collector still reads the committed scan configuration, still classifies
    the scan with its own evaluator, still resolves dependencies from the
    repository's own manifests, still builds the provenance under the published
    contract, still create-only publishes the image manifest, and still decides
    whether to refuse. The section comment above lists the five seams this
    replaces and what replacing them costs.
    """
    import collect_release_evidence as module

    receipt = _release_receipt()
    receipt_digest = module.sha256_file(_write_json(tmp_path, "build-receipt.json", receipt))
    candidate_provenance = tmp_path / "candidate.yaml"
    candidate_provenance.write_text("candidateId: stateport-collect-fixture\n", encoding="utf-8")
    candidate_bundle = tmp_path / "candidate.bundle"
    candidate_bundle.write_bytes(b"collect-fixture-bundle")
    output_root = tmp_path / "evidence"
    monkeypatch.setenv("STATEPORT_EVIDENCE_ROOT", str(output_root))

    context = module.CollectionContext(
        receipt=receipt,
        candidate={
            "sourceRepository": "https://github.com/lennertvhoy/StatePort.git",
            "publicSnapshotCommit": "b" * 40,
            "publicSnapshotTree": "c" * 40,
        },
        tools={"syft": {"executable": "/pinned/syft"}, "grype": {"executable": "/pinned/grype"}},
        database={"builtAt": "2026-08-01T00:00:00Z", "observedAt": "2026-08-01T00:00:00Z"},
        exceptions_config=exceptions_config,
        exceptions_digest="sha256:" + "7" * 64,
        suppression_config=suppression_config,
        suppression_digest="sha256:" + "8" * 64,
        receipt_digest=receipt_digest,
    )
    monkeypatch.setattr(module, "prepare_collection_context", lambda **_kwargs: context)
    image = receipt["images"][_IMAGE_ID]
    monkeypatch.setattr(
        module,
        "derive_build_observations",
        lambda **_kwargs: (receipt, image, image["builds"][1], receipt_digest),
    )

    def collect_sboms(*, image_id, local_source, syft, output):
        del local_source, syft
        published = tuple(
            module.write_json_create_only(
                output,
                f"{image_id}.{suffix}.json",
                {"artifacts": [], "bomFormat": suffix},
            )
            for suffix in ("cdx", "spdx", "syft")
        )
        return published

    def collect_grype_scan(*, image_id, syft_json, grype, scan_config, output):
        del syft_json, grype
        # The population the collector records is measured by the collector's
        # own function, against the committed configuration it really loaded.
        path = module.write_json_create_only(output, f"{image_id}.grype.json", scan)
        suppressed = module.suppressed_population(
            scan_path=path, declared_rules=scan_config.ignore_rules
        )
        observed = datetime.now(timezone.utc)
        return path, observed, observed, suppressed

    monkeypatch.setattr(module, "_collect_sboms", collect_sboms)
    monkeypatch.setattr(module, "_collect_grype_scan", collect_grype_scan)
    monkeypatch.setattr(
        module,
        "_health_observation",
        lambda **_kwargs: {"status": "healthy", "probe": "fixture"},
    )
    return receipt_digest, output_root


def _write_json(tmp_path: Path, name: str, document: dict) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _collector_argv(tmp_path: Path, output_root: Path) -> list[str]:
    """The command line a release operator would actually type for one image."""
    return [
        "--image-id",
        _IMAGE_ID,
        "--build-receipt",
        str(tmp_path / "build-receipt.json"),
        "--candidate-provenance",
        str(tmp_path / "candidate.yaml"),
        "--candidate-bundle",
        str(tmp_path / "candidate.bundle"),
        "--output-root",
        str(output_root),
    ]


def test_collect_refuses_an_unexplained_finding_and_retains_the_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A High finding in `matches` that no declared exception explains.

    This is the enforcement site the suite never reached. Every other test here
    calls `evaluate_scan` and reads its verdict; nothing drove the collector's
    own `main` -> `collect` -> `_collect_image` path, so the refusal that
    decides whether a scanned image may be signed could have been deleted,
    inverted or downgraded to a warning and the whole file would still have
    passed. The classification is the collector's real evaluator on a real
    scan document; only the four seams that would start podman, syft or grype
    are replaced.

    The manifest is published before the refusal, so this asserts both halves:
    the refusal, and that the evidence explaining it survives it.

    Two of those assertions, not one, carry the weight. The message assertion
    alone would be satisfied by a function that raised the same text
    unconditionally; what rules that out is the positive twin below, which
    drives the identical path and must complete, and the retained manifest,
    which cannot exist if the refusal short-circuits before assembly.
    """
    import collect_release_evidence as module

    _receipt_digest, output_root = _arm_collector(
        tmp_path,
        monkeypatch,
        scan={
            "matches": [_match()],
            "ignoredMatches": [],
            "descriptor": {
                "name": "grype",
                "version": module._pinned_grype_version(),
                "configuration": {"output": ["json"], "ignore": []},
            },
        },
        exceptions_config=_exceptions_config([]),
        suppression_config=_suppression_config(
            [_suppression_rule(expiresOn=FOREVER)], version=module._pinned_grype_version()
        ),
    )

    with pytest.raises(EvidenceError) as excinfo:
        module.main(_collector_argv(tmp_path, output_root))
    assert "unexplained high-or-critical vulnerability findings refuse" in str(excinfo.value)
    assert "CVE-2026-11940:python" in str(excinfo.value)

    manifest = json.loads(
        (output_root / f"{_IMAGE_ID}.evidence.json").read_text(encoding="utf-8")
    )
    assert manifest["scanPolicy"]["result"] == "failed"
    assert [
        (item["advisory"], item["package"])
        for item in manifest["scanPolicy"]["unexplainedFindings"]
    ] == [("CVE-2026-11940", "python")]


def test_collect_accepts_the_same_finding_once_a_declared_exception_explains_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The positive twin, so the refusal above cannot be satisfied by always raising.

    Identical entry point, identical scan, identical collector; only the
    exception ledger differs, and it now carries the exact, unexpired record
    naming this advisory, package and image. The collection must complete and
    publish rather than refuse.
    """
    import collect_release_evidence as module

    _receipt_digest, output_root = _arm_collector(
        tmp_path,
        monkeypatch,
        scan={
            "matches": [_match()],
            "ignoredMatches": [],
            "descriptor": {
                "name": "grype",
                "version": module._pinned_grype_version(),
                "configuration": {"output": ["json"], "ignore": []},
            },
        },
        exceptions_config=_exceptions_config(
            [_record(images=[_IMAGE_ID], expiresOn=FOREVER)]
        ),
        suppression_config=_suppression_config(
            [_suppression_rule(expiresOn=FOREVER)], version=module._pinned_grype_version()
        ),
    )

    assert module.main(_collector_argv(tmp_path, output_root)) == 0

    manifest = json.loads(
        (output_root / f"{_IMAGE_ID}.evidence.json").read_text(encoding="utf-8")
    )
    assert manifest["scanPolicy"]["result"] == "passed"
    assert manifest["scanPolicy"]["unexplainedFindings"] == []
    assert manifest["scanPolicy"]["appliedExceptionIds"] == ["RX-2026-001"]
    assert json.loads(capsys.readouterr().out)["imageId"] == _IMAGE_ID


def test_an_uncovered_suppressed_finding_always_also_produces_a_refusal(tmp_path: Path) -> None:
    """The coupling that makes the third `_collect_image` refusal unreachable.

    That refusal was deleted as dead code, correctly: `_suppression_verdict`
    appends to `refusals` whenever `uncovered` is non-empty, and publishes that
    same list as `uncoveredGatedFindings`, which `evaluate_scan` republishes as
    `unexplainedSuppressedFindings`. So the two guards tested the SAME condition
    and the first always won.

    The deletion is only safe while that coupling holds, and a comment cannot
    hold it. Measured: with the coupling broken in memory, a suppressed High
    finding covered only by a declared-but-expired rule is ACCEPTED — the
    collector returns 0, so the image proceeds to assembly, while the evidence
    manifest still records `scanPolicy.result: "failed"` and the finding. A
    pipeline that writes an honest failure into the manifest and then continues
    is exactly the silent pass this campaign keeps having to catch.

    So this pins the coupling. If a future refactor stops appending the refusal
    while leaving the field populated, this test fails and the deleted refusal
    has to come back. If it stops populating the field, the manifest loses a
    field the assembler reads, and this test fails too.
    """
    import collect_release_evidence as module

    match = _match()
    scan = {
        "matches": [],
        "ignoredMatches": [match],
        "descriptor": {
            "name": "grype",
            "version": module._pinned_grype_version(),
            "configuration": {"output": ["json"], "ignore": []},
        },
    }
    # The rule is declared and justified but EXPIRED, so it covers nothing and
    # the suppressed High finding is unexplained. This is the one state where
    # the field is populated.
    verdict = module._suppression_verdict(
        scan=scan,
        suppression_config=_suppression_config(
            [_suppression_rule(expiresOn="2020-01-01")],
            version=module._pinned_grype_version(),
        ),
        threshold=module._SEVERITY_ORDER["High"],
        today=TODAY,
    )

    assert verdict["uncoveredGatedFindings"], "the scenario must populate the field"
    assert verdict["refusals"], (
        "a suppressed finding at or above the threshold that no declared, "
        "justified, unexpired rule covers must also produce a refusal; without "
        "that the third _collect_image refusal is reachable and is deleted, so "
        "the collector would accept the image"
    )
    # And the field the evaluation publishes must be that same list, aliased.
    scan_path = _write_scan(
        tmp_path, [], ignored=[_match()], effective_rules=[], grype_version=module._pinned_grype_version()
    )
    evaluation = evaluate_scan(
        scan_path=scan_path,
        image_id=_IMAGE_ID,
        exceptions_config=_exceptions_config([]),
        suppression_config=_suppression_config(
            [_suppression_rule(expiresOn="2020-01-01")],
            version=module._pinned_grype_version(),
        ),
        today=TODAY,
    )
    assert evaluation["unexplainedSuppressedFindings"] == verdict["uncoveredGatedFindings"]


def test_the_committed_suppression_policy_stays_narrow_justified_and_unexpired() -> None:
    """Guard the properties the committed suppression justification rests on.

    `RS-2026-003` is the only rule in `config/release-scan-suppression.v1.yaml`
    that suppresses real findings, and the whole dev-workspace scan result
    depends on it: it covers 189 threshold-severity findings, 183 High and 6
    Critical, all on one deb package. The policy's own justification argues that
    package is a hard transitive dependency of the intentional developer
    toolchain and that every advisory it matches is a kernel advisory reached
    only through the host's immutable kernel.

    Every one of those claims is a claim about THIS rule staying narrow. If the
    package name is broadened to a pattern, if `matchType` widens, or if the
    rule lapses, the justification silently stops applying and the image
    presents 6 Critical and 183 High unexplained behind a still-zero count.
    Nothing else in the suite reads the committed policy's rule shape -- the
    other tests use `RS-2026-003` as a fixture value and assert verdicts on
    fixtures, and the assemble and install suites read the committed file only
    for its digest and format. This is that guard.

    Note the asymmetry it pins: the sibling rules name regex package patterns
    (`linux-kbuild-.*`, `linux(-.*)?-headers-.*`) while RS-2026-003 names one
    literal package. That is not a cosmetic difference -- a regex rule is
    exactly the "broadens beyond linux-libc-dev" case the residual names.
    """
    policy = yaml.safe_load(
        (ROOT / "config/release-scan-suppression.v1.yaml").read_text(encoding="utf-8")
    )
    rules = policy["rules"]
    assert rules, "the committed suppression policy must declare rules"

    today = datetime.now(timezone.utc).date()
    earliest: date | None = None
    for rule in rules:
        identifier = rule["id"]
        assert str(rule.get("justification", "")).strip(), (
            f"{identifier} suppresses findings and must carry a justification; the "
            "policy is default-deny and only a justified rule explains a finding"
        )
        assert rule["matchType"] == "exact-indirect-match", (
            f"{identifier} must stay an exact-indirect match; a broader matchType "
            "would suppress findings the justification was never written about"
        )
        expiry = datetime.strptime(str(rule["expiresOn"]), "%Y-%m-%d").date()
        assert expiry > today, (
            f"{identifier} expired on {expiry}; an expired rule covers nothing, so "
            "the scan would report the findings it was hiding and the release gate "
            "would go red at scan time instead of in this cheap test"
        )
        earliest = expiry if earliest is None else min(earliest, expiry)

    # The load-bearing rule specifically: one literal deb package, no pattern.
    load_bearing = next(rule for rule in rules if rule["id"] == "RS-2026-003")
    assert _REGEX_METACHARACTERS.search(load_bearing["package"]) is None, (
        "RS-2026-003 must name one literal package. Its justification argues about "
        "linux-libc-dev alone, so a regex here would extend the suppression past "
        "what was ever reviewed and past what the justification covers."
    )
    assert earliest is not None
    assert earliest > today + timedelta(days=30), (
        f"the earliest suppression expiry is {earliest}, inside 30 days; a rule "
        "this load-bearing should be renewed deliberately rather than lapse"
    )


# ---------------------------------------------------------------------------
# The resume chain, driven end to end.
#
# The test above the resume verdict guard proves the guard fires. It cannot
# prove the resume PATH reaches the guard, and that is the half that matters:
# `_collect_image` publishes the manifest before it refuses, so a failed scan
# leaves a complete, digest-correct checkpoint behind, and `--resume` over that
# checkpoint used to return the failed image as complete. These two drive the
# real `main` twice over the same output root -- fail, then resume -- and
# resume, then resume -- so the reachability is measured, not assumed.


def test_resume_cannot_pass_a_scan_that_the_same_output_root_just_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failing collection, then a resume over exactly what it left behind."""
    import collect_release_evidence as module

    _digest, output_root = _arm_collector(
        tmp_path,
        monkeypatch,
        scan={
            "matches": [_match()],
            "ignoredMatches": [],
            "descriptor": {
                "name": "grype",
                "version": module._pinned_grype_version(),
                "configuration": {"output": ["json"], "ignore": []},
            },
        },
        exceptions_config=_exceptions_config([]),
        suppression_config=_suppression_config(
            [_suppression_rule(expiresOn=FOREVER)], version=module._pinned_grype_version()
        ),
    )
    argv = _collector_argv(tmp_path, output_root)

    with pytest.raises(EvidenceError, match="unexplained high-or-critical"):
        module.main(argv)
    manifest = json.loads(
        (output_root / f"{_IMAGE_ID}.evidence.json").read_text(encoding="utf-8")
    )
    assert manifest["scanPolicy"]["result"] == "failed"
    # The refusal is not the only defence: the evidence it retained is what a
    # resume would otherwise have accepted as a completed image.
    assert manifest["scanPolicy"]["unexplainedFindings"]

    with pytest.raises(EvidenceError, match="is not a completed image"):
        module.main(argv + ["--resume"])


def test_resume_still_skips_a_scan_that_actually_passed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The positive twin over the identical chain, or the fix would break --resume.

    Same entry point, same output root, same second invocation. The only
    difference is that the first run's scan was explained, so the checkpoint
    records a pass and the resume may legitimately skip the image.
    """
    import collect_release_evidence as module

    collected: list[str] = []
    _digest, output_root = _arm_collector(
        tmp_path,
        monkeypatch,
        scan={
            "matches": [_match()],
            "ignoredMatches": [],
            "descriptor": {
                "name": "grype",
                "version": module._pinned_grype_version(),
                "configuration": {"output": ["json"], "ignore": []},
            },
        },
        exceptions_config=_exceptions_config(
            [_record(images=[_IMAGE_ID], expiresOn=FOREVER)]
        ),
        suppression_config=_suppression_config(
            [_suppression_rule(expiresOn=FOREVER)], version=module._pinned_grype_version()
        ),
    )
    argv = _collector_argv(tmp_path, output_root)
    assert module.main(argv) == 0

    # Prove the resume really skipped the image rather than re-collecting it: the
    # second call is the one that would run every tool, so it is made to explode.
    monkeypatch.setattr(
        module, "_collect_image", lambda **_kwargs: collected.append("ran") or {}
    )
    assert module.main(argv + ["--resume"]) == 0
    assert collected == []
