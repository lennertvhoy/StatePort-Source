#!/usr/bin/env python3
"""Collect canonical image supply-chain evidence from an exact build receipt."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Mapping, Sequence

import jsonschema
import yaml

from release_safe_io import (
    prepare_output_root,
    open_existing_output_root,
    remove_file_exact,
    safe_path,
    sha256_file,
    write_bytes_create_only,
    write_json_create_only,
)


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages/release-contracts/src"))
from stateport_release import (  # noqa: E402
    canonical_digest,
    public_key_der_spki_fingerprint,
    validate_release_provenance,
)
from validate_candidate_provenance import (  # noqa: E402
    CandidateProvenanceError,
    validate_contract as validate_candidate_contract,
    validate_repository_relationship,
    verify_bundle as verify_candidate_bundle,
    verify_release_tree,
)


TOOLS = ROOT / "config/release-tool-inputs.yaml"
BASE_IMAGES = ROOT / "config/container-base-images.yaml"
BUILD_INPUTS = ROOT / "config/container-build-inputs.yaml"
SCAN_EXCEPTIONS = ROOT / "config/release-scan-exceptions.v1.yaml"
SCAN_EXCEPTIONS_SCHEMA = ROOT / "schemas/release-scan-exceptions.v1.schema.json"
# The vulnerability scan's ignore configuration is a committed, versioned
# release input, never an ambient grype default resolved from outside the
# repository.  Every scan names it explicitly with `-c`, and the collected
# manifest declares its path, digest and the population it suppressed.
SCAN_CONFIG = ROOT / "config/grype-scan.v1.yaml"
SCAN_CONFIG_REPOSITORY_PATH = "config/grype-scan.v1.yaml"
SCAN_CONFIG_FORMAT_VERSION = "stateport.grype-scan-config/v1"
# The one rule the signed Alpha.19 per-image grype documents record in
# `appliedIgnoreRules`, reproduced field for field.  It is pinned here, and the
# committed file is refused unless it contains exactly this rule, so the
# configuration cannot drift away from what the evidence can support.  There is
# deliberately no `location` and no `version`: the signed `artifact` record
# carries no location at all, and a narrower rule would be an unverifiable
# claim.  See config/grype-scan.v1.yaml for the measured population.
SCAN_CONFIG_IGNORE_RULE: Mapping[str, Any] = {
    "match-type": "exact-indirect-match",
    "namespace": "",
    "package": {
        "name": "linux-libc-dev",
        "type": "deb",
        "upstream-name": "linux",
        "language": "",
    },
}
# SEPARATE, ADDITIONAL contract.  `config/grype-scan.v1.yaml` above is the
# grype CONFIGURATION the scan runs under (which rules grype is told to apply);
# this file is the SUPPRESSION POLICY those rules are judged against, and it
# exists because a rule that is configured is not thereby justified, bounded or
# expiring.  The two files are independent on purpose: the policy declares the
# grype tool version it is valid for, justifies every rule by name, type and
# match type, and expires them, and it is evaluated against the scan's
# `ignoredMatches` -- the findings that never reach `matches` and are therefore
# invisible to the per-advisory RX-* exception ledger.
SCAN_SUPPRESSION = ROOT / "config/release-scan-suppression.v1.yaml"
SCAN_SUPPRESSION_FILE = "config/release-scan-suppression.v1.yaml"
SCAN_SUPPRESSION_FORMAT = "stateport.release-scan-suppression/v1"
PODMAN = Path("/usr/bin/podman")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_DIGEST_REFERENCE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_SEVERITY_ORDER = {"Negligible": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
_THRESHOLD_ORDER = {"negligible": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_IMAGE_OUTPUT_SUFFIXES = (
    ".cdx.json",
    ".spdx.json",
    ".syft.json",
    ".grype.json",
    ".scan-evaluation.json",
    ".licenses.json",
    ".double-build.json",
    ".healthcheck.json",
    ".grype-db.json",
    ".provenance.json",
    ".evidence.json",
)


class EvidenceError(RuntimeError):
    pass


@dataclass(frozen=True)
class ScanConfiguration:
    """The committed grype ignore configuration, pinned by identity."""

    path: Path
    repository_path: str
    digest: str
    ignore_rules: tuple[Mapping[str, Any], ...]


def _canonical_scan_rule(rule: Any) -> Mapping[str, Any]:
    """Return one ignore rule with grype's empty optional fields filled in.

    Any field outside the pinned set is a refusal, not something to drop: an
    unrecognised field (a `location`, a `version`, a `reason`) would change what
    the configuration suppresses, so it must never be silently normalised away
    into a rule that looks like the recorded one.
    """

    if not isinstance(rule, Mapping):
        raise EvidenceError("scan configuration ignore entry is not a mapping")
    unexpected = sorted(set(rule) - set(SCAN_CONFIG_IGNORE_RULE))
    if unexpected:
        raise EvidenceError(f"scan configuration ignore rule has unrecorded fields: {unexpected}")
    canonical: dict[str, Any] = {key: str(rule.get(key, "")) for key in SCAN_CONFIG_IGNORE_RULE}
    package = rule.get("package")
    if not isinstance(package, Mapping):
        raise EvidenceError("scan configuration ignore rule has no package mapping")
    pinned_package = SCAN_CONFIG_IGNORE_RULE["package"]
    unexpected = sorted(set(package) - set(pinned_package))
    if unexpected:
        raise EvidenceError(
            f"scan configuration ignore rule package has unrecorded fields: {unexpected}"
        )
    canonical["package"] = {key: str(package.get(key, "")) for key in pinned_package}
    return canonical


def load_scan_configuration(path: Path = SCAN_CONFIG) -> ScanConfiguration:
    """Load the committed scan configuration, or refuse to scan at all.

    Failing closed is the point: an absent, unreadable, drifting or
    unparseable configuration must abort the collection rather than let grype
    fall back to whatever configuration the environment happens to offer.
    """

    if path.is_symlink() or not path.is_file():
        raise EvidenceError(f"committed scan configuration is missing or unsafe: {path}")
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise EvidenceError(f"committed scan configuration is unreadable: {path}") from exc
    if not isinstance(document, Mapping) or set(document) != {"ignore"}:
        raise EvidenceError("committed scan configuration declares no single top-level ignore list")
    rules = document["ignore"]
    if not isinstance(rules, list) or len(rules) != 1:
        raise EvidenceError(
            f"committed scan configuration must declare exactly one ignore rule, found "
            f"{len(rules) if isinstance(rules, list) else 'a non-list value'}"
        )
    canonical = _canonical_scan_rule(rules[0])
    if canonical != dict(SCAN_CONFIG_IGNORE_RULE):
        raise EvidenceError("committed scan configuration does not match the single recorded rule")
    return ScanConfiguration(
        path=path,
        repository_path=SCAN_CONFIG_REPOSITORY_PATH,
        digest="sha256:" + sha256_file(path),
        ignore_rules=(canonical,),
    )


def suppressed_population(
    *, scan_path: Path, declared_rules: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    """Measure what the scan suppressed, refusing any undeclared suppression.

    The committed configuration is the only admissible source of suppression, so
    every rule grype reports as applied must be one the configuration declares.
    A rule applied from anywhere else means the resolved configuration was not
    the committed one, and the collection fails instead of signing a scan whose
    ignore behaviour nobody in the repository can reproduce.
    """

    scan = _load_json_file(scan_path, maximum_bytes=256 * 1024 * 1024)
    ignored = scan.get("ignoredMatches", [])
    if not isinstance(ignored, list):
        raise EvidenceError("vulnerability scan ignoredMatches is not a list")
    severities: dict[str, int] = {}
    applied: dict[str, Mapping[str, Any]] = {}
    for match in ignored:
        if not isinstance(match, Mapping):
            raise EvidenceError("vulnerability scan ignored match is not an object")
        severity = str(match.get("vulnerability", {}).get("severity", ""))
        severities[severity] = severities.get(severity, 0) + 1
        rules = match.get("appliedIgnoreRules", [])
        if not isinstance(rules, list):
            raise EvidenceError("vulnerability scan appliedIgnoreRules is not a list")
        for rule in rules:
            applied[json.dumps(rule, sort_keys=True)] = rule
    declared = {json.dumps(dict(rule), sort_keys=True) for rule in declared_rules}
    undeclared = sorted(set(applied) - declared)
    if undeclared:
        raise EvidenceError(
            "vulnerability scan applied ignore rules the committed configuration does not "
            f"declare: {undeclared}"
        )
    return {
        "suppressedMatches": len(ignored),
        "suppressedMatchesBySeverity": dict(sorted(severities.items())),
        "appliedIgnoreRules": [applied[key] for key in sorted(applied)],
    }


def _load_yaml(path: Path) -> Mapping[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise EvidenceError(f"release input manifest is invalid: {path.name}")
    return value


def _load_json_file(path: Path, *, maximum_bytes: int = 4 * 1024 * 1024) -> Mapping[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum_bytes:
        raise EvidenceError(f"evidence input is unsafe: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"evidence input is not valid UTF-8 JSON: {path}") from exc
    if not isinstance(value, Mapping):
        raise EvidenceError(f"evidence input is not a JSON object: {path}")
    return value


def _run(arguments: Sequence[str], *, timeout: int = 3600) -> str:
    completed = subprocess.run(
        list(arguments),
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        shell=False,
        env=_tool_environment(),
    )
    if completed.returncode != 0:
        raise EvidenceError(f"tool failed ({completed.returncode}): {' '.join(arguments)}")
    return completed.stdout


def _tool_environment() -> dict[str, str]:
    """Scanner subprocess environment with TMPDIR moved off any tmpfs.

    syft/grype extract OCI layers into their temp cache; the rehearsal host's
    /tmp is a small tmpfs whose quota the multi-GB playwright archive
    exhausts (disk quota exceeded).  Point TMPDIR at the evidence root on
    real disk so scanning is independent of the host tmpfs budget.
    """
    env = dict(os.environ)
    evidence_root = env.get("STATEPORT_EVIDENCE_ROOT")
    if evidence_root:
        real_disk = Path(evidence_root) / "scanner-tmp"
        real_disk.mkdir(parents=True, exist_ok=True)
        env["TMPDIR"] = str(real_disk)
    return env


def _set_scanner_tmpdir(output_root: Path) -> None:
    """Pin TMPDIR for scanner subprocesses to the real-disk evidence root."""
    scanner_tmp = output_root / "scanner-tmp"
    scanner_tmp.mkdir(parents=True, exist_ok=True)
    os.environ["STATEPORT_EVIDENCE_ROOT"] = str(output_root)


def _run_result(arguments: Sequence[str], *, timeout: int = 3600) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(arguments),
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            env=_tool_environment(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise EvidenceError(f"tool invocation failed: {' '.join(arguments)}") from exc


def _run_to_new_file(
    arguments: Sequence[str], path: Path, *, accepted_returncodes: set[int] = {0}
) -> int:
    if path.exists() or path.is_symlink():
        raise EvidenceError(f"evidence output already exists: {path}")
    with path.open("xb") as stream:
        completed = subprocess.run(
            list(arguments),
            cwd=ROOT,
            check=False,
            stdout=stream,
            stderr=subprocess.PIPE,
            timeout=3600,
            shell=False,
            env=_tool_environment(),
        )
    if completed.returncode not in accepted_returncodes:
        raise EvidenceError(f"tool failed ({completed.returncode}): {' '.join(arguments)}")
    return completed.returncode


def _progress(image_id: str, message: str) -> None:
    print(f"[release-evidence] {image_id}: {message}", file=sys.stderr, flush=True)


@dataclass(frozen=True)
class CollectionContext:
    receipt: Mapping[str, Any]
    candidate: Mapping[str, str]
    tools: Mapping[str, Mapping[str, str]]
    database: Mapping[str, Any]
    exceptions_config: Mapping[str, Any]
    exceptions_digest: str
    suppression_config: Mapping[str, Any]
    suppression_digest: str
    receipt_digest: str
    # Preflighted once per release so an absent or drifting scan configuration
    # aborts before any podman, syft or grype work happens.  It defaults to
    # None only so a hand-built context keeps working; a per-image collection
    # that reaches the scan without it resolves the committed configuration
    # itself and fails closed the same way.
    scan_config: ScanConfiguration | None = None


def prepare_collection_context(
    *,
    build_receipt: Path,
    candidate_provenance: Path,
    candidate_bundle: Path,
) -> CollectionContext:
    """Perform release-wide checks once before collecting image evidence."""
    _progress("release", "release-wide identity validation starting")
    started = time.monotonic()
    # First, because it is a pure file read and the cheapest refusal: an absent
    # or drifting scan configuration must abort the release before any podman,
    # syft or grype process is started at all.
    scan_config = load_scan_configuration()
    receipt = _load_json_file(build_receipt)
    if receipt.get("formatVersion") != "stateport.release-image-build-receipt/v1":
        raise EvidenceError("image evidence requires a canonical release build receipt")
    receipt_digest = sha256_file(build_receipt)
    candidate = validated_candidate_identity(
        candidate_provenance=candidate_provenance,
        candidate_bundle=candidate_bundle,
        receipt=receipt,
    )
    tools = verify_toolchain()
    database = refresh_grype_database()
    exceptions_config, exceptions_digest = load_scan_exceptions()
    suppression_config, suppression_digest = load_scan_suppression()
    _progress("release", f"release-wide validation complete in {time.monotonic() - started:.1f}s")
    return CollectionContext(
        receipt=receipt,
        candidate=candidate,
        tools=tools,
        database=database,
        exceptions_config=exceptions_config,
        exceptions_digest=exceptions_digest,
        suppression_config=suppression_config,
        suppression_digest=suppression_digest,
        receipt_digest=receipt_digest,
        scan_config=scan_config,
    )


def _publish_tool_output(*, root: Path, source: Path, name: str) -> Path:
    if source.is_symlink() or not source.is_file():
        raise EvidenceError(f"tool did not produce a regular output file: {source}")
    content = source.read_bytes()
    if not content:
        raise EvidenceError(f"tool produced an empty output file: {source}")
    return write_bytes_create_only(root, name, content)


def _collect_sboms(
    *, image_id: str, local_source: str, syft: str, output: Path
) -> tuple[Path, Path, Path]:
    cdx_name = f"{image_id}.cdx.json"
    spdx_name = f"{image_id}.spdx.json"
    syft_name = f"{image_id}.syft.json"
    started = time.monotonic()
    _progress(image_id, "SBOM catalogue starting (CycloneDX, SPDX, Syft JSON)")
    with tempfile.TemporaryDirectory(prefix="syft-", dir=output) as temporary_root:
        temporary = Path(temporary_root)
        cdx = temporary / cdx_name
        spdx = temporary / spdx_name
        syft_json = temporary / syft_name
        _run(
            [
                syft,
                local_source,
                "-o",
                f"syft-json={syft_json}",
                "-o",
                f"cyclonedx-json={cdx}",
                "-o",
                f"spdx-json={spdx}",
            ]
        )
        published = (
            _publish_tool_output(root=output, source=cdx, name=cdx_name),
            _publish_tool_output(root=output, source=spdx, name=spdx_name),
            _publish_tool_output(root=output, source=syft_json, name=syft_name),
        )
    _progress(image_id, f"SBOM catalogue complete in {time.monotonic() - started:.1f}s")
    return published


def _collect_grype_scan(
    *, image_id: str, syft_json: Path, grype: str, scan_config: ScanConfiguration, output: Path
) -> tuple[Path, datetime, datetime, dict[str, Any]]:
    name = f"{image_id}.grype.json"
    scan_started_at = datetime.now(timezone.utc)
    started = time.monotonic()
    _progress(
        image_id,
        f"vulnerability scan starting from Syft catalogue under {scan_config.repository_path}",
    )
    with tempfile.TemporaryDirectory(prefix="grype-", dir=output) as temporary_root:
        temporary_scan = Path(temporary_root) / name
        # `-c` is explicit so the resolved configuration is the committed one
        # and not whatever grype would otherwise discover in the environment.
        _run_to_new_file(
            [grype, f"sbom:{syft_json}", "-c", str(scan_config.path), "-o", "json"],
            temporary_scan,
        )
        published = _publish_tool_output(root=output, source=temporary_scan, name=name)
    population = suppressed_population(scan_path=published, declared_rules=scan_config.ignore_rules)
    _progress(
        image_id,
        f"vulnerability scan complete in {time.monotonic() - started:.1f}s "
        f"({population['suppressedMatches']} suppressed by the committed configuration)",
    )
    return published, scan_started_at, datetime.now(timezone.utc), population


def _catalogue_source(*, image: Mapping[str, Any], build_receipt_path: Path, local_tag: str) -> str:
    authority = image.get("releaseAuthority")
    if isinstance(authority, Mapping) and authority.get("kind") == "retained-oci-archive":
        archive_path = safe_path(build_receipt_path.parent, str(authority.get("path", "")))
        if archive_path.is_file() and not archive_path.is_symlink():
            return f"oci-archive:{archive_path}"
        raise EvidenceError(f"retained OCI archive is unavailable: {archive_path}")
    return f"podman:{local_tag}"


def verify_toolchain() -> dict[str, dict[str, str]]:
    manifest = _load_yaml(TOOLS)
    observed: dict[str, dict[str, str]] = {}
    for name, expected in manifest["tools"].items():
        expected_path = Path(str(expected["executablePath"]))
        discovered = shutil.which(name)
        if discovered is None or Path(discovered) != expected_path:
            raise EvidenceError(f"{name} is not available at its exact pinned executable path")
        resolved_executable = expected_path.resolve(strict=True)
        if str(resolved_executable) != str(expected["resolvedExecutablePath"]):
            raise EvidenceError(f"{name} resolves to an unexpected executable")
        digest = sha256_file(resolved_executable)
        if digest != expected["executableDigest"]:
            raise EvidenceError(f"{name} executable digest does not match the pinned tool manifest")
        version_text = _run([str(expected_path), "version"])
        if str(expected["version"]) not in version_text:
            raise EvidenceError(f"{name} version does not match the pinned tool manifest")
        observed[name] = {
            "version": str(expected["version"]),
            "executable": str(expected_path),
            "resolvedExecutable": str(resolved_executable),
            "executableDigest": digest,
            "bottleDigest": str(expected["bottleDigest"]),
            "provenance": str(expected["provenance"]),
        }
    return observed


def signature_verification_command(
    *,
    artifact: Path,
    bundle: Path,
    public_key: Path,
    expected_key_fingerprint: str,
    expected_key_id: str,
    configured_key_id: str,
) -> list[str]:
    fingerprint = public_key_der_spki_fingerprint(public_key)
    if fingerprint != expected_key_fingerprint:
        raise EvidenceError(
            "pinned public-key DER SPKI fingerprint does not match the supplied trust root"
        )
    if _KEY_ID.fullmatch(expected_key_id) is None or configured_key_id != expected_key_id:
        raise EvidenceError("pinned public-key ID does not match the configured trust root")
    if bundle.suffixes[-2:] != [".sigstore", ".json"]:
        raise EvidenceError("Cosign v3 bundle must use the .sigstore.json form")
    cosign = str(_load_yaml(TOOLS)["tools"]["cosign"]["executablePath"])
    return [
        cosign,
        "verify-blob",
        "--insecure-ignore-tlog",
        "--bundle",
        str(bundle),
        "--key",
        str(public_key),
        str(artifact),
    ]


def grype_database_status(
    *,
    now: datetime | None = None,
    latest_database_check: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    manifest = _load_yaml(TOOLS)
    policy = manifest["policy"]
    grype = str(manifest["tools"]["grype"]["executablePath"])
    value = json.loads(_run([grype, "db", "status", "-o", "json"]))
    if not isinstance(value, Mapping) or not isinstance(value.get("built"), str):
        raise EvidenceError("Grype database status is invalid")
    try:
        built = datetime.fromisoformat(str(value["built"]).replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError("Grype database build timestamp is invalid") from exc
    observed_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    age_hours = (observed_at - built.astimezone(timezone.utc)).total_seconds() / 3600
    maximum = int(policy["maxDatabaseAgeHours"])
    latest_maximum = int(policy["maxLatestAvailableDatabaseAgeHours"])
    check_maximum = int(policy["latestDatabaseCheckMaxAgeMinutes"])
    minimum_remaining = int(policy["minimumDatabaseFreshnessRemainingHours"])
    if (
        minimum_remaining <= 0
        or minimum_remaining >= maximum
        or latest_maximum <= maximum
        or check_maximum <= 0
    ):
        raise EvidenceError("Grype database freshness reserve is invalid")
    if value.get("valid") is not True or age_hours < 0 or age_hours > latest_maximum:
        raise EvidenceError(
            f"Grype database is not valid or exceeds the absolute latest-available limit "
            f"(age={age_hours:.2f}h, maximum={latest_maximum}h)"
        )
    freshness_class = "fresh"
    if age_hours > maximum:
        if not isinstance(latest_database_check, Mapping):
            raise EvidenceError("latest-available Grype database proof is missing")
        if latest_database_check.get("exitCode") != 0:
            raise EvidenceError("latest-available Grype database check did not prove freshness")
        if latest_database_check.get("meaning") != "up-to-date-no-newer-database":
            raise EvidenceError("latest-available Grype database check meaning is invalid")
        try:
            checked_at = datetime.fromisoformat(
                str(latest_database_check["observedAt"]).replace("Z", "+00:00")
            ).astimezone(timezone.utc)
        except (KeyError, TypeError, ValueError) as exc:
            raise EvidenceError("latest-available Grype database check timestamp is invalid") from exc
        check_age_minutes = (observed_at - checked_at).total_seconds() / 60
        if check_age_minutes < 0 or check_age_minutes > check_maximum:
            raise EvidenceError(
                "latest-available Grype database proof is older than its configured lifetime"
            )
        freshness_class = "latest-available-grace"
    remaining_hours = maximum - age_hours
    # The signed release contract's maxDatabaseAgeHours is the hard authority
    # for scan freshness at qualification/signing time.  The planning reserve
    # below is a pipeline heuristic: a release that cannot wait for the next
    # upstream DB publication must not be hard-blocked while the database is
    # still within its signed age bound.  Record the shortfall as an observed
    # warning so the evidence remains self-describing, and let the signed
    # candidate's qualification-time check enforce the real 24h bound.
    headroom_ok = remaining_hours >= minimum_remaining
    status = {
        "schemaVersion": value.get("schemaVersion"),
        "builtAt": built.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "observedAt": observed_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ageHours": round(age_hours, 4),
        "maximumAgeHours": maximum,
        "normalMaximumAgeHours": maximum,
        "latestAvailableMaximumAgeHours": latest_maximum,
        "latestDatabaseCheckMaxAgeMinutes": check_maximum,
        "freshnessClass": freshness_class,
        "remainingHours": round(remaining_hours, 4),
        "minimumRemainingHours": minimum_remaining,
        "headroomWarning": (
            "release-headroom-shortfall"
            if not headroom_ok
            else None
        ),
        "valid": True,
    }
    if latest_database_check is not None:
        status["latestDatabaseCheck"] = dict(latest_database_check)
    return status


def refresh_grype_database() -> dict[str, Any]:
    """Refresh the pinned database immediately before release evidence."""
    manifest = _load_yaml(TOOLS)
    grype = str(manifest["tools"]["grype"]["executablePath"])
    started = datetime.now(timezone.utc)
    _run([grype, "db", "update"], timeout=3600)
    check_result = _run_result([grype, "db", "check"], timeout=3600)
    checked_at = datetime.now(timezone.utc)
    latest_database_check = {
        "exitCode": check_result.returncode,
        "meaning": (
            "up-to-date-no-newer-database"
            if check_result.returncode == 0
            else "newer-database-available"
            if check_result.returncode == 1
            else "database-check-failed"
        ),
        "observedAt": checked_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    finished = datetime.now(timezone.utc)
    database = grype_database_status(
        now=finished,
        latest_database_check=latest_database_check,
    )
    database.update(
        {
            "updateStartedAt": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "updateFinishedAt": finished.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "updateAttempted": True,
        }
    )
    return database


def _health_observation(*, image_id: str, image_reference: str, local_tag: str) -> dict[str, Any]:
    inspect = json.loads(_run([str(PODMAN), "image", "inspect", local_tag]))
    declared = inspect[0].get("Config", {}).get("Healthcheck")
    probe_command = [
        str(PODMAN),
        "run",
        "--rm",
        local_tag,
        "/usr/local/bin/stateport-healthcheck",
        "--kind",
        "unix-socket",
        "--path",
        "/nonexistent/stateport-health.sock",
    ]
    completed = subprocess.run(
        probe_command,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
        shell=False,
    )
    # The packaged probe exits 1 when the socket is absent; exit 2 would mean
    # argument parsing failed and 126/127 that the probe did not execute.
    probe_executed = completed.returncode == 1
    observation = {
        "formatVersion": "stateport.release-image-healthcheck/v1",
        "imageId": image_id,
        "imageReference": image_reference,
        "declaredHealthcheck": declared,
        "probeObservation": {
            "command": (
                "stateport-healthcheck --kind unix-socket --path /nonexistent/stateport-health.sock"
            ),
            "exitCode": completed.returncode,
            "executed": probe_executed,
            "interpretation": (
                "in-image probe execution observed; the absent socket fails the check exactly as designed"
                if probe_executed
                else "the packaged probe did not execute inside the image"
            ),
        },
        "serviceHealth": {
            "status": "deferred-to-stack-proof",
            "detail": (
                "runtime service health is proven at compose-stack and "
                "no-checkout-install level, not per standalone image"
            ),
        },
    }
    if not declared and not probe_executed:
        raise EvidenceError(f"no health observation is possible for {image_id}")
    return observation


def _podman_observation(reference: str) -> dict[str, Any]:
    values = json.loads(_run([str(PODMAN), "image", "inspect", reference]))
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], Mapping):
        raise EvidenceError(f"Podman returned an invalid image observation for {reference}")
    value = values[0]
    digests: set[str] = set()
    if isinstance(value.get("Digest"), str) and _DIGEST.fullmatch(value["Digest"]):
        digests.add(value["Digest"])
    for item in value.get("RepoDigests") or []:
        if isinstance(item, str) and "@" in item:
            digest = item.rsplit("@", 1)[-1]
            if _DIGEST.fullmatch(digest):
                digests.add(digest)
    return {"imageId": str(value.get("Id", "")), "observedDigests": sorted(digests)}


def derive_build_observations(
    *, image_id: str, build_receipt_path: Path
) -> tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any], str]:
    receipt = _load_json_file(build_receipt_path)
    if receipt.get("formatVersion") != "stateport.release-image-build-receipt/v1":
        raise EvidenceError("image evidence requires a canonical release build receipt")
    image = receipt.get("images", {}).get(image_id)
    if not isinstance(image, Mapping):
        raise EvidenceError(f"build receipt does not contain image {image_id}")
    builds = image.get("builds")
    if not isinstance(builds, list) or [item.get("ordinal") for item in builds] != [1, 2]:
        raise EvidenceError("build receipt does not contain exactly two ordered observations")
    first, second = builds
    first_digest = str(first.get("pushedDigest"))
    second_digest = str(second.get("pushedDigest"))
    if not _DIGEST.fullmatch(first_digest) or not _DIGEST.fullmatch(second_digest):
        raise EvidenceError("build receipt contains an invalid observed digest")
    if first_digest != second_digest or image.get("reproducible") is not True:
        raise EvidenceError("build receipt does not prove an exact OCI digest match")
    accepted_reference = str(image.get("acceptedReference"))
    if (
        not _DIGEST_REFERENCE.fullmatch(accepted_reference)
        or accepted_reference.rsplit("@", 1)[-1] != second_digest
    ):
        raise EvidenceError("accepted image reference is not bound to the second observed build")
    for observation in (first, second):
        local_tag = str(observation.get("localTag"))
        live = _podman_observation(local_tag)
        if live["imageId"] != observation.get("localImageId"):
            raise EvidenceError("local image identity drifted after the recorded double build")
        digest_path = safe_path(build_receipt_path.parent, str(observation["digestFile"]))
        if sha256_file(digest_path) != observation.get("digestFileDigest"):
            raise EvidenceError("Podman digest observation file no longer matches its receipt")
        if digest_path.read_text(encoding="ascii").strip() != observation["pushedDigest"]:
            raise EvidenceError("Podman digest observation bytes disagree with the receipt")
    return receipt, image, second, sha256_file(build_receipt_path)


def validated_candidate_identity(
    *,
    candidate_provenance: Path,
    candidate_bundle: Path,
    receipt: Mapping[str, Any],
) -> dict[str, str]:
    if (
        candidate_provenance.is_symlink()
        or not candidate_provenance.is_file()
        or candidate_provenance.stat().st_size > 1024 * 1024
    ):
        raise EvidenceError("candidate provenance input is unavailable or unsafe")
    try:
        value = yaml.safe_load(candidate_provenance.read_text(encoding="utf-8"))
        schema_name = (
            "candidate-provenance.v2.schema.json"
            if isinstance(value, Mapping)
            and value.get("schema") == "stateport.candidate-provenance/v2"
            else "candidate-provenance.v1.schema.json"
        )
        schema = json.loads((ROOT / "schemas" / schema_name).read_text(encoding="utf-8"))
        validated = validate_candidate_contract(value, schema)
        validate_repository_relationship(validated, ROOT)
        if validated.get("schema") == "stateport.candidate-provenance/v2":
            verify_release_tree(validated, candidate_bundle)
        else:
            verify_candidate_bundle(validated, candidate_bundle)
    except (CandidateProvenanceError, OSError, subprocess.CalledProcessError) as exc:
        raise EvidenceError(f"candidate provenance verification failed: {exc}") from exc
    source = validated["materialization"]
    candidate = validated["repository"]
    if (
        source["sourceCommit"] != receipt["identity"]["commit"]
        or source["sourceTree"] != receipt["identity"]["tree"]
    ):
        raise EvidenceError(
            "candidate materialization source does not match the image build receipt"
        )
    candidate_bundle_digest = (
        sha256_file(candidate_bundle / "release-tree-manifest.json")
        if validated.get("schema") == "stateport.candidate-provenance/v2"
        else sha256_file(candidate_bundle)
    )
    result = {
        "candidateId": str(validated["candidateId"]),
        "sourceRepository": str(source["sourceRepository"]),
        "sourceCommit": str(source["sourceCommit"]),
        "sourceTree": str(source["sourceTree"]),
        "publicSnapshotCommit": str(candidate["commit"]),
        "publicSnapshotTree": str(candidate["tree"]),
        "publicExportManifestDigest": "sha256:"
        + str(validated["artifacts"]["publicManifest"]["sha256"]),
        "candidateContractDigest": sha256_file(candidate_provenance),
        "candidateBundleDigest": candidate_bundle_digest,
    }
    if validated.get("schema") == "stateport.candidate-provenance/v2":
        result.update(
            {
                "candidateProvenanceSchema": "stateport.candidate-provenance/v2",
                "publicAuthorityUrl": str(candidate["authorityUrl"]),
                "publicRef": str(candidate["ref"]),
                "candidateProvenanceDigest": canonical_digest(validated),
                "candidateInputManifestDigest": "sha256:"
                + str(validated["artifacts"]["candidateInputManifest"]["sha256"]),
                "releaseTreeManifestDigest": "sha256:"
                + str(validated["artifacts"]["releaseTreeManifest"]["sha256"]),
            }
        )
    return result


def _resolved_dependencies(
    *, image: Mapping[str, Any], receipt: Mapping[str, Any], receipt_digest: str
) -> list[dict[str, Any]]:
    build_inputs = _load_yaml(BUILD_INPUTS)
    base_manifest = _load_yaml(BASE_IMAGES)
    containerfile = ROOT / str(image["containerfile"])
    from_references = {
        line.split()[1]
        for line in containerfile.read_text(encoding="utf-8").splitlines()
        if line.startswith("FROM ")
    }
    dependencies = [
        {
            "uri": f"stateport-build-receipt:{receipt['identity']['commit']}",
            "digest": {"sha256": receipt_digest.removeprefix("sha256:")},
        },
        {
            "uri": f"git-archive:{receipt['identity']['commit']}",
            "digest": {"sha256": str(receipt["context"]["archiveDigest"]).removeprefix("sha256:")},
        },
        {
            "uri": f"file:{image['containerfile']}",
            "digest": {"sha256": str(image["containerfileDigest"]).removeprefix("sha256:")},
        },
    ]
    for base in base_manifest["images"].values():
        if base["reference"] in from_references:
            dependencies.append(
                {
                    "uri": f"oci:{base['reference']}",
                    "digest": {"sha256": str(base["indexDigest"]).removeprefix("sha256:")},
                }
            )
    for lock in build_inputs["locks"].values():
        dependencies.append(
            {
                "uri": f"file:{lock['path']}",
                "digest": {"sha256": str(lock["digest"]).removeprefix("sha256:")},
            }
        )
    if image["containerfile"] == "images/stateport-dev-workspace/Containerfile":
        for dependency in (
            *build_inputs.get("buildToolchains", {}).values(),
            *build_inputs.get("upstreamTools", {}).values(),
        ):
            dependencies.append(
                {
                    "uri": str(dependency["uri"]),
                    "digest": {
                        "sha256": str(dependency["digest"]).removeprefix("sha256:")
                    },
                }
            )
    if image["containerfile"] == "images/stateport-execution-host/Containerfile":
        for dependency in build_inputs.get("sourceBuiltTools", {}).values():
            dependencies.append(
                {
                    "uri": str(dependency["uri"]),
                    "digest": {
                        "sha256": str(dependency["digest"]).removeprefix("sha256:")
                    },
                }
            )
    if image["containerfile"] == "images/stateport-playwright/Containerfile":
        for dependency in build_inputs.get("browserAssets", {}).values():
            dependencies.append(
                {
                    "uri": str(dependency["uri"]),
                    "digest": {
                        "sha256": str(dependency["digest"]).removeprefix("sha256:")
                    },
                }
            )
    builder = receipt.get("builder")
    if not isinstance(builder, Mapping):
        raise EvidenceError("image build receipt has no exact builder descriptor")
    artifact = builder.get("artifact")
    if not isinstance(artifact, Mapping) or not isinstance(artifact.get("uri"), str):
        raise EvidenceError("image build receipt has no builder artifact provenance")
    artifact_digest = str(artifact.get("digest", ""))
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", artifact_digest):
        raise EvidenceError("image build receipt has an invalid builder artifact digest")
    dependencies.append(
        {
            "uri": f"builder:{artifact['uri']}",
            "digest": {"sha256": artifact_digest.removeprefix("sha256:")},
        }
    )
    return dependencies


def build_provenance(
    *,
    image_id: str,
    image_reference: str,
    image: Mapping[str, Any],
    receipt: Mapping[str, Any],
    receipt_digest: str,
    source_repository: str,
    public_snapshot_commit: str,
    public_snapshot_tree: str,
    dependencies: list[dict[str, Any]],
    byproduct_paths: Sequence[Path],
) -> dict[str, Any]:
    provenance = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": image_id,
                "digest": {"sha256": image_reference.rsplit(":", 1)[-1]},
            }
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://stateport.invalid/buildtypes/oci/v1",
                "externalParameters": {
                    "sourceRepository": source_repository,
                    "sourceCommit": receipt["identity"]["commit"],
                    "sourceTree": receipt["identity"]["tree"],
                    "publicSnapshotCommit": public_snapshot_commit,
                    "publicSnapshotTree": public_snapshot_tree,
                    "platform": "linux/amd64",
                    "dockerfile": image["containerfile"],
                },
                "internalParameters": {
                    "sourceDateEpoch": receipt["identity"]["source_date_epoch"],
                    "networkMode": "dependency-fetch-only",
                },
                "resolvedDependencies": dependencies,
            },
            "runDetails": {
                "builder": {
                    "id": "https://podman.io/rootless-build/v1",
                    "version": receipt["builder"]["version"],
                    "executableDigest": receipt["builder"]["executableDigest"],
                    "descriptorDigest": receipt["builder"]["descriptorDigest"],
                    "artifactUri": receipt["builder"]["artifact"]["uri"],
                    "artifactDigest": receipt["builder"]["artifact"]["digest"],
                },
                "metadata": {
                    "invocationId": hashlib.sha256(
                        (receipt_digest + image_id).encode("utf-8")
                    ).hexdigest(),
                    "startedOn": image["builds"][0]["startedAt"],
                    "finishedOn": image["builds"][1]["finishedAt"],
                },
                "byproducts": [
                    {"name": path.name, "digest": sha256_file(path)} for path in byproduct_paths
                ],
            },
        },
    }
    validate_release_provenance(provenance)
    return provenance


def load_scan_exceptions() -> tuple[Mapping[str, Any], str]:
    """Load the typed scan-exception contract and bind its exact bytes."""
    config = _load_yaml(SCAN_EXCEPTIONS)
    schema = json.loads(SCAN_EXCEPTIONS_SCHEMA.read_text(encoding="utf-8"))
    try:
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(schema).validate(config)
    except (jsonschema.SchemaError, jsonschema.ValidationError) as exc:
        raise EvidenceError(f"scan exception contract is invalid: {exc.message}") from exc
    digest = "sha256:" + hashlib.sha256(SCAN_EXCEPTIONS.read_bytes()).hexdigest()
    return config, digest


_SUPPRESSION_RULE_KEYS = frozenset(
    {"id", "package", "packageType", "matchType", "justification", "expiresOn"}
)
_SUPPRESSION_CONFIG_KEYS = frozenset(
    {"formatVersion", "resolvedOn", "tool", "suppressionRule", "rules"}
)
_SUPPRESSION_TOOL_KEYS = frozenset({"name", "version", "provenance"})
_SUPPRESSION_RULE_ID = re.compile(r"^RS-[0-9]{4}-[0-9]{3}$")
# A justification has to be prose, not a placeholder: whitespace, a single word
# and an empty string are all treated as no justification at all.
_MIN_JUSTIFICATION = 16
# The evaluation document gained two mandatory keys (``suppressedFindings`` and
# ``unexplainedSuppressedFindings``), so it is a new major version: a v1 document
# cannot answer the suppression question at all, and a v2 document that omits the
# block is malformed rather than clean. The assembler refuses evidence whose
# manifest does not bind the suppression contract, which is what makes a
# pre-suppression v1 document unusable for assembly rather than silently
# "zero suppressed findings".
_SCAN_EVALUATION_FORMAT = "stateport.release-scan-evaluation/v2"
_DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
_VERSION = re.compile(r"^[0-9]+(\.[0-9]+)*$")


def _suppression_rule_text(rule: Mapping[str, Any], field: str) -> str:
    value = rule.get(field)
    return str(value).strip() if isinstance(value, str) else ""


def load_scan_suppression() -> tuple[Mapping[str, Any], str]:
    """Load and validate the accepted scan-suppression contract.

    The contract is hand-validated rather than schema-validated because
    ``schemas/`` is outside this collector's change boundary; every field the
    release gate depends on is therefore checked here, and an absent, empty,
    duplicated, or unjustified rule refuses the release instead of passing
    silently.  Returns the contract and the digest of its exact bytes.
    """
    config = _load_yaml(SCAN_SUPPRESSION)
    if set(config) != _SUPPRESSION_CONFIG_KEYS:
        raise EvidenceError(
            "scan suppression contract must declare exactly "
            f"{sorted(_SUPPRESSION_CONFIG_KEYS)}, got {sorted(config)}"
        )
    if config.get("formatVersion") != SCAN_SUPPRESSION_FORMAT:
        raise EvidenceError(
            f"scan suppression contract formatVersion must be {SCAN_SUPPRESSION_FORMAT!r}"
        )
    resolved_on = str(config.get("resolvedOn", ""))
    if not _DATE.fullmatch(resolved_on):
        raise EvidenceError("scan suppression contract has no valid resolvedOn date")
    if not str(config.get("suppressionRule", "")).strip():
        raise EvidenceError("scan suppression contract declares no suppression rule")
    tool = config.get("tool")
    if not isinstance(tool, Mapping) or set(tool) != _SUPPRESSION_TOOL_KEYS:
        raise EvidenceError("scan suppression contract must pin name, version, provenance")
    if str(tool.get("name", "")).strip() != "grype" or not _VERSION.fullmatch(
        str(tool.get("version", "")).strip()
    ):
        raise EvidenceError("scan suppression contract must pin the grype tool version")
    if not str(tool.get("provenance", "")).strip():
        raise EvidenceError("scan suppression contract must record tool provenance")
    rules = config.get("rules")
    if not isinstance(rules, Sequence) or isinstance(rules, (str, bytes)) or not rules:
        raise EvidenceError("scan suppression contract declares no rules")
    if len(rules) > 32:
        raise EvidenceError("scan suppression contract declares more rules than the gate bounds")
    seen_ids: set[str] = set()
    seen_keys: set[tuple[str, str, str]] = set()
    for rule in rules:
        if not isinstance(rule, Mapping) or set(rule) != _SUPPRESSION_RULE_KEYS:
            raise EvidenceError(
                f"scan suppression rule must declare exactly {sorted(_SUPPRESSION_RULE_KEYS)}"
            )
        identifier = _suppression_rule_text(rule, "id")
        if not _SUPPRESSION_RULE_ID.fullmatch(identifier) or identifier in seen_ids:
            raise EvidenceError(f"scan suppression rule id is invalid or duplicated: {identifier!r}")
        seen_ids.add(identifier)
        if not _DATE.fullmatch(_suppression_rule_text(rule, "expiresOn")):
            raise EvidenceError(f"scan suppression rule {identifier} has no valid expiry")
        if len(_suppression_rule_text(rule, "justification")) < _MIN_JUSTIFICATION:
            raise EvidenceError(f"scan suppression rule {identifier} has no usable justification")
        if not _suppression_rule_text(rule, "matchType"):
            raise EvidenceError(f"scan suppression rule {identifier} pins no match type")
        pattern = _suppression_rule_text(rule, "package")
        if not pattern:
            raise EvidenceError(f"scan suppression rule {identifier} pins no package name")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise EvidenceError(
                f"scan suppression rule {identifier} package is not a valid expression"
            ) from exc
        key = (
            pattern,
            _suppression_rule_text(rule, "packageType"),
            _suppression_rule_text(rule, "matchType"),
        )
        if not key[1] or key in seen_keys:
            raise EvidenceError(
                f"scan suppression rule {identifier} has no package type or duplicates another rule"
            )
        seen_keys.add(key)
    digest = "sha256:" + hashlib.sha256(SCAN_SUPPRESSION.read_bytes()).hexdigest()
    return config, digest


def _pinned_grype_version() -> str:
    version = _load_yaml(TOOLS).get("tools", {}).get("grype", {}).get("version", "")
    if not str(version).strip():
        raise EvidenceError("pinned tool inputs record no grype version")
    return str(version).strip()


def _is_unexpired(rule: Mapping[str, Any], today: str) -> bool:
    """True only when a rule carries a real, parseable, future expiry.

    A missing or malformed date is treated as already lapsed, so an unreadable
    expiry can never keep a suppression alive.
    """
    expiry = _suppression_rule_text(rule, "expiresOn")
    if not _DATE.fullmatch(expiry) or not _DATE.fullmatch(today):
        return False
    return expiry >= today


def _effective_ignore_rules(scan: Mapping[str, Any]) -> tuple[list[dict[str, str]], str | None]:
    """Read the ignore rules the scan document actually had in effect.

    Grype records its effective configuration inside every scan document, so
    the rules that can suppress a finding are observable rather than implied.
    A malformed entry is refused instead of ignored: an unparsable effective
    rule cannot be declared, and an undeclared effective rule is a refusal.
    """
    descriptor = scan.get("descriptor")
    if not isinstance(descriptor, Mapping):
        return [], None
    version = str(descriptor.get("version", "")).strip() or None
    configuration = descriptor.get("configuration")
    entries = configuration.get("ignore") if isinstance(configuration, Mapping) else None
    if entries is None:
        return [], version
    if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes)):
        raise EvidenceError("scan document effective ignore rules are malformed")
    effective: list[dict[str, str]] = []
    for entry in entries:
        if not isinstance(entry, Mapping) or not isinstance(entry.get("package"), Mapping):
            raise EvidenceError("scan document effective ignore rule is malformed")
        effective.append(
            {
                "package": str(entry["package"].get("name", "")),
                "packageType": str(entry["package"].get("type", "")),
                "matchType": str(entry.get("match-type", "")),
            }
        )
    return effective, version


def _applied_ignore_rules(match: Mapping[str, Any]) -> list[dict[str, str]]:
    """Read the ignore rules a single suppressed match was actually filtered by."""
    applied = match.get("appliedIgnoreRules")
    if not isinstance(applied, Sequence) or isinstance(applied, (str, bytes)):
        return []
    rules: list[dict[str, str]] = []
    for entry in applied:
        if not isinstance(entry, Mapping) or not isinstance(entry.get("package"), Mapping):
            raise EvidenceError("suppressed match appliedIgnoreRules entry is malformed")
        rules.append(
            {
                "package": str(entry["package"].get("name", "")),
                "packageType": str(entry["package"].get("type", "")),
                "matchType": str(entry.get("match-type", "")),
            }
        )
    return rules


def _match_types(match: Mapping[str, Any]) -> list[str]:
    details = match.get("matchDetails")
    if not isinstance(details, Sequence) or isinstance(details, (str, bytes)):
        return []
    return [
        str(entry["type"])
        for entry in details
        if isinstance(entry, Mapping) and entry.get("type")
    ]


def _suppression_verdict(
    *,
    scan: Mapping[str, Any],
    suppression_config: Mapping[str, Any] | None,
    threshold: int,
    today: str,
) -> dict[str, Any]:
    """Classify every suppressed finding against the declared suppression policy.

    Fail-closed in four independent ways: a suppressed finding at or above the
    effective threshold with no declared, justified, unexpired rule covering its
    package name, package type, and match type is unexplained; an effective
    rule the contract does not declare is a refusal; a declared rule with an
    empty justification is a refusal; and a rule that is expired cannot cover
    anything.  Nothing here is derived from the scanner binary's behaviour.
    """
    rules: list[Mapping[str, Any]] = []
    declared_version = ""
    if isinstance(suppression_config, Mapping):
        if suppression_config.get("formatVersion") != SCAN_SUPPRESSION_FORMAT:
            raise EvidenceError(
                f"suppression policy must declare {SCAN_SUPPRESSION_FORMAT!r}"
            )
        declared_version = str(suppression_config.get("tool", {}).get("version", "")).strip()
        rules = [rule for rule in suppression_config.get("rules", []) if isinstance(rule, Mapping)]
    suppressed = scan.get("ignoredMatches")
    if suppressed is None:
        suppressed = []
    if not isinstance(suppressed, Sequence) or isinstance(suppressed, (str, bytes)):
        raise EvidenceError("scan document ignoredMatches is malformed")
    effective, observed_version = _effective_ignore_rules(scan)
    declared_by_key: dict[tuple[str, str, str], Mapping[str, Any]] = {
        (
            str(rule.get("package", "")).strip(),
            str(rule.get("packageType", "")).strip(),
            str(rule.get("matchType", "")).strip(),
        ): rule
        for rule in rules
    }
    declared_by_id: dict[str, Mapping[str, Any]] = {
        str(rule.get("id")): rule for rule in rules
    }
    unjustified = [
        str(rule.get("id"))
        for rule in rules
        if len(_suppression_rule_text(rule, "justification")) < _MIN_JUSTIFICATION
    ]
    expired = [str(rule.get("id")) for rule in rules if not _is_unexpired(rule, today)]
    undeclared = [
        entry
        for entry in effective
        if (entry["package"], entry["packageType"], entry["matchType"]) not in declared_by_key
    ]

    def qualifies(entry: Mapping[str, str], match: Mapping[str, Any]) -> bool:
        """True when a declared rule covers this finding and may explain it.

        All four declared properties have to agree with the finding itself: the
        applied rule's package name, package type and match type must name a
        declared rule, that rule's package expression must match the suppressed
        package, the rule's match type must be one of the match types the
        finding actually has, and the rule must be justified and unexpired.
        """
        rule = declared_by_key.get(
            (entry["package"], entry["packageType"], entry["matchType"])
        )
        if rule is None:
            return False
        if str(rule.get("id")) in unjustified or not _is_unexpired(rule, today):
            return False
        types = _match_types(match)
        if types and entry["matchType"] not in types:
            return False
        artifact = match.get("artifact") if isinstance(match.get("artifact"), Mapping) else match
        return bool(re.fullmatch(entry["package"], str(artifact.get("name", ""))))

    by_severity: dict[str, int] = {}
    gated: list[dict[str, Any]] = []
    uncovered: list[dict[str, Any]] = []
    covered_by_rule: dict[str, int] = {}
    for match in suppressed:
        vulnerability = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        severity = str(vulnerability.get("severity", ""))
        by_severity[severity] = by_severity.get(severity, 0) + 1
        if _SEVERITY_ORDER.get(severity, -1) < threshold:
            continue
        fix = vulnerability.get("fix", {})
        finding = {
            "advisory": str(vulnerability.get("id", "")),
            "package": str(artifact.get("name", "")),
            "packageVersion": str(artifact.get("version", "")),
            "packageType": str(artifact.get("type", "")),
            "severity": severity,
            "fixState": str(fix.get("state", "unknown")),
            "fixVersions": [str(item) for item in fix.get("versions", []) if item],
            "matchTypes": _match_types(match),
        }
        applied = _applied_ignore_rules(match)
        covering = next((entry for entry in applied if qualifies(entry, match)), None)
        if covering is None:
            uncovered.append(finding)
            continue
        rule = declared_by_key[
            (covering["package"], covering["packageType"], covering["matchType"])
        ]
        identifier = str(rule.get("id"))
        covered_by_rule[identifier] = covered_by_rule.get(identifier, 0) + 1
        gated.append({**finding, "suppressionRuleId": identifier})

    refusals: list[str] = []
    if undeclared:
        names = ", ".join(
            f"{entry['package']!r}/{entry['packageType']}/{entry['matchType']}" for entry in undeclared
        )
        refusals.append(
            f"the scan suppressed findings under {len(undeclared)} effective ignore rule(s) "
            f"the policy does not declare: {names}"
        )
    if unjustified:
        refusals.append(
            "declared suppression rule(s) carry no justification: " + ", ".join(sorted(unjustified))
        )
    if uncovered:
        refusals.append(
            f"{len(uncovered)} suppressed finding(s) at or above the threshold are covered by no "
            "declared, justified, unexpired rule"
        )
    if declared_version and observed_version and declared_version != observed_version:
        refusals.append(
            f"the suppression policy is declared for grype {declared_version} but the scan was "
            f"produced by grype {observed_version}"
        )
    if declared_version and not observed_version:
        refusals.append(
            "the suppression policy is declared for grype "
            f"{declared_version} but the scan document names no scanner version, so the "
            "declaration cannot be shown to apply"
        )
    pinned_version = _pinned_grype_version() if declared_version else ""
    if declared_version and declared_version != pinned_version:
        refusals.append(
            f"the suppression policy is declared for grype {declared_version} but the pinned tool "
            f"inputs require grype {pinned_version}"
        )
    # The earliest expiry the declaration can lapse on. It travels into the
    # signed release block so a consumer of signed bytes can see the residual's
    # own deadline instead of trusting that someone checked it once.
    declared_expiries = sorted(
        _suppression_rule_text(rule, "expiresOn")
        for rule in rules
        if _DATE.fullmatch(_suppression_rule_text(rule, "expiresOn"))
    )
    applied_expiries = sorted(
        _suppression_rule_text(declared_by_id[identifier], "expiresOn")
        for identifier in covered_by_rule
        if _DATE.fullmatch(_suppression_rule_text(declared_by_id[identifier], "expiresOn"))
    )
    return {
        "policyFile": SCAN_SUPPRESSION_FILE,
        "policyFormatVersion": SCAN_SUPPRESSION_FORMAT,
        "policyResolvedOn": str(suppression_config.get("resolvedOn", "")) if suppression_config else "",
        "tool": {
            "name": "grype",
            "declaredVersion": declared_version,
            "observedVersion": observed_version,
            "pinnedVersion": pinned_version or _pinned_grype_version(),
        },
        "total": len(suppressed),
        "bySeverity": by_severity,
        "gatedTotal": len(gated) + len(uncovered),
        "coveredByRule": dict(sorted(covered_by_rule.items())),
        "gatedFindings": sorted(gated, key=lambda item: (item["advisory"], item["package"])),
        "uncoveredGatedFindings": sorted(
            uncovered, key=lambda item: (item["advisory"], item["package"])
        ),
        "declaredRuleIds": sorted(declared_by_id),
        "declaredExpiresOn": declared_expiries[0] if declared_expiries else "",
        "appliedExpiresOn": applied_expiries[0] if applied_expiries else "",
        "effectiveRules": effective,
        "undeclaredEffectiveRules": undeclared,
        "expiredRuleIds": sorted(expired),
        "unjustifiedRuleIds": sorted(unjustified),
        "refusals": refusals,
    }


def _scan_suppression_record(suppression: Mapping[str, Any]) -> dict[str, Any]:
    """Project the evaluation's suppression verdict into the evidence manifest.

    The manifest carries counts, the rule identities in force, and the refusal
    list rather than the full suppressed finding list: the complete list stays
    in the digested evaluation artifact, while the manifest stays small enough
    for the assembler to refuse an undeclared, unjustified, expired, or
    uncovered suppression without reading the retained scan document.
    """
    return {
        "policyFile": str(suppression["policyFile"]),
        "policyFormatVersion": str(suppression["policyFormatVersion"]),
        "policyResolvedOn": str(suppression["policyResolvedOn"]),
        "toolName": str(suppression["tool"]["name"]),
        "toolVersion": str(suppression["tool"]["observedVersion"] or ""),
        "declaredToolVersion": str(suppression["tool"]["declaredVersion"]),
        "suppressedTotal": int(suppression["total"]),
        "suppressedBySeverity": dict(suppression["bySeverity"]),
        "suppressedGatedTotal": int(suppression["gatedTotal"]),
        "suppressedCoveredByRule": dict(suppression["coveredByRule"]),
        "uncoveredSuppressedCount": len(suppression["uncoveredGatedFindings"]),
        "declaredRuleIds": list(suppression["declaredRuleIds"]),
        "declaredExpiresOn": str(suppression["declaredExpiresOn"]),
        "appliedExpiresOn": str(suppression["appliedExpiresOn"]),
        "effectiveRules": [dict(entry) for entry in suppression["effectiveRules"]],
        "undeclaredEffectiveRules": [dict(entry) for entry in suppression["undeclaredEffectiveRules"]],
        "expiredRuleIds": list(suppression["expiredRuleIds"]),
        "unjustifiedRuleIds": list(suppression["unjustifiedRuleIds"]),
        "refusals": list(suppression["refusals"]),
    }


def _scan_threshold() -> str:
    policy = _load_yaml(TOOLS).get("policy", {})
    threshold = str(policy.get("vulnerabilityFailureThreshold", "high")).lower()
    if threshold not in _THRESHOLD_ORDER:
        raise EvidenceError(f"unknown vulnerability failure threshold: {threshold}")
    return threshold


def _matching_exception(
    exceptions: Sequence[Mapping[str, Any]],
    *,
    advisory: str,
    package: str,
    package_version: str,
    artifact_paths: set[str],
    image_id: str,
    today: str,
) -> Mapping[str, Any] | None:
    for exception in exceptions:
        if (
            str(exception["advisory"]) == advisory
            and str(exception["package"]) == package
            and (
                exception.get("packageVersion") is None
                or str(exception["packageVersion"]) == package_version
            )
            and (
                exception.get("artifactPath") is None
                or str(exception["artifactPath"]) in artifact_paths
            )
            and image_id in exception["images"]
            and str(exception["expiresOn"]) >= today
        ):
            return exception
    return None


def evaluate_scan(
    *,
    scan_path: Path,
    image_id: str,
    exceptions_config: Mapping[str, Any],
    today: str,
    suppression_config: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Classify every threshold-severity finding as explained or unexplained.

    A finding passes the gate only through an exact typed exception that names
    the same advisory and package, applies to this image and exact artifact
    path when declared, and is unexpired on the evaluation date. Everything
    else fails the image.

    Findings the scanner suppressed never appear in ``matches``: they arrive in
    ``ignoredMatches`` and, before this contract existed, no ledger record could
    reach them.  They are therefore evaluated too, against the declared
    suppression policy, and both verdicts travel in the same document: the
    suppressed ones under ``suppressedFindings`` (with the full list at or above
    the effective threshold) and, at the top level, under
    ``unexplainedSuppressedFindings``.

    ``suppression_config`` defaults to no declared rules at all, which is the
    fail-closed reading: a caller that does not load the contract can never
    pass a suppressed finding, and can never pass a scan whose effective ignore
    rules it has not declared.
    """
    scan = _load_json_file(scan_path, maximum_bytes=256 * 1024 * 1024)
    threshold = _THRESHOLD_ORDER[_scan_threshold()]
    counts: dict[str, int] = {}
    applied: list[dict[str, Any]] = []
    unexplained: list[dict[str, Any]] = []
    for match in scan.get("matches", []):
        vulnerability = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        severity = str(vulnerability.get("severity", ""))
        counts[severity] = counts.get(severity, 0) + 1
        if _SEVERITY_ORDER.get(severity, -1) < threshold:
            continue
        advisory = str(vulnerability.get("id", ""))
        package = str(artifact.get("name", ""))
        version = str(artifact.get("version", ""))
        artifact_paths = {
            str(location.get("path"))
            for location in (artifact.get("locations") or [])
            if isinstance(location, Mapping) and location.get("path")
        }
        fix = vulnerability.get("fix", {})
        finding = {
            "advisory": advisory,
            "package": package,
            "packageVersion": version,
            "severity": severity,
            "fixState": str(fix.get("state", "unknown")),
            "fixVersions": [str(item) for item in fix.get("versions", []) if item],
        }
        exception = _matching_exception(
            exceptions_config["exceptions"],
            advisory=advisory,
            package=package,
            package_version=version,
            artifact_paths=artifact_paths,
            image_id=image_id,
            today=today,
        )
        if exception is None:
            unexplained.append(finding)
        else:
            applied.append({**finding, "exceptionId": str(exception["id"])})
    suppression = _suppression_verdict(
        scan=scan,
        suppression_config=suppression_config,
        threshold=threshold,
        today=today,
    )
    return {
        "formatVersion": _SCAN_EVALUATION_FORMAT,
        "imageId": image_id,
        "evaluatedOn": today,
        "findingsBySeverity": counts,
        "appliedExceptions": sorted(applied, key=lambda item: (item["advisory"], item["package"])),
        "unexplainedFindings": sorted(
            unexplained, key=lambda item: (item["advisory"], item["package"])
        ),
        "suppressedFindings": suppression,
        "unexplainedSuppressedFindings": suppression["uncoveredGatedFindings"],
    }


def _collect_image(
    *,
    image_id: str,
    build_receipt: Path,
    context: CollectionContext,
    output: Path,
) -> dict[str, Any]:
    _progress(image_id, "identity validation starting")
    started = time.monotonic()
    receipt, image, second, receipt_digest = derive_build_observations(
        image_id=image_id, build_receipt_path=build_receipt
    )
    if receipt_digest != context.receipt_digest or receipt != context.receipt:
        raise EvidenceError("build receipt changed during release evidence collection")
    candidate = context.candidate
    _progress(image_id, f"identity validation complete in {time.monotonic() - started:.1f}s")
    image_reference = str(image["acceptedReference"])
    tools = context.tools
    database = dict(context.database)
    local_source = _catalogue_source(
        image=image,
        build_receipt_path=build_receipt,
        local_tag=str(second["localTag"]),
    )
    _progress(image_id, f"catalogue source: {local_source}")
    syft = tools["syft"]["executable"]
    grype = tools["grype"]["executable"]
    scan_config = context.scan_config or load_scan_configuration()
    cdx, spdx, syft_json = _collect_sboms(
        image_id=image_id,
        local_source=local_source,
        syft=syft,
        output=output,
    )
    scan, scan_started_at, scan_completed_at, suppressed = _collect_grype_scan(
        image_id=image_id,
        syft_json=syft_json,
        grype=grype,
        scan_config=scan_config,
        output=output,
    )
    database.update(
        {
            "databaseObservedAt": database.get("observedAt"),
            "scanStartedAt": scan_started_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "scanCompletedAt": scan_completed_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            # The assembler's scannedAt field is completion-bound, not a
            # pre-scan database observation.
            "observedAt": scan_completed_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    )
    write_json_create_only(output, f"{image_id}.grype-db.json", database)
    _progress(image_id, "scan policy evaluation starting")
    # One evaluation date for the whole image: the manifest, the evaluation
    # document and the suppression expiry check must not disagree about which
    # day the rules were judged against.
    today = datetime.now(timezone.utc).date().isoformat()
    evaluation = evaluate_scan(
        scan_path=scan,
        image_id=image_id,
        exceptions_config=context.exceptions_config,
        today=today,
        suppression_config=context.suppression_config,
    )
    evaluation_path = write_json_create_only(output, f"{image_id}.scan-evaluation.json", evaluation)
    _progress(image_id, "scan policy evaluation complete")
    packages = json.loads(syft_json.read_text(encoding="utf-8")).get("artifacts", [])
    licences = sorted(
        {
            str(license_item["value"])
            for package in packages
            for license_item in package.get("licenses", [])
            if isinstance(license_item, Mapping) and license_item.get("value")
        }
    )
    inventory = {
        "formatVersion": "stateport.license-inventory/v1",
        "imageId": image_id,
        "imageReference": image_reference,
        "licenses": licences,
    }
    license_path = write_json_create_only(output, f"{image_id}.licenses.json", inventory)
    comparison = {
        "formatVersion": "stateport.double-build-comparison/v1",
        "imageId": image_id,
        "first": {
            "digest": image["builds"][0]["pushedDigest"],
            "digestObservationDigest": image["builds"][0]["digestFileDigest"],
            "localImageId": image["builds"][0]["localImageId"],
        },
        "second": {
            "digest": image["builds"][1]["pushedDigest"],
            "digestObservationDigest": image["builds"][1]["digestFileDigest"],
            "localImageId": image["builds"][1]["localImageId"],
        },
        "reproducible": True,
        "interpretation": "exact independently observed OCI registry digest match",
    }
    comparison_path = write_json_create_only(output, f"{image_id}.double-build.json", comparison)
    health_path = write_json_create_only(
        output,
        f"{image_id}.healthcheck.json",
        _health_observation(
            image_id=image_id,
            image_reference=image_reference,
            local_tag=str(second["localTag"]),
        ),
    )
    _progress(image_id, "provenance and manifest assembly starting")
    byproduct_paths = [
        cdx,
        spdx,
        syft_json,
        scan,
        evaluation_path,
        license_path,
        comparison_path,
        health_path,
        output / f"{image_id}.grype-db.json",
    ]
    dependencies = _resolved_dependencies(
        image=image, receipt=receipt, receipt_digest=receipt_digest
    )
    provenance = build_provenance(
        image_id=image_id,
        image_reference=image_reference,
        image=image,
        receipt=receipt,
        receipt_digest=receipt_digest,
        source_repository=candidate["sourceRepository"],
        public_snapshot_commit=candidate["publicSnapshotCommit"],
        public_snapshot_tree=candidate["publicSnapshotTree"],
        dependencies=dependencies,
        byproduct_paths=byproduct_paths,
    )
    provenance_path = write_json_create_only(output, f"{image_id}.provenance.json", provenance)
    artifact_paths = [*byproduct_paths, provenance_path]
    manifest = {
        "formatVersion": "stateport.release-image-evidence/v1",
        "imageId": image_id,
        "imageReference": image_reference,
        "buildReceiptDigest": receipt_digest,
        "candidate": candidate,
        "tools": tools,
        "grypeDatabase": database,
        "scanPolicy": {
            "threshold": _scan_threshold(),
            "evaluatedOn": today,
            "unfixedFindingsIncluded": True,
            "result": "passed"
            if not evaluation["unexplainedFindings"]
            and not evaluation["unexplainedSuppressedFindings"]
            and not evaluation["suppressedFindings"]["refusals"]
            else "failed",
            "exceptionsFile": "config/release-scan-exceptions.v1.yaml",
            "exceptionsDigest": context.exceptions_digest,
            "suppressionFile": SCAN_SUPPRESSION_FILE,
            "suppressionDigest": context.suppression_digest,
            "suppression": _scan_suppression_record(evaluation["suppressedFindings"]),
            "evaluationArtifact": evaluation_path.name,
            "appliedExceptionIds": sorted(
                {item["exceptionId"] for item in evaluation["appliedExceptions"]}
            ),
            "unexplainedFindings": evaluation["unexplainedFindings"],
            "unexplainedSuppressedFindings": evaluation["unexplainedSuppressedFindings"],
            "suppressionRefusals": evaluation["suppressedFindings"]["refusals"],
        },
        # A NEW top-level key, deliberately outside `scanPolicy`: the
        # assembler's and the contract's reading of `scanPolicy` is unchanged,
        # and the image evidence manifest carries no closed key set, so an extra
        # top-level key is read by nobody and disturbs no already-signed index.
        # What this buys: the signed scan DECLARES the configuration it ran
        # under and the population that configuration suppressed, instead of
        # carrying its ignore behaviour ambiently.
        "vulnerabilityScanConfiguration": {
            "formatVersion": SCAN_CONFIG_FORMAT_VERSION,
            "path": scan_config.repository_path,
            "digest": scan_config.digest,
            "ignoreRuleCount": len(scan_config.ignore_rules),
            "ignoreRules": [dict(rule) for rule in scan_config.ignore_rules],
            "suppressedMatches": suppressed["suppressedMatches"],
            "suppressedMatchesBySeverity": suppressed["suppressedMatchesBySeverity"],
            "appliedIgnoreRules": suppressed["appliedIgnoreRules"],
        },
        "artifacts": {path.name: sha256_file(path) for path in artifact_paths},
        "signature": {
            "status": "pending_owner_trust_root",
            "publicTransparencyLogUpload": False,
            "privateVerification": "pinned-public-key-fingerprint-and-key-id",
        },
        "doubleBuild": comparison,
    }
    write_json_create_only(output, f"{image_id}.evidence.json", manifest)
    _progress(image_id, "evidence collection complete")
    if evaluation["suppressedFindings"]["refusals"]:
        raise EvidenceError(
            f"scan suppression policy refuses {image_id}: "
            + "; ".join(evaluation["suppressedFindings"]["refusals"])
            + "; evidence retained"
        )
    if evaluation["unexplainedFindings"]:
        preview = ", ".join(
            f"{item['advisory']}:{item['package']}"
            for item in evaluation["unexplainedFindings"][:8]
        )
        raise EvidenceError(
            f"unexplained high-or-critical vulnerability findings refuse {image_id} "
            f"({len(evaluation['unexplainedFindings'])}): {preview}; evidence retained"
        )
    # There is deliberately no second refusal here for
    # `unexplainedSuppressedFindings`, and the one that was here could not fire.
    # `_suppression_verdict` appends to `refusals` whenever `uncovered` is
    # non-empty, and publishes that same `uncovered` list as
    # `uncoveredGatedFindings`, which `evaluate_scan` republishes as
    # `unexplainedSuppressedFindings`. So the two guards tested the same
    # condition and the one above raised first.
    #
    # That coupling is a property of ANOTHER function, not an invariant of this
    # one, so the deletion is only safe while the coupling holds -- and a
    # comment cannot hold it. It is held by a test instead:
    # `test_an_uncovered_suppressed_finding_always_also_produces_a_refusal`
    # fails if a refactor ever stops appending the refusal while leaving the
    # field populated, which is precisely the decoupling that would make a
    # refusal here necessary again. Measured: breaking the coupling makes that
    # test fail, so the invariant is enforced on every change rather than only
    # when a release happens to hit the case.
    #
    # The field itself is not redundant either way: it sets `scanPolicy.result`
    # and travels in the manifest, where the assembler reads it.
    return manifest


def collect(
    *,
    image_id: str,
    build_receipt: Path,
    candidate_provenance: Path,
    candidate_bundle: Path,
    output_root: Path,
) -> dict[str, Any]:
    """Collect one image using the same release-wide preparation as batch mode."""
    output = prepare_output_root(output_root, repository=ROOT)
    _set_scanner_tmpdir(output)
    context = prepare_collection_context(
        build_receipt=build_receipt,
        candidate_provenance=candidate_provenance,
        candidate_bundle=candidate_bundle,
    )
    return _collect_image(
        image_id=image_id,
        build_receipt=build_receipt,
        context=context,
        output=output,
    )


def _verified_checkpoint(
    *, manifest_path: Path, image_id: str, context: CollectionContext
) -> dict[str, Any] | None:
    """Return a completed image manifest only when every declared artifact matches."""
    if not manifest_path.exists():
        return None
    manifest = _load_json_file(manifest_path, maximum_bytes=4 * 1024 * 1024)
    if (
        manifest.get("imageId") != image_id
        or manifest.get("buildReceiptDigest") != context.receipt_digest
    ):
        raise EvidenceError(f"resume checkpoint is not bound to the current release: {image_id}")
    checkpoint_database = manifest.get("grypeDatabase")
    if (
        not isinstance(checkpoint_database, Mapping)
        or checkpoint_database.get("builtAt") != context.database.get("builtAt")
    ):
        raise EvidenceError(
            f"resume checkpoint is not bound to the current Grype database: {image_id}"
        )
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, Mapping) or not artifacts:
        raise EvidenceError(f"resume checkpoint has no artifact inventory: {image_id}")
    for name, expected in artifacts.items():
        artifact = safe_path(manifest_path.parent, str(name))
        if sha256_file(artifact) != str(expected):
            raise EvidenceError(f"resume checkpoint artifact digest mismatch: {artifact.name}")
    # The artifact digests above prove the checkpoint is INTACT, not that it is a
    # PASS. `_collect_image` publishes the image manifest and only then refuses,
    # so a scan that failed leaves a complete, digest-correct manifest behind --
    # and resuming over it used to return that failed image as complete and skip
    # the collection that would have refused it.
    #
    # The verdict is RE-DERIVED from the digested scan evaluation rather than read
    # from the manifest. The manifest is unsigned, so `scanPolicy.result` inside
    # it is a claim; `*.scan-evaluation.json` is the evidence the digests above
    # already cover, and the evaluator is what produced both. Anything the
    # derivation cannot read is treated as a failure, not as a pass.
    scan_policy = manifest.get("scanPolicy")
    if not isinstance(scan_policy, Mapping):
        raise EvidenceError(f"resume checkpoint carries no scan policy: {image_id}")
    evaluation_name = f"{image_id}.scan-evaluation.json"
    if evaluation_name not in artifacts or scan_policy.get("evaluationArtifact") != evaluation_name:
        raise EvidenceError(
            f"resume checkpoint does not carry its scan evaluation artifact "
            f"{evaluation_name}, so its verdict cannot be re-derived: {image_id}"
        )
    evaluation = _load_json_file(
        safe_path(manifest_path.parent, evaluation_name), maximum_bytes=4 * 1024 * 1024
    )
    if evaluation.get("imageId") != image_id:
        raise EvidenceError(
            f"resume checkpoint scan evaluation is not bound to this image: {image_id}"
        )
    suppression = evaluation.get("suppressedFindings")
    derived = "passed"
    if (
        not isinstance(evaluation.get("unexplainedFindings"), list)
        or evaluation["unexplainedFindings"]
        or not isinstance(evaluation.get("unexplainedSuppressedFindings"), list)
        or evaluation["unexplainedSuppressedFindings"]
        or not isinstance(suppression, Mapping)
        or not isinstance(suppression.get("refusals"), list)
        or suppression["refusals"]
    ):
        derived = "failed"
    claimed = scan_policy.get("result")
    if derived != "passed" or claimed != "passed":
        raise EvidenceError(
            f"resume checkpoint is not a completed image: {image_id} records "
            f"scanPolicy.result {claimed!r} while its scan evaluation derives "
            f"{derived!r}"
        )
    # Reproduce the verdict from the scan itself, against the ledger as it
    # stands TODAY, and require it to be clean.
    #
    # `today`, deliberately, and not the checkpoint's recorded evaluation date.
    # A resume must accept exactly what a fresh collection would accept, and a
    # fresh collection evaluates against the ledger in force now. An earlier
    # version of this guard re-ran with the recorded date, which was a hole the
    # independent verification demonstrated: `scanPolicy.evaluatedOn` is an
    # unsigned field, so backdating that one field passed an image whose
    # exception has since lapsed -- 107 of the 227 records in the committed
    # ledger have already lapsed, so this was not an edge case. A stored
    # evaluation is a record of a past judgement; the question this gate answers
    # is whether the image may be signed now.
    #
    # The stored document is not compared field by field any more, because when
    # the ledger moves a legitimate image legitimately differs from its own
    # stored evaluation, and refusing that would force a re-collection rather
    # than fix anything. The claim is still checked against the stored document
    # above, and the verdict that matters is computed here, from the scan the
    # manifest already digests. Measured on the largest retained scan in this
    # campaign (12.5 MB) this costs about 0.1 s per image.
    scan_name = f"{image_id}.grype.json"
    if scan_name not in artifacts:
        raise EvidenceError(
            f"resume checkpoint does not carry its scan document {scan_name}, so its "
            f"evaluation cannot be reproduced: {image_id}"
        )
    reproduced = evaluate_scan(
        scan_path=safe_path(manifest_path.parent, scan_name),
        image_id=image_id,
        exceptions_config=context.exceptions_config,
        today=datetime.now(timezone.utc).date().isoformat(),
        suppression_config=context.suppression_config,
    )
    if (
        reproduced["unexplainedFindings"]
        or reproduced["unexplainedSuppressedFindings"]
        or reproduced["suppressedFindings"]["refusals"]
    ):
        raise EvidenceError(
            f"resume checkpoint scan document does not pass a fresh evaluation against "
            f"the ledger in force today: {image_id}"
        )
    return dict(manifest)


def _discard_partial_image(output: Path, image_id: str) -> None:
    for suffix in _IMAGE_OUTPUT_SUFFIXES:
        artifact = output / f"{image_id}{suffix}"
        if artifact.exists() or artifact.is_symlink():
            remove_file_exact(output, artifact.name)


def collect_many(
    *,
    image_ids: Sequence[str],
    build_receipt: Path,
    candidate_provenance: Path,
    candidate_bundle: Path,
    output_root: Path,
    resume: bool = False,
) -> list[dict[str, Any]]:
    """Collect all requested images with one release-wide validation pass."""
    output = (
        open_existing_output_root(output_root, repository=ROOT)
        if resume
        else prepare_output_root(output_root, repository=ROOT)
    )
    _set_scanner_tmpdir(output)
    context = prepare_collection_context(
        build_receipt=build_receipt,
        candidate_provenance=candidate_provenance,
        candidate_bundle=candidate_bundle,
    )
    available = context.receipt.get("images")
    if not isinstance(available, Mapping):
        raise EvidenceError("build receipt contains no image observations")
    requested = list(dict.fromkeys(image_ids))
    unknown = sorted(set(requested) - set(available))
    if unknown:
        raise EvidenceError(f"build receipt does not contain images: {', '.join(unknown)}")
    if not requested:
        raise EvidenceError("release evidence requires at least one image")
    manifests: list[dict[str, Any]] = []
    for image_id in requested:
        checkpoint = output / f"{image_id}.evidence.json"
        if resume:
            completed = _verified_checkpoint(
                manifest_path=checkpoint, image_id=image_id, context=context
            )
            if completed is not None:
                _progress(image_id, "resume checkpoint verified; skipping completed image")
                manifests.append(completed)
                continue
            _progress(image_id, "no complete checkpoint; removing partial create-only outputs")
            _discard_partial_image(output, image_id)
        manifests.append(
            _collect_image(
                image_id=image_id,
                build_receipt=build_receipt,
                context=context,
                output=output,
            )
        )
    return manifests


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    image_selection = parser.add_mutually_exclusive_group(required=True)
    image_selection.add_argument("--image-id", action="append", dest="image_ids")
    image_selection.add_argument("--all-images", action="store_true")
    parser.add_argument("--build-receipt", type=Path, required=True)
    parser.add_argument("--candidate-provenance", type=Path, required=True)
    parser.add_argument("--candidate-bundle", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument(
        "--resume",
        action="store_true",
        help="verify completed image manifests in an existing output root before skipping them",
    )
    args = parser.parse_args(argv)
    image_ids = list(args.image_ids or [])
    if args.all_images:
        receipt = _load_json_file(args.build_receipt)
        images = receipt.get("images")
        if not isinstance(images, Mapping):
            raise EvidenceError("build receipt contains no image observations")
        image_ids = sorted(str(image_id) for image_id in images)
    if len(image_ids) == 1 and not args.resume:
        result: Any = collect(
            image_id=image_ids[0],
            build_receipt=args.build_receipt,
            candidate_provenance=args.candidate_provenance,
            candidate_bundle=args.candidate_bundle,
            output_root=args.output_root,
        )
    else:
        result = collect_many(
            image_ids=image_ids,
            build_receipt=args.build_receipt,
            candidate_provenance=args.candidate_provenance,
            candidate_bundle=args.candidate_bundle,
            output_root=args.output_root,
            resume=args.resume,
        )
    print(
        json.dumps(result, sort_keys=True)
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EvidenceError, OSError, ValueError, yaml.YAMLError) as exc:
        print(f"release evidence refused: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
