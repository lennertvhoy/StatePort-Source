"""RunBundle v1 ingestion for StateBench execution scorecards."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable


class RunBundleIngestionError(ValueError):
    pass


_REQUIRED_VERIFIED_ARTIFACTS = frozenset({
    "execution/agent-run-spec.json",
    "execution/result.json",
    "execution/engine.json",
    "execution/capability-negotiation.json",
    "identities/state-before.json",
    "identities/state-after.json",
})
_MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
_MAX_BUNDLE_BYTES = 64 * 1024 * 1024
_MAX_BUNDLE_PATH_LENGTH = 512


def _safe_bundle_path(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_BUNDLE_PATH_LENGTH or value.startswith("/") or "\\" in value or ".." in Path(value).parts or any(ord(char) < 32 for char in value):
        raise RunBundleIngestionError("RunBundle path is unsafe")
    return value


def _read_json(root: Path, relative: str) -> dict[str, Any]:
    _safe_bundle_path(relative)
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise RunBundleIngestionError(f"RunBundle is missing {relative}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RunBundleIngestionError(f"RunBundle artifact is not an object: {relative}")
    return value


def _integrity_status(path: Path, manifest: dict[str, Any]) -> str:
    """Verify producer bytes when possible; never turn producer claims into truth.

    Older alpha fixtures may not carry an immutable checksum manifest.  They
    remain usable as explicitly ``unverified`` references, not authoritative
    results.  A declared but malformed digest map fails closed.
    """
    files = manifest.get("files")
    if files == {}:
        return "unverified"
    if not isinstance(files, dict) or len(files) > 1024:
        raise RunBundleIngestionError("RunBundle file map is malformed")
    if not _REQUIRED_VERIFIED_ARTIFACTS.issubset(files):
        raise RunBundleIngestionError("verified RunBundle does not cover required evidence")
    total_bytes = 0
    for relative, digest in files.items():
        _safe_bundle_path(relative)
        if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise RunBundleIngestionError("RunBundle file map contains an invalid digest")
        target = path / relative
        if target.is_symlink() or not target.is_file():
            raise RunBundleIngestionError("RunBundle artifact is missing or unsafe")
        size = target.stat().st_size
        total_bytes += size
        if size > _MAX_ARTIFACT_BYTES or total_bytes > _MAX_BUNDLE_BYTES:
            raise RunBundleIngestionError("RunBundle artifact volume exceeds ingestion bound")
        if "sha256:" + hashlib.sha256(target.read_bytes()).hexdigest() != digest:
            raise RunBundleIngestionError("RunBundle artifact digest mismatch")
    # RunBundleWriter's canonical JSON deliberately ends with a newline.
    calculated = "sha256:" + hashlib.sha256((json.dumps(files, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")).hexdigest()
    if manifest.get("contentDigest") != calculated:
        raise RunBundleIngestionError("RunBundle content digest mismatch")
    sums = path / "SHA256SUMS"
    if sums.is_symlink() or not sums.is_file():
        raise RunBundleIngestionError("verified RunBundle is missing SHA256SUMS")
    entries: dict[str, str] = {}
    for line in sums.read_text(encoding="utf-8").splitlines():
        digest, marker, relative = line.partition("  ")
        _safe_bundle_path(relative)
        if not marker or not re.fullmatch(r"[0-9a-f]{64}", digest) or relative in entries:
            raise RunBundleIngestionError("RunBundle SHA256SUMS is malformed")
        entries[relative] = digest
    expected = {key: value.removeprefix("sha256:") for key, value in files.items()}
    expected["bundle-manifest.json"] = hashlib.sha256((path / "bundle-manifest.json").read_bytes()).hexdigest()
    if entries != expected:
        raise RunBundleIngestionError("RunBundle SHA256SUMS does not match manifest")
    return "verified"


def ingest_run_bundle(root: str | Path) -> dict[str, Any]:
    """Extract only declared, redacted run evidence into a matrix row."""

    path = Path(root)
    if path.is_symlink() or not path.is_dir():
        raise RunBundleIngestionError("RunBundle root is unsafe")
    walked = 0
    walked_bytes = 0
    for candidate in path.rglob("*"):
        walked += 1
        if walked > 1_024:
            raise RunBundleIngestionError("RunBundle tree exceeds ingestion entry bound")
        if candidate.is_symlink():
            raise RunBundleIngestionError("RunBundle symlink artifacts are forbidden")
        if candidate.is_file():
            walked_bytes += candidate.stat().st_size
            if candidate.stat().st_size > _MAX_ARTIFACT_BYTES or walked_bytes > _MAX_BUNDLE_BYTES:
                raise RunBundleIngestionError("RunBundle tree exceeds ingestion volume bound")
    manifest = _read_json(path, "bundle-manifest.json")
    if manifest.get("formatVersion") != "stateport.run-bundle/v1":
        raise RunBundleIngestionError("unsupported RunBundle format")
    integrity = _integrity_status(path, manifest)
    result = _read_json(path, "execution/result.json")
    engine = _read_json(path, "execution/engine.json")
    negotiation = _read_json(path, "execution/capability-negotiation.json")
    before = _read_json(path, "identities/state-before.json")
    after = _read_json(path, "identities/state-after.json")
    return {
        "formatVersion": "statebench.run-bundle-row/v1",
        "integrityStatus": integrity,
        "authoritative": False,
        "producerClaimsTrusted": False,
        "bundleDigest": manifest.get("contentDigest"),
        "runId": manifest.get("runId"),
        "applicationId": manifest.get("applicationId"),
        "engineId": engine.get("engineId"),
        "adapterId": engine.get("adapterId"),
        "status": manifest.get("status"),
        "statePreserved": before.get("digest") == after.get("digest") or result.get("canonicalStateUnchanged") is True,
        "capabilityDegradations": negotiation.get("degraded", negotiation.get("degradations", [])),
        "acceptedRun": negotiation.get("acceptedRun"),
        "usageAvailable": isinstance(result.get("usage"), dict) or result.get("usageAvailable"),
        "latencyMs": result.get("latencyMs"),
        "unauthorizedMutations": result.get("unauthorizedMutations", 0),
        "bundleFileCount": len(manifest.get("files", {})),
    }


def build_execution_matrix(bundles: Iterable[str | Path]) -> dict[str, Any]:
    rows = sorted((ingest_run_bundle(item) for item in bundles), key=lambda row: (str(row.get("applicationId")), str(row.get("engineId")), str(row.get("runId"))))
    return {
        "formatVersion": "statebench.execution-matrix/v1",
        "applications": sorted({row.get("applicationId") for row in rows}),
        "engines": sorted({row.get("engineId") for row in rows}),
        "rows": rows,
        "scorecards": ["protocol_conformance", "state_preservation", "adapter_conformance", "lifecycle_correctness", "latency", "usage_cost_availability"],
        "qualityScore": None,
        "authoritative": False,
    }
