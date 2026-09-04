#!/usr/bin/env python3
"""Assemble, sign, and verify a ``stateport.release-index/v1`` private candidate.

Assembly is fail-closed: the build receipt, per-image evidence manifests, and
candidate provenance must agree on the exact source commit and tree, every
referenced artifact is re-hashed, and no floating or mutable tag is ever
accepted as release authority.  Signing uses the pinned Cosign executable
with an operator-held key pair that lives outside Git; the public key is
pinned by its SHA-256 DER SubjectPublicKeyInfo fingerprint plus key ID.
Only ``candidate`` qualification can be produced here: ``published`` requires
a transparency-log upload this toolchain deliberately never performs.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Mapping, Sequence
import zipfile

import jsonschema
import yaml

from release_safe_io import (
    prepare_output_root,
    sha256_file,
    write_bytes_create_only,
    write_json_create_only,
)


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages/release-contracts/src"))
from stateport_release import (  # noqa: E402
    CosignVerificationError,
    CosignVerifier,
    PinnedPublicKeyIdentity,
    ReleaseVerificationPolicy,
    SignatureVerifier,
    canonical_digest,
    canonical_json_bytes,
    load_release_index_file,
    public_key_der_spki_fingerprint,
    quadlet_bundle_digest,
    render_quadlet_bundle,
    signature_bundle_name,
    signature_verification_proof_set,
    topology_digest,
    validate_release_index,
    verify_release_index,
)
from stateport_release.contract import (  # noqa: E402
    AuthenticatedPredecessor,
    validate_successor_disposition_transition,
    verify_release_predecessor,
)
from stateport_release.cosign import private_key_der_spki_fingerprint  # noqa: E402
from validate_candidate_provenance import (  # noqa: E402
    CandidateProvenanceError,
    validate_contract as validate_candidate_contract,
)
from release_guard import require_guard  # noqa: E402
from build_release_images import (  # noqa: E402
    ReleaseBuildError,
    oci_archive_manifest_bytes,
    render_pull_compose,
    validate_definitions,
)


TOOLS = ROOT / "config/release-tool-inputs.yaml"
SCAN_EXCEPTIONS = ROOT / "config/release-scan-exceptions.v1.yaml"
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_SEMVER = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


def _semver_key(version: str) -> tuple[int, int, int, int, str]:
    core, _, rest = version.partition("-")
    major, minor, patch = (int(part) for part in core.split("."))
    trailing = re.search(r"(\d+)$", rest)
    return (major, minor, patch, int(trailing.group(1)) if trailing else -1, rest)
_RELEASE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_DIGEST_REFERENCE = re.compile(
    r"^[a-z0-9][a-z0-9._-]*(?::[0-9]{1,5})?(?:/[a-z0-9][a-z0-9._-]*)+@sha256:[0-9a-f]{64}$"
)
_HTTPS_REPOSITORY = re.compile(r"^https://[^\s?#]+(?:\.git)?$")
_ALPHA10_ARTIFACT_IDS = (
    "installer",
    "executionHostProvisioner",
    "updater",
    "compose",
    "quadlet",
    "sourceArchive",
    "releaseNotes",
    "knownLimitations",
)
_ARTIFACT_IDS = (*_ALPHA10_ARTIFACT_IDS, "podmanPackageBundle")
_IMAGE_ARTIFACTS = {
    "cycloneDx": ("{image_id}.cdx.json", "application/vnd.cyclonedx+json"),
    "spdx": ("{image_id}.spdx.json", "application/spdx+json"),
    "packageInventory": ("{image_id}.syft.json", "application/json"),
    "licenseInventory": ("{image_id}.licenses.json", "application/json"),
    "scan": ("{image_id}.grype.json", "application/json"),
    "provenance": ("{image_id}.provenance.json", "application/vnd.in-toto+json"),
}
BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
QUADLET_MEDIA_TYPE = "application/vnd.stateport.quadlet-bundle"
# verify_release_index generates signature proofs inline during the call, so a
# policy clock captured beforehand reads every honest proof as "from the
# future".  Thirty seconds covers proof creation without meaningfully moving
# the hour-scale scan-freshness and expiry boundaries.


class AssemblyError(RuntimeError):
    pass


def _load_yaml(path: Path) -> Mapping[str, Any]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as exc:
        raise AssemblyError(f"release input is not valid UTF-8 YAML: {path}") from exc
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        location = ""
        if mark is not None:
            location = f" at line {mark.line + 1}, column {mark.column + 1}"
        raise AssemblyError(f"release input is invalid YAML{location}: {path}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise AssemblyError(f"release input is not a mapping: {path}")
    return value


def _load_json_file(path: Path, *, maximum_bytes: int = 4 * 1024 * 1024) -> Mapping[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum_bytes:
        raise AssemblyError(f"release input is unsafe: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AssemblyError(f"release input is not valid UTF-8 JSON: {path}") from exc
    if not isinstance(value, Mapping):
        raise AssemblyError(f"release input is not a JSON object: {path}")
    return value


def _read_bounded(path: Path, *, description: str) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_ARTIFACT_BYTES:
        raise AssemblyError(f"{description} is unavailable or unsafe: {path}")
    if path.stat().st_size < 1:
        raise AssemblyError(f"{description} is empty: {path}")
    return path.read_bytes()


def _pinned_cosign() -> str:
    expected = _load_yaml(TOOLS)["tools"]["cosign"]
    path = Path(str(expected["executablePath"]))
    resolved = path.resolve(strict=True)
    if str(resolved) != str(expected["resolvedExecutablePath"]):
        raise AssemblyError("Cosign resolves to an unexpected executable")
    if sha256_file(resolved) != expected["executableDigest"]:
        raise AssemblyError("Cosign executable digest does not match the pinned tool manifest")
    completed = subprocess.run(
        [str(path), "version"],
        check=False,
        capture_output=True,
        text=True,
        # Bounded but generous: the probe is a liveness check whose gate is
        # the version match, not the duration; loaded hosts may stall exec.
        timeout=300,
        shell=False,
        stdin=subprocess.DEVNULL,
    )
    if completed.returncode != 0 or str(expected["version"]) not in completed.stdout:
        raise AssemblyError("Cosign version does not match the pinned tool manifest")
    return str(path)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssemblyError(message)


def _checked_str(value: Any, pattern: re.Pattern[str], description: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise AssemblyError(f"{description} is invalid: {value!r}")
    return value


@dataclass(frozen=True)
class AssemblyRequest:
    build_receipt: Path
    evidence_dir: Path
    candidate_provenance: Path
    topology: Path
    release_id: str
    version: str
    channel: str
    qualification: str
    image_repository: str
    public_snapshot_repository: str
    updater_minimum_version: str
    schema_migration_version: int
    database_migration_version: int
    predecessor_index: Path | None
    rollback_supported: bool
    rollback_minimum_version: str | None
    rollback_data_compatible: bool
    rollback_reason: str
    installer: Path
    execution_host_provisioner: Path
    updater: Path
    source_archive: Path
    release_notes: Path
    known_limitations: Path
    public_export_manifest: Path
    expires_at: str | None
    trust_public_key: Path
    trust_key_id: str
    trust_key_fingerprint: str
    image_bundle_dir: Path
    output_root: Path
    successor_semantics: bool = True
    qualification_at: str | None = None
    podman_package_bundle: Path | None = None


def _artifact_ids_for_version(version: str) -> tuple[str, ...]:
    alpha = re.fullmatch(r"0\.1\.0-alpha\.(\d+)", version)
    if alpha is not None:
        return _ARTIFACT_IDS if int(alpha.group(1)) >= 11 else _ALPHA10_ARTIFACT_IDS
    if re.fullmatch(r"0\.0\.0-j1\.\d+", version) is not None:
        return _ARTIFACT_IDS
    return _ALPHA10_ARTIFACT_IDS


def _load_receipt(path: Path, *, expected_version: str) -> Mapping[str, Any]:
    receipt = _load_json_file(path, maximum_bytes=64 * 1024 * 1024)
    _require(
        receipt.get("formatVersion") == "stateport.release-image-build-receipt/v1",
        "assembly requires a canonical release image build receipt",
    )
    identity = receipt.get("identity")
    _require(isinstance(identity, Mapping), "build receipt has no source identity")
    _require(
        identity.get("version") == expected_version,
        "build receipt version does not equal the requested release version",
    )
    _checked_str(identity.get("commit"), _SHA1, "build receipt source commit")
    _checked_str(identity.get("tree"), _SHA1, "build receipt source tree")
    images = receipt.get("images")
    _require(isinstance(images, Mapping) and bool(images), "build receipt has no images")
    for image_id, image in images.items():
        _checked_str(image_id, _RELEASE_ID, "build receipt image ID")
        _require(isinstance(image, Mapping), f"build receipt image is malformed: {image_id}")
        _checked_str(
            image.get("acceptedReference"), _DIGEST_REFERENCE, f"{image_id} accepted reference"
        )
    return receipt


def _load_candidate(path: Path) -> dict[str, Any]:
    provenance = _load_yaml(path)
    schema_version = provenance.get("schema")
    _require(
        schema_version in {
            "stateport.candidate-provenance/v1",
            "stateport.candidate-provenance/v2",
        },
        "candidate provenance schema is unsupported",
    )
    if schema_version == "stateport.candidate-provenance/v2":
        try:
            schema = json.loads(
                (ROOT / "schemas" / "candidate-provenance.v2.schema.json").read_text(
                    encoding="utf-8"
                )
            )
            jsonschema.Draft202012Validator(schema).validate(provenance)
            validate_candidate_contract(provenance, schema)
        except (OSError, UnicodeError, json.JSONDecodeError, jsonschema.ValidationError) as exc:
            raise AssemblyError(f"candidate provenance schema validation failed: {exc}") from exc
        except CandidateProvenanceError as exc:
            raise AssemblyError(f"candidate provenance verification failed: {exc}") from exc
    materialization = provenance.get("materialization")
    repository = provenance.get("repository")
    artifacts = provenance.get("artifacts")
    _require(
        isinstance(materialization, Mapping)
        and isinstance(repository, Mapping)
        and isinstance(artifacts, Mapping)
        and isinstance(artifacts.get("publicManifest"), Mapping),
        "candidate provenance is missing materialization, repository, or public manifest",
    )
    source_repository = _checked_str(
        materialization.get("sourceRepository"), _HTTPS_REPOSITORY, "candidate source repository"
    )
    source_archive = artifacts.get(
        "sourceArchive" if schema_version == "stateport.candidate-provenance/v2" else "auditedSourceArchive"
    )
    _require(isinstance(source_archive, Mapping), "candidate source archive artifact is missing")
    candidate: dict[str, Any] = {
        "schema": str(schema_version),
        "sourceRepository": source_repository,
        "sourceCommit": _checked_str(
            materialization.get("sourceCommit"), _SHA1, "candidate source commit"
        ),
        "sourceTree": _checked_str(
            materialization.get("sourceTree"), _SHA1, "candidate source tree"
        ),
        "publicSnapshotCommit": _checked_str(
            repository.get("commit"), _SHA1, "public snapshot commit"
        ),
        "publicSnapshotTree": _checked_str(repository.get("tree"), _SHA1, "public snapshot tree"),
        "publicManifestSha256": _checked_str(
            artifacts["publicManifest"].get("sha256"),
            re.compile(r"^[0-9a-f]{64}$"),
            "public export manifest digest",
        ),
        "auditedSourceArchiveSha256": str(source_archive.get("sha256", "")),
        "updaterWheelSha256": str(
            artifacts.get("updaterWheel", {}).get("sha256", "")
            if schema_version == "stateport.candidate-provenance/v2"
            else ""
        ),
        "executionHostProvisionerSha256": str(
            artifacts.get("executionHostProvisioner", {}).get("sha256", "")
            if schema_version == "stateport.candidate-provenance/v2"
            else ""
        ),
        "podmanPackageBundleSha256": str(
            artifacts.get("podmanPackageBundle", {}).get("sha256", "")
            if schema_version == "stateport.candidate-provenance/v2"
            else ""
        ),
    }
    if schema_version == "stateport.candidate-provenance/v2":
        _require(
            isinstance(repository.get("authorityUrl"), str)
            and isinstance(repository.get("ref"), str),
            "v2 candidate provenance has no public authority identity",
        )
        candidate.update(
            {
                "publicAuthorityUrl": repository["authorityUrl"],
                "publicRef": repository["ref"],
                "candidateProvenance": provenance,
                "candidateProvenanceDigest": canonical_digest(provenance),
            }
        )
        for field in ("candidateInputManifest", "releaseTreeManifest"):
            artifact = artifacts.get(field)
            _require(
                isinstance(artifact, Mapping) and isinstance(artifact.get("sha256"), str),
                f"v2 candidate provenance has no {field} digest",
            )
    return candidate


def _receipt_archive_path(build_receipt: Path, authority: Mapping[str, Any]) -> Path:
    """Resolve a retained archive without allowing receipt-relative escapes."""

    raw = authority.get("path")
    _require(isinstance(raw, str) and raw, "retained OCI archive path is missing")
    relative = Path(raw)
    _require(not relative.is_absolute() and ".." not in relative.parts, "retained OCI archive path escapes receipt root")
    root = build_receipt.parent.resolve()
    archive = (build_receipt.parent / relative).resolve()
    _require(archive.is_relative_to(root), "retained OCI archive path escapes receipt root")
    return archive


def _evidence_artifact(
    evidence_dir: Path,
    manifest: Mapping[str, Any],
    image_id: str,
    name_template: str,
    media_type: str,
) -> dict[str, Any]:
    name = name_template.format(image_id=image_id)
    artifacts = manifest.get("artifacts")
    _require(isinstance(artifacts, Mapping), f"evidence for {image_id} has no artifact inventory")
    expected = artifacts.get(name)
    _require(
        isinstance(expected, str) and _DIGEST.fullmatch(expected),
        f"evidence for {image_id} does not record a digest for {name}",
    )
    path = evidence_dir / name
    _require(
        not path.is_symlink() and path.is_file(),
        f"evidence artifact is missing: {name}",
    )
    _require(sha256_file(path) == expected, f"evidence artifact digest drifted: {name}")
    return {
        "uri": f"operator://release/{image_id}/{name}",
        "digest": expected,
        "size": path.stat().st_size,
        "mediaType": media_type,
    }


def _health_evidence_artifact(evidence_dir: Path, image_id: str) -> dict[str, Any]:
    name = f"{image_id}.healthcheck.json"
    path = evidence_dir / name
    _require(
        not path.is_symlink() and path.is_file(),
        f"health probe evidence is missing: {name}",
    )
    evidence = _load_json_file(path, maximum_bytes=1024 * 1024)
    _require(
        evidence.get("formatVersion") == "stateport.release-image-healthcheck/v1",
        f"health evidence for {image_id} is not stateport.release-image-healthcheck/v1",
    )
    _require(
        evidence.get("imageId") == image_id,
        f"health evidence image ID disagrees: {image_id}",
    )
    probe = evidence.get("probeObservation")
    _require(
        isinstance(probe, Mapping) and probe.get("executed") is True,
        f"health probe did not verifiably execute inside {image_id}",
    )
    return {
        "uri": f"operator://release/{image_id}/{name}",
        "digest": sha256_file(path),
        "size": path.stat().st_size,
        "mediaType": "application/json",
    }


def _load_evidence(
    request: AssemblyRequest,
    receipt: Mapping[str, Any],
    candidate: Mapping[str, str],
    image_set: Mapping[str, Any],
) -> dict[str, Mapping[str, Any]]:
    manifests: dict[str, Mapping[str, Any]] = {}
    for image_id, receipt_image in receipt["images"].items():
        path = request.evidence_dir / f"{image_id}.evidence.json"
        _require(path.is_file() and not path.is_symlink(), f"evidence is missing for {image_id}")
        manifest = _load_json_file(path, maximum_bytes=16 * 1024 * 1024)
        _require(
            manifest.get("formatVersion") == "stateport.release-image-evidence/v1",
            f"evidence for {image_id} is not stateport.release-image-evidence/v1",
        )
        _require(manifest.get("imageId") == image_id, f"evidence image ID disagrees: {image_id}")
        reference = _checked_str(
            manifest.get("imageReference"), _DIGEST_REFERENCE, f"{image_id} evidence reference"
        )
        digest = reference.rsplit("@", 1)[-1]
        accepted = str(receipt_image["acceptedReference"])
        _require(
            accepted.rsplit("@", 1)[-1] == digest,
            f"evidence and build receipt digests disagree for {image_id}",
        )
        evidence_candidate = manifest.get("candidate")
        _require(
            isinstance(evidence_candidate, Mapping),
            f"evidence for {image_id} has no candidate identity",
        )
        for field, expected in (
            ("sourceCommit", candidate["sourceCommit"]),
            ("sourceTree", candidate["sourceTree"]),
            ("publicSnapshotCommit", candidate["publicSnapshotCommit"]),
            ("publicSnapshotTree", candidate["publicSnapshotTree"]),
        ):
            _require(
                evidence_candidate.get(field) == expected,
                f"evidence candidate {field} disagrees for {image_id}",
            )
        if candidate["schema"] == "stateport.candidate-provenance/v2":
            for field, expected in (
                ("publicAuthorityUrl", candidate["publicAuthorityUrl"]),
                ("publicRef", candidate["publicRef"]),
            ):
                _require(
                    evidence_candidate.get(field) == expected,
                    f"evidence candidate {field} disagrees for {image_id}",
                )
        scan_policy = manifest.get("scanPolicy")
        _require(
            isinstance(scan_policy, Mapping) and scan_policy.get("result") == "passed",
            f"vulnerability scan did not pass for {image_id}",
        )
        _require(
            scan_policy.get("exceptionsFile") == "config/release-scan-exceptions.v1.yaml"
            and scan_policy.get("exceptionsDigest") == sha256_file(SCAN_EXCEPTIONS),
            f"scan exception policy is not bound to the pinned contract for {image_id}",
        )
        _require(
            isinstance(scan_policy.get("appliedExceptionIds"), list)
            and isinstance(scan_policy.get("unexplainedFindings"), list)
            and not scan_policy["unexplainedFindings"],
            f"scan evaluation for {image_id} is incomplete or unexplained",
        )
        _require(
            image_id in image_set["images"],
            f"{image_id} is not declared by the pinned release image set",
        )
        manifests[image_id] = manifest
    return manifests


def _cross_check_tools(
    manifests: Mapping[str, Mapping[str, Any]],
) -> dict[str, Mapping[str, Any]]:
    pinned = _load_yaml(TOOLS)["tools"]
    observed: dict[str, Mapping[str, Any]] = {}
    for image_id, manifest in manifests.items():
        tools = manifest.get("tools")
        _require(isinstance(tools, Mapping), f"evidence for {image_id} has no toolchain record")
        for name, expected in pinned.items():
            tool = tools.get(name)
            _require(
                isinstance(tool, Mapping),
                f"evidence for {image_id} does not record the pinned tool {name}",
            )
            for field in ("version", "executableDigest", "bottleDigest", "provenance"):
                _require(
                    tool.get(field) == expected[field],
                    f"tool {name} {field} disagrees with the pinned manifest for {image_id}",
                )
            if name in observed and dict(tool) != dict(observed[name]):
                raise AssemblyError(f"tool {name} record disagrees across image evidence")
            observed[name] = tool
    _require(set(observed) == set(pinned), "supply-chain tool inventory is incomplete")
    return {name: pinned[name] for name in sorted(pinned)}


def _bundle_artifact(bundle_dir: Path, name: str, *, uri_prefix: str) -> dict[str, Any]:
    path = bundle_dir / name
    _require(
        path.is_file() and not path.is_symlink(),
        f"Cosign signature bundle is missing: {name}",
    )
    content = _read_bounded(path, description="Cosign signature bundle")
    try:
        bundle = json.loads(content)
    except json.JSONDecodeError as exc:
        raise AssemblyError(f"Cosign signature bundle is not JSON: {name}") from exc
    _require(
        isinstance(bundle, Mapping) and bundle.get("mediaType") == BUNDLE_MEDIA_TYPE,
        f"signature bundle is not a Cosign v0.3 bundle: {name}",
    )
    return {
        "uri": f"{uri_prefix}/{name}",
        "digest": sha256_file(path),
        "size": len(content),
        "mediaType": "application/vnd.sigstore.bundle.v0.3+json",
    }


def _image_signature(
    bundle_dir: Path,
    image_id: str,
    digest: str,
    request: AssemblyRequest,
) -> dict[str, Any]:
    return {
        "scheme": "cosign-v3-bundle",
        "subjectDigest": digest,
        "subjectKind": "oci-manifest-blob",
        "bundle": _bundle_artifact(
            bundle_dir,
            f"{image_id}.sigstore.json",
            uri_prefix=f"operator://release/{image_id}",
        ),
        "trustMode": "pinned-public-key",
        "publicKeyFingerprint": request.trust_key_fingerprint,
        "publicKeyFingerprintAlgorithm": "sha256-canonical-der-spki",
        "publicKeyId": request.trust_key_id,
        "transparencyLog": "not-uploaded-private-candidate",
    }


def _sign_images(
    *,
    build_receipt: Path,
    signing_key: Path,
    receipt: Mapping[str, Any],
    output: Path,
    cosign: str,
) -> None:
    _require(
        signing_key.is_file() and not signing_key.is_symlink(),
        "signing key is unavailable or unsafe",
    )
    _require(
        bool(os.environ.get("COSIGN_PASSWORD")),
        "COSIGN_PASSWORD must be set for non-interactive private-candidate signing",
    )
    for image_id in sorted(receipt["images"]):
        bundle = output / f"{image_id}.sigstore.json"
        _require(not bundle.exists(), f"signature bundle already exists: {bundle.name}")
        authority = receipt["images"][image_id].get("releaseAuthority")
        _require(
            isinstance(authority, Mapping)
            and authority.get("kind") == "retained-oci-archive"
            and isinstance(authority.get("path"), str),
            f"private image signing requires a retained OCI archive for {image_id}",
        )
        archive = _receipt_archive_path(build_receipt, authority)
        _require(
            archive.is_file() and not archive.is_symlink(),
            f"private image signing archive is unavailable for {image_id}",
        )
        try:
            manifest_bytes = oci_archive_manifest_bytes(
                archive, expected_manifest_digest=str(authority.get("manifestDigest", ""))
            )
        except (OSError, ReleaseBuildError, tarfile.TarError, json.JSONDecodeError) as exc:
            raise AssemblyError(f"private image signing archive is invalid for {image_id}: {exc}") from exc
        _require(
            "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
            == str(authority.get("manifestDigest")),
            f"private image signing manifest digest is not archive-bound for {image_id}",
        )
        manifest_path = output / f".{image_id}.oci-manifest.json"
        manifest_path.write_bytes(manifest_bytes)
        try:
            completed = subprocess.run(
                [
                    cosign,
                    "sign-blob",
                    "--use-signing-config=false",
                    "--tlog-upload=false",
                    "--bundle",
                    str(bundle),
                    "--key",
                    str(signing_key),
                    str(manifest_path),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=3600,
                shell=False,
                stdin=subprocess.DEVNULL,
            )
            _require(
                completed.returncode == 0 and bundle.is_file(),
                f"Cosign local manifest signing failed for {image_id}: {completed.stderr.strip()[:300]}",
            )
        finally:
            manifest_path.unlink(missing_ok=True)


def sign_images(
    *,
    build_receipt: Path,
    version: str,
    signing_key: Path,
    trust_public_key: Path,
    trust_key_id: str,
    trust_key_fingerprint: str,
    output_root: Path,
) -> dict[str, Any]:
    """Sign only the retained image manifests into a create-only bundle directory."""

    _checked_str(version, _SEMVER, "release version")
    _checked_str(trust_key_id, _KEY_ID, "trust key ID")
    fingerprint = public_key_der_spki_fingerprint(trust_public_key)
    _require(
        fingerprint == trust_key_fingerprint,
        "trust public key does not match the expected DER SPKI fingerprint",
    )
    _require(
        private_key_der_spki_fingerprint(signing_key, cosign=_pinned_cosign()) == fingerprint,
        "signing key does not derive the pinned trust public key",
    )
    receipt = _load_receipt(build_receipt, expected_version=version)
    image_set = validate_definitions()
    _require(
        set(receipt["images"]) == set(image_set["images"]),
        "image signing requires the complete pinned release image set",
    )
    output = prepare_output_root(output_root, repository=ROOT)
    try:
        _sign_images(
            build_receipt=build_receipt,
            signing_key=signing_key,
            receipt=receipt,
            output=output,
            cosign=_pinned_cosign(),
        )
        bundles = {
            image_id: sha256_file(output / f"{image_id}.sigstore.json")
            for image_id in sorted(receipt["images"])
        }
        write_bytes_create_only(
            output,
            "image-signing-receipt.json",
            canonical_json_bytes(
                {
                    "formatVersion": "stateport.image-signing-receipt/v1",
                    "version": version,
                    "buildReceiptDigest": sha256_file(build_receipt),
                    "trustKeyId": trust_key_id,
                    "trustKeyFingerprint": trust_key_fingerprint,
                    "bundles": bundles,
                }
            )
            + b"\n",
        )
        return {"version": version, "output": str(output), "bundles": bundles}
    except Exception:
        if output.is_dir() and not output.is_symlink():
            shutil.rmtree(output)
        raise


def _local_image_manifest(
    request: AssemblyRequest, receipt: Mapping[str, Any], image_id: str
) -> bytes:
    """Load the exact local OCI manifest used for private image signatures."""

    authority = receipt["images"][image_id].get("releaseAuthority")
    _require(
        isinstance(authority, Mapping)
        and authority.get("kind") == "retained-oci-archive"
        and isinstance(authority.get("path"), str),
        f"private image verification requires a retained OCI archive for {image_id}",
    )
    archive = _receipt_archive_path(request.build_receipt, authority)
    _require(
        archive.is_file() and not archive.is_symlink(),
        f"private image verification archive is unavailable for {image_id}",
    )
    try:
        return oci_archive_manifest_bytes(
            archive, expected_manifest_digest=str(authority.get("manifestDigest", ""))
        )
    except (OSError, ReleaseBuildError, tarfile.TarError, json.JSONDecodeError) as exc:
        raise AssemblyError(f"private image verification archive is invalid for {image_id}: {exc}") from exc


def _validate_grype_database_proof(
    *, image_id: str, database: Mapping[str, Any], scanned_at: str, policy: Mapping[str, Any]
) -> tuple[str, str]:
    """Validate the database freshness classification before it enters the signed index."""
    normal_maximum = int(policy["maxDatabaseAgeHours"])
    latest_maximum = int(policy["maxLatestAvailableDatabaseAgeHours"])
    check_maximum = int(policy["latestDatabaseCheckMaxAgeMinutes"])
    freshness_class = database.get("freshnessClass")
    _require(freshness_class in {"fresh", "latest-available-grace"}, f"{image_id} has an unknown Grype freshness class")
    _require(database.get("valid") is True, f"Grype database for {image_id} is not valid")
    _require(database.get("updateAttempted") is True, f"Grype update was not attempted for {image_id}")
    _require(database.get("normalMaximumAgeHours") == normal_maximum, f"{image_id} normal Grype age policy disagrees")
    _require(database.get("latestAvailableMaximumAgeHours") == latest_maximum, f"{image_id} latest Grype age policy disagrees")
    _require(database.get("latestDatabaseCheckMaxAgeMinutes") == check_maximum, f"{image_id} Grype check lifetime disagrees")
    built_at = _checked_str(database.get("builtAt"), _TIMESTAMP, f"{image_id} Grype database build time")
    observed_at = _checked_str(database.get("databaseObservedAt"), _TIMESTAMP, f"{image_id} Grype database observation time")
    scan_at = _checked_str(scanned_at, _TIMESTAMP, f"{image_id} scan observation time")
    built = datetime.strptime(built_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    observed = datetime.strptime(observed_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    scanned = datetime.strptime(scan_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    age_hours = (observed - built).total_seconds() / 3600
    _require(observed >= built and scanned >= observed, f"{image_id} Grype timestamps are not ordered")
    _require(abs(float(database.get("ageHours", -1)) - round(age_hours, 4)) <= 0.001, f"{image_id} Grype age is not internally consistent")
    _require(0 <= age_hours <= latest_maximum, f"{image_id} Grype database exceeds its absolute age limit")
    check = database.get("latestDatabaseCheck")
    _require(isinstance(check, Mapping), f"{image_id} latest Grype check proof is missing")
    check_observed_at = _checked_str(check.get("observedAt"), _TIMESTAMP, f"{image_id} latest Grype check time")
    check_observed = datetime.strptime(check_observed_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    expected_meaning = "up-to-date-no-newer-database" if check.get("exitCode") == 0 else "newer-database-available" if check.get("exitCode") == 1 else "database-check-failed"
    _require(check.get("meaning") == expected_meaning, f"{image_id} latest Grype check meaning is inconsistent")
    _require(check_observed <= observed, f"{image_id} latest Grype check is from the future")
    if freshness_class == "latest-available-grace":
        _require(age_hours > normal_maximum, f"{image_id} grace class is unnecessary for a fresh database")
        _require(database.get("updateAttempted") is True, f"{image_id} grace proof lacks an update attempt")
        _require(check.get("exitCode") == 0, f"{image_id} grace proof does not prove latest availability")
        _require(check.get("meaning") == "up-to-date-no-newer-database", f"{image_id} grace proof meaning is invalid")
        _require((observed - check_observed).total_seconds() <= check_maximum * 60, f"{image_id} latest Grype check proof is too old")
    else:
        _require(age_hours <= normal_maximum, f"{image_id} fresh class exceeds the normal age limit")
    return built_at, scan_at


def _assemble_images(
    request: AssemblyRequest,
    receipt: Mapping[str, Any],
    manifests: Mapping[str, Mapping[str, Any]],
    image_set: Mapping[str, Any],
    bundle_dir: Path,
) -> list[dict[str, Any]]:
    policy = _load_yaml(TOOLS)["policy"]
    images: list[dict[str, Any]] = []
    for image_id in sorted(manifests):
        manifest = manifests[image_id]
        receipt_image = receipt["images"][image_id]
        set_image = image_set["images"][image_id]
        reference = str(manifest["imageReference"])
        digest = reference.rsplit("@", 1)[-1]
        release_reference = f"{request.image_repository}/{image_id}@{digest}"
        _require(
            _DIGEST_REFERENCE.fullmatch(release_reference) is not None,
            f"release image reference is not digest-bound: {release_reference}",
        )
        authority = receipt_image.get("releaseAuthority")
        _require(
            isinstance(authority, Mapping)
            and isinstance(authority.get("sizeBytes"), int)
            and authority["sizeBytes"] >= 1,
            f"build receipt records no retained image size for {image_id}",
        )
        _require(
            authority.get("manifestDigest") == digest,
            f"retained OCI archive manifest disagrees with the evidence digest for {image_id}",
        )
        role = str(set_image.get("role"))
        _require(
            role in {"runtime-service", "stable-host-service", "optional-profile"},
            f"image set declares an unknown role for {image_id}",
        )
        runtime_user = str(set_image.get("runtimeUser", ""))
        _require(
            runtime_user.split(":", 1)[0].isdigit() and int(runtime_user.split(":", 1)[0]) >= 1,
            f"image set declares an invalid runtime user for {image_id}",
        )
        _require(
            set_image.get("readOnlyRootCompatible") is True,
            f"image set does not prove a read-only root for {image_id}",
        )
        database = manifest.get("grypeDatabase")
        _require(
            isinstance(database, Mapping), f"evidence for {image_id} has no Grype database record"
        )
        # The evidence manifest records the database observation immediately
        # before the scan ran; using it as the scan time is conservative for
        # freshness checks (it can only make the scan appear older).
        scanned_at = _checked_str(database.get("observedAt"), _TIMESTAMP, f"{image_id} scan observation time")
        built_at, scanned_at = _validate_grype_database_proof(
            image_id=image_id,
            database=database,
            scanned_at=scanned_at,
            policy=policy,
        )
        package_inventory = _evidence_artifact(
            request.evidence_dir, manifest, image_id, *_IMAGE_ARTIFACTS["packageInventory"]
        )
        tools = manifest["tools"]["grype"]
        images.append(
            {
                "imageId": image_id,
                "role": role,
                "reference": release_reference,
                "digest": digest,
                "sourceCommit": str(receipt["identity"]["commit"]),
                "sourceTree": str(receipt["identity"]["tree"]),
                "platform": "linux/amd64",
                "sizeBytes": authority["sizeBytes"],
                "runAsUser": int(runtime_user.split(":", 1)[0]),
                "readOnlyRoot": True,
                "healthProbe": {
                    "executable": "/usr/local/bin/stateport-healthcheck",
                    "protocol": "stateport-healthcheck/v1",
                    "packageInventoryDigest": package_inventory["digest"],
                    "evidence": _health_evidence_artifact(request.evidence_dir, image_id),
                },
                "sboms": {
                    "cycloneDx": _evidence_artifact(
                        request.evidence_dir, manifest, image_id, *_IMAGE_ARTIFACTS["cycloneDx"]
                    ),
                    "spdx": _evidence_artifact(
                        request.evidence_dir, manifest, image_id, *_IMAGE_ARTIFACTS["spdx"]
                    ),
                },
                "scan": {
                    "artifact": _evidence_artifact(
                        request.evidence_dir, manifest, image_id, *_IMAGE_ARTIFACTS["scan"]
                    ),
                    "tool": "grype",
                    "toolVersion": str(tools["version"]),
                    "databaseBuiltAt": built_at,
                    "scannedAt": scanned_at,
                    "maxDatabaseAgeHours": int(policy["maxDatabaseAgeHours"]),
                    "maxScanAgeHours": int(policy["maxScanAgeHours"]),
                    "policy": "stateport.grype-policy/v1",
                },
                "provenance": _evidence_artifact(
                    request.evidence_dir, manifest, image_id, *_IMAGE_ARTIFACTS["provenance"]
                ),
                "signature": _image_signature(bundle_dir, image_id, digest, request),
                "packageInventory": package_inventory,
                "licenseInventory": _evidence_artifact(
                    request.evidence_dir, manifest, image_id, *_IMAGE_ARTIFACTS["licenseInventory"]
                ),
            }
        )
    return images


def _assemble_targets(
    request: AssemblyRequest,
    images: Sequence[Mapping[str, Any]],
    topology: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    targets = topology.get("targets")
    _require(
        isinstance(targets, list) and 1 <= len(targets) <= 16,
        "topology must declare 1..16 targets",
    )
    image_by_id = {str(image["imageId"]): image for image in images}
    assembled: list[dict[str, Any]] = []
    bundle_files: dict[str, bytes] = {}
    for entry in targets:
        _require(isinstance(entry, Mapping), "topology target is not a mapping")
        _require(
            not (
                {"releaseId", "artifactIds", "topologyDigest", "quadletBundleDigest"} & set(entry)
            ),
            "topology must not pre-compute assembler-owned fields",
        )
        target_id = _checked_str(entry.get("targetId"), _RELEASE_ID, "topology target ID")
        execution_mode = str(entry.get("executionHostMode"))
        _require(
            execution_mode
            in {"none", "stable-host-daemon-client", "stable-host-daemon-bootstrap-only"},
            f"topology target {target_id} has an unknown execution host mode",
        )
        services = entry.get("services")
        _require(
            isinstance(services, list) and services,
            f"topology target {target_id} has no services",
        )
        for service in services:
            _require(isinstance(service, Mapping), f"topology service is malformed: {target_id}")
            image = image_by_id.get(str(service.get("imageId")))
            _require(
                image is not None and image["role"] == "runtime-service",
                f"topology service {service.get('serviceId')} names a missing or non-runtime image",
            )
            _require(
                service.get("runAsUser") == image["runAsUser"]
                and service.get("readOnlyRoot") == image["readOnlyRoot"],
                f"topology service {service.get('serviceId')} execution identity disagrees "
                "with its image",
            )
        host_services = entry.get("hostServices", [])
        _require(
            isinstance(host_services, list),
            f"topology target {target_id} host services are malformed",
        )
        for host_service in host_services:
            _require(
                isinstance(host_service, Mapping),
                f"topology host service is malformed: {target_id}",
            )
            image = image_by_id.get(str(host_service.get("imageId")))
            _require(
                image is not None and image["role"] == "stable-host-service",
                f"topology host service {host_service.get('serviceId')} names a missing "
                "or non-host image",
            )
            _require(
                host_service.get("runAsUser") == image["runAsUser"]
                and host_service.get("readOnlyRoot") == image["readOnlyRoot"],
                f"topology host service {host_service.get('serviceId')} execution identity "
                "disagrees with its image",
            )
        execution_contract = entry.get("executionContract")
        if execution_contract is not None:
            _require(
                isinstance(execution_contract, Mapping),
                f"topology target {target_id} execution contract is malformed",
            )
            contract_image = image_by_id.get(str(execution_contract.get("imageId")))
            _require(
                contract_image is not None and contract_image["role"] == "stable-host-service",
                f"topology target {target_id} execution contract names a missing or non-host image",
            )
            if execution_contract.get("imageDigest") is None:
                # The digest is knowable only after the double build; the
                # assembler binds it to the exact signed stable-host image.
                execution_contract = {
                    **execution_contract,
                    "imageDigest": contract_image["digest"],
                }
            _require(
                execution_contract["imageDigest"] == contract_image["digest"],
                f"topology target {target_id} execution contract digest disagrees "
                "with the signed image",
            )
        target: dict[str, Any] = {
            "targetId": target_id,
            "releaseId": request.release_id,
            "releaseEligibility": (
                "bootstrap-only"
                if execution_mode == "stable-host-daemon-bootstrap-only"
                else "release-candidate"
            ),
            "os": "linux",
            "architecture": "amd64",
            "hostBaseline": str(entry.get("hostBaseline", target_id)),
            "cgroupVersion": "v2",
            "containerEngine": "rootless-podman-quadlet",
            "executionHostMode": execution_mode,
            "executionContract": execution_contract,
            "hostServices": entry.get("hostServices", []),
            "sharedWritableVolumes": entry.get("sharedWritableVolumes", []),
            "runtimeDerivation": entry.get("runtimeDerivation"),
            "artifactIds": sorted(_artifact_ids_for_version(request.version)),
            "services": services,
        }
        target["topologyDigest"] = topology_digest(target)
        files = render_quadlet_bundle(target, images)
        target["quadletBundleDigest"] = quadlet_bundle_digest(files)
        prefix = f"{target_id}/"
        for name, content in files.items():
            key = prefix + name
            _require(key not in bundle_files, f"quadlet bundle path collision: {key}")
            bundle_files[key] = content
        assembled.append(target)
    return assembled, bundle_files


def _preflight_topology(topology: Mapping[str, Any]) -> None:
    """Reject structural topology errors before evidence or signing work."""

    _require(
        topology.get("formatVersion") == "stateport.release-topology/v1",
        "topology formatVersion is unsupported",
    )
    _require(
        set(topology).issubset({"formatVersion", "description", "targets"}),
        "topology contains unknown top-level fields",
    )
    targets = topology.get("targets")
    _require(
        isinstance(targets, list) and 1 <= len(targets) <= 16,
        "topology must declare 1..16 targets",
    )
    target_ids: set[str] = set()
    target_fields = {
        "targetId", "hostBaseline", "executionHostMode", "executionContract", "hostServices",
        "sharedWritableVolumes", "runtimeDerivation", "services",
    }
    service_fields = {
        "serviceId", "imageId", "trustDomain", "quadletOwner", "revisionScoped",
        "runAsUser", "readOnlyRoot", "health", "ports", "writableVolumes",
        "resources", "capabilities",
    }
    host_service_fields = service_fields | {
        "engineAccess", "socket", "lifecycle", "userNamespace", "logging",
        "updateCompatibility",
    }
    for entry in targets:
        _require(isinstance(entry, Mapping), "topology target is not a mapping")
        _require(
            set(entry).issubset(target_fields),
            f"topology target {entry.get('targetId')} contains unknown fields",
        )
        _require(
            not ({"releaseId", "artifactIds", "topologyDigest", "quadletBundleDigest"} & set(entry)),
            "topology must not pre-compute assembler-owned fields",
        )
        target_id = _checked_str(entry.get("targetId"), _RELEASE_ID, "topology target ID")
        _require(target_id not in target_ids, f"topology target {target_id} is duplicated")
        target_ids.add(target_id)
        execution_mode = entry.get("executionHostMode")
        _require(
            execution_mode
            in {"none", "stable-host-daemon-client", "stable-host-daemon-bootstrap-only"},
            f"topology target {target_id} has an unknown execution host mode",
        )
        services = entry.get("services")
        _require(
            isinstance(services, list) and services,
            f"topology target {target_id} has no services",
        )
        _require(
            all(isinstance(service, Mapping) for service in services),
            f"topology target {target_id} has a malformed service",
        )
        for service in services:
            _require(
                set(service).issubset(service_fields),
                f"topology target {target_id} service contains unknown fields",
            )
        host_services = entry.get("hostServices", [])
        _require(
            isinstance(host_services, list)
            and all(isinstance(service, Mapping) for service in host_services),
            f"topology target {target_id} has malformed host services",
        )
        for service in host_services:
            _require(
                set(service).issubset(host_service_fields),
                f"topology target {target_id} host service contains unknown fields",
            )
        if "executionContract" in entry:
            _require(
                isinstance(entry["executionContract"], Mapping),
                f"topology target {target_id} execution contract is malformed",
            )


def _retained_artifact(
    source: Path,
    output: Path,
    *,
    relative: str,
    artifact_id: str,
    media_type: str,
    expected_digest: str | None = None,
) -> dict[str, Any]:
    content = _read_bounded(source, description=f"{artifact_id} artifact")
    retained = write_bytes_create_only(output, relative, content)
    digest = sha256_file(retained)
    if expected_digest is not None:
        _require(
            digest == expected_digest,
            f"{artifact_id} does not match its provenance-recorded digest",
        )
    return {
        "uri": f"operator://release/{relative}",
        "digest": digest,
        "size": len(content),
        "mediaType": media_type,
    }


def _updater_wheel_version(path: Path) -> str:
    try:
        with zipfile.ZipFile(path) as wheel:
            metadata = [
                name
                for name in wheel.namelist()
                if name.count("/") == 1 and name.endswith(".dist-info/METADATA")
            ]
            _require(len(metadata) == 1, "updater wheel metadata is ambiguous")
            metadata_path = metadata[0]
            text = wheel.read(metadata_path).decode("utf-8")
    except (OSError, UnicodeError, zipfile.BadZipFile) as exc:
        raise AssemblyError("updater wheel metadata is unreadable") from exc
    versions = [line.removeprefix("Version: ") for line in text.splitlines() if line.startswith("Version: ")]
    names = [line.removeprefix("Name: ") for line in text.splitlines() if line.startswith("Name: ")]
    _require(names == ["stateport-updater"], "updater wheel project name is invalid")
    _require(len(versions) == 1, "updater wheel version is missing")
    _checked_str(versions[0], _SEMVER, "updater wheel version")
    _require(
        metadata_path.split("/", 1)[0] == f"stateport_updater-{versions[0]}.dist-info",
        "updater wheel metadata directory does not match its name and version",
    )
    return versions[0]


def _assemble_artifacts(
    request: AssemblyRequest,
    candidate: Mapping[str, str],
    output: Path,
    targets: Sequence[Mapping[str, Any]],
    bundle_files: Mapping[str, bytes],
    images: Sequence[Mapping[str, Any]],
    image_set: Mapping[str, Any],
) -> dict[str, Any]:
    if len(targets) != 1:
        raise AssemblyError("this toolchain assembles exactly one target per release index")
    artifacts: dict[str, Any] = {
        "installer": _retained_artifact(
            request.installer,
            output,
            relative="artifacts/installer",
            artifact_id="installer",
            media_type="application/octet-stream",
        ),
        "executionHostProvisioner": _retained_artifact(
            request.execution_host_provisioner,
            output,
            relative="artifacts/executionHostProvisioner",
            artifact_id="execution-host provisioner",
            media_type="application/octet-stream",
            expected_digest=(
                "sha256:" + candidate["executionHostProvisionerSha256"]
                if candidate["executionHostProvisionerSha256"]
                else None
            ),
        ),
        "updater": _retained_artifact(
            request.updater,
            output,
            relative="artifacts/updater",
            artifact_id="updater",
            media_type="application/octet-stream",
            expected_digest=(
                "sha256:" + candidate["updaterWheelSha256"]
                if candidate["updaterWheelSha256"]
                else None
            ),
        ),
        "sourceArchive": _retained_artifact(
            request.source_archive,
            output,
            relative="artifacts/sourceArchive",
            artifact_id="source archive",
            media_type="application/octet-stream",
            expected_digest=(
                "sha256:" + candidate["auditedSourceArchiveSha256"]
                if candidate["auditedSourceArchiveSha256"]
                else None
            ),
        ),
        "releaseNotes": _retained_artifact(
            request.release_notes,
            output,
            relative="artifacts/releaseNotes",
            artifact_id="release notes",
            media_type="text/markdown",
        ),
        "knownLimitations": _retained_artifact(
            request.known_limitations,
            output,
            relative="artifacts/knownLimitations",
            artifact_id="known limitations",
            media_type="text/markdown",
        ),
    }
    if "podmanPackageBundle" in _artifact_ids_for_version(request.version):
        _require(
            request.podman_package_bundle is not None,
            "successor package bundle input is missing",
        )
        artifacts["podmanPackageBundle"] = _retained_artifact(
            request.podman_package_bundle,
            output,
            relative="artifacts/podmanPackageBundle",
            artifact_id="Podman package bundle",
            media_type="application/vnd.stateport.podman-package-bundle+tar",
            expected_digest=(
                "sha256:" + candidate["podmanPackageBundleSha256"]
                if candidate["podmanPackageBundleSha256"]
                else None
            ),
        )
    compose_references = {
        str(image["imageId"]): str(image["reference"])
        for image in images
        if isinstance(image_set["images"][str(image["imageId"])].get("pullCompose"), Mapping)
        and image_set["images"][str(image["imageId"])]["pullCompose"].get("enabled")
    }
    compose = render_pull_compose(compose_references)
    compose_path = write_bytes_create_only(output, "compose.release.yaml", compose.encode("utf-8"))
    artifacts["compose"] = {
        "uri": "operator://release/compose.release.yaml",
        "digest": sha256_file(compose_path),
        "size": compose_path.stat().st_size,
        "mediaType": "application/yaml",
    }
    quadlet_size = 0
    for name, content in sorted(bundle_files.items()):
        write_bytes_create_only(output, f"quadlet/{name}", content)
        quadlet_size += len(content)
    artifacts["quadlet"] = {
        "uri": "operator://release/quadlet",
        "digest": targets[0]["quadletBundleDigest"],
        "size": quadlet_size,
        "mediaType": QUADLET_MEDIA_TYPE,
    }
    return artifacts


def _assemble_supply_chain(
    request: AssemblyRequest,
    candidate: Mapping[str, str],
    manifests: Mapping[str, Mapping[str, Any]],
    tools: Mapping[str, Mapping[str, Any]],
    output: Path,
) -> dict[str, Any]:
    tool_entries: list[dict[str, Any]] = []
    for name, pinned in tools.items():
        record = {
            "formatVersion": "stateport.release-tool-provenance/v1",
            "name": name,
            "version": str(pinned["version"]),
            "executableDigest": str(pinned["executableDigest"]),
            "bottleDigest": str(pinned["bottleDigest"]),
            "bottleUri": str(pinned["bottleUri"]),
            "provenance": str(pinned["provenance"]),
        }
        path = write_json_create_only(output, f"supply-chain/{name}.tool-provenance.json", record)
        tool_entries.append(
            {
                "name": name,
                "version": str(pinned["version"]),
                "executableDigest": str(pinned["executableDigest"]),
                "provenance": {
                    "uri": f"operator://release/supply-chain/{name}.tool-provenance.json",
                    "digest": sha256_file(path),
                    "size": path.stat().st_size,
                    "mediaType": "application/json",
                },
            }
        )
    comparison = {
        "formatVersion": "stateport.release-double-build-comparison/v1",
        "interpretation": "exact independently observed OCI registry digest match per image",
        "images": {
            image_id: manifest["doubleBuild"] for image_id, manifest in sorted(manifests.items())
        },
    }
    comparison_path = write_json_create_only(
        output, "supply-chain/double-build-comparison.json", comparison
    )
    return {
        "tools": tool_entries,
        "doubleBuildComparison": {
            "uri": "operator://release/supply-chain/double-build-comparison.json",
            "digest": sha256_file(comparison_path),
            "size": comparison_path.stat().st_size,
            "mediaType": "application/json",
        },
        "publicExportManifest": _retained_artifact(
            request.public_export_manifest,
            output,
            relative="supply-chain/public-export-manifest.json",
            artifact_id="public export manifest",
            media_type="application/json",
            expected_digest="sha256:" + candidate["publicManifestSha256"],
        ),
    }


def _authenticate_predecessor(
    request: AssemblyRequest, index_path: Path
) -> AuthenticatedPredecessor:
    predecessor_index = load_release_index_file(index_path, legacy_predecessor=True)
    identity = PinnedPublicKeyIdentity(request.trust_key_fingerprint, request.trust_key_id)
    with tempfile.TemporaryDirectory(prefix="stateport-predecessor-bundles-") as retained:
        retained_root = Path(retained)
        retained_root.chmod(0o700)
        verifier = CosignVerifier(
            cosign=Path(_pinned_cosign()),
            public_key=request.trust_public_key,
            identity=identity,
            bundle_root=retained_root,
        )
        for signature in predecessor_index.document["signatures"]:
            source = index_path.parent / signature_bundle_name(signature)
            verifier.retain_bundle(source, signature)
        authenticated = verify_release_predecessor(
            predecessor_index,
            expected_trust_mode="pinned-public-key",
            accepted_public_keys=frozenset({identity}),
            verifier=verifier,
            legacy_predecessor=True,
        )
    return authenticated


def _assemble_compatibility(
    request: AssemblyRequest,
) -> tuple[dict[str, Any], AuthenticatedPredecessor | None]:
    predecessor = None
    authenticated: AuthenticatedPredecessor | None = None
    if request.predecessor_index is not None:
        if request.successor_semantics:
            authenticated = _authenticate_predecessor(request, request.predecessor_index)
            index = authenticated.index
        else:
            index = load_release_index_file(request.predecessor_index)
        predecessor = {
            "releaseId": str(index.document["signed"]["release"]["releaseId"]),
            "version": str(index.document["signed"]["release"]["version"]),
            "signedPayloadDigest": index.signed_digest,
        }
        # The updater's exact-predecessor contract compares releaseId AND
        # signedPayloadDigest against the installed release, so a successor in
        # the same release lane legitimately embeds a predecessor with the
        # same releaseId (qualification lane 900001 does this by design).
        # What distinguishes an embedded predecessor from an accidental
        # self-reference is the older semantic version, not the lane identity.
        _require(
            _SEMVER.fullmatch(predecessor["version"]) is not None
            and _SEMVER.fullmatch(request.version) is not None,
            "predecessor and successor versions must be semantic versions",
        )
        _require(
            _semver_key(predecessor["version"]) < _semver_key(request.version),
            "predecessor must be an older release than the successor",
        )
    if request.rollback_supported:
        _require(predecessor is not None, "rollback support requires an exact predecessor")
    if request.rollback_minimum_version is not None:
        _require(
            _SEMVER.fullmatch(request.rollback_minimum_version) is not None,
            "rollback minimum predecessor version is not semantic versioning",
        )
    return (
        {
            "updaterMinimumVersion": request.updater_minimum_version,
            "schemaMigrationVersion": request.schema_migration_version,
            "databaseMigrationVersion": request.database_migration_version,
            "predecessor": predecessor,
            "rollback": {
                "supported": request.rollback_supported,
                "minimumPredecessorVersion": request.rollback_minimum_version,
                "dataCompatible": request.rollback_data_compatible,
                "reason": request.rollback_reason,
            },
        },
        authenticated,
    )


def _validate_request(request: AssemblyRequest) -> None:
    _checked_str(request.release_id, _RELEASE_ID, "release ID")
    _checked_str(request.version, _SEMVER, "release version")
    _require(request.channel in {"alpha", "stable", "owner-dogfood"}, "unknown release channel")
    _require(
        request.qualification == "candidate",
        "published releases require a transparency-log upload and are refused by this toolchain",
    )
    _require(
        request.successor_semantics,
        "release assembly requires the explicitly versioned successor contract",
    )
    if request.qualification_at is not None:
        _checked_str(request.qualification_at, _TIMESTAMP, "qualification time")
    _checked_str(request.updater_minimum_version, _SEMVER, "updater minimum version")
    _require(
        request.updater_minimum_version == _updater_wheel_version(request.updater),
        "updater minimum version must equal the bundled updater wheel version",
    )
    expects_package_bundle = "podmanPackageBundle" in _artifact_ids_for_version(
        request.version
    )
    _require(
        (request.podman_package_bundle is not None) == expects_package_bundle,
        "release version and Podman package bundle inventory disagree",
    )
    _require(
        request.schema_migration_version >= 0 and request.database_migration_version >= 0,
        "migration versions must be non-negative",
    )
    _require(1 <= len(request.rollback_reason) <= 1024, "rollback reason is missing or too long")
    if request.expires_at is not None:
        _checked_str(request.expires_at, _TIMESTAMP, "release expiry")
    _checked_str(
        request.public_snapshot_repository, _HTTPS_REPOSITORY, "public snapshot repository"
    )
    _checked_str(request.trust_key_id, _KEY_ID, "trust key ID")
    _checked_str(
        request.trust_key_fingerprint,
        re.compile(r"^sha256:[0-9a-f]{64}$"),
        "trust key fingerprint",
    )
    observed = public_key_der_spki_fingerprint(request.trust_public_key)
    _require(
        observed == request.trust_key_fingerprint,
        "trust public key does not match the pinned DER SPKI fingerprint "
        "(the fingerprint is SHA-256 over the DER SubjectPublicKeyInfo, not the PEM file bytes)",
    )
    _require(
        isinstance(request.image_bundle_dir, Path)
        and request.image_bundle_dir.is_dir()
        and not request.image_bundle_dir.is_symlink(),
        "assembly requires a separate, completed image-signing output directory",
    )


def _check_scan_freshness_at(images: Sequence[Mapping[str, Any]], observed_at: datetime) -> None:
    for image in images:
        scan = image["scan"]
        database_built = datetime.strptime(scan["databaseBuiltAt"], "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
        scanned_at = datetime.strptime(scan["scannedAt"], "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
        _require(
            database_built <= observed_at and scanned_at <= observed_at,
            f"{image['imageId']} scan evidence is from the future at qualification",
        )
        _require(
            (observed_at - database_built).total_seconds() <= scan["maxDatabaseAgeHours"] * 3600,
            f"{image['imageId']} Grype database is stale at signing/qualification time",
        )
        _require(
            (observed_at - scanned_at).total_seconds() <= image["scan"]["maxScanAgeHours"] * 3600,
            f"{image['imageId']} vulnerability scan is stale at signing/qualification time",
        )


def _check_qualification_timestamp_at(
    successor: Mapping[str, Any], images: Sequence[Mapping[str, Any]], observed_at: datetime
) -> None:
    qualified_at = datetime.strptime(
        successor["qualificationEvent"]["qualifiedAt"], "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=timezone.utc)
    _require(
        qualified_at <= observed_at,
        "successor qualification event is from the future at signing",
    )
    maximum_age_hours = min(int(image["scan"]["maxScanAgeHours"]) for image in images)
    _require(
        (observed_at - qualified_at).total_seconds() <= maximum_age_hours * 3600,
        "successor qualification event is stale at signing",
    )


def _canonicalize_qualification_event(event: Mapping[str, Any]) -> dict[str, Any]:
    value = dict(event)
    observations = value.get("images")
    _require(
        isinstance(observations, Sequence) and not isinstance(observations, (str, bytes)),
        "qualification event image observations are missing",
    )
    observations = list(observations)
    _require(
        all(
            isinstance(item, Mapping) and isinstance(item.get("imageId"), str)
            for item in observations
        ),
        "qualification event image observations must be typed",
    )
    image_ids = [
        item["imageId"]
        for item in observations
    ]
    _require(
        len(image_ids) == len(set(image_ids)),
        "qualification event image observations must be unique and typed",
    )
    value["images"] = sorted(
        (dict(item) for item in observations), key=lambda item: item["imageId"]
    )
    value["eventId"] = canonical_digest(
        {key: item for key, item in value.items() if key != "eventId"}
    )
    return value


def _successor_semantics(
    request: AssemblyRequest,
    images: Sequence[Mapping[str, Any]],
    authenticated_predecessor: AuthenticatedPredecessor | None,
    qualification_event: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    _require(request.successor_semantics, "release assembly requires successor semantics")
    if qualification_event is None:
        _require(
            request.qualification_at is not None,
            "deterministic release assembly requires an explicit qualification time or event",
        )
        qualified_at = datetime.strptime(request.qualification_at, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
        _check_scan_freshness_at(images, qualified_at)
        event: dict[str, Any] = {
            "formatVersion": "stateport.release-qualification/v1",
            "releaseId": request.release_id,
            "version": request.version,
            "qualifiedAt": qualified_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "result": "qualified",
            "freshnessBasis": "scan-and-database-checked-at-qualification",
            "images": [
                {
                    "imageId": image["imageId"],
                    "digest": image["digest"],
                    "databaseBuiltAt": image["scan"]["databaseBuiltAt"],
                    "scannedAt": image["scan"]["scannedAt"],
                }
                for image in sorted(images, key=lambda item: item["imageId"])
            ],
        }
        event = _canonicalize_qualification_event(event)
    else:
        event = _canonicalize_qualification_event(qualification_event)

    predecessor_document = (
        None
        if authenticated_predecessor is None
        else authenticated_predecessor.index.document
    )
    predecessor_successor = (
        None
        if predecessor_document is None
        else predecessor_document["signed"].get("successor")
    )
    sequence = 1 if predecessor_successor is None else predecessor_successor["disposition"]["sequence"] + 1
    previous_disposition_digest = (
        None
        if predecessor_successor is None
        else canonical_digest(predecessor_successor["disposition"])
    )
    disposition = {
        "formatVersion": "stateport.release-disposition/v2",
        "signedBy": "stateport.release-index/v1",
        "sequence": sequence,
        "status": "active",
        "at": None,
        "reason": None,
        "previousDispositionDigest": previous_disposition_digest,
    }
    predecessor_claim = None
    if authenticated_predecessor is not None:
        predecessor_index = authenticated_predecessor.index
        predecessor_claim = {
            "formatVersion": "stateport.release-predecessor/v1",
            "releaseId": predecessor_index.release_id,
            "version": predecessor_index.version,
            "signedPayloadDigest": predecessor_index.signed_digest,
            "indexDigest": predecessor_index.index_digest,
            "signature": dict(authenticated_predecessor.signature),
            "rawIndex": json.loads(predecessor_index.canonical_index_bytes),
        }
    successor = {
        "formatVersion": "stateport.release-successor/v1",
        "freshnessEnforcement": "qualification-and-signing-time",
        "qualificationEvent": event,
        "disposition": disposition,
        "predecessor": predecessor_claim,
        "versionBindings": {
            "releaseVersion": request.version,
            "buildReceiptFormatVersion": "stateport.release-image-build-receipt/v1",
            "buildReceiptVersion": request.version,
            "imageEvidenceFormatVersion": "stateport.release-image-evidence/v1",
            "qualificationEventFormatVersion": "stateport.release-qualification/v1",
        },
    }
    validate_successor_disposition_transition(
        None if predecessor_successor is None else predecessor_successor,
        successor,
    )
    return successor


def _assemble_signed(
    request: AssemblyRequest,
    output: Path,
    *,
    qualification_event: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    _validate_request(request)
    # Parse topology before receipts, evidence, image assembly, or signing so a
    # malformed release contract fails at the cheap input boundary.
    topology = _load_yaml(request.topology)
    _preflight_topology(topology)
    receipt = _load_receipt(request.build_receipt, expected_version=request.version)
    candidate = _load_candidate(request.candidate_provenance)
    if candidate["schema"] == "stateport.candidate-provenance/v2":
        _require(
            request.public_snapshot_repository == candidate["publicAuthorityUrl"],
            "requested public snapshot repository disagrees with v2 candidate authority",
        )
    identity = receipt["identity"]
    _require(
        identity["commit"] == candidate["sourceCommit"]
        and identity["tree"] == candidate["sourceTree"],
        "build receipt source identity does not match candidate provenance",
    )
    image_set = validate_definitions()
    manifests = _load_evidence(request, receipt, candidate, image_set)
    tools = _cross_check_tools(manifests)
    references = {
        image_id: f"{request.image_repository}/{image_id}@"
        + str(manifest["imageReference"]).rsplit("@", 1)[-1]
        for image_id, manifest in manifests.items()
    }
    bundle_dir = request.image_bundle_dir
    _require(
        bundle_dir.is_dir() and not bundle_dir.is_symlink(),
        "image bundle directory is unavailable or unsafe",
    )
    images = _assemble_images(request, receipt, manifests, image_set, bundle_dir)
    for image in images:
        image_id = str(image["imageId"])
        bundle_name = signature_bundle_name(image["signature"])
        write_bytes_create_only(
            output,
            f"image-bundles/{bundle_name}",
            _read_bounded(bundle_dir / bundle_name, description=f"{image_id} image signature bundle"),
        )
    targets, bundle_files = _assemble_targets(request, images, topology)
    artifacts = _assemble_artifacts(
        request, candidate, output, targets, bundle_files, images, image_set
    )
    supply_chain = _assemble_supply_chain(request, candidate, manifests, tools, output)
    compatibility, authenticated_predecessor = _assemble_compatibility(request)
    return {
        "release": {
            "releaseId": request.release_id,
            "version": request.version,
            "channel": request.channel,
            "qualification": "candidate",
        },
        "source": {
            "repository": candidate["sourceRepository"],
            "commit": str(identity["commit"]),
            "tree": str(identity["tree"]),
            "dirty": False,
            "publicSnapshot": {
                "repository": (
                    candidate["publicAuthorityUrl"]
                    if candidate["schema"] == "stateport.candidate-provenance/v2"
                    else request.public_snapshot_repository
                ),
                "commit": candidate["publicSnapshotCommit"],
                "tree": candidate["publicSnapshotTree"],
                "manifestDigest": "sha256:" + candidate["publicManifestSha256"],
                **(
                    {
                        "authorityUrl": candidate["publicAuthorityUrl"],
                        "ref": candidate["publicRef"],
                    }
                    if candidate["schema"] == "stateport.candidate-provenance/v2"
                    else {}
                ),
            },
            **(
                {
                    "candidateProvenance": {
                        "schema": candidate["schema"],
                        "digest": candidate["candidateProvenanceDigest"],
                        "document": candidate["candidateProvenance"],
                    }
                }
                if candidate["schema"] == "stateport.candidate-provenance/v2"
                else {}
            ),
        },
        "targets": targets,
        "artifacts": artifacts,
        "images": images,
        "signaturePolicy": {
            "trustMode": "pinned-public-key",
            "imageSignaturesRequired": True,
            "verificationProof": "stateport.signature-verification-proof/v1",
        },
        "supplyChain": supply_chain,
        "compatibility": compatibility,
        "publication": {
            "publishedAt": None,
            "expiresAt": request.expires_at,
            "deprecation": {"status": "active", "at": None, "reason": None},
        },
        "successor": _successor_semantics(
            request,
            images,
            authenticated_predecessor,
            qualification_event,
        ),
    }


def _validate_packaged_consumer(index_bytes: bytes, updater_wheel: Path) -> None:
    """Require the exact release-contract package shipped in the updater wheel."""
    _require(updater_wheel.is_file() and not updater_wheel.is_symlink(), "updater wheel is unavailable")
    with tempfile.TemporaryDirectory(prefix="stateport-packaged-consumer-") as temporary:
        root = Path(temporary)
        package_root = root / "package"
        package_root.mkdir(mode=0o700)
        try:
            with zipfile.ZipFile(updater_wheel) as archive:
                members = archive.infolist()
                for member in members:
                    member_path = PurePosixPath(member.filename)
                    if member_path.is_absolute() or ".." in member_path.parts:
                        raise AssemblyError("updater wheel contains an unsafe path")
                    archive.extract(member, package_root)
        except (OSError, zipfile.BadZipFile) as exc:
            raise AssemblyError("updater wheel cannot be inspected for its packaged consumer") from exc
        index_path = root / "release-index.json"
        index_path.write_bytes(index_bytes)
        probe = (
            "from pathlib import Path; import sys; sys.path.insert(0, sys.argv[1]); "
            "from stateport_release import load_release_index_file; "
            "load_release_index_file(Path(sys.argv[2]), require_signatures=False)"
        )
        completed = subprocess.run(
            [sys.executable, "-I", "-c", probe, str(package_root), str(index_path)],
            check=False,
            capture_output=True,
            text=True,
            env={"PATH": os.environ.get("PATH", "")},
        )
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip().splitlines()
            raise AssemblyError(
                "exact packaged release consumer rejected the unsigned index"
                + (f": {detail[-1][:300]}" if detail else "")
            )


def assemble(request: AssemblyRequest) -> dict[str, Any]:
    output = prepare_output_root(request.output_root, repository=ROOT)
    signed = _assemble_signed(request, output)
    predecessor = signed["successor"]["predecessor"]
    if predecessor is not None:
        _require(request.predecessor_index is not None, "successor predecessor input is missing")
        bundle_name = signature_bundle_name(predecessor["signature"])
        bundle = request.predecessor_index.parent / bundle_name
        write_bytes_create_only(
            output,
            f"predecessor-bundle/{bundle_name}",
            _read_bounded(bundle, description="authenticated predecessor signature bundle"),
        )
    document = {"schema": "stateport.release-index/v1", "signed": signed, "signatures": []}
    index = validate_release_index(document, require_signatures=False)
    _validate_packaged_consumer(
        index.canonical_index_bytes + b"\n", request.updater,
    )
    write_bytes_create_only(
        output, "release-index.candidate.json", index.canonical_index_bytes + b"\n"
    )
    return {
        "releaseId": request.release_id,
        "qualification": "candidate",
        "signedPayloadDigest": index.signed_digest,
        "candidate": str(output / "release-index.candidate.json"),
        "signatureStatus": "unsigned-awaiting-operator-key",
        "imageSignatureStatus": "retained-bundles-bound",
    }


def sign(
    *,
    candidate: Path,
    build_receipt: Path,
    signing_key: Path,
    trust_public_key: Path,
    trust_key_id: str,
    trust_key_fingerprint: str,
    image_verifier: SignatureVerifier | None = None,
) -> dict[str, Any]:
    root = candidate.parent
    index = load_release_index_file(candidate, require_signatures=False)
    receipt = _load_receipt(build_receipt, expected_version=str(index.version))
    _require(not index.document["signatures"], "candidate release index is already signed")
    _require(
        signing_key.is_file() and not signing_key.is_symlink(),
        "signing key is unavailable or unsafe",
    )
    _require(
        bool(os.environ.get("COSIGN_PASSWORD")),
        "COSIGN_PASSWORD must be set for non-interactive private-candidate signing",
    )
    _checked_str(trust_key_id, _KEY_ID, "trust key ID")
    fingerprint = public_key_der_spki_fingerprint(trust_public_key)
    _require(
        fingerprint == trust_key_fingerprint,
        "trust public key does not match the expected DER SPKI fingerprint",
    )
    _require(
        private_key_der_spki_fingerprint(signing_key, cosign=_pinned_cosign()) == fingerprint,
        "signing key does not derive the pinned trust public key",
    )
    successor = index.document["signed"].get("successor")
    if successor is not None:
        now = datetime.now(timezone.utc)
        _check_scan_freshness_at(index.document["signed"]["images"], now)
        _check_qualification_timestamp_at(successor, index.document["signed"]["images"], now)
        expires_at = index.document["signed"]["publication"]["expiresAt"]
        if expires_at is not None:
            _require(
                now
                < datetime.strptime(expires_at, "%Y-%m-%dT%H:%M:%SZ").replace(
                    tzinfo=timezone.utc
                ),
                "release expiresAt is already expired at signing",
            )
        predecessor = successor["predecessor"]
        predecessor_successor = (
            None
            if predecessor is None
            else predecessor["rawIndex"]["signed"].get("successor")
        )
        validate_successor_disposition_transition(predecessor_successor, successor)
        if predecessor is not None:
            raw_index = predecessor["rawIndex"]
            identity = PinnedPublicKeyIdentity(trust_key_fingerprint, trust_key_id)
            with tempfile.TemporaryDirectory(prefix="stateport-sign-predecessor-") as retained:
                retained_root = Path(retained)
                retained_root.chmod(0o700)
                verifier = CosignVerifier(
                    cosign=Path(_pinned_cosign()),
                    public_key=trust_public_key,
                    identity=identity,
                    bundle_root=retained_root,
                )
                bundle_name = signature_bundle_name(predecessor["signature"])
                verifier.retain_bundle(
                    root / "predecessor-bundle" / bundle_name, predecessor["signature"]
                )
                authenticated = verify_release_predecessor(
                    raw_index,
                    expected_trust_mode="pinned-public-key",
                    accepted_public_keys=frozenset({identity}),
                    verifier=verifier,
                    legacy_predecessor=True,
                )
            _require(
                authenticated.signature == predecessor["signature"],
                "successor predecessor signature is not the authenticated signature",
            )
    verifier: SignatureVerifier
    retained_root: tempfile.TemporaryDirectory[str] | None = None
    if image_verifier is None:
        retained_root = tempfile.TemporaryDirectory(prefix="stateport-sign-image-bundles-")
        retained_path = Path(retained_root.name)
        retained_path.chmod(0o700)
        verifier = CosignVerifier(
            cosign=Path(_pinned_cosign()),
            public_key=trust_public_key,
            identity=PinnedPublicKeyIdentity(fingerprint, trust_key_id),
            bundle_root=retained_path,
        )
    else:
        verifier = image_verifier
    for image in index.document["signed"]["images"]:
        signature = image["signature"]
        _require(
            signature["trustMode"] == "pinned-public-key"
            and signature["publicKeyFingerprint"] == fingerprint
            and signature["publicKeyId"] == trust_key_id,
            f"candidate image signature for {image['imageId']} is not bound to this trust root",
        )
        bundle_name = signature_bundle_name(signature)
        source = root / "image-bundles" / bundle_name
        if not source.is_file():
            source = root / bundle_name
        retain = getattr(verifier, "retain_bundle", None)
        _require(callable(retain), "image verifier cannot retain signature bundles")
        try:
            retain(source, signature)
            authority = receipt["images"][str(image["imageId"])].get("releaseAuthority")
            _require(
                isinstance(authority, Mapping)
                and authority.get("kind") == "retained-oci-archive"
                and isinstance(authority.get("path"), str),
                f"private image verification requires a retained OCI archive for {image['imageId']}",
            )
            archive = _receipt_archive_path(build_receipt, authority)
            _require(
                archive.is_file() and not archive.is_symlink(),
                f"private image verification archive is unavailable for {image['imageId']}",
            )
            verifier.verify_blob(
                oci_archive_manifest_bytes(
                    archive, expected_manifest_digest=str(authority.get("manifestDigest", ""))
                ),
                signature,
            )
        except Exception as exc:
            raise AssemblyError(
                f"local image manifest signature verification failed for {image['imageId']}: {exc}"
            ) from exc
    payload = write_bytes_create_only(root, "release-index.signed-payload.json", index.signed_bytes)
    bundle = root / "release-index.sigstore.json"
    _require(not bundle.exists(), "release index signature bundle already exists")
    completed = subprocess.run(
        [
            _pinned_cosign(),
            "sign-blob",
            "--use-signing-config=false",
            "--tlog-upload=false",
            "--bundle",
            str(bundle),
            "--key",
            str(signing_key),
            str(payload),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=3600,
        shell=False,
        stdin=subprocess.DEVNULL,
    )
    _require(
        completed.returncode == 0 and bundle.is_file(),
        f"Cosign payload signing failed: {completed.stderr.strip()[:300]}",
    )
    document = json.loads(candidate.read_text(encoding="utf-8"))
    document["signatures"] = [
        {
            "scheme": "cosign-v3-bundle",
            "subjectDigest": index.signed_digest,
            "bundle": {
                "uri": "operator://release/release-index.sigstore.json",
                "digest": sha256_file(bundle),
                "size": bundle.stat().st_size,
                "mediaType": "application/vnd.sigstore.bundle.v0.3+json",
            },
            "trustMode": "pinned-public-key",
            "publicKeyFingerprint": fingerprint,
            "publicKeyFingerprintAlgorithm": "sha256-canonical-der-spki",
            "publicKeyId": trust_key_id,
            "transparencyLog": "not-uploaded-private-candidate",
        }
    ]
    signed_index = validate_release_index(document)
    write_bytes_create_only(root, "release-index.json", signed_index.canonical_index_bytes + b"\n")
    if retained_root is not None:
        retained_root.cleanup()
    return {
        "releaseId": signed_index.document["signed"]["release"]["releaseId"],
        "signedPayloadDigest": signed_index.signed_digest,
        "releaseIndex": str(root / "release-index.json"),
        "bundle": str(bundle),
        "signatureStatus": "signed-private-candidate",
        "transparencyLog": "not-uploaded-private-candidate",
    }


def verify(
    *,
    index_path: Path,
    request: AssemblyRequest,
    expected_channel: str,
    updater_version: str,
    expected_target: str | None,
    trust_public_key: Path,
    trust_key_id: str,
    trust_key_fingerprint: str,
    bundle_root: Path | None,
    verifier: SignatureVerifier | None = None,
) -> dict[str, Any]:
    index = load_release_index_file(index_path)
    receipt = _load_receipt(request.build_receipt, expected_version=request.version)
    source_bundle_root = bundle_root or index_path.parent
    with tempfile.TemporaryDirectory(prefix="stateport-release-verify-") as temporary:
        temp_root = Path(temporary)
        temp_root.chmod(0o700)
        rederived = replace(
            request,
            output_root=temp_root / "rederived",
            image_bundle_dir=source_bundle_root / "image-bundles",
        )
        output = prepare_output_root(rederived.output_root, repository=ROOT)
        signed = _assemble_signed(
            rederived,
            output,
            qualification_event=(
                index.document["signed"].get("successor", {}).get("qualificationEvent")
                if index.document["signed"].get("successor") is not None
                else None
            ),
        )
    _require(
        canonical_json_bytes(signed) == index.signed_bytes,
        "release index does not match a full re-derivation from its recorded inputs",
    )
    fingerprint = public_key_der_spki_fingerprint(trust_public_key)
    _require(
        fingerprint == trust_key_fingerprint,
        "trust public key does not match the expected DER SPKI fingerprint",
    )
    targets = index.document["signed"]["targets"]
    if expected_target is None:
        _require(len(targets) == 1, "verify requires --expected-target for multi-target indexes")
        expected_target = str(targets[0]["targetId"])
    identity = PinnedPublicKeyIdentity(fingerprint, trust_key_id)
    local_image_payloads: dict[str, bytes] = {}
    with tempfile.TemporaryDirectory(prefix="stateport-release-bundles-") as retained:
        retained_root = Path(retained)
        retained_root.chmod(0o700)
        if verifier is None:
            verifier = CosignVerifier(
                cosign=Path(_pinned_cosign()),
                public_key=trust_public_key,
                identity=identity,
                bundle_root=retained_root,
            )
        # Verification resolves bundles only from content-addressed retained
        # slots; the flat assembly directory is transport, never authority.
        for signature in index.document["signatures"]:
            verifier.retain_bundle(source_bundle_root / signature_bundle_name(signature), signature)
        for image in index.document["signed"]["images"]:
            signature = image["signature"]
            bundle_name = signature_bundle_name(signature)
            source = source_bundle_root / "image-bundles" / bundle_name
            if not source.is_file():
                source = source_bundle_root / bundle_name
            verifier.retain_bundle(source, signature)
            if signature.get("subjectKind") == "oci-manifest-blob":
                local_image_payloads[str(image["imageId"])] = _local_image_manifest(
                    request, receipt, str(image["imageId"])
                )
        predecessor_index = None
        if index.document["signed"].get("successor", {}).get("predecessor") is not None:
            _require(
                request.predecessor_index is not None,
                "successor verification requires the predecessor index input",
            )
            predecessor_index = load_release_index_file(
                request.predecessor_index, legacy_predecessor=True
            )
            for signature in predecessor_index.document["signatures"]:
                verifier.retain_bundle(
                    request.predecessor_index.parent / signature_bundle_name(signature), signature
                )
        policy = ReleaseVerificationPolicy(
            expected_channel=expected_channel,
            expected_target=expected_target,
            updater_version=updater_version,
            accepted_signers=frozenset(),
            accepted_public_keys=frozenset({identity}),
            expected_trust_mode="pinned-public-key",
            now=datetime.now(timezone.utc),
            allow_candidate=True,
        )
        verified = verify_release_index(
            index,
            policy=policy,
            verifier=verifier,
            predecessor=predecessor_index,
            local_image_payloads=local_image_payloads,
        )
    return {
        "releaseId": verified.index.release_id,
        "channel": verified.index.channel,
        "target": expected_target,
        "signedPayloadDigest": verified.index.signed_digest,
        "rederivation": "matched-recorded-inputs",
        "verificationProofs": signature_verification_proof_set(verified),
    }


def _assembly_request(args: argparse.Namespace, output_root: Path) -> AssemblyRequest:
    return AssemblyRequest(
        build_receipt=args.build_receipt,
        evidence_dir=args.evidence_dir,
        candidate_provenance=args.candidate_provenance,
        topology=args.topology,
        release_id=args.release_id,
        version=args.version,
        channel=args.channel,
        qualification=args.qualification,
        image_repository=args.image_repository,
        public_snapshot_repository=args.public_snapshot_repository,
        updater_minimum_version=args.updater_minimum_version,
        schema_migration_version=args.schema_migration_version,
        database_migration_version=args.database_migration_version,
        predecessor_index=args.predecessor_index,
        rollback_supported=args.rollback_supported,
        rollback_minimum_version=args.rollback_minimum_version,
        rollback_data_compatible=args.rollback_data_compatible,
        rollback_reason=args.rollback_reason,
        installer=args.installer,
        execution_host_provisioner=args.execution_host_provisioner,
        updater=args.updater,
        source_archive=args.source_archive,
        release_notes=args.release_notes,
        known_limitations=args.known_limitations,
        public_export_manifest=args.public_export_manifest,
        expires_at=args.expires_at,
        trust_public_key=args.trust_public_key,
        trust_key_id=args.trust_key_id,
        trust_key_fingerprint=args.trust_key_fingerprint,
        image_bundle_dir=args.image_bundle_dir,
        output_root=output_root,
        successor_semantics=True,
        qualification_at=args.qualification_at,
        podman_package_bundle=args.podman_package_bundle,
    )


def _add_assembly_arguments(parser: argparse.ArgumentParser, *, for_verify: bool) -> None:
    parser.add_argument("--build-receipt", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--candidate-provenance", type=Path, required=True)
    parser.add_argument("--topology", type=Path, required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--channel", required=True, choices=("alpha", "stable", "owner-dogfood"))
    parser.add_argument("--qualification", default="candidate", choices=("candidate", "published"))
    parser.add_argument(
        "--qualification-at",
        help="explicit UTC qualification timestamp for deterministic assembly",
    )
    parser.add_argument("--image-repository", required=True)
    parser.add_argument("--public-snapshot-repository", required=True)
    parser.add_argument("--updater-minimum-version", required=True)
    parser.add_argument("--schema-migration-version", type=int, required=True)
    parser.add_argument("--database-migration-version", type=int, required=True)
    parser.add_argument("--predecessor-index", type=Path)
    parser.add_argument(
        "--rollback-supported", action=argparse.BooleanOptionalAction, default=False
    )
    parser.add_argument("--rollback-minimum-version")
    parser.add_argument(
        "--rollback-data-compatible", action=argparse.BooleanOptionalAction, default=False
    )
    parser.add_argument("--rollback-reason", required=True)
    parser.add_argument("--installer", type=Path, required=True)
    parser.add_argument("--execution-host-provisioner", type=Path, required=True)
    parser.add_argument("--podman-package-bundle", type=Path)
    parser.add_argument("--updater", type=Path, required=True)
    parser.add_argument("--source-archive", type=Path, required=True)
    parser.add_argument("--release-notes", type=Path, required=True)
    parser.add_argument("--known-limitations", type=Path, required=True)
    parser.add_argument("--public-export-manifest", type=Path, required=True)
    parser.add_argument("--expires-at")
    parser.add_argument("--trust-public-key", type=Path, required=True)
    parser.add_argument("--trust-key-id", required=True)
    parser.add_argument("--trust-key-fingerprint", required=True)
    parser.add_argument("--image-bundle-dir", type=Path, required=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    assemble_parser = commands.add_parser("assemble", help="assemble an unsigned candidate index")
    _add_assembly_arguments(assemble_parser, for_verify=False)
    assemble_parser.add_argument("--output-root", type=Path, required=True)
    sign_images_parser = commands.add_parser(
        "sign-images", help="sign retained image manifests with the operator key"
    )
    sign_images_parser.add_argument("--build-receipt", type=Path, required=True)
    sign_images_parser.add_argument("--version", required=True)
    sign_images_parser.add_argument("--signing-key", type=Path, required=True)
    sign_images_parser.add_argument("--trust-public-key", type=Path, required=True)
    sign_images_parser.add_argument("--trust-key-id", required=True)
    sign_images_parser.add_argument("--trust-key-fingerprint", required=True)
    sign_images_parser.add_argument("--output-root", type=Path, required=True)
    sign_parser = commands.add_parser("sign", help="sign a candidate index with the operator key")
    sign_parser.add_argument("--candidate", type=Path, required=True)
    sign_parser.add_argument("--build-receipt", type=Path, required=True)
    sign_parser.add_argument("--signing-key", type=Path, required=True)
    sign_parser.add_argument("--trust-public-key", type=Path, required=True)
    sign_parser.add_argument("--trust-key-id", required=True)
    sign_parser.add_argument("--trust-key-fingerprint", required=True)
    verify_parser = commands.add_parser(
        "verify", help="re-derive and cryptographically verify a signed index"
    )
    _add_assembly_arguments(verify_parser, for_verify=True)
    verify_parser.add_argument("--index", type=Path, required=True)
    verify_parser.add_argument("--expected-channel", required=True)
    verify_parser.add_argument("--expected-target")
    verify_parser.add_argument("--updater-version", required=True)
    verify_parser.add_argument("--bundle-root", type=Path)
    args = parser.parse_args(argv)
    if args.command in {"assemble", "sign-images", "sign"}:
        require_guard(
            "candidate_construction" if args.command == "assemble" else "signing",
            sys.argv if argv is None else [str(Path(__file__)), *argv],
        )
    if args.command == "assemble":
        result = assemble(_assembly_request(args, args.output_root))
    elif args.command == "sign-images":
        result = sign_images(
            build_receipt=args.build_receipt,
            version=args.version,
            signing_key=args.signing_key,
            trust_public_key=args.trust_public_key,
            trust_key_id=args.trust_key_id,
            trust_key_fingerprint=args.trust_key_fingerprint,
            output_root=args.output_root,
        )
    elif args.command == "sign":
        result = sign(
            candidate=args.candidate,
            build_receipt=args.build_receipt,
            signing_key=args.signing_key,
            trust_public_key=args.trust_public_key,
            trust_key_id=args.trust_key_id,
            trust_key_fingerprint=args.trust_key_fingerprint,
        )
    else:
        result = verify(
            index_path=args.index,
            request=_assembly_request(args, args.index.parent / "verify-output"),
            expected_channel=args.expected_channel,
            updater_version=args.updater_version,
            expected_target=args.expected_target,
            trust_public_key=args.trust_public_key,
            trust_key_id=args.trust_key_id,
            trust_key_fingerprint=args.trust_key_fingerprint,
            bundle_root=args.bundle_root,
        )
    print(json.dumps(result, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        AssemblyError,
        CosignVerificationError,
        ReleaseBuildError,
        OSError,
        ValueError,
        yaml.YAMLError,
    ) as exc:
        print(f"release assembly refused: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
