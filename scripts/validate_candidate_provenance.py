#!/usr/bin/env python3
"""Validate external candidate identity, recovery, and retention contracts."""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import subprocess
import tarfile
import tempfile
from typing import Any, Mapping, Sequence
import zipfile

import jsonschema
import yaml
from export_public_candidate import COPYABLE_CLASSIFICATIONS, ExportError, _classify, load_policy


ROOT = Path(__file__).resolve().parents[1]
PODMAN_PACKAGE_ROOTFS = {
    "architecture": "amd64",
    "digest": "sha256:9b2f7730dc68227dd04a9f3e5eab86ad85caf556b8606ad94f1f29ff5c4fd3f5",
    "release": "24.04.4",
    "url": "https://releases.ubuntu.com/24.04.4/ubuntu-24.04.4-wsl-amd64.wsl",
}
CONTROLLED_GIT_CWD = Path("/")
GIT_SAFE_OPTIONS = (
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.fsmonitorHook=",
    "-c",
    "credential.helper=",
    "-c",
    "core.askPass=",
    "-c",
    "core.sshCommand=",
    "-c",
    "http.proxy=",
    "-c",
    "http.extraHeader=",
)
CONTRACT_ROOT = ROOT / "config" / "candidate-provenance"
SCHEMA_PATH = ROOT / "schemas" / "candidate-provenance.v1.schema.json"
ABSOLUTE_WINDOWS = re.compile(r"^[A-Za-z]:[\\/]")
TOOL_RECEIPT = re.compile(r"^snapshot_receipt_[0-9a-f]{32}$")
LOCKED_BUILD_VERSIONS = {"setuptools": "80.10.2", "wheel": "0.45.1"}
UNTRUSTED_GIT_ENVIRONMENT = frozenset(
    {
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_ASKPASS",
        "GIT_COMMON_DIR",
        "GIT_CREDENTIAL_HELPER",
        "GIT_DIR",
        "GIT_GRAFT_FILE",
        "GIT_HTTP_EXTRAHEADER",
        "GIT_INDEX_FILE",
        "GIT_NAMESPACE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_REPLACE_REF_BASE",
        "GIT_SHALLOW_FILE",
        "GIT_WORK_TREE",
    }
)


def _hermetic_git_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
        }
    )
    return environment


# Tool-issued receipt identities are deterministic and content-bound: the
# pinned validation/materialization tooling derives them from the exact
# digests the receipt accounts for, so an operator without a broker daemon
# can produce a verifiable provenance contract (agent-native operation).
# Broker-issued authority_receipt_* identities pass through unchanged.
def _derive_tool_receipt(purpose: str, *bound_digests: str) -> str:
    payload = "stateport.tool-receipt/v1|" + purpose + "|" + "|".join(bound_digests)
    return "snapshot_receipt_" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


def _expected_tool_receipts(value: Mapping[str, Any]) -> dict[str, str]:
    artifacts = value["artifacts"]
    bundle = artifacts["gitBundle"]
    return {
        "materialization.receipt.id": _derive_tool_receipt(
            "materialization", value["materialization"]["receipt"]["digest"]
        ),
        "artifacts.gitBundle.recoveryReceipt": _derive_tool_receipt("recovery", bundle["sha256"]),
        "retention.preservationReceipt": _derive_tool_receipt(
            "preservation",
            bundle["sha256"],
            artifacts["auditedSourceArchive"]["sha256"],
        ),
    }


def _verify_tool_receipts(value: Mapping[str, Any]) -> None:
    observed = {
        "materialization.receipt.id": value["materialization"]["receipt"]["id"],
        "artifacts.gitBundle.recoveryReceipt": value["artifacts"]["gitBundle"]["recoveryReceipt"],
        "retention.preservationReceipt": value["retention"]["preservationReceipt"],
    }
    expected = _expected_tool_receipts(value)
    for field, receipt in observed.items():
        if TOOL_RECEIPT.fullmatch(receipt) is None:
            continue
        if not secrets.compare_digest(receipt, expected[field]):
            raise CandidateProvenanceError(
                f"tool-issued receipt does not match its content derivation at {field}"
            )


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _validate_schema_document(document: object, filename: str, label: str) -> None:
    try:
        schema = json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(schema).validate(document)
    except (OSError, UnicodeError, json.JSONDecodeError, jsonschema.SchemaError, jsonschema.ValidationError) as exc:
        raise CandidateProvenanceError(f"{label} does not satisfy its schema") from exc


def _locked_inputs_digest(wheels: Sequence[Mapping[str, Any]]) -> str:
    return hashlib.sha256(
        _canonical_json(
            [
                {"filename": item["filename"], "sha256": item["sha256"], "bytes": item["bytes"]}
                for item in wheels
            ]
        )
    ).hexdigest()


def _verify_locked_wheel(filename: str, data: bytes) -> None:
    package = next((name for name in LOCKED_BUILD_VERSIONS if filename.startswith(f"{name}-")), None)
    if package is None or not filename.endswith(".whl"):
        raise CandidateProvenanceError("candidate-input locked wheel name is not an approved tool")
    version = LOCKED_BUILD_VERSIONS[package]
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as wheel:
            metadata_paths = [
                name
                for name in wheel.namelist()
                if name == f"{package}-{version}.dist-info/METADATA"
            ]
            if len(metadata_paths) != 1:
                raise CandidateProvenanceError("candidate-input locked wheel lacks canonical metadata")
            metadata = wheel.read(metadata_paths[0]).decode("utf-8")
    except (UnicodeDecodeError, OSError, zipfile.BadZipFile) as exc:
        raise CandidateProvenanceError("candidate-input locked wheel is not a real wheel") from exc
    fields = dict(
        line.split(": ", 1)
        for line in metadata.splitlines()
        if ": " in line and line.split(": ", 1)[0] in {"Name", "Version"}
    )
    if fields.get("Name", "").casefold().replace("-", "_") != package or fields.get("Version") != version:
        raise CandidateProvenanceError("candidate-input locked wheel metadata does not match its pinned version")


def _parse_locked_requirements(data: bytes) -> dict[str, tuple[str, set[str]]]:
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise CandidateProvenanceError("build-requirements.lock is not UTF-8") from exc
    parsed: dict[str, tuple[str, set[str]]] = {}
    current: tuple[str, str] | None = None
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if "==" in stripped:
            package, version = stripped.split("==", 1)
            current = (package.strip(), version.split()[0].strip())
            parsed[current[0]] = (current[1], set())
        match = re.search(r"--hash=sha256:([0-9a-f]{64})", stripped)
        if match and current is not None:
            parsed[current[0]][1].add(match.group(1))
    if set(parsed) != set(LOCKED_BUILD_VERSIONS) or any(
        version != LOCKED_BUILD_VERSIONS[package] or not hashes
        for package, (version, hashes) in parsed.items()
    ):
        raise CandidateProvenanceError("build-requirements.lock does not contain the exact pinned tool hashes")
    return parsed


def _verify_successor_contract(value: Mapping[str, Any]) -> None:
    repository = value["repository"]
    clone = repository["normalCloneVerification"]
    local_authority = value["authorityClass"] == "local_qualification_git_authority_and_local_build_evidence"
    expected_clone_status = (
        "verified_local_qualification_clone"
        if local_authority
        else "verified_anonymous_normal_clone"
    )
    expected_format = (
        "stateport.local-qualification-clone-receipt/v1"
        if local_authority
        else "stateport.anonymous-normal-clone-receipt/v1"
    )
    expected_verification = (
        "local-clone-and-recovery-with-fsck"
        if local_authority
        else "credential-free-normal-clone-fetch-and-ls-remote"
    )
    if clone["status"] != expected_clone_status or value["verification"]["normalClone"] != expected_clone_status:
        raise CandidateProvenanceError("candidate clone status does not match its authority class")
    if clone["url"] != repository["authorityUrl"] or clone["ref"] != repository["ref"]:
        raise CandidateProvenanceError("anonymous clone receipt does not match public Git authority")
    if clone["commit"] != repository["commit"] or clone["tree"] != repository["tree"]:
        raise CandidateProvenanceError("anonymous clone receipt does not match repository identity")
    receipt_payload = {
        "formatVersion": expected_format,
        "url": clone["url"],
        "ref": clone["ref"],
        "commit": clone["commit"],
        "tree": clone["tree"],
        "verification": expected_verification,
    }
    expected_digest = hashlib.sha256(_canonical_json(receipt_payload)).hexdigest()
    if clone["receiptSha256"] != expected_digest:
        raise CandidateProvenanceError("anonymous clone receipt digest does not match its identity")
    expected_id = "clone_receipt_" + expected_digest[:32]
    if not secrets.compare_digest(clone["receiptId"], expected_id):
        raise CandidateProvenanceError("anonymous clone receipt ID does not match its identity")
    artifacts = value["artifacts"]
    public_manifest = artifacts["publicManifest"]
    archive_identity = artifacts["sourceArchive"]["embeddedGitIdentity"]
    if archive_identity["authorityUrl"] != repository["authorityUrl"]:
        raise CandidateProvenanceError("source archive authority does not match candidate")
    for field in ("ref", "commit", "tree"):
        if archive_identity[field] != repository[field]:
            raise CandidateProvenanceError(f"source archive {field} does not match candidate")
    if archive_identity["manifestSha256"] != public_manifest["sha256"]:
        raise CandidateProvenanceError("source archive manifest digest does not match public manifest")
    receipt_document = {**receipt_payload, "receiptId": clone["receiptId"], "receiptSha256": clone["receiptSha256"]}
    receipt_artifact = artifacts["normalCloneReceipt"]
    receipt_bytes = _json_bytes(receipt_document)
    if receipt_artifact["sha256"] != hashlib.sha256(receipt_bytes).hexdigest():
        raise CandidateProvenanceError("anonymous clone receipt artifact digest does not match content")
    if receipt_artifact["bytes"] != len(receipt_bytes):
        raise CandidateProvenanceError("anonymous clone receipt artifact size does not match content")
    bundle = artifacts["gitBundle"]
    for field in ("ref", "commit", "tree"):
        if bundle[field] != repository[field]:
            raise CandidateProvenanceError(f"Git bundle {field} does not match candidate")
    installer = artifacts["installer"]
    if installer["sourceCommit"] != value["materialization"]["sourceCommit"]:
        raise CandidateProvenanceError("installer is not extracted from the frozen source commit")
    provisioner = artifacts["executionHostProvisioner"]
    if provisioner["sourceCommit"] != value["materialization"]["sourceCommit"]:
        raise CandidateProvenanceError(
            "execution-host provisioner is not extracted from the frozen source commit"
        )
    wheel = artifacts["updaterWheel"]
    if wheel["firstSha256"] != wheel["secondSha256"] or not wheel["reproducible"]:
        raise CandidateProvenanceError("updater wheel reproducibility is not proven")
    if wheel["sha256"] != wheel["firstSha256"] or wheel["bytes"] < 1:
        raise CandidateProvenanceError("updater wheel artifact digest is not bound to the reproducible builds")
    paths = {
        str(artifacts[field]["path"])
        for field in (
            "publicManifest",
            "licensingInventory",
            "normalCloneReceipt",
            "sourceArchive",
            "gitBundle",
            "installer",
            "executionHostProvisioner",
            "candidateInputManifest",
            "releaseTreeManifest",
        )
    }
    paths.update({str(wheel["firstPath"]), str(wheel["secondPath"]), str(wheel["path"])})
    package_bundle = artifacts.get("podmanPackageBundle")
    if package_bundle is not None:
        if package_bundle.get("path") != "packages/podman-package-bundle.tar":
            raise CandidateProvenanceError(
                "Podman package bundle does not use its canonical candidate path"
            )
        paths.add(str(package_bundle["path"]))
    if len(paths) != (13 if package_bundle is not None else 12):
        raise CandidateProvenanceError("successor artifact paths are duplicated")


class CandidateProvenanceError(RuntimeError):
    """Candidate provenance is malformed, ambiguous, or unrecoverable."""


def _load(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise CandidateProvenanceError(f"could not parse {path.name}") from exc


def _walk(value: Any, field: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            _walk(child, f"{field}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _walk(child, f"{field}[{index}]")
    elif isinstance(value, str):
        if value.startswith(("/", "~/")) or ABSOLUTE_WINDOWS.match(value):
            raise CandidateProvenanceError(f"absolute host path is forbidden at {field}")


def validate_contract(value: Any, schema: Mapping[str, Any]) -> Mapping[str, Any]:
    try:
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(schema).validate(value)
    except (jsonschema.SchemaError, jsonschema.ValidationError) as exc:
        raise CandidateProvenanceError(
            f"candidate contract schema validation failed: {exc.message}"
        ) from exc
    if not isinstance(value, Mapping):
        raise CandidateProvenanceError("candidate contract must be an object")
    _walk(value)
    if value["schema"] == "stateport.candidate-provenance/v1":
        _verify_tool_receipts(value)
    else:
        _verify_successor_contract(value)
    repository = value["repository"]
    artifacts = value["artifacts"]
    if value["schema"] == "stateport.candidate-provenance/v1":
        if artifacts["auditedSourceArchive"]["embeddedCommit"] != repository["commit"]:
            raise CandidateProvenanceError("source archive embedded commit does not match candidate")
        bundle = artifacts["gitBundle"]
        if bundle["ref"] != repository["ref"]:
            raise CandidateProvenanceError("bundle ref does not match candidate ref")
        recovery = value["verification"]["recovery"]
        if recovery["bundleLocator"] != bundle["locator"]:
            raise CandidateProvenanceError("recovery command locator does not match bundle locator")
    return value


def _release_file(root: Path, relative: str) -> tuple[Path, bytes]:
    path = PurePosixPath(relative)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise CandidateProvenanceError("release artifact path is unsafe")
    selected = root.joinpath(*path.parts)
    if selected.is_symlink() or not selected.is_file():
        raise CandidateProvenanceError(f"release artifact is missing or unsafe: {relative}")
    return selected, selected.read_bytes()


def _podman_bundle_metadata(data: bytes) -> dict[str, object]:
    try:
        archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:")
    except tarfile.TarError as exc:
        raise CandidateProvenanceError("candidate Podman package bundle is not a plain tar") from exc
    with archive:
        matching = [
            member
            for member in archive.getmembers()
            if member.name == "podman-package-bundle/manifest.json"
        ]
        if len(matching) != 1 or not matching[0].isfile() or matching[0].size > 1024 * 1024:
            raise CandidateProvenanceError("candidate Podman package manifest is unavailable")
        stream = archive.extractfile(matching[0])
        if stream is None:
            raise CandidateProvenanceError("candidate Podman package manifest cannot be read")
        with stream:
            manifest_bytes = stream.read(1024 * 1024 + 1)
    try:
        manifest = json.loads(manifest_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateProvenanceError("candidate Podman package manifest is invalid JSON") from exc
    packages = manifest.get("packages") if isinstance(manifest, Mapping) else None
    if (
        not isinstance(manifest, Mapping)
        or manifest.get("schema") != "stateport/podman-package-bundle/v2"
        or manifest.get("rootfs") != PODMAN_PACKAGE_ROOTFS
        or not isinstance(packages, list)
        or not 17 <= len(packages) <= 128
    ):
        raise CandidateProvenanceError("candidate Podman package manifest identity is invalid")
    canonical = (
        json.dumps(manifest, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("utf-8")
    if manifest_bytes != canonical:
        raise CandidateProvenanceError("candidate Podman package manifest is not canonical")
    return {
        "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "packageCount": len(packages),
        "rootfsIdentity": dict(PODMAN_PACKAGE_ROOTFS),
    }


def _verify_candidate_input_manifest(
    value: Mapping[str, Any],
    data: bytes,
    root: Path,
    archive_files: Mapping[str, bytes],
    bundle_files: Mapping[str, tuple[bytes, str]],
) -> str:
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateProvenanceError("candidate-input manifest is not valid JSON") from exc
    if document.get("formatVersion") != "stateport.candidate-input-manifest/v1":
        raise CandidateProvenanceError("candidate-input manifest format is unsupported")
    repository = value["repository"]
    materialization = value["materialization"]
    if document.get("authority") != {"url": repository["authorityUrl"], "ref": repository["ref"]}:
        raise CandidateProvenanceError("candidate-input authority is not bound to provenance")
    if document.get("source") != {
        "commit": materialization["sourceCommit"],
        "tree": materialization["sourceTree"],
    }:
        raise CandidateProvenanceError("candidate-input source identity is not bound to provenance")
    expected_paths = {
        "config/public-export-allowlist.v1.yaml",
        "packages/execution-host/src/execution_host/identity-contract.v1.json",
        "packages/execution-host/src/execution_host/identity_contract.py",
        "packages/updater/build-requirements.lock",
        "packages/updater/pyproject.toml",
        "scripts/build_public_release_bundle.py",
        "scripts/export_public_candidate.py",
        "scripts/install_no_checkout.py",
        "scripts/stateport-execution-host-provision",
        "scripts/materialize_public_snapshot.py",
        "scripts/public_snapshot_audit.py",
    }
    tracked = document.get("trackedInputs")
    if not isinstance(tracked, list) or {item.get("path") for item in tracked if isinstance(item, Mapping)} != expected_paths:
        raise CandidateProvenanceError("candidate-input tracked paths are not the exact build inputs")
    for item in tracked:
        if (
            not isinstance(item, Mapping)
            or not isinstance(item.get("path"), str)
            or not re.fullmatch(r"[0-9a-f]{40}", str(item.get("gitBlob")))
            or not re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256")))
            or set(str(item.get("sha256"))) == {"0"}
            or not isinstance(item.get("bytes"), int)
            or item["bytes"] < 1
        ):
            raise CandidateProvenanceError("candidate-input tracked digest entry is malformed")
    external = document.get("externalInputs")
    if not isinstance(external, Mapping):
        raise CandidateProvenanceError("candidate-input external inputs are missing")
    candidate_artifacts = value.get("artifacts")
    candidate_package = (
        candidate_artifacts.get("podmanPackageBundle")
        if isinstance(candidate_artifacts, Mapping)
        else None
    )
    package_input = external.get("podmanPackageBundle")
    if candidate_package is not None:
        expected_path = "packages/podman-package-bundle.tar"
        tracked_by_path = {
            item["path"]: item for item in tracked if isinstance(item, Mapping)
        }
        builder = tracked_by_path["scripts/build_public_release_bundle.py"]
        construction = package_input.get("construction") if isinstance(package_input, Mapping) else None
        if (
            not isinstance(candidate_package, Mapping)
            or not isinstance(package_input, Mapping)
            or set(package_input)
            != {
                "bytes",
                "construction",
                "manifestSha256",
                "packageCount",
                "path",
                "rootfsIdentity",
                "sha256",
            }
            or package_input.get("path") != expected_path
            or package_input.get("sha256") != candidate_package.get("sha256")
            or package_input.get("bytes") != candidate_package.get("bytes")
            or package_input.get("rootfsIdentity") != PODMAN_PACKAGE_ROOTFS
            or not isinstance(package_input.get("packageCount"), int)
            or not 17 <= package_input["packageCount"] <= 128
            or not isinstance(construction, Mapping)
            or construction
            != {
                "builderSourcePath": "scripts/build_public_release_bundle.py",
                "builderGitBlob": builder["gitBlob"],
                "builderSha256": builder["sha256"],
            }
        ):
            raise CandidateProvenanceError(
                "candidate-input Podman package bundle is not bound to provenance"
            )
        _path, package_data = _release_file(root, expected_path)
        if (
            hashlib.sha256(package_data).hexdigest() != package_input["sha256"]
            or len(package_data) != package_input["bytes"]
            or _podman_bundle_metadata(package_data)
            != {
                "manifestSha256": package_input["manifestSha256"],
                "packageCount": package_input["packageCount"],
                "rootfsIdentity": package_input["rootfsIdentity"],
            }
        ):
            raise CandidateProvenanceError(
                "candidate-input Podman package bundle differs from the retained output"
            )
    elif package_input is not None:
        raise CandidateProvenanceError(
            "candidate-input carries an unowned Podman package bundle"
        )
    detector = external.get("privateDetectorSet")
    if (
        not isinstance(detector, Mapping)
        or not re.fullmatch(r"[0-9a-f]{64}", str(detector.get("sha256")))
        or set(str(detector.get("sha256"))) == {"0"}
        or not isinstance(detector.get("bytes"), int)
        or detector["bytes"] < 1
    ):
        raise CandidateProvenanceError("candidate-input detector digest entry is malformed")
    wheels = external.get("lockedBuildWheels")
    if not isinstance(wheels, list) or not wheels:
        raise CandidateProvenanceError("candidate-input locked wheels are missing")
    wheel_names: set[str] = set()
    for wheel in wheels:
        if (
            not isinstance(wheel, Mapping)
            or not isinstance(wheel.get("filename"), str)
            or "/" in wheel["filename"]
            or "\\" in wheel["filename"]
            or not re.fullmatch(r"[0-9a-f]{64}", str(wheel.get("sha256")))
            or set(str(wheel.get("sha256"))) == {"0"}
            or not isinstance(wheel.get("bytes"), int)
            or wheel["bytes"] < 1
        ):
            raise CandidateProvenanceError("candidate-input locked wheel digest entry is malformed")
        wheel_names.add(str(wheel["filename"]))
        wheel_path = wheel.get("path")
        if not isinstance(wheel_path, str) or wheel_path != f"evidence/locked-build-inputs/{wheel['filename']}":
            raise CandidateProvenanceError("candidate-input locked wheel path is missing")
        _path, wheel_data = _release_file(root, wheel_path)
        if hashlib.sha256(wheel_data).hexdigest() != wheel["sha256"] or len(wheel_data) != wheel["bytes"]:
            raise CandidateProvenanceError("candidate-input locked wheel does not match its output file")
        _verify_locked_wheel(wheel["filename"], wheel_data)
    if len(wheel_names) != 2 or not any(name.startswith("setuptools-") for name in wheel_names) or not any(
        name.startswith("wheel-") for name in wheel_names
    ):
        raise CandidateProvenanceError("candidate-input locked wheels are not the pinned build tool pair")
    lock_entry = bundle_files.get("packages/updater/build-requirements.lock")
    if lock_entry is None:
        raise CandidateProvenanceError("recovered Git tree lacks build-requirements.lock")
    locked_requirements = _parse_locked_requirements(lock_entry[0])
    seen_packages: set[str] = set()
    for wheel in wheels:
        package = next(
            (name for name in LOCKED_BUILD_VERSIONS if wheel["filename"].startswith(f"{name}-")), None
        )
        if package is None or package in seen_packages or wheel["sha256"] not in locked_requirements[package][1]:
            raise CandidateProvenanceError("candidate-input locked wheel digest is not present in the exact lock")
        seen_packages.add(package)
    if seen_packages != set(LOCKED_BUILD_VERSIONS):
        raise CandidateProvenanceError("candidate-input locked wheels do not cover the exact lock")
    for item in tracked:
        path = str(item["path"])
        archive_content = archive_files.get(path)
        bundle_entry = bundle_files.get(path)
        bundle_content = bundle_entry[0] if bundle_entry is not None else None
        if archive_content is None or bundle_content is None:
            raise CandidateProvenanceError(f"candidate-input path is absent from the public source tree: {path}")
        if archive_content != bundle_content:
            raise CandidateProvenanceError(f"candidate-input source trees disagree: {path}")
        git_blob = hashlib.sha1(f"blob {len(bundle_content)}\0".encode() + bundle_content).hexdigest()
        if (
            item["gitBlob"] != git_blob
            or item["sha256"] != hashlib.sha256(bundle_content).hexdigest()
            or item["bytes"] != len(bundle_content)
        ):
            raise CandidateProvenanceError(f"candidate-input digest does not match recovered Git bundle: {path}")
    tracked_by_path = {str(item["path"]): item for item in tracked}
    for label, path in (
        ("materializer", "scripts/materialize_public_snapshot.py"),
        ("exporter", "scripts/export_public_candidate.py"),
        ("policy", "config/public-export-allowlist.v1.yaml"),
    ):
        tool = materialization[label]
        item = tracked_by_path[path]
        if item["gitBlob"] != tool["gitBlob"] or item["sha256"] != tool["sha256"]:
            raise CandidateProvenanceError(f"candidate-input {label} blob is not bound to the recovered Git tree")
    locked_inputs_sha256 = _locked_inputs_digest(wheels)
    if external.get("lockedBuildInputsSha256") != locked_inputs_sha256:
        raise CandidateProvenanceError("candidate-input locked input digest is not content-bound")
    return locked_inputs_sha256


def _verify_source_archive(
    value: Mapping[str, Any], root: Path, data: bytes
) -> tuple[dict[str, bytes], dict[str, str]]:
    artifacts = value["artifacts"]
    public_path, public_data = _release_file(root, artifacts["publicManifest"]["path"])
    del public_path
    try:
        public_manifest = json.loads(public_data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateProvenanceError("public export manifest is not valid JSON") from exc
    _validate_schema_document(
        public_manifest, "public-export-manifest.v1.schema.json", "public export manifest"
    )
    if public_manifest.get("status") != "exported" or not isinstance(public_manifest.get("files"), list):
        raise CandidateProvenanceError("public export manifest is not an exported file set")
    expected_identity = {
        "formatVersion": "stateport.public-source-identity/v1",
        "authorityUrl": value["repository"]["authorityUrl"],
        "ref": value["repository"]["ref"],
        "commit": value["repository"]["commit"],
        "tree": value["repository"]["tree"],
        "manifestSha256": artifacts["publicManifest"]["sha256"],
    }
    observed: dict[str, bytes] = {}
    observed_modes: dict[str, str] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            for member in archive.getmembers():
                path = PurePosixPath(member.name)
                if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
                    raise CandidateProvenanceError("source archive contains an unsafe path")
                if not member.isfile() or member.name in observed:
                    raise CandidateProvenanceError("source archive contains an unsafe entry")
                stream = archive.extractfile(member)
                if stream is None:
                    raise CandidateProvenanceError("source archive entry is unreadable")
                observed[member.name] = stream.read()
                observed_modes[member.name] = format(member.mode & 0o777, "04o")
    except tarfile.TarError as exc:
        raise CandidateProvenanceError("source archive is not a readable tar archive") from exc
    identity_data = observed.get("SOURCE-IDENTITY.json")
    if identity_data is None:
        raise CandidateProvenanceError("source archive has no embedded Git identity")
    try:
        if json.loads(identity_data.decode("utf-8")) != expected_identity:
            raise CandidateProvenanceError("source archive embedded Git identity does not match provenance")
    except UnicodeDecodeError as exc:
        raise CandidateProvenanceError("source archive identity is not UTF-8 JSON") from exc
    expected_files: set[str] = set()
    for item in public_manifest["files"]:
        if not isinstance(item, Mapping) or not isinstance(item.get("path"), str):
            raise CandidateProvenanceError("public export manifest entry is malformed")
        path = str(item["path"])
        expected_files.add(path)
        content = observed.get(path)
        if (
            content is None
            or item.get("digest") != "sha256:" + hashlib.sha256(content).hexdigest()
            or item.get("mode") != observed_modes.get(path)
        ):
            raise CandidateProvenanceError(f"source archive content does not match public manifest: {path}")
    if set(observed) != expected_files | {"SOURCE-IDENTITY.json"}:
        raise CandidateProvenanceError("source archive contents do not match public manifest")
    return observed, observed_modes


def _verify_updater_wheel(value: Mapping[str, Any], root: Path, locked_inputs_sha256: str) -> None:
    artifact = value["artifacts"]["updaterWheel"]
    wheel_data = _release_file(root, artifact["path"])[1]
    first_data = _release_file(root, artifact["firstPath"])[1]
    second_data = _release_file(root, artifact["secondPath"])[1]
    if wheel_data != first_data or wheel_data != second_data:
        raise CandidateProvenanceError("updater wheel outputs are not byte-identical")
    evidence = artifact["buildEvidence"]
    try:
        with zipfile.ZipFile(io.BytesIO(wheel_data)) as wheel:
            names = wheel.namelist()
            if len(names) != len(set(names)) or any(
                "\\" in name
                or PurePosixPath(name).is_absolute()
                or any(part in {"", ".", ".."} for part in PurePosixPath(name).parts)
                for name in names
            ):
                raise CandidateProvenanceError("updater wheel contains unsafe or duplicate entries")
            identity_path = str(evidence["path"])
            if identity_path not in names:
                raise CandidateProvenanceError("updater wheel lacks embedded build evidence")
            identity_module = wheel.read(identity_path)
    except zipfile.BadZipFile as exc:
        raise CandidateProvenanceError("updater wheel is not a valid ZIP wheel") from exc
    try:
        module = ast.parse(identity_module.decode("ascii"), filename=identity_path)
        assignments = [
            node
            for node in module.body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "STATEPORT_BUILD_EVIDENCE_JSON" for target in node.targets)
        ]
        if len(assignments) != 1:
            raise CandidateProvenanceError("updater wheel build evidence module is malformed")
        encoded = ast.literal_eval(assignments[0].value)
        embedded = json.loads(encoded)
    except (SyntaxError, UnicodeDecodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise CandidateProvenanceError("updater wheel build evidence is not canonical JSON") from exc
    expected = {key: value for key, value in evidence.items() if key != "path"}
    if embedded != expected:
        raise CandidateProvenanceError("updater wheel build evidence does not match provenance")
    if (
        embedded["sourceTree"] != value["repository"]["tree"]
        or embedded["lockedInputsSha256"] != locked_inputs_sha256
    ):
        raise CandidateProvenanceError("updater wheel is not bound to the recovered source tree and locked inputs")


def _verify_licensing_inventory(value: Mapping[str, Any], root: Path) -> None:
    artifacts = value["artifacts"]
    _public_path, public_data = _release_file(root, artifacts["publicManifest"]["path"])
    _license_path, license_data = _release_file(root, artifacts["licensingInventory"]["path"])
    try:
        public_manifest = json.loads(public_data.decode("utf-8"))
        licensing = yaml.safe_load(license_data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, yaml.YAMLError) as exc:
        raise CandidateProvenanceError("licensing or public manifest is malformed") from exc
    _validate_schema_document(licensing, "rights-inventory.v1.schema.json", "rights inventory")
    if licensing.get("formatVersion") != "stateport.rights-inventory/v1":
        raise CandidateProvenanceError("licensing inventory format is unsupported")
    public_paths = {item.get("path") for item in public_manifest.get("files", []) if isinstance(item, Mapping)}
    license_files = licensing.get("files") if isinstance(licensing, Mapping) else None
    if not isinstance(license_files, list) or {
        item.get("path") for item in license_files if isinstance(item, Mapping)
    } != public_paths:
        raise CandidateProvenanceError("licensing inventory does not cover the public manifest")
    if any(
        not isinstance(item, Mapping)
        or item.get("publicExportDecision") != "include"
        or item.get("redistributable") is not True
        for item in license_files
    ):
        raise CandidateProvenanceError("licensing inventory contains an uncleared file")


def _verify_exact_export_policy(
    manifest: Mapping[str, Any],
    licensing: Mapping[str, Any],
    archive_files: Mapping[str, bytes],
    bundle_files: Mapping[str, tuple[bytes, str]],
) -> None:
    policy_data = archive_files.get("config/public-export-allowlist.v1.yaml")
    bundle_policy_data = bundle_files.get("config/public-export-allowlist.v1.yaml")
    if policy_data is None or bundle_policy_data is None or policy_data != bundle_policy_data[0]:
        raise CandidateProvenanceError("exact export policy is absent or differs between archive and Git tree")
    try:
        policy = load_policy(policy_data)
    except (ExportError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise CandidateProvenanceError("exact export policy is not valid") from exc
    manifest_files = manifest.get("files")
    if not isinstance(manifest_files, list):
        raise CandidateProvenanceError("public export manifest files are not a list")
    manifest_by_path: dict[str, Mapping[str, Any]] = {}
    for item in manifest_files:
        if not isinstance(item, Mapping) or not isinstance(item.get("path"), str):
            raise CandidateProvenanceError("public export manifest entry is malformed")
        path = str(item["path"])
        if path in manifest_by_path:
            raise CandidateProvenanceError("public export manifest repeats a path")
        manifest_by_path[path] = item
        rule = _classify(path, policy)
        if rule.classification not in COPYABLE_CLASSIFICATIONS:
            raise CandidateProvenanceError(f"public export manifest includes a policy-blocked path: {path}")
        if (
            item["classification"] != rule.classification
            or item["license"] != rule.license
            or item["provenanceRationale"] != rule.rationale
        ):
            raise CandidateProvenanceError(f"public export manifest does not match exact policy: {path}")
    for path in bundle_files:
        rule = _classify(path, policy)
        if rule.classification not in COPYABLE_CLASSIFICATIONS or path not in manifest_by_path:
            raise CandidateProvenanceError(f"recovered Git tree is not exactly policy-exported: {path}")
    for rule in policy.rules:
        if rule.classification in COPYABLE_CLASSIFICATIONS and any(
            path not in bundle_files for path in rule.paths
        ):
            raise CandidateProvenanceError(f"exact export policy path is absent from recovered Git tree: {rule.identifier}")
        if rule.classification in COPYABLE_CLASSIFICATIONS and any(
            not any(path.startswith(prefix) for path in bundle_files) for prefix in rule.prefixes
        ):
            raise CandidateProvenanceError(f"exact export policy prefix is absent from recovered Git tree: {rule.identifier}")
    rights_by_path: dict[str, Mapping[str, Any]] = {}
    raw_rights = licensing.get("files")
    if not isinstance(raw_rights, list):
        raise CandidateProvenanceError("rights inventory files are not a list")
    category_by_classification = {
        "public-source": "owned_code",
        "public-documentation": "owned_documentation",
        "public-generated": "generated_owned_output",
        "third-party-reviewed": "third_party_redistributable",
    }
    for item in raw_rights:
        if not isinstance(item, Mapping) or not isinstance(item.get("path"), str):
            raise CandidateProvenanceError("rights inventory entry is malformed")
        path = str(item["path"])
        if path in rights_by_path:
            raise CandidateProvenanceError("rights inventory repeats a path")
        rights_by_path[path] = item
    if set(rights_by_path) != set(manifest_by_path):
        raise CandidateProvenanceError("rights inventory does not exactly cover the public manifest")
    for path, item in manifest_by_path.items():
        right = rights_by_path[path]
        expected_category = category_by_classification[item["classification"]]
        if (
            right["category"] != expected_category
            or right["proposedLicence"] != item["license"]
            or right["publicExportDecision"] != "include"
            or right["redistributable"] is not True
        ):
            raise CandidateProvenanceError(f"rights inventory does not match exact policy: {path}")


def _verify_materialization_receipt(value: Mapping[str, Any], root: Path) -> None:
    _path, data = _release_file(root, "evidence/materialization-receipt.json")
    try:
        receipt = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateProvenanceError("materialization receipt is not valid JSON") from exc
    expected = {
        "formatVersion": "stateport.public-snapshot-materialization/v1",
        "candidateHead": value["repository"]["commit"],
        "candidateTree": value["repository"]["tree"],
        "sourceCommit": value["materialization"]["sourceCommit"],
        "sourceTree": value["materialization"]["sourceTree"],
        "publicManifestDigest": "sha256:" + value["artifacts"]["publicManifest"]["sha256"],
        "status": "passed",
    }
    if any(receipt.get(key) != expected_value for key, expected_value in expected.items()):
        raise CandidateProvenanceError("materialization receipt is not bound to source and recovered Git identity")


def verify_release_tree(value: Mapping[str, Any], root: Path) -> None:
    if value.get("schema") != "stateport.candidate-provenance/v2":
        raise CandidateProvenanceError("release-tree validation requires successor provenance v2")
    root = root.resolve(strict=True)
    artifacts = value["artifacts"]
    artifact_records = [
        artifacts[field]
        for field in (
            "publicManifest",
            "licensingInventory",
            "normalCloneReceipt",
            "sourceArchive",
            "gitBundle",
            "installer",
            "executionHostProvisioner",
            "candidateInputManifest",
            "releaseTreeManifest",
        )
    ]
    wheel = artifacts["updaterWheel"]
    artifact_records.extend(
        [
            {"path": wheel["path"], "sha256": wheel["sha256"], "bytes": wheel["bytes"]},
            {"path": wheel["firstPath"], "sha256": wheel["firstSha256"], "bytes": wheel["firstBytes"]},
            {"path": wheel["secondPath"], "sha256": wheel["secondSha256"], "bytes": wheel["secondBytes"]},
        ]
    )
    observed_paths: set[str] = set()
    for record in artifact_records:
        relative = str(record["path"])
        if relative in observed_paths:
            raise CandidateProvenanceError("release artifact paths are duplicated")
        observed_paths.add(relative)
        _path, data = _release_file(root, relative)
        if hashlib.sha256(data).hexdigest() != record["sha256"] or len(data) != record["bytes"]:
            raise CandidateProvenanceError(f"release artifact digest or size mismatch: {relative}")

    clone_document_data = _release_file(root, artifacts["normalCloneReceipt"]["path"])[1]
    try:
        clone_document = json.loads(clone_document_data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateProvenanceError("anonymous clone receipt artifact is not valid JSON") from exc
    local_authority = value["authorityClass"] == "local_qualification_git_authority_and_local_build_evidence"
    expected_format = (
        "stateport.local-qualification-clone-receipt/v1"
        if local_authority
        else "stateport.anonymous-normal-clone-receipt/v1"
    )
    expected_verification = (
        "local-clone-and-recovery-with-fsck"
        if local_authority
        else "credential-free-normal-clone-fetch-and-ls-remote"
    )
    expected_clone_document = {
        "formatVersion": expected_format,
        "url": value["repository"]["authorityUrl"],
        "ref": value["repository"]["ref"],
        "commit": value["repository"]["commit"],
        "tree": value["repository"]["tree"],
        "verification": expected_verification,
        "receiptId": value["repository"]["normalCloneVerification"]["receiptId"],
        "receiptSha256": value["repository"]["normalCloneVerification"]["receiptSha256"],
    }
    if clone_document != expected_clone_document:
        raise CandidateProvenanceError("anonymous clone receipt artifact content is not bound")
    installer_data = _release_file(root, artifacts["installer"]["path"])[1]
    if not installer_data.startswith(b"#!/usr/bin/env python3\n"):
        raise CandidateProvenanceError("installer artifact content is not the frozen no-checkout installer")

    provenance_path, provenance_bytes = _release_file(root, "provenance/candidate-provenance.yaml")
    del provenance_path
    try:
        if yaml.safe_load(provenance_bytes) != dict(value):
            raise CandidateProvenanceError("durable provenance file does not match the validated contract")
    except yaml.YAMLError as exc:
        raise CandidateProvenanceError("durable provenance file is not valid YAML") from exc

    archive_files, archive_modes = _verify_source_archive(
        value, root, _release_file(root, artifacts["sourceArchive"]["path"])[1]
    )
    with tempfile.TemporaryDirectory(prefix="stateport-release-bundle-verify-") as temporary:
        bundle_path = Path(temporary) / "candidate.bundle"
        bundle_path.write_bytes(_release_file(root, artifacts["gitBundle"]["path"])[1])
        bundle_files = _recover_bundle_files(value, bundle_path)
    locked_inputs_sha256 = _verify_candidate_input_manifest(
        value,
        _release_file(root, artifacts["candidateInputManifest"]["path"])[1],
        root,
        archive_files,
        bundle_files,
    )
    _verify_updater_wheel(value, root, locked_inputs_sha256)
    _verify_licensing_inventory(value, root)
    try:
        public_manifest = json.loads(_release_file(root, artifacts["publicManifest"]["path"])[1].decode("utf-8"))
        licensing_inventory = yaml.safe_load(
            _release_file(root, artifacts["licensingInventory"]["path"])[1].decode("utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError, yaml.YAMLError) as exc:
        raise CandidateProvenanceError("export manifest or rights inventory cannot be reloaded") from exc
    _verify_exact_export_policy(public_manifest, licensing_inventory, archive_files, bundle_files)
    _verify_materialization_receipt(value, root)
    if set(archive_files) - {"SOURCE-IDENTITY.json"} != set(bundle_files):
        raise CandidateProvenanceError("source archive file set does not match recovered Git bundle tree")
    for path, content in archive_files.items():
        if path != "SOURCE-IDENTITY.json" and bundle_files[path][0] != content:
            raise CandidateProvenanceError(f"source archive content does not match recovered Git bundle: {path}")
        if path != "SOURCE-IDENTITY.json" and archive_modes[path] != bundle_files[path][1]:
            raise CandidateProvenanceError(f"source archive mode does not match recovered Git bundle: {path}")
    installer_data = _release_file(root, artifacts["installer"]["path"])[1]
    if archive_files.get("scripts/install_no_checkout.py") != installer_data:
        raise CandidateProvenanceError("installer artifact does not match the frozen source archive installer")
    provisioner_data = _release_file(
        root, artifacts["executionHostProvisioner"]["path"]
    )[1]
    if archive_files.get("scripts/stateport-execution-host-provision") != provisioner_data:
        derived = artifacts["executionHostProvisioner"].get(
            "qualificationDerivedFromSourceSha256"
        )
        if (
            value.get("classification") != "local_qualification_candidate"
            or derived != hashlib.sha256(
                archive_files["scripts/stateport-execution-host-provision"]
            ).hexdigest()
        ):
            raise CandidateProvenanceError(
                "execution-host provisioner artifact does not match the frozen source archive"
            )

    manifest_path, manifest_bytes = _release_file(root, str(artifacts["releaseTreeManifest"]["path"]))
    del manifest_path
    if hashlib.sha256(manifest_bytes).hexdigest() != artifacts["releaseTreeManifest"]["sha256"]:
        raise CandidateProvenanceError("release-tree manifest digest does not match its output file")
    if len(manifest_bytes) != artifacts["releaseTreeManifest"]["bytes"]:
        raise CandidateProvenanceError("release-tree manifest size does not match its output file")
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateProvenanceError("release-tree manifest is not valid JSON") from exc
    _validate_schema_document(manifest, "release-tree-manifest.v1.schema.json", "release-tree manifest")
    excluded = manifest.get("excludedPaths")
    expected_excluded = [
        "bundle-receipt.json",
        "provenance/candidate-provenance.yaml",
        "release-tree-manifest.json",
    ]
    if excluded != expected_excluded:
        raise CandidateProvenanceError("release-tree manifest exclusion set is not exact")
    entries = manifest.get("files")
    if not isinstance(entries, list):
        raise CandidateProvenanceError("release-tree manifest files are not a list")
    actual: dict[str, bytes] = {}
    actual_modes: dict[str, str] = {}
    for path in root.rglob("*"):
        if path.is_symlink():
            raise CandidateProvenanceError("release tree contains a symlink")
        if path.is_file():
            actual[path.relative_to(root).as_posix()] = path.read_bytes()
            mode_bits = stat.S_IMODE(path.stat().st_mode)
            if mode_bits not in {0o644, 0o755}:
                raise CandidateProvenanceError("release tree contains an unsupported file mode")
            actual_modes[path.relative_to(root).as_posix()] = f"{mode_bits:04o}"
    observed: set[str] = set()
    for item in entries:
        if not isinstance(item, Mapping) or not isinstance(item.get("path"), str):
            raise CandidateProvenanceError("release-tree manifest entry is malformed")
        relative = str(item["path"])
        if relative in observed or relative in excluded or relative not in actual:
            raise CandidateProvenanceError("release-tree manifest entry is unsafe or missing")
        data = actual[relative]
        if (
            item.get("sha256") != hashlib.sha256(data).hexdigest()
            or item.get("bytes") != len(data)
            or item.get("mode") != actual_modes[relative]
        ):
            raise CandidateProvenanceError(f"release-tree entry digest or size mismatch: {relative}")
        observed.add(relative)
    if observed != set(actual) - set(excluded):
        raise CandidateProvenanceError("release-tree manifest does not cover the output tree")
    installer_path, _installer_data = _release_file(root, "installer/install.sh")
    if stat.S_IMODE(installer_path.stat().st_mode) != 0o755:
        raise CandidateProvenanceError("installer artifact is not executable")
    provisioner_path, _provisioner_data = _release_file(
        root, "provisioning/stateport-execution-host-provision"
    )
    if stat.S_IMODE(provisioner_path.stat().st_mode) != 0o755:
        raise CandidateProvenanceError("execution-host provisioner artifact is not executable")
    receipt_path, receipt_bytes = _release_file(root, "bundle-receipt.json")
    del receipt_path
    try:
        receipt = json.loads(receipt_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateProvenanceError("bundle receipt is not valid JSON") from exc
    receipt_content_hash = receipt.pop("receiptContentSha256", None)
    receipt_content_bytes = receipt.pop("receiptContentBytes", None)
    canonical_receipt = _canonical_json(receipt)
    if receipt_content_hash != hashlib.sha256(canonical_receipt).hexdigest():
        raise CandidateProvenanceError("bundle receipt content digest does not match")
    if receipt_content_bytes != len(canonical_receipt):
        raise CandidateProvenanceError("bundle receipt content size does not match")
    if receipt.get("formatVersion") != "stateport.public-release-bundle/v1":
        raise CandidateProvenanceError("bundle receipt format is unsupported")
    if (
        receipt.get("candidateId") != value["candidateId"]
        or receipt.get("sourceCommit") != value["materialization"]["sourceCommit"]
        or receipt.get("sourceTree") != value["materialization"]["sourceTree"]
        or receipt.get("publicCommit") != value["repository"]["commit"]
        or receipt.get("publicTree") != value["repository"]["tree"]
        or receipt.get("publicAuthority") != value["repository"]["authorityUrl"]
        or receipt.get("publicRef") != value["repository"]["ref"]
        or receipt.get("status") != "built_local_unpublished_pending_signing"
    ):
        raise CandidateProvenanceError("bundle receipt identity does not match provenance")
    if receipt.get("releaseTreeManifestSha256") != artifacts["releaseTreeManifest"]["sha256"]:
        raise CandidateProvenanceError("bundle receipt release-tree digest does not match provenance")
    if receipt.get("candidateInputManifestSha256") != artifacts["candidateInputManifest"]["sha256"]:
        raise CandidateProvenanceError("bundle receipt candidate-input digest does not match provenance")
    provenance_binding = receipt.get("provenance")
    if not isinstance(provenance_binding, Mapping):
        raise CandidateProvenanceError("bundle receipt lacks durable provenance binding")
    if (
        provenance_binding.get("path") != "provenance/candidate-provenance.yaml"
        or provenance_binding.get("sha256") != hashlib.sha256(provenance_bytes).hexdigest()
        or provenance_binding.get("bytes") != len(provenance_bytes)
    ):
        raise CandidateProvenanceError("bundle receipt provenance binding does not match output")


def _git(repository: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *GIT_SAFE_OPTIONS, "-C", str(repository), *args],
        check=check,
        text=True,
        capture_output=True,
        cwd=CONTROLLED_GIT_CWD,
        env=_hermetic_git_environment(),
    )


def validate_repository_relationship(value: Mapping[str, Any], repository: Path = ROOT) -> None:
    source = value["materialization"]
    candidate = value["repository"]
    if (
        _git(
            repository, "cat-file", "-e", f"{source['sourceCommit']}^{{commit}}", check=False
        ).returncode
        != 0
    ):
        raise CandidateProvenanceError(
            "materialization source commit is not retained by the primary repository"
        )
    source_tree = _git(repository, "rev-parse", f"{source['sourceCommit']}^{{tree}}").stdout.strip()
    if not secrets.compare_digest(source_tree, str(source["sourceTree"])):
        raise CandidateProvenanceError(
            "materialization source tree does not match the source commit"
        )
    for label in ("materializer", "exporter", "policy"):
        tool = source[label]
        blob = str(tool["gitBlob"])
        blob_type = _git(repository, "cat-file", "-t", blob, check=False)
        if blob_type.returncode != 0 or blob_type.stdout.strip() != "blob":
            raise CandidateProvenanceError(f"materialization {label} blob is not retained")
        payload = subprocess.run(
            ["git", *GIT_SAFE_OPTIONS, "-C", str(repository), "cat-file", "blob", blob],
            check=True,
            capture_output=True,
            cwd=CONTROLLED_GIT_CWD,
            env=_hermetic_git_environment(),
        ).stdout
        if hashlib.sha256(payload).hexdigest() != tool["sha256"]:
            raise CandidateProvenanceError(f"materialization {label} blob digest does not match")
    if (
        _git(
            repository, "cat-file", "-e", f"{candidate['commit']}^{{commit}}", check=False
        ).returncode
        == 0
    ):
        raise CandidateProvenanceError(
            "candidate unexpectedly resolves in the primary repository; update its namespace contract"
        )


def verify_bundle(value: Mapping[str, Any], bundle: Path) -> None:
    if not bundle.is_file() or bundle.is_symlink():
        raise CandidateProvenanceError("operator bundle is missing or unsafe")
    expected = value["artifacts"]["gitBundle"]
    digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    if digest != expected["sha256"] or bundle.stat().st_size != expected["bytes"]:
        raise CandidateProvenanceError("operator bundle digest or size does not match the contract")
    listed = subprocess.run(
        ["git", *GIT_SAFE_OPTIONS, "bundle", "list-heads", str(bundle)],
        check=True,
        text=True,
        capture_output=True,
        cwd=CONTROLLED_GIT_CWD,
        env=_hermetic_git_environment(),
    ).stdout.strip()
    candidate = value["repository"]
    if listed != f"{candidate['commit']} {candidate['ref']}":
        raise CandidateProvenanceError("operator bundle does not contain the exact candidate ref")
    with tempfile.TemporaryDirectory(prefix="stateport-candidate-recovery-") as temporary:
        verification_repo = Path(temporary) / "verification.git"
        subprocess.run(
            ["git", *GIT_SAFE_OPTIONS, "init", "--bare", str(verification_repo)],
            check=True,
            text=True,
            capture_output=True,
            cwd=CONTROLLED_GIT_CWD,
            env=_hermetic_git_environment(),
        )
        subprocess.run(
            ["git", *GIT_SAFE_OPTIONS, "-C", str(verification_repo), "bundle", "verify", str(bundle)],
            check=True,
            text=True,
            capture_output=True,
            cwd=CONTROLLED_GIT_CWD,
            env=_hermetic_git_environment(),
        )
        recovered = Path(temporary) / "candidate"
        subprocess.run(
            [
                "git",
                *GIT_SAFE_OPTIONS,
                "-c",
                "init.defaultBranch=main",
                "clone",
                "--quiet",
                "--no-checkout",
                str(bundle),
                str(recovered),
            ],
            check=True,
            cwd=CONTROLLED_GIT_CWD,
            env=_hermetic_git_environment(),
        )
        branch = candidate["ref"].removeprefix("refs/heads/")
        head = _git(recovered, "rev-parse", f"origin/{branch}").stdout.strip()
        tree = _git(recovered, "rev-parse", f"origin/{branch}^{{tree}}").stdout.strip()
        if head != candidate["commit"] or tree != candidate["tree"]:
            raise CandidateProvenanceError("recovered bundle identity does not match the contract")
        _git(recovered, "fsck", "--full", "--strict", "--no-reflogs")


def _recover_bundle_files(value: Mapping[str, Any], bundle: Path) -> dict[str, tuple[bytes, str]]:
    verify_bundle(value, bundle)
    candidate = value["repository"]
    branch = candidate["ref"].removeprefix("refs/heads/")
    with tempfile.TemporaryDirectory(prefix="stateport-candidate-tree-") as temporary:
        recovered = Path(temporary) / "candidate"
        subprocess.run(
            [
                "git",
                *GIT_SAFE_OPTIONS,
                "-c",
                "init.defaultBranch=main",
                "clone",
                "--quiet",
                "--no-checkout",
                str(bundle),
                str(recovered),
            ],
            check=True,
            capture_output=True,
            cwd=CONTROLLED_GIT_CWD,
            env=_hermetic_git_environment(),
        )
        revision = f"origin/{branch}"
        listing = subprocess.run(
            ["git", *GIT_SAFE_OPTIONS, "-C", str(recovered), "ls-tree", "-r", "-z", "--full-tree", revision],
            check=True,
            capture_output=True,
            cwd=CONTROLLED_GIT_CWD,
            env=_hermetic_git_environment(),
        ).stdout
        files: dict[str, tuple[bytes, str]] = {}
        for entry in listing.split(b"\0"):
            if not entry:
                continue
            metadata, raw_path = entry.split(b"\t", 1)
            fields = metadata.split()
            if len(fields) != 3 or fields[1] != b"blob" or fields[0] not in {b"100644", b"100755"}:
                raise CandidateProvenanceError("recovered Git bundle contains a non-blob tree entry")
            path = raw_path.decode("utf-8")
            content = subprocess.run(
                ["git", *GIT_SAFE_OPTIONS, "-C", str(recovered), "show", f"{revision}:{path}"],
                check=True,
                capture_output=True,
                cwd=CONTROLLED_GIT_CWD,
                env=_hermetic_git_environment(),
            ).stdout
            files[path] = (content, "0755" if fields[0] == b"100755" else "0644")
        return files


def validate_all(
    root: Path = ROOT, bundle: Path | None = None, release_root: Path | None = None
) -> tuple[str, ...]:
    schemas = {
        "stateport.candidate-provenance/v1": json.loads(
            (root / "schemas" / "candidate-provenance.v1.schema.json").read_text(encoding="utf-8")
        ),
        "stateport.candidate-provenance/v2": json.loads(
            (root / "schemas" / "candidate-provenance.v2.schema.json").read_text(encoding="utf-8")
        ),
    }
    contracts = sorted((root / "config" / "candidate-provenance").glob("*.yaml"))
    if not contracts:
        raise CandidateProvenanceError("at least one candidate provenance contract is required")
    identities: set[str] = set()
    validated: list[str] = []
    for path in contracts:
        loaded = _load(path)
        if not isinstance(loaded, Mapping) or loaded.get("schema") not in schemas:
            raise CandidateProvenanceError("candidate contract has an unsupported schema")
        value = validate_contract(loaded, schemas[str(loaded["schema"])])
        candidate_id = str(value["candidateId"])
        if candidate_id in identities or path.stem != candidate_id:
            raise CandidateProvenanceError(
                "candidate ID is duplicate or does not match its file name"
            )
        identities.add(candidate_id)
        if value["schema"] == "stateport.candidate-provenance/v1":
            validate_repository_relationship(value, root)
        if bundle is not None:
            if len(contracts) != 1:
                raise CandidateProvenanceError("--bundle requires exactly one candidate contract")
            verify_bundle(value, bundle)
        if release_root is not None:
            if len(contracts) != 1:
                raise CandidateProvenanceError("--release-root requires exactly one candidate contract")
            verify_release_tree(value, release_root)
        validated.append(candidate_id)
    return tuple(validated)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--release-root", type=Path)
    args = parser.parse_args(argv)
    try:
        candidates = validate_all(
            args.root.resolve(),
            args.bundle,
            args.release_root.resolve() if args.release_root is not None else None,
        )
    except (
        CandidateProvenanceError,
        OSError,
        subprocess.CalledProcessError,
        json.JSONDecodeError,
    ) as exc:
        print(f"FAIL: {exc}")
        return 1
    if args.bundle is None and args.release_root is None:
        print(
            f"PASS: {len(candidates)} external candidate provenance contract(s) are typed; "
            "external recovery bundle not inspected"
        )
    else:
        print(
            f"PASS: {len(candidates)} external candidate provenance contract(s) are typed "
            "and requested external artifacts were verified"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
