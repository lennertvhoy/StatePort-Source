#!/usr/bin/env python3
"""Orchestrate one local-only J1 candidate through production mechanisms."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Any, Mapping
import zipfile

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "packages/release-contracts/src"))
sys.path.insert(0, str(ROOT / "scripts"))

import assemble_release_index as assembler  # noqa: E402
import build_public_release_bundle as source_builder  # noqa: E402
import collect_release_evidence as evidence_collector  # noqa: E402
from render_wsl2_install_bootstrap import render as render_bootstrap  # noqa: E402


QUALIFICATION_ATTEMPT = "900001"
RELEASE_ID = f"stateport-j1-integrated-qualification-{QUALIFICATION_ATTEMPT}"
LOCAL_REF = f"refs/heads/qualification-local-{QUALIFICATION_ATTEMPT}"
INTEGRATED_PHASE_REFUSAL = (
    "integrated candidate construction and signing require separate owner-authorized phases"
)
TARGET_ID = "wsl2-ubuntu2404-linux-amd64-rootless-podman-quadlet"
LOCAL_AUTHORITY = "https://127.0.0.1:5443/stateport-qualification.git"
LOCAL_KEY_PREFIX = f"stateport-qualification-{QUALIFICATION_ATTEMPT}"
QUALIFICATION_VERSION_RE = re.compile(r"0\.0\.0-j1\.[0-9]+")


class QualificationError(RuntimeError):
    """The local qualification candidate cannot be admitted."""


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def release_control_identity() -> dict[str, Any]:
    """Bind qualification evidence to the control revision that produced it."""
    def git_revision(expression: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", expression],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            raise QualificationError(f"cannot resolve release-control identity: {expression}")
        return completed.stdout.strip()

    tooling_paths = (
        "scripts/collect_release_evidence.py",
        "scripts/assemble_release_index.py",
        "packages/release-contracts/src/stateport_release/contract.py",
        "schemas/release-index.v1.schema.json",
        "packages/release-contracts/src/stateport_release/schemas/release-index.v1.schema.json",
    )
    return {
        "commit": git_revision("HEAD"),
        "tree": git_revision("HEAD^{tree}"),
        "policy": {
            "path": "config/release-tool-inputs.yaml",
            "sha256": _digest(ROOT / "config/release-tool-inputs.yaml"),
        },
        "tooling": {path: _digest(ROOT / path) for path in tooling_paths},
    }


def grype_database_receipt_evidence(
    evidence_root: Path, image_ids: list[str]
) -> dict[str, dict[str, Any]]:
    """Bind detailed database observation and latest-proof bytes to the receipt."""
    result: dict[str, dict[str, Any]] = {}
    for image_id in image_ids:
        path = evidence_root / f"{image_id}.grype-db.json"
        database = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(database, Mapping):
            raise QualificationError(f"Grype database evidence is not a mapping for {image_id}")
        observed_at = database.get("databaseObservedAt")
        latest_check = database.get("latestDatabaseCheck")
        if not isinstance(observed_at, str) or not isinstance(latest_check, Mapping):
            raise QualificationError(f"Grype database proof is incomplete for {image_id}")
        result[image_id] = {
            "path": str(path),
            "sha256": _digest(path),
            "databaseObservedAt": observed_at,
            "freshnessClass": database.get("freshnessClass"),
            "latestDatabaseCheck": dict(latest_check),
        }
    return result


def qualification_version(receipt: Mapping[str, Any]) -> str:
    """Use the version embedded in the preserved image build receipt."""
    identity = receipt.get("identity")
    version = identity.get("version") if isinstance(identity, Mapping) else None
    if not isinstance(version, str) or QUALIFICATION_VERSION_RE.fullmatch(version) is None:
        raise QualificationError(
            "preserved build version is not an approved J1 qualification identity"
        )
    return version


def validate_lane_inputs(
    *,
    candidate_provenance: Path | None,
    candidate_bundle: Path | None,
    evidence_dir: Path | None,
    template_index: Path | None = None,
    updater: Path | None = None,
) -> None:
    if template_index is not None:
        raise QualificationError("template index and copied supply-chain evidence are forbidden")
    if updater is not None:
        raise QualificationError("arbitrary updater bytes are forbidden; build the wheel from provenance")
    for value, label in (
        (candidate_provenance, "candidate provenance"),
        (candidate_bundle, "candidate bundle"),
        (evidence_dir, "evidence directory"),
    ):
        if value is None:
            raise QualificationError(f"{label} is required")


def validate_local_snapshot_identity(identity: Mapping[str, Any]) -> None:
    if identity.get("authorityUrl") != LOCAL_AUTHORITY:
        raise QualificationError("snapshot identity is not a local qualification authority")
    if identity.get("ref") != LOCAL_REF:
        raise QualificationError("snapshot identity is not bound to the local qualification ref")
    for field in ("commit", "tree"):
        value = identity.get(field)
        if not isinstance(value, str) or len(value) != 40 or any(char not in "0123456789abcdef" for char in value):
            raise QualificationError(f"local snapshot {field} is invalid")


def validate_updater_binding(record: Mapping[str, Any], updater: Path) -> None:
    if updater.is_symlink() or not updater.is_file():
        raise QualificationError("updater wheel is unavailable or unsafe")
    observed = hashlib.sha256(updater.read_bytes()).hexdigest()
    if str(record.get("sha256", "")).removeprefix("sha256:") != observed or record.get("bytes") != updater.stat().st_size:
        raise QualificationError("updater wheel is not bound to candidate provenance")


def validate_qualification_key_id(key_id: str) -> None:
    if not key_id.startswith(LOCAL_KEY_PREFIX):
        raise QualificationError("production trust identities are forbidden; use a qualification key")


def specialize_qualification_provisioner(
    provisioner: Path,
    *,
    trust_public_key: Path,
    trust_key_id: str,
    trust_key_fingerprint: str,
) -> None:
    """Bind the root helper to the ephemeral trust root used by this lane.

    Production bundles compile the root helper to the production Alpha key.
    A local qualification candidate must instead use the exact ephemeral key
    that signs its private index, or materialization would reject its own
    signed inputs before guest installation.
    """
    if provisioner.is_symlink() or not provisioner.is_file():
        raise QualificationError("qualification provisioner is unavailable or unsafe")
    data = provisioner.read_bytes()
    replacements = (
        (
            b"sha256:798d6ea6e2703993758f0fb45618b1f05b40f6ef116e7d286fd5a6867859b8ad",
            _digest(trust_public_key).encode("ascii"),
        ),
        (b"stateport-alpha-private-2026-08", trust_key_id.encode("ascii")),
        (
            b"sha256:df24c1ccdcf1ecf72da6d8d81ae8b0ffaca8d399826091b107cc4d6905915ea5",
            trust_key_fingerprint.encode("ascii"),
        ),
    )
    for old, new in replacements:
        if data.count(old) == 0:
            raise QualificationError("qualification provisioner is missing the production trust root")
        data = data.replace(old, new)
    provisioner.write_bytes(data)


def specialize_qualification_wheel(
    wheel: Path,
    *,
    trust_key_id: str,
    trust_key_fingerprint: str,
) -> None:
    """Bind the wheel's embedded provisioning module to the private root."""
    source = BytesIO(wheel.read_bytes())
    output = BytesIO()
    replaced = 0
    with zipfile.ZipFile(source) as archive, zipfile.ZipFile(output, "w") as rebuilt:
        for info in archive.infolist():
            data = archive.read(info.filename)
            if info.filename == "stateport_release/execution_host_provisioning.py":
                for old, new in (
                    (
                        b"stateport-alpha-private-2026-08",
                        trust_key_id.encode("ascii"),
                    ),
                    (
                        b"sha256:df24c1ccdcf1ecf72da6d8d81ae8b0ffaca8d399826091b107cc4d6905915ea5",
                        trust_key_fingerprint.encode("ascii"),
                    ),
                ):
                    count = data.count(old)
                    if count == 0:
                        raise QualificationError("qualification updater is missing the production trust root")
                    replaced += count
                    data = data.replace(old, new)
            rebuilt.writestr(info, data)
    if replaced != 2:
        raise QualificationError("qualification updater qualification derivation was incomplete")
    wheel.write_bytes(output.getvalue())


def rebind_qualification_provenance(bundle: Path, source_provisioner_digest: str) -> None:
    """Record the deliberate private-lane provisioner derivation."""
    provenance_path = bundle / "provenance/candidate-provenance.yaml"
    provenance = yaml.safe_load(provenance_path.read_text(encoding="utf-8"))
    artifact = provenance["artifacts"]["executionHostProvisioner"]
    provisioner = bundle / artifact["path"]
    artifact["sha256"] = hashlib.sha256(provisioner.read_bytes()).hexdigest()
    artifact["bytes"] = provisioner.stat().st_size
    artifact["qualificationDerivedFromSourceSha256"] = source_provisioner_digest
    wheel_artifact = provenance["artifacts"]["updaterWheel"]
    source_wheel_digest = wheel_artifact["firstSha256"]
    wheel_artifact["qualificationDerivedFromSourceSha256"] = source_wheel_digest
    for path_key, digest_key, bytes_key in (
        ("path", "sha256", "bytes"),
        ("firstPath", "firstSha256", "firstBytes"),
        ("secondPath", "secondSha256", "secondBytes"),
    ):
        wheel_path = bundle / wheel_artifact[path_key]
        wheel_artifact[digest_key] = hashlib.sha256(wheel_path.read_bytes()).hexdigest()
        wheel_artifact[bytes_key] = wheel_path.stat().st_size

    manifest_path = bundle / "release-tree-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for item in manifest["files"]:
        if item["path"] == artifact["path"]:
            item["sha256"] = artifact["sha256"]
            item["bytes"] = artifact["bytes"]
            break
    manifest_path.write_bytes(json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8") + b"\n")
    manifest_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    provenance["artifacts"]["releaseTreeManifest"]["sha256"] = manifest_digest
    provenance["artifacts"]["releaseTreeManifest"]["bytes"] = manifest_path.stat().st_size
    provenance_path.write_bytes(yaml.safe_dump(provenance, sort_keys=True).encode("utf-8"))

    receipt_path = bundle / "bundle-receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["releaseTreeManifestSha256"] = manifest_digest
    provenance_bytes = provenance_path.read_bytes()
    receipt["provenance"] = {
        "path": "provenance/candidate-provenance.yaml",
        "sha256": hashlib.sha256(provenance_bytes).hexdigest(),
        "bytes": len(provenance_bytes),
    }
    content = {key: value for key, value in receipt.items() if key not in {"receiptContentSha256", "receiptContentBytes"}}
    canonical = json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")
    receipt["receiptContentSha256"] = hashlib.sha256(canonical).hexdigest()
    receipt["receiptContentBytes"] = len(canonical)
    receipt_path.write_bytes(json.dumps(receipt, indent=2, sort_keys=True).encode("utf-8") + b"\n")


def discard_unverified_output(staging: Path, final: Path) -> None:
    """Remove only this run's private staging tree, never a final candidate."""
    if final.exists() or final.is_symlink():
        raise QualificationError(f"refusing to replace create-only candidate output: {final}")
    if staging.is_symlink() or not staging.exists():
        return
    if not staging.is_dir():
        raise QualificationError(f"qualification staging path is not a directory: {staging}")
    shutil.rmtree(staging)


def validate_phase0_receipt(receipt: Mapping[str, Any], expected: Mapping[str, Any]) -> bool:
    if receipt.get("mode") != "phase0-transport" or receipt.get("result") != "passed" or receipt.get("binding") != dict(expected):
        raise QualificationError("phase-0 receipt is missing or bound to a different candidate")
    return True


def _compatibility_fields(predecessor_release_index: Path | None) -> dict[str, Any]:
    """Derive the assembler compatibility inputs for one qualification candidate.

    A predecessor-bound candidate embeds the authenticated predecessor index,
    declares rollback support with data compatibility, and states the restore
    reason explicitly; the standalone default keeps historical semantics.
    """
    bound = predecessor_release_index is not None
    return {
        "predecessor_index": predecessor_release_index,
        "rollback_supported": bound,
        "rollback_minimum_version": None,
        "rollback_data_compatible": bound,
        "rollback_reason": (
            "Exact retained predecessor binding supports automatic and manual restore."
            if bound
            else "Qualification-only candidate has no predecessor semantics."
        ),
    }


def build(
    *,
    source: Path,
    source_commit: str,
    build_receipt: Path,
    private_detectors: Path,
    wheelhouse: Path,
    podman_package_bundle: Path,
    topology: Path,
    signing_key: Path,
    trust_public_key: Path,
    trust_key_id: str,
    trust_key_fingerprint: str,
    expires_at: str,
    output: Path,
    image_repository: str = "127.0.0.1:5443/stateport-alpha",
    release_root_url: str | None = None,
    predecessor_release_index: Path | None = None,
) -> dict[str, Any]:
    raise QualificationError(INTEGRATED_PHASE_REFUSAL)
    validate_qualification_key_id(trust_key_id)
    if output.exists() or output.is_symlink():
        raise QualificationError(f"candidate output must be new: {output}")
    source_bundle = output.parent / f".{output.name}.source"
    evidence_root = output.parent / f".{output.name}.evidence"
    image_bundle_dir = output.parent / f".{output.name}.image-signatures"
    staging = output.parent / f".{output.name}.staging"
    validate_lane_inputs(
        candidate_provenance=source_bundle / "provenance/candidate-provenance.yaml",
        candidate_bundle=source_bundle,
        evidence_dir=evidence_root,
    )
    try:
        receipt = json.loads(build_receipt.read_text(encoding="utf-8"))
        version = qualification_version(receipt)
        release_root_url = release_root_url or (
            f"https://127.0.0.1/StatePort-Site/download/{version}"
        )
        source_result = source_builder.build_release_bundle(
            source=source,
            source_commit=source_commit,
            release_version=version,
            source_url="https://github.com/lennertvhoy/StatePort.git",
            public_url=LOCAL_AUTHORITY,
            public_clone=output.parent,
            detector=private_detectors,
            wheelhouse=wheelhouse,
            podman_package_bundle=podman_package_bundle,
            output=source_bundle,
            candidate_id=RELEASE_ID,
            qualification_local=True,
            qualification_ref=LOCAL_REF,
        )
        provenance = source_bundle / "provenance/candidate-provenance.yaml"
        source_provisioner_digest = yaml.safe_load(
            provenance.read_text(encoding="utf-8")
        )["artifacts"]["executionHostProvisioner"]["sha256"]
        image_ids = sorted(str(image_id) for image_id in receipt["images"])
        evidence_collector.collect_many(
            image_ids=image_ids,
            build_receipt=build_receipt,
            candidate_provenance=provenance,
            candidate_bundle=source_bundle,
            output_root=evidence_root,
        )
        specialize_qualification_provisioner(
            source_bundle / "provisioning/stateport-execution-host-provision",
            trust_public_key=trust_public_key,
            trust_key_id=trust_key_id,
            trust_key_fingerprint=trust_key_fingerprint,
        )
        for wheel_name in (
            "updater/stateport-updater.whl",
            "updater/stateport-updater-first.whl",
            "updater/stateport-updater-second.whl",
        ):
            specialize_qualification_wheel(
                source_bundle / wheel_name,
                trust_key_id=trust_key_id,
                trust_key_fingerprint=trust_key_fingerprint,
            )
        rebind_qualification_provenance(source_bundle, source_provisioner_digest)
        source_tree = str(source_result["sourceTree"])
        image_ids = sorted(str(image_id) for image_id in receipt["images"])
        database_receipt_evidence = grype_database_receipt_evidence(evidence_root, image_ids)
        request = assembler.AssemblyRequest(
            build_receipt=build_receipt,
            evidence_dir=evidence_root,
            candidate_provenance=provenance,
            topology=topology,
            release_id=RELEASE_ID,
            version=version,
            channel="alpha",
            qualification="candidate",
            image_repository=image_repository,
            public_snapshot_repository=LOCAL_AUTHORITY,
            updater_minimum_version=assembler._updater_wheel_version(source_bundle / "updater/stateport-updater.whl"),
            schema_migration_version=1,
            database_migration_version=1,
            **_compatibility_fields(predecessor_release_index),
            installer=source_bundle / "installer/install.sh",
            execution_host_provisioner=source_bundle / "provisioning/stateport-execution-host-provision",
            podman_package_bundle=source_bundle / "packages/podman-package-bundle.tar",
            updater=source_bundle / "updater/stateport-updater.whl",
            source_archive=source_bundle / "source/stateport-source.tar",
            release_notes=source_bundle / "notes/release-notes.md",
            known_limitations=source_bundle / "limitations/known-limitations.md",
            public_export_manifest=source_bundle / "source/public-export-manifest.json",
            expires_at=expires_at,
            trust_public_key=trust_public_key,
            trust_key_id=trust_key_id,
            trust_key_fingerprint=trust_key_fingerprint,
            image_bundle_dir=image_bundle_dir,
            output_root=staging,
            qualification_at=_timestamp(),
        )
        assembler.sign_images(
            build_receipt=build_receipt,
            version=version,
            signing_key=signing_key,
            trust_public_key=trust_public_key,
            trust_key_id=trust_key_id,
            trust_key_fingerprint=trust_key_fingerprint,
            output_root=request.image_bundle_dir,
        )
        assembled = assembler.assemble(request)
        assembler.sign(candidate=Path(str(assembled["candidate"])), build_receipt=build_receipt, signing_key=signing_key, trust_public_key=trust_public_key, trust_key_id=trust_key_id, trust_key_fingerprint=trust_key_fingerprint)
        verified = assembler.verify(index_path=staging / "release-index.json", request=request, expected_channel="alpha", updater_version=request.updater_minimum_version, expected_target=TARGET_ID, trust_public_key=trust_public_key, trust_key_id=trust_key_id, trust_key_fingerprint=trust_key_fingerprint, bundle_root=staging)
        bootstrap = render_bootstrap(
            candidate=staging,
            trust_public_key=trust_public_key,
            release_root_url=release_root_url,
        )
        with (staging / "bootstrap.sh").open("xb") as stream:
            stream.write(bootstrap)
            stream.flush()
            os.fsync(stream.fileno())
        (staging / "bootstrap.sh").chmod(0o755)
        shutil.rmtree(image_bundle_dir)
        staging.rename(output)
        qualification_receipt = {
            "formatVersion": "stateport.j1-local-test-signed-qualification/v2",
            "lane": "integratedQualification",
            "keyClass": "ephemeral-local-qualification",
            "admissibleForRelease": False,
            "publishable": False,
            "productionTrustKeyUsed": False,
            "candidateSourceCommit": source_commit,
            "candidateSourceTree": source_tree,
            "candidateBundle": str(source_bundle),
            "evidenceRoot": str(evidence_root),
            "buildReceipt": str(build_receipt),
            "buildReceiptSha256": _digest(build_receipt),
            "releaseControl": release_control_identity(),
            "grypeDatabaseEvidence": database_receipt_evidence,
            "releaseIndex": str(output / "release-index.json"),
            "releaseIndexSha256": _digest(output / "release-index.json"),
            "signedPayloadDigest": verified["signedPayloadDigest"],
            "verification": verified,
        }
        with (output / "qualification-receipt.json").open("xb") as stream:
            stream.write(json.dumps(qualification_receipt, indent=2, sort_keys=True).encode("utf-8"))
        return {"output": str(output), "releaseIndex": str(output / "release-index.json"), "signedPayloadDigest": verified["signedPayloadDigest"], "sourceCommit": source_commit, "sourceTree": source_tree}
    except Exception:
        if image_bundle_dir.is_dir() and not image_bundle_dir.is_symlink():
            shutil.rmtree(image_bundle_dir)
        discard_unverified_output(staging, output)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--build-receipt", type=Path, required=True)
    parser.add_argument("--private-detectors", type=Path, required=True)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--podman-package-bundle", type=Path, required=True)
    parser.add_argument("--topology", type=Path, default=ROOT / "config/release-topology.v1.yaml")
    parser.add_argument("--signing-key", type=Path, required=True)
    parser.add_argument("--trust-public-key", type=Path, required=True)
    parser.add_argument("--trust-key-id", required=True)
    parser.add_argument("--trust-key-fingerprint", required=True)
    parser.add_argument("--expires-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image-repository", default="127.0.0.1:5443/stateport-alpha")
    parser.add_argument("--release-root-url")
    parser.add_argument("--predecessor-release-index", type=Path)
    parser.parse_args(argv)
    raise QualificationError(INTEGRATED_PHASE_REFUSAL)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (QualificationError, OSError, ValueError, yaml.YAMLError) as exc:
        print(f"qualification candidate refused: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
