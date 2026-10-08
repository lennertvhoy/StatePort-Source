#!/usr/bin/env python3
"""Fail-closed Ubuntu 24.04 clean-host qualification gate.

The stage validates candidate bytes and an operator-produced isolated-guest
receipt. It never turns a missing VM run, a source checkout, or a placeholder
receipt into qualification evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import tarfile
import tempfile
from typing import Any, Mapping, Sequence

import jsonschema


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "packages/release-contracts/src"))
from stateport_release import (  # noqa: E402
    CosignVerifier,
    PinnedPublicKeyIdentity,
    embedded_predecessor_index,
    signature_bundle_name,
    validate_release_index,
)
from stateport_release.contract import ReleaseIndex, verify_release_predecessor  # noqa: E402
CONFIG_SCHEMA = ROOT / "infra/qualification/schemas/ubuntu2404-config.v1.schema.json"
RECEIPT_SCHEMA = ROOT / "infra/qualification/schemas/ubuntu2404-receipt.v1.schema.json"
CONFIG_FORMAT = "stateport.qualification.ubuntu2404-config/v1"
RECEIPT_FORMAT = "stateport.qualification.ubuntu2404-receipt/v1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA1 = re.compile(r"^[0-9a-f]{40}$")


class QualificationRefusal(ValueError):
    """The Ubuntu qualification contract is absent, stale, or incomplete."""


def _load_json(path: Path, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise QualificationRefusal(f"{label} could not be loaded: {exc}") from exc
    if not isinstance(value, Mapping):
        raise QualificationRefusal(f"{label} is not a JSON object")
    return value


def _digest(path: Path, label: str) -> str:
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise QualificationRefusal(f"{label} is unavailable or unsafe: {path}") from exc
    if path.is_symlink() or not path.is_file() or resolved != path.absolute():
        raise QualificationRefusal(f"{label} is unavailable or unsafe: {path}")
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _reject_placeholder(value: str, label: str) -> None:
    raw = value.removeprefix("sha256:")
    if raw and len(set(raw)) == 1:
        raise QualificationRefusal(f"{label} is a placeholder digest")


def _load_release_index(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise QualificationRefusal(f"release index could not be loaded: {exc}") from exc
    if not isinstance(value, Mapping) or value.get("schema") != "stateport.release-index/v1":
        raise QualificationRefusal("candidate release index has an unsupported schema")
    signed = value.get("signed")
    if not isinstance(signed, Mapping) or not value.get("signatures"):
        raise QualificationRefusal("candidate release index is not signed")
    return value


def _verify_signed_release_index(
    config: Mapping[str, Any], release_index_path: Path, signed_payload_path: Path
) -> ReleaseIndex:
    """Verify the index signature and canonical payload with the pinned key."""

    verification = config["verification"]
    public_key = verification["publicKey"]
    signature_bundle = verification["signatureBundle"]
    predecessor_bundle = verification["predecessorSignatureBundle"]
    cosign = verification["cosign"]
    public_key_path = Path(str(public_key["path"]))
    bundle_path = Path(str(signature_bundle["path"]))
    predecessor_bundle_path = Path(str(predecessor_bundle["path"]))
    cosign_path = Path(str(cosign["path"]))
    for path, label, expected in (
        (public_key_path, "qualification public key", public_key["sha256"]),
        (bundle_path, "release index signature bundle", signature_bundle["sha256"]),
        (
            predecessor_bundle_path,
            "predecessor release index signature bundle",
            predecessor_bundle["sha256"],
        ),
        (cosign_path, "qualification Cosign executable", cosign["sha256"]),
    ):
        if _digest(path, label) != expected:
            raise QualificationRefusal(f"{label} digest does not match config")
    raw = _load_release_index(release_index_path)
    try:
        index = validate_release_index(raw, require_signatures=True)
    except Exception as exc:
        raise QualificationRefusal(f"candidate release index validation failed: {exc}") from exc
    signed_payload = signed_payload_path.read_bytes()
    if signed_payload != index.signed_bytes:
        raise QualificationRefusal("signed payload is not the index canonical signed bytes")
    signatures = raw["signatures"]
    if not isinstance(signatures, list) or len(signatures) != 1:
        raise QualificationRefusal("candidate release index must have exactly one signature")
    signature = signatures[0]
    identity = PinnedPublicKeyIdentity(
        str(verification["publicKeyFingerprint"]), str(verification["keyId"])
    )
    if (
        signature.get("publicKeyFingerprint") != identity.public_key_fingerprint
        or signature.get("publicKeyId") != identity.key_id
        or signature.get("subjectDigest") != "sha256:" + hashlib.sha256(index.signed_bytes).hexdigest()
    ):
        raise QualificationRefusal("release index signature is not bound to the configured key and payload")
    with tempfile.TemporaryDirectory(prefix="stateport-ubuntu-index-verify-") as bundle_root:
        try:
            verifier = CosignVerifier(
                cosign=cosign_path,
                public_key=public_key_path,
                identity=identity,
                bundle_root=Path(bundle_root),
            )
            verifier.retain_bundle(bundle_path, signature)
            verifier.verify_blob(index.signed_bytes, signature)
            predecessor = embedded_predecessor_index(index)
            successor = index.document["signed"].get("successor")
            claimed_predecessor = (
                successor.get("predecessor") if isinstance(successor, Mapping) else None
            )
            if predecessor is None or not isinstance(claimed_predecessor, Mapping):
                raise QualificationRefusal("candidate does not bind its signed predecessor")
            predecessor_signature = claimed_predecessor.get("signature")
            if not isinstance(predecessor_signature, Mapping):
                raise QualificationRefusal("candidate predecessor signature is missing")
            expected_predecessor_path = (
                release_index_path.parent
                / "predecessor-bundle"
                / signature_bundle_name(predecessor_signature)
            )
            try:
                predecessor_parent = predecessor_bundle_path.parent.resolve(strict=True)
                expected_parent = expected_predecessor_path.parent.resolve(strict=True)
            except (OSError, RuntimeError) as exc:
                raise QualificationRefusal(
                    "predecessor signature bundle path is unavailable or unsafe"
                ) from exc
            if (
                predecessor_bundle_path.name != expected_predecessor_path.name
                or predecessor_parent != expected_parent
            ):
                raise QualificationRefusal(
                    "predecessor signature bundle is outside the canonical transport path"
                )
            if predecessor_bundle["sha256"] != predecessor_signature["bundle"]["digest"]:
                raise QualificationRefusal(
                    "predecessor signature bundle digest is not signed-index-bound"
                )
            verifier.retain_bundle(predecessor_bundle_path, predecessor_signature)
            authenticated = verify_release_predecessor(
                predecessor,
                expected_trust_mode="pinned-public-key",
                accepted_public_keys=frozenset({identity}),
                verifier=verifier,
                legacy_predecessor=True,
            )
            if authenticated.signature != predecessor_signature:
                raise QualificationRefusal(
                    "candidate predecessor signature is not the authenticated signature"
                )
            for image_id, artifact in config["artifacts"]["images"].items():
                image = next(
                    (
                        item
                        for item in index.document["signed"]["images"]
                        if str(item.get("imageId")) == str(image_id)
                    ),
                    None,
                )
                if not isinstance(image, Mapping):
                    raise QualificationRefusal(f"signed image inventory is missing: {image_id}")
                image_signature = image.get("signature")
                if not isinstance(image_signature, Mapping):
                    raise QualificationRefusal(f"signed image has no signature: {image_id}")
                image_bundle = artifact["signatureBundle"]
                image_bundle_path = Path(str(image_bundle["path"]))
                if _digest(image_bundle_path, f"image signature bundle {image_id}") != image_bundle["sha256"]:
                    raise QualificationRefusal(f"image signature bundle digest does not match config: {image_id}")
                verifier.retain_bundle(image_bundle_path, image_signature)
                verifier.verify_blob(
                    _oci_manifest_bytes(Path(str(artifact["archivePath"])), str(image["digest"])),
                    image_signature,
                )
        except Exception as exc:
            raise QualificationRefusal(f"release index Cosign verification failed: {exc}") from exc
    return index


def _require_candidate_index_digest(
    candidate: Mapping[str, Any], verified_index: ReleaseIndex
) -> None:
    if verified_index.index_digest != candidate["releaseIndexDigest"]:
        raise QualificationRefusal("canonical release index digest is not bound to the candidate")


def _verified_candidate_signed(
    config: Mapping[str, Any], release_index_path: Path, signed_payload_path: Path
) -> Mapping[str, Any]:
    verified_index = _verify_signed_release_index(
        config, release_index_path, signed_payload_path
    )
    _require_candidate_index_digest(config["candidate"], verified_index)
    signed = verified_index.document.get("signed")
    if not isinstance(signed, Mapping):
        raise QualificationRefusal("candidate release index is missing its signed payload")
    return signed


def _verify_oci_manifest(path: Path, expected: str) -> None:
    if _DIGEST.fullmatch(expected) is None:
        raise QualificationRefusal("image manifest digest is malformed")
    if path.is_symlink() or not path.is_file():
        raise QualificationRefusal(f"image archive is unavailable or unsafe: {path}")
    try:
        with tarfile.open(path, mode="r:*") as archive:
            members = {member.name: member for member in archive.getmembers()}
            index_member = members.get("index.json")
            if index_member is None or not index_member.isfile():
                raise QualificationRefusal("image archive has no OCI index")
            index = json.loads(archive.extractfile(index_member).read())  # type: ignore[union-attr]
            manifests = index.get("manifests") if isinstance(index, Mapping) else None
            if not isinstance(manifests, list) or len(manifests) != 1:
                raise QualificationRefusal("image archive does not contain one manifest")
            descriptor = manifests[0]
            if not isinstance(descriptor, Mapping) or descriptor.get("digest") != expected:
                raise QualificationRefusal("image archive manifest is not candidate-bound")
            blob = members.get("blobs/sha256/" + expected.removeprefix("sha256:"))
            if blob is None or not blob.isfile():
                raise QualificationRefusal("image archive manifest blob is missing")
            payload = archive.extractfile(blob).read()  # type: ignore[union-attr]
            if "sha256:" + hashlib.sha256(payload).hexdigest() != expected:
                raise QualificationRefusal("image archive manifest bytes are tampered")
    except (OSError, tarfile.TarError, json.JSONDecodeError) as exc:
        raise QualificationRefusal(f"image archive verification failed: {exc}") from exc


def _oci_manifest_bytes(path: Path, expected: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise QualificationRefusal(f"image archive is unavailable or unsafe: {path}")
    try:
        with tarfile.open(path, mode="r:*") as archive:
            member = archive.getmember("blobs/sha256/" + expected.removeprefix("sha256:"))
            if not member.isfile():
                raise QualificationRefusal("image archive manifest blob is not a regular file")
            payload = archive.extractfile(member).read()  # type: ignore[union-attr]
    except (OSError, tarfile.TarError, KeyError) as exc:
        raise QualificationRefusal(f"image archive manifest could not be read: {exc}") from exc
    if "sha256:" + hashlib.sha256(payload).hexdigest() != expected:
        raise QualificationRefusal("image archive manifest bytes are tampered")
    return payload


def _validate_schema(value: Mapping[str, Any], schema_path: Path, label: str) -> None:
    schema = _load_json(schema_path, f"{label} schema")
    try:
        jsonschema.Draft202012Validator(schema).validate(value)
    except jsonschema.ValidationError as exc:
        raise QualificationRefusal(f"{label} schema validation failed: {exc.message}") from exc


def _validate_candidate_artifacts(config: Mapping[str, Any]) -> None:
    candidate = config["candidate"]
    artifacts = config["artifacts"]
    for key in (
        "releaseIndex",
        "signedPayload",
        "installer",
        "executionHostProvisioner",
        "updater",
    ):
        item = artifacts[key]
        path = Path(str(item["path"]))
        observed = _digest(path, f"candidate artifact {key}")
        if observed != item["sha256"]:
            raise QualificationRefusal(f"candidate artifact {key} digest does not match config")
        _reject_placeholder(str(item["sha256"]), f"candidate artifact {key}")
    if artifacts["signedPayload"]["sha256"] != candidate["signedPayloadDigest"]:
        raise QualificationRefusal("signed payload digest is not bound to the candidate")
    if artifacts["installer"]["sha256"] != candidate["installerDigest"]:
        raise QualificationRefusal("installer digest is not bound to the candidate")
    image_digests: list[str] = []
    for image_id, image in artifacts["images"].items():
        observed = _digest(Path(str(image["archivePath"])), f"image archive {image_id}")
        if observed != image["archiveDigest"]:
            raise QualificationRefusal(f"image archive digest does not match config: {image_id}")
        _reject_placeholder(str(image["archiveDigest"]), f"image archive {image_id}")
        _verify_oci_manifest(Path(str(image["archivePath"])), str(image["manifestDigest"]))
        image_digests.append(str(image["manifestDigest"]))
    if sorted(image_digests) != sorted(candidate["imageDigests"]):
        raise QualificationRefusal("image manifest digests are not bound to the candidate")
    release_index_path = Path(str(artifacts["releaseIndex"]["path"]))
    signed = _verified_candidate_signed(
        config,
        release_index_path,
        Path(str(artifacts["signedPayload"]["path"])),
    )
    release = signed.get("release") if isinstance(signed, Mapping) else None
    source = signed.get("source") if isinstance(signed, Mapping) else None
    images = signed.get("images") if isinstance(signed, Mapping) else None
    if not isinstance(release, Mapping) or not isinstance(source, Mapping) or not isinstance(images, tuple):
        raise QualificationRefusal("candidate release index is missing signed identity fields")
    targets = signed.get("targets") if isinstance(signed, Mapping) else None
    if (release.get("releaseId"), release.get("version")) != (
        candidate["releaseId"], candidate["version"]
    ) or not isinstance(targets, tuple) or [
        target.get("targetId") for target in targets if isinstance(target, Mapping)
    ] != [candidate["targetId"]]:
        raise QualificationRefusal("release identity does not match the candidate")
    if (source.get("commit"), source.get("tree")) != (candidate["sourceCommit"], candidate["sourceTree"]):
        raise QualificationRefusal("release source identity does not match the candidate")
    public = source.get("publicSnapshot")
    if not isinstance(public, Mapping) or {
        "authorityUrl": public.get("authorityUrl"),
        "ref": public.get("ref"),
        "commit": public.get("commit"),
        "tree": public.get("tree"),
    } != candidate["publicSource"]:
        raise QualificationRefusal("public source identity does not match the candidate")
    signed_images = {
        str(image.get("imageId")): image for image in images if isinstance(image, Mapping)
    }
    if set(artifacts["images"]) != set(signed_images):
        raise QualificationRefusal("configured image archives do not match the signed image inventory")
    for image_id, configured in artifacts["images"].items():
        if configured["manifestDigest"] != signed_images[image_id].get("digest"):
            raise QualificationRefusal(f"image manifest digest is not signed-index-bound: {image_id}")
    observed_images = sorted(str(image.get("digest")) for image in signed_images.values())
    if observed_images != sorted(candidate["imageDigests"]):
        raise QualificationRefusal("release image inventory does not match the candidate")
    signed_image_references = []
    for image_id, image in signed_images.items():
        reference = str(image.get("reference", ""))
        if not reference.endswith("@" + str(image.get("digest", ""))):
            raise QualificationRefusal(
                f"signed image reference is not digest pinned: {image_id}"
            )
        signed_image_references.append(reference)
    updater = signed.get("artifacts", {}).get("updater")
    if not isinstance(updater, Mapping) or updater.get("digest") != artifacts["updater"]["sha256"]:
        raise QualificationRefusal("updater artifact is not signed-index-bound")
    provisioner = signed.get("artifacts", {}).get("executionHostProvisioner")
    if (
        not isinstance(provisioner, Mapping)
        or provisioner.get("digest") != artifacts["executionHostProvisioner"]["sha256"]
    ):
        raise QualificationRefusal("execution-host provisioner is not signed-index-bound")
    target = next(
        (
            target
            for target in signed.get("targets", [])
            if isinstance(target, Mapping) and target.get("targetId") == candidate["targetId"]
        ),
        None,
    )
    contract = target.get("executionContract") if isinstance(target, Mapping) else None
    host_image_id = contract.get("imageId") if isinstance(contract, Mapping) else None
    if not isinstance(host_image_id, str) or signed_images.get(host_image_id, {}).get("role") != "stable-host-service":
        raise QualificationRefusal("signed target does not bind a stable execution-host image")
    if contract.get("imageDigest") != signed_images[host_image_id].get("digest"):
        raise QualificationRefusal("signed execution-host contract is not image-bound")
    guest_stage = config["guestStage"]
    if set(guest_stage["ownedImages"]) != set(signed_images):
        raise QualificationRefusal("qualification cleanup image inventory is not signed-index-bound")
    required_services = {
        "stateport-accepted.target",
        "stateport-execution-host.service",
        "podman.socket",
    }
    if not required_services.issubset(set(guest_stage["ownedServices"])):
        raise QualificationRefusal("qualification cleanup service inventory is incomplete")
    config["_executionHostImageId"] = host_image_id
    config["_executionHostImageDigest"] = str(signed_images[host_image_id].get("digest"))
    config["_signedImageReferences"] = signed_image_references


def validate_config(value: Mapping[str, Any]) -> Mapping[str, Any]:
    if value.get("schema") != CONFIG_FORMAT:
        raise QualificationRefusal("Ubuntu qualification config schema is unsupported")
    _validate_schema(value, CONFIG_SCHEMA, "Ubuntu qualification config")
    if value["guest"]["distribution"] != "ubuntu" or value["guest"]["version"] != "24.04":
        raise QualificationRefusal("Ubuntu qualification is restricted to Ubuntu 24.04")
    validated = dict(value)
    _validate_candidate_artifacts(validated)
    return validated


def validate_receipt(receipt: Mapping[str, Any], config: Mapping[str, Any]) -> Mapping[str, Any]:
    if receipt.get("schema") != RECEIPT_FORMAT:
        raise QualificationRefusal("Ubuntu qualification receipt schema is unsupported")
    if receipt.get("evidenceClass") != "real_guest":
        raise QualificationRefusal("fixture or simulated evidence cannot qualify as a real Ubuntu guest")
    _validate_schema(receipt, RECEIPT_SCHEMA, "Ubuntu qualification receipt")
    if receipt["candidate"] != config["candidate"]:
        raise QualificationRefusal("Ubuntu receipt is bound to a different candidate")
    guest = receipt["guest"]
    if guest["distribution"] != "ubuntu" or guest["version"] != "24.04":
        raise QualificationRefusal("receipt is not an Ubuntu 24.04 guest")
    if guest["guestId"] != config["guest"]["guestId"]:
        raise QualificationRefusal("receipt guest identity does not match config")
    if not guest["isolated"] or guest["sourceCheckoutPresent"] or guest["preExistingStatePortImages"] or guest["preExistingStatePortServices"]:
        raise QualificationRefusal("receipt does not prove an isolated clean guest")
    facts = guest["hostFacts"]
    if facts["wslDetected"] or not facts["kernelRelease"]:
        raise QualificationRefusal("receipt does not prove a native Linux substrate")
    if not facts["podmanVersionMeetsFloor"]:
        raise QualificationRefusal("guest Podman version is below the required floor")
    if not facts["eligible"]:
        raise QualificationRefusal("guest capability evaluation is ineligible")
    execution = receipt["executionHostReceipt"]
    if (
        execution["imageId"] != config["_executionHostImageId"]
        or
        execution["sourceCommit"] != config["candidate"]["sourceCommit"]
        or execution["sourceTree"] != config["candidate"]["sourceTree"]
        or execution["installerDigest"] != config["candidate"]["installerDigest"]
        or execution["imageDigest"] != config["_executionHostImageDigest"]
    ):
        raise QualificationRefusal("execution-host receipt is not bound to the exact candidate")
    stages = receipt["stages"]
    required = [
        "capability_evaluation", "provisioning", "install", "protocol_health",
        "persistence_reboot", "reinstall_convergence", "cleanup",
    ]
    if [stage["stageId"] for stage in stages] != required or any(stage["result"] != "passed" for stage in stages):
        raise QualificationRefusal("Ubuntu receipt does not contain every passed required stage")
    if execution["protocolHealth"]["describeCapabilities"] is not True:
        raise QualificationRefusal("execution-host describeCapabilities health is unproven")
    if execution["protocolHealth"]["result"] != "passed":
        raise QualificationRefusal("execution-host protocol health did not pass")
    if receipt["cleanup"] != {
        "result": "passed",
        "removedImages": True,
        "removedServices": True,
        "removedAccounts": True,
        "removedGroups": True,
        "removedSubordinateMappings": True,
        "removedRootArtifacts": True,
    }:
        raise QualificationRefusal("clean-host cleanup did not pass")
    return receipt


def qualify(config_path: Path, receipt_path: Path) -> dict[str, str]:
    config = validate_config(_load_json(config_path, "Ubuntu qualification config"))
    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise QualificationRefusal("a real Ubuntu 24.04 receipt is required; none is available")
    _reject_placeholder(str(config["receipt"]["sha256"]), "configured Ubuntu qualification receipt")
    if _digest(receipt_path, "Ubuntu qualification receipt") != config["receipt"]["sha256"]:
        raise QualificationRefusal("Ubuntu qualification receipt digest does not match config")
    receipt = validate_receipt(_load_json(receipt_path, "Ubuntu qualification receipt"), config)
    return {
        "status": "qualified_candidate_only",
        "receiptDigest": config["receipt"]["sha256"],
        "guestId": str(receipt["guest"]["guestId"]),
        "qualification": "Ubuntu 24.04 exact isolated clean-host receipt validated",
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = qualify(args.config, args.receipt)
    except (OSError, QualificationRefusal) as exc:
        print(f"qualification: refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
