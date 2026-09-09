from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import os
import re
import shutil
import subprocess
import sys
import tarfile

import jsonschema
import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages/release-contracts/src"))

from stateport_release import (  # noqa: E402
    ReleaseContractError,
    ReleaseVerificationPolicy,
    PinnedPublicKeyIdentity,
    SignatureVerificationProof,
    SignerIdentity,
    canonical_digest,
    canonical_json_bytes,
    image_set_digest,
    installer_directive_digest,
    load_release_index,
    load_release_index_file,
    quadlet_bundle_digest,
    materialize_accepted_quadlet_bundle,
    materialize_verified_quadlet_bundle,
    owner_materialization_spec_digest,
    derive_revision_authority_proofs,
    plan_stable_host_service_transition,
    record_revision_port_activation_recheck,
    reserve_revision_port_allocation,
    render_accepted_activation,
    revision_contract_digest,
    render_quadlet_bundle,
    render_stable_host_quadlet_bundle,
    release_identity_from_verified,
    service_set_digest,
    reverify_updater_release_envelope,
    signed_payload_bytes,
    signature_verification_proof_set_digest,
    topology_digest,
    to_updater_release_envelope,
    validate_install_receipt,
    validate_activation_pointer_transition,
    validate_revision_contract,
    validate_release_provenance,
    validate_update_failure_evidence,
    validate_update_authority_link,
    validate_update_plan,
    validate_update_receipt,
    validate_update_status,
    update_plan_digest,
    update_policy_digest,
    validate_release_index,
    verify_release_index,
    verify_quadlet_bundle,
    verify_stable_host_quadlet_bundle,
)
from stateport_release.cosign import (  # noqa: E402
    CosignVerificationError,
    CosignVerifier,
    bundle_slot,
    public_key_der_spki_fingerprint,
    retain_bundle,
    signature_bundle_name,
)
from stateport_release.contract import (  # noqa: E402
    parse_last_line_json,
    validate_release_disposition,
    validate_successor_disposition_transition,
    verify_release_predecessor,
)


HEX = "a" * 64
DIGEST = f"sha256:{HEX}"
COMMIT = "b" * 40
TREE = "c" * 40
SIGNER = SignerIdentity(
    "https://github.com/stateport/stateport/.github/workflows/private-release-candidate.yml@refs/heads/agent/integration",
    "https://token.actions.githubusercontent.com",
)
PINNED_KEY = PinnedPublicKeyIdentity(f"sha256:{'9' * 64}", "stateport-alpha-private-2026-08")


def _artifact(name: str, *, digest: str = DIGEST) -> dict[str, object]:
    return {
        "uri": f"operator://release/{name}",
        "digest": digest,
        "size": 64,
        "mediaType": "application/json",
    }


def _signature(subject_digest: str, name: str) -> dict[str, object]:
    return {
        "scheme": "cosign-v3-bundle",
        "subjectDigest": subject_digest,
        "bundle": _artifact(f"{name}.sigstore.json"),
        "trustMode": "keyless-certificate",
        "certificateIdentity": SIGNER.certificate_identity,
        "certificateOidcIssuer": SIGNER.oidc_issuer,
        "transparencyLog": "not-uploaded-private-candidate",
    }


def _pinned_key_signature(subject_digest: str, name: str) -> dict[str, object]:
    return {
        "scheme": "cosign-v3-bundle",
        "subjectDigest": subject_digest,
        "bundle": _artifact(f"{name}.sigstore.json"),
        "trustMode": "pinned-public-key",
        "publicKeyFingerprint": PINNED_KEY.public_key_fingerprint,
        "publicKeyFingerprintAlgorithm": "sha256-canonical-der-spki",
        "publicKeyId": PINNED_KEY.key_id,
        "transparencyLog": "not-uploaded-private-candidate",
    }


def release_index() -> dict[str, object]:
    artifacts = {
        name: _artifact(name)
        for name in (
            "installer",
            "executionHostProvisioner",
            "updater",
            "compose",
            "quadlet",
            "sourceArchive",
            "releaseNotes",
            "knownLimitations",
        )
    }
    signed: dict[str, object] = {
        "release": {
            "releaseId": "stateport-alpha-0.2.0-rc.1",
            "version": "0.2.0-rc.1",
            "channel": "alpha",
            "qualification": "candidate",
        },
        "source": {
            "repository": "https://github.com/stateport/stateport.git",
            "commit": COMMIT,
            "tree": TREE,
            "dirty": False,
            "publicSnapshot": {
                "repository": "https://github.com/stateport/stateport-public.git",
                "commit": "d" * 40,
                "tree": "e" * 40,
                "manifestDigest": DIGEST,
            },
        },
        "signaturePolicy": {
            "trustMode": "keyless-certificate",
            "imageSignaturesRequired": True,
            "verificationProof": "stateport.signature-verification-proof/v1",
        },
        "targets": [
            {
                "targetId": "linux-amd64-rootless-podman-quadlet",
                "releaseId": "stateport-alpha-0.2.0-rc.1",
                "releaseEligibility": "release-candidate",
                "os": "linux",
                "architecture": "amd64",
                "hostBaseline": "linux-amd64-rootless-podman-quadlet",
                "cgroupVersion": "v2",
                "containerEngine": "rootless-podman-quadlet",
                "artifactIds": sorted(artifacts),
                "services": [
                    {
                        "serviceId": "stateport-web",
                        "imageId": "stateport-web",
                        "trustDomain": "control",
                        "quadletOwner": "stateport-control",
                        "revisionScoped": True,
                        "runAsUser": 65532,
                        "readOnlyRoot": True,
                        "health": {"kind": "http", "containerPort": 8080, "path": "/readyz"},
                        "ports": [
                            {
                                "name": "http",
                                "containerPort": 8080,
                                "hostScope": "loopback",
                                "allocation": "full-revision-digest-derived-collision-probed",
                            }
                        ],
                        "writableVolumes": [
                            {
                                "name": "stateport-data",
                                "mountPath": "/var/lib/stateport",
                                "purpose": "durable-state",
                                "scope": "installation",
                                "validation": {
                                    "mode": "read-only-snapshot-copy",
                                    "authority": "exact-backup-receipt-required",
                                },
                            }
                        ],
                        "resources": {
                            "memoryMaxBytes": 1073741824,
                            "cpuQuotaPercent": 200,
                            "pidsMax": 512,
                        },
                        "capabilities": {
                            "podmanSocketAccess": "none",
                            "controlContract": "none",
                        },
                    }
                ],
            }
        ],
        "artifacts": artifacts,
        "images": [
            {
                "imageId": "stateport-web",
                "role": "runtime-service",
                "reference": f"ghcr.io/stateport/stateport-web@{DIGEST}",
                "digest": DIGEST,
                "sourceCommit": COMMIT,
                "sourceTree": TREE,
                "platform": "linux/amd64",
                "sizeBytes": 1048576,
                "runAsUser": 65532,
                "readOnlyRoot": True,
                "healthProbe": {
                    "executable": "/usr/local/bin/stateport-healthcheck",
                    "protocol": "stateport-healthcheck/v1",
                    "packageInventoryDigest": DIGEST,
                    "evidence": _artifact("web.healthcheck.json"),
                },
                "sboms": {
                    "cycloneDx": _artifact("web.cdx.json"),
                    "spdx": _artifact("web.spdx.json"),
                },
                "scan": {
                    "artifact": _artifact("web.grype.json"),
                    "tool": "grype",
                    "toolVersion": "0.117.0",
                    "databaseBuiltAt": "2026-08-01T08:00:00Z",
                    "scannedAt": "2026-08-01T09:00:00Z",
                    "maxDatabaseAgeHours": 24,
                    "maxScanAgeHours": 24,
                    "policy": "stateport.grype-policy/v1",
                },
                "provenance": _artifact("web.provenance.json"),
                "signature": _signature(DIGEST, "web"),
                "packageInventory": _artifact("web.packages.json"),
                "licenseInventory": _artifact("web.licenses.json"),
            }
        ],
        "supplyChain": {
            "tools": [
                {
                    "name": name,
                    "version": version,
                    "executableDigest": DIGEST,
                    "provenance": _artifact(f"{name}.provenance.json"),
                }
                for name, version in (
                    ("syft", "1.51.0"),
                    ("grype", "0.117.0"),
                    ("cosign", "3.1.3"),
                )
            ],
            "doubleBuildComparison": _artifact("double-build.json"),
            "publicExportManifest": _artifact("public-export.json"),
        },
        "compatibility": {
            "updaterMinimumVersion": "0.1.0",
            "schemaMigrationVersion": 1,
            "databaseMigrationVersion": 1,
            "predecessor": {
                "releaseId": "stateport-alpha-0.1.0",
                "version": "0.1.0",
                "signedPayloadDigest": f"sha256:{'f' * 64}",
            },
            "rollback": {
                "supported": True,
                "minimumPredecessorVersion": "0.1.0",
                "dataCompatible": True,
                "reason": "Alpha predecessor remains retained and data compatible.",
            },
        },
        "publication": {
            "publishedAt": None,
            "expiresAt": "2026-09-01T00:00:00Z",
            "deprecation": {"status": "active", "at": None, "reason": None},
        },
    }
    target = signed["targets"][0]
    host_image = deepcopy(signed["images"][0])
    host_image["imageId"] = "stateport-execution-host"
    host_image["role"] = "stable-host-service"
    host_image["reference"] = f"ghcr.io/stateport/stateport-execution-host@{DIGEST}"
    signed["images"].append(host_image)
    target["services"][0]["capabilities"]["controlContract"] = "narrow-unix-client"
    target["executionHostMode"] = "stable-host-daemon-client"
    target["hostServices"] = [
        {
            "serviceId": "stateport-execution-host",
            "imageId": "stateport-execution-host",
            "trustDomain": "execution",
            "quadletOwner": "stateport-exec",
            "revisionScoped": False,
            "lifecycle": "stable-out-of-revision",
            "runAsUser": 65532,
            "userNamespace": "keep-id",
            "readOnlyRoot": True,
            "engineAccess": {
                "mode": "owned-execution-user-podman-socket",
                "owner": "stateport-exec",
                "hostPath": "%t/podman",
                "containerPath": "/run/stateport-engine",
                "access": "read-write",
            },
            "socket": {
                "transport": "confined-host-unix-socket",
                "hostDirectory": "/run/stateport/execution-control",
                "socketName": "control.sock",
                "directoryOwner": "stateport-exec",
                "directoryGroup": "stateport-execution-control",
                "allowedClientUser": "stateport-control",
                "directoryMode": "2750",
                "socketMode": "0660",
                "peerIdentity": "unix-peer-credentials-required",
            },
            "ports": [
                {
                    "name": "metrics",
                    "containerPort": 9911,
                    "hostPort": 17001,
                    "hostScope": "private-proxy",
                    "allocation": "stable-operator-bound",
                }
            ],
            "writableVolumes": [
                {
                    "name": "execution-state",
                    "hostPath": "/var/lib/stateport-exec/stateport-execution-host/state",
                    "mountPath": "/var/lib/stateport/execution-host",
                    "purpose": "durable-state",
                    "scope": "stable-host-service",
                    "owner": "stateport-exec",
                    "mode": "rw",
                }
            ],
            "resources": {
                "memoryMaxBytes": 536870912,
                "cpuQuotaPercent": 100,
                "pidsMax": 256,
            },
            "logging": {"driver": "k8s-file", "maxSizeBytes": 10485760},
            "health": {
                "kind": "unix-socket",
                "value": "/run/stateport-execution/control.sock",
            },
            "updateCompatibility": {
                "contractVersion": 1,
                "minimumClientVersion": 1,
                "maximumClientVersion": 2,
                "replacementPolicy": "explicit-compatible-host-update-only",
            },
        }
    ]
    target["executionContract"] = {
        "transport": "confined-host-unix-socket",
        "serviceId": "stateport-execution-host",
        "imageId": "stateport-execution-host",
        "imageDigest": DIGEST,
        "contractVersion": 1,
        "clientCompatibility": {"minimum": 1, "maximum": 2},
        "hostDirectory": "/run/stateport/execution-control",
        "containerDirectory": "/run/stateport-execution",
        "socketName": "control.sock",
        "bootstrap": "operator-provisioned-tmpfiles",
        "directoryOwner": "stateport-exec",
        "directoryGroup": "stateport-execution-control",
        "allowedClientUser": "stateport-control",
        "directoryMode": "2750",
        "socketMode": "0660",
        "peerIdentity": "unix-peer-credentials-required",
        "socketGroupGid": 65530,
        "allowedClientUid": 65531,
        "allowedClientGid": 65531,
        "runtimeUid": 65532,
        "runtimeGid": 65532,
    }
    target["runtimeDerivation"] = {
        "format": "stateport.revision-materialization/v2",
        "profiles": ["validation", "accepted"],
        "materialization": {
            "templateTokenVersion": "stateport.quadlet-template/v2",
            "stageRoot": "/var/lib/stateport/releases/staged",
            "liveQuadletRoots": {
                "stateport-control": "xdg-config-containers-systemd",
                "stateport-exec": "xdg-config-containers-systemd",
            },
            "regularSystemdRoot": "xdg-config-systemd-user",
            "candidateLocation": "outside-live-quadlet-search-roots",
            "acceptedLocation": "copied-after-acceptance-cas-only",
        },
        "portPolicy": {
            "algorithm": "sha256-full-revision-service-port-modulo-probe-v1",
            "rangeStart": 18000,
            "rangeEnd": 18999,
            "probeStep": 17,
            "maximumAttempts": 512,
            "collisionInputs": ["current", "predecessor", "candidate"],
            "observedHostCollision": "installer-refuses-before-start",
        },
        "stateMachine": {
            "stage": [
                "verify-images-by-digest-and-signature",
                "materialize-outside-live-quadlet-roots",
                "verify-materialization-manifest",
                "pre-pull-with-pull-never-runtime",
            ],
            "validate": [
                "create-exact-backup-or-snapshot-copy",
                "start-validation-profile-only",
                "run-health-api-browser-and-state-checks",
                "stop-validation-profile",
                "retain-validation-evidence",
            ],
            "promote": [
                "acquire-quiesced-maintenance-lease",
                "stop-and-discard-validation-generation",
                "fence-ingress-and-quiesce-predecessor-writers",
                "write-fresh-authoritative-backup-d0",
                "create-and-migrate-distinct-data-generation-d1",
                "fsync-data-generation-d1",
                "run-private-candidate-checks-on-d1",
                "write-durable-activation-decision-receipt-r1",
                "reconcile-owner-bundles-per-user",
                "atomically-materialize-and-fsync-regular-target-and-route-projections",
                "daemon-reload-control-user",
                "explicitly-start-observe-and-stop-candidate",
                "write-terminal-promotion-receipts",
                "switch-ingress-and-unfence",
                "retain-predecessor",
            ],
            "rollback": [
                "stop-failed-candidate",
                "evaluate-data-compatibility",
                "restore-or-reuse-data-only-if-authorized",
                "copy-predecessor-profile-to-live-quadlet-roots",
                "daemon-reload",
                "start-predecessor",
                "run-health-and-state-checks",
                "route-cas-to-predecessor",
                "enable-predecessor-activation-target",
                "retain-failure-evidence",
                "do-not-claim-external-side-effect-reversal",
            ],
            "rebootRecovery": [
                "load-accepted-pointer",
                "verify-acceptance-receipt",
                "materialize-only-accepted-live-units",
                "daemon-reload",
                "start-accepted-activation-target",
                "refuse-staged-or-stale-auto-start",
            ],
            "activationCas": "generation-and-acceptance-receipt-digest",
        },
    }
    target["topologyDigest"] = topology_digest(target)
    target["quadletBundleDigest"] = quadlet_bundle_digest(
        render_quadlet_bundle(target, signed["images"])
    )
    return {
        "schema": "stateport.release-index/v1",
        "signed": signed,
        "signatures": [_signature(canonical_digest(signed), "release-index")],
    }


def _successor_index(
    predecessor: dict[str, object],
    *,
    version: str = "0.3.0-rc.1",
    disposition_sequence: int = 1,
) -> dict[str, object]:
    value = deepcopy(release_index())
    signed = value["signed"]
    signed["release"]["releaseId"] = "stateport-alpha-0.3.0-rc.1"
    signed["release"]["version"] = version
    target = signed["targets"][0]
    target["releaseId"] = signed["release"]["releaseId"]
    target["topologyDigest"] = topology_digest(target)
    target["quadletBundleDigest"] = quadlet_bundle_digest(
        render_quadlet_bundle(target, signed["images"])
    )
    predecessor_index = validate_release_index(predecessor)
    predecessor_identity = {
        "releaseId": predecessor_index.release_id,
        "version": predecessor_index.version,
        "signedPayloadDigest": predecessor_index.signed_digest,
    }
    signed["compatibility"]["predecessor"] = predecessor_identity
    event: dict[str, object] = {
        "formatVersion": "stateport.release-qualification/v1",
        "releaseId": signed["release"]["releaseId"],
        "version": version,
        "qualifiedAt": "2026-08-01T09:30:00Z",
        "result": "qualified",
        "freshnessBasis": "scan-and-database-checked-at-qualification",
        "images": [
            {
                "imageId": image["imageId"],
                "digest": image["digest"],
                "databaseBuiltAt": image["scan"]["databaseBuiltAt"],
                "scannedAt": image["scan"]["scannedAt"],
            }
            for image in sorted(signed["images"], key=lambda item: item["imageId"])
        ],
    }
    event["eventId"] = canonical_digest(event)
    signed["successor"] = {
        "formatVersion": "stateport.release-successor/v1",
        "qualificationEvent": event,
        "disposition": {
            "formatVersion": "stateport.release-disposition/v2",
            "signedBy": "stateport.release-index/v1",
            "sequence": disposition_sequence,
            "status": "active",
            "at": None,
            "reason": None,
            "previousDispositionDigest": None,
        },
        "predecessor": {
            "formatVersion": "stateport.release-predecessor/v1",
            **predecessor_identity,
            "indexDigest": predecessor_index.index_digest,
            "signature": deepcopy(predecessor["signatures"][0]),
            "rawIndex": json.loads(predecessor_index.canonical_index_bytes),
        },
        "versionBindings": {
            "releaseVersion": version,
            "buildReceiptFormatVersion": "stateport.release-image-build-receipt/v1",
            "buildReceiptVersion": version,
            "imageEvidenceFormatVersion": "stateport.release-image-evidence/v1",
            "qualificationEventFormatVersion": "stateport.release-qualification/v1",
        },
    }
    value["signatures"] = [_signature(canonical_digest(signed), "release-index")]
    return value


class _EphemeralTestVerifier:
    """Structural test double; never release-signing evidence."""

    def __init__(self) -> None:
        self.payloads: list[bytes] = []
        self.images: list[str] = []

    def _proof(self, signature: dict[str, object]) -> SignatureVerificationProof:
        if signature["trustMode"] == "keyless-certificate":
            primary = str(signature["certificateIdentity"])
            secondary = str(signature["certificateOidcIssuer"])
        else:
            primary = str(signature["publicKeyFingerprint"])
            secondary = str(signature["publicKeyId"])
        return SignatureVerificationProof(
            subject_digest=str(signature["subjectDigest"]),
            bundle_digest=str(signature["bundle"]["digest"]),
            trust_mode=str(signature["trustMode"]),
            identity_primary=primary,
            identity_secondary=secondary,
            verified_at=datetime(2026, 8, 1, 9, 30, tzinfo=timezone.utc),
            transparency_log_mode=str(signature["transparencyLog"]),
        )

    def verify_blob(
        self, payload: bytes, signature: dict[str, object]
    ) -> SignatureVerificationProof:
        assert signature["scheme"] == "cosign-v3-bundle"
        self.payloads.append(payload)
        return self._proof(signature)

    def retain_bundle(self, source: Path, signature: dict[str, object]) -> None:
        """Typed seam double: the structural verifier never touches the disk."""
        assert signature["scheme"] == "cosign-v3-bundle"
        return None

    def verify_image(
        self, reference: str, signature: dict[str, object]
    ) -> SignatureVerificationProof:
        assert reference.endswith(str(signature["subjectDigest"]))
        self.images.append(reference)
        return self._proof(signature)


class _CanonicalAuthorityResolver:
    """Test double for exact protected-store lookup, never release evidence."""

    def __init__(self, documents: dict[str, dict[str, object]]) -> None:
        self.documents = deepcopy(documents)

    def resolve_revision_authority(
        self,
        *,
        request_id: str,
        reservation_id: str,
        claim_id: str,
        receipt_id: str,
    ) -> dict[str, dict[str, object]]:
        assert self.documents["reservation"]["requestId"] == request_id
        assert self.documents["reservation"]["reservationId"] == reservation_id
        assert self.documents["claim"]["claimId"] == claim_id
        assert self.documents["receipt"]["receiptId"] == receipt_id
        return deepcopy(self.documents)


def _policy(**changes: object) -> ReleaseVerificationPolicy:
    values: dict[str, object] = {
        "expected_channel": "alpha",
        "expected_target": "linux-amd64-rootless-podman-quadlet",
        "updater_version": "0.1.0",
        "accepted_signers": frozenset({SIGNER}),
        "expected_trust_mode": "keyless-certificate",
        "now": datetime(2026, 8, 1, 10, tzinfo=timezone.utc),
        "allow_candidate": True,
    }
    values.update(changes)
    return ReleaseVerificationPolicy(**values)


DATA_D0 = f"data_{'0' * 32}"
DATA_D1 = f"data_{'1' * 32}"
DATA_D2 = f"data_{'2' * 32}"
DATA_D1_DIGEST = f"sha256:{'1' * 64}"
DATA_D2_DIGEST = f"sha256:{'2' * 64}"
ROUTE_DIGEST = f"sha256:{'7' * 64}"


def _derived_contract(
    value: dict[str, object],
    *,
    digest_field: str,
    id_field: str | None = None,
    id_prefix: str | None = None,
) -> dict[str, object]:
    digest = revision_contract_digest(value, digest_field=digest_field, id_field=id_field)
    value[digest_field] = digest
    if id_field is not None:
        assert id_prefix is not None
        value[id_field] = f"{id_prefix}{digest[7:39]}"
    validate_revision_contract(value)
    return value


def _embedded(files: dict[str, bytes], suffix: str) -> dict[str, object]:
    matches = [content for path, content in files.items() if path.endswith(suffix)]
    assert len(matches) == 1
    return json.loads(matches[0])


def _authority_digest(value: dict[str, object]) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _authority_documents(
    verified: object, *, operation_plan_digest: str = DIGEST
) -> dict[str, dict[str, object]]:
    request_id = f"authority_request_{'1' * 32}"
    reservation_id = f"authority_reservation_{'1' * 32}"
    claim_id = f"authority_claim_{'1' * 32}"
    authorized_by = {
        "type": "grant",
        "id": "grant_release_activation_test_001",
        "digest": f"sha256:{'2' * 64}",
    }
    scope = {
        "repository": {
            "canonicalPath": "/srv/stateport",
            "gitCommonDir": "/srv/stateport/.git",
            "remoteUrl": "https://github.com/stateport/stateport.git",
            "identityDigest": f"sha256:{'3' * 64}",
        },
        "branch": "agent/integration",
        "sliceId": verified.target["targetId"],
        "applicationId": verified.index.release_id,
        "runId": operation_plan_digest,
        "paths": ["release-index.json"],
    }
    decision_body: dict[str, object] = {
        "schema": "stateport.authority-decision/v1",
        "requestId": request_id,
        "action": "apply_deployment",
        "actorId": "stateport-updater",
        "authorizedBy": authorized_by,
        "scope": scope,
        "profile": "balanced",
        "configuredPolicy": "auto_with_receipt",
        "policy": "auto_with_receipt",
        "decision": "authorized",
        "reason": "scope_matched",
        "missingAssurances": [],
        "estimatedCostUsd": 0.0,
        "estimatedDurationSeconds": 60,
        "requestedCapabilities": {
            "domains": [],
            "provider": None,
            "secretCapabilities": [],
            "assurances": [],
            "sourceIdentity": None,
        },
        "decidedAt": "2026-08-01T09:39:45.000000Z",
    }
    decision = {**decision_body, "decisionDigest": _authority_digest(decision_body)}
    reservation_body: dict[str, object] = {
        "schema": "stateport.authority-action-reservation/v1",
        "reservationId": reservation_id,
        "requestId": request_id,
        "decision": decision,
        "reservedAt": "2026-08-01T09:39:50.000000Z",
    }
    reservation = {
        **reservation_body,
        "reservationDigest": _authority_digest(reservation_body),
    }
    claim_body: dict[str, object] = {
        "schema": "stateport.authority-action-claim/v1",
        "claimId": claim_id,
        "requestId": request_id,
        "reservationId": reservation_id,
        "reservationDigest": reservation["reservationDigest"],
        "decisionDigest": decision["decisionDigest"],
        "claimedAt": "2026-08-01T09:40:05.000000Z",
    }
    claim = {**claim_body, "claimDigest": _authority_digest(claim_body)}
    receipt_body: dict[str, object] = {
        "schema": "stateport.authority-action-receipt/v1",
        "receiptId": f"authority_receipt_{'4' * 32}",
        "requestId": request_id,
        "action": "apply_deployment",
        "actorId": "stateport-updater",
        "authorizedBy": authorized_by,
        "scope": scope,
        "profile": "balanced",
        "configuredPolicy": "auto_with_receipt",
        "policy": "auto_with_receipt",
        "decision": "authorized",
        "result": {
            "status": "succeeded",
            "code": None,
            "summary": "Exact release revision activation finalized",
            "resource": {
                "operationPlanDigest": operation_plan_digest,
                "releaseId": verified.index.release_id,
                "signedPayloadDigest": verified.index.signed_digest,
                "targetId": verified.target["targetId"],
                "topologyDigest": verified.target["topologyDigest"],
            },
        },
        "startedAt": "2026-08-01T09:40:05.000000Z",
        "completedAt": "2026-08-01T09:40:19.000000Z",
        "estimatedCostUsd": 0.0,
        "actualCostUsd": 0.0,
        "decisionDigest": decision["decisionDigest"],
        "reservation": {
            "reservationId": reservation_id,
            "reservationDigest": reservation["reservationDigest"],
        },
        "claim": {"claimId": claim_id, "claimDigest": claim["claimDigest"]},
    }
    receipt = {**receipt_body, "receiptDigest": _authority_digest(receipt_body)}
    return {"reservation": reservation, "claim": claim, "receipt": receipt}


def _revision_pipeline(
    value: dict[str, object] | None = None,
    *,
    occupied: list[dict[str, object]] | None = None,
    current_pointer: dict[str, object] | None = None,
    accepted_data_generation: str = DATA_D1,
    accepted_data_generation_digest: str = DATA_D1_DIGEST,
    predecessor_volume_names: list[str] | None = None,
    accepted_volume_name: str = "stateport-data-d1",
    promotion_predecessor_override: dict[str, object] | None = None,
    written_at: str = "2026-08-01T09:40:25Z",
) -> dict[str, object]:
    index = release_index() if value is None else value
    verified = verify_release_index(index, policy=_policy(), verifier=_EphemeralTestVerifier())
    service_id = str(verified.target["services"][0]["serviceId"])
    volume_key = f"{service_id}:stateport-data"
    predecessor = {
        "predecessorPointerDigest": (
            None if current_pointer is None else current_pointer["pointerDigest"]
        ),
        "predecessorReleaseId": None if current_pointer is None else current_pointer["releaseId"],
        "predecessorSignedPayloadDigest": (
            None if current_pointer is None else current_pointer["signedPayloadDigest"]
        ),
        "predecessorDataGeneration": (
            None if current_pointer is None else current_pointer["acceptedDataGeneration"]
        ),
        "predecessorDataGenerationDigest": (
            None if current_pointer is None else current_pointer["acceptedDataGenerationDigest"]
        ),
    }
    promotion_predecessor = (
        predecessor
        if promotion_predecessor_override is None
        else {**predecessor, **promotion_predecessor_override}
    )
    pointer_generation = 0 if current_pointer is None else int(current_pointer["generation"])
    validation_backup = _derived_contract(
        {
            "schema": "stateport.revision-validation-backup-receipt/v1",
            "operationPlanDigest": DIGEST,
            "releaseId": verified.index.release_id,
            "signedPayloadDigest": verified.index.signed_digest,
            "targetId": verified.target["targetId"],
            "topologyDigest": verified.target["topologyDigest"],
            "backupReceiptDigest": DIGEST,
            "snapshotSetDigest": f"sha256:{'2' * 64}",
            "volumeBindings": [
                {
                    "volumeKey": volume_key,
                    "snapshotVolumeName": "stateport-validation-snapshot-d0",
                    "sourceDataGeneration": predecessor["predecessorDataGeneration"],
                    "readOnly": True,
                }
            ],
            "createdAt": "2026-08-01T09:31:00Z",
            "consistencyMode": "quiesced",
            "consistencyEvidenceDigest": f"sha256:{'3' * 64}",
            "result": "succeeded",
        },
        digest_field="receiptDigest",
    )
    staged = materialize_verified_quadlet_bundle(
        verified,
        operation_plan_digest=DIGEST,
        host_identity_digest=f"sha256:{'4' * 64}",
        collision_inventory_digests={
            "current": f"sha256:{'5' * 64}",
            "predecessor": f"sha256:{'6' * 64}",
            "candidate": f"sha256:{'7' * 64}",
            "observedHost": f"sha256:{'8' * 64}",
        },
        occupied_port_inputs=[] if occupied is None else occupied,
        proposed_at="2026-08-01T09:32:00Z",
        validation_backup_receipt=validation_backup,
    )
    proposal = _embedded(staged, "/port-allocation.proposal.json")
    promotion_spec = _derived_contract(
        {
            "schema": "stateport.revision-data-promotion-spec/v1",
            "operationPlanDigest": DIGEST,
            "releaseId": verified.index.release_id,
            "signedPayloadDigest": verified.index.signed_digest,
            "targetId": verified.target["targetId"],
            "topologyDigest": verified.target["topologyDigest"],
            **promotion_predecessor,
            "expectedAcceptedDataGeneration": accepted_data_generation,
            "requiredVolumeKeys": [volume_key],
            "databaseMigrationVersion": 1,
            "rollbackDataCompatible": True,
        },
        digest_field="specDigest",
    )
    owner_spec_digest = owner_materialization_spec_digest(
        verified, staged, expected_accepted_data_generation=accepted_data_generation
    )
    plan = _derived_contract(
        {
            "schema": "stateport.revision-activation-plan/v1",
            "operationPlanDigest": DIGEST,
            "releaseId": verified.index.release_id,
            "signedPayloadDigest": verified.index.signed_digest,
            "targetId": verified.target["targetId"],
            "topologyDigest": verified.target["topologyDigest"],
            "expectedPointerGeneration": pointer_generation,
            "newPointerGeneration": pointer_generation + 1,
            "expectedAcceptedDataGeneration": accepted_data_generation,
            "promotionSpecDigest": promotion_spec["specDigest"],
            "ownerMaterializationSpecDigest": owner_spec_digest,
            "portAllocationProposalDigest": proposal["proposalDigest"],
            "signatureVerificationProofSetDigest": signature_verification_proof_set_digest(
                verified
            ),
            "steps": list(verified.target["runtimeDerivation"]["stateMachine"]["promote"]),
        },
        digest_field="planDigest",
        id_field="planId",
        id_prefix="revision_activation_plan_",
    )
    port_receipt = reserve_revision_port_allocation(
        verified,
        staged,
        activation_plan=plan,
        reservation_receipt_digest=f"sha256:{'9' * 64}",
        recheck_inventory_digest=f"sha256:{'a' * 64}",
        rechecked_occupied_port_inputs=[] if occupied is None else occupied,
        allocated_at="2026-08-01T09:33:00Z",
        reservation_expires_at="2026-08-01T10:03:00Z",
    )
    promotion = _derived_contract(
        {
            "schema": "stateport.revision-data-promotion-receipt/v1",
            "operationPlanDigest": DIGEST,
            "activationPlanDigest": plan["planDigest"],
            "promotionSpecDigest": promotion_spec["specDigest"],
            "releaseId": verified.index.release_id,
            "signedPayloadDigest": verified.index.signed_digest,
            "targetId": verified.target["targetId"],
            "topologyDigest": verified.target["topologyDigest"],
            **promotion_predecessor,
            "predecessorVolumeNames": (
                [] if predecessor_volume_names is None else predecessor_volume_names
            ),
            "backupDigestD0": f"sha256:{'b' * 64}",
            "acceptedDataGeneration": accepted_data_generation,
            "acceptedDataGenerationDigest": accepted_data_generation_digest,
            "volumeBindings": [
                {
                    "volumeKey": volume_key,
                    "volumeName": accepted_volume_name,
                    "dataGeneration": accepted_data_generation,
                }
            ],
            "migrationReceiptDigest": f"sha256:{'c' * 64}",
            "privateChecksReceiptDigest": f"sha256:{'d' * 64}",
            "authoritativeWriterFenceReceiptDigest": f"sha256:{'e' * 64}",
            "fsyncReceiptDigest": f"sha256:{'f' * 64}",
            "validationDataDisposition": "discarded-not-promoted",
            "externalSideEffects": "not-reversed-by-filesystem-restore",
            "completedAt": "2026-08-01T09:40:00Z",
            "result": "succeeded",
        },
        digest_field="receiptDigest",
    )
    accepted = materialize_accepted_quadlet_bundle(
        verified,
        staged,
        data_promotion_spec=promotion_spec,
        data_promotion_receipt=promotion,
        port_allocation_receipt=port_receipt,
    )
    accepted_manifest = _embedded(accepted, "/accepted-materialization.json")
    owner_digests = accepted_manifest["ownerBundleDigests"]
    port_recheck = record_revision_port_activation_recheck(
        verified,
        activation_plan=plan,
        port_allocation_receipt=port_receipt,
        observed_occupied_port_inputs=[] if occupied is None else occupied,
        host_observation_receipt_digest=f"sha256:{'0' * 64}",
        checked_at="2026-08-01T09:40:10Z",
        valid_until="2026-08-01T09:40:40Z",
    )
    authority_documents = _authority_documents(verified)
    authority_resolver = _CanonicalAuthorityResolver(authority_documents)
    authority_proofs = derive_revision_authority_proofs(
        authority_documents,
        resolver=authority_resolver,
        operation_plan_digest=DIGEST,
        release_id=verified.index.release_id,
        signed_payload_digest=verified.index.signed_digest,
        target_id=verified.target["targetId"],
        topology_digest_value=verified.target["topologyDigest"],
    )
    decision = _derived_contract(
        {
            "schema": "stateport.revision-activation-decision/v1",
            "operationPlanDigest": DIGEST,
            "activationPlanDigest": plan["planDigest"],
            "predecessorPointerDigest": predecessor["predecessorPointerDigest"],
            "predecessorDecisionDigest": (
                None if current_pointer is None else current_pointer["decisionDigest"]
            ),
            "releaseId": verified.index.release_id,
            "signedPayloadDigest": verified.index.signed_digest,
            "targetId": verified.target["targetId"],
            "topologyDigest": verified.target["topologyDigest"],
            "pointerGeneration": pointer_generation + 1,
            "acceptedDataGeneration": accepted_data_generation,
            "acceptedDataGenerationDigest": accepted_data_generation_digest,
            "dataPromotionReceiptDigest": promotion["receiptDigest"],
            "ownerBundleDigests": owner_digests,
            "portAllocationReceiptDigest": port_receipt["receiptDigest"],
            "portActivationRecheckReceiptDigest": port_recheck["receiptDigest"],
            "authorityReservationProof": authority_proofs["reservation"],
            "authorityClaimProof": authority_proofs["claim"],
            "signatureVerificationProofSetDigest": signature_verification_proof_set_digest(
                verified
            ),
            "revisionUnitProjectionDigest": accepted_manifest["revisionUnitProjectionDigest"],
            "routeProjectionDigest": ROUTE_DIGEST,
            "decidedAt": "2026-08-01T09:40:15Z",
            "state": "activation_decided",
        },
        digest_field="decisionDigest",
        id_field="decisionId",
        id_prefix="revision_activation_decision_",
    )
    terminal = _derived_contract(
        {
            "schema": "stateport.revision-terminal-acceptance-receipt/v1",
            "operationPlanDigest": DIGEST,
            "activationPlanDigest": plan["planDigest"],
            "activationDecisionDigest": decision["decisionDigest"],
            "releaseId": verified.index.release_id,
            "signedPayloadDigest": verified.index.signed_digest,
            "targetId": verified.target["targetId"],
            "topologyDigest": verified.target["topologyDigest"],
            "pointerGeneration": pointer_generation + 1,
            "acceptedDataGeneration": accepted_data_generation,
            "acceptedDataGenerationDigest": accepted_data_generation_digest,
            "ownerBundleDigests": owner_digests,
            "revisionUnitProjectionDigest": accepted_manifest["revisionUnitProjectionDigest"],
            "routeProjectionDigest": ROUTE_DIGEST,
            "portActivationRecheckReceiptDigest": port_recheck["receiptDigest"],
            "healthEvidenceDigest": f"sha256:{'3' * 64}",
            "explicitStartReceiptDigest": f"sha256:{'4' * 64}",
            "explicitStopReceiptDigest": f"sha256:{'5' * 64}",
            "authorityFinalizeProof": authority_proofs["finalize"],
            "acceptedAt": "2026-08-01T09:40:20Z",
            "result": "accepted",
        },
        digest_field="receiptDigest",
    )
    activation = render_accepted_activation(
        verified,
        accepted,
        activation_plan=plan,
        activation_decision=decision,
        terminal_acceptance_receipt=terminal,
        data_promotion_receipt=promotion,
        port_allocation_receipt=port_receipt,
        port_activation_recheck_receipt=port_recheck,
        authority_source_documents=authority_documents,
        authority_source_resolver=authority_resolver,
        current_pointer=current_pointer,
        route_projection_digest=ROUTE_DIGEST,
        written_at=written_at,
    )
    return {
        "verified": verified,
        "validationBackup": validation_backup,
        "staged": staged,
        "proposal": proposal,
        "promotionSpec": promotion_spec,
        "plan": plan,
        "portReceipt": port_receipt,
        "portRecheck": port_recheck,
        "promotion": promotion,
        "accepted": accepted,
        "acceptedManifest": accepted_manifest,
        "decision": decision,
        "terminal": terminal,
        "authorityDocuments": authority_documents,
        "authorityResolver": authority_resolver,
        "authorityProofs": authority_proofs,
        "activation": activation,
    }


def test_release_index_schema_and_cross_bindings_pass() -> None:
    value = release_index()
    schema = json.loads((ROOT / "schemas/release-index.v1.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(value)
    result = validate_release_index(value)
    assert result.release_id == "stateport-alpha-0.2.0-rc.1"
    assert result.channel == "alpha"
    assert result.signed_digest == value["signatures"][0]["subjectDigest"]
    assert signed_payload_bytes(result) == canonical_json_bytes(value["signed"])


def test_release_index_rejects_detailed_database_observation_metadata() -> None:
    value = release_index()
    value["signed"]["images"][0]["scan"]["databaseObservedAt"] = "2026-08-01T08:30:00Z"
    with pytest.raises(ReleaseContractError, match="schema validation failed"):
        validate_release_index(value)


def test_v2_candidate_provenance_binds_the_signed_updater_artifact() -> None:
    value = release_index()
    source = value["signed"]["source"]
    updater = value["signed"]["artifacts"]["updater"]
    source["candidateProvenance"] = {
        "schema": "stateport.candidate-provenance/v2",
        "document": {
            "schema": "stateport.candidate-provenance/v2",
            "repository": {
                "authorityUrl": source["publicSnapshot"]["repository"],
                "ref": "refs/heads/main",
                "commit": source["publicSnapshot"]["commit"],
                "tree": source["publicSnapshot"]["tree"],
            },
            "materialization": {
                "sourceRepository": source["repository"],
                "sourceCommit": source["commit"],
                "sourceTree": source["tree"],
            },
                "artifacts": {
                "publicManifest": {
                    "sha256": source["publicSnapshot"]["manifestDigest"].removeprefix("sha256:")
                },
                    "updaterWheel": {
                        "sha256": updater["digest"].removeprefix("sha256:"),
                        "bytes": updater["size"],
                    },
                    "executionHostProvisioner": {
                        "sha256": value["signed"]["artifacts"][
                            "executionHostProvisioner"
                        ]["digest"].removeprefix("sha256:"),
                        "bytes": value["signed"]["artifacts"][
                            "executionHostProvisioner"
                        ]["size"],
                        "sourceCommit": source["commit"],
                    },
                },
        },
    }
    source["candidateProvenance"]["digest"] = canonical_digest(
        source["candidateProvenance"]["document"]
    )
    source["publicSnapshot"]["authorityUrl"] = source["publicSnapshot"]["repository"]
    source["publicSnapshot"]["ref"] = "refs/heads/main"
    value["signatures"] = [_signature(canonical_digest(value["signed"]), "release-index")]
    validate_release_index(value)
    source["candidateProvenance"]["document"]["artifacts"]["updaterWheel"]["sha256"] = "0" * 64
    source["candidateProvenance"]["digest"] = canonical_digest(
        source["candidateProvenance"]["document"]
    )
    value["signatures"] = [_signature(canonical_digest(value["signed"]), "release-index")]
    with pytest.raises(ReleaseContractError, match="updater wheel disagrees"):
        validate_release_index(value)


def test_v2_candidate_provenance_digest_binds_the_embedded_document() -> None:
    value = release_index()
    source = value["signed"]["source"]
    document = {
        "schema": "stateport.candidate-provenance/v2",
        "repository": {
            "authorityUrl": source["publicSnapshot"]["repository"],
            "ref": "refs/heads/main",
            "commit": source["publicSnapshot"]["commit"],
            "tree": source["publicSnapshot"]["tree"],
        },
        "materialization": {
            "sourceRepository": source["repository"],
            "sourceCommit": source["commit"],
            "sourceTree": source["tree"],
        },
        "artifacts": {
            "publicManifest": {
                "sha256": source["publicSnapshot"]["manifestDigest"].removeprefix("sha256:")
            },
            "updaterWheel": {
                "sha256": value["signed"]["artifacts"]["updater"]["digest"].removeprefix(
                    "sha256:"
                ),
                "bytes": value["signed"]["artifacts"]["updater"]["size"],
            },
            "executionHostProvisioner": {
                "sha256": value["signed"]["artifacts"]["executionHostProvisioner"][
                    "digest"
                ].removeprefix("sha256:"),
                "bytes": value["signed"]["artifacts"]["executionHostProvisioner"]["size"],
                "sourceCommit": source["commit"],
            },
        },
    }
    source["publicSnapshot"].update(
        {"authorityUrl": source["publicSnapshot"]["repository"], "ref": "refs/heads/main"}
    )
    source["candidateProvenance"] = {
        "schema": "stateport.candidate-provenance/v2",
        "digest": DIGEST,
        "document": document,
    }
    value["signatures"] = [_signature(canonical_digest(value["signed"]), "release-index")]
    with pytest.raises(ReleaseContractError, match="digest does not bind"):
        validate_release_index(value)


def test_v2_candidate_provenance_rejects_provisioner_source_commit_mismatch() -> None:
    value = release_index()
    source = value["signed"]["source"]
    document = {
        "schema": "stateport.candidate-provenance/v2",
        "repository": {
            "authorityUrl": source["publicSnapshot"]["repository"],
            "ref": "refs/heads/main",
            "commit": source["publicSnapshot"]["commit"],
            "tree": source["publicSnapshot"]["tree"],
        },
        "materialization": {
            "sourceRepository": source["repository"],
            "sourceCommit": source["commit"],
            "sourceTree": source["tree"],
        },
        "artifacts": {
            "publicManifest": {
                "sha256": source["publicSnapshot"]["manifestDigest"].removeprefix("sha256:")
            },
            "updaterWheel": {
                "sha256": value["signed"]["artifacts"]["updater"]["digest"].removeprefix(
                    "sha256:"
                ),
                "bytes": value["signed"]["artifacts"]["updater"]["size"],
            },
            "executionHostProvisioner": {
                "sha256": value["signed"]["artifacts"]["executionHostProvisioner"][
                    "digest"
                ].removeprefix("sha256:"),
                "bytes": value["signed"]["artifacts"]["executionHostProvisioner"]["size"],
                "sourceCommit": "0" * 40,
            },
        },
    }
    source["publicSnapshot"].update(
        {"authorityUrl": source["publicSnapshot"]["repository"], "ref": "refs/heads/main"}
    )
    source["candidateProvenance"] = {
        "schema": "stateport.candidate-provenance/v2",
        "digest": canonical_digest(document),
        "document": document,
    }
    value["signatures"] = [_signature(canonical_digest(value["signed"]), "release-index")]
    with pytest.raises(ReleaseContractError, match="source commit disagrees"):
        validate_release_index(value)


def test_supporting_release_schemas_are_well_formed() -> None:
    for name in (
        "install-receipt.v1.schema.json",
        "update-plan.v1.schema.json",
        "update-receipt.v1.schema.json",
        "update-status.v1.schema.json",
        "update-failure-evidence.v1.schema.json",
        "update-authority-link.v1.schema.json",
        "release-provenance.v1.schema.json",
        "revision-activation-plan.v1.schema.json",
        "revision-activation-decision.v1.schema.json",
        "revision-activation-pointer.v1.schema.json",
        "revision-owner-bundle.v1.schema.json",
        "revision-port-allocation-proposal.v1.schema.json",
        "revision-port-allocation-receipt.v1.schema.json",
        "revision-port-activation-recheck-receipt.v1.schema.json",
        "revision-authority-proof.v1.schema.json",
        "revision-data-promotion-spec.v1.schema.json",
        "revision-data-promotion-receipt.v1.schema.json",
        "revision-validation-backup-receipt.v1.schema.json",
        "revision-terminal-acceptance-receipt.v1.schema.json",
        "stable-host-service-plan.v1.schema.json",
        "stable-host-service-transition.v1.schema.json",
    ):
        schema = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)


def test_successor_disposition_schema_is_monotonic() -> None:
    first = {
        "formatVersion": "stateport.release-disposition/v2",
        "signedBy": "stateport.release-index/v1",
        "sequence": 1,
        "status": "active",
        "at": None,
        "reason": None,
        "previousDispositionDigest": None,
    }
    second = dict(first)
    second["sequence"] = 2
    second["previousDispositionDigest"] = canonical_digest(first)
    validate_release_disposition(first)
    validate_release_disposition(second, predecessor=first)
    rolled_back = dict(second)
    rolled_back["sequence"] = 1
    with pytest.raises(ReleaseContractError, match="not monotonic"):
        validate_release_disposition(rolled_back, predecessor=first)
    active_with_details = dict(first)
    active_with_details["reason"] = "not allowed"
    with pytest.raises(ReleaseContractError, match="active release disposition"):
        validate_release_disposition(active_with_details)
    deprecated_without_details = dict(first)
    deprecated_without_details["status"] = "deprecated"
    with pytest.raises(ReleaseContractError, match="requires time and reason"):
        validate_release_disposition(deprecated_without_details)
    deprecated = dict(deprecated_without_details)
    deprecated["at"] = "2026-08-09T12:00:00Z"
    deprecated["reason"] = "superseded by successor"
    validate_release_disposition(deprecated)


def test_successor_status_resets_for_a_new_release_chain() -> None:
    predecessor = {
        "formatVersion": "stateport.release-successor/v1",
        "qualificationEvent": {"releaseId": "stateport-alpha-0.1.0"},
        "disposition": {
            "formatVersion": "stateport.release-disposition/v2",
            "signedBy": "stateport.release-index/v1",
            "sequence": 1,
            "status": "deprecated",
            "at": "2026-08-09T12:00:00Z",
            "reason": "superseded",
            "previousDispositionDigest": None,
        },
    }
    successor = {
        "formatVersion": "stateport.release-successor/v1",
        "qualificationEvent": {"releaseId": "stateport-alpha-0.2.0"},
        "disposition": {
            "formatVersion": "stateport.release-disposition/v2",
            "signedBy": "stateport.release-index/v1",
            "sequence": 2,
            "status": "active",
            "at": None,
            "reason": None,
            "previousDispositionDigest": canonical_digest(predecessor["disposition"]),
        },
    }
    validate_successor_disposition_transition(predecessor, successor)


def test_successor_disposition_timestamp_cannot_move_backwards() -> None:
    predecessor = {
        "formatVersion": "stateport.release-successor/v1",
        "qualificationEvent": {"releaseId": "stateport-alpha-0.2.0"},
        "disposition": {
            "formatVersion": "stateport.release-disposition/v2",
            "signedBy": "stateport.release-index/v1",
            "sequence": 1,
            "status": "deprecated",
            "at": "2026-08-09T12:00:00Z",
            "reason": "superseded",
            "previousDispositionDigest": None,
        },
    }
    successor = {
        "formatVersion": "stateport.release-successor/v1",
        "qualificationEvent": {"releaseId": "stateport-alpha-0.2.0"},
        "disposition": {
            "formatVersion": "stateport.release-disposition/v2",
            "signedBy": "stateport.release-index/v1",
            "sequence": 2,
            "status": "withdrawn",
            "at": "2026-08-09T11:00:00Z",
            "reason": "withdrawn",
            "previousDispositionDigest": canonical_digest(predecessor["disposition"]),
        },
    }
    with pytest.raises(ReleaseContractError, match="timestamp is not monotonic"):
        validate_successor_disposition_transition(predecessor, successor)


def test_packaged_schemas_match_repository_contracts_byte_for_byte() -> None:
    package_root = ROOT / "packages/release-contracts/src/stateport_release/schemas"
    for repository_schema in sorted((ROOT / "schemas").glob("*.schema.json")):
        packaged = package_root / repository_schema.name
        if packaged.exists():
            assert packaged.read_bytes() == repository_schema.read_bytes()


def test_canonical_json_is_stable_and_rejects_ambiguous_values() -> None:
    assert canonical_json_bytes({"z": 1, "a": "é"}) == '{"a":"é","z":1}'.encode()
    with pytest.raises(ReleaseContractError, match="floating-point"):
        canonical_json_bytes({"value": 1.0})
    with pytest.raises(ReleaseContractError, match="NFC"):
        canonical_json_bytes({"value": "e\N{COMBINING ACUTE ACCENT}"})
    duplicate = b'{"schema":"stateport.release-index/v1","schema":"wrong"}'
    with pytest.raises(ReleaseContractError, match="duplicate"):
        load_release_index(duplicate)


def test_policy_verification_calls_only_pinned_cosign_interface() -> None:
    verifier = _EphemeralTestVerifier()
    verified = verify_release_index(release_index(), policy=_policy(), verifier=verifier)
    assert verified.verified_signers == (SIGNER,)
    assert verified.target["targetId"] == "linux-amd64-rootless-podman-quadlet"
    assert verifier.payloads == [canonical_json_bytes(release_index()["signed"])]
    assert verifier.images == [
        image["reference"] for image in release_index()["signed"]["images"]
    ]
    envelope = to_updater_release_envelope(verified)
    assert envelope.document["releaseIndexDigest"] == verified.index.index_digest
    assert envelope.document["signedPayloadDigest"] == verified.index.signed_digest
    assert envelope.document["source"]["commit"] == COMMIT
    assert envelope.document["target"]["services"][0]["serviceId"] == "stateport-web"
    assert envelope.document["signatureVerificationProofSetDigest"] == canonical_digest(
        envelope.document["verificationProofs"]
    )
    envelope_value = envelope.as_dict()
    assert envelope_value["artifacts"] == release_index()["signed"]["artifacts"]
    assert envelope_value["images"] == release_index()["signed"]["images"]
    assert envelope.document["images"][0]["sboms"]["cycloneDx"]["digest"] == DIGEST
    assert envelope.document["images"][0]["scan"]["policy"] == "stateport.grype-policy/v1"
    assert envelope.document["images"][0]["provenance"]["digest"] == DIGEST
    assert envelope.document["images"][0]["signature"]["subjectDigest"] == DIGEST
    assert envelope_value["supplyChain"] == release_index()["signed"]["supplyChain"]
    assert envelope.document["compatibility"]["predecessor"] == {
        "releaseId": "stateport-alpha-0.1.0",
        "version": "0.1.0",
        "signedPayloadDigest": f"sha256:{'f' * 64}",
    }
    assert envelope.document["images"][0]["sizeBytes"] == 1048576
    assert envelope.document["publication"]["publishedAt"] is None
    identity = release_identity_from_verified(verified)
    assert identity["releaseId"] == "stateport-alpha-0.2.0-rc.1"
    assert identity["publishedAt"] is None
    copied = envelope.as_dict()
    copied["source"]["commit"] = "0" * 40
    assert envelope.document["source"]["commit"] == COMMIT


def test_predecessor_authentication_retains_the_exact_verified_signature() -> None:
    predecessor = release_index()
    predecessor["signatures"].append(deepcopy(predecessor["signatures"][0]))
    authenticated = verify_release_predecessor(
        predecessor,
        expected_trust_mode="keyless-certificate",
        accepted_signers=frozenset({SIGNER}),
        verifier=_EphemeralTestVerifier(),
    )
    assert authenticated.signature == predecessor["signatures"][0]


def test_successor_verification_requires_monotonic_authenticated_predecessor() -> None:
    predecessor = release_index()
    successor = _successor_index(predecessor, disposition_sequence=2)
    with pytest.raises(ReleaseContractError, match="authenticated predecessor index"):
        verify_release_index(successor, policy=_policy(), verifier=_EphemeralTestVerifier())
    with pytest.raises(ReleaseContractError, match="monotonic chain"):
        verify_release_index(
            successor,
            policy=_policy(),
            verifier=_EphemeralTestVerifier(),
            predecessor=predecessor,
        )


def test_successor_predecessor_version_must_be_older() -> None:
    predecessor = release_index()
    predecessor["signed"]["release"]["version"] = "0.3.0"
    predecessor["signatures"] = [
        _signature(canonical_digest(predecessor["signed"]), "release-index")
    ]
    successor = _successor_index(predecessor, version="0.2.0-rc.1")
    with pytest.raises(ReleaseContractError, match="predecessor version must precede"):
        validate_release_index(successor, require_signatures=False)


def test_signed_qualification_event_rejects_reordered_or_duplicate_images() -> None:
    predecessor = release_index()
    successor = _successor_index(predecessor)
    event = successor["signed"]["successor"]["qualificationEvent"]
    event["images"] = list(reversed(event["images"]))
    event["eventId"] = canonical_digest(
        {key: value for key, value in event.items() if key != "eventId"}
    )
    successor["signatures"] = []
    with pytest.raises(ReleaseContractError, match="not canonicalized"):
        validate_release_index(successor, require_signatures=False)


@pytest.mark.parametrize(
    ("policy", "message"),
    [
        (_policy(expected_channel="stable"), "channel"),
        (_policy(expected_target="linux-arm64-rootless-podman-quadlet"), "target"),
        (_policy(updater_version="0.0.9"), "older"),
        (_policy(now=datetime(2026, 9, 1, tzinfo=timezone.utc)), "expired"),
        (_policy(allow_candidate=False), "candidate"),
        (_policy(accepted_signers=frozenset()), "certificate identities"),
    ],
)
def test_policy_refuses_mismatched_release(policy: ReleaseVerificationPolicy, message: str) -> None:
    with pytest.raises(ReleaseContractError, match=message):
        verify_release_index(release_index(), policy=policy, verifier=_EphemeralTestVerifier())


def test_verification_refuses_stale_scan_and_future_publication() -> None:
    stale = release_index()
    scan = stale["signed"]["images"][0]["scan"]
    scan["databaseBuiltAt"] = "2026-07-29T08:00:00Z"
    scan["scannedAt"] = "2026-07-29T09:00:00Z"
    stale["signatures"][0]["subjectDigest"] = canonical_digest(stale["signed"])
    with pytest.raises(ReleaseContractError, match="stale at verification time"):
        verify_release_index(stale, policy=_policy(), verifier=_EphemeralTestVerifier())

    future = release_index()
    future["signed"]["release"]["qualification"] = "published"
    future["signed"]["publication"]["publishedAt"] = "2026-08-02T10:00:00Z"
    future["signed"]["publication"]["expiresAt"] = "2026-09-01T00:00:00Z"
    future["signatures"][0]["transparencyLog"] = "required-public-release"
    for image in future["signed"]["images"]:
        image["signature"]["transparencyLog"] = "required-public-release"
    future["signatures"][0]["subjectDigest"] = canonical_digest(future["signed"])
    with pytest.raises(ReleaseContractError, match="future"):
        verify_release_index(
            future,
            policy=_policy(allow_candidate=False),
            verifier=_EphemeralTestVerifier(),
        )


def test_marked_successor_uses_qualification_and_signing_time_freshness() -> None:
    predecessor = release_index()
    successor = _successor_index(predecessor)
    successor["signed"]["successor"]["freshnessEnforcement"] = (
        "qualification-and-signing-time"
    )
    successor["signatures"][0]["subjectDigest"] = canonical_digest(successor["signed"])
    verified = verify_release_index(
        successor,
        policy=_policy(now=datetime(2026, 8, 2, 10, tzinfo=timezone.utc)),
        verifier=_EphemeralTestVerifier(),
        predecessor=predecessor,
    )
    assert verified.index.release_id == successor["signed"]["release"]["releaseId"]


def test_unmarked_successor_retains_legacy_verification_time_freshness() -> None:
    predecessor = release_index()
    successor = _successor_index(predecessor)
    with pytest.raises(ReleaseContractError, match="stale at verification time"):
        verify_release_index(
            successor,
            policy=_policy(now=datetime(2026, 8, 2, 10, tzinfo=timezone.utc)),
            verifier=_EphemeralTestVerifier(),
            predecessor=predecessor,
        )


def test_marked_successor_still_refuses_future_scan_evidence() -> None:
    predecessor = release_index()
    successor = _successor_index(predecessor)
    successor["signed"]["successor"]["freshnessEnforcement"] = (
        "qualification-and-signing-time"
    )
    successor["signatures"][0]["subjectDigest"] = canonical_digest(successor["signed"])
    with pytest.raises(ReleaseContractError, match="from the future"):
        verify_release_index(
            successor,
            policy=_policy(now=datetime(2026, 7, 31, tzinfo=timezone.utc)),
            verifier=_EphemeralTestVerifier(),
            predecessor=predecessor,
        )


def test_transparency_log_policy_is_explicit_and_private_candidate_is_not_uploaded() -> None:
    value = release_index()
    assert value["signatures"][0]["transparencyLog"] == "not-uploaded-private-candidate"
    with pytest.raises(ReleaseContractError, match="transparency-log proof"):
        verify_release_index(
            value,
            policy=_policy(require_transparency_log=True),
            verifier=_EphemeralTestVerifier(),
        )


def test_private_candidate_verifies_with_exact_pinned_public_key_identity() -> None:
    value = release_index()
    value["signed"]["signaturePolicy"]["trustMode"] = "pinned-public-key"
    for image in value["signed"]["images"]:
        image["signature"] = _pinned_key_signature(DIGEST, image["imageId"])
    value["signatures"] = [
        _pinned_key_signature(canonical_digest(value["signed"]), "release-index")
    ]
    policy = _policy(
        expected_trust_mode="pinned-public-key",
        accepted_signers=frozenset(),
        accepted_public_keys=frozenset({PINNED_KEY}),
    )
    verified = verify_release_index(value, policy=policy, verifier=_EphemeralTestVerifier())
    assert verified.verified_signers == (PINNED_KEY,)

    with pytest.raises(ReleaseContractError, match="untrusted signer"):
        verify_release_index(
            value,
            policy=_policy(
                accepted_signers=frozenset(),
                expected_trust_mode="pinned-public-key",
                accepted_public_keys=frozenset(
                    {PinnedPublicKeyIdentity(f"sha256:{'8' * 64}", PINNED_KEY.key_id)}
                ),
            ),
            verifier=_EphemeralTestVerifier(),
        )
    with pytest.raises(ReleaseContractError, match="public-key identities"):
        verify_release_index(
            value,
            policy=_policy(
                expected_trust_mode="pinned-public-key",
                accepted_signers=frozenset(),
                accepted_public_keys=frozenset(),
            ),
            verifier=_EphemeralTestVerifier(),
        )


def test_signature_trust_modes_cannot_be_mixed_or_mislabeled() -> None:
    mixed = release_index()
    mixed_signature = _pinned_key_signature(canonical_digest(mixed["signed"]), "release-index")
    mixed_signature["certificateIdentity"] = SIGNER.certificate_identity
    mixed_signature["certificateOidcIssuer"] = SIGNER.oidc_issuer
    mixed["signatures"] = [mixed_signature]
    with pytest.raises(ReleaseContractError, match="mixes pinned-public-key and keyless trust"):
        validate_release_index(mixed)

    public_log = release_index()
    signature = _pinned_key_signature(canonical_digest(public_log["signed"]), "release-index")
    signature["transparencyLog"] = "required-public-release"
    public_log["signatures"] = [signature]
    with pytest.raises(ReleaseContractError, match="schema validation|transparency-log"):
        validate_release_index(public_log)

    mixed_image = release_index()
    mixed_image["signed"]["images"][0]["signature"] = _pinned_key_signature(DIGEST, "web")
    mixed_image["signatures"][0]["subjectDigest"] = canonical_digest(mixed_image["signed"])
    with pytest.raises(ReleaseContractError, match="homogeneous trust mode"):
        validate_release_index(mixed_image)


def test_typed_signature_proof_must_bind_subject_bundle_identity_and_time() -> None:
    class WrongImageProof(_EphemeralTestVerifier):
        def verify_image(
            self, reference: str, signature: dict[str, object]
        ) -> SignatureVerificationProof:
            proof = super().verify_image(reference, signature)
            return SignatureVerificationProof(
                subject_digest=f"sha256:{'0' * 64}",
                bundle_digest=proof.bundle_digest,
                trust_mode=proof.trust_mode,
                identity_primary=proof.identity_primary,
                identity_secondary=proof.identity_secondary,
                verified_at=proof.verified_at,
                transparency_log_mode=proof.transparency_log_mode,
            )

    with pytest.raises(ReleaseContractError, match="does not bind subject_digest"):
        verify_release_index(release_index(), policy=_policy(), verifier=WrongImageProof())

    class UntypedProof(_EphemeralTestVerifier):
        def verify_blob(self, payload: bytes, signature: dict[str, object]) -> object:
            return None

    with pytest.raises(ReleaseContractError, match="no typed proof"):
        verify_release_index(release_index(), policy=_policy(), verifier=UntypedProof())


def test_tamper_and_topology_drift_fail_before_verifier() -> None:
    tampered = release_index()
    tampered["signed"]["release"]["version"] = "0.2.1"
    with pytest.raises(ReleaseContractError, match="canonical signed payload"):
        validate_release_index(tampered)

    unused = release_index()
    extra = deepcopy(unused["signed"]["images"][0])
    extra["imageId"] = "stateport-worker"
    extra["reference"] = f"ghcr.io/stateport/stateport-worker@{DIGEST}"
    unused["signed"]["images"].append(extra)
    unused["signatures"][0]["subjectDigest"] = canonical_digest(unused["signed"])
    with pytest.raises(ReleaseContractError, match="installed services"):
        validate_release_index(unused)

    git_mount = release_index()
    git_mount["signed"]["targets"][0]["services"][0]["writableVolumes"][0]["mountPath"] = (
        "/workspace/.git"
    )
    git_mount["signed"]["targets"][0]["topologyDigest"] = topology_digest(
        git_mount["signed"]["targets"][0]
    )
    git_mount["signatures"][0]["subjectDigest"] = canonical_digest(git_mount["signed"])
    with pytest.raises(ReleaseContractError, match="Git metadata"):
        validate_release_index(git_mount)

    topology = release_index()
    topology["signed"]["targets"][0]["services"][0]["serviceId"] = "stateport-api"
    topology["signatures"][0]["subjectDigest"] = canonical_digest(topology["signed"])
    with pytest.raises(ReleaseContractError, match="topology digest"):
        validate_release_index(topology)

    socket_grant = release_index()
    service = socket_grant["signed"]["targets"][0]["services"][0]
    service["capabilities"]["podmanSocketAccess"] = "owned-execution-user"
    socket_grant["signed"]["targets"][0]["topologyDigest"] = topology_digest(
        socket_grant["signed"]["targets"][0]
    )
    socket_grant["signatures"][0]["subjectDigest"] = canonical_digest(socket_grant["signed"])
    with pytest.raises(ReleaseContractError, match="unauthorized Podman"):
        validate_release_index(socket_grant)

    missing_probe = release_index()
    missing_probe["signed"]["images"][0]["healthProbe"]["packageInventoryDigest"] = (
        f"sha256:{'0' * 64}"
    )
    missing_probe["signatures"][0]["subjectDigest"] = canonical_digest(missing_probe["signed"])
    with pytest.raises(ReleaseContractError, match="health probe.*package inventory"):
        validate_release_index(missing_probe)


def _shared_operations_index() -> dict[str, object]:
    value = release_index()
    signed = value["signed"]
    target = signed["targets"][0]
    web = target["services"][0]
    api = deepcopy(web)
    api.update({"serviceId": "stateport-api", "imageId": "stateport-api"})
    api["writableVolumes"][0].update(
        {"name": "stateport-operations", "mountPath": "/workspace/.stateport"}
    )
    worker = deepcopy(api)
    worker.update({"serviceId": "stateport-worker", "imageId": "stateport-worker"})
    target["services"].extend([api, worker])
    target["sharedWritableVolumes"] = [
        {
            "volumeKey": "stateport-shared:stateport-operations",
            "volumeName": "stateport-operations",
            "members": ["stateport-api", "stateport-worker"],
            "writerCoordination": "sqlite-immediate-and-posix-advisory-locks",
        }
    ]
    for image_id in ("stateport-api", "stateport-worker"):
        image = deepcopy(signed["images"][0])
        image.update(
            {"imageId": image_id, "reference": f"ghcr.io/stateport/{image_id}@{DIGEST}"}
        )
        signed["images"].append(image)
    _refresh_index_topology(value)
    return value


def test_shared_writable_volume_binds_one_key_and_exact_members() -> None:
    value = _shared_operations_index()
    verified = verify_release_index(value, policy=_policy(), verifier=_EphemeralTestVerifier())
    files = render_quadlet_bundle(verified.target, verified.index.document["signed"]["images"])
    shared_token = b"@@STATEPORT_ACCEPTED_DATA_VOLUME:stateport-shared:stateport-operations@@"
    units = [content for path, content in files.items() if path.endswith(".container.in")]
    assert sum(shared_token in content for content in units) == 2

    missing_member = _shared_operations_index()
    missing_member["signed"]["targets"][0]["sharedWritableVolumes"][0]["members"] = [
        "stateport-api",
        "stateport-web",
    ]
    _refresh_index_topology(missing_member)
    with pytest.raises(ReleaseContractError, match="exact service members"):
        validate_release_index(missing_member)

    metadata_drift = _shared_operations_index()
    metadata_drift["signed"]["targets"][0]["services"][-1]["writableVolumes"][0][
        "mountPath"
    ] = "/workspace/.stateport-worker"
    _refresh_index_topology(metadata_drift)
    with pytest.raises(ReleaseContractError, match="inconsistent attachment metadata"):
        validate_release_index(metadata_drift)


def test_zero_padded_numeric_semver_prerelease_is_rejected() -> None:
    value = release_index()
    value["signed"]["release"]["version"] = "0.2.0-rc.01"
    value["signatures"][0]["subjectDigest"] = canonical_digest(value["signed"])
    with pytest.raises(ReleaseContractError, match="zero-padded"):
        validate_release_index(value)


def test_unsigned_candidate_is_assembly_only() -> None:
    value = release_index()
    value["signatures"] = []
    prepared = validate_release_index(value, require_signatures=False)
    assert prepared.version == "0.2.0-rc.1"
    with pytest.raises(ReleaseContractError, match="no detached"):
        validate_release_index(value)


def test_safe_file_loader_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "index.json"
    target.write_text(json.dumps(release_index()), encoding="utf-8")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    assert load_release_index_file(target).version == "0.2.0-rc.1"
    with pytest.raises(ReleaseContractError, match="opened safely"):
        load_release_index_file(link)


def test_verified_release_and_updater_envelope_are_deeply_immutable() -> None:
    verified = verify_release_index(
        release_index(), policy=_policy(), verifier=_EphemeralTestVerifier()
    )
    with pytest.raises(TypeError):
        verified.index.document["signed"]["targets"][0]["services"][0]["serviceId"] = "tampered"
    with pytest.raises(TypeError):
        verified.target["services"][0]["capabilities"]["podmanSocketAccess"] = (
            "owned-execution-user"
        )
    envelope = to_updater_release_envelope(verified)
    with pytest.raises(TypeError):
        envelope.document["target"]["services"][0]["serviceId"] = "tampered"
    reverified = reverify_updater_release_envelope(
        envelope, policy=_policy(), verifier=_EphemeralTestVerifier()
    )
    assert reverified.index.signed_digest == verified.index.signed_digest
    persisted = json.loads(envelope.canonical_index_bytes)
    persisted["signed"]["targets"][0]["services"][0]["serviceId"] = "tampered"
    with pytest.raises(ReleaseContractError, match="schema validation|canonical signed payload"):
        load_release_index(json.dumps(persisted))


def test_successor_updater_envelope_reverification_carries_predecessor() -> None:
    predecessor = release_index()
    successor = _successor_index(predecessor)
    verifier = _EphemeralTestVerifier()
    verified = verify_release_index(
        successor,
        policy=_policy(),
        verifier=verifier,
        predecessor=predecessor,
    )
    envelope = to_updater_release_envelope(verified)
    context = envelope.document["authenticatedPredecessor"]
    assert context["signedPayloadDigest"] == canonical_digest(predecessor["signed"])
    reverified = reverify_updater_release_envelope(
        envelope, policy=_policy(), verifier=_EphemeralTestVerifier()
    )
    assert reverified.authenticated_predecessor is not None
    assert reverified.authenticated_predecessor.index.signed_digest == context[
        "signedPayloadDigest"
    ]


def test_quadlet_templates_stage_profiles_and_terminal_activation_only() -> None:
    pipeline = _revision_pipeline()
    verified = pipeline["verified"]
    signed = verified.index.document["signed"]
    templates = render_quadlet_bundle(verified.target, signed["images"])
    assert verify_quadlet_bundle(templates, verified) == verified.target["quadletBundleDigest"]
    assert any(name.endswith(".container.in") for name in templates)
    assert all(
        b"[Install]" not in content and b"WantedBy=" not in content
        for content in templates.values()
    )

    staged = pipeline["staged"]
    assert all(path.startswith("staged/") for path in staged)
    staged_containers = [content for path, content in staged.items() if ".container" in path]
    assert any(
        b"stateport-validation-snapshot-d0:/var/lib/stateport:ro" in content
        for content in staged_containers
    )
    assert any(b"@@STATEPORT_ACCEPTED_DATA_VOLUME:" in content for content in staged_containers)
    assert all(
        b"Pull=never" in content and b"RunInit=true" in content for content in staged_containers
    )
    assert all(
        b"LogDriver=k8s-file" in content
        and b"PodmanArgs=--log-opt=max-size=10485760" in content
        and re.search(rb'HealthCmd="[^"]*stateport-healthcheck --kind http --host 127\.0\.0\.1 --port \d+ --path /[^"]*"', content)
        and b"/usr/bin/curl" not in content
        for content in staged_containers
    )
    assert all(b"[Install]" not in content for content in staged.values())
    staged_manifest = _embedded(staged, "/materialization.json")
    assert all(len(revision) == 64 for revision in staged_manifest["revisions"].values())
    assert (
        staged_manifest["revisions"]["stateport-web:validation"]
        != staged_manifest["revisions"]["stateport-web:accepted"]
    )

    accepted = pipeline["accepted"]
    accepted_containers = [
        content for path, content in accepted.items() if path.endswith(".container")
    ]
    assert accepted_containers
    assert all(
        b"stateport-data-d1:/var/lib/stateport:rw" in content for content in accepted_containers
    )
    assert all(
        b"stateport-validation-snapshot-d0" not in content for content in accepted_containers
    )
    assert all(
        b"[Install]" not in content and b"WantedBy=" not in content for content in accepted.values()
    )
    owner_bundle = _embedded(accepted, "/owner-bundles/stateport-control.json")
    assert owner_bundle["owner"] == "stateport-control"
    assert owner_bundle["rootIdentity"] == "xdg-config-containers-systemd"
    assert owner_bundle["crossUserAtomic"] is False

    activation = pipeline["activation"]
    assert set(activation) >= {
        "activation/stateport-accepted.target",
        "activation/stateport-accepted.target.d/10-stateport-activation.conf",
        "activation/stateport-accepted.current.json",
    }
    assert b"[Install]" in activation["activation/stateport-accepted.target"]
    assert b"WantedBy=default.target" in activation["activation/stateport-accepted.target"]
    assert (
        b"[Install]"
        not in activation["activation/stateport-accepted.target.d/10-stateport-activation.conf"]
    )
    pointer = _embedded(activation, "stateport-accepted.current.json")
    assert pointer["state"] == "accepted"
    assert pointer["terminalAcceptanceReceiptDigest"] == pipeline["terminal"]["receiptDigest"]
    assert "validation" not in canonical_json_bytes(pointer).decode()
    write_plan = _embedded(activation, "activation-write-plan.json")
    assert write_plan["preTerminalOrder"][-1] == "explicit-start-observe-stop"
    assert write_plan["terminalOrder"][-1] == "fsync-terminal-acceptance-receipt"
    assert write_plan["postTerminalOrder"] == [
        "compare-and-swap-pointer",
        "switch-ingress-and-unfence",
    ]
    assert write_plan["terminalAcceptanceReceiptDigest"] == pipeline["terminal"]["receiptDigest"]
    assert (
        write_plan["portActivationRecheckReceiptDigest"] == pipeline["portRecheck"]["receiptDigest"]
    )
    assert write_plan["crashRecovery"].startswith("structural-effect-reconciliation-only")

    tampered = dict(templates)
    container_path = next(path for path in templates if path.endswith(".container.in"))
    tampered[container_path] += b"# tamper\n"
    with pytest.raises(ReleaseContractError, match="do not match"):
        verify_quadlet_bundle(tampered, verified)
    with pytest.raises(ReleaseContractError, match="unsafe"):
        quadlet_bundle_digest({"../stateport-web.container": b"unsafe"})


def test_staged_units_bind_external_loopback_port_for_host_validation() -> None:
    """Every published unit must name its signed host port for the service.

    The persistent-app loopback guard (``_valid_request_host``) only accepts a
    Host authority naming the bound container port or the configured external
    loopback port.  Without ``STATEPORT_EXTERNAL_LOOPBACK_PORT`` resolved to
    the signed host port, install-time health probes and operator browsers
    are refused with 421 and installation fails closed with health_timeout
    (dogfood defect at ca87812).
    """

    pipeline = _revision_pipeline()
    for bundle_key in ("staged", "accepted"):
        containers = [
            content for path, content in pipeline[bundle_key].items() if ".container" in path
        ]
        assert containers
        for content in containers:
            lines = content.split(b"\n")
            published = [line for line in lines if line.startswith(b"PublishPort=127.0.0.1:")]
            env = [
                line
                for line in lines
                if line.startswith(b"Environment=STATEPORT_EXTERNAL_LOOPBACK_PORT=")
            ]
            if not published:
                assert not env
                continue
            assert len(env) == 1, content
            external_port = env[0].rsplit(b"=", 1)[1]
            assert external_port.isdigit(), env[0]
            health = re.search(rb'--kind http --host 127\.0\.0\.1 --port (\d+)', content)
            assert health is not None, content
            assert (b"PublishPort=127.0.0.1:" + external_port + b":" + health.group(1)) in lines, (
                content
            )


def test_unsigned_staged_quadlet_mutation_addition_and_removal_are_refused() -> None:
    pipeline = _revision_pipeline()
    container_path = next(path for path in pipeline["staged"] if path.endswith(".container.in"))
    mutated = dict(pipeline["staged"])
    mutated[container_path] += (
        b"Volume=%t/podman:/run/stateport-engine:rw\n"
    )
    with pytest.raises(ReleaseContractError, match="staged materialization byte drift"):
        owner_materialization_spec_digest(
            pipeline["verified"],
            mutated,
            expected_accepted_data_generation=DATA_D1,
        )

    added = dict(pipeline["staged"])
    staged_root = container_path.rsplit("/", 1)[0]
    added[f"{staged_root}/unsigned-extra.container"] = b"[Container]\nImage=evil\n"
    with pytest.raises(ReleaseContractError, match="missing or additional paths"):
        owner_materialization_spec_digest(
            pipeline["verified"], added, expected_accepted_data_generation=DATA_D1
        )

    missing = dict(pipeline["staged"])
    del missing[container_path]
    with pytest.raises(ReleaseContractError, match="missing or additional paths"):
        owner_materialization_spec_digest(
            pipeline["verified"], missing, expected_accepted_data_generation=DATA_D1
        )


def test_operation_plan_substitution_is_refused_after_approval() -> None:
    pipeline = _revision_pipeline()
    substituted = deepcopy(pipeline["plan"])
    substituted["operationPlanDigest"] = f"sha256:{'0' * 64}"
    substituted["planDigest"] = revision_contract_digest(
        substituted, digest_field="planDigest", id_field="planId"
    )
    substituted["planId"] = f"revision_activation_plan_{substituted['planDigest'][7:39]}"
    validate_revision_contract(substituted)
    with pytest.raises(ReleaseContractError, match="another release"):
        reserve_revision_port_allocation(
            pipeline["verified"],
            pipeline["staged"],
            activation_plan=substituted,
            reservation_receipt_digest=DIGEST,
            recheck_inventory_digest=DIGEST,
            rechecked_occupied_port_inputs=[],
            allocated_at="2026-08-01T09:33:00Z",
            reservation_expires_at="2026-08-01T10:03:00Z",
        )


def test_forged_authority_projection_and_noncanonical_store_chain_are_refused() -> None:
    pipeline = _revision_pipeline()
    forged_documents = deepcopy(pipeline["authorityDocuments"])
    decision = forged_documents["reservation"]["decision"]
    decision["actorId"] = "forged-updater"
    decision_body = {key: value for key, value in decision.items() if key != "decisionDigest"}
    decision["decisionDigest"] = _authority_digest(decision_body)
    reservation = forged_documents["reservation"]
    reservation_body = {
        key: value for key, value in reservation.items() if key != "reservationDigest"
    }
    reservation["reservationDigest"] = _authority_digest(reservation_body)
    claim = forged_documents["claim"]
    claim["reservationDigest"] = reservation["reservationDigest"]
    claim["decisionDigest"] = decision["decisionDigest"]
    claim_body = {key: value for key, value in claim.items() if key != "claimDigest"}
    claim["claimDigest"] = _authority_digest(claim_body)
    receipt = forged_documents["receipt"]
    receipt["actorId"] = "forged-updater"
    receipt["decisionDigest"] = decision["decisionDigest"]
    receipt["reservation"]["reservationDigest"] = reservation["reservationDigest"]
    receipt["claim"]["claimDigest"] = claim["claimDigest"]
    receipt_body = {key: value for key, value in receipt.items() if key != "receiptDigest"}
    receipt["receiptDigest"] = _authority_digest(receipt_body)

    with pytest.raises(ReleaseContractError, match="protected canonical authority store"):
        derive_revision_authority_proofs(
            forged_documents,
            resolver=pipeline["authorityResolver"],
            operation_plan_digest=DIGEST,
            release_id=pipeline["verified"].index.release_id,
            signed_payload_digest=pipeline["verified"].index.signed_digest,
            target_id=pipeline["verified"].target["targetId"],
            topology_digest_value=pipeline["verified"].target["topologyDigest"],
        )

    forged_decision = deepcopy(pipeline["decision"])
    forged_proof = forged_decision["authorityClaimProof"]
    forged_proof["actorId"] = "forged-updater"
    forged_proof["proofDigest"] = revision_contract_digest(forged_proof, digest_field="proofDigest")
    forged_decision["decisionDigest"] = revision_contract_digest(
        forged_decision, digest_field="decisionDigest", id_field="decisionId"
    )
    forged_decision["decisionId"] = (
        f"revision_activation_decision_{forged_decision['decisionDigest'][7:39]}"
    )
    forged_terminal = deepcopy(pipeline["terminal"])
    forged_terminal["activationDecisionDigest"] = forged_decision["decisionDigest"]
    forged_terminal["receiptDigest"] = revision_contract_digest(
        forged_terminal, digest_field="receiptDigest"
    )
    with pytest.raises(ReleaseContractError, match="authority.*chain|canonical source"):
        render_accepted_activation(
            pipeline["verified"],
            pipeline["accepted"],
            activation_plan=pipeline["plan"],
            activation_decision=forged_decision,
            terminal_acceptance_receipt=forged_terminal,
            data_promotion_receipt=pipeline["promotion"],
            port_allocation_receipt=pipeline["portReceipt"],
            port_activation_recheck_receipt=pipeline["portRecheck"],
            authority_source_documents=pipeline["authorityDocuments"],
            authority_source_resolver=pipeline["authorityResolver"],
            current_pointer=None,
            route_projection_digest=ROUTE_DIGEST,
            written_at="2026-08-01T09:40:25Z",
        )


def test_expired_port_reservation_and_activation_collision_are_refused() -> None:
    pipeline = _revision_pipeline()
    allocated_port = pipeline["portReceipt"]["allocations"][0]["port"]
    with pytest.raises(ReleaseContractError, match="live collision"):
        record_revision_port_activation_recheck(
            pipeline["verified"],
            activation_plan=pipeline["plan"],
            port_allocation_receipt=pipeline["portReceipt"],
            observed_occupied_port_inputs=[
                {
                    "class": "observed-host",
                    "port": allocated_port,
                    "identityDigest": DIGEST,
                }
            ],
            host_observation_receipt_digest=DIGEST,
            checked_at="2026-08-01T09:40:10Z",
            valid_until="2026-08-01T09:40:40Z",
        )
    with pytest.raises(ReleaseContractError, match="unexpired immediate pre-effect"):
        render_accepted_activation(
            pipeline["verified"],
            pipeline["accepted"],
            activation_plan=pipeline["plan"],
            activation_decision=pipeline["decision"],
            terminal_acceptance_receipt=pipeline["terminal"],
            data_promotion_receipt=pipeline["promotion"],
            port_allocation_receipt=pipeline["portReceipt"],
            port_activation_recheck_receipt=pipeline["portRecheck"],
            authority_source_documents=pipeline["authorityDocuments"],
            authority_source_resolver=pipeline["authorityResolver"],
            current_pointer=None,
            route_projection_digest=ROUTE_DIGEST,
            written_at="2026-08-01T10:04:00Z",
        )


def _stable_execution_index(*, bootstrap_only: bool = False) -> dict[str, object]:
    value = release_index()
    if bootstrap_only:
        signed = value["signed"]
        target = signed["targets"][0]
        target["executionHostMode"] = "stable-host-daemon-bootstrap-only"
        target["releaseEligibility"] = "bootstrap-only"
        _refresh_index_topology(value)
    return value


def _refresh_index_topology(value: dict[str, object]) -> None:
    signed = value["signed"]
    target = signed["targets"][0]
    target["topologyDigest"] = topology_digest(target)
    target["quadletBundleDigest"] = quadlet_bundle_digest(
        render_quadlet_bundle(target, signed["images"])
    )
    value["signatures"][0]["subjectDigest"] = canonical_digest(signed)


def test_stable_execution_host_has_separate_operational_lifecycle_and_normal_client() -> None:
    value = _stable_execution_index()
    verified = verify_release_index(value, policy=_policy(), verifier=_EphemeralTestVerifier())
    files = render_quadlet_bundle(verified.target, verified.index.document["signed"]["images"])
    assert "host/execution-contract.json" not in files
    assert not any("host/stateport-exec/" in path for path in files)
    assert any(
        b"/run/stateport/execution-control:/run/stateport-execution:ro" in content
        for content in files.values()
    )
    client_units = [
        content
        for content in files.values()
        if b"STATEPORT_EXECUTION_SOCKET=" in content
    ]
    assert client_units
    assert all(b"PodmanArgs=--group-add=keep-groups" in content for content in client_units)
    assert all(
        b"PodmanArgs=--runtime=/usr/libexec/stateport/crun" in content
        for content in client_units
    )
    assert all(b"GroupAdd=" not in content for content in client_units)
    stable_files = render_stable_host_quadlet_bundle(
        verified.target, verified.index.document["signed"]["images"]
    )
    assert verify_stable_host_quadlet_bundle(stable_files, verified) == quadlet_bundle_digest(
        stable_files
    )
    host_unit = stable_files["host/stateport-exec/stateport-execution-host.container"]
    assert b"UserNS=keep-id:uid=65532,gid=65532" in host_unit
    assert b"PodmanArgs=--group-add=keep-groups" in host_unit
    assert b"PodmanArgs=--runtime=/usr/libexec/stateport/crun" in host_unit
    assert b"GroupAdd=" not in host_unit
    assert b"Volume=%t/podman:/run/stateport-engine:rw" in host_unit
    assert b"Environment=STATEPORT_ENGINE_SOCKET=/run/stateport-engine/podman.sock" in host_unit
    assert b"After=podman.socket" in host_unit
    # Sibling-class guard: no rendered unit bind-mounts a socket FILE
    # (podman.socket recreates the inode on restart).
    assert not [line for line in host_unit.splitlines() if line.startswith(b"Volume=") and b".sock" in line]
    assert b"127.0.0.1:17001:9911" in host_unit
    assert b"0.0.0.0" not in host_unit
    assert b"MemoryMax=536870912" in host_unit
    assert b"CPUQuota=100%" in host_unit
    assert b"TasksMax=256" in host_unit
    assert b"LogDriver=k8s-file" in host_unit
    assert b"PodmanArgs=--log-opt=max-size=10485760" in host_unit
    assert re.search(
        rb'HealthCmd="[^"]*stateport-healthcheck --kind unix-socket --path /[^"]*"', host_unit
    )
    assert b'"--kind", "unix-socket"' not in host_unit
    assert b"STATEPORT_EXECUTION_HOST_SOCKET_DIRECTORY_MODE=2750" in host_unit
    assert b"STATEPORT_EXECUTION_HOST_GRANTS_DIR=/var/lib/stateport/execution-host/grants" in host_unit
    assert b"/var/lib/stateport/execution-host/state/grants" not in host_unit
    assert b"WantedBy=default.target" in host_unit

    create = plan_stable_host_service_transition(
        verified,
        observed_services=[],
        host_identity_digest=DIGEST,
        port_reservation_receipt_digest=DIGEST,
    )
    assert create["actions"][0]["action"] == "create"
    desired = json.loads(canonical_json_bytes(verified.target["hostServices"][0]))
    observed = {
        field: deepcopy(desired[field])
        for field in (
            "serviceId",
            "imageId",
            "quadletOwner",
            "engineAccess",
            "socket",
            "ports",
            "writableVolumes",
            "resources",
            "logging",
            "health",
        )
    }
    observed["imageDigest"] = DIGEST
    observed["contractVersion"] = 1
    retain = plan_stable_host_service_transition(
        verified,
        observed_services=[observed],
        host_identity_digest=DIGEST,
        port_reservation_receipt_digest=DIGEST,
    )
    assert retain["actions"][0]["action"] == "retain"
    compatible = deepcopy(observed)
    compatible["imageDigest"] = f"sha256:{'0' * 64}"
    replace = plan_stable_host_service_transition(
        verified,
        observed_services=[compatible],
        host_identity_digest=DIGEST,
        port_reservation_receipt_digest=DIGEST,
    )
    assert replace["actions"][0]["action"] == "replace"

    bootstrap = _stable_execution_index(bootstrap_only=True)
    with pytest.raises(ReleaseContractError, match="bootstrap-only"):
        verify_release_index(bootstrap, policy=_policy(), verifier=_EphemeralTestVerifier())
    bootstrap_verified = verify_release_index(
        bootstrap,
        policy=_policy(allow_bootstrap_target=True),
        verifier=_EphemeralTestVerifier(),
    )
    assert bootstrap_verified.target["releaseEligibility"] == "bootstrap-only"
    bootstrap_revision = render_quadlet_bundle(
        bootstrap_verified.target, bootstrap_verified.index.document["signed"]["images"]
    )
    assert "host/execution-contract.json" in bootstrap_revision
    assert not any(
        path.endswith("stateport-execution-host.container") for path in bootstrap_revision
    )

    legacy_rootless_contract = deepcopy(value)
    legacy_target = legacy_rootless_contract["signed"]["targets"][0]
    legacy_host = legacy_target["hostServices"][0]
    legacy_host["userNamespace"] = "host"
    legacy_host["socket"]["directoryMode"] = "0750"
    legacy_target["executionContract"]["directoryMode"] = "0750"
    _refresh_index_topology(legacy_rootless_contract)
    with pytest.raises(ReleaseContractError, match="requires keep-id"):
        validate_release_index(legacy_rootless_contract)

    unsigned_identity_contract = deepcopy(value)
    unsigned_execution = unsigned_identity_contract["signed"]["targets"][0][
        "executionContract"
    ]
    for field in (
        "socketGroupGid",
        "allowedClientUid",
        "allowedClientGid",
        "runtimeUid",
        "runtimeGid",
    ):
        del unsigned_execution[field]
    _refresh_index_topology(unsigned_identity_contract)
    with pytest.raises(ReleaseContractError, match="explicit signed numeric identities"):
        validate_release_index(unsigned_identity_contract)

    invalid = deepcopy(value)
    server = deepcopy(invalid["signed"]["targets"][0]["services"][0])
    server["serviceId"] = "stateport-execution-host"
    server["trustDomain"] = "execution"
    server["quadletOwner"] = "stateport-exec"
    server["capabilities"]["controlContract"] = "narrow-unix-server"
    invalid["signed"]["targets"][0]["services"].append(server)
    invalid["signed"]["targets"][0]["topologyDigest"] = topology_digest(
        invalid["signed"]["targets"][0]
    )
    invalid["signatures"][0]["subjectDigest"] = canonical_digest(invalid["signed"])
    with pytest.raises(ReleaseContractError, match="stable execution host"):
        validate_release_index(invalid)

    leaked_engine = deepcopy(value)
    stable = leaked_engine["signed"]["targets"][0]["hostServices"][0]
    stable["trustDomain"] = "maintenance"
    stable["quadletOwner"] = "stateport-control"
    stable["writableVolumes"] = []
    leaked_engine["signed"]["targets"][0]["topologyDigest"] = topology_digest(
        leaked_engine["signed"]["targets"][0]
    )
    leaked_engine["signed"]["targets"][0]["quadletBundleDigest"] = quadlet_bundle_digest(
        render_quadlet_bundle(
            leaked_engine["signed"]["targets"][0], leaked_engine["signed"]["images"]
        )
    )
    leaked_engine["signatures"][0]["subjectDigest"] = canonical_digest(leaked_engine["signed"])
    with pytest.raises(ReleaseContractError, match="execution engine authority"):
        validate_release_index(leaked_engine)


def test_stable_host_rejects_public_bind_collision_unbounded_and_unsafe_inputs() -> None:
    collision = _stable_execution_index()
    service = collision["signed"]["targets"][0]["hostServices"][0]
    service["ports"].append(
        {
            "name": "debug",
            "containerPort": 9912,
            "hostPort": 17001,
            "hostScope": "loopback",
            "allocation": "stable-operator-bound",
        }
    )
    _refresh_index_topology(collision)
    with pytest.raises(ReleaseContractError, match="repeats a port name or number"):
        validate_release_index(collision)

    overlap = _stable_execution_index()
    overlap["signed"]["targets"][0]["hostServices"][0]["ports"][0]["hostPort"] = 18001
    _refresh_index_topology(overlap)
    with pytest.raises(ReleaseContractError, match="overlaps revision allocation range"):
        validate_release_index(overlap)

    hostile_health = _stable_execution_index()
    hostile_health["signed"]["targets"][0]["hostServices"][0]["health"] = {
        "kind": "http",
        "value": "http://127.0.0.1:9911/ready;touch-/tmp/pwned",
    }
    _refresh_index_topology(hostile_health)
    with pytest.raises(ReleaseContractError, match="schema validation"):
        validate_release_index(hostile_health)

    unsafe_mount = _stable_execution_index()
    unsafe_mount["signed"]["targets"][0]["hostServices"][0]["writableVolumes"][0]["mountPath"] = (
        "/etc/stateport"
    )
    _refresh_index_topology(unsafe_mount)
    with pytest.raises(ReleaseContractError, match="schema validation"):
        validate_release_index(unsafe_mount)

    unbounded = _stable_execution_index()
    del unbounded["signed"]["targets"][0]["hostServices"][0]["resources"]
    _refresh_index_topology(unbounded)
    with pytest.raises(ReleaseContractError, match="schema validation"):
        validate_release_index(unbounded)


def _stable_volume(value: dict[str, object]) -> dict[str, object]:
    return value["signed"]["targets"][0]["hostServices"][0]["writableVolumes"][0]


def test_stable_host_paths_reject_dotdot_escape_and_noncanonical_spellings() -> None:
    # D1: interior ".." in a stable hostPath escapes containment to /etc.
    etc_escape = _stable_execution_index()
    _stable_volume(etc_escape)["hostPath"] = (
        "/var/lib/stateport-exec/stateport-execution-host/state/../../../../../etc/stateport"
    )
    _refresh_index_topology(etc_escape)
    with pytest.raises(ReleaseContractError, match="schema validation"):
        validate_release_index(etc_escape)

    # D1: interior ".." escaping to /var/evil is rejected the same way.
    var_evil = _stable_execution_index()
    _stable_volume(var_evil)["hostPath"] = (
        "/var/lib/stateport-exec/stateport-execution-host/state/../../../evil"
    )
    _refresh_index_topology(var_evil)
    with pytest.raises(ReleaseContractError, match="schema validation"):
        validate_release_index(var_evil)

    # D1: a canonical path outside the owner root never reaches rendering.
    outside = _stable_execution_index()
    _stable_volume(outside)["hostPath"] = "/var/evil/state"
    _refresh_index_topology(outside)
    with pytest.raises(ReleaseContractError, match="schema validation"):
        validate_release_index(outside)

    # D1: a canonical sibling-service root is caught by component comparison.
    sibling = _stable_execution_index()
    _stable_volume(sibling)["hostPath"] = "/var/lib/stateport-exec/stateport-api/state"
    _refresh_index_topology(sibling)
    with pytest.raises(ReleaseContractError, match="crosses its Linux owner"):
        validate_release_index(sibling)

    # D1: prefix confusion (stateport-execution-host2) stays rejected.
    confused = _stable_execution_index()
    _stable_volume(confused)["hostPath"] = "/var/lib/stateport-exec/stateport-execution-host2/state"
    _refresh_index_topology(confused)
    with pytest.raises(ReleaseContractError, match="crosses its Linux owner"):
        validate_release_index(confused)

    # D2: interior ".." in a stable mountPath escapes the protected root.
    mount_escape = _stable_execution_index()
    _stable_volume(mount_escape)["mountPath"] = "/var/lib/stateport/a/../../../../etc"
    _refresh_index_topology(mount_escape)
    with pytest.raises(ReleaseContractError, match="schema validation"):
        validate_release_index(mount_escape)

    # D2: prefix confusion on the protected mount root stays rejected.
    mount_confused = _stable_execution_index()
    _stable_volume(mount_confused)["mountPath"] = "/var/lib/stateport-evil/execution-host"
    _refresh_index_topology(mount_confused)
    with pytest.raises(ReleaseContractError, match="schema validation"):
        validate_release_index(mount_confused)

    # D3/D5: overlap aliases are rejected as non-canonical before comparison.
    for alias in (
        "/var/lib/stateport-exec/stateport-execution-host/x/../state",
        "/var/lib/stateport-exec/stateport-execution-host/./state",
        "/var/lib/stateport-exec/stateport-execution-host//state",
    ):
        noncanonical = _stable_execution_index()
        _stable_volume(noncanonical)["hostPath"] = alias
        _refresh_index_topology(noncanonical)
        with pytest.raises(ReleaseContractError, match="schema validation"):
            validate_release_index(noncanonical)

    # D5: non-canonical mountPath spellings are rejected as well.
    for alias in (
        "/var/lib/stateport//execution-host",
        "/var/lib/stateport/./execution-host",
    ):
        noncanonical_mount = _stable_execution_index()
        _stable_volume(noncanonical_mount)["mountPath"] = alias
        _refresh_index_topology(noncanonical_mount)
        with pytest.raises(ReleaseContractError, match="schema validation"):
            validate_release_index(noncanonical_mount)

    # Canonical containment still catches a nested writable root overlap.
    nested = _stable_execution_index()
    nested_volume = deepcopy(_stable_volume(nested))
    nested_volume["name"] = "execution-state-nested"
    nested_volume["hostPath"] = "/var/lib/stateport-exec/stateport-execution-host/state/nested"
    nested_volume["mountPath"] = "/var/lib/stateport/execution-host/nested"
    nested["signed"]["targets"][0]["hostServices"][0]["writableVolumes"].append(nested_volume)
    _refresh_index_topology(nested)
    with pytest.raises(ReleaseContractError, match="share overlapping writable roots"):
        validate_release_index(nested)

    # Positive control: the valid stable execution fixture still validates.
    valid = _stable_execution_index()
    verified = verify_release_index(valid, policy=_policy(), verifier=_EphemeralTestVerifier())
    assert verified.index.release_id == valid["signed"]["release"]["releaseId"]


def test_revision_mount_paths_reject_leading_and_interior_dotdot() -> None:
    # D4: leading ".." components escape the revision mount root.
    for escape in ("/..", "/../etc"):
        leading = release_index()
        leading["signed"]["targets"][0]["services"][0]["writableVolumes"][0]["mountPath"] = escape
        leading["signed"]["targets"][0]["topologyDigest"] = topology_digest(
            leading["signed"]["targets"][0]
        )
        leading["signatures"][0]["subjectDigest"] = canonical_digest(leading["signed"])
        with pytest.raises(ReleaseContractError, match="schema validation"):
            validate_release_index(leading)

    # D4: interior ".." sequences remain rejected.
    interior = release_index()
    interior["signed"]["targets"][0]["services"][0]["writableVolumes"][0]["mountPath"] = (
        "/x/../../etc"
    )
    interior["signed"]["targets"][0]["topologyDigest"] = topology_digest(
        interior["signed"]["targets"][0]
    )
    interior["signatures"][0]["subjectDigest"] = canonical_digest(interior["signed"])
    with pytest.raises(ReleaseContractError, match="schema validation"):
        validate_release_index(interior)

    # Positive control: the valid revision mount path still validates.
    valid = release_index()
    verified = verify_release_index(valid, policy=_policy(), verifier=_EphemeralTestVerifier())
    assert verified.index.version == "0.2.0-rc.1"


def test_port_reservation_rechecks_host_and_data_generations_never_share_writes() -> None:
    pipeline = _revision_pipeline()
    allocated = pipeline["proposal"]["allocations"][0]["port"]
    with pytest.raises(ReleaseContractError, match="changed after approval"):
        reserve_revision_port_allocation(
            pipeline["verified"],
            pipeline["staged"],
            activation_plan=pipeline["plan"],
            reservation_receipt_digest=DIGEST,
            recheck_inventory_digest=DIGEST,
            rechecked_occupied_port_inputs=[
                {"class": "observed-host", "port": allocated, "identityDigest": DIGEST}
            ],
            allocated_at="2026-08-01T09:33:00Z",
            reservation_expires_at="2026-08-01T10:03:00Z",
        )
    shared = deepcopy(pipeline["promotion"])
    shared["predecessorVolumeNames"] = ["stateport-data-d1"]
    shared["receiptDigest"] = revision_contract_digest(shared, digest_field="receiptDigest")
    with pytest.raises(ReleaseContractError, match="share a writable"):
        validate_revision_contract(shared)


def test_two_release_revisions_have_distinct_full_id_ports_and_writable_d1() -> None:
    first = _revision_pipeline()
    successor_value = release_index()
    successor_value["signed"]["release"]["releaseId"] = "stateport-alpha-0.2.0-rc.2"
    successor_value["signed"]["release"]["version"] = "0.2.0-rc.2"
    successor_target = successor_value["signed"]["targets"][0]
    successor_target["releaseId"] = "stateport-alpha-0.2.0-rc.2"
    successor_target["topologyDigest"] = topology_digest(successor_target)
    successor_target["quadletBundleDigest"] = quadlet_bundle_digest(
        render_quadlet_bundle(successor_target, successor_value["signed"]["images"])
    )
    successor_value["signatures"][0]["subjectDigest"] = canonical_digest(successor_value["signed"])
    occupied = [
        {
            "class": "current",
            "port": allocation["port"],
            "identityDigest": canonical_digest(allocation),
        }
        for allocation in first["proposal"]["allocations"]
    ]
    second = _revision_pipeline(
        successor_value,
        occupied=occupied,
        current_pointer=_embedded(first["activation"], "stateport-accepted.current.json"),
        accepted_data_generation=DATA_D2,
        accepted_data_generation_digest=DATA_D2_DIGEST,
        predecessor_volume_names=["stateport-data-d1"],
        accepted_volume_name="stateport-data-d2",
    )
    first_manifest = _embedded(first["staged"], "/materialization.json")
    second_manifest = _embedded(second["staged"], "/materialization.json")
    assert set(first_manifest["revisions"].values()).isdisjoint(
        second_manifest["revisions"].values()
    )
    assert {allocation["port"] for allocation in first["proposal"]["allocations"]}.isdisjoint(
        {allocation["port"] for allocation in second["proposal"]["allocations"]}
    )
    assert second["promotion"]["acceptedDataGeneration"] == DATA_D2
    assert second["promotion"]["volumeBindings"][0]["volumeName"] == "stateport-data-d2"


def test_successor_cannot_promote_from_stale_predecessor_data() -> None:
    first = _revision_pipeline()
    pointer = _embedded(first["activation"], "stateport-accepted.current.json")
    successor = release_index()
    successor["signed"]["release"]["releaseId"] = "stateport-alpha-0.2.0-rc.2"
    successor["signed"]["release"]["version"] = "0.2.0-rc.2"
    target = successor["signed"]["targets"][0]
    target["releaseId"] = "stateport-alpha-0.2.0-rc.2"
    target["topologyDigest"] = topology_digest(target)
    target["quadletBundleDigest"] = quadlet_bundle_digest(
        render_quadlet_bundle(target, successor["signed"]["images"])
    )
    successor["signatures"][0]["subjectDigest"] = canonical_digest(successor["signed"])
    with pytest.raises(ReleaseContractError, match="does not match accepted pointer"):
        _revision_pipeline(
            successor,
            current_pointer=pointer,
            accepted_data_generation=DATA_D2,
            accepted_data_generation_digest=DATA_D2_DIGEST,
            predecessor_volume_names=["stateport-data-d1"],
            accepted_volume_name="stateport-data-d2",
            promotion_predecessor_override={
                "predecessorDataGeneration": DATA_D0,
                "predecessorDataGenerationDigest": f"sha256:{'0' * 64}",
            },
        )


def test_activation_pointer_refuses_replay_torn_write_and_validation_authority() -> None:
    pipeline = _revision_pipeline()
    pointer = _embedded(pipeline["activation"], "stateport-accepted.current.json")
    with pytest.raises(ReleaseContractError, match="replay"):
        validate_activation_pointer_transition(pointer, pointer)
    torn = deepcopy(pointer)
    torn["generation"] = 2
    torn["previousGeneration"] = 1
    torn["previousPointerDigest"] = DIGEST
    torn["pointerDigest"] = revision_contract_digest(torn, digest_field="pointerDigest")
    with pytest.raises(ReleaseContractError, match="predecessor digest"):
        validate_activation_pointer_transition(pointer, torn)
    forbidden = deepcopy(pointer)
    forbidden["validationGeneration"] = "validation-data"
    with pytest.raises(ReleaseContractError, match="additional property"):
        validate_revision_contract(forbidden)
    circular_decision = deepcopy(pipeline["decision"])
    circular_decision["terminalAcceptanceReceiptDigest"] = pipeline["terminal"]["receiptDigest"]
    circular_decision["decisionDigest"] = revision_contract_digest(
        circular_decision, digest_field="decisionDigest", id_field="decisionId"
    )
    with pytest.raises(ReleaseContractError, match="additional property"):
        validate_revision_contract(circular_decision)
    assert "terminalAcceptanceReceiptDigest" not in pipeline["decision"]
    assert pipeline["terminal"]["authorityFinalizeProof"]["phase"] == "finalize"


def test_owner_bundle_refuses_path_escape_and_nul() -> None:
    pipeline = _revision_pipeline()
    owner_bundle = deepcopy(
        _embedded(pipeline["accepted"], "/owner-bundles/stateport-control.json")
    )
    owner_bundle["artifacts"][0]["liveRelativePath"] = "../escape.container"
    owner_bundle["bundleDigest"] = revision_contract_digest(
        owner_bundle, digest_field="bundleDigest"
    )
    with pytest.raises(ReleaseContractError, match="schema validation"):
        validate_revision_contract(owner_bundle)

    owner_bundle["artifacts"][0]["liveRelativePath"] = "escape\x00.container"
    owner_bundle["bundleDigest"] = revision_contract_digest(
        owner_bundle, digest_field="bundleDigest"
    )
    with pytest.raises(ReleaseContractError, match="unsafe live artifact path"):
        validate_revision_contract(owner_bundle)


def test_runtime_names_remain_bounded_at_schema_maximum() -> None:
    value = release_index()
    signed = value["signed"]
    service = signed["targets"][0]["services"][0]
    image = signed["images"][0]
    maximal = "stateport-" + "s" * 63
    service["serviceId"] = maximal
    service["imageId"] = maximal
    image["imageId"] = maximal
    image["reference"] = f"ghcr.io/stateport/{maximal}@{DIGEST}"
    signed["targets"][0]["topologyDigest"] = topology_digest(signed["targets"][0])
    signed["targets"][0]["quadletBundleDigest"] = quadlet_bundle_digest(
        render_quadlet_bundle(signed["targets"][0], signed["images"])
    )
    value["signatures"][0]["subjectDigest"] = canonical_digest(signed)
    pipeline = _revision_pipeline(value)
    all_paths = [*pipeline["staged"], *pipeline["accepted"], *pipeline["activation"]]
    assert max(len(Path(path).name.encode()) for path in all_paths) <= 255
    for content in [*pipeline["staged"].values(), *pipeline["accepted"].values()]:
        for field in (b"ContainerName=", b"NetworkName=", b"VolumeName="):
            for line in content.splitlines():
                if line.startswith(field):
                    assert len(line.split(b"=", 1)[1]) <= 128


def _run_noble_systemd_quadlet_compatibility(
    tmp_path: Path,
    *,
    quadlet: Path,
    expected_quadlet_version: str,
    proof_label: str,
) -> None:
    podman = shutil.which("podman")
    assert podman is not None
    noble = (
        "docker.io/jrei/systemd-ubuntu@"
        "sha256:1651d37afbe971fecf757cb920bda47925452213bb9a01e13a9848def52f912f"
    )
    assert quadlet.is_file()
    assert subprocess.run([podman, "image", "exists", noble], check=False).returncode == 0

    pipeline = _revision_pipeline()
    quadlet_dir = tmp_path / "quadlets"
    regular_dir = tmp_path / "regular"
    generated = tmp_path / "generated"
    generated_early = tmp_path / "generated-early"
    generated_late = tmp_path / "generated-late"
    for directory in (
        quadlet_dir,
        regular_dir,
        generated,
        generated_early,
        generated_late,
    ):
        directory.mkdir()
    owner_bundle = _embedded(pipeline["accepted"], "/owner-bundles/stateport-control.json")
    for artifact in owner_bundle["artifacts"]:
        destination = quadlet_dir / artifact["liveRelativePath"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(pipeline["accepted"][artifact["sourcePath"]])
    stable_index = _stable_execution_index()
    stable_verified = verify_release_index(
        stable_index, policy=_policy(), verifier=_EphemeralTestVerifier()
    )
    stable_bundle = render_stable_host_quadlet_bundle(
        stable_verified.target, stable_verified.index.document["signed"]["images"]
    )
    for path, content in stable_bundle.items():
        if not path.endswith(".container"):
            continue
        (quadlet_dir / Path(path).name).write_bytes(content)
    for path, content in pipeline["activation"].items():
        relative = path.removeprefix("activation/")
        if not (
            relative == "stateport-accepted.target"
            or relative.startswith("stateport-accepted.target.d/")
        ):
            continue
        destination = regular_dir / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)

    completed = subprocess.run(
        [
            podman,
            "run",
            "--rm",
            "--pull=never",
            "--network=none",
            "--label",
            f"io.stateport.task={proof_label}",
            "--security-opt",
            "label=disable",
            "-v",
            f"{quadlet}:/usr/local/bin/quadlet:ro",
            "-v",
            "/usr/bin/true:/usr/bin/podman:ro",
            "-v",
            f"{quadlet_dir}:/quadlets:ro",
            "-v",
            f"{regular_dir}:/regular:ro",
            "-v",
            f"{generated}:/generated:rw",
            "-v",
            f"{generated_early}:/generated-early:rw",
            "-v",
            f"{generated_late}:/generated-late:rw",
            noble,
            "sh",
            "-ceu",
            'test "$(. /etc/os-release; echo "$VERSION_ID")" = 24.04; '
            f'test "$(/usr/local/bin/quadlet -version)" = {expected_quadlet_version}; '
            "QUADLET_UNIT_DIRS=/quadlets /usr/local/bin/quadlet -user "
            "/generated /generated-early /generated-late; "
            "systemd-analyze verify /generated/*.service /regular/stateport-accepted.target",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    services = sorted(generated.glob("*.service"))
    assert services
    assert any("stateport" in service.name for service in services)
    assert any("stateport-execution-host" in service.name for service in services)
    container_units = [
        service.read_text(encoding="utf-8")
        for service in services
        if "podman run" in service.read_text(encoding="utf-8")
    ]
    assert container_units
    assert all("--log-driver k8s-file" in content for content in container_units)
    assert all("--log-opt=max-size=10485760" in content for content in container_units)
    assert all("/usr/local/bin/stateport-healthcheck" in content for content in container_units)
    assert all("0.0.0.0" not in content for content in container_units)
    stable_unit = next(
        service.read_text(encoding="utf-8")
        for service in services
        if "stateport-execution-host" in service.name
    )
    assert "MemoryMax=536870912" in stable_unit
    assert "CPUQuota=100%" in stable_unit
    assert "TasksMax=256" in stable_unit
    assert "--group-add=keep-groups" in stable_unit
    assert "unsupported key" not in completed.stderr


def test_noble_systemd_accepts_host_quadlet_584_generated_units(tmp_path: Path) -> None:
    if os.environ.get("STATEPORT_NOBLE_SYSTEMD_HOST_QUADLET_584_PROOF") != "1":
        pytest.skip(
            "set STATEPORT_NOBLE_SYSTEMD_HOST_QUADLET_584_PROOF=1 for the "
            "Noble-systemd/host-Quadlet-5.8.4 proof"
        )
    quadlet = Path("/usr/libexec/podman/quadlet")
    assert quadlet.is_file()
    assert hashlib.sha256(quadlet.read_bytes()).hexdigest() == (
        "80fc48eed3caeeee20b1c7b20a15f2c747c01315a97f0b3282d822f3bde446bb"
    )
    _run_noble_systemd_quadlet_compatibility(
        tmp_path,
        quadlet=quadlet,
        expected_quadlet_version="5.8.4",
        proof_label="alpha-slice-b-noble-systemd-host-quadlet-584-proof",
    )


def _extract_ubuntu_noble_quadlet_493(package: Path, destination: Path) -> str:
    assert hashlib.sha256(package.read_bytes()).hexdigest() == (
        "e5c1c37e387ed14c352a744a75fbb79fb2f82573ca7bf36886e3b7333fc9ef1a"
    )
    listing = subprocess.run(
        ["ar", "t", str(package)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    data_members = [name for name in listing if name.startswith("data.tar.")]
    assert len(data_members) == 1
    payload = subprocess.run(
        ["ar", "p", str(package), data_members[0]],
        check=True,
        capture_output=True,
    ).stdout
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as archive:
        matches = [
            member
            for member in archive.getmembers()
            if member.name.lstrip("./") == "usr/libexec/podman/quadlet"
        ]
        assert len(matches) == 1 and matches[0].isfile()
        source = archive.extractfile(matches[0])
        assert source is not None
        content = source.read()
    destination.write_bytes(content)
    destination.chmod(0o755)
    return hashlib.sha256(content).hexdigest()


def test_ubuntu_noble_quadlet_493_and_systemd_verify_real_units(tmp_path: Path) -> None:
    if os.environ.get("STATEPORT_NOBLE_QUADLET_493_PROOF") != "1":
        pytest.skip(
            "set STATEPORT_NOBLE_QUADLET_493_PROOF=1 and "
            "STATEPORT_NOBLE_PODMAN_493_DEB to prove the Ubuntu baseline"
        )
    package_value = os.environ.get("STATEPORT_NOBLE_PODMAN_493_DEB")
    assert package_value is not None
    package = Path(package_value)
    assert package.is_absolute() and package.is_file() and not package.is_symlink()
    quadlet = tmp_path / "ubuntu-noble-quadlet-4.9.3"
    quadlet_digest = _extract_ubuntu_noble_quadlet_493(package, quadlet)
    assert quadlet_digest == ("9e95fafe06ef5b630dbb59cbf3630d38931c3fc27ba7c7f9cf472f064d9798b9")
    _run_noble_systemd_quadlet_compatibility(
        tmp_path,
        quadlet=quadlet,
        expected_quadlet_version="4.9.3",
        proof_label="alpha-slice-b-ubuntu-noble-quadlet-493-systemd-proof",
    )


def test_release_package_validates_outside_checkout(tmp_path: Path) -> None:
    site = tmp_path / "site"
    site.mkdir()
    shutil.copytree(
        ROOT / "packages/release-contracts/src/stateport_release",
        site / "stateport_release",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    index_path = tmp_path / "release-index.json"
    index_path.write_text(json.dumps(release_index()), encoding="utf-8")
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP"}
    }
    environment["PYTHONPATH"] = str(site)
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "from pathlib import Path; from stateport_release import load_release_index; "
            "print(load_release_index(Path('release-index.json').read_bytes()).release_id)",
        ],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "stateport-alpha-0.2.0-rc.1"


def _update_release(
    release_id: str,
    version: str,
    *,
    signed_digest: str,
) -> dict[str, object]:
    return {
        "releaseId": release_id,
        "version": version,
        "channel": "alpha",
        "signedPayloadDigest": signed_digest,
        "imageSetDigest": DIGEST,
        "sourceCommit": COMMIT,
        "sourceTree": TREE,
        "qualification": "candidate",
        "publishedAt": None,
    }


def _authority_scope(run_id: str) -> dict[str, object]:
    return {
        "repository": {
            "origin": "https://github.com/stateport/stateport.git",
            "repositoryKey": "1" * 32,
            "repositoryRoot": "/srv/stateport/control",
        },
        "branch": None,
        "sliceId": "BL-CONTAINER-DEPLOYMENT-ALPHA-001-B",
        "applicationId": "stateport",
        "runId": run_id,
        "paths": ["operator://stateport/update"],
    }


def _update_authority_reference(plan_digest: str) -> dict[str, object]:
    return {
        "action": "apply_update",
        "actorId": "stateport-updater",
        "grantId": "grant_update_fixture_001",
        "grantDigest": f"sha256:{'6' * 64}",
        "profile": "balanced",
        "configuredPolicy": "auto_with_receipt",
        "effectivePolicy": "auto_with_receipt",
        "scope": _authority_scope(plan_digest),
        "runId": plan_digest,
        "planDigest": plan_digest,
        "requestId": f"authority_request_{'7' * 32}",
        "decisionDigest": f"sha256:{'7' * 64}",
        "reservationId": f"authority_reservation_{'8' * 32}",
        "reservationDigest": f"sha256:{'8' * 64}",
        "claimId": f"authority_claim_{'9' * 32}",
        "claimDigest": f"sha256:{'9' * 64}",
    }


def test_canonical_update_documents_share_exact_digest_chain() -> None:
    current = _update_release("stateport-alpha-0.1.0", "0.1.0", signed_digest=f"sha256:{'f' * 64}")
    successor = _update_release(
        "stateport-alpha-0.2.0-rc.1", "0.2.0-rc.1", signed_digest=f"sha256:{'e' * 64}"
    )
    policy: dict[str, object] = {
        "mode": "automatic-with-rollback",
        "channel": "alpha",
        "schedule": {"daysOfWeek": [1, 2, 3, 4, 5, 6, 7], "startMinuteUtc": 120},
        "retention": {
            "acceptedPredecessors": 1,
            "failedSuccessors": 1,
            "maximumVersions": 3,
            "maximumAgeDays": 30,
        },
        "downloadAhead": True,
    }
    policy["policyDigest"] = update_policy_digest(policy)
    plan_value: dict[str, object] = {
        "schema": "stateport.update-plan/v1",
        "operation": "update",
        "installationId": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
        "current": current,
        "successor": successor,
        "releaseIndexDigest": f"sha256:{'d' * 64}",
        "signedPayloadDigest": successor["signedPayloadDigest"],
        "policy": policy,
        "estimatedPullBytes": 1048576,
        "compatibility": {
            "updaterCompatible": True,
            "migrationCompatible": True,
            "rollbackCompatible": True,
            "downgrade": False,
        },
        "backupRequired": True,
        "steps": [
            "verify",
            "backup",
            "pull",
            "stage",
            "dry-run-migrations",
            "start-successor",
            "health-successor",
            "browser-successor",
            "studystate-successor",
            "state-check-successor",
            "switch",
            "health-accepted-route",
            "state-check-accepted-route",
            "retain-predecessor",
            "record-receipt",
        ],
        "rollback": {
            "automaticOnFailure": True,
            "retainedPredecessor": True,
            "dataCompatible": True,
        },
        "authority": {
            "action": "apply_update",
            "status": "awaiting_authority_claim",
        },
        "createdAt": "2026-08-01T10:00:00Z",
        "expiresAt": "2026-08-01T10:30:00Z",
    }
    plan_value["planDigest"] = update_plan_digest(plan_value)
    plan_value["authority"]["runId"] = plan_value["planDigest"]
    plan_value["planId"] = (
        "update_plan_" + str(plan_value["planDigest"]).removeprefix("sha256:")[:32]
    )
    plan = validate_update_plan(
        plan_value,
        now=datetime(2026, 8, 1, 10, 1, tzinfo=timezone.utc),
    )
    assert plan.document["planDigest"] == plan_value["planDigest"]
    with pytest.raises(ReleaseContractError, match="expired"):
        validate_update_plan(
            plan_value,
            now=datetime(2026, 8, 1, 10, 30, tzinfo=timezone.utc),
        )

    failure = validate_update_failure_evidence(
        {
            "schema": "stateport.update-failure-evidence/v1",
            "failureId": f"update_failure_{'4' * 32}",
            "planId": plan_value["planId"],
            "planDigest": plan.digest,
            "successor": {
                "releaseId": successor["releaseId"],
                "version": successor["version"],
                "signedPayloadDigest": successor["signedPayloadDigest"],
            },
            "failedStep": "health-successor",
            "errorCode": "successor_unhealthy",
            "safeSummary": "The isolated successor did not become ready.",
            "artifacts": [],
            "retained": True,
            "observedAt": "2026-08-01T10:02:00Z",
        }
    )
    status = validate_update_status(
        {
            "schema": "stateport.update-status/v1",
            "sequence": 3,
            "phase": "rolled_back",
            "installationId": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
            "policy": policy,
            "current": {
                "releaseId": current["releaseId"],
                "version": current["version"],
                "signedPayloadDigest": current["signedPayloadDigest"],
            },
            "accepted": {
                "releaseId": current["releaseId"],
                "version": current["version"],
                "signedPayloadDigest": current["signedPayloadDigest"],
            },
            "retainedPredecessor": None,
            "stagedSuccessor": None,
            "failedSuccessorEvidence": failure.document["failureId"],
            "lastReceipt": f"update_receipt_{'5' * 32}",
            "updatedAt": "2026-08-01T10:03:00Z",
        }
    )
    assert status.document["failedSuccessorEvidence"] == failure.document["failureId"]

    receipt = validate_update_receipt(
        {
            "schema": "stateport.update-receipt/v1",
            "receiptId": f"update_receipt_{'5' * 32}",
            "installationId": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
            "planId": plan_value["planId"],
            "planDigest": plan.digest,
            "operation": "update",
            "from": current,
            "attempted": successor,
            "accepted": current,
            "releaseIndexDigest": plan_value["releaseIndexDigest"],
            "backupReceipt": "backup_receipt_fixture",
            "checks": {"health": "failed", "rollback": "passed"},
            "rollback": {
                "attempted": True,
                "succeeded": True,
                "retainedFailureEvidence": True,
            },
            "authority": _update_authority_reference(plan.digest),
            "startedAt": "2026-08-01T10:01:00Z",
            "finishedAt": "2026-08-01T10:03:00Z",
            "result": "rolled_back",
        }
    )
    assert receipt.document["accepted"] == receipt.document["from"]
    link = validate_update_authority_link(
        {
            "schema": "stateport.update-authority-link/v1",
            "linkId": f"update_authority_link_{'b' * 32}",
            "planDigest": plan.digest,
            "runId": plan.digest,
            "updateReceiptId": receipt.document["receiptId"],
            "updateReceiptDigest": receipt.digest,
            "authority": {
                **_update_authority_reference(plan.digest),
                "receiptId": f"authority_receipt_{'a' * 32}",
                "receiptDigest": f"sha256:{'a' * 64}",
            },
            "linkedAt": "2026-08-01T10:04:00Z",
        }
    )
    assert link.document["runId"] == plan.digest


def test_install_receipt_and_provenance_contracts_validate() -> None:
    index = release_index()
    signed = index["signed"]
    signed_target = signed["targets"][0]
    index_digest = canonical_digest(index)
    signed_digest = canonical_digest(signed)
    images = signed["images"]
    observed_services = [
        {
            "serviceId": service["serviceId"],
            "imageId": service["imageId"],
            "imageDigest": next(
                image["digest"] for image in images if image["imageId"] == service["imageId"]
            ),
            "healthy": True,
        }
        for service in signed_target["services"]
    ]
    observed_image_set = image_set_digest(images)
    observed_service_set = service_set_digest(observed_services)
    target_identity: dict[str, object] = {
        "targetId": signed_target["targetId"],
        "topologyDigest": signed_target["topologyDigest"],
        "quadletArtifactDigest": signed["artifacts"]["quadlet"]["digest"],
        "quadletBundleDigest": signed_target["quadletBundleDigest"],
        "imageSetDigest": observed_image_set,
        "serviceSetDigest": observed_service_set,
    }
    target_identity["targetDigest"] = canonical_digest(target_identity)
    runtime: dict[str, object] = {
        "releaseId": signed["release"]["releaseId"],
        "releaseIndexDigest": index_digest,
        "signedPayloadDigest": signed_digest,
        "targetDigest": target_identity["targetDigest"],
        "topologyDigest": target_identity["topologyDigest"],
        "quadletArtifactDigest": target_identity["quadletArtifactDigest"],
        "quadletBundleDigest": target_identity["quadletBundleDigest"],
        "imageSetDigest": observed_image_set,
        "serviceSetDigest": observed_service_set,
        "services": observed_services,
        "localUrl": "http://127.0.0.1:8080/",
        "healthy": True,
    }
    runtime["runtimeIdentityDigest"] = canonical_digest(runtime)
    directive: dict[str, object] = {
        "kind": "installer-directive",
        "directiveId": f"installer_directive_{'2' * 32}",
        "directiveKind": "interactive-exact-plan",
        "actorId": "local-owner",
        "installerDigest": DIGEST,
        "releaseIndexDigest": index_digest,
        "planDigest": DIGEST,
        "confirmationReceiptDigest": f"sha256:{'3' * 64}",
        "confirmedAt": "2026-08-01T09:59:59Z",
    }
    directive["directiveDigest"] = installer_directive_digest(directive)
    receipt = validate_install_receipt(
        {
            "schema": "stateport.install-receipt/v1",
            "receiptId": f"install_receipt_{'6' * 32}",
            "operation": "install",
            "installer": {"version": "0.1.0", "digest": DIGEST},
            "release": {
                "releaseId": signed["release"]["releaseId"],
                "version": signed["release"]["version"],
                "channel": signed["release"]["channel"],
                "signedPayloadDigest": signed_digest,
                "sourceCommit": signed["source"]["commit"],
                "sourceTree": signed["source"]["tree"],
            },
            "releaseIndexDigest": index_digest,
            "installPlanDigest": DIGEST,
            "target": target_identity,
            "host": {
                "kernel": "Linux",
                "osId": "ubuntu",
                "versionId": "24.04",
                "architecture": "amd64",
                "cgroupVersion": "v2",
                "podmanVersion": "5.4.2",
                "rootless": True,
                "quadlet": True,
                "systemdUser": True,
                "subuidConfigured": True,
                "subgidConfigured": True,
                "supportTier": "validated_baseline",
            },
            "verification": {
                "signedIndex": {
                    "expectedDigest": index_digest,
                    "observedDigest": index_digest,
                    "status": "verified",
                },
                "signers": [
                    {
                        "subjectKind": "release-index",
                        "subjectId": "release-index",
                        "subjectDigest": signed_digest,
                        "trustMode": "keyless-certificate",
                        "certificateIdentity": SIGNER.certificate_identity,
                        "certificateOidcIssuer": SIGNER.oidc_issuer,
                        "bundleDigest": index["signatures"][0]["bundle"]["digest"],
                        "verifiedAt": "2026-08-01T09:59:00Z",
                        "transparencyLogStatus": "not-required-private-candidate",
                        "status": "verified",
                    },
                    *[
                        {
                            "subjectKind": "image",
                            "subjectId": image["imageId"],
                            "subjectDigest": image["digest"],
                            "trustMode": "keyless-certificate",
                            "certificateIdentity": SIGNER.certificate_identity,
                            "certificateOidcIssuer": SIGNER.oidc_issuer,
                            "bundleDigest": image["signature"]["bundle"]["digest"],
                            "verifiedAt": "2026-08-01T09:59:00Z",
                            "transparencyLogStatus": "not-required-private-candidate",
                            "status": "verified",
                        }
                        for image in images
                    ],
                ],
                "artifacts": [
                    {
                        "artifactId": artifact_id,
                        "expectedDigest": artifact["digest"],
                        "observedDigest": artifact["digest"],
                        "status": "verified",
                    }
                    for artifact_id, artifact in signed["artifacts"].items()
                ],
                "images": [
                    {
                        "imageId": image["imageId"],
                        "reference": image["reference"],
                        "expectedDigest": image["digest"],
                        "observedDigest": image["digest"],
                        "sizeBytes": image["sizeBytes"],
                        "signatureBundleDigest": image["signature"]["bundle"]["digest"],
                        "cycloneDxDigest": image["sboms"]["cycloneDx"]["digest"],
                        "spdxDigest": image["sboms"]["spdx"]["digest"],
                        "scanDigest": image["scan"]["artifact"]["digest"],
                        "provenanceDigest": image["provenance"]["digest"],
                        "status": "verified",
                    }
                    for image in images
                ],
            },
            "runtime": runtime,
            "dataDisposition": "created",
            "authority": directive,
            "startedAt": "2026-08-01T10:00:00Z",
            "finishedAt": "2026-08-01T10:01:00Z",
            "result": "succeeded",
        }
    )
    assert receipt.document["runtime"]["healthy"] is True

    provenance = validate_release_provenance(
        {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "stateport-web", "digest": {"sha256": HEX}}],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://stateport.invalid/buildtypes/oci/v1",
                    "externalParameters": {
                        "sourceRepository": "https://github.com/stateport/stateport.git",
                        "sourceCommit": COMMIT,
                        "sourceTree": TREE,
                        "publicSnapshotCommit": "d" * 40,
                        "publicSnapshotTree": "e" * 40,
                        "platform": "linux/amd64",
                        "dockerfile": "images/stateport-web/Containerfile",
                    },
                    "internalParameters": {
                        "sourceDateEpoch": 1785578400,
                        "networkMode": "dependency-fetch-only",
                    },
                    "resolvedDependencies": [{"uri": "oci://python", "digest": {"sha256": HEX}}],
                },
                "runDetails": {
                    "builder": {
                        "id": "operator://builder/local",
                        "version": "podman-5",
                        "executableDigest": "sha256:" + "a" * 64,
                        "descriptorDigest": "sha256:" + "b" * 64,
                        "artifactUri": "https://example.invalid/podman-5",
                        "artifactDigest": "sha256:" + "a" * 64,
                    },
                    "metadata": {
                        "invocationId": "fixture-build",
                        "startedOn": "2026-08-01T10:00:00Z",
                        "finishedOn": "2026-08-01T10:01:00Z",
                    },
                    "byproducts": [],
                },
            },
        }
    )
    assert provenance.document["predicateType"] == "https://slsa.dev/provenance/v1"


# ---------------------------------------------------------------------------
# Content-addressed signature-bundle retention
# ---------------------------------------------------------------------------

RETAINED_BUNDLE_BYTES = (
    b'{"mediaType":"application/vnd.sigstore.bundle.v0.3+json","retained":true}\n'
)
SUCCESSOR_BUNDLE_BYTES = (
    b'{"mediaType":"application/vnd.sigstore.bundle.v0.3+json","retained":"successor"}\n'
)


def _retained_signature(
    bundle_bytes: bytes,
    *,
    name: str = "release-index.sigstore.json",
    fingerprint: str = PINNED_KEY.public_key_fingerprint,
    key_id: str = PINNED_KEY.key_id,
) -> dict[str, object]:
    return {
        "scheme": "cosign-v3-bundle",
        "subjectDigest": DIGEST,
        "bundle": {
            "uri": f"operator://release/{name}",
            "digest": "sha256:" + hashlib.sha256(bundle_bytes).hexdigest(),
            "size": len(bundle_bytes),
            "mediaType": "application/vnd.sigstore.bundle.v0.3+json",
        },
        "trustMode": "pinned-public-key",
        "publicKeyFingerprint": fingerprint,
        "publicKeyFingerprintAlgorithm": "sha256-canonical-der-spki",
        "publicKeyId": key_id,
        "transparencyLog": "not-uploaded-private-candidate",
    }


def test_signature_bundle_name_requires_a_retained_bundle_uri() -> None:
    signature = _retained_signature(RETAINED_BUNDLE_BYTES)
    assert signature_bundle_name(signature) == "release-index.sigstore.json"
    broken = deepcopy(signature)
    broken["bundle"]["uri"] = "operator://release/release-index.json"
    with pytest.raises(CosignVerificationError, match="does not name a retained bundle"):
        signature_bundle_name(broken)


def test_bundle_slot_is_content_addressed_by_the_recorded_digest() -> None:
    signature = _retained_signature(RETAINED_BUNDLE_BYTES)
    slot = bundle_slot(Path("/bundles"), signature)
    assert slot == (
        Path("/bundles")
        / hashlib.sha256(RETAINED_BUNDLE_BYTES).hexdigest()
        / "release-index.sigstore.json"
    )
    malformed = deepcopy(signature)
    malformed["bundle"]["digest"] = "sha256:not-hex"
    with pytest.raises(CosignVerificationError, match="bundle digest is malformed"):
        bundle_slot(Path("/bundles"), malformed)


def test_retain_bundle_is_create_only_digest_checked_and_idempotent(tmp_path: Path) -> None:
    root = tmp_path / "bundles"
    root.mkdir()
    source = tmp_path / "release-index.sigstore.json"
    source.write_bytes(RETAINED_BUNDLE_BYTES)
    signature = _retained_signature(RETAINED_BUNDLE_BYTES)

    slot = retain_bundle(root, source, signature)
    assert slot == bundle_slot(root, signature)
    assert slot.read_bytes() == RETAINED_BUNDLE_BYTES
    assert slot.stat().st_mode & 0o777 == 0o600
    assert retain_bundle(root, source, signature) == slot

    slot.chmod(0o600)
    slot.write_bytes(SUCCESSOR_BUNDLE_BYTES)
    with pytest.raises(CosignVerificationError, match="do not match the recorded digest"):
        retain_bundle(root, source, signature)


def test_retain_bundle_refuses_a_source_that_diverges_from_the_record(tmp_path: Path) -> None:
    root = tmp_path / "bundles"
    root.mkdir()
    source = tmp_path / "release-index.sigstore.json"
    source.write_bytes(SUCCESSOR_BUNDLE_BYTES)
    signature = _retained_signature(RETAINED_BUNDLE_BYTES)
    with pytest.raises(CosignVerificationError, match="do not match the recorded digest"):
        retain_bundle(root, source, signature)
    assert list(root.iterdir()) == []


def test_retain_bundle_keeps_same_named_bundles_in_separate_digest_slots(tmp_path: Path) -> None:
    root = tmp_path / "bundles"
    root.mkdir()
    genesis = _retained_signature(RETAINED_BUNDLE_BYTES)
    successor = _retained_signature(SUCCESSOR_BUNDLE_BYTES)
    genesis_source = tmp_path / "genesis" / "release-index.sigstore.json"
    successor_source = tmp_path / "successor" / "release-index.sigstore.json"
    genesis_source.parent.mkdir()
    successor_source.parent.mkdir()
    genesis_source.write_bytes(RETAINED_BUNDLE_BYTES)
    successor_source.write_bytes(SUCCESSOR_BUNDLE_BYTES)

    genesis_slot = retain_bundle(root, genesis_source, genesis)
    successor_slot = retain_bundle(root, successor_source, successor)
    assert genesis_slot != successor_slot
    assert genesis_slot.read_bytes() == RETAINED_BUNDLE_BYTES
    assert successor_slot.read_bytes() == SUCCESSOR_BUNDLE_BYTES


def test_retain_bundle_refuses_a_symlink_source(tmp_path: Path) -> None:
    root = tmp_path / "bundles"
    root.mkdir()
    target = tmp_path / "target.sigstore.json"
    target.write_bytes(RETAINED_BUNDLE_BYTES)
    source = tmp_path / "release-index.sigstore.json"
    source.symlink_to(target)
    with pytest.raises(CosignVerificationError, match="not a regular file"):
        retain_bundle(root, source, _retained_signature(RETAINED_BUNDLE_BYTES))
    assert list(root.iterdir()) == []


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl fingerprints the fixture key")
def test_cosign_verifier_resolves_bundles_only_from_the_retained_slot(tmp_path: Path) -> None:
    from scripts.test_install_no_checkout import TEST_PUBLIC_KEY_PEM

    cosign = tmp_path / "cosign"
    cosign.write_bytes(b"#!/bin/sh\nexit 0\n")
    cosign.chmod(0o755)
    pem = tmp_path / "trust.pub"
    pem.write_text(TEST_PUBLIC_KEY_PEM, encoding="ascii")
    identity = PinnedPublicKeyIdentity(public_key_der_spki_fingerprint(pem), "alpha-release")
    root = tmp_path / "bundles"
    root.mkdir()
    verifier = CosignVerifier(cosign=cosign, public_key=pem, identity=identity, bundle_root=root)
    signature = _retained_signature(
        RETAINED_BUNDLE_BYTES,
        fingerprint=identity.public_key_fingerprint,
        key_id=identity.key_id,
    )
    signature["subjectDigest"] = "sha256:" + hashlib.sha256(b"payload").hexdigest()
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "release-index.sigstore.json").write_bytes(RETAINED_BUNDLE_BYTES)
    # A flat bundle beside the verifier root is the pre-fix layout and must be dead.
    (root / "release-index.sigstore.json").write_bytes(RETAINED_BUNDLE_BYTES)
    with pytest.raises(CosignVerificationError, match="not a regular file"):
        verifier.verify_blob(b"payload", signature)

    verifier.retain_bundle(staging / "release-index.sigstore.json", signature)
    proof = verifier.verify_blob(b"payload", signature)
    assert proof.bundle_digest == signature["bundle"]["digest"]


def test_parse_last_line_json_helper_contract() -> None:
    """I3: the shared last-non-empty-line JSON parser has a fixed contract."""

    assert parse_last_line_json('{"healthy": true}\n') == {"healthy": True}
    assert parse_last_line_json("noise line\n{\"a\": 1}\n") == {"a": 1}
    assert parse_last_line_json("") is None
    assert parse_last_line_json("   \n\n") is None
    assert parse_last_line_json("not json") is None
    assert parse_last_line_json("noise\nnot json either\n") is None
    # A trailing blank line after the payload is tolerated (last NON-EMPTY line).
    assert parse_last_line_json('{"x": 2}\n\n\n') == {"x": 2}
    # Non-object JSON values parse too; callers validate the shape themselves.
    assert parse_last_line_json("[1, 2]\n") == [1, 2]


def test_internal_cli_emitter_parser_pairs_share_the_i3_helper() -> None:
    """I3: every internal CLI emitter/parser pair parses the last non-empty
    line through the single shared ``parse_last_line_json`` helper.

    The known pairs are the execution-host ``health-probe`` CLI (parsed by the
    privileged provisioning step) and the StateBench protected evaluator
    (parsed by the real-project harness). The installer's install-end gate
    consumes the provisioning receipt and intentionally has no duplicate probe
    parser.
    A hand-rolled ``json.loads(stdout.strip().splitlines()[-1])`` anywhere in
    those parsers is exactly the drift this invariant forbids.
    """

    root = Path(__file__).resolve().parents[1]
    pairs = [
        root / "packages/release-contracts/src/stateport_release/execution_host_provisioning.py",
        root / "packages/statebench/src/statebench/real_project_harness.py",
    ]
    hand_rolled = "json.loads(completed.stdout.strip().splitlines()[-1])"
    for source in pairs:
        text = source.read_text(encoding="utf-8")
        assert "parse_last_line_json" in text, f"{source} must use the shared I3 helper"
        assert hand_rolled not in text, f"{source} re-introduced a hand-rolled last-line parse"


def test_web_template_source_mount_is_read_only_and_uses_pinned_group_runtime() -> None:
    value = _stable_execution_index()
    service = value["signed"]["targets"][0]["services"][0]
    service["readOnlyHostMounts"] = [
        {
            "name": "template-sources",
            "hostPath": "/var/lib/stateport/imports",
            "mountPath": "/imports",
            "purpose": "template-sources",
            "sourceOwner": "installer-client",
            "sourceGroup": "stateport-execution-control",
            "mode": "ro",
            "environmentVariable": "STATEPORT_REPOSITORY_ROOTS",
        }
    ]
    _refresh_index_topology(value)
    verified = verify_release_index(value, policy=_policy(), verifier=_EphemeralTestVerifier())
    files = render_quadlet_bundle(verified.target, verified.index.document["signed"]["images"])
    web_units = [
        content
        for path, content in files.items()
        if "stateport-web" in Path(path).name and path.endswith(".container.in")
    ]
    assert web_units
    assert all(b"Volume=/var/lib/stateport/imports:/imports:ro" in unit for unit in web_units)
    assert all(b"Environment=STATEPORT_REPOSITORY_ROOTS=/imports" in unit for unit in web_units)
    assert all(b"PodmanArgs=--runtime=/usr/libexec/stateport/crun" in unit for unit in web_units)
    assert all(b"Volume=/var/lib/stateport/imports:/imports:rw" not in unit for unit in web_units)


def test_provider_home_is_persistent_only_in_accepted_profile_and_outside_data_volumes() -> None:
    from stateport_release.contract import PROVIDER_HOME_CONTRACT

    value = _stable_execution_index()
    service = value["signed"]["targets"][0]["services"][0]
    volumes_before = deepcopy(service["writableVolumes"])
    service["providerHome"] = dict(PROVIDER_HOME_CONTRACT)
    _refresh_index_topology(value)
    verified = verify_release_index(value, policy=_policy(), verifier=_EphemeralTestVerifier())
    files = render_quadlet_bundle(verified.target, verified.index.document["signed"]["images"])
    host_path = PROVIDER_HOME_CONTRACT["hostPath"].encode()
    for path, content in files.items():
        if "stateport-web" not in Path(path).name or not path.endswith(".container.in"):
            assert host_path not in content
            continue
        assert b"Environment=CODEX_HOME=/var/lib/stateport-provider/codex" in content
        assert b"UserNS=keep-id:uid=65532,gid=65532" in content
        if "-accepted-" in path:
            assert b"Volume=" + host_path + b":/var/lib/stateport-provider/codex:rw\n" in content
            provider_mounts = [line for line in content.decode().splitlines()
                               if line.startswith(("Volume=", "Tmpfs=")) and "stateport-provider/codex" in line]
            assert provider_mounts == ["Volume=" + host_path.decode() + ":/var/lib/stateport-provider/codex:rw"]
        else:
            assert host_path not in content
            provider_mounts = [line for line in content.decode().splitlines()
                               if line.startswith(("Volume=", "Tmpfs=")) and "stateport-provider/codex" in line]
            assert provider_mounts == [
                "Tmpfs=/var/lib/stateport-provider/codex:rw,noexec,nosuid,nodev,notmpcopyup,mode=0700,size=67108864,U"
            ]
            # This exact option set passed a real rootless Podman6.1 image
            # smoke with UID/GID 65532 and mode 0700 assertions. U sets mount
            # ownership; accepted host credential storage must never use U.
            options = provider_mounts[0].split(":", 1)[1].split(",")
            assert not any(option.startswith(("uid=", "gid=")) for option in options)
            assert "tmpcopyup" not in options
    # The existing snapshot/export generation exclusively consumes these data
    # volumes. Provider storage adds no volume or validation snapshot binding.
    assert service["writableVolumes"] == volumes_before
    assert not any(volume["mountPath"].startswith("/var/lib/stateport-provider") for volume in volumes_before)
    pipeline = _revision_pipeline(value)
    for document in (pipeline["validationBackup"], pipeline["promotionSpec"], pipeline["promotion"]):
        assert "provider-auth" not in json.dumps(document)
        assert "stateport-provider" not in json.dumps(document)
        assert len(document.get("volumeBindings", document.get("requiredVolumeKeys"))) == len(volumes_before)


def test_provider_home_cannot_be_attached_to_another_service() -> None:
    from stateport_release.contract import PROVIDER_HOME_CONTRACT

    document = _stable_execution_index()
    service = document["signed"]["targets"][0]["services"][0]
    service["providerHome"] = dict(PROVIDER_HOME_CONTRACT)
    service["serviceId"] = "stateport-other"
    _refresh_index_topology(document)
    with pytest.raises(ReleaseContractError, match="unauthorized provider home"):
        verify_release_index(document, policy=_policy(), verifier=_EphemeralTestVerifier())


@pytest.mark.parametrize("field,value", [
    ("hostPath", "/home/operator/.codex"), ("mountPath", "/var/lib/stateport/auth"),
    ("provider", "other"), ("owner", "root"), ("mode", "0755"),
    ("validation", "read-only-snapshot-copy"), ("environmentVariable", "HOME"),
])
def test_provider_home_refuses_contract_widening(field: str, value: str) -> None:
    from stateport_release.contract import PROVIDER_HOME_CONTRACT

    document = _stable_execution_index()
    document["signed"]["targets"][0]["services"][0]["providerHome"] = dict(PROVIDER_HOME_CONTRACT) | {field: value}
    _refresh_index_topology(document)
    with pytest.raises(ReleaseContractError):
        verify_release_index(document, policy=_policy(), verifier=_EphemeralTestVerifier())


def test_same_lane_predecessor_identity_rules() -> None:
    """A shared releaseId is legal only for a strictly older same-lane version.

    The updater compares releaseId AND signedPayloadDigest against the
    installed release, so the qualification lane (one releaseId across
    candidates) must embed predecessors carrying its own releaseId.
    """
    from stateport_release.contract import _validate_same_lane_predecessor_identity

    lane = {"releaseId": "stateport-j1-integrated-qualification-900001"}

    def check(predecessor_version: str, successor_version: str) -> None:
        _validate_same_lane_predecessor_identity(
            {
                "releaseId": lane["releaseId"],
                "version": predecessor_version,
                "signedPayloadDigest": "sha256:" + "3" * 64,
            },
            release={**lane, "version": successor_version},
        )

    check("0.0.0-j1.35", "0.0.0-j1.39")
    with pytest.raises(ReleaseContractError, match="older release than the successor"):
        check("0.0.0-j1.40", "0.0.0-j1.39")
    with pytest.raises(ReleaseContractError, match="older release than the successor"):
        check("0.0.0-j1.39", "0.0.0-j1.39")

    other_lane = {
        "releaseId": "stateport-alpha-0.2.0",
        "version": "9.9.9",
        "signedPayloadDigest": "sha256:" + "4" * 64,
    }
    _validate_same_lane_predecessor_identity(
        other_lane, release={**lane, "version": "0.0.1"}
    )


def test_signed_qualification_event_rejects_reordered_or_duplicate_images() -> None:
    predecessor = release_index()
    successor = _successor_index(predecessor)
    event = successor["signed"]["successor"]["qualificationEvent"]
    event["images"] = list(reversed(event["images"]))
    event["eventId"] = canonical_digest(
        {key: value for key, value in event.items() if key != "eventId"}
    )
    successor["signatures"] = []
    with pytest.raises(ReleaseContractError, match="not canonicalized"):
        validate_release_index(successor, require_signatures=False)


@pytest.mark.parametrize(
    ("policy", "message"),
    [
        (_policy(expected_channel="stable"), "channel"),
        (_policy(expected_target="linux-arm64-rootless-podman-quadlet"), "target"),
        (_policy(updater_version="0.0.9"), "older"),
        (_policy(now=datetime(2026, 9, 1, tzinfo=timezone.utc)), "expired"),
        (_policy(allow_candidate=False), "candidate"),
        (_policy(accepted_signers=frozenset()), "certificate identities"),
    ],
)
def test_policy_refuses_mismatched_release(policy: ReleaseVerificationPolicy, message: str) -> None:
    with pytest.raises(ReleaseContractError, match=message):
        verify_release_index(release_index(), policy=policy, verifier=_EphemeralTestVerifier())


def test_verification_refuses_stale_scan_and_future_publication() -> None:
    stale = release_index()
    scan = stale["signed"]["images"][0]["scan"]
    scan["databaseBuiltAt"] = "2026-07-29T08:00:00Z"
    scan["scannedAt"] = "2026-07-29T09:00:00Z"
    stale["signatures"][0]["subjectDigest"] = canonical_digest(stale["signed"])
    with pytest.raises(ReleaseContractError, match="stale at verification time"):
        verify_release_index(stale, policy=_policy(), verifier=_EphemeralTestVerifier())

    future = release_index()
    future["signed"]["release"]["qualification"] = "published"
    future["signed"]["publication"]["publishedAt"] = "2026-08-02T10:00:00Z"
    future["signed"]["publication"]["expiresAt"] = "2026-09-01T00:00:00Z"
    future["signatures"][0]["transparencyLog"] = "required-public-release"
    for image in future["signed"]["images"]:
        image["signature"]["transparencyLog"] = "required-public-release"
    future["signatures"][0]["subjectDigest"] = canonical_digest(future["signed"])
    with pytest.raises(ReleaseContractError, match="future"):
        verify_release_index(
            future,
            policy=_policy(allow_candidate=False),
            verifier=_EphemeralTestVerifier(),
        )


def test_marked_successor_uses_qualification_and_signing_time_freshness() -> None:
    predecessor = release_index()
    successor = _successor_index(predecessor)
    successor["signed"]["successor"]["freshnessEnforcement"] = (
        "qualification-and-signing-time"
    )
    successor["signatures"][0]["subjectDigest"] = canonical_digest(successor["signed"])
    verified = verify_release_index(
        successor,
        policy=_policy(now=datetime(2026, 8, 2, 10, tzinfo=timezone.utc)),
        verifier=_EphemeralTestVerifier(),
        predecessor=predecessor,
    )
    assert verified.index.release_id == successor["signed"]["release"]["releaseId"]


def test_unmarked_successor_retains_legacy_verification_time_freshness() -> None:
    predecessor = release_index()
    successor = _successor_index(predecessor)
    with pytest.raises(ReleaseContractError, match="stale at verification time"):
        verify_release_index(
            successor,
            policy=_policy(now=datetime(2026, 8, 2, 10, tzinfo=timezone.utc)),
            verifier=_EphemeralTestVerifier(),
            predecessor=predecessor,
        )


def test_marked_successor_still_refuses_future_scan_evidence() -> None:
    predecessor = release_index()
    successor = _successor_index(predecessor)
    successor["signed"]["successor"]["freshnessEnforcement"] = (
        "qualification-and-signing-time"
    )
    successor["signatures"][0]["subjectDigest"] = canonical_digest(successor["signed"])
    with pytest.raises(ReleaseContractError, match="from the future"):
        verify_release_index(
            successor,
            policy=_policy(now=datetime(2026, 7, 31, tzinfo=timezone.utc)),
            verifier=_EphemeralTestVerifier(),
            predecessor=predecessor,
        )


def test_transparency_log_policy_is_explicit_and_private_candidate_is_not_uploaded() -> None:
    value = release_index()
    assert value["signatures"][0]["transparencyLog"] == "not-uploaded-private-candidate"
    with pytest.raises(ReleaseContractError, match="transparency-log proof"):
        verify_release_index(
            value,
            policy=_policy(require_transparency_log=True),
            verifier=_EphemeralTestVerifier(),
        )


def test_private_candidate_verifies_with_exact_pinned_public_key_identity() -> None:
    value = release_index()
    value["signed"]["signaturePolicy"]["trustMode"] = "pinned-public-key"
    for image in value["signed"]["images"]:
        image["signature"] = _pinned_key_signature(DIGEST, image["imageId"])
    value["signatures"] = [
        _pinned_key_signature(canonical_digest(value["signed"]), "release-index")
    ]
    policy = _policy(
        expected_trust_mode="pinned-public-key",
        accepted_signers=frozenset(),
        accepted_public_keys=frozenset({PINNED_KEY}),
    )
    verified = verify_release_index(value, policy=policy, verifier=_EphemeralTestVerifier())
    assert verified.verified_signers == (PINNED_KEY,)

    with pytest.raises(ReleaseContractError, match="untrusted signer"):
        verify_release_index(
            value,
            policy=_policy(
                accepted_signers=frozenset(),
                expected_trust_mode="pinned-public-key",
                accepted_public_keys=frozenset(
                    {PinnedPublicKeyIdentity(f"sha256:{'8' * 64}", PINNED_KEY.key_id)}
                ),
            ),
            verifier=_EphemeralTestVerifier(),
        )
    with pytest.raises(ReleaseContractError, match="public-key identities"):
        verify_release_index(
            value,
            policy=_policy(
                expected_trust_mode="pinned-public-key",
                accepted_signers=frozenset(),
                accepted_public_keys=frozenset(),
            ),
            verifier=_EphemeralTestVerifier(),
        )


def test_signature_trust_modes_cannot_be_mixed_or_mislabeled() -> None:
    mixed = release_index()
    mixed_signature = _pinned_key_signature(canonical_digest(mixed["signed"]), "release-index")
    mixed_signature["certificateIdentity"] = SIGNER.certificate_identity
    mixed_signature["certificateOidcIssuer"] = SIGNER.oidc_issuer
    mixed["signatures"] = [mixed_signature]
    with pytest.raises(ReleaseContractError, match="mixes pinned-public-key and keyless trust"):
        validate_release_index(mixed)

    public_log = release_index()
    signature = _pinned_key_signature(canonical_digest(public_log["signed"]), "release-index")
    signature["transparencyLog"] = "required-public-release"
    public_log["signatures"] = [signature]
    with pytest.raises(ReleaseContractError, match="schema validation|transparency-log"):
        validate_release_index(public_log)

    mixed_image = release_index()
    mixed_image["signed"]["images"][0]["signature"] = _pinned_key_signature(DIGEST, "web")
    mixed_image["signatures"][0]["subjectDigest"] = canonical_digest(mixed_image["signed"])
    with pytest.raises(ReleaseContractError, match="homogeneous trust mode"):
        validate_release_index(mixed_image)


def test_typed_signature_proof_must_bind_subject_bundle_identity_and_time() -> None:
    class WrongImageProof(_EphemeralTestVerifier):
        def verify_image(
            self, reference: str, signature: dict[str, object]
        ) -> SignatureVerificationProof:
            proof = super().verify_image(reference, signature)
            return SignatureVerificationProof(
                subject_digest=f"sha256:{'0' * 64}",
                bundle_digest=proof.bundle_digest,
                trust_mode=proof.trust_mode,
                identity_primary=proof.identity_primary,
                identity_secondary=proof.identity_secondary,
                verified_at=proof.verified_at,
                transparency_log_mode=proof.transparency_log_mode,
            )

    with pytest.raises(ReleaseContractError, match="does not bind subject_digest"):
        verify_release_index(release_index(), policy=_policy(), verifier=WrongImageProof())

    class UntypedProof(_EphemeralTestVerifier):
        def verify_blob(self, payload: bytes, signature: dict[str, object]) -> object:
            return None

    with pytest.raises(ReleaseContractError, match="no typed proof"):
        verify_release_index(release_index(), policy=_policy(), verifier=UntypedProof())


def test_tamper_and_topology_drift_fail_before_verifier() -> None:
    tampered = release_index()
    tampered["signed"]["release"]["version"] = "0.2.1"
    with pytest.raises(ReleaseContractError, match="canonical signed payload"):
        validate_release_index(tampered)

    unused = release_index()
    extra = deepcopy(unused["signed"]["images"][0])
    extra["imageId"] = "stateport-worker"
    extra["reference"] = f"ghcr.io/stateport/stateport-worker@{DIGEST}"
    unused["signed"]["images"].append(extra)
    unused["signatures"][0]["subjectDigest"] = canonical_digest(unused["signed"])
    with pytest.raises(ReleaseContractError, match="installed services"):
        validate_release_index(unused)

    git_mount = release_index()
    git_mount["signed"]["targets"][0]["services"][0]["writableVolumes"][0]["mountPath"] = (
        "/workspace/.git"
    )
    git_mount["signed"]["targets"][0]["topologyDigest"] = topology_digest(
        git_mount["signed"]["targets"][0]
    )
    git_mount["signatures"][0]["subjectDigest"] = canonical_digest(git_mount["signed"])
    with pytest.raises(ReleaseContractError, match="Git metadata"):
        validate_release_index(git_mount)

    topology = release_index()
    topology["signed"]["targets"][0]["services"][0]["serviceId"] = "stateport-api"
    topology["signatures"][0]["subjectDigest"] = canonical_digest(topology["signed"])
    with pytest.raises(ReleaseContractError, match="topology digest"):
        validate_release_index(topology)

    socket_grant = release_index()
    service = socket_grant["signed"]["targets"][0]["services"][0]
    service["capabilities"]["podmanSocketAccess"] = "owned-execution-user"
    socket_grant["signed"]["targets"][0]["topologyDigest"] = topology_digest(
        socket_grant["signed"]["targets"][0]
    )
    socket_grant["signatures"][0]["subjectDigest"] = canonical_digest(socket_grant["signed"])
    with pytest.raises(ReleaseContractError, match="unauthorized Podman"):
        validate_release_index(socket_grant)

    missing_probe = release_index()
    missing_probe["signed"]["images"][0]["healthProbe"]["packageInventoryDigest"] = (
        f"sha256:{'0' * 64}"
    )
    missing_probe["signatures"][0]["subjectDigest"] = canonical_digest(missing_probe["signed"])
    with pytest.raises(ReleaseContractError, match="health probe.*package inventory"):
        validate_release_index(missing_probe)


def _shared_operations_index() -> dict[str, object]:
    value = release_index()
    signed = value["signed"]
    target = signed["targets"][0]
    web = target["services"][0]
    api = deepcopy(web)
    api.update({"serviceId": "stateport-api", "imageId": "stateport-api"})
    api["writableVolumes"][0].update(
        {"name": "stateport-operations", "mountPath": "/workspace/.stateport"}
    )
    worker = deepcopy(api)
    worker.update({"serviceId": "stateport-worker", "imageId": "stateport-worker"})
    target["services"].extend([api, worker])
    target["sharedWritableVolumes"] = [
        {
            "volumeKey": "stateport-shared:stateport-operations",
            "volumeName": "stateport-operations",
            "members": ["stateport-api", "stateport-worker"],
            "writerCoordination": "sqlite-immediate-and-posix-advisory-locks",
        }
    ]
    for image_id in ("stateport-api", "stateport-worker"):
        image = deepcopy(signed["images"][0])
        image.update(
            {"imageId": image_id, "reference": f"ghcr.io/stateport/{image_id}@{DIGEST}"}
        )
        signed["images"].append(image)
    _refresh_index_topology(value)
    return value


def test_shared_writable_volume_binds_one_key_and_exact_members() -> None:
    value = _shared_operations_index()
    verified = verify_release_index(value, policy=_policy(), verifier=_EphemeralTestVerifier())
    files = render_quadlet_bundle(verified.target, verified.index.document["signed"]["images"])
    shared_token = b"@@STATEPORT_ACCEPTED_DATA_VOLUME:stateport-shared:stateport-operations@@"
    units = [content for path, content in files.items() if path.endswith(".container.in")]
    assert sum(shared_token in content for content in units) == 2

    missing_member = _shared_operations_index()
    missing_member["signed"]["targets"][0]["sharedWritableVolumes"][0]["members"] = [
        "stateport-api",
        "stateport-web",
    ]
    _refresh_index_topology(missing_member)
    with pytest.raises(ReleaseContractError, match="exact service members"):
        validate_release_index(missing_member)

    metadata_drift = _shared_operations_index()
    metadata_drift["signed"]["targets"][0]["services"][-1]["writableVolumes"][0][
        "mountPath"
    ] = "/workspace/.stateport-worker"
    _refresh_index_topology(metadata_drift)
    with pytest.raises(ReleaseContractError, match="inconsistent attachment metadata"):
        validate_release_index(metadata_drift)


def test_zero_padded_numeric_semver_prerelease_is_rejected() -> None:
    value = release_index()
    value["signed"]["release"]["version"] = "0.2.0-rc.01"
    value["signatures"][0]["subjectDigest"] = canonical_digest(value["signed"])
    with pytest.raises(ReleaseContractError, match="zero-padded"):
        validate_release_index(value)


def test_unsigned_candidate_is_assembly_only() -> None:
    value = release_index()
    value["signatures"] = []
    prepared = validate_release_index(value, require_signatures=False)
    assert prepared.version == "0.2.0-rc.1"
    with pytest.raises(ReleaseContractError, match="no detached"):
        validate_release_index(value)


def test_safe_file_loader_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "index.json"
    target.write_text(json.dumps(release_index()), encoding="utf-8")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    assert load_release_index_file(target).version == "0.2.0-rc.1"
    with pytest.raises(ReleaseContractError, match="opened safely"):
        load_release_index_file(link)


def test_verified_release_and_updater_envelope_are_deeply_immutable() -> None:
    verified = verify_release_index(
        release_index(), policy=_policy(), verifier=_EphemeralTestVerifier()
    )
    with pytest.raises(TypeError):
        verified.index.document["signed"]["targets"][0]["services"][0]["serviceId"] = "tampered"
    with pytest.raises(TypeError):
        verified.target["services"][0]["capabilities"]["podmanSocketAccess"] = (
            "owned-execution-user"
        )
    envelope = to_updater_release_envelope(verified)
    with pytest.raises(TypeError):
        envelope.document["target"]["services"][0]["serviceId"] = "tampered"
    reverified = reverify_updater_release_envelope(
        envelope, policy=_policy(), verifier=_EphemeralTestVerifier()
    )
    assert reverified.index.signed_digest == verified.index.signed_digest
    persisted = json.loads(envelope.canonical_index_bytes)
    persisted["signed"]["targets"][0]["services"][0]["serviceId"] = "tampered"
    with pytest.raises(ReleaseContractError, match="schema validation|canonical signed payload"):
        load_release_index(json.dumps(persisted))


def test_successor_updater_envelope_reverification_carries_predecessor() -> None:
    predecessor = release_index()
    successor = _successor_index(predecessor)
    verifier = _EphemeralTestVerifier()
    verified = verify_release_index(
        successor,
        policy=_policy(),
        verifier=verifier,
        predecessor=predecessor,
    )
    envelope = to_updater_release_envelope(verified)
    context = envelope.document["authenticatedPredecessor"]
    assert context["signedPayloadDigest"] == canonical_digest(predecessor["signed"])
    reverified = reverify_updater_release_envelope(
        envelope, policy=_policy(), verifier=_EphemeralTestVerifier()
    )
    assert reverified.authenticated_predecessor is not None
    assert reverified.authenticated_predecessor.index.signed_digest == context[
        "signedPayloadDigest"
    ]


def test_quadlet_templates_stage_profiles_and_terminal_activation_only() -> None:
    pipeline = _revision_pipeline()
    verified = pipeline["verified"]
    signed = verified.index.document["signed"]
    templates = render_quadlet_bundle(verified.target, signed["images"])
    assert verify_quadlet_bundle(templates, verified) == verified.target["quadletBundleDigest"]
    assert any(name.endswith(".container.in") for name in templates)
    assert all(
        b"[Install]" not in content and b"WantedBy=" not in content
        for content in templates.values()
    )

    staged = pipeline["staged"]
    assert all(path.startswith("staged/") for path in staged)
    staged_containers = [content for path, content in staged.items() if ".container" in path]
    assert any(
        b"stateport-validation-snapshot-d0:/var/lib/stateport:ro" in content
        for content in staged_containers
    )
    assert any(b"@@STATEPORT_ACCEPTED_DATA_VOLUME:" in content for content in staged_containers)
    assert all(
        b"Pull=never" in content and b"RunInit=true" in content for content in staged_containers
    )
    assert all(
        b"LogDriver=k8s-file" in content
        and b"PodmanArgs=--log-opt=max-size=10485760" in content
        and re.search(rb'HealthCmd="[^"]*stateport-healthcheck --kind http --host 127\.0\.0\.1 --port \d+ --path /[^"]*"', content)
        and b"/usr/bin/curl" not in content
        for content in staged_containers
    )
    assert all(b"[Install]" not in content for content in staged.values())
    staged_manifest = _embedded(staged, "/materialization.json")
    assert all(len(revision) == 64 for revision in staged_manifest["revisions"].values())
    assert (
        staged_manifest["revisions"]["stateport-web:validation"]
        != staged_manifest["revisions"]["stateport-web:accepted"]
    )

    accepted = pipeline["accepted"]
    accepted_containers = [
        content for path, content in accepted.items() if path.endswith(".container")
    ]
    assert accepted_containers
    assert all(
        b"stateport-data-d1:/var/lib/stateport:rw" in content for content in accepted_containers
    )
    assert all(
        b"stateport-validation-snapshot-d0" not in content for content in accepted_containers
    )
    assert all(
        b"[Install]" not in content and b"WantedBy=" not in content for content in accepted.values()
    )
    owner_bundle = _embedded(accepted, "/owner-bundles/stateport-control.json")
    assert owner_bundle["owner"] == "stateport-control"
    assert owner_bundle["rootIdentity"] == "xdg-config-containers-systemd"
    assert owner_bundle["crossUserAtomic"] is False

    activation = pipeline["activation"]
    assert set(activation) >= {
        "activation/stateport-accepted.target",
        "activation/stateport-accepted.target.d/10-stateport-activation.conf",
        "activation/stateport-accepted.current.json",
    }
    assert b"[Install]" in activation["activation/stateport-accepted.target"]
    assert b"WantedBy=default.target" in activation["activation/stateport-accepted.target"]
    assert (
        b"[Install]"
        not in activation["activation/stateport-accepted.target.d/10-stateport-activation.conf"]
    )
    pointer = _embedded(activation, "stateport-accepted.current.json")
    assert pointer["state"] == "accepted"
    assert pointer["terminalAcceptanceReceiptDigest"] == pipeline["terminal"]["receiptDigest"]
    assert "validation" not in canonical_json_bytes(pointer).decode()
    write_plan = _embedded(activation, "activation-write-plan.json")
    assert write_plan["preTerminalOrder"][-1] == "explicit-start-observe-stop"
    assert write_plan["terminalOrder"][-1] == "fsync-terminal-acceptance-receipt"
    assert write_plan["postTerminalOrder"] == [
        "compare-and-swap-pointer",
        "switch-ingress-and-unfence",
    ]
    assert write_plan["terminalAcceptanceReceiptDigest"] == pipeline["terminal"]["receiptDigest"]
    assert (
        write_plan["portActivationRecheckReceiptDigest"] == pipeline["portRecheck"]["receiptDigest"]
    )
    assert write_plan["crashRecovery"].startswith("structural-effect-reconciliation-only")

    tampered = dict(templates)
    container_path = next(path for path in templates if path.endswith(".container.in"))
    tampered[container_path] += b"# tamper\n"
    with pytest.raises(ReleaseContractError, match="do not match"):
        verify_quadlet_bundle(tampered, verified)
    with pytest.raises(ReleaseContractError, match="unsafe"):
        quadlet_bundle_digest({"../stateport-web.container": b"unsafe"})


def test_staged_units_bind_external_loopback_port_for_host_validation() -> None:
    """Every published unit must name its signed host port for the service.

    The persistent-app loopback guard (``_valid_request_host``) only accepts a
    Host authority naming the bound container port or the configured external
    loopback port.  Without ``STATEPORT_EXTERNAL_LOOPBACK_PORT`` resolved to
    the signed host port, install-time health probes and operator browsers
    are refused with 421 and installation fails closed with health_timeout
    (dogfood defect at ca87812).
    """

    pipeline = _revision_pipeline()
    for bundle_key in ("staged", "accepted"):
        containers = [
            content for path, content in pipeline[bundle_key].items() if ".container" in path
        ]
        assert containers
        for content in containers:
            lines = content.split(b"\n")
            published = [line for line in lines if line.startswith(b"PublishPort=127.0.0.1:")]
            env = [
                line
                for line in lines
                if line.startswith(b"Environment=STATEPORT_EXTERNAL_LOOPBACK_PORT=")
            ]
            if not published:
                assert not env
                continue
            assert len(env) == 1, content
            external_port = env[0].rsplit(b"=", 1)[1]
            assert external_port.isdigit(), env[0]
            health = re.search(rb'--kind http --host 127\.0\.0\.1 --port (\d+)', content)
            assert health is not None, content
            assert (b"PublishPort=127.0.0.1:" + external_port + b":" + health.group(1)) in lines, (
                content
            )


def test_unsigned_staged_quadlet_mutation_addition_and_removal_are_refused() -> None:
    pipeline = _revision_pipeline()
    container_path = next(path for path in pipeline["staged"] if path.endswith(".container.in"))
    mutated = dict(pipeline["staged"])
    mutated[container_path] += (
        b"Volume=%t/podman:/run/stateport-engine:rw\n"
    )
    with pytest.raises(ReleaseContractError, match="staged materialization byte drift"):
        owner_materialization_spec_digest(
            pipeline["verified"],
            mutated,
            expected_accepted_data_generation=DATA_D1,
        )

    added = dict(pipeline["staged"])
    staged_root = container_path.rsplit("/", 1)[0]
    added[f"{staged_root}/unsigned-extra.container"] = b"[Container]\nImage=evil\n"
    with pytest.raises(ReleaseContractError, match="missing or additional paths"):
        owner_materialization_spec_digest(
            pipeline["verified"], added, expected_accepted_data_generation=DATA_D1
        )

    missing = dict(pipeline["staged"])
    del missing[container_path]
    with pytest.raises(ReleaseContractError, match="missing or additional paths"):
        owner_materialization_spec_digest(
            pipeline["verified"], missing, expected_accepted_data_generation=DATA_D1
        )


def test_operation_plan_substitution_is_refused_after_approval() -> None:
    pipeline = _revision_pipeline()
    substituted = deepcopy(pipeline["plan"])
    substituted["operationPlanDigest"] = f"sha256:{'0' * 64}"
    substituted["planDigest"] = revision_contract_digest(
        substituted, digest_field="planDigest", id_field="planId"
    )
    substituted["planId"] = f"revision_activation_plan_{substituted['planDigest'][7:39]}"
    validate_revision_contract(substituted)
    with pytest.raises(ReleaseContractError, match="another release"):
        reserve_revision_port_allocation(
            pipeline["verified"],
            pipeline["staged"],
            activation_plan=substituted,
            reservation_receipt_digest=DIGEST,
            recheck_inventory_digest=DIGEST,
            rechecked_occupied_port_inputs=[],
            allocated_at="2026-08-01T09:33:00Z",
            reservation_expires_at="2026-08-01T10:03:00Z",
        )


def test_forged_authority_projection_and_noncanonical_store_chain_are_refused() -> None:
    pipeline = _revision_pipeline()
    forged_documents = deepcopy(pipeline["authorityDocuments"])
    decision = forged_documents["reservation"]["decision"]
    decision["actorId"] = "forged-updater"
    decision_body = {key: value for key, value in decision.items() if key != "decisionDigest"}
    decision["decisionDigest"] = _authority_digest(decision_body)
    reservation = forged_documents["reservation"]
    reservation_body = {
        key: value for key, value in reservation.items() if key != "reservationDigest"
    }
    reservation["reservationDigest"] = _authority_digest(reservation_body)
    claim = forged_documents["claim"]
    claim["reservationDigest"] = reservation["reservationDigest"]
    claim["decisionDigest"] = decision["decisionDigest"]
    claim_body = {key: value for key, value in claim.items() if key != "claimDigest"}
    claim["claimDigest"] = _authority_digest(claim_body)
    receipt = forged_documents["receipt"]
    receipt["actorId"] = "forged-updater"
    receipt["decisionDigest"] = decision["decisionDigest"]
    receipt["reservation"]["reservationDigest"] = reservation["reservationDigest"]
    receipt["claim"]["claimDigest"] = claim["claimDigest"]
    receipt_body = {key: value for key, value in receipt.items() if key != "receiptDigest"}
    receipt["receiptDigest"] = _authority_digest(receipt_body)

    with pytest.raises(ReleaseContractError, match="protected canonical authority store"):
        derive_revision_authority_proofs(
            forged_documents,
            resolver=pipeline["authorityResolver"],
            operation_plan_digest=DIGEST,
            release_id=pipeline["verified"].index.release_id,
            signed_payload_digest=pipeline["verified"].index.signed_digest,
            target_id=pipeline["verified"].target["targetId"],
            topology_digest_value=pipeline["verified"].target["topologyDigest"],
        )

    forged_decision = deepcopy(pipeline["decision"])
    forged_proof = forged_decision["authorityClaimProof"]
    forged_proof["actorId"] = "forged-updater"
    forged_proof["proofDigest"] = revision_contract_digest(forged_proof, digest_field="proofDigest")
    forged_decision["decisionDigest"] = revision_contract_digest(
        forged_decision, digest_field="decisionDigest", id_field="decisionId"
    )
    forged_decision["decisionId"] = (
        f"revision_activation_decision_{forged_decision['decisionDigest'][7:39]}"
    )
    forged_terminal = deepcopy(pipeline["terminal"])
    forged_terminal["activationDecisionDigest"] = forged_decision["decisionDigest"]
    forged_terminal["receiptDigest"] = revision_contract_digest(
        forged_terminal, digest_field="receiptDigest"
    )
    with pytest.raises(ReleaseContractError, match="authority.*chain|canonical source"):
        render_accepted_activation(
            pipeline["verified"],
            pipeline["accepted"],
            activation_plan=pipeline["plan"],
            activation_decision=forged_decision,
            terminal_acceptance_receipt=forged_terminal,
            data_promotion_receipt=pipeline["promotion"],
            port_allocation_receipt=pipeline["portReceipt"],
            port_activation_recheck_receipt=pipeline["portRecheck"],
            authority_source_documents=pipeline["authorityDocuments"],
            authority_source_resolver=pipeline["authorityResolver"],
            current_pointer=None,
            route_projection_digest=ROUTE_DIGEST,
            written_at="2026-08-01T09:40:25Z",
        )


def test_expired_port_reservation_and_activation_collision_are_refused() -> None:
    pipeline = _revision_pipeline()
    allocated_port = pipeline["portReceipt"]["allocations"][0]["port"]
    with pytest.raises(ReleaseContractError, match="live collision"):
        record_revision_port_activation_recheck(
            pipeline["verified"],
            activation_plan=pipeline["plan"],
            port_allocation_receipt=pipeline["portReceipt"],
            observed_occupied_port_inputs=[
                {
                    "class": "observed-host",
                    "port": allocated_port,
                    "identityDigest": DIGEST,
                }
            ],
            host_observation_receipt_digest=DIGEST,
            checked_at="2026-08-01T09:40:10Z",
            valid_until="2026-08-01T09:40:40Z",
        )
    with pytest.raises(ReleaseContractError, match="unexpired immediate pre-effect"):
        render_accepted_activation(
            pipeline["verified"],
            pipeline["accepted"],
            activation_plan=pipeline["plan"],
            activation_decision=pipeline["decision"],
            terminal_acceptance_receipt=pipeline["terminal"],
            data_promotion_receipt=pipeline["promotion"],
            port_allocation_receipt=pipeline["portReceipt"],
            port_activation_recheck_receipt=pipeline["portRecheck"],
            authority_source_documents=pipeline["authorityDocuments"],
            authority_source_resolver=pipeline["authorityResolver"],
            current_pointer=None,
            route_projection_digest=ROUTE_DIGEST,
            written_at="2026-08-01T10:04:00Z",
        )


def _stable_execution_index(*, bootstrap_only: bool = False) -> dict[str, object]:
    value = release_index()
    if bootstrap_only:
        signed = value["signed"]
        target = signed["targets"][0]
        target["executionHostMode"] = "stable-host-daemon-bootstrap-only"
        target["releaseEligibility"] = "bootstrap-only"
        _refresh_index_topology(value)
    return value


def _refresh_index_topology(value: dict[str, object]) -> None:
    signed = value["signed"]
    target = signed["targets"][0]
    target["topologyDigest"] = topology_digest(target)
    target["quadletBundleDigest"] = quadlet_bundle_digest(
        render_quadlet_bundle(target, signed["images"])
    )
    value["signatures"][0]["subjectDigest"] = canonical_digest(signed)


def test_stable_execution_host_has_separate_operational_lifecycle_and_normal_client() -> None:
    value = _stable_execution_index()
    verified = verify_release_index(value, policy=_policy(), verifier=_EphemeralTestVerifier())
    files = render_quadlet_bundle(verified.target, verified.index.document["signed"]["images"])
    assert "host/execution-contract.json" not in files
    assert not any("host/stateport-exec/" in path for path in files)
    assert any(
        b"/run/stateport/execution-control:/run/stateport-execution:ro" in content
        for content in files.values()
    )
    client_units = [
        content
        for content in files.values()
        if b"STATEPORT_EXECUTION_SOCKET=" in content
    ]
    assert client_units
    assert all(b"PodmanArgs=--group-add=keep-groups" in content for content in client_units)
    assert all(
        b"PodmanArgs=--runtime=/usr/libexec/stateport/crun" in content
        for content in client_units
    )
    assert all(b"GroupAdd=" not in content for content in client_units)
    stable_files = render_stable_host_quadlet_bundle(
        verified.target, verified.index.document["signed"]["images"]
    )
    assert verify_stable_host_quadlet_bundle(stable_files, verified) == quadlet_bundle_digest(
        stable_files
    )
    host_unit = stable_files["host/stateport-exec/stateport-execution-host.container"]
    assert b"UserNS=keep-id:uid=65532,gid=65532" in host_unit
    assert b"PodmanArgs=--group-add=keep-groups" in host_unit
    assert b"PodmanArgs=--runtime=/usr/libexec/stateport/crun" in host_unit
    assert b"GroupAdd=" not in host_unit
    assert b"Volume=%t/podman:/run/stateport-engine:rw" in host_unit
    assert b"Environment=STATEPORT_ENGINE_SOCKET=/run/stateport-engine/podman.sock" in host_unit
    assert b"After=podman.socket" in host_unit
    # Sibling-class guard: no rendered unit bind-mounts a socket FILE
    # (podman.socket recreates the inode on restart).
    assert not [line for line in host_unit.splitlines() if line.startswith(b"Volume=") and b".sock" in line]
    assert b"127.0.0.1:17001:9911" in host_unit
    assert b"0.0.0.0" not in host_unit
    assert b"MemoryMax=536870912" in host_unit
    assert b"CPUQuota=100%" in host_unit
    assert b"TasksMax=256" in host_unit
    assert b"LogDriver=k8s-file" in host_unit
    assert b"PodmanArgs=--log-opt=max-size=10485760" in host_unit
    assert re.search(
        rb'HealthCmd="[^"]*stateport-healthcheck --kind unix-socket --path /[^"]*"', host_unit
    )
    assert b'"--kind", "unix-socket"' not in host_unit
    assert b"STATEPORT_EXECUTION_HOST_SOCKET_DIRECTORY_MODE=2750" in host_unit
    assert b"STATEPORT_EXECUTION_HOST_GRANTS_DIR=/var/lib/stateport/execution-host/grants" in host_unit
    assert b"/var/lib/stateport/execution-host/state/grants" not in host_unit
    assert b"WantedBy=default.target" in host_unit

    create = plan_stable_host_service_transition(
        verified,
        observed_services=[],
        host_identity_digest=DIGEST,
        port_reservation_receipt_digest=DIGEST,
    )
    assert create["actions"][0]["action"] == "create"
    desired = json.loads(canonical_json_bytes(verified.target["hostServices"][0]))
    observed = {
        field: deepcopy(desired[field])
        for field in (
            "serviceId",
            "imageId",
            "quadletOwner",
            "engineAccess",
            "socket",
            "ports",
            "writableVolumes",
            "resources",
            "logging",
            "health",
        )
    }
    observed["imageDigest"] = DIGEST
    observed["contractVersion"] = 1
    retain = plan_stable_host_service_transition(
        verified,
        observed_services=[observed],
        host_identity_digest=DIGEST,
        port_reservation_receipt_digest=DIGEST,
    )
    assert retain["actions"][0]["action"] == "retain"
    compatible = deepcopy(observed)
    compatible["imageDigest"] = f"sha256:{'0' * 64}"
    replace = plan_stable_host_service_transition(
        verified,
        observed_services=[compatible],
        host_identity_digest=DIGEST,
        port_reservation_receipt_digest=DIGEST,
    )
    assert replace["actions"][0]["action"] == "replace"

    bootstrap = _stable_execution_index(bootstrap_only=True)
    with pytest.raises(ReleaseContractError, match="bootstrap-only"):
        verify_release_index(bootstrap, policy=_policy(), verifier=_EphemeralTestVerifier())
    bootstrap_verified = verify_release_index(
        bootstrap,
        policy=_policy(allow_bootstrap_target=True),
        verifier=_EphemeralTestVerifier(),
    )
    assert bootstrap_verified.target["releaseEligibility"] == "bootstrap-only"
    bootstrap_revision = render_quadlet_bundle(
        bootstrap_verified.target, bootstrap_verified.index.document["signed"]["images"]
    )
    assert "host/execution-contract.json" in bootstrap_revision
    assert not any(
        path.endswith("stateport-execution-host.container") for path in bootstrap_revision
    )

    legacy_rootless_contract = deepcopy(value)
    legacy_target = legacy_rootless_contract["signed"]["targets"][0]
    legacy_host = legacy_target["hostServices"][0]
    legacy_host["userNamespace"] = "host"
    legacy_host["socket"]["directoryMode"] = "0750"
    legacy_target["executionContract"]["directoryMode"] = "0750"
    _refresh_index_topology(legacy_rootless_contract)
    with pytest.raises(ReleaseContractError, match="requires keep-id"):
        validate_release_index(legacy_rootless_contract)

    unsigned_identity_contract = deepcopy(value)
    unsigned_execution = unsigned_identity_contract["signed"]["targets"][0][
        "executionContract"
    ]
    for field in (
        "socketGroupGid",
        "allowedClientUid",
        "allowedClientGid",
        "runtimeUid",
        "runtimeGid",
    ):
        del unsigned_execution[field]
    _refresh_index_topology(unsigned_identity_contract)
    with pytest.raises(ReleaseContractError, match="explicit signed numeric identities"):
        validate_release_index(unsigned_identity_contract)

    invalid = deepcopy(value)
    server = deepcopy(invalid["signed"]["targets"][0]["services"][0])
    server["serviceId"] = "stateport-execution-host"
    server["trustDomain"] = "execution"
    server["quadletOwner"] = "stateport-exec"
    server["capabilities"]["controlContract"] = "narrow-unix-server"
    invalid["signed"]["targets"][0]["services"].append(server)
    invalid["signed"]["targets"][0]["topologyDigest"] = topology_digest(
        invalid["signed"]["targets"][0]
    )
    invalid["signatures"][0]["subjectDigest"] = canonical_digest(invalid["signed"])
    with pytest.raises(ReleaseContractError, match="stable execution host"):
        validate_release_index(invalid)

    leaked_engine = deepcopy(value)
    stable = leaked_engine["signed"]["targets"][0]["hostServices"][0]
    stable["trustDomain"] = "maintenance"
    stable["quadletOwner"] = "stateport-control"
    stable["writableVolumes"] = []
    leaked_engine["signed"]["targets"][0]["topologyDigest"] = topology_digest(
        leaked_engine["signed"]["targets"][0]
    )
    leaked_engine["signed"]["targets"][0]["quadletBundleDigest"] = quadlet_bundle_digest(
        render_quadlet_bundle(
            leaked_engine["signed"]["targets"][0], leaked_engine["signed"]["images"]
        )
    )
    leaked_engine["signatures"][0]["subjectDigest"] = canonical_digest(leaked_engine["signed"])
    with pytest.raises(ReleaseContractError, match="execution engine authority"):
        validate_release_index(leaked_engine)


def test_stable_host_rejects_public_bind_collision_unbounded_and_unsafe_inputs() -> None:
    collision = _stable_execution_index()
    service = collision["signed"]["targets"][0]["hostServices"][0]
    service["ports"].append(
        {
            "name": "debug",
            "containerPort": 9912,
            "hostPort": 17001,
            "hostScope": "loopback",
            "allocation": "stable-operator-bound",
        }
    )
    _refresh_index_topology(collision)
    with pytest.raises(ReleaseContractError, match="repeats a port name or number"):
        validate_release_index(collision)

    overlap = _stable_execution_index()
    overlap["signed"]["targets"][0]["hostServices"][0]["ports"][0]["hostPort"] = 18001
    _refresh_index_topology(overlap)
    with pytest.raises(ReleaseContractError, match="overlaps revision allocation range"):
        validate_release_index(overlap)

    hostile_health = _stable_execution_index()
    hostile_health["signed"]["targets"][0]["hostServices"][0]["health"] = {
        "kind": "http",
        "value": "http://127.0.0.1:9911/ready;touch-/tmp/pwned",
    }
    _refresh_index_topology(hostile_health)
    with pytest.raises(ReleaseContractError, match="schema validation"):
        validate_release_index(hostile_health)

    unsafe_mount = _stable_execution_index()
    unsafe_mount["signed"]["targets"][0]["hostServices"][0]["writableVolumes"][0]["mountPath"] = (
        "/etc/stateport"
    )
    _refresh_index_topology(unsafe_mount)
    with pytest.raises(ReleaseContractError, match="schema validation"):
        validate_release_index(unsafe_mount)

    unbounded = _stable_execution_index()
    del unbounded["signed"]["targets"][0]["hostServices"][0]["resources"]
    _refresh_index_topology(unbounded)
    with pytest.raises(ReleaseContractError, match="schema validation"):
        validate_release_index(unbounded)


def _stable_volume(value: dict[str, object]) -> dict[str, object]:
    return value["signed"]["targets"][0]["hostServices"][0]["writableVolumes"][0]


def test_stable_host_paths_reject_dotdot_escape_and_noncanonical_spellings() -> None:
    # D1: interior ".." in a stable hostPath escapes containment to /etc.
    etc_escape = _stable_execution_index()
    _stable_volume(etc_escape)["hostPath"] = (
        "/var/lib/stateport-exec/stateport-execution-host/state/../../../../../etc/stateport"
    )
    _refresh_index_topology(etc_escape)
    with pytest.raises(ReleaseContractError, match="schema validation"):
        validate_release_index(etc_escape)

    # D1: interior ".." escaping to /var/evil is rejected the same way.
    var_evil = _stable_execution_index()
    _stable_volume(var_evil)["hostPath"] = (
        "/var/lib/stateport-exec/stateport-execution-host/state/../../../evil"
    )
    _refresh_index_topology(var_evil)
    with pytest.raises(ReleaseContractError, match="schema validation"):
        validate_release_index(var_evil)

    # D1: a canonical path outside the owner root never reaches rendering.
    outside = _stable_execution_index()
    _stable_volume(outside)["hostPath"] = "/var/evil/state"
    _refresh_index_topology(outside)
    with pytest.raises(ReleaseContractError, match="schema validation"):
        validate_release_index(outside)

    # D1: a canonical sibling-service root is caught by component comparison.
    sibling = _stable_execution_index()
    _stable_volume(sibling)["hostPath"] = "/var/lib/stateport-exec/stateport-api/state"
    _refresh_index_topology(sibling)
    with pytest.raises(ReleaseContractError, match="crosses its Linux owner"):
        validate_release_index(sibling)

    # D1: prefix confusion (stateport-execution-host2) stays rejected.
    confused = _stable_execution_index()
    _stable_volume(confused)["hostPath"] = "/var/lib/stateport-exec/stateport-execution-host2/state"
    _refresh_index_topology(confused)
    with pytest.raises(ReleaseContractError, match="crosses its Linux owner"):
        validate_release_index(confused)

    # D2: interior ".." in a stable mountPath escapes the protected root.
    mount_escape = _stable_execution_index()
    _stable_volume(mount_escape)["mountPath"] = "/var/lib/stateport/a/../../../../etc"
    _refresh_index_topology(mount_escape)
    with pytest.raises(ReleaseContractError, match="schema validation"):
        validate_release_index(mount_escape)

    # D2: prefix confusion on the protected mount root stays rejected.
    mount_confused = _stable_execution_index()
    _stable_volume(mount_confused)["mountPath"] = "/var/lib/stateport-evil/execution-host"
    _refresh_index_topology(mount_confused)
    with pytest.raises(ReleaseContractError, match="schema validation"):
        validate_release_index(mount_confused)

    # D3/D5: overlap aliases are rejected as non-canonical before comparison.
    for alias in (
        "/var/lib/stateport-exec/stateport-execution-host/x/../state",
        "/var/lib/stateport-exec/stateport-execution-host/./state",
        "/var/lib/stateport-exec/stateport-execution-host//state",
    ):
        noncanonical = _stable_execution_index()
        _stable_volume(noncanonical)["hostPath"] = alias
        _refresh_index_topology(noncanonical)
        with pytest.raises(ReleaseContractError, match="schema validation"):
            validate_release_index(noncanonical)

    # D5: non-canonical mountPath spellings are rejected as well.
    for alias in (
        "/var/lib/stateport//execution-host",
        "/var/lib/stateport/./execution-host",
    ):
        noncanonical_mount = _stable_execution_index()
        _stable_volume(noncanonical_mount)["mountPath"] = alias
        _refresh_index_topology(noncanonical_mount)
        with pytest.raises(ReleaseContractError, match="schema validation"):
            validate_release_index(noncanonical_mount)

    # Canonical containment still catches a nested writable root overlap.
    nested = _stable_execution_index()
    nested_volume = deepcopy(_stable_volume(nested))
    nested_volume["name"] = "execution-state-nested"
    nested_volume["hostPath"] = "/var/lib/stateport-exec/stateport-execution-host/state/nested"
    nested_volume["mountPath"] = "/var/lib/stateport/execution-host/nested"
    nested["signed"]["targets"][0]["hostServices"][0]["writableVolumes"].append(nested_volume)
    _refresh_index_topology(nested)
    with pytest.raises(ReleaseContractError, match="share overlapping writable roots"):
        validate_release_index(nested)

    # Positive control: the valid stable execution fixture still validates.
    valid = _stable_execution_index()
    verified = verify_release_index(valid, policy=_policy(), verifier=_EphemeralTestVerifier())
    assert verified.index.release_id == valid["signed"]["release"]["releaseId"]


def test_revision_mount_paths_reject_leading_and_interior_dotdot() -> None:
    # D4: leading ".." components escape the revision mount root.
    for escape in ("/..", "/../etc"):
        leading = release_index()
        leading["signed"]["targets"][0]["services"][0]["writableVolumes"][0]["mountPath"] = escape
        leading["signed"]["targets"][0]["topologyDigest"] = topology_digest(
            leading["signed"]["targets"][0]
        )
        leading["signatures"][0]["subjectDigest"] = canonical_digest(leading["signed"])
        with pytest.raises(ReleaseContractError, match="schema validation"):
            validate_release_index(leading)

    # D4: interior ".." sequences remain rejected.
    interior = release_index()
    interior["signed"]["targets"][0]["services"][0]["writableVolumes"][0]["mountPath"] = (
        "/x/../../etc"
    )
    interior["signed"]["targets"][0]["topologyDigest"] = topology_digest(
        interior["signed"]["targets"][0]
    )
    interior["signatures"][0]["subjectDigest"] = canonical_digest(interior["signed"])
    with pytest.raises(ReleaseContractError, match="schema validation"):
        validate_release_index(interior)

    # Positive control: the valid revision mount path still validates.
    valid = release_index()
    verified = verify_release_index(valid, policy=_policy(), verifier=_EphemeralTestVerifier())
    assert verified.index.version == "0.2.0-rc.1"


def test_port_reservation_rechecks_host_and_data_generations_never_share_writes() -> None:
    pipeline = _revision_pipeline()
    allocated = pipeline["proposal"]["allocations"][0]["port"]
    with pytest.raises(ReleaseContractError, match="changed after approval"):
        reserve_revision_port_allocation(
            pipeline["verified"],
            pipeline["staged"],
            activation_plan=pipeline["plan"],
            reservation_receipt_digest=DIGEST,
            recheck_inventory_digest=DIGEST,
            rechecked_occupied_port_inputs=[
                {"class": "observed-host", "port": allocated, "identityDigest": DIGEST}
            ],
            allocated_at="2026-08-01T09:33:00Z",
            reservation_expires_at="2026-08-01T10:03:00Z",
        )
    shared = deepcopy(pipeline["promotion"])
    shared["predecessorVolumeNames"] = ["stateport-data-d1"]
    shared["receiptDigest"] = revision_contract_digest(shared, digest_field="receiptDigest")
    with pytest.raises(ReleaseContractError, match="share a writable"):
        validate_revision_contract(shared)


def test_two_release_revisions_have_distinct_full_id_ports_and_writable_d1() -> None:
    first = _revision_pipeline()
    successor_value = release_index()
    successor_value["signed"]["release"]["releaseId"] = "stateport-alpha-0.2.0-rc.2"
    successor_value["signed"]["release"]["version"] = "0.2.0-rc.2"
    successor_target = successor_value["signed"]["targets"][0]
    successor_target["releaseId"] = "stateport-alpha-0.2.0-rc.2"
    successor_target["topologyDigest"] = topology_digest(successor_target)
    successor_target["quadletBundleDigest"] = quadlet_bundle_digest(
        render_quadlet_bundle(successor_target, successor_value["signed"]["images"])
    )
    successor_value["signatures"][0]["subjectDigest"] = canonical_digest(successor_value["signed"])
    occupied = [
        {
            "class": "current",
            "port": allocation["port"],
            "identityDigest": canonical_digest(allocation),
        }
        for allocation in first["proposal"]["allocations"]
    ]
    second = _revision_pipeline(
        successor_value,
        occupied=occupied,
        current_pointer=_embedded(first["activation"], "stateport-accepted.current.json"),
        accepted_data_generation=DATA_D2,
        accepted_data_generation_digest=DATA_D2_DIGEST,
        predecessor_volume_names=["stateport-data-d1"],
        accepted_volume_name="stateport-data-d2",
    )
    first_manifest = _embedded(first["staged"], "/materialization.json")
    second_manifest = _embedded(second["staged"], "/materialization.json")
    assert set(first_manifest["revisions"].values()).isdisjoint(
        second_manifest["revisions"].values()
    )
    assert {allocation["port"] for allocation in first["proposal"]["allocations"]}.isdisjoint(
        {allocation["port"] for allocation in second["proposal"]["allocations"]}
    )
    assert second["promotion"]["acceptedDataGeneration"] == DATA_D2
    assert second["promotion"]["volumeBindings"][0]["volumeName"] == "stateport-data-d2"


def test_successor_cannot_promote_from_stale_predecessor_data() -> None:
    first = _revision_pipeline()
    pointer = _embedded(first["activation"], "stateport-accepted.current.json")
    successor = release_index()
    successor["signed"]["release"]["releaseId"] = "stateport-alpha-0.2.0-rc.2"
    successor["signed"]["release"]["version"] = "0.2.0-rc.2"
    target = successor["signed"]["targets"][0]
    target["releaseId"] = "stateport-alpha-0.2.0-rc.2"
    target["topologyDigest"] = topology_digest(target)
    target["quadletBundleDigest"] = quadlet_bundle_digest(
        render_quadlet_bundle(target, successor["signed"]["images"])
    )
    successor["signatures"][0]["subjectDigest"] = canonical_digest(successor["signed"])
    with pytest.raises(ReleaseContractError, match="does not match accepted pointer"):
        _revision_pipeline(
            successor,
            current_pointer=pointer,
            accepted_data_generation=DATA_D2,
            accepted_data_generation_digest=DATA_D2_DIGEST,
            predecessor_volume_names=["stateport-data-d1"],
            accepted_volume_name="stateport-data-d2",
            promotion_predecessor_override={
                "predecessorDataGeneration": DATA_D0,
                "predecessorDataGenerationDigest": f"sha256:{'0' * 64}",
            },
        )


def test_activation_pointer_refuses_replay_torn_write_and_validation_authority() -> None:
    pipeline = _revision_pipeline()
    pointer = _embedded(pipeline["activation"], "stateport-accepted.current.json")
    with pytest.raises(ReleaseContractError, match="replay"):
        validate_activation_pointer_transition(pointer, pointer)
    torn = deepcopy(pointer)
    torn["generation"] = 2
    torn["previousGeneration"] = 1
    torn["previousPointerDigest"] = DIGEST
    torn["pointerDigest"] = revision_contract_digest(torn, digest_field="pointerDigest")
    with pytest.raises(ReleaseContractError, match="predecessor digest"):
        validate_activation_pointer_transition(pointer, torn)
    forbidden = deepcopy(pointer)
    forbidden["validationGeneration"] = "validation-data"
    with pytest.raises(ReleaseContractError, match="additional property"):
        validate_revision_contract(forbidden)
    circular_decision = deepcopy(pipeline["decision"])
    circular_decision["terminalAcceptanceReceiptDigest"] = pipeline["terminal"]["receiptDigest"]
    circular_decision["decisionDigest"] = revision_contract_digest(
        circular_decision, digest_field="decisionDigest", id_field="decisionId"
    )
    with pytest.raises(ReleaseContractError, match="additional property"):
        validate_revision_contract(circular_decision)
    assert "terminalAcceptanceReceiptDigest" not in pipeline["decision"]
    assert pipeline["terminal"]["authorityFinalizeProof"]["phase"] == "finalize"


def test_owner_bundle_refuses_path_escape_and_nul() -> None:
    pipeline = _revision_pipeline()
    owner_bundle = deepcopy(
        _embedded(pipeline["accepted"], "/owner-bundles/stateport-control.json")
    )
    owner_bundle["artifacts"][0]["liveRelativePath"] = "../escape.container"
    owner_bundle["bundleDigest"] = revision_contract_digest(
        owner_bundle, digest_field="bundleDigest"
    )
    with pytest.raises(ReleaseContractError, match="schema validation"):
        validate_revision_contract(owner_bundle)

    owner_bundle["artifacts"][0]["liveRelativePath"] = "escape\x00.container"
    owner_bundle["bundleDigest"] = revision_contract_digest(
        owner_bundle, digest_field="bundleDigest"
    )
    with pytest.raises(ReleaseContractError, match="unsafe live artifact path"):
        validate_revision_contract(owner_bundle)


def test_runtime_names_remain_bounded_at_schema_maximum() -> None:
    value = release_index()
    signed = value["signed"]
    service = signed["targets"][0]["services"][0]
    image = signed["images"][0]
    maximal = "stateport-" + "s" * 63
    service["serviceId"] = maximal
    service["imageId"] = maximal
    image["imageId"] = maximal
    image["reference"] = f"ghcr.io/stateport/{maximal}@{DIGEST}"
    signed["targets"][0]["topologyDigest"] = topology_digest(signed["targets"][0])
    signed["targets"][0]["quadletBundleDigest"] = quadlet_bundle_digest(
        render_quadlet_bundle(signed["targets"][0], signed["images"])
    )
    value["signatures"][0]["subjectDigest"] = canonical_digest(signed)
    pipeline = _revision_pipeline(value)
    all_paths = [*pipeline["staged"], *pipeline["accepted"], *pipeline["activation"]]
    assert max(len(Path(path).name.encode()) for path in all_paths) <= 255
    for content in [*pipeline["staged"].values(), *pipeline["accepted"].values()]:
        for field in (b"ContainerName=", b"NetworkName=", b"VolumeName="):
            for line in content.splitlines():
                if line.startswith(field):
                    assert len(line.split(b"=", 1)[1]) <= 128


def _run_noble_systemd_quadlet_compatibility(
    tmp_path: Path,
    *,
    quadlet: Path,
    expected_quadlet_version: str,
    proof_label: str,
) -> None:
    podman = shutil.which("podman")
    assert podman is not None
    noble = (
        "docker.io/jrei/systemd-ubuntu@"
        "sha256:1651d37afbe971fecf757cb920bda47925452213bb9a01e13a9848def52f912f"
    )
    assert quadlet.is_file()
    assert subprocess.run([podman, "image", "exists", noble], check=False).returncode == 0

    pipeline = _revision_pipeline()
    quadlet_dir = tmp_path / "quadlets"
    regular_dir = tmp_path / "regular"
    generated = tmp_path / "generated"
    generated_early = tmp_path / "generated-early"
    generated_late = tmp_path / "generated-late"
    for directory in (
        quadlet_dir,
        regular_dir,
        generated,
        generated_early,
        generated_late,
    ):
        directory.mkdir()
    owner_bundle = _embedded(pipeline["accepted"], "/owner-bundles/stateport-control.json")
    for artifact in owner_bundle["artifacts"]:
        destination = quadlet_dir / artifact["liveRelativePath"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(pipeline["accepted"][artifact["sourcePath"]])
    stable_index = _stable_execution_index()
    stable_verified = verify_release_index(
        stable_index, policy=_policy(), verifier=_EphemeralTestVerifier()
    )
    stable_bundle = render_stable_host_quadlet_bundle(
        stable_verified.target, stable_verified.index.document["signed"]["images"]
    )
    for path, content in stable_bundle.items():
        if not path.endswith(".container"):
            continue
        (quadlet_dir / Path(path).name).write_bytes(content)
    for path, content in pipeline["activation"].items():
        relative = path.removeprefix("activation/")
        if not (
            relative == "stateport-accepted.target"
            or relative.startswith("stateport-accepted.target.d/")
        ):
            continue
        destination = regular_dir / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)

    completed = subprocess.run(
        [
            podman,
            "run",
            "--rm",
            "--pull=never",
            "--network=none",
            "--label",
            f"io.stateport.task={proof_label}",
            "--security-opt",
            "label=disable",
            "-v",
            f"{quadlet}:/usr/local/bin/quadlet:ro",
            "-v",
            "/usr/bin/true:/usr/bin/podman:ro",
            "-v",
            f"{quadlet_dir}:/quadlets:ro",
            "-v",
            f"{regular_dir}:/regular:ro",
            "-v",
            f"{generated}:/generated:rw",
            "-v",
            f"{generated_early}:/generated-early:rw",
            "-v",
            f"{generated_late}:/generated-late:rw",
            noble,
            "sh",
            "-ceu",
            'test "$(. /etc/os-release; echo "$VERSION_ID")" = 24.04; '
            f'test "$(/usr/local/bin/quadlet -version)" = {expected_quadlet_version}; '
            "QUADLET_UNIT_DIRS=/quadlets /usr/local/bin/quadlet -user "
            "/generated /generated-early /generated-late; "
            "systemd-analyze verify /generated/*.service /regular/stateport-accepted.target",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    services = sorted(generated.glob("*.service"))
    assert services
    assert any("stateport" in service.name for service in services)
    assert any("stateport-execution-host" in service.name for service in services)
    container_units = [
        service.read_text(encoding="utf-8")
        for service in services
        if "podman run" in service.read_text(encoding="utf-8")
    ]
    assert container_units
    assert all("--log-driver k8s-file" in content for content in container_units)
    assert all("--log-opt=max-size=10485760" in content for content in container_units)
    assert all("/usr/local/bin/stateport-healthcheck" in content for content in container_units)
    assert all("0.0.0.0" not in content for content in container_units)
    stable_unit = next(
        service.read_text(encoding="utf-8")
        for service in services
        if "stateport-execution-host" in service.name
    )
    assert "MemoryMax=536870912" in stable_unit
    assert "CPUQuota=100%" in stable_unit
    assert "TasksMax=256" in stable_unit
    assert "--group-add=keep-groups" in stable_unit
    assert "unsupported key" not in completed.stderr


def test_noble_systemd_accepts_host_quadlet_584_generated_units(tmp_path: Path) -> None:
    if os.environ.get("STATEPORT_NOBLE_SYSTEMD_HOST_QUADLET_584_PROOF") != "1":
        pytest.skip(
            "set STATEPORT_NOBLE_SYSTEMD_HOST_QUADLET_584_PROOF=1 for the "
            "Noble-systemd/host-Quadlet-5.8.4 proof"
        )
    quadlet = Path("/usr/libexec/podman/quadlet")
    assert quadlet.is_file()
    assert hashlib.sha256(quadlet.read_bytes()).hexdigest() == (
        "80fc48eed3caeeee20b1c7b20a15f2c747c01315a97f0b3282d822f3bde446bb"
    )
    _run_noble_systemd_quadlet_compatibility(
        tmp_path,
        quadlet=quadlet,
        expected_quadlet_version="5.8.4",
        proof_label="alpha-slice-b-noble-systemd-host-quadlet-584-proof",
    )


def _extract_ubuntu_noble_quadlet_493(package: Path, destination: Path) -> str:
    assert hashlib.sha256(package.read_bytes()).hexdigest() == (
        "e5c1c37e387ed14c352a744a75fbb79fb2f82573ca7bf36886e3b7333fc9ef1a"
    )
    listing = subprocess.run(
        ["ar", "t", str(package)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    data_members = [name for name in listing if name.startswith("data.tar.")]
    assert len(data_members) == 1
    payload = subprocess.run(
        ["ar", "p", str(package), data_members[0]],
        check=True,
        capture_output=True,
    ).stdout
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as archive:
        matches = [
            member
            for member in archive.getmembers()
            if member.name.lstrip("./") == "usr/libexec/podman/quadlet"
        ]
        assert len(matches) == 1 and matches[0].isfile()
        source = archive.extractfile(matches[0])
        assert source is not None
        content = source.read()
    destination.write_bytes(content)
    destination.chmod(0o755)
    return hashlib.sha256(content).hexdigest()


def test_ubuntu_noble_quadlet_493_and_systemd_verify_real_units(tmp_path: Path) -> None:
    if os.environ.get("STATEPORT_NOBLE_QUADLET_493_PROOF") != "1":
        pytest.skip(
            "set STATEPORT_NOBLE_QUADLET_493_PROOF=1 and "
            "STATEPORT_NOBLE_PODMAN_493_DEB to prove the Ubuntu baseline"
        )
    package_value = os.environ.get("STATEPORT_NOBLE_PODMAN_493_DEB")
    assert package_value is not None
    package = Path(package_value)
    assert package.is_absolute() and package.is_file() and not package.is_symlink()
    quadlet = tmp_path / "ubuntu-noble-quadlet-4.9.3"
    quadlet_digest = _extract_ubuntu_noble_quadlet_493(package, quadlet)
    assert quadlet_digest == ("9e95fafe06ef5b630dbb59cbf3630d38931c3fc27ba7c7f9cf472f064d9798b9")
    _run_noble_systemd_quadlet_compatibility(
        tmp_path,
        quadlet=quadlet,
        expected_quadlet_version="4.9.3",
        proof_label="alpha-slice-b-ubuntu-noble-quadlet-493-systemd-proof",
    )


def test_release_package_validates_outside_checkout(tmp_path: Path) -> None:
    site = tmp_path / "site"
    site.mkdir()
    shutil.copytree(
        ROOT / "packages/release-contracts/src/stateport_release",
        site / "stateport_release",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    index_path = tmp_path / "release-index.json"
    index_path.write_text(json.dumps(release_index()), encoding="utf-8")
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP"}
    }
    environment["PYTHONPATH"] = str(site)
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "from pathlib import Path; from stateport_release import load_release_index; "
            "print(load_release_index(Path('release-index.json').read_bytes()).release_id)",
        ],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "stateport-alpha-0.2.0-rc.1"


def _update_release(
    release_id: str,
    version: str,
    *,
    signed_digest: str,
) -> dict[str, object]:
    return {
        "releaseId": release_id,
        "version": version,
        "channel": "alpha",
        "signedPayloadDigest": signed_digest,
        "imageSetDigest": DIGEST,
        "sourceCommit": COMMIT,
        "sourceTree": TREE,
        "qualification": "candidate",
        "publishedAt": None,
    }


def _authority_scope(run_id: str) -> dict[str, object]:
    return {
        "repository": {
            "origin": "https://github.com/stateport/stateport.git",
            "repositoryKey": "1" * 32,
            "repositoryRoot": "/srv/stateport/control",
        },
        "branch": None,
        "sliceId": "BL-CONTAINER-DEPLOYMENT-ALPHA-001-B",
        "applicationId": "stateport",
        "runId": run_id,
        "paths": ["operator://stateport/update"],
    }


def _update_authority_reference(plan_digest: str) -> dict[str, object]:
    return {
        "action": "apply_update",
        "actorId": "stateport-updater",
        "grantId": "grant_update_fixture_001",
        "grantDigest": f"sha256:{'6' * 64}",
        "profile": "balanced",
        "configuredPolicy": "auto_with_receipt",
        "effectivePolicy": "auto_with_receipt",
        "scope": _authority_scope(plan_digest),
        "runId": plan_digest,
        "planDigest": plan_digest,
        "requestId": f"authority_request_{'7' * 32}",
        "decisionDigest": f"sha256:{'7' * 64}",
        "reservationId": f"authority_reservation_{'8' * 32}",
        "reservationDigest": f"sha256:{'8' * 64}",
        "claimId": f"authority_claim_{'9' * 32}",
        "claimDigest": f"sha256:{'9' * 64}",
    }


def test_canonical_update_documents_share_exact_digest_chain() -> None:
    current = _update_release("stateport-alpha-0.1.0", "0.1.0", signed_digest=f"sha256:{'f' * 64}")
    successor = _update_release(
        "stateport-alpha-0.2.0-rc.1", "0.2.0-rc.1", signed_digest=f"sha256:{'e' * 64}"
    )
    policy: dict[str, object] = {
        "mode": "automatic-with-rollback",
        "channel": "alpha",
        "schedule": {"daysOfWeek": [1, 2, 3, 4, 5, 6, 7], "startMinuteUtc": 120},
        "retention": {
            "acceptedPredecessors": 1,
            "failedSuccessors": 1,
            "maximumVersions": 3,
            "maximumAgeDays": 30,
        },
        "downloadAhead": True,
    }
    policy["policyDigest"] = update_policy_digest(policy)
    plan_value: dict[str, object] = {
        "schema": "stateport.update-plan/v1",
        "operation": "update",
        "installationId": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
        "current": current,
        "successor": successor,
        "releaseIndexDigest": f"sha256:{'d' * 64}",
        "signedPayloadDigest": successor["signedPayloadDigest"],
        "policy": policy,
        "estimatedPullBytes": 1048576,
        "compatibility": {
            "updaterCompatible": True,
            "migrationCompatible": True,
            "rollbackCompatible": True,
            "downgrade": False,
        },
        "backupRequired": True,
        "steps": [
            "verify",
            "backup",
            "pull",
            "stage",
            "dry-run-migrations",
            "start-successor",
            "health-successor",
            "browser-successor",
            "studystate-successor",
            "state-check-successor",
            "switch",
            "health-accepted-route",
            "state-check-accepted-route",
            "retain-predecessor",
            "record-receipt",
        ],
        "rollback": {
            "automaticOnFailure": True,
            "retainedPredecessor": True,
            "dataCompatible": True,
        },
        "authority": {
            "action": "apply_update",
            "status": "awaiting_authority_claim",
        },
        "createdAt": "2026-08-01T10:00:00Z",
        "expiresAt": "2026-08-01T10:30:00Z",
    }
    plan_value["planDigest"] = update_plan_digest(plan_value)
    plan_value["authority"]["runId"] = plan_value["planDigest"]
    plan_value["planId"] = (
        "update_plan_" + str(plan_value["planDigest"]).removeprefix("sha256:")[:32]
    )
    plan = validate_update_plan(
        plan_value,
        now=datetime(2026, 8, 1, 10, 1, tzinfo=timezone.utc),
    )
    assert plan.document["planDigest"] == plan_value["planDigest"]
    with pytest.raises(ReleaseContractError, match="expired"):
        validate_update_plan(
            plan_value,
            now=datetime(2026, 8, 1, 10, 30, tzinfo=timezone.utc),
        )

    failure = validate_update_failure_evidence(
        {
            "schema": "stateport.update-failure-evidence/v1",
            "failureId": f"update_failure_{'4' * 32}",
            "planId": plan_value["planId"],
            "planDigest": plan.digest,
            "successor": {
                "releaseId": successor["releaseId"],
                "version": successor["version"],
                "signedPayloadDigest": successor["signedPayloadDigest"],
            },
            "failedStep": "health-successor",
            "errorCode": "successor_unhealthy",
            "safeSummary": "The isolated successor did not become ready.",
            "artifacts": [],
            "retained": True,
            "observedAt": "2026-08-01T10:02:00Z",
        }
    )
    status = validate_update_status(
        {
            "schema": "stateport.update-status/v1",
            "sequence": 3,
            "phase": "rolled_back",
            "installationId": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
            "policy": policy,
            "current": {
                "releaseId": current["releaseId"],
                "version": current["version"],
                "signedPayloadDigest": current["signedPayloadDigest"],
            },
            "accepted": {
                "releaseId": current["releaseId"],
                "version": current["version"],
                "signedPayloadDigest": current["signedPayloadDigest"],
            },
            "retainedPredecessor": None,
            "stagedSuccessor": None,
            "failedSuccessorEvidence": failure.document["failureId"],
            "lastReceipt": f"update_receipt_{'5' * 32}",
            "updatedAt": "2026-08-01T10:03:00Z",
        }
    )
    assert status.document["failedSuccessorEvidence"] == failure.document["failureId"]

    receipt = validate_update_receipt(
        {
            "schema": "stateport.update-receipt/v1",
            "receiptId": f"update_receipt_{'5' * 32}",
            "installationId": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
            "planId": plan_value["planId"],
            "planDigest": plan.digest,
            "operation": "update",
            "from": current,
            "attempted": successor,
            "accepted": current,
            "releaseIndexDigest": plan_value["releaseIndexDigest"],
            "backupReceipt": "backup_receipt_fixture",
            "checks": {"health": "failed", "rollback": "passed"},
            "rollback": {
                "attempted": True,
                "succeeded": True,
                "retainedFailureEvidence": True,
            },
            "authority": _update_authority_reference(plan.digest),
            "startedAt": "2026-08-01T10:01:00Z",
            "finishedAt": "2026-08-01T10:03:00Z",
            "result": "rolled_back",
        }
    )
    assert receipt.document["accepted"] == receipt.document["from"]
    link = validate_update_authority_link(
        {
            "schema": "stateport.update-authority-link/v1",
            "linkId": f"update_authority_link_{'b' * 32}",
            "planDigest": plan.digest,
            "runId": plan.digest,
            "updateReceiptId": receipt.document["receiptId"],
            "updateReceiptDigest": receipt.digest,
            "authority": {
                **_update_authority_reference(plan.digest),
                "receiptId": f"authority_receipt_{'a' * 32}",
                "receiptDigest": f"sha256:{'a' * 64}",
            },
            "linkedAt": "2026-08-01T10:04:00Z",
        }
    )
    assert link.document["runId"] == plan.digest


def test_install_receipt_and_provenance_contracts_validate() -> None:
    index = release_index()
    signed = index["signed"]
    signed_target = signed["targets"][0]
    index_digest = canonical_digest(index)
    signed_digest = canonical_digest(signed)
    images = signed["images"]
    observed_services = [
        {
            "serviceId": service["serviceId"],
            "imageId": service["imageId"],
            "imageDigest": next(
                image["digest"] for image in images if image["imageId"] == service["imageId"]
            ),
            "healthy": True,
        }
        for service in signed_target["services"]
    ]
    observed_image_set = image_set_digest(images)
    observed_service_set = service_set_digest(observed_services)
    target_identity: dict[str, object] = {
        "targetId": signed_target["targetId"],
        "topologyDigest": signed_target["topologyDigest"],
        "quadletArtifactDigest": signed["artifacts"]["quadlet"]["digest"],
        "quadletBundleDigest": signed_target["quadletBundleDigest"],
        "imageSetDigest": observed_image_set,
        "serviceSetDigest": observed_service_set,
    }
    target_identity["targetDigest"] = canonical_digest(target_identity)
    runtime: dict[str, object] = {
        "releaseId": signed["release"]["releaseId"],
        "releaseIndexDigest": index_digest,
        "signedPayloadDigest": signed_digest,
        "targetDigest": target_identity["targetDigest"],
        "topologyDigest": target_identity["topologyDigest"],
        "quadletArtifactDigest": target_identity["quadletArtifactDigest"],
        "quadletBundleDigest": target_identity["quadletBundleDigest"],
        "imageSetDigest": observed_image_set,
        "serviceSetDigest": observed_service_set,
        "services": observed_services,
        "localUrl": "http://127.0.0.1:8080/",
        "healthy": True,
    }
    runtime["runtimeIdentityDigest"] = canonical_digest(runtime)
    directive: dict[str, object] = {
        "kind": "installer-directive",
        "directiveId": f"installer_directive_{'2' * 32}",
        "directiveKind": "interactive-exact-plan",
        "actorId": "local-owner",
        "installerDigest": DIGEST,
        "releaseIndexDigest": index_digest,
        "planDigest": DIGEST,
        "confirmationReceiptDigest": f"sha256:{'3' * 64}",
        "confirmedAt": "2026-08-01T09:59:59Z",
    }
    directive["directiveDigest"] = installer_directive_digest(directive)
    receipt = validate_install_receipt(
        {
            "schema": "stateport.install-receipt/v1",
            "receiptId": f"install_receipt_{'6' * 32}",
            "operation": "install",
            "installer": {"version": "0.1.0", "digest": DIGEST},
            "release": {
                "releaseId": signed["release"]["releaseId"],
                "version": signed["release"]["version"],
                "channel": signed["release"]["channel"],
                "signedPayloadDigest": signed_digest,
                "sourceCommit": signed["source"]["commit"],
                "sourceTree": signed["source"]["tree"],
            },
            "releaseIndexDigest": index_digest,
            "installPlanDigest": DIGEST,
            "target": target_identity,
            "host": {
                "kernel": "Linux",
                "osId": "ubuntu",
                "versionId": "24.04",
                "architecture": "amd64",
                "cgroupVersion": "v2",
                "podmanVersion": "5.4.2",
                "rootless": True,
                "quadlet": True,
                "systemdUser": True,
                "subuidConfigured": True,
                "subgidConfigured": True,
                "supportTier": "validated_baseline",
            },
            "verification": {
                "signedIndex": {
                    "expectedDigest": index_digest,
                    "observedDigest": index_digest,
                    "status": "verified",
                },
                "signers": [
                    {
                        "subjectKind": "release-index",
                        "subjectId": "release-index",
                        "subjectDigest": signed_digest,
                        "trustMode": "keyless-certificate",
                        "certificateIdentity": SIGNER.certificate_identity,
                        "certificateOidcIssuer": SIGNER.oidc_issuer,
                        "bundleDigest": index["signatures"][0]["bundle"]["digest"],
                        "verifiedAt": "2026-08-01T09:59:00Z",
                        "transparencyLogStatus": "not-required-private-candidate",
                        "status": "verified",
                    },
                    *[
                        {
                            "subjectKind": "image",
                            "subjectId": image["imageId"],
                            "subjectDigest": image["digest"],
                            "trustMode": "keyless-certificate",
                            "certificateIdentity": SIGNER.certificate_identity,
                            "certificateOidcIssuer": SIGNER.oidc_issuer,
                            "bundleDigest": image["signature"]["bundle"]["digest"],
                            "verifiedAt": "2026-08-01T09:59:00Z",
                            "transparencyLogStatus": "not-required-private-candidate",
                            "status": "verified",
                        }
                        for image in images
                    ],
                ],
                "artifacts": [
                    {
                        "artifactId": artifact_id,
                        "expectedDigest": artifact["digest"],
                        "observedDigest": artifact["digest"],
                        "status": "verified",
                    }
                    for artifact_id, artifact in signed["artifacts"].items()
                ],
                "images": [
                    {
                        "imageId": image["imageId"],
                        "reference": image["reference"],
                        "expectedDigest": image["digest"],
                        "observedDigest": image["digest"],
                        "sizeBytes": image["sizeBytes"],
                        "signatureBundleDigest": image["signature"]["bundle"]["digest"],
                        "cycloneDxDigest": image["sboms"]["cycloneDx"]["digest"],
                        "spdxDigest": image["sboms"]["spdx"]["digest"],
                        "scanDigest": image["scan"]["artifact"]["digest"],
                        "provenanceDigest": image["provenance"]["digest"],
                        "status": "verified",
                    }
                    for image in images
                ],
            },
            "runtime": runtime,
            "dataDisposition": "created",
            "authority": directive,
            "startedAt": "2026-08-01T10:00:00Z",
            "finishedAt": "2026-08-01T10:01:00Z",
            "result": "succeeded",
        }
    )
    assert receipt.document["runtime"]["healthy"] is True

    provenance = validate_release_provenance(
        {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "stateport-web", "digest": {"sha256": HEX}}],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://stateport.invalid/buildtypes/oci/v1",
                    "externalParameters": {
                        "sourceRepository": "https://github.com/stateport/stateport.git",
                        "sourceCommit": COMMIT,
                        "sourceTree": TREE,
                        "publicSnapshotCommit": "d" * 40,
                        "publicSnapshotTree": "e" * 40,
                        "platform": "linux/amd64",
                        "dockerfile": "images/stateport-web/Containerfile",
                    },
                    "internalParameters": {
                        "sourceDateEpoch": 1785578400,
                        "networkMode": "dependency-fetch-only",
                    },
                    "resolvedDependencies": [{"uri": "oci://python", "digest": {"sha256": HEX}}],
                },
                "runDetails": {
                    "builder": {
                        "id": "operator://builder/local",
                        "version": "podman-5",
                        "executableDigest": "sha256:" + "a" * 64,
                        "descriptorDigest": "sha256:" + "b" * 64,
                        "artifactUri": "https://example.invalid/podman-5",
                        "artifactDigest": "sha256:" + "a" * 64,
                    },
                    "metadata": {
                        "invocationId": "fixture-build",
                        "startedOn": "2026-08-01T10:00:00Z",
                        "finishedOn": "2026-08-01T10:01:00Z",
                    },
                    "byproducts": [],
                },
            },
        }
    )
    assert provenance.document["predicateType"] == "https://slsa.dev/provenance/v1"


# ---------------------------------------------------------------------------
# Content-addressed signature-bundle retention
# ---------------------------------------------------------------------------

RETAINED_BUNDLE_BYTES = (
    b'{"mediaType":"application/vnd.sigstore.bundle.v0.3+json","retained":true}\n'
)
SUCCESSOR_BUNDLE_BYTES = (
    b'{"mediaType":"application/vnd.sigstore.bundle.v0.3+json","retained":"successor"}\n'
)


def _retained_signature(
    bundle_bytes: bytes,
    *,
    name: str = "release-index.sigstore.json",
    fingerprint: str = PINNED_KEY.public_key_fingerprint,
    key_id: str = PINNED_KEY.key_id,
) -> dict[str, object]:
    return {
        "scheme": "cosign-v3-bundle",
        "subjectDigest": DIGEST,
        "bundle": {
            "uri": f"operator://release/{name}",
            "digest": "sha256:" + hashlib.sha256(bundle_bytes).hexdigest(),
            "size": len(bundle_bytes),
            "mediaType": "application/vnd.sigstore.bundle.v0.3+json",
        },
        "trustMode": "pinned-public-key",
        "publicKeyFingerprint": fingerprint,
        "publicKeyFingerprintAlgorithm": "sha256-canonical-der-spki",
        "publicKeyId": key_id,
        "transparencyLog": "not-uploaded-private-candidate",
    }


def test_signature_bundle_name_requires_a_retained_bundle_uri() -> None:
    signature = _retained_signature(RETAINED_BUNDLE_BYTES)
    assert signature_bundle_name(signature) == "release-index.sigstore.json"
    broken = deepcopy(signature)
    broken["bundle"]["uri"] = "operator://release/release-index.json"
    with pytest.raises(CosignVerificationError, match="does not name a retained bundle"):
        signature_bundle_name(broken)


def test_bundle_slot_is_content_addressed_by_the_recorded_digest() -> None:
    signature = _retained_signature(RETAINED_BUNDLE_BYTES)
    slot = bundle_slot(Path("/bundles"), signature)
    assert slot == (
        Path("/bundles")
        / hashlib.sha256(RETAINED_BUNDLE_BYTES).hexdigest()
        / "release-index.sigstore.json"
    )
    malformed = deepcopy(signature)
    malformed["bundle"]["digest"] = "sha256:not-hex"
    with pytest.raises(CosignVerificationError, match="bundle digest is malformed"):
        bundle_slot(Path("/bundles"), malformed)


def test_retain_bundle_is_create_only_digest_checked_and_idempotent(tmp_path: Path) -> None:
    root = tmp_path / "bundles"
    root.mkdir()
    source = tmp_path / "release-index.sigstore.json"
    source.write_bytes(RETAINED_BUNDLE_BYTES)
    signature = _retained_signature(RETAINED_BUNDLE_BYTES)

    slot = retain_bundle(root, source, signature)
    assert slot == bundle_slot(root, signature)
    assert slot.read_bytes() == RETAINED_BUNDLE_BYTES
    assert slot.stat().st_mode & 0o777 == 0o600
    assert retain_bundle(root, source, signature) == slot

    slot.chmod(0o600)
    slot.write_bytes(SUCCESSOR_BUNDLE_BYTES)
    with pytest.raises(CosignVerificationError, match="do not match the recorded digest"):
        retain_bundle(root, source, signature)


def test_retain_bundle_refuses_a_source_that_diverges_from_the_record(tmp_path: Path) -> None:
    root = tmp_path / "bundles"
    root.mkdir()
    source = tmp_path / "release-index.sigstore.json"
    source.write_bytes(SUCCESSOR_BUNDLE_BYTES)
    signature = _retained_signature(RETAINED_BUNDLE_BYTES)
    with pytest.raises(CosignVerificationError, match="do not match the recorded digest"):
        retain_bundle(root, source, signature)
    assert list(root.iterdir()) == []


def test_retain_bundle_keeps_same_named_bundles_in_separate_digest_slots(tmp_path: Path) -> None:
    root = tmp_path / "bundles"
    root.mkdir()
    genesis = _retained_signature(RETAINED_BUNDLE_BYTES)
    successor = _retained_signature(SUCCESSOR_BUNDLE_BYTES)
    genesis_source = tmp_path / "genesis" / "release-index.sigstore.json"
    successor_source = tmp_path / "successor" / "release-index.sigstore.json"
    genesis_source.parent.mkdir()
    successor_source.parent.mkdir()
    genesis_source.write_bytes(RETAINED_BUNDLE_BYTES)
    successor_source.write_bytes(SUCCESSOR_BUNDLE_BYTES)

    genesis_slot = retain_bundle(root, genesis_source, genesis)
    successor_slot = retain_bundle(root, successor_source, successor)
    assert genesis_slot != successor_slot
    assert genesis_slot.read_bytes() == RETAINED_BUNDLE_BYTES
    assert successor_slot.read_bytes() == SUCCESSOR_BUNDLE_BYTES


def test_retain_bundle_refuses_a_symlink_source(tmp_path: Path) -> None:
    root = tmp_path / "bundles"
    root.mkdir()
    target = tmp_path / "target.sigstore.json"
    target.write_bytes(RETAINED_BUNDLE_BYTES)
    source = tmp_path / "release-index.sigstore.json"
    source.symlink_to(target)
    with pytest.raises(CosignVerificationError, match="not a regular file"):
        retain_bundle(root, source, _retained_signature(RETAINED_BUNDLE_BYTES))
    assert list(root.iterdir()) == []


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl fingerprints the fixture key")
def test_cosign_verifier_resolves_bundles_only_from_the_retained_slot(tmp_path: Path) -> None:
    from scripts.test_install_no_checkout import TEST_PUBLIC_KEY_PEM

    cosign = tmp_path / "cosign"
    cosign.write_bytes(b"#!/bin/sh\nexit 0\n")
    cosign.chmod(0o755)
    pem = tmp_path / "trust.pub"
    pem.write_text(TEST_PUBLIC_KEY_PEM, encoding="ascii")
    identity = PinnedPublicKeyIdentity(public_key_der_spki_fingerprint(pem), "alpha-release")
    root = tmp_path / "bundles"
    root.mkdir()
    verifier = CosignVerifier(cosign=cosign, public_key=pem, identity=identity, bundle_root=root)
    signature = _retained_signature(
        RETAINED_BUNDLE_BYTES,
        fingerprint=identity.public_key_fingerprint,
        key_id=identity.key_id,
    )
    signature["subjectDigest"] = "sha256:" + hashlib.sha256(b"payload").hexdigest()
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "release-index.sigstore.json").write_bytes(RETAINED_BUNDLE_BYTES)
    # A flat bundle beside the verifier root is the pre-fix layout and must be dead.
    (root / "release-index.sigstore.json").write_bytes(RETAINED_BUNDLE_BYTES)
    with pytest.raises(CosignVerificationError, match="not a regular file"):
        verifier.verify_blob(b"payload", signature)

    verifier.retain_bundle(staging / "release-index.sigstore.json", signature)
    proof = verifier.verify_blob(b"payload", signature)
    assert proof.bundle_digest == signature["bundle"]["digest"]


def test_parse_last_line_json_helper_contract() -> None:
    """I3: the shared last-non-empty-line JSON parser has a fixed contract."""

    assert parse_last_line_json('{"healthy": true}\n') == {"healthy": True}
    assert parse_last_line_json("noise line\n{\"a\": 1}\n") == {"a": 1}
    assert parse_last_line_json("") is None
    assert parse_last_line_json("   \n\n") is None
    assert parse_last_line_json("not json") is None
    assert parse_last_line_json("noise\nnot json either\n") is None
    # A trailing blank line after the payload is tolerated (last NON-EMPTY line).
    assert parse_last_line_json('{"x": 2}\n\n\n') == {"x": 2}
    # Non-object JSON values parse too; callers validate the shape themselves.
    assert parse_last_line_json("[1, 2]\n") == [1, 2]


def test_internal_cli_emitter_parser_pairs_share_the_i3_helper() -> None:
    """I3: every internal CLI emitter/parser pair parses the last non-empty
    line through the single shared ``parse_last_line_json`` helper.

    The known pairs are the execution-host ``health-probe`` CLI (parsed by the
    privileged provisioning step) and the StateBench protected evaluator
    (parsed by the real-project harness). The installer's install-end gate
    consumes the provisioning receipt and intentionally has no duplicate probe
    parser.
    A hand-rolled ``json.loads(stdout.strip().splitlines()[-1])`` anywhere in
    those parsers is exactly the drift this invariant forbids.
    """

    root = Path(__file__).resolve().parents[1]
    pairs = [
        root / "packages/release-contracts/src/stateport_release/execution_host_provisioning.py",
        root / "packages/statebench/src/statebench/real_project_harness.py",
    ]
    hand_rolled = "json.loads(completed.stdout.strip().splitlines()[-1])"
    for source in pairs:
        text = source.read_text(encoding="utf-8")
        assert "parse_last_line_json" in text, f"{source} must use the shared I3 helper"
        assert hand_rolled not in text, f"{source} re-introduced a hand-rolled last-line parse"


@pytest.mark.parametrize('profile_id', [None, 'stateport.empty-workspace-terminal/v1', 'stateport.reviewed-source-workspace-terminal/v1'])
def test_signed_workspace_profile_selection_is_explicit_and_read_only(profile_id):
    value = _stable_execution_index()
    service = value['signed']['targets'][0]['services'][0]
    workspace = {'name': 'workspace-authority', 'hostPath': '/etc/stateport/workspace-authority',
                 'mountPath': '/run/stateport-workspace-authority', 'purpose': 'workspace-authority',
                 'sourceOwner': 'root', 'sourceGroup': 'root', 'mode': 'ro',
                 'environmentVariable': 'STATEPORT_WORKSPACE_AUTHORITY_DIRECTORY'}
    if profile_id is not None:
        workspace['profileId'] = profile_id
    service['readOnlyHostMounts'] = [
        {'name': 'template-sources', 'hostPath': '/var/lib/stateport/imports', 'mountPath': '/imports',
         'purpose': 'template-sources', 'sourceOwner': 'installer-client', 'sourceGroup': 'stateport-execution-control',
         'mode': 'ro', 'environmentVariable': 'STATEPORT_REPOSITORY_ROOTS'}, workspace]
    _refresh_index_topology(value)
    verified = verify_release_index(value, policy=_policy(), verifier=_EphemeralTestVerifier())
    units = render_quadlet_bundle(verified.target, verified.index.document['signed']['images'])
    web = [content.decode() for path, content in units.items() if 'stateport-web' in Path(path).name and path.endswith('.container.in')]
    assert web and all('Volume=/etc/stateport/workspace-authority:/run/stateport-workspace-authority:ro' in unit for unit in web)
    for unit in web:
        selectors = [line for line in unit.splitlines() if line.startswith('Environment=STATEPORT_WORKSPACE_AUTHORITY_PROFILE=')]
        assert selectors == ([] if profile_id is None else ['Environment=STATEPORT_WORKSPACE_AUTHORITY_PROFILE=' + profile_id])
    service['readOnlyHostMounts'][1]['profileId'] = 'stateport.browser-selected-source/v1'
    _refresh_index_topology(value)
    with pytest.raises(ReleaseContractError):
        verify_release_index(value, policy=_policy(), verifier=_EphemeralTestVerifier())
