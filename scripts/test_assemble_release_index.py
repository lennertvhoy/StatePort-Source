from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import io
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import zipfile

import jsonschema
import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "packages/release-contracts/src"))

from stateport_release import (  # noqa: E402
    CosignVerificationError,
    CosignVerifier,
    PinnedPublicKeyIdentity,
    ReleaseContractError,
    ReleaseVerificationPolicy,
    SignatureVerificationProof,
    canonical_digest,
    canonical_json_bytes,
    load_release_index_file,
    public_key_der_spki_fingerprint,
    validate_release_index,
    verify_release_index,
)
import assemble_release_index as assembler  # noqa: E402
from release_safe_io import sha256_file  # noqa: E402


COSIGN = Path("/home/linuxbrew/.linuxbrew/bin/cosign")
pytestmark = pytest.mark.skipif(
    not COSIGN.is_file(), reason="pinned Cosign toolchain is unavailable"
)

COMMIT = "b" * 40
TREE = "c" * 40
PUBLIC_COMMIT = "d" * 40
PUBLIC_TREE = "e" * 40
IMAGES = ("stateport-web", "stateport-api", "stateport-worker", "stateport-execution-host")
HEALTH = {
    "stateport-web": (8080, "/health"),
    "stateport-api": (8790, "/readyz"),
    "stateport-worker": (8791, "/readyz"),
}
BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"


@pytest.fixture(scope="module")
def trust_root(tmp_path_factory: pytest.TempPathFactory) -> dict[str, object]:
    """Ephemeral, test-only Cosign key pair; never release evidence."""

    root = tmp_path_factory.mktemp("trust-root")
    root.chmod(0o700)
    env = {**os.environ, "COSIGN_PASSWORD": "test-ephemeral-non-release"}
    subprocess.run(
        [str(COSIGN), "generate-key-pair", "--output-key-prefix", "test"],
        cwd=root,
        check=True,
        capture_output=True,
        env=env,
    )
    public = root / "test.pub"
    return {
        "private": root / "test.key",
        "public": public,
        "fingerprint": public_key_der_spki_fingerprint(public),
        "key_id": "stateport-alpha-test-2026-08",
    }


@pytest.fixture(autouse=True)
def _cosign_password(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COSIGN_PASSWORD", "test-ephemeral-non-release")


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _minimal_updater_wheel(
    *, name: str = "stateport-updater", version: str = "0.1.1"
) -> bytes:
    normalized = name.replace("-", "_")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(
            f"{normalized}-{version}.dist-info/METADATA",
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n",
        )
        archive.writestr(
            f"{normalized}-{version}.dist-info/WHEEL",
            "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
        package = ROOT / "packages/release-contracts/src/stateport_release"
        for path in sorted(package.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(package.parent).as_posix())
    return buffer.getvalue()


def _service(
    service_id: str,
    volume_name: str,
    mount_path: str,
    control_contract: str = "none",
) -> dict[str, object]:
    port, path = HEALTH[service_id]
    return {
        "serviceId": service_id,
        "imageId": service_id,
        "trustDomain": "control",
        "quadletOwner": "stateport-control",
        "revisionScoped": True,
        "runAsUser": 65532,
        "readOnlyRoot": True,
        "health": {"kind": "http", "containerPort": port, "path": path},
        "ports": [
            {
                "name": "http",
                "containerPort": port,
                "hostScope": "loopback",
                "allocation": "full-revision-digest-derived-collision-probed",
            }
        ],
        "writableVolumes": [
            {
                "name": volume_name,
                "mountPath": mount_path,
                "purpose": "durable-state",
                "scope": "installation",
                "validation": {
                    "mode": "read-only-snapshot-copy",
                    "authority": "exact-backup-receipt-required",
                },
            }
        ],
        "resources": {"memoryMaxBytes": 1073741824, "cpuQuotaPercent": 200, "pidsMax": 512},
        "capabilities": {"podmanSocketAccess": "none", "controlContract": control_contract},
    }


def _execution_host_service() -> dict[str, object]:
    return {
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
        "resources": {"memoryMaxBytes": 536870912, "cpuQuotaPercent": 100, "pidsMax": 256},
        "logging": {"driver": "k8s-file", "maxSizeBytes": 10485760},
        "health": {"kind": "unix-socket", "value": "/run/stateport-execution/control.sock"},
        "updateCompatibility": {
            "contractVersion": 1,
            "minimumClientVersion": 1,
            "maximumClientVersion": 2,
            "replacementPolicy": "explicit-compatible-host-update-only",
        },
    }


def _execution_contract() -> dict[str, object]:
    return {
        "transport": "confined-host-unix-socket",
        "serviceId": "stateport-execution-host",
        "imageId": "stateport-execution-host",
        # The assembler binds the digest to the exact signed stable-host image.
        "imageDigest": None,
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


def _runtime_derivation() -> dict[str, object]:
    return {
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


def _image_digest(image_id: str) -> str:
    config = b"{}"
    config_digest = hashlib.sha256(config).hexdigest()
    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "config": {"digest": "sha256:" + config_digest, "size": len(config)},
            "layers": [],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return "sha256:" + hashlib.sha256(manifest).hexdigest()


def _write_oci_archive(path: Path, image_id: str) -> None:
    config = b"{}"
    config_digest = hashlib.sha256(config).hexdigest()
    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "config": {"digest": "sha256:" + config_digest, "size": len(config)},
            "layers": [],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    manifest_digest = hashlib.sha256(manifest).hexdigest()
    index = json.dumps(
        {
            "schemaVersion": 2,
            "manifests": [{"digest": "sha256:" + manifest_digest, "size": len(manifest)}],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    with tarfile.open(path, "w") as archive:
        for name, data in (
            ("index.json", index),
            ("blobs/sha256/" + manifest_digest, manifest),
            ("blobs/sha256/" + config_digest, config),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, __import__("io").BytesIO(data))


@contextmanager
def _assembler_clock(anchor: datetime):
    class FixtureDateTime(datetime):
        @classmethod
        def now(cls, tz: timezone | None = None) -> datetime:
            value = anchor
            return value if tz is not None else value.replace(tzinfo=None)

    original = assembler.datetime
    assembler.datetime = FixtureDateTime
    try:
        yield
    finally:
        assembler.datetime = original


def _build_inputs(tmp_path: Path, fixture_anchor: datetime | None = None) -> dict[str, object]:
    tmp_path.mkdir(mode=0o700, exist_ok=True)
    tmp_path.chmod(0o700)
    now = (fixture_anchor or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
    built_at = _timestamp(now - timedelta(hours=2))
    observed_at = _timestamp(now - timedelta(hours=1))
    expires_at = _timestamp(now + timedelta(days=30))
    pinned = yaml.safe_load((ROOT / "config/release-tool-inputs.yaml").read_text())["tools"]
    tool_records = {
        name: {
            "version": str(tool["version"]),
            "executableDigest": str(tool["executableDigest"]),
            "bottleDigest": str(tool["bottleDigest"]),
            "provenance": str(tool["provenance"]),
        }
        for name, tool in pinned.items()
    }

    operator = tmp_path / "operator"
    operator.mkdir(mode=0o700)
    files: dict[str, Path] = {}
    for name, content in {
        "installer": b"test-installer\n",
        "execution-host-provisioner": b"#!/bin/sh\nexit 0\n",
        "updater": _minimal_updater_wheel(),
        "source-archive.tar.gz": b"test-source-archive\n",
        "release-notes.md": b"# test release notes\n",
        "known-limitations.md": b"# test known limitations\n",
        "public-export.json": b'{"formatVersion":"stateport.public-export-manifest/v1"}\n',
    }.items():
        path = operator / name
        path.write_bytes(content)
        files[name] = path
    public_manifest_sha = hashlib.sha256(files["public-export.json"].read_bytes()).hexdigest()
    source_archive_sha = hashlib.sha256(files["source-archive.tar.gz"].read_bytes()).hexdigest()

    candidate = tmp_path / "candidate.yaml"
    candidate.write_text(
        yaml.safe_dump(
            {
                "schema": "stateport.candidate-provenance/v1",
                "candidateId": "stateport-public-candidate-test",
                "materialization": {
                    "sourceRepository": "https://github.com/lennertvhoy/StatePort.git",
                    "sourceCommit": COMMIT,
                    "sourceTree": TREE,
                },
                "repository": {"commit": PUBLIC_COMMIT, "tree": PUBLIC_TREE},
                "artifacts": {
                    "publicManifest": {"sha256": public_manifest_sha},
                    "auditedSourceArchive": {"sha256": source_archive_sha},
                },
            }
        ),
        encoding="utf-8",
    )

    evidence = tmp_path / "evidence"
    evidence.mkdir(mode=0o700)
    bundles = tmp_path / "bundles"
    bundles.mkdir(mode=0o700)
    archives = tmp_path / "archives"
    archives.mkdir(mode=0o700)
    for image_id in IMAGES:
        digest = _image_digest(image_id)
        _write_oci_archive(archives / f"{image_id}.oci.tar", image_id)
        artifacts: dict[str, str] = {}
        for suffix in (
            "cdx.json",
            "spdx.json",
            "syft.json",
            "grype.json",
            "licenses.json",
            "double-build.json",
            "grype-db.json",
            "provenance.json",
            "healthcheck.json",
        ):
            path = evidence / f"{image_id}.{suffix}"
            if suffix == "healthcheck.json":
                path.write_text(
                    json.dumps(
                        {
                            "formatVersion": "stateport.release-image-healthcheck/v1",
                            "imageId": image_id,
                            "probeObservation": {"executed": True, "exitCode": 1},
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
            else:
                path.write_text(
                    json.dumps({"testArtifact": suffix, "imageId": image_id}) + "\n",
                    encoding="utf-8",
                )
            if suffix != "healthcheck.json":
                artifacts[path.name] = sha256_file(path)
        manifest = {
            "formatVersion": "stateport.release-image-evidence/v1",
            "imageId": image_id,
            "imageReference": f"127.0.0.1:5000/stateport-alpha/{image_id}@{digest}",
            "buildReceiptDigest": "sha256:" + "0" * 64,
            "candidate": {
                "candidateId": "stateport-public-candidate-test",
                "sourceRepository": "https://github.com/lennertvhoy/StatePort.git",
                "sourceCommit": COMMIT,
                "sourceTree": TREE,
                "publicSnapshotCommit": PUBLIC_COMMIT,
                "publicSnapshotTree": PUBLIC_TREE,
                "publicExportManifestDigest": "sha256:" + public_manifest_sha,
            },
            "tools": tool_records,
            "grypeDatabase": {
                "builtAt": built_at,
                "observedAt": observed_at,
                "databaseObservedAt": observed_at,
                "ageHours": 1.0,
                "maximumAgeHours": 24,
                "normalMaximumAgeHours": 24,
                "latestAvailableMaximumAgeHours": 48,
                "latestDatabaseCheckMaxAgeMinutes": 15,
                "freshnessClass": "fresh",
                "latestDatabaseCheck": {
                    "exitCode": 0,
                    "meaning": "up-to-date-no-newer-database",
                    "observedAt": observed_at,
                },
                "updateAttempted": True,
                "valid": True,
            },
            "scanPolicy": {
                "threshold": "high",
                "unfixedFindingsIncluded": True,
                "result": "passed",
                "exceptionsFile": "config/release-scan-exceptions.v1.yaml",
                "exceptionsDigest": "sha256:"
                + hashlib.sha256(
                    (ROOT / "config/release-scan-exceptions.v1.yaml").read_bytes()
                ).hexdigest(),
                "appliedExceptionIds": [],
                "unexplainedFindings": [],
            },
            "artifacts": artifacts,
            "signature": {
                "status": "pending_owner_trust_root",
                "publicTransparencyLogUpload": False,
                "privateVerification": "pinned-public-key-fingerprint-and-key-id",
            },
            "doubleBuild": {
                "formatVersion": "stateport.double-build-comparison/v1",
                "imageId": image_id,
                "first": {"digest": digest},
                "second": {"digest": digest},
                "reproducible": True,
            },
        }
        (evidence / f"{image_id}.evidence.json").write_text(
            json.dumps(manifest) + "\n", encoding="utf-8"
        )
        (bundles / f"{image_id}.sigstore.json").write_text(
            json.dumps(
                {
                    "mediaType": BUNDLE_MEDIA_TYPE,
                    "verificationMaterial": {"publicKey": {"hint": "dGVzdA=="}},
                    "messageSignature": {
                        "messageDigest": {"algorithm": "SHA2_256", "digest": "dGVzdA=="},
                        "signature": "dGVzdA==",
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )

    receipt = tmp_path / "build-receipt.json"
    receipt.write_text(
        json.dumps(
            {
                "formatVersion": "stateport.release-image-build-receipt/v1",
                "identity": {
                    "commit": COMMIT,
                    "tree": TREE,
                    "version": "0.2.0-rc.1",
                    "created": observed_at,
                    "source_date_epoch": 1785578400,
                },
                "builder": {"version": "5.8.4"},
                "images": {
                    image_id: {
                        "acceptedReference": (
                            f"127.0.0.1:5000/stateport-alpha/{image_id}@{_image_digest(image_id)}"
                        ),
                        "releaseAuthority": {
                            "kind": "retained-oci-archive",
                            "sizeBytes": 1048576,
                            "manifestDigest": _image_digest(image_id),
                            "path": f"archives/{image_id}.oci.tar",
                        },
                    }
                    for image_id in IMAGES
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    topology = tmp_path / "topology.yaml"
    topology.write_text(
        yaml.safe_dump(
            {
                "formatVersion": "stateport.release-topology/v1",
                "targets": [
                    {
                        "targetId": "linux-amd64-rootless-podman-quadlet",
                        "executionHostMode": "stable-host-daemon-client",
                        "executionContract": _execution_contract(),
                        "hostServices": [_execution_host_service()],
                        "sharedWritableVolumes": [
                            {
                                "volumeKey": "stateport-shared:stateport-operations",
                                "volumeName": "stateport-operations",
                                "members": ["stateport-api", "stateport-worker"],
                                "writerCoordination": "sqlite-immediate-and-posix-advisory-locks",
                            }
                        ],
                        "runtimeDerivation": _runtime_derivation(),
                        "services": [
                            _service(
                                "stateport-web",
                                "stateport-data",
                                "/var/lib/stateport",
                                control_contract="narrow-unix-client",
                            ),
                            _service(
                                "stateport-api",
                                "stateport-operations",
                                "/workspace/.stateport",
                            ),
                            _service(
                                "stateport-worker",
                                "stateport-operations",
                                "/workspace/.stateport",
                            ),
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return {
        "receipt": receipt,
        "candidate": candidate,
        "evidence": evidence,
        "bundles": bundles,
        "topology": topology,
        "expires_at": expires_at,
        "qualification_at": _timestamp(now),
        "clock_anchor": now,
        "installer": files["installer"],
        "execution_host_provisioner": files["execution-host-provisioner"],
        "updater": files["updater"],
        "source_archive": files["source-archive.tar.gz"],
        "release_notes": files["release-notes.md"],
        "known_limitations": files["known-limitations.md"],
        "public_export_manifest": files["public-export.json"],
    }


def _request(
    inputs: dict[str, object],
    trust_root: dict[str, object],
    output: Path,
    **changes: object,
) -> assembler.AssemblyRequest:
    values: dict[str, object] = {
        "build_receipt": inputs["receipt"],
        "evidence_dir": inputs["evidence"],
        "candidate_provenance": inputs["candidate"],
        "topology": inputs["topology"],
        "release_id": "stateport-alpha-0.2.0-rc.1",
        "version": "0.2.0-rc.1",
        "channel": "alpha",
        "qualification": "candidate",
        "image_repository": "ghcr.io/stateport/stateport-alpha",
        "public_snapshot_repository": "https://github.com/stateport/stateport-public.git",
        "updater_minimum_version": "0.1.1",
        "schema_migration_version": 1,
        "database_migration_version": 1,
        "predecessor_index": None,
        "rollback_supported": False,
        "rollback_minimum_version": None,
        "rollback_data_compatible": False,
        "rollback_reason": "Alpha predecessor remains retained and data compatible.",
        "installer": inputs["installer"],
        "execution_host_provisioner": inputs["execution_host_provisioner"],
        "updater": inputs["updater"],
        "source_archive": inputs["source_archive"],
        "release_notes": inputs["release_notes"],
        "known_limitations": inputs["known_limitations"],
        "public_export_manifest": inputs["public_export_manifest"],
        "expires_at": inputs["expires_at"],
        "trust_public_key": trust_root["public"],
        "trust_key_id": trust_root["key_id"],
        "trust_key_fingerprint": trust_root["fingerprint"],
        "image_bundle_dir": inputs["bundles"],
        "output_root": output,
        "qualification_at": inputs["qualification_at"],
    }
    values.update(changes)
    return assembler.AssemblyRequest(**values)  # type: ignore[arg-type]


def _proof(signature: object) -> SignatureVerificationProof:
    descriptor = dict(signature)  # type: ignore[arg-type]
    return SignatureVerificationProof(
        subject_digest=str(descriptor["subjectDigest"]),
        bundle_digest=str(descriptor["bundle"]["digest"]),
        trust_mode=str(descriptor["trustMode"]),
        identity_primary=str(descriptor["publicKeyFingerprint"]),
        identity_secondary=str(descriptor["publicKeyId"]),
        verified_at=datetime.now(timezone.utc),
        transparency_log_mode=str(descriptor["transparencyLog"]),
    )


class _RegistryDeferredVerifier:
    """Test seam: real Cosign for the payload blob; registry image signature
    verification requires a live registry and is exercised by the operator run,
    not by offline fixtures."""

    def __init__(self, delegate: CosignVerifier) -> None:
        self._delegate = delegate
        self.image_references: list[str] = []
        self.image_manifest_payloads: list[bytes] = []

    def verify_blob(self, payload: bytes, signature: object) -> SignatureVerificationProof:
        self.image_manifest_payloads.append(payload)
        return _proof(signature)

    def retain_bundle(self, source: Path, signature: object) -> Path:
        return self._delegate.retain_bundle(source, signature)  # type: ignore[arg-type]

    def verify_image(self, reference: str, signature: object) -> SignatureVerificationProof:
        descriptor = dict(signature)  # type: ignore[arg-type]
        assert reference.endswith(str(descriptor["subjectDigest"]))
        self.image_references.append(reference)
        return _proof(signature)


def _policy(identity: PinnedPublicKeyIdentity, **changes: object) -> ReleaseVerificationPolicy:
    values: dict[str, object] = {
        "expected_channel": "alpha",
        "expected_target": "linux-amd64-rootless-podman-quadlet",
        "updater_version": "0.1.1",
        "accepted_signers": frozenset(),
        "accepted_public_keys": frozenset({identity}),
        "expected_trust_mode": "pinned-public-key",
        # Inline Cosign proofs are created after the policy is built; allow
        # for their creation time without moving hour-scale freshness bounds.
        "now": datetime.now(timezone.utc) + timedelta(seconds=60),
        "allow_candidate": True,
    }
    values.update(changes)
    return ReleaseVerificationPolicy(**values)  # type: ignore[arg-type]


def _verifier(
    trust_root: dict[str, object], bundle_root: Path, identity: PinnedPublicKeyIdentity
) -> _RegistryDeferredVerifier:
    return _RegistryDeferredVerifier(
        CosignVerifier(
            cosign=COSIGN,
            public_key=trust_root["public"],  # type: ignore[arg-type]
            identity=identity,
            bundle_root=bundle_root,
        )
    )


def _image_verifier(
    trust_root: dict[str, object], candidate: Path
) -> _RegistryDeferredVerifier:
    return _verifier(trust_root, candidate.parent, _identity(trust_root))


def _identity(trust_root: dict[str, object]) -> PinnedPublicKeyIdentity:
    return PinnedPublicKeyIdentity(str(trust_root["fingerprint"]), str(trust_root["key_id"]))


def _assemble_and_sign(
    tmp_path: Path, trust_root: dict[str, object]
) -> tuple[dict[str, object], Path]:
    inputs = _build_inputs(tmp_path)
    output = tmp_path / "release"
    result = assembler.assemble(_request(inputs, trust_root, output))
    candidate = Path(str(result["candidate"]))
    image_verifier = _image_verifier(trust_root, candidate)
    with _assembler_clock(inputs["clock_anchor"]):  # type: ignore[arg-type]
            signed = assembler.sign(
                candidate=candidate,
                build_receipt=inputs["receipt"],  # type: ignore[arg-type]
            signing_key=trust_root["private"],  # type: ignore[arg-type]
            trust_public_key=trust_root["public"],  # type: ignore[arg-type]
            trust_key_id=str(trust_root["key_id"]),
            trust_key_fingerprint=str(trust_root["fingerprint"]),
            image_verifier=image_verifier,
        )
    assert len(image_verifier.image_manifest_payloads) == len(IMAGES)
    return inputs, Path(str(signed["releaseIndex"]))


def test_assembled_candidate_is_schema_valid(tmp_path: Path, trust_root: dict[str, object]) -> None:
    inputs = _build_inputs(tmp_path)
    result = assembler.assemble(_request(inputs, trust_root, tmp_path / "release"))
    candidate = Path(str(result["candidate"]))
    index = load_release_index_file(candidate, require_signatures=False)
    schema = json.loads((ROOT / "schemas/release-index.v1.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(json.loads(candidate.read_text()))
    signed = index.document["signed"]
    assert signed["release"]["qualification"] == "candidate"
    assert not index.document["signatures"]
    for image in signed["images"]:
        assert "@sha256:" in str(image["reference"])
        assert image["signature"]["transparencyLog"] == "not-uploaded-private-candidate"
        assert image["signature"]["publicKeyFingerprint"] == trust_root["fingerprint"]
    target = signed["targets"][0]
    assert target["sharedWritableVolumes"] == (
        {
            "volumeKey": "stateport-shared:stateport-operations",
            "volumeName": "stateport-operations",
            "members": ("stateport-api", "stateport-worker"),
            "writerCoordination": "sqlite-immediate-and-posix-advisory-locks",
        },
    )
    assert list(target["artifactIds"]) == sorted(signed["artifacts"])
    quadlet_dir = candidate.parent / "quadlet" / str(target["targetId"])
    assert quadlet_dir.is_dir() and any(quadlet_dir.iterdir())
    compose = (candidate.parent / "compose.release.yaml").read_text()
    assert ":latest" not in compose and compose.count("@sha256:") == 3
    api = next(
        path.read_text(encoding="utf-8")
        for path in quadlet_dir.rglob("*.container.in")
        if "stateport-api" in path.name and "accepted" in path.name
    )
    worker = next(
        path.read_text(encoding="utf-8")
        for path in quadlet_dir.rglob("*.container.in")
        if "stateport-worker" in path.name and "accepted" in path.name
    )
    shared_token = "@@STATEPORT_ACCEPTED_DATA_VOLUME:stateport-shared:stateport-operations@@"
    assert shared_token in api and shared_token in worker


def test_assembled_index_matches_every_packaged_consumer_schema(
    tmp_path: Path, trust_root: dict[str, object]
) -> None:
    inputs = _build_inputs(tmp_path)
    request = _request(inputs, trust_root, tmp_path / "release")
    result = assembler.assemble(request)
    candidate = Path(str(result["candidate"]))
    document = json.loads(candidate.read_text(encoding="utf-8"))
    root_schema = json.loads((ROOT / "schemas/release-index.v1.schema.json").read_text())
    package_schema_path = (
        ROOT / "packages/release-contracts/src/stateport_release/schemas/release-index.v1.schema.json"
    )
    package_schema = json.loads(package_schema_path.read_text())
    assert package_schema_path.read_bytes() == (ROOT / "schemas/release-index.v1.schema.json").read_bytes()
    jsonschema.Draft202012Validator(root_schema).validate(document)
    jsonschema.Draft202012Validator(package_schema).validate(document)
    with zipfile.ZipFile(request.updater) as archive:  # type: ignore[arg-type]
        embedded = json.loads(
            archive.read("stateport_release/schemas/release-index.v1.schema.json")
        )
    assert embedded == root_schema
    load_release_index_file(candidate, require_signatures=False)


def test_assembly_rejects_a_proposed_index_the_packaged_consumer_rejects(
    tmp_path: Path, trust_root: dict[str, object]
) -> None:
    inputs = _build_inputs(tmp_path)
    result = assembler.assemble(_request(inputs, trust_root, tmp_path / "release"))
    document = json.loads(Path(str(result["candidate"])).read_text(encoding="utf-8"))
    document["signed"]["images"][0]["scan"]["databaseObservedAt"] = "2026-08-01T08:30:00Z"
    wheel = tmp_path / "updater.whl"
    wheel.write_bytes(_minimal_updater_wheel())
    with pytest.raises(assembler.AssemblyError, match="packaged release consumer"):
        assembler._validate_packaged_consumer(
            json.dumps(document, separators=(",", ":")).encode(), wheel
        )


def test_evidence_digest_mismatch_is_refused_before_assembly(
    tmp_path: Path, trust_root: dict[str, object]
) -> None:
    inputs = _build_inputs(tmp_path)
    evidence_path = inputs["evidence"] / "stateport-api.evidence.json"  # type: ignore[operator]
    document = json.loads(evidence_path.read_text(encoding="utf-8"))
    document["imageReference"] = document["imageReference"].rsplit("@", 1)[0] + "@sha256:" + "0" * 64
    evidence_path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(assembler.AssemblyError, match="digests disagree"):
        assembler.assemble(_request(inputs, trust_root, tmp_path / "release"))


def test_topology_parse_failure_has_line_and_column_before_receipt_loading(
    tmp_path: Path, trust_root: dict[str, object]
) -> None:
    inputs = _build_inputs(tmp_path)
    topology = Path(str(inputs["topology"]))
    topology.write_text("targets:\n  - targetId: [\n", encoding="utf-8")
    with pytest.raises(assembler.AssemblyError, match=r"line 3, column"):
        assembler.assemble(_request(inputs, trust_root, tmp_path / "release"))


def test_v1_candidate_projection_remains_unchanged_and_v2_is_preserved(
    tmp_path: Path, trust_root: dict[str, object]
) -> None:
    inputs = _build_inputs(tmp_path)
    v1 = assembler._load_candidate(Path(str(inputs["candidate"])))
    assert v1["schema"] == "stateport.candidate-provenance/v1"
    assert "candidateProvenance" not in v1

    from test_public_release_bundle import _successor_contract

    v2_root = tmp_path / "v2"
    v2_root.mkdir()
    v2_path = tmp_path / "candidate-v2.yaml"
    v2_document = _successor_contract(v2_root)
    v2_path.write_text(yaml.safe_dump(v2_document, sort_keys=True), encoding="utf-8")
    v2 = assembler._load_candidate(v2_path)
    assert v2["schema"] == "stateport.candidate-provenance/v2"
    assert v2["publicAuthorityUrl"] == v2_document["repository"]["authorityUrl"]
    assert v2["publicRef"] == v2_document["repository"]["ref"]
    assert v2["candidateProvenance"] == v2_document
    assert v2["candidateProvenanceDigest"] == canonical_digest(v2_document)

    tampered = dict(v2_document)
    tampered["repository"] = {**tampered["repository"], "authorityUrl": "not-a-url"}
    v2_path.write_text(yaml.safe_dump(tampered, sort_keys=True), encoding="utf-8")
    with pytest.raises(assembler.AssemblyError, match="schema validation"):
        assembler._load_candidate(v2_path)


def test_v2_authority_mismatch_is_refused_before_assembly(
    tmp_path: Path, trust_root: dict[str, object]
) -> None:
    inputs = _build_inputs(tmp_path)
    from test_public_release_bundle import _successor_contract

    v2_root = tmp_path / "v2"
    v2_root.mkdir()
    v2_path = tmp_path / "candidate-v2.yaml"
    v2_document = _successor_contract(v2_root)
    v2_path.write_text(yaml.safe_dump(v2_document, sort_keys=True), encoding="utf-8")
    request = _request(
        inputs,
        trust_root,
        tmp_path / "release",
        candidate_provenance=v2_path,
        public_snapshot_repository="https://example.invalid/different.git",
    )
    with pytest.raises(assembler.AssemblyError, match="disagrees with v2 candidate authority"):
        assembler.assemble(request)


def test_private_image_signing_contract_uses_only_local_manifest_blob(
    tmp_path: Path, trust_root: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _build_inputs(tmp_path)
    request = _request(
        inputs,
        trust_root,
        tmp_path / "release",
    )
    output = tmp_path / "signed-images"
    output.mkdir(mode=0o700)
    calls: list[list[str]] = []

    def fake_run(arguments: list[str], **_kwargs: object) -> object:
        calls.append(arguments)
        Path(arguments[arguments.index("--bundle") + 1]).write_text(
            json.dumps({"mediaType": BUNDLE_MEDIA_TYPE}), encoding="utf-8"
        )
        return type("Completed", (), {"returncode": 0, "stderr": ""})()

    monkeypatch.setattr(assembler.subprocess, "run", fake_run)
    assembler._sign_images(
        build_receipt=request.build_receipt,
        signing_key=trust_root["private"],  # type: ignore[arg-type]
        receipt=json.loads(Path(str(inputs["receipt"])).read_text()),
        output=output,
        cosign="/pinned/cosign",
    )
    assert calls
    assert all(command[1] == "sign-blob" for command in calls)
    assert all("ghcr.io" not in " ".join(command) for command in calls)
    assert all(command[-1].endswith(".oci-manifest.json") for command in calls)
    assert '"sign",' not in inspect.getsource(assembler._sign_images)


def test_sign_and_verify_roundtrip(tmp_path: Path, trust_root: dict[str, object]) -> None:
    inputs, index_path = _assemble_and_sign(tmp_path, trust_root)
    identity = _identity(trust_root)
    with _assembler_clock(inputs["clock_anchor"]):  # type: ignore[arg-type]
        result = assembler.verify(
            index_path=index_path,
            request=_request(inputs, trust_root, tmp_path / "unused"),
            expected_channel="alpha",
            updater_version="0.1.1",
            expected_target=None,
            trust_public_key=trust_root["public"],  # type: ignore[arg-type]
            trust_key_id=str(trust_root["key_id"]),
            trust_key_fingerprint=str(trust_root["fingerprint"]),
            bundle_root=index_path.parent,
            verifier=_verifier(trust_root, index_path.parent, identity),
        )
    assert result["rederivation"] == "matched-recorded-inputs"
    assert len(result["verificationProofs"]) == len(IMAGES) + 1


def test_tampered_signed_field_refused(tmp_path: Path, trust_root: dict[str, object]) -> None:
    _, index_path = _assemble_and_sign(tmp_path, trust_root)
    document = json.loads(index_path.read_text())
    document["signed"]["release"]["version"] = "0.2.0-rc.2"
    with pytest.raises(ReleaseContractError, match="canonical signed payload"):
        validate_release_index(document)
    tampered_dir = tmp_path / "tampered"
    tampered_dir.mkdir(mode=0o700)
    tampered = tampered_dir / "release-index.json"
    tampered.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ReleaseContractError):
        load_release_index_file(tampered)


def test_wrong_key_refused(tmp_path: Path, trust_root: dict[str, object]) -> None:
    _, index_path = _assemble_and_sign(tmp_path, trust_root)
    subprocess.run(
        [str(COSIGN), "generate-key-pair", "--output-key-prefix", "other"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    other_public = tmp_path / "other.pub"
    other_identity = PinnedPublicKeyIdentity(
        public_key_der_spki_fingerprint(other_public), "stateport-alpha-test-other"
    )
    index = load_release_index_file(index_path)
    with pytest.raises(ReleaseContractError, match="untrusted signer"):
        verify_release_index(
            index,
            policy=_policy(other_identity),
            verifier=_verifier(trust_root, index_path.parent, _identity(trust_root)),
        )
    wrong_key_verifier = CosignVerifier(
        cosign=COSIGN,
        public_key=other_public,
        identity=other_identity,
        bundle_root=index_path.parent,
    )
    with pytest.raises(CosignVerificationError):
        wrong_key_verifier.verify_blob(index.signed_bytes, index.document["signatures"][0])


def test_floating_tag_refused(tmp_path: Path, trust_root: dict[str, object]) -> None:
    inputs = _build_inputs(tmp_path)
    manifest_path = Path(str(inputs["evidence"])) / "stateport-web.evidence.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["imageReference"] = "127.0.0.1:5000/stateport-alpha/stateport-web:0.2.0-alpha.1"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(assembler.AssemblyError, match="reference"):
        assembler.assemble(_request(inputs, trust_root, tmp_path / "release"))
    inputs = _build_inputs(tmp_path / "second")
    with pytest.raises(assembler.AssemblyError, match="digest-bound"):
        assembler.assemble(
            _request(
                inputs,
                trust_root,
                tmp_path / "second" / "release",
                image_repository="ghcr.io/stateport/stateport-alpha:latest",
            )
        )


def test_missing_evidence_refused(tmp_path: Path, trust_root: dict[str, object]) -> None:
    inputs = _build_inputs(tmp_path)
    (Path(str(inputs["evidence"])) / "stateport-worker.evidence.json").unlink()
    with pytest.raises(assembler.AssemblyError, match="evidence is missing"):
        assembler.assemble(_request(inputs, trust_root, tmp_path / "release"))

    inputs = _build_inputs(tmp_path / "second")
    (Path(str(inputs["evidence"])) / "stateport-api.healthcheck.json").unlink()
    with pytest.raises(assembler.AssemblyError, match="health probe evidence is missing"):
        assembler.assemble(_request(inputs, trust_root, tmp_path / "second" / "release"))

    inputs = _build_inputs(tmp_path / "third")
    drifted = Path(str(inputs["evidence"])) / "stateport-web.cdx.json"
    drifted.write_text('{"tampered": true}\n', encoding="utf-8")
    with pytest.raises(assembler.AssemblyError, match="drifted"):
        assembler.assemble(_request(inputs, trust_root, tmp_path / "third" / "release"))


def test_unexecuted_health_probe_refused(tmp_path: Path, trust_root: dict[str, object]) -> None:
    inputs = _build_inputs(tmp_path)
    probe_path = Path(str(inputs["evidence"])) / "stateport-api.healthcheck.json"
    probe_path.write_text(
        json.dumps(
            {
                "formatVersion": "stateport.release-image-healthcheck/v1",
                "imageId": "stateport-api",
                "probeObservation": {"executed": False, "exitCode": 127},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(assembler.AssemblyError, match="did not verifiably execute"):
        assembler.assemble(_request(inputs, trust_root, tmp_path / "release"))


def test_der_spki_fingerprint_is_distinct_and_enforced(
    tmp_path: Path, trust_root: dict[str, object]
) -> None:
    public = Path(str(trust_root["public"]))
    der_fingerprint = public_key_der_spki_fingerprint(public)
    pem_fingerprint = sha256_file(public)
    assert der_fingerprint != pem_fingerprint
    inputs = _build_inputs(tmp_path)
    with pytest.raises(assembler.AssemblyError, match="DER SubjectPublicKeyInfo"):
        assembler.assemble(
            _request(
                inputs,
                trust_root,
                tmp_path / "release",
                trust_key_fingerprint=pem_fingerprint,
            )
        )
    result = assembler.assemble(
        _request(
            inputs,
            trust_root,
            tmp_path / "release-der",
            trust_key_fingerprint=der_fingerprint,
        )
    )
    assert result["signedPayloadDigest"].startswith("sha256:")


def test_signing_key_must_derive_pinned_trust_public_key(
    tmp_path: Path, trust_root: dict[str, object]
) -> None:
    inputs = _build_inputs(tmp_path)
    result = assembler.assemble(_request(inputs, trust_root, tmp_path / "release"))
    other_root = tmp_path / "other-key"
    other_root.mkdir(mode=0o700)
    subprocess.run(
        [str(COSIGN), "generate-key-pair", "--output-key-prefix", "other"],
        cwd=other_root,
        check=True,
        capture_output=True,
        env={**os.environ, "COSIGN_PASSWORD": "test-ephemeral-non-release"},
    )
    with pytest.raises(assembler.AssemblyError, match="does not derive"):
        with _assembler_clock(inputs["clock_anchor"]):  # type: ignore[arg-type]
                assembler.sign(
                    candidate=Path(str(result["candidate"])),
                    build_receipt=inputs["receipt"],  # type: ignore[arg-type]
                signing_key=other_root / "other.key",
                trust_public_key=trust_root["public"],  # type: ignore[arg-type]
                trust_key_id=str(trust_root["key_id"]),
                trust_key_fingerprint=str(trust_root["fingerprint"]),
                image_verifier=_image_verifier(trust_root, Path(str(result["candidate"]))),
            )


def test_signing_rejects_already_expired_expires_at(
    tmp_path: Path, trust_root: dict[str, object]
) -> None:
    inputs = _build_inputs(tmp_path)
    result = assembler.assemble(
        _request(
            inputs,
            trust_root,
            tmp_path / "release",
            expires_at="2020-01-01T00:00:00Z",
        )
    )
    candidate = Path(str(result["candidate"]))
    with pytest.raises(assembler.AssemblyError, match="expiresAt is already expired"):
        with _assembler_clock(inputs["clock_anchor"]):  # type: ignore[arg-type]
                assembler.sign(
                    candidate=candidate,
                    build_receipt=inputs["receipt"],  # type: ignore[arg-type]
                signing_key=trust_root["private"],  # type: ignore[arg-type]
                trust_public_key=trust_root["public"],  # type: ignore[arg-type]
                trust_key_id=str(trust_root["key_id"]),
                trust_key_fingerprint=str(trust_root["fingerprint"]),
                image_verifier=_image_verifier(trust_root, candidate),
            )


def test_sign_refuses_evidence_stale_at_signing_after_fresh_qualification(
    tmp_path: Path, trust_root: dict[str, object]
) -> None:
    qualified_at = datetime(2026, 8, 9, 12, tzinfo=timezone.utc)
    inputs = _build_inputs(tmp_path, fixture_anchor=qualified_at)
    result = assembler.assemble(_request(inputs, trust_root, tmp_path / "release"))
    candidate = Path(str(result["candidate"]))
    signing_at = qualified_at + timedelta(hours=25)

    with pytest.raises(assembler.AssemblyError, match="Grype database is stale"):
        with _assembler_clock(signing_at):
                assembler.sign(
                    candidate=candidate,
                    build_receipt=inputs["receipt"],  # type: ignore[arg-type]
                signing_key=trust_root["private"],  # type: ignore[arg-type]
                trust_public_key=trust_root["public"],  # type: ignore[arg-type]
                trust_key_id=str(trust_root["key_id"]),
                trust_key_fingerprint=str(trust_root["fingerprint"]),
                image_verifier=_image_verifier(trust_root, candidate),
            )


def test_canonical_bytes_are_stable_and_newline_free(
    tmp_path: Path, trust_root: dict[str, object]
) -> None:
    first_inputs = _build_inputs(tmp_path / "first")
    second_inputs = _build_inputs(tmp_path / "second", fixture_anchor=first_inputs["clock_anchor"])  # type: ignore[arg-type]
    first = assembler.assemble(_request(first_inputs, trust_root, tmp_path / "first" / "release"))
    second = assembler.assemble(
        _request(second_inputs, trust_root, tmp_path / "second" / "release")
    )
    assert first["signedPayloadDigest"] == second["signedPayloadDigest"]
    index = load_release_index_file(Path(str(first["candidate"])), require_signatures=False)
    assert not index.signed_bytes.endswith(b"\n")
    assert index.signed_bytes == canonical_json_bytes(json.loads(index.signed_bytes))
    assert b": " not in index.signed_bytes


def test_source_mismatch_refused(tmp_path: Path, trust_root: dict[str, object]) -> None:
    inputs = _build_inputs(tmp_path)
    candidate = Path(str(inputs["candidate"]))
    provenance = yaml.safe_load(candidate.read_text())
    provenance["materialization"]["sourceCommit"] = "0" * 40
    candidate.write_text(yaml.safe_dump(provenance), encoding="utf-8")
    with pytest.raises(assembler.AssemblyError, match="candidate provenance"):
        assembler.assemble(_request(inputs, trust_root, tmp_path / "release"))


def test_published_qualification_refused(tmp_path: Path, trust_root: dict[str, object]) -> None:
    inputs = _build_inputs(tmp_path)
    with pytest.raises(assembler.AssemblyError, match="transparency-log"):
        assembler.assemble(
            _request(inputs, trust_root, tmp_path / "release", qualification="published")
        )


def test_image_signatures_without_registry_are_deferred_not_faked(
    tmp_path: Path, trust_root: dict[str, object]
) -> None:
    inputs = _build_inputs(tmp_path)
    with pytest.raises(assembler.AssemblyError, match="separate, completed image-signing"):
        assembler.assemble(
            _request(inputs, trust_root, tmp_path / "release", image_bundle_dir=None)
        )


def test_successor_semantics_emit_signed_qualification_and_disposition(
    tmp_path: Path, trust_root: dict[str, object]
) -> None:
    inputs = _build_inputs(tmp_path)
    result = assembler.assemble(
        _request(inputs, trust_root, tmp_path / "release")
    )
    index = load_release_index_file(Path(str(result["candidate"])), require_signatures=False)
    schema = json.loads((ROOT / "schemas/release-index.v1.schema.json").read_text())
    jsonschema.Draft202012Validator(schema).validate(json.loads(index.canonical_index_bytes))
    successor = index.document["signed"]["successor"]
    assert successor["formatVersion"] == "stateport.release-successor/v1"
    assert successor["freshnessEnforcement"] == "qualification-and-signing-time"
    assert successor["qualificationEvent"]["result"] == "qualified"
    assert successor["disposition"]["sequence"] == 1
    assert successor["disposition"]["signedBy"] == "stateport.release-index/v1"
    assert successor["versionBindings"]["buildReceiptVersion"] == "0.2.0-rc.1"


def test_successor_semantics_cannot_be_disabled_for_assembly(
    tmp_path: Path, trust_root: dict[str, object]
) -> None:
    inputs = _build_inputs(tmp_path)
    with pytest.raises(assembler.AssemblyError, match="requires the explicitly versioned"):
        assembler.assemble(
            _request(inputs, trust_root, tmp_path / "release", successor_semantics=False)
        )


def test_assembly_requires_explicit_qualification_input(
    tmp_path: Path, trust_root: dict[str, object]
) -> None:
    inputs = _build_inputs(tmp_path)
    with pytest.raises(assembler.AssemblyError, match="explicit qualification time or event"):
        assembler.assemble(
            _request(inputs, trust_root, tmp_path / "release", qualification_at=None)
        )


def test_genesis_successor_requires_sequence_one(
    tmp_path: Path, trust_root: dict[str, object]
) -> None:
    inputs = _build_inputs(tmp_path)
    result = assembler.assemble(_request(inputs, trust_root, tmp_path / "release"))
    candidate = Path(str(result["candidate"]))
    document = json.loads(candidate.read_text())
    document["signed"]["successor"]["disposition"]["sequence"] = 2
    with pytest.raises(ReleaseContractError, match="genesis successor disposition"):
        assembler.validate_release_index(document, require_signatures=False)


def test_sign_refuses_future_qualification_and_nonmonotonic_genesis_disposition(
    tmp_path: Path, trust_root: dict[str, object]
) -> None:
    inputs = _build_inputs(tmp_path)
    result = assembler.assemble(_request(inputs, trust_root, tmp_path / "release"))
    candidate = Path(str(result["candidate"]))
    document = json.loads(candidate.read_text())
    event = document["signed"]["successor"]["qualificationEvent"]
    event["qualifiedAt"] = _timestamp(inputs["clock_anchor"] + timedelta(minutes=10))  # type: ignore[operator]
    event["eventId"] = assembler.canonical_digest(
        {key: value for key, value in event.items() if key != "eventId"}
    )
    candidate.write_bytes(assembler.canonical_json_bytes(document) + b"\n")
    with pytest.raises(assembler.AssemblyError, match="future at signing"):
        with _assembler_clock(inputs["clock_anchor"]):  # type: ignore[arg-type]
                assembler.sign(
                    candidate=candidate,
                    build_receipt=inputs["receipt"],  # type: ignore[arg-type]
                signing_key=trust_root["private"],  # type: ignore[arg-type]
                trust_public_key=trust_root["public"],  # type: ignore[arg-type]
                trust_key_id=str(trust_root["key_id"]),
                trust_key_fingerprint=str(trust_root["fingerprint"]),
                image_verifier=_image_verifier(trust_root, candidate),
            )

    inputs = _build_inputs(tmp_path / "sequence")
    result = assembler.assemble(_request(inputs, trust_root, tmp_path / "sequence" / "release"))
    candidate = Path(str(result["candidate"]))
    document = json.loads(candidate.read_text())
    document["signed"]["successor"]["disposition"]["sequence"] = 2
    candidate.write_bytes(assembler.canonical_json_bytes(document) + b"\n")
    with pytest.raises(ReleaseContractError, match="genesis successor"):
        with _assembler_clock(inputs["clock_anchor"]):  # type: ignore[arg-type]
                assembler.sign(
                    candidate=candidate,
                    build_receipt=inputs["receipt"],  # type: ignore[arg-type]
                signing_key=trust_root["private"],  # type: ignore[arg-type]
                trust_public_key=trust_root["public"],  # type: ignore[arg-type]
                trust_key_id=str(trust_root["key_id"]),
                trust_key_fingerprint=str(trust_root["fingerprint"]),
                image_verifier=_image_verifier(trust_root, candidate),
            )


def test_qualification_event_reordering_is_canonical_and_duplicates_refused(
    tmp_path: Path, trust_root: dict[str, object]
) -> None:
    inputs = _build_inputs(tmp_path)
    result = assembler.assemble(_request(inputs, trust_root, tmp_path / "release"))
    index = load_release_index_file(Path(str(result["candidate"])), require_signatures=False)
    event = json.loads(index.canonical_index_bytes)["signed"]["successor"]["qualificationEvent"]
    reordered = json.loads(json.dumps(event))
    reordered["images"] = list(reversed(reordered["images"]))
    assert assembler._canonicalize_qualification_event(reordered) == event
    duplicate = json.loads(json.dumps(event))
    duplicate["images"].append(duplicate["images"][0])
    with pytest.raises(assembler.AssemblyError, match="unique"):
        assembler._canonicalize_qualification_event(duplicate)


def test_build_receipt_version_mismatch_is_refused(
    tmp_path: Path, trust_root: dict[str, object]
) -> None:
    inputs = _build_inputs(tmp_path)
    receipt = Path(str(inputs["receipt"]))
    value = json.loads(receipt.read_text())
    value["identity"]["version"] = "0.2.0-alpha.1"
    receipt.write_text(json.dumps(value) + "\n", encoding="utf-8")
    with pytest.raises(assembler.AssemblyError, match="build receipt version"):
        assembler.assemble(_request(inputs, trust_root, tmp_path / "release"))


@pytest.mark.parametrize(
    ("wheel", "message"),
    [
        (_minimal_updater_wheel(name="unrelated-package"), "project name"),
        (_minimal_updater_wheel(version="0.1.0"), "minimum version"),
        (b"not-a-wheel", "metadata is unreadable"),
    ],
)
def test_updater_wheel_identity_is_exact(
    tmp_path: Path,
    trust_root: dict[str, object],
    wheel: bytes,
    message: str,
) -> None:
    inputs = _build_inputs(tmp_path)
    Path(str(inputs["updater"])).write_bytes(wheel)
    with pytest.raises(assembler.AssemblyError, match=message):
        assembler.assemble(_request(inputs, trust_root, tmp_path / "release"))


def test_predecessor_requires_explicit_successor_authentication(
    tmp_path: Path, trust_root: dict[str, object]
) -> None:
    inputs = _build_inputs(tmp_path)
    with pytest.raises(assembler.AssemblyError, match="explicitly versioned successor"):
        assembler.assemble(
            _request(
                inputs,
                trust_root,
                tmp_path / "release",
                predecessor_index=inputs["candidate"],
                successor_semantics=False,
            )
        )


def test_immutable_alpha3_predecessor_remains_schema_compatible() -> None:
    predecessor = (
        Path(__file__).resolve().parents[2]
        / "StatePort-Site"
        / "download"
        / "0.1.0-alpha.3"
        / "release-index.json"
    )
    if not predecessor.is_file():
        pytest.skip("immutable Alpha.3 predecessor checkout is unavailable")
    index = load_release_index_file(predecessor, legacy_predecessor=True)
    execution = index.document["signed"]["targets"][0]["executionContract"]
    assert "socketGroupGid" not in execution
    assert "userNamespace" not in index.document["signed"]["targets"][0]["hostServices"][0]
    forged = json.loads(index.canonical_index_bytes)
    forged["signed"]["source"]["commit"] = "0" * 40
    forged["signatures"][0]["subjectDigest"] = assembler.canonical_digest(forged["signed"])
    with pytest.raises(ReleaseContractError):
        validate_release_index(forged, legacy_predecessor=True)


def test_topology_preflight_rejects_duplicate_and_unknown_target_fields(
    tmp_path: Path, trust_root: dict[str, object]
) -> None:
    inputs = _build_inputs(tmp_path)
    topology = Path(str(inputs["topology"]))
    value = yaml.safe_load(topology.read_text(encoding="utf-8"))
    value["targets"].append(json.loads(json.dumps(value["targets"][0])))
    topology.write_text(yaml.safe_dump(value), encoding="utf-8")
    with pytest.raises(assembler.AssemblyError, match="duplicated"):
        assembler.assemble(_request(inputs, trust_root, tmp_path / "duplicate"))
    value["targets"] = value["targets"][:1]
    value["targets"][0]["unexpected"] = True
    topology.write_text(yaml.safe_dump(value), encoding="utf-8")
    with pytest.raises(assembler.AssemblyError, match="unknown fields"):
        assembler.assemble(_request(inputs, trust_root, tmp_path / "unknown"))


def test_rederivation_preserves_signed_qualification_event(
    tmp_path: Path, trust_root: dict[str, object]
) -> None:
    inputs = _build_inputs(tmp_path)
    request = _request(inputs, trust_root, tmp_path / "release", successor_semantics=True)
    result = assembler.assemble(request)
    index = load_release_index_file(Path(str(result["candidate"])), require_signatures=False)
    event = index.document["signed"]["successor"]["qualificationEvent"]
    output = tmp_path / "rederived"
    assembler.prepare_output_root(output, repository=assembler.ROOT)
    signed = assembler._assemble_signed(request, output, qualification_event=event)
    assert assembler.canonical_json_bytes(signed) == index.signed_bytes
    with _assembler_clock(inputs["clock_anchor"]):  # type: ignore[arg-type]
        signed_result = assembler.sign(
            candidate=Path(str(result["candidate"])),
            build_receipt=inputs["receipt"],  # type: ignore[arg-type]
            signing_key=trust_root["private"],  # type: ignore[arg-type]
            trust_public_key=trust_root["public"],  # type: ignore[arg-type]
            trust_key_id=str(trust_root["key_id"]),
            trust_key_fingerprint=str(trust_root["fingerprint"]),
            image_verifier=_image_verifier(trust_root, Path(str(result["candidate"]))),
        )
        verified = assembler.verify(
            index_path=Path(str(signed_result["releaseIndex"])),
            request=request,
            expected_channel="alpha",
            updater_version="0.1.1",
            expected_target=None,
            trust_public_key=trust_root["public"],  # type: ignore[arg-type]
            trust_key_id=str(trust_root["key_id"]),
            trust_key_fingerprint=str(trust_root["fingerprint"]),
            bundle_root=Path(str(signed_result["releaseIndex"])).parent,
            verifier=_verifier(trust_root, Path(str(signed_result["releaseIndex"])).parent, _identity(trust_root)),
        )
    assert verified["rederivation"] == "matched-recorded-inputs"


def test_sign_refuses_successor_when_authenticated_predecessor_bundle_is_removed(
    tmp_path: Path, trust_root: dict[str, object]
) -> None:
    predecessor_inputs = _build_inputs(tmp_path / "predecessor")
    predecessor_request = _request(
        predecessor_inputs, trust_root, tmp_path / "predecessor" / "release"
    )
    predecessor_candidate = assembler.assemble(predecessor_request)
    with _assembler_clock(predecessor_inputs["clock_anchor"]):  # type: ignore[arg-type]
        predecessor_signed = assembler.sign(
            candidate=Path(str(predecessor_candidate["candidate"])),
            build_receipt=predecessor_inputs["receipt"],  # type: ignore[arg-type]
            signing_key=trust_root["private"],  # type: ignore[arg-type]
            trust_public_key=trust_root["public"],  # type: ignore[arg-type]
            trust_key_id=str(trust_root["key_id"]),
            trust_key_fingerprint=str(trust_root["fingerprint"]),
            image_verifier=_image_verifier(trust_root, Path(str(predecessor_candidate["candidate"]))),
        )

    successor_inputs = _build_inputs(tmp_path / "successor")
    receipt = Path(str(successor_inputs["receipt"]))
    receipt_value = json.loads(receipt.read_text())
    receipt_value["identity"]["version"] = "0.3.0-rc.1"
    receipt.write_text(json.dumps(receipt_value) + "\n", encoding="utf-8")
    successor_request = _request(
        successor_inputs,
        trust_root,
        tmp_path / "successor" / "release",
        release_id="stateport-alpha-0.3.0-rc.1",
        version="0.3.0-rc.1",
        predecessor_index=Path(str(predecessor_signed["releaseIndex"])),
    )
    successor_candidate = assembler.assemble(successor_request)
    bundle = Path(str(successor_candidate["candidate"])).parent / "predecessor-bundle" / "release-index.sigstore.json"
    bundle.unlink()
    with pytest.raises(CosignVerificationError):
        with _assembler_clock(successor_inputs["clock_anchor"]):  # type: ignore[arg-type]
            assembler.sign(
                candidate=Path(str(successor_candidate["candidate"])),
                build_receipt=successor_inputs["receipt"],  # type: ignore[arg-type]
                signing_key=trust_root["private"],  # type: ignore[arg-type]
                trust_public_key=trust_root["public"],  # type: ignore[arg-type]
                trust_key_id=str(trust_root["key_id"]),
                trust_key_fingerprint=str(trust_root["fingerprint"]),
                image_verifier=_image_verifier(trust_root, Path(str(successor_candidate["candidate"]))),
            )
def test_canonical_topology_declares_one_separate_wsl2_target() -> None:
    topology = yaml.safe_load((ROOT / "config/release-topology.v1.yaml").read_text())
    assembler._preflight_topology(topology)
    assert len(topology["targets"]) == 1
    target = topology["targets"][0]
    assert target["targetId"] == "wsl2-ubuntu2404-linux-amd64-rootless-podman-quadlet"
    assert target["hostBaseline"] == target["targetId"]
    web = next(service for service in target["services"] if service["serviceId"] == "stateport-web")
    assert web["readOnlyHostMounts"] == [
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


def test_same_lane_older_predecessor_embedding_is_allowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A qualification-lane successor embeds its same-releaseId predecessor.

    The updater's exact-predecessor contract compares releaseId AND payload
    digest against the installed release, so the J1 qualification lane
    (one shared releaseId across candidates) must embed predecessors that
    carry the successor's own releaseId; only the older semantic version
    distinguishes them.
    """
    from types import SimpleNamespace

    request = SimpleNamespace(
        predecessor_index=tmp_path / "predecessor-index.json",
        successor_semantics=True,
        release_id="stateport-j1-integrated-qualification-900001",
        version="0.0.0-j1.39",
        updater_minimum_version="0.1.1",
        schema_migration_version=1,
        database_migration_version=1,
        rollback_supported=True,
        rollback_minimum_version="0.0.0-j1.35",
        rollback_data_compatible=True,
        rollback_reason="qualification lane retains predecessor volumes",
    )
    predecessor_index = SimpleNamespace(
        document={
            "signed": {
                "release": {
                    "releaseId": "stateport-j1-integrated-qualification-900001",
                    "version": "0.0.0-j1.35",
                }
            }
        },
        signed_digest="sha256:" + "3" * 64,
    )
    authenticated = SimpleNamespace(index=predecessor_index)
    monkeypatch.setattr(
        assembler, "_authenticate_predecessor", lambda req, path: authenticated
    )
    compatibility, seen = assembler._assemble_compatibility(request)
    assert seen is authenticated
    assert compatibility["predecessor"]["version"] == "0.0.0-j1.35"
    assert compatibility["rollback"]["supported"] is True


def test_newer_predecessor_embedding_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import SimpleNamespace

    request = SimpleNamespace(
        predecessor_index=tmp_path / "predecessor-index.json",
        successor_semantics=True,
        release_id="stateport-j1-integrated-qualification-900001",
        version="0.0.0-j1.39",
        updater_minimum_version="0.1.1",
        schema_migration_version=1,
        database_migration_version=1,
        rollback_supported=False,
        rollback_minimum_version=None,
        rollback_data_compatible=False,
        rollback_reason="n/a",
    )
    predecessor_index = SimpleNamespace(
        document={
            "signed": {
                "release": {
                    "releaseId": "stateport-j1-integrated-qualification-900001",
                    "version": "0.0.0-j1.40",
                }
            }
        },
        signed_digest="sha256:" + "4" * 64,
    )
    monkeypatch.setattr(
        assembler,
        "_authenticate_predecessor",
        lambda req, path: SimpleNamespace(index=predecessor_index),
    )
    with pytest.raises(assembler.AssemblyError, match="older release than the successor"):
        assembler._assemble_compatibility(request)


def test_semver_key_orders_numeric_prerelease_tails() -> None:
    assert assembler._semver_key("0.0.0-j1.9") < assembler._semver_key("0.0.0-j1.38")
    assert assembler._semver_key("0.0.0-j1.38") < assembler._semver_key("0.0.0-j1.39")
