from __future__ import annotations

from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, replace
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import shlex
import stat
import subprocess
import sys
import tarfile
from types import MappingProxyType
from typing import Any, Mapping, Sequence
import zipfile

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "packages/release-contracts/src"))
sys.path.insert(0, str(ROOT / "packages/updater/src"))
sys.path.insert(0, str(ROOT / "packages/execution-host/src"))
sys.path.insert(0, str(ROOT / "packages/runtime-contracts/src"))

from stateport_release import (  # noqa: E402
    ReleaseContractError,
    SignatureVerificationProof,
    canonical_digest,
    load_release_index_file,
    validate_install_receipt,
)
import stateport_updater.engine as updater_engine  # noqa: E402
import stateport_updater.installed as updater_installed  # noqa: E402
import stateport_updater.models as updater_models  # noqa: E402
import stateport_updater.store as updater_store  # noqa: E402
import render_wsl2_install_bootstrap as wsl2_bootstrap  # noqa: E402
import stateport_updater.control_plane as updater_control_plane  # noqa: E402
import public_alpha_preflight  # noqa: E402
import stateport_release  # noqa: E402
import stateport_release.execution_host_provisioning as provisioning  # noqa: E402
import assemble_release_index as assembler  # noqa: E402
import install_no_checkout as installer  # noqa: E402
from release_safe_io import sha256_file  # noqa: E402


pytestmark = pytest.mark.skipif(
    shutil.which("openssl") is None, reason="openssl is required to fingerprint the fixture key"
)

# Throwaway, test-only P-256 public key (the private half was deleted).  It is
# never release evidence and never signs anything: signature verification is
# exercised through the injected runner and verifier seams.
TEST_PUBLIC_KEY_PEM = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnmFuNZUaTmFwa1oQGPi1vYD0u+yq\n"
    "aL3blYr9sdh1Rmfghm65WBwZ/sEXjt8TOqUlUotpoY7XWxaoYiQ1WnkgWA==\n"
    "-----END PUBLIC KEY-----\n"
)
KEY_ID = "stateport-alpha-test-2026-08"
COMMIT = "b" * 40
TREE = "c" * 40
PUBLIC_COMMIT = "d" * 40
PUBLIC_TREE = "e" * 40
IMAGES = ("stateport-web", "stateport-api", "stateport-worker", "stateport-execution-host")
# The execution host is a stable out-of-revision service: it is signed and pulled
# with the release but never installed as a revision Quadlet unit.
REVISION_SERVICES = ("stateport-web", "stateport-api", "stateport-worker")
HEALTH = {
    "stateport-web": (8080, "/health"),
    "stateport-api": (8790, "/readyz"),
    "stateport-worker": (8791, "/readyz"),
}
BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"


def _rendered_install_invocations(text: str) -> list[list[str]]:
    logical = text.replace("\\\n", " ")
    invocations: list[list[str]] = []
    for line in logical.splitlines():
        command = line.strip()
        if not command.startswith('python3 "$tmp/installer"'):
            continue
        argv = shlex.split(command)
        if "--release-index" in argv and (
            "--prepare-execution-host" in argv or "--confirmed-plan-digest" in argv
        ):
            invocations.append(argv[2:])
    return invocations


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _service(
    service_id: str,
    volume_name: str,
    mount_path: str,
    control_contract: str = "none",
) -> dict[str, object]:
    port, path = HEALTH[service_id]
    # The signed contract requires every health port to be declared in ports;
    # loopback-only publishing keeps api and worker off the network while the
    # installer still observes them over 127.0.0.1.
    ports = [
        {
            "name": "http",
            "containerPort": port,
            "hostScope": "loopback",
            "allocation": "full-revision-digest-derived-collision-probed",
        }
    ]
    return {
        "serviceId": service_id,
        "imageId": service_id,
        "trustDomain": "control",
        "quadletOwner": "stateport-control",
        "revisionScoped": True,
        "runAsUser": 65532,
        "readOnlyRoot": True,
        "health": {"kind": "http", "containerPort": port, "path": path},
        "ports": ports,
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


def _image_manifest_bytes(image_id: str) -> bytes:
    config = image_id.encode()
    config_digest = hashlib.sha256(config).hexdigest()
    return json.dumps(
        {
            "schemaVersion": 2,
            "config": {"digest": "sha256:" + config_digest, "size": len(config)},
            "layers": [],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _image_digest(image_id: str) -> str:
    manifest = _image_manifest_bytes(image_id)
    return "sha256:" + hashlib.sha256(manifest).hexdigest()


def _write_oci_archive(path: Path, image_id: str) -> None:
    config = image_id.encode()
    config_digest = hashlib.sha256(config).hexdigest()
    manifest = _image_manifest_bytes(image_id)
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
            archive.addfile(info, io.BytesIO(data))


def _minimal_wheel_bytes() -> bytes:
    """A real, minimal wheel zip with pip-parseable .dist-info metadata.

    The installer derives the staged pip filename from the wheel's own
    metadata (regression for the VM refusal ``venv_install_failed-17a40047``:
    a digest-decorated name is not a valid wheel filename), so fixtures that
    flow through ``_stage_wheel_for_pip`` must be genuine zips.
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("stateport_release/sentinel.py", "wheel-bytes\n")
        archive.writestr(
            "stateport_release/__init__.py",
            "import json\n"
            "from pathlib import Path\n"
            "\n"
            "def load_release_index_file(path: Path, *, require_signatures: bool = True):\n"
            "    return json.loads(path.read_bytes())\n",
        )
        archive.writestr(
            "stateport_updater-0.1.1.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: stateport-updater\nVersion: 0.1.1\n",
        )
        archive.writestr(
            "stateport_updater-0.1.1.dist-info/WHEEL",
            "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
    return buffer.getvalue()


PACKAGE_VERSIONS = {
    "aardvark-dns": "1.14.0-3stateport1~24.04.1",
    "catatonit": "0.1.7-1",
    "conmon": "2.1.10+ds1-1build2",
    "containers-storage": "1.51.0+ds1-2ubuntu0.24.04.3",
    "dbus-user-session": "1.14.10-4ubuntu4.1",
    "fuse-overlayfs": "1.13-1",
    "golang-github-containers-common": "0.57.4+ds1-2ubuntu0.2",
    "golang-github-containers-image": "5.29.2-2",
    "libslirp0": "4.7.0-1ubuntu3.1",
    "libsubid4": "1:4.13+dfsg1-4ubuntu3.2",
    "netavark": "1.14.0-2stateport1~24.04.1",
    "podman": "5.4.2+ds1-2stateport2~24.04.1",
    "python3-venv": "3.12.3-0ubuntu2.1",
    "runc": "1.3.4-0ubuntu1~24.04.1",
    "slirp4netns": "1.2.1-1build2",
    "skopeo": "1.13.3+ds1-2build2",
    "uidmap": "1:4.13+dfsg1-4ubuntu3.2",
}
PACKAGE_ARCHITECTURES = {
    name: "all" if name.startswith("golang-github-containers-") else "amd64"
    for name in PACKAGE_VERSIONS
}


def _write_podman_package_bundle(path: Path) -> None:
    root = path.parent / "podman-package-bundle"
    packages = root / "packages"
    packages.mkdir(parents=True)
    records = []
    sums = []
    for name, version in sorted(PACKAGE_VERSIONS.items()):
        architecture = PACKAGE_ARCHITECTURES[name]
        filename = f"{name}_{version.replace(':', '%3a')}_{architecture}.deb"
        payload = f"fixture Debian package: {name}={version}\n".encode()
        package = packages / filename
        package.write_bytes(payload)
        digest = hashlib.sha256(payload).hexdigest()
        records.append(
            {
                "name": name,
                "version": version,
                "architecture": architecture,
                "file": filename,
                "sha256": digest,
                "size": len(payload),
            }
        )
        sums.append(f"{digest}  packages/{filename}")
    manifest = {
        "schema": "stateport/podman-package-bundle/v2",
        "target": installer.WSL2_TARGET_ID,
        "rootfs": installer._WSL_ROOTFS_IDENTITY,
        "sourceDateEpoch": 1788220800,
        "packages": records,
        "install": {
            "packageNames": sorted(PACKAGE_VERSIONS),
            "packageVersions": {name: PACKAGE_VERSIONS[name] for name in sorted(PACKAGE_VERSIONS)},
        },
    }
    (root / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    (root / "SHA256SUMS").write_text(
        "\n".join(sorted(sums)) + "\n", encoding="ascii"
    )
    with tarfile.open(path, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for source in sorted(
            (root, *root.rglob("*")),
            key=lambda item: item.relative_to(path.parent).as_posix(),
        ):
            relative = source.relative_to(path.parent).as_posix()
            info = archive.gettarinfo(str(source), arcname=relative)
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = 0
            info.mode = 0o755 if source.is_dir() else 0o644
            if source.is_file():
                with source.open("rb") as stream:
                    archive.addfile(info, stream)
            else:
                archive.addfile(info)


def _build_inputs(
    tmp_path: Path,
    *,
    expires_at: str | None = None,
    target_id: str = installer.PORTABLE_LINUX_TARGET_ID,
    version: str = "0.2.0-rc.1",
) -> dict[str, object]:
    """Fixture assembly inputs, in the style of scripts/test_assemble_release_index.py."""

    tmp_path.mkdir(mode=0o700, exist_ok=True)
    now = datetime.now(timezone.utc)
    built_at = _timestamp(now - timedelta(hours=2))
    observed_at = _timestamp(now - timedelta(hours=1))
    if expires_at is None:
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
        "installer": b"test-installer-no-checkout\n",
        "execution-host-provisioner": b"#!/bin/sh\nexit 0\n",
        "updater": _minimal_wheel_bytes(),
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
                            "probeObservation": {"executed": True, "exitCode": 0},
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
                "updateAttempted": True,
                "latestDatabaseCheck": {
                    "observedAt": observed_at,
                    "exitCode": 0,
                    "meaning": "up-to-date-no-newer-database",
                },
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
                    "version": version,
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
                        "targetId": target_id,
                        "hostBaseline": target_id,
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
                                "stateport-product-data",
                                "/var/lib/stateport",
                                control_contract="narrow-unix-client",
                            ),
                            _service(
                                "stateport-api", "stateport-operations", "/workspace/.stateport"
                            ),
                            _service(
                                "stateport-worker", "stateport-operations", "/workspace/.stateport"
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
        "archives": archives,
        "topology": topology,
        "expires_at": expires_at,
        "qualification_at": _timestamp(now),
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
    trust: dict[str, object],
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
        "qualification_at": inputs["qualification_at"],
        "trust_public_key": trust["public"],
        "trust_key_id": KEY_ID,
        "trust_key_fingerprint": trust["fingerprint"],
        "image_bundle_dir": inputs["bundles"],
        "output_root": output,
    }
    values.update(changes)
    return assembler.AssemblyRequest(**values)  # type: ignore[arg-type]


class FakeRunner:
    """Single subprocess seam: exact argv rules, no podman/systemctl/cosign needed."""

    def __init__(
        self,
        *,
        cosign_returncode: int = 0,
        podman_version: str = "5.0.0",
        rootless: bool = True,
        health_probe_healthy: bool = True,
        package_status: str = "installed",
    ) -> None:
        self.cosign_returncode = cosign_returncode
        self.podman_version = podman_version
        self.rootless = rootless
        self.health_probe_healthy = health_probe_healthy
        self.package_status = package_status
        self.calls: list[tuple[str, ...]] = []
        self.volumes: set[str] = set()
        self.active_units: set[str] = set()
        self.enabled_units: set[str] = set()
        self.containers: set[str] = set()
        # Consumed one per `systemctl --user stop`: an int returncode or an
        # OSError instance models one mid-uninstall interruption.
        self.stop_failures: list[object] = []

    def run(self, argv: Sequence[str], *, timeout: int) -> installer.Completed:
        call = tuple(str(item) for item in argv)
        self.calls.append(call)
        # Control-plane unit operations route through the stateport-control
        # user's systemd manager via runuser; unwrap for the systemctl rules.
        if (
            len(call) >= 5
            and call[0] == "runuser"
            and call[1:4] == ("-u", "stateport-control", "--")
        ):
            call = call[4:]
        if call == ("uname", "-s"):
            return installer.Completed(0, "Linux\n", "")
        if call == ("uname", "-m"):
            return installer.Completed(0, "x86_64\n", "")
        if call[0].endswith("cosign") or "cosign" in call[0]:
            return installer.Completed(self.cosign_returncode, "", "verification failed")
        if call[:3] == ("sudo", "-n", "cat"):
            # The fixture world never runs a root provisioning transaction;
            # the privileged control-unit read fails and the reconciliation
            # falls back to the installer's own convergence copy.
            return installer.Completed(1, "", "Permission denied")
        if call[:2] == ("podman", "version"):
            return installer.Completed(0, self.podman_version + "\n", "")
        if call[:2] == ("podman", "info"):
            if "OCIRuntime.Name" in call[-1]:
                return installer.Completed(0, "runc|netavark\n", "")
            return installer.Completed(0, ("true" if self.rootless else "false") + "\n", "")
        if call[:2] == ("dpkg-query", "--show"):
            version = PACKAGE_VERSIONS.get(call[-1])
            if version is None:
                return installer.Completed(1, "", "package missing")
            architecture = PACKAGE_ARCHITECTURES[call[-1]]
            if self.package_status == "not-installed":
                # A negative "not-installed" dpkg record (for example podman
                # after netavark is installed on a stock Noble cloud image)
                # reports rc 0 with empty version and architecture fields.
                return installer.Completed(
                    0, f"{self.package_status}\t\t\n", ""
                )
            return installer.Completed(
                0, f"{self.package_status}\t{version}\t{architecture}\n", ""
            )
        if call[:2] == ("dpkg", "--compare-versions") or call == ("dpkg", "--audit"):
            return installer.Completed(0, "", "")
        if call[:3] == ("systemctl", "--user", "show"):
            return installer.Completed(0, "254\n", "")
        if call[:2] == ("loginctl", "show-user"):
            return installer.Completed(0, "yes\n", "")
        if call[:2] == ("podman", "pull"):
            if "@sha256:" not in call[-1]:
                return installer.Completed(1, "", "tag references are refused")
            return installer.Completed(0, "", "")
        if call[:3] == ("podman", "image", "inspect"):
            reference = call[-1]
            if "@sha256:" not in reference:
                return installer.Completed(1, "", "no such image")
            return installer.Completed(0, reference.rsplit("@", 1)[-1] + "\n", "")
        if call[:3] == ("podman", "volume", "exists"):
            return installer.Completed(0 if call[-1] in self.volumes else 1, "", "")
        if call[:3] == ("podman", "volume", "create"):
            self.volumes.add(call[-1])
            return installer.Completed(0, call[-1] + "\n", "")
        if call[:3] == ("podman", "volume", "rm"):
            if call[-1] in self.volumes:
                self.volumes.discard(call[-1])
                return installer.Completed(0, call[-1] + "\n", "")
            return installer.Completed(1, "", "no such volume")
        if call[:3] == ("podman", "container", "exists"):
            return installer.Completed(0 if call[-1] in self.containers else 1, "", "")
        if call[:3] == ("podman", "rm", "-f"):
            if call[-1] in self.containers:
                self.containers.discard(call[-1])
                return installer.Completed(0, call[-1] + "\n", "")
            return installer.Completed(1, "", "no such container")
        if call[:2] == ("podman", "inspect"):
            return installer.Completed(0, "healthy\n", "")
        if call[:3] == ("systemctl", "--user", "daemon-reload"):
            return installer.Completed(0, "", "")
        if call[:3] == ("systemctl", "--user", "start"):
            self.active_units.add(call[-1])
            return installer.Completed(0, "", "")
        if call[:3] == ("systemctl", "--user", "enable"):
            self.enabled_units.add(call[-1])
            return installer.Completed(0, "", "")
        if call[:3] == ("systemctl", "--user", "stop"):
            if self.stop_failures:
                failure = self.stop_failures.pop(0)
                if isinstance(failure, BaseException):
                    raise failure
                return installer.Completed(int(failure), "", "simulated stop failure")  # type: ignore[arg-type]
            self.active_units.discard(call[-1])
            return installer.Completed(0, "", "")
        if call[:3] == ("systemctl", "--user", "is-active"):
            if call[-1] in self.active_units:
                return installer.Completed(0, "active\n", "")
            return installer.Completed(3, "inactive\n", "")
        if call[:3] == ("systemctl", "--user", "is-enabled"):
            if call[-1] in self.enabled_units:
                return installer.Completed(0, "enabled\n", "")
            return installer.Completed(1, "disabled\n", "")
        if call[:3] == ("systemctl", "--user", "disable"):
            self.enabled_units.discard(call[-1])
            return installer.Completed(0, "", "")
        if call[1:4] == ("-m", "stateport_release.execution_host_provisioning", "health-probe"):
            if self.health_probe_healthy:
                payload = json.dumps(
                    {"healthy": True, "contractVersion": 1, "reason": None, "detail": None}
                )
                return installer.Completed(0, payload + "\n", "")
            payload = json.dumps(
                {
                    "healthy": False,
                    "reason": "simulated-unhealthy",
                    "detail": "test-probe-refused",
                }
            )
            return installer.Completed(1, payload + "\n", "")
        if call[0].endswith("/pip"):
            return installer.Completed(0, "Successfully installed stateport-updater\n", "")
        if call[0].endswith("/python"):
            return installer.Completed(0, "", "")
        raise AssertionError(f"unexpected subprocess call: {call}")


class PackageRunner(FakeRunner):
    def run(self, argv: Sequence[str], *, timeout: int) -> installer.Completed:
        call = tuple(str(item) for item in argv)
        if call[:2] == ("dpkg-deb", "--field"):
            self.calls.append(call)
            package = Path(call[2]).name
            name = next(
                candidate for candidate in PACKAGE_VERSIONS if package.startswith(candidate + "_")
            )
            if call[-1] == "Depends":
                return installer.Completed(
                    0,
                    "runc (>= 1.3.4), slirp4netns (>= 1.2.1), conmon\n",
                    "",
                )
            return installer.Completed(
                0,
                f"Package: {name}\nVersion: {PACKAGE_VERSIONS[name]}\n"
                f"Architecture: {PACKAGE_ARCHITECTURES[name]}\n",
                "",
            )
        if call[:2] == ("apt-get", "--simulate"):
            self.calls.append(call)
            return installer.Completed(0, "0 upgraded, 0 newly installed, 0 to remove.\n", "")
        return super().run(call, timeout=timeout)


class FakeProbe:
    def __init__(
        self,
        facts: installer.HostFacts,
        occupied: list[int] | None = None,
        substrate: installer.HostSubstrateFacts | None = None,
    ) -> None:
        self._facts = facts
        self._occupied = occupied or []
        self._substrate = substrate or installer.HostSubstrateFacts(
            kernel_release="6.8.0-79-generic",
            proc_version="Linux version 6.8.0-79-generic",
            wsl_interop_present=False,
            wsl_distro_name_present=False,
        )
        self.gather_calls = 0

    def substrate(self) -> installer.HostSubstrateFacts:
        return self._substrate

    def gather(self) -> installer.HostFacts:
        self.gather_calls += 1
        return self._facts

    def occupied_ports(self) -> list[int]:
        return list(self._occupied)


def _facts(**changes: object) -> installer.HostFacts:
    values: dict[str, object] = {
        "kernel": "Linux",
        "os_id": "ubuntu",
        "version_id": "24.04",
        "architecture": "amd64",
        "cgroup_version": "v2",
        "podman_version": "5.0.0",
        "rootless": True,
        "quadlet": True,
        "systemd_user": True,
        "subuid_configured": True,
        "subgid_configured": True,
    }
    values.update(changes)
    return installer.HostFacts(**values)  # type: ignore[arg-type]


class FakeFetcher:
    def __init__(
        self,
        healthy: bool = True,
        downloads: Mapping[str, bytes] | None = None,
        *,
        page_marker: bool = True,
        page_status: int = 200,
        session_ok: bool = True,
        session_body: bytes | None = None,
        catalog_valid: bool = True,
        catalog_status: int = 200,
        catalog_body: bytes | None = None,
        catalog_network_policy: str = "disabled",
    ) -> None:
        self.healthy = healthy
        self.downloads = dict(downloads or {})
        self.page_marker = page_marker
        self.page_status = page_status
        self.session_ok = session_ok
        self.session_body = session_body
        self.catalog_valid = catalog_valid
        self.catalog_status = catalog_status
        self.catalog_body = catalog_body
        self.catalog_network_policy = catalog_network_policy
        self.requests: list[str] = []

    def fetch(self, url: str, *, timeout: float, max_bytes: int) -> installer.FetchResult:
        self.requests.append(url)
        if url in self.downloads:
            return installer.FetchResult(200, self.downloads[url])
        if url.startswith("http://127.0.0.1:"):
            if not self.healthy:
                return installer.FetchResult(0, b"")
            if url.endswith("/health") or url.endswith("/readyz"):
                body = json.dumps(
                    {
                        "service": "stateport-web",
                        "signedPayloadDigest": "sha256:" + "0" * 64,
                        "status": "ok",
                    }
                ).encode()
                return installer.FetchResult(200, body)
            if url.endswith("/session"):
                if not self.session_ok:
                    return installer.FetchResult(500, b"")
                if self.session_body is not None:
                    return installer.FetchResult(200, self.session_body)
                body = json.dumps(
                    {"ok": True, "result": {"session": "local", "csrfToken": "test-token"}}
                ).encode()
                return installer.FetchResult(200, body)
            if url.endswith("/v1/applications"):
                if self.catalog_body is not None:
                    return installer.FetchResult(self.catalog_status, self.catalog_body)
                if not self.catalog_valid:
                    return installer.FetchResult(
                        200, json.dumps({"ok": True, "result": {"applications": []}}).encode()
                    )
                body = json.dumps(
                    {
                        "ok": True,
                        "result": {
                            "applications": [
                                {
                                    "applicationId": "studystate.sample",
                                    "displayName": "StudyState Sample",
                                    "install": {
                                        "status": "available",
                                        "reasons": [],
                                        "confirmationRequired": True,
                                        "sourceKind": "bundled_public_fixture",
                                        "requestedCapabilities": [
                                            "conversation",
                                            "goal_execution",
                                            "proactive_notifications",
                                            "progress_dashboard",
                                        ],
                                        "networkPolicy": self.catalog_network_policy,
                                    },
                                }
                            ]
                        },
                    }
                ).encode()
                return installer.FetchResult(self.catalog_status, body)
            if url.endswith("/"):
                marker = b'<html><head><title>StatePort</title></head><body><div id="root"></div></body></html>'
                other = b"<html><head><title>other</title></head><body></body></html>"
                return installer.FetchResult(
                    self.page_status, marker if self.page_marker else other
                )
            return installer.FetchResult(200, b"ok")
        raise AssertionError(f"unexpected fetch: {url}")


class FakeVerifier:
    """Mirrors the CosignVerifier proof contract without a registry or cosign."""

    def __init__(self, clock) -> None:
        self._clock = clock
        self._local_payloads: dict[str, bytes] = {}

    def set_local_image_payloads(self, payloads: Mapping[str, bytes]) -> None:
        self._local_payloads = dict(payloads)

    def resolve_local_image_manifest(self, image_id: str, digest: str) -> bytes | None:
        payload = self._local_payloads.get(image_id)
        if payload is None or "sha256:" + hashlib.sha256(payload).hexdigest() != digest:
            return None
        return payload

    def _proof(self, signature: Mapping[str, Any]) -> SignatureVerificationProof:
        # The contract refuses proofs newer than policy.now, and the updater
        # engine truncates its policy time to whole seconds; mirror that
        # truncation so real-clock tests are not racy at second boundaries.
        verified_at = self._clock().astimezone(timezone.utc).replace(microsecond=0)
        return SignatureVerificationProof(
            subject_digest=str(signature["subjectDigest"]),
            bundle_digest=str(signature["bundle"]["digest"]),
            trust_mode=str(signature["trustMode"]),
            identity_primary=str(signature["publicKeyFingerprint"]),
            identity_secondary=str(signature["publicKeyId"]),
            verified_at=verified_at,
            transparency_log_mode=str(signature["transparencyLog"]),
        )

    def verify_blob(
        self, payload: bytes, signature: Mapping[str, Any]
    ) -> SignatureVerificationProof:
        observed = "sha256:" + hashlib.sha256(payload).hexdigest()
        if observed != signature["subjectDigest"]:
            raise ReleaseContractError("blob payload does not match the signed subject digest")
        return self._proof(signature)

    def verify_image(
        self, reference: str, signature: Mapping[str, Any]
    ) -> SignatureVerificationProof:
        if not reference.endswith(str(signature["subjectDigest"])):
            raise ReleaseContractError("image reference is not bound to the signed digest")
        return self._proof(signature)


def _modules(venv_dir: Path) -> installer.VerifiedModules:
    return installer.VerifiedModules(
        release=stateport_release,
        updater_engine=updater_engine,
        updater_installed=updater_installed,
        updater_models=updater_models,
        updater_store=updater_store,
    )


def _fake_venv_creator(venv_dir: Path) -> None:
    bin_dir = venv_dir / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    (bin_dir / "pip").touch()
    (bin_dir / "python").touch()
    (venv_dir / "pyvenv.cfg").write_text("home = /fake\n", encoding="utf-8")


@pytest.fixture
def trust(tmp_path: Path) -> dict[str, object]:
    public = tmp_path / "trust.pub"
    public.write_text(TEST_PUBLIC_KEY_PEM, encoding="utf-8")
    return {
        "public": public,
        "fingerprint": installer.der_spki_fingerprint(TEST_PUBLIC_KEY_PEM.encode("ascii")),
        "key_id": KEY_ID,
    }


@dataclass(frozen=True)
class Fixture:
    inputs: dict[str, object]
    index_path: Path
    bundle_root: Path
    artifact_paths: dict[str, Path]
    trust: dict[str, object]


def _signed_index(
    tmp_path: Path,
    trust: dict[str, object],
    *,
    expires_at: str | None = None,
    target_id: str = installer.PORTABLE_LINUX_TARGET_ID,
    version: str = "0.2.0-rc.1",
) -> Fixture:
    """Assemble a fixture index and bind a synthetic pinned-key signature.

    The signature descriptor is real in structure but its bundle is a fixture
    placeholder: cryptographic verification is exercised through the runner
    (bootstrap cosign) and FakeVerifier (contract) seams, never claimed here.
    """

    inputs = _build_inputs(
        tmp_path, expires_at=expires_at, target_id=target_id, version=version
    )
    output = tmp_path / "release"
    result = assembler.assemble(
        _request(
            inputs,
            trust,
            output,
            release_id=f"stateport-alpha-{version}",
            version=version,
        )
    )
    candidate = Path(str(result["candidate"]))
    unsigned = load_release_index_file(candidate, require_signatures=False)
    bundle_root = Path(str(inputs["bundles"]))
    archive_root = bundle_root / "image-archives"
    archive_root.mkdir()
    for archive in Path(str(inputs["archives"])).glob("*.oci.tar"):
        shutil.copyfile(archive, archive_root / archive.name)
    index_bundle = bundle_root / "release-index.sigstore.json"
    index_bundle.write_text(
        json.dumps(
            {
                "mediaType": BUNDLE_MEDIA_TYPE,
                "verificationMaterial": {"publicKey": {"hint": "aW5kZXg="}},
                "messageSignature": {
                    "messageDigest": {"algorithm": "SHA2_256", "digest": "aW5kZXg="},
                    "signature": "aW5kZXg=",
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    document = json.loads(candidate.read_text(encoding="utf-8"))
    document["signatures"] = [
        {
            "scheme": "cosign-v3-bundle",
            "subjectDigest": unsigned.signed_digest,
            "bundle": {
                "uri": "operator://release/release-index.sigstore.json",
                "digest": sha256_file(index_bundle),
                "size": index_bundle.stat().st_size,
                "mediaType": "application/vnd.sigstore.bundle.v0.3+json",
            },
            "trustMode": "pinned-public-key",
            "publicKeyFingerprint": str(trust["fingerprint"]),
            "publicKeyFingerprintAlgorithm": "sha256-canonical-der-spki",
            "publicKeyId": KEY_ID,
            "transparencyLog": "not-uploaded-private-candidate",
        }
    ]
    index_path = tmp_path / "release-index.json"
    index_path.write_text(json.dumps(document) + "\n", encoding="utf-8")
    artifact_paths = {
        "installer": Path(str(inputs["installer"])),
        "executionHostProvisioner": Path(str(inputs["execution_host_provisioner"])),
        "updater": Path(str(inputs["updater"])),
        "sourceArchive": Path(str(inputs["source_archive"])),
        "releaseNotes": Path(str(inputs["release_notes"])),
        "knownLimitations": Path(str(inputs["known_limitations"])),
        "compose": output / "compose.release.yaml",
    }
    return Fixture(inputs, index_path, bundle_root, artifact_paths, trust)


def _alpha11_fixture(base: Fixture, package_bundle: Path) -> tuple[Fixture, Path]:
    candidate = base.index_path.parent / "release"
    shutil.copyfile(
        base.bundle_root / "release-index.sigstore.json",
        candidate / "release-index.sigstore.json",
    )
    for image_id in IMAGES:
        shutil.copyfile(
            base.bundle_root / f"{image_id}.sigstore.json",
            candidate / f"{image_id}.sigstore.json",
        )
    package_path = candidate / "artifacts" / "podmanPackageBundle"
    shutil.copyfile(package_bundle, package_path)
    document = json.loads(base.index_path.read_text(encoding="utf-8"))
    document["signed"]["release"]["releaseId"] = "stateport-alpha-0.1.0-alpha.11"
    document["signed"]["release"]["version"] = "0.1.0-alpha.11"
    document["signed"]["targets"][0]["releaseId"] = "stateport-alpha-0.1.0-alpha.11"
    document["signed"].pop("successor", None)
    document["signed"]["artifacts"]["podmanPackageBundle"] = {
        "uri": "operator://release/artifacts/podmanPackageBundle",
        "digest": sha256_file(package_path),
        "size": package_path.stat().st_size,
        "mediaType": "application/vnd.stateport.podman-package-bundle+tar",
    }
    document["signed"]["targets"][0]["artifactIds"] = sorted(
        document["signed"]["artifacts"]
    )
    document["signed"]["targets"][0]["topologyDigest"] = stateport_release.topology_digest(
        document["signed"]["targets"][0]
    )
    quadlet_files = stateport_release.render_quadlet_bundle(
        document["signed"]["targets"][0], document["signed"]["images"]
    )
    quadlet_digest = stateport_release.quadlet_bundle_digest(quadlet_files)
    document["signed"]["targets"][0]["quadletBundleDigest"] = quadlet_digest
    document["signed"]["artifacts"]["quadlet"]["digest"] = quadlet_digest
    document["signed"]["artifacts"]["quadlet"]["size"] = sum(
        len(content) for content in quadlet_files.values()
    )
    document["signatures"][0]["subjectDigest"] = canonical_digest(document["signed"])
    index_path = candidate / "release-index.json"
    index_path.write_text(json.dumps(document) + "\n", encoding="utf-8")
    artifact_paths = {**base.artifact_paths, "podmanPackageBundle": package_path}
    return (
        Fixture(base.inputs, index_path, base.bundle_root, artifact_paths, base.trust),
        candidate,
    )


def _alpha11_preflight(
    fixture: Fixture,
    tmp_path: Path,
    package_bundle: Path,
    cosign_executable: Path,
    *,
    runner: PackageRunner | None = None,
) -> tuple[Path, str]:
    """Authenticate the Alpha.11 package bundle and preserve the pre-install plan.

    Mirrors the bootstrap's unprivileged preflight pass: the returned preflight
    JSON is the authenticated owner-confirmed transaction evidence that the
    install pass must preserve and re-bind.
    """
    output_dir = tmp_path / "preflight-output"
    preflight = installer.verify_podman_package_bundle(
        installer.PackageBundlePreflightConfig(
            release_index=fixture.index_path,
            bundle_root=fixture.bundle_root,
            trust_public_key=Path(str(fixture.trust["public"])),
            trust_key_id=KEY_ID,
            trust_key_fingerprint=str(fixture.trust["fingerprint"]),
            cosign=cosign_executable,
            installer_path=fixture.artifact_paths["installer"],
            podman_package_bundle=package_bundle,
            output_dir=output_dir,
            expected_target=installer.WSL2_TARGET_ID,
        ),
        runner=runner or PackageRunner(podman_version="5.4.2"),
    )
    preflight = dict(preflight)
    preflight["releaseAdmission"] = {
        "schema": "stateport.release-admission/v1",
        "status": "verified",
        "releaseIndexDigest": preflight["releaseIndexDigest"],
        "signedPayloadDigest": preflight["signedPayloadDigest"],
        "targetId": preflight["targetId"],
        "artifactDigests": {"podmanPackageBundle": preflight["artifactDigest"]},
    }
    preflight_path = tmp_path / "podman-package-preflight.json"
    preflight_path.write_text(
        json.dumps(preflight, sort_keys=True) + "\n", encoding="utf-8"
    )
    package_plan_digest = str(preflight["packagePlanDigest"])
    assert installer._DIGEST.fullmatch(package_plan_digest) is not None
    return preflight_path, package_plan_digest


def _verified_from_fixture(fixture: Fixture, expected_target: str):
    """Verify the fixture's signed index with the test trust root."""
    from datetime import datetime, timedelta, timezone as _tz

    index = load_release_index_file(fixture.index_path)
    clock = datetime.now(_tz.utc)
    policy = stateport_release.ReleaseVerificationPolicy(
        expected_channel="alpha",
        expected_target=expected_target,
        updater_version="0.1.1",
        accepted_signers=frozenset(),
        accepted_public_keys=frozenset(
            {
                stateport_release.PinnedPublicKeyIdentity(
                    str(fixture.trust["fingerprint"]), KEY_ID
                )
            }
        ),
        expected_trust_mode="pinned-public-key",
        now=clock + timedelta(seconds=60),
        allow_candidate=True,
    )
    return stateport_release.verify_release_index(
        index,
        policy=policy,
        verifier=FakeVerifier(lambda: clock),
        local_image_payloads=installer._local_image_manifest_payloads(index, fixture.bundle_root),
    )


def _control_plane_materialization_for_receipt(
    target: Mapping[str, Any],
    index: Any,
    tmp_path: Path,
    fixture: Fixture,
    occupied: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, bytes] | None:
    """Derive the control-plane materialization for the fixture receipt.

    The control-plane unit bytes (Image, User, ports, volumes) depend on the
    occupied-port inventory exactly as the installer derives them; a fixed
    install-plan digest yields the same bytes.  If the fixture cannot derive
    a materialization, the receipt simply carries none.
    """
    import datetime

    try:
        verified = _verified_from_fixture(fixture, str(target["targetId"]))
        normalized_occupied = []
        for item in occupied or []:
            if isinstance(item, int):
                normalized_occupied.append(
                    {
                        "class": "observed-host",
                        "port": item,
                        "identityDigest": canonical_digest({"test": "foreign-listener"}),
                    }
                )
            else:
                normalized_occupied.append(dict(item))
        return installer._derive_control_plane_materialization(
            release=stateport_release,
            verified=verified,
            index=index,
            target=target,
            images=index.document["signed"]["images"],
            plan_digest="sha256:" + "11" * 32,
            host_identity_digest="sha256:" + "22" * 32,
            collision_digests={
                name: "sha256:" + "44" * 32
                for name in ("current", "predecessor", "candidate", "observedHost")
            },
            occupied=normalized_occupied,
            state_root=tmp_path,
            clock=lambda: datetime.datetime(2026, 8, 9, tzinfo=datetime.timezone.utc),
        )
    except (installer.InstallerRefusal, Exception):  # noqa: BLE001 - fixture fallback
        return None


def _config(fixture: Fixture, tmp_path: Path, **changes: object) -> installer.InstallConfig:
    occupied_ports = changes.pop("_occupied_ports", None)
    receipt_path = tmp_path / "execution-host-provisioning-receipt.json"
    index = load_release_index_file(fixture.index_path)
    targets = index.document["signed"]["targets"]
    expected_target = str(
        changes.get("expected_target", targets[0]["targetId"])
    )
    target = next(
        item
        for item in index.document["signed"]["targets"]
        if item["targetId"] == expected_target
    )
    client = provisioning.resolve_client_identity()
    assert client is not None, "installer tests require a resolvable invoking user"
    plan = provisioning.render_provisioning_plan(
        target,
        index.document["signed"]["images"],
        verification_basis="signature-verified-apply",
        client_user=client[0],
        client_uid=client[1],
        client_gid=client[2],
        control_plane_materialization=(
            _control_plane_materialization_for_receipt(
                target,
                index,
                tmp_path,
                fixture,
                occupied=occupied_ports,
            )
        ),
        control_plane_environment=installer._default_control_plane_environment(tmp_path / "state"),
    )
    client_user = client[0]
    receipt = {
        "schema": provisioning.RECEIPT_SCHEMA,
        "receiptId": "exec_host_provision_" + "a" * 32,
        "receiptPath": str(receipt_path),
        "planDigest": plan["planDigest"],
        "releaseId": target["releaseId"],
        "releaseIndexDigest": index.index_digest,
        "signedPayloadDigest": index.signed_digest,
        "sourceCommit": index.document["signed"]["source"]["commit"],
        "sourceTree": index.document["signed"]["source"]["tree"],
        "installerDigest": index.document["signed"]["artifacts"]["installer"]["digest"],
        "targetId": target["targetId"],
        "topologyDigest": target["topologyDigest"],
        "verificationBasis": "signature-verified-apply",
        "revalidatedImmediatelyBeforeWrites": True,
        "evidenceClass": "locally-simulated",
        "executionUser": plan["executionUser"],
        "executionUid": plan["executionUid"],
        "executionGid": plan["executionGid"],
        "controlUser": plan["controlUser"],
        "controlUid": plan["controlUid"],
        "controlGid": plan["controlGid"],
        "executionControlGroup": plan["executionControlGroup"],
        "executionControlGroupGid": plan["executionControlGroupGid"],
        "allowedClientUser": plan["allowedClientUser"],
        "subordinateIds": {
            "user": plan["subordinateIds"]["user"],
            "start": 100000,
            "count": 65536,
            "files": ["/etc/subuid", "/etc/subgid"],
        },
        "image": {
            "imageId": plan["image"]["imageId"],
            "reference": plan["image"]["reference"],
            "expectedDigest": plan["image"]["digest"],
            "observedDigest": plan["image"]["digest"],
            "storeOwner": "stateport-exec",
            "status": "verified",
        },
        "health": {
            "kind": "describeCapabilities",
            "socketPath": plan["socketPath"],
            "peerUsers": ["stateport-exec", client_user],
            "status": "healthy",
            "healthy": True,
            "contractVersion": 1,
            "refusal": None,
            "probes": [
                {"peerUser": "stateport-exec", "healthy": True, "contractVersion": 1, "reason": None},
                {"peerUser": client_user, "healthy": True, "contractVersion": 1, "reason": None},
            ],
        },
        "steps": [
            {"step": str(step["step"]), "result": "applied", "commands": [], "detail": ""}
            for step in plan["steps"]
        ],
        "rollback": {"performed": False, "status": "not-reached", "actions": [], "failures": []},
        "uninstall": ["test-only fixture"],
        "controlGrant": {
            "grantId": "control-plane-default",
            "peerUid": plan["controlUid"],
            "workloadId": "default-dev",
            "workloadKind": "workspace",
            "workloadSpecDigest": provisioning.DEFAULT_WORKSPACE_SPEC_DIGEST,
            "imageReference": provisioning.DEFAULT_WORKSPACE_IMAGE,
            "grantDigest": "sha256:" + "cd" * 32,
        },
        "startedAt": "2026-08-09T00:00:00Z",
        "finishedAt": "2026-08-09T00:00:01Z",
        "result": "succeeded",
    }
    receipt["receiptDigest"] = stateport_release.revision_contract_digest(
        receipt, digest_field="receiptDigest"
    )
    receipt_path.write_text(json.dumps(receipt) + "\n", encoding="utf-8")
    values: dict[str, object] = {
        "release_index": str(fixture.index_path),
        "bundle_root": fixture.bundle_root,
        "trust_public_key": fixture.trust["public"],
        "trust_key_id": KEY_ID,
        "trust_key_fingerprint": fixture.trust["fingerprint"],
        "updater_wheel": str(fixture.artifact_paths["updater"]),
        "execution_host_provisioner": str(
            fixture.artifact_paths["executionHostProvisioner"]
        ),
        "channel": "alpha",
        "cosign": Path("/usr/bin/cosign-fixture"),
        "state_root": tmp_path / "state",
        "live_quadlet_root": tmp_path / "quadlets",
        "actor_id": "local-owner-test",
        "installer_path": fixture.artifact_paths["installer"],
        "compose": str(fixture.artifact_paths["compose"]),
        "source_archive": str(fixture.artifact_paths["sourceArchive"]),
        "release_notes": str(fixture.artifact_paths["releaseNotes"]),
        "known_limitations": str(fixture.artifact_paths["knownLimitations"]),
        "expected_target": expected_target,
        "execution_host_receipt": receipt_path,
        "assume_yes": True,
        "health_timeout_seconds": 30.0,
        "health_poll_seconds": 0.01,
    }
    values.update(changes)
    return installer.InstallConfig(**values)  # type: ignore[arg-type]


def test_default_control_plane_environment_separates_operator_and_approver(
    tmp_path: Path,
) -> None:
    state_root = tmp_path / "state"
    first = installer._default_control_plane_environment(state_root)
    identities = json.loads(first["stateport-api.STATEPORT_IDENTITIES_JSON"])
    tokens = json.loads(first["stateport-api.STATEPORT_AUTH_TOKENS_JSON"])

    assert identities == {
        "local-approver": {"instances": ["*"], "roles": ["approver"]},
        "local-operator": {"instances": ["*"], "roles": ["operator"]},
    }
    assert set(tokens) == {"local-approver", "local-operator"}
    assert tokens["local-approver"] != tokens["local-operator"]
    assert all(len(token) >= 16 for token in tokens.values())
    for role in ("operator", "approver"):
        token_path = state_root / f"control-plane-{role}-token"
        assert token_path.read_text(encoding="utf-8") == tokens[f"local-{role}"]
        assert stat.S_IMODE(token_path.stat().st_mode) == 0o600

    assert installer._default_control_plane_environment(state_root) == first


@pytest.fixture
def cosign_executable(tmp_path: Path) -> Path:
    path = tmp_path / "cosign"
    path.write_bytes(b"#!/bin/false\n")
    return path


def _run_install(
    config: installer.InstallConfig,
    *,
    runner: FakeRunner,
    probe: FakeProbe,
    fetcher: FakeFetcher,
    confirmer=lambda summary: True,
) -> installer.InstallOutcome:
    clock = lambda: datetime.now(timezone.utc)  # noqa: E731
    return installer.install(
        config,
        runner=runner,
        probe=probe,
        fetcher=fetcher,
        module_loader=_modules,
        verifier_factory=lambda modules: FakeVerifier(clock),
        clock=clock,
        confirmer=confirmer,
        venv_creator=_fake_venv_creator,
    )


def _happy(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path, **probe_changes: object
) -> tuple[installer.InstallOutcome, FakeRunner, Fixture, installer.InstallConfig]:
    fixture = _signed_index(tmp_path / "fixture", trust)
    runner = FakeRunner()
    probe = FakeProbe(_facts(**probe_changes), occupied=[])
    fetcher = FakeFetcher()
    config = _config(fixture, tmp_path, cosign=cosign_executable)
    outcome = _run_install(config, runner=runner, probe=probe, fetcher=fetcher)
    return outcome, runner, fixture, config


def test_happy_path_installs_and_receipts(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    outcome, runner, fixture, config = _happy(tmp_path, trust, cosign_executable)
    assert outcome.status == "succeeded", outcome.message
    assert outcome.local_url is not None and outcome.local_url.startswith("http://127.0.0.1:")
    assert outcome.receipt_path is not None and outcome.receipt_path.is_file()

    receipt = json.loads(outcome.receipt_path.read_text(encoding="utf-8"))
    validated = validate_install_receipt(receipt)
    assert validated.document["result"] == "succeeded"
    assert validated.document["operation"] == "install"
    assert validated.document["runtime"]["healthy"] is True
    assert validated.document["host"]["architecture"] == "amd64"
    assert validated.document["host"]["podmanVersion"] == "5.0.0"


    index = load_release_index_file(fixture.index_path)
    signed = index.document["signed"]
    assert validated.document["releaseIndexDigest"] == index.index_digest
    assert validated.document["runtime"]["signedPayloadDigest"] == index.signed_digest
    assert validated.document["installer"]["digest"] == signed["artifacts"]["installer"]["digest"]
    assert (
        validated.document["target"]["targetDigest"]
        == validated.document["runtime"]["targetDigest"]
    )
    assert len(validated.document["verification"]["artifacts"]) == 8
    assert len(validated.document["verification"]["signers"]) == len(IMAGES) + 1
    assert validated.document["authority"]["kind"] == "installer-directive"
    assert validated.document["dataDisposition"] == "created"

    # Loopback-only publishing; accepted units are token-free and not boot-enabled.
    live_units = sorted(config.live_quadlet_root.iterdir())
    assert live_units, "no accepted units were installed"
    container_units = [path for path in live_units if path.suffix == ".container"]
    assert len(container_units) == len(REVISION_SERVICES)
    for path in live_units:
        text = path.read_text(encoding="utf-8")
        assert "@@STATEPORT_" not in text
        assert "[Install]" not in text and "WantedBy=" not in text
        if "PublishPort=" in text:
            assert "PublishPort=127.0.0.1:" in text

    # Web data plus one shared API/worker store, each with one snapshot copy.
    assert len(runner.volumes) == 2 * 2
    api_unit = next(
        path for path in container_units
        if "Label=io.stateport.service.id=stateport-api" in path.read_text(encoding="utf-8")
    )
    worker_unit = next(
        path for path in container_units
        if "Label=io.stateport.service.id=stateport-worker" in path.read_text(encoding="utf-8")
    )
    api_volume = next(
        line for line in api_unit.read_text(encoding="utf-8").splitlines()
        if line.startswith("Volume=") and line.endswith(":/workspace/.stateport:rw,U")
    )
    worker_volume = next(
        line for line in worker_unit.read_text(encoding="utf-8").splitlines()
        if line.startswith("Volume=") and line.endswith(":/workspace/.stateport:rw,U")
    )
    assert api_volume == worker_volume

    # Exact digest-pinned pulls and a hash-locked, index-less wheel install.
    pulls = [call for call in runner.calls if call[:2] == ("podman", "pull")]
    assert len(pulls) == len(IMAGES)
    for call in pulls:
        assert "@sha256:" in call[-1]
    pip_calls = [call for call in runner.calls if call[0].endswith("/pip")]
    assert pip_calls and "--no-index" in pip_calls[0] and "--no-deps" in pip_calls[0]
    cosign_calls = [call for call in runner.calls if "verify-blob" in call]
    assert cosign_calls and "--insecure-ignore-tlog" in cosign_calls[0]

    # Updater genesis: durable trust root, status, admission, and authority.
    status = json.loads((config.state_root / "updater" / "status.json").read_text())
    assert status["phase"] == "idle" and status["sequence"] == 0
    assert status["current"]["releaseId"] == signed["release"]["releaseId"]
    assert status["current"]["signedPayloadDigest"] == index.signed_digest
    releases = list((config.state_root / "updater" / "releases").glob("*.release-index.json"))
    assert len(releases) == 1

    trust_dir = config.state_root / "updater" / "trust"
    pem_path = trust_dir / f"{KEY_ID}.pem"
    assert pem_path.read_bytes() == (config.trust_public_key).read_bytes()
    trust_root = json.loads((trust_dir / "trust-root.json").read_text())
    assert trust_root["schema"] == "stateport.internal-update-trust-root/v1"
    assert trust_root["mode"] == "pinned-public-key"
    assert trust_root["keyId"] == KEY_ID
    assert trust_root["publicKeyFingerprint"] == config.trust_key_fingerprint
    assert trust_root["publicKeyFingerprintAlgorithm"] == "sha256-canonical-der-spki"
    assert trust_root["channel"] == "alpha"
    assert trust_root["targetId"] == installer.EXPECTED_TARGET
    assert trust_root["publicKeyFileDigest"] == installer._sha256_digest(pem_path.read_bytes())
    trust_body = {
        key: value
        for key, value in trust_root.items()
        if key not in {"trustRootId", "trustRootDigest"}
    }
    assert canonical_digest(trust_body) == trust_root["trustRootDigest"]
    assert trust_root["trustRootId"] == (
        f"update_trust_root_{trust_root['trustRootDigest'].removeprefix('sha256:')[:32]}"
    )

    # Real typed pinned-key admission and installed-authority identity; the
    # deferred genesis boundary record must not be written anymore.
    admissions = list((config.state_root / "updater" / "release-admissions").glob("*.json"))
    assert len(admissions) == 1
    admission = json.loads(admissions[0].read_text())
    assert admission["kind"] == "installed-initialize"
    assert admission["trustMode"] == "pinned-public-key"
    assert admission["releaseIndexDigest"] == index.index_digest
    assert admission["verifiedSigners"] == [
        {
            "mode": "pinned-public-key",
            "keyId": KEY_ID,
            "publicKeyDigest": config.trust_key_fingerprint,
        }
    ]
    identities = list(
        (config.state_root / "updater" / "installed-authority" / "identity").glob("*.json")
    )
    assert len(identities) == 1
    identity = json.loads(identities[0].read_text())
    assert identity["releaseId"] == signed["release"]["releaseId"]
    assert identity["releaseIndexDigest"] == index.index_digest
    assert identity["installerDigest"] == signed["artifacts"]["installer"]["digest"]
    assert identity["installerOrigin"] == installer.INSTALLER_ORIGIN
    assert identity["installerVersion"] == installer.INSTALLER_VERSION
    assert identity["actorId"] == "local-owner-test"
    assert not (config.state_root / "updater" / "genesis-boundary.json").exists()

    install_trust = json.loads((trust_dir / "install-trust.json").read_text())
    assert install_trust["schema"] == "stateport.internal-install-trust/v1"
    assert install_trust["trustRootDigest"] == trust_root["trustRootDigest"]
    assert install_trust["keyId"] == KEY_ID
    assert install_trust["publicKeyFingerprint"] == config.trust_key_fingerprint
    assert install_trust["admissionDigest"] == admission["admissionDigest"]
    assert install_trust["installedIdentityDigest"] == identity["identityDigest"]

    # The installed updater entry point binds the control-plane seam exactly.
    wrapper_path = config.state_root / "bin" / "stateport-update"
    assert wrapper_path.is_file() and not wrapper_path.is_symlink()
    assert stat.S_IMODE(wrapper_path.stat().st_mode) & 0o777 == 0o755
    wrapper_text = wrapper_path.read_text(encoding="utf-8")
    assert wrapper_text.startswith("#!/bin/sh\n")
    assert (
        "export STATEPORT_UPDATER_CONTROL_PLANE=stateport_updater.control_plane:build\n"
        in wrapper_text
    )
    assert f"export STATEPORT_COSIGN={installer.INSTALLED_COSIGN_PATH}\n" in wrapper_text
    assert "STATEPORT_UPDATER_BUNDLE_ROOT" not in wrapper_text
    assert f"export STATEPORT_QUADLET_ROOT={config.live_quadlet_root}\n" in wrapper_text
    assert wrapper_text.endswith(
        f"exec {config.state_root}/updater-venv/bin/python -m stateport_updater "
        f'--state-root {config.state_root}/updater "$@"\n'
    )

    # Runtime identity evidence is captured from the services, not claimed.
    evidence = json.loads((config.state_root / "runtime-identity-evidence.json").read_text())
    assert {item["serviceId"] for item in evidence["evidence"]} == set(REVISION_SERVICES)
    for item in evidence["evidence"]:
        assert item["source"] == "http-health"
        assert item["url"].startswith("http://127.0.0.1:")


def test_installed_operational_files_never_reference_per_run_temp_paths(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    """Installed files that execute after the install run must not bind any
    per-run path (the bootstrap deletes its download directory on exit)."""
    outcome, _runner, _fixture, config = _happy(tmp_path, trust, cosign_executable)
    assert outcome.status == "succeeded", outcome.message

    operational_files = [config.state_root / "bin" / "stateport-update"]
    operational_files.extend(
        path for path in sorted(config.live_quadlet_root.rglob("*")) if path.is_file()
    )
    assert len(operational_files) > 1
    forbidden = (
        str(config.cosign),  # the per-run download location in a real install
        str(config.installer_path),
        "$tmp",
        "stateport-wsl2-install",
        "/.part",
    )
    for path in operational_files:
        text = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in text, f"{path} references per-run path token {token!r}"



def test_wsl1_refuses_before_plan_emission_or_any_install_mutation(
    tmp_path: Path,
    trust: dict[str, object],
    cosign_executable: Path,
) -> None:
    fixture = _signed_index(tmp_path / "fixture", trust)
    config = _config(fixture, tmp_path, cosign=cosign_executable)
    runner = FakeRunner()
    fetcher = FakeFetcher()
    probe = FakeProbe(
        _facts(),
        substrate=installer.HostSubstrateFacts(
            kernel_release="4.4.0-19041-Microsoft",
            proc_version="Linux version 4.4.0-19041-Microsoft",
            wsl_interop_present=True,
            wsl_distro_name_present=True,
        ),
    )

    outcome = _run_install(config, runner=runner, probe=probe, fetcher=fetcher)

    assert outcome.status == "refused"
    assert outcome.code == "wsl1_substrate_unsupported"
    assert outcome.receipt_path is None
    assert probe.gather_calls == 0
    assert runner.calls == []
    assert fetcher.requests == []
    # The installer itself must not mutate before the wsl1 refusal.  The
    # _config fixture pre-creates the state root (the persisted control-plane
    # operator token), so assert no install/updater artifacts appeared.
    assert not (config.state_root / "receipts").exists()
    assert not (config.state_root / "intent").exists()
    assert not (config.state_root / "updater").exists()


def test_wsl2_ubuntu_2404_installs_the_separate_signed_target(
    tmp_path: Path,
    trust: dict[str, object],
    cosign_executable: Path,
) -> None:
    fixture = _signed_index(
        tmp_path / "fixture", trust, target_id=installer.WSL2_TARGET_ID
    )
    config = _config(
        fixture,
        tmp_path,
        cosign=cosign_executable,
        expected_target=installer.WSL2_TARGET_ID,
    )
    substrate = installer.HostSubstrateFacts(
        kernel_release="6.6.87.2-microsoft-standard-WSL2",
        proc_version="Linux version 6.6.87.2-microsoft-standard-WSL2",
        wsl_interop_present=True,
        wsl_distro_name_present=True,
    )
    outcome = _run_install(
        config,
        runner=FakeRunner(),
        probe=FakeProbe(_facts(), occupied=[], substrate=substrate),
        fetcher=FakeFetcher(),
    )

    assert outcome.status == "succeeded", outcome.message
    receipt = json.loads(outcome.receipt_path.read_text(encoding="utf-8"))
    assert receipt["target"]["targetId"] == installer.WSL2_TARGET_ID
    assert receipt["host"]["supportTier"] == "compatible_unvalidated"
    assert receipt["host"]["substrate"] == "wsl2"
    assert "microsoft-standard-WSL2" in receipt["host"]["kernelRelease"]
    assert receipt["host"]["osId"] == "ubuntu"
    assert receipt["host"]["versionId"] == "24.04"


def test_wsl2_prepare_mode_auto_selects_target_without_runtime_mutation(
    tmp_path: Path,
    trust: dict[str, object],
    cosign_executable: Path,
) -> None:
    fixture = _signed_index(
        tmp_path / "fixture", trust, target_id=installer.WSL2_TARGET_ID
    )
    config = _config(fixture, tmp_path, cosign=cosign_executable)
    config = replace(
        config,
        expected_target=installer.PORTABLE_LINUX_TARGET_ID,
        prepare_execution_host=True,
    )
    substrate = installer.HostSubstrateFacts(
        kernel_release="6.6.87.2-microsoft-standard-WSL2",
        proc_version="Linux version 6.6.87.2-microsoft-standard-WSL2",
        wsl_interop_present=True,
        wsl_distro_name_present=True,
    )
    runner = FakeRunner()
    probe = FakeProbe(_facts(), occupied=[], substrate=substrate)

    outcome = _run_install(
        config,
        runner=runner,
        probe=probe,
        fetcher=FakeFetcher(),
    )

    assert outcome.status == "prepared"
    assert outcome.code == "execution_host_plan_ready"
    assert outcome.execution_host is not None
    assert probe.gather_calls == 1
    assert not [call for call in runner.calls if call[:2] == ("podman", "pull")]
    assert not [call for call in runner.calls if call[:2] == ("systemctl", "--user")]


def test_wsl2_bootstrap_is_deterministic_pinned_and_one_command_ready(
    tmp_path: Path,
    trust: dict[str, object],
) -> None:
    fixture = _signed_index(
        tmp_path / "fixture", trust, target_id=installer.WSL2_TARGET_ID,
        version="0.1.0-alpha.5",
    )
    candidate = fixture.index_path.parent / "release"
    shutil.copyfile(fixture.index_path, candidate / "release-index.json")
    shutil.copyfile(
        fixture.bundle_root / "release-index.sigstore.json",
        candidate / "release-index.sigstore.json",
    )
    for image_id in IMAGES:
        shutil.copyfile(
            fixture.bundle_root / f"{image_id}.sigstore.json",
            candidate / f"{image_id}.sigstore.json",
        )

    arguments = {
        "candidate": candidate,
        "trust_public_key": Path(str(trust["public"])),
        "release_root_url": "https://example.invalid/download/0.1.0-alpha.5",
    }
    first = wsl2_bootstrap.render(**arguments)
    second = wsl2_bootstrap.render(**arguments)
    assert first == second
    text = first.decode("utf-8")
    assert "--prepare-execution-host" in text
    assert "stateport-execution-host-provision materialize" in text
    assert "stateport-execution-host-provision provision" in text
    assert text.index("ensure_root_helper_parent / 0 0 sudo") < text.index(
        'sudo -n install -o root -g root -m 0555 "$tmp/provisioner"'
    )
    assert text.count('python3 "$tmp/installer"') == 2
    assert "Windows 11 build 22000 or newer is required" in text
    assert "wsl2-ubuntu2404-linux-amd64-rootless-podman-quadlet" in text
    assert "apt-get install -y" in text and "skopeo" in text
    assert 'PROBE_ROOT="https://example.invalid/download/alpha5-manifests"' in text
    assert "StatePort Alpha.5 transport probe passed" in text
    assert "StatePort Alpha.5 materialization preflight passed" in text
    # The bootstrap sources /etc/os-release, which exports VERSION; the
    # release identity must survive that sourcing for the owner-facing prompts.
    assert 'STATEPORT_VERSION="0.1.0-alpha.5"' in text
    assert '\nVERSION=' not in text
    assert '"$VERSION"' not in text
    probe_start = text.index('if [ "$mode" = probe ]; then')
    probe_end = text.index("\nfi\n", probe_start)
    probe = text[probe_start:probe_end]
    assert "7 exact image manifests verified; installer was not executed" in probe
    assert not any(marker in probe for marker in ("sudo", "apt-get", 'python3 "$tmp/installer"'))
    preflight_start = text.index('if [ "$mode" = materialization-preflight ]; then')
    preflight_end = text.index("\nfi\n", preflight_start)
    preflight = text[preflight_start:preflight_end]
    assert "absent-parent creation order verified" in preflight
    assert not any(
        marker in preflight
        for marker in ("sudo", "apt-get", "skopeo", "manifest_carrier", 'python3 "$tmp/installer"')
    )
    assert 'partial="$destination.part"' in text
    assert 'while [ "$attempt" -le 4 ]' in text
    assert 'fail "Download failed after 4 attempts: $label ($url)"' in text
    # F17: every curl invocation is bounded; a stalled TLS connection enters
    # the labeled retry loop instead of hanging forever.
    curl_calls = [line for line in text.splitlines() if "curl -" in line]
    assert curl_calls
    assert all(
        "--connect-timeout 20" in line and "--max-time 600" in line for line in curl_calls
    )
    # F15: apt waits out fresh-boot unattended-upgrades locks and retries the
    # update once instead of failing on "Could not get lock".
    assert text.count("apt-get update -o DPkg::Lock::Timeout=300") == 2
    assert "StatePort apt update retry after lock contention" in text
    # F10: after the privileged provisioner confines the invoking user into the
    # socket group, the user manager is restarted once so the keep-groups
    # container starts with the fresh membership, before the final installer.
    assert text.index(
        "stateport-execution-host-provision provision"
    ) < text.index('sudo -n systemctl restart "user@$(id -u).service"') < text.rindex(
        'python3 "$tmp/installer"'
    )
    assert "apt-get install -y -o DPkg::Lock::Timeout=300" in text
    # F16: the sudo timestamp is refreshed immediately before the sudo -n
    # stage; slow links can no longer expire it mid-run after partial work.
    assert text.count("sudo -v") == 2
    last_refresh = text.rindex("sudo -v")
    assert "sudo -v\nensure_root_helper_parent / 0 0 sudo" in text
    for line in text.splitlines():
        if line.startswith("sudo -n"):
            assert text.index(line) > last_refresh, (
                f"sudo -n statement executes before the final timestamp refresh: {line}"
            )
    # F18: signal traps exit with the conventional status (HUP 129, INT 130,
    # TERM 143) so the EXIT cleanup runs and the script never continues with a
    # deleted working directory.
    assert "EXIT HUP INT TERM" not in text
    assert text.count("trap 'exit 129' HUP") == 3
    assert text.count("trap 'exit 130' INT") == 3
    assert text.count("trap 'exit 143' TERM") == 3
    assert text.count("trap 'rm -rf \"$tmp\"' EXIT") == 3
    loaded_index = load_release_index_file(fixture.index_path)
    document = loaded_index.document
    assert f'check "{hashlib.sha256(fixture.index_path.read_bytes()).hexdigest()}" "$tmp/release-index.json"' in text
    for artifact_id, destination in (
        ("installer", "$tmp/installer"),
        ("executionHostProvisioner", "$tmp/provisioner"),
        ("updater", "$tmp/updater"),
    ):
        digest = str(document["signed"]["artifacts"][artifact_id]["digest"]).removeprefix("sha256:")
        assert f'check "{digest}" "{destination}"' in text
    assert '--source-archive "$RELEASE_ROOT/stateport-source.tar"' in text
    assert document["signed"]["source"]["commit"] == COMMIT
    assert document["signed"]["source"]["tree"] == TREE
    assert loaded_index.signed_digest.startswith("sha256:")
    for image in document["signed"]["images"]:
        signature = image["signature"]
        assert (
            f"manifest_carrier {image['imageId']} {image['reference']} "
            f"{signature['subjectDigest']}"
        ) in text
        assert (
            f'get "$PROBE_ROOT/{image["imageId"]}.json" '
            f'"$tmp/{image["imageId"]}.manifest.json"'
        ) in probe
        assert (
            f'check "{str(signature["subjectDigest"]).removeprefix("sha256:")}" '
            f'"$tmp/{image["imageId"]}.manifest.json"'
        ) in probe
    assert not [line for line in text.splitlines() if line.startswith("+")]
    script = tmp_path / "install.sh"
    script.write_bytes(first)
    completed = subprocess.run(
        ["sh", "-n", str(script)], capture_output=True, text=True, check=False
    )
    assert completed.returncode == 0, completed.stderr


def test_alpha11_bootstrap_authenticates_packages_before_sudo(
    tmp_path: Path,
    trust: dict[str, object],
) -> None:
    fixture = _signed_index(
        tmp_path / "fixture",
        trust,
        target_id=installer.WSL2_TARGET_ID,
        version="0.1.0-alpha.5",
    )
    package_bundle = tmp_path / "podman-package-bundle.tar"
    _write_podman_package_bundle(package_bundle)
    _alpha11, candidate = _alpha11_fixture(fixture, package_bundle)

    text = wsl2_bootstrap.render(
        candidate=candidate,
        trust_public_key=Path(str(trust["public"])),
        release_root_url="https://example.invalid/download/0.1.0-alpha.11",
    ).decode("utf-8")

    subprocess.run(["/bin/sh", "-n", "-c", text], check=True)
    invocations = _rendered_install_invocations(text)
    assert len(invocations) == 2
    prepare = next(argv for argv in invocations if "--prepare-execution-host" in argv)
    final = next(argv for argv in invocations if "--prepare-execution-host" not in argv)
    required_artifact_flags = {
        "--release-index",
        "--bundle-root",
        "--trust-public-key",
        "--trust-key-id",
        "--trust-key-fingerprint",
        "--updater-wheel",
        "--execution-host-provisioner",
        "--compose",
        "--source-archive",
        "--release-notes",
        "--known-limitations",
        "--podman-package-bundle",
        "--podman-package-preflight",
        "--confirmed-package-plan-digest",
        "--cosign",
        "--installer-path",
        "--execution-host-receipt",
        "--state-root",
    }
    for argv in invocations:
        installer._parser().parse_args(argv)
        assert required_artifact_flags <= set(argv)
        assert argv[argv.index("--confirmed-package-plan-digest") + 1] == (
            "$package_plan_digest"
        )
    assert prepare[prepare.index("--confirmed-plan-digest") + 1] == (
        "$package_plan_digest"
    )
    assert "--yes" not in prepare
    assert final[final.index("--confirmed-plan-digest") + 1] == "$install_plan_digest"
    assert "--yes" in final
    package_download = text.index("stateport-podman-package-bundle.tar")
    package_preflight = text.index("--verify-podman-package-bundle")
    # Host-level python venv dependency prep (universe) may precede the
    # admission so its offline closure simulation resolves, but the signed
    # bundle's own debs are only installed (via dpkg, since noble apt 2.8.3
    # cannot install local .debs) after the plan is authenticated.
    venv_prep = text.index("sudo apt-get install -y --no-install-recommends")
    bundle_install = text.index("dpkg -i -- *.deb")
    assert package_download < venv_prep < package_preflight < bundle_install
    assert "Type install-packages to authorize this exact authenticated package plan" in text
    assert text.index("install-packages", text.index("Type install-packages")) < bundle_install
    assert "--verify-installed-podman-packages" in text
    assert "--verify-sealed-podman-package-bundle" in text
    assert '--podman-package-bundle "$tmp/podman-package-bundle.tar"' in text
    assert 'cd "$1/podman-package-bundle/packages" && dpkg -i -- *.deb' in text
    assert "Type install-exact to authorize this exact plan" in text
    assert "--confirmed-plan-digest" in text
    assert " questing" not in text.casefold()
    assert "apt-get install -y -o DPkg::Lock::Timeout=300" not in text
    assert "\n+  --" not in text


def test_alpha11_bootstrap_retains_signature_bundles_into_digest_slots_before_preflight(
    tmp_path: Path,
    trust: dict[str, object],
) -> None:
    fixture = _signed_index(
        tmp_path / "fixture",
        trust,
        target_id=installer.WSL2_TARGET_ID,
        version="0.1.0-alpha.5",
    )
    package_bundle = tmp_path / "podman-package-bundle.tar"
    _write_podman_package_bundle(package_bundle)
    _alpha11, candidate = _alpha11_fixture(fixture, package_bundle)

    text = wsl2_bootstrap.render(
        candidate=candidate,
        trust_public_key=Path(str(trust["public"])),
        release_root_url="https://example.invalid/download/0.1.0-alpha.11",
    ).decode("utf-8")

    subprocess.run(["/bin/sh", "-n", "-c", text], check=True)
    document = json.loads(candidate.joinpath("release-index.json").read_text(encoding="utf-8"))
    expected_slots: list[tuple[str, str, str]] = []
    for signature in document["signatures"]:
        digest = signature["bundle"]["digest"].removeprefix("sha256:")
        name = signature["bundle"]["uri"].rsplit("/", 1)[-1]
        expected_slots.append((digest, name, "$tmp/release-index.sigstore.json"))
    for image in document["signed"]["images"]:
        digest = image["signature"]["bundle"]["digest"].removeprefix("sha256:")
        name = image["signature"]["bundle"]["uri"].rsplit("/", 1)[-1]
        expected_slots.append(
            (digest, name, f'$tmp/image-bundles/{name}')
        )
    retention = text.index("retain_slot() {")
    preflight = text.index("--verify-podman-package-bundle")
    assert retention < preflight
    for digest, name, staged in expected_slots:
        assert f'retain_slot "$tmp/{digest}" "{staged}" "{name}"' in text
    assert retention > text.index("image-carriers/stateport-api")
    first_slot = text.index("retain_slot \"$tmp/", retention)
    assert first_slot < preflight
    # Host python venv dependency prep and leftover-dpkg-row normalization must run
    # before the immutable package-preflight admission queries the baseline.
    assert "python3-venv" in text
    venv_prep = text.index("sudo apt-get install -y --no-install-recommends")
    assert venv_prep < preflight
    # the prep must install the full host dependency set, including the real
    # python3-venv (matching the signed bundle), so the offline closure
    # simulation resolves and the baseline is not a phantom
    install_line = text[venv_prep:preflight]
    assert "python3-venv" in install_line
    assert "nftables" in install_line
    assert "libglib2.0-0t64" in install_line


def test_phantom_not_installed_podman_record_is_an_install_action(
    tmp_path: Path,
    trust: dict[str, object],
    cosign_executable: Path,
) -> None:
    """A negative not-installed dpkg row must not refuse the package preflight.

    On a stock Noble cloud image, installing netavark leaves podman as a
    "not-installed" dpkg record that dpkg-query --show reports with rc 0 and
    empty version/architecture fields. The preflight must treat that as a
    genuine absence (the sealed bundle installs podman), not as a malformed
    installed identity.
    """
    base = _signed_index(
        tmp_path / "fixture",
        trust,
        target_id=installer.WSL2_TARGET_ID,
        version="0.1.0-alpha.5",
    )
    package_bundle = tmp_path / "podman-package-bundle.tar"
    _write_podman_package_bundle(package_bundle)
    fixture, _candidate = _alpha11_fixture(base, package_bundle)

    class PhantomRunner(PackageRunner):
        def run(self, argv: Sequence[str], *, timeout: int) -> installer.Completed:
            call = tuple(str(item) for item in argv)
            if call[:2] == ("dpkg-query", "--show") and call[-1] == "podman":
                return installer.Completed(0, "not-installed\t\t\n", "")
            if call[:2] == ("apt-get", "--simulate"):
                # The phantom podman is the only package the transaction plans
                # to install; every other bundle package is already present at
                # the pinned version, so the offline closure simulation emits
                # exactly one Inst line to match the transaction.
                return installer.Completed(
                    0,
                    "Inst podman (5.4.2+ds1-2stateport2~24.04.1)\n"
                    "0 upgraded, 1 newly installed, 0 to remove.\n",
                    "",
                )
            return super().run(call, timeout=timeout)

    output_dir = tmp_path / "phantom-output"
    preflight = installer.verify_podman_package_bundle(
        installer.PackageBundlePreflightConfig(
            release_index=fixture.index_path,
            bundle_root=fixture.bundle_root,
            trust_public_key=Path(str(fixture.trust["public"])),
            trust_key_id=KEY_ID,
            trust_key_fingerprint=str(fixture.trust["fingerprint"]),
            cosign=cosign_executable,
            installer_path=fixture.artifact_paths["installer"],
            podman_package_bundle=package_bundle,
            output_dir=output_dir,
            expected_target=installer.WSL2_TARGET_ID,
        ),
        runner=PhantomRunner(podman_version="5.4.2"),
    )
    transaction = preflight["transaction"]
    assert transaction["podman"]["action"] == "install"
    assert transaction["podman"]["currentVersion"] is None
    assert transaction["podman"]["targetVersion"] == PACKAGE_VERSIONS["podman"]


def test_installed_podman_package_evidence_binds_exact_runtime() -> None:
    packages = {
        name: {
            "architecture": PACKAGE_ARCHITECTURES[name],
            "version": version,
            "sha256": "sha256:" + f"{position % 16:x}" * 64,
            "size": position,
        }
        for position, (name, version) in enumerate(sorted(PACKAGE_VERSIONS.items()), 1)
    }
    runtime_contract = {
        "podmanMinimumVersion": "5.4.2",
        "runcMinimumVersion": "1.3.4",
        "slirp4netnsMinimumVersion": "1.2.1",
        "ociRuntime": "runc",
        "networkBackend": "netavark",
    }
    package_plan = {
        "releaseIndexDigest": "sha256:" + "1" * 64,
        "signedPayloadDigest": "sha256:" + "2" * 64,
        "artifactDigest": "sha256:" + "3" * 64,
        "bundleManifestDigest": "sha256:" + "4" * 64,
        "targetId": installer.WSL2_TARGET_ID,
        "rootfsIdentity": installer._WSL_ROOTFS_IDENTITY,
        "dependencyClosure": "apt-simulated-empty-sources-no-download",
        "transaction": {
            name: {
                "action": "keep",
                "architecture": record["architecture"],
                "currentVersion": record["version"],
                "targetVersion": record["version"],
            }
            for name, record in packages.items()
        },
        "packages": packages,
        "runtimeContract": runtime_contract,
    }
    preflight = {
        "schema": "stateport.podman-package-preflight/v1",
        **package_plan,
        "packagePlanDigest": stateport_release.canonical_digest(package_plan),
        "dpkgStateBeforeDigest": stateport_release.canonical_digest(
            package_plan["transaction"]
        ),
    }

    with pytest.raises(installer.InstallerRefusal) as missing_admission:
        installer.verify_installed_podman_packages(preflight, runner=FakeRunner())
    assert missing_admission.value.code == "package_preflight_invalid"

    preflight["releaseAdmission"] = {
        "schema": "stateport.release-admission/v1",
        "status": "verified",
        "releaseIndexDigest": preflight["releaseIndexDigest"],
        "signedPayloadDigest": preflight["signedPayloadDigest"],
        "targetId": preflight["targetId"],
        "artifactDigests": {"podmanPackageBundle": preflight["artifactDigest"]},
    }

    with pytest.raises(installer.InstallerRefusal) as not_installed:
        installer.verify_installed_podman_packages(
            preflight,
            runner=FakeRunner(package_status="config-files"),
        )
    assert not_installed.value.code == "package_installation_invalid"

    result = installer.verify_installed_podman_packages(preflight, runner=FakeRunner())

    assert result["artifactDigest"] == preflight["artifactDigest"]
    assert result["packages"]["podman"]["version"] == (
        "5.4.2+ds1-2stateport2~24.04.1"
    )
    assert result["dependencies"]["runc"]["minimumVersion"] == "1.3.4"
    assert result["dependencies"]["slirp4netns"]["minimumVersion"] == "1.2.1"
    assert result["runtime"] == {"ociRuntime": "runc", "networkBackend": "netavark"}
    assert result["dpkgAudit"] == "clean"


def test_alpha11_release_admission_needs_no_python_venv_before_package_mutation(
    tmp_path: Path,
    trust: dict[str, object],
    cosign_executable: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = _signed_index(
        tmp_path / "fixture",
        trust,
        target_id=installer.WSL2_TARGET_ID,
        version="0.1.0-alpha.5",
    )
    package_bundle = tmp_path / "podman-package-bundle.tar"
    _write_podman_package_bundle(package_bundle)
    fixture, _candidate = _alpha11_fixture(base, package_bundle)
    config = _config(
        fixture,
        tmp_path,
        cosign=cosign_executable,
        podman_package_bundle=str(fixture.artifact_paths["podmanPackageBundle"]),
    )
    clock = lambda: datetime.now(timezone.utc)  # noqa: E731
    monkeypatch.setattr(
        installer,
        "_install_venv",
        lambda *_args, **_kwargs: pytest.fail("pre-privilege admission used python3-venv"),
    )
    monkeypatch.setattr(
        installer,
        "_create_venv",
        lambda *_args, **_kwargs: pytest.fail("pre-privilege admission created a venv"),
    )

    admission = installer.verify_release_admission(
        config,
        runner=PackageRunner(podman_version="5.4.2"),
        fetcher=FakeFetcher(),
        module_loader=_modules,
        verifier_factory=lambda modules: FakeVerifier(clock),
        clock=clock,
    )

    assert admission["status"] == "verified"
    assert admission["targetId"] == installer.WSL2_TARGET_ID
    assert set(admission["artifactDigests"]) == {
        "installer",
        "executionHostProvisioner",
        "podmanPackageBundle",
        "updater",
        "compose",
        "quadlet",
        "sourceArchive",
        "releaseNotes",
        "knownLimitations",
    }


def test_alpha11_install_receipt_binds_authenticated_package_results(
    tmp_path: Path,
    trust: dict[str, object],
    cosign_executable: Path,
) -> None:
    base = _signed_index(
        tmp_path / "fixture",
        trust,
        target_id=installer.WSL2_TARGET_ID,
        version="0.1.0-alpha.5",
    )
    package_bundle = tmp_path / "podman-package-bundle.tar"
    _write_podman_package_bundle(package_bundle)
    fixture, _candidate = _alpha11_fixture(base, package_bundle)
    preflight_path, package_plan_digest = _alpha11_preflight(
        fixture, tmp_path, package_bundle, cosign_executable
    )
    config = _config(
        fixture,
        tmp_path,
        cosign=cosign_executable,
        podman_package_bundle=str(fixture.artifact_paths["podmanPackageBundle"]),
        podman_package_preflight=preflight_path,
        confirmed_package_plan_digest=package_plan_digest,
        assume_yes=False,
    )
    runner = PackageRunner(podman_version="5.4.2")
    substrate = installer.HostSubstrateFacts(
        kernel_release="6.6.87.2-microsoft-standard-WSL2",
        proc_version="Linux version 6.6.87.2-microsoft-standard-WSL2",
        wsl_interop_present=True,
        wsl_distro_name_present=True,
    )

    outcome = _run_install(
        config,
        runner=runner,
        probe=FakeProbe(
            _facts(podman_version="5.4.2"), occupied=[], substrate=substrate
        ),
        fetcher=FakeFetcher(),
    )

    assert outcome.status == "succeeded", outcome.message
    assert outcome.receipt_path is not None
    receipt = json.loads(outcome.receipt_path.read_text(encoding="utf-8"))
    package_result = receipt["podmanPackageInstallation"]
    package_artifact = next(
        artifact
        for artifact in receipt["verification"]["artifacts"]
        if artifact["artifactId"] == "podmanPackageBundle"
    )
    assert package_result["artifactDigest"] == package_artifact["expectedDigest"]
    assert {
        name: record["version"] for name, record in package_result["packages"].items()
    } == PACKAGE_VERSIONS
    assert package_result["runtime"] == {
        "ociRuntime": "runc",
        "networkBackend": "netavark",
    }
    validate_install_receipt(receipt)
    tampered = json.loads(json.dumps(receipt))
    tampered["podmanPackageInstallation"]["packages"]["podman"]["version"] = "5.4.3-1"
    with pytest.raises(ReleaseContractError, match="package installation evidence disagrees"):
        validate_install_receipt(tampered)


def test_wsl2_bootstrap_refuses_a_non_alpha_signed_version(
    tmp_path: Path,
    trust: dict[str, object],
) -> None:
    fixture = _signed_index(
        tmp_path / "fixture", trust, target_id=installer.WSL2_TARGET_ID
    )
    candidate = fixture.index_path.parent / "release"
    shutil.copyfile(fixture.index_path, candidate / "release-index.json")
    shutil.copyfile(
        fixture.bundle_root / "release-index.sigstore.json",
        candidate / "release-index.sigstore.json",
    )
    for image_id in IMAGES:
        shutil.copyfile(
            fixture.bundle_root / f"{image_id}.sigstore.json",
            candidate / f"{image_id}.sigstore.json",
        )

    with pytest.raises(ValueError, match="0.1.0-alpha.N"):
        wsl2_bootstrap.render(
            candidate=candidate,
            trust_public_key=Path(str(trust["public"])),
            release_root_url="https://example.invalid/download/0.2.0-rc.1",
        )


def test_wsl2_bootstrap_materialization_parent_and_http_retry_fail_closed(
    tmp_path: Path,
    trust: dict[str, object],
) -> None:
    fixture = _signed_index(
        tmp_path / "fixture", trust, target_id=installer.WSL2_TARGET_ID,
        version="0.1.0-alpha.5",
    )
    candidate = fixture.index_path.parent / "release"
    shutil.copyfile(fixture.index_path, candidate / "release-index.json")
    shutil.copyfile(
        fixture.bundle_root / "release-index.sigstore.json",
        candidate / "release-index.sigstore.json",
    )
    for image_id in IMAGES:
        shutil.copyfile(
            fixture.bundle_root / f"{image_id}.sigstore.json",
            candidate / f"{image_id}.sigstore.json",
        )
    rendered = wsl2_bootstrap.render(
        candidate=candidate,
        trust_public_key=Path(str(trust["public"])),
        release_root_url="https://example.invalid/download/0.1.0-alpha.5",
    ).decode("utf-8")

    ensure_start = rendered.index("ensure_root_helper_parent() {")
    ensure_end = rendered.index("\n}\n", ensure_start) + 3
    ensure_function = rendered[ensure_start:ensure_end]
    fake_root = tmp_path / "fresh-root"
    for path in (fake_root, fake_root / "usr", fake_root / "usr/local"):
        path.mkdir()
        path.chmod(0o755)
    helper_source = tmp_path / "provisioner"
    helper_source.write_bytes(b"pinned helper\n")
    parent_script = tmp_path / "parent.sh"
    parent_script.write_text(
        "#!/bin/sh\nset -eu\n"
        'fail() { printf "%s\\n" "$*" >&2; exit 1; }\n'
        + ensure_function
        + "\n"
        + f'ensure_root_helper_parent "{fake_root}" "{os.getuid()}" "{os.getgid()}" local\n'
        + f'install -m 0555 -- "{helper_source}" "{fake_root}/usr/local/libexec/stateport-execution-host-provision"\n',
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["/bin/sh", str(parent_script)], capture_output=True, text=True, check=False
    )
    assert completed.returncode == 0, completed.stderr
    installed_helper = fake_root / "usr/local/libexec/stateport-execution-host-provision"
    assert installed_helper.read_bytes() == helper_source.read_bytes()
    assert stat.S_IMODE((fake_root / "usr/local/libexec").stat().st_mode) == 0o755

    installed_helper.unlink()
    (fake_root / "usr/local/libexec").rmdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (fake_root / "usr/local/libexec").symlink_to(outside, target_is_directory=True)
    refused = subprocess.run(
        ["/bin/sh", str(parent_script)], capture_output=True, text=True, check=False
    )
    assert refused.returncode != 0
    assert "symlinked" in refused.stderr
    assert not (outside / "stateport-execution-host-provision").exists()

    get_start = rendered.index("get() {")
    get_end = rendered.index("\n}\n", get_start) + 3
    get_function = rendered[get_start:get_end]
    check_line = next(
        line for line in rendered.splitlines() if line.startswith("check() {")
    )
    binary_root = tmp_path / "bin"
    binary_root.mkdir()
    curl = binary_root / "curl"
    curl.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        'count=0; [ ! -f "$CURL_COUNT" ] || count=$(cat "$CURL_COUNT")\n'
        'count=$((count + 1)); printf "%s\\n" "$count" > "$CURL_COUNT"\n'
        'output=; while [ "$#" -gt 0 ]; do case "$1" in -o) output=$2; shift 2 ;; *) shift ;; esac; done\n'
        'if [ "${CURL_FAIL_ALWAYS:-0}" = 1 ] || [ "$count" -eq 1 ]; then printf "%s\\n" "curl: (22) 503" >&2; exit 22; fi\n'
        'cp "$CURL_SOURCE" "$output"\n',
        encoding="utf-8",
    )
    curl.chmod(0o755)
    sleep = binary_root / "sleep"
    sleep.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    sleep.chmod(0o755)
    payload = tmp_path / "payload"
    payload.write_bytes(b"trusted payload\n")
    destination = tmp_path / "downloaded"
    count_path = tmp_path / "curl-count"
    get_script = tmp_path / "get.sh"
    get_script.write_text(
        "#!/bin/sh\nset -eu\n"
        'fail() { printf "%s\\n" "$*" >&2; exit 1; }\n'
        + get_function
        + "\n"
        + check_line
        + "\n"
        + f'get "https://example.invalid/helper" "{destination}" "execution-host provisioner"\n'
        + f'check "{hashlib.sha256(payload.read_bytes()).hexdigest()}" "{destination}"\n',
        encoding="utf-8",
    )
    environment = {
        "CURL_COUNT": str(count_path),
        "CURL_SOURCE": str(payload),
        "LC_ALL": "C",
        "PATH": f"{binary_root}:{os.environ.get('PATH', '')}",
    }
    retried = subprocess.run(
        ["/bin/sh", str(get_script)],
        capture_output=True,
        text=True,
        check=False,
        env=environment,
    )
    assert retried.returncode == 0, retried.stderr
    assert count_path.read_text(encoding="ascii").strip() == "2"
    assert destination.read_bytes() == payload.read_bytes()
    assert not destination.with_name(destination.name + ".part").exists()

    destination.unlink()
    count_path.unlink()
    permanently_failed = subprocess.run(
        ["/bin/sh", str(get_script)],
        capture_output=True,
        text=True,
        check=False,
        env={**environment, "CURL_FAIL_ALWAYS": "1"},
    )
    assert permanently_failed.returncode != 0
    assert count_path.read_text(encoding="ascii").strip() == "4"
    assert "execution-host provisioner (https://example.invalid/helper)" in permanently_failed.stderr
    assert not destination.exists()
    assert not destination.with_name(destination.name + ".part").exists()


def test_wsl2_bootstrap_manifest_carriers_supply_every_private_signature_payload(
    tmp_path: Path,
    trust: dict[str, object],
) -> None:
    fixture = _signed_index(
        tmp_path / "fixture", trust, target_id=installer.WSL2_TARGET_ID,
        version="0.1.0-alpha.5",
    )
    candidate = fixture.index_path.parent / "release"
    shutil.copyfile(fixture.index_path, candidate / "release-index.json")
    shutil.copyfile(
        fixture.bundle_root / "release-index.sigstore.json",
        candidate / "release-index.sigstore.json",
    )
    for image_id in IMAGES:
        shutil.copyfile(
            fixture.bundle_root / f"{image_id}.sigstore.json",
            candidate / f"{image_id}.sigstore.json",
        )
    rendered = wsl2_bootstrap.render(
        candidate=candidate,
        trust_public_key=Path(str(trust["public"])),
        release_root_url="https://example.invalid/download/0.1.0-alpha.5",
    ).decode("utf-8")
    function_start = rendered.index("manifest_carrier() {")
    function_end = rendered.index("\n}\n", function_start) + 3
    function = rendered[function_start:function_end]
    calls = [line for line in rendered.splitlines() if line.startswith("manifest_carrier ")]
    probe_start = rendered.index('if [ "$mode" = probe ]; then')
    probe_end = rendered.index("\nfi\n", probe_start)
    probe_downloads = [
        line for line in rendered[probe_start:probe_end].splitlines()
        if line.startswith(("  get ", "  check "))
    ]

    manifest_root = tmp_path / "manifests"
    manifest_root.mkdir()
    for image_id in IMAGES:
        (manifest_root / image_id).write_bytes(_image_manifest_bytes(image_id))
    binary_root = tmp_path / "bin"
    binary_root.mkdir()
    skopeo = binary_root / "skopeo"
    skopeo.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        "reference=${3#docker://}\n"
        "image=${reference##*/}\n"
        "image=${image%@*}\n"
        'exec cat "$MANIFEST_ROOT/$image"\n',
        encoding="utf-8",
    )
    skopeo.chmod(0o755)

    probe_root = tmp_path / "probe-root"
    probe_root.mkdir()
    probe_script = tmp_path / "probe-manifests.sh"
    probe_script.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        f'tmp="{probe_root}"\n'
        'PROBE_ROOT="https://example.invalid/download/alpha5-manifests"\n'
        'fail() { printf "%s\\n" "$*" >&2; exit 1; }\n'
        'get() { name=${1##*/}; name=${name%.json}; cp "$MANIFEST_ROOT/$name" "$2"; }\n'
        'check() { printf "%s  %s\\n" "$1" "$2" | sha256sum -c --status || fail "checksum"; }\n'
        + "\n".join(probe_downloads)
        + "\n",
        encoding="utf-8",
    )
    probe_completed = subprocess.run(
        ["/bin/sh", str(probe_script)],
        check=False,
        capture_output=True,
        text=True,
        env={
            "LC_ALL": "C",
            "MANIFEST_ROOT": str(manifest_root),
            "PATH": os.environ.get("PATH", ""),
        },
    )
    assert probe_completed.returncode == 0, probe_completed.stderr
    for image_id in IMAGES:
        assert (probe_root / f"{image_id}.manifest.json").read_bytes() == _image_manifest_bytes(
            image_id
        )

    carrier_root = tmp_path / "carrier-root"
    for directory in ("image-manifests", "image-archives", "image-carriers"):
        (carrier_root / directory).mkdir(parents=True)
    script = tmp_path / "materialize-carriers.sh"
    script.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        f'tmp="{carrier_root}"\n'
        'fail() { printf "%s\\n" "$*" >&2; exit 1; }\n'
        'check() { printf "%s  %s\\n" "$1" "$2" | sha256sum -c --status || fail "checksum"; }\n'
        + function
        + "\n"
        + "\n".join(calls)
        + "\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["/bin/sh", str(script)],
        check=False,
        capture_output=True,
        text=True,
        env={
            "LC_ALL": "C",
            "MANIFEST_ROOT": str(manifest_root),
            "PATH": f"{binary_root}:{os.environ.get('PATH', '')}",
        },
    )
    assert completed.returncode == 0, completed.stderr
    index = load_release_index_file(fixture.index_path)
    assert installer._local_image_manifest_payloads(index, carrier_root) == {
        image_id: _image_manifest_bytes(image_id) for image_id in IMAGES
    }


def test_wsl2_bootstrap_oci_archive_creation_is_byte_deterministic(
    tmp_path: Path,
    trust: dict[str, object],
) -> None:
    fixture = _signed_index(
        tmp_path / "fixture", trust, target_id=installer.WSL2_TARGET_ID,
        version="0.1.0-alpha.5",
    )
    candidate = fixture.index_path.parent / "release"
    shutil.copyfile(fixture.index_path, candidate / "release-index.json")
    shutil.copyfile(
        fixture.bundle_root / "release-index.sigstore.json",
        candidate / "release-index.sigstore.json",
    )
    for image_id in IMAGES:
        shutil.copyfile(
            fixture.bundle_root / f"{image_id}.sigstore.json",
            candidate / f"{image_id}.sigstore.json",
        )
    rendered = wsl2_bootstrap.render(
        candidate=candidate,
        trust_public_key=Path(str(trust["public"])),
        release_root_url="https://example.invalid/download/0.1.0-alpha.5",
    ).decode("utf-8")
    function_start = rendered.index("manifest_carrier() {")
    function_end = rendered.index("\n}\n", function_start)
    function = rendered[function_start:function_end]
    tar_lines = [
        line.strip() for line in function.splitlines() if "tar -cf" in line
    ]
    assert len(tar_lines) == 1
    tar_command = tar_lines[0]
    for flag in ("--sort=name", "--mtime=@0", "--owner=0", "--group=0", "--numeric-owner"):
        assert flag in tar_command

    image_id = IMAGES[0]
    manifest = _image_manifest_bytes(image_id)
    digest_hex = hashlib.sha256(manifest).hexdigest()
    archives: list[bytes] = []
    for run, mtime in enumerate(("202001010000.00", "203012312359.59")):
        root = tmp_path / f"run-{run}"
        carrier = root / "image-carriers" / image_id
        blobs = carrier / "blobs" / "sha256"
        blobs.mkdir(parents=True)
        (blobs / digest_hex).write_bytes(manifest)
        (carrier / "index.json").write_text(
            f'{{"schemaVersion":2,"manifests":[{{"digest":"sha256:{digest_hex}"}}]}}\n',
            encoding="utf-8",
        )
        (root / "image-archives").mkdir()
        subprocess.run(
            ["find", str(carrier), "-exec", "touch", "-t", mtime, "{}", "+"],
            check=True,
        )
        script = root / "archive.sh"
        script.write_text(
            "#!/bin/sh\n"
            "set -eu\n"
            f'tmp="{root}"\n'
            f'image_id={image_id}\n'
            f'digest_hex={digest_hex}\n'
            f'carrier="{carrier}"\n'
            + tar_command
            + "\n",
            encoding="utf-8",
        )
        completed = subprocess.run(
            ["/bin/sh", str(script)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 0, completed.stderr
        archives.append(
            (root / "image-archives" / f"{image_id}.oci.tar").read_bytes()
        )

    assert archives[0] == archives[1]


def test_wsl2_bootstrap_retains_the_authenticated_predecessor_bundle(
    tmp_path: Path,
) -> None:
    candidate = tmp_path / "candidate"
    bundle = candidate / "predecessor-bundle" / "release-index.sigstore.json"
    bundle.parent.mkdir(parents=True)
    bundle.write_bytes(b"authenticated predecessor bundle\n")
    digest = sha256_file(bundle)
    descriptor = MappingProxyType(
        {
            "uri": "operator://release/release-index.sigstore.json",
            "digest": digest,
            "size": bundle.stat().st_size,
        }
    )
    signature = MappingProxyType({"bundle": descriptor})
    raw_index = MappingProxyType({"signatures": (signature,)})
    predecessor = MappingProxyType({"rawIndex": raw_index})
    successor = MappingProxyType({"predecessor": predecessor})
    document = MappingProxyType(
        {"signed": MappingProxyType({"successor": successor})}
    )

    lines = wsl2_bootstrap._predecessor_bundle_downloads(candidate, document)

    assert lines == [
        'mkdir -m 700 "$tmp/predecessor-bundle"',
        'get "$RELEASE_ROOT/predecessor-bundle/release-index.sigstore.json" "$tmp/predecessor-bundle/release-index.sigstore.json" "predecessor signature bundle"',
        f'check "{digest.removeprefix("sha256:")}" "$tmp/predecessor-bundle/release-index.sigstore.json"',
    ]
    bundle.unlink()
    with pytest.raises(ValueError, match="predecessor bundle is missing"):
        wsl2_bootstrap._predecessor_bundle_downloads(candidate, document)


def test_wrapper_survives_an_exact_reinstall(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    outcome, _runner, fixture, config = _happy(tmp_path, trust, cosign_executable)
    assert outcome.status == "succeeded", outcome.message
    wrapper_path = config.state_root / "bin" / "stateport-update"
    before = wrapper_path.read_bytes()

    rerun = _run_install(
        config,
        runner=FakeRunner(),
        probe=FakeProbe(_facts(), occupied=[]),
        fetcher=FakeFetcher(),
    )
    assert rerun.status == "succeeded", rerun.message
    assert wrapper_path.read_bytes() == before


def test_wrapper_conflict_refuses_closed(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    outcome, _runner, fixture, config = _happy(tmp_path, trust, cosign_executable)
    assert outcome.status == "succeeded", outcome.message
    wrapper_path = config.state_root / "bin" / "stateport-update"
    wrapper_path.write_text("#!/bin/sh\n# foreign content\n", encoding="utf-8")

    rerun = _run_install(
        config,
        runner=FakeRunner(),
        probe=FakeProbe(_facts(), occupied=[]),
        fetcher=FakeFetcher(),
    )
    assert rerun.status == "refused"
    assert rerun.code == "updater_wrapper_conflict"


def test_installed_control_plane_builds_from_the_installer_trust_root(
    tmp_path: Path,
    trust: dict[str, object],
    cosign_executable: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcome, _runner, fixture, config = _happy(tmp_path, trust, cosign_executable)
    assert outcome.status == "succeeded", outcome.message
    monkeypatch.setenv("STATEPORT_COSIGN", str(config.cosign))
    monkeypatch.delenv("STATEPORT_UPDATER_BUNDLE_ROOT", raising=False)
    monkeypatch.setenv("STATEPORT_QUADLET_ROOT", str(config.live_quadlet_root))

    # The installer retains the genesis index bundle in the durable
    # content-addressed root, so the installed control plane needs no
    # staging-directory environment override.
    bundle_bytes = (fixture.bundle_root / "release-index.sigstore.json").read_bytes()
    retained = (
        config.state_root
        / "updater"
        / "bundles"
        / hashlib.sha256(bundle_bytes).hexdigest()
        / "release-index.sigstore.json"
    )
    assert retained.is_file() and not retained.is_symlink()
    assert retained.read_bytes() == bundle_bytes
    assert retained.stat().st_mode & 0o777 == 0o600

    binding = updater_control_plane.build(config.state_root / "updater")

    policy = binding.verification_policy
    assert policy.expected_channel == "alpha"
    assert policy.expected_target == installer.EXPECTED_TARGET
    assert policy.expected_trust_mode == "pinned-public-key"
    assert {identity.key_id for identity in policy.accepted_public_keys} == {KEY_ID}
    assert {identity.public_key_fingerprint for identity in policy.accepted_public_keys} == {
        config.trust_key_fingerprint
    }
    assert binding.host.quadlet_root == config.live_quadlet_root


def test_signature_tamper_refused_before_cosign(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    fixture = _signed_index(tmp_path / "fixture", trust)
    document = json.loads(fixture.index_path.read_text(encoding="utf-8"))
    document["signed"]["release"]["version"] = "0.2.0-rc.2"
    tampered = tmp_path / "tampered-index.json"
    tampered.write_text(json.dumps(document) + "\n", encoding="utf-8")
    runner = FakeRunner()
    outcome = _run_install(
        _config(fixture, tmp_path, release_index=str(tampered), cosign=cosign_executable),
        runner=runner,
        probe=FakeProbe(_facts()),
        fetcher=FakeFetcher(),
    )
    assert outcome.status == "refused"
    assert outcome.code == "signature_payload_mismatch"
    # The tamper is caught by the stdlib digest binding before any trust decision.
    assert not [call for call in runner.calls if call[0].endswith("/pip")]


def test_cosign_verification_failure_refused(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    fixture = _signed_index(tmp_path / "fixture", trust)
    runner = FakeRunner(cosign_returncode=1)
    outcome = _run_install(
        _config(fixture, tmp_path, cosign=cosign_executable),
        runner=runner,
        probe=FakeProbe(_facts()),
        fetcher=FakeFetcher(),
    )
    assert outcome.status == "refused"
    assert outcome.code == "signature_verification_failed"
    assert not [call for call in runner.calls if call[0].endswith("/pip")]


def test_missing_cosign_refused(tmp_path: Path, trust: dict[str, object]) -> None:
    fixture = _signed_index(tmp_path / "fixture", trust)
    outcome = _run_install(
        _config(fixture, tmp_path, cosign=tmp_path / "no-such-cosign"),
        runner=FakeRunner(),
        probe=FakeProbe(_facts()),
        fetcher=FakeFetcher(),
    )
    assert outcome.status == "refused"
    assert outcome.code == "cosign_missing"


def test_wrong_architecture_refused(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    outcome, _, _, _ = _happy(tmp_path, trust, cosign_executable, architecture="arm64")
    assert outcome.status == "refused"
    assert outcome.code == "host_architecture_mismatch"


def test_capable_non_baseline_host_installs_as_compatible_unvalidated(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    for os_id, version_id in (
        ("fedora", "44"),
        ("debian", "13"),
        ("arch", "rolling"),
    ):
        root = tmp_path / f"{os_id}-{version_id}"
        root.mkdir(parents=True, exist_ok=True)
        outcome, _, _, _ = _happy(
            root,
            trust,
            cosign_executable,
            os_id=os_id,
            version_id=version_id,
        )
        assert outcome.status == "succeeded", (os_id, version_id, outcome.code, outcome.message)
        receipt = json.loads(outcome.receipt_path.read_text(encoding="utf-8"))
        assert receipt["host"]["osId"] == os_id
        assert receipt["host"]["versionId"] == version_id
        assert receipt["host"]["supportTier"] == "compatible_unvalidated"


def test_validated_baseline_host_records_support_tier(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    outcome, _, _, _ = _happy(tmp_path, trust, cosign_executable)
    receipt = json.loads(outcome.receipt_path.read_text(encoding="utf-8"))
    assert receipt["host"]["osId"] == "ubuntu"
    assert receipt["host"]["versionId"] == "24.04"
    assert receipt["host"]["supportTier"] == "validated_baseline"
    assert receipt["host"]["kernel"] == "Linux"
    assert receipt["host"]["systemdUser"] is True
    assert receipt["host"]["subuidConfigured"] is True
    assert receipt["host"]["subgidConfigured"] is True


def test_missing_subordinate_uid_mapping_refused(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    outcome, _, _, _ = _happy(
        tmp_path, trust, cosign_executable, subuid_configured=False, subgid_configured=False
    )
    assert outcome.status == "refused"
    assert outcome.code == "subuid_mapping_missing"


def test_expired_index_refused(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    expired = _timestamp(datetime.now(timezone.utc) - timedelta(days=1))
    fixture = _signed_index(tmp_path / "fixture", trust, expires_at=expired)
    outcome = _run_install(
        _config(fixture, tmp_path, cosign=cosign_executable),
        runner=FakeRunner(),
        probe=FakeProbe(_facts()),
        fetcher=FakeFetcher(),
    )
    assert outcome.status == "refused"
    assert outcome.code == "index_expired"


def test_channel_mismatch_refused(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    fixture = _signed_index(tmp_path / "fixture", trust)
    outcome = _run_install(
        _config(fixture, tmp_path, channel="stable", cosign=cosign_executable),
        runner=FakeRunner(),
        probe=FakeProbe(_facts()),
        fetcher=FakeFetcher(),
    )
    assert outcome.status == "refused"
    assert outcome.code == "channel_mismatch"


def test_tag_reference_refused(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    fixture = _signed_index(tmp_path / "fixture", trust)
    document = json.loads(fixture.index_path.read_text(encoding="utf-8"))
    document["signed"]["images"][0]["reference"] = (
        "ghcr.io/stateport/stateport-alpha/stateport-web:latest"
    )
    # Rebind the payload digest so only the mutable-tag reference is dishonest.
    signed_bytes = json.dumps(
        document["signed"], ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()
    document["signatures"][0]["subjectDigest"] = (
        "sha256:" + hashlib.sha256(signed_bytes).hexdigest()
    )
    tagged = tmp_path / "tagged-index.json"
    tagged.write_text(json.dumps(document) + "\n", encoding="utf-8")
    outcome = _run_install(
        _config(fixture, tmp_path, release_index=str(tagged), cosign=cosign_executable),
        runner=FakeRunner(),
        probe=FakeProbe(_facts()),
        fetcher=FakeFetcher(),
    )
    assert outcome.status == "refused"
    assert outcome.code in {
        "signature_verification_failed",
        "release_verification_failed",
        "image_reference_refused",
        "index_verification_failed",
    }


def test_wheel_digest_mismatch_refused_before_pip(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    fixture = _signed_index(tmp_path / "fixture", trust)
    fixture.artifact_paths["updater"].write_bytes(b"tampered-wheel-bytes\n")
    runner = FakeRunner()
    outcome = _run_install(
        _config(fixture, tmp_path, cosign=cosign_executable),
        runner=runner,
        probe=FakeProbe(_facts()),
        fetcher=FakeFetcher(),
    )
    assert outcome.status == "refused"
    assert outcome.code == "wheel_digest_mismatch"
    assert not [call for call in runner.calls if call[0].endswith("/pip")]


def test_extensionless_bundle_wheel_is_staged_with_whl_suffix_for_pip(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    # Regression for the VM refusals venv_install_failed-56add791 and
    # venv_install_failed-17a40047: the shipped bundle names the wheel
    # artifact extensionless (artifacts/updater), and pip refuses both a
    # non-.whl path and a decorated name that is not a valid wheel filename
    # (the digest contains a colon and the name lacks the tag components).
    outcome, runner, fixture, config = _happy(tmp_path, trust, cosign_executable)
    assert outcome.status == "succeeded", outcome.message
    wheel = fixture.artifact_paths["updater"]
    assert wheel.suffix != ".whl"  # the fixture mirrors the real bundle layout
    pip_calls = [call for call in runner.calls if call[0].endswith("/pip")]
    assert pip_calls, "the updater wheel must be installed through pip"
    for call in pip_calls:
        target = Path(call[-1])
        # The exact PEP 427 name pip parses without error: no colon, the
        # wheel's own dist-info base, and the py-abi-platform tag triplet.
        assert target.name == "stateport_updater-0.1.1-py3-none-any.whl"
        assert target.is_file()
        assert target.read_bytes() == wheel.read_bytes()


def test_stage_wheel_for_pip_passes_whl_path_through(tmp_path: Path) -> None:
    wheel = tmp_path / "stateport_updater-0.1.1-py3-none-any.whl"
    wheel.write_bytes(_minimal_wheel_bytes())
    staged = installer._stage_wheel_for_pip(wheel, tmp_path / "venv")
    assert staged == wheel


def test_stage_wheel_for_pip_derives_pep427_name_from_wheel_metadata(
    tmp_path: Path,
) -> None:
    wheel = tmp_path / "updater"  # extensionless, like the shipped bundle
    wheel.write_bytes(_minimal_wheel_bytes())
    staged = installer._stage_wheel_for_pip(wheel, tmp_path / "venv")
    assert staged.name == "stateport_updater-0.1.1-py3-none-any.whl"
    assert staged.read_bytes() == wheel.read_bytes()


def test_stage_wheel_for_pip_replaces_stale_staged_copy(tmp_path: Path) -> None:
    wheel = tmp_path / "updater"
    wheel.write_bytes(_minimal_wheel_bytes())
    venv_dir = tmp_path / "venv"
    staged = installer._stage_wheel_for_pip(wheel, venv_dir)
    staged.unlink()  # the staged file hardlinks the wheel; replace, not overwrite
    staged.write_bytes(b"stale-bytes-from-an-interrupted-run\n")
    restaged = installer._stage_wheel_for_pip(wheel, venv_dir)
    assert restaged == staged
    assert restaged.read_bytes() == wheel.read_bytes()


def test_stage_wheel_for_pip_refuses_unparseable_wheel(tmp_path: Path) -> None:
    wheel = tmp_path / "updater"
    wheel.write_bytes(b"not-a-zip-archive\n")
    with pytest.raises(installer.InstallerRefusal) as refusal:
        installer._stage_wheel_for_pip(wheel, tmp_path / "venv")
    assert refusal.value.code == "wheel_layout_invalid"


def test_stage_wheel_for_pip_hardlink_fallback_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wheel = tmp_path / "updater"
    wheel.write_bytes(_minimal_wheel_bytes())

    def _no_link(source: Path, target: Path) -> None:
        raise OSError("cross-device link")

    monkeypatch.setattr(installer.os, "link", _no_link)
    staged = installer._stage_wheel_for_pip(wheel, tmp_path / "venv")
    assert staged.suffix == ".whl"
    assert staged.read_bytes() == wheel.read_bytes()


def test_cached_updater_wheel_reinstalls_when_installed_bytes_drift(
    tmp_path: Path,
) -> None:
    wheel = tmp_path / "updater"
    wheel.write_bytes(_minimal_wheel_bytes())
    venv_dir = tmp_path / "venv"
    site_packages = venv_dir / "lib/python3.12/site-packages"
    site_packages.mkdir(parents=True)
    (venv_dir / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    (venv_dir / "bin").mkdir()
    (venv_dir / "bin/pip").write_bytes(b"pip\n")
    with zipfile.ZipFile(wheel) as archive:
        for member in archive.infolist():
            if member.is_dir() or member.filename.endswith(".dist-info/RECORD"):
                continue
            destination = site_packages / PurePosixPath(member.filename)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(archive.read(member))
    (site_packages / "stateport_release/sentinel.py").write_bytes(b"tampered\n")
    marker = venv_dir / ".updater-wheel-digest"
    marker.write_text(installer._sha256_digest(wheel.read_bytes()) + "\n", encoding="ascii")
    runner = FakeRunner()

    installer._install_venv(wheel, venv_dir, runner, lambda _: None)

    pip_calls = [call for call in runner.calls if call[0].endswith("/pip")]
    assert pip_calls and "--force-reinstall" in pip_calls[0]


def test_podman_version_floor_refused(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    fixture = _signed_index(tmp_path / "fixture", trust)
    outcome = _run_install(
        _config(fixture, tmp_path, cosign=cosign_executable),
        runner=FakeRunner(podman_version="4.0.0"),
        probe=FakeProbe(_facts(podman_version="4.0.0")),
        fetcher=FakeFetcher(),
    )
    assert outcome.status == "refused"
    assert outcome.code == "podman_version_floor"


def test_cgroup_v1_refused(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    outcome, _, _, _ = _happy(tmp_path, trust, cosign_executable, cgroup_version="v1")
    assert outcome.status == "refused"
    assert outcome.code == "cgroup_v2_missing"


def test_rootful_podman_refused(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    outcome, _, _, _ = _happy(tmp_path, trust, cosign_executable, rootless=False)
    assert outcome.status == "refused"
    assert outcome.code == "podman_not_rootless"


def _materialized_web_port(fixture: Fixture, occupied: list[dict[str, object]]) -> tuple[int, int]:
    """Contract-computed accepted web port for a given occupied inventory."""

    clock = datetime.now(timezone.utc)
    index = load_release_index_file(fixture.index_path)
    release = stateport_release
    policy = release.ReleaseVerificationPolicy(
        expected_channel="alpha",
        expected_target=installer.PORTABLE_LINUX_TARGET_ID,
        updater_version="0.1.1",
        accepted_signers=frozenset(),
        accepted_public_keys=frozenset(
            {release.PinnedPublicKeyIdentity(str(fixture.trust["fingerprint"]), KEY_ID)}
        ),
        expected_trust_mode="pinned-public-key",
        now=clock + timedelta(seconds=60),
        allow_candidate=True,
    )
    verified = release.verify_release_index(
        index,
        policy=policy,
        verifier=FakeVerifier(lambda: clock),
        local_image_payloads=installer._local_image_manifest_payloads(index, fixture.bundle_root),
    )
    target = verified.target
    plan_digest = release.canonical_digest({"test": "port-probe"})
    backup = {
        "schema": "stateport.revision-validation-backup-receipt/v1",
        "operationPlanDigest": plan_digest,
        "releaseId": str(verified.index.release_id),
        "signedPayloadDigest": index.signed_digest,
        "targetId": str(target["targetId"]),
        "topologyDigest": str(target["topologyDigest"]),
        "backupReceiptDigest": release.canonical_digest({"test": "backup"}),
        "snapshotSetDigest": release.canonical_digest({"test": "snapshots"}),
        "volumeBindings": [
            {
                "volumeKey": release.revision_volume_key(
                    target, str(service["serviceId"]), str(volume["name"])
                ),
                "snapshotVolumeName": f"stateport-s{'ab' * 6}-{service['serviceId'][10:]}",
                "sourceDataGeneration": None,
                "readOnly": True,
            }
            for service in target["services"]
            for volume in service["writableVolumes"]
        ],
        "createdAt": _timestamp(clock),
        "consistencyMode": "quiesced",
        "consistencyEvidenceDigest": release.canonical_digest({"test": "evidence"}),
        "result": "succeeded",
    }
    backup["volumeBindings"] = list(
        {item["volumeKey"]: item for item in backup["volumeBindings"]}.values()
    )
    backup["receiptDigest"] = release.revision_contract_digest(backup, digest_field="receiptDigest")
    empty = release.canonical_digest([])
    staged = release.materialize_verified_quadlet_bundle(
        verified,
        operation_plan_digest=plan_digest,
        host_identity_digest=release.canonical_digest({"test": "host"}),
        collision_inventory_digests={
            "current": empty,
            "predecessor": empty,
            "candidate": empty,
            "observedHost": release.canonical_digest(
                sorted(occupied, key=lambda item: item["port"])
            ),
        },
        occupied_port_inputs=occupied,
        proposed_at=_timestamp(clock),
        validation_backup_receipt=backup,
    )
    manifest = json.loads(
        staged[f"staged/{index.signed_digest.removeprefix('sha256:')}/materialization.json"]
    )
    proposal = json.loads(
        staged[
            f"staged/{index.signed_digest.removeprefix('sha256:')}/port-allocation.proposal.json"
        ]
    )
    port = int(manifest["ports"]["stateport-web:accepted:http"])
    attempts = {
        item["portName"]: item["probeAttempt"]
        for item in proposal["allocations"]
        if item["serviceId"] == "stateport-web" and item["profile"] == "accepted"
    }
    return port, int(attempts["http"])


def test_occupied_port_collision_probed_not_guessed(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    fixture = _signed_index(tmp_path / "fixture", trust)
    default_port, default_attempts = _materialized_web_port(fixture, [])
    assert default_attempts == 0
    occupied = [
        {
            "class": "observed-host",
            "port": default_port,
            "identityDigest": canonical_digest({"test": "foreign-listener"}),
        }
    ]
    probed_port, probed_attempts = _materialized_web_port(fixture, occupied)
    assert probed_port != default_port and probed_attempts > 0

    config = _config(fixture, tmp_path, cosign=cosign_executable, _occupied_ports=[default_port])
    probe = FakeProbe(_facts(), occupied=[default_port])
    outcome = _run_install(config, runner=FakeRunner(), probe=probe, fetcher=FakeFetcher())
    assert outcome.status == "succeeded", outcome.message
    assert outcome.local_url == f"http://127.0.0.1:{probed_port}/"
    published_units = [
        path
        for path in config.live_quadlet_root.iterdir()
        if path.suffix == ".container" and "PublishPort" in path.read_text(encoding="utf-8")
    ]
    # All three services publish on loopback; the web unit must use the probed
    # port, never the colliding contract default.
    assert len(published_units) == 3
    web_unit = next(path for path in published_units if ":8080" in path.read_text(encoding="utf-8"))
    assert f"PublishPort=127.0.0.1:{probed_port}:8080" in web_unit.read_text(encoding="utf-8")
    assert f":{default_port}:" not in web_unit.read_text(encoding="utf-8")


def test_health_wait_gives_each_service_a_full_budget() -> None:
    """F9: services start strictly serially (one cold WSL2 service observed at
    ~80s), so one shared deadline across the whole set starves the later
    services.  Each service must get the full per-service budget."""
    services = [
        {
            "serviceId": "api",
            "health": {"containerPort": 9000, "path": "/readyz"},
            "ports": [{"containerPort": 9000, "name": "http"}],
        },
        {
            "serviceId": "web",
            "health": {"containerPort": 8080, "path": "/health"},
            "ports": [{"containerPort": 8080, "name": "http"}],
        },
    ]
    ports = {"api:accepted:http": 19000, "web:accepted:http": 18080}
    state = {"now": datetime(2026, 1, 1, tzinfo=timezone.utc)}
    calls: dict[str, int] = {}

    class SlowFetcher:
        def fetch(self, url: str, *, timeout: float, max_bytes: int) -> installer.FetchResult:
            service = "api" if ":19000" in url else "web"
            calls[service] = calls.get(service, 0) + 1
            if calls[service] >= 3:  # two 2s stalls, then healthy
                return installer.FetchResult(200, b"ok")
            state["now"] += timedelta(seconds=2.0)
            return installer.FetchResult(0, b"")

    evidence = installer._wait_for_health(
        services,
        ports,
        {"api": "stateport-api", "web": "stateport-web"},
        fetcher=SlowFetcher(),
        runner=FakeRunner(),
        clock=lambda: state["now"],
        timeout_seconds=5.0,
        poll_seconds=0.01,
    )
    assert {item["serviceId"] for item in evidence} == {"api", "web"}
    # Together the services consumed 8s of clock — beyond one shared 5s
    # budget — yet each individually stayed within its own 5s budget.
    assert calls == {"api": 3, "web": 3}
    assert state["now"] == datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=8.0)


def test_rerun_with_own_ports_occupied_reproduces_the_original_allocation(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    """F2: a failure past service start leaves this installation's containers
    holding the accepted ports.  The rerun must reproduce the original
    allocation exactly instead of shifting ports and overwriting live units
    (the permanent dead-port failure loop)."""
    fixture = _signed_index(tmp_path / "fixture", trust)
    config = _config(fixture, tmp_path, cosign=cosign_executable, health_timeout_seconds=0.2)
    runner = FakeRunner()
    first = _run_install(
        config, runner=runner, probe=FakeProbe(_facts()), fetcher=FakeFetcher(healthy=False)
    )
    assert first.status == "refused" and first.code == "health_timeout"

    live_units = sorted(config.live_quadlet_root.glob("*.container"))
    assert live_units
    before = {path.name: path.read_bytes() for path in live_units}
    own_ports = sorted(
        {
            int(match)
            for path in live_units
            for match in installer._PUBLISH_PORT.findall(path.read_text(encoding="utf-8"))
        }
    )
    assert own_ports

    second = _run_install(
        config,
        runner=runner,
        probe=FakeProbe(_facts(), occupied=own_ports),
        fetcher=FakeFetcher(healthy=True),
    )
    assert second.status == "succeeded", second.message
    after = {path.name: path.read_bytes() for path in sorted(config.live_quadlet_root.glob("*.container"))}
    assert after == before, "rerun shifted the port allocation of its own live units"


def test_interrupted_install_rerun_converges(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    fixture = _signed_index(tmp_path / "fixture", trust)
    config = _config(fixture, tmp_path, cosign=cosign_executable, health_timeout_seconds=0.2)
    runner = FakeRunner()
    first = _run_install(
        config, runner=runner, probe=FakeProbe(_facts()), fetcher=FakeFetcher(healthy=False)
    )
    assert first.status == "refused"
    assert first.code == "health_timeout"
    # The interruption left a schema-conformant failure receipt, not torn state.
    receipts = sorted((config.state_root / "receipts").glob("install_receipt_*.json"))
    assert len(receipts) == 1
    failure = validate_install_receipt(json.loads(receipts[0].read_text(encoding="utf-8")))
    assert failure.document["result"] == "failed"
    assert failure.document["runtime"]["healthy"] is False

    second = _run_install(
        config, runner=runner, probe=FakeProbe(_facts()), fetcher=FakeFetcher(healthy=True)
    )
    assert second.status == "succeeded", second.message
    assert second.receipt_path is not None
    success = validate_install_receipt(json.loads(second.receipt_path.read_text(encoding="utf-8")))
    assert success.document["result"] == "succeeded"
    status = json.loads((config.state_root / "updater" / "status.json").read_text())
    assert status["sequence"] == 0 and status["phase"] == "idle"
    # One durable trust root, admission, and installed identity across the rerun.
    assert len(list((config.state_root / "updater" / "trust").glob("*.json"))) == 2
    assert len(list((config.state_root / "updater" / "release-admissions").glob("*.json"))) == 1
    assert (
        len(
            list(
                (config.state_root / "updater" / "installed-authority" / "identity").glob("*.json")
            )
        )
        == 1
    )
    assert not (config.state_root / "updater" / "genesis-boundary.json").exists()


def _remove_receipts(state_root: Path) -> None:
    for path in (state_root / "receipts").glob("install_receipt_*.json"):
        path.unlink()


def test_genesis_rerun_without_receipt_is_idempotent(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    outcome, runner, _fixture, config = _happy(tmp_path, trust, cosign_executable)
    assert outcome.status == "succeeded", outcome.message

    def durable_genesis_bytes() -> dict[str, bytes]:
        return {
            path.relative_to(config.state_root).as_posix(): path.read_bytes()
            for path in sorted((config.state_root / "updater").rglob("*"))
            if path.is_file()
        }

    before = durable_genesis_bytes()
    _remove_receipts(config.state_root)
    second = _run_install(config, runner=runner, probe=FakeProbe(_facts()), fetcher=FakeFetcher())
    assert second.status == "succeeded", second.message

    assert durable_genesis_bytes() == before
    assert len(list((config.state_root / "updater" / "release-admissions").glob("*.json"))) == 1
    assert (
        len(
            list(
                (config.state_root / "updater" / "installed-authority" / "identity").glob("*.json")
            )
        )
        == 1
    )


def test_conflicting_trust_key_bytes_refuse_rerun(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    outcome, runner, _fixture, config = _happy(tmp_path, trust, cosign_executable)
    assert outcome.status == "succeeded", outcome.message
    pem_path = config.state_root / "updater" / "trust" / f"{KEY_ID}.pem"
    pem_path.write_bytes(b"-----BEGIN PUBLIC KEY-----\ntampered\n-----END PUBLIC KEY-----\n")
    _remove_receipts(config.state_root)
    outcome = _run_install(config, runner=runner, probe=FakeProbe(_facts()), fetcher=FakeFetcher())
    assert outcome.status == "refused"
    assert outcome.code == "trust_root_conflict"


def test_conflicting_trust_root_record_refuses_rerun(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    outcome, runner, _fixture, config = _happy(tmp_path, trust, cosign_executable)
    assert outcome.status == "succeeded", outcome.message
    record_path = config.state_root / "updater" / "trust" / "trust-root.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["channel"] = "stable"
    record_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    _remove_receipts(config.state_root)
    outcome = _run_install(config, runner=runner, probe=FakeProbe(_facts()), fetcher=FakeFetcher())
    assert outcome.status == "refused"
    assert outcome.code == "trust_root_conflict"


def test_stale_status_binding_other_release_refuses_genesis_conflict(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    outcome, runner, _fixture, config = _happy(tmp_path, trust, cosign_executable)
    assert outcome.status == "succeeded", outcome.message
    status_path = config.state_root / "updater" / "status.json"
    status = json.loads(status_path.read_text(encoding="utf-8"))
    status["current"] = {
        **status["current"],
        "releaseId": "stateport-alpha-9.9.9-rc.1",
        "version": "9.9.9-rc.1",
    }
    status["accepted"] = status["current"]
    status_path.write_text(json.dumps(status) + "\n", encoding="utf-8")
    _remove_receipts(config.state_root)
    outcome = _run_install(config, runner=runner, probe=FakeProbe(_facts()), fetcher=FakeFetcher())
    assert outcome.status == "refused"
    assert outcome.code == "updater_genesis_conflict"


def test_stale_genesis_boundary_record_is_left_untouched(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    outcome, runner, _fixture, config = _happy(tmp_path, trust, cosign_executable)
    assert outcome.status == "succeeded", outcome.message
    boundary_path = config.state_root / "updater" / "genesis-boundary.json"
    historic = {
        "schema": "stateport.install-genesis-boundary/v1",
        "code": "pinned_key_admission_contract_unsupported",
        "createdAt": "2026-08-01T00:00:00Z",
    }
    boundary_path.write_text(json.dumps(historic) + "\n", encoding="utf-8")
    boundary_path.chmod(0o600)
    _remove_receipts(config.state_root)
    second = _run_install(config, runner=runner, probe=FakeProbe(_facts()), fetcher=FakeFetcher())
    assert second.status == "succeeded", second.message
    assert json.loads(boundary_path.read_text(encoding="utf-8")) == historic


def test_completed_install_rerun_converges_without_duplicate_receipt(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    fixture = _signed_index(tmp_path / "fixture", trust)
    config = _config(fixture, tmp_path, cosign=cosign_executable)
    runner = FakeRunner()
    first = _run_install(config, runner=runner, probe=FakeProbe(_facts()), fetcher=FakeFetcher())
    assert first.status == "succeeded", first.message
    second = _run_install(config, runner=runner, probe=FakeProbe(_facts()), fetcher=FakeFetcher())
    assert second.status == "succeeded"
    assert second.converged is True
    assert second.code == "already_installed"
    assert second.local_url == first.local_url
    receipts = sorted((config.state_root / "receipts").glob("install_receipt_*.json"))
    assert len(receipts) == 1


def test_identical_install_rerun_keeps_the_installed_updater_operational(
    tmp_path: Path,
    trust: dict[str, object],
    cosign_executable: Path,
) -> None:
    """I1: identical install convergence preserves the updater journey."""
    fixture = _signed_index(tmp_path / "fixture", trust)
    config = _config(fixture, tmp_path, cosign=cosign_executable)
    first = _run_install(config, runner=FakeRunner(), probe=FakeProbe(_facts()), fetcher=FakeFetcher())
    assert first.status == "succeeded", first.message
    gate_evidence = (config.state_root / "install-end-gate-evidence.json").read_bytes()
    second = _run_install(config, runner=FakeRunner(), probe=FakeProbe(_facts()), fetcher=FakeFetcher())
    assert second.status == "succeeded"
    assert second.converged is True
    assert (config.state_root / "install-end-gate-evidence.json").read_bytes() == gate_evidence
    assert len(list((config.state_root / "receipts").glob("install_receipt_*.json"))) == 1


def test_receipt_validates_against_schema(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    outcome, _, fixture, _ = _happy(tmp_path, trust, cosign_executable)
    assert outcome.status == "succeeded", outcome.message
    assert outcome.receipt_path is not None
    receipt = json.loads(outcome.receipt_path.read_text(encoding="utf-8"))
    validated = validate_install_receipt(receipt)
    assert validated.digest == receipt["receiptId"] or validated.document is not None
    index = load_release_index_file(fixture.index_path)
    assert receipt["releaseIndexDigest"] == index.index_digest
    assert receipt["installPlanDigest"].startswith("sha256:")
    assert (
        receipt["target"]["topologyDigest"]
        == index.document["signed"]["targets"][0]["topologyDigest"]
    )
    assert receipt["verification"]["signedIndex"]["status"] == "verified"
    assert all(entry["status"] == "verified" for entry in receipt["verification"]["images"])


def test_confirmation_refused_writes_durable_refusal(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    fixture = _signed_index(tmp_path / "fixture", trust)
    config = _config(fixture, tmp_path, cosign=cosign_executable, assume_yes=False)
    outcome = _run_install(
        config,
        runner=FakeRunner(),
        probe=FakeProbe(_facts()),
        fetcher=FakeFetcher(),
        confirmer=lambda summary: False,
    )
    assert outcome.status == "refused"
    assert outcome.code == "confirmation_refused"
    refusals = sorted((config.state_root / "refusals").glob("*.json"))
    assert len(refusals) == 1
    record = json.loads(refusals[0].read_text(encoding="utf-8"))
    assert record["code"] == "confirmation_refused"
    assert record["executed"] is False
    # Nothing was pulled or installed without confirmation.
    assert not config.live_quadlet_root.exists() or not any(config.live_quadlet_root.iterdir())


def test_https_index_requires_published_digest(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    fixture = _signed_index(tmp_path / "fixture", trust)
    url = "https://releases.stateport.invalid/alpha/release-index.json"
    outcome = _run_install(
        _config(fixture, tmp_path, release_index=url, cosign=cosign_executable),
        runner=FakeRunner(),
        probe=FakeProbe(_facts()),
        fetcher=FakeFetcher(),
    )
    assert outcome.status == "refused"
    assert outcome.code == "published_digest_missing"


def test_https_index_download_digest_mismatch_refused(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    fixture = _signed_index(tmp_path / "fixture", trust)
    url = "https://releases.stateport.invalid/alpha/release-index.json"
    body = fixture.index_path.read_bytes()
    outcome = _run_install(
        _config(
            fixture,
            tmp_path,
            release_index=url,
            release_index_sha256="0" * 64,
            cosign=cosign_executable,
        ),
        runner=FakeRunner(),
        probe=FakeProbe(_facts()),
        fetcher=FakeFetcher(downloads={url: body}),
    )
    assert outcome.status == "refused"
    assert outcome.code == "download_digest_mismatch"


def test_https_index_download_with_published_digest(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    fixture = _signed_index(tmp_path / "fixture", trust)
    url = "https://releases.stateport.invalid/alpha/release-index.json"
    body = fixture.index_path.read_bytes()
    outcome = _run_install(
        _config(
            fixture,
            tmp_path,
            release_index=url,
            release_index_sha256=hashlib.sha256(body).hexdigest(),
            cosign=cosign_executable,
        ),
        runner=FakeRunner(),
        probe=FakeProbe(_facts()),
        fetcher=FakeFetcher(downloads={url: body}),
    )
    assert outcome.status == "succeeded", outcome.message


def test_der_spki_fingerprint_matches_openssl_semantics() -> None:
    fingerprint = installer.der_spki_fingerprint(TEST_PUBLIC_KEY_PEM.encode("ascii"))
    from stateport_release import public_key_der_spki_fingerprint
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".pub", delete=False) as handle:
        handle.write(TEST_PUBLIC_KEY_PEM)
        path = Path(handle.name)
    assert fingerprint == public_key_der_spki_fingerprint(path)
    assert fingerprint.startswith("sha256:")


# ---------------------------------------------------------------------------
# uninstall / purge modes (recorded authority only, converge on partial state)
# ---------------------------------------------------------------------------


def _live_unit_names(config: installer.InstallConfig) -> list[str]:
    return sorted(
        path.name.removesuffix(".container")
        for path in config.live_quadlet_root.glob("*.container")
    )


def _live_container_names(config: installer.InstallConfig) -> list[str]:
    names: list[str] = []
    for path in sorted(config.live_quadlet_root.glob("*.container")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("ContainerName="):
                names.append(line.split("=", 1)[1])
    return sorted(names)


def _live_quadlet_files(config: installer.InstallConfig) -> list[str]:
    return sorted(path.name for path in config.live_quadlet_root.iterdir())


def _state_bytes(state_root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(state_root).as_posix(): path.read_bytes()
        for path in sorted(state_root.rglob("*"))
        if path.is_file()
    }


def _install_trust(config: installer.InstallConfig) -> dict[str, object]:
    return json.loads(
        (config.state_root / "updater" / "trust" / "install-trust.json").read_text(encoding="utf-8")
    )


def _uninstall_config(
    config: installer.InstallConfig, **changes: object
) -> installer.UninstallConfig:
    values: dict[str, object] = {
        "state_root": config.state_root,
        "live_quadlet_root": config.live_quadlet_root,
        "actor_id": "local-owner-test",
        "purge": False,
        "confirm_purge": None,
    }
    values.update(changes)
    return installer.UninstallConfig(**values)  # type: ignore[arg-type]


def _run_uninstall(
    config: installer.UninstallConfig, *, runner: FakeRunner
) -> installer.InstallOutcome:
    clock = lambda: datetime.now(timezone.utc)  # noqa: E731
    return installer.uninstall(config, runner=runner, clock=clock)


def _uninstall_receipts(state_root: Path) -> list[Path]:
    return sorted((state_root / "receipts").glob("uninstall_receipt_*.json"))


def test_reinstall_after_non_purge_uninstall_reinstalls(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    """F3: a non-purge uninstall preserves the succeeded install receipt; the
    rerun must verify the live runtime is gone and REINSTALL instead of
    adopting the historic receipt with already_installed."""
    outcome, runner, _fixture, config = _happy(tmp_path, trust, cosign_executable)
    assert outcome.status == "succeeded", outcome.message
    runner.containers.update(_live_container_names(config))
    removed = _run_uninstall(_uninstall_config(config), runner=runner)
    assert removed.status == "succeeded" and removed.code == "uninstalled"
    assert not any(config.live_quadlet_root.iterdir())

    second = _run_install(
        config, runner=runner, probe=FakeProbe(_facts()), fetcher=FakeFetcher()
    )
    assert second.status == "succeeded", second.message
    assert second.code != "already_installed"
    # The live runtime is back: units, activation target, healthy receipt.
    assert _live_unit_names(config)
    target = config.live_quadlet_root.parent / "systemd" / "user" / "stateport-accepted.target"
    assert target.is_file()
    assert second.receipt_path is not None
    receipt = json.loads(second.receipt_path.read_text(encoding="utf-8"))
    assert receipt["result"] == "succeeded"

    # And a THIRD run with the runtime live converges to already_installed.
    third = _run_install(
        config, runner=runner, probe=FakeProbe(_facts()), fetcher=FakeFetcher()
    )
    assert third.status == "succeeded" and third.code == "already_installed"


def _simulate_accepted_update(
    config: installer.InstallConfig, runner: "FakeRunner"
) -> dict[str, str]:
    """Transform a genesis install into the post-accepted-update state.

    Mirrors the updater's switch + retention: the successor's accepted (and
    validation) units are live, genesis live units are gone, the activation
    target and updater status bind the successor, and the successor's staged
    manifest is retained under updater/host-staged.
    """
    trust_record = _install_trust(config)
    genesis_hex = str(trust_record["signedPayloadDigest"]).removeprefix("sha256:")
    successor_digest = "sha256:" + hashlib.sha256(b"successor-payload").hexdigest()
    successor_hex = successor_digest.removeprefix("sha256:")
    successor_id = "stateport-alpha-0.2.0-rc.2"

    staged = config.state_root / "updater" / "host-staged" / successor_hex
    units = {
        "accepted_container": "stateport-web-accepted-succrev.container",
        "accepted_network": "stateport-succnet.network",
        "validation_container": "stateport-web-validation-succrev.container",
    }
    (staged / "containers").mkdir(parents=True)
    (staged / "networks").mkdir(parents=True)
    (staged / "containers" / units["accepted_container"]).write_text(
        "[Container]\n"
        "ContainerName=stateport-web-accepted-succrev\n"
        "Image=ghcr.io/lennertvhoy/stateport-web@sha256:" + "cd" * 32 + "\n"
        "Volume=@@STATEPORT_ACCEPTED_DATA_VOLUME:web-data@@:/var/lib/stateport:rw,U\n",
        encoding="utf-8",
    )
    (staged / "networks" / units["accepted_network"]).write_text(
        "[Network]\nNetworkName=stateport-succnet\n", encoding="utf-8"
    )
    (staged / "containers" / units["validation_container"]).write_text(
        "[Container]\n"
        "ContainerName=stateport-web-validation-succrev\n"
        "Image=ghcr.io/lennertvhoy/stateport-web@sha256:" + "cd" * 32 + "\n",
        encoding="utf-8",
    )
    prefix = f"staged/{successor_hex}/"
    manifest = {
        "formatVersion": "stateport.quadlet-materialization/v2",
        "signedPayloadDigest": successor_digest,
        "artifacts": [
            {
                "profile": "accepted",
                "kind": "container",
                "stagedPath": prefix + "containers/" + units["accepted_container"],
                "liveRelativePath": units["accepted_container"],
            },
            {
                "profile": "accepted",
                "kind": "network",
                "stagedPath": prefix + "networks/" + units["accepted_network"],
                "liveRelativePath": units["accepted_network"],
            },
            {
                "profile": "validation",
                "kind": "container",
                "stagedPath": prefix + "containers/" + units["validation_container"],
                "liveRelativePath": units["validation_container"],
            },
        ],
        "validationVolumeBindings": {"web-data": "stateport-snap-succ-1"},
    }
    (staged / "materialization.json").write_text(json.dumps(manifest), encoding="utf-8")

    # Switch: successor units live, genesis live units removed.
    for path in list(config.live_quadlet_root.iterdir()):
        path.unlink()
    for name in units.values():
        (config.live_quadlet_root / name).write_text(
            f"[Container]\nContainerName={name.removesuffix('.container')}\n"
            if name.endswith(".container")
            else "[Network]\nNetworkName=stateport-succnet\n",
            encoding="utf-8",
        )
    # Activation target binds the successor.
    target_root = config.live_quadlet_root.parent / "systemd" / "user"
    target_root.mkdir(parents=True, exist_ok=True)
    (target_root / "stateport-accepted.target").write_bytes(
        installer._activation_target_content(
            ["stateport-web-accepted-succrev"],
            release_id=successor_id,
            signed_digest=successor_digest,
        )
    )
    # Updater status binds the successor as current/accepted.
    status_path = config.state_root / "updater" / "status.json"
    status = json.loads(status_path.read_text(encoding="utf-8"))
    identity = {
        "releaseId": successor_id,
        "version": "0.2.0-rc.2",
        "signedPayloadDigest": successor_digest,
    }
    status["current"] = identity
    status["accepted"] = identity
    status_path.write_text(json.dumps(status), encoding="utf-8")
    # Runner truth: successor containers run; genesis containers are gone.
    runner.containers.clear()
    runner.containers.update({"stateport-web-accepted-succrev", "stateport-web-validation-succrev"})
    return {
        "successorDigest": successor_digest,
        "successorId": successor_id,
        "genesisHex": genesis_hex,
    }


def test_uninstall_after_accepted_update_removes_the_union(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    """F5: after an accepted update the live runtime binds the successor; the
    removal plan must union install-trust and updater status, not only the
    genesis staged manifest."""
    outcome, runner, _fixture, config = _happy(tmp_path, trust, cosign_executable)
    assert outcome.status == "succeeded", outcome.message
    runner.containers.update(_live_container_names(config))
    _simulate_accepted_update(config, runner)

    result = _run_uninstall(_uninstall_config(config), runner=runner)

    assert result.status == "succeeded", result.message
    assert result.code == "uninstalled"
    # Successor units, containers, quadlet files, and the successor-bound
    # activation target are all removed.
    assert not any(config.live_quadlet_root.iterdir())
    assert not runner.containers
    target = config.live_quadlet_root.parent / "systemd" / "user" / "stateport-accepted.target"
    assert not target.exists()
    assert result.receipt_path is not None
    receipt = json.loads(result.receipt_path.read_text(encoding="utf-8"))
    removed_files = receipt["removed"]["quadletFiles"]
    assert "stateport-web-accepted-succrev.container" in removed_files
    assert "stateport-web-validation-succrev.container" in removed_files
    assert "stateport-succnet.network" in removed_files
    assert receipt["removed"]["activationTargets"] == ["stateport-accepted.target"]


def test_purge_after_accepted_update_removes_union_volumes(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    outcome, runner, _fixture, config = _happy(tmp_path, trust, cosign_executable)
    assert outcome.status == "succeeded", outcome.message
    runner.containers.update(_live_container_names(config))
    update = _simulate_accepted_update(config, runner)
    trust_record = _install_trust(config)
    runner.volumes.add("stateport-snap-succ-1")
    successor_data = installer._volume_names(update["genesisHex"], "web-data")[0]
    runner.volumes.add(successor_data)
    genesis_volumes = set(runner.volumes)

    result = _run_uninstall(
        _uninstall_config(
            config, purge=True, confirm_purge=str(trust_record["installedIdentityId"])
        ),
        runner=runner,
    )

    assert result.status == "succeeded", (result.code, result.message)
    # Every union volume is gone: genesis data volumes, the successor-derived
    # data volume (genesis-prefixed), and the successor snapshot volume.
    assert not runner.volumes
    assert result.receipt_path is not None
    receipt = json.loads(result.receipt_path.read_text(encoding="utf-8"))
    assert sorted(receipt["removed"]["volumes"]) == sorted(genesis_volumes)
    assert not config.state_root.exists() or not any(config.state_root.iterdir())


def test_uninstall_happy_path_preserves_data(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    outcome, runner, _fixture, config = _happy(tmp_path, trust, cosign_executable)
    assert outcome.status == "succeeded", outcome.message
    units = _live_unit_names(config)
    containers = _live_container_names(config)
    quadlet_files = _live_quadlet_files(config)
    assert len(units) == len(REVISION_SERVICES) == len(containers)
    runner.containers.update(containers)
    # The control-plane units were started by the root provisioning
    # transaction under the stateport-control user; simulate that state.
    runner.active_units.update(units)
    runner.enabled_units.update(units)
    preserved_volumes = set(runner.volumes)
    assert len(preserved_volumes) == 4
    state_before = _state_bytes(config.state_root)
    runner.calls.clear()

    result = _run_uninstall(_uninstall_config(config), runner=runner)

    assert result.status == "succeeded", result.message
    assert result.code == "uninstalled"
    # Control-plane units stop through the stateport-control user's manager;
    # normalize the runuser prefix when matching the recorded stop calls.
    normalized_stops = []
    for call in runner.calls:
        if call[:3] == ("systemctl", "--user", "stop"):
            normalized_stops.append(call)
        elif (
            len(call) >= 8
            and call[:5] == ("runuser", "-u", "stateport-control", "--", "systemctl")
            and call[5:7] == ("--user", "stop")
        ):
            normalized_stops.append(("systemctl", "--user", "stop", call[-1]))
    assert sorted(call[-1] for call in normalized_stops) == units
    reloads = [
        call for call in runner.calls if call[:3] == ("systemctl", "--user", "daemon-reload")
    ]
    assert len(reloads) == 1
    removals = [call for call in runner.calls if call[:3] == ("podman", "rm", "-f")]
    assert sorted(call[-1] for call in removals) == containers
    # Data preservation: not a single volume removal, state root untouched.
    assert not [call for call in runner.calls if call[:3] == ("podman", "volume", "rm")]
    assert runner.volumes == preserved_volumes
    assert not any(config.live_quadlet_root.iterdir())
    state_after = _state_bytes(config.state_root)
    added = set(state_after) - set(state_before)
    assert added and all(name.startswith("receipts/uninstall_receipt_") for name in added), added
    assert not (set(state_before) - set(state_after))
    assert not {
        name
        for name in state_before
        if name in state_after and state_after[name] != state_before[name]
    }

    assert result.receipt_path is not None
    receipt = json.loads(result.receipt_path.read_text(encoding="utf-8"))
    assert receipt["schema"] == "stateport.internal-install-uninstall-receipt/v1"
    assert receipt["action"] == "uninstall"
    assert receipt["actorId"] == "local-owner-test"
    assert receipt["result"] == "succeeded"
    assert (
        receipt["installation"]["signedPayloadDigest"]
        == _install_trust(config)["signedPayloadDigest"]
    )
    assert receipt["removed"]["unitsStopped"] == units
    assert receipt["removed"]["containers"] == containers
    assert receipt["removed"]["quadletFiles"] == quadlet_files
    assert receipt["removed"]["volumes"] == []
    assert receipt["removed"]["stateRootContents"] == []
    assert sorted(receipt["preserved"]["volumes"]) == sorted(preserved_volumes)
    assert str(config.state_root) in receipt["preserved"]["paths"]
    assert str(config.state_root / "updater-venv") in receipt["preserved"]["paths"]


def test_uninstall_without_installation_refused(tmp_path: Path) -> None:
    config = installer.UninstallConfig(
        state_root=tmp_path / "state",
        live_quadlet_root=tmp_path / "quadlets",
        actor_id="local-owner-test",
    )
    runner = FakeRunner()
    outcome = _run_uninstall(config, runner=runner)
    assert outcome.status == "refused"
    assert outcome.code == "no_installation_found"
    # Zero runner mutations and zero new state in a foreign directory.
    assert runner.calls == []
    assert not (tmp_path / "state").exists()


def test_uninstall_rerun_converges(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    outcome, runner, _fixture, config = _happy(tmp_path, trust, cosign_executable)
    assert outcome.status == "succeeded", outcome.message
    runner.containers.update(_live_container_names(config))
    first = _run_uninstall(_uninstall_config(config), runner=runner)
    assert first.status == "succeeded", first.message
    assert first.code == "uninstalled"
    receipts_before = _uninstall_receipts(config.state_root)
    runner.calls.clear()

    second = _run_uninstall(_uninstall_config(config), runner=runner)

    assert second.status == "succeeded", second.message
    assert second.code == "already_uninstalled"
    assert second.converged is True
    assert not [call for call in runner.calls if call[:3] == ("systemctl", "--user", "stop")]
    assert not [call for call in runner.calls if call[:3] == ("podman", "rm", "-f")]
    assert not [call for call in runner.calls if call[:3] == ("podman", "volume", "rm")]
    # The rerun still receipts the observed result.
    assert second.receipt_path is not None
    receipt = json.loads(second.receipt_path.read_text(encoding="utf-8"))
    assert receipt["result"] == "already_uninstalled"
    assert receipt["removed"]["unitsStopped"] == []
    assert receipt["removed"]["containers"] == []
    assert receipt["removed"]["quadletFiles"] == []
    assert len(_uninstall_receipts(config.state_root)) == len(receipts_before) + 1


def test_uninstall_never_touches_foreign_resources(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    outcome, runner, _fixture, config = _happy(tmp_path, trust, cosign_executable)
    assert outcome.status == "succeeded", outcome.message
    runner.containers.update(_live_container_names(config))
    foreign_unit = config.live_quadlet_root / "foreign-app.container"
    foreign_unit.write_text(
        "[Container]\nContainerName=foreign-app\nImage=docker.io/library/alpine:latest\n",
        encoding="utf-8",
    )
    runner.active_units.add("foreign-app")
    runner.containers.add("foreign-app")
    runner.volumes.add("foreign-volume")

    result = _run_uninstall(_uninstall_config(config), runner=runner)

    assert result.status == "succeeded", result.message
    assert foreign_unit.is_file()
    assert "foreign-app" in runner.active_units
    assert "foreign-app" in runner.containers
    assert "foreign-volume" in runner.volumes
    assert not [call for call in runner.calls if any("foreign" in part for part in call)]


def test_purge_without_confirmation_refused(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    outcome, runner, _fixture, config = _happy(tmp_path, trust, cosign_executable)
    assert outcome.status == "succeeded", outcome.message
    runner.containers.update(_live_container_names(config))
    volumes_before = set(runner.volumes)
    quadlets_before = _live_quadlet_files(config)
    runner.calls.clear()

    result = _run_uninstall(_uninstall_config(config, purge=True), runner=runner)

    assert result.status == "refused"
    assert result.code == "purge_confirmation_required"
    assert runner.calls == []
    assert runner.volumes == volumes_before
    assert _live_quadlet_files(config) == quadlets_before


def test_purge_with_wrong_installation_id_refused(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    outcome, runner, _fixture, config = _happy(tmp_path, trust, cosign_executable)
    assert outcome.status == "succeeded", outcome.message
    runner.containers.update(_live_container_names(config))
    volumes_before = set(runner.volumes)
    runner.calls.clear()

    result = _run_uninstall(
        _uninstall_config(config, purge=True, confirm_purge="installed_identity_" + "0" * 32),
        runner=runner,
    )

    assert result.status == "refused"
    assert result.code == "purge_confirmation_required"
    assert runner.calls == []
    assert runner.volumes == volumes_before
    assert any(config.live_quadlet_root.iterdir())


def test_purge_removes_volumes_and_state_root(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    outcome, runner, _fixture, config = _happy(tmp_path, trust, cosign_executable)
    assert outcome.status == "succeeded", outcome.message
    containers = _live_container_names(config)
    runner.containers.update(containers)
    identity_id = str(_install_trust(config)["installedIdentityId"])
    volumes = set(runner.volumes)
    assert len(volumes) == 4
    receipt_path = config.state_root.parent / f"{config.state_root.name}.purge-receipt.json"

    result = _run_uninstall(
        _uninstall_config(config, purge=True, confirm_purge=identity_id), runner=runner
    )

    assert result.status == "succeeded", result.message
    assert result.code == "purged"
    volume_removals = [call for call in runner.calls if call[:3] == ("podman", "volume", "rm")]
    assert sorted(call[-1] for call in volume_removals) == sorted(volumes)
    assert runner.volumes == set()
    assert not any(config.state_root.iterdir())  # contents deleted
    # The receipt was written to the surviving sibling path before deletion.
    assert result.receipt_path == receipt_path
    assert receipt_path.is_file()
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["schema"] == "stateport.internal-install-uninstall-receipt/v1"
    assert receipt["action"] == "purge"
    assert receipt["result"] == "succeeded"
    assert sorted(receipt["removed"]["volumes"]) == sorted(volumes)
    assert receipt["removed"]["containers"] == containers
    assert receipt["removed"]["stateRootContents"]
    assert str(receipt_path) in receipt["preserved"]["paths"]
    assert receipt["preserved"]["volumes"] == []


def test_purge_on_non_stateport_directory_refused(tmp_path: Path) -> None:
    foreign = tmp_path / "random-dir"
    foreign.mkdir()
    (foreign / "keep.txt").write_text("precious\n", encoding="utf-8")
    config = installer.UninstallConfig(
        state_root=foreign,
        live_quadlet_root=tmp_path / "quadlets",
        actor_id="local-owner-test",
        purge=True,
        confirm_purge="installed_identity_" + "0" * 32,
    )
    runner = FakeRunner()

    outcome = _run_uninstall(config, runner=runner)

    assert outcome.status == "refused"
    assert outcome.code == "state_root_not_stateport"
    assert runner.calls == []
    assert (foreign / "keep.txt").read_text(encoding="utf-8") == "precious\n"


@pytest.mark.parametrize("failure", [1, OSError("simulated systemctl exec failure")])
def test_interrupted_uninstall_rerun_converges(
    tmp_path: Path,
    trust: dict[str, object],
    cosign_executable: Path,
    failure: object,
) -> None:
    outcome, runner, _fixture, config = _happy(tmp_path, trust, cosign_executable)
    assert outcome.status == "succeeded", outcome.message
    runner.containers.update(_live_container_names(config))
    _units = _live_unit_names(config)
    runner.active_units.update(_units)
    runner.enabled_units.update(_units)
    runner.stop_failures.append(failure)

    first = _run_uninstall(_uninstall_config(config), runner=runner)

    assert first.status == "refused"
    assert first.code == "unit_stop_failed"
    refusals = sorted((config.state_root / "refusals").glob("*.json"))
    assert any(
        json.loads(path.read_text(encoding="utf-8"))["code"] == "unit_stop_failed"
        for path in refusals
    )

    second = _run_uninstall(_uninstall_config(config), runner=runner)

    assert second.status == "succeeded", second.message
    assert second.code == "uninstalled"
    assert not any(config.live_quadlet_root.iterdir())
    assert runner.containers == set()
    assert runner.active_units == set()


def test_cli_mode_flags_do_not_require_install_arguments() -> None:
    args = installer._parser().parse_args(["--uninstall", "--state-root", "/tmp/state"])
    assert args.uninstall is True
    assert args.purge is False
    args = installer._parser().parse_args(
        ["--purge", "--confirm-purge", "installed_identity_" + "0" * 32]
    )
    assert args.purge is True
    assert args.confirm_purge == "installed_identity_" + "0" * 32


def test_cli_uninstall_and_purge_are_mutually_exclusive() -> None:
    with pytest.raises(SystemExit):
        installer._parser().parse_args(["--uninstall", "--purge"])


# ---------------------------------------------------------------------------
# Execution-host provisioning plan emission (rootless boundary)
# ---------------------------------------------------------------------------


_PRIVILEGED_PROVISIONING_HEADS = {
    "runuser",
    "useradd",
    "groupadd",
    "usermod",
    "systemd-tmpfiles",
    "sudo",
    "userdel",
    "groupdel",
    "gpasswd",
}


def test_install_emits_provisioning_plan_without_escalating(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    outcome, runner, fixture, config = _happy(tmp_path, trust, cosign_executable)
    assert outcome.status == "succeeded", outcome.message
    info = outcome.execution_host
    assert info is not None, "a stable execution host must yield a provisioning plan"
    assert info["status"] == "provisioned-and-healthy"
    assert info["evidenceClass"] == "plan-rendered"
    assert (
        info["boundary"]
        == "rootless-installer-emits-plan;root-helper-provisions-with-explicit-privilege"
    )

    plan_path = Path(info["planPath"])
    assert plan_path == config.state_root / "execution-host-provisioning-plan.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    assert plan["schema"] == "stateport.execution-host-provisioning/v2"
    assert plan["planDigest"] == info["planDigest"]
    assert plan["verificationBasis"] == "signature-verified-install"
    assert plan["grantsDirectory"].endswith("/state/grants")
    assert [step["step"] for step in plan["steps"]][-2:] == [
        "start-control-plane-units",
        "record-provisioning-receipt",
    ]
    # The daemon health gate runs immediately after the daemon start and
    # before the control-plane units, so a dead daemon is caught before the
    # units that depend on its socket.
    assert [step["step"] for step in plan["steps"]][-3:-2] == [
        "verify-protocol-health",
    ]
    health_step = next(step for step in plan["steps"] if "health" in step)
    assert health_step["health"]["kind"] == "describeCapabilities"
    assert plan["rootlessSupplementaryGroupContract"]["status"].startswith("supported-")

    # F10/F11: the emitted plan binds the real invoking user as the confined
    # control-plane client AND always provisions the decorative control
    # account (the control-plane container peer identity), handing the exact
    # host identity to the confined daemon through the socket directory.
    client = provisioning.resolve_client_identity()
    assert client is not None
    client_user, client_uid, client_gid = client
    assert plan["allowedClientUser"] == client_user
    assert plan["controlClient"] == {
        "user": client_user,
        "uid": client_uid,
        "gid": client_gid,
    }
    step_names = [step["step"] for step in plan["steps"]]
    assert "ensure-stateport-control-user" in step_names
    assert "enable-control-user-linger" in step_names
    confine = next(
        step for step in plan["steps"] if step["step"] == "confine-control-plane-client"
    )
    assert confine["commands"][0][-1] == client_user
    assert health_step["health"]["peerUsers"] == ["stateport-exec", client_user]
    identity_write = next(
        write
        for write in plan["writes"]
        if write["path"].endswith("/" + provisioning.CLIENT_IDENTITY_FILE)
    )
    assert identity_write["content"] == f"{client_uid}:{client_gid}\n"
    assert identity_write["mode"] == "0640"
    assert identity_write["owner"] == "root:stateport-execution-control"

    # The privileged apply is an exact, inspectable command the operator runs
    # separately; the rootless installer never executes it.
    argv = info["provisionArgv"]
    assert argv[:2] == ["sudo", "-n"]
    assert argv[2] == "/usr/local/libexec/stateport-execution-host-provision"
    assert "provision" in argv
    assert not any(str(config.state_root) in value and value.endswith("/python") for value in argv)
    assert argv[argv.index("--receipt-out") + 1] == str(
        Path("/var/lib/stateport-provisioning/receipts/execution-host-provisioning-receipt.json")
    )
    assert info["receiptDirectory"] == "/var/lib/stateport-provisioning/receipts"
    privileged_calls = [
        call
        for call in runner.calls
        if call[0] in _PRIVILEGED_PROVISIONING_HEADS
        # Reading the started units' published ports is an unprivileged-intent
        # read through sudo since /var/lib/stateport-control is root-owned;
        # it mutates nothing.
        and call[:3] != ("sudo", "-n", "cat")
    ]
    assert privileged_calls == [], f"rootless installer escalated: {privileged_calls}"


def test_converged_rerun_keeps_provisioning_plan_info(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    first, _runner, _fixture, config = _happy(tmp_path, trust, cosign_executable)
    assert first.status == "succeeded"
    plan_path = config.state_root / "execution-host-provisioning-plan.json"
    plan_bytes = plan_path.read_bytes()
    rerun = _run_install(
        config, runner=FakeRunner(), probe=FakeProbe(_facts()), fetcher=FakeFetcher()
    )
    assert rerun.status == "succeeded"
    assert rerun.code == "already_installed"
    assert rerun.execution_host is not None
    assert rerun.execution_host["planDigest"] == first.execution_host["planDigest"]
    # Create-only convergence: the plan bytes are untouched by the rerun.
    assert plan_path.read_bytes() == plan_bytes


def test_converged_rerun_refuses_legacy_control_plane_identity_environment(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    first, _runner, _fixture, config = _happy(tmp_path, trust, cosign_executable)
    assert first.status == "succeeded"
    plan_path = config.state_root / "execution-host-provisioning-plan.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    environment = dict(plan["controlPlaneEnvironment"])
    operator_token = json.loads(
        environment["stateport-api.STATEPORT_AUTH_TOKENS_JSON"]
    )["local-operator"]
    environment["stateport-api.STATEPORT_IDENTITIES_JSON"] = json.dumps(
        {
            "local-operator": {
                "instances": ["*"],
                "roles": ["operator", "approver"],
            }
        },
        sort_keys=True,
    )
    environment["stateport-api.STATEPORT_AUTH_TOKENS_JSON"] = json.dumps(
        {"local-operator": operator_token}, sort_keys=True
    )
    plan["controlPlaneEnvironment"] = environment
    plan["planDigest"] = canonical_digest(
        {
            key: value
            for key, value in plan.items()
            if key not in {"planDigest", "verificationBasis", "evidenceClass"}
        }
    )
    plan_path.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    assert config.execution_host_receipt is not None
    receipt = json.loads(config.execution_host_receipt.read_text(encoding="utf-8"))
    receipt["planDigest"] = plan["planDigest"]
    if "receiptDigest" in receipt:
        receipt["receiptDigest"] = stateport_release.revision_contract_digest(
            receipt, digest_field="receiptDigest"
        )
    config.execution_host_receipt.write_text(
        json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8"
    )

    rerun = _run_install(
        config, runner=FakeRunner(), probe=FakeProbe(_facts()), fetcher=FakeFetcher()
    )

    assert rerun.status == "refused"
    assert rerun.code == "provisioning_plan_environment_changed"


def test_stable_install_refuses_without_provisioning_receipt(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    fixture = _signed_index(tmp_path / "fixture", trust)
    config = _config(fixture, tmp_path, cosign=cosign_executable, execution_host_receipt=None)
    outcome = _run_install(
        config,
        runner=FakeRunner(),
        probe=FakeProbe(_facts()),
        fetcher=FakeFetcher(),
    )
    assert outcome.status == "refused"
    assert outcome.code == "execution_host_provisioning_required"


def test_stable_install_refuses_when_receipt_health_is_not_proven(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    fixture = _signed_index(tmp_path / "fixture", trust)
    config = _config(fixture, tmp_path, cosign=cosign_executable)
    assert config.execution_host_receipt is not None
    receipt = json.loads(config.execution_host_receipt.read_text(encoding="utf-8"))
    receipt["health"]["healthy"] = False
    receipt["health"]["status"] = "failed"
    receipt["receiptDigest"] = stateport_release.revision_contract_digest(
        receipt, digest_field="receiptDigest"
    )
    config.execution_host_receipt.write_text(json.dumps(receipt) + "\n", encoding="utf-8")
    outcome = _run_install(
        config, runner=FakeRunner(), probe=FakeProbe(_facts()), fetcher=FakeFetcher()
    )
    assert outcome.status == "refused"
    assert outcome.code == "execution_host_receipt_mismatch"
    assert "health" in outcome.message


def test_stable_install_gate_uses_receipt_health_without_unprivileged_live_probe(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    """The privileged receipt carries the live probe; install does not repeat it.

    The provisioning helper probes both peers with the plan-bound uid, gid,
    and socket mode. Re-probing the confined socket from the rootless
    installer would deterministically fail on a real host.
    """
    fixture = _signed_index(tmp_path / "fixture", trust)
    config = _config(fixture, tmp_path, cosign=cosign_executable)
    assert config.execution_host_receipt is not None
    receipt = json.loads(config.execution_host_receipt.read_text(encoding="utf-8"))
    # Fail-old/pass-new: the old unprivileged re-probe would refuse this
    # healthy receipt; the corrected path never probes the confined socket.
    runner = FakeRunner(health_probe_healthy=False)
    outcome = _run_install(
        config, runner=runner, probe=FakeProbe(_facts()), fetcher=FakeFetcher()
    )
    assert outcome.status == "succeeded", outcome.message
    assert outcome.execution_host is not None
    assert outcome.execution_host["status"] == "provisioned-and-healthy"
    assert outcome.execution_host["health"]["healthy"] is True
    assert not any("health-probe" in call for call in runner.calls)
    assert (config.state_root / "install-end-gate-evidence.json").is_file()


def test_stable_install_product_gate_refuses_without_page_marker(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    """Sibling class: /health answers 200 but the web root is a foreign page.

    The service health wait proves only that the container is up; the product
    gate requires the actual StatePort page, session, and catalog.  A 200 on
    /health with a wrong web root must refuse, not pass on HTTP status alone.
    """
    fixture = _signed_index(tmp_path / "fixture", trust)
    config = _config(fixture, tmp_path, cosign=cosign_executable)
    outcome = _run_install(
        config,
        runner=FakeRunner(),
        probe=FakeProbe(_facts()),
        fetcher=FakeFetcher(page_marker=False),
    )
    assert outcome.status == "refused"
    assert outcome.code == "product_gate_failed"
    assert "marker" in outcome.message
    assert outcome.receipt_path is not None and outcome.receipt_path.is_file()


def test_stable_install_product_gate_refuses_when_root_is_404_but_health_is_ok(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    """A healthy container with a missing web root is not an installed product."""
    fixture = _signed_index(tmp_path / "fixture", trust)
    config = _config(fixture, tmp_path, cosign=cosign_executable)
    outcome = _run_install(
        config,
        runner=FakeRunner(),
        probe=FakeProbe(_facts()),
        fetcher=FakeFetcher(page_status=404),
    )
    assert outcome.status == "refused"
    assert outcome.code == "product_gate_failed"
    assert "HTTP 404" in outcome.message


def test_stable_install_product_gate_refuses_when_session_is_down(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    fixture = _signed_index(tmp_path / "fixture", trust)
    config = _config(fixture, tmp_path, cosign=cosign_executable)
    outcome = _run_install(
        config,
        runner=FakeRunner(),
        probe=FakeProbe(_facts()),
        fetcher=FakeFetcher(session_ok=False),
    )
    assert outcome.status == "refused"
    assert outcome.code == "product_gate_failed"


def test_stable_install_product_gate_refuses_when_session_payload_is_malformed(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    fixture = _signed_index(tmp_path / "fixture", trust)
    config = _config(fixture, tmp_path, cosign=cosign_executable)
    outcome = _run_install(
        config,
        runner=FakeRunner(),
        probe=FakeProbe(_facts()),
        fetcher=FakeFetcher(session_body=b"not-json"),
    )
    assert outcome.status == "refused"
    assert outcome.code == "product_gate_failed"


def test_stable_install_product_gate_refuses_when_catalog_is_invalid(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    """Sibling class: catalog reachable but the sample contract is wrong.

    A 200 catalog with a missing sample (or a sample with a different
    networkPolicy) must refuse exactly like an unreachable catalog: the gate is
    about the product contract, not mere HTTP availability.
    """
    fixture = _signed_index(tmp_path / "fixture", trust)
    config = _config(fixture, tmp_path, cosign=cosign_executable)
    outcome = _run_install(
        config,
        runner=FakeRunner(),
        probe=FakeProbe(_facts()),
        fetcher=FakeFetcher(catalog_valid=False),
    )
    assert outcome.status == "refused"
    assert outcome.code == "product_gate_failed"
    assert "catalog" in outcome.message
    assert outcome.receipt_path is not None and outcome.receipt_path.is_file()


def test_stable_install_product_gate_refuses_when_catalog_is_unavailable(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    fixture = _signed_index(tmp_path / "fixture", trust)
    config = _config(fixture, tmp_path, cosign=cosign_executable)
    outcome = _run_install(
        config,
        runner=FakeRunner(),
        probe=FakeProbe(_facts()),
        fetcher=FakeFetcher(catalog_status=503, catalog_body=b"temporarily unavailable"),
    )
    assert outcome.status == "refused"
    assert outcome.code == "product_gate_failed"
    assert "HTTP 503" in outcome.message


def test_stable_install_product_gate_refuses_when_catalog_network_policy_is_enabled(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    fixture = _signed_index(tmp_path / "fixture", trust)
    config = _config(fixture, tmp_path, cosign=cosign_executable)
    outcome = _run_install(
        config,
        runner=FakeRunner(),
        probe=FakeProbe(_facts()),
        fetcher=FakeFetcher(catalog_network_policy="enabled"),
    )
    assert outcome.status == "refused"
    assert outcome.code == "product_gate_failed"
    assert "networkPolicy" in outcome.message


def test_product_gate_refuses_non_object_catalog_response() -> None:
    class CatalogFetcher:
        def fetch(self, url: str, *, timeout: float, max_bytes: int) -> installer.FetchResult:
            if url.endswith("/"):
                return installer.FetchResult(200, b'<title>StatePort</title>')
            if url.endswith("/session"):
                return installer.FetchResult(200, b'{"ok": true}')
            return installer.FetchResult(200, b'[]')

    with pytest.raises(installer.InstallerRefusal, match="not an object") as raised:
        installer._verify_installed_product(
            CatalogFetcher(), local_url="http://127.0.0.1:8080/", timeout=1
        )
    assert raised.value.code == "product_gate_failed"


def test_installer_product_catalog_validator_matches_public_alpha_preflight() -> None:
    """Drift guard: the mirrored catalog validator agrees with the checkout
    preflight on identical payloads.

    The installer cannot import scripts/public_alpha_preflight.py (it is not
    in the digest-pinned updater wheel), so the constants and validation are
    mirrored.  This test pins that the two agree on the same good and bad
    payloads so a product contract change cannot silently split them.
    """
    good = {
        "ok": True,
        "result": {
            "applications": [
                {
                    "applicationId": "studystate.sample",
                    "displayName": "StudyState Sample",
                    "install": {
                        "status": "available",
                        "reasons": [],
                        "confirmationRequired": True,
                        "sourceKind": "bundled_public_fixture",
                        "requestedCapabilities": [
                            "conversation",
                            "goal_execution",
                            "proactive_notifications",
                            "progress_dashboard",
                        ],
                        "networkPolicy": "disabled",
                    },
                }
            ]
        },
    }
    assert installer._validate_product_catalog(good)["applicationId"] == "studystate.sample"
    assert public_alpha_preflight.validate_catalog(good)["applicationId"] == "studystate.sample"

    bad_variants = [
        {"ok": True, "result": {"applications": []}},
        {"ok": True, "result": {"applications": [{"applicationId": "other.sample", "displayName": "Other"}]}},
        {
            "ok": True,
            "result": {
                "applications": [
                    {
                        "applicationId": "studystate.sample",
                        "displayName": "StudyState Sample",
                        "install": {
                            "status": "available",
                            "reasons": [],
                            "confirmationRequired": True,
                            "sourceKind": "bundled_public_fixture",
                            "requestedCapabilities": [
                                "conversation",
                                "goal_execution",
                                "proactive_notifications",
                                "progress_dashboard",
                            ],
                            "networkPolicy": "enabled",
                        },
                    }
                ]
            },
        },
        {
            "ok": True,
            "result": {
                "applications": [
                    {
                        "applicationId": "studystate.sample",
                        "displayName": "StudyState Sample",
                        "install": {
                            "status": "available",
                            "reasons": [],
                            "confirmationRequired": True,
                            "sourceKind": "bundled_public_fixture",
                            "requestedCapabilities": ["conversation"],
                            "networkPolicy": "disabled",
                        },
                    }
                ]
            },
        },
    ]
    for payload in bad_variants:
        with pytest.raises(installer.InstallerRefusal):
            installer._validate_product_catalog(payload)
        with pytest.raises(public_alpha_preflight.PreflightError):
            public_alpha_preflight.validate_catalog(payload)


def test_foreign_provisioning_plan_content_refuses_closed(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    fixture = _signed_index(tmp_path / "fixture", trust)
    config = _config(fixture, tmp_path, cosign=cosign_executable)
    config.state_root.mkdir(parents=True, exist_ok=True)
    (config.state_root / "execution-host-provisioning-plan.json").write_bytes(b"foreign\n")
    outcome = _run_install(
        config, runner=FakeRunner(), probe=FakeProbe(_facts()), fetcher=FakeFetcher()
    )
    assert outcome.status == "refused"
    assert outcome.code == "provisioning_plan_conflict"


def test_reconcile_ports_prefers_installed_unit_publications() -> None:
    staged = {
        "staged/abc/unit/stateport-api-accepted.container": (
            "Label=io.stateport.service.id=stateport-api\n"
            "Label=io.stateport.profile=accepted\n"
            "PublishPort=127.0.0.1:18512:8790\n"
        ).encode(),
        "staged/abc/unit/stateport-web-accepted.container": (
            "Label=io.stateport.service.id=stateport-web\n"
            "Label=io.stateport.profile=accepted\n"
            "PublishPort=127.0.0.1:18707:8080\n"
        ).encode(),
    }
    services = [
        {
            "serviceId": "stateport-api",
            "ports": [{"name": "http", "containerPort": 8790}],
        },
        {
            "serviceId": "stateport-web",
            "ports": [{"name": "http", "containerPort": 8080}],
        },
    ]
    ports = {
        "stateport-api:accepted:http": 18529,
        "stateport-web:accepted:http": 18707,
    }
    reconciled = installer._reconcile_ports_with_installed_units(
        ports, staged, "staged/abc/", services
    )
    assert reconciled["stateport-api:accepted:http"] == 18512
    assert reconciled["stateport-web:accepted:http"] == 18707


def test_reconcile_ports_refuses_units_missing_a_declared_publish() -> None:
    staged = {
        "staged/abc/unit/stateport-api-accepted.container": (
            "Label=io.stateport.service.id=stateport-api\n"
            "Label=io.stateport.profile=accepted\n"
        ).encode(),
    }
    services = [
        {"serviceId": "stateport-api", "ports": [{"name": "http", "containerPort": 8790}]}
    ]
    reconciled = installer._reconcile_ports_with_installed_units(
        {"stateport-api:accepted:http": 18529}, staged, "staged/abc/", services
    )
    # Without a published port in the unit bytes the manifest value stands.
    assert reconciled["stateport-api:accepted:http"] == 18529


class _SudoCatRunner:
    """Minimal runner seam: serves canned bytes for `sudo -n cat <path>`."""

    def __init__(self, files: dict[str, str]) -> None:
        self.files = files

    def run(self, argv, *, check: bool = False, timeout=None, input=None, env=None):
        class _Result:
            def __init__(self, returncode: int, stdout: str, stderr: str = "") -> None:
                self.returncode = returncode
                self.stdout = stdout
                self.stderr = stderr

        if argv[:3] == ["sudo", "-n", "cat"]:
            path = argv[3]
            if path in self.files:
                return _Result(0, self.files[path])
            return _Result(1, "", f"cat: {path}: No such file or directory")
        raise AssertionError(f"unexpected runner call: {argv}")


def _live_reconciliation_fixtures(tmp_path: Path) -> tuple[dict[str, int], list[dict], list[dict], Path, Path]:
    services = [
        {
            "serviceId": "stateport-api",
            "ports": [{"name": "http", "containerPort": 8790}],
        },
        {
            "serviceId": "stateport-web",
            "ports": [{"name": "http", "containerPort": 8080}],
        },
    ]
    artifacts = [
        {
            "profile": "accepted",
            "kind": "container",
            "owner": "stateport-control",
            "liveRelativePath": "stateport-f544857680bc-accepted-c438.container",
        },
        {
            "profile": "accepted",
            "kind": "container",
            "owner": "rehearsal",
            "liveRelativePath": "stateport-ae4a67f11969-accepted-2db2.container",
        },
    ]
    ports = {
        "stateport-api:accepted:http": 18709,
        "stateport-web:accepted:http": 18264,
    }
    control_root = tmp_path / "control"
    live_root = tmp_path / "live"
    control_root.mkdir(parents=True, exist_ok=True)
    return ports, services, artifacts, live_root, control_root


def test_live_reconciliation_polls_the_provisioner_rendered_ports(tmp_path: Path) -> None:
    ports, services, artifacts, live_root, control_root = _live_reconciliation_fixtures(tmp_path)
    live_root.mkdir(parents=True)
    (live_root / "stateport-ae4a67f11969-accepted-2db2.container").write_text(
        "Label=io.stateport.service.id=stateport-web\n"
        "Label=io.stateport.profile=accepted\n"
        "PublishPort=127.0.0.1:18264:8080\n",
        encoding="utf-8",
    )
    runner = _SudoCatRunner(
        {
            str(control_root / "stateport-f544857680bc-accepted-c438.container"): (
                "Label=io.stateport.service.id=stateport-api\n"
                "Label=io.stateport.profile=accepted\n"
                "PublishPort=127.0.0.1:18692:8790\n"
            )
        }
    )
    reconciled = installer._reconcile_ports_with_live_units(
        ports,
        services,
        artifacts,
        live_root=live_root,
        control_root=control_root,
        runner=runner,
        provisioned=True,
    )
    # The root provisioning transaction re-rendered the api unit with its own
    # collision inventory; the poll must follow the unit actually started.
    assert reconciled["stateport-api:accepted:http"] == 18692
    assert reconciled["stateport-web:accepted:http"] == 18264


def test_live_reconciliation_refuses_declared_port_missing_from_started_unit(
    tmp_path: Path,
) -> None:
    ports, services, artifacts, live_root, control_root = _live_reconciliation_fixtures(tmp_path)
    live_root.mkdir(parents=True)
    (live_root / "stateport-ae4a67f11969-accepted-2db2.container").write_text(
        "Label=io.stateport.service.id=stateport-web\n"
        "Label=io.stateport.profile=accepted\n"
        "PublishPort=127.0.0.1:18264:8080\n",
        encoding="utf-8",
    )
    runner = _SudoCatRunner(
        {
            str(control_root / "stateport-f544857680bc-accepted-c438.container"): (
                "Label=io.stateport.service.id=stateport-api\n"
                "Label=io.stateport.profile=accepted\n"
            )
        }
    )
    with pytest.raises(installer.InstallerRefusal) as excinfo:
        installer._reconcile_ports_with_live_units(
            ports,
            services,
            artifacts,
            live_root=live_root,
            control_root=control_root,
            runner=runner,
            provisioned=True,
        )
    assert excinfo.value.code == "port_publication_missing"


def test_live_reconciliation_refuses_unreadable_control_unit(tmp_path: Path) -> None:
    ports, services, artifacts, live_root, control_root = _live_reconciliation_fixtures(tmp_path)
    live_root.mkdir(parents=True)
    (live_root / "stateport-ae4a67f11969-accepted-2db2.container").write_text(
        "Label=io.stateport.service.id=stateport-web\n"
        "Label=io.stateport.profile=accepted\n"
        "PublishPort=127.0.0.1:18264:8080\n",
        encoding="utf-8",
    )
    runner = _SudoCatRunner({})
    with pytest.raises(installer.InstallerRefusal) as excinfo:
        installer._reconcile_ports_with_live_units(
            ports,
            services,
            artifacts,
            live_root=live_root,
            control_root=control_root,
            runner=runner,
            provisioned=True,
        )
    assert excinfo.value.code == "port_publication_missing"


def test_live_reconciliation_skips_control_units_without_provisioning(tmp_path: Path) -> None:
    ports, services, artifacts, live_root, control_root = _live_reconciliation_fixtures(tmp_path)
    live_root.mkdir(parents=True)
    (live_root / "stateport-ae4a67f11969-accepted-2db2.container").write_text(
        "Label=io.stateport.service.id=stateport-web\n"
        "Label=io.stateport.profile=accepted\n"
        "PublishPort=127.0.0.1:18264:8080\n",
        encoding="utf-8",
    )

    class _ForbiddenRunner:
        def run(self, argv, **kwargs):
            raise AssertionError(f"unexpected runner call without provisioning: {argv}")

    reconciled = installer._reconcile_ports_with_live_units(
        ports,
        services,
        artifacts,
        live_root=live_root,
        control_root=control_root,
        runner=_ForbiddenRunner(),
        provisioned=False,
    )
    # Without the root transaction nothing re-rendered control units; the
    # manifest value stands and no privileged read is attempted.
    assert reconciled["stateport-api:accepted:http"] == 18709
    assert reconciled["stateport-web:accepted:http"] == 18264


def test_zipimported_wheel_loads_release_index_schema(
    tmp_path: Path, trust: dict[str, object], cosign_executable: Path
) -> None:
    """The authenticated wheel must validate an index when imported from its zip.

    Regression for the owner public-path refusal
    ``release_verification_failed: release schema is unavailable`` on
    Windows 11 + WSL2 + Ubuntu 24.04: ``load_modules_from_authenticated_wheel``
    imports ``stateport_release`` directly from the wheel zip (zipimport), so
    ``__file__``-relative schema reads point at a path that is not a real
    directory.  The contract loader must fall back to reading the schema as a
    zip member through the zipimporter.
    """
    import subprocess

    # Build a genuine wheel zip from the real release-contracts source so the
    # zipimport path sees the actual package data (schemas included).
    release_src = ROOT / "packages/release-contracts/src/stateport_release"
    wheel = tmp_path / "stateport_updater-0.1.1-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(release_src.rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            relative = path.relative_to(release_src.parent).as_posix()
            archive.writestr(relative, path.read_bytes())
        archive.writestr(
            "stateport_updater-0.1.1.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: stateport-updater\nVersion: 0.1.1\n",
        )
        archive.writestr(
            "stateport_updater-0.1.1.dist-info/WHEEL",
            "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )

    fixture = _signed_index(tmp_path / "fixture", trust)
    index_path = fixture.index_path

    script = (
        "import json, pathlib, sys\n"
        "wheel = pathlib.Path(sys.argv[1])\n"
        "index = json.loads(pathlib.Path(sys.argv[2]).read_text())\n"
        "sys.path.insert(0, str(wheel))\n"
        "import stateport_release\n"
        "from stateport_release import contract\n"
        "assert type(contract.__loader__).__name__ == 'zipimporter', contract.__loader__\n"
        "verified = contract.validate_release_index(index)\n"
        "print(verified.release_id)\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script, str(wheel), str(index_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "stateport-alpha-0.2.0-rc.1"
