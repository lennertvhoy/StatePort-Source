#!/usr/bin/env python3
"""Single-entrypoint runner for the custom provider OCI producer build.

Implements decisions D1-D7 of
``evidence/one-line-release-001/stage1-producer-build-procedure-r2.md``
fail-closed:

D1. Per-run self-signed TLS CA under the external output root; consumer trust
    only through ``~/.config/containers/certs.d/<registry>/ca.crt`` (written,
    recorded, removed at teardown).
D2. Single-platform identity: ``manifestDigest = platformManifestDigest =
    podman push --digestfile`` value.
D3. EPOCH = ``git show -s --format=%ct <H>`` where H is the clean committed
    StatePort head at admission.
D4. Pinned ``registry:2`` base verified by local observation before start;
    TLS task-owned loopback registry with create-only storage whose identity
    is recorded and identity-checked at teardown.
D5. Governor service membership required; output root must be a new directory
    outside the repository.
D6. Byte-identical double build (same ``producer-r1`` tag) with
    ``--tls-verify=false --format docker --digestfile`` pushes; the run fails
    unless both pushed digests are equal.
D7. ``producer-build-receipt.json`` (formatVersion
    ``stateport.producer-build-receipt/v1``) records every binding listed in
    the procedure. Deviations are fail-closed.

Retention lifecycle (procedure r2 amendment F2):

- ``--keep-registry``: on a SUCCESSFUL run the task-owned TLS registry
  container, its registry-storage directory and the per-user certs.d trust
  entry are deliberately retained so the subsequent consumer rebuild can
  pre-pull the provider image from the pinned loopback reference. The
  receipt records ``registryRetention``. On a FAILED run nothing is
  retained: the fail-closed teardown still removes everything.
- ``--teardown --receipt <producer-build-receipt.json>``: lightweight
  cleanup-only mode that re-verifies every retained identity exactly
  (container ID plus recorded image ID and managed labels, storage
  directory identity, certs.d CA digest) and only then removes the
  retained resources by their exact recorded identities, writing a
  create-only ``producer-build-teardown.json`` sidecar. It never removes
  by name or guess, never rewrites the receipt, and does not require the
  ``image_build`` governor action. If a teardown removes only some of the
  resources, the sidecar still records the per-resource errors; any
  residue must then be removed manually by its exact recorded identity
  after inspection.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import time
from typing import Any, Mapping
from urllib.error import URLError
from urllib.request import urlopen

import yaml

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import build_release_images as bri  # noqa: E402  (scripts/ import pattern)

from release_guard import ReleaseGuardError, require_guard  # noqa: E402
from release_safe_io import (  # noqa: E402
    directory_identity,
    prepare_output_root,
    remove_tree_exact,
    safe_path,
    sha256_file,
    write_json_create_only,
)


ROOT = Path(__file__).resolve().parents[1]
RECEIPT_NAME = "producer-build-receipt.json"
FAILURE_NAME = "producer-build-failure.json"
TLS_DIR = "tls"
DIGESTS_DIR = "digests"
STORAGE_DIR = "registry-storage"
PROVIDER_REPOSITORY = "stateport-alpha/stateport-provider"
PRODUCER_TAG_NAME = "producer-r1"
CONTEXT_RECEIPT_FORMAT = "stateport.provider-real-context-receipt/v1"
RECEIPT_FORMAT = "stateport.producer-build-receipt/v1"
FAILURE_FORMAT = "stateport.producer-build-failure/v1"
TEARDOWN_FORMAT = "stateport.producer-build-teardown/v1"
TEARDOWN_NAME = "producer-build-teardown.json"
RETENTION_MODE = "retained-for-consumer-rebuild"
CONSUMER_RESERVED_PORT = 5000
MANAGED_REGISTRY_LABELS = {
    "io.stateport.managed": "true",
    "io.stateport.purpose": "producer-local-registry",
}
_FULL_COMMIT = re.compile(r"[0-9a-f]{40}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_CONTAINER_ID = re.compile(r"[0-9a-f]{12,64}")
_CERTS_D = Path(".config/containers/certs.d")


class ProducerBuildError(RuntimeError):
    """The producer build was refused or failed fail-closed."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fail(message: str) -> ProducerBuildError:
    return ProducerBuildError(message)


def _safe_child(root: Path, name: str) -> Path:
    if PurePosixPath(name).parts != (name,) or name in {"", ".", ".."}:
        raise _fail(f"unsafe output-root child name: {name!r}")
    return root / name


def refuse_reserved_consumer_port(registry: str) -> None:
    """Refuse the loopback port reserved by the consumer rebuild.

    ``build_release_images.py`` starts its consumer registry on the default
    ``127.0.0.1:5000``. A producer registry there would collide with it, so
    build mode refuses that exact loopback port before any other work.
    """

    if not registry.startswith("127.0.0.1:"):
        return
    port_text = registry.rsplit(":", 1)[-1]
    if port_text.isdigit() and int(port_text) == CONSUMER_RESERVED_PORT:
        raise _fail(
            f"the producer registry must not use port {CONSUMER_RESERVED_PORT}: "
            "it is reserved for the consumer rebuild registry "
            "(build_release_images.py default); use another loopback port such as 5001"
        )


def verify_context(context: Path, receipt_path: Path) -> dict[str, Any]:
    """Recompute every context file against the reviewed payload receipt.

    The receipt's ``context.files`` table is the reviewed authority (P3/D7).
    The directory must contain exactly the recorded files — no missing, no
    extra, no subdirectories, no symlinks — with byte-identical sha256
    digests, sizes, and modes.
    """

    if context.is_symlink() or not context.is_dir():
        raise _fail(f"producer build context is unavailable or unsafe: {context}")
    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise _fail(f"provider context receipt is unavailable or unsafe: {receipt_path}")
    receipt_digest = sha256_file(receipt_path)
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise _fail(f"provider context receipt is unreadable: {exc}") from exc
    if not isinstance(receipt, Mapping):
        raise _fail("provider context receipt is not an object")
    if receipt.get("formatVersion") != CONTEXT_RECEIPT_FORMAT:
        raise _fail("provider context receipt has an unsupported formatVersion")
    recorded_context = receipt.get("context")
    if not isinstance(recorded_context, Mapping) or not isinstance(
        recorded_context.get("files"), Mapping
    ):
        raise _fail("provider context receipt lacks the context.files table")
    recorded_files = recorded_context["files"]
    if not recorded_files:
        raise _fail("provider context receipt records no context files")
    if "Containerfile" not in recorded_files:
        raise _fail("provider context receipt lacks the Containerfile entry")
    try:
        entries = sorted(context.iterdir(), key=lambda item: item.name)
    except OSError as exc:
        raise _fail(f"producer build context is unreadable: {exc}") from exc
    observed: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if entry.is_symlink() or not entry.is_file():
            raise _fail(
                f"producer build context contains a non-regular entry: {entry.name!r}"
            )
        observed[entry.name] = {
            "sha256": sha256_file(entry),
            "bytes": entry.stat().st_size,
            "mode": format(stat.S_IMODE(entry.stat().st_mode), "04o"),
        }
    if set(observed) != set(recorded_files):
        missing = sorted(set(recorded_files) - set(observed))
        extra = sorted(set(observed) - set(recorded_files))
        raise _fail(
            "producer build context does not match the reviewed receipt "
            f"(missing: {missing}, extra: {extra})"
        )
    verified: dict[str, dict[str, Any]] = {}
    for name in sorted(recorded_files):
        expected = recorded_files[name]
        if not isinstance(expected, Mapping):
            raise _fail(f"provider context receipt entry is malformed: {name}")
        digest = str(expected.get("sha256", ""))
        if _HEX64.fullmatch(digest) is None:
            raise _fail(f"provider context receipt digest is invalid for {name}")
        actual = observed[name]
        expected_bytes = expected.get("bytes")
        if not isinstance(expected_bytes, int) or isinstance(expected_bytes, bool):
            raise _fail(f"provider context receipt byte size is invalid for {name}")
        expected_mode = str(expected.get("mode", ""))
        if not expected_mode.startswith("0o"):
            raise _fail(f"provider context receipt mode is invalid for {name}")
        try:
            expected_mode_bits = int(expected_mode[2:], 8)
        except ValueError:
            raise _fail(f"provider context receipt mode is invalid for {name}") from None
        if (
            actual["sha256"] != "sha256:" + digest
            or actual["bytes"] != expected_bytes
            or actual["mode"] != format(expected_mode_bits, "04o")
        ):
            raise _fail(
                f"producer build context file drifted from the reviewed receipt: {name}"
            )
        verified[name] = {
            "sha256": digest,
            "bytes": actual["bytes"],
            "mode": "0o" + format(int(actual["mode"], 8), "03o"),
        }
    if len(verified) != 9:
        raise _fail(
            f"provider context receipt must bind exactly the 9 reviewed files, got {len(verified)}"
        )
    return {
        "receiptPath": str(receipt_path.resolve()),
        "receiptDigest": receipt_digest,
        "contextPath": str(context.resolve()),
        "fileCount": len(verified),
        "files": verified,
        "verification": "exact-set-sha256-bytes-mode-against-reviewed-receipt",
    }


def derive_epoch(head: str | None) -> dict[str, Any]:
    """Derive EPOCH from the clean committed admission head (D3)."""

    dirty = bri._run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=ROOT,
        capture=True,
    )
    if dirty:
        raise _fail("producer build requires an exact clean committed tree")
    current = bri._run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture=True)
    if _FULL_COMMIT.fullmatch(current) is None:
        raise _fail("current StatePort head is not an exact SHA-1 commit")
    if head is None:
        resolved = current
    else:
        if _FULL_COMMIT.fullmatch(head) is None:
            raise _fail("--head must be one exact full SHA-1 commit")
        observed = bri._run(
            ["git", "rev-parse", "--verify", f"{head}^{{commit}}"],
            cwd=ROOT,
            capture=True,
        )
        if observed != head:
            raise _fail("--head did not resolve exactly to a StatePort commit")
        resolved = head
    if resolved != current:
        raise _fail(
            "--head differs from the clean current HEAD at admission; "
            "EPOCH must derive from the admitted head"
        )
    raw_epoch = bri._run(
        ["git", "show", "-s", "--format=%ct", resolved],
        cwd=ROOT,
        capture=True,
    )
    if re.fullmatch(r"[0-9]+", raw_epoch) is None:
        raise _fail("git did not return a numeric committer timestamp for EPOCH")
    epoch = int(raw_epoch)
    created = datetime.fromtimestamp(epoch, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    return {
        "head": resolved,
        "epoch": epoch,
        "created": created,
        "epochDerivationCommand": ["git", "show", "-s", "--format=%ct", resolved],
        "epochRule": "git-committer-timestamp-of-admission-head",
    }


def verify_registry_base() -> dict[str, Any]:
    """Bind the pinned registry:2 base by local observation (D4).

    Mirrors ``build_release_images.pull_and_verify_base_images`` /
    ``start_local_registry`` verification: the config's registry-2 index
    digest AND platform manifest digest must both be observed on the local
    image with one shared imageId on linux/amd64. The base is never pulled
    here; a missing pre-pulled base fails closed.
    """

    manifest = bri._load_yaml(bri.BASE_IMAGES)
    images = manifest.get("images")
    if not isinstance(images, Mapping) or "registry-2" not in images:
        raise _fail("container base images lack the registry-2 entry")
    entry = images["registry-2"]
    reference = str(entry.get("reference", ""))
    if reference != bri.REGISTRY_IMAGE:
        raise _fail("registry-2 reference does not match the pinned release registry image")
    index_digest = str(entry.get("indexDigest", ""))
    platform_digest = str(entry.get("platformManifestDigest", ""))
    if reference.rsplit("@", 1)[-1] != index_digest:
        raise _fail("registry-2 index digest is not the pinned reference digest")
    platform_reference = reference.rsplit("@", 1)[0] + "@" + platform_digest
    index_observation = bri._image_observation(reference)
    platform_observation = bri._image_observation(platform_reference)
    required = {index_digest, platform_digest}
    if (
        index_observation["digest"] != index_digest
        or platform_observation["digest"] != platform_digest
        or not required.issubset(index_observation["observedDigests"])
        or not required.issubset(platform_observation["observedDigests"])
        or index_observation["imageId"] != platform_observation["imageId"]
        or (index_observation["os"], index_observation["architecture"]) != ("linux", "amd64")
        or (platform_observation["os"], platform_observation["architecture"])
        != ("linux", "amd64")
    ):
        raise _fail(
            "pinned registry base is not the pre-pulled qualified linux/amd64 "
            "index and platform manifest"
        )
    return {
        "baseId": "registry-2",
        "reference": reference,
        "indexDigest": index_digest,
        "platformManifestDigest": platform_digest,
        "platform": "linux/amd64",
        "imageId": index_observation["imageId"],
        "observedDigests": sorted(set(index_observation["observedDigests"])),
        "verification": "exact-index-and-platform-manifest",
        "pullPolicy": "never-pre-pulled-base-required",
    }


def generate_tls_material(output: Path, registry_host: str) -> dict[str, Any]:
    """Generate the per-run self-signed CA and server certificate (D1)."""

    openssl = shutil.which("openssl")
    if not openssl:
        raise _fail("producer TLS setup requires an openssl executable")
    tls_dir = _safe_child(output, TLS_DIR)
    if tls_dir.exists() or tls_dir.is_symlink():
        raise _fail("producer TLS directory must be create-only")
    tls_dir.mkdir(mode=0o700)
    try:
        ipaddress.ip_address(registry_host)
        san = f"IP:{registry_host},DNS:localhost"
    except ValueError:
        san = f"DNS:{registry_host}"
    ca_key = tls_dir / "ca.key"
    ca_crt = tls_dir / "ca.crt"
    server_key = tls_dir / "server.key"
    server_csr = tls_dir / "server.csr"
    server_crt = tls_dir / "server.crt"
    ext_file = tls_dir / "server-ext.cnf"
    bri._run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-nodes",
            "-keyout",
            str(ca_key),
            "-out",
            str(ca_crt),
            "-days",
            "2",
            "-subj",
            "/CN=stateport-producer-registry-ca",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ]
    )
    bri._run(
        [
            openssl,
            "req",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-nodes",
            "-keyout",
            str(server_key),
            "-out",
            str(server_csr),
            "-subj",
            f"/CN={registry_host}",
        ]
    )
    ext_content = (
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        f"subjectAltName={san}\n"
    )
    ext_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(ext_file, ext_flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(ext_content)
    bri._run(
        [
            openssl,
            "x509",
            "-req",
            "-in",
            str(server_csr),
            "-CA",
            str(ca_crt),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-out",
            str(server_crt),
            "-days",
            "2",
            "-sha256",
            "-extfile",
            str(ext_file),
        ]
    )
    for produced in (ca_crt, ca_key, server_key, server_crt):
        if produced.is_symlink() or not produced.is_file() or produced.stat().st_size == 0:
            raise _fail(f"openssl did not produce usable TLS material: {produced.name}")
    return {
        "directory": str(tls_dir),
        "caCert": str(ca_crt),
        "caKey": str(ca_key),
        "serverCert": str(server_crt),
        "serverKey": str(server_key),
        "caCertDigest": sha256_file(ca_crt),
        "serverCertDigest": sha256_file(server_crt),
        "subjectAltName": san,
        "validityDays": 2,
        "scope": "per-run-loopback-registry-only",
    }


def install_certs_d_trust(
    tls: Mapping[str, Any], registry: str, *, home: Path | None = None
) -> dict[str, Any]:
    """Publish the CA through per-user certs.d only (D1)."""

    base = (home or Path.home()) / _CERTS_D
    if base.is_symlink():
        raise _fail("containers certs.d trust root must not be a symlink")
    endpoint_dir = base / registry
    if endpoint_dir.is_symlink():
        raise _fail("certs.d endpoint directory must not be a symlink")
    if endpoint_dir.exists():
        raise _fail(
            "certs.d endpoint directory already exists; refusing to reuse or "
            "overwrite an existing trust entry"
        )
    ca_crt = Path(str(tls["caCert"]))
    if ca_crt.is_symlink() or not ca_crt.is_file():
        raise _fail("producer CA certificate is unavailable")
    ca_bytes = ca_crt.read_bytes()
    endpoint_dir.mkdir(parents=True, exist_ok=False)
    target = endpoint_dir / "ca.crt"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(target, flags, 0o444)
    try:
        view = memoryview(ca_bytes)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise _fail("producer certs.d CA write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return {
        "trustRoot": str(base),
        "endpointDir": str(endpoint_dir),
        "path": str(target),
        "caDigest": "sha256:" + hashlib.sha256(ca_bytes).hexdigest(),
        "writtenAt": _utc_now(),
        "written": True,
        "mechanism": "per-user-containers-certs-d-only",
    }


def remove_certs_d_trust(record: Mapping[str, Any]) -> dict[str, Any]:
    """Remove the exact written certs.d entry after identity validation."""

    target = Path(str(record["path"]))
    if target.is_symlink() or not target.is_file():
        raise _fail("certs.d trust entry disappeared or is unsafe before removal")
    data = target.read_bytes()
    if "sha256:" + hashlib.sha256(data).hexdigest() != str(record["caDigest"]):
        raise _fail("certs.d trust entry changed after write; refusing to remove blindly")
    endpoint_dir = target.parent
    certs_d_root = endpoint_dir.parent
    if certs_d_root.name != "certs.d":
        raise _fail("certs.d trust entry does not live under a certs.d trust root")
    target.unlink()
    pruned: list[str] = []
    for directory in (endpoint_dir, certs_d_root):
        try:
            directory.rmdir()
        except OSError:
            break
        pruned.append(str(directory))
    return {
        **dict(record),
        "removed": True,
        "removedAt": _utc_now(),
        "prunedEmptyDirs": pruned,
    }


def _wait_registry_health(
    endpoint: str, ca_path: Path, *, timeout_seconds: int = 20, interval: float = 0.2
) -> bool:
    """Poll the TLS /v2/ health endpoint trusting only the per-run CA."""

    context = ssl.create_default_context(cafile=str(ca_path))
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            with urlopen(f"https://{endpoint}/v2/", timeout=2, context=context) as response:
                if response.status == 200:
                    return True
        except (OSError, URLError, ssl.SSLError):
            pass
        time.sleep(interval)
    return False


def start_producer_registry(
    registry: str,
    *,
    name: str,
    storage: Path,
    tls: Mapping[str, Any],
    base_record: Mapping[str, Any],
    cgroup_parent: str | None,
) -> dict[str, Any]:
    """Start the TLS task-owned loopback registry (D4)."""

    bri.validate_registry_endpoint(registry)
    if bri._container_exists(name):
        raise _fail(f"task-owned producer registry container already exists: {name}")
    if base_record.get("verification") != "exact-index-and-platform-manifest":
        raise _fail("registry base verification record is incomplete")
    # Mirror build_release_images.start_local_registry: re-observe the live
    # registry image immediately before start and bind it to the recorded
    # base verification (imageId and both digests on linux/amd64).
    live_registry_image = bri._image_observation(bri.REGISTRY_IMAGE)
    if (
        base_record.get("baseId") != "registry-2"
        or base_record.get("reference") != bri.REGISTRY_IMAGE
        or base_record.get("imageId") != live_registry_image["imageId"]
        or base_record.get("indexDigest") not in live_registry_image["observedDigests"]
        or base_record.get("platformManifestDigest")
        not in live_registry_image["observedDigests"]
        or (live_registry_image["os"], live_registry_image["architecture"])
        != ("linux", "amd64")
    ):
        raise _fail(
            "producer registry base is not the pre-pulled qualified linux/amd64 "
            "index and platform manifest observed immediately before start"
        )
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", int(registry.rsplit(":", 1)[1])))
        except OSError as exc:
            raise _fail(f"producer registry port is already in use: {registry}") from exc
    container_id = bri._run(
        [
            str(bri.PODMAN),
            *(["--cgroup-manager=cgroupfs"] if cgroup_parent else []),
            "run",
            *(["--cgroup-parent", cgroup_parent] if cgroup_parent else []),
            "--pull=never",
            "--detach",
            "--name",
            name,
            "--label",
            "io.stateport.managed=true",
            "--label",
            "io.stateport.purpose=producer-local-registry",
            "--publish",
            f"{registry}:5000",
            "--volume",
            f"{storage}:/var/lib/registry:Z",
            "--volume",
            f"{tls['directory']}:/certs:Z",
            "-e",
            "REGISTRY_HTTP_ADDR=0.0.0.0:5000",
            "-e",
            "REGISTRY_HTTP_TLS_CERTIFICATE=/certs/server.crt",
            "-e",
            "REGISTRY_HTTP_TLS_KEY=/certs/server.key",
            bri.REGISTRY_IMAGE,
        ],
        capture=True,
    )
    if _CONTAINER_ID.fullmatch(container_id) is None:
        raise _fail("podman did not return an exact producer registry container ID")
    healthy = _wait_registry_health(registry, Path(str(tls["caCert"])))
    if not healthy:
        try:
            bri._run([str(bri.PODMAN), "rm", "--force", container_id], timeout=60)
        finally:
            raise _fail("task-owned producer registry did not become healthy over TLS")
    return {
        "name": name,
        "containerId": container_id,
        "image": bri.REGISTRY_IMAGE,
        "imageId": live_registry_image["imageId"],
        "imageObservation": live_registry_image,
        "endpoint": registry,
        "publish": f"{registry}:5000",
        "transport": "tls-selfsigned-ca-via-per-user-certs-d-loopback-only",
        "healthEndpoint": f"https://{registry}/v2/",
        "healthy": True,
        "storage": STORAGE_DIR,
        "storageIdentity": directory_identity(storage),
        "baseVerification": dict(base_record),
        "imagePullPolicy": "never-after-exact-prequalification",
        "labels": dict(MANAGED_REGISTRY_LABELS),
        "startedAt": _utc_now(),
    }


def stop_producer_registry(record: Mapping[str, Any]) -> dict[str, Any]:
    """Stop and remove the registry by its exact recorded container ID."""

    container_id = str(record["containerId"])
    if _CONTAINER_ID.fullmatch(container_id) is None:
        raise _fail("producer registry record has no exact container ID")
    bri._run([str(bri.PODMAN), "stop", "--time", "10", container_id], timeout=60)
    bri._run([str(bri.PODMAN), "rm", container_id], timeout=60)
    if bri._container_exists(container_id):
        raise _fail("task-owned producer registry remained after cleanup")
    return {
        **dict(record),
        "stoppedAt": _utc_now(),
        "cleanup": "container-removed-by-exact-id",
    }


def producer_build_command(
    *,
    registry: str,
    context: Path,
    epoch: int,
    cgroup_parent: str | None,
) -> list[str]:
    """Return the byte-identical double-build command (D6)."""

    tag = f"{registry}/{PROVIDER_REPOSITORY}:{PRODUCER_TAG_NAME}"
    # The cgroup child path is a stability key only (buildah never uses the
    # file). Both producer builds must share ONE slot because their argv has
    # to stay byte-identical.
    digest_slot = Path("/stateport-producer-cgroup-slot") / f"{PRODUCER_TAG_NAME}.digest"
    return [
        str(bri.PODMAN),
        *(["--cgroup-manager=cgroupfs"] if cgroup_parent else []),
        "build",
        *(
            [
                "--cgroup-parent",
                bri.build_cgroup_path(cgroup_parent, digest_file=digest_slot),
                "--isolation=oci",
            ]
            if cgroup_parent
            else []
        ),
        "--no-cache",
        "--pull=never",
        "--network=private",
        "--format",
        "docker",
        "--platform",
        "linux/amd64",
        "--timestamp",
        str(epoch),
        "-f",
        str(context / "Containerfile"),
        "-t",
        tag,
        str(context),
    ]


def producer_push_command(registry: str, digest_file: Path) -> list[str]:
    tag = f"{registry}/{PROVIDER_REPOSITORY}:{PRODUCER_TAG_NAME}"
    return [
        str(bri.PODMAN),
        "push",
        "--tls-verify=false",
        "--digestfile",
        str(digest_file),
        "--format",
        "docker",
        tag,
        f"docker://{tag}",
    ]


def execute_double_build(
    *,
    build_command: list[str],
    registry: str,
    digest_root: Path,
) -> tuple[list[dict[str, Any]], str]:
    """Run the byte-identical double build and enforce digest equality (D6)."""

    tag = f"{registry}/{PROVIDER_REPOSITORY}:{PRODUCER_TAG_NAME}"
    observations: list[dict[str, Any]] = []
    pushed: list[str] = []
    for ordinal in (1, 2):
        digest_file = digest_root / f"{PRODUCER_TAG_NAME}-build{ordinal}.digest"
        if digest_file.exists() or digest_file.is_symlink():
            raise _fail(f"digest output already exists: {digest_file.name}")
        started = _utc_now()
        bri._run(build_command)
        bri._run(producer_push_command(registry, digest_file))
        observed = bri._read_observed_digest(digest_file)
        pushed.append(observed)
        observations.append(
            {
                "ordinal": ordinal,
                "command": list(build_command),
                "pushCommand": producer_push_command(registry, digest_file),
                "pushedDigest": observed,
                "digestFile": f"{DIGESTS_DIR}/{digest_file.name}",
                "digestFileDigest": sha256_file(digest_file),
                "startedAt": started,
                "finishedAt": _utc_now(),
            }
        )
    if pushed[0] != pushed[1]:
        raise _fail(
            f"producer double build is not OCI-digest reproducible: "
            f"{pushed[0]} != {pushed[1]}"
        )
    return observations, pushed[0]


def _teardown(
    *,
    registry_record: Mapping[str, Any] | None,
    output: Path | None,
    storage_identity: Mapping[str, Any] | None,
    certs_record: Mapping[str, Any] | None,
) -> tuple[dict[str, Any], list[str]]:
    """Best-effort identity-checked teardown of every created resource."""

    result: dict[str, Any] = {
        "container": "not-started",
        "storage": "not-created",
        "certsD": "not-written",
    }
    errors: list[str] = []
    if registry_record is not None:
        try:
            stopped = stop_producer_registry(registry_record)
            result["container"] = stopped["cleanup"]
            result["stoppedAt"] = stopped["stoppedAt"]
        except Exception as exc:
            result["container"] = "removal-failed"
            errors.append(f"container: {type(exc).__name__}: {exc}")
    if output is not None and storage_identity is not None:
        try:
            remove_tree_exact(
                output, STORAGE_DIR, expected_identity=storage_identity
            )
            result["storage"] = "removed-identity-checked"
        except Exception as exc:
            result["storage"] = "removal-failed"
            errors.append(f"storage: {type(exc).__name__}: {exc}")
    if certs_record is not None:
        try:
            removed = remove_certs_d_trust(certs_record)
            result["certsD"] = "removed-identity-checked"
            result["certsDRemovedAt"] = removed["removedAt"]
        except Exception as exc:
            result["certsD"] = "removal-failed"
            errors.append(f"certsD: {type(exc).__name__}: {exc}")
    result["errors"] = errors
    return result, errors


def remove_certs_d_record(
    record: Mapping[str, Any], teardown: Mapping[str, Any]
) -> dict[str, Any]:
    """Fold the teardown result into the recorded certs.d lifecycle."""

    return {
        **dict(record),
        "removed": teardown.get("certsD") == "removed-identity-checked",
        "removedAt": teardown.get("certsDRemovedAt"),
    }


def load_retained_receipt(receipt_path: Path) -> tuple[dict[str, Any], str]:
    """Load a successful retained producer-build receipt exactly (F2).

    The receipt is the teardown's only authority: it must be a regular
    non-symlink file, must carry the producer receipt formatVersion, must
    record a succeeded result and must carry the ``registryRetention``
    block of a ``--keep-registry`` run.
    """

    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise _fail(f"producer-build receipt is unavailable or unsafe: {receipt_path}")
    raw = receipt_path.read_bytes()
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    try:
        receipt = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise _fail(f"producer-build receipt is unreadable: {exc}") from exc
    if not isinstance(receipt, Mapping):
        raise _fail("producer-build receipt is not an object")
    if receipt.get("formatVersion") != RECEIPT_FORMAT:
        raise _fail(
            f"producer-build receipt has an unsupported formatVersion: "
            f"{receipt.get('formatVersion')!r}"
        )
    if receipt.get("result") != "succeeded":
        raise _fail(
            f"producer-build receipt does not record a succeeded run: {receipt.get('result')!r}"
        )
    retention = receipt.get("registryRetention")
    if not isinstance(retention, Mapping):
        raise _fail(
            "producer-build receipt records no retained registry; nothing to tear down"
        )
    if retention.get("mode") != RETENTION_MODE:
        raise _fail(
            f"registryRetention mode is not {RETENTION_MODE!r}: {retention.get('mode')!r}"
        )
    return dict(receipt), digest


def verify_retained_container(
    retention: Mapping[str, Any], receipt: Mapping[str, Any]
) -> dict[str, Any]:
    """Re-verify the retained container by exact ID and managed labels (F2)."""

    container_id = retention.get("containerId")
    if not isinstance(container_id, str) or _CONTAINER_ID.fullmatch(container_id) is None:
        raise _fail(f"retained registry container ID is not an exact container ID: {container_id!r}")
    registry_record = receipt.get("registry")
    if not isinstance(registry_record, Mapping):
        raise _fail("producer-build receipt lacks the registry record")
    if registry_record.get("containerId") != container_id:
        raise _fail(
            "registryRetention containerId does not match the receipt registry record: "
            f"{container_id!r} != {registry_record.get('containerId')!r}"
        )
    expected_labels = registry_record.get("labels")
    if not isinstance(expected_labels, Mapping) or dict(expected_labels) != dict(
        MANAGED_REGISTRY_LABELS
    ):
        raise _fail(
            "receipt registry record does not pin the exact stateport managed labels"
        )
    base_verification = registry_record.get("baseVerification")
    if not isinstance(base_verification, Mapping):
        raise _fail("receipt registry record lacks the base verification record")
    expected_image = base_verification.get("imageId")
    if not isinstance(expected_image, str) or not expected_image.startswith("sha256:"):
        raise _fail("receipt registry record lacks the recorded base image ID")
    recorded_image = registry_record.get("imageId")
    if recorded_image is not None and recorded_image != expected_image:
        raise _fail(
            "receipt registry imageId does not match the base verification imageId: "
            f"{recorded_image!r} != {expected_image!r}"
        )
    try:
        raw = bri._run(
            [str(bri.PODMAN), "container", "inspect", container_id],
            capture=True,
            timeout=60,
        )
    except Exception as exc:
        raise _fail(
            f"retained registry container is missing or uninspectable by its exact ID: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    try:
        entries = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise _fail(f"podman container inspect returned unreadable JSON: {exc}") from exc
    if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], Mapping):
        raise _fail("podman container inspect did not return exactly one container object")
    observed = entries[0]
    observed_id = observed.get("Id")
    if observed_id != container_id:
        raise _fail(
            f"retained registry container identity mismatch: inspected {observed_id!r}, "
            f"receipt recorded {container_id!r}"
        )
    observed_image = observed.get("Image")
    if observed_image != expected_image:
        raise _fail(
            f"retained registry container image mismatch: inspected {observed_image!r}, "
            f"receipt recorded {expected_image!r}"
        )
    labels = observed.get("Labels")
    if not isinstance(labels, Mapping):
        config = observed.get("Config")
        labels = config.get("Labels") if isinstance(config, Mapping) else None
    if not isinstance(labels, Mapping) or dict(labels) != dict(MANAGED_REGISTRY_LABELS):
        raise _fail(
            f"retained registry container labels mismatch: observed {labels!r}, "
            f"required {dict(MANAGED_REGISTRY_LABELS)!r}"
        )
    return {
        "expectedContainerId": container_id,
        "observedContainerId": observed_id,
        "imageId": observed_image,
        "labels": dict(labels),
        "verification": "exact-id-image-and-managed-labels",
    }


def verify_retained_storage(
    retention: Mapping[str, Any], receipt: Mapping[str, Any]
) -> dict[str, Any]:
    """Re-verify the retained registry-storage directory identity (F2)."""

    recorded = retention.get("storageIdentity")
    if not isinstance(recorded, Mapping):
        raise _fail("registryRetention lacks the recorded storage identity")
    registry_record = receipt.get("registry")
    if not isinstance(registry_record, Mapping) or registry_record.get(
        "storageIdentity"
    ) != recorded:
        raise _fail(
            "registryRetention storageIdentity does not match the receipt registry record"
        )
    output_root = receipt.get("outputRoot")
    if not isinstance(output_root, str) or not output_root:
        raise _fail("producer-build receipt lacks the output root")
    storage = Path(output_root) / STORAGE_DIR
    if recorded.get("path") != str(storage):
        raise _fail(
            f"recorded storage identity does not name the receipt's registry storage: "
            f"{recorded.get('path')!r} != {str(storage)!r}"
        )
    try:
        observed = directory_identity(storage)
    except Exception as exc:
        raise _fail(
            f"retained registry storage is missing or unsafe: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    if (
        observed.get("device") != recorded.get("device")
        or observed.get("inode") != recorded.get("inode")
        or observed.get("mode") != recorded.get("mode")
    ):
        raise _fail(
            "retained registry storage identity mismatch: observed "
            f"({observed.get('device')}, {observed.get('inode')}, {observed.get('mode')}) "
            f"!= recorded ({recorded.get('device')}, {recorded.get('inode')}, "
            f"{recorded.get('mode')})"
        )
    return {
        "recordedIdentity": dict(recorded),
        "observedIdentity": observed,
        "verification": "exact-directory-device-inode-mode",
    }


def verify_retained_certs(
    retention: Mapping[str, Any], receipt: Mapping[str, Any]
) -> dict[str, Any]:
    """Re-verify the retained certs.d trust entry digest (F2)."""

    certs_record = receipt.get("certsD")
    if not isinstance(certs_record, Mapping) or "path" not in certs_record:
        raise _fail("producer-build receipt lacks the certs.d trust record")
    certs_path = Path(str(certs_record["path"]))
    if retention.get("certsPath") != str(certs_path):
        raise _fail(
            f"registryRetention certsPath does not match the receipt certs.d record: "
            f"{retention.get('certsPath')!r} != {str(certs_path)!r}"
        )
    if "caDigest" not in certs_record:
        raise _fail("producer-build receipt certs.d record lacks the CA digest")
    if certs_path.is_symlink() or not certs_path.is_file():
        raise _fail(
            f"retained certs.d trust entry is missing or unsafe: {certs_path}"
        )
    try:
        observed_digest = sha256_file(certs_path)
    except Exception as exc:
        raise _fail(
            f"retained certs.d trust entry is unreadable: {type(exc).__name__}: {exc}"
        ) from exc
    if observed_digest != str(certs_record["caDigest"]):
        raise _fail(
            f"retained certs.d trust entry digest mismatch: observed {observed_digest}, "
            f"recorded {certs_record['caDigest']}"
        )
    return {
        "path": str(certs_path),
        "caDigest": observed_digest,
        "verification": "exact-sha256-against-recorded-ca-identity",
    }


def retained_registry_teardown(receipt_path: Path) -> dict[str, Any]:
    """Tear down a retained ``--keep-registry`` producer registry (F2).

    Cleanup-only: re-verifies every retained identity against reality and
    refuses with the exact mismatch before removing anything. Removal is
    strictly by exact recorded identity (container ID, directory identity,
    CA digest). The receipt itself is never modified; a create-only
    ``producer-build-teardown.json`` sidecar is written beside it.
    """

    receipt, receipt_digest = load_retained_receipt(receipt_path)
    receipt_dir = receipt_path.resolve().parent
    if (receipt_dir / TEARDOWN_NAME).exists() or (receipt_dir / TEARDOWN_NAME).is_symlink():
        raise _fail(
            "teardown sidecar already exists; retained teardown must not run twice"
        )
    retention = receipt["registryRetention"]
    verified = {
        "container": verify_retained_container(retention, receipt),
        "storage": verify_retained_storage(retention, receipt),
        "certsD": verify_retained_certs(retention, receipt),
    }
    started = _utc_now()
    removed: dict[str, Any] = {}
    errors: list[str] = []
    try:
        stopped = stop_producer_registry(
            {"containerId": retention["containerId"], "name": receipt["registry"]["name"]}
        )
        removed["container"] = stopped["cleanup"]
        removed["stoppedAt"] = stopped["stoppedAt"]
    except Exception as exc:
        removed["container"] = "removal-failed"
        errors.append(f"container: {type(exc).__name__}: {exc}")
    try:
        remove_tree_exact(
            Path(str(receipt["outputRoot"])),
            STORAGE_DIR,
            expected_identity=retention["storageIdentity"],
        )
        removed["storage"] = "removed-identity-checked"
    except Exception as exc:
        removed["storage"] = "removal-failed"
        errors.append(f"storage: {type(exc).__name__}: {exc}")
    try:
        certs_removed = remove_certs_d_trust(receipt["certsD"])
        removed["certsD"] = "removed-identity-checked"
        removed["certsDRemovedAt"] = certs_removed["removedAt"]
        removed["prunedEmptyDirs"] = certs_removed["prunedEmptyDirs"]
    except Exception as exc:
        removed["certsD"] = "removal-failed"
        errors.append(f"certsD: {type(exc).__name__}: {exc}")
    report: dict[str, Any] = {
        "formatVersion": TEARDOWN_FORMAT,
        "mode": "cleanup-only-identity-verified",
        "receiptPath": str(receipt_path.resolve()),
        "receiptSha256": receipt_digest,
        "retentionMode": retention["mode"],
        "verified": verified,
        "removed": removed,
        "errors": errors,
        "startedAt": started,
        "finishedAt": _utc_now(),
    }
    try:
        write_json_create_only(receipt_dir, TEARDOWN_NAME, report)
    except OSError as exc:
        raise _fail(f"teardown sidecar could not be written create-only: {exc}") from exc
    if errors:
        raise _fail(
            "retained registry teardown removed resources only partially; "
            f"sidecar records the failures: {errors}"
        )
    return report


def producer_build(
    *,
    context: Path,
    context_receipt: Path,
    output_root: Path,
    registry: str,
    head: str | None = None,
    guard_receipt_digest: str | None = None,
    home: Path | None = None,
    keep_registry: bool = False,
) -> dict[str, Any]:
    """Execute the D1-D7 producer procedure and write the build receipt.

    ``home`` overrides the certs.d trust root for tests; production uses the
    real per-user home. With ``keep_registry`` a successful run retains the
    task-owned registry container, its storage and the certs.d trust entry
    for the subsequent consumer rebuild and records ``registryRetention``;
    a failed run still tears down everything (fail-closed).
    """

    # D5/F2: reserved-port refusal, loopback-only endpoint and governor
    # service membership before any other work.
    refuse_reserved_consumer_port(registry)
    bri.validate_registry_endpoint(registry)
    cgroup_parent = bri.governor_cgroup_parent()
    identity = derive_epoch(head)
    builder = bri.verify_podman_builder()
    context_verification = verify_context(context, context_receipt)
    output = prepare_output_root(output_root, repository=ROOT)
    output_identity = directory_identity(output)
    digests_dir = _safe_child(output, DIGESTS_DIR)
    digests_dir.mkdir(mode=0o700)
    started = _utc_now()
    base_record = verify_registry_base()
    tls = generate_tls_material(output, registry.rsplit(":", 1)[0])
    certs_record: dict[str, Any] | None = None
    registry_record: dict[str, Any] | None = None
    storage_identity: dict[str, Any] | None = None
    try:
        certs_record = install_certs_d_trust(tls, registry, home=home)
        storage = _safe_child(output, STORAGE_DIR)
        if storage.exists() or storage.is_symlink():
            raise _fail("task-owned registry storage must be create-only")
        storage.mkdir(mode=0o700)
        storage_identity = directory_identity(storage)
        name = (
            f"stateport-producer-registry-{identity['head'][:12]}-{os.getpid()}"
        )
        registry_record = start_producer_registry(
            registry,
            name=name,
            storage=storage,
            tls=tls,
            base_record=base_record,
            cgroup_parent=cgroup_parent,
        )
        build_command = producer_build_command(
            registry=registry,
            context=Path(context_verification["contextPath"]),
            epoch=int(identity["epoch"]),
            cgroup_parent=cgroup_parent,
        )
        observations, pushed_digest = execute_double_build(
            build_command=build_command,
            registry=registry,
            digest_root=digests_dir,
        )
        image_observation = bri._image_observation(
            f"{registry}/{PROVIDER_REPOSITORY}:{PRODUCER_TAG_NAME}"
        )
    except BaseException as failure:
        teardown, _errors = _teardown(
            registry_record=registry_record,
            output=output,
            storage_identity=storage_identity,
            certs_record=certs_record,
        )
        try:
            write_json_create_only(
                output,
                FAILURE_NAME,
                {
                    "formatVersion": FAILURE_FORMAT,
                    "identity": identity,
                    "failedAt": _utc_now(),
                    "errorType": type(failure).__name__,
                    "message": str(failure)[:1000],
                    "teardown": teardown,
                },
            )
        except OSError:
            pass
        raise
    retention_record: dict[str, Any] | None = None
    if keep_registry:
        # F2: retain the registry, its storage and the certs.d trust entry
        # for the consumer rebuild; record the retention block only.
        registry_full = {
            **registry_record,
            "cleanup": RETENTION_MODE,
            "storageResult": RETENTION_MODE,
        }
        certs_final = dict(certs_record)
        retention_record = {
            "mode": RETENTION_MODE,
            "containerId": registry_record["containerId"],
            "storageIdentity": dict(storage_identity),
            "certsPath": certs_record["path"],
            "retainedAt": _utc_now(),
        }
    else:
        teardown, teardown_errors = _teardown(
            registry_record=registry_record,
            output=output,
            storage_identity=storage_identity,
            certs_record=certs_record,
        )
        if teardown_errors:
            raise _fail(
                "producer build succeeded but identity-checked teardown failed; "
                f"no success receipt written: {teardown_errors}"
            )
        registry_full = {
            **registry_record,
            "stoppedAt": teardown.get("stoppedAt"),
            "cleanup": teardown["container"],
            "storageResult": teardown["storage"],
        }
        certs_final = remove_certs_d_record(certs_record, teardown)
    receipt: dict[str, Any] = {
        "formatVersion": RECEIPT_FORMAT,
        "outputRoot": str(output),
        "outputRootIdentity": output_identity,
        "identity": identity,
        "guard": {
            "action": "image_build",
            "cgroupParent": cgroup_parent,
            "receiptDigest": guard_receipt_digest,
        },
        "builder": builder,
        "contextReceipt": context_verification,
        "registry": registry_full,
        "tls": dict(tls),
        "certsD": certs_final,
        "tag": f"{registry}/{PROVIDER_REPOSITORY}:{PRODUCER_TAG_NAME}",
        "builds": observations,
        "buildArgvIdentical": observations[0]["command"] == observations[1]["command"],
        "reproducible": True,
        "manifestDigest": pushed_digest,
        "platformManifestDigest": pushed_digest,
        "image": {
            "imageId": image_observation["imageId"],
            "digest": image_observation.get("digest"),
            "observedDigests": sorted(image_observation.get("observedDigests", [])),
            "os": image_observation.get("os"),
            "architecture": image_observation.get("architecture"),
            "platform": "linux/amd64",
        },
        "acceptedReference": (
            f"{registry}/{PROVIDER_REPOSITORY}@{pushed_digest}"
        ),
        "startedAt": started,
        "finishedAt": _utc_now(),
        "result": "succeeded",
    }
    if retention_record is not None:
        receipt["registryRetention"] = retention_record
    try:
        write_json_create_only(output, RECEIPT_NAME, receipt)
    except BaseException as exc:
        # Any failure while persisting the success receipt — including
        # ReleaseIOError, which derives from ValueError rather than OSError —
        # must revoke retention: a retained registry without a receipt would
        # be unremovable by --teardown. The run therefore tears down exactly
        # what it created and records the failure (fail-closed retention).
        if retention_record is not None:
            teardown, _errors = _teardown(
                registry_record=registry_record,
                output=output,
                storage_identity=storage_identity,
                certs_record=certs_record,
            )
            try:
                write_json_create_only(
                    output,
                    FAILURE_NAME,
                    {
                        "formatVersion": FAILURE_FORMAT,
                        "identity": identity,
                        "failedAt": _utc_now(),
                        "errorType": type(exc).__name__,
                        "message": str(exc)[:1000],
                        "teardown": teardown,
                    },
                )
            except (OSError, ValueError):
                pass
        raise
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Custom provider OCI producer build (Stage 1 lane 4, procedure r2 D1-D7). "
            "Build mode verifies the reviewed context, runs the byte-identical double "
            "build against a task-owned TLS loopback registry and writes "
            "producer-build-receipt.json. Teardown mode is cleanup-only: it "
            "re-verifies the retained registry identities recorded in a "
            "--keep-registry receipt and removes exactly those resources."
        ),
    )
    parser.add_argument(
        "--context",
        type=Path,
        help="build mode: reviewed provider-real-context directory (verified against --context-receipt)",
    )
    parser.add_argument(
        "--context-receipt",
        type=Path,
        help="build mode: provider-real-context-receipt.json binding the 9 context files",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        help="build mode: new create-only output root outside the repository (absolute path)",
    )
    parser.add_argument(
        "--registry-host",
        default="127.0.0.1",
        help="build mode: registry host; loopback 127.0.0.1 only (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5001,
        help=(
            "build mode: producer registry loopback port (default: 5001); "
            "port 5000 is refused because the consumer rebuild registry reserves it"
        ),
    )
    parser.add_argument(
        "--head",
        help="build mode: exact clean committed StatePort head H for EPOCH derivation (default: current HEAD)",
    )
    parser.add_argument(
        "--keep-registry",
        action="store_true",
        help=(
            "build mode: on SUCCESS retain the TLS registry container, its "
            "registry-storage directory and the certs.d trust entry for the "
            "subsequent consumer rebuild; the receipt records registryRetention "
            "{mode: retained-for-consumer-rebuild, containerId, storageIdentity, "
            "certsPath, retainedAt}. A FAILED run still tears down everything "
            "(fail-closed). Retained resources are removed later with "
            "--teardown --receipt <producer-build-receipt.json>"
        ),
    )
    parser.add_argument(
        "--teardown",
        action="store_true",
        help=(
            "cleanup-only mode: load --receipt, re-verify every retained identity "
            "exactly (container ID plus recorded image ID and managed labels, storage "
            "directory identity, certs.d CA sha256), refuse with the exact mismatch on "
            "any drift, and "
            "only then stop/remove the container by exact ID, remove the storage by "
            "recorded identity and remove the certs.d entry after digest re-check. "
            "Writes a create-only producer-build-teardown.json sidecar; never "
            "modifies the receipt. A partially failed teardown still writes the "
            "sidecar recording the per-resource errors; any residue must then be "
            "removed manually by its exact recorded identity after inspection. "
            "Does not require the image_build governor action."
        ),
    )
    parser.add_argument(
        "--receipt",
        type=Path,
        help="teardown mode: path to the producer-build-receipt.json of a --keep-registry run",
    )
    args = parser.parse_args(argv)

    if args.teardown:
        if args.receipt is None:
            parser.error("--teardown requires --receipt <producer-build-receipt.json>")
        report = retained_registry_teardown(args.receipt)
        print(json.dumps(report, sort_keys=True))
        return 0

    missing = [
        name
        for name, value in (
            ("--context", args.context),
            ("--context-receipt", args.context_receipt),
            ("--output-root", args.output_root),
        )
        if value is None
    ]
    if missing:
        parser.error(f"the following arguments are required in build mode: {', '.join(missing)}")
    if args.port == CONSUMER_RESERVED_PORT:
        parser.error(
            f"--port {CONSUMER_RESERVED_PORT} is reserved for the consumer rebuild "
            "registry (build_release_images.py default); choose another loopback "
            "port such as 5001"
        )
    if args.receipt is not None:
        parser.error("--receipt is only valid together with --teardown")
    script_argv = sys.argv if argv is None else [str(Path(__file__).resolve()), *argv]
    guard_receipt_digest = require_guard("image_build", script_argv)
    registry = f"{args.registry_host}:{args.port}"
    receipt = producer_build(
        context=args.context,
        context_receipt=args.context_receipt,
        output_root=args.output_root,
        registry=registry,
        head=args.head,
        guard_receipt_digest=guard_receipt_digest,
        keep_registry=args.keep_registry,
    )
    print(json.dumps(receipt, sort_keys=True))
    return 0


def entrypoint(argv: list[str] | None = None) -> int:
    """CLI entrypoint: translate every controlled refusal into a clean exit 2."""

    try:
        return main(argv)
    except (
        OSError,
        ProducerBuildError,
        bri.ReleaseBuildError,
        ReleaseGuardError,
        ValueError,
        subprocess.TimeoutExpired,
        yaml.YAMLError,
    ) as exc:
        print(f"producer build refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(entrypoint())
