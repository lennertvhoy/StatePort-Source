#!/usr/bin/env python3
"""Render the immutable one-command WSL2 bootstrap from a signed candidate."""

from __future__ import annotations

import argparse
import hashlib
from io import BytesIO
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import tarfile
from typing import Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
WSL2_TARGET_ID = "wsl2-ubuntu2404-linux-amd64-rootless-podman-quadlet"
COSIGN_VERSION = "v3.1.3"
COSIGN_SHA256 = "4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71"
COSIGN_URL = (
    "https://github.com/sigstore/cosign/releases/download/"
    f"{COSIGN_VERSION}/cosign-linux-amd64"
)
PODMAN_REQUIRED_PACKAGES = frozenset(
    {
        "aardvark-dns",
        "catatonit",
        "conmon",
        "containers-storage",
        "fuse-overlayfs",
        "golang-github-containers-common",
        "golang-github-containers-image",
        "libslirp0",
        "libsubid4",
        "netavark",
        "podman",
        "runc",
        "stateport-crun",
        "slirp4netns",
        "uidmap",
    }
)
WSL_ROOTFS_DIGEST = "sha256:9b2f7730dc68227dd04a9f3e5eab86ad85caf556b8606ad94f1f29ff5c4fd3f5"
_BUNDLE_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,118}\.sigstore\.json$")


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _alpha_release_label(version: str) -> tuple[str, str]:
    """Bind the user-facing label and manifest directory to the signed version.

    Fail-closed: a non-alpha version can never render a WSL2 bootstrap with a
    stale or invented label.
    """
    match = re.fullmatch(r"0\.1\.0-alpha\.(\d+)", version)
    _require(match is not None, f"WSL2 bootstrap requires a 0.1.0-alpha.N signed version, got: {version}")
    return f"Alpha.{match.group(1)}", f"alpha{match.group(1)}"


def _release_label(
    document: Mapping[str, object], *, version: str, trust_key_id: str, release_root_url: str
) -> tuple[str, str]:
    """Admit the reserved local J1 identity without widening public alpha rules."""
    if re.fullmatch(r"0\.1\.0-alpha\.[0-9]+", version):
        return _alpha_release_label(version)

    _require(
        re.fullmatch(r"0\.0\.0-j1\.[0-9]+", version) is not None,
        f"WSL2 bootstrap requires a 0.1.0-alpha.N signed version, got: {version}",
    )
    signed = document.get("signed")
    _require(isinstance(signed, Mapping), "signed candidate document is malformed")
    release = signed.get("release")
    _require(isinstance(release, Mapping), "signed candidate release is missing")
    _require(release.get("qualification") == "candidate", "qualification bootstrap requires a candidate")
    release_id = release.get("releaseId")
    _require(
        isinstance(release_id, str)
        and re.fullmatch(r"stateport-j1-integrated-qualification-[a-z0-9-]+", release_id)
        is not None,
        "qualification bootstrap requires a qualification-only release ID",
    )
    _require(
        trust_key_id.startswith("stateport-qualification-"),
        "qualification bootstrap requires a qualification trust key",
    )
    _require(
        re.fullmatch(r"https://127\.0\.0\.1(?::[0-9]{1,5})?/[^?#]+", release_root_url)
        is not None,
        "qualification bootstrap requires a loopback HTTPS release root",
    )
    publication = signed.get("publication")
    _require(
        isinstance(publication, Mapping) and publication.get("publishedAt") is None,
        "qualification bootstrap requires an unpublished candidate",
    )
    source = signed.get("source")
    candidate_provenance = source.get("candidateProvenance") if isinstance(source, Mapping) else None
    provenance_document = (
        candidate_provenance.get("document")
        if isinstance(candidate_provenance, Mapping)
        else None
    )
    _require(
        isinstance(provenance_document, Mapping)
        and provenance_document.get("classification") == "local_qualification_candidate",
        "qualification bootstrap requires local qualification provenance",
    )
    suffix = version.removeprefix("0.0.0-j1.")
    return f"J1 qualification {suffix}", f"j1-{suffix}"


def _artifact(candidate: Path, document: Mapping[str, object], artifact_id: str) -> Path:
    descriptor = document["signed"]["artifacts"][artifact_id]  # type: ignore[index]
    path = candidate / "artifacts" / artifact_id
    _require(path.is_file() and not path.is_symlink(), f"missing candidate artifact: {artifact_id}")
    _require(_sha256(path) == descriptor["digest"], f"candidate artifact digest mismatch: {artifact_id}")  # type: ignore[index]
    _require(path.stat().st_size == descriptor["size"], f"candidate artifact size mismatch: {artifact_id}")  # type: ignore[index]
    return path


def _predecessor_bundle_downloads(
    candidate: Path, document: Mapping[str, object]
) -> list[str]:
    signed = document["signed"]  # type: ignore[index]
    successor = signed.get("successor")  # type: ignore[union-attr]
    predecessor = successor.get("predecessor") if isinstance(successor, Mapping) else None
    if predecessor is None:
        return []
    raw_index = predecessor.get("rawIndex") if isinstance(predecessor, Mapping) else None
    signatures = raw_index.get("signatures") if isinstance(raw_index, Mapping) else None
    _require(
        isinstance(signatures, Sequence) and not isinstance(signatures, (str, bytes)) and signatures,
        "signed predecessor has no signatures",
    )
    downloads = ['mkdir -m 700 "$tmp/predecessor-bundle"']
    for signature in signatures:
        _require(isinstance(signature, Mapping), "signed predecessor signature is malformed")
        descriptor = signature.get("bundle")
        _require(isinstance(descriptor, Mapping), "signed predecessor bundle is malformed")
        uri = descriptor.get("uri")
        _require(isinstance(uri, str), "signed predecessor bundle URI is malformed")
        bundle_name = uri.rsplit("/", 1)[-1]
        _require(
            bundle_name == "release-index.sigstore.json",
            "signed predecessor bundle name is unsupported",
        )
        bundle = candidate / "predecessor-bundle" / bundle_name
        _require(
            bundle.is_file() and not bundle.is_symlink(),
            "signed predecessor bundle is missing",
        )
        _require(_sha256(bundle) == descriptor.get("digest"), "predecessor bundle digest mismatch")
        _require(bundle.stat().st_size == descriptor.get("size"), "predecessor bundle size mismatch")
        downloads.extend(
            (
                f'get "$RELEASE_ROOT/predecessor-bundle/{bundle_name}" "$tmp/predecessor-bundle/{bundle_name}" "predecessor signature bundle"',
                f'check "{_sha256(bundle).removeprefix("sha256:")}" "$tmp/predecessor-bundle/{bundle_name}"',
            )
        )
    return downloads


def _image_manifest_carrier_commands(document: Mapping[str, object]) -> list[str]:
    """Fetch exact signed manifests into the immutable installer's archive seam."""

    commands: list[str] = []
    images = document["signed"]["images"]  # type: ignore[index]
    for image in sorted(images, key=lambda item: item["imageId"]):  # type: ignore[union-attr]
        signature = image["signature"]
        if signature.get("subjectKind") != "oci-manifest-blob":
            continue
        image_id = str(image["imageId"])
        reference = str(image["reference"])
        digest = str(signature["subjectDigest"])
        _require(
            reference.endswith("@" + digest),
            f"private image reference is not digest-bound: {image_id}",
        )
        commands.append(
            "manifest_carrier "
            + " ".join(shlex.quote(value) for value in (image_id, reference, digest))
        )
    return commands


def _image_manifest_probe_downloads(document: Mapping[str, object]) -> list[str]:
    """Download every exact private manifest without entering installation."""

    downloads: list[str] = []
    images = document["signed"]["images"]  # type: ignore[index]
    for image in sorted(images, key=lambda item: item["imageId"]):  # type: ignore[union-attr]
        signature = image["signature"]
        if signature.get("subjectKind") != "oci-manifest-blob":
            continue
        image_id = str(image["imageId"])
        digest = str(signature["subjectDigest"]).removeprefix("sha256:")
        downloads.extend(
            (
                f'  get "$PROBE_ROOT/{image_id}.json" "$tmp/{image_id}.manifest.json" "image manifest: {image_id}"',
                f'  check "{digest}" "$tmp/{image_id}.manifest.json"',
            )
        )
    return downloads


def _image_manifest_static_carrier_commands(document: Mapping[str, object]) -> list[str]:
    """Materialize exact static manifests without requiring Podman or Skopeo."""

    commands: list[str] = []
    images = document["signed"]["images"]  # type: ignore[index]
    for image in sorted(images, key=lambda item: item["imageId"]):  # type: ignore[union-attr]
        signature = image["signature"]
        if signature.get("subjectKind") != "oci-manifest-blob":
            continue
        image_id = str(image["imageId"])
        digest = str(signature["subjectDigest"])
        digest_hex = digest.removeprefix("sha256:")
        commands.extend(
            (
                f'get "$PROBE_ROOT/{image_id}.json" "$tmp/image-manifests/{image_id}" "image manifest: {image_id}"',
                f'check "{digest_hex}" "$tmp/image-manifests/{image_id}"',
                f'mkdir -m 700 "$tmp/image-carriers/{image_id}" "$tmp/image-carriers/{image_id}/blobs" "$tmp/image-carriers/{image_id}/blobs/sha256"',
                f'cp "$tmp/image-manifests/{image_id}" "$tmp/image-carriers/{image_id}/blobs/sha256/{digest_hex}"',
                f'printf \'{{"schemaVersion":2,"manifests":[{{"digest":"{digest}"}}]}}\\n\' > "$tmp/image-carriers/{image_id}/index.json"',
                f'tar -cf "$tmp/image-archives/{image_id}.oci.tar" --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -C "$tmp/image-carriers/{image_id}" index.json "blobs/sha256/{digest_hex}"',
            )
        )
    return commands


def _digest_slot_bundle_commands(document: Mapping[str, object], candidate: Path) -> list[str]:
    """Emit commands that retain every signed bundle into its digest slot.

    The installer's release-contract verifier reads each signature bundle from
    ``bundle_root/<sha256>/<bundle_name>`` (content-addressed slots), while the
    bootstrap stages the same bytes flat (release-index.sigstore.json) and under
    ``image-bundles/``.  Both layouts must exist under ``$tmp`` so the package
    preflight admission and the genesis install retention resolve every bundle
    without any prior durable state.
    """

    commands: list[str] = ['retain_slot() { mkdir -p -m 700 "$1"; install -m 600 "$2" "$1/$3"; }']
    for signature in document.get("signatures", []):  # type: ignore[union-attr]
        if not isinstance(signature, Mapping):
            continue
        bundle = signature.get("bundle")
        if not isinstance(bundle, Mapping):
            continue
        digest = bundle.get("digest")
        uri = bundle.get("uri")
        if not isinstance(digest, str) or not isinstance(uri, str):
            continue
        name = uri.rsplit("/", 1)[-1]
        if _BUNDLE_NAME.fullmatch(name) is None:
            raise ValueError(f"signature bundle URI names no retained bundle: {uri}")
        if name == "release-index.sigstore.json":
            staged = '$tmp/release-index.sigstore.json'
        else:
            staged = f'$tmp/image-bundles/{name}'
        commands.append(
            f'retain_slot "$tmp/{digest.removeprefix("sha256:")}" "{staged}" "{name}"'
        )
    images = document["signed"]["images"]  # type: ignore[index]
    for image in sorted(images, key=lambda item: item["imageId"]):  # type: ignore[union-attr]
        signature = image["signature"]
        if not isinstance(signature, Mapping):
            continue
        bundle = signature.get("bundle")
        if not isinstance(bundle, Mapping):
            continue
        digest = bundle.get("digest")
        uri = bundle.get("uri")
        if not isinstance(digest, str) or not isinstance(uri, str):
            continue
        name = uri.rsplit("/", 1)[-1]
        if _BUNDLE_NAME.fullmatch(name) is None:
            raise ValueError(f"image bundle URI names no retained bundle: {uri}")
        digest_hex = digest.removeprefix("sha256:")
        image_id = str(image["imageId"])
        image_bundle = candidate / "image-bundles" / f"{image_id}.sigstore.json"
        if not image_bundle.is_file():
            image_bundle = candidate / f"{image_id}.sigstore.json"
        _require(
            image_bundle.is_file() and not image_bundle.is_symlink(),
            f"missing image bundle: {image_id}",
        )
        _require(
            _sha256(image_bundle) == digest, f"image bundle digest mismatch: {image_id}"
        )
        commands.append(f'retain_slot "$tmp/{digest_hex}" "$tmp/image-bundles/{name}" "{name}"')
    return commands


def _podman_package_filenames(bundle: Path) -> tuple[str, ...]:
    try:
        with tarfile.open(fileobj=BytesIO(bundle.read_bytes()), mode="r:") as archive:
            member = archive.getmember("podman-package-bundle/manifest.json")
            _require(member.isfile(), "Podman package manifest is not a regular file")
            stream = archive.extractfile(member)
            _require(stream is not None, "Podman package manifest is unreadable")
            manifest = json.load(stream)
    except (OSError, KeyError, tarfile.TarError, json.JSONDecodeError) as exc:
        raise ValueError("Podman package manifest is invalid JSON") from exc
    _require(isinstance(manifest, Mapping), "Podman package manifest is not an object")
    records = manifest.get("packages")
    _require(
        manifest.get("schema") == "stateport/podman-package-bundle/v2"
        and manifest.get("target") == WSL2_TARGET_ID
        and isinstance(manifest.get("rootfs"), Mapping)
        and manifest["rootfs"].get("digest") == WSL_ROOTFS_DIGEST
        and isinstance(records, list)
        and len(PODMAN_REQUIRED_PACKAGES) <= len(records) <= 128,
        "Podman package manifest identity is invalid",
    )
    filenames: dict[str, str] = {}
    for record in records:
        _require(isinstance(record, Mapping), "Podman package record is malformed")
        name = record.get("name")
        filename = record.get("file")
        _require(
            isinstance(name, str)
            and re.fullmatch(r"[a-z0-9][a-z0-9+.-]{0,127}", name) is not None
            and isinstance(filename, str)
            and PurePosixPath(filename).name == filename
            and filename.endswith(("_all.deb", "_amd64.deb"))
            and name not in filenames,
            "Podman package filename inventory is invalid",
        )
        filenames[str(name)] = filename
    _require(
        PODMAN_REQUIRED_PACKAGES <= set(filenames),
        "Podman package filename inventory is incomplete",
    )
    return tuple(filenames[name] for name in sorted(filenames))


def render(
    *,
    candidate: Path,
    trust_public_key: Path,
    release_root_url: str,
) -> bytes:
    import sys

    release_src = ROOT / "packages" / "release-contracts" / "src"
    if str(release_src) not in sys.path:
        sys.path.insert(0, str(release_src))
    from stateport_release import (  # noqa: PLC0415
        load_release_index_file,
        public_key_der_spki_fingerprint,
    )

    _require(release_root_url.startswith("https://"), "release root must use HTTPS")
    _require("?" not in release_root_url and "#" not in release_root_url, "release root is not canonical")
    candidate = candidate.resolve()
    index_path = candidate / "release-index.json"
    index_bundle = candidate / "release-index.sigstore.json"
    _require(index_path.is_file() and index_bundle.is_file(), "signed candidate index is incomplete")
    index = load_release_index_file(index_path)
    document = index.document
    targets = document["signed"]["targets"]
    _require(len(targets) == 1 and targets[0]["targetId"] == WSL2_TARGET_ID, "candidate is not the exact WSL2 target")
    _require(len(document["signatures"]) == 1, "candidate must carry one index signature")
    signature = document["signatures"][0]
    _require(_sha256(index_bundle) == signature["bundle"]["digest"], "index bundle digest mismatch")
    _require(trust_public_key.is_file() and not trust_public_key.is_symlink(), "trust key is missing")
    _require(
        public_key_der_spki_fingerprint(trust_public_key) == signature["publicKeyFingerprint"],
        "trust key fingerprint mismatch",
    )
    installer = _artifact(candidate, document, "installer")
    provisioner = _artifact(candidate, document, "executionHostProvisioner")
    updater = _artifact(candidate, document, "updater")
    package_descriptor = document["signed"]["artifacts"].get("podmanPackageBundle")
    podman_package_bundle = (
        _artifact(candidate, document, "podmanPackageBundle")
        if package_descriptor is not None
        else None
    )
    predecessor_downloads = _predecessor_bundle_downloads(candidate, document)
    manifest_carrier_commands = _image_manifest_carrier_commands(document)
    manifest_probe_downloads = _image_manifest_probe_downloads(document)
    package_manifest_commands: list[str] = []
    if podman_package_bundle is not None:
        package_manifest_commands = _image_manifest_static_carrier_commands(document)
        manifest_carrier_commands = []

    image_downloads: list[str] = []
    for image in sorted(document["signed"]["images"], key=lambda item: item["imageId"]):
        image_id = str(image["imageId"])
        bundle = candidate / "image-bundles" / f"{image_id}.sigstore.json"
        if not bundle.is_file():
            bundle = candidate / f"{image_id}.sigstore.json"
        _require(bundle.is_file() and not bundle.is_symlink(), f"missing image bundle: {image_id}")
        _require(_sha256(bundle) == image["signature"]["bundle"]["digest"], f"image bundle digest mismatch: {image_id}")
        image_downloads.extend(
            (
                f'get "$RELEASE_ROOT/signatures/{image_id}.sigstore.json" "$tmp/image-bundles/{image_id}.sigstore.json" "image signature: {image_id}"',
                f'check "{_sha256(bundle).removeprefix("sha256:")}" "$tmp/image-bundles/{image_id}.sigstore.json"',
            )
        )
    digest_slot_commands = _digest_slot_bundle_commands(document, candidate)

    version = str(document["signed"]["release"]["version"])
    trust_id = str(signature["publicKeyId"])
    label, slug = _release_label(
        document, version=version, trust_key_id=trust_id, release_root_url=release_root_url
    )
    _require(
        release_root_url.rstrip("/").rsplit("/", 1)[-1] == version,
        "release root URL must end with the exact signed version",
    )
    trust_fingerprint = str(signature["publicKeyFingerprint"])
    index_sha = _sha256(index_path).removeprefix("sha256:")
    index_bundle_sha = _sha256(index_bundle).removeprefix("sha256:")
    key_sha = _sha256(trust_public_key).removeprefix("sha256:")
    installer_sha = _sha256(installer).removeprefix("sha256:")
    provisioner_sha = _sha256(provisioner).removeprefix("sha256:")
    updater_sha = _sha256(updater).removeprefix("sha256:")
    package_bundle_sha = (
        _sha256(podman_package_bundle).removeprefix("sha256:")
        if podman_package_bundle is not None
        else None
    )
    provisioner_bytes = provisioner.stat().st_size
    probe_root_url = release_root_url.rstrip("/").rsplit("/", 1)[0] + f"/{slug}-manifests"

    installer_args = " \\\n  ".join(
        shlex.quote(value)
        for value in (
            '--release-index "$tmp/release-index.json"',
            '--bundle-root "$tmp"',
            '--trust-public-key "$tmp/release.pub"',
            f"--trust-key-id {trust_id}",
            f"--trust-key-fingerprint {trust_fingerprint}",
            '--updater-wheel "$tmp/updater"',
            '--execution-host-provisioner "$tmp/provisioner"',
            '--compose "$RELEASE_ROOT/compose.yaml"',
            '--source-archive "$RELEASE_ROOT/stateport-source.tar"',
            '--release-notes "$RELEASE_ROOT/release-notes.md"',
            '--known-limitations "$RELEASE_ROOT/known-limitations.md"',
            *(
                (
                    '--podman-package-bundle "$tmp/podman-package-bundle.tar"',
                )
                if podman_package_bundle is not None
                else ()
            ),
            '--channel alpha',
            '--cosign "$tmp/cosign"',
            '--installer-path "$tmp/installer"',
            '--execution-host-receipt "$RECEIPT"',
            '--state-root "$STATE_ROOT"',
            *(("--yes",) if podman_package_bundle is None else ()),
        )
    ).replace("'", "")

    package_downloads: list[str] = []
    package_install: list[str] = [
        'sudo -v',
        'sudo apt-get update -o DPkg::Lock::Timeout=300 || { printf "StatePort apt update retry after lock contention\\n" >&2; sleep 10; sudo apt-get update -o DPkg::Lock::Timeout=300; }',
        'sudo apt-get install -y -o DPkg::Lock::Timeout=300 ca-certificates curl python3 python3-venv podman skopeo uidmap slirp4netns fuse-overlayfs dbus-user-session',
    ]
    runtime_post_checks = [
        'sudo loginctl enable-linger "$USER"',
        'command -v curl >/dev/null 2>&1 || fail "curl installation failed."',
        'command -v skopeo >/dev/null 2>&1 || fail "skopeo installation failed."',
        'command -v tar >/dev/null 2>&1 || fail "tar is required."',
        'command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required."',
    ]
    package_prerequisites: list[str] = []
    pre_download_runtime_setup = package_install + runtime_post_checks
    post_download_runtime_setup: list[str] = []
    if podman_package_bundle is not None:
        package_prerequisites = [
            'command -v curl >/dev/null 2>&1 || fail "curl is required before privileged installation."',
            'command -v dpkg-deb >/dev/null 2>&1 || fail "dpkg-deb is required before privileged installation."',
            'command -v python3 >/dev/null 2>&1 || fail "python3 is required before privileged installation."',
            'command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required before privileged installation."',
            'command -v tar >/dev/null 2>&1 || fail "tar is required before privileged installation."',
        ]
        package_downloads = [
            'get "$RELEASE_ROOT/stateport-podman-package-bundle.tar" "$tmp/podman-package-bundle.tar" "signed Podman package bundle"',
            f'check "{package_bundle_sha}" "$tmp/podman-package-bundle.tar"',
        ]
        package_preflight_args = " \\\n+  ".join(
            (
                '--release-index "$tmp/release-index.json"',
                '--bundle-root "$tmp"',
                '--trust-public-key "$tmp/release.pub"',
                f'--trust-key-id "{trust_id}"',
                f'--trust-key-fingerprint "{trust_fingerprint}"',
                '--updater-wheel "$tmp/updater"',
                '--execution-host-provisioner "$tmp/provisioner"',
                '--compose "$RELEASE_ROOT/compose.yaml"',
                '--source-archive "$RELEASE_ROOT/stateport-source.tar"',
                '--release-notes "$RELEASE_ROOT/release-notes.md"',
                '--known-limitations "$RELEASE_ROOT/known-limitations.md"',
                '--channel alpha',
                '--cosign "$tmp/cosign"',
                '--installer-path "$tmp/installer"',
                '--podman-package-bundle "$tmp/podman-package-bundle.tar"',
                '--podman-package-output "$tmp/podman-packages"',
            )
        )
        package_preflight_args = package_preflight_args.replace("\n+", "\n")
        package_install = [
            # Install every host-side package the signed repository-free
            # bundle depends on before the immutable unprivileged admission.
            # The bundle debs pin exact host library/runtime versions (python3,
            # dbus, glib, gpgme, devmapper, fuse, systemd/pam, nftables), so a
            # stock or lightly-seeded WSL host must already provide them for
            # the admission's offline apt closure simulation to resolve.
            # python3-venv must be genuinely installed (not merely referenced
            # by apt metadata): a negative not-installed record makes
            # dpkg-query --show report empty fields and the preflight refuse.
            'sudo -v',
            'sudo apt-get update -o DPkg::Lock::Timeout=300 || { printf "StatePort apt update retry after lock contention\\n" >&2; sleep 10; sudo apt-get update -o DPkg::Lock::Timeout=300; }',
            'sudo apt-get install -y --no-install-recommends -o DPkg::Lock::Timeout=300 ca-certificates fuse3 nftables libglib2.0-0t64 libgpgme11t64 libdevmapper1.02.1 libfuse3-3 libseccomp2 libsqlite3-0 libaudit1 libselinux1 dbus-broker dbus-session-bus-common libpam-systemd systemd python3 python3-venv',
            'python3 "$tmp/installer" --verify-podman-package-bundle \\\n+  ' + package_preflight_args + ' > "$tmp/podman-package-preflight.json"',
            'package_plan_digest=$(python3 - "$tmp/podman-package-preflight.json" <<\'PY\'\nimport json, re, sys\nvalue = json.load(open(sys.argv[1], encoding="utf-8"))\ndigest = value.get("packagePlanDigest", "")\nif re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:\n    raise SystemExit("invalid authenticated package plan")\nprint("Authenticated repository-free package plan:", digest, file=sys.stderr)\nfor name, action in sorted(value["transaction"].items()):\n    package = value["packages"][name]\n    current = action["currentVersion"] or "absent"\n    print(f"  {action[\'action\']}: {name} {current} -> {action[\'targetVersion\']} ({package[\'sha256\']}, {package[\'size\']} bytes)", file=sys.stderr)\nprint(digest, end="")\nPY\n)',
            'printf "Type install-packages to authorize this exact authenticated package plan: " >/dev/tty',
            'IFS= read -r package_answer </dev/tty || package_answer=',
            '[ "$package_answer" = install-packages ] || fail "Authenticated package plan not confirmed."',
            'sudo -v',
            'root_stage=$(sudo -n mktemp -d /var/tmp/stateport-podman-packages.XXXXXX) || fail "Cannot create sealed root package staging."',
            'trap \'status=$?; [ -z "${root_stage-}" ] || sudo -n rm -rf -- "$root_stage" >/dev/null 2>&1 || true; rm -rf "$tmp"; exit "$status"\' EXIT',
            'sudo -n install -o root -g root -m 0500 "$tmp/installer" "$root_stage/installer"',
            'sudo -n install -o root -g root -m 0500 "$tmp/cosign" "$root_stage/cosign"',
            'sudo -n install -o root -g root -m 0400 "$tmp/release-index.json" "$root_stage/release-index.json"',
            'sudo -n install -o root -g root -m 0400 "$tmp/release-index.sigstore.json" "$root_stage/release-index.sigstore.json"',
            'sudo -n install -o root -g root -m 0400 "$tmp/release.pub" "$root_stage/release.pub"',
            'sudo -n install -o root -g root -m 0400 "$tmp/podman-package-bundle.tar" "$root_stage/podman-package-bundle.tar"',
            'sudo -n sh -c \'printf "%s  %s\\n" "$1" "$2" | sha256sum -c --status\' sh "' + installer_sha + '" "$root_stage/installer" || fail "Sealed installer copy changed."',
            'sudo -n sh -c \'printf "%s  %s\\n" "$1" "$2" | sha256sum -c --status\' sh "' + COSIGN_SHA256 + '" "$root_stage/cosign" || fail "Sealed Cosign copy changed."',
            'sudo -n sh -c \'printf "%s  %s\\n" "$1" "$2" | sha256sum -c --status\' sh "' + index_sha + '" "$root_stage/release-index.json" || fail "Sealed release index changed."',
            'sudo -n sh -c \'printf "%s  %s\\n" "$1" "$2" | sha256sum -c --status\' sh "' + index_bundle_sha + '" "$root_stage/release-index.sigstore.json" || fail "Sealed release signature changed."',
            'sudo -n sh -c \'printf "%s  %s\\n" "$1" "$2" | sha256sum -c --status\' sh "' + key_sha + '" "$root_stage/release.pub" || fail "Sealed trust key changed."',
            'sudo -n sh -c \'printf "%s  %s\\n" "$1" "$2" | sha256sum -c --status\' sh "' + str(package_bundle_sha) + '" "$root_stage/podman-package-bundle.tar" || fail "Sealed package bundle changed."',
            'sudo -n "$root_stage/installer" --verify-sealed-podman-package-bundle \\\n+  --release-index "$root_stage/release-index.json" --bundle-root "$root_stage" \\\n+  --trust-public-key "$root_stage/release.pub" --trust-key-id "' + trust_id + '" \\\n+  --trust-key-fingerprint "' + trust_fingerprint + '" --cosign "$root_stage/cosign" \\\n+  --installer-path "$root_stage/installer" \\\n+  --podman-package-bundle "$root_stage/podman-package-bundle.tar" \\\n+  --podman-package-output "$root_stage/extracted" > "$tmp/root-package-preflight.json"',
            'python3 - "$tmp/podman-package-preflight.json" "$tmp/root-package-preflight.json" <<\'PY\'\nimport json, sys\nleft, right = (json.load(open(path, encoding="utf-8")) for path in sys.argv[1:])\nleft.pop("releaseAdmission", None)\nif left != right:\n    raise SystemExit("root package re-verification differs from unprivileged admission")\nPY',
            'root_package_dir="$root_stage/extracted"',
            # Install the sealed bundle debs with dpkg directly.  apt on noble
            # (2.8.3) has an Internal Error ("Pathname to install is not
            # absolute") for every local .deb install, while the preflight has
            # already authenticated the exact package set and digests and the
            # root re-verification matched the unprivileged admission.
            'sudo -n sh -c \'cd "$1/podman-package-bundle/packages" && dpkg -i -- *.deb\' sh "$root_package_dir"',
            'sudo -n rm -rf -- "$root_stage"; root_stage=',
            'python3 "$tmp/installer" --verify-installed-podman-packages --podman-package-preflight "$tmp/podman-package-preflight.json" > "$tmp/podman-package-installation.json"',
        ]
        package_install = [command.replace("\n+", "\n") for command in package_install]
        installer_args += (
            ' \\\n+  --podman-package-preflight "$tmp/podman-package-preflight.json"'
            ' \\\n+  --confirmed-package-plan-digest "$package_plan_digest"'
        ).replace("\n+", "\n")
        pre_download_runtime_setup = []
        post_download_runtime_setup = package_install + runtime_post_checks
    initial_confirmation = (
        [
            'printf "StatePort %s will install the WSL2 runtime and signed alpha. Type install: " "$STATEPORT_VERSION" >/dev/tty',
            'IFS= read -r answer </dev/tty || answer=',
            '[ "$answer" = install ] || fail "Installation not confirmed."',
        ]
        if podman_package_bundle is None
        else []
    )
    exact_install_confirmation: list[str] = []
    final_installer_confirmation = ""
    if podman_package_bundle is not None:
        exact_install_confirmation = [
            'install_plan_digest=$(python3 - "$STATE_ROOT/install-plan.json" <<\'PY\'\nimport json, re, sys\nvalue = json.load(open(sys.argv[1], encoding="utf-8"))\ndigest = value.get("planDigest", "")\nif re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:\n    raise SystemExit("prepared install plan has no exact digest")\nprint("Exact StatePort install plan:", digest, file=sys.stderr)\nprint("  release:", value["release"]["version"], value["release"]["signedPayloadDigest"], file=sys.stderr)\nprint("  package plan:", value["podmanPackageInstallation"]["packagePlanDigest"], file=sys.stderr)\nfor image in value["images"]:\n    print("  image:", image["imageId"], image["digest"], file=sys.stderr)\nprint(digest, end="")\nPY\n)',
            'printf "Type install-exact to authorize this exact plan: " >/dev/tty',
            'IFS= read -r install_answer </dev/tty || install_answer=',
            '[ "$install_answer" = install-exact ] || fail "Exact install plan not confirmed."',
        ]
        final_installer_confirmation = ' \\\n+  --yes --confirmed-plan-digest "$install_plan_digest"'
        final_installer_confirmation = final_installer_confirmation.replace("\n+", "\n")

    lines = [
        "#!/bin/sh",
        f"# StatePort v{version} Windows 11 + WSL2 + Ubuntu 24.04 bootstrap.",
        "set -eu",
        f'STATEPORT_VERSION="{version}"',
        f'RELEASE_ROOT="{release_root_url.rstrip("/")}"',
        f'PROBE_ROOT="{probe_root_url}"',
        f'TARGET="{WSL2_TARGET_ID}"',
        'STATE_ROOT="${STATEPORT_STATE_ROOT:-$HOME/.local/state/stateport-install}"',
        'RECEIPT="/var/lib/stateport-provisioning/receipts/execution-host-provisioning-receipt.json"',
        f'COSIGN_URL="{COSIGN_URL}"',
        'fail() { printf "StatePort install: %s\\n" "$*" >&2; exit 1; }',
        'mode=install',
        'case "${1-}" in --transport-probe) mode=probe; shift ;; --materialization-preflight) mode=materialization-preflight; shift ;; "") ;; *) fail "Usage: $0 [--transport-probe|--materialization-preflight]" ;; esac',
        '[ "$#" -eq 0 ] || fail "Usage: $0 [--transport-probe|--materialization-preflight]"',
        '[ "$(id -u)" -ne 0 ] || fail "Run this as your normal WSL user, not root."',
        'release=$(uname -r 2>/dev/null || true)',
        'case "$(printf "%s" "$release" | tr "[:upper:]" "[:lower:]")" in *microsoft*wsl2*) ;; *) fail "WSL2 is required; WSL1 and native Linux are not this release target." ;; esac',
        '[ "$(uname -m 2>/dev/null || true)" = "x86_64" ] || fail "WSL2 AMD64 is required."',
        '. /etc/os-release 2>/dev/null || fail "Cannot read /etc/os-release."',
        '[ "${ID:-}" = ubuntu ] && [ "${VERSION_ID:-}" = 24.04 ] || fail "Ubuntu 24.04 for WSL is required."',
        '[ "$(ps -p 1 -o comm= 2>/dev/null | tr -d " ")" = systemd ] || fail "Enable systemd in WSL, run wsl --shutdown in PowerShell, reopen Ubuntu, then retry."',
        'command -v powershell.exe >/dev/null 2>&1 || fail "Windows interoperability is required."',
        'win_build=$(powershell.exe -NoProfile -NonInteractive -Command "[int](Get-CimInstance Win32_OperatingSystem).BuildNumber" 2>/dev/null | tr -d "\\r\\n ")',
        'case "$win_build" in *[!0-9]*|"") fail "Cannot verify the Windows build." ;; esac',
        '[ "$win_build" -ge 22000 ] || fail "Windows 11 build 22000 or newer is required."',
        'get() {',
        '  url=$1; destination=$2; label=$3; partial="$destination.part"; attempt=1',
        '  while [ "$attempt" -le 4 ]; do',
        '    rm -f "$partial"',
        '    if curl -fsSL --proto "=https" --tlsv1.2 --connect-timeout 20 --max-time 600 -o "$partial" "$url"; then mv "$partial" "$destination"; return 0; fi',
        '    printf "StatePort download retry: %s (attempt %s/4)\\n" "$label" "$attempt" >&2',
        '    attempt=$((attempt + 1)); [ "$attempt" -gt 4 ] || sleep 1',
        '  done',
        '  rm -f "$partial"',
        '  fail "Download failed after 4 attempts: $label ($url)"',
        '}',
        'check() { printf "%s  %s\\n" "$1" "$2" | sha256sum -c --status || fail "Checksum failed: $2"; }',
        'ensure_root_helper_parent() {',
        '  case "$1" in /) prefix= ;; /*) prefix=${1%/} ;; *) fail "Root-helper prefix must be absolute." ;; esac',
        '  owner=$2; group=$3; action=$4',
        '  for path in "$prefix/usr" "$prefix/usr/local"; do',
        '    [ -d "$path" ] && [ ! -L "$path" ] || fail "Root-helper parent is unavailable or symlinked: $path"',
        '    metadata=$(stat -c "%u:%g:%a" -- "$path") || fail "Cannot inspect root-helper parent: $path"',
        '    case "$metadata" in "$owner:$group:755"|"$owner:$group:555") ;; *) fail "Root-helper parent has unsafe ownership or mode: $path ($metadata)" ;; esac',
        '  done',
        '  parent="$prefix/usr/local/libexec"',
        '  [ ! -L "$parent" ] || fail "Root-helper directory is symlinked: $parent"',
        '  if [ ! -e "$parent" ]; then',
        '    case "$action" in sudo) sudo -n install -d -o "$owner" -g "$group" -m 0755 -- "$parent" ;; local) install -d -m 0755 -- "$parent" ;; check) return 0 ;; *) fail "Unknown root-helper parent action." ;; esac',
        '  fi',
        '  [ -d "$parent" ] && [ ! -L "$parent" ] || fail "Root-helper directory is unavailable or symlinked: $parent"',
        '  metadata=$(stat -c "%u:%g:%a" -- "$parent") || fail "Cannot inspect root-helper directory: $parent"',
        '  [ "$metadata" = "$owner:$group:755" ] || fail "Root-helper directory has unsafe ownership or mode: $parent ($metadata)"',
        '}',
        'if [ "$mode" = probe ]; then',
        '  command -v curl >/dev/null 2>&1 || fail "curl is required for the transport probe."',
        '  command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required for the transport probe."',
        '  umask 077',
        f'  tmp=$(mktemp -d "${{TMPDIR:-/tmp}}/stateport-{slug}-probe.XXXXXX") || fail "Cannot create a private probe directory."',
        '  trap \'rm -rf "$tmp"\' EXIT',
        '  trap \'exit 129\' HUP',
        '  trap \'exit 130\' INT',
        '  trap \'exit 143\' TERM',
        *manifest_probe_downloads,
        f'  printf "StatePort {label} transport probe passed: bootstrap syntax and 7 exact image manifests verified; installer was not executed.\\n"',
        '  exit 0',
        'fi',
        'if [ "$mode" = materialization-preflight ]; then',
        '  command -v curl >/dev/null 2>&1 || fail "curl is required for the materialization preflight."',
        '  command -v install >/dev/null 2>&1 || fail "install is required for the materialization preflight."',
        '  command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required for the materialization preflight."',
        '  command -v stat >/dev/null 2>&1 || fail "stat is required for the materialization preflight."',
        '  ensure_root_helper_parent / 0 0 check',
        '  umask 077',
        f'  tmp=$(mktemp -d "${{TMPDIR:-/tmp}}/stateport-{slug}-materialization.XXXXXX") || fail "Cannot create a private preflight directory."',
        '  trap \'rm -rf "$tmp"\' EXIT',
        '  trap \'exit 129\' HUP',
        '  trap \'exit 130\' INT',
        '  trap \'exit 143\' TERM',
        '  mkdir -m 755 "$tmp/root" "$tmp/root/usr" "$tmp/root/usr/local"',
        '  ensure_root_helper_parent "$tmp/root" "$(id -u)" "$(id -g)" local',
        '  get "$RELEASE_ROOT/stateport-execution-host-provision" "$tmp/provisioner" "execution-host provisioner"',
        f'  check "{provisioner_sha}" "$tmp/provisioner"',
        '  install -m 0555 -- "$tmp/provisioner" "$tmp/root/usr/local/libexec/stateport-execution-host-provision"',
        f'  check "{provisioner_sha}" "$tmp/root/usr/local/libexec/stateport-execution-host-provision"',
        f'  printf "StatePort {label} materialization preflight passed: target, pinned helper transport, and absent-parent creation order verified; packages, root files, images, and installer were not changed or executed.\\n"',
        '  exit 0',
        'fi',
        'command -v sudo >/dev/null 2>&1 || fail "sudo is required."',
        *package_prerequisites,
        *initial_confirmation,
        *pre_download_runtime_setup,
        'umask 077',
        'tmp=$(mktemp -d "${TMPDIR:-/tmp}/stateport-wsl2-install.XXXXXX") || fail "Cannot create a private temporary directory."',
        "trap 'rm -rf \"$tmp\"' EXIT",
        "trap 'exit 129' HUP",
        "trap 'exit 130' INT",
        "trap 'exit 143' TERM",
        'mkdir -m 700 "$tmp/image-bundles" "$tmp/image-manifests" "$tmp/image-archives" "$tmp/image-carriers"',
        'manifest_carrier() {',
        '  image_id=$1',
        '  reference=$2',
        '  digest=$3',
        '  digest_hex=${digest#sha256:}',
        '  manifest="$tmp/image-manifests/$image_id"',
        '  carrier="$tmp/image-carriers/$image_id"',
        '  skopeo inspect --raw "docker://$reference" > "$manifest" || fail "Manifest download failed: $image_id"',
        '  check "$digest_hex" "$manifest"',
        '  mkdir -m 700 "$carrier"',
        '  mkdir -p -m 700 "$carrier/blobs/sha256"',
        '  cp "$manifest" "$carrier/blobs/sha256/$digest_hex"',
        '  printf \'{"schemaVersion":2,"manifests":[{"digest":"%s"}]}\\n\' "$digest" > "$carrier/index.json"',
        '  tar -cf "$tmp/image-archives/$image_id.oci.tar" --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -C "$carrier" index.json "blobs/sha256/$digest_hex"',
        '}',
        'get "$RELEASE_ROOT/stateport-installer" "$tmp/installer" "signed installer"',
        f'check "{installer_sha}" "$tmp/installer"',
        'get "$RELEASE_ROOT/stateport-execution-host-provision" "$tmp/provisioner" "execution-host provisioner"',
        f'check "{provisioner_sha}" "$tmp/provisioner"',
        'get "$RELEASE_ROOT/stateport-updater" "$tmp/updater" "signed updater"',
        f'check "{updater_sha}" "$tmp/updater"',
        'get "$RELEASE_ROOT/release-index.json" "$tmp/release-index.json" "signed release index"',
        f'check "{index_sha}" "$tmp/release-index.json"',
        'get "$RELEASE_ROOT/release-index.sigstore.json" "$tmp/release-index.sigstore.json" "release index signature"',
        f'check "{index_bundle_sha}" "$tmp/release-index.sigstore.json"',
        'get "$RELEASE_ROOT/stateport-alpha-2026-08-cosign.pub" "$tmp/release.pub" "release trust key"',
        f'check "{key_sha}" "$tmp/release.pub"',
        'get "$COSIGN_URL" "$tmp/cosign" "Cosign executable"',
        f'check "{COSIGN_SHA256}" "$tmp/cosign"',
        'chmod 700 "$tmp/installer" "$tmp/cosign"',
        *predecessor_downloads,
        *image_downloads,
        *package_downloads,
        *package_manifest_commands,
        *digest_slot_commands,
        *post_download_runtime_setup,
        *manifest_carrier_commands,
        # The frozen Alpha.12 installer's argparse requires --confirmed-plan-digest
        # in install mode even for --prepare-execution-host, whose code path
        # returns before the digest is ever validated.  The prepare call
        # therefore carries the authenticated package-plan digest as a
        # placeholder so it satisfies the frozen installer's parser; the final
        # install call below still supplies the real exact-plan digest that the
        # prepare step produced, so the confirmation gate is never weakened.
        *(
            (
                'python3 "$tmp/installer" \\\n  ' + installer_args + ' \\\n  --confirmed-plan-digest "$package_plan_digest" \\\n  --prepare-execution-host',
            )
            if podman_package_bundle is not None
            else (
                'python3 "$tmp/installer" \\\n  ' + installer_args + ' \\\n  --prepare-execution-host',
            )
        ),
        'sudo -v',
        *exact_install_confirmation,
        'ensure_root_helper_parent / 0 0 sudo',
        'sudo -n install -o root -g root -m 0555 "$tmp/provisioner" /usr/local/libexec/stateport-execution-host-provision',
        'sudo -n /usr/local/libexec/stateport-execution-host-provision materialize \\\n  --execution-host-provisioner /usr/local/libexec/stateport-execution-host-provision \\\n  --execution-host-provisioner-digest "sha256:' + provisioner_sha + '" \\\n  --execution-host-provisioner-bytes "' + str(provisioner_bytes) + '" \\\n  --updater-wheel "$tmp/updater" --updater-wheel-digest "sha256:' + updater_sha + '" \\\n  --release-index "$tmp/release-index.json" --bundle-root "$tmp" \\\n  --cosign "$tmp/cosign" --cosign-digest "sha256:' + COSIGN_SHA256 + '" \\\n  --trust-public-key "$tmp/release.pub" --trust-public-key-digest "sha256:' + key_sha + '" \\\n  --trust-key-id "' + trust_id + '" --trust-key-fingerprint "' + trust_fingerprint + '"',
        'sudo -n /usr/local/libexec/stateport-execution-host-provision provision \\\n  --release-index "$tmp/release-index.json" --plan "$STATE_ROOT/execution-host-provisioning-plan.json" \\\n  --cosign /usr/local/lib/stateport/tools/cosign \\\n  --trust-public-key /etc/stateport/alpha-2026-08-cosign.pub \\\n  --trust-key-id "' + trust_id + '" --trust-key-fingerprint "' + trust_fingerprint + '" \\\n  --channel alpha --bundle-root "$STATE_ROOT/updater/bundles" --receipt-out "$RECEIPT"',
        # The privileged provisioner confined the invoking user into
        # stateport-execution-control; a running user manager predating that
        # usermod still holds stale groups, so restart it once to make the
        # keep-groups container start with the fresh membership.
        'sudo -n systemctl restart "user@$(id -u).service"',
        'python3 "$tmp/installer" \\\n  ' + installer_args + final_installer_confirmation,
        'printf "StatePort %s installed successfully for %s.\\n" "$STATEPORT_VERSION" "$TARGET"',
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--trust-public-key", type=Path, required=True)
    parser.add_argument("--release-root-url", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    content = render(
        candidate=args.candidate,
        trust_public_key=args.trust_public_key,
        release_root_url=args.release_root_url,
    )
    if args.output.exists() or args.output.is_symlink():
        raise ValueError("bootstrap output already exists")
    args.output.write_bytes(content)
    args.output.chmod(0o755)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
