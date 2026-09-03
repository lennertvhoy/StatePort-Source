#!/usr/bin/env python3
"""Stage a local release Site tree for the clean-guest rehearsal.

The WSL2 rehearsal serves this tree over HTTPS at the real public hostname and
runs the unmodified production bootstrap against it. The bootstrap transport
probe downloads one exact OCI manifest per image from
``download/<slug>-manifests/<imageId>.json`` and pins each download to the
subject digest recorded in the signed release index, so every staged manifest
byte is verified against the candidate's own signature before any guest work.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[2]

_DIGEST_HEX = frozenset("0123456789abcdef")
_MAX_MANIFEST_BYTES = 4 * 1024 * 1024


class SiteStagingError(RuntimeError):
    """The qualification site tree cannot be staged fail-closed."""


def _slug(version: str) -> str:
    if len(version) > 64 or version != version.strip() or "/" in version:
        raise SiteStagingError(f"unsupported qualification version: {version!r}")
    for prefix, slug_prefix in (("0.0.0-j1.", "j1-"), ("0.1.0-alpha.", "alpha")):
        suffix = version.removeprefix(prefix)
        if suffix != version and suffix and suffix.isascii() and suffix.isdecimal():
            return f"{slug_prefix}{suffix}"
    raise SiteStagingError(
        "version must match 0.0.0-j1.<number> or 0.1.0-alpha.<number>: "
        f"{version!r}"
    )


def _digest_hex(value: object, label: str) -> str:
    text = str(value or "").removeprefix("sha256:")
    if len(text) != 64 or any(char not in _DIGEST_HEX for char in text):
        raise SiteStagingError(f"{label} digest is malformed")
    return text


def _manifest_blob_bytes(archive: Path, digest_hex: str) -> bytes:
    if archive.is_symlink() or not archive.is_file():
        raise SiteStagingError(f"retained OCI archive is unavailable: {archive.name}")
    wanted = PurePosixPath("blobs") / "sha256" / digest_hex
    with tarfile.open(archive, mode="r:") as bundle:
        for member in bundle:
            if not member.isfile():
                continue
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts:
                raise SiteStagingError(f"retained archive has an unsafe entry: {member.name!r}")
            if name != wanted:
                continue
            if (member.size or 0) > _MAX_MANIFEST_BYTES:
                raise SiteStagingError(f"manifest blob is oversized for {archive.name}")
            extracted = bundle.extractfile(member)
            if extracted is None:
                raise SiteStagingError(f"manifest blob is unreadable for {archive.name}")
            payload = extracted.read()
            break
        else:
            raise SiteStagingError(f"manifest blob {digest_hex[:12]} absent from {archive.name}")
    observed = hashlib.sha256(payload).hexdigest()
    if observed != digest_hex:
        raise SiteStagingError(f"manifest blob digest drifted for {archive.name}")
    return payload


def _write_new(path: Path, payload: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise SiteStagingError(f"staged path already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def _copy_new(source: Path, target: Path) -> str:
    if source.is_symlink() or not source.is_file():
        raise SiteStagingError(f"artifact source is unavailable: {source.name}")
    if target.exists() or target.is_symlink():
        raise SiteStagingError(f"staged path already exists: {target}")
    payload = source.read_bytes()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(payload)
    return "sha256:" + hashlib.sha256(payload).hexdigest()


_BUNDLE_ARTIFACTS: tuple[tuple[str, str], ...] = (
    ("stateport-execution-host-provision", "provisioning/stateport-execution-host-provision"),
    ("stateport-installer", "installer/install.sh"),
    ("stateport-updater", "updater/stateport-updater.whl"),
    ("stateport-source.tar", "source/stateport-source.tar"),
    ("release-notes.md", "notes/release-notes.md"),
    ("known-limitations.md", "limitations/known-limitations.md"),
    ("stateport-podman-package-bundle.tar", "packages/podman-package-bundle.tar"),
)


def _bundle_artifacts(version: str) -> tuple[tuple[str, str], ...]:
    alpha = re.fullmatch(r"0\.1\.0-alpha\.(\d+)", version)
    if alpha is not None and int(alpha.group(1)) >= 11:
        return _BUNDLE_ARTIFACTS
    if re.fullmatch(r"0\.0\.0-j1\.\d+", version) is not None:
        return _BUNDLE_ARTIFACTS
    return _BUNDLE_ARTIFACTS[:-1]

_PROVENANCE_VERIFIED: tuple[str, str] = (
    "executionHostProvisioner",
    "updaterWheel",
)


def _verify_provenance_digests(bundle: Path) -> dict[str, str]:
    """Pin the qualification-derived provisioner and updater wheel bytes."""
    import yaml

    provenance_path = bundle / "provenance" / "candidate-provenance.yaml"
    try:
        document = yaml.safe_load(provenance_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise SiteStagingError("candidate provenance is unreadable") from exc
    artifacts = document.get("artifacts") if isinstance(document, dict) else None
    if not isinstance(artifacts, dict):
        raise SiteStagingError("candidate provenance has no artifacts")
    verified: dict[str, str] = {}
    for name, record in artifacts.items():
        if not isinstance(record, dict):
            continue
        for path_key, digest_key in (("path", "sha256"), ("firstPath", "firstSha256")):
            relative = record.get(path_key)
            expected = record.get(digest_key)
            if not isinstance(relative, str) or not isinstance(expected, str):
                continue
            artifact = bundle / relative
            if artifact.is_symlink() or not artifact.is_file():
                raise SiteStagingError(f"provenance artifact is unavailable: {relative}")
            observed = hashlib.sha256(artifact.read_bytes()).hexdigest()
            if observed != expected.removeprefix("sha256:"):
                raise SiteStagingError(f"provenance digest drifted for {relative}")
            verified[f"{name}:{relative}"] = "sha256:" + observed
    required = {"executionHostProvisioner", "updaterWheel"}
    if not required.issubset({key.split(":", 1)[0] for key in verified}):
        raise SiteStagingError("candidate provenance omits required artifact verification")
    return verified


def _stage_image_signatures(candidate: Path, release_dir: Path, document: dict) -> dict[str, str]:
    """Stage per-image cosign bundles exactly as the bootstrap fetches them."""
    staged: dict[str, str] = {}
    images = document["signed"]["images"]
    signatures_dir = release_dir / "signatures"
    if signatures_dir.exists() or signatures_dir.is_symlink():
        raise SiteStagingError("signatures directory is not fresh")
    signatures_dir.mkdir(parents=True)
    for image in images:
        if not isinstance(image, dict):
            continue
        image_id = image.get("imageId")
        signature = image.get("signature")
        if not isinstance(image_id, str) or not isinstance(signature, dict):
            continue
        expected = _digest_hex(
            (signature.get("bundle") or {}).get("digest"), f"{image_id} bundle"
        )
        source = candidate / f"{image_id}.sigstore.json"
        if source.is_symlink() or not source.is_file():
            raise SiteStagingError(f"candidate image signature bundle is unavailable: {image_id}")
        payload = source.read_bytes()
        observed = hashlib.sha256(payload).hexdigest()
        if observed != expected:
            raise SiteStagingError(f"image signature bundle digest drifted for {image_id}")
        target = signatures_dir / f"{image_id}.sigstore.json"
        target.write_bytes(payload)
        staged[image_id] = "sha256:" + observed
    if len(staged) != len(images):
        raise SiteStagingError("not every signed image has a staged signature bundle")
    return staged


def stage_site(
    *,
    candidate: Path,
    archive_root: Path,
    version: str,
    output: Path,
    candidate_bundle: Path | None = None,
    trust_public_key: Path | None = None,
) -> dict[str, object]:
    if candidate.is_symlink() or not candidate.is_dir():
        raise SiteStagingError("candidate directory is unavailable")
    if archive_root.is_symlink() or not archive_root.is_dir():
        raise SiteStagingError("retained archive root is unavailable")
    if candidate_bundle is not None and (candidate_bundle.is_symlink() or not candidate_bundle.is_dir()):
        raise SiteStagingError("candidate bundle directory is unavailable")
    if output.is_symlink() or output.exists():
        raise SiteStagingError(f"site output must be a new directory: {output}")
    if candidate_bundle is None:
        sibling = candidate.parent / f".{candidate.name}.source"
        candidate_bundle = sibling if sibling.is_dir() else None
    provenance_verified: dict[str, str] = {}
    if candidate_bundle is not None:
        provenance_verified = _verify_provenance_digests(candidate_bundle)
    else:
        raise SiteStagingError("retained candidate bundle is required for artifact staging")
    slug = _slug(version)
    index_path = candidate / "release-index.json"
    try:
        document = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SiteStagingError("candidate release index is unreadable") from exc
    signed = document.get("signed") if isinstance(document, dict) else None
    release = signed.get("release") if isinstance(signed, dict) else None
    if not isinstance(release, dict) or release.get("version") != version:
        raise SiteStagingError("requested staging version differs from the signed release version")
    images = signed.get("images")
    if not isinstance(images, list) or not images:
        raise SiteStagingError("candidate release index has no signed images")

    manifests_dir = output / "download" / f"{slug}-manifests"
    staged: dict[str, str] = {}
    for image in images:
        if not isinstance(image, dict) or not isinstance(image.get("imageId"), str):
            raise SiteStagingError("candidate image inventory is malformed")
        image_id = str(image["imageId"])
        signature = image.get("signature")
        if not isinstance(signature, dict):
            raise SiteStagingError(f"image signature is malformed for {image_id}")
        if signature.get("subjectKind") != "oci-manifest-blob":
            continue
        digest_hex = _digest_hex(signature.get("subjectDigest"), f"{image_id} subject")
        payload = _manifest_blob_bytes(archive_root / f"{image_id}.oci.tar", digest_hex)
        _write_new(manifests_dir / f"{image_id}.json", payload)
        staged[image_id] = "sha256:" + digest_hex
    if not staged:
        raise SiteStagingError("candidate declares no oci-manifest-blob signatures to stage")

    release_dir = output / "download" / version
    shutil.copytree(candidate, release_dir, symlinks=False)
    bootstrap_source = release_dir / "bootstrap.sh"
    if bootstrap_source.is_symlink() or not bootstrap_source.is_file():
        raise SiteStagingError("candidate bootstrap is unavailable after copy")
    install_sh = output / "download" / "install.sh"
    shutil.copyfile(bootstrap_source, install_sh)

    compose_source = release_dir / "compose.release.yaml"
    if compose_source.is_symlink() or not compose_source.is_file():
        raise SiteStagingError("candidate compose file is unavailable")
    staged_artifacts: dict[str, str] = {"compose.yaml": _copy_new(compose_source, output / "download" / version / "compose.yaml")}
    signatures_dir = release_dir / "signatures"
    staged_signatures = _stage_image_signatures(candidate, release_dir, document)
    pub_target = release_dir / "stateport-alpha-2026-08-cosign.pub"
    if trust_public_key is None:
        raise SiteStagingError("the qualification trust public key is required")
    if trust_public_key.is_symlink() or not trust_public_key.is_file():
        raise SiteStagingError("qualification trust public key is unavailable")
    if pub_target.exists():
        raise SiteStagingError("trust public key already staged under a reserved name")
    for flat_name, relative in _bundle_artifacts(version):
        source = candidate_bundle / relative
        if source.is_symlink() or not source.is_file():
            raise SiteStagingError(f"bundle artifact is unavailable: {relative}")
        staged_artifacts[flat_name] = _copy_new(source, release_dir / flat_name)
    staged_artifacts["stateport-alpha-2026-08-cosign.pub"] = _copy_new(
        trust_public_key,
        pub_target,
    )
    return {
        "output": str(output),
        "slug": slug,
        "version": version,
        "stagedManifests": staged,
        "stagedArtifacts": staged_artifacts,
        "stagedSignatures": staged_signatures,
        "provenanceVerified": provenance_verified,
        "installSha256": "sha256:" + hashlib.sha256(install_sh.read_bytes()).hexdigest(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--archive-root", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--candidate-bundle", type=Path)
    parser.add_argument("--trust-public-key", type=Path)
    args = parser.parse_args(argv)
    print(json.dumps(stage_site(**vars(args)), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (SiteStagingError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"site staging refused: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
