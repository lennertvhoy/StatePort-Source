"""Production Cosign v3 verifier for the pinned-public-key private trust root.

This module is the production :class:`~stateport_release.SignatureVerifier`
seam.  It shells out to the exact pinned Cosign executable and binds every
verification to an exact DER SubjectPublicKeyInfo fingerprint plus key ID.
It never treats a digest comparison as a signature, never uploads to a
transparency log, and refuses any signature that claims public keyless or
transparency-log authority: those belong to a future public-release adapter,
not to the private candidate toolchain.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
from typing import Any, Mapping
from urllib.parse import urlsplit

from .contract import PinnedPublicKeyIdentity, SignatureVerificationProof


BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
MAX_PUBLIC_KEY_BYTES = 64 * 1024
MAX_BUNDLE_BYTES = 4 * 1024 * 1024
MAX_IMAGE_MANIFEST_BYTES = 2 * 1024 * 1024
_BUNDLE_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,118}\.sigstore\.json$")
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_FINGERPRINT = re.compile(r"^sha256:[0-9a-f]{64}$")


class CosignVerificationError(RuntimeError):
    """A Cosign invocation or trust-root binding failed closed."""


def _regular_file(path: Path, *, description: str, maximum_bytes: int) -> Path:
    if path.is_symlink() or not path.is_file():
        raise CosignVerificationError(f"{description} is not a regular file: {path}")
    observed = path.stat()
    if not stat.S_ISREG(observed.st_mode) or observed.st_size > maximum_bytes:
        raise CosignVerificationError(f"{description} is unsafe: {path}")
    return path


def signature_bundle_name(signature: Mapping[str, Any]) -> str:
    """Return the retained-bundle basename named by a signature descriptor."""

    bundle = signature.get("bundle")
    if not isinstance(bundle, Mapping):
        raise CosignVerificationError("signature descriptor has no bundle artifact")
    uri = str(bundle.get("uri", ""))
    name = PurePosixPath(urlsplit(uri).path).name
    if _BUNDLE_NAME.fullmatch(name) is None:
        raise CosignVerificationError(f"bundle URI does not name a retained bundle: {uri}")
    return name


def bundle_slot(bundle_root: Path, signature: Mapping[str, Any]) -> Path:
    """Content-addressed durable slot for a signature bundle.

    Every release index names its bundle ``release-index.sigstore.json``, so a
    flat directory can only ever retain one release's bundle.  The durable
    layout keys each bundle by its recorded digest instead: genesis and
    successor bundles coexist, retention is create-only by construction, and
    a swapped or renamed file can never resolve.  Location is not authority —
    the bytes are still required to hash to the recorded digest on every use.
    """

    digest = signature.get("bundle", {})
    digest = digest.get("digest") if isinstance(digest, Mapping) else None
    if not isinstance(digest, str) or _FINGERPRINT.fullmatch(digest) is None:
        raise CosignVerificationError("signature bundle digest is malformed")
    return bundle_root / digest.removeprefix("sha256:") / signature_bundle_name(signature)


def _check_bundle_bytes(content: bytes, signature: Mapping[str, Any]) -> None:
    bundle = signature.get("bundle")
    if not isinstance(bundle, Mapping):
        raise CosignVerificationError("signature descriptor has no bundle artifact")
    if "sha256:" + hashlib.sha256(content).hexdigest() != bundle.get("digest"):
        raise CosignVerificationError("retained bundle bytes do not match the recorded digest")
    if len(content) != bundle.get("size"):
        raise CosignVerificationError("retained bundle size does not match the record")


def retain_bundle(bundle_root: Path, source: Path, signature: Mapping[str, Any]) -> Path:
    """Create-only, digest-checked retention of a signature bundle into its slot.

    Retention is safe before cryptographic verification: the slot name and the
    byte check both bind the recorded digest, so retained bytes are inert until
    a signature over them verifies against the pinned trust root, and a forged
    bundle can never occupy another bundle's slot.  An existing slot must still
    hash to its recorded digest; anything else is a typed refusal, never a
    silent overwrite.
    """

    candidate = _regular_file(
        source, description="signature bundle source", maximum_bytes=MAX_BUNDLE_BYTES
    )
    content = candidate.read_bytes()
    _check_bundle_bytes(content, signature)
    slot = bundle_slot(bundle_root, signature)
    if slot.exists() or slot.is_symlink():
        retained = _regular_file(
            slot, description="retained signature bundle", maximum_bytes=MAX_BUNDLE_BYTES
        ).read_bytes()
        _check_bundle_bytes(retained, signature)
        return slot
    slot.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(slot.parent, 0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{slot.name}.", dir=slot.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, slot)
        os.chmod(slot, 0o600)
        directory_descriptor = os.open(slot.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return slot


def _run(arguments: list[str], *, timeout: int = 300, env: Mapping[str, str] | None = None) -> str:
    merged_env = None if env is None else {**os.environ, **env}
    completed = subprocess.run(
        arguments,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        shell=False,
        env=merged_env,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip().splitlines()
        suffix = f": {detail[-1][:200]}" if detail else ""
        raise CosignVerificationError(
            f"tool failed ({completed.returncode}): {arguments[1]}{suffix}"
        )
    return completed.stdout


def public_key_der_spki_fingerprint(public_key: Path, *, openssl: str | None = None) -> str:
    """Fingerprint a PEM public key as SHA-256 over its DER SubjectPublicKeyInfo.

    This deliberately differs from hashing the PEM file bytes: PEM armor,
    line endings, and comments are not key identity, while the DER SPKI is
    exactly what a verifier pins.
    """

    candidate = _regular_file(
        public_key, description="public key", maximum_bytes=MAX_PUBLIC_KEY_BYTES
    )
    executable = openssl or shutil.which("openssl")
    if executable is None:
        raise CosignVerificationError("openssl is required for DER SPKI fingerprinting")
    completed = subprocess.run(
        [executable, "pkey", "-pubin", "-in", str(candidate), "-outform", "DER"],
        check=False,
        capture_output=True,
        timeout=60,
        shell=False,
    )
    if completed.returncode != 0 or not completed.stdout:
        raise CosignVerificationError("public key is not a parseable PEM SubjectPublicKeyInfo")
    return "sha256:" + hashlib.sha256(completed.stdout).hexdigest()


def private_key_der_spki_fingerprint(
    private_key: Path, *, cosign: str | None = None, openssl: str | None = None
) -> str:
    """Fingerprint the public key derived from a Cosign-encrypted private key."""

    candidate = _regular_file(
        private_key, description="private key", maximum_bytes=MAX_PUBLIC_KEY_BYTES
    )
    if not os.environ.get("COSIGN_PASSWORD"):
        raise CosignVerificationError("COSIGN_PASSWORD is required for private-key derivation")
    cosign_executable = cosign or shutil.which("cosign")
    if cosign_executable is None:
        raise CosignVerificationError("cosign is required for private-key derivation")
    exported = subprocess.run(
        [cosign_executable, "public-key", "--key", str(candidate)],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
        shell=False,
    )
    if exported.returncode != 0 or not exported.stdout:
        raise CosignVerificationError("private key is not a decryptable Cosign key")
    openssl_executable = openssl or shutil.which("openssl")
    if openssl_executable is None:
        raise CosignVerificationError("openssl is required for DER SPKI fingerprinting")
    derived = subprocess.run(
        [openssl_executable, "pkey", "-pubin", "-outform", "DER"],
        input=exported.stdout.encode("utf-8"),
        check=False,
        capture_output=True,
        timeout=60,
        shell=False,
    )
    if derived.returncode != 0 or not derived.stdout:
        raise CosignVerificationError("Cosign did not export a parseable public key")
    return "sha256:" + hashlib.sha256(derived.stdout).hexdigest()


def _verify_private_candidate_trust(signature: Mapping[str, Any], *, context: str) -> None:
    if signature.get("scheme") != "cosign-v3-bundle":
        raise CosignVerificationError(f"{context} is not a Cosign v3 bundle signature")
    if signature.get("trustMode") != "pinned-public-key":
        raise CosignVerificationError(f"{context} is outside the pinned-public-key trust root")
    if signature.get("transparencyLog") != "not-uploaded-private-candidate":
        raise CosignVerificationError(
            f"{context} claims transparency-log authority the private toolchain never uploads"
        )
    if signature.get("publicKeyFingerprintAlgorithm") != "sha256-canonical-der-spki":
        raise CosignVerificationError(f"{context} uses a non-canonical key fingerprint algorithm")


@dataclass(frozen=True)
class CosignVerifier:
    """Verify Cosign v3 bundles against one exact pinned public key.

    ``bundle_root`` is the operator-controlled directory that retains the
    ``.sigstore.json`` bundles referenced by signature descriptors in
    content-addressed digest slots (see :func:`bundle_slot`).  A bundle is
    trusted only after its bytes hash to the digest recorded in the
    signature descriptor, so a renamed or replaced bundle fails closed.
    """

    cosign: Path
    public_key: Path
    identity: PinnedPublicKeyIdentity
    bundle_root: Path
    openssl: str | None = None

    def __post_init__(self) -> None:
        # The pinned Homebrew path is a managed symlink; bind the resolved target.
        resolved_cosign = self.cosign.resolve(strict=True)
        _regular_file(
            resolved_cosign, description="Cosign executable", maximum_bytes=512 * 1024 * 1024
        )
        object.__setattr__(self, "cosign", resolved_cosign)
        if _KEY_ID.fullmatch(self.identity.key_id) is None:
            raise CosignVerificationError("pinned key ID is malformed")
        if _FINGERPRINT.fullmatch(self.identity.public_key_fingerprint) is None:
            raise CosignVerificationError("pinned public-key fingerprint is malformed")
        observed = public_key_der_spki_fingerprint(self.public_key, openssl=self.openssl)
        if observed != self.identity.public_key_fingerprint:
            raise CosignVerificationError(
                "supplied public key does not match the pinned DER SPKI fingerprint"
            )
        if not self.bundle_root.is_dir() or self.bundle_root.is_symlink():
            raise CosignVerificationError("bundle root is not an operator-controlled directory")

    def retain_bundle(self, source: Path, signature: Mapping[str, Any]) -> Path:
        """Retain a verified-source bundle into this verifier's durable root."""

        return retain_bundle(self.bundle_root, source, signature)

    def resolve_local_image_manifest(self, image_id: str, digest: str) -> bytes | None:
        """Resolve a private candidate manifest from retained bytes or archives.

        The digest-keyed manifest slot is the small durable transport used by
        the control-account bootstrap.  Archives remain supported for the
        existing installer path, but a present manifest slot is authoritative:
        malformed or changed bytes refuse instead of falling back to another
        carrier.
        """

        if _FINGERPRINT.fullmatch(digest) is None:
            raise CosignVerificationError("private image manifest digest is malformed")
        manifest_root = self.bundle_root / "image-manifests"
        manifest_path = manifest_root / f"{digest.removeprefix('sha256:')}.json"
        if manifest_root.is_symlink():
            raise CosignVerificationError("private image manifest directory is symlinked")
        if manifest_path.exists() or manifest_path.is_symlink():
            candidate = _regular_file(
                manifest_path,
                description=f"private image manifest {image_id}",
                maximum_bytes=MAX_IMAGE_MANIFEST_BYTES,
            )
            payload = candidate.read_bytes()
            if "sha256:" + hashlib.sha256(payload).hexdigest() != digest:
                raise CosignVerificationError(
                    f"private image manifest is tampered: {image_id}"
                )
            return payload

        candidates = (
            self.bundle_root / "image-archives" / f"{image_id}.oci.tar",
            self.bundle_root / f"{image_id}.oci.tar",
        )
        archive_path = next(
            (path for path in candidates if path.is_file() and not path.is_symlink()), None
        )
        if archive_path is None:
            return None
        with tarfile.open(archive_path, mode="r:*") as archive:
            members = {member.name: member for member in archive.getmembers()}
            index_member = members.get("index.json")
            if index_member is None or not index_member.isfile():
                raise CosignVerificationError(f"private image archive has no OCI index: {image_id}")
            index = json.loads(archive.extractfile(index_member).read())  # type: ignore[union-attr]
            manifests = index.get("manifests") if isinstance(index, Mapping) else None
            if not isinstance(manifests, list) or len(manifests) != 1:
                raise CosignVerificationError(f"private image archive has no single manifest: {image_id}")
            manifest_digest = manifests[0].get("digest") if isinstance(manifests[0], Mapping) else None
            if manifest_digest != digest:
                raise CosignVerificationError(f"private image archive is not candidate-bound: {image_id}")
            member = members.get("blobs/sha256/" + digest.removeprefix("sha256:"))
            if member is None or not member.isfile():
                raise CosignVerificationError(f"private image archive manifest is missing: {image_id}")
            payload = archive.extractfile(member).read()  # type: ignore[union-attr]
            if "sha256:" + hashlib.sha256(payload).hexdigest() != digest:
                raise CosignVerificationError(f"private image archive manifest is tampered: {image_id}")
            return payload

    def _bundle_path(self, signature: Mapping[str, Any]) -> Path:
        candidate = _regular_file(
            bundle_slot(self.bundle_root, signature),
            description="signature bundle",
            maximum_bytes=MAX_BUNDLE_BYTES,
        )
        _check_bundle_bytes(candidate.read_bytes(), signature)
        return candidate

    def _proof(self, signature: Mapping[str, Any]) -> SignatureVerificationProof:
        return SignatureVerificationProof(
            subject_digest=str(signature["subjectDigest"]),
            bundle_digest=str(signature["bundle"]["digest"]),
            trust_mode=str(signature["trustMode"]),
            identity_primary=str(signature["publicKeyFingerprint"]),
            identity_secondary=str(signature["publicKeyId"]),
            verified_at=datetime.now(timezone.utc),
            transparency_log_mode=str(signature["transparencyLog"]),
        )

    def verify_blob(
        self, payload: bytes, signature: Mapping[str, Any]
    ) -> SignatureVerificationProof:
        """Verify a detached blob bundle with the pinned key, never the log."""

        _verify_private_candidate_trust(signature, context="blob signature")
        if (
            signature.get("publicKeyFingerprint") != self.identity.public_key_fingerprint
            or signature.get("publicKeyId") != self.identity.key_id
        ):
            raise CosignVerificationError("blob signature is not bound to the pinned key identity")
        bundle = self._bundle_path(signature)
        observed_subject = "sha256:" + hashlib.sha256(payload).hexdigest()
        if signature.get("subjectDigest") != observed_subject:
            raise CosignVerificationError("blob signature is not bound to the exact payload bytes")
        descriptor, payload_path = tempfile.mkstemp(prefix=".cosign-payload-", dir=self.bundle_root)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            _run(
                [
                    str(self.cosign),
                    "verify-blob",
                    "--insecure-ignore-tlog",
                    "--bundle",
                    str(bundle),
                    "--key",
                    str(self.public_key),
                    payload_path,
                ]
            )
        finally:
            os.unlink(payload_path)
        return self._proof(signature)

    def verify_image(
        self, reference: str, signature: Mapping[str, Any]
    ) -> SignatureVerificationProof:
        """Verify a registry image signature with the pinned key, never the log."""

        _verify_private_candidate_trust(signature, context="image signature")
        if (
            signature.get("publicKeyFingerprint") != self.identity.public_key_fingerprint
            or signature.get("publicKeyId") != self.identity.key_id
        ):
            raise CosignVerificationError("image signature is not bound to the pinned key identity")
        if not reference.endswith(str(signature.get("subjectDigest", ""))):
            raise CosignVerificationError("image reference is not bound to the signed digest")
        bundle = self._bundle_path(signature)
        _run(
            [
                str(self.cosign),
                "verify",
                "--insecure-ignore-tlog",
                "--key",
                str(self.public_key),
                reference,
            ],
            timeout=600,
        )
        return self._proof(signature)
