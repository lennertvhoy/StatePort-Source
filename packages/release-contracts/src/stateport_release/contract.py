"""Canonical serialization and trust-policy checks for release-index/v1.

The signed payload deliberately permits only integers (never JSON floating
point values), NFC Unicode strings, and unique object keys.  That makes the
``stateport.canonical-json/v1`` representation stable across the supported
Python installer and updater without pretending to implement every optional
number rule in RFC 8785.

Cryptographic verification is supplied through :class:`SignatureVerifier`.
The contract never treats a digest comparison as a signature and never embeds
an implicit trust root. Production callers must pin either a Cosign v3
certificate identity plus OIDC issuer or an exact raw public-key fingerprint
plus key ID through :class:`ReleaseVerificationPolicy`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from math import gcd
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import stat
from types import MappingProxyType
from typing import Any, Mapping, Protocol, Sequence
import unicodedata
from urllib.parse import urlsplit


INDEX_SCHEMA = "stateport.release-index/v1"
SUCCESSOR_FORMAT = "stateport.release-successor/v1"
CANONICAL_FORMAT = "stateport.canonical-json/v1"
MAX_INDEX_BYTES = 4 * 1024 * 1024
_LEGACY_PREDECESSOR_RELEASE_ID = "stateport-alpha-0.1.0-alpha.3"
_LEGACY_PREDECESSOR_VERSION = "0.1.0-alpha.3"
_LEGACY_PREDECESSOR_SIGNED_DIGEST = (
    "sha256:2639e29d6ca0a5bd83d07013edb49f22692efaf53a6049234fe6b70810c89166"
)
_LEGACY_PREDECESSOR_INDEX_DIGEST = (
    "sha256:3353fdb6477fcb5269169177c625205c7737b13c904de0c4f70801d7189f3f38"
)
SCHEMA_DIRECTORY = Path(__file__).resolve().parent / "schemas"
_CONTRACT_SCHEMAS = {
    "stateport.release-index/v1": "release-index.v1.schema.json",
    "stateport.install-receipt/v1": "install-receipt.v1.schema.json",
    "stateport.update-plan/v1": "update-plan.v1.schema.json",
    "stateport.update-receipt/v1": "update-receipt.v1.schema.json",
    "stateport.update-authority-link/v1": "update-authority-link.v1.schema.json",
    "stateport.update-status/v1": "update-status.v1.schema.json",
    "stateport.update-failure-evidence/v1": "update-failure-evidence.v1.schema.json",
    "stateport.release-provenance/v1": "release-provenance.v1.schema.json",
    "stateport.revision-activation-plan/v1": "revision-activation-plan.v1.schema.json",
    "stateport.revision-activation-decision/v1": "revision-activation-decision.v1.schema.json",
    "stateport.revision-activation-pointer/v1": "revision-activation-pointer.v1.schema.json",
    "stateport.revision-owner-bundle/v1": "revision-owner-bundle.v1.schema.json",
    "stateport.revision-port-allocation-receipt/v1": "revision-port-allocation-receipt.v1.schema.json",
    "stateport.revision-port-allocation-proposal/v1": "revision-port-allocation-proposal.v1.schema.json",
    "stateport.revision-port-activation-recheck-receipt/v1": "revision-port-activation-recheck-receipt.v1.schema.json",
    "stateport.revision-authority-proof/v1": "revision-authority-proof.v1.schema.json",
    "stateport.revision-data-promotion-receipt/v1": "revision-data-promotion-receipt.v1.schema.json",
    "stateport.revision-validation-backup-receipt/v1": "revision-validation-backup-receipt.v1.schema.json",
    "stateport.revision-terminal-acceptance-receipt/v1": "revision-terminal-acceptance-receipt.v1.schema.json",
    "stateport.revision-data-promotion-spec/v1": "revision-data-promotion-spec.v1.schema.json",
    "stateport.stable-host-service-plan/v1": "stable-host-service-plan.v1.schema.json",
    "stateport.stable-host-service-transition/v1": "stable-host-service-transition.v1.schema.json",
    "stateport.execution-host-provisioning-receipt/v1": "execution-host-provisioning-receipt.v1.schema.json",
}
_SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")
# Bounded tolerance for verifier clock skew when judging proof freshness.
_PROOF_FUTURE_TOLERANCE = timedelta(minutes=5)
_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_LEGACY_ARTIFACT_IDS = frozenset(
    {
        "installer",
        "updater",
        "compose",
        "quadlet",
        "sourceArchive",
        "releaseNotes",
        "knownLimitations",
    }
)
_ALPHA10_ARTIFACT_IDS = _LEGACY_ARTIFACT_IDS | {"executionHostProvisioner"}
_ARTIFACT_IDS = _ALPHA10_ARTIFACT_IDS | {"podmanPackageBundle"}
CONFINED_GROUP_OCI_RUNTIME_PATH = "/usr/libexec/stateport/crun"
PROVIDER_HOME_CONTRACT = {
    "provider": "codex",
    "hostPath": "/var/lib/stateport-control/provider-auth/codex",
    "mountPath": "/var/lib/stateport-provider/codex",
    "owner": "stateport-control",
    "mode": "0700",
    "environmentVariable": "CODEX_HOME",
    "validation": "ephemeral-empty",
}
CONFINED_GROUP_OCI_RUNTIME_VERSION = "1.28"
CONFINED_GROUP_OCI_RUNTIME_SHA256 = (
    "sha256:2aa6b7024a9c9f153895c0d11ae233d3758f54844011c3a039e3e89048d01d42"
)
_LEGACY_PODMAN_PACKAGE_NAMES = frozenset(
    {
        "aardvark-dns",
        "catatonit",
        "conmon",
        "containers-storage",
        "dbus-user-session",
        "fuse-overlayfs",
        "golang-github-containers-common",
        "golang-github-containers-image",
        "libslirp0",
        "libsubid4",
        "netavark",
        "podman",
        "python3-venv",
        "runc",
        "slirp4netns",
        "skopeo",
        "uidmap",
    }
)
_PODMAN_PACKAGE_NAMES = _LEGACY_PODMAN_PACKAGE_NAMES | {"stateport-crun"}
_UPDATE_STEPS = (
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
)
_ROLLBACK_STEPS = (
    "verify",
    "backup",
    "stage",
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
)


def _release_artifact_ids(version: str, *, legacy: bool = False) -> frozenset[str]:
    if legacy:
        return _LEGACY_ARTIFACT_IDS
    alpha = re.fullmatch(r"0\.1\.0-alpha\.(\d+)", version)
    if alpha is not None:
        return _ARTIFACT_IDS if int(alpha.group(1)) >= 11 else _ALPHA10_ARTIFACT_IDS
    if re.fullmatch(r"0\.0\.0-j1\.\d+", version) is not None:
        return _ARTIFACT_IDS
    return _ALPHA10_ARTIFACT_IDS


_REVISION_STAGE_STEPS = (
    "verify-images-by-digest-and-signature",
    "materialize-outside-live-quadlet-roots",
    "verify-materialization-manifest",
    "pre-pull-with-pull-never-runtime",
)
_REVISION_VALIDATE_STEPS = (
    "create-exact-backup-or-snapshot-copy",
    "start-validation-profile-only",
    "run-health-api-browser-and-state-checks",
    "stop-validation-profile",
    "retain-validation-evidence",
)
_REVISION_PROMOTE_STEPS = (
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
)
_REVISION_ROLLBACK_STEPS = (
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
)
_REVISION_REBOOT_STEPS = (
    "load-accepted-pointer",
    "verify-acceptance-receipt",
    "materialize-only-accepted-live-units",
    "daemon-reload",
    "start-accepted-activation-target",
    "refuse-staged-or-stale-auto-start",
)


class ReleaseContractError(ValueError):
    """A release document is unsafe, inconsistent, or unverifiable."""


class SignatureVerifier(Protocol):
    """External verifier for a detached Cosign v3 bundle.

    Implementations receive the exact canonical signed payload bytes and one
    schema-validated signature descriptor.  They must raise on any failure.
    A no-op verifier is never provided by this package.
    """

    def verify_blob(
        self, payload: bytes, signature: Mapping[str, Any]
    ) -> "SignatureVerificationProof": ...

    def verify_image(
        self, reference: str, signature: Mapping[str, Any]
    ) -> "SignatureVerificationProof": ...


class AuthoritySourceResolver(Protocol):
    """Trusted lookup boundary for the protected canonical authority store."""

    def resolve_revision_authority(
        self,
        *,
        request_id: str,
        reservation_id: str,
        claim_id: str,
        receipt_id: str,
    ) -> Mapping[str, Mapping[str, Any]]: ...


@dataclass(frozen=True, order=True)
class SignerIdentity:
    certificate_identity: str
    oidc_issuer: str


@dataclass(frozen=True, order=True)
class PinnedPublicKeyIdentity:
    public_key_fingerprint: str
    key_id: str


TrustIdentity = SignerIdentity | PinnedPublicKeyIdentity


@dataclass(frozen=True, order=True)
class SignatureVerificationProof:
    subject_digest: str
    bundle_digest: str
    trust_mode: str
    identity_primary: str
    identity_secondary: str
    verified_at: datetime
    transparency_log_mode: str


@dataclass(frozen=True)
class AuthenticatedPredecessor:
    """Authenticated predecessor identity without release eligibility."""

    index: ReleaseIndex
    signer: TrustIdentity
    proof: SignatureVerificationProof
    signature: Mapping[str, Any]


@dataclass(frozen=True)
class ReleaseVerificationPolicy:
    expected_channel: str
    expected_target: str
    updater_version: str
    accepted_signers: frozenset[SignerIdentity]
    expected_trust_mode: str
    now: datetime
    accepted_public_keys: frozenset[PinnedPublicKeyIdentity] = frozenset()
    allow_candidate: bool = False
    allow_bootstrap_target: bool = False
    allow_deprecated: bool = False
    require_transparency_log: bool = False


def _signature_trust_identity(signature: Mapping[str, Any], *, context: str) -> TrustIdentity:
    mode = signature.get("trustMode")
    certificate_fields = ("certificateIdentity", "certificateOidcIssuer")
    public_key_fields = ("publicKeyFingerprint", "publicKeyId")
    has_certificate = any(field in signature for field in certificate_fields)
    has_public_key = any(field in signature for field in public_key_fields)
    if mode == "keyless-certificate":
        if not all(isinstance(signature.get(field), str) for field in certificate_fields):
            raise ReleaseContractError(f"{context} has an incomplete keyless certificate identity")
        if has_public_key:
            raise ReleaseContractError(f"{context} mixes keyless and pinned-public-key trust")
        return SignerIdentity(
            str(signature["certificateIdentity"]), str(signature["certificateOidcIssuer"])
        )
    if mode == "pinned-public-key":
        if not all(isinstance(signature.get(field), str) for field in public_key_fields):
            raise ReleaseContractError(f"{context} has an incomplete pinned public-key identity")
        if has_certificate:
            raise ReleaseContractError(f"{context} mixes pinned-public-key and keyless trust")
        if signature.get("publicKeyFingerprintAlgorithm") != "sha256-canonical-der-spki":
            raise ReleaseContractError(
                f"{context} public-key fingerprint is not canonical DER SubjectPublicKeyInfo"
            )
        if signature.get("transparencyLog") == "required-public-release":
            raise ReleaseContractError(
                f"{context} cannot claim keyless transparency-log authority for a raw public key"
            )
        return PinnedPublicKeyIdentity(
            str(signature["publicKeyFingerprint"]), str(signature["publicKeyId"])
        )
    raise ReleaseContractError(f"{context} has an unsupported signature trust mode")


def _validate_verification_proof(
    proof: SignatureVerificationProof,
    *,
    signature: Mapping[str, Any],
    identity: TrustIdentity,
    context: str,
) -> None:
    if not isinstance(proof, SignatureVerificationProof):
        raise ReleaseContractError(f"{context} verifier returned no typed proof")
    expected_primary, expected_secondary = (
        (identity.certificate_identity, identity.oidc_issuer)
        if isinstance(identity, SignerIdentity)
        else (identity.public_key_fingerprint, identity.key_id)
    )
    expected = {
        "subject_digest": signature["subjectDigest"],
        "bundle_digest": signature["bundle"]["digest"],
        "trust_mode": signature["trustMode"],
        "identity_primary": expected_primary,
        "identity_secondary": expected_secondary,
        "transparency_log_mode": signature["transparencyLog"],
    }
    for field, value in expected.items():
        if getattr(proof, field) != value:
            raise ReleaseContractError(f"{context} verification proof does not bind {field}")
    if proof.verified_at.tzinfo is None:
        raise ReleaseContractError(f"{context} verification proof time is timezone-naive")
    # A genuine proof is stamped by the verifier during this very
    # verification run, so it is legitimately newer than the policy
    # freshness reference captured before verification began. Judge proof
    # freshness against the verifier's real clock with a bounded skew
    # tolerance instead of the policy reference time.
    if (
        proof.verified_at.astimezone(timezone.utc)
        > datetime.now(timezone.utc) + _PROOF_FUTURE_TOLERANCE
    ):
        raise ReleaseContractError(f"{context} verification proof is from the future")


@dataclass(frozen=True)
class ReleaseIndex:
    document: Mapping[str, Any]
    signed_bytes: bytes
    signed_digest: str
    index_digest: str
    canonical_index_bytes: bytes

    @property
    def release_id(self) -> str:
        return str(self.document["signed"]["release"]["releaseId"])

    @property
    def version(self) -> str:
        return str(self.document["signed"]["release"]["version"])

    @property
    def channel(self) -> str:
        return str(self.document["signed"]["release"]["channel"])


class VerifiedRelease:
    __slots__ = (
        "_index",
        "_verified_signers",
        "_verification_proofs",
        "_target",
        "_authenticated_predecessor",
    )

    def __init__(self) -> None:
        raise TypeError("VerifiedRelease can only be created by verify_release_index")

    @classmethod
    def _from_verification(
        cls,
        index: ReleaseIndex,
        verified_signers: tuple[TrustIdentity, ...],
        verification_proofs: tuple[SignatureVerificationProof, ...],
        target: Mapping[str, Any],
        authenticated_predecessor: AuthenticatedPredecessor | None = None,
    ) -> "VerifiedRelease":
        instance = object.__new__(cls)
        instance._index = index
        instance._verified_signers = tuple(verified_signers)
        instance._verification_proofs = tuple(verification_proofs)
        instance._target = target
        instance._authenticated_predecessor = authenticated_predecessor
        return instance

    @property
    def index(self) -> ReleaseIndex:
        return self._index

    @property
    def verified_signers(self) -> tuple[TrustIdentity, ...]:
        return self._verified_signers

    @property
    def verification_proofs(self) -> tuple[SignatureVerificationProof, ...]:
        return self._verification_proofs

    @property
    def target(self) -> Mapping[str, Any]:
        return self._target

    @property
    def authenticated_predecessor(self) -> AuthenticatedPredecessor | None:
        return self._authenticated_predecessor


class UpdaterReleaseEnvelope:
    """In-memory verified updater input; persist ``canonical_index_bytes`` only."""

    __slots__ = (
        "_document",
        "_canonical_index_bytes",
        "_verified_signers",
        "_verification_proofs",
    )

    def __init__(self) -> None:
        raise TypeError("UpdaterReleaseEnvelope can only be created from VerifiedRelease")

    @classmethod
    def _from_verified(
        cls,
        document: Mapping[str, Any],
        canonical_index_bytes: bytes,
        verified_signers: tuple[TrustIdentity, ...],
        verification_proofs: tuple[SignatureVerificationProof, ...],
    ) -> "UpdaterReleaseEnvelope":
        instance = object.__new__(cls)
        instance._document = _freeze(_thaw(document))
        instance._canonical_index_bytes = bytes(canonical_index_bytes)
        instance._verified_signers = tuple(verified_signers)
        instance._verification_proofs = tuple(verification_proofs)
        return instance

    @property
    def document(self) -> Mapping[str, Any]:
        return self._document

    @property
    def canonical_index_bytes(self) -> bytes:
        return self._canonical_index_bytes

    @property
    def verified_signers(self) -> tuple[TrustIdentity, ...]:
        return self._verified_signers

    @property
    def verification_proofs(self) -> tuple[SignatureVerificationProof, ...]:
        return self._verification_proofs

    def as_dict(self) -> dict[str, Any]:
        return _thaw(self._document)


def signature_verification_proof_set(release: VerifiedRelease) -> list[dict[str, str]]:
    """Serialize exact historic admission proofs without trusting caller summaries."""

    if not isinstance(release, VerifiedRelease):
        raise ReleaseContractError("signature proof inventory requires a verified release")
    values = []
    for proof in release.verification_proofs:
        values.append(
            {
                "subjectDigest": proof.subject_digest,
                "bundleDigest": proof.bundle_digest,
                "trustMode": proof.trust_mode,
                "identityPrimary": proof.identity_primary,
                "identitySecondary": proof.identity_secondary,
                "verifiedAt": proof.verified_at.astimezone(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
                "transparencyLogMode": proof.transparency_log_mode,
            }
        )
    return sorted(
        values,
        key=lambda item: (
            item["subjectDigest"],
            item["bundleDigest"],
            item["identityPrimary"],
            item["identitySecondary"],
        ),
    )


def signature_verification_proof_set_digest(release: VerifiedRelease) -> str:
    return canonical_digest(signature_verification_proof_set(release))


def _is_legacy_predecessor(document: Mapping[str, Any]) -> bool:
    signed = document.get("signed")
    release = signed.get("release") if isinstance(signed, Mapping) else None
    return isinstance(release, Mapping) and (
        release.get("releaseId") == _LEGACY_PREDECESSOR_RELEASE_ID
        and release.get("version") == _LEGACY_PREDECESSOR_VERSION
        and canonical_digest(signed) == _LEGACY_PREDECESSOR_SIGNED_DIGEST
        and canonical_digest(document) == _LEGACY_PREDECESSOR_INDEX_DIGEST
    )


def embedded_predecessor_index(
    document: Mapping[str, Any] | ReleaseIndex,
) -> ReleaseIndex | None:
    """Return the exact signed predecessor embedded by a successor index."""

    index = (
        document
        if isinstance(document, ReleaseIndex)
        else validate_release_index(document, require_signatures=True)
    )
    successor = index.document["signed"].get("successor")
    if successor is None or successor["predecessor"] is None:
        return None
    raw = successor["predecessor"].get("rawIndex")
    if not isinstance(raw, Mapping):
        raise ReleaseContractError("successor predecessor raw index is missing")
    return validate_release_index(
        raw, legacy_predecessor=_is_legacy_predecessor(raw)
    )


def verify_release_predecessor(
    document: Mapping[str, Any] | ReleaseIndex,
    *,
    expected_trust_mode: str,
    accepted_signers: frozenset[SignerIdentity] = frozenset(),
    accepted_public_keys: frozenset[PinnedPublicKeyIdentity] = frozenset(),
    verifier: SignatureVerifier,
    legacy_predecessor: bool = False,
) -> AuthenticatedPredecessor:
    """Authenticate a predecessor's raw index without applying eligibility.

    A predecessor can be expired, deprecated, or no longer installable and
    still be the authenticated rollback/history predecessor of a successor.
    Only its canonical index bytes, detached signature, and pinned identity are
    admitted here; successor policy decides whether it is otherwise eligible.
    """

    raw_document = document.document if isinstance(document, ReleaseIndex) else document
    allow_legacy = legacy_predecessor and _is_legacy_predecessor(raw_document)
    index = (
        document
        if isinstance(document, ReleaseIndex)
        else validate_release_index(document, legacy_predecessor=allow_legacy)
    )
    if isinstance(document, ReleaseIndex):
        rebound = validate_release_index(
            document.document, legacy_predecessor=allow_legacy
        )
        if (
            rebound.signed_bytes != document.signed_bytes
            or rebound.signed_digest != document.signed_digest
            or rebound.index_digest != document.index_digest
        ):
            raise ReleaseContractError("predecessor index fields are not canonically bound")
        index = rebound
    if expected_trust_mode not in {"keyless-certificate", "pinned-public-key"}:
        raise ReleaseContractError("predecessor trust mode is unsupported")
    if expected_trust_mode == "pinned-public-key":
        if not accepted_public_keys or accepted_signers:
            raise ReleaseContractError("predecessor pinned-key policy is malformed")
    elif not accepted_signers or accepted_public_keys:
        raise ReleaseContractError("predecessor keyless policy is malformed")

    failures: list[str] = []
    for position, signature in enumerate(index.document["signatures"]):
        identity = _signature_trust_identity(signature, context=f"predecessor signatures[{position}]")
        accepted = (
            identity in accepted_signers
            if isinstance(identity, SignerIdentity)
            else identity in accepted_public_keys
        )
        if not accepted:
            continue
        try:
            proof = verifier.verify_blob(index.signed_bytes, signature)
            _validate_verification_proof(
                proof,
                signature=signature,
                identity=identity,
                context=f"predecessor signatures[{position}]",
            )
        except Exception as exc:
            failures.append(str(exc))
            continue
        return AuthenticatedPredecessor(
            index=index, signer=identity, proof=proof, signature=signature
        )
    detail = failures[0] if failures else "no accepted predecessor signature"
    raise ReleaseContractError(f"predecessor signature verification failed: {detail}")


@dataclass(frozen=True)
class ValidatedContract:
    document: Mapping[str, Any]
    digest: str

    def as_dict(self) -> dict[str, Any]:
        return _thaw(self.document)


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list) or isinstance(value, tuple):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple) or isinstance(value, list):
        return [_thaw(item) for item in value]
    return value


def _validate_canonical_value(value: object, path: str = "$") -> None:
    if value is None or isinstance(value, bool) or isinstance(value, int):
        return
    if isinstance(value, float):
        raise ReleaseContractError(f"{path}: floating-point JSON values are not canonical")
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise ReleaseContractError(f"{path}: strings must use NFC Unicode")
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise ReleaseContractError(f"{path}: Unicode surrogate code points are forbidden")
        return
    if isinstance(value, list) or isinstance(value, tuple):
        for index, item in enumerate(value):
            _validate_canonical_value(item, f"{path}[{index}]")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ReleaseContractError(f"{path}: object keys must be strings")
            _validate_canonical_value(key, f"{path}.<key>")
            _validate_canonical_value(item, f"{path}.{key}")
        return
    raise ReleaseContractError(f"{path}: unsupported canonical JSON type {type(value).__name__}")


def canonical_json_bytes(value: object) -> bytes:
    """Serialize a value using the bounded ``stateport.canonical-json/v1`` form."""

    _validate_canonical_value(value)
    return json.dumps(
        _thaw(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def parse_last_line_json(stdout: str) -> Any:
    """Parse the LAST non-empty stdout line as JSON; return None when unusable.

    Internal CLI emitter/parser pairs (for example ``health-probe`` and the
    protected StateBench evaluator) emit one compact JSON object as the final
    stdout line so callers can tolerate diagnostic noise on earlier lines.
    Every parser of such an emitter MUST use this single helper so the
    last-non-empty-line contract cannot drift (invariant I3).
    """

    if not stdout.strip():
        return None
    line = stdout.strip().splitlines()[-1]
    try:
        return json.loads(line)
    except ValueError:
        return None


def update_plan_digest(document: Mapping[str, Any]) -> str:
    """Digest the exact plan payload, excluding its two digest-derived IDs."""

    if not isinstance(document, Mapping):
        raise ReleaseContractError("update plan must be a mapping")
    payload = _thaw(document)
    payload.pop("planId", None)
    payload.pop("planDigest", None)
    authority = payload.get("authority")
    if isinstance(authority, dict):
        authority.pop("runId", None)
    return canonical_digest(payload)


def update_policy_digest(policy: Mapping[str, Any]) -> str:
    if not isinstance(policy, Mapping):
        raise ReleaseContractError("update policy must be a mapping")
    payload = _thaw(policy)
    payload.pop("policyDigest", None)
    return canonical_digest(payload)


def installer_directive_digest(directive: Mapping[str, Any]) -> str:
    """Digest an installer confirmation, excluding its derived digest field."""

    if not isinstance(directive, Mapping):
        raise ReleaseContractError("installer directive must be a mapping")
    payload = _thaw(directive)
    payload.pop("directiveDigest", None)
    return canonical_digest(payload)


def revision_contract_digest(
    document: Mapping[str, Any], *, digest_field: str, id_field: str | None = None
) -> str:
    """Digest a revision transition contract without its derived fields."""

    if not isinstance(document, Mapping):
        raise ReleaseContractError("revision contract must be a mapping")
    payload = _thaw(document)
    payload.pop(digest_field, None)
    if id_field is not None:
        payload.pop(id_field, None)
    return canonical_digest(payload)


def image_set_digest(images: Sequence[Mapping[str, Any]]) -> str:
    """Digest an exact order-independent image identity inventory."""

    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for image in images:
        if not isinstance(image, Mapping):
            raise ReleaseContractError("image-set entries must be mappings")
        image_id = image.get("imageId")
        digest = image.get("digest", image.get("expectedDigest"))
        size = image.get("sizeBytes")
        if (
            not isinstance(image_id, str)
            or not isinstance(digest, str)
            or not isinstance(size, int)
        ):
            raise ReleaseContractError("image-set entries require imageId, digest, and sizeBytes")
        if image_id in seen:
            raise ReleaseContractError(f"duplicate image ID in image set: {image_id}")
        seen.add(image_id)
        normalized.append({"imageId": image_id, "digest": digest, "sizeBytes": size})
    return canonical_digest(sorted(normalized, key=lambda item: item["imageId"]))


def service_set_digest(services: Sequence[Mapping[str, Any]]) -> str:
    """Digest exact observed service/image identities, independent of order."""

    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for service in services:
        if not isinstance(service, Mapping):
            raise ReleaseContractError("service-set entries must be mappings")
        service_id = service.get("serviceId")
        image_id = service.get("imageId")
        image_digest = service.get("imageDigest")
        if not all(isinstance(item, str) for item in (service_id, image_id, image_digest)):
            raise ReleaseContractError(
                "service-set entries require serviceId, imageId, and imageDigest"
            )
        if service_id in seen:
            raise ReleaseContractError(f"duplicate service ID in service set: {service_id}")
        seen.add(service_id)
        normalized.append(
            {"serviceId": service_id, "imageId": image_id, "imageDigest": image_digest}
        )
    return canonical_digest(sorted(normalized, key=lambda item: item["serviceId"]))


def topology_digest(target: Mapping[str, Any]) -> str:
    """Digest the signed topology fields that authorize deterministic rendering."""

    fields = (
        "targetId",
        "releaseId",
        "releaseEligibility",
        "os",
        "architecture",
        "hostBaseline",
        "cgroupVersion",
        "containerEngine",
        "executionHostMode",
        "executionContract",
        "hostServices",
        "runtimeDerivation",
        "services",
    )
    missing = [field for field in fields if field not in target]
    if missing:
        raise ReleaseContractError(f"topology is missing fields: {missing}")
    topology = {field: target[field] for field in fields}
    if "sharedWritableVolumes" in target:
        topology["sharedWritableVolumes"] = target["sharedWritableVolumes"]
    return canonical_digest(topology)


def revision_volume_key(
    target: Mapping[str, Any], service_id: str, volume_name: str
) -> str:
    """Resolve one signed service volume attachment to its lifecycle identity."""

    for shared in target.get("sharedWritableVolumes", ()):
        if shared["volumeName"] == volume_name and service_id in shared["members"]:
            return str(shared["volumeKey"])
    return f"{service_id}:{volume_name}"


def quadlet_bundle_digest(files: Mapping[str, bytes]) -> str:
    """Hash a deterministic sorted ``path\0length\0bytes`` Quadlet inventory."""

    if not isinstance(files, Mapping) or not files or len(files) > 128:
        raise ReleaseContractError("Quadlet bundle must contain 1..128 files")
    hasher = hashlib.sha256()
    total = 0
    for name in sorted(files):
        content = files[name]
        path = PurePosixPath(name)
        if (
            not isinstance(name, str)
            or not name
            or path.is_absolute()
            or str(path) != name
            or any(part in {"", ".", ".."} for part in path.parts)
            or "\\" in name
            or "\x00" in name
        ):
            raise ReleaseContractError(f"unsafe Quadlet bundle path: {name!r}")
        if not isinstance(content, bytes):
            raise ReleaseContractError(f"Quadlet bundle entry must be bytes: {name}")
        total += len(content)
        if total > 16 * 1024 * 1024:
            raise ReleaseContractError("Quadlet bundle exceeds the 16 MiB content limit")
        encoded = name.encode("utf-8")
        hasher.update(encoded)
        hasher.update(b"\0")
        hasher.update(str(len(content)).encode("ascii"))
        hasher.update(b"\0")
        hasher.update(content)
    return "sha256:" + hasher.hexdigest()


def signed_workspace_image(target: Mapping[str, Any], images: Sequence[Mapping[str, Any]]) -> Mapping[str, Any] | None:
    """Select only the explicit image role from the verified signed image set.

    Callers rendering unverified input still only obtain an inert plan; root apply
    independently verifies the enclosing release before using this selection.
    """
    contract = target.get("executionContract") or {}
    if "workspaceImageId" not in contract:
        return None
    if contract["workspaceImageId"] != "stateport-dev-workspace":
        raise ReleaseContractError("unsupported signed workspace image selector")
    matches = [image for image in images if image.get("imageId") == "stateport-dev-workspace"]
    if len(matches) != 1:
        raise ReleaseContractError("signed workspace image is missing or duplicated")
    image = matches[0]
    if (image.get("role") != "optional-profile" or not isinstance(image.get("reference"), str)
            or image["reference"].rsplit("@", 1)[-1] != image.get("digest")
            or (image.get("signature") or {}).get("subjectDigest") != image.get("digest")):
        raise ReleaseContractError("workspace image does not carry exact signed image metadata")
    return image


def workspace_image_environment(target: Mapping[str, Any], images: Sequence[Mapping[str, Any]]) -> list[str]:
    image = signed_workspace_image(target, images)
    if image is None:
        return []
    from execution_host.daemon_contract import workspace_template_for_image
    reference = str(image["reference"])
    digest = canonical_digest(workspace_template_for_image(reference))
    return ["Environment=STATEPORT_EXECUTION_HOST_WORKSPACE_IMAGE_REFERENCE=" + reference,
            "Environment=STATEPORT_EXECUTION_HOST_WORKSPACE_SPEC_DIGEST=" + digest]


def render_quadlet_bundle(
    target: Mapping[str, Any], images: Sequence[Mapping[str, Any]]
) -> dict[str, bytes]:
    """Render signed, stage-only Quadlet templates and their owner map.

    The actual full revision identity includes the canonical signed payload
    digest, which is only known after this template bundle is signed. Concrete
    units are therefore derived by :func:`materialize_verified_quadlet_bundle`.
    Nothing returned here is in a live Quadlet search root and no candidate
    container is boot-enabled.
    """

    services = target.get("services")
    if not isinstance(services, Sequence) or isinstance(services, (str, bytes)):
        raise ReleaseContractError("signed target has no service inventory")
    profiles = target.get("runtimeDerivation", {}).get("profiles")
    if not isinstance(profiles, Sequence) or set(profiles) != {"validation", "accepted"}:
        raise ReleaseContractError("signed target has no validation/accepted profile contract")
    materialization = target["runtimeDerivation"]["materialization"]
    execution_contract = target.get("executionContract")
    image_by_id = {
        image.get("imageId"): image
        for image in images
        if isinstance(image, Mapping) and isinstance(image.get("imageId"), str)
    }
    files: dict[str, bytes] = {}
    execution_mode = target.get("executionHostMode")
    if execution_mode == "stable-host-daemon-bootstrap-only":
        if not isinstance(execution_contract, Mapping):
            raise ReleaseContractError("stable execution daemon bootstrap lacks a host contract")
        files["host/execution-contract.json"] = canonical_json_bytes(execution_contract) + b"\n"
    elif execution_mode == "stable-host-daemon-client":
        if not isinstance(execution_contract, Mapping):
            raise ReleaseContractError("stable execution daemon client lacks a host contract")
    elif execution_contract is not None:
        raise ReleaseContractError("target without an execution daemon must not render its socket")

    artifacts: list[dict[str, str]] = []
    owners = sorted({str(service["quadletOwner"]) for service in services})
    for owner in owners:
        for profile in ("validation", "accepted"):
            network_token = f"@@STATEPORT_NETWORK:{owner}:{profile}@@"
            template_path = f"templates/{owner}/stateport-{network_token}.network.in"
            files[template_path] = (
                "[Network]\n"
                f"NetworkName=stateport-{network_token}\n"
                "Label=io.stateport.managed=true\n"
                f"Label=io.stateport.release.id={target['releaseId']}\n"
                f"Label=io.stateport.target.id={target['targetId']}\n"
                f"Label=io.stateport.profile={profile}\n"
                "Internal=true\n"
            ).encode("utf-8")
            artifacts.append(
                {
                    "templatePath": template_path,
                    "owner": owner,
                    "profile": profile,
                    "kind": "network",
                    "liveRoot": materialization["liveQuadletRoots"][owner],
                    "phase": "validation-start" if profile == "validation" else "promotion-cas",
                }
            )

    for service in services:
        service_id = str(service["serviceId"])
        service_name_id = canonical_digest({"serviceId": service_id}).removeprefix("sha256:")[:12]
        if service["trustDomain"] == "execution":
            raise ReleaseContractError(
                "execution host is stable host lifecycle and cannot be a control revision service"
            )
        image = image_by_id.get(service["imageId"])
        if not isinstance(image, Mapping):
            raise ReleaseContractError(f"signed service {service_id} has no signed image")
        owner = str(service["quadletOwner"])
        for profile in ("validation", "accepted"):
            revision_token = f"@@STATEPORT_REVISION:{service_id}:{profile}@@"
            network_token = f"@@STATEPORT_NETWORK:{owner}:{profile}@@"
            unit_token = f"stateport-{service_name_id}-{profile}-{revision_token}"
            lines = [
                "[Unit]",
                f"Description=StatePort staged {profile} profile for {service_id}",
                "",
                "[Container]",
                f"ContainerName={unit_token}",
                f"Image={image['reference']}",
                "Pull=never",
                "RunInit=true",
                f"User={service['runAsUser']}",
                "ReadOnly=true",
                "NoNewPrivileges=true",
                "DropCapability=all",
                f"UserNS=keep-id:uid={service['runAsUser']},gid={service['runAsUser']}",
                f"Network=stateport-{network_token}.network",
                f"Label=io.stateport.source.commit={image['sourceCommit']}",
                f"Label=io.stateport.source.tree={image['sourceTree']}",
                f"Label=io.stateport.release.id={target['releaseId']}",
                "Label=io.stateport.release.signed-payload=@@STATEPORT_SIGNED_PAYLOAD_DIGEST@@",
                f"Label=io.stateport.target.id={target['targetId']}",
                f"Label=io.stateport.target.topology={target['topologyDigest']}",
                f"Label=io.stateport.service.id={service_id}",
                f"Label=io.stateport.revision.id={revision_token}",
                f"Label=io.stateport.profile={profile}",
                f"Environment=STATEPORT_RELEASE_PROFILE={profile}",
                f"Environment=STATEPORT_RELEASE_REVISION={revision_token}",
            ]
            if service_id == "stateport-web":
                lines.extend(workspace_image_environment(target, images))
            for port in sorted(
                service["ports"], key=lambda item: (item["name"], item["containerPort"])
            ):
                lines.append(
                    "PublishPort=127.0.0.1:"
                    f"@@STATEPORT_PORT:{service_id}:{profile}:{port['name']}@@:"
                    f"{port['containerPort']}"
                )
            if service["ports"]:
                # The persistent-app loopback guard only accepts a Host
                # authority naming the bound container port or the configured
                # external loopback port.  Bind the signed host port of the
                # health port (the installer's probe target) so health probes
                # and operator browsers are accepted instead of refused 421.
                health = service["health"]
                health_port = next(
                    (
                        port
                        for port in service["ports"]
                        if port["containerPort"] == health["containerPort"]
                    ),
                    service["ports"][0],
                )
                lines.append(
                    "Environment=STATEPORT_EXTERNAL_LOOPBACK_PORT="
                    f"@@STATEPORT_PORT:{service_id}:{profile}:{health_port['name']}@@"
                )
            for volume in sorted(service["writableVolumes"], key=lambda item: item["name"]):
                volume_key = revision_volume_key(target, service_id, str(volume["name"]))
                if profile == "validation" and volume["validation"]["mode"] == (
                    "read-only-snapshot-copy"
                ):
                    lines.append(
                        f"Volume=@@STATEPORT_VALIDATION_VOLUME:{volume_key}@@:"
                        f"{volume['mountPath']}:ro"
                    )
                    continue
                if profile == "accepted" and volume["scope"] == "installation":
                    lines.append(
                        f"Volume=@@STATEPORT_ACCEPTED_DATA_VOLUME:{volume_key}@@:"
                        f"{volume['mountPath']}:rw,U"
                    )
                    continue
                volume_template = (
                    f"templates/{owner}/{unit_token}-v-"
                    f"{canonical_digest({'volumeKey': volume_key})[7:19]}.volume.in"
                )
                volume_name = f"{unit_token}-v-{canonical_digest({'volumeKey': volume_key})[7:19]}"
                files[volume_template] = (
                    "[Volume]\n"
                    f"VolumeName={volume_name}\n"
                    "Label=io.stateport.managed=true\n"
                    f"Label=io.stateport.release.id={target['releaseId']}\n"
                    f"Label=io.stateport.revision.id={revision_token}\n"
                    f"Label=io.stateport.profile={profile}\n"
                ).encode("utf-8")
                artifacts.append(
                    {
                        "templatePath": volume_template,
                        "owner": owner,
                        "profile": profile,
                        "kind": "volume",
                        "liveRoot": materialization["liveQuadletRoots"][owner],
                        "phase": (
                            "validation-start" if profile == "validation" else "promotion-cas"
                        ),
                    }
                )
                lines.append(f"Volume={volume_name}.volume:{volume['mountPath']}:rw")
            for mount in sorted(
                service.get("readOnlyHostMounts", ()), key=lambda item: item["name"]
            ):
                lines.extend(
                    [
                        f"Volume={mount['hostPath']}:{mount['mountPath']}:ro",
                        f"Environment={mount['environmentVariable']}={mount['mountPath']}",
                    ]
                )
                if mount["name"] == "workspace-authority":
                    lines.append("Environment=STATEPORT_APPLICATION_WORKSPACE_BINDINGS=" + mount["mountPath"] + "/bindings.json")
                    lines.append("Environment=STATEPORT_APPLICATION_WORKSPACE_BINDINGS_FORMAT=stateport.application-workspace-bindings/v2")
                    if mount.get("profileId") in {"stateport.empty-workspace-terminal/v1", "stateport.reviewed-source-workspace-terminal/v1"}:
                        lines.append("Environment=STATEPORT_WORKSPACE_AUTHORITY_PROFILE=" + mount["profileId"])
            provider_home = service.get("providerHome")
            if provider_home is not None:
                lines.append(f"Environment=CODEX_HOME={provider_home['mountPath']}")
                if profile == "accepted":
                    # Provider-owned auth is outside all copied StatePort data
                    # generations. Do not use :U or inspect its file contents.
                    lines.append(f"Volume={provider_home['hostPath']}:{provider_home['mountPath']}:rw")
                else:
                    # Podman accepts U for tmpfs and derives its mount UID/GID
                    # from User=. Literal uid=/gid= options are rejected.
                    # This is an empty tmpfs, never the accepted host auth path.
                    lines.append(
                        f"Tmpfs={provider_home['mountPath']}:rw,noexec,nosuid,nodev,"
                        "notmpcopyup,mode=0700,size=67108864,U"
                    )
            if service["capabilities"]["controlContract"] == "narrow-unix-client":
                if not isinstance(execution_contract, Mapping):
                    raise ReleaseContractError(f"service {service_id} lacks stable daemon contract")
                lines.extend(
                    [
                        f"PodmanArgs=--runtime={CONFINED_GROUP_OCI_RUNTIME_PATH}",
                        "PodmanArgs=--group-add=keep-groups",
                        f"Volume={execution_contract['hostDirectory']}:"
                        f"{execution_contract['containerDirectory']}:ro",
                        "Environment=STATEPORT_EXECUTION_SOCKET="
                        f"{execution_contract['containerDirectory']}/{execution_contract['socketName']}",
                        f"Environment=STATEPORT_EXECUTION_PEER_POLICY={execution_contract['peerIdentity']}",
                    ]
                )
            health = service["health"]
            health_probe = image["healthProbe"]
            lines.extend(
                [
                    # Quadlet HealthCmd= with unquoted arguments renders as
                    # `--health-cmd <cmd> --kind http ...`, and older Podman
                    # parses --kind as its own flag ("unknown flag"), so the
                    # container fails at start.  The JSON-array form is passed
                    # verbatim (brackets included) and cannot be exec'd.  The
                    # single-quoted shell form renders as
                    # `--health-cmd "cmd args"`, which podman runs through
                    # /bin/sh -c with the exact arguments.
                    "HealthCmd=" + json.dumps(
                        " ".join(
                            [
                                str(health_probe["executable"]),
                                "--kind",
                                "http",
                                "--host",
                                "127.0.0.1",
                                "--port",
                                str(health["containerPort"]),
                                "--path",
                                str(health["path"]),
                            ]
                        )
                    ),
                    "HealthInterval=30s",
                    "HealthTimeout=10s",
                    "HealthRetries=3",
                    "LogDriver=k8s-file",
                    "PodmanArgs=--log-opt=max-size=10485760",
                    "",
                    "[Service]",
                    "Restart=on-failure",
                    "RestartSec=5s",
                    "TimeoutStartSec=900s",
                    "StandardOutput=journal",
                    "StandardError=journal",
                    f"SyslogIdentifier={service_id}-{profile}",
                    "LogRateLimitIntervalSec=30s",
                    "LogRateLimitBurst=1000",
                    f"MemoryMax={service['resources']['memoryMaxBytes']}",
                    f"CPUQuota={service['resources']['cpuQuotaPercent']}%",
                    f"TasksMax={service['resources']['pidsMax']}",
                    "",
                ]
            )
            template_path = f"templates/{owner}/{unit_token}.container.in"
            files[template_path] = "\n".join(lines).encode("utf-8")
            artifacts.append(
                {
                    "templatePath": template_path,
                    "owner": owner,
                    "profile": profile,
                    "kind": "container",
                    "liveRoot": materialization["liveQuadletRoots"][owner],
                    "phase": "validation-start" if profile == "validation" else "promotion-cas",
                }
            )
    manifest = {
        "formatVersion": "stateport.quadlet-materialization-template/v2",
        "releaseId": target["releaseId"],
        "targetId": target["targetId"],
        "topologyDigest": target["topologyDigest"],
        "materialization": materialization,
        "portPolicy": target["runtimeDerivation"]["portPolicy"],
        "stateMachine": target["runtimeDerivation"]["stateMachine"],
        "artifacts": sorted(artifacts, key=lambda item: item["templatePath"]),
    }
    files["materialization.template.json"] = canonical_json_bytes(manifest) + b"\n"
    if any(b"[Install]" in content or b"WantedBy=" in content for content in files.values()):
        raise ReleaseContractError("candidate template bundle contains implicit boot activation")
    return files


def render_stable_host_quadlet_bundle(
    target: Mapping[str, Any], images: Sequence[Mapping[str, Any]]
) -> dict[str, bytes]:
    """Render the separately governed, out-of-revision host service bundle."""

    host_services = target.get("hostServices")
    if (
        not isinstance(host_services, Sequence)
        or isinstance(host_services, (str, bytes))
        or not host_services
    ):
        raise ReleaseContractError("stable host bundle requires a non-empty host service inventory")
    image_by_id = {
        image.get("imageId"): image
        for image in images
        if isinstance(image, Mapping) and isinstance(image.get("imageId"), str)
    }
    unit_files: dict[str, bytes] = {}
    services: list[dict[str, Any]] = []
    for service in sorted(host_services, key=lambda item: item["serviceId"]):
        image = image_by_id.get(service["imageId"])
        if not isinstance(image, Mapping) or image.get("role") != "stable-host-service":
            raise ReleaseContractError(
                f"stable host service {service['serviceId']} lacks its exact signed image"
            )
        unit_path = f"host/{service['quadletOwner']}/{service['serviceId']}.container"
        user_namespace = service["userNamespace"]
        if user_namespace == "keep-id":
            user_namespace = f"keep-id:uid={service['runAsUser']},gid={service['runAsUser']}"
        lines = [
            "[Unit]",
            f"Description=StatePort stable host service {service['serviceId']}",
        ]
        if service["engineAccess"] is not None:
            # The unit bind-mounts the podman runtime directory; ordering after
            # podman.socket guarantees the directory exists at start.
            lines.append("After=podman.socket")
        lines.extend(
            [
                "",
                "[Container]",
                f"ContainerName={service['serviceId']}",
                f"Image={image['reference']}",
                "Pull=never",
                "RunInit=true",
                f"User={service['runAsUser']}",
                "ReadOnly=true",
                "NoNewPrivileges=true",
                "DropCapability=all",
                f"UserNS={user_namespace}",
                "Network=slirp4netns",
                "Label=io.stateport.managed=true",
                "Label=io.stateport.lifecycle=stable-host-service",
                f"Label=io.stateport.release.id={target['releaseId']}",
                f"Label=io.stateport.target.id={target['targetId']}",
                f"Label=io.stateport.target.topology={target['topologyDigest']}",
                f"Label=io.stateport.service.id={service['serviceId']}",
                f"Label=io.stateport.image.digest={image['digest']}",
            ]
        )
        if service["trustDomain"] == "execution":
            # Rootless bind-mount traversal depends on the host execution-control
            # supplemental group. This does not map that GID for chown; the
            # privileged provisioner separately refuses that unsupported claim.
            lines.extend(
                [
                    f"PodmanArgs=--runtime={CONFINED_GROUP_OCI_RUNTIME_PATH}",
                    "PodmanArgs=--group-add=keep-groups",
                ]
            )
        socket = service["socket"]
        if socket is not None:
            container_directory = socket["hostDirectory"]
            execution_contract = target.get("executionContract")
            if service["trustDomain"] == "execution":
                if not isinstance(execution_contract, Mapping):
                    raise ReleaseContractError("execution host bundle lacks client contract")
                container_directory = execution_contract["containerDirectory"]
            lines.extend(
                [
                    f"Volume={socket['hostDirectory']}:{container_directory}:rw",
                    f"Environment=STATEPORT_HOST_SOCKET={container_directory}/{socket['socketName']}",
                    f"Environment=STATEPORT_PEER_POLICY={socket['peerIdentity']}",
                ]
            )
            if service["trustDomain"] == "execution":
                assert isinstance(execution_contract, Mapping)
                numeric = {
                    "STATEPORT_EXECUTION_HOST_SOCKET_GROUP_GID": execution_contract.get(
                        "socketGroupGid", 65530
                    ),
                    "STATEPORT_EXECUTION_HOST_ALLOWED_CLIENT_UID": execution_contract.get(
                        "allowedClientUid", 65531
                    ),
                    "STATEPORT_EXECUTION_HOST_ALLOWED_CLIENT_GID": execution_contract.get(
                        "allowedClientGid", 65531
                    ),
                    "STATEPORT_EXECUTION_HOST_RUNTIME_UID": execution_contract.get(
                        "runtimeUid", 65532
                    ),
                    "STATEPORT_EXECUTION_HOST_RUNTIME_GID": execution_contract.get(
                        "runtimeGid", 65532
                    ),
                }
                if any(type(value) is not int or value < 1 for value in numeric.values()):
                    raise ReleaseContractError(
                        "execution host contract numeric identity handoff is invalid"
                    )
                lines.extend(
                    [
                        "Environment=STATEPORT_EXECUTION_HOST_REQUIRE_NUMERIC_HANDOFF=1",
                        "Environment=STATEPORT_EXECUTION_HOST_USER_NAMESPACE="
                        f"{service['userNamespace']}",
                        "Environment=STATEPORT_EXECUTION_HOST_SOCKET_DIRECTORY_MODE="
                        f"{execution_contract['directoryMode']}",
                        "Environment=STATEPORT_EXECUTION_HOST_SOCKET_GROUP="
                        f"{execution_contract['directoryGroup']}",
                        "Environment=STATEPORT_EXECUTION_HOST_ALLOWED_CLIENT_USER="
                        f"{execution_contract['allowedClientUser']}",
                        *[
                            f"Environment={name}={value}"
                            for name, value in numeric.items()
                        ],
                    ]
                )
        engine_access = service["engineAccess"]
        if engine_access is not None:
            # Directory-form mounts (current) and legacy file-form mounts
            # (immutable signed predecessors) both validate; the socket env
            # path is derived from whichever form the topology carries.
            engine_container_path = str(engine_access["containerPath"])
            if not engine_container_path.endswith(".sock"):
                engine_container_path = f"{engine_container_path}/podman.sock"
            lines.extend(
                [
                    f"Volume={engine_access['hostPath']}:{engine_access['containerPath']}:rw",
                    f"Environment=STATEPORT_ENGINE_SOCKET={engine_container_path}",
                ]
            )
        if service["trustDomain"] == "execution":
            execution_contract = target.get("executionContract")
            assert isinstance(execution_contract, Mapping)
            lines.extend(
                [
                    "Environment=STATEPORT_EXECUTION_HOST_STATE_DIR="
                    f"{service['writableVolumes'][0]['mountPath']}",
                    "Environment=STATEPORT_EXECUTION_HOST_GRANTS_DIR="
                    f"{service['writableVolumes'][0]['mountPath']}/grants",
                ]
            )
        if service["serviceId"] == (target.get("executionContract") or {}).get("serviceId"):
            lines.extend(workspace_image_environment(target, images))
        for volume in sorted(service["writableVolumes"], key=lambda item: item["name"]):
            lines.append(f"Volume={volume['hostPath']}:{volume['mountPath']}:rw")
        for port in sorted(service["ports"], key=lambda item: item["name"]):
            lines.append(f"PublishPort=127.0.0.1:{port['hostPort']}:{port['containerPort']}")
        health = service["health"]
        health_probe = image["healthProbe"]
        if health["kind"] == "unix-socket":
            if socket is None:
                raise ReleaseContractError("unix-socket health requires a confined socket")
            container_directory = (
                target["executionContract"]["containerDirectory"]
                if service["trustDomain"] == "execution"
                else socket["hostDirectory"]
            )
            health_command = json.dumps(
                " ".join(
                    [
                        str(health_probe["executable"]),
                        "--kind",
                        "unix-socket",
                        "--path",
                        f"{container_directory}/{socket['socketName']}",
                    ]
                )
            )
        else:
            parsed_health = urlsplit(str(health["value"]))
            health_command = json.dumps(
                " ".join(
                    [
                        str(health_probe["executable"]),
                        "--kind",
                        "http",
                        "--host",
                        "127.0.0.1",
                        "--port",
                        str(parsed_health.port),
                        "--path",
                        str(parsed_health.path),
                    ]
                )
            )
        lines.extend(
            [
                f"HealthCmd={health_command}",
                "HealthInterval=30s",
                "HealthTimeout=10s",
                "HealthRetries=3",
                f"LogDriver={service['logging']['driver']}",
                f"PodmanArgs=--log-opt=max-size={service['logging']['maxSizeBytes']}",
                "",
                "[Service]",
                "Restart=on-failure",
                "RestartSec=5s",
                "TimeoutStartSec=900s",
                "StandardOutput=journal",
                "StandardError=journal",
                f"SyslogIdentifier={service['serviceId']}",
                "LogRateLimitIntervalSec=30s",
                "LogRateLimitBurst=1000",
                f"MemoryMax={service['resources']['memoryMaxBytes']}",
                f"CPUQuota={service['resources']['cpuQuotaPercent']}%",
                f"TasksMax={service['resources']['pidsMax']}",
                "",
                "[Install]",
                "WantedBy=default.target",
                "",
            ]
        )
        unit_files[unit_path] = "\n".join(lines).encode("utf-8")
        services.append(
            {
                "serviceId": service["serviceId"],
                "imageId": service["imageId"],
                "imageReference": image["reference"],
                "imageDigest": image["digest"],
                "quadletOwner": service["quadletOwner"],
                "runAsUser": service["runAsUser"],
                "engineAccess": _thaw(service["engineAccess"]),
                "socket": _thaw(service["socket"]),
                "ports": _thaw(service["ports"]),
                "writableVolumes": _thaw(service["writableVolumes"]),
                "resources": _thaw(service["resources"]),
                "logging": _thaw(service["logging"]),
                "health": _thaw(service["health"]),
                "updateCompatibility": _thaw(service["updateCompatibility"]),
                "unitPath": unit_path,
                "activation": "enabled-by-explicit-host-plan-only",
            }
        )
    plan: dict[str, Any] = {
        "schema": "stateport.stable-host-service-plan/v1",
        "releaseId": target["releaseId"],
        "targetId": target["targetId"],
        "topologyDigest": target["topologyDigest"],
        "lifecycleRoot": "stable-out-of-revision-quadlet-root",
        "replacementPolicy": "explicit-compatible-host-update-only",
        "services": services,
        "bundleDigest": quadlet_bundle_digest(unit_files),
    }
    plan["planDigest"] = revision_contract_digest(plan, digest_field="planDigest")
    validate_contract_document(plan, expected_schema="stateport.stable-host-service-plan/v1")
    return {
        **unit_files,
        "host/stable-host-service.plan.json": canonical_json_bytes(plan) + b"\n",
    }


def verify_stable_host_quadlet_bundle(files: Mapping[str, bytes], release: VerifiedRelease) -> str:
    """Verify exact stable host bytes without admitting them to revision activation."""

    if not isinstance(release, VerifiedRelease):
        raise ReleaseContractError("stable host verification requires a verified release")
    expected = render_stable_host_quadlet_bundle(
        release.target, release.index.document["signed"]["images"]
    )
    if set(files) != set(expected) or any(
        files[path] != content for path, content in expected.items()
    ):
        raise ReleaseContractError("stable host bundle differs from signed deterministic topology")
    return quadlet_bundle_digest(files)


def plan_stable_host_service_transition(
    release: VerifiedRelease,
    *,
    observed_services: Sequence[Mapping[str, Any]],
    host_identity_digest: str,
    port_reservation_receipt_digest: str,
) -> dict[str, Any]:
    """Plan create/retain/replace effects for the separate stable-host lifecycle."""

    if not isinstance(release, VerifiedRelease):
        raise ReleaseContractError("stable host transition requires a verified release")
    if any(
        _DIGEST.fullmatch(value) is None
        for value in (host_identity_digest, port_reservation_receipt_digest)
    ):
        raise ReleaseContractError(
            "stable host transition lacks exact host identity or port reservation"
        )
    expected_fields = {
        "serviceId",
        "imageId",
        "imageDigest",
        "contractVersion",
        "quadletOwner",
        "engineAccess",
        "socket",
        "ports",
        "writableVolumes",
        "resources",
        "logging",
        "health",
    }
    observed_by_id: dict[str, dict[str, Any]] = {}
    for position, item in enumerate(observed_services):
        if not isinstance(item, Mapping) or set(item) != expected_fields:
            raise ReleaseContractError(
                f"observed stable host service {position} is not an exact typed inventory entry"
            )
        normalized = _thaw(item)
        service_id = normalized["serviceId"]
        if not isinstance(service_id, str) or service_id in observed_by_id:
            raise ReleaseContractError("observed stable host inventory repeats a service")
        if (
            _DIGEST.fullmatch(str(normalized["imageDigest"])) is None
            or not isinstance(normalized["contractVersion"], int)
            or isinstance(normalized["contractVersion"], bool)
        ):
            raise ReleaseContractError("observed stable host identity is invalid")
        observed_by_id[service_id] = normalized
    desired_ids = {service["serviceId"] for service in release.target["hostServices"]}
    if set(observed_by_id) - desired_ids:
        raise ReleaseContractError("stable host inventory contains an unmanaged extra service")
    images = {image["imageId"]: image for image in release.index.document["signed"]["images"]}
    actions: list[dict[str, Any]] = []
    for desired in sorted(release.target["hostServices"], key=lambda item: item["serviceId"]):
        image = images[desired["imageId"]]
        observed = observed_by_id.get(desired["serviceId"])
        if observed is None:
            action, reason, observed_digest = "create", "missing", None
        else:
            invariant_fields = (
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
            if any(_thaw(observed[field]) != _thaw(desired[field]) for field in invariant_fields):
                raise ReleaseContractError(
                    f"stable host service {desired['serviceId']} changed its authority boundary"
                )
            observed_digest = observed["imageDigest"]
            if observed_digest == image["digest"]:
                if observed["contractVersion"] != desired["updateCompatibility"]["contractVersion"]:
                    raise ReleaseContractError("stable host exact image reports another contract")
                action, reason = "retain", "exact-identity"
            else:
                compatibility = desired["updateCompatibility"]
                if not (
                    compatibility["minimumClientVersion"]
                    <= observed["contractVersion"]
                    <= compatibility["maximumClientVersion"]
                ):
                    raise ReleaseContractError(
                        f"stable host service {desired['serviceId']} replacement is incompatible"
                    )
                action, reason = "replace", "compatible-explicit-replacement"
        actions.append(
            {
                "serviceId": desired["serviceId"],
                "action": action,
                "observedImageDigest": observed_digest,
                "desiredImageDigest": image["digest"],
                "contractVersion": desired["updateCompatibility"]["contractVersion"],
                "reason": reason,
            }
        )
    stable_bundle = render_stable_host_quadlet_bundle(
        release.target, release.index.document["signed"]["images"]
    )
    desired_plan = _canonical_embedded_document(stable_bundle, "/stable-host-service.plan.json")
    observed_inventory = sorted(observed_by_id.values(), key=lambda item: item["serviceId"])
    transition: dict[str, Any] = {
        "schema": "stateport.stable-host-service-transition/v1",
        "releaseId": release.index.release_id,
        "targetId": release.target["targetId"],
        "topologyDigest": release.target["topologyDigest"],
        "hostIdentityDigest": host_identity_digest,
        "portReservationReceiptDigest": port_reservation_receipt_digest,
        "observedInventoryDigest": canonical_digest(observed_inventory),
        "desiredPlanDigest": desired_plan["planDigest"],
        "actions": actions,
        "effectBoundary": "separate-host-authority-never-revision-activation",
    }
    transition["transitionDigest"] = revision_contract_digest(
        transition, digest_field="transitionDigest"
    )
    return _thaw(
        validate_contract_document(
            transition, expected_schema="stateport.stable-host-service-transition/v1"
        ).document
    )


def _revision_id(
    release: VerifiedRelease, service: Mapping[str, Any], image: Mapping[str, Any], profile: str
) -> str:
    return canonical_digest(
        {
            "formatVersion": "stateport.full-revision-identity/v1",
            "releaseId": release.index.release_id,
            "signedPayloadDigest": release.index.signed_digest,
            "targetId": release.target["targetId"],
            "topologyDigest": release.target["topologyDigest"],
            "serviceId": service["serviceId"],
            "imageDigest": image["digest"],
            "profile": profile,
        }
    ).removeprefix("sha256:")


def materialize_verified_quadlet_bundle(
    release: VerifiedRelease,
    *,
    operation_plan_digest: str,
    host_identity_digest: str,
    collision_inventory_digests: Mapping[str, str],
    occupied_port_inputs: Sequence[Mapping[str, Any]],
    proposed_at: str,
    validation_backup_receipt: Mapping[str, Any] | None,
) -> dict[str, bytes]:
    """Derive concrete stage artifacts from a cryptographically verified release."""

    if not isinstance(release, VerifiedRelease):
        raise ReleaseContractError("Quadlet materialization requires a verified release")
    target = release.target
    images = release.index.document["signed"]["images"]
    templates = render_quadlet_bundle(target, images)
    if quadlet_bundle_digest(templates) != target["quadletBundleDigest"]:
        raise ReleaseContractError("signed Quadlet template digest is stale")
    image_by_id = {image["imageId"]: image for image in images}
    revisions: dict[tuple[str, str], str] = {}
    networks: dict[tuple[str, str], str] = {}
    for service in target["services"]:
        image = image_by_id[service["imageId"]]
        for profile in ("validation", "accepted"):
            revisions[(service["serviceId"], profile)] = _revision_id(
                release, service, image, profile
            )
            networks[(service["quadletOwner"], profile)] = canonical_digest(
                {
                    "formatVersion": "stateport.revision-network/v1",
                    "signedPayloadDigest": release.index.signed_digest,
                    "targetId": target["targetId"],
                    "owner": service["quadletOwner"],
                    "profile": profile,
                }
            ).removeprefix("sha256:")
    policy = target["runtimeDerivation"]["portPolicy"]
    range_start = policy["rangeStart"]
    span = policy["rangeEnd"] - range_start + 1
    for label, digest in {
        "operation plan": operation_plan_digest,
        "host identity": host_identity_digest,
        **{f"{key} inventory": value for key, value in collision_inventory_digests.items()},
    }.items():
        if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
            raise ReleaseContractError(f"{label} digest is invalid")
    if set(collision_inventory_digests) != {
        "current",
        "predecessor",
        "candidate",
        "observedHost",
    }:
        raise ReleaseContractError("port allocation lacks exact collision inventories")
    _parse_timestamp(proposed_at, "proposedAt")
    normalized_occupied: list[dict[str, Any]] = []
    for position, item in enumerate(occupied_port_inputs):
        if not isinstance(item, Mapping):
            raise ReleaseContractError(f"occupied port input {position} is not typed")
        normalized = {
            "class": item.get("class"),
            "port": item.get("port"),
            "identityDigest": item.get("identityDigest"),
        }
        if normalized["class"] not in {
            "current",
            "predecessor",
            "candidate",
            "observed-host",
        }:
            raise ReleaseContractError(f"occupied port input {position} has an invalid class")
        if not isinstance(normalized["port"], int) or isinstance(normalized["port"], bool):
            raise ReleaseContractError(f"occupied port input {position} has an invalid port")
        if (
            not isinstance(normalized["identityDigest"], str)
            or _DIGEST.fullmatch(normalized["identityDigest"]) is None
        ):
            raise ReleaseContractError(
                f"occupied port input {position} has no exact identity digest"
            )
        normalized_occupied.append(normalized)
    used = {int(item["port"]) for item in normalized_occupied}
    if any(port < 1 or port > 65535 for port in used):
        raise ReleaseContractError("occupied port input is outside the TCP port range")
    ports: dict[tuple[str, str, str], int] = {}
    probe_attempts: dict[tuple[str, str, str], int] = {}
    for service in sorted(target["services"], key=lambda item: item["serviceId"]):
        for profile in ("validation", "accepted"):
            revision = revisions[(service["serviceId"], profile)]
            for port in sorted(service["ports"], key=lambda item: item["name"]):
                seed = int(
                    hashlib.sha256(
                        f"{revision}\0{service['serviceId']}\0{profile}\0{port['name']}".encode()
                    ).hexdigest(),
                    16,
                )
                selected: int | None = None
                for attempt in range(policy["maximumAttempts"]):
                    candidate = range_start + (seed % span + attempt * policy["probeStep"]) % span
                    if candidate not in used:
                        selected = candidate
                        break
                if selected is None:
                    raise ReleaseContractError("deterministic revision port range is exhausted")
                used.add(selected)
                ports[(service["serviceId"], profile, port["name"])] = selected
                probe_attempts[(service["serviceId"], profile, port["name"])] = attempt

    requires_snapshot = any(
        volume["validation"]["mode"] == "read-only-snapshot-copy"
        for service in target["services"]
        for volume in service["writableVolumes"]
    )
    validation_bindings: dict[str, str] = {}
    validation_backup_receipt_digest: str | None = None
    validated_backup_document: Mapping[str, Any] | None = None
    if requires_snapshot:
        if not isinstance(validation_backup_receipt, Mapping):
            raise ReleaseContractError("validation snapshot volumes require a typed backup receipt")
        validated_backup = validate_contract_document(
            validation_backup_receipt,
            expected_schema="stateport.revision-validation-backup-receipt/v1",
        ).document
        validated_backup_document = validated_backup
        expected_identity = {
            "operationPlanDigest": operation_plan_digest,
            "releaseId": release.index.release_id,
            "signedPayloadDigest": release.index.signed_digest,
            "targetId": target["targetId"],
            "topologyDigest": target["topologyDigest"],
        }
        if any(
            validated_backup[field] != expected for field, expected in expected_identity.items()
        ):
            raise ReleaseContractError("validation backup receipt belongs to another release plan")
        validation_bindings = {
            item["volumeKey"]: item["snapshotVolumeName"]
            for item in validated_backup["volumeBindings"]
        }
        required_keys = {
            revision_volume_key(target, str(service["serviceId"]), str(volume["name"]))
            for service in target["services"]
            for volume in service["writableVolumes"]
            if volume["validation"]["mode"] == "read-only-snapshot-copy"
        }
        if set(validation_bindings) != required_keys:
            raise ReleaseContractError(
                "validation backup receipt does not bind the exact snapshot set"
            )
        validation_backup_receipt_digest = str(validated_backup["receiptDigest"])
    elif validation_backup_receipt is not None:
        raise ReleaseContractError("release has no validation snapshot requiring a backup receipt")
    replacements = {
        "@@STATEPORT_SIGNED_PAYLOAD_DIGEST@@": release.index.signed_digest,
    }
    for (service_id, profile), revision in revisions.items():
        replacements[f"@@STATEPORT_REVISION:{service_id}:{profile}@@"] = revision
    for (owner, profile), network in networks.items():
        replacements[f"@@STATEPORT_NETWORK:{owner}:{profile}@@"] = network
    for (service_id, profile, name), port in ports.items():
        replacements[f"@@STATEPORT_PORT:{service_id}:{profile}:{name}@@"] = str(port)
    for service in target["services"]:
        for volume in service["writableVolumes"]:
            if volume["validation"]["mode"] != "read-only-snapshot-copy":
                continue
            key = revision_volume_key(target, str(service["serviceId"]), str(volume["name"]))
            binding = validation_bindings.get(key)
            if (
                not isinstance(binding, str)
                or re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,127}", binding) is None
            ):
                raise ReleaseContractError(f"validation snapshot volume is unbound: {key}")
            replacements[f"@@STATEPORT_VALIDATION_VOLUME:{key}@@"] = binding

    signed_hex = release.index.signed_digest.removeprefix("sha256:")
    materialized: dict[str, bytes] = {}
    artifact_map: list[dict[str, Any]] = []
    template_manifest = json.loads(templates["materialization.template.json"])
    for template_path, content in templates.items():
        if template_path == "materialization.template.json":
            continue
        text = content.decode("utf-8")
        path = template_path
        for token, value in replacements.items():
            text = text.replace(token, value)
            path = path.replace(token, value)
        accepted_pending = "@@STATEPORT_ACCEPTED_DATA_VOLUME:" in text
        unresolved = [
            token
            for token in re.findall(r"@@STATEPORT_[^@]+@@", text + "\n" + path)
            if not token.startswith("@@STATEPORT_ACCEPTED_DATA_VOLUME:")
        ]
        if unresolved:
            raise ReleaseContractError(f"unresolved Quadlet materialization token: {template_path}")
        relative = path.removeprefix("templates/").removesuffix(".in")
        if accepted_pending:
            relative += ".in"
        staged_path = f"staged/{signed_hex}/{relative}"
        materialized[staged_path] = text.encode("utf-8")
    for artifact in template_manifest["artifacts"]:
        path = artifact["templatePath"]
        for token, value in replacements.items():
            path = path.replace(token, value)
        relative = path.removeprefix("templates/").removesuffix(".in")
        source_content = templates[artifact["templatePath"]].decode("utf-8")
        accepted_pending = "@@STATEPORT_ACCEPTED_DATA_VOLUME:" in source_content
        if accepted_pending:
            relative += ".in"
        artifact_map.append(
            {
                **artifact,
                "stagedPath": f"staged/{signed_hex}/{relative}",
                "liveRelativePath": "/".join(relative.removesuffix(".in").split("/")[1:]),
                "dataPromotionPending": accepted_pending,
            }
        )
    manifest = {
        "formatVersion": "stateport.quadlet-materialization/v2",
        "operationPlanDigest": operation_plan_digest,
        "releaseId": release.index.release_id,
        "signedPayloadDigest": release.index.signed_digest,
        "targetId": target["targetId"],
        "topologyDigest": target["topologyDigest"],
        "signedTemplateBundleDigest": target["quadletBundleDigest"],
        "stageRoot": target["runtimeDerivation"]["materialization"]["stageRoot"],
        "artifacts": artifact_map,
        "revisions": {
            f"{service}:{profile}": revision
            for (service, profile), revision in sorted(revisions.items())
        },
        "ports": {
            f"{service}:{profile}:{name}": port
            for (service, profile, name), port in sorted(ports.items())
        },
        "portProbeAttempts": {
            f"{service}:{profile}:{name}": attempt
            for (service, profile, name), attempt in sorted(probe_attempts.items())
        },
        "occupiedPortInputs": sorted(
            normalized_occupied,
            key=lambda item: (item["class"], item["port"], item["identityDigest"]),
        ),
        "validationBackupReceiptDigest": validation_backup_receipt_digest,
        "validationVolumeBindings": dict(sorted(validation_bindings.items())),
        "acceptedDataPromotionPending": any(
            artifact["dataPromotionPending"] for artifact in artifact_map
        ),
        "activation": "none-stage-only",
    }
    allocations = []
    for (service_id, profile, name), port in sorted(ports.items()):
        allocations.append(
            {
                "serviceId": service_id,
                "profile": profile,
                "portName": name,
                "revisionId": revisions[(service_id, profile)],
                "port": port,
                "probeAttempt": probe_attempts[(service_id, profile, name)],
            }
        )
    port_proposal: dict[str, Any] = {
        "schema": "stateport.revision-port-allocation-proposal/v1",
        "operationPlanDigest": operation_plan_digest,
        "releaseId": release.index.release_id,
        "signedPayloadDigest": release.index.signed_digest,
        "targetId": target["targetId"],
        "topologyDigest": target["topologyDigest"],
        "hostIdentityDigest": host_identity_digest,
        "rangeStart": policy["rangeStart"],
        "rangeEnd": policy["rangeEnd"],
        "inventoryDigests": dict(sorted(collision_inventory_digests.items())),
        "occupiedInputs": manifest["occupiedPortInputs"],
        "allocations": allocations,
        "proposedAt": proposed_at,
    }
    port_proposal["proposalDigest"] = revision_contract_digest(
        port_proposal, digest_field="proposalDigest"
    )
    validate_contract_document(
        port_proposal, expected_schema="stateport.revision-port-allocation-proposal/v1"
    )
    manifest["portAllocationProposalDigest"] = port_proposal["proposalDigest"]
    materialized[f"staged/{signed_hex}/materialization.json"] = (
        canonical_json_bytes(manifest) + b"\n"
    )
    materialized[f"staged/{signed_hex}/port-allocation.proposal.json"] = (
        canonical_json_bytes(port_proposal) + b"\n"
    )
    if validated_backup_document is not None:
        materialized[f"staged/{signed_hex}/validation-backup.receipt.json"] = (
            canonical_json_bytes(validated_backup_document) + b"\n"
        )
    if any(b"[Install]" in content or b"WantedBy=" in content for content in materialized.values()):
        raise ReleaseContractError("materialized candidate contains implicit boot activation")
    return materialized


def _canonical_embedded_document(files: Mapping[str, bytes], suffix: str) -> dict[str, Any]:
    matches = [content for path, content in files.items() if path.endswith(suffix)]
    if len(matches) != 1:
        raise ReleaseContractError(f"expected one exact embedded {suffix} document")
    try:
        value = json.loads(matches[0])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseContractError(f"embedded {suffix} document is unreadable") from exc
    if not isinstance(value, dict) or matches[0] != canonical_json_bytes(value) + b"\n":
        raise ReleaseContractError(f"embedded {suffix} document is not canonical")
    return value


def _reverify_staged_materialization(
    release: VerifiedRelease, staged: Mapping[str, bytes]
) -> tuple[dict[str, Any], Mapping[str, Any]]:
    """Re-derive every staged path and byte from signed templates plus typed receipts.

    Staging is deliberately not an authority boundary.  A caller may persist
    and reload the files, but every downstream transition replays this closure
    check before hashing or copying them into an accepted owner root.
    """

    if not isinstance(release, VerifiedRelease):
        raise ReleaseContractError("staged materialization requires a verified release")
    quadlet_bundle_digest(staged)
    manifest = _canonical_embedded_document(staged, "/materialization.json")
    proposal_value = _canonical_embedded_document(staged, "/port-allocation.proposal.json")
    proposal = validate_contract_document(
        proposal_value,
        expected_schema="stateport.revision-port-allocation-proposal/v1",
    ).document
    expected_manifest_fields = {
        "formatVersion",
        "operationPlanDigest",
        "releaseId",
        "signedPayloadDigest",
        "targetId",
        "topologyDigest",
        "signedTemplateBundleDigest",
        "stageRoot",
        "artifacts",
        "revisions",
        "ports",
        "portProbeAttempts",
        "occupiedPortInputs",
        "validationBackupReceiptDigest",
        "validationVolumeBindings",
        "acceptedDataPromotionPending",
        "activation",
        "portAllocationProposalDigest",
    }
    if set(manifest) != expected_manifest_fields:
        raise ReleaseContractError("staged materialization manifest fields are incomplete or extra")
    target = release.target
    expected_identity = {
        "releaseId": release.index.release_id,
        "signedPayloadDigest": release.index.signed_digest,
        "targetId": target["targetId"],
        "topologyDigest": target["topologyDigest"],
    }
    for document_name, document in (("staged manifest", manifest), ("port proposal", proposal)):
        if any(document.get(field) != expected for field, expected in expected_identity.items()):
            raise ReleaseContractError(f"{document_name} belongs to another verified release")
    if (
        manifest["formatVersion"] != "stateport.quadlet-materialization/v2"
        or manifest["stageRoot"] != target["runtimeDerivation"]["materialization"]["stageRoot"]
        or manifest["activation"] != "none-stage-only"
        or manifest["signedTemplateBundleDigest"] != target["quadletBundleDigest"]
        or _DIGEST.fullmatch(str(manifest["operationPlanDigest"])) is None
        or manifest["portAllocationProposalDigest"] != proposal["proposalDigest"]
        or proposal["operationPlanDigest"] != manifest["operationPlanDigest"]
    ):
        raise ReleaseContractError("staged materialization is not bound to its signed topology")

    images = release.index.document["signed"]["images"]
    templates = render_quadlet_bundle(target, images)
    if quadlet_bundle_digest(templates) != target["quadletBundleDigest"]:
        raise ReleaseContractError("signed Quadlet template digest is stale")
    template_manifest = json.loads(templates["materialization.template.json"])
    if (
        templates["materialization.template.json"]
        != canonical_json_bytes(template_manifest) + b"\n"
    ):
        raise ReleaseContractError("signed Quadlet template manifest is not canonical")
    image_by_id = {image["imageId"]: image for image in images}
    revisions: dict[tuple[str, str], str] = {}
    networks: dict[tuple[str, str], str] = {}
    for service in target["services"]:
        image = image_by_id[service["imageId"]]
        for profile in ("validation", "accepted"):
            revisions[(service["serviceId"], profile)] = _revision_id(
                release, service, image, profile
            )
            networks[(service["quadletOwner"], profile)] = canonical_digest(
                {
                    "formatVersion": "stateport.revision-network/v1",
                    "signedPayloadDigest": release.index.signed_digest,
                    "targetId": target["targetId"],
                    "owner": service["quadletOwner"],
                    "profile": profile,
                }
            ).removeprefix("sha256:")
    expected_revisions = {
        f"{service}:{profile}": revision
        for (service, profile), revision in sorted(revisions.items())
    }
    if manifest["revisions"] != expected_revisions:
        raise ReleaseContractError("staged materialization revisions are not signed derivations")

    policy = target["runtimeDerivation"]["portPolicy"]
    proposal_occupied = _thaw(proposal["occupiedInputs"])
    if (
        proposal["rangeStart"] != policy["rangeStart"]
        or proposal["rangeEnd"] != policy["rangeEnd"]
        or proposal_occupied != manifest["occupiedPortInputs"]
        or proposal_occupied
        != sorted(
            proposal_occupied,
            key=lambda item: (item["class"], item["port"], item["identityDigest"]),
        )
    ):
        raise ReleaseContractError("staged port proposal does not match signed allocation policy")
    used = {int(item["port"]) for item in proposal_occupied}
    range_start = int(policy["rangeStart"])
    span = int(policy["rangeEnd"]) - range_start + 1
    ports: dict[tuple[str, str, str], int] = {}
    probe_attempts: dict[tuple[str, str, str], int] = {}
    for service in sorted(target["services"], key=lambda item: item["serviceId"]):
        for profile in ("validation", "accepted"):
            revision = revisions[(service["serviceId"], profile)]
            for port in sorted(service["ports"], key=lambda item: item["name"]):
                seed = int(
                    hashlib.sha256(
                        f"{revision}\0{service['serviceId']}\0{profile}\0{port['name']}".encode()
                    ).hexdigest(),
                    16,
                )
                selected: int | None = None
                for attempt in range(policy["maximumAttempts"]):
                    candidate = range_start + (seed % span + attempt * policy["probeStep"]) % span
                    if candidate not in used:
                        selected = candidate
                        break
                if selected is None:
                    raise ReleaseContractError("staged deterministic port range is exhausted")
                used.add(selected)
                key = (service["serviceId"], profile, port["name"])
                ports[key] = selected
                probe_attempts[key] = attempt
    expected_allocations = [
        {
            "serviceId": service_id,
            "profile": profile,
            "portName": name,
            "revisionId": revisions[(service_id, profile)],
            "port": port,
            "probeAttempt": probe_attempts[(service_id, profile, name)],
        }
        for (service_id, profile, name), port in sorted(ports.items())
    ]
    expected_ports = {
        f"{service}:{profile}:{name}": port
        for (service, profile, name), port in sorted(ports.items())
    }
    expected_attempts = {
        f"{service}:{profile}:{name}": attempt
        for (service, profile, name), attempt in sorted(probe_attempts.items())
    }
    if (
        _thaw(proposal["allocations"]) != expected_allocations
        or manifest["ports"] != expected_ports
        or manifest["portProbeAttempts"] != expected_attempts
    ):
        raise ReleaseContractError("staged ports are not exact deterministic derivations")

    required_snapshot_keys = {
        revision_volume_key(target, str(service["serviceId"]), str(volume["name"]))
        for service in target["services"]
        for volume in service["writableVolumes"]
        if volume["validation"]["mode"] == "read-only-snapshot-copy"
    }
    backup_matches = [path for path in staged if path.endswith("/validation-backup.receipt.json")]
    validation_bindings: dict[str, str] = {}
    backup_document: Mapping[str, Any] | None = None
    if required_snapshot_keys:
        if len(backup_matches) != 1:
            raise ReleaseContractError("staged materialization lacks one exact validation backup")
        backup_value = _canonical_embedded_document(staged, "/validation-backup.receipt.json")
        backup_document = validate_contract_document(
            backup_value,
            expected_schema="stateport.revision-validation-backup-receipt/v1",
        ).document
        expected_backup_identity = {
            **expected_identity,
            "operationPlanDigest": manifest["operationPlanDigest"],
        }
        if any(
            backup_document.get(field) != expected
            for field, expected in expected_backup_identity.items()
        ):
            raise ReleaseContractError("staged validation backup belongs to another operation plan")
        if backup_document["receiptDigest"] != manifest["validationBackupReceiptDigest"]:
            raise ReleaseContractError("staged validation backup digest is stale")
        validation_bindings = {
            item["volumeKey"]: item["snapshotVolumeName"]
            for item in backup_document["volumeBindings"]
        }
        if set(validation_bindings) != required_snapshot_keys:
            raise ReleaseContractError(
                "staged validation backup does not bind the exact volume set"
            )
    elif (
        backup_matches
        or manifest["validationBackupReceiptDigest"] is not None
        or manifest["validationVolumeBindings"] != {}
    ):
        raise ReleaseContractError("staged materialization contains an unauthorized backup")
    if manifest["validationVolumeBindings"] != dict(sorted(validation_bindings.items())):
        raise ReleaseContractError("staged validation volume bindings drifted from their receipt")

    replacements = {"@@STATEPORT_SIGNED_PAYLOAD_DIGEST@@": release.index.signed_digest}
    for (service_id, profile), revision in revisions.items():
        replacements[f"@@STATEPORT_REVISION:{service_id}:{profile}@@"] = revision
    for (owner, profile), network in networks.items():
        replacements[f"@@STATEPORT_NETWORK:{owner}:{profile}@@"] = network
    for (service_id, profile, name), port in ports.items():
        replacements[f"@@STATEPORT_PORT:{service_id}:{profile}:{name}@@"] = str(port)
    for key, binding in validation_bindings.items():
        replacements[f"@@STATEPORT_VALIDATION_VOLUME:{key}@@"] = binding

    signed_hex = release.index.signed_digest.removeprefix("sha256:")
    expected_files: dict[str, bytes] = {}
    for template_path, content in templates.items():
        if template_path == "materialization.template.json":
            continue
        text = content.decode("utf-8")
        path = template_path
        for token, value in replacements.items():
            text = text.replace(token, value)
            path = path.replace(token, value)
        accepted_pending = "@@STATEPORT_ACCEPTED_DATA_VOLUME:" in text
        unresolved = [
            token
            for token in re.findall(r"@@STATEPORT_[^@]+@@", text + "\n" + path)
            if not token.startswith("@@STATEPORT_ACCEPTED_DATA_VOLUME:")
        ]
        if unresolved:
            raise ReleaseContractError(f"signed template could not be re-derived: {template_path}")
        relative = path.removeprefix("templates/").removesuffix(".in")
        if accepted_pending:
            relative += ".in"
        expected_files[f"staged/{signed_hex}/{relative}"] = text.encode("utf-8")

    expected_artifacts: list[dict[str, Any]] = []
    for artifact in template_manifest["artifacts"]:
        path = artifact["templatePath"]
        for token, value in replacements.items():
            path = path.replace(token, value)
        relative = path.removeprefix("templates/").removesuffix(".in")
        source_content = templates[artifact["templatePath"]].decode("utf-8")
        accepted_pending = "@@STATEPORT_ACCEPTED_DATA_VOLUME:" in source_content
        if accepted_pending:
            relative += ".in"
        expected_artifacts.append(
            {
                **artifact,
                "stagedPath": f"staged/{signed_hex}/{relative}",
                "liveRelativePath": "/".join(relative.removesuffix(".in").split("/")[1:]),
                "dataPromotionPending": accepted_pending,
            }
        )
    if manifest["artifacts"] != expected_artifacts or manifest[
        "acceptedDataPromotionPending"
    ] != any(item["dataPromotionPending"] for item in expected_artifacts):
        raise ReleaseContractError(
            "staged artifact inventory is not the signed template projection"
        )
    expected_files[f"staged/{signed_hex}/materialization.json"] = (
        canonical_json_bytes(manifest) + b"\n"
    )
    expected_files[f"staged/{signed_hex}/port-allocation.proposal.json"] = (
        canonical_json_bytes(proposal) + b"\n"
    )
    if backup_document is not None:
        expected_files[f"staged/{signed_hex}/validation-backup.receipt.json"] = (
            canonical_json_bytes(backup_document) + b"\n"
        )
    if set(staged) != set(expected_files):
        raise ReleaseContractError("staged materialization has missing or additional paths")
    for path, expected in expected_files.items():
        if staged[path] != expected:
            raise ReleaseContractError(f"staged materialization byte drift: {path}")
    return manifest, proposal


def _validate_runtime_name_lengths(files: Mapping[str, bytes]) -> None:
    for path, content in files.items():
        if len(PurePosixPath(path).name.encode("utf-8")) > 255:
            raise ReleaseContractError(f"runtime unit filename exceeds NAME_MAX: {path}")
        text = content.decode("utf-8")
        for field in ("ContainerName", "NetworkName", "VolumeName"):
            for match in re.finditer(rf"(?m)^{field}=([^\n]+)$", text):
                if len(match.group(1).encode("utf-8")) > 128:
                    raise ReleaseContractError(f"{field} exceeds StatePort's 128-byte bound")


def owner_materialization_spec_digest(
    release: VerifiedRelease,
    staged: Mapping[str, bytes],
    *,
    expected_accepted_data_generation: str,
) -> str:
    if re.fullmatch(r"data_[0-9a-f]{32}", expected_accepted_data_generation) is None:
        raise ReleaseContractError("owner materialization specification has an invalid D1")
    manifest, _proposal = _reverify_staged_materialization(release, staged)
    accepted_artifacts = [
        {
            "owner": item["owner"],
            "kind": item["kind"],
            "stagedPath": item["stagedPath"],
            "liveRelativePath": item["liveRelativePath"],
            "stagedContentDigest": "sha256:"
            + hashlib.sha256(staged[item["stagedPath"]]).hexdigest(),
        }
        for item in manifest["artifacts"]
        if item["profile"] == "accepted"
    ]
    return canonical_digest(
        {
            "formatVersion": "stateport.owner-materialization-spec/v1",
            "operationPlanDigest": manifest["operationPlanDigest"],
            "releaseId": release.index.release_id,
            "signedPayloadDigest": release.index.signed_digest,
            "targetId": release.target["targetId"],
            "topologyDigest": release.target["topologyDigest"],
            "expectedAcceptedDataGeneration": expected_accepted_data_generation,
            "portAllocationProposalDigest": manifest["portAllocationProposalDigest"],
            "artifacts": accepted_artifacts,
        }
    )


def reserve_revision_port_allocation(
    release: VerifiedRelease,
    staged: Mapping[str, bytes],
    *,
    activation_plan: Mapping[str, Any],
    reservation_receipt_digest: str,
    recheck_inventory_digest: str,
    rechecked_occupied_port_inputs: Sequence[Mapping[str, Any]],
    allocated_at: str,
    reservation_expires_at: str,
) -> dict[str, Any]:
    """Bind a pre-plan proposal to an approved plan after a host-local recheck."""

    plan = validate_contract_document(
        activation_plan, expected_schema="stateport.revision-activation-plan/v1"
    ).document
    _staged_manifest, proposal = _reverify_staged_materialization(release, staged)
    for label, digest in (
        ("reservation receipt", reservation_receipt_digest),
        ("recheck inventory", recheck_inventory_digest),
    ):
        if _DIGEST.fullmatch(digest) is None:
            raise ReleaseContractError(f"port {label} digest is invalid")
    normalized: list[dict[str, Any]] = []
    for position, item in enumerate(rechecked_occupied_port_inputs):
        if not isinstance(item, Mapping):
            raise ReleaseContractError(f"rechecked occupied port {position} is not typed")
        candidate = {
            "class": item.get("class"),
            "port": item.get("port"),
            "identityDigest": item.get("identityDigest"),
        }
        if candidate["class"] not in {
            "current",
            "predecessor",
            "candidate",
            "observed-host",
        }:
            raise ReleaseContractError("rechecked occupied port has an invalid class")
        if not isinstance(candidate["port"], int) or isinstance(candidate["port"], bool):
            raise ReleaseContractError("rechecked occupied port has an invalid port")
        if (
            not isinstance(candidate["identityDigest"], str)
            or _DIGEST.fullmatch(candidate["identityDigest"]) is None
        ):
            raise ReleaseContractError("rechecked occupied port lacks exact identity")
        normalized.append(candidate)
    allocated_ports = {item["port"] for item in proposal["allocations"]}
    if allocated_ports & {item["port"] for item in normalized}:
        raise ReleaseContractError("host-local port changed after approval; reservation refused")
    expected_identity = {
        "operationPlanDigest": _staged_manifest["operationPlanDigest"],
        "releaseId": release.index.release_id,
        "signedPayloadDigest": release.index.signed_digest,
        "targetId": release.target["targetId"],
        "topologyDigest": release.target["topologyDigest"],
    }
    for document_name, document in (("activation plan", plan), ("port proposal", proposal)):
        if any(document.get(field) != expected for field, expected in expected_identity.items()):
            raise ReleaseContractError(f"{document_name} belongs to another release")
    if plan["portAllocationProposalDigest"] != proposal["proposalDigest"]:
        raise ReleaseContractError("activation plan does not bind exact port proposal")
    receipt: dict[str, Any] = {
        "schema": "stateport.revision-port-allocation-receipt/v1",
        "activationPlanDigest": plan["planDigest"],
        "proposalDigest": proposal["proposalDigest"],
        "reservationReceiptDigest": reservation_receipt_digest,
        **expected_identity,
        "hostIdentityDigest": proposal["hostIdentityDigest"],
        "rangeStart": proposal["rangeStart"],
        "rangeEnd": proposal["rangeEnd"],
        "inventoryDigests": _thaw(proposal["inventoryDigests"]),
        "recheckInventoryDigest": recheck_inventory_digest,
        "occupiedInputs": sorted(
            normalized,
            key=lambda item: (item["class"], item["port"], item["identityDigest"]),
        ),
        "allocations": _thaw(proposal["allocations"]),
        "observedHostCollision": "refused-before-start",
        "allocatedAt": allocated_at,
        "reservationExpiresAt": reservation_expires_at,
        "result": "collision-free",
    }
    receipt["receiptDigest"] = revision_contract_digest(receipt, digest_field="receiptDigest")
    return _thaw(
        validate_contract_document(
            receipt, expected_schema="stateport.revision-port-allocation-receipt/v1"
        ).document
    )


def record_revision_port_activation_recheck(
    release: VerifiedRelease,
    *,
    activation_plan: Mapping[str, Any],
    port_allocation_receipt: Mapping[str, Any],
    observed_occupied_port_inputs: Sequence[Mapping[str, Any]],
    host_observation_receipt_digest: str,
    checked_at: str,
    valid_until: str,
) -> dict[str, Any]:
    """Record the bounded collision check performed immediately before effects."""

    if not isinstance(release, VerifiedRelease):
        raise ReleaseContractError("port activation recheck requires a verified release")
    plan = validate_contract_document(
        activation_plan, expected_schema="stateport.revision-activation-plan/v1"
    ).document
    port_receipt = validate_contract_document(
        port_allocation_receipt,
        expected_schema="stateport.revision-port-allocation-receipt/v1",
    ).document
    if _DIGEST.fullmatch(host_observation_receipt_digest) is None:
        raise ReleaseContractError("port activation recheck lacks a host observation receipt")
    expected_identity = {
        "operationPlanDigest": plan["operationPlanDigest"],
        "releaseId": release.index.release_id,
        "signedPayloadDigest": release.index.signed_digest,
        "targetId": release.target["targetId"],
        "topologyDigest": release.target["topologyDigest"],
    }
    for name, document in (("activation plan", plan), ("port receipt", port_receipt)):
        if any(document.get(field) != expected for field, expected in expected_identity.items()):
            raise ReleaseContractError(f"port recheck {name} belongs to another operation plan")
    if port_receipt["activationPlanDigest"] != plan["planDigest"]:
        raise ReleaseContractError("port recheck receipt names another activation plan")
    normalized: list[dict[str, Any]] = []
    for position, item in enumerate(observed_occupied_port_inputs):
        if not isinstance(item, Mapping):
            raise ReleaseContractError(f"activation port observation {position} is not typed")
        value = {
            "class": item.get("class"),
            "port": item.get("port"),
            "identityDigest": item.get("identityDigest"),
        }
        if value["class"] not in {
            "current",
            "predecessor",
            "candidate",
            "observed-host",
        }:
            raise ReleaseContractError("activation port observation has an invalid class")
        if (
            not isinstance(value["port"], int)
            or isinstance(value["port"], bool)
            or not isinstance(value["identityDigest"], str)
            or _DIGEST.fullmatch(value["identityDigest"]) is None
        ):
            raise ReleaseContractError("activation port observation has an invalid identity")
        normalized.append(value)
    if {item["port"] for item in port_receipt["allocations"]} & {
        item["port"] for item in normalized
    }:
        raise ReleaseContractError("activation port recheck observed a live collision")
    checked = _parse_timestamp(checked_at, "checkedAt")
    expires = _parse_timestamp(valid_until, "validUntil")
    reservation_expires = _parse_timestamp(
        port_receipt["reservationExpiresAt"], "reservationExpiresAt"
    )
    allocated = _parse_timestamp(port_receipt["allocatedAt"], "allocatedAt")
    if checked < allocated or expires > reservation_expires:
        raise ReleaseContractError("activation port recheck is outside its reservation lifetime")
    receipt: dict[str, Any] = {
        "schema": "stateport.revision-port-activation-recheck-receipt/v1",
        **expected_identity,
        "activationPlanDigest": plan["planDigest"],
        "portAllocationReceiptDigest": port_receipt["receiptDigest"],
        "hostIdentityDigest": port_receipt["hostIdentityDigest"],
        "allocations": _thaw(port_receipt["allocations"]),
        "occupiedInputs": sorted(
            normalized,
            key=lambda item: (item["class"], item["port"], item["identityDigest"]),
        ),
        "hostObservationReceiptDigest": host_observation_receipt_digest,
        "checkedAt": checked_at,
        "validUntil": valid_until,
        "result": "collision-free-immediate-pre-effect",
    }
    receipt["receiptDigest"] = revision_contract_digest(receipt, digest_field="receiptDigest")
    return _thaw(
        validate_contract_document(
            receipt,
            expected_schema="stateport.revision-port-activation-recheck-receipt/v1",
        ).document
    )


def materialize_accepted_quadlet_bundle(
    release: VerifiedRelease,
    staged: Mapping[str, bytes],
    *,
    data_promotion_spec: Mapping[str, Any],
    data_promotion_receipt: Mapping[str, Any],
    port_allocation_receipt: Mapping[str, Any],
) -> dict[str, bytes]:
    """Resolve accepted D1 volumes only after a typed promotion receipt exists."""

    if not isinstance(release, VerifiedRelease):
        raise ReleaseContractError("accepted materialization requires a verified release")
    staged_manifest, port_proposal = _reverify_staged_materialization(release, staged)
    port_receipt = validate_contract_document(
        port_allocation_receipt,
        expected_schema="stateport.revision-port-allocation-receipt/v1",
    ).document
    promotion = validate_contract_document(
        data_promotion_receipt,
        expected_schema="stateport.revision-data-promotion-receipt/v1",
    ).document
    promotion_spec = validate_contract_document(
        data_promotion_spec,
        expected_schema="stateport.revision-data-promotion-spec/v1",
    ).document
    expected_identity = {
        "operationPlanDigest": staged_manifest["operationPlanDigest"],
        "releaseId": release.index.release_id,
        "signedPayloadDigest": release.index.signed_digest,
        "targetId": release.target["targetId"],
        "topologyDigest": release.target["topologyDigest"],
    }
    for document_name, document in (
        ("staged materialization", staged_manifest),
        ("port proposal", port_proposal),
        ("port receipt", port_receipt),
        ("data-promotion receipt", promotion),
        ("data-promotion specification", promotion_spec),
    ):
        if any(document.get(field) != expected for field, expected in expected_identity.items()):
            raise ReleaseContractError(f"{document_name} belongs to another release revision")
    if port_receipt["activationPlanDigest"] != promotion["activationPlanDigest"]:
        raise ReleaseContractError("port allocation and data promotion name different plans")
    if staged_manifest.get("portAllocationProposalDigest") != port_proposal["proposalDigest"]:
        raise ReleaseContractError("staged materialization does not bind its port proposal")
    if port_receipt["proposalDigest"] != port_proposal["proposalDigest"]:
        raise ReleaseContractError("port reservation does not bind staged proposal")
    proposal_fields = (
        "hostIdentityDigest",
        "rangeStart",
        "rangeEnd",
        "allocations",
    )
    if any(port_receipt[field] != port_proposal[field] for field in proposal_fields):
        raise ReleaseContractError("port reservation changed its approved proposal")
    if promotion["promotionSpecDigest"] != promotion_spec["specDigest"]:
        raise ReleaseContractError("data-promotion receipt does not bind approved D1 spec")
    if promotion["acceptedDataGeneration"] != promotion_spec["expectedAcceptedDataGeneration"]:
        raise ReleaseContractError("data-promotion receipt produced an unplanned D1")
    if promotion["predecessorDataGeneration"] != promotion_spec["predecessorDataGeneration"]:
        raise ReleaseContractError("data-promotion receipt names an unplanned predecessor")
    predecessor_fields = (
        "predecessorPointerDigest",
        "predecessorReleaseId",
        "predecessorSignedPayloadDigest",
        "predecessorDataGeneration",
        "predecessorDataGenerationDigest",
    )
    if any(promotion[field] != promotion_spec[field] for field in predecessor_fields):
        raise ReleaseContractError("data-promotion receipt changed its exact predecessor source")
    data_bindings = {item["volumeKey"]: item["volumeName"] for item in promotion["volumeBindings"]}
    required_data_keys = {
        revision_volume_key(
            release.target, str(service["serviceId"]), str(volume["name"])
        )
        for service in release.target["services"]
        for volume in service["writableVolumes"]
        if volume["scope"] == "installation"
    }
    if set(data_bindings) != required_data_keys:
        raise ReleaseContractError("D1 receipt does not bind the exact accepted writable set")
    if set(promotion_spec["requiredVolumeKeys"]) != required_data_keys:
        raise ReleaseContractError("data-promotion spec does not bind the exact writable set")
    validation_names = set(staged_manifest["validationVolumeBindings"].values())
    if validation_names & set(data_bindings.values()):
        raise ReleaseContractError("validation data was promoted into the accepted revision")

    signed_hex = release.index.signed_digest.removeprefix("sha256:")
    accepted: dict[str, bytes] = {}
    artifacts: list[dict[str, Any]] = []
    for artifact in staged_manifest["artifacts"]:
        if artifact["profile"] != "accepted":
            continue
        source_path = artifact["stagedPath"]
        content = staged.get(source_path)
        if not isinstance(content, bytes):
            raise ReleaseContractError(f"accepted staged artifact is missing: {source_path}")
        text = content.decode("utf-8")
        for volume_key, volume_name in data_bindings.items():
            text = text.replace(f"@@STATEPORT_ACCEPTED_DATA_VOLUME:{volume_key}@@", volume_name)
        if "@@STATEPORT_" in text:
            raise ReleaseContractError("accepted artifact has unresolved authority tokens")
        live_relative = artifact["liveRelativePath"]
        accepted_path = f"accepted/{signed_hex}/{artifact['owner']}/{live_relative}"
        content_bytes = text.encode("utf-8")
        if b"[Install]" in content_bytes or b"WantedBy=" in content_bytes:
            raise ReleaseContractError("accepted Quadlet artifact contains boot activation")
        if accepted_path in accepted:
            raise ReleaseContractError("accepted materialization repeats an artifact path")
        accepted[accepted_path] = content_bytes
        artifacts.append(
            {
                "owner": artifact["owner"],
                "kind": artifact["kind"],
                "sourcePath": accepted_path,
                "liveRelativePath": live_relative,
                "contentDigest": "sha256:" + hashlib.sha256(content_bytes).hexdigest(),
            }
        )
    if not artifacts:
        raise ReleaseContractError("accepted materialization contains no artifacts")
    _validate_runtime_name_lengths(accepted)

    owner_bundle_digests: list[dict[str, str]] = []
    for owner in sorted({artifact["owner"] for artifact in artifacts}):
        owner_document: dict[str, Any] = {
            "schema": "stateport.revision-owner-bundle/v1",
            "owner": owner,
            "rootIdentity": release.target["runtimeDerivation"]["materialization"][
                "liveQuadletRoots"
            ][owner],
            **expected_identity,
            "profile": "accepted",
            "acceptedDataGeneration": promotion["acceptedDataGeneration"],
            "acceptedDataGenerationDigest": promotion["acceptedDataGenerationDigest"],
            "artifacts": [
                {
                    key: artifact[key]
                    for key in ("kind", "sourcePath", "liveRelativePath", "contentDigest")
                }
                for artifact in artifacts
                if artifact["owner"] == owner
            ],
            "reconciliationSteps": [
                "write-temporary-files",
                "fsync-files",
                "atomic-rename-within-owner-root",
                "fsync-owner-directory",
                "daemon-reload-owner",
            ],
            "crossUserAtomic": False,
        }
        owner_document["bundleDigest"] = revision_contract_digest(
            owner_document, digest_field="bundleDigest"
        )
        validate_contract_document(
            owner_document, expected_schema="stateport.revision-owner-bundle/v1"
        )
        accepted[f"accepted/{signed_hex}/owner-bundles/{owner}.json"] = (
            canonical_json_bytes(owner_document) + b"\n"
        )
        owner_bundle_digests.append({"owner": owner, "digest": owner_document["bundleDigest"]})
    accepted_manifest = {
        "formatVersion": "stateport.accepted-materialization/v1",
        **expected_identity,
        "activationPlanDigest": promotion["activationPlanDigest"],
        "acceptedDataGeneration": promotion["acceptedDataGeneration"],
        "acceptedDataGenerationDigest": promotion["acceptedDataGenerationDigest"],
        "dataPromotionReceiptDigest": promotion["receiptDigest"],
        "portAllocationReceiptDigest": port_receipt["receiptDigest"],
        "portAllocationProposalDigest": port_proposal["proposalDigest"],
        "ownerBundleDigests": owner_bundle_digests,
        "artifacts": artifacts,
        "revisionUnitProjectionDigest": canonical_digest(
            [
                {
                    "owner": item["owner"],
                    "kind": item["kind"],
                    "liveRelativePath": item["liveRelativePath"],
                    "contentDigest": item["contentDigest"],
                }
                for item in artifacts
            ]
        ),
        "ownerMaterializationSpecDigest": owner_materialization_spec_digest(
            release,
            staged,
            expected_accepted_data_generation=promotion["acceptedDataGeneration"],
        ),
        "validationDataDisposition": "discarded-not-promoted",
        "crossUserReconciliation": "ordered-per-owner-never-claimed-atomic",
        "activation": "none-until-durable-decision",
    }
    accepted[f"accepted/{signed_hex}/accepted-materialization.json"] = (
        canonical_json_bytes(accepted_manifest) + b"\n"
    )
    return accepted


def validate_activation_pointer_transition(
    current_pointer: Mapping[str, Any] | None,
    successor_pointer: Mapping[str, Any],
) -> ValidatedContract:
    """Refuse replay, skipped generations, and torn pointer projections."""

    successor = validate_contract_document(
        successor_pointer, expected_schema="stateport.revision-activation-pointer/v1"
    )
    if current_pointer is None:
        if successor.document["previousGeneration"] != 0:
            raise ReleaseContractError("initial activation pointer skips generation zero")
        return successor
    current = validate_contract_document(
        current_pointer, expected_schema="stateport.revision-activation-pointer/v1"
    )
    if successor.document["generation"] <= current.document["generation"]:
        raise ReleaseContractError("activation pointer replay or downgrade refused")
    if successor.document["previousGeneration"] != current.document["generation"]:
        raise ReleaseContractError("activation pointer generation has a torn transition")
    if successor.document["previousPointerDigest"] != current.document["pointerDigest"]:
        raise ReleaseContractError("activation pointer predecessor digest has a torn transition")
    return successor


def _validated_authority_proof(
    value: Mapping[str, Any],
    *,
    phase: str,
    expected_identity: Mapping[str, Any],
) -> Mapping[str, Any]:
    proof = validate_contract_document(
        value, expected_schema="stateport.revision-authority-proof/v1"
    ).document
    if proof["phase"] != phase:
        raise ReleaseContractError(f"activation authority proof is not the {phase} phase")
    if any(proof.get(field) != expected for field, expected in expected_identity.items()):
        raise ReleaseContractError(f"activation authority {phase} proof names another operation")
    return proof


def _authority_document_digest(value: Mapping[str, Any]) -> str:
    """Reproduce the canonical digest used by the private authority store."""

    return "sha256:" + hashlib.sha256(_authority_document_bytes(value)).hexdigest()


def _authority_document_bytes(value: Mapping[str, Any]) -> bytes:
    """Reproduce the exact canonical bytes stored by the authority subsystem."""

    try:
        return json.dumps(
            _thaw(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ReleaseContractError("canonical authority document is not serializable") from exc


def _parse_authority_timestamp(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ReleaseContractError(f"{path}: authority timestamp must be UTC")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise ReleaseContractError(f"{path}: authority timestamp is invalid") from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ReleaseContractError(f"{path}: authority timestamp must be UTC")
    return parsed


def derive_revision_authority_proofs(
    source_documents: Mapping[str, Mapping[str, Any]],
    *,
    resolver: AuthoritySourceResolver,
    operation_plan_digest: str,
    release_id: str,
    signed_payload_digest: str,
    target_id: str,
    topology_digest_value: str,
) -> dict[str, dict[str, Any]]:
    """Validate canonical authority-store documents and derive bounded proofs.

    The proof objects are projections, not authority by themselves.  Callers
    must provide the exact reservation, claim, and terminal receipt loaded
    from the canonical private authority store.  Every source digest and link
    is re-derived here before the projection can be admitted.
    """

    if set(source_documents) != {"reservation", "claim", "receipt"}:
        raise ReleaseContractError(
            "revision activation requires exact reservation, claim, and receipt documents"
        )
    if any(
        _DIGEST.fullmatch(value) is None
        for value in (operation_plan_digest, signed_payload_digest, topology_digest_value)
    ):
        raise ReleaseContractError("revision authority source identity is invalid")
    reservation = _thaw(source_documents["reservation"])
    claim = _thaw(source_documents["claim"])
    receipt = _thaw(source_documents["receipt"])
    reservation_fields = {
        "schema",
        "reservationId",
        "requestId",
        "decision",
        "reservedAt",
        "reservationDigest",
    }
    claim_fields = {
        "schema",
        "claimId",
        "requestId",
        "reservationId",
        "reservationDigest",
        "decisionDigest",
        "claimedAt",
        "claimDigest",
    }
    receipt_fields = {
        "schema",
        "receiptId",
        "requestId",
        "action",
        "actorId",
        "authorizedBy",
        "scope",
        "profile",
        "configuredPolicy",
        "policy",
        "decision",
        "result",
        "startedAt",
        "completedAt",
        "estimatedCostUsd",
        "actualCostUsd",
        "decisionDigest",
        "reservation",
        "claim",
        "receiptDigest",
    }
    if (
        set(reservation) != reservation_fields
        or set(claim) != claim_fields
        or set(receipt) != receipt_fields
    ):
        raise ReleaseContractError("revision authority source document fields are not canonical")
    decision = reservation.get("decision")
    if not isinstance(decision, Mapping):
        raise ReleaseContractError("revision authority reservation lacks its canonical decision")
    decision = _thaw(decision)
    decision_fields = {
        "schema",
        "requestId",
        "action",
        "actorId",
        "authorizedBy",
        "scope",
        "profile",
        "configuredPolicy",
        "policy",
        "decision",
        "reason",
        "missingAssurances",
        "estimatedCostUsd",
        "estimatedDurationSeconds",
        "requestedCapabilities",
        "decidedAt",
        "decisionDigest",
    }
    if set(decision) != decision_fields:
        raise ReleaseContractError("revision authority decision fields are not canonical")
    digest_checks = (
        (decision, "decisionDigest"),
        (reservation, "reservationDigest"),
        (claim, "claimDigest"),
        (receipt, "receiptDigest"),
    )
    for document, field in digest_checks:
        body = {key: value for key, value in document.items() if key != field}
        if document[field] != _authority_document_digest(body):
            raise ReleaseContractError(f"canonical authority {field} is stale or tampered")
    request_id = decision.get("requestId")
    if (
        not isinstance(request_id, str)
        or re.fullmatch(r"authority_request_[0-9a-f]{32}", request_id) is None
    ):
        raise ReleaseContractError("canonical authority request identity is invalid")
    suffix = request_id.removeprefix("authority_request_")
    reservation_id = f"authority_reservation_{suffix}"
    claim_id = f"authority_claim_{suffix}"
    if not callable(getattr(resolver, "resolve_revision_authority", None)):
        raise ReleaseContractError("canonical authority resolver is required")
    try:
        resolved = resolver.resolve_revision_authority(
            request_id=request_id,
            reservation_id=reservation_id,
            claim_id=claim_id,
            receipt_id=str(receipt.get("receiptId", "")),
        )
    except Exception as exc:
        raise ReleaseContractError("canonical authority store lookup failed closed") from exc
    if not isinstance(resolved, Mapping) or set(resolved) != {
        "reservation",
        "claim",
        "receipt",
    }:
        raise ReleaseContractError("canonical authority store returned an incomplete chain")
    for name, supplied in source_documents.items():
        canonical = resolved.get(name)
        if not isinstance(canonical, Mapping) or _authority_document_bytes(
            canonical
        ) != _authority_document_bytes(supplied):
            raise ReleaseContractError(
                f"caller {name} differs from protected canonical authority store"
            )
    scope = decision.get("scope")
    authorized_by = decision.get("authorizedBy")
    if not isinstance(scope, Mapping) or not isinstance(authorized_by, Mapping):
        raise ReleaseContractError("canonical authority decision lacks typed scope or grant")
    expected_scope = {
        "applicationId": release_id,
        "sliceId": target_id,
        "runId": operation_plan_digest,
    }
    if any(scope.get(field) != expected for field, expected in expected_scope.items()):
        raise ReleaseContractError("canonical authority decision names another release operation")
    if (
        decision.get("schema") != "stateport.authority-decision/v1"
        or decision.get("action") != "apply_deployment"
        or decision.get("decision") != "authorized"
        or decision.get("policy") not in {"auto_and_notify", "auto_with_receipt"}
        or authorized_by.get("type") != "grant"
        or not isinstance(authorized_by.get("id"), str)
        or re.fullmatch(r"grant_[A-Za-z0-9._:-]{3,127}", authorized_by["id"]) is None
        or _DIGEST.fullmatch(str(authorized_by.get("digest"))) is None
    ):
        raise ReleaseContractError("canonical authority decision is not an executable grant")
    if (
        reservation["schema"] != "stateport.authority-action-reservation/v1"
        or reservation["requestId"] != request_id
        or reservation["reservationId"] != reservation_id
        or reservation["decision"] != decision
        or claim["schema"] != "stateport.authority-action-claim/v1"
        or claim["requestId"] != request_id
        or claim["reservationId"] != reservation_id
        or claim["reservationDigest"] != reservation["reservationDigest"]
        or claim["decisionDigest"] != decision["decisionDigest"]
        or claim["claimId"] != claim_id
    ):
        raise ReleaseContractError("canonical authority reservation/claim chain is torn")
    expected_resource = {
        "operationPlanDigest": operation_plan_digest,
        "releaseId": release_id,
        "signedPayloadDigest": signed_payload_digest,
        "targetId": target_id,
        "topologyDigest": topology_digest_value,
    }
    result = receipt.get("result")
    resource = result.get("resource") if isinstance(result, Mapping) else None
    if (
        receipt["schema"] != "stateport.authority-action-receipt/v1"
        or receipt["requestId"] != request_id
        or receipt["action"] != decision["action"]
        or receipt["actorId"] != decision["actorId"]
        or receipt["authorizedBy"] != decision["authorizedBy"]
        or receipt["scope"] != decision["scope"]
        or receipt["decision"] != "authorized"
        or receipt["decisionDigest"] != decision["decisionDigest"]
        or receipt["reservation"]
        != {
            "reservationId": reservation_id,
            "reservationDigest": reservation["reservationDigest"],
        }
        or receipt["claim"] != {"claimId": claim_id, "claimDigest": claim["claimDigest"]}
        or not isinstance(result, Mapping)
        or result.get("status") != "succeeded"
        or not isinstance(resource, Mapping)
        or any(resource.get(field) != expected for field, expected in expected_resource.items())
    ):
        raise ReleaseContractError(
            "canonical authority terminal receipt is not exact activation proof"
        )
    reserved_at = _parse_authority_timestamp(reservation["reservedAt"], "authority.reservedAt")
    claimed_at = _parse_authority_timestamp(claim["claimedAt"], "authority.claimedAt")
    started_at = _parse_authority_timestamp(receipt["startedAt"], "authority.startedAt")
    completed_at = _parse_authority_timestamp(receipt["completedAt"], "authority.completedAt")
    if not reserved_at <= claimed_at <= started_at <= completed_at:
        raise ReleaseContractError("canonical authority source timeline is torn")
    identity = {
        "action": "apply_deployment",
        "operationPlanDigest": operation_plan_digest,
        "releaseId": release_id,
        "signedPayloadDigest": signed_payload_digest,
        "targetId": target_id,
        "topologyDigest": topology_digest_value,
        "actorId": decision["actorId"],
        "grantId": authorized_by["id"],
        "requestId": request_id,
        "reservationId": reservation_id,
        "reservationDigest": reservation["reservationDigest"],
    }
    source_by_phase = {
        "reservation": reservation,
        "claim": claim,
        "finalize": receipt,
    }
    phase_fields = {
        "reservation": {
            "sourceSchema": reservation["schema"],
            "claimId": None,
            "claimDigest": None,
            "receiptId": None,
            "receiptDigest": None,
            "result": "reserved",
        },
        "claim": {
            "sourceSchema": claim["schema"],
            "claimId": claim_id,
            "claimDigest": claim["claimDigest"],
            "receiptId": None,
            "receiptDigest": None,
            "result": "claimed",
        },
        "finalize": {
            "sourceSchema": receipt["schema"],
            "claimId": claim_id,
            "claimDigest": claim["claimDigest"],
            "receiptId": receipt["receiptId"],
            "receiptDigest": receipt["receiptDigest"],
            "result": "finalized",
        },
    }
    proofs: dict[str, dict[str, Any]] = {}
    for phase, fields in phase_fields.items():
        proof: dict[str, Any] = {
            "schema": "stateport.revision-authority-proof/v1",
            "phase": phase,
            "sourceDocumentDigest": _authority_document_digest(source_by_phase[phase]),
            **fields,
            **identity,
        }
        proof["proofDigest"] = revision_contract_digest(proof, digest_field="proofDigest")
        proofs[phase] = _thaw(
            validate_contract_document(
                proof, expected_schema="stateport.revision-authority-proof/v1"
            ).document
        )
    return proofs


def render_accepted_activation(
    release: VerifiedRelease,
    accepted_materialized: Mapping[str, bytes],
    *,
    activation_plan: Mapping[str, Any],
    activation_decision: Mapping[str, Any],
    terminal_acceptance_receipt: Mapping[str, Any],
    data_promotion_receipt: Mapping[str, Any],
    port_allocation_receipt: Mapping[str, Any],
    port_activation_recheck_receipt: Mapping[str, Any],
    authority_source_documents: Mapping[str, Mapping[str, Any]],
    authority_source_resolver: AuthoritySourceResolver,
    current_pointer: Mapping[str, Any] | None,
    route_projection_digest: str,
    written_at: str,
) -> dict[str, bytes]:
    """Render one stable regular systemd activation target from durable R1."""

    if not isinstance(release, VerifiedRelease):
        raise ReleaseContractError("activation requires a verified release")
    if _DIGEST.fullmatch(route_projection_digest) is None:
        raise ReleaseContractError("activation route projection digest is invalid")
    written = _parse_timestamp(written_at, "writtenAt")
    accepted_manifest = _canonical_embedded_document(
        accepted_materialized, "/accepted-materialization.json"
    )
    plan = validate_contract_document(
        activation_plan, expected_schema="stateport.revision-activation-plan/v1"
    ).document
    decision = validate_contract_document(
        activation_decision, expected_schema="stateport.revision-activation-decision/v1"
    ).document
    terminal = validate_contract_document(
        terminal_acceptance_receipt,
        expected_schema="stateport.revision-terminal-acceptance-receipt/v1",
    ).document
    promotion = validate_contract_document(
        data_promotion_receipt,
        expected_schema="stateport.revision-data-promotion-receipt/v1",
    ).document
    port_receipt = validate_contract_document(
        port_allocation_receipt,
        expected_schema="stateport.revision-port-allocation-receipt/v1",
    ).document
    port_recheck = validate_contract_document(
        port_activation_recheck_receipt,
        expected_schema="stateport.revision-port-activation-recheck-receipt/v1",
    ).document
    owner_bundles: list[Mapping[str, Any]] = []
    for path, content in accepted_materialized.items():
        if "/owner-bundles/" not in path or not path.endswith(".json"):
            continue
        value = json.loads(content)
        if content != canonical_json_bytes(value) + b"\n":
            raise ReleaseContractError("owner bundle is not canonical")
        owner_bundles.append(
            validate_contract_document(
                value, expected_schema="stateport.revision-owner-bundle/v1"
            ).document
        )
        for artifact in owner_bundles[-1]["artifacts"]:
            source = accepted_materialized.get(artifact["sourcePath"])
            if not isinstance(source, bytes):
                raise ReleaseContractError("owner bundle source artifact is missing")
            observed = "sha256:" + hashlib.sha256(source).hexdigest()
            if observed != artifact["contentDigest"]:
                raise ReleaseContractError("owner bundle source artifact digest is stale")
    owner_digests = sorted(
        ({"owner": item["owner"], "digest": item["bundleDigest"]} for item in owner_bundles),
        key=lambda item: item["owner"],
    )
    expected_identity = {
        "operationPlanDigest": plan["operationPlanDigest"],
        "releaseId": release.index.release_id,
        "signedPayloadDigest": release.index.signed_digest,
        "targetId": release.target["targetId"],
        "topologyDigest": release.target["topologyDigest"],
    }
    for document_name, document in (
        ("accepted materialization", accepted_manifest),
        ("activation plan", plan),
        ("activation decision", decision),
        ("terminal acceptance receipt", terminal),
        ("data-promotion receipt", promotion),
        ("port-allocation receipt", port_receipt),
        ("port-activation recheck receipt", port_recheck),
    ):
        if any(document.get(field) != expected for field, expected in expected_identity.items()):
            raise ReleaseContractError(f"{document_name} belongs to another release revision")
    if plan["promotionSpecDigest"] != promotion["promotionSpecDigest"]:
        raise ReleaseContractError("activation plan does not bind exact D1 promotion spec")
    if plan["expectedAcceptedDataGeneration"] != promotion["acceptedDataGeneration"]:
        raise ReleaseContractError("activation plan expected a different D1")
    if (
        accepted_manifest["acceptedDataGenerationDigest"]
        != promotion["acceptedDataGenerationDigest"]
    ):
        raise ReleaseContractError("accepted units do not bind exact D1 content")
    if plan["portAllocationProposalDigest"] != accepted_manifest["portAllocationProposalDigest"]:
        raise ReleaseContractError("activation plan does not bind exact port proposal")
    if (
        plan["ownerMaterializationSpecDigest"]
        != accepted_manifest["ownerMaterializationSpecDigest"]
    ):
        raise ReleaseContractError("activation plan does not bind owner materialization spec")
    if plan["signatureVerificationProofSetDigest"] != (
        signature_verification_proof_set_digest(release)
    ):
        raise ReleaseContractError("activation plan does not bind historic signature admission")
    if promotion["activationPlanDigest"] != plan["planDigest"]:
        raise ReleaseContractError("D1 promotion receipt names another activation plan")
    if port_receipt["activationPlanDigest"] != plan["planDigest"]:
        raise ReleaseContractError("port reservation receipt names another activation plan")
    if decision["activationPlanDigest"] != plan["planDigest"]:
        raise ReleaseContractError("activation decision names another activation plan")
    if decision["dataPromotionReceiptDigest"] != promotion["receiptDigest"]:
        raise ReleaseContractError("activation decision does not bind exact D1 receipt")
    if decision["portAllocationReceiptDigest"] != port_receipt["receiptDigest"]:
        raise ReleaseContractError("activation decision does not bind exact port reservation")
    if (
        decision["portActivationRecheckReceiptDigest"] != port_recheck["receiptDigest"]
        or terminal["portActivationRecheckReceiptDigest"] != port_recheck["receiptDigest"]
    ):
        raise ReleaseContractError("activation does not bind the immediate port recheck")
    if (
        port_recheck["activationPlanDigest"] != plan["planDigest"]
        or port_recheck["portAllocationReceiptDigest"] != port_receipt["receiptDigest"]
        or port_recheck["hostIdentityDigest"] != port_receipt["hostIdentityDigest"]
        or _thaw(port_recheck["allocations"]) != _thaw(port_receipt["allocations"])
    ):
        raise ReleaseContractError("activation port recheck changed the reserved allocation")
    if sorted(decision["ownerBundleDigests"], key=lambda item: item["owner"]) != owner_digests:
        raise ReleaseContractError("activation decision does not bind exact per-user owner bundles")
    if decision["acceptedDataGeneration"] != promotion["acceptedDataGeneration"]:
        raise ReleaseContractError("activation decision does not bind exact D1")
    if decision["acceptedDataGenerationDigest"] != promotion["acceptedDataGenerationDigest"]:
        raise ReleaseContractError("activation decision does not bind exact D1 content")
    if decision["pointerGeneration"] != plan["newPointerGeneration"]:
        raise ReleaseContractError("activation decision pointer generation disagrees with plan CAS")
    if accepted_manifest["dataPromotionReceiptDigest"] != promotion["receiptDigest"]:
        raise ReleaseContractError("accepted units do not bind exact D1 promotion receipt")
    if accepted_manifest["portAllocationReceiptDigest"] != port_receipt["receiptDigest"]:
        raise ReleaseContractError("accepted units do not bind exact port allocation receipt")
    if accepted_manifest["ownerBundleDigests"] != owner_digests:
        raise ReleaseContractError("accepted units do not bind exact owner bundle inventory")
    if decision["signatureVerificationProofSetDigest"] != (
        signature_verification_proof_set_digest(release)
    ):
        raise ReleaseContractError("activation decision lacks exact historic signature proof set")
    if (
        decision["revisionUnitProjectionDigest"]
        != accepted_manifest["revisionUnitProjectionDigest"]
    ):
        raise ReleaseContractError("activation decision does not bind exact unit projection")
    if decision["routeProjectionDigest"] != route_projection_digest:
        raise ReleaseContractError("activation decision does not bind exact route projection")
    terminal_bindings = {
        "activationPlanDigest": plan["planDigest"],
        "activationDecisionDigest": decision["decisionDigest"],
        "pointerGeneration": plan["newPointerGeneration"],
        "acceptedDataGeneration": promotion["acceptedDataGeneration"],
        "acceptedDataGenerationDigest": promotion["acceptedDataGenerationDigest"],
        "ownerBundleDigests": owner_digests,
        "revisionUnitProjectionDigest": accepted_manifest["revisionUnitProjectionDigest"],
        "routeProjectionDigest": route_projection_digest,
    }
    if any(
        _thaw(terminal[field]) != _thaw(expected) for field, expected in terminal_bindings.items()
    ):
        raise ReleaseContractError("terminal acceptance does not bind prepared activation")

    authority_identity = {
        **expected_identity,
    }
    reservation_proof = _validated_authority_proof(
        decision["authorityReservationProof"],
        phase="reservation",
        expected_identity=authority_identity,
    )
    claim_proof = _validated_authority_proof(
        decision["authorityClaimProof"],
        phase="claim",
        expected_identity=authority_identity,
    )
    finalize_proof = _validated_authority_proof(
        terminal["authorityFinalizeProof"],
        phase="finalize",
        expected_identity=authority_identity,
    )
    canonical_authority_proofs = derive_revision_authority_proofs(
        authority_source_documents,
        resolver=authority_source_resolver,
        operation_plan_digest=plan["operationPlanDigest"],
        release_id=release.index.release_id,
        signed_payload_digest=release.index.signed_digest,
        target_id=release.target["targetId"],
        topology_digest_value=release.target["topologyDigest"],
    )
    if (
        _thaw(reservation_proof) != canonical_authority_proofs["reservation"]
        or _thaw(claim_proof) != canonical_authority_proofs["claim"]
        or _thaw(finalize_proof) != canonical_authority_proofs["finalize"]
    ):
        raise ReleaseContractError(
            "activation authority projection differs from canonical source documents"
        )
    chain_fields = (
        "actorId",
        "grantId",
        "requestId",
        "reservationId",
        "reservationDigest",
    )
    if any(
        reservation_proof[field] != claim_proof[field]
        or claim_proof[field] != finalize_proof[field]
        for field in chain_fields
    ):
        raise ReleaseContractError("activation authority reservation/claim/finalize chain is torn")
    if (
        claim_proof["claimId"] != finalize_proof["claimId"]
        or claim_proof["claimDigest"] != finalize_proof["claimDigest"]
    ):
        raise ReleaseContractError("activation authority claim identity changed before finalize")

    previous_generation = 0
    previous_digest: str | None = None
    if current_pointer is not None:
        current = validate_contract_document(
            current_pointer, expected_schema="stateport.revision-activation-pointer/v1"
        ).document
        previous_generation = int(current["generation"])
        previous_digest = str(current["pointerDigest"])
    if plan["expectedPointerGeneration"] != previous_generation:
        raise ReleaseContractError("activation plan CAS observed a different current generation")
    expected_predecessor_decision = None if current_pointer is None else current["decisionDigest"]
    if (
        decision["predecessorPointerDigest"] != previous_digest
        or decision["predecessorDecisionDigest"] != expected_predecessor_decision
    ):
        raise ReleaseContractError("activation decision predecessor binding is stale")
    expected_promotion_predecessor = {
        "predecessorPointerDigest": None if current_pointer is None else current["pointerDigest"],
        "predecessorReleaseId": None if current_pointer is None else current["releaseId"],
        "predecessorSignedPayloadDigest": (
            None if current_pointer is None else current["signedPayloadDigest"]
        ),
        "predecessorDataGeneration": (
            None if current_pointer is None else current["acceptedDataGeneration"]
        ),
        "predecessorDataGenerationDigest": (
            None if current_pointer is None else current["acceptedDataGenerationDigest"]
        ),
    }
    if any(
        promotion[field] != expected for field, expected in expected_promotion_predecessor.items()
    ):
        raise ReleaseContractError("data promotion predecessor does not match accepted pointer")
    allocated = _parse_timestamp(port_receipt["allocatedAt"], "allocatedAt")
    reservation_expires = _parse_timestamp(
        port_receipt["reservationExpiresAt"], "reservationExpiresAt"
    )
    checked = _parse_timestamp(port_recheck["checkedAt"], "checkedAt")
    recheck_expires = _parse_timestamp(port_recheck["validUntil"], "validUntil")
    decided = _parse_timestamp(decision["decidedAt"], "decidedAt")
    accepted_at = _parse_timestamp(terminal["acceptedAt"], "acceptedAt")
    if not (
        allocated <= checked <= decided <= accepted_at <= written < recheck_expires
        and written < reservation_expires
        and recheck_expires <= reservation_expires
    ):
        raise ReleaseContractError(
            "activation requires an unexpired immediate pre-effect port reservation recheck"
        )
    pointer: dict[str, Any] = {
        "schema": "stateport.revision-activation-pointer/v1",
        "generation": plan["newPointerGeneration"],
        "previousGeneration": previous_generation,
        "previousPointerDigest": previous_digest,
        "operationPlanDigest": plan["operationPlanDigest"],
        "decisionDigest": decision["decisionDigest"],
        "terminalAcceptanceReceiptDigest": terminal["receiptDigest"],
        "dataPromotionReceiptDigest": promotion["receiptDigest"],
        **expected_identity,
        "acceptedDataGeneration": promotion["acceptedDataGeneration"],
        "acceptedDataGenerationDigest": promotion["acceptedDataGenerationDigest"],
        "activationTarget": "stateport-accepted.target",
        "routeProjectionDigest": route_projection_digest,
        "ownerBundleDigests": owner_digests,
        "state": "accepted",
        "writtenAt": written_at,
    }
    pointer["pointerDigest"] = revision_contract_digest(pointer, digest_field="pointerDigest")
    validate_activation_pointer_transition(current_pointer, pointer)

    units = sorted(
        artifact["liveRelativePath"].removesuffix(".container") + ".service"
        for owner_bundle in owner_bundles
        for artifact in owner_bundle["artifacts"]
        if artifact["kind"] == "container"
    )
    if not units:
        raise ReleaseContractError("accepted activation has no service units")
    if len(units) != len(set(units)):
        raise ReleaseContractError("accepted activation repeats a generated service unit")
    decision_short = decision["decisionDigest"].removeprefix("sha256:")[:16]
    target_bytes = (
        "[Unit]\n"
        "Description=StatePort accepted revision activation\n"
        "\n[Install]\n"
        "WantedBy=default.target\n"
    ).encode("utf-8")
    dropin_bytes = (
        "[Unit]\n"
        f"Description=StatePort accepted decision {decision_short}\n"
        "Wants=\n"
        "After=\n"
        f"Wants={' '.join(units)}\n"
        f"After={' '.join(units)}\n"
    ).encode("utf-8")
    write_plan = {
        "formatVersion": "stateport.activation-write-projection/v1",
        "regularSystemdRoot": release.target["runtimeDerivation"]["materialization"][
            "regularSystemdRoot"
        ],
        "decisionDigest": decision["decisionDigest"],
        "pointerDigest": pointer["pointerDigest"],
        "target": "stateport-accepted.target",
        "dropIn": "stateport-accepted.target.d/10-stateport-activation.conf",
        "routeProjectionDigest": route_projection_digest,
        "preTerminalOrder": [
            "persist-activation-decision-r1",
            "verify-owner-bundle-reconciliation-receipts",
            "write-target-dropin-route-temporaries",
            "fsync-projection-files",
            "atomic-rename-within-control-user-root",
            "fsync-control-user-root",
            "daemon-reload",
            "explicit-start-observe-stop",
        ],
        "terminalOrder": [
            "finalize-authority-claim",
            "persist-terminal-acceptance-receipt",
            "fsync-terminal-acceptance-receipt",
        ],
        "postTerminalOrder": [
            "compare-and-swap-pointer",
            "switch-ingress-and-unfence",
        ],
        "terminalAcceptanceReceiptDigest": terminal["receiptDigest"],
        "portActivationRecheckReceiptDigest": port_recheck["receiptDigest"],
        "crashRecovery": "structural-effect-reconciliation-only-never-remint-expired-activation",
        "sequencingGuarantee": "pointer-and-ingress-after-terminal-acceptance-only",
        "crossUserAtomicity": "not-claimed-owner-receipts-required",
    }
    result = {
        "activation/stateport-accepted.target": target_bytes,
        "activation/stateport-accepted.target.d/10-stateport-activation.conf": dropin_bytes,
        "activation/stateport-accepted.current.json": canonical_json_bytes(pointer) + b"\n",
        "activation/activation-decision.receipt.json": canonical_json_bytes(decision) + b"\n",
        "activation/terminal-acceptance.receipt.json": canonical_json_bytes(terminal) + b"\n",
        "activation/activation-write-plan.json": canonical_json_bytes(write_plan) + b"\n",
    }
    _validate_runtime_name_lengths(result)
    return result


def verify_quadlet_bundle(
    files: Mapping[str, bytes],
    release: VerifiedRelease | UpdaterReleaseEnvelope,
) -> str:
    if isinstance(release, VerifiedRelease):
        target = release.target
        images = release.index.document["signed"]["images"]
    elif isinstance(release, UpdaterReleaseEnvelope):
        target = release.document["target"]
        images = release.document["images"]
    else:
        raise ReleaseContractError("Quadlet verification requires a verified release")
    expected_files = render_quadlet_bundle(target, images)
    if set(files) != set(expected_files):
        raise ReleaseContractError(
            "Quadlet bundle inventory does not match deterministic signed topology"
        )
    for name, expected_content in expected_files.items():
        if files.get(name) != expected_content:
            raise ReleaseContractError(
                f"Quadlet bundle bytes do not match deterministic signed topology: {name}"
            )
    observed = quadlet_bundle_digest(files)
    expected = target.get("quadletBundleDigest")
    if observed != expected:
        raise ReleaseContractError(
            "Quadlet bundle content digest does not match signed target authority"
        )
    return observed


def signed_payload_bytes(index: Mapping[str, Any] | ReleaseIndex) -> bytes:
    if isinstance(index, ReleaseIndex):
        return index.signed_bytes
    signed = index.get("signed") if isinstance(index, Mapping) else None
    if not isinstance(signed, Mapping):
        raise ReleaseContractError("release index has no signed payload")
    return canonical_json_bytes(signed)


def _object_without_duplicates(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ReleaseContractError(f"duplicate JSON object key: {key!r}")
        value[key] = item
    return value


def _parse_document(content: bytes | str) -> dict[str, Any]:
    raw = content.encode("utf-8") if isinstance(content, str) else content
    if not isinstance(raw, bytes):
        raise ReleaseContractError("release index input must be UTF-8 bytes or text")
    if len(raw) > MAX_INDEX_BYTES:
        raise ReleaseContractError("release index exceeds the 4 MiB limit")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ReleaseContractError("release index must not contain a UTF-8 BOM")
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_float=lambda _value: (_ for _ in ()).throw(
                ReleaseContractError("floating-point JSON values are forbidden")
            ),
            parse_constant=lambda value: (_ for _ in ()).throw(
                ReleaseContractError(f"non-finite JSON value is forbidden: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseContractError("release index must be valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ReleaseContractError("release index must be a JSON object")
    _validate_canonical_value(value)
    return value


def _schema_issues(value: Any, schema: Mapping[str, Any]) -> list[str]:
    root = schema

    def resolve(reference: str) -> Mapping[str, Any] | None:
        if not reference.startswith("#/$defs/"):
            return None
        found = root.get("$defs", {}).get(reference.removeprefix("#/$defs/"))
        return found if isinstance(found, Mapping) else None

    def type_matches(item: Any, expected: str) -> bool:
        return {
            "object": isinstance(item, dict),
            "array": isinstance(item, list),
            "string": isinstance(item, str),
            "boolean": isinstance(item, bool),
            "integer": isinstance(item, int) and not isinstance(item, bool),
            "number": isinstance(item, (int, float)) and not isinstance(item, bool),
            "null": item is None,
        }.get(expected, False)

    def check(item: Any, current: Mapping[str, Any], path: str) -> list[str]:
        reference = current.get("$ref")
        if isinstance(reference, str):
            resolved = resolve(reference)
            return (
                [f"{path}: unsupported schema reference {reference}"]
                if resolved is None
                else check(item, resolved, path)
            )
        issues: list[str] = []
        expected = current.get("type")
        if isinstance(expected, str) and not type_matches(item, expected):
            return [f"{path}: expected {expected}, got {type(item).__name__}"]
        if isinstance(expected, list) and not any(
            type_matches(item, choice) for choice in expected
        ):
            return [f"{path}: expected one of {expected}, got {type(item).__name__}"]
        if "const" in current and item != current["const"]:
            issues.append(f"{path}: expected constant {current['const']!r}")
        if "enum" in current and item not in current["enum"]:
            issues.append(f"{path}: expected one of {current['enum']}")
        if isinstance(item, str):
            if isinstance(current.get("minLength"), int) and len(item) < current["minLength"]:
                issues.append(f"{path}: string is too short")
            if isinstance(current.get("maxLength"), int) and len(item) > current["maxLength"]:
                issues.append(f"{path}: string is too long")
            pattern = current.get("pattern")
            if isinstance(pattern, str) and re.search(pattern, item) is None:
                issues.append(f"{path}: string does not match {pattern!r}")
        if isinstance(item, int) and not isinstance(item, bool):
            if isinstance(current.get("minimum"), int) and item < current["minimum"]:
                issues.append(f"{path}: integer is below minimum")
            if isinstance(current.get("maximum"), int) and item > current["maximum"]:
                issues.append(f"{path}: integer exceeds maximum")
        if isinstance(item, list):
            if isinstance(current.get("minItems"), int) and len(item) < current["minItems"]:
                issues.append(f"{path}: array has too few items")
            if isinstance(current.get("maxItems"), int) and len(item) > current["maxItems"]:
                issues.append(f"{path}: array has too many items")
            if current.get("uniqueItems") is True:
                encoded = [canonical_json_bytes(entry) for entry in item]
                if len(encoded) != len(set(encoded)):
                    issues.append(f"{path}: array items must be unique")
            nested = current.get("items")
            if isinstance(nested, Mapping):
                for index, entry in enumerate(item):
                    issues.extend(check(entry, nested, f"{path}[{index}]"))
        if isinstance(item, dict):
            if (
                isinstance(current.get("minProperties"), int)
                and len(item) < current["minProperties"]
            ):
                issues.append(f"{path}: object has too few properties")
            required = current.get("required")
            if isinstance(required, list):
                issues.extend(
                    f"{path}: missing required property {key!r}"
                    for key in required
                    if key not in item
                )
            properties = current.get("properties")
            properties = properties if isinstance(properties, Mapping) else {}
            for key, nested in properties.items():
                if key in item and isinstance(nested, Mapping):
                    issues.extend(check(item[key], nested, f"{path}.{key}"))
            additional = current.get("additionalProperties", True)
            for key, nested_value in item.items():
                if key in properties:
                    continue
                if additional is False:
                    issues.append(f"{path}.{key}: additional property is forbidden")
                elif isinstance(additional, Mapping):
                    issues.extend(check(nested_value, additional, f"{path}.{key}"))
        one_of = current.get("oneOf")
        if isinstance(one_of, list):
            matches = sum(
                not check(item, branch, path) for branch in one_of if isinstance(branch, Mapping)
            )
            if matches != 1:
                issues.append(f"{path}: expected exactly one matching schema branch")
        return issues

    return check(value, root, "$")


def _zip_schema_bytes(schema_path: Path) -> bytes | None:
    """Read a schema from a zip-imported wheel when no real filesystem path exists.

    The installer authenticates and imports the release-contract wheel directly
    from its zip archive (``sys.path`` on the wheel) before any pip install, so
    ``__file__``-relative schema reads would point at a path that does not exist
    on disk.  Under a ``zipimporter`` the schema is a zip member instead, and
    ``loader.get_data`` reads it without extracting the wheel.
    """
    import sys
    import zipimport

    module = sys.modules.get(__name__)
    loader = getattr(module, "__loader__", None)
    if not isinstance(loader, zipimport.zipimporter):
        return None
    archive_root = Path(getattr(loader, "archive", "") or "")
    try:
        relative = schema_path.resolve().relative_to(archive_root.resolve())
    except ValueError:
        return None
    try:
        data = loader.get_data(relative.as_posix())
    except OSError:
        return None
    if not isinstance(data, bytes):
        return None
    return data


def _load_schema(schema_path: Path) -> dict[str, Any]:
    if schema_path.is_symlink() or not schema_path.is_file():
        schema_bytes = _zip_schema_bytes(schema_path)
        if schema_bytes is None:
            raise ReleaseContractError(f"release schema is unavailable: {schema_path}")
    else:
        try:
            schema_bytes = schema_path.read_bytes()
        except OSError as exc:
            raise ReleaseContractError("release schema is unreadable") from exc
    try:
        value = json.loads(schema_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseContractError("release schema is unreadable") from exc
    if not isinstance(value, dict):
        raise ReleaseContractError("release schema must be an object")
    return value


def validate_contract_document(
    document: Mapping[str, Any],
    *,
    expected_schema: str,
    schema_directory: Path = SCHEMA_DIRECTORY,
) -> ValidatedContract:
    """Validate a packaged install/update/provenance document and digest it."""

    filename = _CONTRACT_SCHEMAS.get(expected_schema)
    if filename is None:
        raise ReleaseContractError(f"unsupported contract schema: {expected_schema}")
    if not isinstance(document, Mapping):
        raise ReleaseContractError(f"{expected_schema} document must be a mapping")
    value = _thaw(document)
    _validate_canonical_value(value)
    if value.get("schema") != expected_schema and not (
        expected_schema == "stateport.release-provenance/v1"
        and value.get("_type") == "https://in-toto.io/Statement/v1"
    ):
        raise ReleaseContractError(f"document does not declare {expected_schema}")
    issues = _schema_issues(value, _load_schema(schema_directory / filename))
    if issues:
        raise ReleaseContractError(f"{expected_schema} schema validation failed: {issues[0]}")
    _validate_contract_cross_fields(value, expected_schema)
    return ValidatedContract(_freeze(value), canonical_digest(value))


def _validate_update_policy_state(policy: Mapping[str, Any]) -> None:
    if policy["policyDigest"] != update_policy_digest(policy):
        raise ReleaseContractError("update policy digest does not match its exact state")
    scheduled_mode = policy["mode"] in {"scheduled", "automatic-with-rollback"}
    if scheduled_mode != (policy["schedule"] is not None):
        raise ReleaseContractError("update policy schedule does not match its mode")
    download_mode = policy["mode"] in {
        "download-and-notify",
        "scheduled",
        "automatic-with-rollback",
    }
    if policy["downloadAhead"] != download_mode:
        raise ReleaseContractError("update policy download-ahead state does not match its mode")
    retention = policy["retention"]
    if (
        retention["maximumVersions"]
        < 1 + retention["acceptedPredecessors"] + retention["failedSuccessors"]
    ):
        raise ReleaseContractError(
            "update retention cannot keep current, predecessor, and failed evidence"
        )


def _validate_contract_cross_fields(value: Mapping[str, Any], schema: str) -> None:
    if schema == "stateport.update-plan/v1":
        created = _parse_timestamp(value["createdAt"], "createdAt")
        if len(value["steps"]) != len(set(value["steps"])):
            raise ReleaseContractError("update plan steps must not repeat")
        expected_steps = _UPDATE_STEPS if value["operation"] == "update" else _ROLLBACK_STEPS
        if tuple(value["steps"]) != expected_steps:
            raise ReleaseContractError(
                "update plan does not contain the complete ordered safe step sequence"
            )
        if value["successor"]["signedPayloadDigest"] != value["signedPayloadDigest"]:
            raise ReleaseContractError("update plan successor and signed payload digests disagree")
        for label in ("current", "successor"):
            release = value[label]
            _semver_key(release["version"])
            if release["qualification"] == "candidate" and release["publishedAt"] is not None:
                raise ReleaseContractError(f"{label} candidate cannot claim publication time")
            if release["qualification"] == "published" and release["publishedAt"] is None:
                raise ReleaseContractError(f"{label} published release requires publication time")
            if release["publishedAt"] is not None:
                _parse_timestamp(release["publishedAt"], f"{label}.publishedAt")
        if value["operation"] == "update" and _semver_key(
            value["successor"]["version"]
        ) <= _semver_key(value["current"]["version"]):
            raise ReleaseContractError("update successor must be newer than current")
        if value["operation"] == "rollback" and _semver_key(
            value["successor"]["version"]
        ) >= _semver_key(value["current"]["version"]):
            raise ReleaseContractError("rollback successor must be older than current")
        policy = value["policy"]
        _validate_update_policy_state(policy)
        if policy["channel"] != value["successor"]["channel"]:
            raise ReleaseContractError("update policy channel does not match successor channel")
        compatibility = value["compatibility"]
        if not all(
            compatibility[key]
            for key in ("updaterCompatible", "migrationCompatible", "rollbackCompatible")
        ):
            raise ReleaseContractError("update plan cannot proceed with failed compatibility gates")
        if compatibility["downgrade"] != (value["operation"] == "rollback"):
            raise ReleaseContractError("update plan downgrade flag disagrees with operation")
        rollback = value["rollback"]
        if not rollback["dataCompatible"] or not rollback["retainedPredecessor"]:
            raise ReleaseContractError("update plan lacks a data-compatible retained rollback")
        if rollback["automaticOnFailure"] != (value["operation"] == "update"):
            raise ReleaseContractError(
                "forward updates must automatically roll back failed accepted-route checks"
            )
        expires = _parse_timestamp(value["expiresAt"], "expiresAt")
        if expires <= created:
            raise ReleaseContractError("update plan expiry must be after creation")
        expected_digest = update_plan_digest(value)
        if value["planDigest"] != expected_digest:
            raise ReleaseContractError("update plan digest does not match its canonical payload")
        expected_id = f"update_plan_{expected_digest.removeprefix('sha256:')[:32]}"
        if value["planId"] != expected_id:
            raise ReleaseContractError("update plan ID does not derive from its canonical digest")
        if value["authority"]["runId"] != expected_digest:
            raise ReleaseContractError("authority run ID must equal the exact update plan digest")
        expected_action = "apply_update" if value["operation"] == "update" else "rollback_update"
        if value["authority"]["action"] != expected_action:
            raise ReleaseContractError("authority action does not match update plan operation")
    elif schema in {"stateport.update-receipt/v1", "stateport.install-receipt/v1"}:
        started = _parse_timestamp(value["startedAt"], "startedAt")
        finished = _parse_timestamp(value["finishedAt"], "finishedAt")
        if finished < started:
            raise ReleaseContractError("receipt finished before it started")
        if schema == "stateport.update-receipt/v1":
            if value["authority"]["planDigest"] != value["planDigest"]:
                raise ReleaseContractError(
                    "authority reference is not bound to the update plan digest"
                )
            if value["authority"]["runId"] != value["planDigest"]:
                raise ReleaseContractError("authority run ID is not the exact update plan digest")
            if value["authority"]["scope"]["runId"] != value["planDigest"]:
                raise ReleaseContractError("authority scope is not bound to the update plan digest")
            expected_action = (
                "apply_update" if value["operation"] == "update" else "rollback_update"
            )
            if value["authority"]["action"] != expected_action:
                raise ReleaseContractError(
                    "authority action does not match update receipt operation"
                )
            rollback = value["rollback"]
            if rollback["succeeded"] and not rollback["attempted"]:
                raise ReleaseContractError("rollback cannot succeed without being attempted")
            if value["result"] == "accepted" and value["accepted"] != value["attempted"]:
                raise ReleaseContractError("accepted update must bind the attempted release")
            if value["result"] == "rolled_back" and value["accepted"] != value["from"]:
                raise ReleaseContractError("rolled-back update must retain the predecessor")
        else:
            _semver_key(value["installer"]["version"])
            _semver_key(value["release"]["version"])
            _semver_key(value["host"]["podmanVersion"])
            target = value["target"]
            target_payload = dict(target)
            target_payload.pop("targetDigest")
            if target["targetDigest"] != canonical_digest(target_payload):
                raise ReleaseContractError(
                    "install target digest does not match its exact identity"
                )
            runtime = value["runtime"]
            runtime_payload = dict(runtime)
            runtime_payload.pop("runtimeIdentityDigest")
            if runtime["runtimeIdentityDigest"] != canonical_digest(runtime_payload):
                raise ReleaseContractError("runtime identity digest is stale or tampered")
            expected_runtime = {
                "releaseId": value["release"]["releaseId"],
                "releaseIndexDigest": value["releaseIndexDigest"],
                "signedPayloadDigest": value["release"]["signedPayloadDigest"],
                "targetDigest": target["targetDigest"],
                "topologyDigest": target["topologyDigest"],
                "quadletArtifactDigest": target["quadletArtifactDigest"],
                "quadletBundleDigest": target["quadletBundleDigest"],
                "imageSetDigest": target["imageSetDigest"],
                "serviceSetDigest": target["serviceSetDigest"],
            }
            for field, expected in expected_runtime.items():
                if runtime[field] != expected:
                    raise ReleaseContractError(
                        f"runtime {field} disagrees with verified target identity"
                    )
            verification = value["verification"]
            signed_index = verification["signedIndex"]
            signer_modes: set[str] = set()
            for signer_position, signer in enumerate(verification["signers"]):
                descriptor = dict(signer)
                signer_modes.add(str(signer["trustMode"]))
                if descriptor.get("trustMode") == "pinned-public-key":
                    descriptor["transparencyLog"] = "not-uploaded-private-candidate"
                else:
                    descriptor["transparencyLog"] = (
                        "required-public-release"
                        if descriptor.get("transparencyLogStatus") == "verified"
                        else "not-uploaded-private-candidate"
                    )
                _signature_trust_identity(
                    descriptor, context=f"verification.signers[{signer_position}]"
                )
                _parse_timestamp(
                    signer["verifiedAt"], f"verification.signers[{signer_position}].verifiedAt"
                )
            if len(signer_modes) != 1:
                raise ReleaseContractError("install receipt mixes signature trust modes")
            if signed_index["expectedDigest"] != value["releaseIndexDigest"]:
                raise ReleaseContractError(
                    "signed-index verification is not bound to the release index"
                )
            artifact_by_id = {
                artifact["artifactId"]: artifact for artifact in verification["artifacts"]
            }
            legacy_receipt = (
                value["release"]["releaseId"] == _LEGACY_PREDECESSOR_RELEASE_ID
                and value["release"]["version"] == _LEGACY_PREDECESSOR_VERSION
                and value["release"]["signedPayloadDigest"]
                == _LEGACY_PREDECESSOR_SIGNED_DIGEST
                and value["releaseIndexDigest"] == _LEGACY_PREDECESSOR_INDEX_DIGEST
            )
            expected_artifacts = _release_artifact_ids(
                str(value["release"]["version"]), legacy=legacy_receipt
            )
            if set(artifact_by_id) != expected_artifacts:
                raise ReleaseContractError(
                    "install receipt artifact inventory is incomplete or duplicated"
                )
            package_installation = value.get("podmanPackageInstallation")
            if "podmanPackageBundle" in expected_artifacts:
                if not isinstance(package_installation, Mapping):
                    raise ReleaseContractError(
                        "install receipt lacks signed Podman package installation evidence"
                    )
                package_artifact = artifact_by_id["podmanPackageBundle"]
                package_records = package_installation["packages"]
                transaction = package_installation["transaction"]
                requires_confined_runtime = (
                    value["release"]["version"] == "0.1.0-alpha.15"
                    or "stateport-crun" in package_records
                )
                required_package_names = (
                    _PODMAN_PACKAGE_NAMES
                    if requires_confined_runtime
                    else _LEGACY_PODMAN_PACKAGE_NAMES
                )
                expected_package_runtime = {
                    "podmanMinimumVersion": "5.4.2",
                    "runcMinimumVersion": "1.3.4",
                    "slirp4netnsMinimumVersion": "1.2.1",
                    "ociRuntime": "runc",
                    "networkBackend": "netavark",
                }
                if requires_confined_runtime:
                    expected_package_runtime.update(
                        {
                            "supplementaryGroupRuntime": "crun",
                            "supplementaryGroupRuntimePath": CONFINED_GROUP_OCI_RUNTIME_PATH,
                            "supplementaryGroupRuntimeVersion": CONFINED_GROUP_OCI_RUNTIME_VERSION,
                            "supplementaryGroupRuntimeSha256": CONFINED_GROUP_OCI_RUNTIME_SHA256,
                        }
                    )
                package_plan = {
                    "releaseIndexDigest": package_installation["releaseIndexDigest"],
                    "signedPayloadDigest": package_installation["signedPayloadDigest"],
                    "artifactDigest": package_installation["artifactDigest"],
                    "bundleManifestDigest": package_installation["bundleManifestDigest"],
                    "targetId": package_installation["targetId"],
                    "rootfsIdentity": package_installation["rootfsIdentity"],
                    "dependencyClosure": package_installation["dependencyClosure"],
                    "transaction": transaction,
                    "packages": {
                        name: {
                            "architecture": package_records[name]["architecture"],
                            "version": package_records[name]["version"],
                            "sha256": package_records[name]["bundleSha256"],
                            "size": package_records[name]["bundleSize"],
                        }
                        for name in sorted(package_records)
                    },
                    "runtimeContract": expected_package_runtime,
                }
                installed_state = {
                    name: {
                        "architecture": package_records[name]["architecture"],
                        "version": package_records[name]["version"],
                    }
                    for name in sorted(package_records)
                }
                if (
                    package_installation["releaseIndexDigest"] != value["releaseIndexDigest"]
                    or package_installation["signedPayloadDigest"]
                    != value["release"]["signedPayloadDigest"]
                    or package_installation["artifactDigest"]
                    != package_artifact["expectedDigest"]
                    or package_artifact["observedDigest"] != package_artifact["expectedDigest"]
                    or package_artifact.get("mediaType")
                    not in {None, "application/vnd.stateport.podman-package-bundle+tar"}
                    or package_installation["targetId"] != target["targetId"]
                    or not required_package_names <= set(package_records)
                    or set(transaction) != set(package_records)
                    or package_installation["changedPackages"]
                    != sorted(
                        name
                        for name, action in transaction.items()
                        if action["action"] != "keep"
                    )
                    or package_installation["dpkgStateBeforeDigest"]
                    != canonical_digest(transaction)
                    or package_installation["dpkgStateAfterDigest"]
                    != canonical_digest(installed_state)
                    or package_installation["packagePlanDigest"]
                    != canonical_digest(package_plan)
                    or package_installation["dependencies"]["runc"]["minimumVersion"]
                    != "1.3.4"
                    or package_installation["dependencies"]["slirp4netns"][
                        "minimumVersion"
                    ]
                    != "1.2.1"
                    or (
                        requires_confined_runtime
                        and (
                            package_installation["dependencies"]["stateport-crun"][
                                "minimumVersion"
                            ]
                            != CONFINED_GROUP_OCI_RUNTIME_VERSION
                            or package_installation["runtime"]
                            != {
                                "ociRuntime": "runc",
                                "networkBackend": "netavark",
                                "supplementaryGroupRuntime": "crun",
                                "supplementaryGroupRuntimePath": CONFINED_GROUP_OCI_RUNTIME_PATH,
                                "supplementaryGroupRuntimeVersion": CONFINED_GROUP_OCI_RUNTIME_VERSION,
                                "supplementaryGroupRuntimeSha256": CONFINED_GROUP_OCI_RUNTIME_SHA256,
                            }
                        )
                    )
                    or (
                        not requires_confined_runtime
                        and package_installation["runtime"]
                        != {"ociRuntime": "runc", "networkBackend": "netavark"}
                    )
                    or re.match(
                        rf"^{re.escape(value['host']['podmanVersion'])}(?:[+~]|$)",
                        package_installation["packages"]["podman"]["version"],
                    )
                    is None
                ):
                    raise ReleaseContractError(
                        "Podman package installation evidence disagrees with the verified release or host"
                    )
            elif package_installation is not None:
                raise ReleaseContractError(
                    "install receipt carries Podman package evidence for a release without that artifact"
                )
            if artifact_by_id["installer"]["expectedDigest"] != value["installer"]["digest"]:
                raise ReleaseContractError(
                    "installer verification is not bound to the executing installer"
                )
            if artifact_by_id["quadlet"]["expectedDigest"] != target["quadletArtifactDigest"]:
                raise ReleaseContractError(
                    "Quadlet artifact verification disagrees with target identity"
                )
            image_by_id = {image["imageId"]: image for image in verification["images"]}
            if len(image_by_id) != len(verification["images"]):
                raise ReleaseContractError("install receipt contains duplicate image identities")
            for image in verification["images"]:
                if image["reference"].rsplit("@", 1)[-1] != image["expectedDigest"]:
                    raise ReleaseContractError(
                        "verified image reference and expected digest disagree"
                    )
            proof_by_subject = {
                (proof["subjectKind"], proof["subjectId"]): proof
                for proof in verification["signers"]
            }
            if len(proof_by_subject) != len(verification["signers"]):
                raise ReleaseContractError("install receipt repeats a signature verification proof")
            expected_proof_subjects = {
                ("release-index", "release-index"),
                *(("image", image_id) for image_id in image_by_id),
            }
            if set(proof_by_subject) != expected_proof_subjects:
                raise ReleaseContractError(
                    "install receipt signature proof inventory is incomplete"
                )
            release_proof = proof_by_subject[("release-index", "release-index")]
            if release_proof["subjectDigest"] != value["release"]["signedPayloadDigest"]:
                raise ReleaseContractError("release signature proof names another signed payload")
            for image_id, image in image_by_id.items():
                proof = proof_by_subject[("image", image_id)]
                if proof["subjectDigest"] != image["expectedDigest"]:
                    raise ReleaseContractError("image signature proof names another image digest")
                if proof["bundleDigest"] != image["signatureBundleDigest"]:
                    raise ReleaseContractError("image signature proof bundle is not retained")
            if target["imageSetDigest"] != image_set_digest(verification["images"]):
                raise ReleaseContractError("install image-set digest is stale or incomplete")
            if target["serviceSetDigest"] != service_set_digest(runtime["services"]):
                raise ReleaseContractError("install service-set digest is stale or incomplete")
            for service in runtime["services"]:
                image = image_by_id.get(service["imageId"])
                if image is None or service["imageDigest"] != image["expectedDigest"]:
                    raise ReleaseContractError("runtime service is not bound to a verified image")
            authority = value["authority"]
            operation = value["operation"]
            if operation in {"install", "reinstall"}:
                if authority.get("kind") != "installer-directive":
                    raise ReleaseContractError(
                        "install and reinstall require an exact installer directive"
                    )
                if authority["installerDigest"] != value["installer"]["digest"]:
                    raise ReleaseContractError("installer directive names a different installer")
                if authority["releaseIndexDigest"] != value["releaseIndexDigest"]:
                    raise ReleaseContractError(
                        "installer directive names a different release index"
                    )
                if authority["planDigest"] != value["installPlanDigest"]:
                    raise ReleaseContractError("installer directive names a different install plan")
                if authority["directiveDigest"] != installer_directive_digest(authority):
                    raise ReleaseContractError("installer directive digest is stale or tampered")
                _parse_timestamp(authority["confirmedAt"], "authority.confirmedAt")
            else:
                if authority.get("kind") != "stateport-authority":
                    raise ReleaseContractError(
                        "installed lifecycle operation requires StatePort authority"
                    )
                expected_action = {
                    "uninstall": "uninstall_release",
                    "purge": "purge_release_data",
                }[operation]
                if authority["action"] != expected_action:
                    raise ReleaseContractError(
                        "authority action does not match install lifecycle operation"
                    )
                if authority["planDigest"] != value["installPlanDigest"]:
                    raise ReleaseContractError("authority reference names a different install plan")
                if authority["runId"] != value["installPlanDigest"]:
                    raise ReleaseContractError(
                        "authority run ID must equal the exact install plan digest"
                    )
                if authority["scope"]["runId"] != value["installPlanDigest"]:
                    raise ReleaseContractError(
                        "authority scope is not bound to the install plan digest"
                    )
            disposition = value["dataDisposition"]
            allowed_dispositions = {
                "install": {"created", "preserved", "restored"},
                "reinstall": {"created", "preserved", "restored"},
                "uninstall": {"preserved", "not_applicable"},
                "purge": {"purged"},
            }
            if disposition not in allowed_dispositions[operation]:
                raise ReleaseContractError(
                    "data disposition contradicts install lifecycle operation"
                )
            if value["result"] == "succeeded":
                verification_items = [
                    signed_index,
                    *verification["artifacts"],
                    *verification["images"],
                ]
                if any(item["status"] != "verified" for item in verification_items):
                    raise ReleaseContractError(
                        "successful install receipt contains failed verification"
                    )
                if any(
                    item["expectedDigest"] != item["observedDigest"] for item in verification_items
                ):
                    raise ReleaseContractError(
                        "successful install receipt contains digest mismatch"
                    )
                if any(signer["status"] != "verified" for signer in verification["signers"]):
                    raise ReleaseContractError(
                        "successful install receipt contains unverified signer"
                    )
                if not runtime["healthy"] or any(
                    not service["healthy"] for service in runtime["services"]
                ):
                    raise ReleaseContractError(
                        "successful install receipt requires healthy runtime services"
                    )
    elif schema == "stateport.update-status/v1":
        _parse_timestamp(value["updatedAt"], "updatedAt")
        _validate_update_policy_state(value["policy"])
        if value["phase"] == "idle" and value["stagedSuccessor"] is not None:
            raise ReleaseContractError("idle update status cannot retain a staged successor")
    elif schema == "stateport.update-failure-evidence/v1":
        _parse_timestamp(value["observedAt"], "observedAt")
    elif schema == "stateport.update-authority-link/v1":
        _parse_timestamp(value["linkedAt"], "linkedAt")
        if value["runId"] != value["planDigest"]:
            raise ReleaseContractError("final authority link run ID must equal the plan digest")
        if value["authority"]["runId"] != value["planDigest"]:
            raise ReleaseContractError("final authority receipt run ID must equal the plan digest")
        if value["authority"]["planDigest"] != value["planDigest"]:
            raise ReleaseContractError("final authority receipt is not bound to the plan digest")
        if value["authority"]["scope"]["runId"] != value["planDigest"]:
            raise ReleaseContractError("final authority link scope is not bound to the plan digest")
    elif schema == "stateport.release-provenance/v1":
        predicate = value["predicate"]
        started = _parse_timestamp(predicate["runDetails"]["metadata"]["startedOn"], "startedOn")
        finished = _parse_timestamp(predicate["runDetails"]["metadata"]["finishedOn"], "finishedOn")
        if finished < started:
            raise ReleaseContractError("provenance build finished before it started")
    elif schema == "stateport.revision-activation-plan/v1":
        expected = revision_contract_digest(value, digest_field="planDigest", id_field="planId")
        if value["planDigest"] != expected:
            raise ReleaseContractError("revision activation plan digest is stale or tampered")
        if value["planId"] != f"revision_activation_plan_{expected[7:39]}":
            raise ReleaseContractError("revision activation plan ID is not digest-derived")
        if value["newPointerGeneration"] != value["expectedPointerGeneration"] + 1:
            raise ReleaseContractError("revision activation plan is not an exact CAS successor")
        if tuple(value["steps"]) != _REVISION_PROMOTE_STEPS:
            raise ReleaseContractError("revision activation plan steps are incomplete or reordered")
    elif schema == "stateport.revision-activation-decision/v1":
        expected = revision_contract_digest(
            value, digest_field="decisionDigest", id_field="decisionId"
        )
        if value["decisionDigest"] != expected:
            raise ReleaseContractError("revision activation decision digest is stale or tampered")
        if value["decisionId"] != f"revision_activation_decision_{expected[7:39]}":
            raise ReleaseContractError("revision activation decision ID is not digest-derived")
        _parse_timestamp(value["decidedAt"], "decidedAt")
        owners = [item["owner"] for item in value["ownerBundleDigests"]]
        if len(owners) != len(set(owners)):
            raise ReleaseContractError("revision activation decision repeats an owner bundle")
        initial = value["pointerGeneration"] == 1
        if initial != (
            value["predecessorPointerDigest"] is None and value["predecessorDecisionDigest"] is None
        ):
            raise ReleaseContractError("activation decision predecessor binding is inconsistent")
        validate_contract_document(
            value["authorityReservationProof"],
            expected_schema="stateport.revision-authority-proof/v1",
        )
        validate_contract_document(
            value["authorityClaimProof"],
            expected_schema="stateport.revision-authority-proof/v1",
        )
    elif schema == "stateport.revision-activation-pointer/v1":
        expected = revision_contract_digest(value, digest_field="pointerDigest")
        if value["pointerDigest"] != expected:
            raise ReleaseContractError("revision activation pointer digest is stale or torn")
        if value["generation"] != value["previousGeneration"] + 1:
            raise ReleaseContractError(
                "revision activation pointer generation is not a CAS successor"
            )
        if (value["previousGeneration"] == 0) != (value["previousPointerDigest"] is None):
            raise ReleaseContractError(
                "revision activation pointer predecessor binding is inconsistent"
            )
        _parse_timestamp(value["writtenAt"], "writtenAt")
        owners = [item["owner"] for item in value["ownerBundleDigests"]]
        if len(owners) != len(set(owners)):
            raise ReleaseContractError("revision activation pointer repeats an owner bundle")
    elif schema == "stateport.revision-owner-bundle/v1":
        expected = revision_contract_digest(value, digest_field="bundleDigest")
        if value["bundleDigest"] != expected:
            raise ReleaseContractError("revision owner bundle digest is stale or tampered")
        if value["owner"] != "stateport-control" or value["rootIdentity"] != (
            "xdg-config-containers-systemd"
        ):
            raise ReleaseContractError("revision owner bundle crosses its logical owner root")
        expected_steps = (
            "write-temporary-files",
            "fsync-files",
            "atomic-rename-within-owner-root",
            "fsync-owner-directory",
            "daemon-reload-owner",
        )
        if tuple(value["reconciliationSteps"]) != expected_steps:
            raise ReleaseContractError("revision owner reconciliation is incomplete or reordered")
        paths = [artifact["liveRelativePath"] for artifact in value["artifacts"]]
        if len(paths) != len(set(paths)):
            raise ReleaseContractError("revision owner bundle repeats a live artifact path")
        for path in paths:
            parsed = PurePosixPath(path)
            if (
                parsed.is_absolute()
                or str(parsed) != path
                or any(part in {"", ".", ".."} for part in parsed.parts)
                or "\\" in path
                or "\x00" in path
            ):
                raise ReleaseContractError(
                    f"revision owner bundle has unsafe live artifact path: {path!r}"
                )
    elif schema == "stateport.revision-port-allocation-receipt/v1":
        expected = revision_contract_digest(value, digest_field="receiptDigest")
        if value["receiptDigest"] != expected:
            raise ReleaseContractError("revision port allocation receipt is stale or tampered")
        if value["rangeEnd"] <= value["rangeStart"]:
            raise ReleaseContractError("revision port allocation range is invalid")
        _parse_timestamp(value["allocatedAt"], "allocatedAt")
        expires = _parse_timestamp(value["reservationExpiresAt"], "reservationExpiresAt")
        allocated = _parse_timestamp(value["allocatedAt"], "allocatedAt")
        if expires <= allocated:
            raise ReleaseContractError("revision port reservation expiry is not after allocation")
        allocated_ports = [allocation["port"] for allocation in value["allocations"]]
        if len(allocated_ports) != len(set(allocated_ports)):
            raise ReleaseContractError("revision port allocation contains a collision")
        allocation_keys = [
            (item["serviceId"], item["profile"], item["portName"]) for item in value["allocations"]
        ]
        if len(allocation_keys) != len(set(allocation_keys)):
            raise ReleaseContractError("revision port allocation repeats a service port")
        if any(port < value["rangeStart"] or port > value["rangeEnd"] for port in allocated_ports):
            raise ReleaseContractError("revision port allocation falls outside its signed range")
        occupied = [item["port"] for item in value["occupiedInputs"]]
        if set(allocated_ports) & set(occupied):
            raise ReleaseContractError("revision port allocation collides with observed host state")
    elif schema == "stateport.revision-port-allocation-proposal/v1":
        expected = revision_contract_digest(value, digest_field="proposalDigest")
        if value["proposalDigest"] != expected:
            raise ReleaseContractError("revision port allocation proposal is stale or tampered")
        _parse_timestamp(value["proposedAt"], "proposedAt")
        if value["rangeEnd"] <= value["rangeStart"]:
            raise ReleaseContractError("revision port proposal range is invalid")
        allocated_ports = [allocation["port"] for allocation in value["allocations"]]
        if len(allocated_ports) != len(set(allocated_ports)):
            raise ReleaseContractError("revision port proposal contains a collision")
        allocation_keys = [
            (item["serviceId"], item["profile"], item["portName"]) for item in value["allocations"]
        ]
        if len(allocation_keys) != len(set(allocation_keys)):
            raise ReleaseContractError("revision port proposal repeats a service port")
        if any(port < value["rangeStart"] or port > value["rangeEnd"] for port in allocated_ports):
            raise ReleaseContractError("revision port proposal falls outside its signed range")
        if set(allocated_ports) & {item["port"] for item in value["occupiedInputs"]}:
            raise ReleaseContractError("revision port proposal collides with observed host state")
    elif schema == "stateport.revision-port-activation-recheck-receipt/v1":
        expected = revision_contract_digest(value, digest_field="receiptDigest")
        if value["receiptDigest"] != expected:
            raise ReleaseContractError("revision port activation recheck is stale or tampered")
        checked = _parse_timestamp(value["checkedAt"], "checkedAt")
        valid_until = _parse_timestamp(value["validUntil"], "validUntil")
        window = (valid_until - checked).total_seconds()
        if window <= 0 or window > 30:
            raise ReleaseContractError("port activation recheck window must be 1..30 seconds")
        allocated_ports = [item["port"] for item in value["allocations"]]
        if len(allocated_ports) != len(set(allocated_ports)):
            raise ReleaseContractError("port activation recheck repeats an allocation")
        if set(allocated_ports) & {item["port"] for item in value["occupiedInputs"]}:
            raise ReleaseContractError("port activation recheck observed a live collision")
    elif schema == "stateport.revision-data-promotion-receipt/v1":
        expected = revision_contract_digest(value, digest_field="receiptDigest")
        if value["receiptDigest"] != expected:
            raise ReleaseContractError("revision data-promotion receipt is stale or tampered")
        _parse_timestamp(value["completedAt"], "completedAt")
        if value["predecessorDataGeneration"] == value["acceptedDataGeneration"]:
            raise ReleaseContractError("data promotion reused the predecessor writable generation")
        predecessor_fields = (
            "predecessorPointerDigest",
            "predecessorReleaseId",
            "predecessorSignedPayloadDigest",
            "predecessorDataGeneration",
            "predecessorDataGenerationDigest",
        )
        predecessor_values = [value[field] for field in predecessor_fields]
        if any(item is None for item in predecessor_values) and not all(
            item is None for item in predecessor_values
        ):
            raise ReleaseContractError("data promotion has a partial predecessor identity")
        volume_keys = [item["volumeKey"] for item in value["volumeBindings"]]
        volume_names = [item["volumeName"] for item in value["volumeBindings"]]
        if len(volume_keys) != len(set(volume_keys)) or len(volume_names) != len(set(volume_names)):
            raise ReleaseContractError("data promotion repeats a writable volume binding")
        if set(volume_names) & set(value["predecessorVolumeNames"]):
            raise ReleaseContractError("two release revisions share a writable data volume")
        if any(
            item["dataGeneration"] != value["acceptedDataGeneration"]
            for item in value["volumeBindings"]
        ):
            raise ReleaseContractError("data promotion volume is not bound to exact D1")
    elif schema == "stateport.revision-validation-backup-receipt/v1":
        expected = revision_contract_digest(value, digest_field="receiptDigest")
        if value["receiptDigest"] != expected:
            raise ReleaseContractError("validation backup receipt is stale or tampered")
        _parse_timestamp(value["createdAt"], "createdAt")
        keys = [item["volumeKey"] for item in value["volumeBindings"]]
        names = [item["snapshotVolumeName"] for item in value["volumeBindings"]]
        if len(keys) != len(set(keys)) or len(names) != len(set(names)):
            raise ReleaseContractError("validation backup repeats a snapshot volume binding")
    elif schema == "stateport.revision-data-promotion-spec/v1":
        expected = revision_contract_digest(value, digest_field="specDigest")
        if value["specDigest"] != expected:
            raise ReleaseContractError("data-promotion specification is stale or tampered")
        if value["predecessorDataGeneration"] == value["expectedAcceptedDataGeneration"]:
            raise ReleaseContractError("data-promotion specification reuses predecessor D0")
        predecessor_fields = (
            "predecessorPointerDigest",
            "predecessorReleaseId",
            "predecessorSignedPayloadDigest",
            "predecessorDataGeneration",
            "predecessorDataGenerationDigest",
        )
        predecessor_values = [value[field] for field in predecessor_fields]
        if any(item is None for item in predecessor_values) and not all(
            item is None for item in predecessor_values
        ):
            raise ReleaseContractError("data-promotion specification has a partial predecessor")
        if len(value["requiredVolumeKeys"]) != len(set(value["requiredVolumeKeys"])):
            raise ReleaseContractError("data-promotion specification repeats a volume key")
    elif schema == "stateport.revision-terminal-acceptance-receipt/v1":
        expected = revision_contract_digest(value, digest_field="receiptDigest")
        if value["receiptDigest"] != expected:
            raise ReleaseContractError("terminal acceptance receipt is stale or tampered")
        _parse_timestamp(value["acceptedAt"], "acceptedAt")
        owners = [item["owner"] for item in value["ownerBundleDigests"]]
        if len(owners) != len(set(owners)):
            raise ReleaseContractError("terminal acceptance repeats an owner bundle")
        validate_contract_document(
            value["authorityFinalizeProof"],
            expected_schema="stateport.revision-authority-proof/v1",
        )
    elif schema == "stateport.revision-authority-proof/v1":
        expected = revision_contract_digest(value, digest_field="proofDigest")
        if value["proofDigest"] != expected:
            raise ReleaseContractError("revision authority proof is stale or tampered")
        suffix = value["requestId"].removeprefix("authority_request_")
        if value["reservationId"] != f"authority_reservation_{suffix}":
            raise ReleaseContractError("revision authority reservation identity is torn")
        expected_by_phase = {
            "reservation": {
                "sourceSchema": "stateport.authority-action-reservation/v1",
                "claimId": None,
                "claimDigest": None,
                "receiptId": None,
                "receiptDigest": None,
                "result": "reserved",
            },
            "claim": {
                "sourceSchema": "stateport.authority-action-claim/v1",
                "claimId": f"authority_claim_{suffix}",
                "receiptId": None,
                "receiptDigest": None,
                "result": "claimed",
            },
            "finalize": {
                "sourceSchema": "stateport.authority-action-receipt/v1",
                "claimId": f"authority_claim_{suffix}",
                "result": "finalized",
            },
        }[value["phase"]]
        for field, expected_value in expected_by_phase.items():
            if value[field] != expected_value:
                raise ReleaseContractError(
                    f"revision authority {value['phase']} proof has invalid {field}"
                )
        if value["phase"] in {"claim", "finalize"} and value["claimDigest"] is None:
            raise ReleaseContractError("revision authority claimed proof lacks claim digest")
        if value["phase"] == "finalize" and (
            value["receiptId"] is None or value["receiptDigest"] is None
        ):
            raise ReleaseContractError("revision authority finalize proof lacks terminal receipt")
    elif schema == "stateport.stable-host-service-plan/v1":
        expected = revision_contract_digest(value, digest_field="planDigest")
        if value["planDigest"] != expected:
            raise ReleaseContractError("stable host service plan is stale or tampered")
        service_ids = [item["serviceId"] for item in value["services"]]
        unit_paths = [item["unitPath"] for item in value["services"]]
        if len(service_ids) != len(set(service_ids)) or len(unit_paths) != len(set(unit_paths)):
            raise ReleaseContractError("stable host service plan repeats an identity or unit")
    elif schema == "stateport.stable-host-service-transition/v1":
        expected = revision_contract_digest(value, digest_field="transitionDigest")
        if value["transitionDigest"] != expected:
            raise ReleaseContractError("stable host service transition is stale or tampered")
        service_ids = [item["serviceId"] for item in value["actions"]]
        if len(service_ids) != len(set(service_ids)):
            raise ReleaseContractError("stable host transition repeats a service")


def _parse_timestamp(value: str, path: str) -> datetime:
    if _TIMESTAMP.fullmatch(value) is None:
        raise ReleaseContractError(f"{path}: timestamp must be whole-second UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ReleaseContractError(f"{path}: timestamp is invalid") from exc
    return parsed


def _canonical_absolute_parts(path: str, field: str) -> tuple[str, ...]:
    """Return the component tuple of a canonical absolute POSIX path.

    Rejects relative paths, ``.``/``..`` components, empty components, and
    non-canonical spellings (``//``, ``/./``, trailing ``/``) instead of
    silently normalizing them, so no raw string prefix check ever acts as
    path authority.
    """
    parsed = PurePosixPath(path)
    if (
        not parsed.is_absolute()
        or path.startswith("//")
        or str(parsed) != path
        or any(part in {"", ".", ".."} for part in parsed.parts)
        or "\\" in path
        or "\x00" in path
    ):
        raise ReleaseContractError(f"{field} is not a canonical absolute path: {path!r}")
    return parsed.parts


def _paths_overlap(candidate: tuple[str, ...], existing: tuple[str, ...]) -> bool:
    shared = min(len(candidate), len(existing))
    return candidate[:shared] == existing[:shared]


def _validate_uri(value: str, path: str) -> None:
    parsed = urlsplit(value)
    if parsed.fragment or parsed.username is not None or parsed.password is not None:
        raise ReleaseContractError(f"{path}: URI fragments and credentials are forbidden")
    if parsed.scheme == "http":
        if parsed.hostname != "127.0.0.1":
            raise ReleaseContractError(f"{path}: plain HTTP is allowed only on 127.0.0.1")
    elif parsed.scheme == "https":
        if not parsed.hostname:
            raise ReleaseContractError(f"{path}: HTTPS URI requires a host")
    elif parsed.scheme in {"oci", "operator"}:
        if not parsed.netloc:
            raise ReleaseContractError(f"{path}: {parsed.scheme} URI requires an authority")
    else:
        raise ReleaseContractError(f"{path}: unsupported artifact URI scheme")
    try:
        parsed.port
    except ValueError as exc:
        raise ReleaseContractError(f"{path}: URI port is invalid") from exc


def _semver_key(value: str) -> tuple[int, int, int, tuple[tuple[int, int | str], ...]]:
    match = _SEMVER.fullmatch(value)
    if match is None:
        raise ReleaseContractError(f"invalid semantic version: {value!r}")
    prerelease = match.group(4)
    if prerelease is None:
        pre_key = ((2, ""),)
    else:
        values: list[tuple[int, int | str]] = []
        for identifier in prerelease.split("."):
            if identifier.isdigit():
                if len(identifier) > 1 and identifier.startswith("0"):
                    raise ReleaseContractError(
                        f"numeric semantic-version prerelease identifiers cannot be zero-padded: {value!r}"
                    )
                values.append((0, int(identifier)))
            else:
                values.append((1, identifier))
        pre_key = tuple(values)
    return int(match.group(1)), int(match.group(2)), int(match.group(3)), pre_key


def _disposition_rank(status: str) -> int:
    return {"active": 0, "deprecated": 1, "withdrawn": 2}[status]


def _validate_successor_fields(index: Mapping[str, Any]) -> None:
    signed = index["signed"]
    successor = signed.get("successor")
    if successor is None:
        return
    if not isinstance(successor, Mapping):
        raise ReleaseContractError("successor semantics are malformed")
    if successor["formatVersion"] != SUCCESSOR_FORMAT:
        raise ReleaseContractError("successor semantics are not explicitly versioned")
    required_successor_fields = {
        "qualificationEvent",
        "disposition",
        "predecessor",
        "versionBindings",
    }
    if not required_successor_fields <= set(successor):
        raise ReleaseContractError("successor semantics are incomplete")
    freshness_enforcement = successor.get("freshnessEnforcement")
    if freshness_enforcement not in (None, "qualification-and-signing-time"):
        raise ReleaseContractError("successor freshness enforcement is unsupported")

    release = signed["release"]
    event = successor["qualificationEvent"]
    if not isinstance(event, Mapping):
        raise ReleaseContractError("successor qualification event is missing")
    required_event_fields = {
        "formatVersion",
        "eventId",
        "releaseId",
        "version",
        "qualifiedAt",
        "result",
        "freshnessBasis",
        "images",
    }
    if not required_event_fields <= set(event):
        raise ReleaseContractError("successor qualification event is incomplete")
    if event["releaseId"] != release["releaseId"] or event["version"] != release["version"]:
        raise ReleaseContractError("qualification event does not bind the successor release")
    event_payload = {key: value for key, value in event.items() if key != "eventId"}
    if event["eventId"] != canonical_digest(event_payload):
        raise ReleaseContractError("qualification event identity is not canonically bound")
    qualified_at = _parse_timestamp(event["qualifiedAt"], "successor.qualificationEvent.qualifiedAt")
    image_by_id = {image["imageId"]: image for image in signed["images"]}
    observations = event["images"]
    observation_ids = [item["imageId"] for item in observations]
    if not all(isinstance(item, str) for item in observation_ids):
        raise ReleaseContractError("qualification event image observations are not typed")
    if len(observation_ids) != len(set(observation_ids)):
        raise ReleaseContractError("qualification event image observations are not unique")
    if observation_ids != sorted(observation_ids):
        raise ReleaseContractError("qualification event image observations are not canonicalized")
    if set(observation_ids) != set(image_by_id):
        raise ReleaseContractError("qualification event image inventory is incomplete")
    for item in observations:
        image = image_by_id[item["imageId"]]
        if item["digest"] != image["digest"]:
            raise ReleaseContractError(
                f"qualification event digest disagrees for {item['imageId']}"
            )
        database_built = _parse_timestamp(
            item["databaseBuiltAt"], f"successor.qualificationEvent.{item['imageId']}.databaseBuiltAt"
        )
        scanned_at = _parse_timestamp(
            item["scannedAt"], f"successor.qualificationEvent.{item['imageId']}.scannedAt"
        )
        if database_built > qualified_at or scanned_at > qualified_at:
            raise ReleaseContractError("qualification event contains future scan evidence")
        scan = image["scan"]
        if (qualified_at - database_built).total_seconds() > scan["maxDatabaseAgeHours"] * 3600:
            raise ReleaseContractError("successor qualification event contains stale database evidence")
        if (qualified_at - scanned_at).total_seconds() > scan["maxScanAgeHours"] * 3600:
            raise ReleaseContractError("successor qualification event contains stale scan evidence")
        if (
            item["databaseBuiltAt"] != scan["databaseBuiltAt"]
            or item["scannedAt"] != scan["scannedAt"]
        ):
            raise ReleaseContractError("qualification event is not bound to image scan evidence")

    bindings = successor["versionBindings"]
    if bindings["releaseVersion"] != release["version"]:
        raise ReleaseContractError("successor version binding disagrees with release version")
    if bindings["buildReceiptVersion"] != release["version"]:
        raise ReleaseContractError("successor build receipt version disagrees with release version")

    disposition = successor["disposition"]
    publication = signed["publication"]["deprecation"]
    if disposition["status"] != publication["status"]:
        raise ReleaseContractError("successor disposition disagrees with publication status")
    if disposition["at"] != publication["at"] or disposition["reason"] != publication["reason"]:
        raise ReleaseContractError("successor disposition is not bound to publication details")
    if disposition["sequence"] < 1:
        raise ReleaseContractError("successor disposition sequence is invalid")
    if disposition["at"] is not None:
        disposition_at = _parse_timestamp(disposition["at"], "successor.disposition.at")
        if disposition_at < qualified_at:
            raise ReleaseContractError("successor disposition predates qualification")

    predecessor = successor["predecessor"]
    compatibility_predecessor = signed["compatibility"]["predecessor"]
    if predecessor is None:
        if compatibility_predecessor is not None:
            raise ReleaseContractError("successor predecessor authentication is missing its binding")
        if disposition["sequence"] != 1:
            raise ReleaseContractError("genesis successor disposition must begin at sequence one")
        if disposition["previousDispositionDigest"] is not None:
            raise ReleaseContractError("genesis successor disposition has an unexpected predecessor")
    else:
        if compatibility_predecessor is None:
            raise ReleaseContractError("authenticated predecessor is missing compatibility identity")
        for field in ("releaseId", "version", "signedPayloadDigest"):
            if predecessor[field] != compatibility_predecessor[field]:
                raise ReleaseContractError(f"successor predecessor {field} is not cross-bound")
        if _semver_key(predecessor["version"]) >= _semver_key(release["version"]):
            raise ReleaseContractError("predecessor version must precede successor version")
        if (
            _DIGEST.fullmatch(predecessor["signedPayloadDigest"]) is None
            or _DIGEST.fullmatch(predecessor["indexDigest"]) is None
        ):
            raise ReleaseContractError("successor predecessor raw index digests are malformed")
        predecessor_signature = predecessor["signature"]
        if predecessor_signature["subjectDigest"] != predecessor["signedPayloadDigest"]:
            raise ReleaseContractError("predecessor signature is not bound to its raw signed payload")
        _validate_uri(predecessor_signature["bundle"]["uri"], "successor.predecessor.signature.bundle.uri")
        _signature_trust_identity(predecessor_signature, context="successor.predecessor.signature")
        if predecessor_signature["trustMode"] != signed["signaturePolicy"]["trustMode"]:
            raise ReleaseContractError("predecessor signature trust mode disagrees with successor policy")
        if predecessor["indexDigest"] == canonical_digest(index):
            raise ReleaseContractError("predecessor raw index identity equals the successor index")
        raw_index = predecessor["rawIndex"]
        if not isinstance(raw_index, Mapping):
            raise ReleaseContractError("successor predecessor raw index is missing")
        authenticated_index = validate_release_index(
            raw_index, legacy_predecessor=_is_legacy_predecessor(raw_index)
        )
        if (
            authenticated_index.release_id != predecessor["releaseId"]
            or authenticated_index.version != predecessor["version"]
            or authenticated_index.signed_digest != predecessor["signedPayloadDigest"]
            or authenticated_index.index_digest != predecessor["indexDigest"]
            or predecessor_signature not in authenticated_index.document["signatures"]
        ):
            raise ReleaseContractError("successor predecessor raw index identity is forged")


def validate_successor_disposition_transition(
    predecessor: Mapping[str, Any] | None,
    successor: Mapping[str, Any],
) -> None:
    """Reject disposition rollback or sequence reuse across successor indexes."""

    if successor.get("formatVersion") != SUCCESSOR_FORMAT:
        raise ReleaseContractError("unsupported successor disposition semantics")
    current = successor["disposition"]
    if predecessor is None:
        if current["sequence"] != 1 or current["previousDispositionDigest"] is not None:
            raise ReleaseContractError("successor disposition does not start a monotonic chain")
        return
    if predecessor.get("formatVersion") != SUCCESSOR_FORMAT:
        if current["sequence"] != 1 or current["previousDispositionDigest"] is not None:
            raise ReleaseContractError("successor disposition cannot roll back a v1 predecessor")
        return
    previous = predecessor["disposition"]
    if current["sequence"] <= previous["sequence"]:
        raise ReleaseContractError("successor disposition sequence is not monotonic")
    if current["previousDispositionDigest"] != canonical_digest(previous):
        raise ReleaseContractError("successor disposition does not name the exact predecessor")
    previous_at = previous["at"]
    current_at = current["at"]
    if previous_at is not None and current_at is not None:
        if _parse_timestamp(current_at, "successor.disposition.at") < _parse_timestamp(
            previous_at, "predecessor.disposition.at"
        ):
            raise ReleaseContractError("successor disposition timestamp is not monotonic")
    previous_release_id = predecessor.get("qualificationEvent", {}).get("releaseId")
    current_release_id = successor.get("qualificationEvent", {}).get("releaseId")
    if (
        previous_release_id == current_release_id
        and _disposition_rank(current["status"]) < _disposition_rank(previous["status"])
    ):
        raise ReleaseContractError("successor disposition rolls back a predecessor status")


def _validate_candidate_provenance_binding(
    source: Mapping[str, Any], release_artifacts: Mapping[str, Any]
) -> None:
    candidate = source.get("candidateProvenance")
    if candidate is None:
        return
    if not isinstance(candidate, Mapping) or candidate.get("schema") != "stateport.candidate-provenance/v2":
        raise ReleaseContractError("source candidate provenance is not v2")
    digest = candidate.get("digest")
    document = candidate.get("document")
    if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
        raise ReleaseContractError("source candidate provenance digest is invalid")
    if not isinstance(document, Mapping) or document.get("schema") != "stateport.candidate-provenance/v2":
        raise ReleaseContractError("source candidate provenance document is not v2")
    if canonical_digest(document) != digest:
        raise ReleaseContractError("source candidate provenance digest does not bind its document")
    repository = document.get("repository")
    materialization = document.get("materialization")
    public_snapshot = source.get("publicSnapshot")
    if not isinstance(repository, Mapping) or not isinstance(materialization, Mapping):
        raise ReleaseContractError("source candidate provenance identity is incomplete")
    if not isinstance(public_snapshot, Mapping):
        raise ReleaseContractError("source public snapshot is missing")
    bindings = (
        ("source.repository", source.get("repository"), materialization.get("sourceRepository")),
        ("source.commit", source.get("commit"), materialization.get("sourceCommit")),
        ("source.tree", source.get("tree"), materialization.get("sourceTree")),
        ("publicSnapshot.repository", public_snapshot.get("repository"), repository.get("authorityUrl")),
        ("publicSnapshot.authorityUrl", public_snapshot.get("authorityUrl"), repository.get("authorityUrl")),
        ("publicSnapshot.ref", public_snapshot.get("ref"), repository.get("ref")),
        ("publicSnapshot.commit", public_snapshot.get("commit"), repository.get("commit")),
        ("publicSnapshot.tree", public_snapshot.get("tree"), repository.get("tree")),
    )
    for field, observed, expected in bindings:
        if observed != expected:
            raise ReleaseContractError(f"candidate provenance disagrees with {field}")
    artifacts = document.get("artifacts")
    public_manifest = artifacts.get("publicManifest") if isinstance(artifacts, Mapping) else None
    if not isinstance(public_manifest, Mapping):
        raise ReleaseContractError("source candidate provenance public manifest is missing")
    if public_snapshot.get("manifestDigest") != "sha256:" + str(public_manifest.get("sha256")):
        raise ReleaseContractError("candidate provenance public manifest disagrees with source")
    updater_wheel = artifacts.get("updaterWheel") if isinstance(artifacts, Mapping) else None
    if not isinstance(updater_wheel, Mapping):
        raise ReleaseContractError("source candidate provenance updater wheel is missing")
    updater = release_artifacts.get("updater")
    if (
        not isinstance(updater, Mapping)
        or updater.get("digest") != "sha256:" + str(updater_wheel.get("sha256"))
        or updater.get("size") != updater_wheel.get("bytes")
    ):
        raise ReleaseContractError("candidate provenance updater wheel disagrees with release")
    candidate_provisioner = (
        artifacts.get("executionHostProvisioner") if isinstance(artifacts, Mapping) else None
    )
    provisioner = release_artifacts.get("executionHostProvisioner")
    if (
        not isinstance(candidate_provisioner, Mapping)
        or not isinstance(provisioner, Mapping)
        or provisioner.get("digest")
        != "sha256:" + str(candidate_provisioner.get("sha256"))
        or provisioner.get("size") != candidate_provisioner.get("bytes")
    ):
        raise ReleaseContractError(
            "candidate provenance execution-host provisioner disagrees with release"
        )
    if candidate_provisioner.get("sourceCommit") != materialization.get("sourceCommit"):
        raise ReleaseContractError(
            "candidate provenance execution-host provisioner source commit disagrees with release"
        )
    package_bundle = release_artifacts.get("podmanPackageBundle")
    if package_bundle is not None:
        candidate_bundle = (
            artifacts.get("podmanPackageBundle") if isinstance(artifacts, Mapping) else None
        )
        if (
            not isinstance(candidate_bundle, Mapping)
            or not isinstance(package_bundle, Mapping)
            or package_bundle.get("digest")
            != "sha256:" + str(candidate_bundle.get("sha256"))
            or package_bundle.get("size") != candidate_bundle.get("bytes")
        ):
            raise ReleaseContractError(
                "candidate provenance Podman package bundle disagrees with release"
            )


def _validate_same_lane_predecessor_identity(
    predecessor: Mapping[str, Any], *, release: Mapping[str, Any]
) -> None:
    """Allow a shared releaseId only for a strictly older same-lane version.

    The updater's exact-predecessor contract compares releaseId AND
    signedPayloadDigest against the installed release, so a successor in one
    release lane (a single releaseId shared across candidates, as in the J1
    qualification lane) legitimately embeds a predecessor carrying its own
    releaseId. An accidental self-reference is excluded by requiring the
    embedded predecessor to be the strictly older semantic version.
    """
    if predecessor["releaseId"] != release["releaseId"]:
        return
    if not _semver_key(str(predecessor["version"])) < _semver_key(str(release["version"])):
        raise ReleaseContractError(
            "same-lane predecessor must be an older release than the successor"
        )


def _validate_cross_fields(
    index: Mapping[str, Any], *, require_signatures: bool, legacy_predecessor: bool = False
) -> None:
    signed = index["signed"]
    source = signed["source"]
    images = signed["images"]
    artifacts = signed["artifacts"]
    targets = signed["targets"]
    signatures = index["signatures"]
    signed_digest = canonical_digest(signed)
    trust_mode = signed["signaturePolicy"]["trustMode"]
    _validate_candidate_provenance_binding(source, artifacts)

    compatibility = signed["compatibility"]
    semvers = [
        signed["release"]["version"],
        compatibility["updaterMinimumVersion"],
        *(tool["version"] for tool in signed["supplyChain"]["tools"]),
    ]
    predecessor = compatibility["predecessor"]
    for optional_version in (
        predecessor["version"] if predecessor is not None else None,
        compatibility["rollback"]["minimumPredecessorVersion"],
    ):
        if optional_version is not None:
            semvers.append(optional_version)
    for version in semvers:
        _semver_key(version)
    rollback = compatibility["rollback"]
    if rollback["supported"] and predecessor is None:
        raise ReleaseContractError("rollback support requires an exact predecessor identity")
    if predecessor is not None:
        _validate_same_lane_predecessor_identity(
            predecessor,
            release=signed["release"],
        )
    if rollback["minimumPredecessorVersion"] is not None and predecessor is not None:
        if _semver_key(predecessor["version"]) < _semver_key(rollback["minimumPredecessorVersion"]):
            raise ReleaseContractError("predecessor is older than rollback compatibility permits")

    if require_signatures and not signatures:
        raise ReleaseContractError("release index has no detached Cosign v3 signature")
    for position, signature in enumerate(signatures):
        if signature["subjectDigest"] != signed_digest:
            raise ReleaseContractError(
                f"signatures[{position}] is not bound to the canonical signed payload"
            )
        _validate_uri(signature["bundle"]["uri"], f"signatures[{position}].bundle.uri")
        _signature_trust_identity(signature, context=f"signatures[{position}]")
        if signature["trustMode"] != trust_mode:
            raise ReleaseContractError(
                f"signatures[{position}] disagrees with the signed homogeneous trust mode"
            )

    for artifact_id, artifact in artifacts.items():
        _validate_uri(artifact["uri"], f"signed.artifacts.{artifact_id}.uri")
    expected_artifacts = _release_artifact_ids(
        str(signed["release"]["version"]), legacy=legacy_predecessor
    )
    if set(artifacts) != expected_artifacts:
        raise ReleaseContractError("release artifact set is incomplete or unexpected")

    image_by_id: dict[str, Mapping[str, Any]] = {}
    for position, image in enumerate(images):
        image_id = image["imageId"]
        if image_id in image_by_id:
            raise ReleaseContractError(f"duplicate image ID: {image_id}")
        image_by_id[image_id] = image
        if image["reference"].rsplit("@", 1)[-1] != image["digest"]:
            raise ReleaseContractError(f"images[{position}] reference and digest disagree")
        if image["sourceCommit"] != source["commit"] or image["sourceTree"] != source["tree"]:
            raise ReleaseContractError(
                f"images[{position}] source identity disagrees with the release"
            )
        if image["signature"]["subjectDigest"] != image["digest"]:
            raise ReleaseContractError(
                f"images[{position}] signature is not bound to the image digest"
            )
        _signature_trust_identity(image["signature"], context=f"images[{position}].signature")
        if image["signature"]["trustMode"] != trust_mode:
            raise ReleaseContractError(
                f"images[{position}].signature disagrees with the signed homogeneous trust mode"
            )
        for name in ("cycloneDx", "spdx"):
            _validate_uri(image["sboms"][name]["uri"], f"images[{position}].sboms.{name}.uri")
        for name in ("provenance", "packageInventory", "licenseInventory"):
            _validate_uri(image[name]["uri"], f"images[{position}].{name}.uri")
        _validate_uri(
            image["healthProbe"]["evidence"]["uri"],
            f"images[{position}].healthProbe.evidence.uri",
        )
        if image["healthProbe"]["packageInventoryDigest"] != image["packageInventory"]["digest"]:
            raise ReleaseContractError(
                f"images[{position}] health probe is not bound to its package inventory"
            )
        _validate_uri(image["scan"]["artifact"]["uri"], f"images[{position}].scan.artifact.uri")
        _validate_uri(
            image["signature"]["bundle"]["uri"], f"images[{position}].signature.bundle.uri"
        )
        scanned = _parse_timestamp(image["scan"]["scannedAt"], f"images[{position}].scan.scannedAt")
        built = _parse_timestamp(image["scan"]["databaseBuiltAt"], f"images[{position}].scan.databaseBuiltAt")
        age = (scanned - built).total_seconds()
        if age < 0 or age > image["scan"]["maxDatabaseAgeHours"] * 3600:
            raise ReleaseContractError(
                f"images[{position}] Grype database is outside its freshness policy"
            )

    used_runtime_images: set[str] = set()
    used_host_images: set[str] = set()
    target_ids: set[str] = set()
    for target_position, target in enumerate(targets):
        if target["targetId"] in target_ids:
            raise ReleaseContractError(f"duplicate target ID: {target['targetId']}")
        target_ids.add(target["targetId"])
        if set(target["artifactIds"]) != expected_artifacts:
            raise ReleaseContractError(
                f"targets[{target_position}] does not bind the complete artifact set"
            )
        if target["releaseId"] != signed["release"]["releaseId"]:
            raise ReleaseContractError(
                f"targets[{target_position}] release identity disagrees with the signed release"
            )
        runtime = target["runtimeDerivation"]
        if tuple(runtime["profiles"]) != ("validation", "accepted"):
            raise ReleaseContractError(
                f"targets[{target_position}] must declare validation then accepted profiles"
            )
        state_machine = runtime["stateMachine"]
        expected_sequences = {
            "stage": _REVISION_STAGE_STEPS,
            "validate": _REVISION_VALIDATE_STEPS,
            "promote": _REVISION_PROMOTE_STEPS,
            "rollback": _REVISION_ROLLBACK_STEPS,
            "rebootRecovery": _REVISION_REBOOT_STEPS,
        }
        for phase, expected in expected_sequences.items():
            if tuple(state_machine[phase]) != expected:
                raise ReleaseContractError(
                    f"targets[{target_position}] {phase} sequence is incomplete or reordered"
                )
        port_policy = runtime["portPolicy"]
        port_span = port_policy["rangeEnd"] - port_policy["rangeStart"] + 1
        if port_span <= 1:
            raise ReleaseContractError(f"targets[{target_position}] port range is invalid")
        if gcd(port_policy["probeStep"], port_span) != 1:
            raise ReleaseContractError(
                f"targets[{target_position}] port probe step cannot traverse the signed range"
            )
        if port_policy["maximumAttempts"] > port_span:
            raise ReleaseContractError(
                f"targets[{target_position}] port attempts exceed the collision-free traversal"
            )
        if tuple(port_policy["collisionInputs"]) != (
            "current",
            "predecessor",
            "candidate",
        ):
            raise ReleaseContractError(
                f"targets[{target_position}] port collision inputs are incomplete or reordered"
            )
        if target["topologyDigest"] != topology_digest(target):
            raise ReleaseContractError(
                f"targets[{target_position}] topology digest is stale or tampered"
            )
        execution_contract = target["executionContract"]
        signed_workspace_image(target, images)
        execution_mode = target["executionHostMode"]
        stable_execution = execution_mode in {
            "stable-host-daemon-client",
            "stable-host-daemon-bootstrap-only",
        }
        if stable_execution != isinstance(execution_contract, Mapping):
            raise ReleaseContractError(
                f"targets[{target_position}] execution-host mode and confined host contract disagree"
            )
        expected_eligibility = (
            "bootstrap-only"
            if execution_mode == "stable-host-daemon-bootstrap-only"
            else "release-candidate"
        )
        if target["releaseEligibility"] != expected_eligibility:
            raise ReleaseContractError(
                f"targets[{target_position}] execution lifecycle and release eligibility disagree"
            )
        service_ids: set[str] = set()
        revision_volume_names: dict[str, str] = {}
        volume_attachments: dict[str, list[tuple[str, Mapping[str, Any]]]] = {}
        shared_by_name: dict[str, Mapping[str, Any]] = {}
        shared_keys: set[str] = set()
        for shared in target.get("sharedWritableVolumes", ()):
            name = str(shared["volumeName"])
            key = str(shared["volumeKey"])
            if name in shared_by_name or key in shared_keys:
                raise ReleaseContractError(
                    f"targets[{target_position}] repeats a shared writable volume identity"
                )
            shared_by_name[name] = shared
            shared_keys.add(key)
        contract_clients: list[str] = []
        for service_position, service in enumerate(target["services"]):
            service_id = service["serviceId"]
            if service_id in service_ids:
                raise ReleaseContractError(
                    f"targets[{target_position}] has duplicate service {service_id}"
                )
            service_ids.add(service_id)
            image = image_by_id.get(service["imageId"])
            if image is None or image["role"] != "runtime-service":
                raise ReleaseContractError(
                    f"service {service_id} names a missing or non-runtime image"
                )
            if (
                service["runAsUser"] != image["runAsUser"]
                or service["readOnlyRoot"] != image["readOnlyRoot"]
            ):
                raise ReleaseContractError(
                    f"service {service_id} execution identity disagrees with its image"
                )
            if service["trustDomain"] == "execution":
                raise ReleaseContractError(
                    f"service {service_id} places the stable execution host inside a release revision"
                )
            if service["quadletOwner"] != "stateport-control":
                raise ReleaseContractError(
                    f"service {service_id} release revision is not owned by stateport-control"
                )
            port_numbers = {port["containerPort"] for port in service["ports"]}
            if service["health"]["containerPort"] not in port_numbers:
                raise ReleaseContractError(f"service {service_id} health port is not declared")
            port_names = [port["name"] for port in service["ports"]]
            if len(port_names) != len(set(port_names)):
                raise ReleaseContractError(f"service {service_id} has duplicate port names")
            for volume in service["writableVolumes"]:
                volume_name = str(volume["name"])
                prior_owner = revision_volume_names.get(volume_name)
                shared = shared_by_name.get(volume_name)
                if prior_owner is not None and shared is None and not legacy_predecessor:
                    raise ReleaseContractError(
                        f"services {prior_owner} and {service_id} name one writable volume; "
                        "shared queue/state volumes require an explicit contract"
                    )
                revision_volume_names[volume_name] = service_id
                volume_attachments.setdefault(volume_name, []).append((service_id, volume))
                if "/.git" in volume["mountPath"] or volume["mountPath"].endswith("/.git"):
                    raise ReleaseContractError(
                        f"service {service_id} attempts to mount Git metadata"
                    )
                validation = volume["validation"]
                if volume["purpose"] == "durable-state":
                    if volume["scope"] != "installation":
                        raise ReleaseContractError(
                            f"service {service_id} durable state must survive release revisions"
                        )
                    if validation != {
                        "mode": "read-only-snapshot-copy",
                        "authority": "exact-backup-receipt-required",
                    }:
                        raise ReleaseContractError(
                            f"service {service_id} validation cannot write authoritative durable state"
                        )
                elif volume["purpose"] in {"cache", "runtime"}:
                    if volume["scope"] != "release-revision" or validation != {
                        "mode": "ephemeral-empty",
                        "authority": "release-revision-local",
                    }:
                        raise ReleaseContractError(
                            f"service {service_id} runtime/cache volume must be disposable per revision"
                        )
                elif volume["scope"] == "installation" and validation != {
                    "mode": "read-only-snapshot-copy",
                    "authority": "exact-backup-receipt-required",
                }:
                    raise ReleaseContractError(
                        f"service {service_id} installation-scoped validation volume is not a read-only snapshot"
                    )
                elif volume["scope"] == "release-revision" and validation != {
                    "mode": "ephemeral-empty",
                    "authority": "release-revision-local",
                }:
                    raise ReleaseContractError(
                        f"service {service_id} revision-scoped validation volume is not disposable"
                    )
            provider_home = service.get("providerHome")
            if provider_home is not None and (
                provider_home != PROVIDER_HOME_CONTRACT
                or service_id != "stateport-web"
                or service["quadletOwner"] != "stateport-control"
                or service["runAsUser"] != 65532
                or service["capabilities"]["controlContract"] != "narrow-unix-client"
            ):
                raise ReleaseContractError(f"service {service_id} has an unauthorized provider home")
            read_only_mounts = service.get("readOnlyHostMounts", ())
            if read_only_mounts:
                expected_template_mount = {
                    "name": "template-sources",
                    "hostPath": "/var/lib/stateport/imports",
                    "mountPath": "/imports",
                    "purpose": "template-sources",
                    "sourceOwner": "installer-client",
                    "sourceGroup": "stateport-execution-control",
                    "mode": "ro",
                    "environmentVariable": "STATEPORT_REPOSITORY_ROOTS",
                }
                expected_workspace_mount = {
                    "name": "workspace-authority", "hostPath": "/etc/stateport/workspace-authority",
                    "mountPath": "/run/stateport-workspace-authority", "purpose": "workspace-authority",
                    "sourceOwner": "root", "sourceGroup": "root", "mode": "ro",
                    "environmentVariable": "STATEPORT_WORKSPACE_AUTHORITY_DIRECTORY",
                }
                if (
                    service_id != "stateport-web"
                    or list(read_only_mounts) not in (
                        [expected_template_mount], [expected_template_mount, expected_workspace_mount],
                        [expected_template_mount, {**expected_workspace_mount, "profileId": "stateport.empty-workspace-terminal/v1"}],
                        [expected_template_mount, {**expected_workspace_mount, "profileId": "stateport.reviewed-source-workspace-terminal/v1"}],
                    )
                    or service["capabilities"]["controlContract"] != "narrow-unix-client"
                ):
                    raise ReleaseContractError(
                        f"service {service_id} has an unauthorized host template-source mount"
                    )
            capabilities = service["capabilities"]
            if capabilities["podmanSocketAccess"] != "none":
                raise ReleaseContractError(
                    f"service {service_id} has unauthorized Podman socket authority"
                )
            if capabilities["controlContract"] == "narrow-unix-server":
                raise ReleaseContractError(
                    f"service {service_id} cannot host the stable execution control contract"
                )
            elif capabilities["controlContract"] == "narrow-unix-client":
                contract_clients.append(service_id)
            used_runtime_images.add(service["imageId"])
        if not legacy_predecessor:
            for name, shared in shared_by_name.items():
                attachments = volume_attachments.get(name, [])
                members = {service_id for service_id, _volume in attachments}
                if members != set(shared["members"]) or len(attachments) != len(members):
                    raise ReleaseContractError(
                        f"shared writable volume {name} does not bind its exact service members"
                    )
                metadata = {
                    canonical_json_bytes(
                        {
                            field: volume[field]
                            for field in ("mountPath", "purpose", "scope", "validation")
                        }
                    )
                    for _service_id, volume in attachments
                }
                if len(metadata) != 1:
                    raise ReleaseContractError(
                        f"shared writable volume {name} has inconsistent attachment metadata"
                    )
                sample = attachments[0][1]
                if (
                    sample["purpose"] != "durable-state"
                    or sample["scope"] != "installation"
                    or sample["validation"]
                    != {
                        "mode": "read-only-snapshot-copy",
                        "authority": "exact-backup-receipt-required",
                    }
                ):
                    raise ReleaseContractError(
                        f"shared writable volume {name} is not durable installation state"
                    )
        execution_hosts: list[Mapping[str, Any]] = []
        stable_host_ports: set[int] = set()
        stable_host_paths: list[tuple[str, ...]] = []
        stable_mount_paths: list[tuple[str, ...]] = []
        for host_service in target["hostServices"]:
            service_id = host_service["serviceId"]
            if service_id in service_ids:
                raise ReleaseContractError(
                    f"targets[{target_position}] repeats service identity across stable and revision lifecycles"
                )
            service_ids.add(service_id)
            image = image_by_id.get(host_service["imageId"])
            if image is None or image["role"] != "stable-host-service":
                raise ReleaseContractError(
                    f"stable service {service_id} names a missing or non-host image"
                )
            if (
                host_service["runAsUser"] != image["runAsUser"]
                or host_service["readOnlyRoot"] != image["readOnlyRoot"]
            ):
                raise ReleaseContractError(
                    f"stable service {service_id} execution identity disagrees with its image"
                )
            compatibility = host_service["updateCompatibility"]
            if not (
                compatibility["minimumClientVersion"]
                <= compatibility["contractVersion"]
                <= compatibility["maximumClientVersion"]
            ):
                raise ReleaseContractError(
                    f"stable service {service_id} has an impossible update compatibility range"
                )
            port_names = [port["name"] for port in host_service["ports"]]
            port_numbers = [port["containerPort"] for port in host_service["ports"]]
            host_port_numbers = [port["hostPort"] for port in host_service["ports"]]
            if (
                len(port_names) != len(set(port_names))
                or len(port_numbers) != len(set(port_numbers))
                or len(host_port_numbers) != len(set(host_port_numbers))
            ):
                raise ReleaseContractError(
                    f"stable service {service_id} repeats a port name or number"
                )
            if stable_host_ports & set(host_port_numbers):
                raise ReleaseContractError("stable host services collide on a host port")
            port_policy = target["runtimeDerivation"]["portPolicy"]
            if any(
                port_policy["rangeStart"] <= port <= port_policy["rangeEnd"]
                for port in host_port_numbers
            ):
                raise ReleaseContractError(
                    f"stable service {service_id} host port overlaps revision allocation range"
                )
            stable_host_ports.update(host_port_numbers)
            engine_access = host_service["engineAccess"]
            if host_service["trustDomain"] == "execution":
                if host_service["quadletOwner"] != "stateport-exec":
                    raise ReleaseContractError(
                        f"stable execution service {service_id} is not owned by stateport-exec"
                    )
                if not isinstance(host_service["socket"], Mapping):
                    raise ReleaseContractError(
                        f"stable execution service {service_id} lacks its confined socket"
                    )
                if not isinstance(engine_access, Mapping):
                    raise ReleaseContractError(
                        f"stable execution service {service_id} lacks owned engine authority"
                    )
                if not legacy_predecessor and (
                    host_service["userNamespace"] != "keep-id"
                    or host_service["socket"]["directoryMode"] != "2750"
                ):
                    raise ReleaseContractError(
                        f"stable execution service {service_id} requires keep-id and a setgid socket directory"
                    )
                execution_hosts.append(host_service)
            else:
                if host_service["quadletOwner"] != "stateport-control":
                    raise ReleaseContractError(
                        f"stable {host_service['trustDomain']} service {service_id} is not control-owned"
                    )
                if engine_access is not None:
                    raise ReleaseContractError(
                        f"stable {host_service['trustDomain']} service {service_id} has execution engine authority"
                    )
            for volume in host_service["writableVolumes"]:
                host_parts = _canonical_absolute_parts(
                    volume["hostPath"],
                    f"stable service {service_id} writable root",
                )
                expected_host_root = (
                    "/",
                    "var",
                    "lib",
                    host_service["quadletOwner"],
                    service_id,
                )
                if (
                    volume["owner"] != host_service["quadletOwner"]
                    or len(host_parts) <= len(expected_host_root)
                    or host_parts[: len(expected_host_root)] != expected_host_root
                ):
                    raise ReleaseContractError(
                        f"stable service {service_id} writable root crosses its Linux owner"
                    )
                mount_parts = _canonical_absolute_parts(
                    volume["mountPath"],
                    f"stable service {service_id} writable mount",
                )
                expected_mount_root = {
                    "durable-state": ("/", "var", "lib", "stateport"),
                    "configuration": ("/", "var", "lib", "stateport"),
                    "evidence": ("/", "var", "lib", "stateport"),
                    "cache": ("/", "var", "cache", "stateport"),
                    "runtime": ("/", "run", "stateport"),
                }[volume["purpose"]]
                if (
                    len(mount_parts) <= len(expected_mount_root)
                    or mount_parts[: len(expected_mount_root)] != expected_mount_root
                ):
                    raise ReleaseContractError(
                        f"stable service {service_id} writable mount crosses a protected root"
                    )
                for existing in stable_host_paths:
                    if _paths_overlap(host_parts, existing):
                        raise ReleaseContractError(
                            "stable host services share overlapping writable roots"
                        )
                for existing in stable_mount_paths:
                    if _paths_overlap(mount_parts, existing):
                        raise ReleaseContractError("stable host services share overlapping mounts")
                stable_host_paths.append(host_parts)
                stable_mount_paths.append(mount_parts)
            health = host_service["health"]
            if health["kind"] == "unix-socket":
                socket = host_service["socket"]
                if not isinstance(socket, Mapping):
                    raise ReleaseContractError(
                        f"stable service {service_id} unix health lacks a confined socket"
                    )
                health_directory = socket["hostDirectory"]
                if host_service["trustDomain"] == "execution":
                    health_directory = target["executionContract"]["containerDirectory"]
                if health["value"] != f"{health_directory}/{socket['socketName']}":
                    raise ReleaseContractError(
                        f"stable service {service_id} health names another socket"
                    )
            else:
                parsed_health = urlsplit(health["value"])
                if (
                    parsed_health.scheme != "http"
                    or parsed_health.hostname != "127.0.0.1"
                    or parsed_health.username is not None
                    or parsed_health.password is not None
                    or parsed_health.query
                    or parsed_health.fragment
                    or parsed_health.port not in port_numbers
                ):
                    raise ReleaseContractError(
                        f"stable service {service_id} has unsafe or unbound HTTP health"
                    )
            used_host_images.add(host_service["imageId"])
        if execution_mode == "none" and contract_clients:
            raise ReleaseContractError(
                f"targets[{target_position}] has orphan execution-contract clients"
            )
        if stable_execution and not contract_clients:
            raise ReleaseContractError(
                f"targets[{target_position}] stable execution host has no control-plane client"
            )
        if execution_mode == "none" and execution_hosts:
            raise ReleaseContractError(
                f"targets[{target_position}] inventories an execution host without a client contract"
            )
        if stable_execution and len(execution_hosts) != 1:
            raise ReleaseContractError(
                f"targets[{target_position}] must bind exactly one stable execution host"
            )
        if stable_execution:
            host_service = execution_hosts[0]
            host_socket = host_service["socket"]
            if not legacy_predecessor and execution_contract["directoryMode"] != "2750":
                raise ReleaseContractError(
                    f"targets[{target_position}] execution contract lacks setgid socket confinement"
                )
            identity_fields = (
                "socketGroupGid",
                "allowedClientUid",
                "allowedClientGid",
                "runtimeUid",
                "runtimeGid",
            )
            if not legacy_predecessor and any(
                field not in execution_contract for field in identity_fields
            ):
                raise ReleaseContractError(
                    f"targets[{target_position}] execution contract lacks explicit signed numeric identities"
                )
            if not legacy_predecessor and (
                execution_contract["runtimeUid"] != host_service["runAsUser"]
                or execution_contract["runtimeGid"] != host_service["runAsUser"]
            ):
                raise ReleaseContractError(
                    f"targets[{target_position}] execution runtime identity disagrees with its stable service"
                )
            image = image_by_id[host_service["imageId"]]
            expected_contract = {
                "serviceId": host_service["serviceId"],
                "imageId": host_service["imageId"],
                "imageDigest": image["digest"],
                "contractVersion": host_service["updateCompatibility"]["contractVersion"],
                "hostDirectory": host_socket["hostDirectory"],
                "socketName": host_socket["socketName"],
                "directoryOwner": host_socket["directoryOwner"],
                "directoryGroup": host_socket["directoryGroup"],
                "allowedClientUser": host_socket["allowedClientUser"],
                "directoryMode": host_socket["directoryMode"],
                "socketMode": host_socket["socketMode"],
                "peerIdentity": host_socket["peerIdentity"],
            }
            if any(
                execution_contract[field] != value for field, value in expected_contract.items()
            ):
                raise ReleaseContractError(
                    f"targets[{target_position}] execution contract is not bound to its exact stable service"
                )
            compatibility = execution_contract["clientCompatibility"]
            if (
                compatibility["minimum"]
                != host_service["updateCompatibility"]["minimumClientVersion"]
                or compatibility["maximum"]
                != host_service["updateCompatibility"]["maximumClientVersion"]
                or compatibility["minimum"] > compatibility["maximum"]
            ):
                raise ReleaseContractError(
                    f"targets[{target_position}] execution client compatibility disagrees with the stable host"
                )
    declared_runtime_images = {
        image_id for image_id, image in image_by_id.items() if image["role"] == "runtime-service"
    }
    if declared_runtime_images != used_runtime_images:
        raise ReleaseContractError(
            "runtime-service images and declared installed services must match exactly"
        )
    declared_host_images = {
        image_id
        for image_id, image in image_by_id.items()
        if image["role"] == "stable-host-service"
    }
    if declared_host_images != used_host_images:
        raise ReleaseContractError(
            "stable-host-service images and out-of-revision services must match exactly"
        )

    tool_names = [tool["name"] for tool in signed["supplyChain"]["tools"]]
    if sorted(tool_names) != ["cosign", "grype", "syft"]:
        raise ReleaseContractError("supply-chain tools must bind exactly Syft, Grype, and Cosign")
    for position, tool in enumerate(signed["supplyChain"]["tools"]):
        _validate_uri(
            tool["provenance"]["uri"], f"signed.supplyChain.tools[{position}].provenance.uri"
        )
    for name in ("doubleBuildComparison", "publicExportManifest"):
        _validate_uri(signed["supplyChain"][name]["uri"], f"signed.supplyChain.{name}.uri")

    release = signed["release"]
    publication = signed["publication"]
    deprecation = publication["deprecation"]
    if release["qualification"] == "published" and publication["publishedAt"] is None:
        raise ReleaseContractError("published release requires publication time")
    if release["qualification"] == "candidate" and publication["publishedAt"] is not None:
        raise ReleaseContractError("candidate release cannot claim a publication time")
    if release["qualification"] == "published" and any(
        signature["transparencyLog"] != "required-public-release" for signature in signatures
    ):
        raise ReleaseContractError(
            "published release signatures require transparency-log verification"
        )
    if release["qualification"] == "published" and any(
        image["signature"]["transparencyLog"] != "required-public-release" for image in images
    ):
        raise ReleaseContractError(
            "published image signatures require transparency-log verification"
        )
    if deprecation["status"] == "active" and (
        deprecation["at"] is not None or deprecation["reason"] is not None
    ):
        raise ReleaseContractError("active release cannot carry deprecation details")
    if deprecation["status"] != "active" and (
        deprecation["at"] is None or deprecation["reason"] is None
    ):
        raise ReleaseContractError("deprecated or withdrawn release requires time and reason")
    published_time = (
        _parse_timestamp(publication["publishedAt"], "signed.publication.publishedAt")
        if publication["publishedAt"] is not None
        else None
    )
    expiry_time = (
        _parse_timestamp(publication["expiresAt"], "signed.publication.expiresAt")
        if publication["expiresAt"] is not None
        else None
    )
    if published_time is not None and expiry_time is not None and published_time >= expiry_time:
        raise ReleaseContractError("release publication time must precede expiry")
    if deprecation["at"] is not None:
        _parse_timestamp(deprecation["at"], "signed.publication.deprecation.at")
    _validate_successor_fields(index)


def validate_release_index(
    document: Mapping[str, Any],
    *,
    require_signatures: bool = True,
    schema_directory: Path = SCHEMA_DIRECTORY,
    legacy_predecessor: bool = False,
) -> ReleaseIndex:
    """Validate shape and cross-field bindings without claiming authenticity."""

    if not isinstance(document, Mapping):
        raise ReleaseContractError("release index must be a mapping")
    value = _thaw(document)
    legacy_predecessor = legacy_predecessor and _is_legacy_predecessor(value)
    _validate_canonical_value(value)
    issues = _schema_issues(value, _load_schema(schema_directory / _CONTRACT_SCHEMAS[INDEX_SCHEMA]))
    if issues:
        raise ReleaseContractError(f"release index schema validation failed: {issues[0]}")
    _validate_cross_fields(
        value, require_signatures=require_signatures, legacy_predecessor=legacy_predecessor
    )
    payload = canonical_json_bytes(value["signed"])
    return ReleaseIndex(
        _freeze(value),
        payload,
        "sha256:" + hashlib.sha256(payload).hexdigest(),
        canonical_digest(value),
        canonical_json_bytes(value),
    )


def validate_release_disposition(
    document: Mapping[str, Any], *, predecessor: Mapping[str, Any] | None = None
) -> ValidatedContract:
    """Validate a signed successor disposition and its anti-rollback link."""

    if not isinstance(document, Mapping):
        raise ReleaseContractError("release disposition must be a mapping")
    value = _thaw(document)
    _validate_canonical_value(value)
    issues = _schema_issues(
        value, _load_schema(SCHEMA_DIRECTORY / "release-disposition.v2.schema.json")
    )
    if issues:
        raise ReleaseContractError(f"release disposition schema validation failed: {issues[0]}")
    status = value["status"]
    at = value["at"]
    reason = value["reason"]
    if status == "active" and (at is not None or reason is not None):
        raise ReleaseContractError("active release disposition cannot carry details")
    if status != "active" and (at is None or reason is None):
        raise ReleaseContractError("deprecated or withdrawn disposition requires time and reason")
    if at is not None:
        _parse_timestamp(at, "release disposition.at")
    if predecessor is None:
        if value["sequence"] != 1 or value["previousDispositionDigest"] is not None:
            raise ReleaseContractError("release disposition chain must start at sequence one")
    else:
        if value["sequence"] <= predecessor["sequence"]:
            raise ReleaseContractError("release disposition sequence is not monotonic")
        if value["previousDispositionDigest"] != canonical_digest(predecessor):
            raise ReleaseContractError("release disposition does not bind its predecessor")
        if value["at"] is not None and predecessor["at"] is not None:
            if _parse_timestamp(value["at"], "release disposition.at") < _parse_timestamp(
                predecessor["at"], "predecessor disposition.at"
            ):
                raise ReleaseContractError("release disposition timestamp is not monotonic")
        if _disposition_rank(value["status"]) < _disposition_rank(predecessor["status"]):
            raise ReleaseContractError("release disposition rolls back status")
    return ValidatedContract(_freeze(value), canonical_digest(value))


def load_release_index(
    content: bytes | str,
    *,
    require_signatures: bool = True,
    schema_directory: Path = SCHEMA_DIRECTORY,
    legacy_predecessor: bool = False,
) -> ReleaseIndex:
    parsed = _parse_document(content)
    allow_legacy = legacy_predecessor and _is_legacy_predecessor(parsed)
    return validate_release_index(
        parsed,
        require_signatures=require_signatures,
        schema_directory=schema_directory,
        legacy_predecessor=allow_legacy,
    )


def load_release_index_file(
    path: Path | str,
    *,
    require_signatures: bool = True,
    schema_directory: Path = SCHEMA_DIRECTORY,
    legacy_predecessor: bool = False,
) -> ReleaseIndex:
    """Read a bounded regular file without following a final symlink."""

    candidate = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
    except OSError as exc:
        raise ReleaseContractError("release index file could not be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_INDEX_BYTES:
            raise ReleaseContractError("release index path must be a bounded regular file")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1 << 20, MAX_INDEX_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_INDEX_BYTES:
                raise ReleaseContractError("release index exceeds the 4 MiB limit")
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ReleaseContractError("release index changed while being read")
    finally:
        os.close(descriptor)
    return load_release_index(
        b"".join(chunks),
        require_signatures=require_signatures,
        schema_directory=schema_directory,
        legacy_predecessor=legacy_predecessor,
    )


def verify_release_index(
    document: Mapping[str, Any] | ReleaseIndex,
    *,
    policy: ReleaseVerificationPolicy,
    verifier: SignatureVerifier,
    predecessor: Mapping[str, Any] | ReleaseIndex | None = None,
    local_image_payloads: Mapping[str, bytes] | None = None,
    legacy_predecessor: bool = False,
) -> VerifiedRelease:
    """Verify exact digest, policy, and successor qualification/disposition links."""

    raw_document = document.document if isinstance(document, ReleaseIndex) else document
    allow_legacy = legacy_predecessor and _is_legacy_predecessor(raw_document)
    if isinstance(document, ReleaseIndex):
        rebound = validate_release_index(
            document.document, legacy_predecessor=allow_legacy
        )
        if (
            rebound.signed_bytes != document.signed_bytes
            or rebound.signed_digest != document.signed_digest
            or rebound.index_digest != document.index_digest
            or rebound.canonical_index_bytes != document.canonical_index_bytes
        ):
            raise ReleaseContractError(
                "ReleaseIndex object fields are not bound to its canonical document"
            )
        index = rebound
    else:
        index = validate_release_index(
            document, legacy_predecessor=allow_legacy
        )
    if not index.document["signatures"]:
        raise ReleaseContractError("release index has no signatures")
    if policy.now.tzinfo is None or policy.now.utcoffset() is None:
        raise ReleaseContractError("verification time must be timezone-aware")
    if policy.expected_trust_mode not in {"keyless-certificate", "pinned-public-key"}:
        raise ReleaseContractError("verification policy has an unsupported trust mode")
    if policy.expected_trust_mode == "keyless-certificate":
        if not policy.accepted_signers or policy.accepted_public_keys:
            raise ReleaseContractError(
                "keyless verification policy must contain only certificate identities"
            )
    elif not policy.accepted_public_keys or policy.accepted_signers:
        raise ReleaseContractError(
            "pinned-key verification policy must contain only raw public-key identities"
        )
    if _SEMVER.fullmatch(policy.updater_version) is None:
        raise ReleaseContractError("updater version is not semantic versioning")
    release = index.document["signed"]["release"]
    signature_policy = index.document["signed"]["signaturePolicy"]
    if signature_policy["trustMode"] != policy.expected_trust_mode:
        raise ReleaseContractError("signed trust mode does not match verification policy")
    if release["channel"] != policy.expected_channel:
        raise ReleaseContractError("release channel does not match verification policy")
    if release["qualification"] != "published" and not policy.allow_candidate:
        raise ReleaseContractError("candidate release is not installable under this policy")
    targets = [
        target
        for target in index.document["signed"]["targets"]
        if target["targetId"] == policy.expected_target
    ]
    if len(targets) != 1:
        raise ReleaseContractError("release does not contain exactly one expected target")
    if targets[0]["releaseEligibility"] == "bootstrap-only" and not policy.allow_bootstrap_target:
        raise ReleaseContractError(
            "bootstrap-only execution-host target is not a releasable application target"
        )
    minimum = index.document["signed"]["compatibility"]["updaterMinimumVersion"]
    if _semver_key(policy.updater_version) < _semver_key(minimum):
        raise ReleaseContractError("updater is older than the release minimum")
    publication = index.document["signed"]["publication"]
    now = policy.now.astimezone(timezone.utc)
    published_at = (
        _parse_timestamp(publication["publishedAt"], "publishedAt")
        if publication["publishedAt"] is not None
        else None
    )
    if published_at is not None and published_at > now:
        raise ReleaseContractError("release publication time is in the future")
    if publication["expiresAt"] is not None and now >= _parse_timestamp(
        publication["expiresAt"], "expiresAt"
    ):
        raise ReleaseContractError("release index is expired")
    successor = index.document["signed"].get("successor")
    # Legacy signed indexes remain verification-time bound. New successors opt
    # in explicitly so immutable releases do not expire as their signing DB ages.
    qualification_time_freshness = (
        isinstance(successor, Mapping)
        and successor.get("freshnessEnforcement") == "qualification-and-signing-time"
    )
    for position, image in enumerate(index.document["signed"]["images"]):
        scan = image["scan"]
        scanned_at = _parse_timestamp(scan["scannedAt"], "scannedAt")
        database_built = _parse_timestamp(scan["databaseBuiltAt"], "databaseBuiltAt")
        if database_built > now or scanned_at > now:
            raise ReleaseContractError(f"images[{position}] scan evidence is from the future")
        if not qualification_time_freshness and (
            (now - database_built).total_seconds() > scan["maxDatabaseAgeHours"] * 3600
        ):
            raise ReleaseContractError(
                f"images[{position}] Grype database is stale at verification time"
            )
        if not qualification_time_freshness and (
            (now - scanned_at).total_seconds() > scan["maxScanAgeHours"] * 3600
        ):
            raise ReleaseContractError(
                f"images[{position}] vulnerability scan is stale at verification time"
            )
    if index.document["signed"].get("successor") is not None:
        qualified_at = _parse_timestamp(
            index.document["signed"]["successor"]["qualificationEvent"]["qualifiedAt"],
            "successor.qualificationEvent.qualifiedAt",
        )
        if qualified_at > now:
            raise ReleaseContractError("successor qualification event is from the future")
    status = publication["deprecation"]["status"]
    if status == "withdrawn" or (status == "deprecated" and not policy.allow_deprecated):
        raise ReleaseContractError(f"release is {status}")
    authenticated_predecessor: AuthenticatedPredecessor | None = None
    if successor is not None:
        claimed_predecessor = successor["predecessor"]
        if claimed_predecessor is None:
            if predecessor is not None:
                raise ReleaseContractError("successor has an unexpected predecessor input")
        else:
            if predecessor is None:
                raise ReleaseContractError(
                    "successor verification requires its authenticated predecessor index"
                )
            authenticated_predecessor = verify_release_predecessor(
                predecessor,
                expected_trust_mode=policy.expected_trust_mode,
                accepted_signers=policy.accepted_signers,
                accepted_public_keys=policy.accepted_public_keys,
                verifier=verifier,
                legacy_predecessor=True,
            )
            predecessor_index = authenticated_predecessor.index
            predecessor_successor = predecessor_index.document["signed"].get("successor")
            validate_successor_disposition_transition(predecessor_successor, successor)
            expected_identity = {
                "releaseId": predecessor_index.release_id,
                "version": predecessor_index.version,
                "signedPayloadDigest": predecessor_index.signed_digest,
                "indexDigest": predecessor_index.index_digest,
                "signature": dict(authenticated_predecessor.signature),
            }
            claimed_identity = {
                key: claimed_predecessor[key]
                for key in (
                    "formatVersion",
                    "releaseId",
                    "version",
                    "signedPayloadDigest",
                    "indexDigest",
                    "signature",
                )
            }
            if (
                claimed_identity
                != {"formatVersion": claimed_predecessor["formatVersion"], **expected_identity}
                or not isinstance(claimed_predecessor.get("rawIndex"), Mapping)
                or canonical_json_bytes(claimed_predecessor["rawIndex"])
                != predecessor_index.canonical_index_bytes
            ):
                raise ReleaseContractError(
                    "successor predecessor identity or authenticated signature is forged"
                )
                if _semver_key(predecessor_index.version) >= _semver_key(release["version"]):
                    raise ReleaseContractError("predecessor version must precede successor version")
    if local_image_payloads is not None:
        setter = getattr(verifier, "set_local_image_payloads", None)
        if callable(setter):
            setter(local_image_payloads)
    verified: list[TrustIdentity] = []
    proofs: list[SignatureVerificationProof] = []
    failures: list[str] = []
    for position, signature in enumerate(index.document["signatures"]):
        signer = _signature_trust_identity(signature, context=f"signatures[{position}]")
        accepted = (
            signer in policy.accepted_signers
            if isinstance(signer, SignerIdentity)
            else signer in policy.accepted_public_keys
        )
        signer_label = (
            signer.certificate_identity
            if isinstance(signer, SignerIdentity)
            else f"{signer.key_id} ({signer.public_key_fingerprint})"
        )
        if not accepted:
            failures.append(f"untrusted signer {signer_label}")
            continue
        if (
            policy.require_transparency_log
            and signature["transparencyLog"] != "required-public-release"
        ):
            failures.append(f"signature for {signer_label} has no required transparency-log proof")
            continue
        try:
            proof = verifier.verify_blob(index.signed_bytes, signature)
            _validate_verification_proof(
                proof,
                signature=signature,
                identity=signer,
                context=f"signatures[{position}]",
            )
        except Exception as exc:  # verifier implementations intentionally define their own failures
            failures.append(f"signature verification failed for {signer_label}: {exc}")
            continue
        verified.append(signer)
        proofs.append(proof)
    for position, image in enumerate(index.document["signed"]["images"]):
        signature = image["signature"]
        signer = _signature_trust_identity(signature, context=f"images[{position}].signature")
        accepted = (
            signer in policy.accepted_signers
            if isinstance(signer, SignerIdentity)
            else signer in policy.accepted_public_keys
        )
        if not accepted:
            failures.append(f"images[{position}] has an untrusted signing identity")
            continue
        if (
            policy.require_transparency_log
            and signature["transparencyLog"] != "required-public-release"
        ):
            failures.append(f"images[{position}] has no required transparency-log proof")
            continue
        try:
            if signature.get("subjectKind") == "oci-manifest-blob":
                image_id = str(image["imageId"])
                payload = (
                    None if local_image_payloads is None else local_image_payloads.get(image_id)
                )
                if payload is None:
                    resolver = getattr(verifier, "resolve_local_image_manifest", None)
                    if callable(resolver):
                        payload = resolver(image_id, str(signature["subjectDigest"]))
                if payload is None:
                    raise ReleaseContractError(
                        "private image signature requires exact local manifest bytes"
                    )
                proof = verifier.verify_blob(payload, signature)
            else:
                proof = verifier.verify_image(image["reference"], signature)
            _validate_verification_proof(
                proof,
                signature=signature,
                identity=signer,
                context=f"images[{position}].signature",
            )
        except Exception as exc:
            failures.append(f"image signature verification failed for {image['imageId']}: {exc}")
            continue
        proofs.append(proof)
    expected_proof_count = len(index.document["signatures"]) + len(
        index.document["signed"]["images"]
    )
    if failures or not verified or len(proofs) != expected_proof_count:
        detail = "; ".join(failures) or "no acceptable signature"
        raise ReleaseContractError(detail)
    return VerifiedRelease._from_verification(
        index,
        tuple(
            sorted(
                set(verified),
                key=lambda identity: (
                    (
                        "keyless-certificate",
                        identity.certificate_identity,
                        identity.oidc_issuer,
                    )
                    if isinstance(identity, SignerIdentity)
                    else (
                        "pinned-public-key",
                        identity.public_key_fingerprint,
                        identity.key_id,
                    )
                ),
            )
        ),
        tuple(proofs),
        targets[0],
        authenticated_predecessor,
    )


def to_updater_release_envelope(verified: VerifiedRelease) -> UpdaterReleaseEnvelope:
    """Map a verified index into the updater's exact immutable input envelope.

    This is intentionally unavailable for an unverified :class:`ReleaseIndex`.
    Installer and updater code therefore share one normalization path and
    cannot silently disagree about source, image, predecessor, rollback, or
    publication identity.
    """

    signed = verified.index.document["signed"]
    compatibility = signed["compatibility"]
    document: dict[str, Any] = {
        "schema": "stateport.updater-release-envelope/v1",
        "release": _thaw(signed["release"]),
        "releaseIndexDigest": verified.index.index_digest,
        "signedPayloadDigest": verified.index.signed_digest,
        "source": _thaw(signed["source"]),
        "target": _thaw(verified.target),
        "artifacts": _thaw(signed["artifacts"]),
        "images": _thaw(signed["images"]),
        "supplyChain": _thaw(signed["supplyChain"]),
        "compatibility": {
            "updaterMinimumVersion": compatibility["updaterMinimumVersion"],
            "schemaMigrationVersion": compatibility["schemaMigrationVersion"],
            "databaseMigrationVersion": compatibility["databaseMigrationVersion"],
            "predecessor": _thaw(compatibility["predecessor"]),
            "rollback": _thaw(compatibility["rollback"]),
        },
        "publication": _thaw(signed["publication"]),
        "verificationProofs": signature_verification_proof_set(verified),
        "signatureVerificationProofSetDigest": signature_verification_proof_set_digest(verified),
    }
    if verified.authenticated_predecessor is not None:
        predecessor = verified.authenticated_predecessor
        document["authenticatedPredecessor"] = {
            "index": _thaw(predecessor.index.document),
            "indexDigest": predecessor.index.index_digest,
            "signedPayloadDigest": predecessor.index.signed_digest,
            "signature": _thaw(predecessor.signature),
        }
    return UpdaterReleaseEnvelope._from_verified(
        document,
        verified.index.canonical_index_bytes,
        verified.verified_signers,
        verified.verification_proofs,
    )


def reverify_updater_release_envelope(
    envelope: UpdaterReleaseEnvelope,
    *,
    policy: ReleaseVerificationPolicy,
    verifier: SignatureVerifier,
) -> VerifiedRelease:
    """Reload and reverify the persisted canonical index before updater reuse."""

    if not isinstance(envelope, UpdaterReleaseEnvelope):
        raise ReleaseContractError("updater input is not a verified release envelope")
    if (
        canonical_digest(envelope.document["verificationProofs"])
        != envelope.document["signatureVerificationProofSetDigest"]
    ):
        raise ReleaseContractError("updater historic signature proof set is stale or tampered")
    index = load_release_index(envelope.canonical_index_bytes)
    predecessor: Mapping[str, Any] | None = None
    predecessor_context = envelope.document.get("authenticatedPredecessor")
    if index.document["signed"].get("successor", {}).get("predecessor") is not None:
        if not isinstance(predecessor_context, Mapping):
            raise ReleaseContractError("updater envelope lacks its authenticated predecessor")
        predecessor = predecessor_context.get("index")
        if not isinstance(predecessor, Mapping):
            raise ReleaseContractError("updater envelope predecessor index is malformed")
    verified = verify_release_index(
        index, policy=policy, verifier=verifier, predecessor=predecessor
    )
    if verified.authenticated_predecessor is not None:
        if not isinstance(predecessor_context, Mapping):
            raise ReleaseContractError("updater envelope predecessor authentication is missing")
        authenticated = verified.authenticated_predecessor
        if (
            predecessor_context.get("indexDigest") != authenticated.index.index_digest
            or predecessor_context.get("signedPayloadDigest") != authenticated.index.signed_digest
            or predecessor_context.get("signature") != _thaw(authenticated.signature)
        ):
            raise ReleaseContractError("updater envelope predecessor authentication is stale")
    return verified


def release_identity_from_verified(verified: VerifiedRelease) -> dict[str, Any]:
    """Return the canonical release identity used by update plans and receipts."""

    signed = verified.index.document["signed"]
    return {
        "releaseId": signed["release"]["releaseId"],
        "version": signed["release"]["version"],
        "channel": signed["release"]["channel"],
        "signedPayloadDigest": verified.index.signed_digest,
        "imageSetDigest": image_set_digest(signed["images"]),
        "sourceCommit": signed["source"]["commit"],
        "sourceTree": signed["source"]["tree"],
        "qualification": signed["release"]["qualification"],
        "publishedAt": signed["publication"]["publishedAt"],
    }


def validate_install_receipt(document: Mapping[str, Any]) -> ValidatedContract:
    return validate_contract_document(document, expected_schema="stateport.install-receipt/v1")


def validate_revision_contract(document: Mapping[str, Any]) -> ValidatedContract:
    schema = document.get("schema") if isinstance(document, Mapping) else None
    if not isinstance(schema, str) or not schema.startswith("stateport.revision-"):
        raise ReleaseContractError("document is not a revision transition contract")
    return validate_contract_document(document, expected_schema=schema)


def validate_update_plan(
    document: Mapping[str, Any],
    *,
    now: datetime,
) -> ValidatedContract:
    validated = validate_contract_document(document, expected_schema="stateport.update-plan/v1")
    if now.tzinfo is None or now.utcoffset() is None:
        raise ReleaseContractError("update plan validation time must be timezone-aware")
    created = _parse_timestamp(str(validated.document["createdAt"]), "createdAt")
    expires = _parse_timestamp(str(validated.document["expiresAt"]), "expiresAt")
    observed = now.astimezone(timezone.utc)
    if observed < created:
        raise ReleaseContractError("update plan is not active yet")
    if observed >= expires:
        raise ReleaseContractError("update plan is expired")
    return ValidatedContract(validated.document, str(validated.document["planDigest"]))


def validate_update_receipt(document: Mapping[str, Any]) -> ValidatedContract:
    return validate_contract_document(document, expected_schema="stateport.update-receipt/v1")


def validate_update_authority_link(document: Mapping[str, Any]) -> ValidatedContract:
    return validate_contract_document(
        document, expected_schema="stateport.update-authority-link/v1"
    )


def validate_update_status(document: Mapping[str, Any]) -> ValidatedContract:
    return validate_contract_document(document, expected_schema="stateport.update-status/v1")


def validate_update_failure_evidence(document: Mapping[str, Any]) -> ValidatedContract:
    return validate_contract_document(
        document, expected_schema="stateport.update-failure-evidence/v1"
    )


def validate_release_provenance(document: Mapping[str, Any]) -> ValidatedContract:
    return validate_contract_document(document, expected_schema="stateport.release-provenance/v1")
