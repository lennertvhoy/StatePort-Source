"""Strict, non-authoritative catalog metadata for canonical application sources.

The catalog describes the release StatePort is allowed to look for and records
an observed development candidate.  It never replaces immutable resolution:
successful resolution still flows through :mod:`statedd_core.source_contract`
and produces the existing ``statedd.source/v2`` descriptor and lifecycle lock.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any, Mapping
from urllib.parse import urlsplit

from statedd_core.lifecycle_errors import LifecycleError
from statedd_core.yaml import StateDDYamlError, parse_yaml_text


CANONICAL_SOURCE_DESCRIPTOR_FORMAT = "stateport.canonical-source/v1"
CANONICAL_SOURCE_CLASSES = frozenset(
    {"canonical_release", "development_candidate", "synthetic_fixture", "compatibility_snapshot"}
)
CANONICAL_SOURCE_TRUST_STATES = frozenset(
    {"unverified", "development_only", "verified_release", "rejected"}
)
CANONICAL_SOURCE_STATUS_CODES = frozenset(
    {"awaiting_verified_release", "source_available", "rejected"}
)

_FULL_OID = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_RELEASE_REF = re.compile(r"^refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$")
_CANONICAL_MANIFEST_PATH = ".statedd/manifest.yaml"


def _mapping(value: Any, label: str, keys: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise LifecycleError(f"{label} must be a mapping")
    unknown = sorted(set(value) - keys)
    if unknown:
        raise LifecycleError(f"{label} contains unknown fields: {', '.join(unknown)}")
    missing = sorted(keys - set(value))
    if missing:
        raise LifecycleError(f"{label} is missing required fields: {', '.join(missing)}")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LifecycleError(f"{label} must be a non-empty string")
    return value.strip()


def _nullable_string(value: Any, label: str) -> str | None:
    return None if value is None else _string(value, label)


def _string_list(value: Any, label: str, *, empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or (not empty and not value):
        suffix = "" if empty else " non-empty"
        raise LifecycleError(f"{label} must be a{suffix} list of strings")
    normalized = tuple(_string(item, f"{label}[]") for item in value)
    if len(set(normalized)) != len(normalized):
        raise LifecycleError(f"{label} must not contain duplicates")
    return normalized


def _remote_repository(value: Any, label: str) -> str:
    repository = _string(value, label)
    parsed = urlsplit(repository)
    if (
        parsed.scheme not in {"https", "ssh"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise LifecycleError(f"{label} must be a credential-free https or ssh repository URL")
    return repository


def _confined_path(value: Any, label: str) -> str:
    raw = _string(value, label)
    path = Path(raw)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise LifecycleError(f"{label} must be a confined relative path")
    return path.as_posix()


@dataclass(frozen=True)
class CanonicalSourceIdentity:
    """Projection of immutable fields from an existing ``statedd.source/v2`` descriptor."""

    repository: str
    commit: str
    tree: str
    manifest_digest: str
    source_digest: str

    @classmethod
    def from_mapping(cls, data: Any, label: str = "identity") -> "CanonicalSourceIdentity":
        value = _mapping(
            data,
            label,
            {"repository", "commit", "tree", "manifestDigest", "sourceDigest"},
        )
        repository = _remote_repository(value["repository"], f"{label}.repository")
        commit = _string(value["commit"], f"{label}.commit")
        tree = _string(value["tree"], f"{label}.tree")
        manifest_digest = _string(value["manifestDigest"], f"{label}.manifestDigest")
        source_digest = _string(value["sourceDigest"], f"{label}.sourceDigest")
        if not _FULL_OID.fullmatch(commit):
            raise LifecycleError(f"{label}.commit must be a lowercase full Git object ID")
        if not _FULL_OID.fullmatch(tree):
            raise LifecycleError(f"{label}.tree must be a lowercase full Git object ID")
        if not _DIGEST.fullmatch(manifest_digest):
            raise LifecycleError(f"{label}.manifestDigest must be a sha256 digest")
        if not _DIGEST.fullmatch(source_digest):
            raise LifecycleError(f"{label}.sourceDigest must be a sha256 digest")
        return cls(repository, commit, tree, manifest_digest, source_digest)

    @classmethod
    def from_resolved_descriptor(cls, descriptor: Mapping[str, Any]) -> "CanonicalSourceIdentity":
        """Project an already verified lifecycle descriptor; never resolve independently."""
        if descriptor.get("formatVersion") != "statedd.source/v2" or descriptor.get("kind") != "git":
            raise LifecycleError("resolved source must be an existing statedd.source/v2 Git descriptor")
        return cls.from_mapping(
            {
                "repository": descriptor.get("repository"),
                "commit": descriptor.get("resolvedCommit"),
                "tree": descriptor.get("resolvedTree"),
                "manifestDigest": descriptor.get("manifestDigest"),
                "sourceDigest": descriptor.get("sourceDigest"),
            },
            "resolvedSource.identity",
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "repository": self.repository,
            "commit": self.commit,
            "tree": self.tree,
            "manifestDigest": self.manifest_digest,
            "sourceDigest": self.source_digest,
        }


@dataclass(frozen=True)
class CanonicalSourceResolution:
    source_class: str
    requested_ref: str | None
    identity: CanonicalSourceIdentity | None
    release_status: str | None
    verified_modules: tuple[str, ...]
    verified_self_tests: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "sourceClass": self.source_class,
            "requestedRef": self.requested_ref,
            "identity": None if self.identity is None else self.identity.to_dict(),
            "releaseStatus": self.release_status,
            "verifiedModules": list(self.verified_modules),
            "verifiedSelfTests": list(self.verified_self_tests),
        }


@dataclass(frozen=True)
class CanonicalSourceTrust:
    state: str
    canonical_install_allowed: bool
    development_testing_allowed: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "canonicalInstallAllowed": self.canonical_install_allowed,
            "developmentTestingAllowed": self.development_testing_allowed,
        }


@dataclass(frozen=True)
class CanonicalSourceStatus:
    code: str
    installable: bool
    unresolved_reason: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "installable": self.installable,
            "unresolvedReason": self.unresolved_reason,
        }


@dataclass(frozen=True)
class CanonicalSourceDescriptor:
    """A strict release policy and observation record, not installed source authority."""

    source_id: str
    application_id: str
    public_name: str
    legacy_identifiers: tuple[str, ...]
    repository: str
    canonical_ref_policy: str
    manifest_path: str
    manifest_contract: str
    required_modules: tuple[str, ...]
    expected_self_tests: tuple[str, ...]
    canonical_resolution: CanonicalSourceResolution
    development_candidate: CanonicalSourceResolution | None
    trust: CanonicalSourceTrust
    status: CanonicalSourceStatus
    observed_canonical_ref: str
    observed_canonical_commit: str
    observed_canonical_manifest_present: bool
    observed_at: str

    @property
    def identity(self) -> CanonicalSourceIdentity | None:
        """Canonical identity only; a candidate is deliberately never substituted."""
        return self.canonical_resolution.identity

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": CANONICAL_SOURCE_DESCRIPTOR_FORMAT,
            "sourceId": self.source_id,
            "application": {
                "id": self.application_id,
                "publicName": self.public_name,
                "legacyIdentifiers": list(self.legacy_identifiers),
            },
            "authority": {
                "repository": self.repository,
                "canonicalRefPolicy": self.canonical_ref_policy,
                "manifestPath": self.manifest_path,
                "manifestContract": self.manifest_contract,
            },
            "requirements": {
                "modules": list(self.required_modules),
                "selfTests": list(self.expected_self_tests),
            },
            "canonicalResolution": self.canonical_resolution.to_dict(),
            "developmentCandidate": (
                None if self.development_candidate is None else self.development_candidate.to_dict()
            ),
            "trust": self.trust.to_dict(),
            "status": self.status.to_dict(),
            "observations": {
                "canonicalRef": self.observed_canonical_ref,
                "canonicalCommit": self.observed_canonical_commit,
                "canonicalManifestPresent": self.observed_canonical_manifest_present,
                "observedAt": self.observed_at,
            },
        }


def _resolution(data: Any, label: str, expected_class: str) -> CanonicalSourceResolution:
    value = _mapping(
        data,
        label,
        {"sourceClass", "requestedRef", "identity", "releaseStatus", "verifiedModules", "verifiedSelfTests"},
    )
    source_class = _string(value["sourceClass"], f"{label}.sourceClass")
    if source_class not in CANONICAL_SOURCE_CLASSES or source_class != expected_class:
        raise LifecycleError(f"{label}.sourceClass must be {expected_class}")
    identity = (
        None
        if value["identity"] is None
        else CanonicalSourceIdentity.from_mapping(value["identity"], f"{label}.identity")
    )
    return CanonicalSourceResolution(
        source_class,
        _nullable_string(value["requestedRef"], f"{label}.requestedRef"),
        identity,
        _nullable_string(value["releaseStatus"], f"{label}.releaseStatus"),
        _string_list(value["verifiedModules"], f"{label}.verifiedModules", empty=True),
        _string_list(value["verifiedSelfTests"], f"{label}.verifiedSelfTests", empty=True),
    )


def normalize_canonical_source_descriptor(data: Any) -> CanonicalSourceDescriptor:
    """Validate catalog syntax and cross-field trust/installability invariants."""
    root = _mapping(
        data,
        "canonical source descriptor",
        {
            "formatVersion", "sourceId", "application", "authority", "requirements",
            "canonicalResolution", "developmentCandidate", "trust", "status", "observations",
        },
    )
    if root["formatVersion"] != CANONICAL_SOURCE_DESCRIPTOR_FORMAT:
        raise LifecycleError(f"formatVersion must be {CANONICAL_SOURCE_DESCRIPTOR_FORMAT!r}")

    application = _mapping(root["application"], "application", {"id", "publicName", "legacyIdentifiers"})
    authority = _mapping(
        root["authority"],
        "authority",
        {"repository", "canonicalRefPolicy", "manifestPath", "manifestContract"},
    )
    requirements = _mapping(root["requirements"], "requirements", {"modules", "selfTests"})
    trust_data = _mapping(
        root["trust"],
        "trust",
        {"state", "canonicalInstallAllowed", "developmentTestingAllowed"},
    )
    status_data = _mapping(root["status"], "status", {"code", "installable", "unresolvedReason"})
    observations = _mapping(
        root["observations"],
        "observations",
        {"canonicalRef", "canonicalCommit", "canonicalManifestPresent", "observedAt"},
    )

    repository = _remote_repository(authority["repository"], "authority.repository")
    policy = _string(authority["canonicalRefPolicy"], "authority.canonicalRefPolicy")
    if policy != "immutable_release_tag":
        raise LifecycleError("authority.canonicalRefPolicy must be immutable_release_tag")
    manifest_path = _confined_path(authority["manifestPath"], "authority.manifestPath")
    if manifest_path != _CANONICAL_MANIFEST_PATH:
        raise LifecycleError(
            f"authority.manifestPath must be {_CANONICAL_MANIFEST_PATH!r} until one configurable manifest authority is supported"
        )
    manifest_contract = _string(authority["manifestContract"], "authority.manifestContract")
    if manifest_contract != "statedd.template-manifest/v2":
        raise LifecycleError("authority.manifestContract must be statedd.template-manifest/v2")

    required_modules = _string_list(requirements["modules"], "requirements.modules")
    expected_self_tests = _string_list(requirements["selfTests"], "requirements.selfTests")
    canonical = _resolution(root["canonicalResolution"], "canonicalResolution", "canonical_release")
    candidate = (
        None
        if root["developmentCandidate"] is None
        else _resolution(root["developmentCandidate"], "developmentCandidate", "development_candidate")
    )

    trust_state = _string(trust_data["state"], "trust.state")
    if trust_state not in CANONICAL_SOURCE_TRUST_STATES:
        raise LifecycleError(f"trust.state must be one of {sorted(CANONICAL_SOURCE_TRUST_STATES)}")
    if not isinstance(trust_data["canonicalInstallAllowed"], bool) or not isinstance(
        trust_data["developmentTestingAllowed"], bool
    ):
        raise LifecycleError("trust permission fields must be booleans")
    trust = CanonicalSourceTrust(
        trust_state,
        trust_data["canonicalInstallAllowed"],
        trust_data["developmentTestingAllowed"],
    )

    status_code = _string(status_data["code"], "status.code")
    if status_code not in CANONICAL_SOURCE_STATUS_CODES:
        raise LifecycleError(f"status.code must be one of {sorted(CANONICAL_SOURCE_STATUS_CODES)}")
    if not isinstance(status_data["installable"], bool):
        raise LifecycleError("status.installable must be a boolean")
    status = CanonicalSourceStatus(
        status_code,
        status_data["installable"],
        _nullable_string(status_data["unresolvedReason"], "status.unresolvedReason"),
    )

    for label, resolution in (("canonicalResolution", canonical), ("developmentCandidate", candidate)):
        if resolution is None:
            continue
        if resolution.identity is not None and resolution.identity.repository != repository:
            raise LifecycleError(f"{label}.identity.repository must match authority.repository")
        if resolution.identity is None and any(
            (resolution.requested_ref, resolution.release_status, resolution.verified_modules, resolution.verified_self_tests)
        ):
            raise LifecycleError(f"{label} cannot claim verification without immutable identity")

    if canonical.identity is not None:
        if canonical.requested_ref is None or not _RELEASE_REF.fullmatch(canonical.requested_ref):
            raise LifecycleError("canonicalResolution.requestedRef must be an immutable semantic release tag")
        if canonical.release_status != "released":
            raise LifecycleError("canonicalResolution.releaseStatus must be released")
        if not set(required_modules).issubset(canonical.verified_modules):
            raise LifecycleError("canonical resolution is missing a required module")
        if not set(expected_self_tests).issubset(canonical.verified_self_tests):
            raise LifecycleError("canonical resolution is missing a successful expected self-test")
    if candidate is not None:
        if candidate.identity is None or not _FULL_OID.fullmatch(candidate.identity.commit):
            raise LifecycleError("developmentCandidate requires an immutable identity")
        if candidate.requested_ref is None:
            raise LifecycleError("developmentCandidate.requestedRef is required")
        if candidate.release_status != "candidate":
            raise LifecycleError("developmentCandidate.releaseStatus must be candidate")
        if not set(required_modules).issubset(candidate.verified_modules):
            raise LifecycleError("development candidate is missing a required module")
        if not set(expected_self_tests).issubset(candidate.verified_self_tests):
            raise LifecycleError("development candidate is missing a successful expected self-test")

    effective_installable = bool(
        canonical.identity
        and trust.state == "verified_release"
        and trust.canonical_install_allowed
        and status.code == "source_available"
    )
    if status.installable != effective_installable:
        raise LifecycleError("status.installable disagrees with canonical identity and trust policy")
    if canonical.identity is None:
        if status.code != "awaiting_verified_release" or status.unresolved_reason is None:
            raise LifecycleError("unresolved canonical sources require an explicit unresolved reason")
        if trust.canonical_install_allowed:
            raise LifecycleError("unresolved canonical sources cannot allow installation")
    elif status.unresolved_reason is not None:
        raise LifecycleError("resolved canonical sources cannot retain an unresolved reason")
    if candidate is not None and trust.development_testing_allowed is not True:
        raise LifecycleError("a recorded development candidate requires explicit development-only permission")
    if candidate is not None and candidate.identity == canonical.identity:
        raise LifecycleError("a development candidate cannot be substituted for the canonical release")

    canonical_commit = _string(observations["canonicalCommit"], "observations.canonicalCommit")
    if not _FULL_OID.fullmatch(canonical_commit):
        raise LifecycleError("observations.canonicalCommit must be a lowercase full Git object ID")
    if not isinstance(observations["canonicalManifestPresent"], bool):
        raise LifecycleError("observations.canonicalManifestPresent must be a boolean")

    return CanonicalSourceDescriptor(
        _string(root["sourceId"], "sourceId"),
        _string(application["id"], "application.id"),
        _string(application["publicName"], "application.publicName"),
        _string_list(application["legacyIdentifiers"], "application.legacyIdentifiers", empty=True),
        repository,
        policy,
        manifest_path,
        manifest_contract,
        required_modules,
        expected_self_tests,
        canonical,
        candidate,
        trust,
        status,
        _string(observations["canonicalRef"], "observations.canonicalRef"),
        canonical_commit,
        observations["canonicalManifestPresent"],
        _string(observations["observedAt"], "observations.observedAt"),
    )


def load_canonical_source_descriptor(path: Path | str) -> CanonicalSourceDescriptor:
    """Load tracked metadata without fetching, resolving, or trusting local paths."""
    try:
        data = parse_yaml_text(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, StateDDYamlError) as exc:
        raise LifecycleError("canonical source descriptor could not be read safely") from exc
    return normalize_canonical_source_descriptor(data)
