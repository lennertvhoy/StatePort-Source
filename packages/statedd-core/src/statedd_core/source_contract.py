"""Explicit, immutable source selection for StatePort operator demos.

The source contract is intentionally separate from a template checkout path.
Paths are observations used to access bytes; the selected source identity is
the exact Git commit, resolved tree, manifest digest, and StateDD policy.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit

from statedd_core.lifecycle import load_template_manifest, resolve_git_source
from statedd_core.lifecycle_errors import LifecycleError
from statedd_core.yaml import StateDDYamlError, parse_yaml_text


SOURCE_CONTRACT_FORMAT = "stateport.source-contract/v1"
BUILTIN_STUDYDD_PROFILE = "builtin:studydd-local-alpha"
_FULL_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_FULL_TREE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class SourceSelectionError(ValueError):
    """An expected source-input failure with a stable diagnostic envelope."""

    def __init__(self, diagnostic: Any) -> None:
        self.diagnostic = diagnostic
        super().__init__(diagnostic.explanation)


@dataclass(frozen=True)
class SourceContract:
    format_version: str
    template_id: str
    repository: str
    commit: str
    manifest_path: str = ".statedd/manifest.yaml"
    expected_tree: str | None = None
    expected_manifest_digest: str | None = None
    source_class: str = "canonical_source"
    production_eligible: bool = True
    profile: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.format_version,
            "template": {"id": self.template_id},
            "source": {
                "repository": self.repository,
                "commit": self.commit,
                "manifestPath": self.manifest_path,
                "expectedTree": self.expected_tree,
                "expectedManifestDigest": self.expected_manifest_digest,
                "class": self.source_class,
                "productionEligible": self.production_eligible,
            },
            "profile": self.profile,
        }


@dataclass(frozen=True)
class ResolvedSource:
    contract: SourceContract
    root: Path
    descriptor: dict[str, Any]
    manifest: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "templateId": self.contract.template_id,
            "repository": self.descriptor["repository"],
            "requestedRef": self.descriptor["requestedRef"],
            "resolvedCommit": self.descriptor["resolvedCommit"],
            "resolvedTree": self.descriptor["resolvedTree"],
            "manifestPath": self.contract.manifest_path,
            "manifestDigest": self.descriptor["manifestDigest"],
            "sourceDigest": self.descriptor["sourceDigest"],
            "sourceClass": self.descriptor["sourceClass"],
            "productionEligible": self.descriptor["productionEligible"],
            "checkoutLocation": self.root.as_posix(),
            "profile": self.contract.profile,
        }


def _required_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value.strip()


def _strict_mapping(value: Any, label: str, allowed: set[str], required: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be a mapping")
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(f"{label} contains unknown fields: {', '.join(unknown)}")
    missing = sorted(required - set(value))
    if missing:
        raise ValueError(f"{label} is missing required fields: {', '.join(missing)}")
    return value


def _safe_repository(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme and parsed.netloc:
        netloc = parsed.hostname or "<invalid>"
        if parsed.port:
            netloc += f":{parsed.port}"
        return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))
    return value


def _safe_ref(value: str) -> str:
    return value if _FULL_COMMIT.fullmatch(value) else "<invalid-ref>"


def _diagnostic(
    code: str,
    explanation: str,
    *,
    repository: str,
    requested_ref: str,
    remediation: str,
    details: Mapping[str, Any] | None = None,
) -> Any:
    from diagnostics import Diagnostic

    return Diagnostic(
        code,
        "error",
        "source",
        explanation,
        {
            "repository": _safe_repository(repository),
            "requestedRef": _safe_ref(requested_ref),
            **dict(details or {}),
        },
        remediation,
        ("source contract", "immutable Git resolver"),
    )


def _raise(
    code: str,
    explanation: str,
    *,
    repository: str,
    requested_ref: str,
    remediation: str,
    details: Mapping[str, Any] | None = None,
) -> None:
    raise SourceSelectionError(
        _diagnostic(
            code,
            explanation,
            repository=repository,
            requested_ref=requested_ref,
            remediation=remediation,
            details=details,
        )
    )


def _validate_contract(contract: SourceContract) -> SourceContract:
    if contract.format_version != SOURCE_CONTRACT_FORMAT:
        raise ValueError(f"formatVersion must be {SOURCE_CONTRACT_FORMAT!r}")
    template_id = _required_string(contract.template_id, "template.id")
    repository = _required_string(contract.repository, "source.repository")
    commit = _required_string(contract.commit, "source.commit").lower()
    if not _FULL_COMMIT.fullmatch(commit):
        raise ValueError("source.commit must be a lowercase 40-character Git commit")
    manifest_path = _required_string(contract.manifest_path, "source.manifestPath")
    candidate = Path(manifest_path)
    if candidate.is_absolute() or any(part in {".", ".."} for part in candidate.parts):
        raise ValueError("source.manifestPath must be a confined relative path")
    if Path(manifest_path).as_posix() != ".statedd/manifest.yaml":
        raise ValueError(
            "source.manifestPath must be '.statedd/manifest.yaml' until one configurable manifest authority is supported"
        )
    if contract.source_class != "canonical_source" or contract.production_eligible is not True:
        raise ValueError("demo sources must be production-eligible canonical_source values")
    if contract.expected_tree is not None:
        expected_tree = _required_string(contract.expected_tree, "source.expectedTree").lower()
        if not _FULL_TREE.fullmatch(expected_tree):
            raise ValueError("source.expectedTree must be a full Git tree id")
    else:
        expected_tree = None
    if contract.expected_manifest_digest is not None:
        manifest_digest = _required_string(
            contract.expected_manifest_digest, "source.expectedManifestDigest"
        ).lower()
        if not _DIGEST.fullmatch(manifest_digest):
            raise ValueError("source.expectedManifestDigest must be a sha256 digest")
    else:
        manifest_digest = None
    return SourceContract(
        SOURCE_CONTRACT_FORMAT,
        template_id,
        repository,
        commit,
        Path(manifest_path).as_posix(),
        expected_tree,
        manifest_digest,
        contract.source_class,
        True,
        contract.profile,
    )


def _contract_from_mapping(data: Mapping[str, Any], *, profile: str | None = None) -> SourceContract:
    data = _strict_mapping(
        data,
        "source contract",
        {"formatVersion", "template", "source"},
        {"formatVersion", "template", "source"},
    )
    template = _strict_mapping(data["template"], "template", {"id"}, {"id"})
    source = _strict_mapping(
        data["source"],
        "source",
        {
            "repository", "commit", "manifestPath", "expectedTree",
            "expectedManifestDigest", "class", "productionEligible",
        },
        {"repository", "commit"},
    )
    return _validate_contract(
        SourceContract(
            _required_string(data.get("formatVersion"), "formatVersion"),
            _required_string(template.get("id"), "template.id"),
            _required_string(source.get("repository"), "source.repository"),
            _required_string(source.get("commit"), "source.commit"),
            source.get("manifestPath", ".statedd/manifest.yaml"),
            source.get("expectedTree"),
            source.get("expectedManifestDigest"),
            source.get("class", "canonical_source"),
            source.get("productionEligible", True),
            profile,
        )
    )


def load_source_contract(path: Path | str) -> SourceContract:
    try:
        data = parse_yaml_text(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, StateDDYamlError) as exc:
        raise ValueError(f"could not read source profile: {exc}") from exc
    return _contract_from_mapping(data, profile=Path(path).as_posix())


def load_builtin_source_contract(name: str) -> SourceContract:
    if name != BUILTIN_STUDYDD_PROFILE:
        raise ValueError(f"unknown built-in source profile: {name}")
    path = Path(__file__).resolve().parents[4] / "sources" / "profiles" / "studydd-local-alpha.yaml"
    try:
        data = parse_yaml_text(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, StateDDYamlError) as exc:
        raise ValueError(f"could not read built-in source profile: {exc}") from exc
    return _contract_from_mapping(data, profile=name)


def _map_resolver_error(
    exc: LifecycleError,
    *,
    repository: str,
    requested_ref: str,
    root: Path | None,
) -> None:
    message = str(exc)
    lowered = message.lower()
    if root is not None and not root.exists():
        _raise(
            "SP-SOURCE-REPOSITORY-NOT-FOUND",
            "The explicit local Git source path does not exist.",
            repository=repository,
            requested_ref=requested_ref,
            remediation="Provide an existing Git repository or use a versioned source profile with an available checkout.",
            details={"pathState": "missing"},
        )
    if "manifest" in lowered and ("missing" in lowered or "read" in lowered or "file" in lowered):
        _raise(
            "SP-SOURCE-MANIFEST-NOT-FOUND",
            "The selected commit does not provide the required lifecycle manifest.",
            repository=repository,
            requested_ref=requested_ref,
            remediation="Use a StudyState commit containing .statedd/manifest.yaml in the selected tree.",
            details={"manifestPath": ".statedd/manifest.yaml"},
        )
    if "not a git checkout" in lowered or "git source checkout" in lowered:
        _raise(
            "SP-SOURCE-REPOSITORY-NOT-FOUND",
            "The explicit source is not a usable Git repository.",
            repository=repository,
            requested_ref=requested_ref,
            remediation="Provide a Git repository or an explicit local mirror containing the requested commit; copied directories are not accepted.",
            details={"pathState": "not-git"},
        )
    if "rev-parse" in lowered or "unknown revision" in lowered or "expected_commit" in lowered:
        _raise(
            "SP-SOURCE-COMMIT-NOT-FOUND",
            "The requested immutable Git commit cannot be resolved in the explicit source.",
            repository=repository,
            requested_ref=requested_ref,
            remediation="Fetch or provide a mirror containing the exact 40-character commit, then retry.",
            details={"resolverMessage": "Git could not resolve the requested commit"},
        )
    _raise(
        "SP-SOURCE-IDENTITY-MISMATCH",
        "The explicit source failed immutable identity or production-policy verification.",
        repository=repository,
        requested_ref=requested_ref,
        remediation="Use the exact canonical StudyState source commit and a clean Git checkout whose manifest matches the contract.",
        details={"resolverMessage": "source verification failed"},
    )


def resolve_source_contract(
    contract: SourceContract,
    *,
    repository_override: Path | str | None = None,
    checkout_path: Path | str | None = None,
) -> ResolvedSource:
    """Resolve and verify one explicit source before instance creation."""
    try:
        contract = _validate_contract(contract)
    except ValueError as exc:
        _raise(
            "SP-SOURCE-IDENTITY-MISMATCH",
            "The explicit source contract is invalid and cannot identify a source.",
            repository=str(getattr(contract, "repository", "<invalid>")),
            requested_ref=str(getattr(contract, "commit", "<invalid-ref>")),
            remediation="Provide a repository, exact 40-character commit, expected template ID, and supported source policy.",
            details={"contractError": str(exc)},
        )
    repository = str(repository_override) if repository_override is not None else contract.repository
    local_root = Path(repository).expanduser() if not _looks_remote(repository) else None
    if local_root is not None and not local_root.exists():
        _raise(
            "SP-SOURCE-REPOSITORY-NOT-FOUND",
            "The explicit local Git source path does not exist.",
            repository=repository,
            requested_ref=contract.commit,
            remediation="Provide an existing Git repository or use a versioned source profile with an available checkout.",
            details={"pathState": "missing"},
        )
    try:
        descriptor = resolve_git_source(
            repository,
            requested_ref=contract.commit,
            checkout_path=checkout_path,
            expected_commit=contract.commit,
        )
    except LifecycleError as exc:
        _map_resolver_error(
            exc,
            repository=repository,
            requested_ref=contract.commit,
            root=local_root,
        )
        raise AssertionError("unreachable")
    root = Path(descriptor["checkoutLocation"])
    if _looks_remote(contract.repository) and descriptor.get("repository") != contract.repository:
        _raise(
            "SP-SOURCE-IDENTITY-MISMATCH",
            "The local mirror origin does not match the repository bound by the source contract.",
            repository=contract.repository,
            requested_ref=contract.commit,
            remediation="Use a mirror cloned from the configured StudyState repository or resolve the configured URL directly.",
            details={"resolvedRepository": _safe_repository(str(descriptor.get("repository", "")))},
        )
    if descriptor.get("resolvedCommit") != contract.commit:
        _raise(
            "SP-SOURCE-IDENTITY-MISMATCH",
            "The resolved commit does not equal the requested immutable commit.",
            repository=repository,
            requested_ref=contract.commit,
            remediation="Retry with a clean mirror containing the exact requested commit.",
            details={"resolvedCommit": descriptor.get("resolvedCommit")},
        )
    if contract.expected_tree is not None and descriptor.get("resolvedTree") != contract.expected_tree:
        _raise(
            "SP-SOURCE-IDENTITY-MISMATCH",
            "The resolved Git tree does not match the source contract.",
            repository=repository,
            requested_ref=contract.commit,
            remediation="Use the exact StudyState commit/tree bound by the versioned source profile.",
            details={"expectedTree": contract.expected_tree, "resolvedTree": descriptor.get("resolvedTree")},
        )
    manifest_path = root / contract.manifest_path
    if not manifest_path.is_file():
        _raise(
            "SP-SOURCE-MANIFEST-NOT-FOUND",
            "The selected commit does not provide the required lifecycle manifest.",
            repository=repository,
            requested_ref=contract.commit,
            remediation=f"Use a StudyState commit containing {contract.manifest_path} in the selected tree.",
            details={"manifestPath": contract.manifest_path},
        )
    try:
        manifest = load_template_manifest(root)
    except LifecycleError as exc:
        if "manifest" in str(exc).lower() and "formatversion" not in str(exc).lower():
            _raise(
                "SP-SOURCE-MANIFEST-NOT-FOUND",
                "The selected commit does not provide a usable lifecycle manifest.",
                repository=repository,
                requested_ref=contract.commit,
                remediation="Use a commit with a supported .statedd/manifest.yaml.",
                details={"manifestPath": contract.manifest_path},
            )
        _raise(
            "SP-SOURCE-IDENTITY-MISMATCH",
            "The selected lifecycle manifest is not supported by the StatePort demo policy.",
            repository=repository,
            requested_ref=contract.commit,
            remediation="Use a canonical StudyState v2 lifecycle manifest with production eligibility enabled.",
            details={"manifestPath": contract.manifest_path},
        )
        raise AssertionError("unreachable")
    if manifest.get("templateId") != contract.template_id:
        _raise(
            "SP-SOURCE-TEMPLATE-ID-MISMATCH",
            "The selected source manifest has the wrong template ID.",
            repository=repository,
            requested_ref=contract.commit,
            remediation=f"Use a source whose manifest template ID is {contract.template_id!r}.",
            details={"expectedTemplateId": contract.template_id, "resolvedTemplateId": manifest.get("templateId")},
        )
    if manifest.get("sourceClass") != contract.source_class or manifest.get("productionEligible") is not contract.production_eligible:
        _raise(
            "SP-SOURCE-IDENTITY-MISMATCH",
            "The selected source class or production eligibility is not allowed by the demo policy.",
            repository=repository,
            requested_ref=contract.commit,
            remediation="Use the production-eligible canonical StudyState source, not a fixture or copied directory.",
            details={"sourceClass": manifest.get("sourceClass"), "productionEligible": manifest.get("productionEligible")},
        )
    actual_manifest_digest = descriptor["manifestDigest"]
    if contract.expected_manifest_digest is not None and actual_manifest_digest != contract.expected_manifest_digest:
        _raise(
            "SP-SOURCE-IDENTITY-MISMATCH",
            "The selected manifest digest does not match the source contract.",
            repository=repository,
            requested_ref=contract.commit,
            remediation="Use the exact StudyState functional source bound by the versioned profile.",
            details={"expectedManifestDigest": contract.expected_manifest_digest},
        )
    return ResolvedSource(contract, root, descriptor, manifest)


def _looks_remote(repository: str) -> bool:
    return bool(re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", repository) or repository.startswith(("git@", "ssh:")))
