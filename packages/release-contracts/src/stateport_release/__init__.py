"""Digest-bound StatePort release and update contracts."""

from dataclasses import dataclass
import os
from pathlib import Path
import platform
import re
from typing import Final, Mapping

from .cosign import (
    CosignVerificationError,
    CosignVerifier,
    bundle_slot,
    public_key_der_spki_fingerprint,
    retain_bundle,
    signature_bundle_name,
)
from .contract import (
    ReleaseContractError,
    AuthoritySourceResolver,
    ReleaseIndex,
    ReleaseVerificationPolicy,
    PinnedPublicKeyIdentity,
    SignatureVerificationProof,
    SignatureVerifier,
    SignerIdentity,
    UpdaterReleaseEnvelope,
    ValidatedContract,
    VerifiedRelease,
    canonical_digest,
    canonical_json_bytes,
    embedded_predecessor_index,
    image_set_digest,
    installer_directive_digest,
    release_identity_from_verified,
    reverify_updater_release_envelope,
    load_release_index,
    load_release_index_file,
    quadlet_bundle_digest,
    materialize_verified_quadlet_bundle,
    materialize_accepted_quadlet_bundle,
    owner_materialization_spec_digest,
    parse_last_line_json,
    derive_revision_authority_proofs,
    plan_stable_host_service_transition,
    record_revision_port_activation_recheck,
    reserve_revision_port_allocation,
    render_accepted_activation,
    revision_contract_digest,
    render_quadlet_bundle,
    render_stable_host_quadlet_bundle,
    revision_volume_key,
    service_set_digest,
    topology_digest,
    signed_payload_bytes,
    signature_verification_proof_set,
    signature_verification_proof_set_digest,
    to_updater_release_envelope,
    validate_contract_document,
    validate_install_receipt,
    validate_revision_contract,
    validate_release_index,
    validate_release_provenance,
    validate_update_failure_evidence,
    validate_update_authority_link,
    validate_update_plan,
    validate_update_receipt,
    validate_update_status,
    update_plan_digest,
    update_policy_digest,
    verify_release_index,
    verify_quadlet_bundle,
    verify_stable_host_quadlet_bundle,
    validate_activation_pointer_transition,
)
PORTABLE_LINUX_TARGET_ID: Final = "linux-amd64-rootless-podman-quadlet"
WSL2_TARGET_ID: Final = "wsl2-ubuntu2404-linux-amd64-rootless-podman-quadlet"
SUPPORTED_TARGET_IDS: Final = frozenset({PORTABLE_LINUX_TARGET_ID, WSL2_TARGET_ID})
PODMAN_MINIMUM: Final = (5, 0, 0)
VALIDATED_LINUX_BASELINES: Final = frozenset({("ubuntu", "24.04")})

_PROVISIONING_EXPORTS = frozenset(
    {
        "ProvisioningRefusal",
        "apply_verified_plan",
        "probe_protocol_health",
        "render_provisioning_plan",
    }
)


def __getattr__(name: str):
    if name in _PROVISIONING_EXPORTS:
        from . import execution_host_provisioning

        return getattr(execution_host_provisioning, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


@dataclass(frozen=True)
class LinuxSubstrateObservation:
    """Linux substrate evidence collected without probing mutable services."""

    kernel_release: str
    proc_version: str
    wsl_interop_present: bool
    wsl_distro_name_present: bool

    @property
    def substrate(self) -> str:
        markers = (self.kernel_release.casefold(), self.proc_version.casefold())
        if not any("microsoft" in marker for marker in markers):
            return "native-linux"
        return "wsl2" if any("wsl2" in marker for marker in markers) else "wsl1"


def observe_linux_substrate(
    *,
    kernel_release: str | None = None,
    proc_version_path: Path = Path("/proc/version"),
    environment: Mapping[str, str] | None = None,
) -> LinuxSubstrateObservation:
    """Observe WSL from kernel-owned identity, retaining environment corroboration."""

    try:
        proc_version = proc_version_path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        proc_version = ""
    environment = os.environ if environment is None else environment
    return LinuxSubstrateObservation(
        kernel_release=platform.release() if kernel_release is None else kernel_release,
        proc_version=proc_version,
        wsl_interop_present=bool(environment.get("WSL_INTEROP")),
        wsl_distro_name_present=bool(environment.get("WSL_DISTRO_NAME")),
    )


@dataclass(frozen=True)
class LinuxHostObservation:
    """Observed host facts; distribution identity is evidence, not authority."""

    kernel: str
    architecture: str
    os_id: str
    version_id: str
    cgroup_version: str
    podman_version: str
    rootless: bool
    quadlet: bool
    systemd_user: bool
    subuid_configured: bool
    subgid_configured: bool
    substrate: LinuxSubstrateObservation


@dataclass(frozen=True)
class LinuxHostDecision:
    """Capability eligibility kept separate from clean-install qualification."""

    eligible: bool
    target_id: str
    support_tier: str
    refusal_codes: tuple[str, ...]
    warnings: tuple[str, ...]
    observation: LinuxHostObservation

    def to_dict(self) -> dict[str, object]:
        return {
            "formatVersion": "stateport.linux-host-capability-decision/v1",
            "eligible": self.eligible,
            "targetId": self.target_id,
            "supportTier": self.support_tier,
            "refusalCodes": list(self.refusal_codes),
            "warnings": list(self.warnings),
            "observation": {
                "kernel": self.observation.kernel,
                "architecture": self.observation.architecture,
                "osId": self.observation.os_id,
                "versionId": self.observation.version_id,
                "cgroupVersion": self.observation.cgroup_version,
                "podmanVersion": self.observation.podman_version,
                "rootless": self.observation.rootless,
                "quadlet": self.observation.quadlet,
                "systemdUser": self.observation.systemd_user,
                "subuidConfigured": self.observation.subuid_configured,
                "subgidConfigured": self.observation.subgid_configured,
                "substrate": self.observation.substrate.substrate,
                "kernelRelease": self.observation.substrate.kernel_release,
                "wslInteropPresent": self.observation.substrate.wsl_interop_present,
                "wslDistroNamePresent": self.observation.substrate.wsl_distro_name_present,
            },
        }


def parse_host_semantic_version(value: str) -> tuple[int, int, int] | None:
    """Return a leading semantic version while accepting vendor suffixes."""

    match = re.match(r"^\s*(\d+)\.(\d+)\.(\d+)(?:\D.*)?$", value)
    if match is None:
        return None
    major, minor, patch = (int(part) for part in match.groups())
    return major, minor, patch


def evaluate_linux_host(observation: LinuxHostObservation) -> LinuxHostDecision:
    """Qualify a host by required behavior, never by distribution branding.

    Eligibility means the runtime contract is present. It does not mean that
    exact distribution/version has a clean-install acceptance receipt. That
    evidence distinction is represented by ``support_tier``.
    """

    refusals: list[str] = []
    warnings: list[str] = []

    substrate = observation.substrate.substrate
    target_id = WSL2_TARGET_ID if substrate == "wsl2" else PORTABLE_LINUX_TARGET_ID
    if substrate == "wsl1":
        refusals.append("wsl1_substrate_unsupported")
    if observation.kernel.lower() != "linux":
        refusals.append("linux_kernel_required")
    if observation.architecture not in {"amd64", "x86_64"}:
        refusals.append("linux_amd64_required")
    if observation.cgroup_version != "v2":
        refusals.append("cgroup_v2_required")

    podman_version = parse_host_semantic_version(observation.podman_version)
    if podman_version is None:
        refusals.append("podman_version_unparseable")
    elif podman_version < PODMAN_MINIMUM:
        refusals.append("podman_version_too_old")

    if not observation.rootless:
        refusals.append("rootless_podman_required")
    if not observation.quadlet:
        refusals.append("quadlet_required")
    if not observation.systemd_user:
        refusals.append("systemd_user_required")
    if not observation.subuid_configured:
        refusals.append("subuid_mapping_required")
    if not observation.subgid_configured:
        refusals.append("subgid_mapping_required")

    baseline = (observation.os_id.lower(), observation.version_id)
    if substrate == "wsl2" and baseline != ("ubuntu", "24.04"):
        refusals.append("wsl2_ubuntu_2404_required")
    if refusals:
        support_tier = "ineligible"
    elif substrate == "wsl2":
        support_tier = "compatible_unvalidated"
        warnings.append(
            "host capabilities match, but this WSL2 target lacks a clean-install acceptance receipt"
        )
    elif baseline in VALIDATED_LINUX_BASELINES:
        support_tier = "validated_baseline"
    else:
        support_tier = "compatible_unvalidated"
        warnings.append(
            "host capabilities match, but this distribution/version lacks a clean-install acceptance receipt"
        )

    return LinuxHostDecision(
        eligible=not refusals,
        target_id=target_id,
        support_tier=support_tier,
        refusal_codes=tuple(refusals),
        warnings=tuple(warnings),
        observation=observation,
    )


__all__ = [
    "ReleaseContractError",
    "AuthoritySourceResolver",
    "CosignVerificationError",
    "CosignVerifier",
    "ReleaseIndex",
    "ReleaseVerificationPolicy",
    "PinnedPublicKeyIdentity",
    "SignatureVerificationProof",
    "SignatureVerifier",
    "SignerIdentity",
    "UpdaterReleaseEnvelope",
    "ValidatedContract",
    "VerifiedRelease",
    "ProvisioningRefusal",
    "LinuxSubstrateObservation",
    "LinuxHostObservation",
    "LinuxHostDecision",
    "PORTABLE_LINUX_TARGET_ID",
    "WSL2_TARGET_ID",
    "SUPPORTED_TARGET_IDS",
    "PODMAN_MINIMUM",
    "VALIDATED_LINUX_BASELINES",
    "parse_host_semantic_version",
    "observe_linux_substrate",
    "evaluate_linux_host",
    "apply_verified_plan",
    "canonical_digest",
    "canonical_json_bytes",
    "embedded_predecessor_index",
    "image_set_digest",
    "installer_directive_digest",
    "release_identity_from_verified",
    "reverify_updater_release_envelope",
    "load_release_index",
    "load_release_index_file",
    "quadlet_bundle_digest",
    "materialize_verified_quadlet_bundle",
    "materialize_accepted_quadlet_bundle",
    "owner_materialization_spec_digest",
    "parse_last_line_json",
    "derive_revision_authority_proofs",
    "plan_stable_host_service_transition",
    "probe_protocol_health",
    "record_revision_port_activation_recheck",
    "reserve_revision_port_allocation",
    "render_accepted_activation",
    "revision_contract_digest",
    "render_quadlet_bundle",
    "render_provisioning_plan",
    "render_stable_host_quadlet_bundle",
    "revision_volume_key",
    "service_set_digest",
    "topology_digest",
    "signed_payload_bytes",
    "signature_verification_proof_set",
    "signature_verification_proof_set_digest",
    "to_updater_release_envelope",
    "validate_contract_document",
    "validate_install_receipt",
    "validate_revision_contract",
    "validate_release_index",
    "validate_release_provenance",
    "validate_update_failure_evidence",
    "validate_update_authority_link",
    "validate_update_plan",
    "validate_update_receipt",
    "validate_update_status",
    "update_plan_digest",
    "update_policy_digest",
    "bundle_slot",
    "public_key_der_spki_fingerprint",
    "retain_bundle",
    "signature_bundle_name",
    "verify_release_index",
    "verify_quadlet_bundle",
    "verify_stable_host_quadlet_bundle",
    "validate_activation_pointer_transition",
]
