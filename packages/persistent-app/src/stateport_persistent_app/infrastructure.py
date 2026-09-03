"""Governed local infrastructure operations for the NixOS daily-driver app.

This module deliberately supports one real target: the user-owned
``nixos-homelab`` persistent libvirt VM.  The repository remains the authority
for Nix and libvirt behavior; StatePort owns identity binding, approval,
single-writer leasing, normalized observations, recovery state, and receipts.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import base64
import binascii
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import tempfile
import time
from typing import Any, Callable, Iterator, Mapping, Sequence

try:
    from governed_runner.lease import InstanceLease, InstanceLeaseBusy, InstanceLeaseError
except ModuleNotFoundError:  # Source-tree tests may not pre-install sibling packages.
    InstanceLease = None  # type: ignore[assignment,misc]


FORMAT = "stateport.infrastructure-local-libvirt/v1"
RECEIPT_FORMAT = "stateport.infrastructure-receipt/v1"
RUN_FORMAT = "stateport.infrastructure-run/v1"
# Local libvirt target identity. Neutral defaults ship in source; a private
# operator installation binds its real VM identity through environment
# overrides that stay outside Git.
VM_NAME = os.environ.get("STATEPORT_LOCAL_LIBVIRT_DOMAIN", "stateport-persistent-vm")
VM_DOMAIN_UUID = os.environ.get(
    "STATEPORT_LOCAL_LIBVIRT_DOMAIN_UUID", "00000000-0000-0000-0000-000000000000"
)
VM_SSH_PORT = int(os.environ.get("STATEPORT_LOCAL_LIBVIRT_SSH_PORT", "2223"))
VM_SSH_USER = os.environ.get("STATEPORT_LOCAL_LIBVIRT_SSH_USER", "stateport-operator")
VM_SSH_HOST = os.environ.get("STATEPORT_LOCAL_LIBVIRT_SSH_HOST", "localhost")
VM_SSH_KNOWN_HOST_ALIAS = f"[{VM_SSH_HOST}]:{VM_SSH_PORT}"
VM_CONNECTION = os.environ.get("STATEPORT_LOCAL_LIBVIRT_CONNECTION", "qemu:///session")
PLAN_TTL_SECONDS = 1800
MAX_OUTPUT_BYTES = 12_000
MAX_RUN_RECORD_BYTES = 512 * 1024
SSH_POLICY_FORMAT = "stateport.ssh-host-verification-policy/v1"
SSH_ENROLLMENT_FORMAT = "stateport.ssh-host-key-enrollment/v1"
SSH_RECEIPT_FORMAT = "stateport.ssh-verification-receipt/v1"
DAILY_DRIVER_GRANT_FORMAT = "stateport.infrastructure-daily-driver-grant/v1"
DAILY_DRIVER_GRANT_ID = "nixos-infrastructure-local-daily-driver"
SSH_REASON_CODES = frozenset({
    "ssh_not_configured",
    "ssh_key_not_enrolled",
    "ssh_host_key_mismatch",
    "ssh_host_verification_failed",
    "ssh_connection_refused",
    "ssh_timed_out",
    "ssh_authentication_failed",
    "ssh_ready",
    "ssh_health_degraded",
})
MUTATING_OPERATIONS = frozenset({"create_or_update", "start", "stop", "restart", "destroy"})
READ_ONLY_OPERATIONS = frozenset({"validate", "observe", "health"})
OPERATIONS = MUTATING_OPERATIONS | READ_ONLY_OPERATIONS
RECEIPT_ACTIONS = {
    "validate": "nix.validation",
    "observe": "libvirt.observe",
    "health": "infrastructure.health",
    "create_or_update": "libvirt.apply",
    "start": "libvirt.start",
    "stop": "libvirt.stop",
    "restart": "libvirt.restart",
    "destroy": "libvirt.destroy",
}
GRANT_OPERATION_MAP = {
    "start": "vm.start",
    "stop": "vm.stop.graceful",
    "restart": "vm.restart",
}
DAILY_DRIVER_ALLOWED_OPERATIONS = (
    "repository.inspect",
    "project.file.edit",
    "project.terminal",
    "vm.observe",
    "vm.health.read",
    "vm.start",
    "vm.stop.graceful",
    "vm.restart",
    "vm.ssh.strict",
)
DAILY_DRIVER_DENIED_OPERATIONS = (
    "capability.expand",
    "cloud.apply",
    "credential.change",
    "git.destructive",
    "vm.create",
    "vm.destroy",
    "vm.rebuild.material",
    "vm.storage.change",
    "vm.network.change",
    "ssh.host-key.rotate",
)


class InfrastructureError(RuntimeError):
    """A bounded infrastructure operation was refused or failed."""

    def __init__(self, code: str, message: str, *, details: Mapping[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.details = dict(details or {})


def _has_git_metadata(root: Path) -> bool:
    """Accept primary clones and linked worktrees, but never metadata symlinks."""

    metadata = root / ".git"
    return (
        root.is_dir()
        and not metadata.is_symlink()
        and (metadata.is_dir() or metadata.is_file())
    )


@dataclass(frozen=True)
class LocalNixDailyDriverGrant:
    """A durable, exact-scope grant for ordinary local VM use.

    The grant intentionally authorizes only reversible lifecycle operations.
    Host-key enrollment and rotation remain separately bound to the exact
    public key observed through a trusted local channel.
    """

    grant_id: str
    instance_id: str
    application_id: str
    repository_root: str
    repository_branch: str
    target: dict[str, Any]
    allowed_operations: tuple[str, ...]
    denied_operations: tuple[str, ...]
    ssh_policy: dict[str, Any]
    onboarding: dict[str, Any]
    status: str
    created_at: str
    proposal_digest: str
    approved_at: str | None = None
    approved_by: str | None = None
    grant_digest: str | None = None

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "formatVersion": DAILY_DRIVER_GRANT_FORMAT,
            "grantId": self.grant_id,
            "instanceId": self.instance_id,
            "applicationId": self.application_id,
            "repository": {"root": self.repository_root, "branch": self.repository_branch},
            "target": self.target,
            "allowedOperations": list(self.allowed_operations),
            "deniedOperations": list(self.denied_operations),
            "sshPolicy": self.ssh_policy,
            "onboarding": self.onboarding,
            "status": self.status,
            "createdAt": self.created_at,
            "proposalDigest": self.proposal_digest,
            "approvedAt": self.approved_at,
            "approvedBy": self.approved_by,
        }
        if self.grant_digest is not None:
            value["grantDigest"] = self.grant_digest
        return value


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _timestamp(value: datetime | None = None) -> str:
    return (value or _now()).isoformat().replace("+00:00", "Z")


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _bounded_text(value: object, limit: int = MAX_OUTPUT_BYTES) -> str:
    text = str(value or "")
    return text if len(text) <= limit else text[:limit] + "\n[truncated]"


def _safe_id(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise InfrastructureError("invalid_identity", f"{name} is invalid")
    if not all(character.isalnum() or character in "._-" for character in value):
        raise InfrastructureError("invalid_identity", f"{name} is invalid")
    return value


def _safe_fingerprint(value: object) -> str:
    if not isinstance(value, str) or not value.startswith("SHA256:"):
        raise ValueError("SSH fingerprint must use SHA256 format")
    encoded = value.removeprefix("SHA256:")
    try:
        decoded = base64.b64decode(encoded + ("=" * (-len(encoded) % 4)), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("SSH fingerprint must use SHA256 format") from exc
    if len(decoded) != 32:
        raise ValueError("SSH fingerprint must use SHA256 format")
    return value


def _fingerprint_from_key(key_data: str) -> str:
    try:
        decoded = base64.b64decode(key_data, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("SSH public key data is invalid") from exc
    if not decoded:
        raise ValueError("SSH public key data is empty")
    return "SHA256:" + base64.b64encode(hashlib.sha256(decoded).digest()).decode("ascii").rstrip("=")


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65_536), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


@dataclass(frozen=True)
class SSHHostKeyFingerprint:
    algorithm: str
    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.algorithm, str) or not self.algorithm.startswith(("ssh-", "ecdsa-", "sk-")):
            raise ValueError("SSH host-key algorithm is invalid")
        _safe_fingerprint(self.value)

    def to_dict(self) -> dict[str, str]:
        return {"algorithm": self.algorithm, "fingerprint": self.value}


@dataclass(frozen=True)
class SSHTargetIdentity:
    application_id: str
    target_id: str
    domain: str
    domain_uuid: str
    host: str
    port: int
    user: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "applicationId": self.application_id,
            "targetId": self.target_id,
            "domain": self.domain,
            "domainUuid": self.domain_uuid,
            "host": self.host,
            "port": self.port,
            "user": self.user,
        }


@dataclass(frozen=True)
class SSHKnownHostIdentity:
    alias: str
    key: SSHHostKeyFingerprint
    provenance: str

    def to_dict(self) -> dict[str, Any]:
        return {"alias": self.alias, "key": self.key.to_dict(), "provenance": self.provenance}


@dataclass(frozen=True)
class SSHHostKeyEnrollment:
    target: SSHTargetIdentity
    known_host: SSHKnownHostIdentity
    enrolled_at: str
    enrollment_receipt_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": SSH_ENROLLMENT_FORMAT,
            "target": self.target.to_dict(),
            "knownHost": self.known_host.to_dict(),
            "enrolledAt": self.enrolled_at,
            "enrollmentReceiptId": self.enrollment_receipt_id,
        }


@dataclass(frozen=True)
class SSHHostKeyRotationProposal:
    target: SSHTargetIdentity
    old_fingerprint: str | None
    new_fingerprint: str
    reason: str
    approval_digest: str | None

    def __post_init__(self) -> None:
        if self.old_fingerprint is not None:
            _safe_fingerprint(self.old_fingerprint)
            if not self.approval_digest:
                raise ValueError("SSH host-key rotation requires explicit approval")
        _safe_fingerprint(self.new_fingerprint)

    def to_dict(self) -> dict[str, Any]:
        _safe_fingerprint(self.new_fingerprint)
        return {
            "target": self.target.to_dict(),
            "oldFingerprint": self.old_fingerprint,
            "newFingerprint": self.new_fingerprint,
            "reason": self.reason,
            "approvalDigest": self.approval_digest,
        }


@dataclass(frozen=True)
class SSHVerificationReceipt:
    target: SSHTargetIdentity
    status: str
    reason: str
    expected_fingerprint: str | None
    observed_fingerprint: str | None
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        if self.reason not in SSH_REASON_CODES:
            raise ValueError("SSH verification reason is invalid")
        return {
            "formatVersion": SSH_RECEIPT_FORMAT,
            "target": self.target.to_dict(),
            "status": self.status,
            "reason": self.reason,
            "expectedFingerprint": self.expected_fingerprint,
            "observedFingerprint": self.observed_fingerprint,
            "createdAt": self.created_at,
        }


@dataclass(frozen=True)
class SSHHostVerificationPolicy:
    target: SSHTargetIdentity
    known_hosts_alias: str
    known_hosts_digest: str | None
    enrollment: SSHHostKeyEnrollment | None
    version: str = SSH_POLICY_FORMAT

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.version,
            "target": self.target.to_dict(),
            "knownHostsAlias": self.known_hosts_alias,
            "knownHostsDigest": self.known_hosts_digest,
            "status": "enrolled" if self.enrollment else "unenrolled",
            "enrollment": self.enrollment.to_dict() if self.enrollment else None,
            "strictHostKeyChecking": "yes",
            "globalKnownHosts": "none",
            "automaticTrust": False,
        }


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False) as handle:
            temporary = Path(handle.name)
            json.dump(value, handle, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _exclusive_json(path: Path, value: object) -> None:
    """Create one durable JSON record without replacing an existing identity."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            json.dump(value, handle, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path, follow_symlinks=False)
        temporary.unlink()
        temporary = None
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


@dataclass(frozen=True)
class InfrastructureProjectIdentity:
    root: str
    branch: str
    head_commit: str
    head_tree: str
    dirty: bool
    dirty_digest: str
    remote: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rootDisplay": Path(self.root).name,
            "branch": self.branch,
            "headCommit": self.head_commit,
            "headTree": self.head_tree,
            "dirty": self.dirty,
            "dirtyDigest": self.dirty_digest,
            "remote": self.remote,
        }


@dataclass(frozen=True)
class StatePortIdentity:
    root: str
    branch: str
    head_commit: str
    head_tree: str
    dirty: bool
    dirty_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "branch": self.branch,
            "headCommit": self.head_commit,
            "headTree": self.head_tree,
            "dirty": self.dirty,
            "dirtyDigest": self.dirty_digest,
        }


@dataclass(frozen=True)
class InfrastructureTarget:
    target_id: str = "libvirt-persistent"
    target_type: str = "local_libvirt"
    display_name: str = "Persistent local NixOS VM"
    domain: str = VM_NAME
    connection: str = VM_CONNECTION
    domain_uuid: str = VM_DOMAIN_UUID
    ssh_host: str = VM_SSH_HOST
    ssh_port: int = VM_SSH_PORT
    ssh_user: str = VM_SSH_USER

    def to_dict(self) -> dict[str, Any]:
        return {
            "targetId": self.target_id,
            "targetType": self.target_type,
            "displayName": self.display_name,
            "domain": self.domain,
            "domainUuid": self.domain_uuid,
            "connection": self.connection,
            "ssh": {"host": self.ssh_host, "port": self.ssh_port, "user": self.ssh_user},
        }


class LocalLibvirtAdapter:
    """Typed, digest-bound adapter over the repository's supported VM scripts."""

    def __init__(
        self,
        repository_root: Path | str,
        *,
        instance_id: str,
        state_root: Path | str,
        product_root: Path | str | None = None,
        runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.repository_root = Path(repository_root).expanduser().resolve(strict=True)
        self.instance_id = _safe_id(instance_id, "instance_id")
        self.state_root = Path(state_root).expanduser().resolve()
        self.product_root = Path(product_root).expanduser().resolve(strict=True) if product_root is not None else None
        self._runner = runner or subprocess.run
        self._clock = clock or _now
        if not _has_git_metadata(self.repository_root):
            raise InfrastructureError("repository_unavailable", "the infrastructure repository is not a Git repository")
        if self.repository_root.name != "nixos-homelab":
            raise InfrastructureError("unsupported_repository", "the local libvirt adapter only supports nixos-homelab")
        if not (self.repository_root / "flake.nix").is_file() or not (self.repository_root / "Makefile").is_file():
            raise InfrastructureError("unsupported_repository", "the Nix repository lacks the supported flake/Makefile workflow")
        self.target = InfrastructureTarget()

    @property
    def _plans(self) -> Path:
        return self.state_root / "plans"

    @property
    def _approvals(self) -> Path:
        return self.state_root / "approvals"

    @property
    def _runs(self) -> Path:
        return self.state_root / "runs"

    @property
    def _ssh_root(self) -> Path:
        return self.state_root / "ssh"

    @property
    def _ssh_known_hosts(self) -> Path:
        return self._ssh_root / "known_hosts"

    @property
    def _ssh_enrollment(self) -> Path:
        return self._ssh_root / "enrollment.json"

    @property
    def _daily_driver_grant(self) -> Path:
        return self.state_root / "grants" / f"{DAILY_DRIVER_GRANT_ID}.json"

    @property
    def _lock_path(self) -> Path:
        return self.state_root / "operation.lock"

    @contextmanager
    def _operation_lock(self) -> Iterator[None]:
        self.state_root.mkdir(parents=True, exist_ok=True)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self._lock_path, flags, 0o600)
        except OSError as exc:
            raise InfrastructureError(
                "operation_lock_invalid",
                "the infrastructure operation lock is unsafe or unavailable",
            ) from exc
        try:
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode):
                raise InfrastructureError(
                    "operation_lock_invalid",
                    "the infrastructure operation lock is not a regular file",
                )
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    def _env(self) -> dict[str, str]:
        allowed = {"PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "XDG_RUNTIME_DIR"}
        env = {key: value for key, value in os.environ.items() if key in allowed}
        env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_NOGLOBAL": "1", "GIT_OPTIONAL_LOCKS": "0"})
        return env

    def _ensure_ssh_root(self) -> Path:
        root = self._ssh_root
        if root.exists() and (root.is_symlink() or not root.is_dir()):
            raise InfrastructureError("ssh_policy_invalid", "the StatePort SSH policy directory is not a safe directory")
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        root.chmod(0o700)
        details = root.stat()
        if details.st_uid != os.geteuid() or details.st_mode & 0o077:
            raise InfrastructureError("ssh_policy_invalid", "the StatePort SSH policy directory is not privately owned")
        return root

    def _ensure_grant_root(self) -> Path:
        root = self._daily_driver_grant.parent
        if root.exists() and (root.is_symlink() or not root.is_dir()):
            raise InfrastructureError("grant_invalid", "the local daily-driver grant directory is not safe")
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        root.chmod(0o700)
        details = root.stat()
        if details.st_uid != os.geteuid() or details.st_mode & 0o077:
            raise InfrastructureError("grant_invalid", "the local daily-driver grant directory is not private")
        return root

    @staticmethod
    def _grant_scope_digest(value: Mapping[str, Any]) -> str:
        basis = {
            key: item
            for key, item in value.items()
            if key not in {"status", "proposalDigest", "grantDigest", "approvedAt", "approvedBy"}
        }
        return _digest(basis)

    def _grant_scope(self) -> dict[str, Any]:
        identity = self.project_identity()
        return {
            "formatVersion": DAILY_DRIVER_GRANT_FORMAT,
            "grantId": DAILY_DRIVER_GRANT_ID,
            "instanceId": self.instance_id,
            "applicationId": "nixos-infrastructure",
            "repository": {"root": self.repository_root.as_posix(), "branch": identity.branch},
            "target": self.target.to_dict(),
            "allowedOperations": list(DAILY_DRIVER_ALLOWED_OPERATIONS),
            "deniedOperations": list(DAILY_DRIVER_DENIED_OPERATIONS),
            "sshPolicy": {
                "formatVersion": SSH_POLICY_FORMAT,
                "strictHostKeyChecking": "yes",
                "globalKnownHosts": "none",
                "automaticTrust": False,
            },
            "onboarding": {
                "hostKeyEnrollment": "one_operator_confirmation",
                "hostKeyRotation": "explicit_approval_required",
                "reuseUntil": "target_identity_and_fingerprint_change",
            },
            "createdAt": _timestamp(self._clock()),
        }

    def _grant_from_dict(self, value: Mapping[str, Any]) -> LocalNixDailyDriverGrant:
        if value.get("formatVersion") != DAILY_DRIVER_GRANT_FORMAT:
            raise InfrastructureError("grant_invalid", "the daily-driver grant format is unsupported")
        repository = value.get("repository")
        if not isinstance(repository, Mapping):
            raise InfrastructureError("grant_invalid", "the daily-driver grant repository scope is missing")
        target = value.get("target")
        allowed = value.get("allowedOperations")
        denied = value.get("deniedOperations")
        ssh_policy = value.get("sshPolicy")
        onboarding = value.get("onboarding")
        if (
            value.get("grantId") != DAILY_DRIVER_GRANT_ID
            or value.get("instanceId") != self.instance_id
            or value.get("applicationId") != "nixos-infrastructure"
            or repository.get("root") != self.repository_root.as_posix()
            or not isinstance(repository.get("branch"), str)
            or target != self.target.to_dict()
            or allowed != list(DAILY_DRIVER_ALLOWED_OPERATIONS)
            or denied != list(DAILY_DRIVER_DENIED_OPERATIONS)
            or not isinstance(ssh_policy, Mapping)
            or dict(ssh_policy) != {
                "formatVersion": SSH_POLICY_FORMAT,
                "strictHostKeyChecking": "yes",
                "globalKnownHosts": "none",
                "automaticTrust": False,
            }
            or not isinstance(onboarding, Mapping)
            or onboarding.get("hostKeyEnrollment") != "one_operator_confirmation"
            or onboarding.get("hostKeyRotation") != "explicit_approval_required"
        ):
            raise InfrastructureError("grant_scope_changed", "the daily-driver grant no longer matches the exact application or VM scope")
        status = value.get("status")
        if status not in {"proposed", "active", "revoked"}:
            raise InfrastructureError("grant_invalid", "the daily-driver grant status is invalid")
        proposal_digest = value.get("proposalDigest")
        if not isinstance(proposal_digest, str) or proposal_digest != self._grant_scope_digest(value):
            raise InfrastructureError("grant_invalid", "the daily-driver grant proposal digest is invalid")
        grant_digest = value.get("grantDigest")
        if status == "active":
            if not isinstance(grant_digest, str) or grant_digest != _digest({key: item for key, item in value.items() if key != "grantDigest"}):
                raise InfrastructureError("grant_invalid", "the active daily-driver grant digest is invalid")
            if value.get("approvedBy") != "local-user" or not isinstance(value.get("approvedAt"), str):
                raise InfrastructureError("grant_invalid", "the active daily-driver grant approval is incomplete")
        return LocalNixDailyDriverGrant(
            grant_id=str(value["grantId"]),
            instance_id=str(value["instanceId"]),
            application_id=str(value["applicationId"]),
            repository_root=str(repository["root"]),
            repository_branch=str(repository["branch"]),
            target=dict(target),
            allowed_operations=tuple(str(item) for item in allowed),
            denied_operations=tuple(str(item) for item in denied),
            ssh_policy=dict(ssh_policy),
            onboarding=dict(onboarding),
            status=str(status),
            created_at=str(value["createdAt"]),
            proposal_digest=proposal_digest,
            approved_at=str(value["approvedAt"]) if value.get("approvedAt") is not None else None,
            approved_by=str(value["approvedBy"]) if value.get("approvedBy") is not None else None,
            grant_digest=grant_digest if isinstance(grant_digest, str) else None,
        )

    def _load_daily_driver_grant(self) -> LocalNixDailyDriverGrant | None:
        path = self._daily_driver_grant
        if not path.exists():
            return None
        if path.is_symlink() or not path.is_file():
            raise InfrastructureError("grant_invalid", "the daily-driver grant is not a regular file")
        details = path.stat()
        if details.st_uid != os.geteuid() or details.st_mode & 0o077:
            raise InfrastructureError("grant_invalid", "the daily-driver grant is not private")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise InfrastructureError("grant_invalid", "the daily-driver grant is unreadable") from exc
        if not isinstance(value, Mapping):
            raise InfrastructureError("grant_invalid", "the daily-driver grant is malformed")
        return self._grant_from_dict(value)

    def daily_driver_grant(self) -> dict[str, Any] | None:
        grant = self._load_daily_driver_grant()
        if grant is None:
            return None
        return self._daily_driver_grant_projection(grant)

    def _daily_driver_grant_projection(self, grant: LocalNixDailyDriverGrant) -> dict[str, Any]:
        value = grant.to_dict()
        repository = value.get("repository")
        if isinstance(repository, dict):
            repository.pop("root", None)
            repository["rootDisplay"] = self.repository_root.name
        return value

    def prepare_daily_driver_grant(self) -> dict[str, Any]:
        self._ensure_grant_root()
        try:
            existing = self._load_daily_driver_grant()
        except InfrastructureError as exc:
            if exc.code != "grant_scope_changed":
                raise
            existing = None
        if existing is not None:
            return self.daily_driver_grant() or existing.to_dict()
        value = self._grant_scope()
        value["status"] = "proposed"
        value["proposalDigest"] = self._grant_scope_digest(value)
        value["approvedAt"] = None
        value["approvedBy"] = None
        _atomic_json(self._daily_driver_grant, value)
        self._daily_driver_grant.chmod(0o600)
        return self.daily_driver_grant() or value

    def approve_daily_driver_grant(self, proposal_digest: str, actor_id: str) -> dict[str, Any]:
        if actor_id != "local-user":
            raise InfrastructureError("grant_denied", "the local operator identity is required")
        self._ensure_grant_root()
        current = self._load_daily_driver_grant()
        if current is None or current.status != "proposed":
            raise InfrastructureError("grant_not_found", "the daily-driver grant proposal is not available")
        if current.proposal_digest != proposal_digest:
            raise InfrastructureError("grant_stale", "the daily-driver grant proposal changed; review the current grant")
        scope = self._grant_scope()
        # Creation time is descriptive evidence, not mutable authority.  Keep
        # the proposed timestamp while re-deriving the current repository and
        # target scope, otherwise a proposal becomes stale merely because the
        # clock advanced between preparation and approval.
        scope["createdAt"] = current.created_at
        if self._grant_scope_digest(scope) != proposal_digest:
            raise InfrastructureError("grant_stale", "the application or VM scope changed; prepare a new grant")
        value = current.to_dict()
        value.update({"status": "active", "approvedAt": _timestamp(self._clock()), "approvedBy": actor_id})
        value["grantDigest"] = _digest(value)
        _atomic_json(self._daily_driver_grant, value)
        self._daily_driver_grant.chmod(0o600)
        return self.daily_driver_grant() or value

    def daily_driver_grant_receipt(self, grant: Mapping[str, Any]) -> dict[str, Any]:
        payload = {
            "formatVersion": "stateport.infrastructure-grant-receipt/v1",
            "receiptType": "infrastructure.grant.activate",
            "receiptId": "infra-grant-receipt-" + hashlib.sha256(str(grant.get("grantDigest")).encode()).hexdigest()[:24],
            "action": "infrastructure.grant.activate",
            "status": "completed",
            "sourceKind": "infrastructure",
            "instanceId": self.instance_id,
            "applicationId": "nixos-infrastructure",
            "grantId": grant.get("grantId"),
            "proposalDigest": grant.get("proposalDigest"),
            "grantDigest": grant.get("grantDigest"),
            "target": self.target.to_dict(),
            "repository": {"rootDisplay": self.repository_root.name, "branch": self.project_identity().branch},
            "authorization": "local-user",
            "createdAt": _timestamp(self._clock()),
        }
        payload["receiptDigest"] = _digest(payload)
        return payload

    def _active_grant_for(self, operation: str) -> LocalNixDailyDriverGrant | None:
        grant = self._load_daily_driver_grant()
        if grant is None or grant.status != "active":
            return None
        mapped = GRANT_OPERATION_MAP.get(operation)
        return grant if mapped is not None and mapped in grant.allowed_operations else None

    def _read_known_host(self, target: SSHTargetIdentity) -> SSHHostKeyFingerprint | None:
        path = self._ssh_known_hosts
        if not path.exists():
            return None
        if path.is_symlink() or not path.is_file():
            raise InfrastructureError("ssh_policy_invalid", "the target known-hosts path is not a regular file")
        details = path.stat()
        if details.st_uid != os.geteuid() or details.st_mode & 0o077:
            raise InfrastructureError("ssh_policy_invalid", "the target known-hosts file is not private")
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as exc:
            raise InfrastructureError("ssh_policy_invalid", "the target known-hosts file is unreadable") from exc
        entries: list[SSHHostKeyFingerprint] = []
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            fields = stripped.split()
            if len(fields) < 3 or fields[0] != VM_SSH_KNOWN_HOST_ALIAS:
                raise InfrastructureError("ssh_policy_invalid", "the target known-hosts file contains an unrelated or indirect entry")
            try:
                entries.append(SSHHostKeyFingerprint(fields[1], _fingerprint_from_key(fields[2])))
            except ValueError as exc:
                raise InfrastructureError("ssh_policy_invalid", "the target known-hosts entry is malformed") from exc
        if len(entries) != 1:
            raise InfrastructureError("ssh_policy_invalid", "the target known-hosts file must contain exactly one active entry")
        return entries[0]

    def _ssh_target_identity(self, domain_uuid: str | None = None) -> SSHTargetIdentity:
        return SSHTargetIdentity(
            application_id=self.instance_id,
            target_id=self.target.target_id,
            domain=self.target.domain,
            domain_uuid=self.target.domain_uuid if domain_uuid is None else domain_uuid,
            host=self.target.ssh_host,
            port=self.target.ssh_port,
            user=self.target.ssh_user,
        )

    def _load_ssh_enrollment(self, target: SSHTargetIdentity) -> SSHHostKeyEnrollment | None:
        self._ensure_ssh_root()
        known_host = self._read_known_host(target)
        if not self._ssh_enrollment.exists():
            return None
        if self._ssh_enrollment.is_symlink() or not self._ssh_enrollment.is_file():
            raise InfrastructureError("ssh_policy_invalid", "the SSH enrollment record is not a regular file")
        details = self._ssh_enrollment.stat()
        if details.st_uid != os.geteuid() or details.st_mode & 0o077:
            raise InfrastructureError("ssh_policy_invalid", "the SSH enrollment record is not private")
        try:
            value = json.loads(self._ssh_enrollment.read_text(encoding="utf-8"))
            target_value = value["target"]
            known_value = value["knownHost"]
            key_value = known_value["key"]
            enrollment = SSHHostKeyEnrollment(
                target=SSHTargetIdentity(
                    application_id=str(target_value["applicationId"]),
                    target_id=str(target_value["targetId"]),
                    domain=str(target_value["domain"]),
                    domain_uuid=str(target_value["domainUuid"]),
                    host=str(target_value["host"]),
                    port=int(target_value["port"]),
                    user=str(target_value["user"]),
                ),
                known_host=SSHKnownHostIdentity(
                    alias=str(known_value["alias"]),
                    key=SSHHostKeyFingerprint(str(key_value["algorithm"]), str(key_value["fingerprint"])),
                    provenance=str(known_value["provenance"]),
                ),
                enrolled_at=str(value["enrolledAt"]),
                enrollment_receipt_id=str(value["enrollmentReceiptId"]),
            )
        except (KeyError, TypeError, ValueError, OSError, json.JSONDecodeError) as exc:
            raise InfrastructureError("ssh_policy_invalid", "the SSH enrollment record is malformed") from exc
        if enrollment.target != target or enrollment.known_host.alias != VM_SSH_KNOWN_HOST_ALIAS:
            raise InfrastructureError("ssh_policy_invalid", "the SSH enrollment is bound to a different target")
        if known_host is None or known_host != enrollment.known_host.key:
            raise InfrastructureError(
                "ssh_host_key_mismatch",
                "the SSH host key differs from the enrolled target identity",
                details={
                    "target": target.to_dict(),
                    "expectedFingerprint": enrollment.known_host.key.value,
                    "observedFingerprint": known_host.value if known_host else None,
                    "previousEnrollment": enrollment.enrollment_receipt_id,
                },
            )
        return enrollment

    def _ssh_policy(self, domain_uuid: str | None = None) -> SSHHostVerificationPolicy:
        target = self._ssh_target_identity(domain_uuid)
        enrollment = self._load_ssh_enrollment(target)
        digest = _file_digest(self._ssh_known_hosts) if enrollment else None
        return SSHHostVerificationPolicy(
            target=target,
            known_hosts_alias=VM_SSH_KNOWN_HOST_ALIAS,
            known_hosts_digest=digest,
            enrollment=enrollment,
        )

    def _ssh_identity_file(self) -> Path | None:
        candidate = Path.home() / ".ssh" / "id_ed25519"
        if not candidate.is_file() or candidate.is_symlink():
            return None
        try:
            details = candidate.stat()
        except OSError:
            return None
        if details.st_uid != os.geteuid() or details.st_mode & 0o077:
            return None
        return candidate

    def _ssh_command(self, policy: SSHHostVerificationPolicy, *remote_command: str) -> tuple[str, ...]:
        if policy.enrollment is None:
            raise InfrastructureError("ssh_key_not_enrolled", "the VM SSH host key is not enrolled in StatePort")
        options = [
            "BatchMode=yes",
            "NumberOfPasswordPrompts=0",
            "PasswordAuthentication=no",
            "KbdInteractiveAuthentication=no",
            "PubkeyAuthentication=yes",
            "IdentitiesOnly=yes",
            "IdentityAgent=none",
            "StrictHostKeyChecking=yes",
            f"UserKnownHostsFile={self._ssh_known_hosts.as_posix()}",
            "GlobalKnownHostsFile=none",
            "UpdateHostKeys=no",
            "VerifyHostKeyDNS=no",
            "CheckHostIP=no",
            "ProxyCommand=none",
            "ProxyJump=none",
            "ControlMaster=no",
            "ControlPath=none",
            "ControlPersist=no",
            "ClearAllForwardings=yes",
            "ForwardAgent=no",
            "ForwardX11=no",
            "ForwardX11Trusted=no",
            "GSSAPIAuthentication=no",
            "GSSAPIDelegateCredentials=no",
            "Tunnel=no",
            "PermitLocalCommand=no",
            "LocalCommand=none",
            "EnableEscapeCommandline=no",
            "EscapeChar=none",
            "CanonicalizeHostname=no",
            "RequestTTY=no",
            "TCPKeepAlive=no",
            "ConnectTimeout=5",
            "ConnectionAttempts=1",
            "ServerAliveInterval=15",
            "ServerAliveCountMax=3",
        ]
        identity = self._ssh_identity_file()
        if identity is not None:
            options.append(f"IdentityFile={identity.as_posix()}")
        command: list[str] = ["ssh", "-F", "none"]
        for option in options:
            command.extend(("-o", option))
        command.extend(("-p", str(policy.target.port), f"{policy.target.user}@{policy.target.host}", *remote_command))
        return tuple(command)

    @staticmethod
    def _redacted_command(command: Sequence[str]) -> list[str]:
        result: list[str] = []
        for item in command:
            if item.startswith("IdentityFile="):
                result.append("IdentityFile=<controlled>")
            elif item.startswith("UserKnownHostsFile="):
                result.append("UserKnownHostsFile=<target-controlled>")
            else:
                result.append(item)
        return result

    def _receipt_event(self, event: Mapping[str, Any]) -> dict[str, Any]:
        result = {key: value for key, value in event.items() if key not in {"stdout", "stderr"}}
        if isinstance(result.get("command"), list):
            result["command"] = self._redacted_command(result["command"])
        return result

    def _assert_plan_target_current(self, plan: Mapping[str, Any]) -> None:
        planned_stateport = plan.get("stateport")
        current_stateport = self.stateport_identity()
        if planned_stateport != (current_stateport.to_dict() if current_stateport else None):
            raise InfrastructureError("plan_stale", "the StatePort identity changed after the plan was prepared")
        current_domain = self._domain_observation()
        planned_domain = plan.get("domainBefore")
        if not isinstance(planned_domain, Mapping):
            raise InfrastructureError("plan_invalid", "the plan has no bound domain identity")
        for field in ("domain", "uuid", "state"):
            if current_domain.get(field) != planned_domain.get(field):
                raise InfrastructureError("plan_stale", "the VM target changed after the plan was prepared")
        planned_policy = plan.get("sshVerification")
        current_policy = self._ssh_policy(str(current_domain.get("uuid") or "")).to_dict()
        if planned_policy != current_policy:
            raise InfrastructureError("plan_stale", "the SSH verification policy changed after the plan was prepared")

    def _run(self, command: Sequence[str], *, timeout: float = 30.0, cwd: Path | None = None) -> dict[str, Any]:
        if not command or any(not isinstance(item, str) or not item or "\x00" in item for item in command):
            raise InfrastructureError("command_invalid", "the adapter command is invalid")
        started = time.monotonic()
        try:
            result = self._runner(
                tuple(command),
                cwd=str(cwd or self.repository_root),
                env=self._env(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return {"command": list(command), "status": "timeout", "returnCode": None, "stdout": _bounded_text(exc.stdout), "stderr": _bounded_text(exc.stderr), "durationMs": round((time.monotonic() - started) * 1000)}
        except OSError as exc:
            return {"command": list(command), "status": "unavailable", "returnCode": None, "stdout": "", "stderr": _bounded_text(exc), "durationMs": round((time.monotonic() - started) * 1000)}
        return {"command": list(command), "status": "completed" if result.returncode == 0 else "failed", "returnCode": result.returncode, "stdout": _bounded_text(result.stdout), "stderr": _bounded_text(result.stderr), "durationMs": round((time.monotonic() - started) * 1000)}

    def _git(self, *args: str) -> str:
        result = self._run(("git", "--no-pager", *args), timeout=10)
        if result["status"] != "completed" or result["returnCode"] != 0:
            raise InfrastructureError("repository_identity_unavailable", "the repository identity could not be read")
        return str(result["stdout"]).strip()

    def project_identity(self) -> InfrastructureProjectIdentity:
        branch = self._git("rev-parse", "--abbrev-ref", "HEAD")
        commit = self._git("rev-parse", "HEAD")
        tree = self._git("rev-parse", "HEAD^{tree}")
        status = self._git("status", "--porcelain=v2")
        remote_result = self._run(("git", "config", "--get", "remote.origin.url"), timeout=10)
        remote = str(remote_result["stdout"]).strip() if remote_result["returnCode"] == 0 else None
        if remote and ("@" in remote or remote.startswith(("ssh:", "git:", "file:"))):
            remote = None
        return InfrastructureProjectIdentity(
            self.repository_root.as_posix(), branch, commit, tree, bool(status), _digest(status), remote,
        )

    def stateport_identity(self) -> StatePortIdentity | None:
        if self.product_root is None:
            return None
        if not _has_git_metadata(self.product_root):
            raise InfrastructureError("stateport_identity_unavailable", "the StatePort product root is not a Git repository")
        def git(*args: str) -> str:
            result = self._run(("git", "--no-pager", *args), timeout=10, cwd=self.product_root)
            if result["status"] != "completed" or result["returnCode"] != 0:
                raise InfrastructureError("stateport_identity_unavailable", "the StatePort identity could not be read")
            return str(result["stdout"]).strip()
        status = git("status", "--porcelain=v2")
        return StatePortIdentity(
            root=self.product_root.as_posix(),
            branch=git("rev-parse", "--abbrev-ref", "HEAD"),
            head_commit=git("rev-parse", "HEAD"),
            head_tree=git("rev-parse", "HEAD^{tree}"),
            dirty=bool(status),
            dirty_digest=_digest(status),
        )

    def _virsh(self, *args: str, timeout: float = 15.0) -> dict[str, Any]:
        return self._run(("virsh", "--connect", VM_CONNECTION, *args), timeout=timeout)

    def _domain_observation(self) -> dict[str, Any]:
        state_result = self._virsh("domstate", VM_NAME)
        if state_result["status"] != "completed" or state_result["returnCode"] != 0:
            message = str(state_result["stderr"]).strip()
            lowered = message.lower()
            if "failed to get domain" in lowered or ("domain" in lowered and "not found" in lowered):
                # The hypervisor answered and the domain simply does not exist
                # yet: the target authority is observable and create_or_update
                # remains plannable. This is a neutral state, not an error and
                # not an unavailable target.
                return {"state": "not_defined", "availability": "available", "domain": VM_NAME, "error": None}
            # The domain could not be observed at all: fail closed as unavailable.
            return {"state": "unavailable", "availability": "unavailable", "domain": VM_NAME, "error": message[:256] or None}
        uuid_result = self._virsh("domuuid", VM_NAME)
        uuid = str(uuid_result["stdout"]).strip() if uuid_result["returnCode"] == 0 else None
        return {
            "state": str(state_result["stdout"]).strip().lower(),
            "availability": "available",
            "domain": VM_NAME,
            "uuid": uuid,
            "identityMatches": uuid == VM_DOMAIN_UUID,
            "ssh": self._ssh_observation(uuid),
        }

    def _ssh_observation(self, domain_uuid: str | None = None) -> dict[str, Any]:
        policy = self._ssh_policy(domain_uuid)
        base = {"host": VM_SSH_HOST, "port": VM_SSH_PORT, "user": VM_SSH_USER, "policy": policy.to_dict()}
        if policy.target.domain_uuid != VM_DOMAIN_UUID:
            return {**base, "available": False, "status": "ssh_not_configured", "reason": "domain_uuid_mismatch"}
        if policy.enrollment is None:
            return {**base, "available": False, "status": "ssh_key_not_enrolled", "reason": "ssh_key_not_enrolled"}
        try:
            with socket.create_connection((VM_SSH_HOST, VM_SSH_PORT), timeout=1.0):
                return {**base, "available": True, "status": "ssh_ready", "reason": "ssh_ready"}
        except ConnectionRefusedError:
            return {**base, "available": False, "status": "ssh_connection_refused", "reason": "ssh_connection_refused"}
        except TimeoutError:
            return {**base, "available": False, "status": "ssh_timed_out", "reason": "ssh_timed_out"}
        except OSError:
            return {**base, "available": False, "status": "ssh_not_configured", "reason": "ssh_not_configured"}

    def _health(self) -> dict[str, Any]:
        domain = self._domain_observation()
        ssh = domain.get("ssh") if isinstance(domain.get("ssh"), Mapping) else self._ssh_observation(domain.get("uuid"))
        if not ssh["available"]:
            return {"status": "unreachable", "reason": ssh.get("reason", "ssh_not_configured"), "ssh": ssh}
        policy = self._ssh_policy(str(domain.get("uuid") or ""))
        command = self._ssh_command(policy, "operator-doctor", "--json")
        result = self._run(command, timeout=20, cwd=Path("/"))
        if result["returnCode"] != 0:
            diagnostic = _bounded_text(result["stderr"], 512)
            lowered = diagnostic.lower()
            if "remote host identification has changed" in lowered or "offending" in lowered and "host key" in lowered:
                reason = "ssh_host_key_mismatch"
            elif "host key verification failed" in lowered or "no matching host key" in lowered:
                reason = "ssh_host_verification_failed"
            elif "permission denied" in lowered or "no more authentication methods" in lowered:
                reason = "ssh_authentication_failed"
            elif "timed out" in lowered:
                reason = "ssh_timed_out"
            elif "connection refused" in lowered:
                reason = "ssh_connection_refused"
            else:
                reason = "ssh_health_degraded"
            return {"status": "unhealthy", "reason": reason, "ssh": ssh, "diagnostic": diagnostic}
        try:
            doctor = json.loads(str(result["stdout"]))
        except (TypeError, json.JSONDecodeError):
            doctor = {"rawStatus": "unparseable"}
        verdict = str(doctor.get("verdict") or doctor.get("status") or "observed").lower() if isinstance(doctor, Mapping) else "observed"
        return {"status": "healthy" if verdict in {"pass", "passed", "ok", "healthy"} else "degraded", "reason": "ssh_ready" if verdict in {"pass", "passed", "ok", "healthy"} else "ssh_health_degraded", "ssh": ssh, "doctor": doctor}

    def inspect(self) -> dict[str, Any]:
        identity = self.project_identity()
        stateport = self.stateport_identity()
        return {
            "formatVersion": FORMAT,
            "instanceId": self.instance_id,
            "repository": identity.to_dict(),
            "stateport": stateport.to_dict() if stateport else None,
            "target": self.target.to_dict(),
            "tools": {name: shutil.which(name) is not None for name in ("nix", "virsh", "ssh", "make")},
            "domain": self._domain_observation(),
            "dailyDriverGrant": self.daily_driver_grant(),
            "policy": {"network": "user-mode NAT with localhost SSH forwarding", "execution": "repository-owned scripts only", "destruction": "separate exact approval", "sshVerification": self._ssh_policy().to_dict()},
            "lastRun": self._latest_run(),
        }

    @staticmethod
    def _run_id(plan_digest: str, operation: str) -> str:
        return "infra-run-" + hashlib.sha256(f"{plan_digest}:{operation}".encode()).hexdigest()[:24]

    @staticmethod
    def _validate_timestamp(value: object, field: str) -> datetime:
        if not isinstance(value, str) or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value) is None:
            raise InfrastructureError(
                "run_reconciliation_required",
                f"the stored infrastructure run has an invalid {field}; inspect it before continuing",
            )
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise InfrastructureError(
                "run_reconciliation_required",
                f"the stored infrastructure run has an invalid {field}; inspect it before continuing",
            ) from exc
        if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
            raise InfrastructureError(
                "run_reconciliation_required",
                f"the stored infrastructure run has an invalid {field}; inspect it before continuing",
            )
        return parsed

    @staticmethod
    def _seal_run(run: dict[str, Any]) -> dict[str, Any]:
        run.pop("runDigest", None)
        run["runDigest"] = _digest(run)
        return run

    def _ensure_run_root(self, *, create: bool) -> Path | None:
        root = self._runs
        if root.is_symlink():
            raise InfrastructureError(
                "run_reconciliation_required",
                "the infrastructure run store is unsafe; inspect it before continuing",
            )
        if not root.exists():
            if not create:
                return None
            try:
                root.mkdir(parents=True, mode=0o700)
            except OSError as exc:
                raise InfrastructureError(
                    "run_reconciliation_required",
                    "the infrastructure run store cannot be prepared safely",
                ) from exc
        if root.is_symlink() or not root.is_dir():
            raise InfrastructureError(
                "run_reconciliation_required",
                "the infrastructure run store is unsafe; inspect it before continuing",
            )
        details = root.stat()
        if details.st_uid != os.geteuid():
            raise InfrastructureError(
                "run_reconciliation_required",
                "the infrastructure run store has an unexpected owner; inspect it before continuing",
            )
        if details.st_mode & 0o077:
            root.chmod(0o700)
        return root

    def _read_run_json(self, path: Path) -> dict[str, Any] | None:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except FileNotFoundError:
            return None
        except OSError as exc:
            reason = "symlink" if exc.errno == errno.ELOOP else "unsafe"
            raise InfrastructureError(
                "run_reconciliation_required",
                f"the stored infrastructure run is {reason}; inspect it before continuing",
            ) from exc
        try:
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode):
                raise InfrastructureError(
                    "run_reconciliation_required",
                    "the stored infrastructure run is not a regular file; inspect it before continuing",
                )
            if details.st_size > MAX_RUN_RECORD_BYTES:
                raise InfrastructureError(
                    "run_reconciliation_required",
                    "the stored infrastructure run is oversized; inspect it before continuing",
                )
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                encoded = handle.read(MAX_RUN_RECORD_BYTES + 1)
            if len(encoded) > MAX_RUN_RECORD_BYTES:
                raise InfrastructureError(
                    "run_reconciliation_required",
                    "the stored infrastructure run is oversized; inspect it before continuing",
                )
        finally:
            os.close(descriptor)
        try:
            value = json.loads(encoded.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise InfrastructureError(
                "run_reconciliation_required",
                "the stored infrastructure run is malformed; inspect it before continuing",
            ) from exc
        if not isinstance(value, dict):
            raise InfrastructureError(
                "run_reconciliation_required",
                "the stored infrastructure run is malformed; inspect it before continuing",
            )
        return value

    def _validate_run_authorization(
        self,
        approval: object,
        *,
        operation: str,
        plan_digest: str,
    ) -> dict[str, Any] | None:
        if operation not in MUTATING_OPERATIONS:
            if approval is not None:
                raise InfrastructureError(
                    "run_reconciliation_required",
                    "the stored read-only infrastructure run has unexpected authority; inspect it before continuing",
                )
            return None
        if not isinstance(approval, dict):
            raise InfrastructureError(
                "run_reconciliation_required",
                "the stored infrastructure run lacks its exact authority; inspect it before continuing",
            )
        if approval.get("authorizationType") == "durable_grant":
            expected = {
                "formatVersion",
                "authorizationType",
                "grantId",
                "grantDigest",
                "approvalDigest",
            }
            if set(approval) != expected:
                raise InfrastructureError(
                    "run_reconciliation_required",
                    "the stored infrastructure grant authority is malformed; inspect it before continuing",
                )
            grant_id = approval.get("grantId")
            grant_digest = approval.get("grantDigest")
            approval_digest = approval.get("approvalDigest")
            if (
                approval.get("formatVersion") != "stateport.infrastructure-grant-authorization/v1"
                or not isinstance(grant_id, str)
                or grant_id != DAILY_DRIVER_GRANT_ID
                or re.fullmatch(r"sha256:[0-9a-f]{64}", str(grant_digest)) is None
                or approval_digest != _digest({"planDigest": plan_digest, "grantDigest": grant_digest})
            ):
                raise InfrastructureError(
                    "run_reconciliation_required",
                    "the stored infrastructure grant authority is invalid; inspect it before continuing",
                )
            return approval
        expected = {
            "formatVersion",
            "approvalId",
            "instanceId",
            "actorId",
            "planDigest",
            "approvedAt",
            "expiresAt",
            "approvalDigest",
        }
        if (
            set(approval) != expected
            or approval.get("formatVersion") != "stateport.infrastructure-approval/v1"
            or approval.get("approvalId")
            != "approval-" + hashlib.sha256(f"{self.instance_id}:{plan_digest}:local-user".encode()).hexdigest()[:24]
            or approval.get("instanceId") != self.instance_id
            or approval.get("actorId") != "local-user"
            or approval.get("planDigest") != plan_digest
            or approval.get("approvalDigest") != _digest({key: value for key, value in approval.items() if key != "approvalDigest"})
        ):
            raise InfrastructureError(
                "run_reconciliation_required",
                "the stored infrastructure approval is invalid; inspect it before continuing",
            )
        approved_at = self._validate_timestamp(approval.get("approvedAt"), "approval timestamp")
        expires_at = self._validate_timestamp(approval.get("expiresAt"), "approval expiry")
        if expires_at <= approved_at:
            raise InfrastructureError(
                "run_reconciliation_required",
                "the stored infrastructure approval timestamps are inconsistent; inspect them before continuing",
            )
        return approval

    def _validate_run_events(self, events: object, plan: Mapping[str, Any]) -> list[dict[str, Any]]:
        commands = plan.get("commands")
        if not isinstance(commands, list) or len(commands) > 16:
            raise InfrastructureError(
                "run_reconciliation_required",
                "the stored infrastructure plan has invalid commands; inspect it before continuing",
            )
        if not isinstance(events, list) or len(events) > len(commands):
            raise InfrastructureError(
                "run_reconciliation_required",
                "the stored infrastructure run events are malformed; inspect them before continuing",
            )
        for index, event in enumerate(events):
            if not isinstance(event, dict) or set(event) != {"command", "status", "returnCode", "durationMs"}:
                raise InfrastructureError(
                    "run_reconciliation_required",
                    "the stored infrastructure run events are malformed; inspect them before continuing",
                )
            command = event.get("command")
            expected_command = commands[index]
            if (
                not isinstance(command, list)
                or command != expected_command
                or any(not isinstance(item, str) or not item for item in command)
                or event.get("status") not in {"completed", "failed", "timeout", "unavailable"}
                or isinstance(event.get("durationMs"), bool)
                or not isinstance(event.get("durationMs"), int)
                or event["durationMs"] < 0
            ):
                raise InfrastructureError(
                    "run_reconciliation_required",
                    "the stored infrastructure run events do not match the exact plan; inspect them before continuing",
                )
            return_code = event.get("returnCode")
            if isinstance(return_code, bool) or (return_code is not None and not isinstance(return_code, int)):
                raise InfrastructureError(
                    "run_reconciliation_required",
                    "the stored infrastructure run event result is invalid; inspect it before continuing",
                )
            if (
                (event["status"] == "completed" and return_code != 0)
                or (event["status"] == "failed" and (return_code is None or return_code == 0))
                or (event["status"] in {"timeout", "unavailable"} and return_code is not None)
            ):
                raise InfrastructureError(
                    "run_reconciliation_required",
                    "the stored infrastructure run event result is contradictory; inspect it before continuing",
                )
        return events

    def _validate_run_receipt(
        self,
        receipt: object,
        *,
        plan: Mapping[str, Any],
        run: Mapping[str, Any],
        approval: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        operation = str(plan["operation"])
        state = str(run["state"])
        expected_keys = {
            "formatVersion",
            "receiptType",
            "receiptId",
            "instanceId",
            "action",
            "status",
            "sourceKind",
            "createdAt",
            "planDigest",
            "approvalDigest",
            "authorization",
            "stateport",
            "repository",
            "target",
            "operationState",
            "events",
            "resultDigest",
            "rollback",
            "knownLimitations",
            "receiptDigest",
        }
        if operation == "validate":
            expected_keys.add("validation")
        has_failure_projection = state == "failed" and isinstance(receipt, dict) and "failure" in receipt
        if has_failure_projection:
            expected_keys.add("failure")
        expected_receipt_id = "infra-receipt-" + hashlib.sha256(
            f"{self.instance_id}:{plan['planDigest']}:{state}".encode()
        ).hexdigest()[:24]
        expected_authorization = {
            "type": approval.get("authorizationType") if approval else None,
            "grantId": approval.get("grantId") if approval else None,
            "grantDigest": approval.get("grantDigest") if approval else None,
        }
        if (
            not isinstance(receipt, dict)
            or set(receipt) != expected_keys
            or receipt.get("formatVersion") != RECEIPT_FORMAT
            or receipt.get("receiptType") != RECEIPT_FORMAT
            or receipt.get("receiptId") != expected_receipt_id
            or receipt.get("instanceId") != self.instance_id
            or receipt.get("action") != RECEIPT_ACTIONS[operation]
            or receipt.get("status") != state
            or receipt.get("sourceKind") != "infrastructure"
            or receipt.get("planDigest") != plan["planDigest"]
            or receipt.get("approvalDigest") != (approval.get("approvalDigest") if approval else None)
            or receipt.get("authorization") != expected_authorization
            or receipt.get("stateport") != plan.get("stateport")
            or receipt.get("repository") != plan.get("repository")
            or receipt.get("target") != plan.get("target")
            or receipt.get("operationState") != state
            or receipt.get("events") != run.get("events")
            or receipt.get("resultDigest") != (_digest(run.get("result")) if state == "completed" else None)
            or receipt.get("rollback") != plan.get("rollback")
            or receipt.get("knownLimitations")
            != ["Health is derived from observed libvirt/SSH/doctor results; running does not imply healthy."]
            or receipt.get("receiptDigest")
            != _digest({key: value for key, value in receipt.items() if key != "receiptDigest"})
        ):
            raise InfrastructureError(
                "run_reconciliation_required",
                "the stored infrastructure receipt is invalid; inspect it before continuing",
            )
        self._validate_timestamp(receipt.get("createdAt"), "receipt timestamp")
        if has_failure_projection and receipt.get("failure") != run.get("error"):
            raise InfrastructureError(
                "run_reconciliation_required",
                "the stored infrastructure failure and receipt disagree; inspect them before continuing",
            )
        if operation == "validate":
            events = run.get("events")
            validated = (
                state == "completed"
                and isinstance(events, list)
                and bool(events)
                and all(event.get("status") == "completed" and event.get("returnCode") == 0 for event in events)
            )
            expected_validation = {
                "state": "validated" if validated else "failed" if state == "failed" else "not_recorded",
                "detail": (
                    "The repository-owned Nix flake check completed locally with exit code 0."
                    if validated
                    else "The repository-owned Nix flake check did not complete successfully."
                    if state == "failed"
                    else "The infrastructure run recorded no complete validation event."
                ),
            }
            if receipt.get("validation") != expected_validation:
                raise InfrastructureError(
                    "run_reconciliation_required",
                    "the stored infrastructure validation receipt is inconsistent; inspect it before continuing",
                )
        return receipt

    def _validate_run_record(self, value: dict[str, Any], plan: Mapping[str, Any]) -> dict[str, Any]:
        operation = str(plan.get("operation"))
        plan_digest = str(plan.get("planDigest"))
        run_id = self._run_id(plan_digest, operation)
        state = value.get("state")
        common_keys = {
            "formatVersion",
            "runId",
            "instanceId",
            "operation",
            "planDigest",
            "approval",
            "state",
            "events",
            "startedAt",
        }
        expected_keys = set(common_keys)
        has_run_digest = "runDigest" in value
        if has_run_digest:
            expected_keys.add("runDigest")
        if state == "completed":
            expected_keys.update({"result", "receipt", "endedAt"})
        elif state == "failed":
            expected_keys.update({"error", "receipt", "endedAt"})
        elif state not in {"preparing", "running"}:
            raise InfrastructureError(
                "run_reconciliation_required",
                "the stored infrastructure run state is unknown; inspect it before continuing",
            )
        if (
            set(value) != expected_keys
            or value.get("formatVersion") != RUN_FORMAT
            or value.get("runId") != run_id
            or value.get("instanceId") != self.instance_id
            or value.get("operation") != operation
            or value.get("planDigest") != plan_digest
            or (
                has_run_digest
                and value.get("runDigest")
                != _digest({key: item for key, item in value.items() if key != "runDigest"})
            )
        ):
            raise InfrastructureError(
                "run_reconciliation_required",
                "the stored infrastructure run identity is invalid; inspect it before continuing",
            )
        started_at = self._validate_timestamp(value.get("startedAt"), "start timestamp")
        approval = self._validate_run_authorization(
            value.get("approval"),
            operation=operation,
            plan_digest=plan_digest,
        )
        events = self._validate_run_events(value.get("events"), plan)
        if state == "completed":
            if not isinstance(value.get("result"), dict) or len(events) != len(plan.get("commands", [])):
                raise InfrastructureError(
                    "run_reconciliation_required",
                    "the completed infrastructure run is incomplete; inspect it before continuing",
                )
        if state == "failed":
            error = value.get("error")
            if (
                not isinstance(error, dict)
                or set(error) != {"code", "message", "details"}
                or re.fullmatch(r"[a-z][a-z0-9_]{0,127}", str(error.get("code"))) is None
                or not isinstance(error.get("message"), str)
                or not error["message"]
                or len(error["message"]) > 1024
                or not isinstance(error.get("details"), dict)
            ):
                raise InfrastructureError(
                    "run_reconciliation_required",
                    "the stored infrastructure failure is malformed; inspect it before continuing",
                )
        if state in {"completed", "failed"}:
            ended_at = self._validate_timestamp(value.get("endedAt"), "end timestamp")
            if ended_at < started_at:
                raise InfrastructureError(
                    "run_reconciliation_required",
                    "the stored infrastructure run timestamps are inconsistent; inspect them before continuing",
                )
            self._validate_run_receipt(value.get("receipt"), plan=plan, run=value, approval=approval)
        return value

    def _load_run_for_plan(self, plan: Mapping[str, Any]) -> dict[str, Any] | None:
        root = self._ensure_run_root(create=False)
        if root is None:
            return None
        operation = str(plan["operation"])
        path = root / f"{self._run_id(str(plan['planDigest']), operation)}.json"
        value = self._read_run_json(path)
        return None if value is None else self._validate_run_record(value, plan)

    def _reconcile_existing_run(self, run: dict[str, Any]) -> dict[str, Any]:
        state = run["state"]
        if state == "completed":
            return run
        if state == "failed":
            failure = run["error"]
            receipt = run["receipt"]
            details = dict(failure["details"])
            details.update(
                {
                    "runId": run["runId"],
                    "receiptId": receipt["receiptId"],
                    "storedTerminalFailure": True,
                }
            )
            raise InfrastructureError(failure["code"], failure["message"], details=details)
        raise InfrastructureError(
            "run_reconciliation_required",
            "the infrastructure run may have started; inspect and reconcile it before any new execution",
            details={"runId": run["runId"], "state": state},
        )

    def _latest_run(self) -> dict[str, Any] | None:
        root = self._ensure_run_root(create=False)
        if root is None:
            return None
        files: list[tuple[float, Path]] = []
        for path in root.iterdir():
            if re.fullmatch(r"infra-run-[0-9a-f]{24}\.json", path.name) is None:
                continue
            if path.is_symlink():
                raise InfrastructureError(
                    "run_reconciliation_required",
                    "the stored infrastructure run is a symlink; inspect it before continuing",
                )
            try:
                details = path.stat()
            except OSError as exc:
                raise InfrastructureError(
                    "run_reconciliation_required",
                    "the stored infrastructure run cannot be inspected safely",
                ) from exc
            files.append((details.st_mtime, path))
        files.sort(key=lambda item: item[0], reverse=True)
        if not files:
            return None
        value = self._read_run_json(files[0][1])
        if value is None:
            return None
        plan_digest = value.get("planDigest")
        if not isinstance(plan_digest, str):
            raise InfrastructureError(
                "run_reconciliation_required",
                "the stored infrastructure run lacks its plan identity; inspect it before continuing",
            )
        plan = self._load_plan(plan_digest, require_unexpired=False)
        return self._validate_run_record(value, plan)

    def latest_run(self) -> dict[str, Any] | None:
        """Return the latest durable run projection for service recovery."""

        return self._latest_run()

    def _commands_for(self, operation: str, domain_state: str) -> list[list[str]]:
        if operation == "validate":
            return [["nix", "flake", "check", "--no-build"]]
        if operation == "create_or_update":
            return [["make", "vm-persistent-create"]] if domain_state == "not_defined" else [["make", "vm-persistent-rebuild"]]
        if operation == "start":
            return [["make", "vm-persistent-start"]]
        if operation == "stop":
            return [["make", "vm-persistent-stop"]]
        if operation == "restart":
            return [["make", "vm-persistent-stop"], ["make", "vm-persistent-start"]]
        if operation == "destroy":
            return [["./scripts/vm-persistent-delete.sh", "--yes"]]
        return []

    def plan(self, operation: str) -> dict[str, Any]:
        if operation not in OPERATIONS:
            raise InfrastructureError("operation_unsupported", "the local libvirt operation is unsupported")
        identity = self.project_identity()
        stateport = self.stateport_identity()
        domain = self._domain_observation()
        durable_grant = self._active_grant_for(operation)
        payload: dict[str, Any] = {
            "formatVersion": "stateport.infrastructure-plan/v1",
            "instanceId": self.instance_id,
            "operation": operation,
            "operationMode": "routine_reversible_local" if durable_grant is not None else "exact_operation_approval",
            "stateport": stateport.to_dict() if stateport else None,
            "target": self.target.to_dict(),
            "repository": identity.to_dict(),
            "domainBefore": domain,
            "sshVerification": self._ssh_policy(str(domain.get("uuid") or "")).to_dict(),
            "commands": self._commands_for(operation, str(domain.get("state", "unavailable"))),
            "approvalRequired": operation in MUTATING_OPERATIONS and durable_grant is None,
            "authorization": (
                {"mode": "durable_grant", "grantId": durable_grant.grant_id, "grantDigest": durable_grant.grant_digest}
                if durable_grant is not None
                else {"mode": "exact_plan_approval"}
            ),
            "runtime": {"workingDirectory": Path(identity.root).name, "timeoutSeconds": 900, "sandbox": "StatePort service policy"},
            "rollback": "restore prior domain/disk state where the repository workflow supports it; uncertain state is reported",
            "network": "user-mode NAT; SSH forwarded only to localhost:2223",
            "createdAt": _timestamp(self._clock()),
            "expiresAt": _timestamp(self._clock() + timedelta(seconds=PLAN_TTL_SECONDS)),
        }
        if operation in {"observe", "health"}:
            payload["preflight"] = domain
        payload["planDigest"] = _digest(payload)
        _atomic_json(self._plans / f"{payload['planDigest'][7:]}.json", payload)
        return payload

    def reconcile_lease(self) -> dict[str, Any]:
        """Safely classify an unheld lease without deleting its diagnostic file."""

        if InstanceLease is None:
            raise InfrastructureError("lease_unavailable", "the instance lease contract is unavailable")
        latest = self._latest_run()
        durable_state = latest.get("state") if isinstance(latest, Mapping) else None
        lease = self._lease("reconcile")
        had_lock = lease.lock_path.exists()
        try:
            with self._operation_lock():
                try:
                    lease.acquire()
                except InstanceLeaseBusy:
                    return {"status": "active", "safeToProceed": False, "lockHeld": True, "durableRunState": durable_state}
                finally:
                    lease.release()
        except InstanceLeaseError as exc:
            raise InfrastructureError("lease_reconciliation_failed", "the infrastructure lease could not be reconciled") from exc
        if durable_state in {"preparing", "running"}:
            return {"status": "uncertain", "safeToProceed": False, "lockHeld": False, "durableRunState": durable_state}
        return {"status": "stale_unheld" if had_lock else "clear", "safeToProceed": True, "lockHeld": False, "durableRunState": durable_state}

    def _load_plan(self, plan_digest: str, *, require_unexpired: bool = True) -> dict[str, Any]:
        if not isinstance(plan_digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", plan_digest) is None:
            raise InfrastructureError("plan_invalid", "plan digest is invalid")
        path = self._plans / f"{plan_digest[7:]}.json"
        if path.is_symlink() or not path.is_file():
            raise InfrastructureError("plan_not_found", "the exact infrastructure plan was not found")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise InfrastructureError("plan_invalid", "the stored infrastructure plan is unreadable") from exc
        if not isinstance(value, dict) or value.get("planDigest") != plan_digest or _digest({key: item for key, item in value.items() if key != "planDigest"}) != plan_digest:
            raise InfrastructureError("plan_invalid", "the stored infrastructure plan digest is invalid")
        try:
            expiry = datetime.fromisoformat(str(value["expiresAt"]).replace("Z", "+00:00"))
        except (KeyError, TypeError, ValueError) as exc:
            raise InfrastructureError("plan_invalid", "plan expiry is invalid") from exc
        if require_unexpired and expiry <= self._clock():
            raise InfrastructureError("plan_expired", "the infrastructure plan expired; prepare a new plan")
        return value

    def pending_approval_sources(self, *, maximum_plans: int = 50) -> list[dict[str, Any]]:
        """Derive actionable plan/grant requests from their existing stores.

        No approval status is persisted here.  Each returned plan is
        content-addressed, unexpired, unapproved, and still passes the same
        repository/target checks used by :meth:`approve`.  A proposed durable
        grant is returned only while its exact current scope still matches.
        """

        if isinstance(maximum_plans, bool) or not isinstance(maximum_plans, int) or maximum_plans < 1:
            raise ValueError("maximum_plans must be a positive integer")
        sources: list[dict[str, Any]] = []
        try:
            grant = self._load_daily_driver_grant()
            if grant is not None and grant.status == "proposed":
                scope = self._grant_scope()
                scope["createdAt"] = grant.created_at
                if self._grant_scope_digest(scope) == grant.proposal_digest:
                    sources.append({
                        "type": "authorization_grant",
                        "grant": self._daily_driver_grant_projection(grant),
                    })
        except InfrastructureError:
            # An invalid or stale proposal is not safely actionable.
            pass

        if not self._plans.is_dir() or self._plans.is_symlink():
            return sources
        candidates: list[tuple[float, Path]] = []
        for path in self._plans.iterdir():
            if (
                path.is_symlink()
                or not path.is_file()
                or re.fullmatch(r"[0-9a-f]{64}\.json", path.name) is None
            ):
                continue
            try:
                details = path.stat()
                if details.st_size > 512 * 1024:
                    continue
            except OSError:
                continue
            candidates.append((details.st_mtime, path))
        candidates.sort(key=lambda item: item[0], reverse=True)
        for _modified_at, path in candidates[:maximum_plans]:
            plan_digest = "sha256:" + path.stem
            try:
                plan = self._load_plan(plan_digest)
                if plan.get("approvalRequired") is not True:
                    continue
                try:
                    self._load_approval(plan_digest)
                except InfrastructureError:
                    pass
                else:
                    continue
                if self.project_identity().to_dict() != plan.get("repository"):
                    continue
                self._assert_plan_target_current(plan)
                if (
                    str(plan.get("operation")) in {"start", "restart"}
                    and plan.get("sshVerification", {}).get("status") != "enrolled"
                ):
                    continue
            except InfrastructureError:
                continue
            sources.append({"type": "infrastructure_plan", "plan": plan})
        return sources

    def approve(self, plan_digest: str, actor_id: str) -> dict[str, Any]:
        plan = self._load_plan(plan_digest)
        if plan.get("approvalRequired") is not True:
            raise InfrastructureError("approval_not_required", "this operation is already covered by the active local daily-driver grant")
        if actor_id != "local-user":
            raise InfrastructureError("approval_denied", "the local operator identity is required")
        current = self.project_identity().to_dict()
        if current != plan.get("repository"):
            raise InfrastructureError("plan_stale", "the repository identity changed; prepare a new plan")
        self._assert_plan_target_current(plan)
        if str(plan.get("operation")) in {"start", "restart"} and plan.get("sshVerification", {}).get("status") != "enrolled":
            raise InfrastructureError("ssh_key_not_enrolled", "the VM START plan cannot be approved before SSH host-key enrollment")
        approval = {
            "formatVersion": "stateport.infrastructure-approval/v1",
            "approvalId": "approval-" + hashlib.sha256(f"{self.instance_id}:{plan_digest}:{actor_id}".encode()).hexdigest()[:24],
            "instanceId": self.instance_id,
            "actorId": actor_id,
            "planDigest": plan_digest,
            "approvedAt": _timestamp(self._clock()),
            "expiresAt": _timestamp(self._clock() + timedelta(seconds=PLAN_TTL_SECONDS)),
        }
        approval["approvalDigest"] = _digest(approval)
        _atomic_json(self._approvals / f"{plan_digest[7:]}.json", approval)
        return approval

    def _load_approval(self, plan_digest: str) -> dict[str, Any]:
        path = self._approvals / f"{plan_digest[7:]}.json"
        if path.is_symlink() or not path.is_file():
            raise InfrastructureError("approval_required", "exact approval for this plan is required")
        try:
            approval = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise InfrastructureError("approval_invalid", "the stored infrastructure approval is unreadable") from exc
        expected_keys = {
            "formatVersion",
            "approvalId",
            "instanceId",
            "actorId",
            "planDigest",
            "approvedAt",
            "expiresAt",
            "approvalDigest",
        }
        expected_approval_id = "approval-" + hashlib.sha256(
            f"{self.instance_id}:{plan_digest}:local-user".encode()
        ).hexdigest()[:24]
        if (
            not isinstance(approval, dict)
            or set(approval) != expected_keys
            or approval.get("formatVersion") != "stateport.infrastructure-approval/v1"
            or approval.get("approvalId") != expected_approval_id
            or approval.get("instanceId") != self.instance_id
            or approval.get("planDigest") != plan_digest
            or approval.get("actorId") != "local-user"
            or approval.get("approvalDigest")
            != _digest({key: value for key, value in approval.items() if key != "approvalDigest"})
        ):
            raise InfrastructureError("approval_invalid", "approval does not match the exact plan")
        try:
            approved_at = datetime.fromisoformat(str(approval["approvedAt"]).replace("Z", "+00:00"))
            expiry = datetime.fromisoformat(str(approval["expiresAt"]).replace("Z", "+00:00"))
        except (KeyError, TypeError, ValueError) as exc:
            raise InfrastructureError("approval_invalid", "approval expiry is invalid") from exc
        if (
            approved_at.tzinfo is None
            or approved_at.utcoffset() != timedelta(0)
            or expiry.tzinfo is None
            or expiry.utcoffset() != timedelta(0)
            or expiry <= approved_at
        ):
            raise InfrastructureError("approval_invalid", "approval timestamps are invalid")
        if expiry <= self._clock():
            raise InfrastructureError("approval_expired", "the infrastructure approval expired; prepare a new plan")
        return approval

    def _lease(self, operation: str) -> Any:
        if InstanceLease is None:
            raise InfrastructureError("lease_unavailable", "the instance lease contract is unavailable")
        try:
            return InstanceLease(self.state_root / "leases", self.repository_root, owner=f"{self.instance_id}:{operation}")
        except (InstanceLeaseError, OSError) as exc:
            raise InfrastructureError("lease_unavailable", "the infrastructure writer lease could not be prepared") from exc

    def run(self, plan_digest: str) -> dict[str, Any]:
        # The operation lock covers both the absent check and the complete
        # execution.  A second process therefore either observes the exact
        # terminal record or an explicitly uncertain reservation; it can
        # never pass a second absent check and repeat an external effect.
        with self._operation_lock():
            plan = self._load_plan(plan_digest, require_unexpired=False)
            operation = str(plan["operation"])
            existing = self._load_run_for_plan(plan)
            if existing is not None:
                return self._reconcile_existing_run(existing)

            # Expiry and mutable authority checks apply only before the first
            # reservation.  A lost-response replay remains inspectable after
            # those clocks or observed identities have moved.
            self._load_plan(plan_digest, require_unexpired=True)
            if operation in MUTATING_OPERATIONS:
                durable_grant = self._active_grant_for(operation)
                approval = (
                    {
                        "formatVersion": "stateport.infrastructure-grant-authorization/v1",
                        "authorizationType": "durable_grant",
                        "grantId": durable_grant.grant_id,
                        "grantDigest": durable_grant.grant_digest,
                        "approvalDigest": _digest(
                            {"planDigest": plan_digest, "grantDigest": durable_grant.grant_digest}
                        ),
                    }
                    if durable_grant is not None
                    else self._load_approval(plan_digest)
                )
                if self.project_identity().to_dict() != plan.get("repository"):
                    raise InfrastructureError("plan_stale", "the repository identity changed after approval")
                self._assert_plan_target_current(plan)
                if (
                    durable_grant is None
                    and operation in {"start", "restart"}
                    and plan.get("sshVerification", {}).get("status") != "enrolled"
                ):
                    raise InfrastructureError(
                        "ssh_key_not_enrolled",
                        "the VM operation is blocked until SSH host-key enrollment",
                    )
            else:
                approval = None

            run_id = self._run_id(plan_digest, operation)
            run: dict[str, Any] = {
                "formatVersion": RUN_FORMAT,
                "runId": run_id,
                "instanceId": self.instance_id,
                "operation": operation,
                "planDigest": plan_digest,
                "approval": approval,
                "state": "preparing",
                "events": [],
                "startedAt": _timestamp(self._clock()),
            }
            root = self._ensure_run_root(create=True)
            assert root is not None
            run_path = root / f"{run_id}.json"
            try:
                _exclusive_json(run_path, self._seal_run(run))
            except FileExistsError:
                raced = self._load_run_for_plan(plan)
                if raced is None:
                    raise InfrastructureError(
                        "run_reconciliation_required",
                        "the infrastructure run reservation could not be reconciled; inspect it before continuing",
                    )
                return self._reconcile_existing_run(raced)

            try:
                if operation == "observe":
                    result = self.inspect()
                elif operation == "health":
                    result = {"health": self._health(), "observation": self._domain_observation()}
                else:
                    lease = self._lease(operation) if operation in MUTATING_OPERATIONS else None
                    if lease is not None:
                        try:
                            lease.acquire()
                        except (InstanceLeaseBusy, InstanceLeaseError) as exc:
                            raise InfrastructureError(
                                "writer_lease_busy",
                                "another infrastructure operation owns the repository lease",
                            ) from exc
                    try:
                        for command in plan.get("commands", []):
                            run["state"] = "running"
                            _atomic_json(run_path, self._seal_run(run))
                            event = self._run(command, timeout=900)
                            run["events"].append(self._receipt_event(event))
                            _atomic_json(run_path, self._seal_run(run))
                            if event["status"] != "completed" or event["returnCode"] != 0:
                                raise InfrastructureError(
                                    "operation_failed",
                                    "the repository-owned infrastructure command failed",
                                    details={"event": run["events"][-1]},
                                )
                        result = self.inspect()
                        result["health"] = self._health()
                    finally:
                        if lease is not None:
                            lease.release()
                run["state"] = "completed"
                run["result"] = result
                run["receipt"] = self._receipt(plan, run, "completed")
            except InfrastructureError as exc:
                run["state"] = "failed"
                run["error"] = {"code": exc.code, "message": str(exc), "details": exc.details}
                run["receipt"] = self._receipt(plan, run, "failed")
            run["endedAt"] = _timestamp(self._clock())
            _atomic_json(run_path, self._seal_run(run))
            return self._reconcile_existing_run(run)

    def _receipt(self, plan: Mapping[str, Any], run: Mapping[str, Any], status: str) -> dict[str, Any]:
        operation = str(plan["operation"])
        action = RECEIPT_ACTIONS[operation]
        payload = {
            "formatVersion": RECEIPT_FORMAT,
            "receiptType": RECEIPT_FORMAT,
            "receiptId": "infra-receipt-" + hashlib.sha256(f"{self.instance_id}:{plan['planDigest']}:{status}".encode()).hexdigest()[:24],
            "instanceId": self.instance_id,
            "action": action,
            "status": status,
            "sourceKind": "infrastructure",
            "createdAt": _timestamp(self._clock()),
            "planDigest": plan["planDigest"],
            "approvalDigest": run.get("approval", {}).get("approvalDigest") if isinstance(run.get("approval"), Mapping) else None,
            "authorization": {
                "type": run.get("approval", {}).get("authorizationType") if isinstance(run.get("approval"), Mapping) else None,
                "grantId": run.get("approval", {}).get("grantId") if isinstance(run.get("approval"), Mapping) else None,
                "grantDigest": run.get("approval", {}).get("grantDigest") if isinstance(run.get("approval"), Mapping) else None,
            },
            "stateport": plan.get("stateport"),
            "repository": plan["repository"],
            "target": plan["target"],
            "operationState": run.get("state"),
            "events": run.get("events", []),
            "resultDigest": _digest(run.get("result")) if run.get("result") is not None else None,
            "rollback": plan.get("rollback"),
            "knownLimitations": ["Health is derived from observed libvirt/SSH/doctor results; running does not imply healthy."],
        }
        if status == "failed":
            payload["failure"] = run.get("error")
        if operation == "validate":
            events = run.get("events")
            validated = (
                status == "completed"
                and isinstance(events, list)
                and bool(events)
                and all(
                    isinstance(event, Mapping)
                    and event.get("status") == "completed"
                    and event.get("returnCode") == 0
                    for event in events
                )
            )
            payload["validation"] = {
                "state": "validated" if validated else "failed" if status == "failed" else "not_recorded",
                "detail": (
                    "The repository-owned Nix flake check completed locally with exit code 0."
                    if validated
                    else "The repository-owned Nix flake check did not complete successfully."
                    if status == "failed"
                    else "The infrastructure run recorded no complete validation event."
                ),
            }
        payload["receiptDigest"] = _digest(payload)
        return payload


__all__ = [
    "DAILY_DRIVER_GRANT_FORMAT",
    "DAILY_DRIVER_GRANT_ID",
    "FORMAT",
    "InfrastructureError",
    "InfrastructureProjectIdentity",
    "InfrastructureTarget",
    "LocalNixDailyDriverGrant",
    "LocalLibvirtAdapter",
    "MUTATING_OPERATIONS",
    "OPERATIONS",
    "SSH_ENROLLMENT_FORMAT",
    "SSHHostKeyEnrollment",
    "SSHHostKeyFingerprint",
    "SSHHostKeyRotationProposal",
    "SSHHostVerificationPolicy",
    "SSHKnownHostIdentity",
    "SSHVerificationReceipt",
    "SSHTargetIdentity",
    "StatePortIdentity",
]
