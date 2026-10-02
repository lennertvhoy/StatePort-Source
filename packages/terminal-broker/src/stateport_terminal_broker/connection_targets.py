"""Server-owned SSH launch policy and optional Herdr capability detection.

Nothing in this module opens a network connection or attaches to Herdr.  SSH
plans contain server-only values and deliberately have no public serializer.
The browser receives only an opaque allowlisted target identity and bounded
capability metadata.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import stat
import subprocess
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence

from .broker import TerminalTargetUnavailable
from .contracts import TERMINAL_FORMAT_VERSION, TerminalCapabilities


CONNECTION_TARGET_FORMAT_VERSION = "stateport.terminal-connection-target/v1"
SSH_EXECUTABLE = "/usr/bin/ssh"
HERDR_MINIMUM_MACHINE_STREAM_VERSION = "0.7.2"

SSH_AUTHENTICATION_ROUTES = frozenset({
    "configured_key_reference",
    "sanctioned_secret_broker",
})
SSH_REASON_CODES = frozenset({
    "ssh_authentication_failed",
    "ssh_connection_failed",
    "ssh_connection_refused",
    "ssh_connection_timed_out",
    "ssh_host_key_mismatch",
    "ssh_host_key_verification_failed",
    "ssh_live_connection_not_validated",
    "ssh_target_not_allowlisted",
})
HERDR_REASON_CODES = frozenset({
    "herdr_adapter_not_implemented",
    "herdr_machine_stream_unavailable",
    "herdr_machine_stream_unverified",
    "herdr_machine_stream_unsupported",
    "herdr_not_installed",
    "herdr_version_unreadable",
})
CAPSULE_REASON_CODES = frozenset({
    "capsule_live_exec_not_validated",
    "capsule_execution_host_socket_unavailable",
    "capsule_identity_unresolved",
    "capsule_sealed_workload_digest_mismatch",
})

_OPAQUE_TARGET_ID = re.compile(r"^terminal_target_[0-9a-f]{32,96}$")
_CONTRACT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SSH_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DNS_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_HERDR_VERSION = re.compile(r"^(?:herdr\s+)?([0-9]+)\.([0-9]+)\.([0-9]+)(?:[-+][A-Za-z0-9.-]+)?$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _bounded_printable(value: str, label: str, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError(f"{label} must be bounded printable text")
    return value


def _opaque_target_id(value: str) -> str:
    if not isinstance(value, str) or _OPAQUE_TARGET_ID.fullmatch(value) is None:
        raise ValueError("terminal target id must be opaque")
    return value


def _safe_hostname(value: str) -> str:
    _bounded_printable(value, "SSH hostname", maximum=253)
    if value.startswith("-") or any(character in value for character in "@/\\[]:= \t\r\n"):
        raise ValueError("SSH hostname is invalid")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        labels = value.rstrip(".").split(".")
        if not labels or any(_DNS_LABEL.fullmatch(label) is None for label in labels):
            raise ValueError("SSH hostname is invalid")
        return value


def _host_key_identity(value: str) -> str:
    if not isinstance(value, str) or not value.startswith("SHA256:"):
        raise ValueError("SSH host-key identity must be an SHA256 fingerprint")
    encoded = value.removeprefix("SHA256:")
    if not 43 <= len(encoded) <= 44:
        raise ValueError("SSH host-key identity must be an SHA256 fingerprint")
    try:
        decoded = base64.b64decode(encoded + ("=" * (-len(encoded) % 4)), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("SSH host-key identity must be an SHA256 fingerprint") from exc
    if len(decoded) != 32:
        raise ValueError("SSH host-key identity must be an SHA256 fingerprint")
    return value


def _controlled_directory(value: Path, label: str) -> Path:
    if not isinstance(value, Path) or not value.is_absolute() or ".." in value.parts:
        raise ValueError(f"{label} must be an absolute controlled directory")
    if value.is_symlink():
        raise ValueError(f"{label} may not be a symlink")
    try:
        resolved = value.resolve(strict=True)
        details = resolved.stat()
    except OSError as exc:
        raise ValueError(f"{label} is unavailable") from exc
    if resolved != value or not stat.S_ISDIR(details.st_mode):
        raise ValueError(f"{label} must be an exact directory")
    if details.st_uid != os.geteuid() or details.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError(f"{label} must be owned by StatePort and not group/world writable")
    return resolved


def _controlled_file(value: Path, root: Path, label: str, *, private: bool = False) -> Path:
    if not isinstance(value, Path) or not value.is_absolute() or ".." in value.parts:
        raise ValueError(f"{label} must be an absolute controlled file")
    try:
        value.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{label} must remain inside the SSH configuration root") from exc
    cursor = value
    while cursor != root:
        if cursor.is_symlink():
            raise ValueError(f"{label} may not traverse a symlink")
        cursor = cursor.parent
    cursor = value.parent
    while True:
        try:
            resolved_parent = cursor.resolve(strict=True)
            parent_details = resolved_parent.stat()
        except OSError as exc:
            raise ValueError(f"{label} parent directory is unavailable") from exc
        if (
            resolved_parent != cursor
            or not stat.S_ISDIR(parent_details.st_mode)
            or parent_details.st_uid != os.geteuid()
            or parent_details.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise ValueError(f"{label} parent directories must remain StatePort-controlled")
        if cursor == root:
            break
        cursor = cursor.parent
    try:
        resolved = value.resolve(strict=True)
        details = resolved.stat()
    except OSError as exc:
        raise ValueError(f"{label} is unavailable") from exc
    if resolved != value or not stat.S_ISREG(details.st_mode):
        raise ValueError(f"{label} must be an exact regular file")
    if details.st_uid != os.geteuid() or details.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError(f"{label} must be owned by StatePort and not group/world writable")
    if private and details.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ValueError(f"{label} must not be accessible to group or other users")
    if details.st_size > 1_048_576:
        raise ValueError(f"{label} exceeds the one MiB policy limit")
    return resolved


def _file_digest(value: Path) -> str:
    digest = hashlib.sha256()
    with value.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65_536), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _known_host_fingerprint(value: Path, alias: str) -> str:
    """Bind the displayed identity to the sole key OpenSSH will trust.

    Per-target files deliberately reject wildcard, hashed, marker, multi-host,
    and additional active entries.  OpenSSH must not have a second acceptance
    path which the public fingerprint does not describe.
    """

    matches: list[str] = []
    try:
        lines = value.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ValueError("SSH known-hosts file is unreadable") from exc
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        if len(fields) < 3 or fields[0] != alias:
            raise ValueError("SSH known-hosts file must contain only the exact target alias")
        try:
            key = base64.b64decode(fields[2], validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("SSH known-hosts entry has invalid key data") from exc
        if not key:
            raise ValueError("SSH known-hosts entry has empty key data")
        digest = base64.b64encode(hashlib.sha256(key).digest()).decode("ascii").rstrip("=")
        matches.append("SHA256:" + digest)
    if len(matches) != 1:
        raise ValueError("SSH HostKeyAlias must bind exactly one trusted host key")
    return matches[0]


@dataclass(frozen=True)
class SshTargetProfile:
    """Trusted server configuration; endpoint and key paths are never public."""

    target_id: str
    display_name: str
    connection_label: str
    hostname: str = field(repr=False)
    username: str
    port: int
    host_key_alias: str
    host_key_identity: str
    authentication_route: str
    configuration_root: Path = field(repr=False)
    known_hosts_file: Path = field(repr=False)
    identity_file: Path = field(repr=False)
    instance_ids: tuple[str, ...]
    connect_timeout_seconds: int = 10
    server_alive_interval_seconds: int = 15
    server_alive_count_max: int = 3

    def __post_init__(self) -> None:
        _opaque_target_id(self.target_id)
        _bounded_printable(self.display_name, "SSH display name", maximum=128)
        _bounded_printable(self.connection_label, "SSH connection label", maximum=128)
        _safe_hostname(self.hostname)
        if _SSH_NAME.fullmatch(self.username) is None:
            raise ValueError("SSH username is invalid")
        if isinstance(self.port, bool) or not isinstance(self.port, int) or not 1 <= self.port <= 65_535:
            raise ValueError("SSH port must be between 1 and 65535")
        if _SSH_NAME.fullmatch(self.host_key_alias) is None:
            raise ValueError("SSH HostKeyAlias is invalid")
        _host_key_identity(self.host_key_identity)
        if self.authentication_route not in SSH_AUTHENTICATION_ROUTES:
            raise ValueError("SSH authentication route is unsupported")
        root = _controlled_directory(self.configuration_root, "SSH configuration root")
        known_hosts = _controlled_file(self.known_hosts_file, root, "SSH known-hosts file")
        _controlled_file(self.identity_file, root, "SSH identity reference", private=True)
        if _known_host_fingerprint(known_hosts, self.host_key_alias) != self.host_key_identity:
            raise ValueError("SSH displayed host-key identity does not match the trusted key")
        if not self.instance_ids or len(self.instance_ids) > 128:
            raise ValueError("SSH target requires a bounded instance allowlist")
        if any(_CONTRACT_ID.fullmatch(item) is None for item in self.instance_ids):
            raise ValueError("SSH instance allowlist is invalid")
        if len(set(self.instance_ids)) != len(self.instance_ids):
            raise ValueError("SSH instance allowlist must be unique")
        for value, label, maximum in (
            (self.connect_timeout_seconds, "connect timeout", 60),
            (self.server_alive_interval_seconds, "server-alive interval", 300),
            (self.server_alive_count_max, "server-alive count", 10),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
                raise ValueError(f"SSH {label} is outside policy")

    def public_capability(self) -> dict[str, Any]:
        capabilities = TerminalCapabilities(
            "ssh", False, False, False, False, False, False,
            reconnect_scope="none_until_live_adapter_is_validated",
        )
        return {
            "formatVersion": CONNECTION_TARGET_FORMAT_VERSION,
            "targetId": self.target_id,
            "targetClass": "ssh",
            "displayName": self.display_name,
            "availability": "environment_gated",
            "reasonCode": "ssh_live_connection_not_validated",
            "connectionLabel": self.connection_label,
            "knownHostIdentity": self.host_key_identity,
            "authenticationRoute": self.authentication_route,
            "capabilities": capabilities.to_dict(),
        }


@dataclass(frozen=True)
class SshLaunchPlan:
    """Non-serializable executor input whose representation hides server paths."""

    target_id: str
    argv: tuple[str, ...] = field(repr=False)
    environment: Mapping[str, str] = field(repr=False)
    known_hosts_digest: str
    authentication_route: str

    def __post_init__(self) -> None:
        _opaque_target_id(self.target_id)
        if not self.argv or self.argv[0] != SSH_EXECUTABLE:
            raise ValueError("SSH launch plan must use the fixed executable")
        if _DIGEST.fullmatch(self.known_hosts_digest) is None:
            raise ValueError("SSH known-hosts digest is invalid")
        if self.authentication_route not in SSH_AUTHENTICATION_ROUTES:
            raise ValueError("SSH authentication route is unsupported")


class SshTargetRegistry:
    """Resolve only server-owned profiles from opaque browser selections."""

    def __init__(self, profiles: tuple[SshTargetProfile, ...]) -> None:
        if not profiles or len(profiles) > 128 or any(not isinstance(item, SshTargetProfile) for item in profiles):
            raise ValueError("SSH target registry requires bounded trusted profiles")
        values = {item.target_id: item for item in profiles}
        if len(values) != len(profiles):
            raise ValueError("SSH target ids must be unique")
        self._profiles = MappingProxyType(values)

    def public_targets(self, *, instance_id: str) -> tuple[dict[str, Any], ...]:
        if _CONTRACT_ID.fullmatch(instance_id) is None:
            return ()
        result = tuple(
            profile.public_capability()
            for profile in self._profiles.values()
            if instance_id in profile.instance_ids
        )
        for item in result:
            assert_no_browser_secret_fields(item)
        return result

    def resolve(self, target_id: str, *, instance_id: str) -> SshTargetProfile:
        profile = self._profiles.get(target_id) if isinstance(target_id, str) else None
        if profile is None or instance_id not in profile.instance_ids:
            raise TerminalTargetUnavailable("ssh_target_not_allowlisted")
        return profile


def build_ssh_launch_plan(profile: SshTargetProfile, *, instance_id: str) -> SshLaunchPlan:
    """Compile a shell-free plan which ignores ambient SSH configuration."""

    if not isinstance(profile, SshTargetProfile) or instance_id not in profile.instance_ids:
        raise TerminalTargetUnavailable("ssh_target_not_allowlisted")
    root = _controlled_directory(profile.configuration_root, "SSH configuration root")
    known_hosts = _controlled_file(profile.known_hosts_file, root, "SSH known-hosts file")
    identity = _controlled_file(profile.identity_file, root, "SSH identity reference", private=True)
    if _known_host_fingerprint(known_hosts, profile.host_key_alias) != profile.host_key_identity:
        raise ValueError("SSH trusted host key changed after profile validation")
    options = (
        "BatchMode=yes",
        "NumberOfPasswordPrompts=0",
        "PasswordAuthentication=no",
        "KbdInteractiveAuthentication=no",
        "PubkeyAuthentication=yes",
        "IdentitiesOnly=yes",
        "IdentityAgent=none",
        f"IdentityFile={identity.as_posix()}",
        "StrictHostKeyChecking=yes",
        f"UserKnownHostsFile={known_hosts.as_posix()}",
        "GlobalKnownHostsFile=none",
        f"HostKeyAlias={profile.host_key_alias}",
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
        "RequestTTY=force",
        "TCPKeepAlive=no",
        f"ConnectTimeout={profile.connect_timeout_seconds}",
        f"ServerAliveInterval={profile.server_alive_interval_seconds}",
        f"ServerAliveCountMax={profile.server_alive_count_max}",
    )
    argv: list[str] = [SSH_EXECUTABLE, "-F", "none"]
    for option in options:
        argv.extend(("-o", option))
    argv.extend(("-p", str(profile.port), f"{profile.username}@{profile.hostname}"))
    environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TERM": "xterm-256color",
    }
    return SshLaunchPlan(
        target_id=profile.target_id,
        argv=tuple(argv),
        environment=MappingProxyType(environment),
        known_hosts_digest=_file_digest(known_hosts),
        authentication_route=profile.authentication_route,
    )


def classify_ssh_failure(stderr: str, return_code: int | None) -> str:
    """Reduce bounded OpenSSH diagnostics to a non-secret reason code."""

    text = str(stderr or "")[:16_384].lower()
    if "remote host identification has changed" in text or "offending" in text and "host key" in text:
        return "ssh_host_key_mismatch"
    if "host key verification failed" in text or "no matching host key" in text:
        return "ssh_host_key_verification_failed"
    if "permission denied" in text or "no more authentication methods" in text:
        return "ssh_authentication_failed"
    if "connection timed out" in text or "operation timed out" in text:
        return "ssh_connection_timed_out"
    if "connection refused" in text:
        return "ssh_connection_refused"
    if return_code is None:
        return "ssh_connection_timed_out"
    return "ssh_connection_failed"


@dataclass(frozen=True)
class CapsuleTargetProfile:
    """Execution-host capsule reference; the socket path is never public.

    The capsule target class connects the governed terminal boundary to a
    sealed workload managed by the execution-host daemon (WT-1).  As with the
    SSH and Herdr target classes, the live interactive exec adapter is not yet
    validated: the browser receives only an opaque allowlisted target identity
    and bounded, honest capability metadata.
    """

    target_id: str
    display_name: str
    connection_label: str
    capsule_id: str
    capsule_display_digest: str
    execution_host_socket: Path = field(repr=False)
    instance_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _opaque_target_id(self.target_id)
        _bounded_printable(self.display_name, "capsule display name", maximum=128)
        _bounded_printable(self.connection_label, "capsule connection label", maximum=128)
        if _CONTRACT_ID.fullmatch(self.capsule_id) is None:
            raise ValueError("capsule id must be a bounded contract identifier")
        if _DIGEST.fullmatch(self.capsule_display_digest) is None:
            raise ValueError("capsule display digest must be a sha256 digest")
        if not isinstance(self.execution_host_socket, Path) or not self.execution_host_socket.is_absolute():
            raise ValueError("execution-host socket must be an absolute path")
        if ".." in self.execution_host_socket.parts or self.execution_host_socket.is_symlink():
            raise ValueError("execution-host socket must be an exact controlled path")
        if not self.instance_ids or len(self.instance_ids) > 128:
            raise ValueError("capsule target requires a bounded instance allowlist")
        if any(_CONTRACT_ID.fullmatch(item) is None for item in self.instance_ids):
            raise ValueError("capsule instance allowlist is invalid")
        if len(set(self.instance_ids)) != len(self.instance_ids):
            raise ValueError("capsule instance allowlist must be unique")

    def public_capability(self) -> dict[str, Any]:
        capabilities = TerminalCapabilities(
            "capsule", False, False, False, False, False, False,
            reconnect_scope="none_until_live_exec_adapter_is_validated",
        )
        return {
            "formatVersion": CONNECTION_TARGET_FORMAT_VERSION,
            "targetId": self.target_id,
            "targetClass": "capsule",
            "displayName": self.display_name,
            "availability": "environment_gated",
            "reasonCode": "capsule_live_exec_not_validated",
            "connectionLabel": self.connection_label,
            "capsuleId": self.capsule_id,
            "capsuleDigest": self.capsule_display_digest,
            "capabilities": capabilities.to_dict(),
        }


class CapsuleTargetRegistry:
    """Resolve only server-owned capsule profiles from opaque browser selections."""

    def __init__(self, profiles: tuple[CapsuleTargetProfile, ...]) -> None:
        if not profiles or len(profiles) > 128 or any(not isinstance(item, CapsuleTargetProfile) for item in profiles):
            raise ValueError("capsule target registry requires bounded trusted profiles")
        values = {item.target_id: item for item in profiles}
        if len(values) != len(profiles):
            raise ValueError("capsule target ids must be unique")
        self._profiles = MappingProxyType(values)

    def public_targets(self, *, instance_id: str) -> tuple[dict[str, Any], ...]:
        if _CONTRACT_ID.fullmatch(instance_id) is None:
            return ()
        result = tuple(
            profile.public_capability()
            for profile in self._profiles.values()
            if instance_id in profile.instance_ids
        )
        for item in result:
            assert_no_browser_secret_fields(item)
        return result

    def resolve(self, target_id: str, *, instance_id: str) -> CapsuleTargetProfile:
        profile = self._profiles.get(target_id) if isinstance(target_id, str) else None
        if profile is None or instance_id not in profile.instance_ids:
            raise TerminalTargetUnavailable("capsule_target_not_allowlisted")
        return profile


@dataclass(frozen=True)
class HerdrCapability:
    installed: bool
    observed_version: str | None
    executable_digest: str | None
    availability: str
    reason_code: str
    machine_stream_conformance: bool

    def __post_init__(self) -> None:
        if self.reason_code not in HERDR_REASON_CODES:
            raise ValueError("Herdr reason code is invalid")
        if self.availability not in {"unavailable", "environment_gated"}:
            raise ValueError("Herdr capability may not claim availability before adapter acceptance")
        if self.executable_digest is not None and _DIGEST.fullmatch(self.executable_digest) is None:
            raise ValueError("Herdr executable digest is invalid")
        if not isinstance(self.machine_stream_conformance, bool):
            raise ValueError("Herdr conformance status must be boolean")

    def to_dict(self, *, target_id: str) -> dict[str, Any]:
        _opaque_target_id(target_id)
        capabilities = TerminalCapabilities(
            "herdr_attach", False, False, False, False, False, False,
            reconnect_scope="none_until_machine_stream_conformance_passes",
        )
        return {
            "formatVersion": CONNECTION_TARGET_FORMAT_VERSION,
            "targetId": target_id,
            "targetClass": "herdr_attach",
            "displayName": "Herdr",
            "availability": self.availability,
            "reasonCode": self.reason_code,
            "requiredVersion": HERDR_MINIMUM_MACHINE_STREAM_VERSION,
            "observedVersion": self.observed_version,
            "machineStreamConformance": self.machine_stream_conformance,
            "capabilities": capabilities.to_dict(),
        }


def assess_herdr_capability(
    *,
    installed: bool,
    version_output: str | None,
    executable_digest: str | None = None,
    machine_stream_conformance: bool = False,
) -> HerdrCapability:
    """Classify detection evidence without opening Herdr control surfaces."""

    if not installed:
        return HerdrCapability(False, None, None, "unavailable", "herdr_not_installed", False)
    match = _HERDR_VERSION.fullmatch(str(version_output or "").strip())
    if match is None:
        return HerdrCapability(True, None, executable_digest, "environment_gated", "herdr_version_unreadable", False)
    version = ".".join(match.groups())
    current = tuple(int(item) for item in match.groups())
    minimum = tuple(int(item) for item in HERDR_MINIMUM_MACHINE_STREAM_VERSION.split("."))
    if current < minimum:
        reason = "herdr_machine_stream_unsupported"
    elif not machine_stream_conformance:
        reason = "herdr_machine_stream_unverified"
    else:
        reason = "herdr_adapter_not_implemented"
    return HerdrCapability(True, version, executable_digest, "environment_gated", reason, machine_stream_conformance)


def probe_herdr_version(
    executable: Path,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> HerdrCapability:
    """Run only the bounded documented version query; never attach or mutate."""

    if not isinstance(executable, Path) or not executable.is_absolute() or executable.is_symlink():
        raise ValueError("Herdr executable path must be exact and absolute")
    try:
        resolved = executable.resolve(strict=True)
    except OSError:
        return assess_herdr_capability(installed=False, version_output=None)
    if resolved != executable or not resolved.is_file() or not os.access(resolved, os.X_OK):
        return assess_herdr_capability(installed=False, version_output=None)
    digest = _file_digest(resolved)
    try:
        result = runner(
            (resolved.as_posix(), "--version"),
            check=False,
            capture_output=True,
            text=True,
            timeout=2.0,
            cwd="/",
            env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/bin"},
        )
    except (OSError, subprocess.SubprocessError):
        return assess_herdr_capability(
            installed=True,
            version_output=None,
            executable_digest=digest,
        )
    output = result.stdout.strip() if result.returncode == 0 else None
    return assess_herdr_capability(
        installed=True,
        version_output=output,
        executable_digest=digest,
    )


@dataclass(frozen=True)
class ExternalTerminalAuditReceipt:
    """Transcript-free receipt which never conflates detach with remote exit."""

    receipt_id: str
    session_id: str
    target_id: str
    target_class: str
    actor_id: str
    instance_id: str
    action: str
    outcome: str
    occurred_at: str
    local_adapter_cleanup: str
    remote_process_cleanup: str
    reconnect_scope: str

    def __post_init__(self) -> None:
        for value, label in (
            (self.receipt_id, "receipt id"),
            (self.session_id, "session id"),
            (self.actor_id, "actor id"),
            (self.instance_id, "instance id"),
        ):
            if _CONTRACT_ID.fullmatch(value) is None:
                raise ValueError(f"external terminal {label} is invalid")
        _opaque_target_id(self.target_id)
        if self.target_class not in {"ssh", "herdr_attach", "capsule"}:
            raise ValueError("external terminal target class is invalid")
        if self.action not in {"prepared", "detached", "closed", "refused"}:
            raise ValueError("external terminal receipt action is invalid")
        if self.outcome not in {"accepted", "completed", "environment_gated", "refused"}:
            raise ValueError("external terminal receipt outcome is invalid")
        if self.local_adapter_cleanup not in {"not_started", "detached", "terminated", "cleanup_failed"}:
            raise ValueError("local adapter cleanup status is invalid")
        if self.remote_process_cleanup not in {"not_started", "not_applicable", "unverified"}:
            raise ValueError("remote process cleanup status is invalid")
        _bounded_printable(self.occurred_at, "receipt timestamp", maximum=64)
        _bounded_printable(self.reconnect_scope, "reconnect scope", maximum=128)

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": TERMINAL_FORMAT_VERSION,
            "receiptId": self.receipt_id,
            "sessionId": self.session_id,
            "targetId": self.target_id,
            "targetClass": self.target_class,
            "actorId": self.actor_id,
            "instanceId": self.instance_id,
            "action": self.action,
            "outcome": self.outcome,
            "occurredAt": self.occurred_at,
            "localAdapterCleanup": self.local_adapter_cleanup,
            "remoteProcessCleanup": self.remote_process_cleanup,
            "reconnectScope": self.reconnect_scope,
        }


def assert_no_browser_secret_fields(value: Mapping[str, Any]) -> None:
    """Reject accidental exposure from any future public capability projection."""

    forbidden = {
        "argv", "command", "environment", "hostname", "identityfile",
        "knownhostsfile", "password", "privatekey", "proxycommand", "socket", "socketurl",
        "executionhostsocket",
    }

    def walk(item: Any) -> None:
        if isinstance(item, Mapping):
            for key, nested in item.items():
                normalized = re.sub(r"[^a-z]", "", str(key).lower())
                if normalized in forbidden:
                    raise ValueError("public terminal capability contains a server-only field")
                walk(nested)
        elif isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            for nested in item:
                walk(nested)

    walk(value)
