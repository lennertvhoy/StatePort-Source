"""Signed-release execution-host provisioning: inspectable plan + narrow root helper.

Privilege boundary (deliberate, fail-closed):

- The rootless installer (``install_no_checkout.py``) and this module's
  ``emit-plan`` command only RENDER a plan from a release index.  They never
  escalate.  ``verificationBasis`` records whether the input was
  cryptographically verified or merely shape-validated.
- The transaction is callable by the root-owned host helper after that helper
  has verified the immutable provisioning module set.  The Python module does
  not expose a general ``sudo python -m ... apply`` path: an installer-owned
  interpreter or module tree must never execute as root.
- Every step observes before and after: identity (users/groups) exists and
  matches before any file that depends on it is written; ownership and modes
  are applied numerically and re-observed with ``lstat``; subordinate UID/GID
  mappings are exact lines, re-parsed after writing.  No substring-based
  "already exists" success anywhere: a failed command whose effect is absent
  is a failure.
- File writes are descriptor-relative, ``O_NOFOLLOW``, and atomic
  (write-temp-fsync-rename); symlink parents and symlink destinations refuse.
- The digest-pinned execution-host image is pulled and inspected AS
  ``stateport-exec`` so ``Pull=never`` resolves in that user's rootless
  store; a digest observed anywhere else is not evidence.
- Protocol health is a real ``describeCapabilities`` round trip through
  ``execution_host.client.ExecutionHostClient`` executed as both
  ``stateport-exec`` and the allowed control-plane client, never just socket
  existence. A stale socket inode (connect refused), an empty socket
  directory, or a socket with wrong ownership/mode is not health.
- Every mutation is journaled; any step failure rolls back exactly what this
  transaction created (never foreign bytes), and a schema-valid
  ``stateport.execution-host-provisioning-receipt/v1`` records the outcome,
  the rollback, and the uninstall commands.  ``evidenceClass`` is
  ``clean-host-executed`` only for an unmodified root transaction on ``/``;
  anything with an injected seam is ``locally-simulated``.

The module ships inside the digest-verified updater wheel.  A no-checkout
install may provision only after the operator has materialized that exact
module set root-owned at the helper's fixed path:
``/usr/local/libexec/stateport-execution-host-provision ...``
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import errno
import fcntl
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import secrets
import shlex
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Iterator, Mapping, Protocol, Sequence

from . import PORTABLE_LINUX_TARGET_ID, WSL2_TARGET_ID, observe_linux_substrate

from .contract import (
    CONFINED_GROUP_OCI_RUNTIME_PATH,
    CONFINED_GROUP_OCI_RUNTIME_SHA256,
    CONFINED_GROUP_OCI_RUNTIME_VERSION,
    PROVIDER_HOME_CONTRACT,
    PinnedPublicKeyIdentity,
    ReleaseContractError,
    ReleaseVerificationPolicy,
    VerifiedRelease,
    canonical_digest,
    load_release_index_file,
    parse_last_line_json,
    render_stable_host_quadlet_bundle,
    revision_contract_digest,
    validate_contract_document,
    verify_release_index,
)
from .cosign import CosignVerifier, bundle_slot, signature_bundle_name

CONTROL_USER = "stateport-control"
CONTROL_UID = 65531
CONTROL_GID = 65531
EXEC_USER = "stateport-exec"
EXEC_UID = 65532
EXEC_GID = 65532
EXEC_GROUP = "stateport-execution-control"
EXEC_GROUP_GID = 65530
TMPFILES_PATH = "/etc/tmpfiles.d/stateport-execution-control.conf"
CONTROL_HOME = f"/var/lib/{CONTROL_USER}"
EXEC_HOME = f"/var/lib/{EXEC_USER}"
EXEC_CONFIG_DIR = f"{EXEC_HOME}/.config"
QUADLET_DIR = f"{EXEC_CONFIG_DIR}/containers/systemd"
CONTROL_CONFIG_DIR = f"{CONTROL_HOME}/.config"
CONTROL_QUADLET_DIR = f"{CONTROL_CONFIG_DIR}/containers/systemd"
CONTROL_SYSTEMD_USER_DIR = f"{CONTROL_CONFIG_DIR}/systemd/user"
SERVICE_STATE_ROOT = f"{EXEC_HOME}/stateport-execution-host"
STATE_DIR = f"{SERVICE_STATE_ROOT}/state"
GRANTS_DIR = f"{STATE_DIR}/grants"
TEMPLATE_IMPORT_PARENT = "/var/lib/stateport"
TEMPLATE_IMPORT_ROOT = f"{TEMPLATE_IMPORT_PARENT}/imports"
SUBUID_PATH = "/etc/subuid"
SUBGID_PATH = "/etc/subgid"
LINGER_DIR = "/var/lib/systemd/linger"
SUBID_RANGE_SIZE = 65536
SUBID_MIN_START = 100000
DAEMON_UNIT = "stateport-execution-host.service"
ENGINE_SOCKET_UNIT = "podman.socket"
PLAN_SCHEMA = "stateport.execution-host-provisioning/v2"
_CLIENT_USER_NAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
CLIENT_IDENTITY_FILE = ".stateport-control-client"
RECEIPT_SCHEMA = "stateport.execution-host-provisioning-receipt/v1"
HEALTH_GRANT_ID = "provisioning-health-probe"
HEALTH_GRANT_DIGEST = "sha256:" + "0" * 64
# The default control-plane grant binds the sanctioned control identity (peer
# uid 65531) to both the canonical developer workspace and the narrowly typed
# local deployment boundary. Deployment business authority remains canonical
# control-plane state; this standing host grant only admits that authority mode
# on the exact local adapter/target and bounded descriptor transfer.
DEFAULT_GRANT_ID = "control-plane-default"
DEFAULT_WORKSPACE_ID = "default-dev"
DEFAULT_WORKSPACE_IMAGE = (
    "ghcr.io/lennertvhoy/stateport-dev-workspace@"
    "sha256:0102c422aa8cf9ba1abb5f708f5ba5280799e9407d9db938f2e771d069524b0f"
)
# Canonical digest of the sealed daemon workload rendered from the exact
# WorkspaceSpec below (see _default_workspace_spec).
DEFAULT_WORKSPACE_SPEC_DIGEST = (
    "sha256:a47074b22f26b612627d932262f55567533457e91f834796faf58b03237d506d"
)
_DEFAULT_GRANT_OPERATIONS = (
    "describeCapabilities",
    "createWorkload",
    "listWorkloads",
    "status",
    "logs",
    "start",
    "stop",
    "cancel",
    "removeWorkload",
    "execWorkload",
    "collectGarbage",
    "probeDeploymentTarget",
    "applyDeployment",
    "updateDeployment",
    "observeDeployment",
    "collectDeploymentLogs",
    "restartDeployment",
    "removeDeploymentRuntime",
    "backupDeploymentData",
    "restoreDeploymentData",
    "purgeDeploymentData",
)
_DEFAULT_GRANT_BUDGETS = {
    "maxTimeoutSeconds": 3600,
    "maxOutputBytes": 1024 * 1024,
    "maxMemoryMaxBytes": 512 * 1024 * 1024,
    "maxPidsMax": 256,
    "maxActiveWorkloads": 4,
    "maxCpuQuotaPercent": 200,
    "maxDiskMaxBytes": 1024 * 1024 * 1024,
}
_DEFAULT_DEPLOYMENT_SCOPE = {
    "authorityMode": "canonical-control-plane",
    "targetAdapter": "rootless-podman-local",
    "targetId": "local",
    "allowDataPurge": True,
    "maxArchiveBytes": 576 * 1024 * 1024,
    "maxFiles": 10_000,
}


def _default_workspace_spec() -> dict[str, Any]:
    """Return the canonical default developer workspace declaration.

    This is the ONE workload the default grant binds.  The GUI's real
    workload path creates exactly this workspace; anything else requires a
    per-workload grant extension issued by an operator authority.
    """
    return {
        "formatVersion": "stateport.workspace-spec/v1",
        "workspaceId": DEFAULT_WORKSPACE_ID,
        "imageDigest": DEFAULT_WORKSPACE_IMAGE.rsplit("@", 1)[1],
        "workspacePath": "/workspace",
        "shell": ["/bin/sh"],
        "resources": {
            "memoryMaxBytes": 256 * 1024 * 1024,
            "cpuQuotaPercent": 100,
            "pidsMax": 128,
            "diskMaxBytes": 256 * 1024 * 1024,
        },
        "networkProfile": {"mode": "disabled", "allowlist": []},
        "cacheVolumes": [],
        "lifecyclePolicy": {
            "idleTimeoutSeconds": 3600,
            "stopAfterIdle": True,
            "preserveDataOnRemove": True,
        },
    }


def _default_workspace_spec_digest() -> str:
    """Canonical digest of the WorkspaceSpec document itself (no imports)."""
    return canonical_digest(_default_workspace_spec())


def _default_sealed_workload() -> dict[str, Any]:
    """Render the sealed daemon workload for the default grant.

    The shape matches ``execution_host.daemon_contract.validate_workload_spec``
    normalization exactly (the sealed workspace translation of the canonical
    WorkspaceSpec).  This module deliberately does not import runtime-contracts:
    the provisioner wheel carries only stateport_release and execution_host.
    """
    from execution_host import daemon_contract  # noqa: PLC0415

    parameters: dict[str, Any] = {
        "workspaceId": DEFAULT_WORKSPACE_ID,
        "workspaceSpecDigest": _default_workspace_spec_digest(),
        "volumeName": f"stateport-workspace-{DEFAULT_WORKSPACE_ID}",
        "stopAfterIdle": True,
        "shell": ["/bin/sh"],
        "networkMode": "none",
        "cacheVolumes": [],
        "cpuQuotaPercent": 100,
        "diskMaxBytes": 256 * 1024 * 1024,
        "workSeconds": 0,
        "emitBytes": 0,
    }
    workload = {
        "kind": "workspace",
        "workloadId": DEFAULT_WORKSPACE_ID,
        "image": {"reference": DEFAULT_WORKSPACE_IMAGE},
        "parameters": parameters,
        "timeoutSeconds": 3600,
        "outputByteBound": 65536,
        "resources": {
            "memoryMaxBytes": 256 * 1024 * 1024,
            "pidsMax": 128,
        },
    }
    return daemon_contract.validate_workload_spec(workload)


def default_sealed_workspace_workload() -> dict[str, Any]:
    """Return the exact sealed workload bound by the installed default grant."""

    workload = _default_sealed_workload()
    if canonical_digest(workload) != DEFAULT_WORKSPACE_SPEC_DIGEST:
        raise ReleaseContractError(
            "default workspace sealed digest drifted from the signed contract"
        )
    return workload


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc_plus_days(days: int) -> str:
    value = datetime.now(timezone.utc) + timedelta(days=days)
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


# Deterministic grant timestamps bound into the plan (the plan digest must be
# stable across an interrupted rerun).  The provisioner re-writes the grant
# with real timestamps at apply time.
_DETERMINISTIC_GRANT_ISSUED_AT = "1970-01-01T00:00:00Z"
_DETERMINISTIC_GRANT_EXPIRES_AT = "2999-12-31T23:59:59Z"


def _default_grant_document(
    *,
    peer_uid: int,
    grant_id: str,
    image_reference: str,
    base_revision: str | None,
    budgets: Mapping[str, int],
    operations: Sequence[str],
    issued_at: str,
    expires_at: str,
    revocation_epoch: int,
) -> dict[str, Any]:
    """Render a schema-valid default execution-host authority grant.

    The grant binds the canonical default developer workspace: its workload
    id, kind, complete sealed spec digest, and digest-pinned image.  The
    proxy creates exactly this workload; every other workload requires an
    operator-issued per-workload grant extension.  Lifecycle operations on
    the bound workload (status/logs/start/stop/cancel/remove/exec) verify
    against this grant's workload scope.
    """
    from execution_host import daemon_contract  # noqa: PLC0415

    workload = default_sealed_workspace_workload()
    workload_id = str(workload["workloadId"])
    sealed_digest = daemon_contract.canonical_digest(workload)
    if sealed_digest != DEFAULT_WORKSPACE_SPEC_DIGEST:
        raise ReleaseContractError(
            "default workspace sealed digest drifted from the signed contract"
        )
    document = {
        "formatVersion": "stateport.execution-host-grant/v2",
        "grantId": grant_id,
        "peerUid": peer_uid,
        "operations": list(operations),
        "workloadIds": [workload_id],
        "workloadKinds": [str(workload["kind"])],
        "workloadSpecDigests": {workload_id: sealed_digest},
        "imageReference": image_reference,
        "baseRevision": base_revision,
        "issuedAt": issued_at,
        "expiresAt": expires_at,
        "revocationEpoch": revocation_epoch,
        "budgets": dict(budgets),
    }
    if set(operations) & {
        "probeDeploymentTarget",
        "applyDeployment",
        "updateDeployment",
        "observeDeployment",
        "collectDeploymentLogs",
        "restartDeployment",
        "removeDeploymentRuntime",
        "backupDeploymentData",
        "restoreDeploymentData",
        "purgeDeploymentData",
    }:
        document["deploymentScope"] = dict(_DEFAULT_DEPLOYMENT_SCOPE)
    return document
STABLE_EXECUTION_MODES = (
    "stable-host-daemon-client",
    "stable-host-daemon-bootstrap-only",
)
DEFAULT_NOLOGIN_SHELL = "/usr/sbin/nologin"
DEFAULT_RECEIPT_DIRECTORY = "/var/lib/stateport-provisioning/receipts"
ROOT_HELPER_PATH = "/usr/local/libexec/stateport-execution-host-provision"
ROOT_MODULE_ROOT = "/usr/local/lib/stateport/provisioning"
ROOT_COSIGN_PATH = "/usr/local/lib/stateport/tools/cosign"
ROOT_PUBLIC_KEY_PATH = "/etc/stateport/alpha-2026-08-cosign.pub"
ROOT_TRUST_KEY_ID = "stateport-alpha-private-2026-08"
ROOT_TRUST_KEY_FINGERPRINT = (
    "sha256:df24c1ccdcf1ecf72da6d8d81ae8b0ffaca8d399826091b107cc4d6905915ea5"
)
READINESS_TIMEOUT_SECONDS = 60.0
READINESS_POLL_SECONDS = 0.25
_ROOT_COMMAND_ENV = {
    "HOME": "/root",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "LOGNAME": "root",
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "USER": "root",
}
_TRUSTED_EXECUTABLES = {
    "env": "/usr/bin/env",
    "gpasswd": "/usr/bin/gpasswd",
    "groupadd": "/usr/sbin/groupadd",
    "groupdel": "/usr/sbin/groupdel",
    "journalctl": "/usr/bin/journalctl",
    "loginctl": "/usr/bin/loginctl",
    "podman": "/usr/bin/podman",
    "runuser": "/usr/sbin/runuser",
    "systemctl": "/usr/bin/systemctl",
    "systemd-tmpfiles": "/usr/bin/systemd-tmpfiles",
    "useradd": "/usr/sbin/useradd",
    "userdel": "/usr/sbin/userdel",
    "usermod": "/usr/sbin/usermod",
}
_RENAME_NOREPLACE = 1
_RENAME_EXCHANGE = 2


class ProvisioningRefusal(ReleaseContractError):
    """A typed, fail-closed provisioning refusal (pre-transaction)."""


class ProvisioningConverged(Exception):
    """An existing schema-valid receipt already proves this exact plan."""

    def __init__(self, receipt: Mapping[str, Any]) -> None:
        super().__init__("provisioning already converged")
        self.receipt = receipt


class StepFailed(ReleaseContractError):
    """One provisioning step failed its post-condition; triggers rollback."""

    def __init__(self, step: str, detail: str) -> None:
        super().__init__(f"{step}: {detail}")
        self.step = step
        self.detail = detail


# ---------------------------------------------------------------------------
# Execution and observation seams (injected only by simulations)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Completed:
    returncode: int
    stdout: str
    stderr: str


class Runner(Protocol):
    """Single injected subprocess seam; never a shell."""

    def run(self, argv: Sequence[str], *, timeout: int) -> Completed: ...


class SubprocessRunner:
    def run(self, argv: Sequence[str], *, timeout: int) -> Completed:
        if not argv or not os.path.isabs(str(argv[0])):
            raise ProvisioningRefusal("subprocess execution requires a trusted absolute executable")
        executable = Path(str(argv[0]))
        try:
            original_chain = (*reversed(executable.parents), executable)
            for position, component in enumerate(original_chain):
                observed = os.stat(component, follow_symlinks=False)
                if observed.st_uid != 0 or stat.S_IMODE(observed.st_mode) & 0o022:
                    raise ProvisioningRefusal(
                        f"subprocess executable path is not root-controlled: {component}"
                    )
                if position < len(original_chain) - 1 and not stat.S_ISDIR(
                    observed.st_mode
                ):
                    raise ProvisioningRefusal(
                        f"subprocess executable parent is not a directory: {component}"
                    )
            resolved = executable.resolve(strict=True)
            chain = (*reversed(resolved.parents), resolved)
            for position, component in enumerate(chain):
                observed = os.stat(component, follow_symlinks=False)
                if observed.st_uid != 0 or stat.S_IMODE(observed.st_mode) & 0o022:
                    raise ProvisioningRefusal(
                        f"subprocess executable path is not root-controlled: {component}"
                    )
                if position == len(chain) - 1:
                    if not stat.S_ISREG(observed.st_mode) or not os.access(
                        component, os.X_OK
                    ):
                        raise ProvisioningRefusal(
                            f"subprocess executable is not a regular executable: {resolved}"
                        )
                elif not stat.S_ISDIR(observed.st_mode):
                    raise ProvisioningRefusal(
                        f"subprocess executable parent is not a directory: {component}"
                    )
        except (OSError, RuntimeError) as exc:
            raise ProvisioningRefusal(
                f"subprocess executable cannot be resolved safely: {executable}: {exc}"
            ) from exc
        completed = subprocess.run(
            list(argv),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            stdin=subprocess.DEVNULL,
            cwd=Path("/"),
            env=dict(_ROOT_COMMAND_ENV),
        )
        return Completed(completed.returncode, completed.stdout, completed.stderr)


@dataclass(frozen=True)
class Account:
    name: str
    uid: int
    gid: int
    home: str
    shell: str


@dataclass(frozen=True)
class Group:
    name: str
    gid: int
    members: tuple[str, ...]


class Accounts(Protocol):
    def user(self, name: str) -> Account | None: ...

    def group(self, name: str) -> Group | None: ...

    def primary_group_users(self, group_name: str) -> tuple[str, ...]: ...


class SystemAccounts:
    def user(self, name: str) -> Account | None:
        try:
            record = pwd.getpwnam(name)
        except KeyError:
            return None
        return Account(name, record.pw_uid, record.pw_gid, record.pw_dir, record.pw_shell)

    def group(self, name: str) -> Group | None:
        try:
            record = grp.getgrnam(name)
        except KeyError:
            return None
        return Group(name, record.gr_gid, tuple(record.gr_mem))

    def primary_group_users(self, group_name: str) -> tuple[str, ...]:
        try:
            group = grp.getgrnam(group_name)
        except KeyError:
            return ()
        return tuple(sorted(record.pw_name for record in pwd.getpwall() if record.pw_gid == group.gr_gid))


@dataclass(frozen=True)
class HostLayout:
    """Path resolution root; ``/`` in production, a tmpdir in simulations."""

    root: Path = Path("/")

    def __post_init__(self) -> None:
        if not self.root.is_absolute():
            raise ProvisioningRefusal("host layout root must be absolute")

    def resolve(self, absolute: str) -> Path:
        pure = PurePosixPath(absolute)
        if not pure.is_absolute() or ".." in pure.parts:
            raise ProvisioningRefusal(f"unsafe absolute path in plan: {absolute!r}")
        if self.root == Path("/"):
            return Path(absolute)
        return self.root.joinpath(*pure.parts[1:])


# ---------------------------------------------------------------------------
# Plan rendering (pure, deterministic, inspectable)
# ---------------------------------------------------------------------------


def _contract_numeric_identity(contract: Mapping[str, Any], name: str, fallback: int) -> int:
    value = contract.get(name, fallback)
    if type(value) is not int or not 1 <= value <= 2**31 - 1:
        raise ReleaseContractError(f"execution contract {name} must be a positive numeric identity")
    return value


def _control_systemctl(*arguments: str) -> list[str]:
    """Run a systemctl --user command as the control identity (plan render)."""
    return [
        _TRUSTED_EXECUTABLES["runuser"],
        "-u",
        CONTROL_USER,
        "--",
        _TRUSTED_EXECUTABLES["env"],
        "-i",
        "HOME=" + CONTROL_HOME,
        "LANG=C.UTF-8",
        "LC_ALL=C.UTF-8",
        "LOGNAME=" + CONTROL_USER,
        "PATH=/usr/bin:/bin",
        "USER=" + CONTROL_USER,
        "XDG_CONFIG_HOME=" + CONTROL_CONFIG_DIR,
        "XDG_RUNTIME_DIR=/run/user/" + str(CONTROL_UID),
        "XDG_STATE_HOME=" + CONTROL_HOME + "/.local/state",
        _TRUSTED_EXECUTABLES["systemctl"],
        "--user",
        *arguments,
    ]


def _control_plane_images(
    target: Mapping[str, Any], images: Sequence[Mapping[str, Any]]
) -> list[dict[str, str]]:
    """The digest-pinned images the control-plane units reference."""
    image_by_id = {image.get("imageId"): image for image in images}
    result: list[dict[str, str]] = []
    services = target.get("services")
    if not isinstance(services, Sequence) or isinstance(services, (str, bytes)):
        raise ReleaseContractError("signed target has no service inventory")
    for service in sorted(services, key=lambda item: str(item.get("serviceId"))):
        if str(service.get("quadletOwner")) != CONTROL_USER:
            continue
        image = image_by_id.get(service.get("imageId"))
        if not isinstance(image, Mapping):
            raise ReleaseContractError(
                f"control service {service.get('serviceId')} has no signed image"
            )
        result.append(
            {
                "imageId": str(image["imageId"]),
                "reference": str(image["reference"]),
                "digest": str(image["digest"]),
            }
        )
    return result


def _user_argv(
    user_name: str,
    uid: int,
    home: str,
    shell: str,
    argv: Sequence[str],
    *,
    extra_environment: Mapping[str, str] | None = None,
) -> list[str]:
    runtime = f"/run/user/{uid}"
    environment = {
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={runtime}/bus",
        "HOME": home,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "LOGNAME": user_name,
        "PATH": "/usr/bin:/bin",
        "SHELL": shell,
        "USER": user_name,
        "XDG_CACHE_HOME": f"{home}/.cache",
        "XDG_CONFIG_HOME": f"{home}/.config",
        "XDG_DATA_HOME": f"{home}/.local/share",
        "XDG_RUNTIME_DIR": runtime,
        "XDG_STATE_HOME": f"{home}/.local/state",
        **dict(extra_environment or {}),
    }
    return [
        _TRUSTED_EXECUTABLES["runuser"],
        "-u",
        user_name,
        "--",
        _TRUSTED_EXECUTABLES["env"],
        "-i",
        *(f"{key}={value}" for key, value in sorted(environment.items())),
        *_trusted_argv(argv),
    ]


def render_provisioning_plan(
    target: Mapping[str, Any],
    images: Sequence[Mapping[str, Any]],
    *,
    verification_basis: str,
    client_user: str | None = None,
    client_uid: int | None = None,
    client_gid: int | None = None,
    control_plane_materialization: Mapping[str, bytes] | None = None,
    control_grant_digest: str | None = None,
    control_plane_environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Render the ordered, typed provisioning plan for the stable exec host.

    ``client_user``/``client_uid``/``client_gid`` optionally bind the real
    invoking user as the confined control-plane client (the operator CLI
    identity admitted through the identity file).  The signed contract's
    decorative ``stateport-control`` system account is ALWAYS provisioned:
    it is the peer identity the control-plane containers run as, and its user
    manager must exist with the socket group from birth so rootless
    ``keep-groups`` carries gid 65530 into the control containers.  The bound
    real client is additionally confined into the socket group and recorded
    in the identity file so the operator CLI remains admitted.

    ``control_plane_materialization`` carries the accepted control-plane
    unit/network files (web/api/worker) rendered by the installer's
    materialization ceremony from the same verified release.  The root
    transaction installs them into the ``stateport-control`` user's live
    Quadlet root and starts them under that user's systemd manager; this is
    the ONLY way the control-plane containers present peer uid 65531 with
    the socket group, which the daemon requires.
    """

    if target.get("executionHostMode") not in STABLE_EXECUTION_MODES:
        raise ReleaseContractError("target has no stable execution host to provision")
    contract = target["executionContract"]
    control_uid = _contract_numeric_identity(contract, "allowedClientUid", CONTROL_UID)
    control_gid = _contract_numeric_identity(contract, "allowedClientGid", CONTROL_GID)
    allowed_client = str(contract["allowedClientUser"])
    bound_client = None
    if client_user is not None:
        if (
            not isinstance(client_user, str)
            or _CLIENT_USER_NAME.fullmatch(client_user) is None
            or client_user in {"root", EXEC_USER, CONTROL_USER}
        ):
            raise ReleaseContractError(
                "control-plane client user is invalid; must be a safe account distinct "
                "from the execution identities"
            )
        if (
            type(client_uid) is not int
            or type(client_gid) is not int
            or client_uid < 1
            or client_gid < 1
        ):
            raise ReleaseContractError(
                "control-plane client numeric identity is invalid"
            )
        allowed_client = client_user
        bound_client = {
            "user": client_user,
            "uid": client_uid,
            "gid": client_gid,
        }
    exec_uid = _contract_numeric_identity(contract, "runtimeUid", EXEC_UID)
    exec_gid = _contract_numeric_identity(contract, "runtimeGid", EXEC_GID)
    socket_group_gid = _contract_numeric_identity(
        contract, "socketGroupGid", EXEC_GROUP_GID
    )
    exec_systemctl = lambda *arguments: _user_argv(  # noqa: E731
        EXEC_USER,
        exec_uid,
        EXEC_HOME,
        DEFAULT_NOLOGIN_SHELL,
        [_TRUSTED_EXECUTABLES["systemctl"], "--user", *arguments],
    )
    if control_uid != control_gid or exec_uid != exec_gid:
        raise ReleaseContractError("execution contract requires matching user and primary-group IDs")
    bundle = render_stable_host_quadlet_bundle(target, images)
    quadlet_files = sorted(path for path in bundle if path.startswith(f"host/{EXEC_USER}/"))
    if not quadlet_files:
        raise ReleaseContractError("stable host bundle has no execution-host units")
    image_by_id = {image.get("imageId"): image for image in images}
    image = image_by_id.get(contract["imageId"])
    if not isinstance(image, Mapping):
        raise ReleaseContractError("signed images lack the execution-host image")
    reference = str(image["reference"])
    digest = str(image["digest"])
    if not reference.endswith("@" + digest):
        raise ReleaseContractError("execution-host image reference is not digest-pinned")
    if str(contract["imageDigest"]) != digest:
        raise ReleaseContractError("execution contract and signed image digests diverge")
    socket_path = f"{contract['hostDirectory']}/{contract['socketName']}"
    writes: list[dict[str, Any]] = [
        {
            "path": TMPFILES_PATH,
            "content": (
                f"d {PurePosixPath(contract['hostDirectory']).parent} 0755 root root -\n"
                f"d {contract['hostDirectory']} {contract['directoryMode']} "
                f"{contract['directoryOwner']} {contract['directoryGroup']} -\n"
            ),
            "contentDigest": canonical_digest(
                f"d {PurePosixPath(contract['hostDirectory']).parent} 0755 root root -\n"
                f"d {contract['hostDirectory']} {contract['directoryMode']} "
                f"{contract['directoryOwner']} {contract['directoryGroup']} -\n"
            ),
            "mode": "0644",
            "owner": "root:root",
        }
    ]
    for relative in quadlet_files:
        content = bundle[relative].decode("utf-8")
        writes.append(
            {
                "path": f"{QUADLET_DIR}/{PurePosixPath(relative).name}",
                "content": content,
                "contentDigest": canonical_digest(content),
                "mode": "0640",
                "owner": f"{EXEC_USER}:{EXEC_USER}",
            }
        )
    control_unit_files: list[str] = []
    if control_plane_materialization:
        # The accepted control-plane units (web/api/worker + their networks)
        # are installed into the control user's live Quadlet root. The
        # materialization keys are "accepted/<signed_hex>/<owner>/<relative>"
        # and every file here belongs to the stateport-control owner.
        for relative in sorted(control_plane_materialization):
            content = control_plane_materialization[relative]
            parts = PurePosixPath(relative).parts
            if len(parts) < 4 or parts[0] != "accepted" or parts[2] != CONTROL_USER:
                raise ReleaseContractError(
                    "control-plane materialization carries a non-control artifact path"
                )
            file_name = "/".join(parts[3:])
            writes.append(
                {
                    "path": f"{CONTROL_QUADLET_DIR}/{file_name}",
                    "content": content.decode("utf-8"),
                    "contentDigest": canonical_digest(content.decode("utf-8")),
                    "mode": "0640",
                    "owner": f"{CONTROL_USER}:{CONTROL_USER}",
                }
            )
            control_unit_files.append(file_name)
    if bound_client is not None:
        # The confined client identity travels to the confined daemon through a
        # root-owned file inside the confined socket directory.  The daemon
        # container cannot resolve the host group database, so the provisioning
        # transaction itself proves which host identity it admitted.
        client_identity_content = f"{client_uid}:{client_gid}\n"
        writes.append(
            {
                "path": f"{contract['hostDirectory']}/{CLIENT_IDENTITY_FILE}",
                "content": client_identity_content,
                "contentDigest": canonical_digest(client_identity_content),
                "mode": "0640",
                "owner": f"root:{EXEC_GROUP}",
            }
        )
    directories = [
        {"path": EXEC_HOME, "mode": "0750", "owner": f"{EXEC_USER}:{EXEC_USER}"},
        {"path": EXEC_CONFIG_DIR, "mode": "0700", "owner": f"{EXEC_USER}:{EXEC_USER}"},
        {
            "path": str(PurePosixPath(QUADLET_DIR).parent),
            "mode": "0700",
            "owner": f"{EXEC_USER}:{EXEC_USER}",
        },
        {"path": QUADLET_DIR, "mode": "0700", "owner": f"{EXEC_USER}:{EXEC_USER}"},
        {
            "path": f"{EXEC_CONFIG_DIR}/systemd",
            "mode": "0700",
            "owner": f"{EXEC_USER}:{EXEC_USER}",
        },
        {
            "path": f"{EXEC_CONFIG_DIR}/systemd/user",
            "mode": "0700",
            "owner": f"{EXEC_USER}:{EXEC_USER}",
        },
        {
            "path": f"{EXEC_CONFIG_DIR}/systemd/user/sockets.target.wants",
            "mode": "0700",
            "owner": f"{EXEC_USER}:{EXEC_USER}",
        },
        {"path": SERVICE_STATE_ROOT, "mode": "0700", "owner": f"{EXEC_USER}:{EXEC_USER}"},
        {"path": STATE_DIR, "mode": "0700", "owner": f"{EXEC_USER}:{EXEC_USER}"},
        {"path": GRANTS_DIR, "mode": "0700", "owner": f"{EXEC_USER}:{EXEC_USER}"},
        {"path": CONTROL_HOME, "mode": "0750", "owner": f"{CONTROL_USER}:{CONTROL_USER}"},
        {"path": CONTROL_CONFIG_DIR, "mode": "0700", "owner": f"{CONTROL_USER}:{CONTROL_USER}"},
        {
            "path": str(PurePosixPath(CONTROL_QUADLET_DIR).parent),
            "mode": "0700",
            "owner": f"{CONTROL_USER}:{CONTROL_USER}",
        },
        {"path": CONTROL_QUADLET_DIR, "mode": "0700", "owner": f"{CONTROL_USER}:{CONTROL_USER}"},
        {
            "path": f"{CONTROL_CONFIG_DIR}/systemd",
            "mode": "0700",
            "owner": f"{CONTROL_USER}:{CONTROL_USER}",
        },
        {
            "path": CONTROL_SYSTEMD_USER_DIR,
            "mode": "0700",
            "owner": f"{CONTROL_USER}:{CONTROL_USER}",
        },
        {
            "path": f"{CONTROL_SYSTEMD_USER_DIR}/sockets.target.wants",
            "mode": "0700",
            "owner": f"{CONTROL_USER}:{CONTROL_USER}",
        },
    ]
    template_mounts = [
        mount
        for service in target.get("services", ())
        for mount in service.get("readOnlyHostMounts", ())
    ]
    if template_mounts:
        expected_template_mount = {
            "name": "template-sources",
            "hostPath": TEMPLATE_IMPORT_ROOT,
            "mountPath": "/imports",
            "purpose": "template-sources",
            "sourceOwner": "installer-client",
            "sourceGroup": EXEC_GROUP,
            "mode": "ro",
            "environmentVariable": "STATEPORT_REPOSITORY_ROOTS",
        }
        if template_mounts != [expected_template_mount]:
            raise ReleaseContractError("installed template-source mount contract is malformed")
        directories.extend(
            [
                {"path": TEMPLATE_IMPORT_PARENT, "mode": "0755", "owner": "root:root"},
                {
                    "path": TEMPLATE_IMPORT_ROOT,
                    "mode": "0750",
                    "owner": f"{allowed_client}:{EXEC_GROUP}",
                },
            ]
        )
    provider_services = [service for service in target.get("services", ()) if "providerHome" in service]
    if provider_services:
        if len(provider_services) != 1 or (
            provider_services[0].get("serviceId") != "stateport-web"
            or provider_services[0].get("quadletOwner") != CONTROL_USER
            or provider_services[0].get("runAsUser") != 65532
            or provider_services[0]["providerHome"] != PROVIDER_HOME_CONTRACT
        ):
            raise ReleaseContractError("installed provider home contract is malformed")
        directories.extend([
            {"path": "/var/lib/stateport-control/provider-auth", "mode": "0700", "owner": f"{CONTROL_USER}:{CONTROL_USER}"},
            {"path": PROVIDER_HOME_CONTRACT["hostPath"], "mode": "0700", "owner": f"{CONTROL_USER}:{CONTROL_USER}"},
        ])
    steps: list[dict[str, Any]] = [
        {
            "step": "verify-rootless-supplementary-group-contract",
            "commands": [],
        },
        {
            "step": "ensure-execution-control-group",
            "commands": [
                [
                    _TRUSTED_EXECUTABLES["groupadd"],
                    "--system",
                    "--gid",
                    str(socket_group_gid),
                    EXEC_GROUP,
                ]
            ],
        },
        {
            "step": "ensure-stateport-control-user",
            "commands": [
                [
                    _TRUSTED_EXECUTABLES["groupadd"],
                    "--system",
                    "--gid",
                    str(control_gid),
                    CONTROL_USER,
                ],
                [
                    _TRUSTED_EXECUTABLES["useradd"],
                    "--system",
                    "--uid",
                    str(control_uid),
                    "--gid",
                    str(control_gid),
                    "--home-dir",
                    f"/var/lib/{CONTROL_USER}",
                    "--create-home",
                    "--shell",
                    DEFAULT_NOLOGIN_SHELL,
                    CONTROL_USER,
                ],
            ],
        },
        {
            "step": "ensure-stateport-exec-user",
            "commands": [
                [
                    _TRUSTED_EXECUTABLES["groupadd"],
                    "--system",
                    "--gid",
                    str(exec_gid),
                    EXEC_USER,
                ],
                [
                    _TRUSTED_EXECUTABLES["useradd"],
                    "--system",
                    "--uid",
                    str(exec_uid),
                    "--gid",
                    str(exec_gid),
                    "--home-dir",
                    EXEC_HOME,
                    "--create-home",
                    "--shell",
                    DEFAULT_NOLOGIN_SHELL,
                    EXEC_USER,
                ]
            ],
        },
        {
            "step": "confine-execution-user-group",
            "commands": [
                [
                    _TRUSTED_EXECUTABLES["usermod"],
                    "--append",
                    "--groups",
                    EXEC_GROUP,
                    EXEC_USER,
                ]
            ],
        },
        {
            "step": "confine-control-plane-client",
            "commands": [
                [
                    _TRUSTED_EXECUTABLES["usermod"],
                    "--append",
                    "--groups",
                    EXEC_GROUP,
                    allowed_client,
                ]
            ],
        },
        {
            "step": "establish-subordinate-mappings",
            "subordinateIds": {
                "user": EXEC_USER,
                "rangeSize": SUBID_RANGE_SIZE,
                "files": [SUBUID_PATH, SUBGID_PATH],
            },
            "commands": [],
        },
        {
            "step": "create-host-directories",
            "directories": [entry["path"] for entry in directories],
            "commands": [],
        },
        {
            "step": "write-confined-socket-tmpfiles",
            "writes": [TMPFILES_PATH],
            "commands": [
                [_TRUSTED_EXECUTABLES["systemd-tmpfiles"], "--create", TMPFILES_PATH]
            ],
        },
        {
            "step": "enable-control-user-linger",
            "commands": [
                [_TRUSTED_EXECUTABLES["loginctl"], "enable-linger", CONTROL_USER],
                [
                    _TRUSTED_EXECUTABLES["systemctl"],
                    "start",
                    f"user@{control_uid}.service",
                ],
            ],
        },
        {
            "step": "enable-exec-user-linger",
            "commands": [
                [_TRUSTED_EXECUTABLES["loginctl"], "enable-linger", EXEC_USER],
                [
                    _TRUSTED_EXECUTABLES["systemctl"],
                    "start",
                    f"user@{exec_uid}.service",
                ],
                exec_systemctl("show-environment"),
            ],
        },
        {
            "step": "install-stable-host-quadlets",
            "writes": [write["path"] for write in writes if write["path"] != TMPFILES_PATH],
            "commands": [
                exec_systemctl("daemon-reload")
            ],
        },
        {
            "step": "provision-execution-host-grant",
            "grant": _default_grant_document(
                peer_uid=control_uid,
                grant_id=DEFAULT_GRANT_ID,
                image_reference=DEFAULT_WORKSPACE_IMAGE,
                base_revision=None,
                budgets=contract.get("defaultBudgets") or _DEFAULT_GRANT_BUDGETS,
                operations=_DEFAULT_GRANT_OPERATIONS,
                # Deterministic plan timestamps: the plan digest must be stable
                # across an interrupted rerun.  The provisioner writes the
                # grant with real timestamps at apply time; the receipt carries
                # the actual digest.
                issued_at=_DETERMINISTIC_GRANT_ISSUED_AT,
                expires_at=_DETERMINISTIC_GRANT_EXPIRES_AT,
                revocation_epoch=0,
            ),
            "commands": [],
        },
        {
            "step": "install-control-plane-units",
            "writes": [write["path"] for write in writes if write["path"].startswith(CONTROL_QUADLET_DIR + "/")],
            "commands": [
                _control_systemctl("daemon-reload")
            ],
        },
        {
            "step": "pull-control-plane-images",
            "images": _control_plane_images(target, images),
            "commands": [],
        },
        {
            "step": "pull-execution-host-image",
            "image": {"imageId": str(image["imageId"]), "reference": reference, "digest": digest},
            "commands": [],
        },
        {
            "step": "start-exec-user-engine-socket",
            "commands": [
                exec_systemctl("enable", "--now", ENGINE_SOCKET_UNIT)
            ],
        },
        {
            "step": "start-execution-host-daemon",
            "commands": [
                exec_systemctl("start", DAEMON_UNIT)
            ],
        },
        {
            "step": "verify-protocol-health",
            "health": {
                "kind": "describeCapabilities",
                "socketPath": socket_path,
                "peerUsers": [EXEC_USER, allowed_client],
            },
            "commands": [],
        },
        {
            "step": "start-control-plane-units",
            "units": [
                name
                for name in control_unit_files
                if name.endswith((".container", ".network"))
            ],
            "commands": [],
        },
        {
            "step": "record-provisioning-receipt",
            "commands": [],
        },
    ]
    # The decorative control account is ALWAYS provisioned: it is the peer
    # identity the control-plane containers run as.  A bound real client
    # (the operator CLI) is additionally confined and identity-filed, never a
    # replacement for the control account.
    if bound_client is not None:
        confine = next(
            (step for step in steps if step["step"] == "confine-control-plane-client"),
            None,
        )
        if confine is not None:
            confine["commands"] = [
                [
                    _TRUSTED_EXECUTABLES["usermod"],
                    "--append",
                    "--groups",
                    EXEC_GROUP,
                    allowed_client,
                ]
            ]
    plan: dict[str, Any] = {
        "schema": PLAN_SCHEMA,
        "releaseId": str(target["releaseId"]),
        "targetId": str(target["targetId"]),
        "topologyDigest": str(target["topologyDigest"]),
        "contractVersion": int(contract["contractVersion"]),
        "verificationBasis": verification_basis,
        "evidenceClass": "plan-rendered",
        "executionUser": EXEC_USER,
        "executionUid": exec_uid,
        "executionGid": exec_gid,
        "controlUser": CONTROL_USER,
        "controlUid": control_uid,
        "controlGid": control_gid,
        "executionControlGroup": EXEC_GROUP,
        "executionControlGroupGid": socket_group_gid,
        "allowedClientUser": allowed_client,
        "controlClient": bound_client,
        "controlGrantDigest": control_grant_digest,
        "controlPlaneEnvironment": dict(control_plane_environment or {}),
        "controlPlaneMaterialization": (
            {
                str(relative): __import__("base64").b64encode(content).decode("ascii")
                for relative, content in sorted(control_plane_materialization.items())
            }
            if control_plane_materialization
            else None
        ),
        "homeDirectory": EXEC_HOME,
        "stateDirectory": STATE_DIR,
        "grantsDirectory": GRANTS_DIR,
        "quadletDirectory": QUADLET_DIR,
        "socketDirectory": contract["hostDirectory"],
        "socketDirectoryMode": contract["directoryMode"],
        "socketDirectoryOwner": contract["directoryOwner"],
        "socketDirectoryGroup": contract["directoryGroup"],
        "socketName": contract["socketName"],
        "socketPath": socket_path,
        "socketMode": contract["socketMode"],
        "rootlessSupplementaryGroupContract": {
            "quadletDirective": "PodmanArgs=--group-add=keep-groups",
            "requiredOciRuntime": "crun",
            "runtimePath": CONFINED_GROUP_OCI_RUNTIME_PATH,
            "runtimeVersion": CONFINED_GROUP_OCI_RUNTIME_VERSION,
            "runtimeSha256": CONFINED_GROUP_OCI_RUNTIME_SHA256,
            "userNamespace": "keep-id",
            "socketGroup": EXEC_GROUP,
            "status": "supported-by-pinned-runtime-contract",
            "detail": (
                "the digest-pinned static crun runtime implements keep-groups; keep-id preserves "
                "the execution UID/GID while the setgid host directory preserves confined access"
            ),
        },
        "image": {"imageId": str(image["imageId"]), "reference": reference, "digest": digest},
        "subordinateIds": {
            "user": EXEC_USER,
            "uid": exec_uid,
            "gid": exec_gid,
            "rangeSize": SUBID_RANGE_SIZE,
            "files": [SUBUID_PATH, SUBGID_PATH],
        },
        "directories": directories,
        "writes": writes,
        "steps": steps,
        "rollback": [
            {"action": "disable-unit", "asUser": EXEC_USER, "unit": DAEMON_UNIT},
            {"action": "disable-unit", "asUser": EXEC_USER, "unit": ENGINE_SOCKET_UNIT},
            {
                "action": "stop-user-manager",
                "unit": f"user@{exec_uid}.service",
                "guard": "only-if-started-by-this-transaction",
            },
            {
                "action": "stop-user-manager",
                "unit": f"user@{control_uid}.service",
                "guard": "only-if-started-by-this-transaction",
            },
            {"action": "disable-linger", "user": EXEC_USER},
            {"action": "disable-linger", "user": CONTROL_USER},
            {
                "action": "restore-user-manager",
                "unit": f"user@{exec_uid}.service",
                "guard": "only-if-active-before-this-transaction-and-linger-was-absent",
            },
            {
                "action": "restore-user-manager",
                "unit": f"user@{control_uid}.service",
                "guard": "only-if-active-before-this-transaction-and-linger-was-absent",
            },
            {
                "action": "preserve",
                "detail": "the digest-pinned execution-host image is preserved",
            },
            {
                "action": "remove-files",
                "paths": [write["path"] for write in writes],
                "guard": "only-when-content-still-matches-this-transaction",
            },
            {
                "action": "restore-or-remove-directories",
                "paths": [entry["path"] for entry in directories],
                "guard": "restore-prior-metadata-or-remove-only-empty-transaction-directories",
            },
            {
                "action": "remove-subordinate-id-mappings",
                "user": EXEC_USER,
                "files": [SUBUID_PATH, SUBGID_PATH],
                "guard": "only-lines-added-by-this-transaction",
            },
            {"action": "unconfine-client", "user": CONTROL_USER, "group": EXEC_GROUP},
            {"action": "unconfine-client", "user": EXEC_USER, "group": EXEC_GROUP},
            {"action": "delete-user", "user": EXEC_USER, "guard": "only-if-created-by-this-transaction"},
            {"action": "delete-group", "group": EXEC_USER, "guard": "only-if-created-by-this-transaction"},
            {"action": "delete-user", "user": CONTROL_USER, "guard": "only-if-created-by-this-transaction"},
            {"action": "delete-group", "group": CONTROL_USER, "guard": "only-if-created-by-this-transaction"},
            {"action": "delete-group", "group": EXEC_GROUP, "guard": "only-if-created-by-this-transaction"},
            {
                "action": "preserve",
                "detail": (
                    "the daemon state directory is preserved unless this transaction created it empty"
                ),
            },
        ],
    }
    if bound_client is not None:
        # The bound real client is unconfined; the control account rollback
        # entries stay because the decorative account is always provisioned.
        plan["rollback"] = [
            (
                {
                    **entry,
                    "user": client_user,
                    "group": EXEC_GROUP,
                }
                if entry.get("action") == "unconfine-client" and entry.get("user") == CONTROL_USER
                else entry
            )
            for entry in plan["rollback"]
        ]
    plan["planDigest"] = canonical_digest(
        {
            key: value
            for key, value in plan.items()
            if key not in {"planDigest", "verificationBasis", "evidenceClass"}
        }
    )
    return plan


# ---------------------------------------------------------------------------
# Filesystem primitives: no-follow, descriptor-relative, atomic, observed
# ---------------------------------------------------------------------------


def resolve_client_identity() -> tuple[str, int, int] | None:
    """Resolve the invoking user's exact (name, uid, gid) for client binding.

    The rootless installer (non-root ``os.getuid``) is its own client.  The
    root-owned helper runs under ``sudo`` and therefore names the client via
    ``SUDO_USER``.  ``STATEPORT_CONTROL_CLIENT_USER`` overrides both for
    explicit, testable binding.  Returns ``None`` only when there is no
    resolvable invoking user (structural/simulated use); callers that require
    a real client must refuse on ``None``.
    """
    explicit = os.environ.get("STATEPORT_CONTROL_CLIENT_USER")
    if explicit is not None:
        try:
            record = pwd.getpwnam(explicit)
        except KeyError as exc:
            raise ProvisioningRefusal(
                f"the explicit control-plane client user is not resolvable: {explicit!r}"
            ) from exc
        return record.pw_name, record.pw_uid, record.pw_gid
    uid = os.getuid()
    if uid == 0:
        sudo_user = os.environ.get("SUDO_USER")
        if not sudo_user:
            return None
        try:
            record = pwd.getpwnam(sudo_user)
        except KeyError as exc:
            raise ProvisioningRefusal(
                f"the invoking sudo user is not resolvable: {sudo_user!r}"
            ) from exc
        return record.pw_name, record.pw_uid, record.pw_gid
    try:
        record = pwd.getpwuid(uid)
    except KeyError as exc:
        raise ProvisioningRefusal(f"the invoking uid is not resolvable: {uid}") from exc
    return record.pw_name, record.pw_uid, record.pw_gid


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _stat_fingerprint(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
        value.st_nlink,
    )


def _journal_stat(value: os.stat_result) -> dict[str, int]:
    return {
        "dev": value.st_dev,
        "ino": value.st_ino,
        "mode": stat.S_IMODE(value.st_mode),
        "uid": value.st_uid,
        "gid": value.st_gid,
    }


def _host_parts(absolute: str) -> tuple[str, ...]:
    pure = PurePosixPath(absolute)
    if (
        not pure.is_absolute()
        or ".." in pure.parts
        or str(pure) != absolute
        or any(part in {"", "."} for part in pure.parts[1:])
    ):
        raise ProvisioningRefusal(f"unsafe or non-canonical host path: {absolute!r}")
    return tuple(pure.parts[1:])


@dataclass
class _DirectoryChain:
    """Open directory descriptors from the trusted layout root to one leaf."""

    absolute: str
    fds: list[int]
    names: list[str]

    def verify(self, *, step: str) -> None:
        for position, name in enumerate(self.names):
            try:
                namespace_stat = os.stat(
                    name, dir_fd=self.fds[position], follow_symlinks=False
                )
            except OSError as exc:
                raise StepFailed(
                    step, f"directory component left the anchored namespace: {self.absolute}"
                ) from exc
            opened_stat = os.fstat(self.fds[position + 1])
            if (
                stat.S_ISLNK(namespace_stat.st_mode)
                or not stat.S_ISDIR(namespace_stat.st_mode)
                or not _same_inode(namespace_stat, opened_stat)
            ):
                raise StepFailed(
                    step, f"directory component was swapped during provisioning: {self.absolute}"
                )

    def close(self) -> None:
        for descriptor in reversed(self.fds):
            os.close(descriptor)


@contextmanager
def _open_directory_chain(
    layout: HostLayout,
    absolute: str,
    *,
    step: str,
    create: bool = False,
    created: Callable[[str, os.stat_result], None] | None = None,
) -> Iterator[_DirectoryChain]:
    parts = _host_parts(absolute)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        root_fd = os.open(layout.root, flags)
    except OSError as exc:
        raise StepFailed(step, f"trusted filesystem root is unavailable: {layout.root}") from exc
    chain = _DirectoryChain(absolute=absolute, fds=[root_fd], names=[])
    traversed: list[str] = []
    try:
        if not stat.S_ISDIR(os.fstat(root_fd).st_mode):
            raise StepFailed(step, f"trusted filesystem root is not a directory: {layout.root}")
        for name in parts:
            parent_fd = chain.fds[-1]
            made = False
            try:
                child_fd = os.open(name, flags, dir_fd=parent_fd)
            except FileNotFoundError:
                if not create:
                    raise StepFailed(step, f"directory is absent: /{'/'.join((*traversed, name))}")
                try:
                    os.mkdir(name, 0o700, dir_fd=parent_fd)
                    os.fsync(parent_fd)
                    made = True
                except FileExistsError:
                    # A racing creator is accepted only if the no-follow open below
                    # proves that it created a real directory.
                    pass
                try:
                    child_fd = os.open(name, flags, dir_fd=parent_fd)
                except OSError as exc:
                    raise StepFailed(
                        step,
                        f"new directory component is unsafe: /{'/'.join((*traversed, name))}",
                    ) from exc
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise StepFailed(
                        step,
                        f"path component is not a real directory: /{'/'.join((*traversed, name))}",
                    ) from exc
                raise
            chain.names.append(name)
            chain.fds.append(child_fd)
            traversed.append(name)
            opened = os.fstat(child_fd)
            if not stat.S_ISDIR(opened.st_mode):
                raise StepFailed(step, f"path component is not a directory: /{'/'.join(traversed)}")
            chain.verify(step=step)
            if made and created is not None:
                created("/" + "/".join(traversed), opened)
        chain.verify(step=step)
        yield chain
    finally:
        chain.close()


def _renameat2(dir_fd: int, source: str, destination: str, flags: int) -> None:
    """Linux renameat2 used for no-replace publication and inode CAS exchange."""

    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise OSError(errno.ENOSYS, "renameat2 is unavailable")
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        dir_fd,
        os.fsencode(source),
        dir_fd,
        os.fsencode(destination),
        flags,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), destination)


def _read_regular_file(
    layout: HostLayout,
    absolute: str,
    *,
    step: str,
    absent_ok: bool = False,
) -> tuple[bytes, os.stat_result | None]:
    parts = _host_parts(absolute)
    if not parts:
        raise StepFailed(step, "the filesystem root cannot be read as a regular file")
    parent = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
    name = parts[-1]
    with _open_directory_chain(layout, parent, step=step) as chain:
        try:
            namespace_stat = os.stat(name, dir_fd=chain.fds[-1], follow_symlinks=False)
        except FileNotFoundError:
            if absent_ok:
                return b"", None
            raise StepFailed(step, f"regular file is absent: {absolute}") from None
        if stat.S_ISLNK(namespace_stat.st_mode) or not stat.S_ISREG(namespace_stat.st_mode):
            raise StepFailed(step, f"path is not a regular file: {absolute}")
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=chain.fds[-1],
        )
        try:
            opened_stat = os.fstat(descriptor)
            if not _same_inode(namespace_stat, opened_stat):
                raise StepFailed(step, f"regular file was swapped while opening: {absolute}")
            with os.fdopen(os.dup(descriptor), "rb") as handle:
                content = handle.read()
            if _stat_fingerprint(os.fstat(descriptor)) != _stat_fingerprint(opened_stat):
                raise StepFailed(step, f"regular file changed while reading: {absolute}")
            after = os.stat(name, dir_fd=chain.fds[-1], follow_symlinks=False)
            if _stat_fingerprint(after) != _stat_fingerprint(opened_stat):
                raise StepFailed(step, f"regular file changed in the namespace: {absolute}")
            chain.verify(step=step)
            return content, opened_stat
        finally:
            os.close(descriptor)


def _observe_directory(
    layout: HostLayout, absolute: str, *, step: str, description: str
) -> os.stat_result:
    try:
        with _open_directory_chain(layout, absolute, step=step) as chain:
            observed = os.fstat(chain.fds[-1])
            chain.verify(step=step)
            return observed
    except StepFailed as exc:
        raise StepFailed(step, f"{description} is absent or unsafe: {absolute}: {exc.detail}") from exc


def _ensure_directory_converged(
    ctx: "_Apply",
    path: str,
    *,
    mode: int,
    uid: int,
    gid: int,
    step: str,
    refuse_existing_mismatch: bool = False,
) -> bool:
    """Create missing components (rejecting symlink components), then apply
    and OBSERVE exact numeric ownership and mode on the leaf.

    Returns True when this call changed anything (creation, ownership, mode).
    """

    created_paths: list[str] = []

    def record_created(created_path: str, observed: os.stat_result) -> None:
        created_paths.append(created_path)
        ctx.journal.append(
            {
                "kind": "directory-created",
                "path": created_path,
                **_journal_stat(observed),
            }
        )

    with _open_directory_chain(
        ctx.layout, path, step=step, create=True, created=record_created
    ) as chain:
        descriptor = chain.fds[-1]
        before = os.fstat(descriptor)
        owner_changed = before.st_uid != uid or before.st_gid != gid
        mode_changed = stat.S_IMODE(before.st_mode) != mode
        if refuse_existing_mismatch and path not in created_paths and (owner_changed or mode_changed):
            raise StepFailed(step, "provider-owned directory ownership or mode differs; refusing to take it over")
        metadata_entry: dict[str, Any] | None = None
        if (owner_changed or mode_changed) and path not in created_paths:
            metadata_entry = {
                "kind": "directory-metadata",
                "path": path,
                **_journal_stat(before),
                "appliedUid": uid,
                "appliedGid": gid,
                "appliedMode": mode,
                "ownerChanged": False,
                "modeChanged": False,
            }
            ctx.journal.append(metadata_entry)
        current = os.fstat(descriptor)
        if _stat_fingerprint(current) != _stat_fingerprint(before):
            raise StepFailed(step, f"directory metadata changed before apply: {path}")
        if owner_changed:
            os.fchown(descriptor, uid, gid)
            if metadata_entry is not None:
                metadata_entry["ownerChanged"] = True
        chain.verify(step=step)
        current = os.fstat(descriptor)
        if (
            current.st_uid != (uid if owner_changed else before.st_uid)
            or current.st_gid != (gid if owner_changed else before.st_gid)
            or stat.S_IMODE(current.st_mode) != stat.S_IMODE(before.st_mode)
        ):
            raise StepFailed(step, f"directory metadata changed during apply: {path}")
        if mode_changed:
            os.fchmod(descriptor, mode)
            if metadata_entry is not None:
                metadata_entry["modeChanged"] = True
        observed = os.fstat(descriptor)
        chain.verify(step=step)
        if (
            observed.st_uid != uid
            or observed.st_gid != gid
            or stat.S_IMODE(observed.st_mode) != mode
        ):
            raise StepFailed(
                step,
                f"ownership/mode observation failed for {path}: uid={observed.st_uid} "
                f"gid={observed.st_gid} mode={oct(stat.S_IMODE(observed.st_mode))}",
            )
        return bool(created_paths or owner_changed or mode_changed)


def _write_file_converged(
    ctx: "_Apply",
    path: str,
    content: bytes,
    *,
    mode: int,
    uid: int,
    gid: int,
    step: str,
    journal_kind: str = "file-written",
    journal_extra: Mapping[str, Any] | None = None,
) -> bool:
    """Atomically install exact content, ownership, and mode; observe after.

    Returns True when bytes were written (a journal entry was recorded).
    """

    parts = _host_parts(path)
    if not parts:
        raise StepFailed(step, "the filesystem root cannot be a write destination")
    parent = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
    name = parts[-1]
    prior: bytes | None = None
    prior_stat: os.stat_result | None = None
    prior_fd = -1
    temp_name = ""
    preserve_temp = False
    publication_observed = False
    journal_entry: dict[str, Any] | None = None
    with _open_directory_chain(ctx.layout, parent, step=step) as chain:
        dir_fd = chain.fds[-1]
        try:
            destination = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            if stat.S_ISLNK(destination.st_mode):
                raise StepFailed(step, f"write destination is a symlink: {path}")
            if not stat.S_ISREG(destination.st_mode):
                raise StepFailed(step, f"write destination is not a regular file: {path}")
            prior_fd = os.open(
                name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd
            )
            opened = os.fstat(prior_fd)
            if _stat_fingerprint(opened) != _stat_fingerprint(destination):
                raise StepFailed(step, f"write destination was swapped while opening: {path}")
            with os.fdopen(os.dup(prior_fd), "rb") as handle:
                prior = handle.read()
            if _stat_fingerprint(os.fstat(prior_fd)) != _stat_fingerprint(opened):
                raise StepFailed(step, f"write destination changed while reading: {path}")
            prior_stat = opened
            os.close(prior_fd)
            prior_fd = -1
            if (
                prior == content
                and stat.S_IMODE(opened.st_mode) == mode
                and opened.st_uid == uid
                and opened.st_gid == gid
            ):
                chain.verify(step=step)
                return False
        except FileNotFoundError:
            prior = None
        temp_name = f".{name}.provision-{os.getpid()}-{secrets.token_hex(8)}"
        temp_fd = os.open(
            temp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=dir_fd,
        )
        try:
            with os.fdopen(temp_fd, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
                os.fchown(handle.fileno(), uid, gid)
                os.fchmod(handle.fileno(), mode)
                os.fsync(handle.fileno())
            temp_stat = os.stat(temp_name, dir_fd=dir_fd, follow_symlinks=False)
            journal_entry = {
                "kind": journal_kind,
                "path": path,
                "content": content,
                "prior": prior,
                "priorStat": None if prior_stat is None else _journal_stat(prior_stat),
                "appliedStat": _journal_stat(temp_stat),
                "published": False,
                **dict(journal_extra or {}),
            }
            ctx.journal.append(journal_entry)
            chain.verify(step=step)
            if prior_stat is None:
                try:
                    os.link(
                        temp_name,
                        name,
                        src_dir_fd=dir_fd,
                        dst_dir_fd=dir_fd,
                        follow_symlinks=False,
                    )
                except FileExistsError as exc:
                    raise StepFailed(
                        step, f"write destination appeared during create-only publish: {path}"
                    ) from exc
                journal_entry["published"] = True
                os.unlink(temp_name, dir_fd=dir_fd)
                temp_name = ""
            else:
                current = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                guard_fd = os.open(
                    name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd
                )
                guard_stat = os.fstat(guard_fd)
                if _stat_fingerprint(current) != _stat_fingerprint(
                    prior_stat
                ) or _stat_fingerprint(guard_stat) != _stat_fingerprint(prior_stat):
                    os.close(guard_fd)
                    raise StepFailed(step, f"write destination changed before CAS publish: {path}")
                try:
                    _renameat2(dir_fd, temp_name, name, _RENAME_EXCHANGE)
                except OSError as exc:
                    os.close(guard_fd)
                    raise StepFailed(step, f"atomic exchange is unavailable for {path}: {exc}") from exc
                exchanged_prior = os.stat(temp_name, dir_fd=dir_fd, follow_symlinks=False)
                installed = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                exchanged_fd = os.open(
                    temp_name,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=dir_fd,
                )
                with os.fdopen(exchanged_fd, "rb") as exchanged_handle:
                    exchanged_content = exchanged_handle.read()
                prior_matches = (
                    _same_inode(exchanged_prior, prior_stat)
                    and exchanged_content == prior
                    and stat.S_IMODE(exchanged_prior.st_mode)
                    == stat.S_IMODE(prior_stat.st_mode)
                    and exchanged_prior.st_uid == prior_stat.st_uid
                    and exchanged_prior.st_gid == prior_stat.st_gid
                )
                installed_matches = _same_inode(installed, temp_stat)
                try:
                    latest_installed = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                except OSError:
                    installed_matches = False
                else:
                    installed_matches = installed_matches and _stat_fingerprint(
                        latest_installed
                    ) == _stat_fingerprint(installed)
                if not (prior_matches and installed_matches):
                    if installed_matches:
                        # Our inode still owns the destination, so exchanging back
                        # restores the competing bytes without overwriting them.
                        try:
                            _renameat2(dir_fd, temp_name, name, _RENAME_EXCHANGE)
                        except OSError as restore_exc:
                            os.close(guard_fd)
                            raise StepFailed(
                                step,
                                f"destination CAS lost a race and exchange-back failed for {path}: "
                                f"{restore_exc}",
                            ) from restore_exc
                        os.close(guard_fd)
                        raise StepFailed(step, f"write destination lost its inode/state CAS: {path}")
                    # A racer owns the destination after exchange. Never exchange
                    # over it: retain the original inode under the temporary name
                    # so rollback evidence can point to recoverable prior bytes.
                    recovery_path = (
                        f"/{temp_name}" if parent == "/" else f"{parent}/{temp_name}"
                    )
                    journal_entry["published"] = True
                    journal_entry["recoveryPath"] = recovery_path
                    preserve_temp = True
                    os.close(guard_fd)
                    raise StepFailed(
                        step,
                        f"write destination changed after CAS publish: {path}; foreign state "
                        f"preserved and pre-transaction inode retained at {recovery_path}",
                    )
                chain.verify(step=step)
                publication_observed = True
                os.close(guard_fd)
                journal_entry["published"] = True
                os.unlink(temp_name, dir_fd=dir_fd)
                temp_name = ""
            os.fsync(dir_fd)
            if not publication_observed:
                chain.verify(step=step)
        finally:
            if temp_name and not preserve_temp:
                try:
                    os.unlink(temp_name, dir_fd=dir_fd)
                except OSError:
                    pass
            if journal_entry is not None and not journal_entry["published"]:
                try:
                    ctx.journal.remove(journal_entry)
                except ValueError:
                    pass
        if prior_fd >= 0:
            os.close(prior_fd)
        if publication_observed:
            return True
        observed_content, observed = _read_regular_file(ctx.layout, path, step=step)
        if observed is None or observed_content != content:
            raise StepFailed(step, f"written content diverged at {path}")
        if (
            observed.st_uid != uid
            or observed.st_gid != gid
            or stat.S_IMODE(observed.st_mode) != mode
        ):
            raise StepFailed(
                step,
                f"ownership/mode observation failed for {path}: uid={observed.st_uid} "
                f"gid={observed.st_gid} mode={oct(stat.S_IMODE(observed.st_mode))}",
            )
    return True


# ---------------------------------------------------------------------------
# Subordinate UID/GID mappings
# ---------------------------------------------------------------------------


def _parse_subids(content: bytes, *, path: str, step: str) -> list[tuple[str, int, int]]:
    entries: list[tuple[str, int, int]] = []
    for raw_line in content.splitlines():
        try:
            line = raw_line.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise StepFailed(step, f"non-UTF-8 subordinate id line in {path}") from exc
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(":")
        if (
            len(parts) != 3
            or not parts[0]
            or parts[0] != parts[0].strip()
            or not parts[1].isdigit()
            or not parts[2].isdigit()
            or int(parts[2]) < 1
        ):
            raise StepFailed(step, f"malformed subordinate id line in {path}: {stripped!r}")
        entries.append((parts[0], int(parts[1]), int(parts[2])))
    return entries


def _read_subids(
    ctx: "_Apply", path: str, *, step: str
) -> tuple[bytes, os.stat_result | None, list[tuple[str, int, int]]]:
    content, observed = _read_regular_file(ctx.layout, path, step=step, absent_ok=True)
    return content, observed, _parse_subids(content, path=path, step=step)


@contextmanager
def _subid_lock(ctx: "_Apply", *, step: str) -> Iterator[None]:
    """Serialize provisioners and, on the real host, shadow account tooling."""

    shadow_libc: Any | None = None
    shadow_locked = False
    with _open_directory_chain(ctx.layout, "/etc", step=step) as chain:
        fcntl.flock(chain.fds[-1], fcntl.LOCK_EX)
        try:
            if ctx.layout.root == Path("/"):
                shadow_libc = ctypes.CDLL(None, use_errno=True)
                lock = getattr(shadow_libc, "lckpwdf", None)
                unlock = getattr(shadow_libc, "ulckpwdf", None)
                if lock is None or unlock is None or lock() != 0:
                    error = ctypes.get_errno()
                    raise StepFailed(
                        step,
                        "cannot acquire the shadow account database lock: "
                        + os.strerror(error or errno.EBUSY),
                    )
                shadow_locked = True
            yield
        finally:
            if shadow_locked and shadow_libc is not None:
                shadow_libc.ulckpwdf()
            fcntl.flock(chain.fds[-1], fcntl.LOCK_UN)


def _check_subid_overlap(
    entries: Sequence[tuple[str, int, int]],
    *,
    user: str,
    start: int,
    count: int,
    step: str,
) -> None:
    for name, other_start, other_count in entries:
        if name == user:
            continue
        if start < other_start + other_count and other_start < start + count:
            raise StepFailed(
                step,
                f"subordinate id range {start}:{count} for {user} overlaps "
                f"{name} at {other_start}:{other_count}",
            )


def _next_subid_start(entries: Sequence[tuple[str, int, int]]) -> int:
    """Lowest non-overlapping range start at or above SUBID_MIN_START."""

    start = SUBID_MIN_START
    for low, high in sorted((entry[1], entry[1] + entry[2]) for entry in entries):
        if start + SUBID_RANGE_SIZE <= low:
            break
        start = max(start, high)
    return start


# ---------------------------------------------------------------------------
# Protocol health: a real describeCapabilities round trip
# ---------------------------------------------------------------------------


def probe_protocol_health(
    socket_path: str | Path,
    *,
    expected_uid: int | None = None,
    expected_gid: int | None = None,
    expected_mode: int | None = None,
    expected_contract_version: int | None = None,
    timeout_seconds: int = 30,
) -> dict[str, Any]:
    """Verify the daemon answers a real describeCapabilities request.

    Socket existence is never health: an absent socket (empty directory), a
    symlink or non-socket inode, wrong ownership/mode, a stale inode whose
    listener is gone (connect refused), and a daemon refusal (for example a
    peer-identity mismatch) are all distinct, explicit unhealthy reasons.
    """

    path = Path(socket_path)

    def unhealthy(reason: str, detail: str) -> dict[str, Any]:
        return {"healthy": False, "reason": reason, "detail": detail[:280]}

    try:
        parent = os.lstat(path.parent)
    except OSError:
        return unhealthy("socket-directory-absent", f"{path.parent} does not exist")
    if stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode):
        return unhealthy("socket-directory-not-real", f"{path.parent} is not a real directory")
    try:
        observed = os.lstat(path)
    except FileNotFoundError:
        return unhealthy(
            "socket-absent",
            f"empty socket directory: {path} does not exist; the daemon is not up",
        )
    if stat.S_ISLNK(observed.st_mode):
        return unhealthy("socket-is-symlink", f"{path} is a symlink")
    if not stat.S_ISSOCK(observed.st_mode):
        return unhealthy("socket-not-a-socket", f"{path} is not a unix socket inode")
    if expected_uid is not None and observed.st_uid != expected_uid:
        return unhealthy(
            "socket-owner-mismatch", f"socket uid {observed.st_uid} != expected {expected_uid}"
        )
    if expected_gid is not None and observed.st_gid != expected_gid:
        return unhealthy(
            "socket-group-mismatch", f"socket gid {observed.st_gid} != expected {expected_gid}"
        )
    if expected_mode is not None and stat.S_IMODE(observed.st_mode) != expected_mode:
        return unhealthy(
            "socket-mode-mismatch",
            f"socket mode {oct(stat.S_IMODE(observed.st_mode))} != expected {oct(expected_mode)}",
        )
    try:
        from execution_host.client import (  # noqa: PLC0415 (lazy: package lives outside this wheel)
            ExecutionHostClient,
            ExecutionHostContractError,
            ExecutionHostRefusal,
            ExecutionHostTransportError,
        )
    except ImportError as exc:
        return unhealthy(
            "client-unavailable",
            f"execution_host package is not importable by the probe interpreter: {exc}",
        )
    client = ExecutionHostClient(
        path,
        grant_id=HEALTH_GRANT_ID,
        authority_grant_digest=HEALTH_GRANT_DIGEST,
        timeout_seconds=timeout_seconds,
        output_byte_bound=65536,
    )
    try:
        receipt = client.describe_capabilities()
    except ExecutionHostTransportError as exc:
        message = str(exc)
        if message.startswith("socket-refused"):
            return unhealthy(
                "stale-socket-inode",
                "no live daemon accepts connections on the socket; the inode is stale",
            )
        return unhealthy("transport-failed", message)
    except ExecutionHostRefusal as exc:
        return unhealthy(
            "daemon-refused",
            f"the daemon refused describeCapabilities: {exc.reason}",
        )
    except ExecutionHostContractError as exc:
        return unhealthy("protocol-violation", str(exc))
    result = receipt.get("result")
    if not isinstance(result, Mapping) or result.get("formatVersion") != (
        "stateport.execution-host-contract/v1"
    ) or not isinstance(result.get("contractVersion"), int):
        return unhealthy(
            "protocol-violation", "describeCapabilities result is outside the execution contract"
        )
    if (
        expected_contract_version is not None
        and result["contractVersion"] != expected_contract_version
    ):
        return unhealthy(
            "contract-version-mismatch",
            f"daemon contract {result['contractVersion']} != expected {expected_contract_version}",
        )
    return {
        "healthy": True,
        "reason": None,
        "contractVersion": result["contractVersion"],
        "transport": result.get("transport"),
        "engine": (receipt.get("observed") or {}).get("engine"),
        "engineVersion": (receipt.get("observed") or {}).get("engineVersion"),
    }


def _probe_pythonpath() -> str:
    """Import roots the probe subprocess needs (this package + execution_host)."""

    parents = [str(Path(__file__).resolve().parent.parent)]
    spec = importlib.util.find_spec("execution_host")
    if spec is not None and spec.origin:
        parents.append(str(Path(spec.origin).resolve().parent.parent))
    return ":".join(dict.fromkeys(parents))


# ---------------------------------------------------------------------------
# Root-helper transaction
# ---------------------------------------------------------------------------


@dataclass
class _Apply:
    plan: dict[str, Any]
    signed_payload_digest: str
    runner: Runner
    accounts: Accounts
    layout: HostLayout
    rootless_group_probe: Callable[[Mapping[str, Any]], Mapping[str, Any]]
    journal: list[dict[str, Any]] = field(default_factory=list)
    steps: list[dict[str, Any]] = field(default_factory=list)
    current_commands: list[list[str]] = field(default_factory=list)
    exec_uid: int = -1
    exec_gid: int = -1
    group_gid: int = -1
    subid_start: int | None = None
    control_subid_start: int | None = None
    image_observed: str | None = None
    health: dict[str, Any] | None = None
    grant_digest: str | None = None


def _trusted_argv(argv: Sequence[str]) -> list[str]:
    if not argv:
        raise ProvisioningRefusal("refusing an empty subprocess command")
    values = [str(item) for item in argv]
    values[0] = _TRUSTED_EXECUTABLES.get(values[0], values[0])
    if not os.path.isabs(values[0]):
        raise ProvisioningRefusal(f"untrusted executable path: {values[0]}")
    return values


def _as_user(
    ctx: _Apply,
    user_name: str,
    argv: Sequence[str],
    *,
    extra_environment: Mapping[str, str] | None = None,
) -> list[str]:
    """Run as one account with no ambient root environment or container authority."""

    account = ctx.accounts.user(user_name)
    if account is None:
        raise StepFailed("user-environment", f"account is absent: {user_name}")
    return _user_argv(
        user_name,
        account.uid,
        account.home,
        account.shell,
        argv,
        extra_environment=extra_environment,
    )


def _as_exec(ctx: _Apply, argv: Sequence[str]) -> list[str]:
    """Run argv as stateport-exec with a deliberate user-systemd environment."""

    return _as_user(ctx, EXEC_USER, argv)


def _run(ctx: _Apply, argv: Sequence[str], *, step: str, timeout: int = 300) -> Completed:
    command = _trusted_argv(argv)
    ctx.current_commands.append(command)
    return ctx.runner.run(command, timeout=timeout)


def _write_diagnostic_sidecar(ctx: _Apply, name: str, content: str) -> None:
    """Persist a bounded failure diagnostic outside the rolled-back tree.

    The provisioning rollback removes the control/exec user trees, so the
    container status and log captured at a start failure would be lost with
    them.  Write a bounded sidecar under the root-owned provisioning state
    directory (which the rollback preserves) so a clean-guest rehearsal can
    record the exact systemd/podman error.
    """
    try:
        diagnostics = Path("/var/lib/stateport-provisioning/diagnostics")
        diagnostics.mkdir(mode=0o700, parents=True, exist_ok=True)
        safe = "".join(ch for ch in Path(name).name if ch.isalnum() or ch in ".-_")
        target = diagnostics / safe
        bounded = content[-16000:]
        target.write_text(bounded, encoding="utf-8")
        ctx.journal.append({"kind": "diagnostic-sidecar", "path": str(target)})
    except Exception:  # noqa: BLE001 — diagnostics are best-effort
        pass


def _require(condition: bool, step: str, detail: str) -> None:
    if not condition:
        raise StepFailed(step, detail[:280])


def _default_rootless_group_probe(plan: Mapping[str, Any]) -> Mapping[str, Any]:
    contract = plan["rootlessSupplementaryGroupContract"]
    runtime = Path(str(contract.get("runtimePath", "")))
    expected_digest = str(contract.get("runtimeSha256", ""))
    expected_version = str(contract.get("runtimeVersion", ""))
    if (
        not runtime.is_absolute()
        or runtime != Path(CONFINED_GROUP_OCI_RUNTIME_PATH)
        or runtime.is_symlink()
        or not runtime.is_file()
    ):
        return {
            "supported": False,
            "mechanism": contract.get("quadletDirective", ""),
            "detail": f"pinned supplementary-group runtime is unavailable: {runtime}",
        }
    observed_digest = "sha256:" + hashlib.sha256(runtime.read_bytes()).hexdigest()
    completed = subprocess.run(
        [str(runtime), "--version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        shell=False,
        stdin=subprocess.DEVNULL,
        env=_ROOT_COMMAND_ENV,
    )
    first_line = completed.stdout.splitlines()[0] if completed.stdout.splitlines() else ""
    supported = (
        contract.get("status") == "supported-by-pinned-runtime-contract"
        and expected_digest == CONFINED_GROUP_OCI_RUNTIME_SHA256
        and observed_digest == expected_digest
        and expected_version == CONFINED_GROUP_OCI_RUNTIME_VERSION
        and completed.returncode == 0
        and first_line == f"crun version {expected_version}"
    )
    return {
        "supported": supported,
        "mechanism": contract["quadletDirective"],
        "detail": (
            contract["detail"]
            if supported
            else f"pinned runtime identity mismatch: digest={observed_digest}, version={first_line!r}"
        ),
    }


def _step_rootless_group_contract(ctx: _Apply) -> dict[str, Any]:
    step = "verify-rootless-supplementary-group-contract"
    result = ctx.rootless_group_probe(ctx.plan)
    supported = result.get("supported") is True
    detail = str(result.get("detail", "rootless supplementary-group support is unknown"))
    _require(
        supported,
        step,
        "unsupported rootless socket-group contract: " + detail,
    )
    return {
        "step": step,
        "result": "already-present",
        "commands": [],
        "detail": str(result.get("mechanism", "simulated-supported-contract"))[:300],
    }


def _validate_exec_identity(ctx: _Apply, user: Account, *, step: str) -> Group:
    private_group = ctx.accounts.group(EXEC_USER)
    problems: list[str] = []
    if user.uid <= 0 or user.gid <= 0:
        problems.append(f"unsafe uid/gid {user.uid}:{user.gid}")
    if ctx.layout.root == Path("/") and (user.uid != int(ctx.plan["executionUid"]) or user.gid != int(ctx.plan["executionGid"])):
        problems.append(
            f"numeric identity {user.uid}:{user.gid} != required "
            f"{ctx.plan['executionUid']}:{ctx.plan['executionGid']}"
        )
    if user.home != EXEC_HOME:
        problems.append(f"home={user.home!r}")
    if user.shell != DEFAULT_NOLOGIN_SHELL:
        problems.append(f"shell={user.shell!r}")
    if private_group is None:
        problems.append("private group absent")
    else:
        if ctx.layout.root == Path("/") and private_group.gid != int(ctx.plan["executionGid"]):
            problems.append(
                f"private group gid {private_group.gid} != required {ctx.plan['executionGid']}"
            )
        if user.gid != private_group.gid:
            problems.append(
                f"primary gid {user.gid} != private group gid {private_group.gid}"
            )
        foreign_members = sorted(set(private_group.members) - {EXEC_USER})
        if foreign_members:
            problems.append(f"private group has foreign members {foreign_members}")
        primary_users = set(ctx.accounts.primary_group_users(EXEC_USER))
        if primary_users != {EXEC_USER}:
            problems.append(f"private group primary users are {sorted(primary_users)}")
    _require(
        not problems,
        step,
        f"existing {EXEC_USER} identity is not the required private-group/nologin system "
        f"identity: {'; '.join(problems)}",
    )
    assert private_group is not None
    return private_group


def _validate_control_identity(ctx: _Apply, user: Account, *, step: str) -> Group:
    private_group = ctx.accounts.group(CONTROL_USER)
    problems: list[str] = []
    if user.uid <= 0 or user.gid <= 0:
        problems.append(f"unsafe uid/gid {user.uid}:{user.gid}")
    if ctx.layout.root == Path("/") and (user.uid != int(ctx.plan["controlUid"]) or user.gid != int(ctx.plan["controlGid"])):
        problems.append(
            f"numeric identity {user.uid}:{user.gid} != required "
            f"{ctx.plan['controlUid']}:{ctx.plan['controlGid']}"
        )
    if user.home != CONTROL_HOME:
        problems.append(f"home={user.home!r}")
    if user.shell != DEFAULT_NOLOGIN_SHELL:
        problems.append(f"shell={user.shell!r}")
    if private_group is None:
        problems.append("private group absent")
    else:
        if ctx.layout.root == Path("/") and private_group.gid != int(ctx.plan["controlGid"]):
            problems.append(
                f"private group gid {private_group.gid} != required {ctx.plan['controlGid']}"
            )
        if user.gid != private_group.gid:
            problems.append(
                f"primary gid {user.gid} != private group gid {private_group.gid}"
            )
        foreign_members = sorted(set(private_group.members) - {CONTROL_USER})
        if foreign_members:
            problems.append(f"private group has foreign members {foreign_members}")
        primary_users = set(ctx.accounts.primary_group_users(CONTROL_USER))
        if primary_users != {CONTROL_USER}:
            problems.append(f"private group primary users are {sorted(primary_users)}")
    _require(
        not problems,
        step,
        f"existing {CONTROL_USER} identity is not the required private-group/nologin system "
        f"identity: {'; '.join(problems)}",
    )
    assert private_group is not None
    return private_group


def _validate_control_group(
    ctx: _Apply,
    group: Group,
    *,
    step: str,
    required_members: frozenset[str] = frozenset(),
) -> None:
    allowed_members = {EXEC_USER, CONTROL_USER, str(ctx.plan["allowedClientUser"])}
    foreign_members = sorted(set(group.members) - allowed_members)
    _require(group.gid > 0, step, f"group {EXEC_GROUP} has unsafe gid {group.gid}")
    if ctx.layout.root == Path("/"):
        _require(
            group.gid == int(ctx.plan["executionControlGroupGid"]),
            step,
            f"group {EXEC_GROUP} has gid {group.gid}, expected {ctx.plan['executionControlGroupGid']}",
        )
    _require(
        not foreign_members,
        step,
        f"group {EXEC_GROUP} grants socket access to foreign members {foreign_members}",
    )
    missing_members = sorted(required_members - set(group.members))
    _require(
        not missing_members,
        step,
        f"group {EXEC_GROUP} is missing required members {missing_members}",
    )
    primary_users = ctx.accounts.primary_group_users(EXEC_GROUP)
    _require(
        not primary_users,
        step,
        f"group {EXEC_GROUP} grants primary-group socket access to {list(primary_users)}",
    )


def _step_group(ctx: _Apply) -> dict[str, Any]:
    step = "ensure-execution-control-group"
    group = ctx.accounts.group(EXEC_GROUP)
    if group is not None:
        _validate_control_group(ctx, group, step=step)
        ctx.group_gid = group.gid
        return {"step": step, "result": "already-present", "commands": [], "detail": ""}
    argv = [
        _TRUSTED_EXECUTABLES["groupadd"],
        "--system",
        "--gid",
        str(ctx.plan["executionControlGroupGid"]),
        EXEC_GROUP,
    ]
    journal_entry = {"kind": "group-created", "name": EXEC_GROUP}
    ctx.journal.append(journal_entry)
    completed = _run(ctx, argv, step=step)
    if completed.returncode != 0:
        ctx.journal.remove(journal_entry)
    group = ctx.accounts.group(EXEC_GROUP)
    _require(
        group is not None,
        step,
        f"groupadd exited {completed.returncode} and the group is still absent: "
        f"{completed.stderr.strip()[:200]}",
    )
    _validate_control_group(ctx, group, step=step)
    ctx.group_gid = group.gid
    detail = "" if completed.returncode == 0 else f"postcondition observed after rc={completed.returncode}"
    return {
        "step": step,
        "result": "applied" if completed.returncode == 0 else "already-present",
        "commands": [argv],
        "detail": detail,
    }


def _step_control_user(ctx: _Apply) -> dict[str, Any]:
    step = "ensure-stateport-control-user"
    user = ctx.accounts.user(CONTROL_USER)
    private_group = ctx.accounts.group(CONTROL_USER)
    if user is not None:
        _validate_control_identity(ctx, user, step=step)
        return {"step": step, "result": "already-present", "commands": [], "detail": ""}
    _require(
        private_group is None,
        step,
        f"private group {CONTROL_USER} exists without its user; refusing to adopt it",
    )
    group_argv = [
        _TRUSTED_EXECUTABLES["groupadd"],
        "--system",
        "--gid",
        str(ctx.plan["controlGid"]),
        CONTROL_USER,
    ]
    user_argv = [
        _TRUSTED_EXECUTABLES["useradd"],
        "--system",
        "--uid",
        str(ctx.plan["controlUid"]),
        "--gid",
        str(ctx.plan["controlGid"]),
        "--home-dir",
        CONTROL_HOME,
        "--create-home",
        "--shell",
        DEFAULT_NOLOGIN_SHELL,
        CONTROL_USER,
    ]
    group_entry = {"kind": "group-created", "name": CONTROL_USER}
    user_entry = {"kind": "user-created", "name": CONTROL_USER}
    ctx.journal.extend((group_entry, user_entry))
    group_result = _run(ctx, group_argv, step=step)
    user_result = _run(ctx, user_argv, step=step)
    user = ctx.accounts.user(CONTROL_USER)
    if group_result.returncode != 0 or user_result.returncode != 0:
        if user is None:
            ctx.journal.remove(user_entry)
        if ctx.accounts.group(CONTROL_USER) is None:
            ctx.journal.remove(group_entry)
    _require(
        user is not None,
        step,
        f"useradd exited {user_result.returncode} and {CONTROL_USER} is still absent: "
        f"{user_result.stderr.strip()[:200]}",
    )
    _validate_control_identity(ctx, user, step=step)
    # The control account is the control-plane container peer: it must hold
    # the confined socket group so keep-groups carries it into the containers.
    group = ctx.accounts.group(EXEC_GROUP)
    _require(group is not None, step, f"group {EXEC_GROUP} is absent")
    if CONTROL_USER not in group.members:
        confine_argv = [
            _TRUSTED_EXECUTABLES["usermod"],
            "--append",
            "--groups",
            EXEC_GROUP,
            CONTROL_USER,
        ]
        ctx.journal.append({"kind": "client-confined", "user": CONTROL_USER})
        completed = _run(ctx, confine_argv, step=step)
        if completed.returncode != 0:
            ctx.journal.pop()
        group = ctx.accounts.group(EXEC_GROUP)
        _require(
            group is not None and CONTROL_USER in group.members,
            step,
            f"usermod exited {completed.returncode} and {CONTROL_USER} is still outside "
            f"{EXEC_GROUP}: {completed.stderr.strip()[:200]}",
        )
    _validate_control_group(
        ctx, group, step=step, required_members=frozenset({CONTROL_USER})
    )
    return {
        "step": step,
        "result": "applied" if group_result.returncode == 0 or user_result.returncode == 0 else "already-present",
        "commands": [group_argv, user_argv],
        "detail": "",
    }


def _step_user(ctx: _Apply) -> dict[str, Any]:
    step = "ensure-stateport-exec-user"
    user = ctx.accounts.user(EXEC_USER)
    if user is not None:
        _validate_exec_identity(ctx, user, step=step)
        ctx.exec_uid, ctx.exec_gid = user.uid, user.gid
        return {"step": step, "result": "already-present", "commands": [], "detail": ""}
    _require(
        ctx.accounts.group(EXEC_USER) is None,
        step,
        f"private group {EXEC_USER} exists without its user; refusing to adopt it",
    )
    group_argv = [
        _TRUSTED_EXECUTABLES["groupadd"],
        "--system",
        "--gid",
        str(ctx.plan["executionGid"]),
        EXEC_USER,
    ]
    argv = [
        _TRUSTED_EXECUTABLES["useradd"],
        "--system",
        "--uid",
        str(ctx.plan["executionUid"]),
        "--gid",
        str(ctx.plan["executionGid"]),
        "--home-dir",
        EXEC_HOME,
        "--create-home",
        "--shell",
        DEFAULT_NOLOGIN_SHELL,
        EXEC_USER,
    ]
    # Reversal sees user first, then its private group. Provisional entries
    # also cover a command timeout after account-tool mutation.
    group_entry = {"kind": "group-created", "name": EXEC_USER}
    user_entry = {"kind": "user-created", "name": EXEC_USER}
    ctx.journal.extend((group_entry, user_entry))
    group_result = _run(ctx, group_argv, step=step)
    completed = _run(ctx, argv, step=step)
    if group_result.returncode != 0 or completed.returncode != 0:
        ctx.journal.remove(user_entry)
        if ctx.accounts.group(EXEC_USER) is None:
            ctx.journal.remove(group_entry)
    user = ctx.accounts.user(EXEC_USER)
    _require(
        user is not None,
        step,
        f"useradd exited {completed.returncode} and the user or its private group is "
        f"absent or mismatched: {completed.stderr.strip()[:200]}",
    )
    _validate_exec_identity(ctx, user, step=step)
    ctx.exec_uid, ctx.exec_gid = user.uid, user.gid
    detail = "" if completed.returncode == 0 else f"postcondition observed after rc={completed.returncode}"
    return {
        "step": step,
        "result": "applied" if group_result.returncode == 0 or completed.returncode == 0 else "already-present",
        "commands": [group_argv, argv],
        "detail": detail,
    }


def _step_group_membership(ctx: _Apply, user_name: str, *, step: str) -> dict[str, Any]:
    group = ctx.accounts.group(EXEC_GROUP)
    account = ctx.accounts.user(user_name)
    _require(group is not None, step, f"group {EXEC_GROUP} is absent")
    _validate_control_group(ctx, group, step=step)
    _require(account is not None and account.uid > 0, step, f"safe account {user_name} is absent")
    required_members = {user_name}
    if user_name == str(ctx.plan["allowedClientUser"]):
        required_members.add(EXEC_USER)
    if user_name in group.members:
        _validate_control_group(
            ctx, group, step=step, required_members=frozenset(required_members)
        )
        return {"step": step, "result": "already-present", "commands": [], "detail": ""}
    argv = [
        _TRUSTED_EXECUTABLES["usermod"],
        "--append",
        "--groups",
        EXEC_GROUP,
        user_name,
    ]
    journal_entry = {"kind": "client-confined", "user": user_name}
    ctx.journal.append(journal_entry)
    completed = _run(ctx, argv, step=step)
    if completed.returncode != 0:
        ctx.journal.remove(journal_entry)
    group = ctx.accounts.group(EXEC_GROUP)
    _require(
        group is not None and user_name in group.members,
        step,
        f"usermod exited {completed.returncode} and {user_name} is still outside "
        f"{EXEC_GROUP}: {completed.stderr.strip()[:200]}",
    )
    _validate_control_group(
        ctx, group, step=step, required_members=frozenset(required_members)
    )
    detail = "" if completed.returncode == 0 else f"postcondition observed after rc={completed.returncode}"
    return {
        "step": step,
        "result": "applied" if completed.returncode == 0 else "already-present",
        "commands": [argv],
        "detail": detail,
    }


def _step_confine_exec(ctx: _Apply) -> dict[str, Any]:
    return _step_group_membership(
        ctx, EXEC_USER, step="confine-execution-user-group"
    )


def _step_confine_client(ctx: _Apply) -> dict[str, Any]:
    step = "confine-control-plane-client"
    return _step_group_membership(ctx, str(ctx.plan["allowedClientUser"]), step=step)


def _step_subids(ctx: _Apply) -> dict[str, Any]:
    step = "establish-subordinate-mappings"
    root = ctx.accounts.user("root")
    _require(root is not None, step, "the root account is not resolvable")
    changed = False
    paths = (SUBUID_PATH, SUBGID_PATH)
    # Both the execution host (rootless engine) and the control-plane client
    # (rootless Podman pulls) need subordinate ID ranges.
    mapping_users = (EXEC_USER, CONTROL_USER)
    with _subid_lock(ctx, step=step):
        snapshots = {path: _read_subids(ctx, path, step=step) for path in paths}
        existing_by_user: dict[str, dict[str, tuple[str, int, int] | None]] = {}
        for user in mapping_users:
            by_path: dict[str, tuple[str, int, int] | None] = {}
            for path, (_content, observed, entries) in snapshots.items():
                if observed is not None:
                    _require(
                        observed.st_uid == root.uid
                        and observed.st_gid == root.gid
                        and stat.S_IMODE(observed.st_mode) & 0o022 == 0,
                        step,
                        f"{path} has unsafe metadata uid={observed.st_uid} gid={observed.st_gid} "
                        f"mode={oct(stat.S_IMODE(observed.st_mode))}",
                    )
                mine = [entry for entry in entries if entry[0] == user]
                _require(
                    len(mine) <= 1,
                    step,
                    f"multiple subordinate id mappings for {user} in {path}: {mine}",
                )
                by_path[path] = mine[0] if mine else None
            existing_by_user[user] = by_path
        all_entries = [
            entry
            for _content, _observed, entries in snapshots.values()
            for entry in entries
        ]
        assigned_by_user: dict[str, int] = {}
        for user in mapping_users:
            by_path = existing_by_user[user]
            existing = [mapping for mapping in by_path.values() if mapping is not None]
            observed_values = ", ".join(
                f"{path}={by_path[path] if by_path[path] is not None else 'absent'}"
                for path in paths
            )
            _require(
                all(mapping[2] == SUBID_RANGE_SIZE for mapping in existing),
                step,
                f"existing mappings must have exact count {SUBID_RANGE_SIZE}; observed {observed_values}",
            )
            _require(
                len({mapping[1] for mapping in existing}) <= 1,
                step,
                f"subuid/subgid mappings are incoherent; observed {observed_values}",
            )
            if existing:
                assigned_by_user[user] = existing[0][1]
            else:
                assigned_by_user[user] = _next_subid_start(all_entries)
                all_entries.append((user, assigned_by_user[user], SUBID_RANGE_SIZE))
        _require(
            len({start for start in assigned_by_user.values()}) == len(mapping_users),
            step,
            f"subordinate id ranges must be distinct per user; observed {assigned_by_user}",
        )
        for user in mapping_users:
            start = assigned_by_user[user]
            for _content, _observed, entries in snapshots.values():
                _check_subid_overlap(
                    entries,
                    user=user,
                    start=start,
                    count=SUBID_RANGE_SIZE,
                    step=step,
                )
        for path in paths:
            by_path = {user: existing_by_user[user][path] for user in mapping_users}
            missing = [user for user in mapping_users if by_path[user] is None]
            if not missing:
                continue
            # Re-read both files under both locks immediately before every publish.
            current = {candidate: _read_subids(ctx, candidate, step=step) for candidate in paths}
            for candidate in paths:
                _require(
                    current[candidate][0] == snapshots[candidate][0],
                    step,
                    f"{candidate} changed despite the account/provisioner lock; refusing CAS",
                )
            for _bytes, _metadata, entries in current.values():
                for user in missing:
                    _check_subid_overlap(
                        entries,
                        user=user,
                        start=assigned_by_user[user],
                        count=SUBID_RANGE_SIZE,
                        step=step,
                    )
            prior, prior_stat, _entries = snapshots[path]
            separator = b"" if not prior or prior.endswith(b"\n") else b"\n"
            added_lines = b"".join(
                f"{user}:{assigned_by_user[user]}:{SUBID_RANGE_SIZE}\n".encode("ascii")
                for user in mapping_users
                if by_path[user] is None
            )
            added = separator + added_lines
            _write_file_converged(
                ctx,
                path,
                prior + added,
                mode=0o644 if prior_stat is None else stat.S_IMODE(prior_stat.st_mode),
                uid=root.uid if prior_stat is None else prior_stat.st_uid,
                gid=root.gid if prior_stat is None else prior_stat.st_gid,
                step=step,
                journal_kind="subid-line-added",
                journal_extra={
                    "addedBytes": added,
                    "priorDigest": "sha256:" + hashlib.sha256(prior).hexdigest(),
                },
            )
            snapshots[path] = _read_subids(ctx, path, step=step)
            changed = True
        for user in mapping_users:
            start = assigned_by_user[user]
            for path in paths:
                _content, _observed, entries = _read_subids(ctx, path, step=step)
                mine = [entry for entry in entries if entry[0] == user]
                _require(
                    mine == [(user, start, SUBID_RANGE_SIZE)],
                    step,
                    f"subordinate id observation failed in {path}; observed {mine}",
                )
                _check_subid_overlap(
                    entries,
                    user=user,
                    start=start,
                    count=SUBID_RANGE_SIZE,
                    step=step,
                )
        ctx.subid_start = assigned_by_user[EXEC_USER]
        ctx.control_subid_start = assigned_by_user[CONTROL_USER]
    return {
        "step": step,
        "result": "applied" if changed else "already-present",
        "commands": [],
        "detail": (
            f"{EXEC_USER}:{assigned_by_user[EXEC_USER]}:{SUBID_RANGE_SIZE}; "
            f"{CONTROL_USER}:{assigned_by_user[CONTROL_USER]}:{SUBID_RANGE_SIZE}"
        ),
    }


def _step_directories(ctx: _Apply) -> dict[str, Any]:
    step = "create-host-directories"
    changed = False
    for spec in ctx.plan["directories"]:
        owner_user, _, owner_group = str(spec["owner"]).partition(":")
        account = ctx.accounts.user(owner_user)
        group = ctx.accounts.group(owner_group or owner_user)
        _require(
            account is not None and group is not None,
            step,
            f"identity for {spec['owner']} is absent; users/groups come before files",
        )
        changed = (
            _ensure_directory_converged(
                ctx,
                str(spec["path"]),
                mode=int(spec["mode"], 8),
                uid=account.uid,
                gid=group.gid,
                step=step,
                **({"refuse_existing_mismatch": True} if str(spec["path"]) in {
                    "/var/lib/stateport-control/provider-auth", PROVIDER_HOME_CONTRACT["hostPath"],
                } else {}),
            )
            or changed
        )
    return {
        "step": step,
        "result": "applied" if changed else "already-present",
        "commands": [],
        "detail": "",
    }


def _step_tmpfiles(ctx: _Apply) -> dict[str, Any]:
    step = "write-confined-socket-tmpfiles"
    root = ctx.accounts.user("root")
    _require(root is not None, step, "the root account is not resolvable")
    spec = next(write for write in ctx.plan["writes"] if write["path"] == TMPFILES_PATH)
    _write_file_converged(
        ctx,
        TMPFILES_PATH,
        spec["content"].encode("utf-8"),
        mode=int(spec["mode"], 8),
        uid=root.uid,
        gid=root.gid,
        step=step,
    )
    _ensure_directory_converged(
        ctx,
        str(PurePosixPath(str(ctx.plan["socketDirectory"])).parent),
        mode=0o755,
        uid=root.uid,
        gid=root.gid,
        step=step,
    )
    _ensure_directory_converged(
        ctx,
        str(ctx.plan["socketDirectory"]),
        mode=int(str(ctx.plan["socketDirectoryMode"]), 8),
        uid=ctx.exec_uid,
        gid=ctx.group_gid,
        step=step,
    )
    argv = [_TRUSTED_EXECUTABLES["systemd-tmpfiles"], "--create", TMPFILES_PATH]
    completed = _run(ctx, argv, step=step)
    socket_dir = str(ctx.plan["socketDirectory"])
    observed = _observe_directory(
        ctx.layout, socket_dir, step=step, description="confined socket directory"
    )
    _require(
        completed.returncode == 0
        and observed.st_uid == ctx.exec_uid
        and observed.st_gid == ctx.group_gid
        and stat.S_IMODE(observed.st_mode) == int(str(ctx.plan["socketDirectoryMode"]), 8),
        step,
        f"socket directory observation failed: uid={observed.st_uid} gid={observed.st_gid} "
        f"mode={oct(stat.S_IMODE(observed.st_mode))} (tmpfiles rc={completed.returncode})",
    )
    return {"step": step, "result": "applied", "commands": [argv], "detail": ""}


def _user_manager_unit(ctx: _Apply, user_name: str, *, step: str) -> str:
    account = ctx.accounts.user(user_name)
    _require(account is not None, step, f"account is absent: {user_name}")
    uid_field = "executionUid" if user_name == EXEC_USER else "controlUid"
    expected_uid = int(ctx.plan[uid_field])
    if ctx.layout.root == Path("/"):
        _require(
            account.uid == expected_uid,
            step,
            f"{user_name} UID does not match the signed execution contract",
        )
    return f"user@{expected_uid}.service"


def _step_linger(
    ctx: _Apply, user_name: str, step: str, *, verify_bus: bool = False
) -> dict[str, Any]:
    unit = _user_manager_unit(ctx, user_name, step=step)
    manager_preexisting = _user_manager_active(ctx, unit, step=step)
    if not manager_preexisting:
        ctx.journal.append(
            {"kind": "user-manager-started", "unit": unit, "user": user_name}
        )
    marker = f"{LINGER_DIR}/{user_name}"
    _content, observed = _read_regular_file(ctx.layout, marker, step=step, absent_ok=True)
    marker_created = observed is None
    if marker_created and manager_preexisting:
        ctx.journal.append(
            {"kind": "user-manager-preserve-active", "unit": unit, "user": user_name}
        )
    if marker_created:
        argv = [_TRUSTED_EXECUTABLES["loginctl"], "enable-linger", user_name]
        ctx.journal.append({"kind": "linger-enabled", "user": user_name})
        completed = _run(ctx, argv, step=step)
        _content, observed = _read_regular_file(
            ctx.layout, marker, step=step, absent_ok=True
        )
        _require(
            observed is not None,
            step,
            f"loginctl exited {completed.returncode} and the linger marker did not appear: "
            f"{completed.stderr.strip()[:200]}",
        )
    if not manager_preexisting:
        started = _run(
            ctx,
            [_TRUSTED_EXECUTABLES["systemctl"], "start", unit],
            step=step,
            timeout=120,
        )
        _require(
            _user_manager_active(ctx, unit, step=step),
            step,
            f"user manager did not become active after rc={started.returncode}: "
            f"{started.stderr.strip()[:200]}",
        )
    if verify_bus:
        probe = _run(
            ctx,
            _as_user(
                ctx,
                user_name,
                [_TRUSTED_EXECUTABLES["systemctl"], "--user", "show-environment"],
            ),
            step=step,
            timeout=120,
        )
        _require(
            probe.returncode == 0,
            step,
            f"{user_name} manager bus is unavailable: {probe.stderr.strip()[:200]}",
        )
    return {
        "step": step,
        "result": "applied" if marker_created or not manager_preexisting else "already-present",
        "commands": [],
        "detail": "",
    }


def _user_manager_active(ctx: _Apply, unit: str, *, step: str) -> bool:
    completed = _run(
        ctx,
        [_TRUSTED_EXECUTABLES["systemctl"], "is-active", unit],
        step=step,
        timeout=120,
    )
    state = completed.stdout.strip()
    if completed.returncode == 0 and state in {"active", "reloading"}:
        return True
    if completed.returncode in {3, 4} and state in {"inactive", "failed", "unknown"}:
        return False
    raise StepFailed(
        step,
        f"user manager state probe failed for {unit}: rc={completed.returncode} "
        f"state={state!r} {completed.stderr.strip()[:160]}",
    )


def _step_control_linger(ctx: _Apply) -> dict[str, Any]:
    return _step_linger(ctx, CONTROL_USER, "enable-control-user-linger")


def _step_exec_linger(ctx: _Apply) -> dict[str, Any]:
    return _step_linger(
        ctx, EXEC_USER, "enable-exec-user-linger", verify_bus=True
    )


def _resolve_owner(ctx: _Apply, owner: str, *, step: str) -> tuple[int, int]:
    user_name, separator, group_name = owner.partition(":")
    if not separator or not user_name or not group_name:
        raise StepFailed(step, f"write owner must be user:group: {owner!r}")
    user = ctx.accounts.user(user_name)
    group = ctx.accounts.group(group_name)
    _require(user is not None, step, f"write owner user is absent: {user_name}")
    _require(group is not None, step, f"write owner group is absent: {group_name}")
    return user.uid, group.gid


def _step_quadlets(ctx: _Apply) -> dict[str, Any]:
    step = "install-stable-host-quadlets"
    written = False
    for spec in ctx.plan["writes"]:
        if spec["path"] == TMPFILES_PATH:
            continue
        if str(spec["path"]).startswith(CONTROL_QUADLET_DIR + "/"):
            # Control-plane units belong to the stateport-control user's
            # Quadlet root and are installed by install-control-plane-units,
            # which runs the control user's daemon-reload.  Writing them here
            # (and reloading only the execution user's manager) would leave the
            # control manager without the generated units.
            continue
        content = spec["content"].encode("utf-8")
        _require(
            canonical_digest(spec["content"]) == spec["contentDigest"],
            step,
            f"quadlet content digest mismatch for {spec['path']}",
        )
        owner = str(spec.get("owner", f"{ctx.exec_uid}:{ctx.exec_gid}"))
        if owner == f"{ctx.exec_uid}:{ctx.exec_gid}":
            uid, gid = ctx.exec_uid, ctx.exec_gid
        else:
            uid, gid = _resolve_owner(ctx, owner, step=step)
        written = (
            _write_file_converged(
                ctx,
                str(spec["path"]),
                content,
                mode=int(spec["mode"], 8),
                uid=uid,
                gid=gid,
                step=step,
            )
            or written
        )
    if not written:
        return {"step": step, "result": "already-present", "commands": [], "detail": ""}
    argv = _as_exec(ctx, [_TRUSTED_EXECUTABLES["systemctl"], "--user", "daemon-reload"])
    completed = _run(ctx, argv, step=step)
    _require(
        completed.returncode == 0,
        step,
        f"daemon-reload failed: {completed.stderr.strip()[:200]}",
    )
    return {"step": step, "result": "applied", "commands": [argv], "detail": ""}


def _step_control_units(ctx: _Apply) -> dict[str, Any]:
    """Install the accepted control-plane units into the control user's root."""
    step = "install-control-plane-units"
    specs = ctx.plan["writes"]
    control_specs = [
        spec for spec in specs if str(spec["path"]).startswith(CONTROL_QUADLET_DIR + "/")
    ]
    if not control_specs:
        return {"step": step, "result": "already-present", "commands": [], "detail": "no control-plane units in this plan"}
    written = False
    environment = ctx.plan.get("controlPlaneEnvironment") or {}
    for spec in control_specs:
        content = spec["content"].encode("utf-8")
        _require(
            canonical_digest(spec["content"]) == spec["contentDigest"],
            step,
            f"control unit content digest mismatch for {spec['path']}",
        )
        unit_text = spec["content"]
        if "stateport-web" in str(spec["path"]) and b"STATEPORT_EXECUTION_SOCKET=" in content:
            # The per-install grant digest (computed by the grant step) is
            # injected into the web unit so the sanctioned proxy binds the
            # exact provisioned grant.
            if ctx.grant_digest is not None and "STATEPORT_EXECUTION_GRANT_DIGEST=" not in unit_text:
                unit_text = unit_text.replace(
                    "Environment=STATEPORT_EXECUTION_PEER_POLICY=",
                    "Environment=STATEPORT_EXECUTION_GRANT_DIGEST="
                    + ctx.grant_digest
                    + "\nEnvironment=STATEPORT_EXECUTION_PEER_POLICY=",
                    1,
                )
        # Per-install control-plane environment (worker/API defaults) is
        # injected into the matching unit's [Container] section.  Keys are
        # "<service>.<VARNAME>" so the installer can target per-service env
        # without editing the signed unit template.  Control-plane unit
        # filenames are content-addressed hashes, so the service is detected
        # from the unit's Label=io.stateport.service.id line, never the path.
        for key, value in sorted(environment.items()):
            service_prefix, separator, var_name = key.partition(".")
            if not separator:
                continue
            service_id = None
            label_prefix = "Label=io.stateport.service.id="
            for label_line in unit_text.splitlines():
                if label_line.startswith(label_prefix):
                    service_id = label_line[len(label_prefix):].strip()
                    break
            if service_id is None or service_prefix != service_id:
                continue
            if f"Environment={var_name}=" in unit_text:
                continue
            marker = "HealthCmd="
            if marker in unit_text:
                # systemd Environment= values with spaces or special
                # characters must be double-quoted with the inner quotes
                # escaped; the api identity/auth JSON would otherwise break
                # the Quadlet line and the container fails to start.
                escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
                unit_text = unit_text.replace(
                    marker,
                    f'Environment="{var_name}={escaped}"\n' + marker,
                    1,
                )
        content = unit_text.encode("utf-8")
        uid, gid = _resolve_owner(ctx, f"{CONTROL_USER}:{CONTROL_USER}", step=step)
        written = (
            _write_file_converged(
                ctx,
                str(spec["path"]),
                content,
                mode=int(spec["mode"], 8),
                uid=uid,
                gid=gid,
                step=step,
            )
            or written
        )
    # Reboot recovery: the accepted activation target lives in the control
    # user's regular systemd user-unit root and enables the accepted units.
    control_unit_names: list[str] = []
    for spec in control_specs:
        name = PurePosixPath(spec["path"]).name
        if name.endswith(".container"):
            control_unit_names.append(name.removesuffix(".container") + ".service")
        elif name.endswith(".network"):
            control_unit_names.append(name.removesuffix(".network") + "-network.service")
    control_unit_names.sort()
    _require(control_unit_names, step, "control-plane materialization has no activatable units")
    activation_path = f"{CONTROL_SYSTEMD_USER_DIR}/stateport-accepted.target"
    activation_content = (
        "[Unit]\n"
        "Description=StatePort accepted release\n"
        f"X-StatePort-Control-Identity={CONTROL_USER}\n"
        f"X-StatePort-Release-Id={ctx.plan['releaseId']}\n"
        f"X-StatePort-Signed-Payload={ctx.signed_payload_digest}\n"
        "After=" + " ".join(control_unit_names) + "\n"
        "Wants=" + " ".join(control_unit_names) + "\n"
        "\n"
        "[Install]\n"
        "WantedBy=default.target\n"
        "\n"
    )
    control_uid, control_gid = _resolve_owner(
        ctx, f"{CONTROL_USER}:{CONTROL_USER}", step=step
    )
    activation_written = _write_file_converged(
        ctx,
        activation_path,
        activation_content.encode("utf-8"),
        mode=0o644,
        uid=control_uid,
        gid=control_gid,
        step=step,
    )
    if written or activation_written:
        reload_argv = _control_systemctl("daemon-reload")
        completed = _run(ctx, reload_argv, step=step)
        _require(
            completed.returncode == 0,
            step,
            f"control daemon-reload failed: {completed.stderr.strip()[:200]}",
        )
    activation_unit = "stateport-accepted.target"
    before = _control_unit_observation(ctx, activation_unit, step=step)
    if before["enabled"] != "enabled":
        ctx.journal.append(
            {
                "kind": "control-unit-state-changed",
                "unit": activation_unit,
                "priorActive": bool(before["active"]),
                "priorEnabled": str(before["enabled"]),
                "trackEnabled": True,
            }
        )
        enable_argv = _control_systemctl("enable", activation_unit)
        enabled = _run(ctx, enable_argv, step=step)
        after = _control_unit_observation(ctx, activation_unit, step=step)
        _require(
            enabled.returncode == 0 and after["enabled"] == "enabled",
            step,
            f"control activation target enable failed: {enabled.stderr.strip()[:200]}",
        )
    return {
        "step": step,
        "result": "applied" if written or activation_written else "already-present",
        "commands": [],
        "detail": "",
    }


def _step_control_images(ctx: _Apply) -> dict[str, Any]:
    """Pull the control-plane images into the control user's rootless store."""
    step = "pull-control-plane-images"
    specs = ctx.plan["steps"]
    images_step = next(
        (entry for entry in specs if entry["step"] == step), None
    )
    images = images_step.get("images") if isinstance(images_step, Mapping) else []
    if not isinstance(images, list) or not images:
        return {"step": step, "result": "already-present", "commands": [], "detail": "no control-plane images in this plan"}
    _verify_user_environment(ctx, CONTROL_USER, step=step)
    pulled: list[list[str]] = []
    for image in images:
        reference = str(image["reference"])
        digest = str(image["digest"])
        argv = _as_user(
            ctx,
            CONTROL_USER,
            [
                _TRUSTED_EXECUTABLES["podman"],
                "pull",
                reference,
            ],
        )
        completed = _run(ctx, argv, step=step, timeout=3600)
        _require(
            completed.returncode == 0,
            step,
            f"podman pull as {CONTROL_USER} failed for {reference}: "
            f"{completed.stderr.strip()[:200]}",
        )
        inspected = _run(
            ctx,
            _as_user(
                ctx,
                CONTROL_USER,
                [
                    _TRUSTED_EXECUTABLES["podman"],
                    "image",
                    "inspect",
                    "--format",
                    "{{.Digest}}",
                    reference,
                ],
            ),
            step=step,
            timeout=120,
        )
        observed = "sha256:" + inspected.stdout.strip().removeprefix("sha256:")
        _require(
            inspected.returncode == 0 and observed == digest,
            step,
            f"control image {reference} in the {CONTROL_USER} store has digest "
            f"{observed} != signed {digest}",
        )
        pulled.append(argv)
        ctx.journal.append({"kind": "image-pulled", "reference": reference})
    return {
        "step": step,
        "result": "applied",
        "commands": [item for group in pulled for item in group],
        "detail": f"{len(images)} control images verified in the {CONTROL_USER} store",
    }


def _step_control_start(ctx: _Apply) -> dict[str, Any]:
    """Start the accepted control-plane units under the control user manager."""
    step = "start-control-plane-units"
    specs = ctx.plan["steps"]
    start_step = next((entry for entry in specs if entry["step"] == step), None)
    units = start_step.get("units") if isinstance(start_step, Mapping) else []
    if not isinstance(units, list) or not units:
        return {"step": step, "result": "already-present", "commands": [], "detail": "no control-plane units in this plan"}
    commands: list[list[str]] = []
    control_networks: dict[str, dict[str, Any]] = {}
    network_recovery_attempted = False
    active_container_seen = False

    def observe_start_convergence(
        service_name: str, completed: Completed
    ) -> dict[str, Any]:
        # A cold rootless start may remain activating for the whole readiness
        # window. Keep only the final poll in the receipt; every observation is
        # still executed, while steps[].commands remains within its schema cap.
        pre_poll_commands = list(ctx.current_commands)
        after = _control_unit_observation(ctx, service_name, step=step)
        if not after["active"] and after["state"] == "activating":
            deadline = time.monotonic() + READINESS_TIMEOUT_SECONDS
            while time.monotonic() < deadline:
                time.sleep(READINESS_POLL_SECONDS)
                ctx.current_commands[:] = pre_poll_commands
                after = _control_unit_observation(ctx, service_name, step=step)
                if after["active"] or after["state"] != "activating":
                    break
            if after["active"]:
                ctx.journal.append(
                    {
                        "kind": "control-unit-start-converged-after-restart",
                        "unit": service_name,
                        "initialReturnCode": completed.returncode,
                    }
                )
        return after

    def inspect_control_network(network: Mapping[str, Any]) -> None:
        network_name = str(network["name"])
        labels = dict(network["labels"])
        inspect = _as_user(
            ctx,
            CONTROL_USER,
            [_TRUSTED_EXECUTABLES["podman"], "network", "inspect", network_name],
        )
        inspected = _run(ctx, inspect, step=step, timeout=120)
        try:
            observed_value = json.loads(inspected.stdout)
            observed = observed_value[0] if isinstance(observed_value, list) else observed_value
        except (IndexError, json.JSONDecodeError, TypeError):
            observed = None
        observed_labels = (
            observed.get("labels", observed.get("Labels"))
            if isinstance(observed, Mapping)
            else None
        )
        observed_internal = (
            observed.get("internal", observed.get("Internal"))
            if isinstance(observed, Mapping)
            else None
        )
        observed_name = (
            observed.get("name", observed.get("Name"))
            if isinstance(observed, Mapping)
            else None
        )
        _require(
            inspected.returncode == 0
            and observed_name == network_name
            and observed_internal is True
            and observed_labels == labels,
            step,
            f"control network {network_name} does not match the signed internal labels",
        )
        commands.append(inspect)

    def ensure_control_network(
        network: Mapping[str, Any], *, replace: bool = False
    ) -> None:
        network_name = str(network["name"])
        labels = dict(network["labels"])
        if replace:
            # Only remove the same exact signed network shape that was observed
            # immediately before this bounded recovery transaction.
            inspect_control_network(network)
            remove = _as_user(
                ctx,
                CONTROL_USER,
                [_TRUSTED_EXECUTABLES["podman"], "network", "rm", network_name],
            )
            removed = _run(ctx, remove, step=step, timeout=300)
            _require(
                removed.returncode == 0,
                step,
                f"control network replacement could not remove {network_name}: "
                f"{removed.stderr.strip()[:200]}",
            )
            commands.append(remove)
            return
        ensure = _as_user(
            ctx,
            CONTROL_USER,
            [
                _TRUSTED_EXECUTABLES["podman"],
                "network",
                "create",
                *([] if replace else ["--ignore"]),
                "--internal",
                *[f"--label={key}={value}" for key, value in sorted(labels.items())],
                network_name,
            ],
        )
        ensured = _run(ctx, ensure, step=step, timeout=300)
        _require(
            ensured.returncode == 0,
            step,
            f"control network ensure failed for {network_name}: "
            f"{ensured.stderr.strip()[:200]}",
        )
        commands.append(ensure)
        inspect_control_network(network)
    # Quadlet network units must be started first: the containers reference
    # Network=<name> and podman refuses "network not found" if the network
    # service has not created the podman network yet.  A Quadlet `foo.network`
    # file generates the systemd unit `foo-network.service` (the `.network`
    # suffix maps to `-network.service`), so `systemctl start` must target the
    # generated `-network` service name, not the bare source-file basename.
    for unit in units:
        unit_name = PurePosixPath(unit).name
        if not unit_name.endswith(".network"):
            continue
        service_name = unit_name.removesuffix(".network") + "-network"
        before = _control_unit_observation(ctx, service_name, step=step)
        if before["active"]:
            continue
        ctx.journal.append(
            {
                "kind": "control-unit-state-changed",
                "unit": service_name,
                "priorActive": False,
                "priorEnabled": str(before["enabled"]),
                "trackEnabled": False,
            }
        )
        started_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f UTC")
        argv = _control_systemctl("start", service_name)
        completed = _run(ctx, argv, step=step, timeout=900)
        after = _control_unit_observation(ctx, service_name, step=step)
        _require(
            completed.returncode == 0 and after["active"],
            step,
            f"systemctl --user start {service_name} failed: "
            f"{completed.stderr.strip()[:200]}",
        )
        commands.append(argv)
    # The generated Quadlet network unit is the sole owner of normal network
    # creation. A second direct `podman network create --ignore` can leave
    # netavark's record split from the network observed during container init.
    # Only the bounded recovery below may replace a verified exact network.
    for spec in ctx.plan["writes"]:
        if not str(spec.get("path", "")).startswith(CONTROL_QUADLET_DIR + "/"):
            continue
        if not str(spec.get("path", "")).endswith(".network"):
            continue
        network_name = ""
        labels: dict[str, str] = {}
        internal = False
        for line in str(spec.get("content", "")).splitlines():
            if line.startswith("NetworkName="):
                network_name = line.split("=", 1)[1].strip()
            elif line.startswith("Label="):
                label = line.split("=", 1)[1].strip()
                key, separator, value = label.partition("=")
                _require(
                    bool(separator) and bool(key) and key not in labels,
                    step,
                    f"control network has an invalid label: {label}",
                )
                labels[key] = value
            elif line.startswith("Internal="):
                internal = line.split("=", 1)[1].strip().lower() == "true"
        _require(network_name and labels and internal, step, "control network shape is incomplete")
        network_unit = PurePosixPath(str(spec["path"])).name.removesuffix(".network")
        control_networks[network_name] = {
            "name": network_name,
            "labels": labels,
            "service": network_unit + "-network",
        }
        inspect_control_network(control_networks[network_name])
    for unit in units:
        unit_name = PurePosixPath(unit).name
        if not unit_name.endswith(".container"):
            continue
        service_name = unit_name.removesuffix(".container")
        # The container unit mounts the confined execution socket directory
        # read-only.  The tmpfiles step created it, but older rootless Podman
        # rootless start resolves the mount source from the control user's
        # view of /run; if the directory is absent or the parent is not
        # traversable the container fails at exec with
        # "statfs .../execution-control: no such file or directory".  Ensure
        # the socket directory (and its 0755 parent) exists with the signed
        # ownership/mode immediately before each control container starts.
        socket_parent = str(PurePosixPath(str(ctx.plan["socketDirectory"])).parent)
        root_account = ctx.accounts.user("root")
        _require(root_account is not None, step, "the root account is not resolvable")
        for directory, mode, uid, gid in (
            (socket_parent, 0o755, root_account.uid, root_account.gid),
            (
                str(ctx.plan["socketDirectory"]),
                int(str(ctx.plan["socketDirectoryMode"]), 8),
                ctx.exec_uid,
                ctx.group_gid,
            ),
        ):
            _ensure_directory_converged(
                ctx,
                directory,
                mode=mode,
                uid=uid,
                gid=gid,
                step=step,
            )
        before = _control_unit_observation(ctx, service_name, step=step)
        if before["active"]:
            continue
        ctx.journal.append(
            {
                "kind": "control-unit-state-changed",
                "unit": service_name,
                "priorActive": False,
                "priorEnabled": str(before["enabled"]),
                "trackEnabled": False,
            }
        )
        argv = _control_systemctl("start", service_name)
        completed = _run(ctx, argv, step=step, timeout=900)
        after = observe_start_convergence(service_name, completed)
        if not after["active"] and not network_recovery_attempted and not active_container_seen:
            journal = _run(
                ctx,
                _as_user(
                    ctx,
                    CONTROL_USER,
                    [
                        _TRUSTED_EXECUTABLES["journalctl"],
                        "--user",
                        "--unit",
                        service_name,
                        "--since",
                        started_at,
                        "--no-pager",
                        "--lines",
                        "200",
                    ],
                ),
                step=step,
                timeout=60,
            )
            journal_text = journal.stdout + "\n" + journal.stderr
            matching_networks = [
                network
                for network_name, network in control_networks.items()
                if (
                    f'IPAM error: could not find network "{network_name}"' in journal_text
                    or f"unable to find network with name or ID {network_name}: network not found"
                    in journal_text
                )
            ]
            if len(matching_networks) == 1:
                network_recovery_attempted = True
                network = matching_networks[0]
                network_service = str(network["service"])
                ctx.journal.append(
                    {
                        "kind": "control-network-recovery-attempted",
                        "network": str(network["name"]),
                        "service": network_service,
                        "failedUnit": service_name,
                        "trigger": "exact-ipam-network-not-found",
                    }
                )
                stop_container = _control_systemctl("stop", service_name)
                stopped = _run(ctx, stop_container, step=step, timeout=900)
                container_after_stop = _control_unit_observation(ctx, service_name, step=step)
                _require(
                    stopped.returncode == 0 and not container_after_stop["active"],
                    step,
                    f"one-shot recovery could not quiesce {service_name}: "
                    f"{stopped.stderr.strip()[:200]}",
                )
                commands.append(stop_container)
                stop_network = _control_systemctl("stop", network_service)
                network_stopped = _run(ctx, stop_network, step=step, timeout=900)
                network_after_stop = _control_unit_observation(
                    ctx, network_service, step=step
                )
                _require(
                    network_stopped.returncode == 0
                    and not network_after_stop["active"],
                    step,
                    f"one-shot recovery could not stop {network_service}: "
                    f"{network_stopped.stderr.strip()[:200]}",
                )
                commands.append(stop_network)
                ensure_control_network(network, replace=True)
                start_network = _control_systemctl("start", network_service)
                network_started = _run(ctx, start_network, step=step, timeout=900)
                network_after_start = _control_unit_observation(
                    ctx, network_service, step=step
                )
                _require(
                    network_started.returncode == 0 and network_after_start["active"],
                    step,
                    f"one-shot recovery could not start {network_service}: "
                    f"{network_started.stderr.strip()[:200]}",
                )
                commands.append(start_network)
                # Let the signed Quadlet network unit own recreation. A direct
                # create here can leave netavark's network record split from
                # the network observed by Podman during container init.
                inspect_control_network(network)
                restart_container = _control_systemctl("start", service_name)
                restarted = _run(ctx, restart_container, step=step, timeout=900)
                after = observe_start_convergence(service_name, restarted)
                commands.append(restart_container)
                if after["active"]:
                    ctx.journal.append(
                        {
                            "kind": "control-network-recovery-converged",
                            "network": str(network["name"]),
                            "service": network_service,
                            "recoveredUnit": service_name,
                            "restartReturnCode": restarted.returncode,
                        }
                    )
        if not after["active"]:
            container_log = ""
            try:
                logs = _run(
                    ctx,
                    _as_user(
                        ctx,
                        CONTROL_USER,
                        [
                            _TRUSTED_EXECUTABLES["podman"],
                            "logs",
                            "--tail",
                            "50",
                            service_name,
                        ],
                    ),
                    step=step,
                    timeout=60,
                )
                container_log = logs.stdout.strip()
            except Exception:  # noqa: BLE001 — diagnostics are best-effort
                pass
            detail = f"systemctl --user start {service_name} failed"
            if container_log:
                detail += " | container: " + container_log[:160]
                ctx.journal.append(
                    {
                        "kind": "control-container-log",
                        "service": service_name,
                        "log": container_log[-4000:],
                    }
                )
            try:
                networks = _run(
                    ctx,
                    _as_user(
                        ctx,
                        CONTROL_USER,
                        [_TRUSTED_EXECUTABLES["podman"], "network", "ls"],
                    ),
                    step=step,
                    timeout=60,
                )
                if networks.stdout.strip():
                    ctx.journal.append(
                        {
                            "kind": "control-network-list",
                            "networks": networks.stdout.strip()[-2000:],
                        }
                    )
            except Exception:  # noqa: BLE001 — diagnostics are best-effort
                pass
            try:
                status = _run(
                    ctx,
                    _control_systemctl("status", service_name, "--full", "--no-pager", "-n", "40"),
                    step=step,
                    timeout=60,
                )
                if status.stdout.strip():
                    detail += " | status: " + status.stdout.strip()[:200]
                    _write_diagnostic_sidecar(ctx, f"{service_name}.status.txt", status.stdout.strip())
            except Exception:  # noqa: BLE001 — diagnostics are best-effort
                pass
            detail += " | systemctl: " + completed.stderr.strip()[:60]
            _write_diagnostic_sidecar(
                ctx,
                f"{service_name}.start-stderr.txt",
                completed.stderr.strip(),
            )
            if container_log:
                _write_diagnostic_sidecar(ctx, f"{service_name}.log.txt", container_log)
            _require(False, step, detail)
        commands.append(argv)
        active_container_seen = True
    return {
        "step": step,
        "result": "applied",
        "commands": commands,
        "detail": f"{len(commands)} control-plane units started",
    }


def _verify_user_environment(ctx: _Apply, user_name: str, *, step: str) -> None:
    account = ctx.accounts.user(user_name)
    _require(account is not None, step, f"account is absent: {user_name}")
    script = (
        "import json,os;"
        "print(json.dumps({'uid':os.getuid(),'gid':os.getgid(),'groups':os.getgroups(),"
        "'environment':dict(os.environ)},sort_keys=True))"
    )
    argv = _as_user(ctx, user_name, [sys.executable, "-c", script])
    completed = _run(ctx, argv, step=step, timeout=60)
    try:
        payload = json.loads(completed.stdout.strip())
    except (json.JSONDecodeError, TypeError) as exc:
        raise StepFailed(step, f"cannot observe the sanitized {user_name} environment") from exc
    environment = payload.get("environment") if isinstance(payload, Mapping) else None
    expected = {
        "HOME": account.home,
        "LOGNAME": user_name,
        "USER": user_name,
        "XDG_CONFIG_HOME": f"{account.home}/.config",
        "XDG_DATA_HOME": f"{account.home}/.local/share",
        "XDG_RUNTIME_DIR": f"/run/user/{account.uid}",
        "XDG_STATE_HOME": f"{account.home}/.local/state",
    }
    _require(
        completed.returncode == 0
        and isinstance(environment, Mapping)
        and payload.get("uid") == account.uid
        and payload.get("gid") == account.gid
        and all(environment.get(key) == value for key, value in expected.items())
        and ctx.group_gid in payload.get("groups", []),
        step,
        f"{user_name} HOME/XDG/uid/gid/supplementary-group identity is not exact",
    )
    forbidden = {
        "CONTAINER_HOST",
        "DOCKER_CONFIG",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "REGISTRY_AUTH_FILE",
    }
    _require(
        not (forbidden & set(environment)),
        step,
        f"{user_name} inherited forbidden process/container variables: "
        f"{sorted(forbidden & set(environment))}",
    )


def _step_image(ctx: _Apply) -> dict[str, Any]:
    step = "pull-execution-host-image"
    image = ctx.plan["image"]
    reference = str(image["reference"])
    digest = str(image["digest"])
    _verify_user_environment(ctx, EXEC_USER, step=step)
    storage_argv = _as_exec(
        ctx,
        [
            _TRUSTED_EXECUTABLES["podman"],
            "info",
            "--format",
            "{{.Store.GraphRoot}}|{{.Store.RunRoot}}|{{.Host.OCIRuntime.Name}}",
        ],
    )
    storage = _run(ctx, storage_argv, step=step, timeout=120)
    graph_root, separator, remainder = storage.stdout.strip().partition("|")
    run_root, separator_two, runtime_name = remainder.partition("|")
    _require(
        storage.returncode == 0
        and bool(separator)
        and bool(separator_two)
        and graph_root == f"{EXEC_HOME}/.local/share/containers/storage"
        and run_root == f"/run/user/{ctx.exec_uid}/containers"
        and runtime_name == "runc",
        step,
        "stateport-exec rootless Podman storage/runtime identity is not exact: "
        f"graphRoot={graph_root!r} runRoot={run_root!r} runtime={runtime_name!r}",
    )
    for storage_path in (graph_root, run_root):
        observed_storage = _observe_directory(
            ctx.layout,
            storage_path,
            step=step,
            description=f"stateport-exec rootless storage directory {storage_path}",
        )
        _require(
            observed_storage.st_uid == ctx.exec_uid
            and observed_storage.st_gid == ctx.exec_gid
            and stat.S_IMODE(observed_storage.st_mode) & 0o077 == 0,
            step,
            f"stateport-exec rootless storage directory is not private: {storage_path} "
            f"uid={observed_storage.st_uid} gid={observed_storage.st_gid} "
            f"mode={oct(stat.S_IMODE(observed_storage.st_mode))}",
        )

    def observed_digest() -> str | None:
        argv = _as_exec(
            ctx,
            [
                _TRUSTED_EXECUTABLES["podman"],
                "image",
                "inspect",
                "--format",
                "{{.Digest}}",
                reference,
            ],
        )
        completed = _run(ctx, argv, step=step, timeout=120)
        if completed.returncode != 0:
            return None
        return "sha256:" + completed.stdout.strip().removeprefix("sha256:")

    observed = observed_digest()
    if observed == digest:
        ctx.image_observed = observed
        return {"step": step, "result": "already-present", "commands": [], "detail": ""}
    pull_argv = _as_exec(ctx, [_TRUSTED_EXECUTABLES["podman"], "pull", reference])
    completed = _run(ctx, pull_argv, step=step, timeout=3600)
    _require(
        completed.returncode == 0,
        step,
        f"podman pull as {EXEC_USER} failed: {completed.stderr.strip()[:200]}",
    )
    observed = observed_digest()
    _require(
        observed == digest,
        step,
        f"image in the {EXEC_USER} rootless store has digest {observed} != signed "
        f"{digest}; a pull into any other store is not evidence",
    )
    ctx.image_observed = observed
    ctx.journal.append({"kind": "image-pulled", "reference": reference})
    return {"step": step, "result": "applied", "commands": [pull_argv], "detail": ""}


def _stat_anchored(layout: HostLayout, absolute: str, *, step: str) -> os.stat_result:
    parts = _host_parts(absolute)
    if not parts:
        raise StepFailed(step, "the trusted root has no child entry")
    parent = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
    with _open_directory_chain(layout, parent, step=step) as chain:
        try:
            observed = os.stat(parts[-1], dir_fd=chain.fds[-1], follow_symlinks=False)
        except FileNotFoundError as exc:
            raise StepFailed(step, f"path is absent: {absolute}") from exc
        chain.verify(step=step)
        return observed


def _readlink_anchored(
    layout: HostLayout, absolute: str, *, step: str, absent_ok: bool = False
) -> str | None:
    parts = _host_parts(absolute)
    parent = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
    with _open_directory_chain(layout, parent, step=step) as chain:
        try:
            observed = os.stat(parts[-1], dir_fd=chain.fds[-1], follow_symlinks=False)
        except FileNotFoundError:
            if absent_ok:
                return None
            raise StepFailed(step, f"durable unit link is absent: {absolute}") from None
        if not stat.S_ISLNK(observed.st_mode):
            raise StepFailed(step, f"durable unit link is not a symlink: {absolute}")
        target = os.readlink(parts[-1], dir_fd=chain.fds[-1])
        after = os.stat(parts[-1], dir_fd=chain.fds[-1], follow_symlinks=False)
        if _stat_fingerprint(after) != _stat_fingerprint(observed):
            raise StepFailed(step, f"durable unit link changed while reading: {absolute}")
        chain.verify(step=step)
        return target


def _systemctl_value(ctx: _Apply, unit: str, property_name: str, *, step: str) -> str:
    argv = _as_exec(
        ctx,
        [
            _TRUSTED_EXECUTABLES["systemctl"],
            "--user",
            "show",
            f"--property={property_name}",
            "--value",
            unit,
        ],
    )
    completed = _run(ctx, argv, step=step, timeout=60)
    return completed.stdout.strip() if completed.returncode == 0 else ""


def _unit_observation(ctx: _Apply, unit: str, *, step: str) -> dict[str, Any]:
    active_argv = _as_exec(
        ctx, [_TRUSTED_EXECUTABLES["systemctl"], "--user", "is-active", unit]
    )
    active = _run(ctx, active_argv, step=step, timeout=60)
    enabled_argv = _as_exec(
        ctx, [_TRUSTED_EXECUTABLES["systemctl"], "--user", "is-enabled", unit]
    )
    enabled = _run(ctx, enabled_argv, step=step, timeout=60)
    return {
        "active": active.returncode == 0 and active.stdout.strip() == "active",
        "enabled": enabled.stdout.strip(),
        "fragment": _systemctl_value(ctx, unit, "FragmentPath", step=step),
        "source": _systemctl_value(ctx, unit, "SourcePath", step=step),
    }


def _control_unit_observation(ctx: _Apply, unit: str, *, step: str) -> dict[str, Any]:
    active = _run(ctx, _control_systemctl("is-active", unit), step=step, timeout=60)
    enabled = _run(ctx, _control_systemctl("is-enabled", unit), step=step, timeout=60)
    state = active.stdout.strip()
    return {
        "active": active.returncode == 0 and state == "active",
        "state": state,
        "enabled": enabled.stdout.strip(),
    }


def _verify_unit_fragment(ctx: _Apply, unit: str, observed: Mapping[str, Any], *, step: str) -> None:
    if unit == DAEMON_UNIT:
        expected_fragment = f"/run/user/{ctx.exec_uid}/systemd/generator/{DAEMON_UNIT}"
        expected_source = f"{QUADLET_DIR}/stateport-execution-host.container"
        _require(
            observed["fragment"] == expected_fragment and observed["source"] == expected_source,
            step,
            f"unit {unit} fragment/source identity diverges: fragment={observed['fragment']!r} "
            f"source={observed['source']!r}",
        )
        fragment_bytes, fragment_stat = _read_regular_file(
            ctx.layout, expected_fragment, step=step
        )
        source_bytes, source_stat = _read_regular_file(ctx.layout, expected_source, step=step)
        source_spec = next(
            spec for spec in ctx.plan["writes"] if spec["path"] == expected_source
        )
        _require(
            fragment_stat is not None
            and source_stat is not None
            and bool(fragment_bytes)
            and fragment_stat.st_uid == ctx.exec_uid
            and fragment_stat.st_gid == ctx.exec_gid
            and stat.S_IMODE(fragment_stat.st_mode) & 0o022 == 0
            and source_stat.st_uid == ctx.exec_uid
            and source_stat.st_gid == ctx.exec_gid
            and stat.S_IMODE(source_stat.st_mode) == int(str(source_spec["mode"]), 8)
            and canonical_digest(source_bytes.decode("utf-8"))
            == source_spec["contentDigest"],
            step,
            f"unit {unit} generated fragment or Quadlet source identity is not exact",
        )
        return
    allowed_fragments = {
        "/usr/lib/systemd/user/podman.socket",
        "/usr/local/lib/systemd/user/podman.socket",
    }
    _require(
        observed["fragment"] in allowed_fragments and observed["source"] == "",
        step,
        f"unit {unit} is not the trusted vendor Podman socket: "
        f"fragment={observed['fragment']!r} source={observed['source']!r}",
    )
    content, file_stat = _read_regular_file(
        ctx.layout, str(observed["fragment"]), step=step
    )
    root = ctx.accounts.user("root")
    _require(root is not None, step, "the root account is not resolvable")
    _require(
        file_stat is not None
        and bool(content)
        and file_stat.st_uid == root.uid
        and file_stat.st_gid == root.gid
        and stat.S_IMODE(file_stat.st_mode) & 0o022 == 0,
        step,
        f"unit {unit} vendor fragment ownership/mode is not trusted",
    )


def _verify_unit_durable(ctx: _Apply, unit: str, observed: Mapping[str, Any], *, step: str) -> None:
    _verify_unit_fragment(ctx, unit, observed, step=step)
    if unit == DAEMON_UNIT:
        _require(
            observed["enabled"] == "generated",
            step,
            f"unit {unit} is not durably generator-enabled: {observed['enabled']!r}",
        )
        link = f"/run/user/{ctx.exec_uid}/systemd/generator/default.target.wants/{DAEMON_UNIT}"
        target = _readlink_anchored(ctx.layout, link, step=step)
        _require(
            target == f"../{DAEMON_UNIT}",
            step,
            f"unit {unit} has a foreign generated WantedBy link: {target!r}",
        )
        return
    _require(
        observed["enabled"] == "enabled",
        step,
        f"unit {unit} is not durably enabled: {observed['enabled']!r}",
    )
    link = f"{EXEC_CONFIG_DIR}/systemd/user/sockets.target.wants/{unit}"
    target = _readlink_anchored(ctx.layout, link, step=step)
    _require(
        target == observed["fragment"],
        step,
        f"unit {unit} has a foreign enablement link: {target!r}",
    )


def _step_unit(ctx: _Apply, unit: str, *, step: str) -> dict[str, Any]:
    reload_argv = _as_exec(
        ctx, [_TRUSTED_EXECUTABLES["systemctl"], "--user", "daemon-reload"]
    )
    reloaded = _run(ctx, reload_argv, step=step)
    _require(
        reloaded.returncode == 0,
        step,
        f"daemon-reload failed: {reloaded.stderr.strip()[:200]}",
    )
    before = _unit_observation(ctx, unit, step=step)
    _verify_unit_fragment(ctx, unit, before, step=step)
    if before["active"]:
        _verify_unit_durable(ctx, unit, before, step=step)
        return {"step": step, "result": "already-present", "commands": [], "detail": ""}
    action = "start" if unit == DAEMON_UNIT else "enable"
    arguments = [
        _TRUSTED_EXECUTABLES["systemctl"],
        "--user",
        action,
        *( [] if unit == DAEMON_UNIT else ["--now"] ),
        unit,
    ]
    action_argv = _as_exec(ctx, arguments)
    ctx.journal.append(
        {
            "kind": "unit-state-changed",
            "unit": unit,
            "priorActive": bool(before["active"]),
            "priorEnabled": str(before["enabled"]),
        }
    )
    completed = _run(ctx, action_argv, step=step, timeout=900)
    after = _unit_observation(ctx, unit, step=step)
    if not after["active"]:
        detail = (
            f"unit {unit} is not active after {action} (rc={completed.returncode}): "
            f"{completed.stderr.strip()[:200]}"
        )
        container_log = ""
        try:
            logs = _run(
                ctx,
                _as_exec(
                    ctx,
                    [
                        _TRUSTED_EXECUTABLES["podman"],
                        "logs",
                        "--tail",
                        "50",
                        unit.removesuffix(".service"),
                    ],
                ),
                step=step,
                timeout=60,
            )
            container_log = logs.stdout.strip() or logs.stderr.strip()
            if container_log:
                detail += " | container: " + container_log[:400]
                _write_diagnostic_sidecar(
                    ctx, f"{unit.removesuffix('.service')}.log.txt", container_log
                )
        except Exception:  # noqa: BLE001 — diagnostics are best-effort
            pass
        try:
            status = _run(
                ctx,
                _as_exec(
                    ctx,
                    [
                        _TRUSTED_EXECUTABLES["systemctl"],
                        "--user",
                        "status",
                        unit,
                        "--full",
                        "--no-pager",
                        "-n",
                        "80",
                    ],
                ),
                step=step,
                timeout=60,
            )
            status_text = status.stdout.strip() or status.stderr.strip()
            if status_text:
                detail += " | status: " + status_text[:240]
                _write_diagnostic_sidecar(
                    ctx, f"{unit.removesuffix('.service')}.status.txt", status_text
                )
        except Exception:  # noqa: BLE001 — diagnostics are best-effort
            pass
        _write_diagnostic_sidecar(
            ctx,
            f"{unit.removesuffix('.service')}.start-stderr.txt",
            completed.stderr.strip(),
        )
        _require(False, step, detail)
    _verify_unit_durable(ctx, unit, after, step=step)
    detail = "" if completed.returncode == 0 else f"postcondition observed after rc={completed.returncode}"
    return {"step": step, "result": "applied", "commands": [], "detail": detail}


def _step_engine_socket(ctx: _Apply) -> dict[str, Any]:
    return _step_unit(ctx, ENGINE_SOCKET_UNIT, step="start-exec-user-engine-socket")


def _step_daemon(ctx: _Apply) -> dict[str, Any]:
    return _step_unit(ctx, DAEMON_UNIT, step="start-execution-host-daemon")


def _step_grant(ctx: _Apply) -> dict[str, Any]:
    """Write the provisioned control-plane grant into the daemon-owned store.

    The daemon's grant store is a directory owned by ``stateport-exec`` inside
    the confined state directory; the root transaction writes the grant
    document there with exact ownership/mode and validates it against the
    daemon contract before and after publication.  The revocation document is
    daemon-initialized at boot; a missing or corrupt one fails closed at the
    daemon, so the grant write only ever ADDS an exact document.
    """
    step = "provision-execution-host-grant"
    spec = ctx.plan["steps"]
    grant_spec = next(
        (entry["grant"] for entry in spec if entry["step"] == step), None
    )
    if not isinstance(grant_spec, Mapping):
        raise StepFailed(step, "the provisioning plan lacks the control-plane grant")
    try:
        from execution_host import daemon_contract  # noqa: PLC0415
    except ImportError as exc:
        raise StepFailed(step, "the daemon contract module is unavailable") from exc
    try:
        validated = daemon_contract.validate_grant_document(grant_spec)
    except ValueError as exc:
        raise StepFailed(step, f"the control-plane grant is invalid: {exc}") from exc
    grants_dir = str(ctx.plan["grantsDirectory"])
    grant_path = f"{grants_dir}/{DEFAULT_GRANT_ID}.json"
    content = (json.dumps(validated, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _ensure_directory_converged(
        ctx,
        grants_dir,
        mode=0o700,
        uid=ctx.exec_uid,
        gid=ctx.exec_gid,
        step=step,
    )
    _write_file_converged(
        ctx,
        grant_path,
        content,
        mode=0o600,
        uid=ctx.exec_uid,
        gid=ctx.exec_gid,
        step=step,
        journal_kind="grant-written",
    )
    observed_content, observed = _read_regular_file(ctx.layout, grant_path, step=step)
    _require(
        observed is not None
        and observed_content == content
        and observed.st_uid == ctx.exec_uid
        and observed.st_gid == ctx.exec_gid
        and stat.S_IMODE(observed.st_mode) == 0o600,
        step,
        "control-plane grant publication observation failed",
    )
    ctx.grant_digest = daemon_contract.canonical_digest(validated)
    return {
        "step": step,
        "result": "applied",
        "commands": [],
        "detail": f"grant {DEFAULT_GRANT_ID} written with digest {ctx.grant_digest[:24]}…",
    }


def _step_health(ctx: _Apply) -> dict[str, Any]:
    step = "verify-protocol-health"
    socket_path = str(ctx.plan["socketPath"])
    # Root-side inode hygiene before delegating the protocol request.
    _observe_directory(
        ctx.layout,
        str(PurePosixPath(socket_path).parent),
        step=step,
        description="socket directory",
    )
    peer_users = (EXEC_USER, str(ctx.plan["allowedClientUser"]))
    deadline = time.monotonic() + READINESS_TIMEOUT_SECONDS
    last_detail = f"empty socket directory: {socket_path} does not exist; the daemon is not up"
    # The readiness loop polls until the daemon answers; a slow first start
    # may take many attempts. Record only the final attempt's commands so the
    # receipt stays inside the schema bound (steps[].commands maxItems)
    # regardless of how many polls were needed.
    pre_loop_commands = list(ctx.current_commands)

    def require_active() -> None:
        service = _unit_observation(ctx, DAEMON_UNIT, step=step)
        if not service["active"]:
            detail = f"unit {DAEMON_UNIT} exited during startup readiness"
            try:
                logs = _run(
                    ctx,
                    _as_exec(
                        ctx,
                        [
                            _TRUSTED_EXECUTABLES["podman"],
                            "logs",
                            "--tail",
                            "50",
                            DAEMON_UNIT.removesuffix(".service"),
                        ],
                    ),
                    step=step,
                    timeout=60,
                )
                if logs.stdout.strip():
                    detail += " | container: " + logs.stdout.strip()[:400]
            except Exception:  # noqa: BLE001 — diagnostics are best-effort
                pass
            _require(False, step, detail)
        _verify_unit_durable(ctx, DAEMON_UNIT, service, step=step)

    while True:
        ctx.current_commands[:] = pre_loop_commands
        require_active()
        probe_results: list[dict[str, Any]] = []
        contract_version: int | None = None
        transient = False
        try:
            observed = _stat_anchored(ctx.layout, socket_path, step=step)
        except StepFailed as exc:
            if "path is absent" not in exc.detail:
                raise
            transient = True
        else:
            _require(
                stat.S_ISSOCK(observed.st_mode),
                step,
                f"socket path is not a socket: {socket_path}",
            )
            _require(
                observed.st_uid == ctx.exec_uid
                and observed.st_gid == ctx.group_gid
                and stat.S_IMODE(observed.st_mode) == int(str(ctx.plan["socketMode"]), 8),
                step,
                f"socket ownership/mode mismatch: uid={observed.st_uid} gid={observed.st_gid} "
                f"mode={oct(stat.S_IMODE(observed.st_mode))}",
            )
            for peer_user in peer_users:
                require_active()
                _verify_user_environment(ctx, peer_user, step=step)
                probe_argv = _as_user(
                    ctx,
                    peer_user,
                    [
                        sys.executable,
                        "-m",
                        "stateport_release.execution_host_provisioning",
                        "health-probe",
                        "--socket",
                        socket_path,
                        "--expected-uid",
                        str(ctx.exec_uid),
                        "--expected-gid",
                        str(ctx.group_gid),
                        "--expected-mode",
                        str(ctx.plan["socketMode"]),
                        "--expected-contract-version",
                        str(ctx.plan["contractVersion"]),
                    ],
                    extra_environment={"PYTHONPATH": _probe_pythonpath()},
                )
                remaining = max(1, min(120, int(deadline - time.monotonic() + 0.999)))
                completed = _run(ctx, probe_argv, step=step, timeout=remaining)
                require_active()
                payload: dict[str, Any] | None = None
                candidate = parse_last_line_json(completed.stdout)
                if isinstance(candidate, dict) and "healthy" in candidate:
                    payload = candidate
                healthy = (
                    completed.returncode == 0
                    and payload is not None
                    and payload.get("healthy") is True
                )
                reason = None if healthy else str((payload or {}).get("reason") or "probe-failed")[:80]
                probe_results.append(
                    {
                        "peerUser": peer_user,
                        "healthy": healthy,
                        "contractVersion": payload.get("contractVersion") if payload is not None else None,
                        "reason": reason,
                    }
                )
                if not healthy:
                    last_detail = (
                        str((payload or {}).get("detail") or completed.stderr.strip())[:300]
                        or f"describeCapabilities as {peer_user} failed: {reason}"
                    )
                    transient = reason == "stale-socket-inode"
                    break
                observed_version = payload.get("contractVersion")
                if contract_version is None:
                    contract_version = observed_version
                _require(
                    observed_version == contract_version,
                    step,
                    "daemon self-health and allowed-client health report different contracts",
                )
            if (
                not transient
                and len(probe_results) == len(peer_users)
                and all(result["healthy"] for result in probe_results)
            ):
                ctx.health = {
                    "kind": "describeCapabilities",
                    "socketPath": socket_path,
                    "peerUsers": list(peer_users),
                    "status": "healthy",
                    "healthy": True,
                    "contractVersion": contract_version,
                    "refusal": None,
                    "probes": probe_results,
                }
                return {"step": step, "result": "applied", "commands": [], "detail": ""}
            if not transient:
                ctx.health = {
                    "kind": "describeCapabilities",
                    "socketPath": socket_path,
                    "peerUsers": list(peer_users),
                    "status": "failed",
                    "healthy": False,
                    "contractVersion": contract_version,
                    "refusal": last_detail,
                    "probes": probe_results,
                }
                raise StepFailed(step, last_detail)

        remaining_seconds = deadline - time.monotonic()
        if remaining_seconds <= 0:
            ctx.health = {
                "kind": "describeCapabilities",
                "socketPath": socket_path,
                "peerUsers": list(peer_users),
                "status": "failed",
                "healthy": False,
                "contractVersion": contract_version,
                "refusal": last_detail,
                "probes": probe_results,
            }
            raise StepFailed(step, f"startup readiness timed out: {last_detail}")
        time.sleep(min(READINESS_POLL_SECONDS, remaining_seconds))


_STEP_HANDLERS: dict[str, Callable[[_Apply], dict[str, Any]]] = {
    "verify-rootless-supplementary-group-contract": _step_rootless_group_contract,
    "ensure-execution-control-group": _step_group,
    "ensure-stateport-control-user": _step_control_user,
    "ensure-stateport-exec-user": _step_user,
    "confine-execution-user-group": _step_confine_exec,
    "confine-control-plane-client": _step_confine_client,
    "establish-subordinate-mappings": _step_subids,
    "create-host-directories": _step_directories,
    "write-confined-socket-tmpfiles": _step_tmpfiles,
    "enable-control-user-linger": _step_control_linger,
    "enable-exec-user-linger": _step_exec_linger,
    "install-stable-host-quadlets": _step_quadlets,
    "install-control-plane-units": _step_control_units,
    "pull-control-plane-images": _step_control_images,
    "pull-execution-host-image": _step_image,
    "start-exec-user-engine-socket": _step_engine_socket,
    "start-execution-host-daemon": _step_daemon,
    "provision-execution-host-grant": _step_grant,
    "start-control-plane-units": _step_control_start,
    "verify-protocol-health": _step_health,
}


# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------


def _matches_journal_inode(observed: os.stat_result, expected: Mapping[str, Any]) -> bool:
    return observed.st_dev == expected["dev"] and observed.st_ino == expected["ino"]


def _current_file_for_rollback(
    ctx: _Apply, entry: Mapping[str, Any]
) -> tuple[bytes, os.stat_result] | None:
    try:
        content, observed = _read_regular_file(
            ctx.layout, str(entry["path"]), step="rollback", absent_ok=True
        )
    except StepFailed:
        raise
    if observed is None:
        return None
    applied = entry["appliedStat"]
    if (
        content != entry["content"]
        or not _matches_journal_inode(observed, applied)
        or observed.st_uid != applied["uid"]
        or observed.st_gid != applied["gid"]
        or stat.S_IMODE(observed.st_mode) != applied["mode"]
    ):
        recovery = entry.get("recoveryPath")
        if recovery:
            detail = f"prior retained at {recovery}; foreign destination preserved"
        else:
            detail = f"{entry['path']} changed since this transaction; foreign state is preserved"
        raise StepFailed(
            "rollback",
            detail,
        )
    return content, observed


def _exchange_file_for_rollback(
    ctx: _Apply,
    path: str,
    *,
    expected: os.stat_result,
    content: bytes,
    mode: int,
    uid: int,
    gid: int,
) -> None:
    parts = _host_parts(path)
    parent = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
    name = parts[-1]
    with _open_directory_chain(ctx.layout, parent, step="rollback") as chain:
        dir_fd = chain.fds[-1]
        current = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        if not _same_inode(current, expected):
            raise StepFailed("rollback", f"rollback destination inode changed: {path}")
        temp_name = f".{name}.rollback-{os.getpid()}-{secrets.token_hex(8)}"
        temp_fd = os.open(
            temp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=dir_fd,
        )
        try:
            with os.fdopen(temp_fd, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fchown(handle.fileno(), uid, gid)
                os.fchmod(handle.fileno(), mode)
                os.fsync(handle.fileno())
            chain.verify(step="rollback")
            _renameat2(dir_fd, temp_name, name, _RENAME_EXCHANGE)
            exchanged = os.stat(temp_name, dir_fd=dir_fd, follow_symlinks=False)
            if not _same_inode(exchanged, expected):
                _renameat2(dir_fd, temp_name, name, _RENAME_EXCHANGE)
                raise StepFailed("rollback", f"rollback file CAS lost a race: {path}")
            os.unlink(temp_name, dir_fd=dir_fd)
            temp_name = ""
            os.fsync(dir_fd)
            chain.verify(step="rollback")
        finally:
            if temp_name:
                try:
                    os.unlink(temp_name, dir_fd=dir_fd)
                except OSError:
                    pass
    restored, restored_stat = _read_regular_file(ctx.layout, path, step="rollback")
    if (
        restored_stat is None
        or restored != content
        or restored_stat.st_uid != uid
        or restored_stat.st_gid != gid
        or stat.S_IMODE(restored_stat.st_mode) != mode
    ):
        raise StepFailed("rollback", f"rollback post-observation failed: {path}")


def _remove_file_for_rollback(ctx: _Apply, path: str, expected: os.stat_result) -> None:
    parts = _host_parts(path)
    parent = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
    name = parts[-1]
    with _open_directory_chain(ctx.layout, parent, step="rollback") as chain:
        dir_fd = chain.fds[-1]
        current = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        if not _same_inode(current, expected):
            raise StepFailed("rollback", f"remove-file inode changed: {path}")
        placeholder = f".{name}.remove-{os.getpid()}-{secrets.token_hex(8)}"
        placeholder_fd = os.open(
            placeholder,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o000,
            dir_fd=dir_fd,
        )
        placeholder_stat = os.fstat(placeholder_fd)
        os.close(placeholder_fd)
        try:
            chain.verify(step="rollback")
            _renameat2(dir_fd, placeholder, name, _RENAME_EXCHANGE)
            removed = os.stat(placeholder, dir_fd=dir_fd, follow_symlinks=False)
            installed_placeholder = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            if not _same_inode(removed, expected) or not _same_inode(
                installed_placeholder, placeholder_stat
            ):
                _renameat2(dir_fd, placeholder, name, _RENAME_EXCHANGE)
                raise StepFailed("rollback", f"remove-file CAS lost a race: {path}")
            os.unlink(placeholder, dir_fd=dir_fd)
            placeholder = ""
            latest = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            if not _same_inode(latest, placeholder_stat):
                raise StepFailed("rollback", f"remove-file placeholder was swapped: {path}")
            os.unlink(name, dir_fd=dir_fd)
            os.fsync(dir_fd)
            chain.verify(step="rollback")
        finally:
            if placeholder:
                try:
                    os.unlink(placeholder, dir_fd=dir_fd)
                except OSError:
                    pass


def _rollback_regular_file(ctx: _Apply, entry: Mapping[str, Any]) -> tuple[str, str, str]:
    current = _current_file_for_rollback(ctx, entry)
    path = str(entry["path"])
    if current is None:
        return "remove-file", "done", "already absent"
    _content, observed = current
    prior = entry["prior"]
    if prior is None:
        _remove_file_for_rollback(ctx, path, observed)
        return "remove-file", "done", "transaction file removed"
    prior_stat = entry["priorStat"]
    _exchange_file_for_rollback(
        ctx,
        path,
        expected=observed,
        content=prior,
        mode=int(prior_stat["mode"]),
        uid=int(prior_stat["uid"]),
        gid=int(prior_stat["gid"]),
    )
    return "restore-file", "done", "pre-transaction bytes and metadata restored"


def _rollback_subid_line(ctx: _Apply, entry: Mapping[str, Any]) -> tuple[str, str, str]:
    path = str(entry["path"])
    content, observed = _read_regular_file(ctx.layout, path, step="rollback", absent_ok=True)
    if observed is None:
        return "remove-subordinate-id-line", "done", "already absent"
    applied = entry["appliedStat"]
    if not _matches_journal_inode(observed, applied):
        raise StepFailed("rollback", f"{path} inode changed; foreign account-tool bytes preserved")
    prior_value = entry["prior"]
    prior = prior_value or b""
    added = entry["addedBytes"]
    expected_prefix = prior + added
    if not content.startswith(expected_prefix):
        raise StepFailed("rollback", f"exact transaction line moved or changed in {path}")
    remainder = content[len(expected_prefix) :]
    restored = prior + remainder
    if prior_value is None and not restored:
        _remove_file_for_rollback(ctx, path, observed)
    else:
        prior_stat = entry["priorStat"] or {
            "mode": stat.S_IMODE(observed.st_mode),
            "uid": observed.st_uid,
            "gid": observed.st_gid,
        }
        _exchange_file_for_rollback(
            ctx,
            path,
            expected=observed,
            content=restored,
            mode=int(prior_stat["mode"]),
            uid=int(prior_stat["uid"]),
            gid=int(prior_stat["gid"]),
        )
    return "remove-subordinate-id-line", "done", "only the exact transaction line was removed"


def _rollback_directory_metadata(
    ctx: _Apply, entry: Mapping[str, Any]
) -> tuple[str, str, str]:
    path = str(entry["path"])
    with _open_directory_chain(ctx.layout, path, step="rollback") as chain:
        descriptor = chain.fds[-1]
        observed = os.fstat(descriptor)
        if not _matches_journal_inode(observed, entry):
            raise StepFailed("rollback", f"directory inode changed: {path}")
        expected_uid = int(entry["appliedUid"] if entry["ownerChanged"] else entry["uid"])
        expected_gid = int(entry["appliedGid"] if entry["ownerChanged"] else entry["gid"])
        expected_mode = int(entry["appliedMode"] if entry["modeChanged"] else entry["mode"])
        prior_state = (
            int(entry["uid"]),
            int(entry["gid"]),
            int(entry["mode"]),
        )
        current_state = (
            observed.st_uid,
            observed.st_gid,
            stat.S_IMODE(observed.st_mode),
        )
        if current_state == prior_state:
            return "restore-directory-metadata", "done", "metadata was already restored"
        if current_state != (expected_uid, expected_gid, expected_mode):
            raise StepFailed(
                "rollback", f"directory metadata changed after apply; foreign state preserved: {path}"
            )
        if entry["ownerChanged"]:
            os.fchown(descriptor, int(entry["uid"]), int(entry["gid"]))
        if entry["ownerChanged"] or entry["modeChanged"]:
            os.fchmod(descriptor, int(entry["mode"]))
        final = os.fstat(descriptor)
        chain.verify(step="rollback")
        if (
            final.st_uid != entry["uid"]
            or final.st_gid != entry["gid"]
            or stat.S_IMODE(final.st_mode) != entry["mode"]
        ):
            raise StepFailed("rollback", f"directory metadata restore failed: {path}")
    return "restore-directory-metadata", "done", "pre-transaction owner/mode restored"


def _rollback_created_directory(
    ctx: _Apply, entry: Mapping[str, Any]
) -> tuple[str, str, str]:
    path = str(entry["path"])
    parts = _host_parts(path)
    parent = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
    name = parts[-1]
    try:
        with _open_directory_chain(ctx.layout, parent, step="rollback") as chain:
            dir_fd = chain.fds[-1]
            try:
                observed = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            except FileNotFoundError:
                return "remove-directory", "done", "already absent"
            if not stat.S_ISDIR(observed.st_mode) or not _matches_journal_inode(observed, entry):
                raise StepFailed("rollback", f"created directory inode changed: {path}")
            quarantine = f".{name}.remove-{os.getpid()}-{secrets.token_hex(8)}"
            _renameat2(dir_fd, name, quarantine, _RENAME_NOREPLACE)
            moved = os.stat(quarantine, dir_fd=dir_fd, follow_symlinks=False)
            if not _same_inode(moved, observed):
                _renameat2(dir_fd, quarantine, name, _RENAME_NOREPLACE)
                raise StepFailed("rollback", f"directory removal CAS lost a race: {path}")
            try:
                os.rmdir(quarantine, dir_fd=dir_fd)
            except OSError:
                _renameat2(dir_fd, quarantine, name, _RENAME_NOREPLACE)
                return "remove-directory", "skipped", "directory is not empty; preserved"
            os.fsync(dir_fd)
            chain.verify(step="rollback")
            return "remove-directory", "done", "removed (empty)"
    except FileNotFoundError:
        return "remove-directory", "done", "already absent"


def _restore_unit_state(ctx: _Apply, entry: Mapping[str, Any]) -> tuple[str, str, str]:
    unit = str(entry["unit"])
    before = _unit_observation(ctx, unit, step="rollback")
    prior_active = bool(entry["priorActive"])
    prior_enabled = str(entry["priorEnabled"])
    if unit == ENGINE_SOCKET_UNIT and before["enabled"] != prior_enabled:
        action = "enable" if prior_enabled == "enabled" else "disable"
        arguments = [_TRUSTED_EXECUTABLES["systemctl"], "--user", action]
        if not prior_active:
            arguments.append("--now")
        arguments.append(unit)
        _run(ctx, _as_exec(ctx, arguments), step="rollback", timeout=120)
    current = _unit_observation(ctx, unit, step="rollback")
    if current["active"] != prior_active:
        action = "start" if prior_active else "stop"
        _run(
            ctx,
            _as_exec(ctx, [_TRUSTED_EXECUTABLES["systemctl"], "--user", action, unit]),
            step="rollback",
            timeout=120,
        )
    after = _unit_observation(ctx, unit, step="rollback")
    if after["active"] != prior_active or (
        unit == ENGINE_SOCKET_UNIT and after["enabled"] != prior_enabled
    ):
        raise StepFailed("rollback", f"unit state did not return to its prior state: {unit}")
    return "restore-unit-state", "done", "prior active/enabled state restored"


def _restore_control_unit_state(
    ctx: _Apply, entry: Mapping[str, Any]
) -> tuple[str, str, str]:
    unit = str(entry["unit"])
    prior_active = bool(entry["priorActive"])
    prior_enabled = str(entry["priorEnabled"])
    track_enabled = bool(entry["trackEnabled"])
    before = _control_unit_observation(ctx, unit, step="rollback")
    if track_enabled and before["enabled"] != prior_enabled:
        action = "enable" if prior_enabled == "enabled" else "disable"
        _run(ctx, _control_systemctl(action, unit), step="rollback", timeout=120)
    current = _control_unit_observation(ctx, unit, step="rollback")
    if current["active"] != prior_active:
        action = "start" if prior_active else "stop"
        _run(ctx, _control_systemctl(action, unit), step="rollback", timeout=120)
    after = _control_unit_observation(ctx, unit, step="rollback")
    if after["active"] != prior_active or (
        track_enabled and after["enabled"] != prior_enabled
    ):
        raise StepFailed("rollback", f"control unit state did not return to prior state: {unit}")
    return "restore-control-unit-state", "done", "prior active/enabled state restored"


def _rollback(ctx: _Apply) -> dict[str, Any]:
    """Reverse journaled effects through anchored postcondition-checked operations."""

    if not ctx.journal:
        return {
            "performed": False,
            "status": "not-reached",
            "actions": [],
            "failures": [],
        }
    report: dict[str, Any] = {
        "performed": True,
        "status": "succeeded",
        "actions": [],
        "failures": [],
    }

    def record(
        action: str, target: str, result: str, detail: str, *, intentional_skip: bool = False
    ) -> None:
        report["actions"].append(
            {"action": action, "target": target, "result": result, "detail": detail[:280]}
        )
        if result == "failed" or (result == "skipped" and not intentional_skip):
            report["status"] = "incomplete"
            report["failures"].append(f"{action} {target}: {detail}"[:300])

    subid_entries = [entry for entry in reversed(ctx.journal) if entry["kind"] == "subid-line-added"]
    handled_subids = False
    for entry in reversed(ctx.journal):
        if entry["kind"] != "control-unit-state-changed":
            continue
        target = str(entry["unit"])
        try:
            action, result, detail = _restore_control_unit_state(ctx, entry)
            record(action, target, result, detail)
        except Exception as exc:  # noqa: BLE001
            record("restore-control-unit-state", target, "failed", str(exc)[:200])
    for entry in reversed(ctx.journal):
        if entry["kind"] != "unit-state-changed":
            continue
        target = str(entry["unit"])
        try:
            action, result, detail = _restore_unit_state(ctx, entry)
            record(action, target, result, detail)
        except Exception as exc:  # noqa: BLE001
            record("restore-unit-state", target, "failed", str(exc)[:200])
    handled_user_managers: set[str] = set()
    manager_stop_failed = False
    for entry in reversed(ctx.journal):
        if entry["kind"] != "user-manager-started":
            continue
        unit = str(entry["unit"])
        if unit in handled_user_managers:
            continue
        handled_user_managers.add(unit)
        try:
            completed = _run(
                ctx,
                [_TRUSTED_EXECUTABLES["systemctl"], "stop", unit],
                step="rollback",
                timeout=120,
            )
            active = _user_manager_active(ctx, unit, step="rollback")
            record(
                "stop-user-manager",
                unit,
                "failed" if active else "done",
                completed.stderr.strip() or "postcondition observed",
            )
            manager_stop_failed = manager_stop_failed or active
        except Exception as exc:  # noqa: BLE001
            record("stop-user-manager", unit, "failed", str(exc)[:200])
            manager_stop_failed = True
    if manager_stop_failed:
        record(
            "preserve-managed-identities",
            "transaction-created users and linger state",
            "skipped",
            "a transaction-started user manager could not be proven stopped",
        )
        return report
    preserve_active = {
        str(entry["user"]): str(entry["unit"])
        for entry in ctx.journal
        if entry["kind"] == "user-manager-preserve-active"
    }
    linger_cleanup_failed = False
    for entry in reversed(ctx.journal):
        if entry["kind"] != "linger-enabled":
            continue
        user = str(entry["user"])
        try:
            completed = _run(
                ctx,
                [_TRUSTED_EXECUTABLES["loginctl"], "disable-linger", user],
                step="rollback",
                timeout=120,
            )
            _content, marker = _read_regular_file(
                ctx.layout,
                f"{LINGER_DIR}/{user}",
                step="rollback",
                absent_ok=True,
            )
            removed = marker is None
            record(
                "disable-linger",
                user,
                "done" if removed else "failed",
                completed.stderr.strip() or "postcondition observed",
            )
            linger_cleanup_failed = linger_cleanup_failed or not removed
            unit = preserve_active.get(user)
            if removed and unit is not None:
                stopped = _run(
                    ctx,
                    [_TRUSTED_EXECUTABLES["systemctl"], "stop", unit],
                    step="rollback",
                    timeout=120,
                )
                inactive = not _user_manager_active(ctx, unit, step="rollback")
                record(
                    "settle-user-manager",
                    unit,
                    "done" if inactive else "failed",
                    stopped.stderr.strip() or "post-linger inactive state observed",
                )
                if not inactive:
                    linger_cleanup_failed = True
                    continue
                restarted = _run(
                    ctx,
                    [_TRUSTED_EXECUTABLES["systemctl"], "start", unit],
                    step="rollback",
                    timeout=120,
                )
                active = _user_manager_active(ctx, unit, step="rollback")
                record(
                    "restore-user-manager",
                    unit,
                    "done" if active else "failed",
                    restarted.stderr.strip() or "prior active state restored",
                )
                linger_cleanup_failed = linger_cleanup_failed or not active
        except Exception as exc:  # noqa: BLE001
            record("disable-linger", user, "failed", str(exc)[:200])
            linger_cleanup_failed = True
    if linger_cleanup_failed:
        record(
            "preserve-managed-identities",
            "transaction-created users, groups, and mappings",
            "skipped",
            "transaction-created linger or prior manager state could not be restored",
        )
        return report
    for entry in reversed(ctx.journal):
        kind = entry["kind"]
        target = str(entry.get("path") or entry.get("name") or entry.get("unit") or "?")
        try:
            if kind == "subid-line-added":
                if handled_subids:
                    continue
                handled_subids = True
                with _subid_lock(ctx, step="rollback"):
                    for subid_entry in subid_entries:
                        try:
                            action, result, detail = _rollback_subid_line(ctx, subid_entry)
                            record(action, str(subid_entry["path"]), result, detail)
                        except Exception as subid_exc:  # noqa: BLE001
                            record(
                                "remove-subordinate-id-line",
                                str(subid_entry["path"]),
                                "failed",
                                str(subid_exc),
                            )
            elif kind == "unit-state-changed":
                continue
            elif kind == "image-pulled":
                record(
                    "preserve-image",
                    entry["reference"],
                    "skipped",
                    "image preserved in the stateport-exec rootless store",
                    intentional_skip=True,
                )
            elif kind == "file-written":
                action, result, detail = _rollback_regular_file(ctx, entry)
                record(action, target, result, detail)
            elif kind == "grant-written":
                # The control-plane grant is written with the same exact
                # file-written journal schema; roll it back the same way so a
                # transaction failure never leaves the grant behind.
                action, result, detail = _rollback_regular_file(ctx, entry)
                record(action, target, result, detail)
            elif kind == "directory-metadata":
                action, result, detail = _rollback_directory_metadata(ctx, entry)
                record(action, target, result, detail)
            elif kind == "directory-created":
                action, result, detail = _rollback_created_directory(ctx, entry)
                record(action, target, result, detail)
            elif kind == "linger-enabled":
                continue
            elif kind in {"user-manager-started", "user-manager-preserve-active"}:
                continue
            elif kind == "client-confined":
                completed = _run(
                    ctx,
                    [_TRUSTED_EXECUTABLES["gpasswd"], "-d", entry["user"], EXEC_GROUP],
                    step="rollback",
                    timeout=120,
                )
                group = ctx.accounts.group(EXEC_GROUP)
                removed = group is None or entry["user"] not in group.members
                record(
                    "unconfine-client",
                    entry["user"],
                    "done" if removed else "failed",
                    completed.stderr.strip() or "postcondition observed",
                )
            elif kind == "user-created":
                completed = _run(
                    ctx,
                    [_TRUSTED_EXECUTABLES["userdel"], entry["name"]],
                    step="rollback",
                    timeout=120,
                )
                removed = ctx.accounts.user(entry["name"]) is None
                record(
                    "delete-user",
                    entry["name"],
                    "done" if removed else "failed",
                    completed.stderr.strip() or "postcondition observed",
                )
            elif kind == "group-created":
                completed = _run(
                    ctx,
                    [_TRUSTED_EXECUTABLES["groupdel"], entry["name"]],
                    step="rollback",
                    timeout=120,
                )
                removed = ctx.accounts.group(entry["name"]) is None
                record(
                    "delete-group",
                    entry["name"],
                    "done" if removed else "failed",
                    completed.stderr.strip() or "postcondition observed",
                )
        except Exception as exc:  # noqa: BLE001 — rollback records, never raises
            record(kind, target, "failed", str(exc)[:200])
    return report


# ---------------------------------------------------------------------------
# Receipt
# ---------------------------------------------------------------------------


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _uninstall_commands(plan: Mapping[str, Any]) -> list[str]:
    quadlet_paths = [
        write["path"] for write in plan["writes"] if write["path"] != TMPFILES_PATH
    ]
    control_units = [
        PurePosixPath(unit).name.removesuffix(".container")
        for step in plan["steps"]
        if step["step"] == "start-control-plane-units"
        for unit in step.get("units", [])
        if str(unit).endswith(".container")
    ]
    control_networks = [
        PurePosixPath(unit).name.removesuffix(".network") + "-network"
        for step in plan["steps"]
        if step["step"] == "start-control-plane-units"
        for unit in step.get("units", [])
        if str(unit).endswith(".network")
    ]
    commands = [
        f"runuser -u {CONTROL_USER} -- systemctl --user disable --now stateport-accepted.target",
        *[
            f"runuser -u {CONTROL_USER} -- systemctl --user stop {unit}"
            for unit in sorted(control_units) + sorted(control_networks)
        ],
        f"runuser -u {EXEC_USER} -- systemctl --user disable --now {DAEMON_UNIT}",
        f"runuser -u {EXEC_USER} -- systemctl --user disable --now {ENGINE_SOCKET_UNIT}",
        *[
            f"rm -f {shlex.quote(path)}"
            for path in quadlet_paths
        ],
        f"rm -f {CONTROL_SYSTEMD_USER_DIR}/stateport-accepted.target",
        f"rm -f {shlex.quote(TMPFILES_PATH)}",
        f"loginctl disable-linger {CONTROL_USER}",
        f"loginctl disable-linger {EXEC_USER}",
        f"userdel {CONTROL_USER} (only if created by this transaction)",
        f"groupdel {CONTROL_USER} (only if created by this transaction)",
        f"userdel {EXEC_USER} (only if created by this transaction)",
        f"groupdel {EXEC_USER} (only if created by this transaction)",
        f"groupdel {EXEC_GROUP} (only if created by this transaction)",
        (
            f"remove the exact line '{EXEC_USER}:<assigned-start>:{SUBID_RANGE_SIZE}' from "
            f"{SUBUID_PATH} and {SUBGID_PATH} if this transaction added it"
        ),
        (
            f"remove the exact line '{CONTROL_USER}:<assigned-start>:{SUBID_RANGE_SIZE}' from "
            f"{SUBUID_PATH} and {SUBGID_PATH} if this transaction added it"
        ),
        (
            "preserved: the digest-pinned execution-host image in the stateport-exec "
            f"rootless store and the daemon state directory {STATE_DIR}"
        ),
    ]
    return commands


def _build_receipt(
    ctx: _Apply,
    plan: Mapping[str, Any],
    *,
    verified: VerifiedRelease,
    evidence_class: str,
    started: datetime,
    finished: datetime,
    failed: Exception | None,
    rollback_report: Mapping[str, Any],
    receipt_path: str,
) -> dict[str, Any]:
    digest = str(plan["image"]["digest"])
    signed = verified.index.document["signed"]
    step_results = {entry["step"]: entry["result"] for entry in ctx.steps}
    image_step = step_results.get("pull-execution-host-image", "not-reached")
    health_step = step_results.get("verify-protocol-health", "not-reached")
    health = ctx.health or {
        "kind": "describeCapabilities",
        "socketPath": str(plan["socketPath"]),
        "peerUsers": [EXEC_USER, str(plan["allowedClientUser"])],
        "status": "failed" if health_step == "failed" else "not-reached",
        "healthy": False,
        "contractVersion": None,
        "refusal": None,
        "probes": [],
    }
    receipt: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "receiptId": f"exec_host_provision_{secrets.token_hex(16)}",
        "receiptPath": receipt_path,
        "planDigest": str(plan["planDigest"]),
        "releaseId": str(plan["releaseId"]),
        "releaseIndexDigest": verified.index.index_digest,
        "signedPayloadDigest": verified.index.signed_digest,
        "sourceCommit": str(signed["source"]["commit"]),
        "sourceTree": str(signed["source"]["tree"]),
        "installerDigest": str(signed["artifacts"]["installer"]["digest"]),
        "targetId": str(plan["targetId"]),
        "topologyDigest": str(plan["topologyDigest"]),
        "verificationBasis": str(plan["verificationBasis"]),
        "revalidatedImmediatelyBeforeWrites": True,
        "evidenceClass": evidence_class,
        "executionUser": EXEC_USER,
        "executionUid": int(plan["executionUid"]),
        "executionGid": int(plan["executionGid"]),
        "controlUser": CONTROL_USER,
        "controlUid": int(plan["controlUid"]),
        "controlGid": int(plan["controlGid"]),
        "executionControlGroup": EXEC_GROUP,
        "executionControlGroupGid": int(plan["executionControlGroupGid"]),
        "allowedClientUser": str(plan["allowedClientUser"]),
        "subordinateIds": {
            "user": EXEC_USER,
            "start": ctx.subid_start,
            "count": SUBID_RANGE_SIZE,
            "files": [SUBUID_PATH, SUBGID_PATH],
        },
        "controlSubordinateIds": {
            "user": CONTROL_USER,
            "start": ctx.control_subid_start,
            "count": SUBID_RANGE_SIZE,
            "files": [SUBUID_PATH, SUBGID_PATH],
        },
        "image": {
            "imageId": str(plan["image"]["imageId"]),
            "reference": str(plan["image"]["reference"]),
            "expectedDigest": digest,
            "observedDigest": ctx.image_observed,
            "storeOwner": EXEC_USER,
            "status": (
                "verified"
                if ctx.image_observed == digest
                else ("failed" if image_step == "failed" else "not-reached")
            ),
        },
        "health": health,
        "steps": ctx.steps,
        "rollback": rollback_report,
        "uninstall": _uninstall_commands(plan),
        "startedAt": _timestamp(started),
        "finishedAt": _timestamp(finished),
        "result": "failed" if failed is not None else "succeeded",
    }
    if ctx.grant_digest is not None and failed is None:
        receipt["controlGrant"] = {
            "grantFormatVersion": "stateport.execution-host-grant/v2",
            "grantId": DEFAULT_GRANT_ID,
            "peerUid": int(plan["controlUid"]),
            "workloadId": DEFAULT_WORKSPACE_ID,
            "workloadKind": "workspace",
            "workloadSpecDigest": DEFAULT_WORKSPACE_SPEC_DIGEST,
            "imageReference": DEFAULT_WORKSPACE_IMAGE,
            "deploymentScope": dict(_DEFAULT_DEPLOYMENT_SCOPE),
            "grantDigest": ctx.grant_digest,
        }
    if failed is not None:
        receipt["failure"] = {
            "step": getattr(failed, "step", "pre-transaction"),
            "detail": getattr(failed, "detail", str(failed))[:300],
        }
    return receipt


@dataclass(frozen=True)
class _ReceiptTarget:
    layout: HostLayout
    path: str
    uid: int
    gid: int
    directory_mode: int = 0o700
    file_mode: int = 0o600

    @property
    def intent_path(self) -> str:
        return self.path + ".intent"


def _ensure_receipt_parent(target: _ReceiptTarget) -> None:
    parts = _host_parts(target.path)
    parent = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
    created_paths: set[str] = set()

    def created(path: str, _observed: os.stat_result) -> None:
        created_paths.add(path)

    with _open_directory_chain(
        target.layout,
        parent,
        step="record-provisioning-receipt",
        create=True,
        created=created,
    ) as chain:
        traversed: list[str] = []
        for position, name in enumerate(chain.names):
            traversed.append(name)
            absolute = "/" + "/".join(traversed)
            if absolute in created_paths:
                os.fchown(chain.fds[position + 1], target.uid, target.gid)
                os.fchmod(chain.fds[position + 1], target.directory_mode)
                os.fsync(chain.fds[position + 1])
                os.fsync(chain.fds[position])
        observed = os.fstat(chain.fds[-1])
        if (
            observed.st_uid != target.uid
            or observed.st_gid != target.gid
            or stat.S_IMODE(observed.st_mode) != target.directory_mode
        ):
            raise ProvisioningRefusal(
                f"receipt parent must be private and root-owned: {parent} "
                f"uid={observed.st_uid} gid={observed.st_gid} "
                f"mode={oct(stat.S_IMODE(observed.st_mode))}"
            )
        chain.verify(step="record-provisioning-receipt")


def _create_only_file(target: _ReceiptTarget, path: str, content: bytes) -> None:
    parts = _host_parts(path)
    parent = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
    name = parts[-1]
    with _open_directory_chain(
        target.layout, parent, step="record-provisioning-receipt"
    ) as chain:
        dir_fd = chain.fds[-1]
        try:
            os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ProvisioningRefusal(
                f"provisioning evidence already exists: {path}; refusing to overwrite evidence"
            )
        temp_name = f".{name}.{secrets.token_hex(8)}.tmp"
        descriptor = os.open(
            temp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=dir_fd,
        )
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fchown(handle.fileno(), target.uid, target.gid)
                os.fchmod(handle.fileno(), target.file_mode)
                os.fsync(handle.fileno())
            chain.verify(step="record-provisioning-receipt")
            try:
                os.link(
                    temp_name,
                    name,
                    src_dir_fd=dir_fd,
                    dst_dir_fd=dir_fd,
                    follow_symlinks=False,
                )
            except FileExistsError as exc:
                raise ProvisioningRefusal(
                    f"provisioning evidence destination won its no-replace CAS: {path}"
                ) from exc
            os.unlink(temp_name, dir_fd=dir_fd)
            temp_name = ""
            os.fsync(dir_fd)
            chain.verify(step="record-provisioning-receipt")
        finally:
            if temp_name:
                try:
                    os.unlink(temp_name, dir_fd=dir_fd)
                except OSError:
                    pass
    observed_content, observed = _read_regular_file(
        target.layout, path, step="record-provisioning-receipt"
    )
    if (
        observed is None
        or observed_content != content
        or observed.st_uid != target.uid
        or observed.st_gid != target.gid
        or stat.S_IMODE(observed.st_mode) != target.file_mode
    ):
        raise ProvisioningRefusal(f"provisioning evidence post-observation failed: {path}")


def _unlink_receipt_sidecar(target: _ReceiptTarget, path: str, observed: os.stat_result) -> None:
    parts = _host_parts(path)
    parent = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
    with _open_directory_chain(
        target.layout, parent, step="record-provisioning-receipt"
    ) as chain:
        current = os.stat(parts[-1], dir_fd=chain.fds[-1], follow_symlinks=False)
        if not _same_inode(current, observed):
            raise ProvisioningRefusal("provisioning evidence inode changed during adoption")
        os.unlink(parts[-1], dir_fd=chain.fds[-1])
        os.fsync(chain.fds[-1])
        chain.verify(step="record-provisioning-receipt")


def _archive_failed_receipt(
    target: _ReceiptTarget, observed: os.stat_result, started: datetime
) -> None:
    """Move a failed same-plan receipt aside so the identical rerun can retry.

    The archived evidence is preserved under a unique create-only name; the
    fixed receipt path is freed for the retry.  Only a schema-valid receipt
    that proves THIS plan digest and did not succeed healthy is archived —
    foreign or malformed evidence keeps the original refusal.
    """
    parts = _host_parts(target.path)
    parent = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
    stamp = started.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    with _open_directory_chain(
        target.layout, parent, step="record-provisioning-receipt"
    ) as chain:
        current = os.stat(parts[-1], dir_fd=chain.fds[-1], follow_symlinks=False)
        if not _same_inode(current, observed):
            raise ProvisioningRefusal("provisioning receipt inode changed during archival")
        archive_name = f"{parts[-1]}.failed-{stamp}-{secrets.token_hex(4)}"
        os.rename(
            parts[-1],
            archive_name,
            src_dir_fd=chain.fds[-1],
            dst_dir_fd=chain.fds[-1],
        )
        os.fsync(chain.fds[-1])
        chain.verify(step="record-provisioning-receipt")


def _adopt_pending_intent(target: _ReceiptTarget, plan_digest: str) -> None:
    """Remove a crash-remnant pending intent for THIS exact plan.

    A crash between intent creation and receipt publication leaves a
    create-only intent whose per-run ``startedAt`` can never byte-match a
    rerun.  A pending intent that proves this plan digest and receipt path is
    our own unfinished transaction and is adopted (removed); any other intent
    keeps the original refusal.
    """
    content, observed = _read_regular_file(
        target.layout,
        target.intent_path,
        step="record-provisioning-receipt",
        absent_ok=True,
    )
    if observed is None:
        return
    try:
        existing = json.loads((content or b"").decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        existing = None
    if not (
        isinstance(existing, dict)
        and existing.get("schema") == "stateport.execution-host-provisioning-intent/v1"
        and existing.get("planDigest") == plan_digest
        and existing.get("receiptPath") == target.path
        and existing.get("state") == "pending"
    ):
        raise ProvisioningRefusal(
            f"provisioning evidence already exists: {target.intent_path}; "
            "refusing to overwrite evidence"
        )
    _unlink_receipt_sidecar(target, target.intent_path, observed)


def _prepare_receipt(target: _ReceiptTarget, plan: Mapping[str, Any], started: datetime) -> bytes:
    _ensure_receipt_parent(target)
    _content, existing = _read_regular_file(
        target.layout,
        target.path,
        step="record-provisioning-receipt",
        absent_ok=True,
    )
    if existing is not None:
        # Rerun convergence: an existing receipt is never overwritten. When it
        # is schema-valid, proves this exact plan digest, succeeded, and shows
        # a healthy protocol peer, the transaction it records still stands and
        # the rerun adopts it instead of failing.  A schema-valid receipt for
        # this exact plan that did NOT succeed healthy records a failed
        # transaction: it is archived aside (evidence preserved) and the
        # identical rerun retries.  Any other existing receipt keeps the
        # original refusal.
        try:
            existing_receipt = json.loads((_content or b"").decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            existing_receipt = None
        if (
            isinstance(existing_receipt, dict)
            and existing_receipt.get("schema") == RECEIPT_SCHEMA
            and existing_receipt.get("planDigest") == str(plan["planDigest"])
            and existing_receipt.get("result") == "succeeded"
            and isinstance(existing_receipt.get("health"), dict)
            and existing_receipt["health"].get("healthy") is True
        ):
            validate_contract_document(existing_receipt, expected_schema=RECEIPT_SCHEMA)
            _adopt_pending_intent(target, str(plan["planDigest"]))
            raise ProvisioningConverged(existing_receipt)
        if (
            isinstance(existing_receipt, dict)
            and existing_receipt.get("schema") == RECEIPT_SCHEMA
            and existing_receipt.get("planDigest") == str(plan["planDigest"])
        ):
            validate_contract_document(existing_receipt, expected_schema=RECEIPT_SCHEMA)
            _archive_failed_receipt(target, existing, started)
            _adopt_pending_intent(target, str(plan["planDigest"]))
        else:
            raise ProvisioningRefusal(
                f"provisioning receipt already exists: {target.path}; refusing to overwrite evidence"
            )
    else:
        _adopt_pending_intent(target, str(plan["planDigest"]))
    intent = (
        json.dumps(
            {
                "schema": "stateport.execution-host-provisioning-intent/v1",
                "planDigest": plan["planDigest"],
                "receiptPath": target.path,
                "state": "pending",
                "startedAt": _timestamp(started),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    _create_only_file(target, target.intent_path, intent)
    return intent


def _clear_receipt_intent(target: _ReceiptTarget, expected: bytes) -> None:
    content, observed = _read_regular_file(
        target.layout,
        target.intent_path,
        step="record-provisioning-receipt",
        absent_ok=True,
    )
    if observed is None:
        return
    if content != expected:
        raise ProvisioningRefusal(
            f"provisioning intent changed; preserving it for recovery: {target.intent_path}"
        )
    parts = _host_parts(target.intent_path)
    parent = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
    with _open_directory_chain(
        target.layout, parent, step="record-provisioning-receipt"
    ) as chain:
        current = os.stat(parts[-1], dir_fd=chain.fds[-1], follow_symlinks=False)
        if not _same_inode(current, observed):
            raise ProvisioningRefusal("provisioning intent inode changed during completion")
        os.unlink(parts[-1], dir_fd=chain.fds[-1])
        os.fsync(chain.fds[-1])
        chain.verify(step="record-provisioning-receipt")


def _write_receipt(target: _ReceiptTarget, document: Mapping[str, Any]) -> None:
    serialized = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _create_only_file(target, target.path, serialized)


def _assert_same_release(verified: VerifiedRelease, refreshed: Any) -> None:
    if not isinstance(refreshed, VerifiedRelease):
        raise ProvisioningRefusal("revalidation did not return a verified release")
    if (
        refreshed.index.index_digest != verified.index.index_digest
        or refreshed.target["targetId"] != verified.target["targetId"]
        or refreshed.target["topologyDigest"] != verified.target["topologyDigest"]
    ):
        raise ProvisioningRefusal(
            "revalidation immediately before privileged writes diverged from the verified release"
        )


def apply_verified_plan(
    verified: VerifiedRelease,
    *,
    revalidate: Callable[[], VerifiedRelease],
    runner: Runner | None = None,
    accounts: Accounts | None = None,
    layout: HostLayout | None = None,
    clock: Callable[[], datetime] | None = None,
    euid: int | None = None,
    receipt_path: Path | None = None,
    rootless_group_probe: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
    client_user: str | None = None,
    client_uid: int | None = None,
    client_gid: int | None = None,
    control_plane_materialization: Mapping[str, bytes] | None = None,
    control_grant_digest: str | None = None,
    control_plane_environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Run the freshly rendered plan as root; every step is observed and receipted.

    The plan is re-rendered here from the cryptographically verified release —
    caller-supplied plan bytes are never executed.  ``revalidate`` is invoked
    immediately before the first privileged write and must return a verified
    release identical to ``verified``.
    """

    if not isinstance(verified, VerifiedRelease):
        raise ProvisioningRefusal("execution-host provisioning requires a verified release")
    substrate = observe_linux_substrate().substrate
    target_id = str(verified.target["targetId"])
    if substrate == "wsl1":
        raise ProvisioningRefusal("wsl1_substrate_unsupported")
    expected_target = WSL2_TARGET_ID if substrate == "wsl2" else PORTABLE_LINUX_TARGET_ID
    if target_id != expected_target:
        raise ProvisioningRefusal("wsl_substrate_unqualified")
    effective_uid = os.geteuid() if euid is None else euid
    if effective_uid != 0:
        raise ProvisioningRefusal(
            "execution-host provisioning must run as root through the root helper; the rootless "
            "installer only emits the plan and never escalates"
        )
    simulated = runner is not None or accounts is not None or layout is not None or euid is not None
    evidence_class = "locally-simulated" if simulated else "clean-host-executed"
    runner = runner if runner is not None else SubprocessRunner()
    accounts = accounts if accounts is not None else SystemAccounts()
    layout = layout if layout is not None else HostLayout()
    if rootless_group_probe is not None and layout.root == Path("/"):
        raise ProvisioningRefusal(
            "the simulated rootless-group support seam cannot bypass the real host contract"
        )
    if rootless_group_probe is not None:
        group_probe = rootless_group_probe
    elif layout.root == Path("/"):
        group_probe = _default_rootless_group_probe
    else:
        # A descriptor-root simulation cannot execute a binary inside that
        # synthetic filesystem. It still validates the exact plan identity;
        # only the real root transaction may assert clean-host execution.
        group_probe = lambda plan: {
            "supported": plan["rootlessSupplementaryGroupContract"].get("status")
            == "supported-by-pinned-runtime-contract",
            "mechanism": plan["rootlessSupplementaryGroupContract"].get(
                "quadletDirective", ""
            ),
            "detail": "descriptor-root simulation of the pinned runtime contract",
        }
    clock = clock if clock is not None else (lambda: datetime.now(timezone.utc))
    images = verified.index.document["signed"]["images"]
    plan = render_provisioning_plan(
        verified.target,
        images,
        verification_basis="signature-verified-provisioning",
        client_user=client_user,
        client_uid=client_uid,
        client_gid=client_gid,
        control_plane_materialization=control_plane_materialization,
        control_grant_digest=control_grant_digest,
        control_plane_environment=control_plane_environment,
    )
    started = clock()
    root_account = accounts.user("root")
    if root_account is None:
        raise ProvisioningRefusal("the root account is not resolvable for durable receipts")
    if receipt_path is None:
        receipt_host_path = (
            f"{DEFAULT_RECEIPT_DIRECTORY}/execution-host-"
            f"{_timestamp(started).replace(':', '').replace('-', '')}-{secrets.token_hex(8)}.json"
        )
        receipt_target = _ReceiptTarget(
            layout=layout,
            path=receipt_host_path,
            uid=root_account.uid,
            gid=root_account.gid,
        )
    else:
        if not receipt_path.is_absolute():
            raise ProvisioningRefusal("the provisioning receipt path must be absolute")
        receipt_host_path = receipt_path.as_posix()
        receipt_target = _ReceiptTarget(
            layout=HostLayout() if simulated else layout,
            path=receipt_host_path,
            uid=root_account.uid,
            gid=root_account.gid,
            directory_mode=(
                0o755
                if receipt_host_path.startswith(DEFAULT_RECEIPT_DIRECTORY + "/")
                else 0o700
            ),
            file_mode=(
                0o644
                if receipt_host_path.startswith(DEFAULT_RECEIPT_DIRECTORY + "/")
                else 0o600
            ),
        )
    # Revalidate immediately before the first privileged write.
    _assert_same_release(verified, revalidate())
    ctx = _Apply(
        plan=plan,
        signed_payload_digest=verified.index.signed_digest,
        runner=runner,
        accounts=accounts,
        layout=layout,
        rootless_group_probe=group_probe,
        steps=[
            {
                "step": str(step["step"]),
                "result": "not-reached",
                "commands": [],
                "detail": "",
            }
            for step in plan["steps"]
        ],
    )
    by_name = {entry["step"]: entry for entry in ctx.steps}
    failed: Exception | None = None
    intent_bytes: bytes | None = _prepare_receipt(receipt_target, plan, started)
    for step in plan["steps"]:
        name = str(step["step"])
        if name == "record-provisioning-receipt":
            break
        handler = _STEP_HANDLERS.get(name)
        ctx.current_commands = []
        try:
            if handler is None:
                raise StepFailed(name, "unknown provisioning step")
            result = handler(ctx)
            by_name[name].update(result)
            by_name[name]["commands"] = list(ctx.current_commands)
        except Exception as exc:  # noqa: BLE001 — every failure rolls back and receipts
            failed = (
                exc
                if isinstance(exc, StepFailed) and exc.step == name
                else StepFailed(name, str(exc))
            )
            by_name[name].update(
                {
                    "result": "failed",
                    "commands": list(ctx.current_commands),
                    "detail": str(failed)[:300],
                }
            )
            break
    rollback_report = (
        _rollback(ctx)
        if failed is not None
        else {"performed": False, "status": "not-reached", "actions": [], "failures": []}
    )

    def build_document() -> dict[str, Any]:
        receipt = _build_receipt(
            ctx,
            plan,
            verified=verified,
            evidence_class=evidence_class,
            started=started,
            finished=clock(),
            failed=failed,
            rollback_report=rollback_report,
            receipt_path=receipt_host_path,
        )
        receipt["receiptDigest"] = revision_contract_digest(
            receipt, digest_field="receiptDigest"
        )
        return validate_contract_document(receipt, expected_schema=RECEIPT_SCHEMA).as_dict()

    receipt_step = by_name["record-provisioning-receipt"]
    receipt_step.update({"result": "applied", "commands": [], "detail": ""})
    document = build_document()
    try:
        if intent_bytes is None:
            _ensure_receipt_parent(receipt_target)
        _write_receipt(receipt_target, document)
    except Exception as first_write_error:  # noqa: BLE001 — success must become rollback/failure
        receipt_step.update(
            {
                "result": "failed",
                "detail": f"initial receipt publication failed: {first_write_error}"[:300],
            }
        )
        if failed is None:
            failed = StepFailed(
                "record-provisioning-receipt",
                f"durable no-replace receipt publication failed: {first_write_error}",
            )
            rollback_report = _rollback(ctx)
        # A transient publication failure may recover by writing the failure
        # receipt. A CAS conflict remains a conflict and leaves the intent as
        # deterministic recovery evidence.
        receipt_step.update(
            {
                "result": "applied",
                "detail": "failure receipt published after initial publication failure",
            }
        )
        document = build_document()
        try:
            _write_receipt(receipt_target, document)
        except Exception as second_write_error:  # noqa: BLE001
            raise ProvisioningRefusal(
                "provisioning did not claim success: rollback was attempted, but the durable "
                f"failure receipt could not be published ({second_write_error}); recover from "
                f"the pending intent {receipt_target.intent_path}"
            ) from second_write_error
    if intent_bytes is not None:
        _clear_receipt_intent(receipt_target, intent_bytes)
    return document


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _updater_version() -> str:
    return "0.1.1"


def _verify_cli(args: argparse.Namespace) -> VerifiedRelease:
    """Cryptographically verify the CLI release input with the pinned trust root."""

    from stateport_release import embedded_predecessor_index  # noqa: PLC0415

    if (
        args.trust_key_id != ROOT_TRUST_KEY_ID
        or args.trust_key_fingerprint != ROOT_TRUST_KEY_FINGERPRINT
    ):
        raise ProvisioningRefusal("provisioning trust identity does not match the root helper")
    substrate = observe_linux_substrate().substrate
    if substrate == "wsl1":
        raise ProvisioningRefusal("wsl1_substrate_unsupported")
    expected_target = WSL2_TARGET_ID if substrate == "wsl2" else PORTABLE_LINUX_TARGET_ID
    identity = PinnedPublicKeyIdentity(ROOT_TRUST_KEY_FINGERPRINT, ROOT_TRUST_KEY_ID)
    policy = ReleaseVerificationPolicy(
        expected_channel=args.channel,
        expected_target=expected_target,
        updater_version=_updater_version(),
        accepted_signers=frozenset(),
        accepted_public_keys=frozenset(
            {identity}
        ),
        expected_trust_mode="pinned-public-key",
        now=datetime.now(timezone.utc),
        allow_candidate=True,
        require_transparency_log=False,
    )
    index = load_release_index_file(args.release_index)
    predecessor = embedded_predecessor_index(index)
    signatures: list[tuple[Mapping[str, Any], str]] = [
        (signature, "index") for signature in index.document["signatures"]
    ]
    for image in index.document["signed"]["images"]:
        signature = image.get("signature")
        if isinstance(signature, Mapping):
            signatures.append((signature, "image"))
    if predecessor is not None:
        signatures.extend(
            (signature, "predecessor") for signature in predecessor.document["signatures"]
        )
    transport_root = Path(args.bundle_root)
    with tempfile.TemporaryDirectory(prefix="stateport-root-release-verify-") as retained:
        retained_root = Path(retained)
        retained_root.chmod(0o700)
        verifier = CosignVerifier(
            cosign=Path(ROOT_COSIGN_PATH),
            public_key=Path(ROOT_PUBLIC_KEY_PATH),
            identity=identity,
            bundle_root=retained_root,
        )
        for signature, kind in signatures:
            bundle_name = signature_bundle_name(signature)
            subdirectory = (
                "predecessor-bundle"
                if kind == "predecessor"
                else "image-bundles" if kind == "image" else ""
            )
            candidates = [
                args.release_index.parent / subdirectory / bundle_name,
                transport_root / subdirectory / bundle_name,
                args.release_index.parent / bundle_name,
                transport_root / bundle_name,
                bundle_slot(transport_root, signature),
            ]
            source = next(
                (
                    candidate
                    for candidate in candidates
                    if candidate.is_file() and not candidate.is_symlink()
                ),
                candidates[0],
            )
            verifier.retain_bundle(source, signature)
        archive_root = retained_root / "image-archives"
        archive_root.mkdir(mode=0o700)
        for image in index.document["signed"]["images"]:
            image_id = str(image["imageId"])
            candidates = (
                transport_root / "image-archives" / f"{image_id}.oci.tar",
                transport_root / f"{image_id}.oci.tar",
            )
            source = next(
                (path for path in candidates if path.is_file() and not path.is_symlink()),
                None,
            )
            if source is not None:
                destination = archive_root / source.name
                destination.write_bytes(source.read_bytes())
                destination.chmod(0o600)
        return verify_release_index(
            index,
            policy=policy,
            verifier=verifier,
            predecessor=predecessor,
        )


def _add_trust_args(parser: argparse.ArgumentParser, *, required: bool) -> None:
    parser.add_argument("--cosign", type=Path, default=None, required=required)
    parser.add_argument("--trust-public-key", type=Path, default=None, required=required)
    parser.add_argument("--trust-key-id", default=None, required=required)
    parser.add_argument("--trust-key-fingerprint", default=None, required=required)
    parser.add_argument("--channel", default="alpha")
    parser.add_argument("--bundle-root", type=Path, default=None, required=required)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="provision_execution_host",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    emit = subcommands.add_parser(
        "emit-plan", help="render the inspectable provisioning plan (no privilege)"
    )
    emit.add_argument("--release-index", type=Path, required=True)
    _add_trust_args(emit, required=False)
    provision_parser = subcommands.add_parser(
        "provision",
        help="run the transaction through the root-owned host helper only",
    )
    provision_parser.add_argument("--release-index", type=Path, required=True)
    _add_trust_args(provision_parser, required=True)
    provision_parser.add_argument(
        "--plan",
        type=Path,
        default=None,
        help="optional previously emitted plan; cross-checked by digest, never executed",
    )
    provision_parser.add_argument(
        "--receipt-out",
        type=Path,
        default=None,
        help=(
            "optional absolute create-only receipt path; defaults to a unique root-owned file "
            f"below {DEFAULT_RECEIPT_DIRECTORY}"
        ),
    )
    probe = subcommands.add_parser(
        "health-probe", help="perform a real describeCapabilities request and report JSON"
    )
    probe.add_argument("--socket", required=True)
    probe.add_argument("--expected-uid", type=int, default=None)
    probe.add_argument("--expected-gid", type=int, default=None)
    probe.add_argument(
        "--expected-mode",
        default=None,
        help="expected socket permission bits in octal, e.g. 0660",
    )
    probe.add_argument("--expected-contract-version", type=int, default=None)
    args = parser.parse_args(argv)
    try:
        if args.command == "health-probe":
            expected_mode = (
                int(args.expected_mode, 8) if args.expected_mode is not None else None
            )
            result = probe_protocol_health(
                args.socket,
                expected_uid=args.expected_uid,
                expected_gid=args.expected_gid,
                expected_mode=expected_mode,
                expected_contract_version=args.expected_contract_version,
            )
            # Compact single-line JSON: `_step_health` deliberately parses the
            # LAST stdout line to tolerate noise on earlier lines, so the probe
            # result must be exactly one line.
            json.dump(result, sys.stdout, sort_keys=True)
            sys.stdout.write("\n")
            return 0 if result["healthy"] else 1
        if args.command == "emit-plan":
            index = load_release_index_file(args.release_index)
            target = index.document["signed"]["targets"][0]
            images = index.document["signed"]["images"]
            basis = (
                "structural-only: emit-plan without trust pins; shape-validated, "
                "NOT cryptographically verified"
            )
            if args.cosign is not None:
                verified = _verify_cli(args)
                target = verified.target
                basis = "signature-verified-cli"
            plan = render_provisioning_plan(target, images, verification_basis=basis)
            json.dump(plan, sys.stdout, indent=2, sort_keys=True)
            sys.stdout.write("\n")
            return 0
        # provision is intentionally not an installer-facing sudo path; the
        # root-owned helper is the only supported caller.
        if os.environ.get("STATEPORT_ROOT_HELPER") != "1":
            raise ProvisioningRefusal(
                "direct provisioning is unsupported; invoke the root-owned host helper"
            )
        verified = _verify_cli(args)
        client = resolve_client_identity()
        if client is None:
            raise ProvisioningRefusal(
                "the root helper requires a resolvable invoking user (SUDO_USER or "
                "STATEPORT_CONTROL_CLIENT_USER) to bind the control-plane client"
            )
        client_user, client_uid, client_gid = client
        on_disk_plan: dict[str, Any] | None = None
        if args.plan is not None:
            on_disk_plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
        materialization = None
        grant_digest = None
        plane_environment = None
        if isinstance(on_disk_plan, Mapping):
            raw_materialization = on_disk_plan.get("controlPlaneMaterialization")
            if isinstance(raw_materialization, Mapping) and raw_materialization:
                materialization = {
                    str(key): __import__("base64").b64decode(str(value))
                    for key, value in raw_materialization.items()
                }
            grant_digest = on_disk_plan.get("controlGrantDigest")
            raw_environment = on_disk_plan.get("controlPlaneEnvironment")
            if isinstance(raw_environment, Mapping):
                plane_environment = {
                    str(key): str(value)
                    for key, value in raw_environment.items()
                    if isinstance(key, str) and isinstance(value, str)
                }
        plan = render_provisioning_plan(
            verified.target,
            verified.index.document["signed"]["images"],
            verification_basis="signature-verified-apply",
            client_user=client_user,
            client_uid=client_uid,
            client_gid=client_gid,
            control_plane_materialization=materialization,
            control_grant_digest=grant_digest,
            control_plane_environment=plane_environment,
        )
        if args.plan is not None:
            if on_disk_plan.get("schema") != PLAN_SCHEMA or on_disk_plan.get("planDigest") != plan["planDigest"]:
                raise ProvisioningRefusal(
                    "the on-disk plan diverges from the freshly verified plan; refusing to provision"
                )
        receipt = apply_verified_plan(
            verified,
            revalidate=lambda: _verify_cli(args),
            receipt_path=args.receipt_out,
            client_user=client_user,
            client_uid=client_uid,
            client_gid=client_gid,
            control_plane_materialization=materialization,
            control_grant_digest=grant_digest,
            control_plane_environment=plane_environment,
        )
        json.dump(receipt, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0 if receipt["result"] == "succeeded" else 2
    except ProvisioningConverged as converged:
        print(
            "provisioning already converged: adopting the existing schema-valid "
            f"receipt for this exact plan at {converged.receipt.get('receiptPath')}",
            file=sys.stderr,
        )
        json.dump(converged.receipt, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0
    except ReleaseContractError as exc:
        print(f"provisioning refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "Accounts",
    "Account",
    "CONTROL_GID",
    "CONTROL_UID",
    "CONTROL_USER",
    "DEFAULT_GRANT_ID",
    "DEFAULT_WORKSPACE_ID",
    "DEFAULT_WORKSPACE_SPEC_DIGEST",
    "Completed",
    "EXEC_GROUP",
    "EXEC_GROUP_GID",
    "EXEC_GID",
    "EXEC_HOME",
    "EXEC_UID",
    "EXEC_USER",
    "GRANTS_DIR",
    "Group",
    "HostLayout",
    "PLAN_SCHEMA",
    "ProvisioningConverged",
    "ProvisioningRefusal",
    "QUADLET_DIR",
    "RECEIPT_SCHEMA",
    "Runner",
    "STATE_DIR",
    "StepFailed",
    "SubprocessRunner",
    "SystemAccounts",
    "TMPFILES_PATH",
    "apply_verified_plan",
    "default_sealed_workspace_workload",
    "main",
    "probe_protocol_health",
    "render_provisioning_plan",
    "resolve_client_identity",
]
