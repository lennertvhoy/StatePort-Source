#!/usr/bin/env python3
"""StatePort no-checkout, website-compatible installer (stdlib-only bootstrap).

Installs a signed StatePort release on any capability-matching portable Linux
host (Linux/amd64, cgroup v2, rootless Podman at or above the required floor,
Quadlet, systemd user services, and subordinate UID/GID mappings) without any
source checkout, from downloaded release artifacts.  Distribution branding is
observation, never eligibility: a host whose runtime contract matches but
which lacks a clean-install acceptance receipt installs with an explicit
``compatible_unvalidated`` notice and that tier is recorded in the install
receipt.  The script is Python 3.12+ standard-library only; the release
contracts and updater engine are loaded from the digest-verified updater
wheel, never from a checkout.

Trust order (every step fails closed):

1. The operator pins the trust root out of band: the Cosign trust public key,
   its key ID, and its SHA-256 DER SubjectPublicKeyInfo fingerprint.  The
   fingerprint of the supplied PEM is recomputed in pure stdlib (PEM armor is
   base64 DER SPKI) and must match the pinned value exactly.
2. Bootstrap authentication: the pinned Cosign executable (``--cosign``,
   required; nothing is downloaded implicitly) verifies the release-index
   signature bundle over the canonical signed payload.  The payload bytes are
   re-derived here with the exact ``stateport.canonical-json/v1`` subset
   (sorted keys, tight separators, UTF-8, no floats) and must hash to the
   signature descriptor's ``subjectDigest`` before Cosign is even invoked.
3. Only now is the index content trusted for one purpose: pinning digests.
   The updater wheel is hashed and compared against ``artifacts.updater`` in
   the authenticated signed payload, then installed into an isolated venv
   with ``pip --no-index --no-deps`` (the single digest-pinned wheel is the
   hash-locked requirement; the wheel has no runtime dependencies).
4. ``stateport_release`` and ``stateport_updater`` are imported from that
   venv.  The index is then re-verified end to end with
   ``verify_release_index`` (schema, canonical digests, channel, target,
   expiry, scan freshness, image signatures) using the pinned-key verifier.
   Any divergence between the bootstrap parse and the contract parse refuses.

Genesis boundary (documented, fail-closed): a fresh install has no
predecessor, so the revision validation/promotion ceremony has no typed
producer in this codebase.  The installer therefore creates the exact empty
genesis data volumes and their snapshot copies, records a genuine
``stateport.revision-validation-backup-receipt/v1`` (``sourceDataGeneration``
null, quiesced because no writer exists at genesis), and calls
``materialize_verified_quadlet_bundle`` — never hand-rendered units.  Only
the accepted-profile artifacts are copied into the user's live Quadlet root;
their pending ``@@STATEPORT_ACCEPTED_DATA_VOLUME:*`` tokens are resolved with
the exact genesis named volumes (the same substitution the contract performs
in ``materialize_accepted_quadlet_bundle``, which itself requires promotion
receipts no producer can issue at genesis).  Validation-profile units stay
staged and are never installed or started.  Later updates go through the
installed updater's typed ceremony.

Updater genesis: the alpha release line is pinned-public-key, and the
installed updater's typed proof contract accepts pinned-key admissions.  The
installer creates the durable trust root exactly once (create-only
``updater/trust/<keyId>.pem`` plus the self-digested
``stateport.internal-update-trust-root/v1`` record), initializes the updater
engine against the pinned policy with the real Cosign verifier, records the
schema-valid ``installed-initialize`` admission (``trustMode:
pinned-public-key``), installs the bound installed-authority identity
(installation ID, release ID, index/installer digests, target, state root,
channel), and records the durable ``install-trust.json`` fact.  A
``updater/genesis-boundary.json`` deferral record from a pre-contract install
is a historic artifact, not an outcome of this installer.

Execution-host provisioning boundary (fail-closed): when the verified target
declares a stable execution host, the installer renders the exact provisioning
plan from the signature-verified release (``signature-verified-install``) and
writes it to ``execution-host-provisioning-plan.json`` in the state root —
 create-only, foreign content refuses closed.  Provisioning is a separate,
 explicitly root step through the fixed root-owned host helper; it
 re-verifies the release cryptographically,
   re-renders and cross-checks the plan, revalidates immediately before the
   first privileged write, and writes a create-only root-owned receipt below
    ``/var/lib/stateport-provisioning/receipts``.  This rootless installer never
    escalates; it refuses to claim install success until that exact receipt —
    carrying the privileged transaction's digest-bound protocol-health proof,
    recorded after probing the confined socket as the allowed client — is
    present and matches this exact release and plan.

Uninstall and purge (recorded authority only, converge on partial state):
``--uninstall`` loads the durable installation record (``install-trust.json``
plus the staged materialization manifest) and reverses exactly what install
did — it stops and disables the recorded systemd user units, removes the
recorded containers by exact name, deletes the exact live Quadlet files the
installer materialized, and reloads the user manager.  All genesis data
volumes, snapshot volumes, the state root with every durable record, and the
updater venv are preserved, and a durable
``stateport.internal-install-uninstall-receipt/v1`` records every removed and
preserved name so a later purge or reinstall can read what happened.
``--purge`` additionally removes the recorded genesis data and snapshot
volumes and deletes the state root contents; it refuses closed unless
``--confirm-purge`` names the exact installed identity ID from the durable
record, and its receipt is written to ``<state-root>.purge-receipt.json``
before any state root deletion.  Both modes are idempotent: missing units,
containers, files, or volumes are convergence, and every step touches only
names from the durable record — never a glob, never a foreign resource, and
no external side-effect reversal is ever claimed.

No ``curl | sh``, no mutable tags, no shell, no silent fallback.  Every
refusal is typed and durable; where the receipt schema has every required
fact, a failed run writes a schema-conformant receipt with ``result:
failed`` — earlier refusals write a typed refusal record instead of a
half-populated receipt.  Durable state uses write-ahead intent plus atomic
rename, so an interrupted install is safely re-runnable and converges.
"""

from __future__ import annotations

import argparse
import base64
import http.cookiejar
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import importlib
from io import BytesIO
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Any, Callable, Mapping, Protocol, Sequence
import unicodedata
import urllib.error
import urllib.request
import venv
import zipfile


INSTALLER_VERSION = "0.1.0"
INSTALLER_ORIGIN = "https://stateport.invalid/installer/no-checkout"
# The portable Linux capability target.  The bootstrap pins this string; the
# digest-verified contract wheel is cross-checked against it after loading.
PORTABLE_LINUX_TARGET_ID = "linux-amd64-rootless-podman-quadlet"
WSL2_TARGET_ID = "wsl2-ubuntu2404-linux-amd64-rootless-podman-quadlet"
SUPPORTED_TARGET_IDS = frozenset({PORTABLE_LINUX_TARGET_ID, WSL2_TARGET_ID})
EXPECTED_TARGET = PORTABLE_LINUX_TARGET_ID
MAX_INDEX_BYTES = 4 * 1024 * 1024
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_PRODUCT_PAGE_BYTES = 2 * 1024 * 1024
# Install-end product gate mirrors the checkout-local public_alpha_preflight
# contract so the running web service is verified without any source checkout.
# The installer cannot import scripts/public_alpha_preflight.py (it is not in
# the digest-pinned updater wheel), so the exact constants and validation are
# mirrored here and guarded against drift by a consistency test.
_PRODUCT_PAGE_MARKERS = (b"<title>StatePort</title>", b'<div id="root">')
_PRODUCT_APPLICATION_ID = "studystate.sample"
_PRODUCT_DISPLAY_NAME = "StudyState Sample"
_PRODUCT_EXPECTED_CAPABILITIES = frozenset(
    {"conversation", "goal_execution", "proactive_notifications", "progress_dashboard"}
)
QUADLET_GENERATOR_CANDIDATES = (
    Path("/usr/libexec/podman/quadlet"),
    Path("/usr/lib/podman/quadlet"),
    Path("/usr/lib/systemd/user-generators/podman-user-generator"),
)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_BUNDLE_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,118}\.sigstore\.json$")
_CHANNELS = ("alpha", "stable", "owner-dogfood")
_SUPPLEMENTARY_ARTIFACTS = ("compose", "sourceArchive", "releaseNotes", "knownLimitations")
_PODMAN_PACKAGE_NAMES = frozenset({"aardvark-dns", "netavark", "podman"})
_PODMAN_RUNTIME_DEPENDENCIES = {"runc": "1.3.4", "slirp4netns": "1.2.1"}
_PODMAN_REQUIRED_PACKAGE_NAMES = frozenset(
    {
        *_PODMAN_PACKAGE_NAMES,
        "catatonit",
        "conmon",
        "containers-storage",
        "dbus-user-session",
        "fuse-overlayfs",
        "golang-github-containers-common",
        "golang-github-containers-image",
        "libslirp0",
        "libsubid4",
        "python3-venv",
        *_PODMAN_RUNTIME_DEPENDENCIES,
        "skopeo",
        "uidmap",
    }
)
_PODMAN_PACKAGE_BUNDLE_SCHEMA = "stateport/podman-package-bundle/v2"
_PODMAN_PACKAGE_PREFLIGHT_SCHEMA = "stateport.podman-package-preflight/v1"
_PODMAN_PACKAGE_INSTALLATION_SCHEMA = "stateport.podman-package-installation/v1"
_WSL_ROOTFS_IDENTITY = {
    "architecture": "amd64",
    "digest": "sha256:9b2f7730dc68227dd04a9f3e5eab86ad85caf556b8606ad94f1f29ff5c4fd3f5",
    "release": "24.04.4",
    "url": "https://releases.ubuntu.com/24.04.4/ubuntu-24.04.4-wsl-amd64.wsl",
}
UPDATE_TRUST_ROOT_SCHEMA = "stateport.internal-update-trust-root/v1"
INSTALL_TRUST_SCHEMA = "stateport.internal-install-trust/v1"
UNINSTALL_RECEIPT_SCHEMA = "stateport.internal-install-uninstall-receipt/v1"
ACCEPTED_ACTIVATION_TARGET = "stateport-accepted.target"
CONTROL_IDENTITY = "stateport-control"
# Durable root-owned tool locations installed by the privileged materialize
# step.  Installed references (wrapper, provisioning commands) bind these,
# never the per-run download directory the bootstrap cleans up on exit.
INSTALLED_COSIGN_PATH = "/usr/local/lib/stateport/tools/cosign"
INSTALLED_TRUST_PUBLIC_KEY_PATH = "/etc/stateport/alpha-2026-08-cosign.pub"


class InstallerRefusal(RuntimeError):
    """A typed, fail-closed installer refusal."""

    def __init__(
        self, code: str, message: str, *, observations: list[dict[str, Any]] | None = None
    ) -> None:
        if re.fullmatch(r"[a-z][a-z0-9_]{0,127}", code) is None:
            raise ValueError(f"refusal code is malformed: {code!r}")
        super().__init__(message)
        self.code = code
        self.observations = observations


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
        completed = subprocess.run(
            list(argv),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            stdin=subprocess.DEVNULL,
        )
        return Completed(completed.returncode, completed.stdout, completed.stderr)


@dataclass(frozen=True)
class FetchResult:
    status: int
    body: bytes


class Fetcher(Protocol):
    """Loopback health and bounded HTTPS download seam."""

    def fetch(self, url: str, *, timeout: float, max_bytes: int) -> FetchResult: ...


class UrllibFetcher:
    def __init__(self) -> None:
        # /session sets a session cookie that /v1/applications requires, so the
        # install-end product gate must carry cookies across fetches.
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )

    def fetch(self, url: str, *, timeout: float, max_bytes: int) -> FetchResult:
        if not url.startswith("https://") and not url.startswith("http://127.0.0.1"):
            raise InstallerRefusal("url_refused", f"only HTTPS or loopback HTTP is allowed: {url}")
        request = urllib.request.Request(url, headers={"User-Agent": "stateport-installer"})
        try:
            with self._opener.open(request, timeout=timeout) as response:
                body = response.read(max_bytes + 1)
                status = int(response.status)
        except urllib.error.HTTPError as exc:
            return FetchResult(int(exc.code), b"")
        except (urllib.error.URLError, OSError) as exc:
            raise InstallerRefusal("fetch_failed", f"{url}: {exc}") from exc
        if len(body) > max_bytes:
            raise InstallerRefusal("download_too_large", f"{url} exceeds {max_bytes} bytes")
        return FetchResult(status, body)


@dataclass(frozen=True)
class HostFacts:
    kernel: str
    os_id: str
    version_id: str
    architecture: str
    cgroup_version: str
    podman_version: str
    rootless: bool
    quadlet: bool
    systemd_user: bool
    subuid_configured: bool
    subgid_configured: bool

    def as_receipt(self) -> dict[str, Any]:
        return {
            "kernel": self.kernel,
            "osId": self.os_id,
            "versionId": self.version_id,
            "architecture": self.architecture,
            "cgroupVersion": self.cgroup_version,
            "podmanVersion": self.podman_version,
            "rootless": self.rootless,
            "quadlet": self.quadlet,
            "systemdUser": self.systemd_user,
            "subuidConfigured": self.subuid_configured,
            "subgidConfigured": self.subgid_configured,
        }


@dataclass(frozen=True)
class HostSubstrateFacts:
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

    @property
    def wsl_detected(self) -> bool:
        return self.substrate in {"wsl1", "wsl2"}


class HostProbe(Protocol):
    def substrate(self) -> HostSubstrateFacts: ...

    def gather(self) -> HostFacts: ...

    def occupied_ports(self) -> list[int]: ...


class SystemHostProbe:
    def __init__(
        self,
        runner: Runner,
        *,
        os_release: Path = Path("/etc/os-release"),
        cgroup_controllers: Path = Path("/sys/fs/cgroup/cgroup.controllers"),
        proc_net_tcp: tuple[Path, ...] = (Path("/proc/net/tcp"), Path("/proc/net/tcp6")),
        quadlet_candidates: Sequence[Path] = QUADLET_GENERATOR_CANDIDATES,
        subuid_path: Path = Path("/etc/subuid"),
        subgid_path: Path = Path("/etc/subgid"),
        kernel_release_path: Path = Path("/proc/sys/kernel/osrelease"),
        proc_version_path: Path = Path("/proc/version"),
        environment: Mapping[str, str] | None = None,
    ) -> None:
        self._runner = runner
        self._os_release = os_release
        self._cgroup_controllers = cgroup_controllers
        self._proc_net_tcp = proc_net_tcp
        self._quadlet_candidates = tuple(quadlet_candidates)
        self._subuid_path = subuid_path
        self._subgid_path = subgid_path
        self._kernel_release_path = kernel_release_path
        self._proc_version_path = proc_version_path
        self._environment = os.environ if environment is None else environment

    def substrate(self) -> HostSubstrateFacts:
        try:
            kernel_release = self._kernel_release_path.read_text(
                encoding="utf-8", errors="replace"
            ).strip()
            proc_version = self._proc_version_path.read_text(
                encoding="utf-8", errors="replace"
            ).strip()
        except OSError as exc:
            raise InstallerRefusal(
                "host_probe_failed", "Linux substrate identity is unreadable"
            ) from exc
        if not kernel_release or not proc_version:
            raise InstallerRefusal("host_probe_failed", "Linux substrate identity is empty")
        return HostSubstrateFacts(
            kernel_release=kernel_release,
            proc_version=proc_version,
            wsl_interop_present=bool(self._environment.get("WSL_INTEROP")),
            wsl_distro_name_present=bool(self._environment.get("WSL_DISTRO_NAME")),
        )

    @staticmethod
    def _subordinate_mapping_configured(path: Path) -> bool:
        """Observe whether a subordinate UID/GID mapping file names a range."""
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return False
        for line in lines:
            if not line or line.startswith("#"):
                continue
            fields = line.split(":")
            if (
                len(fields) == 3
                and fields[0]
                and fields[1].isdigit()
                and fields[2].isdigit()
                and int(fields[2]) > 0
            ):
                return True
        return False

    def gather(self) -> HostFacts:
        uname = self._runner.run(["uname", "-s"], timeout=30)
        if uname.returncode != 0:
            raise InstallerRefusal("host_probe_failed", "uname -s failed")
        kernel = uname.stdout.strip() or "unknown"
        uname = self._runner.run(["uname", "-m"], timeout=30)
        if uname.returncode != 0:
            raise InstallerRefusal("host_probe_failed", "uname -m failed")
        architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(
            uname.stdout.strip(), uname.stdout.strip()
        )
        os_id, version_id = "", ""
        try:
            for line in self._os_release.read_text(encoding="utf-8").splitlines():
                key, separator, value = line.partition("=")
                if not separator:
                    continue
                if key == "ID":
                    os_id = value.strip().strip('"')
                elif key == "VERSION_ID":
                    version_id = value.strip().strip('"')
        except OSError as exc:
            raise InstallerRefusal("host_probe_failed", "os-release is unreadable") from exc
        version = self._runner.run(
            ["podman", "version", "--format", "{{.Client.Version}}"], timeout=60
        )
        if version.returncode != 0 or not version.stdout.strip():
            raise InstallerRefusal("podman_missing", "podman is not installed or not executable")
        info = self._runner.run(
            ["podman", "info", "--format", "{{.Host.Security.Rootless}}"], timeout=60
        )
        if info.returncode != 0:
            raise InstallerRefusal("podman_probe_failed", "podman info failed")
        systemd = self._runner.run(
            ["systemctl", "--user", "show", "--property=Version", "--value"], timeout=60
        )
        if systemd.returncode != 0:
            raise InstallerRefusal(
                "systemd_user_missing", "a systemd user session is required for Quadlets"
            )
        return HostFacts(
            kernel=kernel,
            os_id=os_id,
            version_id=version_id,
            architecture=architecture,
            cgroup_version="v2" if self._cgroup_controllers.is_file() else "v1",
            podman_version=version.stdout.strip(),
            rootless=info.stdout.strip() == "true",
            quadlet=any(candidate.is_file() for candidate in self._quadlet_candidates),
            systemd_user=True,
            subuid_configured=self._subordinate_mapping_configured(self._subuid_path),
            subgid_configured=self._subordinate_mapping_configured(self._subgid_path),
        )

    def occupied_ports(self) -> list[int]:
        ports: set[int] = set()
        for path in self._proc_net_tcp:
            try:
                lines = path.read_text(encoding="ascii").splitlines()[1:]
            except OSError:
                continue
            for line in lines:
                fields = line.split()
                if len(fields) < 4 or fields[3] != "0A":  # LISTEN only
                    continue
                _, separator, port_hex = fields[1].rpartition(":")
                if separator:
                    ports.add(int(port_hex, 16))
        return sorted(ports)


@dataclass(frozen=True)
class VerifiedModules:
    """Wheel-loaded contract and updater modules (verified code boundary)."""

    release: Any
    updater_engine: Any
    updater_installed: Any
    updater_models: Any
    updater_store: Any


def load_modules_from_venv(venv_dir: Path) -> VerifiedModules:
    """Import release contracts and the updater from the digest-verified venv."""

    candidates = sorted(venv_dir.glob("lib/python3.*/site-packages"))
    exact = [
        candidate
        for candidate in candidates
        if (candidate / "stateport_release" / "__init__.py").is_file()
        and (candidate / "stateport_updater" / "__init__.py").is_file()
    ]
    if len(exact) != 1:
        raise InstallerRefusal(
            "venv_layout_unexpected", "the updater venv does not contain exactly one module root"
        )
    sys.path.insert(0, str(exact[0]))
    import stateport_release
    import stateport_updater.engine
    import stateport_updater.installed
    import stateport_updater.models
    import stateport_updater.store

    return VerifiedModules(
        release=stateport_release,
        updater_engine=stateport_updater.engine,
        updater_installed=stateport_updater.installed,
        updater_models=stateport_updater.models,
        updater_store=stateport_updater.store,
    )


def load_modules_from_authenticated_wheel(wheel: Path) -> VerifiedModules:
    """Import the stdlib-only release contract from authenticated wheel bytes."""

    _wheel_canonical_name(wheel)
    try:
        with zipfile.ZipFile(wheel) as archive:
            metadata_entries = [
                name
                for name in archive.namelist()
                if name.count("/") == 1 and name.endswith(".dist-info/METADATA")
            ]
            if len(metadata_entries) != 1:
                raise ValueError("the wheel has no exact metadata record")
            metadata = archive.read(metadata_entries[0]).decode("utf-8")
    except (OSError, KeyError, UnicodeDecodeError, ValueError, zipfile.BadZipFile) as exc:
        raise InstallerRefusal(
            "wheel_layout_invalid", "the authenticated updater wheel is not importable"
        ) from exc
    if (
        "Name: stateport-updater\n" not in metadata.replace("\r\n", "\n")
        or any(line.casefold().startswith("requires-dist:") for line in metadata.splitlines())
    ):
        raise InstallerRefusal(
            "wheel_layout_invalid", "the authenticated updater wheel is not dependency-free"
        )
    required_modules = (
        "stateport_release",
        "stateport_updater",
        "stateport_updater.engine",
        "stateport_updater.installed",
        "stateport_updater.models",
        "stateport_updater.store",
    )
    if any(name in sys.modules for name in required_modules):
        raise InstallerRefusal(
            "wheel_import_conflict", "release-contract modules were imported before authentication"
        )
    sys.path.insert(0, str(wheel))
    try:
        import stateport_release
        import stateport_updater.engine
        import stateport_updater.installed
        import stateport_updater.models
        import stateport_updater.store
    except Exception as exc:
        raise InstallerRefusal(
            "wheel_layout_invalid", "the authenticated updater wheel cannot load its contract"
        ) from exc
    expected_origin = str(wheel) + "/"
    loaded_modules = (
        stateport_release,
        stateport_updater,
        stateport_updater.engine,
        stateport_updater.installed,
        stateport_updater.models,
        stateport_updater.store,
    )
    if any(not str(getattr(module, "__file__", "")).startswith(expected_origin) for module in loaded_modules):
        raise InstallerRefusal(
            "wheel_import_conflict", "release-contract modules did not load from authenticated bytes"
        )
    return VerifiedModules(
        release=stateport_release,
        updater_engine=stateport_updater.engine,
        updater_installed=stateport_updater.installed,
        updater_models=stateport_updater.models,
        updater_store=stateport_updater.store,
    )


@dataclass(frozen=True)
class InstallConfig:
    """Exact installer inputs; each artifact value is a local path or https URL."""

    release_index: str
    bundle_root: Path
    trust_public_key: Path
    trust_key_id: str
    trust_key_fingerprint: str
    updater_wheel: str
    channel: str
    cosign: Path
    state_root: Path
    live_quadlet_root: Path
    actor_id: str
    systemd_user_root: Path | None = None
    execution_host_receipt: Path | None = None
    release_index_sha256: str | None = None
    installer_path: Path | None = None
    execution_host_provisioner: str | None = None
    compose: str | None = None
    source_archive: str | None = None
    release_notes: str | None = None
    known_limitations: str | None = None
    podman_package_bundle: str | None = None
    podman_package_preflight: Path | None = None
    confirmed_package_plan_digest: str | None = None
    expected_target: str = EXPECTED_TARGET
    assume_yes: bool = False
    confirmed_plan_digest: str | None = None
    prepare_execution_host: bool = False
    health_timeout_seconds: float = 600.0
    health_poll_seconds: float = 2.0


@dataclass(frozen=True)
class PackageBundlePreflightConfig:
    release_index: Path
    bundle_root: Path
    trust_public_key: Path
    trust_key_id: str
    trust_key_fingerprint: str
    cosign: Path
    installer_path: Path
    podman_package_bundle: Path
    output_dir: Path
    expected_target: str = WSL2_TARGET_ID


@dataclass(frozen=True)
class InstallOutcome:
    status: str
    code: str
    message: str
    local_url: str | None = None
    receipt_path: Path | None = None
    converged: bool = False
    execution_host: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class UninstallConfig:
    """Exact uninstall/purge inputs; both modes act on recorded resources only.

    ``purge`` is its own explicit flag — nothing about uninstall implies it —
    and it stays refused until ``confirm_purge`` names the exact installed
    identity ID from the durable ``install-trust.json`` record.
    """

    state_root: Path
    live_quadlet_root: Path
    actor_id: str
    systemd_user_root: Path | None = None
    purge: bool = False
    confirm_purge: str | None = None


# ---------------------------------------------------------------------------
# stdlib trust bootstrap helpers
# ---------------------------------------------------------------------------


def _canonical_subset_bytes(value: Any) -> bytes:
    """Serialize with the exact ``stateport.canonical-json/v1`` subset.

    The signed payload permits only integers (never floats), NFC strings, and
    unique object keys; this re-serialization is byte-identical to the
    contract's ``canonical_json_bytes`` for that subset and is cross-checked
    against the wheel-loaded contract before any trust decision relies on it.
    """

    def check(item: Any, path: str) -> None:
        if item is None or isinstance(item, bool) or isinstance(item, int):
            return
        if isinstance(item, float):
            raise InstallerRefusal("index_not_canonical", f"{path}: floats are not canonical")
        if isinstance(item, str):
            if unicodedata.normalize("NFC", item) != item:
                raise InstallerRefusal("index_not_canonical", f"{path}: strings must be NFC")
            if any(0xD800 <= ord(character) <= 0xDFFF for character in item):
                raise InstallerRefusal("index_not_canonical", f"{path}: surrogates are forbidden")
            return
        if isinstance(item, list):
            for position, entry in enumerate(item):
                check(entry, f"{path}[{position}]")
            return
        if isinstance(item, dict):
            for key, entry in item.items():
                if not isinstance(key, str):
                    raise InstallerRefusal("index_not_canonical", f"{path}: keys must be strings")
                check(key, f"{path}.<key>")
                check(entry, f"{path}.{key}")
            return
        raise InstallerRefusal("index_not_canonical", f"{path}: unsupported value type")

    check(value, "$")
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


_OWN_RELEASE_LABEL = "Label=io.stateport.release.signed-payload="
_PUBLISH_PORT = re.compile(r"^PublishPort=127\.0\.0\.1:(\d+):\d+\s*$", re.MULTILINE)
_SERVICE_ID_LABEL = re.compile(r"^Label=io\.stateport\.service\.id=(.+)$", re.MULTILINE)
_PROFILE_LABEL = re.compile(r"^Label=io\.stateport\.profile=(.+)$", re.MULTILINE)


_PUBLISH_PORT_PAIR = re.compile(
    r"^PublishPort=127\.0\.0\.1:(\d+):(\d+)\s*$", re.MULTILINE
)


def _published_ports_from_unit_text(text: str) -> dict[tuple[str, int], int]:
    """Map (serviceId, containerPort) -> hostPort for one unit's bytes."""

    service_match = _SERVICE_ID_LABEL.search(text)
    profile_match = _PROFILE_LABEL.search(text)
    if service_match is None or profile_match is None or profile_match.group(1) != "accepted":
        return {}
    published: dict[tuple[str, int], int] = {}
    for host_port, container_port in _PUBLISH_PORT_PAIR.findall(text):
        published[(service_match.group(1), int(container_port))] = int(host_port)
    return published


def _apply_published_ports(
    ports: dict[str, int],
    target_services: Sequence[Mapping[str, Any]],
    published: Mapping[tuple[str, int], int],
    *,
    source: str,
) -> tuple[dict[str, int], list[str]]:
    reconciled = dict(ports)
    drift: list[str] = []
    for service in target_services:
        service_id = str(service["serviceId"])
        for port in service["ports"]:
            key = f"{service_id}:accepted:{port['name']}"
            if key not in reconciled:
                continue
            unit_key = (service_id, int(port["containerPort"]))
            if unit_key not in published:
                continue
            if reconciled[key] != published[unit_key]:
                drift.append(f"{key}: manifest={reconciled[key]} unit={published[unit_key]}")
                reconciled[key] = published[unit_key]
    if drift:
        print(
            f"notice: port allocation drifted between ceremonies; using {source} ports ("
            + "; ".join(sorted(drift)[:8]) + ")",
            flush=True,
        )
    return reconciled, drift


def _reconcile_ports_with_installed_units(
    ports: dict[str, int],
    staged: Mapping[str, bytes],
    prefix: str,
    target_services: Sequence[Mapping[str, Any]],
) -> dict[str, int]:
    """Pin health-poll ports to the exact unit bytes this install stages.

    The port-allocation ceremony is deterministic per inventory, but the plan
    ceremony and the staging ceremony observe host collisions at different
    moments; when they disagree by one probe step the manifest names a port
    no unit publishes.  Staged unit bytes override the manifest value; a
    declared port missing from its unit is tolerated here (the post-install
    live reconciliation is the authority and refuses then).
    """

    published: dict[tuple[str, int], int] = {}
    for relative, content in staged.items():
        if not relative.startswith(prefix) or not relative.endswith(".container"):
            continue
        published.update(_published_ports_from_unit_text(content.decode("utf-8")))
    reconciled, _ = _apply_published_ports(
        ports, target_services, published, source="staged"
    )
    return reconciled


def _reconcile_ports_with_live_units(
    ports: dict[str, int],
    target_services: Sequence[Mapping[str, Any]],
    artifacts: Sequence[Mapping[str, Any]],
    *,
    live_root: Path,
    control_root: Path,
    runner: Any,
    provisioned: bool,
) -> dict[str, int]:
    """Pin health-poll ports to the units actually started on this host.

    When the root provisioning transaction ran, it re-rendered control-plane
    units with its own collision inventory; the activated unit files —
    installer-owned in the live Quadlet root, control-owned under
    /var/lib/stateport-control — are then the only authoritative statement of
    which host ports this runtime publishes, and a declared port missing from
    its started unit is a hard refusal: polling it would manufacture a health
    timeout.  Without provisioning, control-owned units are not started by
    this transaction and their absence is not an error.
    """

    published: dict[tuple[str, int], int] = {}
    read_units: list[str] = []
    for artifact in artifacts:
        if artifact.get("profile") != "accepted" or artifact.get("kind") != "container":
            continue
        relative = artifact.get("liveRelativePath")
        if not isinstance(relative, str):
            continue
        owner = artifact.get("owner")
        unit_path = (control_root if owner == "stateport-control" else live_root) / PurePosixPath(relative).name
        text: str | None = None
        if owner == "stateport-control":
            try:
                if unit_path.is_file() and not unit_path.is_symlink():
                    text = unit_path.read_text(encoding="utf-8")
            except OSError:
                text = None
            if text is None and provisioned:
                read = runner.run(["sudo", "-n", "cat", str(unit_path)], timeout=60)
                convergence_copy = live_root / unit_path.name
                if read.returncode != 0:
                    if convergence_copy.is_file() and not convergence_copy.is_symlink():
                        # The installer's own convergence copy of this unit
                        # carries the staged render; without evidence of a
                        # diverging re-render it is the best available truth.
                        text = convergence_copy.read_text(encoding="utf-8")
                        print(
                            f"notice: control unit {unit_path.name} unreadable; "
                            "using the staged convergence copy",
                            flush=True,
                        )
                    else:
                        raise InstallerRefusal(
                            "port_publication_missing",
                            f"cannot read installed control unit {unit_path.name}: "
                            f"{read.stderr.strip()[:200]}",
                        )
                else:
                    text = read.stdout
        elif unit_path.is_file() and not unit_path.is_symlink():
            text = unit_path.read_text(encoding="utf-8")
        elif provisioned:
            raise InstallerRefusal(
                "port_publication_missing",
                f"installed accepted unit is missing: {unit_path.name}",
            )
        if text is None:
            continue
        published.update(_published_ports_from_unit_text(text))
        service_match = _SERVICE_ID_LABEL.search(text)
        if service_match is not None:
            read_units.append(service_match.group(1))
    reconciled, drift = _apply_published_ports(
        ports, target_services, published, source="installed"
    )
    missing: list[str] = []
    for service in target_services:
        service_id = str(service["serviceId"])
        for port in service["ports"]:
            key = f"{service_id}:accepted:{port['name']}"
            if (
                key in reconciled
                and (service_id, int(port["containerPort"])) not in published
                and service_id in read_units
            ):
                missing.append(key)
    if missing:
        raise InstallerRefusal(
            "port_publication_missing",
            "declared ports absent from started units: " + ", ".join(sorted(missing)),
        )
    return reconciled


def _own_live_unit_ports(live_root: Path, signed_payload_digest: str) -> set[int]:
    """Host ports published by THIS release's own live accepted units.

    Live units of any OTHER release (or unsigned content) are not ours and
    their ports stay in the collision inventory.
    """
    ports: set[int] = set()
    if not live_root.is_dir():
        return ports
    marker = f"{_OWN_RELEASE_LABEL}{signed_payload_digest}"
    for path in sorted(live_root.glob("*.container")):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if marker not in text:
            continue
        ports.update(int(match) for match in _PUBLISH_PORT.findall(text))
    return ports


def _readable_probe(path: Path) -> bool:
    """Existence check that survives a stat-refused parent directory.

    /var/lib/stateport-control is root-owned; the invoking installer cannot
    even lstat inside it.  A refused probe means "present but unverifiable
    directly", which callers treat as present for convergence and verify
    through the privileged channels where bytes matter.
    """
    try:
        path.lstat()
        return True
    except PermissionError:
        return True
    except OSError:
        return False


def _live_runtime_present(
    config: InstallConfig, state_root: Path, signed_payload_digest: str
) -> bool:
    """Whether the accepted runtime this release installed still exists live.

    Verified from the installation's own staged manifest: every accepted
    container/network artifact's live unit file and the accepted activation
    target.  Missing manifest or any missing piece means the runtime is gone
    (for example after a non-purge uninstall).
    """
    signed_hex = signed_payload_digest.removeprefix("sha256:")
    manifest_path = state_root / "releases" / "staged" / signed_hex / "materialization.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        return False
    try:
        manifest = _load_json(manifest_path, "staged materialization manifest")
    except InstallerRefusal:
        return False
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        return False
    accepted = [
        artifact
        for artifact in artifacts
        if isinstance(artifact, dict)
        and artifact.get("profile") == "accepted"
        and artifact.get("kind") in {"container", "network"}
    ]
    if not accepted:
        return False
    control_root = Path("/var/lib/stateport-control/.config/containers/systemd")
    control_present = any(
        artifact.get("owner") == "stateport-control" for artifact in accepted
    ) and all(
        _readable_probe(control_root / a["liveRelativePath"])
        for a in accepted
        if a.get("owner") == "stateport-control"
    )
    for artifact in accepted:
        live_relative = artifact.get("liveRelativePath")
        if not isinstance(live_relative, str):
            return False
        if artifact.get("owner") == "stateport-control" and control_present:
            # Control-plane units live in the stateport-control user's live
            # Quadlet root (installed by the root provisioning transaction).
            unit_path = control_root / live_relative
        else:
            unit_path = config.live_quadlet_root / live_relative
        if not _readable_probe(unit_path):
            return False
    if control_present:
        target_path = (
            Path("/var/lib/stateport-control/.config/systemd/user") / ACCEPTED_ACTIVATION_TARGET
        )
    else:
        target_path = _systemd_user_root(config) / ACCEPTED_ACTIVATION_TARGET
    return _readable_probe(target_path)


def _sha256_digest(content: bytes) -> str:    return "sha256:" + hashlib.sha256(content).hexdigest()


def _local_image_manifest_payloads(index: Any, bundle_root: Path) -> dict[str, bytes]:
    """Load exact local OCI manifests required by private candidate signatures."""

    payloads: dict[str, bytes] = {}
    for image in index.document["signed"]["images"]:
        signature = image["signature"]
        if signature.get("subjectKind") != "oci-manifest-blob":
            continue
        image_id = str(image["imageId"])
        candidates = (
            bundle_root / "image-archives" / f"{image_id}.oci.tar",
            bundle_root / f"{image_id}.oci.tar",
        )
        archive_path = next(
            (path for path in candidates if path.is_file() and not path.is_symlink()), None
        )
        if archive_path is None:
            continue
        try:
            with tarfile.open(archive_path, mode="r:*") as archive:
                members = {member.name: member for member in archive.getmembers()}
                index_member = members.get("index.json")
                if index_member is None or not index_member.isfile():
                    raise InstallerRefusal(
                        "image_archive_invalid", f"private image archive has no OCI index: {image_id}"
                    )
                oci_index = json.loads(archive.extractfile(index_member).read())  # type: ignore[union-attr]
                manifests = oci_index.get("manifests") if isinstance(oci_index, Mapping) else None
                if not isinstance(manifests, list) or len(manifests) != 1:
                    raise InstallerRefusal(
                        "image_archive_invalid", f"private image archive has no single manifest: {image_id}"
                    )
                digest = manifests[0].get("digest") if isinstance(manifests[0], Mapping) else None
                if digest != signature.get("subjectDigest"):
                    raise InstallerRefusal(
                        "image_archive_mismatch", f"private image archive is not candidate-bound: {image_id}"
                    )
                blob = members.get("blobs/sha256/" + str(digest).removeprefix("sha256:"))
                if blob is None or not blob.isfile():
                    raise InstallerRefusal(
                        "image_archive_invalid", f"private image archive manifest is missing: {image_id}"
                    )
                payload = archive.extractfile(blob).read()  # type: ignore[union-attr]
                if _sha256_digest(payload) != digest:
                    raise InstallerRefusal(
                        "image_archive_tampered", f"private image archive manifest is tampered: {image_id}"
                    )
                payloads[image_id] = payload
        except InstallerRefusal:
            raise
        except (OSError, tarfile.TarError, json.JSONDecodeError) as exc:
            raise InstallerRefusal(
                "image_archive_invalid", f"private image archive could not be read: {image_id}"
            ) from exc
    return payloads


def _retain_local_image_archives(source_root: Path, destination_root: Path) -> None:
    """Retain private-candidate OCI archives for updater re-verification."""

    source = source_root / "image-archives"
    if not source.is_dir() or source.is_symlink():
        return
    destination = destination_root / "image-archives"
    destination.mkdir(mode=0o700, exist_ok=True)
    for archive in source.iterdir():
        if archive.is_symlink() or not archive.is_file() or archive.suffixes[-2:] != [".oci", ".tar"]:
            continue
        target = destination / archive.name
        if target.exists() or target.is_symlink():
            if not target.is_file() or target.read_bytes() != archive.read_bytes():
                raise InstallerRefusal(
                    "image_archive_conflict", f"retained image archive differs: {archive.name}"
                )
            continue
        shutil.copyfile(archive, target)


def _read_bounded(path: Path, *, description: str, maximum: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise InstallerRefusal("input_unsafe", f"{description} is not a regular file: {path}")
    size = path.stat().st_size
    if size < 1 or size > maximum:
        raise InstallerRefusal("input_unsafe", f"{description} has an unsafe size: {path}")
    return path.read_bytes()


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def der_spki_fingerprint(pem: bytes) -> str:
    """SHA-256 over the DER SubjectPublicKeyInfo of a PEM public key (stdlib)."""

    try:
        text = pem.decode("ascii").replace("\r\n", "\n")
    except UnicodeDecodeError as exc:
        raise InstallerRefusal("trust_key_invalid", "trust public key is not ASCII PEM") from exc
    match = re.search(
        r"-----BEGIN PUBLIC KEY-----\n([A-Za-z0-9+/=\n]+)\n?-----END PUBLIC KEY-----",
        text,
    )
    if match is None:
        raise InstallerRefusal(
            "trust_key_invalid", "trust public key is not a PEM SubjectPublicKeyInfo"
        )
    body = match.group(1).replace("\n", "")
    try:
        der = base64.b64decode(body, validate=True)
    except ValueError as exc:
        raise InstallerRefusal("trust_key_invalid", "trust public key PEM body is invalid") from exc
    if not der:
        raise InstallerRefusal("trust_key_invalid", "trust public key DER is empty")
    return _sha256_digest(der)


def _acquire_input(
    value: str | None,
    *,
    description: str,
    expected_sha256: str | None,
    require_published_digest: bool,
    fetcher: Fetcher,
    download_dir: Path,
    maximum: int = MAX_ARTIFACT_BYTES,
) -> Path:
    """Resolve one artifact input to a local path.

    Local paths are used directly.  ``https://`` inputs are downloaded with a
    bounded read; the published SHA-256 is verified before any later use when
    one is independently supplied (the release index), and the remaining
    artifacts are verified against the authenticated signed index afterwards.
    """

    if value is None:
        raise InstallerRefusal(
            "artifact_missing",
            f"the {description} input is required: the install receipt binds the exact "
            "verified artifact set and no unverified stand-in is ever recorded",
        )
    if not value.startswith("https://"):
        return Path(value)
    if require_published_digest and (
        expected_sha256 is None or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
    ):
        raise InstallerRefusal(
            "published_digest_missing",
            f"downloading the {description} requires its published SHA-256 up front",
        )
    result = fetcher.fetch(value, timeout=120.0, max_bytes=maximum)
    if result.status != 200 or not result.body:
        raise InstallerRefusal(
            "download_failed", f"{description} download failed with status {result.status}"
        )
    observed = hashlib.sha256(result.body).hexdigest()
    if expected_sha256 is not None and observed != expected_sha256:
        raise InstallerRefusal(
            "download_digest_mismatch",
            f"{description} downloaded digest {observed} != published {expected_sha256}",
        )
    destination = download_dir / f"{description.replace(' ', '-')}-{observed[:16]}"
    _atomic_write(destination, result.body)
    return destination


@dataclass(frozen=True)
class BootstrapIndex:
    document: Mapping[str, Any]
    signed: Mapping[str, Any]
    signed_bytes: bytes
    signed_digest: str
    index_digest: str


def _bootstrap_authenticate(
    config: InstallConfig | PackageBundlePreflightConfig,
    index_content: bytes,
    work_dir: Path,
    runner: Runner,
) -> BootstrapIndex:
    """Authenticate the release index with the pinned Cosign CLI (trust step 2)."""

    if len(index_content) > MAX_INDEX_BYTES:
        raise InstallerRefusal("index_too_large", "release index exceeds the 4 MiB limit")
    try:
        document = json.loads(index_content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InstallerRefusal("index_malformed", "release index is not UTF-8 JSON") from exc
    if not isinstance(document, dict) or not isinstance(document.get("signed"), dict):
        raise InstallerRefusal("index_malformed", "release index has no signed payload object")
    signatures = document.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != 1:
        raise InstallerRefusal("index_malformed", "release index must carry exactly one signature")
    signature = signatures[0]
    if not isinstance(signature, dict):
        raise InstallerRefusal("index_malformed", "release index signature is not an object")
    signed_bytes = _canonical_subset_bytes(document["signed"])
    signed_digest = _sha256_digest(signed_bytes)
    if signature.get("subjectDigest") != signed_digest:
        raise InstallerRefusal(
            "signature_payload_mismatch",
            "signature subject digest does not match the canonical signed payload",
        )
    if signature.get("scheme") != "cosign-v3-bundle":
        raise InstallerRefusal("signature_scheme_refused", "signature is not a Cosign v3 bundle")
    if signature.get("trustMode") != "pinned-public-key":
        raise InstallerRefusal(
            "signature_trust_refused", "signature is outside the pinned-public-key trust root"
        )
    if signature.get("transparencyLog") != "not-uploaded-private-candidate":
        raise InstallerRefusal(
            "signature_trust_refused",
            "signature claims transparency-log authority the private toolchain never uploads",
        )
    if signature.get("publicKeyFingerprintAlgorithm") != "sha256-canonical-der-spki":
        raise InstallerRefusal(
            "signature_trust_refused", "signature uses a non-canonical fingerprint algorithm"
        )
    if (
        signature.get("publicKeyFingerprint") != config.trust_key_fingerprint
        or signature.get("publicKeyId") != config.trust_key_id
    ):
        raise InstallerRefusal(
            "signature_untrusted", "signature is not bound to the pinned key identity"
        )
    bundle = signature.get("bundle")
    if not isinstance(bundle, dict) or _DIGEST.fullmatch(str(bundle.get("digest", ""))) is None:
        raise InstallerRefusal("signature_bundle_invalid", "signature has no digest-bound bundle")
    name = PurePosixPath(str(bundle.get("uri", ""))).name
    if _BUNDLE_NAME.fullmatch(name) is None:
        raise InstallerRefusal("signature_bundle_invalid", "bundle URI names no retained bundle")
    bundle_path = config.bundle_root / name
    bundle_bytes = _read_bounded(
        bundle_path, description="release index signature bundle", maximum=MAX_INDEX_BYTES
    )
    if _sha256_digest(bundle_bytes) != bundle["digest"] or len(bundle_bytes) != bundle.get("size"):
        raise InstallerRefusal(
            "signature_bundle_mismatch", "retained bundle bytes do not match the signed record"
        )
    payload_path = work_dir / "release-index.signed-payload.json"
    _atomic_write(payload_path, signed_bytes)
    completed = runner.run(
        [
            str(config.cosign),
            "verify-blob",
            "--insecure-ignore-tlog",
            "--bundle",
            str(bundle_path),
            "--key",
            str(config.trust_public_key),
            str(payload_path),
        ],
        timeout=300,
    )
    if completed.returncode != 0:
        raise InstallerRefusal(
            "signature_verification_failed",
            f"cosign verify-blob failed: {completed.stderr.strip()[:200]}",
        )
    return BootstrapIndex(
        document=document,
        signed=document["signed"],
        signed_bytes=signed_bytes,
        signed_digest=signed_digest,
        index_digest=_sha256_digest(_canonical_subset_bytes(document)),
    )


def _extract_podman_package_bundle(
    content: bytes, output_dir: Path
) -> set[str]:
    """Extract an uncompressed package tar without trusting archive paths or types."""

    try:
        archive = tarfile.open(fileobj=BytesIO(content), mode="r:")
    except tarfile.TarError as exc:
        raise InstallerRefusal(
            "package_bundle_invalid", "Podman package bundle is not an uncompressed tar"
        ) from exc
    with archive:
        members = archive.getmembers()
        if not members or len(members) > 256:
            raise InstallerRefusal(
                "package_bundle_invalid", "Podman package bundle member count is invalid"
            )
        normalized: dict[str, tarfile.TarInfo] = {}
        total_size = 0
        for member in members:
            name = member.name.rstrip("/") if member.isdir() else member.name
            relative = PurePosixPath(name)
            if (
                not name
                or relative.is_absolute()
                or any(part in {"", ".", ".."} for part in relative.parts)
                or relative.parts[0] != "podman-package-bundle"
                or name in normalized
                or not (member.isdir() or member.isfile())
                or bool(getattr(member, "sparse", None))
            ):
                raise InstallerRefusal(
                    "package_bundle_invalid",
                    "Podman package bundle contains an unsafe, duplicate, or non-regular member",
                )
            total_size += member.size
            if total_size > MAX_ARTIFACT_BYTES:
                raise InstallerRefusal(
                    "package_bundle_invalid", "Podman package bundle expands beyond its limit"
                )
            normalized[name] = member
        output_dir.mkdir(mode=0o700)
        try:
            for name, member in normalized.items():
                destination = output_dir.joinpath(*PurePosixPath(name).parts)
                if member.isdir():
                    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
                    continue
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise InstallerRefusal(
                        "package_bundle_invalid", "Podman package member cannot be read"
                    )
                with source, destination.open("xb") as stream:
                    shutil.copyfileobj(source, stream, length=1024 * 1024)
                    stream.flush()
                    os.fsync(stream.fileno())
                destination.chmod(0o600)
        except Exception:
            shutil.rmtree(output_dir)
            raise
    return set(normalized)


def verify_podman_package_bundle(
    config: PackageBundlePreflightConfig, *, runner: Runner
) -> Mapping[str, Any]:
    """Authenticate and unpack the exact Alpha.11 host package set before sudo."""

    if _KEY_ID.fullmatch(config.trust_key_id) is None or _DIGEST.fullmatch(
        config.trust_key_fingerprint
    ) is None:
        raise InstallerRefusal("trust_key_invalid", "package preflight trust identity is malformed")
    if not config.cosign.is_file() or config.cosign.is_symlink():
        raise InstallerRefusal("cosign_missing", "package preflight requires the pinned Cosign executable")
    pem = _read_bounded(config.trust_public_key, description="trust public key", maximum=64 * 1024)
    if der_spki_fingerprint(pem) != config.trust_key_fingerprint:
        raise InstallerRefusal("trust_key_invalid", "package preflight trust key fingerprint differs")
    if not config.bundle_root.is_dir() or config.bundle_root.is_symlink():
        raise InstallerRefusal("bundle_root_invalid", "package preflight bundle root is unsafe")
    if config.output_dir.exists() or config.output_dir.is_symlink():
        raise InstallerRefusal("package_output_conflict", "package preflight output must be absent")
    if not config.output_dir.parent.is_dir() or config.output_dir.parent.is_symlink():
        raise InstallerRefusal("package_output_invalid", "package preflight output parent is unsafe")

    index_content = _read_bounded(
        config.release_index, description="release index", maximum=MAX_INDEX_BYTES
    )
    try:
        with tempfile.TemporaryDirectory(
            prefix=".stateport-package-preflight-", dir=config.output_dir.parent
        ) as temporary:
            bootstrap = _bootstrap_authenticate(
                config, index_content, Path(temporary), runner
            )
        signed = bootstrap.signed
        artifacts = signed.get("artifacts")
        expected_artifacts = {
            "installer",
            "executionHostProvisioner",
            "podmanPackageBundle",
            "updater",
            "compose",
            "quadlet",
            "sourceArchive",
            "releaseNotes",
            "knownLimitations",
        }
        if not isinstance(artifacts, dict) or set(artifacts) != expected_artifacts:
            raise InstallerRefusal(
                "index_malformed", "package preflight requires the exact Alpha.11 artifact inventory"
            )
        targets = signed.get("targets")
        if (
            not isinstance(targets, list)
            or len(targets) != 1
            or targets[0].get("targetId") != config.expected_target
            or set(targets[0].get("artifactIds", [])) != expected_artifacts
        ):
            raise InstallerRefusal(
                "target_mismatch", "package preflight index does not bind the exact WSL2 target"
            )
        installer_artifact = artifacts["installer"]
        package_artifact = artifacts["podmanPackageBundle"]
        _verify_artifact_bytes(
            config.installer_path, "installer", str(installer_artifact.get("digest"))
        )
        package_bytes = _read_bounded(
            config.podman_package_bundle,
            description="Podman package bundle",
            maximum=MAX_ARTIFACT_BYTES,
        )
        if (
            package_artifact.get("digest") != _sha256_digest(package_bytes)
            or package_artifact.get("size") != len(package_bytes)
            or package_artifact.get("mediaType")
            != "application/vnd.stateport.podman-package-bundle+tar"
        ):
            raise InstallerRefusal(
                "artifact_digest_mismatch",
                "Podman package bundle differs from the authenticated release artifact",
            )

        listed_paths = _extract_podman_package_bundle(package_bytes, config.output_dir)
        root = config.output_dir / "podman-package-bundle"
        manifest_path = root / "manifest.json"
        sums_path = root / "SHA256SUMS"
        if any(path.is_symlink() for path in config.output_dir.rglob("*")):
            raise InstallerRefusal("package_bundle_invalid", "package bundle extracted a symlink")
        try:
            manifest_bytes = _read_bounded(
                manifest_path, description="Podman package manifest", maximum=1024 * 1024
            )
            manifest = json.loads(manifest_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise InstallerRefusal(
                "package_bundle_invalid", "Podman package manifest is invalid JSON"
            ) from exc
        if (
            not isinstance(manifest, dict)
            or set(manifest)
            != {"install", "packages", "rootfs", "schema", "sourceDateEpoch", "target"}
            or manifest.get("schema") != _PODMAN_PACKAGE_BUNDLE_SCHEMA
            or manifest.get("target") != config.expected_target
            or manifest.get("rootfs") != _WSL_ROOTFS_IDENTITY
            or not isinstance(manifest.get("sourceDateEpoch"), int)
            or manifest["sourceDateEpoch"] < 1
            or not isinstance(manifest.get("packages"), list)
            or not len(_PODMAN_REQUIRED_PACKAGE_NAMES) <= len(manifest["packages"]) <= 128
        ):
            raise InstallerRefusal(
                "package_bundle_invalid", "Podman package manifest shape or target is invalid"
            )
        package_records: dict[str, Mapping[str, Any]] = {}
        expected_paths = {
            "podman-package-bundle",
            "podman-package-bundle/SHA256SUMS",
            "podman-package-bundle/manifest.json",
            "podman-package-bundle/packages",
        }
        expected_sums: list[str] = []
        for record in manifest["packages"]:
            if (
                not isinstance(record, dict)
                or set(record)
                != {"architecture", "file", "name", "sha256", "size", "version"}
                or not isinstance(record.get("name"), str)
                or re.fullmatch(r"[a-z0-9][a-z0-9+.-]{0,127}", record["name"]) is None
                or record.get("architecture") not in {"all", "amd64"}
                or not isinstance(record.get("file"), str)
                or PurePosixPath(record["file"]).name != record["file"]
                or not record["file"].endswith(f"_{record.get('architecture')}.deb")
                or not isinstance(record.get("sha256"), str)
                or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None
                or not isinstance(record.get("size"), int)
                or record["size"] < 1
                or not isinstance(record.get("version"), str)
                or not record["version"]
                or record["name"] in package_records
            ):
                raise InstallerRefusal(
                    "package_bundle_invalid", "Podman package manifest record is invalid"
                )
            package_records[record["name"]] = record
            package_path = root / "packages" / record["file"]
            payload = _read_bounded(
                package_path, description=f"{record['name']} package", maximum=MAX_ARTIFACT_BYTES
            )
            if len(payload) != record["size"] or hashlib.sha256(payload).hexdigest() != record["sha256"]:
                raise InstallerRefusal(
                    "package_bundle_invalid", f"{record['name']} package bytes differ from the manifest"
                )
            expected_paths.add(f"podman-package-bundle/packages/{record['file']}")
            expected_sums.append(f"{record['sha256']}  packages/{record['file']}")
            metadata = runner.run(
                [
                    "dpkg-deb",
                    "--field",
                    str(package_path),
                    "Package",
                    "Version",
                    "Architecture",
                ],
                timeout=120,
            )
            observed_fields = dict(
                line.split(": ", 1)
                for line in metadata.stdout.splitlines()
                if ": " in line
            )
            if metadata.returncode != 0 or observed_fields != {
                "Package": record["name"],
                "Version": record["version"],
                "Architecture": record["architecture"],
            }:
                raise InstallerRefusal(
                    "package_bundle_invalid", f"{record['name']} Debian metadata differs from the manifest"
                )
        if not _PODMAN_REQUIRED_PACKAGE_NAMES <= set(package_records) or manifest.get("install") != {
            "packageNames": sorted(package_records),
            "packageVersions": {
                name: package_records[name]["version"] for name in sorted(package_records)
            },
        }:
            raise InstallerRefusal(
                "package_bundle_invalid", "Podman package install inventory is incomplete"
            )
        sums = _read_bounded(
            sums_path, description="Podman package SHA256SUMS", maximum=1024 * 1024
        ).decode("ascii")
        if sums != "\n".join(sorted(expected_sums)) + "\n" or listed_paths != expected_paths:
            raise InstallerRefusal(
                "package_bundle_invalid", "Podman package bundle inventory is not exact"
            )
        podman_record = package_records["podman"]
        dependencies = runner.run(
            [
                "dpkg-deb",
                "--field",
                str(root / "packages" / podman_record["file"]),
                "Depends",
            ],
            timeout=120,
        )
        depends = dependencies.stdout.strip()
        if (
            dependencies.returncode != 0
            or "runc (>= 1.3.4)" not in depends
            or "slirp4netns (>= 1.2.1)" not in depends
            or re.search(r"(?:^|, )(?:crun|passt)(?: |,|$)", depends) is not None
        ):
            raise InstallerRefusal(
                "package_bundle_invalid", "Podman package lacks the qualified Noble runtime contract"
            )
        podman_floor = runner.run(
            ["dpkg", "--compare-versions", str(podman_record["version"]), "ge", "5.4.2"],
            timeout=30,
        )
        if podman_floor.returncode != 0:
            raise InstallerRefusal(
                "package_bundle_invalid", "Podman package is below the signed runtime floor"
            )
        transaction: dict[str, dict[str, Any]] = {}
        for name, record in sorted(package_records.items()):
            queried = runner.run(
                [
                    "dpkg-query",
                    "--show",
                    "--showformat=${db:Status-Status}\\t${Version}\\t${Architecture}\\n",
                    name,
                ],
                timeout=30,
            )
            fields = queried.stdout.strip().split("\t")
            if queried.returncode == 0 and fields[:1] != ["not-installed"]:
                if (
                    len(fields) != 3
                    or fields[0] != "installed"
                    or fields[2] != record["architecture"]
                ):
                    raise InstallerRefusal(
                        "package_baseline_invalid", f"installed {name} package identity is malformed"
                    )
                if fields[1] == record["version"]:
                    action = "keep"
                else:
                    compared = runner.run(
                        ["dpkg", "--compare-versions", fields[1], "lt", str(record["version"])],
                        timeout=30,
                    )
                    if compared.returncode != 0:
                        raise InstallerRefusal(
                            "package_baseline_invalid",
                            f"installed {name} would require a downgrade or ambiguous replacement",
                        )
                    action = "upgrade"
                current_version: str | None = fields[1]
            else:
                # A genuinely absent package makes dpkg-query exit non-zero, and
                # a negative "not-installed" record (left by apt/dpkg metadata
                # processing without the package payload, for example podman
                # after netavark is installed on a stock Noble cloud image)
                # makes it exit 0 with empty version and architecture fields.
                # Both mean the package is not actually installed, so the sealed
                # bundle installs it.
                action = "install"
                current_version = None
            transaction[name] = {
                "action": action,
                "architecture": record["architecture"],
                "currentVersion": current_version,
                "targetVersion": record["version"],
            }

        apt_lists = config.output_dir / ".apt-lists"
        (apt_lists / "partial").mkdir(parents=True, mode=0o700)
        package_paths = [
            str(root / "packages" / package_records[name]["file"])
            for name in sorted(package_records)
        ]
        simulation = runner.run(
            [
                "apt-get",
                "--simulate",
                "--no-download",
                "--no-install-recommends",
                "--no-remove",
                "-o",
                "Dir::Etc::sourcelist=/dev/null",
                "-o",
                "Dir::Etc::sourceparts=-",
                "-o",
                f"Dir::State::lists={apt_lists}",
                "install",
                *package_paths,
            ],
            timeout=300,
        )
        if simulation.returncode != 0 or re.search(r"^Remv ", simulation.stdout, re.MULTILINE):
            raise InstallerRefusal(
                "package_dependency_closure_invalid",
                "signed package bundle is not a complete repository-free dependency closure",
            )
        simulated: dict[str, str] = {}
        for line in simulation.stdout.splitlines():
            match = re.match(r"^Inst ([^ :]+)(?::[^ ]+)?(?: \[[^]]+\])? \(([^ )]+)", line)
            if match is not None:
                simulated[match.group(1)] = match.group(2)
        expected_changes = {
            name: record["targetVersion"]
            for name, record in transaction.items()
            if record["action"] != "keep"
        }
        if simulated != expected_changes:
            raise InstallerRefusal(
                "package_dependency_closure_invalid",
                "APT simulation differs from the signed local package transaction",
            )

        package_plan = {
            "releaseIndexDigest": bootstrap.index_digest,
            "signedPayloadDigest": bootstrap.signed_digest,
            "artifactDigest": package_artifact["digest"],
            "bundleManifestDigest": _sha256_digest(manifest_bytes),
            "targetId": config.expected_target,
            "rootfsIdentity": manifest["rootfs"],
            "dependencyClosure": "apt-simulated-empty-sources-no-download",
            "transaction": transaction,
            "packages": {
                name: {
                    "architecture": package_records[name]["architecture"],
                    "version": package_records[name]["version"],
                    "sha256": "sha256:" + str(package_records[name]["sha256"]),
                    "size": package_records[name]["size"],
                }
                for name in sorted(package_records)
            },
            "runtimeContract": {
                "podmanMinimumVersion": "5.4.2",
                "runcMinimumVersion": "1.3.4",
                "slirp4netnsMinimumVersion": "1.2.1",
                "ociRuntime": "runc",
                "networkBackend": "netavark",
            },
        }
        return {
            "schema": _PODMAN_PACKAGE_PREFLIGHT_SCHEMA,
            **{key: value for key, value in package_plan.items() if key != "runtimeContract"},
            "packagePlanDigest": _sha256_digest(_canonical_subset_bytes(package_plan)),
            "runtimeContract": package_plan["runtimeContract"],
            "dpkgStateBeforeDigest": _sha256_digest(_canonical_subset_bytes(transaction)),
        }
    except Exception:
        if config.output_dir.is_dir() and not config.output_dir.is_symlink():
            shutil.rmtree(config.output_dir)
        raise


def verify_installed_podman_packages(
    preflight: Mapping[str, Any],
    *,
    runner: Runner,
    require_release_admission: bool = True,
) -> Mapping[str, Any]:
    """Verify exact package versions, dependency floors, and selected Podman backends."""

    expected_fields = {
        "schema",
        "releaseIndexDigest",
        "signedPayloadDigest",
        "artifactDigest",
        "bundleManifestDigest",
        "packagePlanDigest",
        "targetId",
        "rootfsIdentity",
        "dependencyClosure",
        "transaction",
        "packages",
        "runtimeContract",
        "dpkgStateBeforeDigest",
    }
    observed_fields = frozenset(preflight)
    if observed_fields not in {
        frozenset(expected_fields),
        frozenset((*expected_fields, "releaseAdmission")),
    } or preflight.get("schema") != _PODMAN_PACKAGE_PREFLIGHT_SCHEMA:
        raise InstallerRefusal(
            "package_preflight_invalid", "Podman package preflight evidence is malformed"
        )
    admission = preflight.get("releaseAdmission")
    if (require_release_admission and admission is None) or (
        admission is not None
        and (
            not isinstance(admission, Mapping)
            or admission.get("schema") != "stateport.release-admission/v1"
            or admission.get("status") != "verified"
            or admission.get("releaseIndexDigest") != preflight["releaseIndexDigest"]
            or admission.get("signedPayloadDigest") != preflight["signedPayloadDigest"]
            or admission.get("targetId") != preflight["targetId"]
            or not isinstance(admission.get("artifactDigests"), Mapping)
            or admission["artifactDigests"].get("podmanPackageBundle")
            != preflight["artifactDigest"]
        )
    ):
        raise InstallerRefusal(
            "package_preflight_invalid", "Podman package preflight lacks exact release admission"
        )
    packages = preflight.get("packages")
    transaction = preflight.get("transaction")
    if (
        not isinstance(packages, Mapping)
        or not _PODMAN_REQUIRED_PACKAGE_NAMES <= set(packages)
        or not isinstance(transaction, Mapping)
        or set(transaction) != set(packages)
        or preflight.get("rootfsIdentity") != _WSL_ROOTFS_IDENTITY
        or preflight.get("dependencyClosure") != "apt-simulated-empty-sources-no-download"
        or preflight.get("dpkgStateBeforeDigest")
        != _sha256_digest(_canonical_subset_bytes(transaction))
    ):
        raise InstallerRefusal(
            "package_preflight_invalid", "Podman package preflight inventory is incomplete"
        )
    for name in sorted(packages):
        record = packages[name]
        action = transaction[name]
        if (
            not isinstance(record, Mapping)
            or set(record) != {"architecture", "sha256", "size", "version"}
            or record.get("architecture") not in {"all", "amd64"}
            or _DIGEST.fullmatch(str(record.get("sha256"))) is None
            or not isinstance(record.get("size"), int)
            or record["size"] < 1
            or not isinstance(record.get("version"), str)
            or not isinstance(action, Mapping)
            or set(action)
            != {"action", "architecture", "currentVersion", "targetVersion"}
            or action.get("action") not in {"install", "keep", "upgrade"}
            or action.get("architecture") != record["architecture"]
            or action.get("targetVersion") != record["version"]
            or (
                action.get("action") == "install"
                and action.get("currentVersion") is not None
            )
            or (
                action.get("action") != "install"
                and not isinstance(action.get("currentVersion"), str)
            )
        ):
            raise InstallerRefusal(
                "package_preflight_invalid", f"Podman package preflight record is invalid: {name}"
            )
    runtime_contract = preflight.get("runtimeContract")
    package_plan = {
        "releaseIndexDigest": preflight.get("releaseIndexDigest"),
        "signedPayloadDigest": preflight.get("signedPayloadDigest"),
        "artifactDigest": preflight.get("artifactDigest"),
        "bundleManifestDigest": preflight.get("bundleManifestDigest"),
        "targetId": preflight.get("targetId"),
        "rootfsIdentity": preflight.get("rootfsIdentity"),
        "dependencyClosure": preflight.get("dependencyClosure"),
        "transaction": transaction,
        "packages": {
            name: {
                key: packages[name].get(key)
                for key in ("architecture", "version", "sha256", "size")
            }
            if isinstance(packages[name], Mapping)
            else None
            for name in sorted(packages)
        },
        "runtimeContract": runtime_contract,
    }
    if (
        runtime_contract
        != {
            "podmanMinimumVersion": "5.4.2",
            "runcMinimumVersion": "1.3.4",
            "slirp4netnsMinimumVersion": "1.2.1",
            "ociRuntime": "runc",
            "networkBackend": "netavark",
        }
        or preflight.get("packagePlanDigest")
        != _sha256_digest(_canonical_subset_bytes(package_plan))
    ):
        raise InstallerRefusal(
            "package_preflight_invalid", "Podman package plan digest or runtime contract is invalid"
        )

    installed_packages: dict[str, Mapping[str, str]] = {}
    for name in sorted(packages):
        queried = runner.run(
            [
                "dpkg-query",
                "--show",
                "--showformat=${db:Status-Status}\\t${Version}\\t${Architecture}\\n",
                name,
            ],
            timeout=30,
        )
        fields = queried.stdout.strip().split("\t")
        if (
            queried.returncode != 0
            or len(fields) != 3
            or fields[0] != "installed"
            or fields[2] != packages[name]["architecture"]
        ):
            raise InstallerRefusal(
                "package_installation_invalid", f"installed {name} package identity is unavailable"
            )
        installed_packages[name] = {"version": fields[1], "architecture": fields[2]}

    for name in sorted(packages):
        record = packages[name]
        if (
            installed_packages[name]["version"] != record.get("version")
            or installed_packages[name]["architecture"] != record.get("architecture")
        ):
            raise InstallerRefusal(
                "package_version_mismatch", f"installed {name} differs from the signed package bundle"
            )
    for name, floor in sorted(_PODMAN_RUNTIME_DEPENDENCIES.items()):
        compared = runner.run(
            ["dpkg", "--compare-versions", installed_packages[name]["version"], "ge", floor],
            timeout=30,
        )
        if compared.returncode != 0:
            raise InstallerRefusal(
                "package_dependency_mismatch", f"installed {name} is below the qualified {floor} floor"
            )

    selection = runner.run(
        [
            "podman",
            "info",
            "--format",
            "{{.Host.OCIRuntime.Name}}|{{.Host.NetworkBackend}}",
        ],
        timeout=60,
    )
    selected = selection.stdout.strip().split("|")
    if selection.returncode != 0 or selected != ["runc", "netavark"]:
        raise InstallerRefusal(
            "package_runtime_mismatch", "Podman did not select the qualified runc/netavark runtime"
        )
    audit = runner.run(["dpkg", "--audit"], timeout=60)
    if audit.returncode != 0 or audit.stdout.strip() or audit.stderr.strip():
        raise InstallerRefusal(
            "package_installation_invalid", "dpkg reports an incomplete package transaction"
        )

    installed_state = {
        name: {
            "architecture": installed_packages[name]["architecture"],
            "version": installed_packages[name]["version"],
        }
        for name in sorted(installed_packages)
    }
    return {
        "schema": _PODMAN_PACKAGE_INSTALLATION_SCHEMA,
        "releaseIndexDigest": preflight["releaseIndexDigest"],
        "signedPayloadDigest": preflight["signedPayloadDigest"],
        "artifactDigest": preflight["artifactDigest"],
        "bundleManifestDigest": preflight["bundleManifestDigest"],
        "packagePlanDigest": preflight["packagePlanDigest"],
        "targetId": preflight["targetId"],
        "rootfsIdentity": preflight["rootfsIdentity"],
        "dependencyClosure": preflight["dependencyClosure"],
        "transaction": transaction,
        "changedPackages": sorted(
            name for name, record in transaction.items() if record["action"] != "keep"
        ),
        "dpkgStateBeforeDigest": preflight["dpkgStateBeforeDigest"],
        "dpkgStateAfterDigest": _sha256_digest(_canonical_subset_bytes(installed_state)),
        "packages": {
            name: {
                **installed_packages[name],
                "bundleSha256": packages[name]["sha256"],
                "bundleSize": packages[name]["size"],
                "status": "installed",
            }
            for name in sorted(packages)
        },
        "dependencies": {
            name: {
                **installed_packages[name],
                "minimumVersion": floor,
                "status": "satisfied",
            }
            for name, floor in sorted(_PODMAN_RUNTIME_DEPENDENCIES.items())
        },
        "runtime": {"ociRuntime": selected[0], "networkBackend": selected[1]},
        "dpkgAudit": "clean",
    }


def verify_release_admission(
    config: InstallConfig,
    *,
    runner: Runner,
    fetcher: Fetcher,
    module_loader: Callable[[Path], VerifiedModules] = load_modules_from_authenticated_wheel,
    verifier_factory: Callable[[VerifiedModules], Any],
    clock: Callable[[], datetime],
) -> Mapping[str, Any]:
    """Fully verify one release without host mutation or durable installer state."""

    if config.channel not in _CHANNELS:
        raise InstallerRefusal("channel_invalid", f"unknown channel: {config.channel}")
    if _KEY_ID.fullmatch(config.trust_key_id) is None or _DIGEST.fullmatch(
        config.trust_key_fingerprint
    ) is None:
        raise InstallerRefusal("trust_key_invalid", "release admission trust identity is malformed")
    if not config.cosign.is_file() or config.cosign.is_symlink():
        raise InstallerRefusal("cosign_missing", "release admission requires pinned Cosign bytes")
    pem = _read_bounded(config.trust_public_key, description="trust public key", maximum=64 * 1024)
    if der_spki_fingerprint(pem) != config.trust_key_fingerprint:
        raise InstallerRefusal("trust_key_invalid", "release admission trust key differs")
    if not config.bundle_root.is_dir() or config.bundle_root.is_symlink():
        raise InstallerRefusal("bundle_root_invalid", "release admission bundle root is unsafe")

    with tempfile.TemporaryDirectory(prefix="stateport-release-admission-") as temporary:
        root = Path(temporary)
        download_dir = root / "downloads"
        download_dir.mkdir(mode=0o700)
        index_path = _acquire_input(
            config.release_index,
            description="release index",
            expected_sha256=config.release_index_sha256,
            require_published_digest=True,
            fetcher=fetcher,
            download_dir=download_dir,
            maximum=MAX_INDEX_BYTES,
        )
        index_content = _read_bounded(
            index_path, description="release index", maximum=MAX_INDEX_BYTES
        )
        bootstrap = _bootstrap_authenticate(config, index_content, root, runner)
        artifacts = bootstrap.signed.get("artifacts")
        if not isinstance(artifacts, Mapping):
            raise InstallerRefusal("index_malformed", "signed payload has no artifact inventory")
        sources = {
            "installer": str(config.installer_path or Path(__file__).resolve()),
            "executionHostProvisioner": config.execution_host_provisioner,
            "updater": config.updater_wheel,
            "compose": config.compose,
            "sourceArchive": config.source_archive,
            "releaseNotes": config.release_notes,
            "knownLimitations": config.known_limitations,
            "podmanPackageBundle": config.podman_package_bundle,
        }
        acquired: dict[str, Path] = {}
        for artifact_id in (
            "installer",
            "executionHostProvisioner",
            "updater",
            "compose",
            "sourceArchive",
            "releaseNotes",
            "knownLimitations",
            *(("podmanPackageBundle",) if "podmanPackageBundle" in artifacts else ()),
        ):
            descriptor = artifacts.get(artifact_id)
            source = sources.get(artifact_id)
            if not isinstance(descriptor, Mapping) or not isinstance(source, str) or not source:
                raise InstallerRefusal(
                    "artifact_missing", f"release admission lacks signed artifact {artifact_id}"
                )
            path = _acquire_input(
                source,
                description=f"{artifact_id} admission artifact",
                expected_sha256=None,
                require_published_digest=False,
                fetcher=fetcher,
                download_dir=download_dir,
            )
            _verify_artifact_bytes(path, artifact_id, str(descriptor["digest"]))
            acquired[artifact_id] = path

        modules = module_loader(acquired["updater"])
        release = modules.release
        if release.canonical_json_bytes(bootstrap.document["signed"]) != bootstrap.signed_bytes:
            raise InstallerRefusal(
                "canonical_divergence", "release admission bootstrap and contract parses diverge"
            )
        try:
            index = release.load_release_index(index_content)
        except release.ReleaseContractError as exc:
            raise _map_contract_refusal(exc) from exc
        if index.index_digest != bootstrap.index_digest or index.signed_digest != bootstrap.signed_digest:
            raise InstallerRefusal(
                "canonical_divergence", "release admission contract digests diverge"
            )
        verifier = verifier_factory(modules)
        policy = release.ReleaseVerificationPolicy(
            expected_channel=config.channel,
            expected_target=config.expected_target,
            updater_version=str(modules.updater_engine.UPDATER_VERSION),
            accepted_signers=frozenset(),
            accepted_public_keys=frozenset(
                {release.PinnedPublicKeyIdentity(config.trust_key_fingerprint, config.trust_key_id)}
            ),
            expected_trust_mode="pinned-public-key",
            now=clock(),
            allow_candidate=True,
        )
        try:
            verified = release.verify_release_index(
                index,
                policy=policy,
                verifier=verifier,
                predecessor=_embedded_predecessor(index, release),
                local_image_payloads=_local_image_manifest_payloads(index, config.bundle_root),
            )
        except release.ReleaseContractError as exc:
            raise _map_contract_refusal(exc) from exc
        return {
            "schema": "stateport.release-admission/v1",
            "releaseId": str(index.release_id),
            "version": str(index.version),
            "channel": str(index.channel),
            "releaseIndexDigest": index.index_digest,
            "signedPayloadDigest": index.signed_digest,
            "targetId": str(verified.target["targetId"]),
            "artifactDigests": {
                artifact_id: str(artifacts[artifact_id]["digest"])
                for artifact_id in sorted(artifacts)
            },
            "status": "verified",
        }


# ---------------------------------------------------------------------------
# durable state helpers (write-ahead intent + atomic rename)
# ---------------------------------------------------------------------------


def _ensure_private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink():
        raise InstallerRefusal("state_root_unsafe", f"state path is a symlink: {path}")
    os.chmod(path, 0o700)
    return path


def _atomic_write(path: Path, content: bytes) -> None:
    """Write-temp-fsync-rename within one directory; never a torn file."""

    if path.is_symlink():
        raise InstallerRefusal("state_root_unsafe", f"refusing to write through symlink: {path}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
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


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    _atomic_write(
        path,
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n",
    )


def _load_json(path: Path, description: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InstallerRefusal("state_unreadable", f"{description} is unreadable: {path}") from exc
    if not isinstance(value, dict):
        raise InstallerRefusal("state_unreadable", f"{description} is not an object: {path}")
    return value


def _write_refusal(
    state_root: Path,
    code: str,
    message: str,
    now: datetime,
    observations: list[dict[str, Any]] | None = None,
) -> Path | None:
    """Best-effort durable typed refusal; never masks the refusal itself."""

    try:
        refusals = _ensure_private_directory(state_root / "refusals")
        path = refusals / f"{_timestamp(now).replace(':', '')}-{code}-{secrets.token_hex(4)}.json"
        record: dict[str, Any] = {
            "schema": "stateport.install-refusal/v1",
            "operation": "install",
            "code": code,
            "message": message[:500],
            "executed": False,
            "at": _timestamp(now),
        }
        if observations:
            record["observations"] = observations[:48]
        _write_json(path, record)
    except (OSError, InstallerRefusal):
        return None
    return path


# ---------------------------------------------------------------------------
# install engine
# ---------------------------------------------------------------------------


# Map the contract's capability refusal codes to the installer's historical
# typed refusal codes.  Distribution identity is not a refusal: a host that
# meets the runtime contract installs and records its support tier.
_REFUSAL_CODE_MAP: dict[str, str] = {
    "linux_kernel_required": "host_kernel_mismatch",
    "linux_amd64_required": "host_architecture_mismatch",
    "cgroup_v2_required": "cgroup_v2_missing",
    "podman_version_unparseable": "podman_version_unparseable",
    "podman_version_too_old": "podman_version_floor",
    "rootless_podman_required": "podman_not_rootless",
    "quadlet_required": "quadlet_missing",
    "systemd_user_required": "systemd_user_required",
    "subuid_mapping_required": "subuid_mapping_missing",
    "subgid_mapping_required": "subgid_mapping_missing",
    "wsl1_substrate_unsupported": "wsl1_substrate_unsupported",
    "wsl2_ubuntu_2404_required": "wsl2_ubuntu_2404_required",
}


def _verify_host(
    release_module: Any,
    facts: HostFacts,
    substrate: HostSubstrateFacts,
    *,
    expected_target: str,
):
    """Qualify the host by the portable capability decision contract.

    Distribution branding is observation only.  An eligible host installs; the
    support tier (validated baseline versus compatible-unvalidated) is decided
    here and recorded in the receipt.  A non-capable host refuses with a typed
    reason, never silently degrading.
    """

    observation = release_module.LinuxHostObservation(
        kernel=facts.kernel,
        architecture=facts.architecture,
        os_id=facts.os_id,
        version_id=facts.version_id,
        cgroup_version=facts.cgroup_version,
        podman_version=facts.podman_version,
        rootless=facts.rootless,
        quadlet=facts.quadlet,
        systemd_user=facts.systemd_user,
        subuid_configured=facts.subuid_configured,
        subgid_configured=facts.subgid_configured,
        substrate=release_module.LinuxSubstrateObservation(
            kernel_release=substrate.kernel_release,
            proc_version=substrate.proc_version,
            wsl_interop_present=substrate.wsl_interop_present,
            wsl_distro_name_present=substrate.wsl_distro_name_present,
        ),
    )
    decision = release_module.evaluate_linux_host(observation)
    if decision.target_id != expected_target:
        raise InstallerRefusal(
            "target_mismatch",
            f"host capability contract target {decision.target_id} != {expected_target}",
        )
    if not decision.eligible:
        codes = decision.refusal_codes
        code = "host_environment_mismatch"
        message = "host does not meet the portable Linux capability contract"
        if codes:
            code = _REFUSAL_CODE_MAP.get(codes[0], "host_environment_mismatch")
            message = "; ".join(codes)[:500]
        raise InstallerRefusal(code, message)
    return decision


def _map_contract_refusal(exc: Exception) -> InstallerRefusal:
    message = str(exc)
    mapping = (
        ("release index is expired", "index_expired"),
        ("channel does not match", "channel_mismatch"),
        ("expected target", "target_missing"),
        ("not installable under this policy", "candidate_not_installable"),
        ("publication time is in the future", "index_not_yet_published"),
        ("untrusted signer", "signature_untrusted"),
        ("verification failed", "signature_verification_failed"),
        ("withdrawn", "release_withdrawn"),
        ("deprecated", "release_deprecated"),
        ("stale", "scan_evidence_stale"),
    )
    for needle, code in mapping:
        if needle in message:
            return InstallerRefusal(code, message[:500])
    return InstallerRefusal("release_verification_failed", message[:500])


def _verify_artifact_bytes(
    path: Path,
    artifact_id: str,
    expected_digest: str,
) -> dict[str, Any]:
    """Digest-verify one release artifact as exact bytes."""

    content = _read_bounded(path, description=f"{artifact_id} artifact", maximum=MAX_ARTIFACT_BYTES)
    observed = _sha256_digest(content)
    if observed != expected_digest:
        raise InstallerRefusal(
            "artifact_digest_mismatch",
            f"{artifact_id} artifact digest {observed} != signed {expected_digest}",
        )
    return {
        "artifactId": artifact_id,
        "expectedDigest": expected_digest,
        "observedDigest": observed,
        "status": "verified",
    }


def _signature_descriptors(index: Any) -> list[Mapping[str, Any]]:
    """Return the index and image signatures that must be transported together."""

    signatures: list[Mapping[str, Any]] = []
    signatures.extend(index.document.get("signatures", []))
    for image in index.document["signed"]["images"]:
        signature = image.get("signature")
        if isinstance(signature, Mapping):
            signatures.append(signature)
    unique: dict[str, Mapping[str, Any]] = {}
    for signature in signatures:
        bundle = signature.get("bundle")
        digest = bundle.get("digest") if isinstance(bundle, Mapping) else None
        if not isinstance(digest, str):
            raise InstallerRefusal("signature_bundle_invalid", "signed material has no bundle digest")
        unique[digest] = signature
    return [unique[digest] for digest in sorted(unique)]


def _embedded_predecessor(index: Any, release: Any) -> Any | None:
    successor = index.document["signed"].get("successor")
    if successor is None or successor["predecessor"] is None:
        return None
    raw = successor["predecessor"].get("rawIndex")
    if not isinstance(raw, Mapping):
        raise InstallerRefusal(
            "release_predecessor_invalid", "successor predecessor raw index is missing"
        )
    try:
        return release.validate_release_index(raw, legacy_predecessor=True)
    except release.ReleaseContractError as exc:
        raise _map_contract_refusal(exc) from exc


def _volume_names(signed_hex: str, volume_key: str) -> tuple[str, str]:
    key_hash = hashlib.sha256(volume_key.encode("utf-8")).hexdigest()[:12]
    return (
        f"stateport-g{signed_hex[:12]}-{key_hash}",
        f"stateport-s{signed_hex[:12]}-{key_hash}",
    )


def _ensure_volume(runner: Runner, name: str) -> None:
    exists = runner.run(["podman", "volume", "exists", name], timeout=60)
    if exists.returncode == 0:
        return
    created = runner.run(["podman", "volume", "create", name], timeout=120)
    if created.returncode != 0:
        raise InstallerRefusal(
            "volume_create_failed", f"podman volume create {name}: {created.stderr.strip()[:200]}"
        )


def _create_venv(venv_dir: Path) -> None:
    venv.create(venv_dir, with_pip=True, clear=False)


def _wheel_canonical_name(wheel: Path) -> str:
    """Return the PEP 427 filename for the digest-verified wheel.

    pip parses the wheel filename (``name-version-pytag-abitag-platform``)
    before it looks at any content, so the staged name must be derived from
    the wheel's own ``.dist-info`` metadata, never invented.  The wheel bytes
    are already digest-verified against the authenticated release index before
    this point, so trusting their metadata for the *filename* adds no trust —
    but an unparseable wheel is still refused instead of handed to pip.
    """
    try:
        with zipfile.ZipFile(wheel) as archive:
            metadata_entries = [
                name
                for name in archive.namelist()
                if name.count("/") == 1 and name.endswith(".dist-info/METADATA")
            ]
            if len(metadata_entries) != 1:
                raise ValueError(
                    f"expected exactly one .dist-info/METADATA entry, found {len(metadata_entries)}"
                )
            dist_info = metadata_entries[0].split("/", 1)[0]
            base = dist_info[: -len(".dist-info")]
            tags = [
                line.split(":", 1)[1].strip()
                for line in archive.read(f"{dist_info}/WHEEL").decode("utf-8").splitlines()
                if line.startswith("Tag:")
            ]
            if not tags:
                raise ValueError("the WHEEL metadata declares no Tag")
    except (OSError, KeyError, UnicodeDecodeError, ValueError, zipfile.BadZipFile) as exc:
        raise InstallerRefusal(
            "wheel_layout_invalid",
            f"the digest-verified updater wheel is not a parseable wheel: {exc}",
        ) from exc
    return f"{base}-{tags[0]}.whl"


def _stage_wheel_for_pip(wheel: Path, venv_dir: Path) -> Path:
    """Return a pip-installable ``.whl`` path for the digest-verified wheel.

    The shipped release bundle uses extensionless artifact names
    (``artifacts/updater``), and pip refuses any path whose filename it cannot
    parse as a wheel.  The staged name is the wheel's own PEP 427 name (see
    ``_wheel_canonical_name``); a digest-derived decorative name is *not* used
    because pip rejects filenames that do not match the exact component
    grammar.  A hardlink keeps the staging free of copies on the same
    filesystem; a copy is the cross-filesystem fallback.  A stale staged file
    from an interrupted earlier run is reused only when its bytes are
    identical, and replaced otherwise.
    """
    if wheel.suffix == ".whl":
        return wheel
    staging_dir = venv_dir / ".wheel-staging"
    staging_dir.mkdir(parents=True, exist_ok=True)
    staged = staging_dir / _wheel_canonical_name(wheel)
    if staged.is_file():
        wheel_bytes = _read_bounded(wheel, description="updater wheel", maximum=MAX_ARTIFACT_BYTES)
        if _read_bounded(staged, description="staged wheel", maximum=MAX_ARTIFACT_BYTES) == (
            wheel_bytes
        ):
            return staged
        staged.unlink()
    try:
        os.link(wheel, staged)
    except OSError:
        shutil.copyfile(wheel, staged)
    return staged


def _installed_wheel_matches(wheel: Path, venv_dir: Path) -> bool:
    """Verify cached pure-Python wheel files before trusting the digest marker."""

    candidates = sorted(venv_dir.glob("lib/python3.*/site-packages"))
    if len(candidates) != 1:
        return False
    site_packages = candidates[0]
    try:
        with zipfile.ZipFile(wheel) as archive:
            members = [
                member
                for member in archive.infolist()
                if not member.is_dir() and not member.filename.endswith(".dist-info/RECORD")
            ]
            for member in members:
                relative = PurePosixPath(member.filename)
                if relative.is_absolute() or ".." in relative.parts:
                    return False
                installed = site_packages.joinpath(*relative.parts)
                if not installed.is_file() or installed.read_bytes() != archive.read(member):
                    return False
    except (OSError, ValueError, zipfile.BadZipFile):
        return False
    return True


def _install_venv(
    wheel: Path, venv_dir: Path, runner: Runner, venv_creator: Callable[[Path], None]
) -> None:
    if not (venv_dir / "pyvenv.cfg").is_file():
        venv_creator(venv_dir)
    pip = venv_dir / "bin" / "pip"
    if not pip.is_file():
        raise InstallerRefusal("venv_layout_unexpected", "the updater venv has no pip executable")
    marker = venv_dir / ".updater-wheel-digest"
    wheel_digest = _sha256_digest(
        _read_bounded(wheel, description="updater wheel", maximum=MAX_ARTIFACT_BYTES)
    )
    if (
        marker.is_file()
        and marker.read_text(encoding="ascii").strip() == wheel_digest
        and _installed_wheel_matches(wheel, venv_dir)
    ):
        already = runner.run(
            [str(venv_dir / "bin" / "python"), "-c", "import stateport_release, stateport_updater"],
            timeout=60,
        )
        if already.returncode == 0:
            return  # converged: the exact wheel is already installed
    completed = runner.run(
        [
            str(pip),
            "install",
            "--force-reinstall",
            "--no-index",
            "--no-deps",
            "--disable-pip-version-check",
            str(_stage_wheel_for_pip(wheel, venv_dir)),
        ],
        timeout=600,
    )
    if completed.returncode != 0:
        raise InstallerRefusal(
            "venv_install_failed", f"pip install failed: {completed.stderr.strip()[:300]}"
        )
    _atomic_write(marker, (wheel_digest + "\n").encode("ascii"))


def _wait_for_health(
    services: Sequence[Mapping[str, Any]],
    ports: Mapping[str, int],
    container_names: Mapping[str, str],
    *,
    fetcher: Fetcher,
    runner: Runner,
    clock: Callable[[], datetime],
    timeout_seconds: float,
    poll_seconds: float,
) -> list[dict[str, Any]]:
    """Wait for every accepted service; capture service-reported identity evidence.

    Services with a signed host port are polled over loopback HTTP; services
    without one are observed through the container health status.  Evidence is
    the exact response digest — never an HTTP 200 alone.
    """

    evidence: list[dict[str, Any]] = []
    for service in sorted(services, key=lambda item: item["serviceId"]):
        # Per-service deadline: services start strictly serially and one cold
        # WSL2 service can need ~80s, so a single shared budget across the
        # whole set exhausts before the last services are ever polled.
        deadline = clock() + timedelta(seconds=timeout_seconds)
        service_id = str(service["serviceId"])
        health = service["health"]
        health_port = next(
            (port for port in service["ports"] if port["containerPort"] == health["containerPort"]),
            service["ports"][0] if service["ports"] else None,
        )
        observed: dict[str, Any] | None = None
        observations: list[dict[str, Any]] = []
        last_sample = -1.0e9

        def _observe(kind: str, status: Any, body_bytes: int, error_class: str, url: str = "") -> None:
            nonlocal last_sample
            elapsed = round(timeout_seconds - max((deadline - clock()).total_seconds(), 0.0), 1)
            changed = not observations or observations[-1]["status"] != status or observations[-1]["errorClass"] != error_class
            if not changed and elapsed - last_sample < 15.0:
                return
            last_sample = elapsed
            entry: dict[str, Any] = {
                "elapsedSeconds": elapsed,
                "kind": kind,
                "status": status,
                "bodyBytes": body_bytes,
                "errorClass": error_class,
            }
            if url:
                entry["url"] = url
            observations.append(entry)

        while observed is None:
            if health_port is not None:
                port = ports[f"{service_id}:accepted:{health_port['name']}"]
                url = f"http://127.0.0.1:{port}{health['path']}"
                try:
                    result = fetcher.fetch(url, timeout=10.0, max_bytes=65536)
                    _observe("http", result.status, len(result.body), "", url=url)
                except InstallerRefusal as exc:
                    _observe("http", 0, 0, f"{type(exc).__name__}:{exc.code}", url=url)
                    result = FetchResult(0, b"")
                except OSError as exc:
                    _observe("http", 0, 0, f"{type(exc).__name__}", url=url)
                    result = FetchResult(0, b"")
                if result.status == 200 and result.body:
                    observed = {
                        "serviceId": service_id,
                        "source": "http-health",
                        "url": url,
                        "responseDigest": _sha256_digest(result.body),
                    }
            else:
                completed = runner.run(
                    [
                        "podman",
                        "inspect",
                        "--format",
                        "{{.State.Healthcheck.Status}}",
                        container_names[service_id],
                    ],
                    timeout=60,
                )
                _observe("podman-healthcheck", completed.returncode, len(completed.stdout.strip()), "" if completed.returncode == 0 else "runner-error")
                if completed.returncode == 0 and completed.stdout.strip() == "healthy":
                    observed = {
                        "serviceId": service_id,
                        "source": "podman-healthcheck",
                        "container": container_names[service_id],
                        "responseDigest": _sha256_digest(completed.stdout.strip().encode()),
                    }
            if observed is None:
                if clock() >= deadline:
                    if health_port is not None and container_names.get(service_id):
                        probed = runner.run(
                            [
                                "podman", "inspect", "--format",
                                "health={{.State.Healthcheck.Status}} failing={{.State.Healthcheck.FailingStreak}}",
                                container_names[service_id],
                            ],
                            timeout=60,
                        )
                        observations.append(
                            {
                                "elapsedSeconds": round(timeout_seconds, 1),
                                "kind": "container-health-at-timeout",
                                "status": probed.stdout.strip() or f"exit={probed.returncode}",
                                "bodyBytes": 0,
                                "errorClass": "",
                            }
                        )
                    raise InstallerRefusal(
                        "health_timeout",
                        f"service {service_id} did not report healthy in time",
                        observations=observations,
                    )
                time.sleep(min(poll_seconds, 0.5))
        evidence.append(observed)
    return evidence


def install(
    config: InstallConfig,
    *,
    runner: Runner,
    probe: HostProbe,
    fetcher: Fetcher,
    module_loader: Callable[[Path], VerifiedModules],
    verifier_factory: Callable[[VerifiedModules], Any],
    clock: Callable[[], datetime],
    confirmer: Callable[[Mapping[str, Any]], bool],
    venv_creator: Callable[[Path], None] = _create_venv,
) -> InstallOutcome:
    """Run the fail-closed install flow; every refusal is typed and durable."""

    try:
        substrate = probe.substrate()
    except InstallerRefusal as refusal:
        return InstallOutcome(
            status="refused",
            code=refusal.code,
            message=str(refusal),
            receipt_path=None,
        )
    if substrate.substrate == "wsl1":
        return InstallOutcome(
            status="refused",
            code="wsl1_substrate_unsupported",
            message="WSL1 is unsupported; StatePort requires WSL2",
            receipt_path=None,
        )
    observed_target = (
        WSL2_TARGET_ID if substrate.substrate == "wsl2" else PORTABLE_LINUX_TARGET_ID
    )
    if config.expected_target == EXPECTED_TARGET and observed_target == WSL2_TARGET_ID:
        config = replace(config, expected_target=WSL2_TARGET_ID)
    elif config.expected_target != observed_target:
        return InstallOutcome(
            status="refused",
            code="target_mismatch",
            message=(
                f"installer target {config.expected_target} does not match observed "
                f"substrate target {observed_target}"
            ),
            receipt_path=None,
        )
    try:
        return _install_inner(
            config,
            runner=runner,
            probe=probe,
            fetcher=fetcher,
            module_loader=module_loader,
            verifier_factory=verifier_factory,
            clock=clock,
            confirmer=confirmer,
            venv_creator=venv_creator,
            substrate=substrate,
            started=clock(),
        )
    except InstallerRefusal as refusal:
        refusal_path = _write_refusal(config.state_root, refusal.code, str(refusal), clock(), observations=getattr(refusal, "observations", None))
        return InstallOutcome(
            status="refused",
            code=refusal.code,
            message=str(refusal),
            receipt_path=refusal_path,
        )


def _install_inner(
    config: InstallConfig,
    *,
    runner: Runner,
    probe: HostProbe,
    fetcher: Fetcher,
    module_loader: Callable[[Path], VerifiedModules],
    verifier_factory: Callable[[VerifiedModules], Any],
    clock: Callable[[], datetime],
    confirmer: Callable[[Mapping[str, Any]], bool],
    venv_creator: Callable[[Path], None],
    substrate: HostSubstrateFacts,
    started: datetime,
) -> InstallOutcome:
    if config.channel not in _CHANNELS:
        raise InstallerRefusal("channel_invalid", f"unknown channel: {config.channel}")
    if _KEY_ID.fullmatch(config.trust_key_id) is None:
        raise InstallerRefusal("trust_key_invalid", "trust key ID is malformed")
    if _DIGEST.fullmatch(config.trust_key_fingerprint) is None:
        raise InstallerRefusal("trust_key_invalid", "trust key fingerprint is malformed")
    if not config.state_root.is_absolute():
        raise InstallerRefusal("state_root_invalid", "the install state root must be absolute")
    if not config.cosign.is_file():
        raise InstallerRefusal(
            "cosign_missing",
            "the pinned Cosign executable is required (--cosign); nothing is downloaded "
            "implicitly and no pure-Python signature verification is attempted",
        )
    pem = _read_bounded(config.trust_public_key, description="trust public key", maximum=64 * 1024)
    if der_spki_fingerprint(pem) != config.trust_key_fingerprint:
        raise InstallerRefusal(
            "trust_key_invalid",
            "supplied trust public key does not match the pinned DER SPKI fingerprint",
        )
    if not config.bundle_root.is_dir() or config.bundle_root.is_symlink():
        raise InstallerRefusal("bundle_root_invalid", "bundle root is not an operator directory")

    state_root = _ensure_private_directory(config.state_root)
    work_dir = _ensure_private_directory(state_root / "work")
    download_dir = _ensure_private_directory(work_dir / "downloads")
    receipts_dir = _ensure_private_directory(state_root / "receipts")
    intent_dir = _ensure_private_directory(state_root / "intent")
    venv_dir = state_root / "updater-venv"

    # Inputs (local paths, or bounded HTTPS downloads with digest binding).
    index_path = _acquire_input(
        config.release_index,
        description="release index",
        expected_sha256=config.release_index_sha256,
        require_published_digest=True,
        fetcher=fetcher,
        download_dir=download_dir,
        maximum=MAX_INDEX_BYTES,
    )
    wheel_path = _acquire_input(
        config.updater_wheel,
        description="updater wheel",
        expected_sha256=None,
        require_published_digest=False,
        fetcher=fetcher,
        download_dir=download_dir,
    )

    # Trust step 2: bootstrap authentication with the pinned Cosign CLI.
    index_content = _read_bounded(index_path, description="release index", maximum=MAX_INDEX_BYTES)
    bootstrap = _bootstrap_authenticate(config, index_content, work_dir, runner)

    # Trust step 3: the authenticated index pins every artifact digest.
    signed = bootstrap.signed
    artifacts = signed.get("artifacts")
    if not isinstance(artifacts, dict):
        raise InstallerRefusal("index_malformed", "signed payload has no artifact inventory")
    updater_artifact = artifacts.get("updater")
    installer_artifact = artifacts.get("installer")
    provisioner_artifact = artifacts.get("executionHostProvisioner")
    if (
        not isinstance(updater_artifact, dict)
        or not isinstance(installer_artifact, dict)
        or not isinstance(provisioner_artifact, dict)
    ):
        raise InstallerRefusal(
            "index_malformed",
            "signed payload lacks installer/updater/executionHostProvisioner artifacts",
        )
    package_installation: Mapping[str, Any] | None = None
    package_artifact = artifacts.get("podmanPackageBundle")
    if isinstance(package_artifact, Mapping):
        if (
            config.podman_package_preflight is None
            or _DIGEST.fullmatch(str(config.confirmed_package_plan_digest)) is None
        ):
            raise InstallerRefusal(
                "package_preflight_missing",
                "package-bearing install requires its authenticated owner-confirmed pre-install plan",
            )
        preserved_preflight = _load_json(
            config.podman_package_preflight, "preserved Podman package preflight"
        )
        if preserved_preflight.get("packagePlanDigest") != config.confirmed_package_plan_digest:
            raise InstallerRefusal(
                "package_preflight_invalid", "preserved package plan differs from its confirmation"
            )
        package_path = _acquire_input(
            config.podman_package_bundle,
            description="podmanPackageBundle artifact",
            expected_sha256=None,
            require_published_digest=False,
            fetcher=fetcher,
            download_dir=download_dir,
        )
        with tempfile.TemporaryDirectory(
            prefix=".stateport-installed-package-verification-", dir=work_dir
        ) as temporary:
            authenticated = verify_podman_package_bundle(
                PackageBundlePreflightConfig(
                    release_index=index_path,
                    bundle_root=config.bundle_root,
                    trust_public_key=config.trust_public_key,
                    trust_key_id=config.trust_key_id,
                    trust_key_fingerprint=config.trust_key_fingerprint,
                    cosign=config.cosign,
                    installer_path=config.installer_path or Path(__file__).resolve(),
                    podman_package_bundle=package_path,
                    output_dir=Path(temporary) / "packages",
                    expected_target=config.expected_target,
                ),
                runner=runner,
            )
            immutable_fields = (
                "releaseIndexDigest", "signedPayloadDigest", "artifactDigest",
                "bundleManifestDigest", "targetId", "rootfsIdentity", "dependencyClosure",
                "packages", "runtimeContract",
            )
            if any(
                preserved_preflight.get(field) != authenticated.get(field)
                for field in immutable_fields
            ):
                raise InstallerRefusal(
                    "package_preflight_invalid",
                    "preserved package plan differs from the authenticated package artifact",
                )
            package_installation = verify_installed_podman_packages(
                preserved_preflight,
                runner=runner,
            )
    elif config.podman_package_bundle is not None:
        raise InstallerRefusal(
            "artifact_unexpected", "install input includes a package bundle absent from the signed index"
        )
    wheel_digest = _sha256_digest(
        _read_bounded(wheel_path, description="updater wheel", maximum=MAX_ARTIFACT_BYTES)
    )
    if wheel_digest != updater_artifact.get("digest"):
        raise InstallerRefusal(
            "wheel_digest_mismatch",
            f"updater wheel digest {wheel_digest} != signed {updater_artifact.get('digest')}",
        )
    provisioner_path = _acquire_input(
        config.execution_host_provisioner,
        description="execution-host provisioner",
        expected_sha256=None,
        require_published_digest=False,
        fetcher=fetcher,
        download_dir=download_dir,
    )
    provisioner_digest = _sha256_digest(
        _read_bounded(
            provisioner_path,
            description="execution-host provisioner",
            maximum=MAX_ARTIFACT_BYTES,
        )
    )
    if provisioner_digest != provisioner_artifact.get("digest"):
        raise InstallerRefusal(
            "artifact_digest_mismatch",
            "execution-host provisioner does not match its signed release artifact",
        )
    _install_venv(wheel_path, venv_dir, runner, venv_creator)

    # Trust step 4: load verified modules, then full contract verification.
    modules = module_loader(venv_dir)
    release = modules.release
    contract_targets = frozenset(getattr(release, "SUPPORTED_TARGET_IDS", ()))
    if contract_targets != SUPPORTED_TARGET_IDS or config.expected_target not in contract_targets:
        raise InstallerRefusal(
            "canonical_divergence",
            "installer bootstrap and contract wheel disagree on supported targets",
        )
    if release.canonical_json_bytes(bootstrap.document["signed"]) != bootstrap.signed_bytes:
        raise InstallerRefusal(
            "canonical_divergence", "stdlib bootstrap serialization diverged from the contract"
        )
    try:
        index = release.load_release_index(index_content)
    except release.ReleaseContractError as exc:
        raise _map_contract_refusal(exc) from exc
    if (
        index.signed_digest != bootstrap.signed_digest
        or index.index_digest != bootstrap.index_digest
    ):
        raise InstallerRefusal(
            "canonical_divergence", "contract digests diverge from the bootstrap digests"
        )
    # Retain the genesis index bundle into the durable content-addressed root
    # before contract verification: the installed updater re-verifies stored
    # index envelopes from this root for the installation's whole life, and
    # the bootstrap already digest-checked these exact staging bytes.
    _ensure_private_directory(config.state_root / "updater")
    durable_bundle_root = _ensure_private_directory(config.state_root / "updater" / "bundles")
    _retain_local_image_archives(config.bundle_root, durable_bundle_root)
    for signature in _signature_descriptors(index):
        try:
            bundle_name = modules.release.signature_bundle_name(signature)
            source = config.bundle_root / bundle_name
            if not source.is_file():
                source = config.bundle_root / "image-bundles" / bundle_name
            modules.release.retain_bundle(
                durable_bundle_root, source, signature
            )
        except modules.release.CosignVerificationError as exc:
            raise InstallerRefusal(
                "signature_bundle_retention_refused",
                f"genesis signature bundle cannot be retained: {exc}",
            ) from exc
    predecessor = _embedded_predecessor(index, release)
    if predecessor is not None:
        for signature in predecessor.document["signatures"]:
            try:
                bundle_name = modules.release.signature_bundle_name(signature)
                modules.release.retain_bundle(
                    durable_bundle_root,
                    config.bundle_root / "predecessor-bundle" / bundle_name,
                    signature,
                )
            except modules.release.CosignVerificationError as exc:
                raise InstallerRefusal(
                    "signature_bundle_retention_refused",
                    f"predecessor signature bundle cannot be retained: {exc}",
                ) from exc
    verifier = verifier_factory(modules)
    policy = release.ReleaseVerificationPolicy(
        expected_channel=config.channel,
        expected_target=config.expected_target,
        updater_version=str(modules.updater_engine.UPDATER_VERSION),
        accepted_signers=frozenset(),
        accepted_public_keys=frozenset(
            {release.PinnedPublicKeyIdentity(config.trust_key_fingerprint, config.trust_key_id)}
        ),
        expected_trust_mode="pinned-public-key",
            now=clock(),
        allow_candidate=True,
    )
    try:
        verified = release.verify_release_index(
            index,
            policy=policy,
            verifier=verifier,
            predecessor=predecessor,
            local_image_payloads=_local_image_manifest_payloads(index, config.bundle_root),
        )
    except release.ReleaseContractError as exc:
        raise _map_contract_refusal(exc) from exc
    target = verified.target
    images = index.document["signed"]["images"]

    # Host verification: capability-based, distribution identity is observation.
    facts = probe.gather()
    decision = _verify_host(
        release, facts, substrate, expected_target=config.expected_target
    )
    support_tier = decision.support_tier
    if support_tier == "compatible_unvalidated":
        for warning in decision.warnings:
            print(f"notice: {warning}", file=sys.stderr)
        print(
            f"notice: this host installs as {support_tier} — it matches the capability "
            "contract but has no clean-install acceptance receipt",
            file=sys.stderr,
        )
    host_identity = {
        "formatVersion": "stateport.install-host-identity/v1",
        **facts.as_receipt(),
        "substrate": substrate.substrate,
        "kernelRelease": substrate.kernel_release,
        "wslInteropPresent": substrate.wsl_interop_present,
        "wslDistroNamePresent": substrate.wsl_distro_name_present,
        "supportTier": support_tier,
        "expectedTarget": config.expected_target,
    }
    host_identity_digest = release.canonical_digest(host_identity)

    # Port collision inventory (contract port policy: probe/refuse, never guess).
    # Ports published by THIS release's own live units are this installation's
    # existing allocation, not host collisions: on a rerun after a failure past
    # service start they are already bound by our own containers.  Excluding
    # them lets the deterministic derivation reproduce the original allocation
    # exactly; counting them as observed-host shifts every port, overwrites the
    # live units, and traps every later rerun in a dead-port health loop.
    own_ports = _own_live_unit_ports(config.live_quadlet_root, index.signed_digest)
    occupied: list[dict[str, Any]] = []
    for port in probe.occupied_ports():
        if port in own_ports:
            continue
        occupied.append(
            {
                "class": "observed-host",
                "port": port,
                "identityDigest": release.canonical_digest(
                    {"class": "observed-host", "port": port, "source": "proc-net-tcp-listen"}
                ),
            }
        )
    empty_inventory = release.canonical_digest([])
    collision_digests = {
        "current": empty_inventory,
        "predecessor": empty_inventory,
        "candidate": empty_inventory,
        "observedHost": release.canonical_digest(sorted(occupied, key=lambda item: item["port"])),
    }

    # Receipt identity pieces known right after verification.
    release_identity = release.release_identity_from_verified(verified)
    quadlet_artifact = artifacts.get("quadlet")
    if not isinstance(quadlet_artifact, dict):
        raise InstallerRefusal("index_malformed", "signed payload lacks the quadlet artifact")
    observed_services = [
        {
            "serviceId": str(service["serviceId"]),
            "imageId": str(service["imageId"]),
            "imageDigest": str(
                next(image["digest"] for image in images if image["imageId"] == service["imageId"])
            ),
            "healthy": False,
        }
        for service in sorted(target["services"], key=lambda item: item["serviceId"])
    ]
    observed_image_set = release.image_set_digest(images)
    observed_service_set = release.service_set_digest(observed_services)
    target_identity: dict[str, Any] = {
        "targetId": str(target["targetId"]),
        "topologyDigest": str(target["topologyDigest"]),
        "quadletArtifactDigest": str(quadlet_artifact["digest"]),
        "quadletBundleDigest": str(target["quadletBundleDigest"]),
        "imageSetDigest": observed_image_set,
        "serviceSetDigest": observed_service_set,
    }
    target_identity["targetDigest"] = release.canonical_digest(target_identity)
    image_by_digest = {str(image["digest"]): image for image in images}
    signer_entries: list[dict[str, Any]] = []
    for proof in release.signature_verification_proof_set(verified):
        if proof["subjectDigest"] == index.signed_digest:
            subject_kind, subject_id = "release-index", "release-index"
        elif proof["subjectDigest"] in image_by_digest:
            subject_kind = "image"
            subject_id = str(image_by_digest[proof["subjectDigest"]]["imageId"])
        else:
            raise InstallerRefusal(
                "receipt_assembly_failed", "verification proof binds an unknown subject"
            )
        signer_entries.append(
            {
                "subjectKind": subject_kind,
                "subjectId": subject_id,
                "subjectDigest": proof["subjectDigest"],
                "trustMode": proof["trustMode"],
                "publicKeyFingerprint": proof["identityPrimary"],
                "publicKeyFingerprintAlgorithm": "sha256-canonical-der-spki",
                "publicKeyId": proof["identitySecondary"],
                "bundleDigest": proof["bundleDigest"],
                "verifiedAt": proof["verifiedAt"],
                "transparencyLogStatus": "not-required-private-candidate",
                "status": "verified",
            }
        )
    signer_entries.sort(key=lambda item: (item["subjectKind"], item["subjectId"]))

    # Exact install plan.
    plan: dict[str, Any] = {
        "schema": "stateport.install-plan/v1",
        "installerVersion": INSTALLER_VERSION,
        "installerDigest": str(installer_artifact["digest"]),
        "release": release_identity,
        "releaseIndexDigest": index.index_digest,
        "target": {
            "targetId": str(target["targetId"]),
            "topologyDigest": str(target["topologyDigest"]),
            "quadletBundleDigest": str(target["quadletBundleDigest"]),
        },
        "images": [
            {
                "imageId": str(image["imageId"]),
                "reference": str(image["reference"]),
                "digest": str(image["digest"]),
            }
            for image in sorted(images, key=lambda item: item["imageId"])
        ],
        "updater": {
            "version": str(modules.updater_engine.UPDATER_VERSION),
            "digest": str(updater_artifact["digest"]),
        },
        "host": host_identity,
        "stateRoot": str(state_root),
        "liveQuadletRoot": str(config.live_quadlet_root),
        "createdAt": _timestamp(started),
    }
    package_artifact = artifacts.get("podmanPackageBundle")
    if isinstance(package_artifact, Mapping):
        plan["podmanPackageBundle"] = {"digest": str(package_artifact["digest"])}
        plan["podmanPackageInstallation"] = package_installation
    # The plan digest binds the exact install identity, not the wall clock:
    # excluding createdAt makes an interrupted rerun converge on the same plan.
    plan_digest = release.canonical_digest(
        {key: value for key, value in plan.items() if key != "createdAt"}
    )
    plan["planDigest"] = plan_digest
    _write_json(state_root / "install-plan.json", plan)

    # Execution-host provisioning: compute the control-plane materialization
    # (deterministic for the verified release + host state) and emit the plan.
    # The privileged apply is a separate operator step; this rootless
    # installer never escalates.  The bootstrap runs the provisioner with this
    # exact plan, so it must already carry the accepted control-plane units.
    execution_host_info = None
    if target.get("executionHostMode") in {
        "stable-host-daemon-client",
        "stable-host-daemon-bootstrap-only",
    }:
        execution_host_info = _emit_execution_host_provisioning_plan(
            config,
            target=target,
            images=images,
            index_path=index_path,
            venv_dir=venv_dir,
            updater_digest=str(updater_artifact["digest"]),
            updater_wheel=wheel_path,
            provisioner_path=provisioner_path,
            provisioner_digest=provisioner_digest,
            provisioner_size=int(provisioner_artifact["size"]),
            state_root=state_root,
            release=release,
            verified=verified,
            index=index,
            plan_digest=plan_digest,
            host_identity_digest=host_identity_digest,
            collision_digests=collision_digests,
            occupied=occupied,
            clock=clock,
        )
    if execution_host_info is not None:
        execution_host_info = {
            **dict(execution_host_info),
            "releaseIndexDigest": index.index_digest,
            "signedPayloadDigest": index.signed_digest,
            "sourceCommit": str(index.document["signed"]["source"]["commit"]),
            "sourceTree": str(index.document["signed"]["source"]["tree"]),
            "installerDigest": str(installer_artifact["digest"]),
        }
        if config.prepare_execution_host:
            return InstallOutcome(
                status="prepared",
                code="execution_host_plan_ready",
                message="signed execution-host plan is ready for the root helper",
                receipt_path=None,
                execution_host=execution_host_info,
            )
        execution_host_info = _gate_execution_host(
            config,
            execution_host_info=execution_host_info,
            target=target,
            release=release,
        )

    # Convergence: an exact succeeded receipt for this plan ends the rerun —
    # but only when the live runtime it records still exists.  After a
    # non-purge uninstall the receipt is historic while the units, containers,
    # and activation target are gone; the rerun must fall through and
    # reinstall, converging the durable records that were preserved.
    for receipt_path in sorted(receipts_dir.glob("install_receipt_*.json")):
        try:
            existing = _load_json(receipt_path, "install receipt")
        except InstallerRefusal:
            continue
        if (
            existing.get("result") == "succeeded"
            and existing.get("operation") == "install"
            and existing.get("installPlanDigest") == plan_digest
            and existing.get("releaseIndexDigest") == index.index_digest
        ):
            if not _live_runtime_present(config, state_root, index.signed_digest):
                break
            # A converged rerun still enforces the create-only entry point:
            # identical content is a no-op, foreign content refuses closed.
            _install_update_wrapper(config, state_root)
            url = str(existing.get("runtime", {}).get("localUrl", ""))
            return InstallOutcome(
                status="succeeded",
                code="already_installed",
                message="an exact succeeded receipt already binds this install plan",
                local_url=url or None,
                receipt_path=receipt_path,
                converged=True,
                execution_host=execution_host_info,
            )

    intent = {
        "schema": "stateport.install-intent/v1",
        "intentId": f"install_intent_{secrets.token_hex(16)}",
        "operation": "install",
        "planDigest": plan_digest,
        "releaseIndexDigest": index.index_digest,
        "startedAt": _timestamp(started),
        "phase": "planned",
    }
    intent_path = intent_dir / f"{intent['intentId']}.json"
    _write_json(intent_path, intent)

    # Interactive exact-plan confirmation (installer-directive authority).
    summary = {
        "releaseId": release_identity["releaseId"],
        "version": release_identity["version"],
        "channel": release_identity["channel"],
        "planDigest": plan_digest,
        "images": [item["reference"] for item in plan["images"]],
        "stateRoot": str(state_root),
    }
    if config.confirmed_plan_digest is not None and config.confirmed_plan_digest != plan_digest:
        raise InstallerRefusal(
            "confirmation_refused", "the supplied exact-plan confirmation names another plan"
        )
    if (
        package_artifact is not None
        and config.assume_yes
        and config.confirmed_plan_digest != plan_digest
    ):
        raise InstallerRefusal(
            "confirmation_refused",
            "noninteractive package installation requires the exact displayed plan digest",
        )
    if not (config.assume_yes or confirmer(summary)):
        raise InstallerRefusal(
            "confirmation_refused", "the exact install plan was not confirmed by the actor"
        )
    confirmed_at = _timestamp(clock())
    confirmation = {
        "schema": "stateport.install-confirmation/v1",
        "planDigest": plan_digest,
        "releaseIndexDigest": index.index_digest,
        "actorId": config.actor_id,
        "confirmation": "interactive-exact-plan-acknowledged",
        "confirmedAt": confirmed_at,
    }
    confirmation_digest = release.canonical_digest(confirmation)
    _write_json(intent_dir / f"confirmation-{intent['intentId']}.json", confirmation)
    directive: dict[str, Any] = {
        "kind": "installer-directive",
        "directiveId": f"installer_directive_{secrets.token_hex(16)}",
        "directiveKind": "interactive-exact-plan",
        "actorId": config.actor_id,
        "installerDigest": str(installer_artifact["digest"]),
        "releaseIndexDigest": index.index_digest,
        "planDigest": plan_digest,
        "confirmationReceiptDigest": confirmation_digest,
        "confirmedAt": confirmed_at,
    }
    directive["directiveDigest"] = release.installer_directive_digest(directive)
    intent["phase"] = "confirmed"
    _write_json(intent_path, intent)

    # From here the receipt schema has every required fact: failures write a
    # schema-conformant receipt with result "failed" before refusing.
    failure_context = _FailureContext(
        release=release,
        receipts_dir=receipts_dir,
        directive=directive,
        release_identity=release_identity,
        index_digest=index.index_digest,
        signed_digest=index.signed_digest,
        plan_digest=plan_digest,
        target_identity=target_identity,
        host=host_identity,
        signer_entries=signer_entries,
        installer_artifact_digest=str(installer_artifact["digest"]),
        package_installation=package_installation,
        started=started,
        clock=clock,
    )
    try:
        outcome = _execute_install(
            config,
            runner=runner,
            fetcher=fetcher,
            modules=modules,
            release=release,
            verified=verified,
            index=index,
            verifier=verifier,
            target=target,
            images=images,
            artifacts=artifacts,
            installer_artifact=installer_artifact,
            updater_artifact=updater_artifact,
            provisioner_artifact=provisioner_artifact,
            wheel_path=wheel_path,
            provisioner_path=provisioner_path,
            plan_digest=plan_digest,
            host_identity_digest=host_identity_digest,
            collision_digests=collision_digests,
            occupied=occupied,
            observed_services=observed_services,
            observed_image_set=observed_image_set,
            observed_service_set=observed_service_set,
            intent=intent,
            intent_path=intent_path,
            state_root=state_root,
            stage_parent=state_root / "releases" / "staged",
            update_policy=modules.updater_models.UpdatePolicy(
                mode="manual", channel=config.channel
            ),
            clock=clock,
            failure_context=failure_context,
            execution_host_info=execution_host_info,
        )
    except InstallerRefusal as refusal:
        failure_context.write(refusal)
        raise
    if execution_host_info is not None:
        outcome = replace(outcome, execution_host=execution_host_info)
    return outcome


@dataclass
class _FailureContext:
    """Everything a schema-conformant failure receipt needs after confirmation."""

    release: Any
    receipts_dir: Path
    directive: Mapping[str, Any]
    release_identity: Mapping[str, Any]
    index_digest: str
    signed_digest: str
    plan_digest: str
    target_identity: Mapping[str, Any]
    host: Mapping[str, Any]
    signer_entries: Sequence[Mapping[str, Any]]
    installer_artifact_digest: str
    package_installation: Mapping[str, Any] | None
    started: datetime
    clock: Callable[[], datetime]
    artifact_entries: list[dict[str, Any]] | None = None
    image_entries: list[dict[str, Any]] | None = None
    runtime: Mapping[str, Any] | None = None
    data_disposition: str = "not_applicable"

    def write(self, refusal: InstallerRefusal) -> Path | None:
        if (
            self.artifact_entries is None
            or self.image_entries is None
            or self.runtime is None
            or len(self.artifact_entries) not in {7, 8, 9}
            or not self.image_entries
        ):
            return None  # the schema has no honest receipt for this stage
        receipt = {
            "schema": "stateport.install-receipt/v1",
            "receiptId": f"install_receipt_{secrets.token_hex(16)}",
            "operation": "install",
            "installer": {
                "version": INSTALLER_VERSION,
                "digest": self.installer_artifact_digest,
            },
            "release": {
                "releaseId": self.release_identity["releaseId"],
                "version": self.release_identity["version"],
                "channel": self.release_identity["channel"],
                "signedPayloadDigest": self.signed_digest,
                "sourceCommit": self.release_identity["sourceCommit"],
                "sourceTree": self.release_identity["sourceTree"],
            },
            "releaseIndexDigest": self.index_digest,
            "installPlanDigest": self.plan_digest,
            "target": self.target_identity,
            "host": {
                key: value
                for key, value in self.host.items()
                if key not in {"formatVersion", "expectedTarget"}
            },
            **(
                {"podmanPackageInstallation": self.package_installation}
                if self.package_installation is not None
                else {}
            ),
            "verification": {
                "signedIndex": {
                    "expectedDigest": self.index_digest,
                    "observedDigest": self.index_digest,
                    "status": "verified",
                },
                "signers": list(self.signer_entries),
                "artifacts": self.artifact_entries,
                "images": self.image_entries,
            },
            "runtime": self.runtime,
            "dataDisposition": self.data_disposition,
            "authority": self.directive,
            "startedAt": _timestamp(self.started),
            "finishedAt": _timestamp(self.clock()),
            "result": "failed",
        }
        try:
            validated = self.release.validate_install_receipt(receipt)
            path = self.receipts_dir / f"{receipt['receiptId']}.json"
            _write_json(path, validated.as_dict())
        except (InstallerRefusal, OSError, self.release.ReleaseContractError):
            return None
        return path


def _persist_update_trust_root(
    config: InstallConfig,
    *,
    release: Any,
    clock: Callable[[], datetime],
) -> dict[str, Any]:
    """Persist the create-only durable updater trust root inside the state root.

    The pinned key bytes and the trust-root record derive only from the
    operator's out-of-band pinning flags, never from a release artifact.  An
    exact reinstall is a no-op; different existing content refuses closed.
    """

    trust_dir = _ensure_private_directory(config.state_root / "updater" / "trust")
    pem = _read_bounded(config.trust_public_key, description="trust public key", maximum=64 * 1024)
    pem_path = trust_dir / f"{config.trust_key_id}.pem"
    if pem_path.exists() or pem_path.is_symlink():
        if (
            _read_bounded(pem_path, description="persisted trust public key", maximum=64 * 1024)
            != pem
        ):
            raise InstallerRefusal(
                "trust_root_conflict",
                "persisted trust key bytes differ from the pinned trust public key",
            )
    else:
        _atomic_write(pem_path, pem)
    body = {
        "schema": UPDATE_TRUST_ROOT_SCHEMA,
        "mode": "pinned-public-key",
        "keyId": config.trust_key_id,
        "publicKeyFingerprint": config.trust_key_fingerprint,
        "publicKeyFingerprintAlgorithm": "sha256-canonical-der-spki",
        "channel": config.channel,
        "targetId": config.expected_target,
        "publicKeyFileDigest": _sha256_digest(pem),
        "createdAt": _timestamp(clock()),
    }
    digest = release.canonical_digest(body)
    record = {
        "trustRootId": f"update_trust_root_{digest.removeprefix('sha256:')[:32]}",
        **body,
        "trustRootDigest": digest,
    }
    comparable = {
        key: value
        for key, value in record.items()
        if key not in {"trustRootId", "trustRootDigest", "createdAt"}
    }
    record_path = trust_dir / "trust-root.json"
    if record_path.exists() or record_path.is_symlink():
        existing = _load_json(record_path, "update trust root record")
        if (
            existing.get("schema") != UPDATE_TRUST_ROOT_SCHEMA
            or {
                key: value
                for key, value in existing.items()
                if key not in {"trustRootId", "trustRootDigest", "createdAt"}
            }
            != comparable
        ):
            raise InstallerRefusal(
                "trust_root_conflict",
                "persisted update trust root binds different trust material",
            )
        return dict(existing)
    _write_json(record_path, record)
    return record


def _install_update_wrapper(config: InstallConfig, state_root: Path) -> None:
    """Persist the create-only ``stateport-update`` entry point.

    The wrapper binds the installed control-plane seam and the operator-
    controlled tool locations, then execs the updater CLI from the
    digest-verified venv against the durable updater store.  An exact
    reinstall is a no-op; different existing content refuses closed.
    """

    wrapper_dir = _ensure_private_directory(state_root / "bin")
    wrapper_path = wrapper_dir / "stateport-update"
    wrapper_content = (
        "#!/bin/sh\n"
        "# Installed StatePort updater entry point; written once by the installer.\n"
        "export STATEPORT_UPDATER_CONTROL_PLANE=stateport_updater.control_plane:build\n"
        f"export STATEPORT_COSIGN={shlex.quote(INSTALLED_COSIGN_PATH)}\n"
        f"export STATEPORT_QUADLET_ROOT={shlex.quote(str(config.live_quadlet_root))}\n"
        f"exec {shlex.quote(str(state_root / 'updater-venv' / 'bin' / 'python'))} "
        f'-m stateport_updater --state-root {shlex.quote(str(state_root / "updater"))} "$@"\n'
    ).encode("utf-8")
    if wrapper_path.exists() or wrapper_path.is_symlink():
        if wrapper_path.is_symlink() or wrapper_path.read_bytes() != wrapper_content:
            raise InstallerRefusal(
                "updater_wrapper_conflict",
                "existing stateport-update wrapper differs from the installer's",
            )
    else:
        _atomic_write(wrapper_path, wrapper_content)
    os.chmod(wrapper_path, 0o755)


def _default_control_plane_environment(state_root: Path) -> dict[str, str]:
    """Per-install control-plane environment for the default topology.

    The API gains separate local operator and approver identities so mutation
    mode is approval-backed without weakening self-approval prevention. Their
    bearer tokens persist create-only in the state root so interrupted reruns
    converge on the same plan bytes. The worker execution flag is NOT set
    here: it only turns on when the operator supplies a digest-pinned runner
    image and the execute capability, so an unconfigured install stays honest.
    """

    def load_or_create_token(role: str) -> str:
        token_path = state_root / f"control-plane-{role}-token"
        if token_path.is_file() and not token_path.is_symlink():
            try:
                token = token_path.read_text(encoding="utf-8").strip()
            except (OSError, UnicodeError) as exc:
                raise InstallerRefusal(
                    f"{role}_token_unreadable",
                    f"the persisted control-plane {role} token is unreadable: {exc}",
                ) from exc
            if len(token) < 16:
                raise InstallerRefusal(
                    f"{role}_token_invalid",
                    f"the persisted control-plane {role} token is too short",
                )
            return token
        token = secrets.token_urlsafe(32)
        token_path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(token_path, token.encode("utf-8"))
        return token

    operator_token = load_or_create_token("operator")
    approver_token = load_or_create_token("approver")
    return {
        "stateport-api.STATEPORT_IDENTITIES_JSON": json.dumps(
            {
                "local-operator": {
                    "roles": ["operator"],
                    "instances": ["*"],
                },
                "local-approver": {
                    "roles": ["approver"],
                    "instances": ["*"],
                },
            },
            sort_keys=True,
        ),
        "stateport-api.STATEPORT_AUTH_TOKENS_JSON": json.dumps(
            {
                "local-approver": approver_token,
                "local-operator": operator_token,
            },
            sort_keys=True,
        ),
        "stateport-api.STATEPORT_OPERATOR_CAPABILITIES": "execute_container,approve,write_state",
    }


def _derive_control_plane_materialization(
    *,
    release: Any,
    verified: Any,
    index: Any,
    target: Mapping[str, Any],
    images: Sequence[Mapping[str, Any]],
    plan_digest: str,
    host_identity_digest: str,
    collision_digests: Mapping[str, str],
    occupied: Sequence[Mapping[str, Any]],
    state_root: Path,
    clock: Callable[[], datetime],
) -> dict[str, bytes] | None:
    """Derive the accepted control-plane unit bytes for the provisioning plan.

    The provisioner (root helper) runs before the installer's effectful phases
    in the single-line flow, so the plan it provisions against must already
    carry the accepted control-plane units.  This renders the same
    materialization ceremony the installer later re-runs: identical
    deterministic inputs produce identical bytes.
    """
    signed_hex = index.signed_digest.removeprefix("sha256:")
    installation_volumes: dict[str, str] = {}
    snapshot_bindings: list[dict[str, Any]] = []
    requires_snapshot = False
    volumes_by_key: dict[str, Mapping[str, Any]] = {}
    for service in target["services"]:
        for volume in service["writableVolumes"]:
            volume_key = release.revision_volume_key(
                target, str(service["serviceId"]), str(volume["name"])
            )
            volumes_by_key[volume_key] = volume
    for volume_key, volume in sorted(volumes_by_key.items()):
        data_name, snapshot_name = _volume_names(signed_hex, volume_key)
        if volume["scope"] == "installation":
            installation_volumes[volume_key] = data_name
        if volume["validation"]["mode"] == "read-only-snapshot-copy":
            requires_snapshot = True
            snapshot_bindings.append(
                {
                    "volumeKey": volume_key,
                    "snapshotVolumeName": snapshot_name,
                    "sourceDataGeneration": None,
                    "readOnly": True,
                }
            )
    validation_backup_receipt: dict[str, Any] | None = None
    if requires_snapshot:
        # Genesis install: no predecessor data and no writer exists; the
        # empty data volumes and their empty snapshot copies are created
        # exactly (mirrors the genesis receipt built in _execute_install).
        genesis_evidence = {
            "formatVersion": "stateport.genesis-backup-evidence/v1",
            "rationale": "genesis install: no predecessor data and no writer exists; "
            "empty data volumes and their empty snapshot copies were created exactly",
            "dataVolumes": dict(sorted(installation_volumes.items())),
            "snapshots": sorted(snapshot_bindings, key=lambda item: item["volumeKey"]),
            "observedAt": _timestamp(clock()),
        }
        validation_backup_receipt = {
            "schema": "stateport.revision-validation-backup-receipt/v1",
            "operationPlanDigest": plan_digest,
            "releaseId": str(verified.index.release_id),
            "signedPayloadDigest": index.signed_digest,
            "targetId": str(target["targetId"]),
            "topologyDigest": str(target["topologyDigest"]),
            "backupReceiptDigest": release.canonical_digest(genesis_evidence),
            "snapshotSetDigest": release.canonical_digest(
                sorted(snapshot_bindings, key=lambda item: item["volumeKey"])
            ),
            "volumeBindings": sorted(snapshot_bindings, key=lambda item: item["volumeKey"]),
            "createdAt": _timestamp(clock()),
            "consistencyMode": "quiesced",
            "consistencyEvidenceDigest": release.canonical_digest(
                {"quiescence": "genesis-no-writers", **genesis_evidence}
            ),
            "result": "succeeded",
        }
        validation_backup_receipt["receiptDigest"] = release.revision_contract_digest(
            validation_backup_receipt, digest_field="receiptDigest"
        )
    try:
        staged = release.materialize_verified_quadlet_bundle(
            verified,
            operation_plan_digest=plan_digest,
            host_identity_digest=host_identity_digest,
            collision_inventory_digests=collision_digests,
            occupied_port_inputs=occupied,
            proposed_at=_timestamp(clock()),
            validation_backup_receipt=validation_backup_receipt,
        )
    except release.ReleaseContractError as exc:
        raise InstallerRefusal(
            "control_plane_materialization_failed", str(exc)[:500]
        ) from exc
    manifest_key = f"staged/{signed_hex}/materialization.json"
    raw_manifest = staged.get(manifest_key)
    if raw_manifest is None:
        raise InstallerRefusal(
            "control_plane_materialization_failed",
            "the staged materialization has no manifest",
        )
    try:
        staged_manifest = json.loads(raw_manifest.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InstallerRefusal(
            "control_plane_materialization_failed",
            f"the staged materialization manifest is invalid: {exc}",
        ) from exc
    if not isinstance(staged_manifest, dict) or not isinstance(
        staged_manifest.get("artifacts"), list
    ):
        raise InstallerRefusal(
            "control_plane_materialization_failed",
            "the staged materialization manifest lacks an artifact inventory",
        )
    control_plane: dict[str, bytes] = {}
    for artifact in staged_manifest["artifacts"]:
        if (
            artifact.get("profile") != "accepted"
            or artifact.get("owner") != "stateport-control"
            or artifact.get("kind") not in {"container", "network"}
        ):
            continue
        source_path = str(artifact["stagedPath"])
        content = staged.get(source_path)
        if not isinstance(content, bytes):
            raise InstallerRefusal(
                "control_plane_materialization_failed",
                f"the staged control-plane artifact is missing: {source_path}",
            )
        text = content.decode("utf-8")
        for volume_key, volume_name in sorted(installation_volumes.items()):
            text = text.replace(f"@@STATEPORT_ACCEPTED_DATA_VOLUME:{volume_key}@@", volume_name)
        if "@@STATEPORT_" in text:
            raise InstallerRefusal(
                "control_plane_materialization_failed",
                f"the control-plane artifact has unresolved authority tokens: {source_path}",
            )
        live_relative = str(artifact["liveRelativePath"])
        accepted_path = f"accepted/{signed_hex}/stateport-control/{live_relative}"
        control_plane[accepted_path] = text.encode("utf-8")
    if not control_plane:
        raise InstallerRefusal(
            "control_plane_materialization_empty",
            "the signed materialization carries no stateport-control artifacts",
        )
    return control_plane


def _emit_execution_host_provisioning_plan(
    config: InstallConfig,
    *,
    target: Mapping[str, Any],
    images: Sequence[Mapping[str, Any]],
    index_path: Path,
    venv_dir: Path,
    updater_digest: str,
    updater_wheel: Path,
    provisioner_path: Path,
    provisioner_digest: str,
    provisioner_size: int,
    state_root: Path,
    release: Any | None = None,
    verified: Any | None = None,
    index: Any | None = None,
    plan_digest: str | None = None,
    host_identity_digest: str | None = None,
    collision_digests: Mapping[str, str] | None = None,
    occupied: Sequence[Mapping[str, Any]] | None = None,
    clock: Callable[[], datetime] | None = None,
) -> dict[str, Any] | None:
    """Render the execution-host provisioning plan from the verified release.

    The rootless installer NEVER escalates: it emits the exact plan and the
    exact privileged command, and the operator runs the apply as a separate,
    explicitly privileged step.  The plan bytes are re-rendered from the
    signature-verified release on every run; an existing plan file must match
    exactly (create-only convergence, foreign content refuses closed).
    """

    if target.get("executionHostMode") not in {
        "stable-host-daemon-client",
        "stable-host-daemon-bootstrap-only",
    }:
        return None
    try:
        provisioning = importlib.import_module(
            "stateport_release.execution_host_provisioning"
        )
    except ImportError as exc:
        raise InstallerRefusal(
            "provisioning_plan_failed",
            f"the verified updater wheel lacks the execution-host provisioning module: {exc}",
        ) from exc
    client = provisioning.resolve_client_identity()
    if client is None:
        raise InstallerRefusal(
            "provisioning_plan_failed",
            "cannot bind the control-plane client: the invoking user is not resolvable",
        )
    client_user, client_uid, client_gid = client
    control_plane_materialization = None
    if (
        release is not None
        and verified is not None
        and index is not None
        and plan_digest is not None
        and host_identity_digest is not None
        and collision_digests is not None
        and occupied is not None
        and clock is not None
    ):
        control_plane_materialization = _derive_control_plane_materialization(
            release=release,
            verified=verified,
            index=index,
            target=target,
            images=images,
            plan_digest=plan_digest,
            host_identity_digest=host_identity_digest,
            collision_digests=collision_digests,
            occupied=occupied,
            state_root=state_root,
            clock=clock,
        )
    plan = provisioning.render_provisioning_plan(
        target,
        images,
        verification_basis="signature-verified-install",
        client_user=client_user,
        client_uid=client_uid,
        client_gid=client_gid,
        control_plane_materialization=control_plane_materialization,
        control_plane_environment=_default_control_plane_environment(state_root),
    )
    plan_path = state_root / "execution-host-provisioning-plan.json"
    serialized = (json.dumps(plan, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if plan_path.exists() or plan_path.is_symlink():
        if plan_path.is_symlink():
            raise InstallerRefusal(
                "provisioning_plan_conflict",
                "existing execution-host provisioning plan binds different content",
            )
        existing_bytes = _read_bounded(
            plan_path, description="execution-host provisioning plan", maximum=MAX_INDEX_BYTES
        )
        if existing_bytes != serialized:
            try:
                existing_plan = json.loads(existing_bytes.decode("utf-8"))
                existing_digest = str(existing_plan["planDigest"])
                existing_canonical_digest = release.canonical_digest(
                    {
                        key: value
                        for key, value in existing_plan.items()
                        if key not in {"planDigest", "verificationBasis", "evidenceClass"}
                    }
                )
                existing_receipt = _load_json(
                    config.execution_host_receipt,
                    "execution-host provisioning receipt",
                )
            except (KeyError, TypeError, UnicodeError, json.JSONDecodeError, InstallerRefusal):
                existing_plan = None
            if (
                not isinstance(existing_plan, Mapping)
                or existing_digest != existing_canonical_digest
                or existing_receipt.get("result") != "succeeded"
                or existing_receipt.get("planDigest") != existing_digest
            ):
                raise InstallerRefusal(
                    "provisioning_plan_conflict",
                    "existing execution-host provisioning plan binds different content",
                )
            if existing_plan.get("controlPlaneEnvironment") != plan.get(
                "controlPlaneEnvironment"
            ):
                raise InstallerRefusal(
                    "provisioning_plan_environment_changed",
                    "the receipt-bound provisioning plan has a different control-plane identity environment and requires explicit reprovisioning",
                )
            # Provisioning creates the users and directories that influence a
            # fresh render. Reuse the already signed and receipt-bound plan.
            plan = dict(existing_plan)
            plan_digest = existing_digest
    else:
        _atomic_write(plan_path, serialized)
    materialize_argv = [
        "sudo",
        "-n",
        "/usr/local/libexec/stateport-execution-host-provision",
        "materialize",
        "--execution-host-provisioner",
        "/usr/local/libexec/stateport-execution-host-provision",
        "--execution-host-provisioner-digest",
        provisioner_digest,
        "--execution-host-provisioner-bytes",
        str(provisioner_size),
        "--updater-wheel",
        str(updater_wheel),
        "--updater-wheel-digest",
        updater_digest,
        "--release-index",
        str(index_path),
        "--bundle-root",
        str(config.bundle_root),
        "--cosign",
        str(config.cosign),
        "--cosign-digest",
        _sha256_digest(
            _read_bounded(
                config.cosign.resolve(strict=True),
                description="Cosign executable",
                maximum=512 * 1024 * 1024,
            )
        ),
        "--trust-public-key",
        str(config.trust_public_key),
        "--trust-public-key-digest",
        _sha256_digest(_read_bounded(config.trust_public_key, description="trust public key", maximum=64 * 1024)),
        "--trust-key-id",
        config.trust_key_id,
        "--trust-key-fingerprint",
        config.trust_key_fingerprint,
    ]
    provision_argv = [
        "sudo",
        "-n",
        "/usr/local/libexec/stateport-execution-host-provision",
        "provision",
        "--release-index",
        str(index_path),
        "--plan",
        str(plan_path),
        "--cosign",
        INSTALLED_COSIGN_PATH,
        "--trust-public-key",
        INSTALLED_TRUST_PUBLIC_KEY_PATH,
        "--trust-key-id",
        config.trust_key_id,
        "--trust-key-fingerprint",
        config.trust_key_fingerprint,
        "--channel",
        config.channel,
        "--bundle-root",
        str(state_root / "updater" / "bundles"),
        "--receipt-out",
        "/var/lib/stateport-provisioning/receipts/execution-host-provisioning-receipt.json",
    ]
    return {
        "status": "pending-root-helper-provisioning",
        "provisionerPath": "/usr/local/libexec/stateport-execution-host-provision",
        "provisionerSourcePath": str(provisioner_path),
        "provisionerDigest": provisioner_digest,
        "evidenceClass": "plan-rendered",
        "boundary": "rootless-installer-emits-plan;root-helper-provisions-with-explicit-privilege",
        "planPath": str(plan_path),
        "planDigest": plan["planDigest"],
        "imageDigest": plan["image"]["digest"],
        "socketPath": plan["socketPath"],
        "materializeCommand": shlex.join(materialize_argv),
        "provisionerInstallCommand": shlex.join(
            [
                "sudo",
                "-n",
                "install",
                "-o",
                "root",
                "-g",
                "root",
                "-m",
                "0555",
                str(provisioner_path),
                "/usr/local/libexec/stateport-execution-host-provision",
            ]
        ),
        "receiptDirectory": "/var/lib/stateport-provisioning/receipts",
        "receiptPath": "/var/lib/stateport-provisioning/receipts/execution-host-provisioning-receipt.json",
        "provisionArgv": provision_argv,
        "provisionCommand": shlex.join(provision_argv),
    }


def _systemd_user_root(config: InstallConfig) -> Path:
    if config.systemd_user_root is not None:
        return config.systemd_user_root
    root = config.live_quadlet_root
    if root.name == "systemd" and root.parent.name == "containers":
        return root.parent.parent / "systemd" / "user"
    return root.parent / "systemd" / "user"


def _activation_target_content(
    units: Sequence[str], *, release_id: str, signed_digest: str
) -> bytes:
    if not units:
        raise InstallerRefusal("activation_target_invalid", "accepted activation has no units")
    lines = [
        "[Unit]",
        "Description=StatePort accepted release",
        f"X-StatePort-Control-Identity={CONTROL_IDENTITY}",
        f"X-StatePort-Release-Id={release_id}",
        f"X-StatePort-Signed-Payload={signed_digest}",
        "After=" + " ".join(sorted(units)),
        "Wants=" + " ".join(sorted(units)),
        "",
        "[Install]",
        "WantedBy=default.target",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def _write_activation_target(
    config: InstallConfig,
    *,
    units: Sequence[str],
    release_id: str,
    signed_digest: str,
) -> Path:
    root = _ensure_private_directory(_systemd_user_root(config))
    path = root / ACCEPTED_ACTIVATION_TARGET
    content = _activation_target_content(
        units, release_id=release_id, signed_digest=signed_digest
    )
    if path.exists() or path.is_symlink():
        if path.is_symlink() or _read_bounded(
            path, description="accepted activation target", maximum=MAX_INDEX_BYTES
        ) != content:
            raise InstallerRefusal(
                "activation_target_conflict",
                "existing accepted activation target binds different release content",
            )
    else:
        _atomic_write(path, content)
    return path


def _check_user_linger(runner: Runner) -> None:
    try:
        completed = runner.run(
            ["loginctl", "show-user", str(os.getuid()), "--property=Linger", "--value"],
            timeout=60,
        )
    except OSError as exc:
        raise InstallerRefusal(
            "control_identity_unavailable", "could not inspect the control user's linger state"
        ) from exc
    if completed.returncode != 0 or completed.stdout.strip().lower() not in {"yes", "true"}:
        raise InstallerRefusal(
            "linger_required",
            "the control identity must have systemd user linger enabled for reboot recovery",
        )


def _verify_installed_product(
    fetcher: Fetcher,
    *,
    local_url: str,
    timeout: float,
) -> dict[str, Any]:
    """Install-end product gate: the running web service serves the real page.

    Mirrors ``public_alpha_preflight.check_service``: the web root returns the
    StatePort page content marker, a local session opens, and the application
    catalog exposes exactly the expected bundled public fixture as
    installable.  A refusal is typed ``product_gate_failed`` and writes a
    failure receipt (the runtime section is already bound by this point).
    """

    def fetch_gate(url: str) -> FetchResult:
        try:
            return fetcher.fetch(url, timeout=timeout, max_bytes=MAX_PRODUCT_PAGE_BYTES)
        except InstallerRefusal as exc:
            raise InstallerRefusal("product_gate_failed", f"{url}: {exc}") from exc

    base = local_url.rstrip("/")
    root = fetch_gate(base + "/")
    if root.status != 200:
        raise InstallerRefusal(
            "product_gate_failed", f"web root returned HTTP {root.status}, expected 200"
        )
    if not any(marker in root.body for marker in _PRODUCT_PAGE_MARKERS):
        raise InstallerRefusal(
            "product_gate_failed",
            "web root did not serve the StatePort page content marker",
        )
    session = fetch_gate(base + "/session")
    if session.status != 200:
        raise InstallerRefusal(
            "product_gate_failed", f"session endpoint returned HTTP {session.status}, expected 200"
        )
    try:
        session_payload = json.loads(session.body) if session.body else {}
    except ValueError:
        session_payload = {}
    if not isinstance(session_payload, dict) or session_payload.get("ok") is not True:
        raise InstallerRefusal("product_gate_failed", "session endpoint is not ready")
    catalog = fetch_gate(base + "/v1/applications")
    if catalog.status != 200:
        raise InstallerRefusal(
            "product_gate_failed",
            f"application catalog returned HTTP {catalog.status}, expected 200",
        )
    try:
        catalog_payload = json.loads(catalog.body) if catalog.body else {}
    except ValueError:
        catalog_payload = {}
    if not isinstance(catalog_payload, dict):
        raise InstallerRefusal(
            "product_gate_failed", "application catalog response is not an object"
        )
    entry = _validate_product_catalog(catalog_payload)
    return {
        "schema": "stateport.install-end-gate-evidence/v1",
        "pageMarker": "StatePort page served",
        "session": "local operator session ready",
        "applicationId": str(entry["applicationId"]),
        "displayName": str(entry["displayName"]),
    }


def _validate_product_catalog(payload: Any) -> dict[str, Any]:
    """Return the exact sample entry or refuse; mirrors public_alpha_preflight."""

    if not isinstance(payload, dict):
        raise InstallerRefusal("product_gate_failed", "application catalog response is not an object")
    result = payload.get("result")
    applications = result.get("applications") if isinstance(result, dict) else None
    if not isinstance(applications, list):
        raise InstallerRefusal(
            "product_gate_failed", "application catalog response has no result.applications list"
        )
    matches = [
        item
        for item in applications
        if isinstance(item, dict) and item.get("applicationId") == _PRODUCT_APPLICATION_ID
    ]
    if len(matches) != 1:
        raise InstallerRefusal(
            "product_gate_failed",
            f"application catalog must contain exactly one {_PRODUCT_APPLICATION_ID!r} entry; "
            f"found {len(matches)}",
        )
    entry = matches[0]
    if entry.get("displayName") != _PRODUCT_DISPLAY_NAME:
        raise InstallerRefusal(
            "product_gate_failed",
            f"{_PRODUCT_APPLICATION_ID} display name is not the expected "
            f"fictional sample {_PRODUCT_DISPLAY_NAME!r}",
        )
    install = entry.get("install")
    if not isinstance(install, dict):
        raise InstallerRefusal("product_gate_failed", f"{_PRODUCT_APPLICATION_ID} has no install contract")
    if install.get("status") != "available":
        reasons = install.get("reasons", [])
        raise InstallerRefusal("product_gate_failed", f"{_PRODUCT_DISPLAY_NAME} is not installable: {reasons}")
    if install.get("sourceKind") != "bundled_public_fixture":
        raise InstallerRefusal(
            "product_gate_failed", f"{_PRODUCT_DISPLAY_NAME} is not identified as a bundled public fixture"
        )
    if install.get("networkPolicy") != "disabled":
        raise InstallerRefusal(
            "product_gate_failed", f"{_PRODUCT_DISPLAY_NAME} does not declare networkPolicy=disabled"
        )
    capabilities = install.get("requestedCapabilities")
    if not isinstance(capabilities, list) or set(capabilities) != _PRODUCT_EXPECTED_CAPABILITIES:
        raise InstallerRefusal(
            "product_gate_failed",
            f"{_PRODUCT_DISPLAY_NAME} requested capabilities do not match the public-alpha contract",
        )
    if install.get("confirmationRequired") is not True:
        raise InstallerRefusal(
            "product_gate_failed", f"{_PRODUCT_DISPLAY_NAME} does not require explicit installation confirmation"
        )
    return entry


def _gate_execution_host(
    config: InstallConfig,
    *,
    execution_host_info: Mapping[str, Any],
    target: Mapping[str, Any],
    release: Any,
) -> dict[str, Any]:
    """Require the root transaction receipt proving a healthy execution host.

    Protocol health is proven by the privileged provisioning transaction,
    which probes the confined control socket as the allowed client identity
    and records the result in the digest-bound receipt. The rootless
    installer must not duplicate that probe in-process: a second socket probe
    by the invoking user would turn a healthy provision into a permission
    failure.
    """

    receipt_path = config.execution_host_receipt
    if receipt_path is None:
        raise InstallerRefusal(
            "execution_host_provisioning_required",
            "stable execution-host installs require --execution-host-receipt from the root helper",
        )
    try:
        receipt = _load_json(receipt_path, "execution-host provisioning receipt")
        validated = release.validate_contract_document(
            receipt,
            expected_schema="stateport.execution-host-provisioning-receipt/v1",
        ).as_dict()
    except (InstallerRefusal, release.ReleaseContractError) as exc:
        raise InstallerRefusal(
            "execution_host_receipt_invalid",
            f"execution-host provisioning receipt is invalid: {exc}",
        ) from exc
    if validated.get("receiptDigest") != release.revision_contract_digest(
        validated, digest_field="receiptDigest"
    ):
        raise InstallerRefusal(
            "execution_host_receipt_invalid", "execution-host provisioning receipt digest is stale"
        )
    plan_digest = str(execution_host_info["planDigest"])
    plan = _load_json(Path(str(execution_host_info["planPath"])), "execution-host plan")
    image = validated.get("image", {})
    mismatches = []
    if validated.get("result") != "succeeded":
        mismatches.append("result")
    if validated.get("planDigest") != plan_digest:
        mismatches.append("planDigest")
    if validated.get("releaseId") != target.get("releaseId"):
        mismatches.append("releaseId")
    for field, expected in (
        ("releaseIndexDigest", execution_host_info["releaseIndexDigest"]),
        ("signedPayloadDigest", execution_host_info["signedPayloadDigest"]),
        ("sourceCommit", execution_host_info["sourceCommit"]),
        ("sourceTree", execution_host_info["sourceTree"]),
        ("installerDigest", execution_host_info["installerDigest"]),
    ):
        if validated.get(field) != expected:
            mismatches.append(field)
    if validated.get("targetId") != target.get("targetId"):
        mismatches.append("targetId")
    if validated.get("topologyDigest") != target.get("topologyDigest"):
        mismatches.append("topologyDigest")
    if validated.get("verificationBasis") not in {
        "signature-verified-provisioning",
        "signature-verified-apply",
    }:
        mismatches.append("verificationBasis")
    if image.get("expectedDigest") != execution_host_info["imageDigest"]:
        mismatches.append("image.expectedDigest")
    if image.get("observedDigest") != execution_host_info["imageDigest"]:
        mismatches.append("image.observedDigest")
    if image.get("status") != "verified":
        mismatches.append("image.status")
    if validated.get("health", {}).get("healthy") is not True:
        mismatches.append("health")
    for field in (
        "executionUser",
        "executionUid",
        "executionGid",
        "controlUser",
        "controlUid",
        "controlGid",
        "executionControlGroup",
        "executionControlGroupGid",
        "allowedClientUser",
    ):
        if validated.get(field) != plan.get(field):
            mismatches.append(field)
    if mismatches:
        raise InstallerRefusal(
            "execution_host_receipt_mismatch",
            "execution-host provisioning receipt does not prove this exact healthy release: "
            + ", ".join(mismatches),
        )
    control_grant = validated.get("controlGrant")
    if (
        not isinstance(control_grant, Mapping)
        or control_grant.get("grantId") != "control-plane-default"
        or not isinstance(control_grant.get("grantDigest"), str)
        or not control_grant["grantDigest"].startswith("sha256:")
    ):
        raise InstallerRefusal(
            "execution_host_grant_missing",
            "execution-host provisioning receipt lacks the provisioned control-plane grant",
        )
    return {
        **dict(execution_host_info),
        "status": "provisioned-and-healthy",
        "receiptPath": str(receipt_path),
        "receiptDigest": str(validated["receiptDigest"]),
        "health": dict(validated.get("health", {})),
        "controlGrant": dict(control_grant),
    }


def _execute_install(
    config: InstallConfig,
    *,
    runner: Runner,
    fetcher: Fetcher,
    modules: VerifiedModules,
    release: Any,
    verified: Any,
    index: Any,
    verifier: Any,
    target: Mapping[str, Any],
    images: Sequence[Mapping[str, Any]],
    artifacts: Mapping[str, Any],
    installer_artifact: Mapping[str, Any],
    updater_artifact: Mapping[str, Any],
    provisioner_artifact: Mapping[str, Any],
    wheel_path: Path,
    provisioner_path: Path,
    plan_digest: str,
    host_identity_digest: str,
    collision_digests: Mapping[str, str],
    occupied: Sequence[Mapping[str, Any]],
    observed_services: list[dict[str, Any]],
    observed_image_set: str,
    observed_service_set: str,
    intent: dict[str, Any],
    intent_path: Path,
    state_root: Path,
    stage_parent: Path,
    update_policy: Any,
    clock: Callable[[], datetime],
    failure_context: _FailureContext,
    execution_host_info: Mapping[str, Any] | None,
) -> InstallOutcome:
    """Effectful phases; every refusal leaves a failure receipt where possible."""

    # Genuine artifact verification: installer self, updater wheel, and every
    # supplementary artifact as exact bytes.  The quadlet artifact is verified
    # by full re-derivation during materialization below.
    installer_path = config.installer_path or Path(__file__).resolve()
    artifact_entries = [
        _verify_artifact_bytes(installer_path, "installer", str(installer_artifact["digest"])),
        _verify_artifact_bytes(
            provisioner_path,
            "executionHostProvisioner",
            str(provisioner_artifact["digest"]),
        ),
        _verify_artifact_bytes(wheel_path, "updater", str(updater_artifact["digest"])),
    ]
    supplementary = {
        "compose": config.compose,
        "sourceArchive": config.source_archive,
        "releaseNotes": config.release_notes,
        "knownLimitations": config.known_limitations,
        "podmanPackageBundle": config.podman_package_bundle,
    }
    download_dir = state_root / "work" / "downloads"
    supplementary_ids = _SUPPLEMENTARY_ARTIFACTS + (
        ("podmanPackageBundle",) if "podmanPackageBundle" in artifacts else ()
    )
    for artifact_id in supplementary_ids:
        artifact = artifacts.get(artifact_id)
        if not isinstance(artifact, dict):
            raise InstallerRefusal(
                "index_malformed", f"signed payload lacks artifact {artifact_id}"
            )
        source = supplementary[artifact_id]
        if not isinstance(source, str) or not source:
            raise InstallerRefusal(
                "artifact_missing", f"install input is missing for signed artifact {artifact_id}"
            )
        path = _acquire_input(
            source,
            description=f"{artifact_id} artifact",
            expected_sha256=None,
            require_published_digest=False,
            fetcher=fetcher,
            download_dir=download_dir,
        )
        artifact_entries.append(_verify_artifact_bytes(path, artifact_id, str(artifact["digest"])))

    # Pull the exact digest-pinned images; verify observed digests.
    image_entries: list[dict[str, Any]] = []
    for image in sorted(images, key=lambda item: item["imageId"]):
        reference = str(image["reference"])
        if "@sha256:" not in reference:
            raise InstallerRefusal(
                "image_reference_refused", f"image reference is not digest-pinned: {reference}"
            )
        pulled = runner.run(["podman", "pull", reference], timeout=3600)
        if pulled.returncode != 0:
            raise InstallerRefusal(
                "image_pull_failed", f"podman pull {reference}: {pulled.stderr.strip()[:200]}"
            )
        inspected = runner.run(
            ["podman", "image", "inspect", "--format", "{{.Digest}}", reference], timeout=120
        )
        if inspected.returncode != 0:
            raise InstallerRefusal(
                "image_inspect_failed", f"podman inspect {reference} failed after pull"
            )
        observed_digest = "sha256:" + inspected.stdout.strip().removeprefix("sha256:")
        if observed_digest != image["digest"]:
            raise InstallerRefusal(
                "image_digest_mismatch",
                f"observed {image['imageId']} digest {observed_digest} != signed {image['digest']}",
            )
        image_entries.append(
            {
                "imageId": str(image["imageId"]),
                "reference": reference,
                "expectedDigest": str(image["digest"]),
                "observedDigest": observed_digest,
                "sizeBytes": int(image["sizeBytes"]),
                "signatureBundleDigest": str(image["signature"]["bundle"]["digest"]),
                "cycloneDxDigest": str(image["sboms"]["cycloneDx"]["digest"]),
                "spdxDigest": str(image["sboms"]["spdx"]["digest"]),
                "scanDigest": str(image["scan"]["artifact"]["digest"]),
                "provenanceDigest": str(image["provenance"]["digest"]),
                "status": "verified",
            }
        )
    intent["phase"] = "images-verified"
    _write_json(intent_path, intent)

    # Genesis data volumes and the honest empty genesis validation backup.
    signed_hex = index.signed_digest.removeprefix("sha256:")
    installation_volumes: dict[str, str] = {}
    snapshot_bindings: list[dict[str, Any]] = []
    requires_snapshot = False
    volumes_by_key: dict[str, Mapping[str, Any]] = {}
    for service in target["services"]:
        for volume in service["writableVolumes"]:
            volume_key = release.revision_volume_key(
                target, str(service["serviceId"]), str(volume["name"])
            )
            volumes_by_key[volume_key] = volume
    for volume_key, volume in sorted(volumes_by_key.items()):
        data_name, snapshot_name = _volume_names(signed_hex, volume_key)
        _ensure_volume(runner, data_name)
        failure_context.data_disposition = "created"
        if volume["scope"] == "installation":
            installation_volumes[volume_key] = data_name
        if volume["validation"]["mode"] == "read-only-snapshot-copy":
            requires_snapshot = True
            _ensure_volume(runner, snapshot_name)
            snapshot_bindings.append(
                {
                    "volumeKey": volume_key,
                    "snapshotVolumeName": snapshot_name,
                    "sourceDataGeneration": None,
                    "readOnly": True,
                }
            )
    validation_backup_receipt: dict[str, Any] | None = None
    if requires_snapshot:
        genesis_evidence = {
            "formatVersion": "stateport.genesis-backup-evidence/v1",
            "rationale": "genesis install: no predecessor data and no writer exists; "
            "empty data volumes and their empty snapshot copies were created exactly",
            "dataVolumes": dict(sorted(installation_volumes.items())),
            "snapshots": sorted(snapshot_bindings, key=lambda item: item["volumeKey"]),
            "observedAt": _timestamp(clock()),
        }
        validation_backup_receipt = {
            "schema": "stateport.revision-validation-backup-receipt/v1",
            "operationPlanDigest": plan_digest,
            "releaseId": str(verified.index.release_id),
            "signedPayloadDigest": index.signed_digest,
            "targetId": str(target["targetId"]),
            "topologyDigest": str(target["topologyDigest"]),
            "backupReceiptDigest": release.canonical_digest(genesis_evidence),
            "snapshotSetDigest": release.canonical_digest(
                sorted(snapshot_bindings, key=lambda item: item["volumeKey"])
            ),
            "volumeBindings": sorted(snapshot_bindings, key=lambda item: item["volumeKey"]),
            "createdAt": _timestamp(clock()),
            "consistencyMode": "quiesced",
            "consistencyEvidenceDigest": release.canonical_digest(
                {"quiescence": "genesis-no-writers", **genesis_evidence}
            ),
            "result": "succeeded",
        }
        validation_backup_receipt["receiptDigest"] = release.revision_contract_digest(
            validation_backup_receipt, digest_field="receiptDigest"
        )

    # Materialize the staged bundle from the verified release (never hand-rendered).
    try:
        staged = release.materialize_verified_quadlet_bundle(
            verified,
            operation_plan_digest=plan_digest,
            host_identity_digest=host_identity_digest,
            collision_inventory_digests=collision_digests,
            occupied_port_inputs=occupied,
            proposed_at=_timestamp(clock()),
            validation_backup_receipt=validation_backup_receipt,
        )
    except release.ReleaseContractError as exc:
        raise InstallerRefusal("materialization_failed", str(exc)[:500]) from exc
    # Quadlet artifact verification is full re-derivation digest equality.
    templates = release.render_quadlet_bundle(target, images)
    observed_quadlet = release.quadlet_bundle_digest(templates)
    if observed_quadlet != target[
        "quadletBundleDigest"
    ] or observed_quadlet != quadlet_artifact_digest(artifacts):
        raise InstallerRefusal(
            "quadlet_digest_mismatch", "re-derived quadlet bundle does not match the signed digest"
        )
    artifact_entries.append(
        {
            "artifactId": "quadlet",
            "expectedDigest": quadlet_artifact_digest(artifacts),
            "observedDigest": observed_quadlet,
            "status": "verified",
        }
    )
    artifact_entries.sort(key=lambda item: item["artifactId"])
    failure_context.artifact_entries = artifact_entries
    failure_context.image_entries = image_entries

    stage_root = _ensure_private_directory(stage_parent / signed_hex)
    staged_manifest: Mapping[str, Any] | None = None
    prefix = f"staged/{signed_hex}/"
    for relative, content in sorted(staged.items()):
        if not relative.startswith(prefix):
            raise InstallerRefusal("materialization_failed", f"unexpected staged path {relative}")
        local = stage_root / PurePosixPath(relative[len(prefix) :])
        _ensure_private_directory(local.parent)
        _atomic_write(local, content)
        if local.name == "materialization.json":
            staged_manifest = json.loads(content)
    if staged_manifest is None:
        raise InstallerRefusal("materialization_failed", "staged bundle has no manifest")
    ports = {key: int(value) for key, value in staged_manifest["ports"].items()}
    ports = _reconcile_ports_with_installed_units(
        ports, staged, prefix, target["services"]
    )
    control_grant_digest: str | None = None
    if execution_host_info is not None:
        _control_grant = execution_host_info.get("controlGrant")
        if isinstance(_control_grant, Mapping) and isinstance(
            _control_grant.get("grantDigest"), str
        ):
            control_grant_digest = _control_grant["grantDigest"]

    # The execution-host plan was emitted (with the control-plane units) before
    # the effectful phases; gate the receipt against it.
    if execution_host_info is not None:
        execution_host_info = _gate_execution_host(
            config,
            execution_host_info=execution_host_info,
            target=target,
            release=release,
        )
        _control_grant = execution_host_info.get("controlGrant")
        if isinstance(_control_grant, Mapping) and isinstance(
            _control_grant.get("grantDigest"), str
        ):
            control_grant_digest = _control_grant["grantDigest"]

    # From here a failure has every fact the runtime section needs: bind the
    # planned loopback URL with all services unhealthy until proven otherwise.
    web_port = ports.get("stateport-web:accepted:http")
    local_url = f"http://127.0.0.1:{web_port}/" if web_port is not None else "http://127.0.0.1/"
    planned_runtime: dict[str, Any] = {
        "releaseId": str(verified.index.release_id),
        "releaseIndexDigest": index.index_digest,
        "signedPayloadDigest": index.signed_digest,
        "targetDigest": target_identity_digest(failure_context),
        "topologyDigest": str(target["topologyDigest"]),
        "quadletArtifactDigest": quadlet_artifact_digest(artifacts),
        "quadletBundleDigest": str(target["quadletBundleDigest"]),
        "imageSetDigest": observed_image_set,
        "serviceSetDigest": observed_service_set,
        "services": [dict(service) for service in observed_services],
        "localUrl": local_url,
        "healthy": False,
    }
    planned_runtime["runtimeIdentityDigest"] = release.canonical_digest(planned_runtime)
    failure_context.runtime = planned_runtime

    # Install accepted-profile artifacts into the live Quadlet root; resolve
    # only the pending accepted-data tokens with the exact genesis volumes.
    # The stateport-control owner's units (web/api/worker) are ALSO written
    # here for convergence detection, but they are started by the root
    # provisioning transaction under the control user, never by this user's
    # systemd manager.
    live_root = _ensure_private_directory(config.live_quadlet_root)
    installed_units: list[str] = []
    provisioner_started_units: set[str] = set()
    for artifact in staged_manifest["artifacts"]:
        if artifact["profile"] != "accepted" or artifact["kind"] not in {"container", "network"}:
            continue
        source = stage_root / PurePosixPath(str(artifact["stagedPath"])[len(prefix) :])
        text = source.read_bytes().decode("utf-8")
        for volume_key, volume_name in sorted(installation_volumes.items()):
            text = text.replace(f"@@STATEPORT_ACCEPTED_DATA_VOLUME:{volume_key}@@", volume_name)
        if "@@STATEPORT_" in text:
            raise InstallerRefusal(
                "materialization_failed",
                f"accepted artifact has unresolved tokens: {artifact['stagedPath']}",
            )
        if "[Install]" in text or "WantedBy=" in text:
            raise InstallerRefusal(
                "boot_activation_refused", "accepted units must never be boot-enabled"
            )
        unit_name = PurePosixPath(str(artifact["liveRelativePath"])).name
        _atomic_write(live_root / unit_name, text.encode("utf-8"))
        if artifact["kind"] == "container":
            installed_units.append(unit_name.removesuffix(".container"))
            if execution_host_info is not None and artifact.get("owner") == "stateport-control":
                # Started by the root provisioning transaction under the
                # control user; never started here.
                provisioner_started_units.add(unit_name.removesuffix(".container"))
    intent["phase"] = "units-installed"
    _write_json(intent_path, intent)

    # The root provisioning transaction re-renders control-plane units with
    # its own collision inventory; poll the ports the started units actually
    # publish, not the plan ceremony's numbers.
    ports = _reconcile_ports_with_live_units(
        ports,
        target["services"],
        staged_manifest["artifacts"],
        live_root=live_root,
        control_root=Path("/var/lib/stateport-control/.config/containers/systemd"),
        runner=runner,
        provisioned=execution_host_info is not None,
    )

    # Start services via the systemd user manager (excluding provisioner-owned
    # control-plane units, which run under the control user).
    reloaded = runner.run(["systemctl", "--user", "daemon-reload"], timeout=120)
    if reloaded.returncode != 0:
        raise InstallerRefusal(
            "systemd_reload_failed", f"daemon-reload failed: {reloaded.stderr.strip()[:200]}"
        )
    for unit in sorted(set(installed_units) - provisioner_started_units):
        started_unit = runner.run(["systemctl", "--user", "start", unit], timeout=900)
        if started_unit.returncode != 0:
            raise InstallerRefusal(
                "service_start_failed",
                f"systemctl --user start {unit}: {started_unit.stderr.strip()[:200]}",
            )

    # Wait for health and capture service-reported runtime identity evidence.
    container_names = {
        str(service["serviceId"]): "stateport-"
        + release.canonical_digest({"serviceId": str(service["serviceId"])})[7:19]
        + "-accepted-"
        + str(staged_manifest["revisions"][f"{service['serviceId']}:accepted"])
        for service in target["services"]
    }
    evidence = _wait_for_health(
        target["services"],
        ports,
        container_names,
        fetcher=fetcher,
        runner=runner,
        clock=clock,
        timeout_seconds=config.health_timeout_seconds,
        poll_seconds=config.health_poll_seconds,
    )
    intent["phase"] = "healthy"
    _write_json(intent_path, intent)
    _write_json(
        state_root / "runtime-identity-evidence.json",
        {"schema": "stateport.runtime-identity-evidence/v1", "evidence": evidence},
    )

    for service in observed_services:
        service["healthy"] = any(item["serviceId"] == service["serviceId"] for item in evidence)

    # Install-end gates (F14): the running web service must serve the real
    # product page and catalog. The privileged provisioning receipt already
    # contains the live execution-host probe performed as the allowed client;
    # the rootless installer must not repeat that confined socket probe.
    # local_url bound earlier reflects the plan ceremony; the gate must knock
    # on the port the started web unit actually publishes.
    reconciled_web_port = ports.get("stateport-web:accepted:http")
    product_gate_url = (
        f"http://127.0.0.1:{reconciled_web_port}/"
        if reconciled_web_port is not None
        else local_url
    )
    product_gate = _verify_installed_product(
        fetcher, local_url=product_gate_url, timeout=config.health_timeout_seconds
    )
    execution_host_recheck = None
    if execution_host_info is not None:
        execution_host_recheck = {
            "source": "privileged-provisioning-receipt",
            "healthy": execution_host_info["health"].get("healthy") is True,
            "contractVersion": execution_host_info["health"].get("contractVersion"),
        }
    _write_json(
        state_root / "install-end-gate-evidence.json",
        {
            "schema": "stateport.install-end-gate-evidence/v1",
            "product": product_gate,
            "executionHostRecheck": execution_host_recheck,
        },
    )

    # Publish reboot recovery only after every accepted service is healthy.
    # Staged/validation units remain outside every boot target and are never
    # auto-started.  With a provisioned stable execution host, the control
    # plane runs under the stateport-control user and the root provisioning
    # transaction writes the authoritative activation target into that user's
    # systemd root; the invoking-user target is still written here as a
    # convergence/fallback marker.
    activation_target = _write_activation_target(
        config,
        units=installed_units,
        release_id=str(verified.index.release_id),
        signed_digest=index.signed_digest,
    )
    if execution_host_info is None:
        _check_user_linger(runner)
        _daemon_reload(runner)
        enabled_target = runner.run(
            ["systemctl", "--user", "enable", ACCEPTED_ACTIVATION_TARGET], timeout=120
        )
        if enabled_target.returncode != 0:
            raise InstallerRefusal(
                "activation_target_enable_failed",
                f"could not enable {ACCEPTED_ACTIVATION_TARGET}: {enabled_target.stderr.strip()[:200]}",
            )
    runtime: dict[str, Any] = {
        "releaseId": str(verified.index.release_id),
        "releaseIndexDigest": index.index_digest,
        "signedPayloadDigest": index.signed_digest,
        "targetDigest": target_identity_digest(failure_context),
        "topologyDigest": str(target["topologyDigest"]),
        "quadletArtifactDigest": quadlet_artifact_digest(artifacts),
        "quadletBundleDigest": str(target["quadletBundleDigest"]),
        "imageSetDigest": observed_image_set,
        "serviceSetDigest": observed_service_set,
        "services": observed_services,
        "localUrl": local_url,
        "healthy": all(service["healthy"] for service in observed_services),
        "activationTarget": ACCEPTED_ACTIVATION_TARGET,
        "activationTargetPath": str(activation_target),
        "controlIdentity": CONTROL_IDENTITY,
    }
    if execution_host_info is not None:
        runtime["executionHostProvisioningReceiptDigest"] = str(
            execution_host_info["receiptDigest"]
        )
    runtime["runtimeIdentityDigest"] = release.canonical_digest(runtime)
    failure_context.runtime = runtime

    # Updater genesis: persist the durable out-of-band trust root, admit the
    # exact genesis release through the typed pinned-key admission contract,
    # and inject the installed-authority identity.  A stale
    # updater/genesis-boundary.json from a pre-contract install is a historic
    # record and is deliberately left untouched.
    store = modules.updater_store.UpdateStore.create(state_root / "updater")
    envelope = release.to_updater_release_envelope(verified)
    trust_root = _persist_update_trust_root(config, release=release, clock=clock)
    engine = modules.updater_engine.UpdateEngine(
        store,
        object(),  # host: genesis initialization performs no host calls
        object(),  # authority: genesis initialization claims no authority
        verification_policy=release.ReleaseVerificationPolicy(
            expected_channel=config.channel,
            expected_target=config.expected_target,
            updater_version=str(modules.updater_engine.UPDATER_VERSION),
            accepted_signers=frozenset(),
            accepted_public_keys=frozenset(
                {release.PinnedPublicKeyIdentity(config.trust_key_fingerprint, config.trust_key_id)}
            ),
            expected_trust_mode="pinned-public-key",
            now=clock(),
            allow_candidate=True,
            require_transparency_log=False,
        ),
        signature_verifier=verifier,
        target_id=config.expected_target,
        clock=clock,
    )
    try:
        engine.initialize(envelope, update_policy)
    except modules.updater_engine.UpdateError as exc:
        if exc.code != "already_initialized":
            raise InstallerRefusal("updater_genesis_failed", str(exc)[:300]) from exc
        existing_status = _load_json(store.status_path, "update status")
        current = existing_status.get("current", {})
        if (
            current.get("releaseId") != str(verified.index.release_id)
            or current.get("signedPayloadDigest") != index.signed_digest
        ):
            raise InstallerRefusal(
                "updater_genesis_conflict", "existing updater status binds a different release"
            ) from exc
    if verified.authenticated_predecessor is not None:
        predecessor_index = verified.authenticated_predecessor.index
        # Same-lane predecessors (the J1 qualification lane shares one
        # releaseId across candidates) are already embedded and authenticated
        # inside the successor's verified index chain; the releases/ store
        # slot is keyed by releaseId, so writing the predecessor there would
        # conflict with the genesis index. Only persist a predecessor when it
        # has a distinct release identity.
        if str(predecessor_index.release_id) != str(verified.index.release_id):
            with store.transaction() as session:
                session.save_release_index_bytes(
                    predecessor_index.release_id, predecessor_index.canonical_index_bytes
                )
    genesis_admissions = [
        item
        for item in (
            _load_json(path, "release admission")
            for path in sorted(store.admissions.glob("*.json"))
        )
        if item.get("kind") == "installed-initialize"
        and item.get("releaseId") == str(verified.index.release_id)
        and item.get("releaseIndexDigest") == index.index_digest
        and item.get("signedPayloadDigest") == index.signed_digest
    ]
    if len(genesis_admissions) != 1:
        raise InstallerRefusal(
            "updater_genesis_conflict",
            "updater admissions do not bind the exact genesis release",
        )
    admission = genesis_admissions[0]
    try:
        identity = modules.updater_installed.InstalledAuthorityAdapter.install(
            store,
            installer_digest=str(installer_artifact["digest"]),
            installer_origin=INSTALLER_ORIGIN,
            installer_version=INSTALLER_VERSION,
            actor_id=config.actor_id,
            clock=clock,
        )
    except modules.updater_installed.UpdateAuthorityError as exc:
        if exc.code != "installed_identity_exists":
            raise InstallerRefusal("updater_genesis_failed", str(exc)[:300]) from exc
        adapter = modules.updater_installed.InstalledAuthorityAdapter(store, clock=clock)
        identities = [
            _load_json(path, "installed identity record")
            for path in sorted(adapter.identity_dir.glob("*.json"))
        ]
        if (
            len(identities) != 1
            or identities[0].get("releaseId") != str(verified.index.release_id)
            or identities[0].get("releaseIndexDigest") != index.index_digest
            or identities[0].get("signedPayloadDigest") != index.signed_digest
            or identities[0].get("installerDigest") != str(installer_artifact["digest"])
        ):
            raise InstallerRefusal(
                "updater_genesis_conflict",
                "existing installed authority binds a different release",
            ) from exc
        identity = identities[0]
    # The install-receipt schema is strict, so the genesis trust binding lives
    # in its own durable record; it never names the PEM path, only digests.
    install_trust = {
        "schema": INSTALL_TRUST_SCHEMA,
        "trustRootId": trust_root["trustRootId"],
        "trustRootDigest": trust_root["trustRootDigest"],
        "mode": "pinned-public-key",
        "keyId": config.trust_key_id,
        "publicKeyFingerprint": config.trust_key_fingerprint,
        "channel": config.channel,
        "targetId": config.expected_target,
        "releaseId": str(verified.index.release_id),
        "releaseIndexDigest": index.index_digest,
        "signedPayloadDigest": index.signed_digest,
        "admissionId": str(admission["admissionId"]),
        "admissionDigest": str(admission["admissionDigest"]),
        "installedIdentityId": str(identity["identityId"]),
        "installedIdentityDigest": str(identity["identityDigest"]),
        "installerDigest": str(installer_artifact["digest"]),
        "createdAt": _timestamp(clock()),
    }
    install_trust_path = state_root / "updater" / "trust" / "install-trust.json"
    comparable = {key: value for key, value in install_trust.items() if key != "createdAt"}
    if install_trust_path.exists() or install_trust_path.is_symlink():
        existing_trust = _load_json(install_trust_path, "install trust record")
        if {
            key: value for key, value in existing_trust.items() if key != "createdAt"
        } != comparable:
            raise InstallerRefusal(
                "updater_genesis_conflict",
                "existing install trust record binds a different release",
            )
    else:
        _write_json(install_trust_path, install_trust)
    intent["phase"] = "updater-genesis"
    _write_json(intent_path, intent)

    _install_update_wrapper(config, state_root)

    receipt: dict[str, Any] = {
        "schema": "stateport.install-receipt/v1",
        "receiptId": f"install_receipt_{secrets.token_hex(16)}",
        "operation": "install",
        "installer": {"version": INSTALLER_VERSION, "digest": str(installer_artifact["digest"])},
        "release": {
            "releaseId": str(verified.index.release_id),
            "version": str(verified.index.version),
            "channel": str(verified.index.channel),
            "signedPayloadDigest": index.signed_digest,
            "sourceCommit": str(index.document["signed"]["source"]["commit"]),
            "sourceTree": str(index.document["signed"]["source"]["tree"]),
        },
        "releaseIndexDigest": index.index_digest,
        "installPlanDigest": plan_digest,
        "target": failure_context.target_identity,
        "host": {
            key: value
            for key, value in failure_context.host.items()
            if key not in {"formatVersion", "expectedTarget"}
        },
        **(
            {"podmanPackageInstallation": failure_context.package_installation}
            if failure_context.package_installation is not None
            else {}
        ),
        "verification": {
            "signedIndex": {
                "expectedDigest": index.index_digest,
                "observedDigest": index.index_digest,
                "status": "verified",
            },
            "signers": list(failure_context.signer_entries),
            "artifacts": artifact_entries,
            "images": image_entries,
        },
        "runtime": runtime,
        "dataDisposition": "created",
        "authority": failure_context.directive,
        "startedAt": _timestamp(failure_context.started),
        "finishedAt": _timestamp(clock()),
        "result": "succeeded",
    }
    try:
        validated = release.validate_install_receipt(receipt)
    except release.ReleaseContractError as exc:
        raise InstallerRefusal("receipt_assembly_failed", str(exc)[:500]) from exc
    receipt_dir = _ensure_private_directory(state_root / "receipts")
    receipt_path = receipt_dir / f"{receipt['receiptId']}.json"
    _write_json(receipt_path, validated.as_dict())
    intent["phase"] = "receipted"
    _write_json(intent_path, intent)
    return InstallOutcome(
        status="succeeded",
        code="installed",
        message="install completed and receipted",
        local_url=local_url,
        receipt_path=receipt_path,
    )


def quadlet_artifact_digest(artifacts: Mapping[str, Any]) -> str:
    quadlet = artifacts.get("quadlet")
    if not isinstance(quadlet, dict):
        raise InstallerRefusal("index_malformed", "signed payload lacks the quadlet artifact")
    return str(quadlet["digest"])


def target_identity_digest(failure_context: _FailureContext) -> str:
    return str(failure_context.target_identity["targetDigest"])


# ---------------------------------------------------------------------------
# uninstall/purge engine (recorded authority only, converge on partial state)
# ---------------------------------------------------------------------------

_CONTAINER_NAME = re.compile(r"^ContainerName=([0-9a-z][0-9a-z._-]{1,127})$", re.MULTILINE)
_ACCEPTED_VOLUME_TOKEN = re.compile(r"@@STATEPORT_ACCEPTED_DATA_VOLUME:([^@]+)@@")
# Refusals for which writing a durable record into the state root would itself
# be wrong: the directory is foreign, unsafe, or the root argument is invalid.
_UNINSTALL_UNRECORDABLE_REFUSALS = frozenset(
    {"no_installation_found", "state_root_not_stateport", "state_root_invalid", "state_root_unsafe"}
)


@dataclass(frozen=True)
class _RemovalPlan:
    """Every resource an uninstall may touch, derived from durable records only."""

    units: tuple[str, ...]
    containers: tuple[str, ...]
    quadlet_files: tuple[str, ...]
    activation_target: str
    data_volumes: tuple[str, ...]
    snapshot_volumes: tuple[str, ...]
    control_units: tuple[str, ...] = ()


def _union_removal_plans(plans: Sequence[_RemovalPlan]) -> _RemovalPlan:
    """Merge per-release removal plans (genesis ∪ accepted update revisions)."""
    return _RemovalPlan(
        units=tuple(sorted({unit for plan in plans for unit in plan.units})),
        containers=tuple(sorted({name for plan in plans for name in plan.containers})),
        quadlet_files=tuple(sorted({name for plan in plans for name in plan.quadlet_files})),
        activation_target=ACCEPTED_ACTIVATION_TARGET,
        data_volumes=tuple(sorted({name for plan in plans for name in plan.data_volumes})),
        snapshot_volumes=tuple(
            sorted({name for plan in plans for name in plan.snapshot_volumes})
        ),
        control_units=tuple(sorted({unit for plan in plans for unit in plan.control_units})),
    )


def _load_updater_accepted_identities(state_root: Path) -> list[dict[str, Any]]:
    """Release identities the updater status records (current/accepted/staged).

    After an accepted update the live runtime binds the SUCCESSOR release, not
    the genesis install-trust record; uninstall/purge must cover the union.
    """
    status_path = state_root / "updater" / "status.json"
    if not status_path.exists():
        return []
    if status_path.is_symlink() or not status_path.is_file():
        raise InstallerRefusal(
            "installation_record_invalid", f"updater status is not a regular file: {status_path}"
        )
    raw = _load_json(status_path, "update status")
    if raw.get("schema") != "stateport.update-status/v1":
        raise InstallerRefusal(
            "installation_record_invalid", f"updater status at {status_path} is not a v1 status"
        )
    identities: list[dict[str, Any]] = []
    for field, kind in (
        ("current", "current"),
        ("accepted", "accepted"),
        ("stagedSuccessor", "stagedSuccessor"),
    ):
        identity = raw.get(field)
        if identity is None:
            continue
        if (
            not isinstance(identity, dict)
            or not isinstance(identity.get("releaseId"), str)
            or not identity["releaseId"]
            or not isinstance(identity.get("signedPayloadDigest"), str)
            or _DIGEST.fullmatch(identity["signedPayloadDigest"]) is None
        ):
            raise InstallerRefusal(
                "installation_record_invalid",
                f"updater status {field} identity is malformed",
            )
        identities.append(
            {
                "kind": kind,
                "releaseId": str(identity["releaseId"]),
                "signedPayloadDigest": str(identity["signedPayloadDigest"]),
            }
        )
    return identities


def _run_effect(runner: Runner, argv: Sequence[str], *, timeout: int, code: str) -> Completed:
    """Run one effect; an executor-level OSError becomes the typed step refusal."""

    try:
        return runner.run(argv, timeout=timeout)
    except OSError as exc:
        raise InstallerRefusal(
            code, f"{' '.join(str(part) for part in argv[:3])} failed to execute: {exc}"
        ) from exc


def _load_installation_record(state_root: Path, *, missing_code: str) -> dict[str, Any]:
    """Load the durable install trust record; never guess an installation."""

    if state_root.is_symlink():
        raise InstallerRefusal("state_root_unsafe", f"state root is a symlink: {state_root}")
    trust_path = state_root / "updater" / "trust" / "install-trust.json"
    if trust_path.is_symlink() or not trust_path.is_file():
        raise InstallerRefusal(
            missing_code,
            f"no StatePort installation record exists at {trust_path}; "
            "uninstall never guesses which resources belong to an installation",
        )
    record = _load_json(trust_path, "install trust record")
    if record.get("schema") != INSTALL_TRUST_SCHEMA:
        raise InstallerRefusal(
            missing_code, f"{trust_path} is not a StatePort install trust record"
        )
    signed = record.get("signedPayloadDigest")
    index_digest = record.get("releaseIndexDigest")
    if (
        not isinstance(signed, str)
        or _DIGEST.fullmatch(signed) is None
        or not isinstance(index_digest, str)
        or _DIGEST.fullmatch(index_digest) is None
        or not isinstance(record.get("releaseId"), str)
        or not isinstance(record.get("installedIdentityId"), str)
        or not record["installedIdentityId"]
    ):
        raise InstallerRefusal(
            "installation_record_invalid",
            f"install trust record at {trust_path} lacks the exact installation identity",
        )
    return record


def _load_staged_manifest(state_root: Path, signed_hex: str) -> dict[str, Any]:
    path = state_root / "releases" / "staged" / signed_hex / "materialization.json"
    return _load_manifest_at(path, signed_hex)


def _load_updater_staged_manifest(
    state_root: Path, signed_hex: str, *, required: bool
) -> dict[str, Any] | None:
    """The updater-retained staged manifest for an accepted (or staged) successor."""
    path = state_root / "updater" / "host-staged" / signed_hex / "materialization.json"
    if not required and (path.is_symlink() or not path.is_file()):
        return None
    return _load_manifest_at(path, signed_hex)


def _load_manifest_at(path: Path, signed_hex: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise InstallerRefusal(
            "installation_record_incomplete",
            f"the staged materialization manifest is missing at {path}; without it the "
            "exact installed unit set is unknowable and uninstall refuses closed",
        )
    manifest = _load_json(path, "staged materialization manifest")
    if (
        manifest.get("formatVersion") != "stateport.quadlet-materialization/v2"
        or manifest.get("signedPayloadDigest") != f"sha256:{signed_hex}"
        or not isinstance(manifest.get("artifacts"), list)
        or not isinstance(manifest.get("validationVolumeBindings"), dict)
    ):
        raise InstallerRefusal(
            "installation_record_incomplete",
            f"staged materialization manifest at {path} is not a complete v2 manifest",
        )
    return manifest


def _derive_removal_plan(
    state_root: Path,
    signed_hex: str,
    manifest: Mapping[str, Any],
    *,
    volume_hex: str | None = None,
    include_validation: bool = False,
) -> _RemovalPlan:
    """Derive the exact removal set from the installation's own durable records.

    Live unit file names come from the staged manifest's accepted artifacts;
    container names come from the ``ContainerName=`` line of the installation's
    own staged Quadlet definitions; genesis data volume names are re-derived
    from the recorded ``@@STATEPORT_ACCEPTED_DATA_VOLUME:*`` tokens with the
    same stdlib formula install used, and snapshot volume names come from the
    manifest's recorded validation volume bindings.

    ``volume_hex`` is the hex whose prefix names data volumes: installation-
    scoped volumes keep the GENESIS prefix across accepted updates, so updater
    manifests derive with the genesis hex, not their own.  ``include_validation``
    covers updater-staged manifests only: the updater writes validation units
    to the live root at stage time; the installer never does for genesis.
    """

    volume_hex = volume_hex or signed_hex
    profiles = {"accepted", "validation"} if include_validation else {"accepted"}
    stage_root = state_root / "releases" / "staged" / signed_hex
    updater_stage_root = state_root / "updater" / "host-staged" / signed_hex
    if not stage_root.is_dir():
        stage_root = updater_stage_root
    prefix = f"staged/{signed_hex}/"
    units: list[str] = []
    containers: list[str] = []
    quadlet_files: list[str] = []
    control_units: list[str] = []
    data_volume_keys: set[str] = set()
    for artifact in manifest["artifacts"]:
        if not isinstance(artifact, dict):
            raise InstallerRefusal(
                "installation_record_incomplete", "manifest artifact is not an object"
            )
        if artifact.get("profile") not in profiles or artifact.get("kind") not in {
            "container",
            "network",
        }:
            continue
        live_relative = artifact.get("liveRelativePath")
        staged_path = artifact.get("stagedPath")
        if (
            not isinstance(live_relative, str)
            or not isinstance(staged_path, str)
            or not staged_path.startswith(prefix)
            or PurePosixPath(live_relative).name != live_relative
            or not live_relative.endswith(f".{artifact['kind']}")
        ):
            raise InstallerRefusal(
                "installation_record_incomplete",
                "manifest artifact does not name an exact live unit file",
            )
        raw = _read_bounded(
            stage_root / PurePosixPath(staged_path[len(prefix) :]),
            description="staged quadlet artifact",
            maximum=1024 * 1024,
        )
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InstallerRefusal(
                "installation_record_incomplete",
                f"staged quadlet artifact is not UTF-8: {staged_path}",
            ) from exc
        if artifact["kind"] == "container":
            names = _CONTAINER_NAME.findall(text)
            if len(names) != 1:
                raise InstallerRefusal(
                    "installation_record_incomplete",
                    f"staged unit {staged_path} does not declare exactly one ContainerName",
                )
            containers.append(names[0])
            units.append(live_relative.removesuffix(".container"))
        if artifact.get("owner") == "stateport-control":
            control_units.append(live_relative.removesuffix(".container"))
        data_volume_keys.update(_ACCEPTED_VOLUME_TOKEN.findall(text))
        quadlet_files.append(live_relative)
    snapshot_volumes: list[str] = []
    for key, name in sorted(manifest["validationVolumeBindings"].items()):
        if not isinstance(key, str) or not isinstance(name, str) or not name:
            raise InstallerRefusal(
                "installation_record_incomplete",
                "validation volume binding is not an exact name pair",
            )
        snapshot_volumes.append(name)
    return _RemovalPlan(
        units=tuple(sorted(units)),
        containers=tuple(sorted(containers)),
        quadlet_files=tuple(sorted(quadlet_files)),
        activation_target=ACCEPTED_ACTIVATION_TARGET,
        data_volumes=tuple(sorted(_volume_names(volume_hex, key)[0] for key in data_volume_keys)),
        snapshot_volumes=tuple(snapshot_volumes),
        control_units=tuple(sorted(control_units)),
    )


def _stop_and_disable_units(
    runner: Runner, units: Sequence[str], *, control_units: Sequence[str] = ()
) -> tuple[list[str], list[str]]:
    """Stop and disable exactly the recorded units; absent ones are convergence.

    Control-plane units run under the ``stateport-control`` user's systemd
    manager; their stop/disable routes through that manager.
    """

    control_set = frozenset(control_units)
    stopped: list[str] = []
    disabled: list[str] = []
    for unit in sorted(units):
        base_argv: tuple[str, ...] = ("systemctl", "--user")
        if unit in control_set:
            base_argv = (
                "runuser",
                "-u",
                "stateport-control",
                "--",
                "systemctl",
                "--user",
            )
        active = _run_effect(
            runner,
            [*base_argv, "is-active", unit],
            timeout=60,
            code="unit_stop_failed",
        )
        if active.returncode == 0:
            completed = _run_effect(
                runner,
                [*base_argv, "stop", unit],
                timeout=900,
                code="unit_stop_failed",
            )
            if completed.returncode != 0:
                raise InstallerRefusal(
                    "unit_stop_failed",
                    f"systemctl --user stop {unit}: {completed.stderr.strip()[:200]}",
                )
            stopped.append(unit)
        enabled = _run_effect(
            runner,
            [*base_argv, "is-enabled", unit],
            timeout=60,
            code="unit_disable_failed",
        )
        if enabled.returncode == 0:
            completed = _run_effect(
                runner,
                [*base_argv, "disable", unit],
                timeout=120,
                code="unit_disable_failed",
            )
            if completed.returncode != 0:
                raise InstallerRefusal(
                    "unit_disable_failed",
                    f"systemctl --user disable {unit}: {completed.stderr.strip()[:200]}",
                )
            disabled.append(unit)
    return stopped, disabled


def _remove_containers(runner: Runner, names: Sequence[str]) -> list[str]:
    """Remove exactly the recorded containers; absent ones are convergence."""

    removed: list[str] = []
    for name in sorted(names):
        exists = _run_effect(
            runner,
            ["podman", "container", "exists", name],
            timeout=60,
            code="container_remove_failed",
        )
        if exists.returncode != 0:
            continue
        completed = _run_effect(
            runner, ["podman", "rm", "-f", name], timeout=300, code="container_remove_failed"
        )
        if completed.returncode != 0:
            raise InstallerRefusal(
                "container_remove_failed",
                f"podman rm -f {name}: {completed.stderr.strip()[:200]}",
            )
        removed.append(name)
    return removed


def _remove_live_quadlet_files(live_root: Path, names: Sequence[str]) -> list[str]:
    """Delete exactly the recorded live unit files; absent ones are convergence."""

    removed: list[str] = []
    for name in sorted(names):
        path = live_root / name
        if path.is_symlink():
            raise InstallerRefusal("live_unit_unsafe", f"live quadlet path is a symlink: {path}")
        if not path.exists():
            continue
        if not path.is_file():
            raise InstallerRefusal(
                "live_unit_unsafe", f"live quadlet path is not a regular file: {path}"
            )
        path.unlink()
        removed.append(name)
    return removed


def _remove_activation_target(
    config: UninstallConfig, *, identities: Sequence[Mapping[str, Any]]
) -> bool:
    root = config.systemd_user_root
    if root is None:
        if config.live_quadlet_root.name == "systemd" and config.live_quadlet_root.parent.name == "containers":
            root = config.live_quadlet_root.parent.parent / "systemd" / "user"
        else:
            root = config.live_quadlet_root.parent / "systemd" / "user"
    path = root / ACCEPTED_ACTIVATION_TARGET
    if not path.exists():
        return False
    if path.is_symlink() or not path.is_file():
        raise InstallerRefusal("activation_target_unsafe", f"activation target is not a regular file: {path}")
    content = _read_bounded(
        path, description="accepted activation target", maximum=MAX_INDEX_BYTES
    ).decode("utf-8")
    # The target binds the CURRENT accepted release: genesis before any update,
    # the accepted successor afterwards.  Any union identity proves ownership.
    bound = any(
        f"X-StatePort-Release-Id={identity['releaseId']}" in content
        and f"X-StatePort-Signed-Payload={identity['signedPayloadDigest']}" in content
        for identity in identities
    )
    if not bound or f"X-StatePort-Control-Identity={CONTROL_IDENTITY}" not in content:
        raise InstallerRefusal(
            "activation_target_conflict",
            "accepted activation target is not bound to the recorded installation",
        )
    path.unlink()
    return True


def _disable_activation_target(runner: Runner) -> bool:
    enabled = _run_effect(
        runner,
        ["systemctl", "--user", "is-enabled", ACCEPTED_ACTIVATION_TARGET],
        timeout=60,
        code="activation_target_disable_failed",
    )
    if enabled.returncode != 0:
        return False
    completed = _run_effect(
        runner,
        ["systemctl", "--user", "disable", ACCEPTED_ACTIVATION_TARGET],
        timeout=120,
        code="activation_target_disable_failed",
    )
    if completed.returncode != 0:
        raise InstallerRefusal(
            "activation_target_disable_failed",
            f"could not disable {ACCEPTED_ACTIVATION_TARGET}: {completed.stderr.strip()[:200]}",
        )
    return True


def _daemon_reload(runner: Runner) -> None:
    completed = _run_effect(
        runner, ["systemctl", "--user", "daemon-reload"], timeout=120, code="systemd_reload_failed"
    )
    if completed.returncode != 0:
        raise InstallerRefusal(
            "systemd_reload_failed", f"daemon-reload failed: {completed.stderr.strip()[:200]}"
        )


def _remove_volumes(runner: Runner, names: Sequence[str]) -> list[str]:
    """Remove exactly the recorded volumes; absent ones are convergence."""

    removed: list[str] = []
    for name in sorted(names):
        exists = _run_effect(
            runner, ["podman", "volume", "exists", name], timeout=60, code="volume_remove_failed"
        )
        if exists.returncode != 0:
            continue
        completed = _run_effect(
            runner, ["podman", "volume", "rm", name], timeout=120, code="volume_remove_failed"
        )
        if completed.returncode != 0:
            raise InstallerRefusal(
                "volume_remove_failed",
                f"podman volume rm {name}: {completed.stderr.strip()[:200]}",
            )
        removed.append(name)
    return removed


def _delete_state_root_contents(state_root: Path) -> list[str]:
    """Delete every child of the state root; never follow a symlink."""

    removed: list[str] = []
    for child in sorted(state_root.iterdir()):
        if child.is_symlink() or child.is_file():
            child.unlink()
        elif child.is_dir():
            shutil.rmtree(child)
        else:
            raise InstallerRefusal(
                "state_root_unsafe", f"refusing to remove non-regular state path: {child}"
            )
        removed.append(child.name)
    return removed


def _validate_uninstall_receipt(receipt: Mapping[str, Any]) -> None:
    """Inline stdlib field check for the self-describing uninstall receipt.

    The receipt is an internal durable record in the style of
    ``install-trust.json``: small, self-describing, and checked here rather
    than against a repository schema or the strict install-receipt schema.
    """

    def fail(message: str) -> None:
        raise InstallerRefusal("receipt_assembly_failed", f"uninstall receipt: {message}")

    if receipt.get("schema") != UNINSTALL_RECEIPT_SCHEMA:
        fail("schema is wrong")
    receipt_id = receipt.get("receiptId")
    if not isinstance(receipt_id, str) or not receipt_id.startswith("uninstall_receipt_"):
        fail("receiptId is malformed")
    if receipt.get("action") not in {"uninstall", "purge"}:
        fail("action is unknown")
    if not isinstance(receipt.get("actorId"), str) or not receipt["actorId"]:
        fail("actorId is missing")
    installation = receipt.get("installation")
    if not isinstance(installation, dict):
        fail("installation identity is missing")
    else:
        for field in ("releaseId", "installedIdentityId", "stateRoot", "liveQuadletRoot"):
            if not isinstance(installation.get(field), str) or not installation[field]:
                fail(f"installation.{field} is missing")
        for field in ("releaseIndexDigest", "signedPayloadDigest"):
            value = installation.get(field)
            if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
                fail(f"installation.{field} is not a sha256 digest")
    for section in ("removed", "preserved"):
        value = receipt.get(section)
        if not isinstance(value, dict):
            fail(f"{section} is missing")
            continue
        for key, entry in value.items():
            if not isinstance(entry, list) or any(not isinstance(item, str) for item in entry):
                fail(f"{section}.{key} is not a list of exact names")
    if receipt.get("result") not in {"succeeded", "already_uninstalled"}:
        fail("result is unknown")
    for field in ("startedAt", "finishedAt"):
        if not isinstance(receipt.get(field), str):
            fail(f"{field} is missing")


def uninstall(
    config: UninstallConfig,
    *,
    runner: Runner,
    clock: Callable[[], datetime],
) -> InstallOutcome:
    """Run the fail-closed uninstall/purge flow; every refusal is typed."""

    try:
        return _uninstall_inner(config, runner=runner, clock=clock, started=clock())
    except InstallerRefusal as refusal:
        refusal_path: Path | None = None
        if refusal.code not in _UNINSTALL_UNRECORDABLE_REFUSALS:
            refusal_path = _write_refusal(config.state_root, refusal.code, str(refusal), clock(), observations=getattr(refusal, "observations", None))
        return InstallOutcome(
            status="refused",
            code=refusal.code,
            message=str(refusal),
            receipt_path=refusal_path,
        )


def _uninstall_inner(
    config: UninstallConfig,
    *,
    runner: Runner,
    clock: Callable[[], datetime],
    started: datetime,
) -> InstallOutcome:
    if not config.state_root.is_absolute():
        raise InstallerRefusal("state_root_invalid", "the state root must be absolute")
    state_root = config.state_root
    missing_code = "state_root_not_stateport" if config.purge else "no_installation_found"
    record = _load_installation_record(state_root, missing_code=missing_code)
    if config.purge and config.confirm_purge != str(record["installedIdentityId"]):
        raise InstallerRefusal(
            "purge_confirmation_required",
            "--purge destroys all installation data and requires --confirm-purge naming the "
            "exact installed identity ID from updater/trust/install-trust.json",
        )
    signed_hex = str(record["signedPayloadDigest"]).removeprefix("sha256:")
    manifest = _load_staged_manifest(state_root, signed_hex)
    plans = [_derive_removal_plan(state_root, signed_hex, manifest)]
    # The removal plan is the UNION of the genesis install-trust record and
    # every release identity the updater status records: after an accepted
    # update the live runtime, activation target, and retained staged manifest
    # bind the successor, not the genesis record.
    identities = [
        {"kind": "genesis", "releaseId": str(record["releaseId"]),
         "signedPayloadDigest": str(record["signedPayloadDigest"])}
    ]
    for identity in _load_updater_accepted_identities(state_root):
        if identity["signedPayloadDigest"] == str(record["signedPayloadDigest"]):
            continue
        successor_hex = identity["signedPayloadDigest"].removeprefix("sha256:")
        successor_manifest = _load_updater_staged_manifest(
            state_root, successor_hex, required=identity["kind"] != "stagedSuccessor"
        )
        if successor_manifest is None:
            continue
        plans.append(
            _derive_removal_plan(
                state_root,
                successor_hex,
                successor_manifest,
                volume_hex=signed_hex,
                include_validation=True,
            )
        )
        identities.append(identity)
    plan = _union_removal_plans(plans)

    stopped, disabled = _stop_and_disable_units(
        runner, plan.units, control_units=plan.control_units
    )
    target_disabled = _disable_activation_target(runner)
    containers_removed = _remove_containers(runner, plan.containers)
    files_removed = _remove_live_quadlet_files(config.live_quadlet_root, plan.quadlet_files)
    target_removed = _remove_activation_target(config, identities=identities)
    _daemon_reload(runner)

    def build_receipt(
        *,
        action: str,
        result: str,
        volumes_removed: Sequence[str],
        state_contents: Sequence[str],
        preserved_volumes: Sequence[str],
        preserved_paths: Sequence[str],
    ) -> dict[str, Any]:
        return {
            "schema": UNINSTALL_RECEIPT_SCHEMA,
            "receiptId": f"uninstall_receipt_{secrets.token_hex(16)}",
            "action": action,
            "actorId": config.actor_id,
            "installation": {
                "releaseId": str(record["releaseId"]),
                "releaseIndexDigest": str(record["releaseIndexDigest"]),
                "signedPayloadDigest": str(record["signedPayloadDigest"]),
                "installedIdentityId": str(record["installedIdentityId"]),
                "stateRoot": str(state_root),
                "liveQuadletRoot": str(config.live_quadlet_root),
            },
            "removed": {
                "unitsStopped": list(stopped),
                "unitsDisabled": list(disabled),
                "containers": list(containers_removed),
                "quadletFiles": list(files_removed),
                "activationTargets": [plan.activation_target] if target_removed else [],
                "volumes": list(volumes_removed),
                "stateRootContents": list(state_contents),
            },
            "preserved": {
                "volumes": list(preserved_volumes),
                "paths": list(preserved_paths),
            },
            "startedAt": _timestamp(started),
            "finishedAt": _timestamp(clock()),
            "result": result,
        }

    if config.purge:
        volumes_removed = _remove_volumes(runner, (*plan.data_volumes, *plan.snapshot_volumes))
        receipt_path = state_root.parent / f"{state_root.name}.purge-receipt.json"
        state_contents = sorted(child.name for child in state_root.iterdir())
        receipt = build_receipt(
            action="purge",
            result="succeeded",
            volumes_removed=volumes_removed,
            state_contents=state_contents,
            preserved_volumes=[],
            preserved_paths=[str(receipt_path)],
        )
        _validate_uninstall_receipt(receipt)
        # The receipt is durable before any state root deletion begins.
        _write_json(receipt_path, receipt)
        _delete_state_root_contents(state_root)
        return InstallOutcome(
            status="succeeded",
            code="purged",
            message="runtime, genesis data volumes, and state root contents removed; the "
            "purge receipt survives beside the state root and no external side-effect "
            "reversal is claimed",
            receipt_path=receipt_path,
        )

    changed = bool(
        stopped
        or disabled
        or target_disabled
        or target_removed
        or containers_removed
        or files_removed
    )
    result = "succeeded" if changed else "already_uninstalled"
    receipt = build_receipt(
        action="uninstall",
        result=result,
        volumes_removed=[],
        state_contents=[],
        preserved_volumes=(*plan.data_volumes, *plan.snapshot_volumes),
        preserved_paths=[str(state_root), str(state_root / "updater-venv")],
    )
    _validate_uninstall_receipt(receipt)
    receipts_dir = _ensure_private_directory(state_root / "receipts")
    receipt_path = receipts_dir / f"{receipt['receiptId']}.json"
    _write_json(receipt_path, receipt)
    return InstallOutcome(
        status="succeeded",
        code="uninstalled" if changed else "already_uninstalled",
        message=(
            "runtime removed; all data volumes, the state root, and the updater venv "
            "are preserved and receipted"
            if changed
            else "the installation was already uninstalled; observed convergence receipted"
        ),
        receipt_path=receipt_path,
        converged=not changed,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _default_state_root() -> Path:
    base = os.environ.get("XDG_STATE_HOME")
    return (Path(base) if base else Path.home() / ".local" / "state") / "stateport"


def _default_quadlet_root() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME")
    return (Path(base) if base else Path.home() / ".config") / "containers" / "systemd"


def _tty_confirmer(summary: Mapping[str, Any]) -> bool:
    print("StatePort exact install plan:")
    print(json.dumps(summary, indent=2, sort_keys=True))
    if not sys.stdin.isatty():
        print("refusing without a TTY: pass --yes to confirm the exact plan", file=sys.stderr)
        return False
    answer = input("Install exactly this plan? [type 'install'] ")
    return answer.strip() == "install"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="install_no_checkout.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--uninstall",
        action="store_true",
        help="remove exactly the recorded runtime resources (units, containers, live "
        "quadlet files) and preserve all data volumes and durable state",
    )
    mode.add_argument(
        "--purge",
        action="store_true",
        help="uninstall plus destroy the recorded genesis data volumes and the state "
        "root contents; requires --confirm-purge",
    )
    mode.add_argument(
        "--verify-podman-package-bundle",
        action="store_true",
        help="authenticate and extract the exact signed Alpha.11 host packages without privileged mutation",
    )
    mode.add_argument(
        "--verify-sealed-podman-package-bundle",
        action="store_true",
        help="re-authenticate a root-owned package copy after full unprivileged release admission",
    )
    mode.add_argument(
        "--verify-installed-podman-packages",
        action="store_true",
        help="verify the installed package versions and selected Podman runtime against preflight evidence",
    )
    parser.add_argument(
        "--confirm-purge",
        default=None,
        metavar="INSTALLED-IDENTITY-ID",
        help="exact installed identity ID from updater/trust/install-trust.json; "
        "required together with --purge, refused in every other mode combination",
    )
    parser.add_argument(
        "--release-index",
        default=None,
        help="install mode only: signed release-index.json (local path or https URL; "
        "a URL requires --release-index-sha256 and no download is ever used before "
        "its digest verifies)",
    )
    parser.add_argument(
        "--release-index-sha256",
        default=None,
        help="published SHA-256 of the release index; mandatory for https downloads",
    )
    parser.add_argument(
        "--bundle-root",
        type=Path,
        default=None,
        help="install mode only: directory with the retained .sigstore.json bundles",
    )
    parser.add_argument("--trust-public-key", type=Path, default=None)
    parser.add_argument("--trust-key-id", default=None)
    parser.add_argument(
        "--trust-key-fingerprint",
        default=None,
        help="sha256:... DER SubjectPublicKeyInfo fingerprint of the trust key",
    )
    parser.add_argument("--updater-wheel", default=None, help="local path or https URL")
    parser.add_argument(
        "--execution-host-provisioner", default=None, help="local path or https URL"
    )
    parser.add_argument("--compose", default=None, help="local path or https URL")
    parser.add_argument("--source-archive", default=None, help="local path or https URL")
    parser.add_argument("--release-notes", default=None, help="local path or https URL")
    parser.add_argument("--known-limitations", default=None, help="local path or https URL")
    parser.add_argument(
        "--podman-package-bundle", default=None, help="local path or https URL"
    )
    parser.add_argument(
        "--podman-package-output",
        type=Path,
        default=None,
        help="preflight mode only: absent directory that receives verified package bytes",
    )
    parser.add_argument(
        "--podman-package-preflight",
        type=Path,
        default=None,
        help="package install/verification: authenticated JSON emitted before package mutation",
    )
    parser.add_argument(
        "--confirmed-package-plan-digest",
        help="exact authenticated package-plan digest confirmed before package mutation",
    )
    parser.add_argument("--channel", default=None, choices=_CHANNELS)
    parser.add_argument(
        "--cosign",
        type=Path,
        default=None,
        help="install mode only: pinned Cosign executable; required, never downloaded implicitly",
    )
    parser.add_argument("--state-root", type=Path, default=_default_state_root())
    parser.add_argument("--live-quadlet-root", type=Path, default=_default_quadlet_root())
    parser.add_argument(
        "--systemd-user-root",
        type=Path,
        default=None,
        help="install mode only: regular systemd user-unit root for accepted reboot activation",
    )
    parser.add_argument(
        "--execution-host-receipt",
        type=Path,
        default=None,
        help="install mode only: exact root-helper provisioning receipt for the stable execution host",
    )
    parser.add_argument("--actor-id", default=f"local-owner-{os.environ.get('USER', 'unknown')}")
    parser.add_argument(
        "--installer-path",
        type=Path,
        default=None,
        help="path of the exact installer artifact to self-verify (defaults to this script)",
    )
    parser.add_argument(
        "--yes", action="store_true", help="confirm the exact install plan non-interactively"
    )
    parser.add_argument(
        "--confirmed-plan-digest",
        help="exact sha256 plan digest displayed by a preceding prepare pass",
    )
    parser.add_argument(
        "--prepare-execution-host",
        action="store_true",
        help="verify the release and host, stage exact inputs, and emit the signed root-helper plan without installing services",
    )
    parser.add_argument("--health-timeout-seconds", type=float, default=600.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    install_flags: dict[str, object] = {
        "--release-index": args.release_index,
        "--bundle-root": args.bundle_root,
        "--trust-public-key": args.trust_public_key,
        "--trust-key-id": args.trust_key_id,
        "--trust-key-fingerprint": args.trust_key_fingerprint,
        "--updater-wheel": args.updater_wheel,
        "--execution-host-provisioner": args.execution_host_provisioner,
        "--compose": args.compose,
        "--source-archive": args.source_archive,
        "--release-notes": args.release_notes,
        "--known-limitations": args.known_limitations,
        "--podman-package-bundle": args.podman_package_bundle,
        "--confirmed-package-plan-digest": args.confirmed_package_plan_digest,
        "--channel": args.channel,
        "--cosign": args.cosign,
        "--confirmed-plan-digest": args.confirmed_plan_digest,
    }
    runner = SubprocessRunner()
    if args.verify_installed_podman_packages:
        if args.podman_package_preflight is None:
            parser.error("installed-package verification requires --podman-package-preflight")
        forbidden = [flag for flag, value in install_flags.items() if value is not None]
        if args.podman_package_output is not None:
            forbidden.append("--podman-package-output")
        if forbidden:
            parser.error(
                "installed-package verification refuses unrelated arguments: "
                + ", ".join(forbidden)
            )
        try:
            preflight = _load_json(args.podman_package_preflight, "Podman package preflight")
            result = verify_installed_podman_packages(preflight, runner=runner)
        except InstallerRefusal as refusal:
            print(
                f"installed-package verification refused ({refusal.code}): {refusal}",
                file=sys.stderr,
            )
            return 2
        print(json.dumps(result, sort_keys=True))
        return 0
    if args.verify_sealed_podman_package_bundle:
        required = {
            "--release-index": args.release_index,
            "--bundle-root": args.bundle_root,
            "--trust-public-key": args.trust_public_key,
            "--trust-key-id": args.trust_key_id,
            "--trust-key-fingerprint": args.trust_key_fingerprint,
            "--cosign": args.cosign,
            "--installer-path": args.installer_path,
            "--podman-package-bundle": args.podman_package_bundle,
            "--podman-package-output": args.podman_package_output,
        }
        missing = [flag for flag, value in required.items() if value is None]
        if missing:
            parser.error("sealed package verification requires: " + ", ".join(missing))
        forbidden = {
            "--updater-wheel": args.updater_wheel,
            "--execution-host-provisioner": args.execution_host_provisioner,
            "--compose": args.compose,
            "--source-archive": args.source_archive,
            "--release-notes": args.release_notes,
            "--known-limitations": args.known_limitations,
            "--channel": args.channel,
            "--podman-package-preflight": args.podman_package_preflight,
            "--confirmed-plan-digest": args.confirmed_plan_digest,
            "--confirmed-package-plan-digest": args.confirmed_package_plan_digest,
        }
        supplied = [flag for flag, value in forbidden.items() if value is not None]
        if supplied:
            parser.error(
                "sealed package verification refuses unrelated arguments: "
                + ", ".join(supplied)
            )
        try:
            result = verify_podman_package_bundle(
                PackageBundlePreflightConfig(
                    release_index=Path(str(args.release_index)),
                    bundle_root=args.bundle_root,
                    trust_public_key=args.trust_public_key,
                    trust_key_id=args.trust_key_id,
                    trust_key_fingerprint=args.trust_key_fingerprint,
                    cosign=args.cosign,
                    installer_path=args.installer_path,
                    podman_package_bundle=Path(str(args.podman_package_bundle)),
                    output_dir=args.podman_package_output,
                ),
                runner=runner,
            )
        except InstallerRefusal as refusal:
            print(f"sealed package verification refused ({refusal.code}): {refusal}", file=sys.stderr)
            return 2
        print(json.dumps(result, sort_keys=True))
        return 0
    if args.verify_podman_package_bundle:
        required = {
            "--release-index": args.release_index,
            "--bundle-root": args.bundle_root,
            "--trust-public-key": args.trust_public_key,
            "--trust-key-id": args.trust_key_id,
            "--trust-key-fingerprint": args.trust_key_fingerprint,
            "--cosign": args.cosign,
            "--installer-path": args.installer_path,
            "--updater-wheel": args.updater_wheel,
            "--execution-host-provisioner": args.execution_host_provisioner,
            "--compose": args.compose,
            "--source-archive": args.source_archive,
            "--release-notes": args.release_notes,
            "--known-limitations": args.known_limitations,
            "--channel": args.channel,
            "--podman-package-bundle": args.podman_package_bundle,
            "--podman-package-output": args.podman_package_output,
        }
        missing = [flag for flag, value in required.items() if value is None]
        if missing:
            parser.error("package preflight requires: " + ", ".join(missing))
        forbidden = {
            "--podman-package-preflight": args.podman_package_preflight,
            "--confirmed-package-plan-digest": args.confirmed_package_plan_digest,
        }
        supplied = [flag for flag, value in forbidden.items() if value is not None]
        if supplied:
            parser.error(
                "package preflight refuses unrelated install arguments: "
                + ", ".join(supplied)
            )
        try:
            admission_config = InstallConfig(
                release_index=str(args.release_index),
                release_index_sha256=args.release_index_sha256,
                bundle_root=args.bundle_root,
                trust_public_key=args.trust_public_key,
                trust_key_id=args.trust_key_id,
                trust_key_fingerprint=args.trust_key_fingerprint,
                updater_wheel=args.updater_wheel,
                channel=args.channel,
                cosign=args.cosign,
                state_root=args.state_root,
                live_quadlet_root=args.live_quadlet_root,
                actor_id=args.actor_id,
                installer_path=args.installer_path,
                execution_host_provisioner=args.execution_host_provisioner,
                compose=args.compose,
                source_archive=args.source_archive,
                release_notes=args.release_notes,
                known_limitations=args.known_limitations,
                podman_package_bundle=args.podman_package_bundle,
                expected_target=WSL2_TARGET_ID,
            )

            def admission_verifier_factory(modules: VerifiedModules) -> Any:
                return modules.release.CosignVerifier(
                    cosign=admission_config.cosign,
                    public_key=admission_config.trust_public_key,
                    identity=modules.release.PinnedPublicKeyIdentity(
                        admission_config.trust_key_fingerprint,
                        admission_config.trust_key_id,
                    ),
                    bundle_root=admission_config.bundle_root,
                )

            admission = verify_release_admission(
                admission_config,
                runner=runner,
                fetcher=UrllibFetcher(),
                verifier_factory=admission_verifier_factory,
                clock=lambda: datetime.now(timezone.utc),
            )
            package_result = verify_podman_package_bundle(
                PackageBundlePreflightConfig(
                    release_index=Path(str(args.release_index)),
                    bundle_root=args.bundle_root,
                    trust_public_key=args.trust_public_key,
                    trust_key_id=args.trust_key_id,
                    trust_key_fingerprint=args.trust_key_fingerprint,
                    cosign=args.cosign,
                    installer_path=args.installer_path,
                    podman_package_bundle=Path(str(args.podman_package_bundle)),
                    output_dir=args.podman_package_output,
                ),
                runner=runner,
            )
            result = {**package_result, "releaseAdmission": admission}
        except InstallerRefusal as refusal:
            print(f"package preflight refused ({refusal.code}): {refusal}", file=sys.stderr)
            return 2
        print(json.dumps(result, sort_keys=True))
        return 0
    if args.uninstall or args.purge:
        provided = [flag for flag, value in install_flags.items() if value is not None]
        if args.podman_package_output is not None:
            provided.append("--podman-package-output")
        if args.podman_package_preflight is not None:
            provided.append("--podman-package-preflight")
        if provided:
            parser.error(
                "--uninstall/--purge are mutually exclusive with install arguments: "
                + ", ".join(provided)
            )
        if args.confirm_purge is not None and not args.purge:
            parser.error("--confirm-purge is only meaningful together with --purge")
        outcome = uninstall(
            UninstallConfig(
                state_root=args.state_root,
                live_quadlet_root=args.live_quadlet_root,
                actor_id=args.actor_id,
                systemd_user_root=args.systemd_user_root,
                purge=bool(args.purge),
                confirm_purge=args.confirm_purge,
            ),
            runner=runner,
            clock=lambda: datetime.now(timezone.utc),
        )
        mode_name = "purge" if args.purge else "uninstall"
        if outcome.status == "succeeded":
            print(f"StatePort {mode_name} completed: {outcome.message}")
            if outcome.receipt_path is not None:
                print(f"receipt: {outcome.receipt_path}")
            return 0
        print(f"{mode_name} refused ({outcome.code}): {outcome.message}", file=sys.stderr)
        if outcome.receipt_path is not None:
            print(f"refusal record: {outcome.receipt_path}", file=sys.stderr)
        return 2
    if args.podman_package_output is not None:
        parser.error("--podman-package-output is only meaningful in package preflight mode")
    if (args.podman_package_preflight is None) != (args.confirmed_package_plan_digest is None):
        parser.error(
            "--podman-package-preflight and --confirmed-package-plan-digest must be supplied together"
        )
    # The --prepare-execution-host mode writes the signed execution-host plan
    # and returns before the confirmed install transaction, so it must not
    # require the final --confirmed-plan-digest (which the bootstrap only has
    # after the prepare step produces the plan).  Requiring it here made the
    # prepare call fail argparse validation before it could ever prepare.
    plan_digest_required = not bool(args.prepare_execution_host)
    missing = [
        flag
        for flag, value in install_flags.items()
        if value is None
        and flag != "--podman-package-bundle"
        and (flag != "--confirmed-plan-digest" or plan_digest_required)
    ]
    if missing:
        parser.error("install mode requires: " + ", ".join(missing))
    config = InstallConfig(
        release_index=args.release_index,
        release_index_sha256=args.release_index_sha256,
        bundle_root=args.bundle_root,
        trust_public_key=args.trust_public_key,
        trust_key_id=args.trust_key_id,
        trust_key_fingerprint=args.trust_key_fingerprint,
        updater_wheel=args.updater_wheel,
        channel=args.channel,
        cosign=args.cosign,
        state_root=args.state_root,
        live_quadlet_root=args.live_quadlet_root,
        actor_id=args.actor_id,
        systemd_user_root=args.systemd_user_root,
        execution_host_receipt=(
            args.execution_host_receipt
            or Path("/var/lib/stateport-provisioning/receipts/execution-host-provisioning-receipt.json")
        ),
        installer_path=args.installer_path,
        execution_host_provisioner=args.execution_host_provisioner,
        compose=args.compose,
        source_archive=args.source_archive,
        release_notes=args.release_notes,
        known_limitations=args.known_limitations,
        podman_package_bundle=args.podman_package_bundle,
        podman_package_preflight=args.podman_package_preflight,
        confirmed_package_plan_digest=args.confirmed_package_plan_digest,
        assume_yes=args.yes,
        confirmed_plan_digest=args.confirmed_plan_digest,
        prepare_execution_host=args.prepare_execution_host,
        health_timeout_seconds=args.health_timeout_seconds,
    )

    def cosign_factory(modules: VerifiedModules) -> Any:
        return modules.release.CosignVerifier(
            cosign=config.cosign,
            public_key=config.trust_public_key,
            identity=modules.release.PinnedPublicKeyIdentity(
                config.trust_key_fingerprint, config.trust_key_id
            ),
            bundle_root=config.state_root / "updater" / "bundles",
        )

    outcome = install(
        config,
        runner=runner,
        probe=SystemHostProbe(runner),
        fetcher=UrllibFetcher(),
        module_loader=load_modules_from_venv,
        verifier_factory=cosign_factory,
        clock=lambda: datetime.now(timezone.utc),
        confirmer=_tty_confirmer,
    )
    if outcome.status == "succeeded":
        print("StatePort is installed and healthy.")
        print(f"  Open StatePort at: {outcome.local_url}")
        print(f"  install receipt: {outcome.receipt_path}")
        if outcome.execution_host is not None:
            print("execution host: provisioned and protocol-healthy; installer did not escalate")
            print(f"  plan: {outcome.execution_host['planPath']}")
            print(f"  provision through root helper: {outcome.execution_host['provisionCommand']}")
        return 0
    if outcome.status == "prepared":
        print(f"StatePort preparation completed: {outcome.message}")
        if outcome.execution_host is not None:
            print(f"plan: {outcome.execution_host['planPath']}")
            print(f"materialize: {outcome.execution_host['materializeCommand']}")
            print(f"provision: {outcome.execution_host['provisionCommand']}")
        return 0
    print(f"install refused ({outcome.code}): {outcome.message}", file=sys.stderr)
    if outcome.receipt_path is not None:
        print(f"refusal record: {outcome.receipt_path}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
