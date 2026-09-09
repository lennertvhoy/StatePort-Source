"""Production UpdateHost driver for rootless Podman and the installer layout.

This module is the shipped execution-host driver behind the installed
control-plane seam.  It implements the bounded :class:`UpdateHost` protocol
against rootless Podman, the systemd user manager, and the exact
installer-managed layout: an owner-private live Quadlet root
(``$XDG_CONFIG_HOME/containers/systemd``), genesis-derived installation data
volumes, and deterministic revision-derived loopback ports.

Runtime model (mirrors the no-checkout installer):

- ``stage`` materializes the verified successor Quadlet bundle under the
  owner-private updater state root and installs the successor *validation*
  units into the live Quadlet root as parallel units that are reloaded but
  never started.  Validation units mount fresh per-plan read-only snapshot
  copies of the installation data volumes; accepted data volumes are never
  recreated.
- ``backup`` quiesces the accepted route (stops the current accepted units),
  exports each snapshot-required data volume into a fresh per-plan snapshot
  volume, restarts the accepted route, and verifies it active again.  The
  resulting ``stateport.revision-validation-backup-receipt/v1`` is what makes
  the ``quiesced`` consistency claim true; the driver never claims quiescence
  it did not enforce.
- ``start-successor`` starts only the validation units.  Health, browser,
  studystate, and state gates are HTTP/systemd-level checks against the
  staged validation loopback ports; they are not browser-automation
  journeys.  Their result digests bind the exact check identity (check kind,
  release, runtime digest, probed services).  A gate probes live on its
  first execution; on re-execution it converges to its durable effect
  receipt, because the switch intentionally stops the validation units it
  once probed.
- ``dry-run-migrations`` is honest about what the alpha runtime does:
  services self-migrate their data on startup.  The dry run verifies the
  typed preconditions on durable state — the staged context exists, the
  successor's declared migration versions are monotonic against the current
  release, and the signed compatibility declares data-compatible rollback —
  and reports the successor's declared versions.  It does not fabricate a
  migration execution.
- ``switch`` creates any successor-introduced data volumes (never
  recreating existing ones), installs the successor accepted units with the
  exact genesis-derived data volume names, stops the predecessor accepted
  units, starts the successor accepted units, and stops the validation
  units.  The accepted data volumes are shared by exactly one running
  profile at a time.
- ``rollback_failed_switch`` restarts the exact predecessor accepted units.
  ``discard_successor`` removes the successor's runtime units while
  retaining the create-only effect receipts as evidence.
  ``enforce_retention`` removes staged trees, per-plan snapshot volumes, and
  unit files of releases outside the retained inventory; retained
  predecessors keep their (stopped) accepted units so the rollback path
  stays available.

Port derivations depend on the collision inventory observed at stage time,
so a unit file left behind by an earlier plan for the *same* exact release
(same signed revision, different plan) may differ only in volatile
derivations (ports, per-plan snapshot volume names).  Such a file is
replaced atomically — but only when its signed release labels bind the exact
successor and the unit is not running.  A file binding any other release is
a hard conflict.

Every effectful step is idempotent for the exact plan digest and persists a
durable create-only effect receipt under
``updater/host-effects/<planDigestHex>/<step>.json`` before returning.  The
engine re-reads those receipts after every step and during crash
reconciliation, so an interrupted effect is never blindly replayed: a step
with a durable receipt converges to its recorded evidence, and a step
without one is reconstructed only through the explicit idempotent operation.
Evidence returned to the engine stays inside its bounded-evidence contract:
no host paths, no secrets, deterministic values.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import time
from typing import Any, Callable, Mapping, Protocol, Sequence
import urllib.error
import urllib.request

from stateport_release import (
    ReleaseContractError,
    canonical_digest,
    image_set_digest,
    load_release_index,
    materialize_verified_quadlet_bundle,
    revision_volume_key,
    revision_contract_digest,
    service_set_digest,
)

from .engine import (
    DIGEST,
    SUPPORTED_TARGET_IDS,
    TARGET_ID,
    UPDATER_VERSION,
    UpdateHostError,
)
from .models import version_key
from stateport_release.contract import PROVIDER_HOME_CONTRACT
from .safe_io import (
    SafeIOError,
    create_bytes,
    create_json,
    ensure_private_directory,
    read_bytes,
    read_json,
    replace_json,
    unlink_regular,
)


EFFECT_RECEIPT_SCHEMA = "stateport.update-host-effect-receipt/v1"
CONTEXT_SCHEMA = "stateport.internal-update-host-context/v1"
MARKER_SCHEMA = "stateport.internal-update-host-marker/v1"
BACKUP_EVIDENCE_FORMAT = "stateport.update-backup-evidence/v1"
BACKUP_RECEIPT_SCHEMA = "stateport.revision-validation-backup-receipt/v1"
HOST_IDENTITY_FORMAT = "stateport.update-host-identity/v1"
ACCEPTED_ACTIVATION_TARGET = "stateport-accepted.target"
CONTROL_IDENTITY = "stateport-control"
RELEASE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")
STEP_NAME = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
UNIT_FILE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
PUBLISH_PORT = re.compile(r"^PublishPort=127\.0\.0\.1:(\d+):(\d+)$", re.MULTILINE)
CONTAINER_LABEL = re.compile(
    r"^Label=io\.stateport\.(release\.id|release\.signed-payload)=(\S+)$", re.MULTILINE
)
MAX_UNIT_FILES = 64
MAX_UNIT_BYTES = 64 * 1024


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
    """Loopback-only HTTP probe seam for health and journey gates."""

    def fetch(self, url: str, *, timeout: float, max_bytes: int) -> FetchResult: ...


class UrllibFetcher:
    def fetch(self, url: str, *, timeout: float, max_bytes: int) -> FetchResult:
        if not url.startswith("http://127.0.0.1:"):
            raise UpdateHostError(
                "host_fetch_refused",
                "only loopback HTTP probes are allowed",
                effect="unknown",
            )
        request = urllib.request.Request(url, headers={"User-Agent": "stateport-updater"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read(max_bytes + 1)
                status = int(response.status)
        except urllib.error.HTTPError as exc:
            return FetchResult(int(exc.code), b"")
        except (urllib.error.URLError, OSError):
            # A refused or reset connection is a normal not-yet-healthy probe.
            return FetchResult(0, b"")
        if len(body) > max_bytes:
            return FetchResult(0, b"")
        return FetchResult(status, body)


def _timestamp(clock: Callable[[], datetime]) -> str:
    value = clock().astimezone(timezone.utc).replace(microsecond=0)
    return value.isoformat().replace("+00:00", "Z")


def _default_quadlet_root() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME")
    return (Path(base) if base else Path.home() / ".config") / "containers" / "systemd"


def _service_name_id(service_id: str) -> str:
    return canonical_digest({"serviceId": service_id}).removeprefix("sha256:")[:12]


def _signed_target(index: Any, target_id: str = TARGET_ID) -> Mapping[str, Any]:
    targets = [
        target
        for target in index.document["signed"]["targets"]
        if target.get("targetId") == target_id
    ]
    if len(targets) != 1:
        raise UpdateHostError(
            "host_release_invalid",
            "release does not carry exactly one updater target",
            effect="unknown",
        )
    return targets[0]


def _installation_volume_keys(
    target: Mapping[str, Any], *, snapshot_required: bool = False
) -> list[str]:
    return sorted(
        {
            revision_volume_key(target, str(service["serviceId"]), str(volume["name"]))
            for service in target["services"]
            for volume in service["writableVolumes"]
            if volume["scope"] == "installation"
            and (
                not snapshot_required
                or volume["validation"]["mode"] == "read-only-snapshot-copy"
            )
        }
    )


def _require_provisioned_provider_home(target: Mapping[str, Any]) -> None:
    """Observe only directory metadata; provider-owned files are never opened."""
    homes = [service.get("providerHome") for service in target["services"] if "providerHome" in service]
    if not homes:
        return
    if homes != [PROVIDER_HOME_CONTRACT]:
        raise UpdateHostError("provider_home_provisioning_required", "successor provider home is not the supported signed contract", effect="not_applied")
    descriptors: list[int] = []
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        descriptors.append(os.open("/", flags))
        for component in Path(PROVIDER_HOME_CONTRACT["hostPath"]).parts[1:]:
            descriptors.append(os.open(component, flags, dir_fd=descriptors[-1]))
            if component in {"stateport-control", "provider-auth", "codex"}:
                info = os.fstat(descriptors[-1])
                if info.st_uid != 65531 or info.st_gid != 65531:
                    raise OSError("provider directory ownership differs")
                if component != "stateport-control" and stat.S_IMODE(info.st_mode) != 0o700:
                    raise OSError("provider directory mode differs")
    except PermissionError as exc:
        raise UpdateHostError(
            "provider_home_updater_identity_unavailable",
            "the installed updater identity cannot inspect the control account's private provider directory; installed upgrade is blocked by the updater/control-account identity boundary. Re-running provisioning does not resolve this refusal. No supported account handoff is available here; do not change directory permissions or copy authentication files.",
            effect="not_applied",
        ) from exc
    except OSError as exc:
        raise UpdateHostError(
            "provider_home_provisioning_required",
            "successor requires its fixed private Codex home; run the signature-verified StatePort provisioner for this successor before retrying. The updater will not create or take over provider authentication directories.",
            effect="not_applied",
        ) from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _revision_hex(
    index: Any,
    service: Mapping[str, Any],
    image: Mapping[str, Any],
    profile: str,
    target_id: str = TARGET_ID,
) -> str:
    target = _signed_target(index, target_id)
    return canonical_digest(
        {
            "formatVersion": "stateport.full-revision-identity/v1",
            "releaseId": index.release_id,
            "signedPayloadDigest": index.signed_digest,
            "targetId": target["targetId"],
            "topologyDigest": target["topologyDigest"],
            "serviceId": service["serviceId"],
            "imageDigest": image["digest"],
            "profile": profile,
        }
    ).removeprefix("sha256:")


def _network_hex(
    index: Any, owner: str, profile: str, target_id: str = TARGET_ID
) -> str:
    target = _signed_target(index, target_id)
    return canonical_digest(
        {
            "formatVersion": "stateport.revision-network/v1",
            "signedPayloadDigest": index.signed_digest,
            "targetId": target["targetId"],
            "owner": owner,
            "profile": profile,
        }
    ).removeprefix("sha256:")


def _expected_revision_digest(index: Any, target_id: str = TARGET_ID) -> str:
    """Recompute the engine's runtime revision identity from durable release bytes."""

    signed = index.document["signed"]
    target = _signed_target(index, target_id)
    image_by_id = {str(image["imageId"]): image for image in signed["images"]}
    observed_services = [
        {
            "serviceId": str(service["serviceId"]),
            "imageId": str(service["imageId"]),
            "imageDigest": str(image_by_id[str(service["imageId"])]["digest"]),
        }
        for service in target["services"]
    ]
    return canonical_digest(
        {
            "schema": "stateport.runtime-revision-identity/v1",
            "profile": "installed-control-plane",
            "targetId": str(target["targetId"]),
            "releaseIndexDigest": index.index_digest,
            "signedPayloadDigest": index.signed_digest,
            "topologyDigest": str(target["topologyDigest"]),
            "quadletBundleDigest": str(target["quadletBundleDigest"]),
            "imageSetDigest": image_set_digest(signed["images"]),
            "serviceSetDigest": service_set_digest(observed_services),
        }
    )


def _container_units(
    index: Any, profile: str, target_id: str = TARGET_ID
) -> dict[str, str]:
    """Map service id to its deterministic quadlet container unit base name."""

    target = _signed_target(index, target_id)
    image_by_id = {str(image["imageId"]): image for image in index.document["signed"]["images"]}
    units: dict[str, str] = {}
    for service in target["services"]:
        service_id = str(service["serviceId"])
        revision = _revision_hex(
            index, service, image_by_id[str(service["imageId"])], profile, target_id
        )
        units[service_id] = f"stateport-{_service_name_id(service_id)}-{profile}-{revision}"
    return units


def _network_units(
    index: Any, profile: str, target_id: str = TARGET_ID
) -> list[str]:
    target = _signed_target(index, target_id)
    owners = sorted({str(service["quadletOwner"]) for service in target["services"]})
    return [
        f"stateport-{_network_hex(index, owner, profile, target_id)}"
        for owner in owners
    ]


def _volume_key_hash(volume_key: str) -> str:
    return hashlib.sha256(volume_key.encode("utf-8")).hexdigest()[:12]


def _data_volume_name(genesis_hex: str, volume_key: str) -> str:
    return f"stateport-g{genesis_hex[:12]}-{_volume_key_hash(volume_key)}"


def _snapshot_volume_name(genesis_hex: str, volume_key: str, plan_digest: str) -> str:
    plan_hex = plan_digest.removeprefix("sha256:")
    return f"stateport-s{genesis_hex[:12]}-{_volume_key_hash(volume_key)}-{plan_hex[:8]}"


def _unit_release_binding(text: str) -> tuple[str, str] | None:
    labels = dict((match.group(1), match.group(2)) for match in CONTAINER_LABEL.finditer(text))
    release_id = labels.get("release.id")
    signed_digest = labels.get("release.signed-payload")
    if not release_id or not signed_digest:
        return None
    return release_id, signed_digest


class LocalPodmanHost:
    """Bounded UpdateHost driver over rootless Podman and the installer layout."""

    def __init__(
        self,
        state_root: Path,
        *,
        runner: Runner | None = None,
        fetcher: Fetcher | None = None,
        clock: Callable[[], datetime] | None = None,
        quadlet_root: Path | None = None,
        podman: str = "podman",
        systemctl: str = "systemctl",
        health_timeout_seconds: float = 120.0,
        health_poll_seconds: float = 0.5,
        require_linger: bool = True,
        target_id: str = TARGET_ID,
    ) -> None:
        if not isinstance(health_timeout_seconds, (int, float)) or isinstance(
            health_timeout_seconds, bool
        ):
            raise ValueError("health timeout is invalid")
        self.root = Path(state_root)
        self.runner = runner or SubprocessRunner()
        self.fetcher = fetcher or UrllibFetcher()
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.quadlet_root = (
            Path(quadlet_root) if quadlet_root is not None else _default_quadlet_root()
        )
        self.podman = podman
        self.systemctl = systemctl
        self.health_timeout_seconds = float(health_timeout_seconds)
        self.health_poll_seconds = float(health_poll_seconds)
        self.require_linger = bool(require_linger)
        if target_id not in SUPPORTED_TARGET_IDS:
            raise ValueError("updater target is unsupported")
        self.target_id = target_id

    # ------------------------------------------------------------------
    # durable effect receipts (engine reconciliation contract)
    # ------------------------------------------------------------------

    def _effects_dir(self, plan_digest: str) -> Path:
        if DIGEST.fullmatch(plan_digest) is None:
            raise UpdateHostError("host_plan_invalid", "plan digest is invalid", effect="unknown")
        return self.root / "host-effects" / plan_digest.removeprefix("sha256:")

    def _receipt_path(self, plan_digest: str, step: str) -> Path:
        if STEP_NAME.fullmatch(step) is None:
            raise UpdateHostError("host_step_invalid", "plan step is invalid", effect="unknown")
        return self._effects_dir(plan_digest) / f"{step}.json"

    def observe_effect_receipt(self, *, plan_digest: str, step: str) -> Mapping[str, Any]:
        path = self._receipt_path(plan_digest, step)
        if not path.exists() and not path.is_symlink():
            raise UpdateHostError(
                "effect_receipt_missing",
                f"no durable host effect receipt for {step}",
                effect="unknown",
            )
        try:
            receipt = read_json(path, "host effect receipt")
        except SafeIOError as exc:
            raise UpdateHostError(
                "effect_receipt_invalid", "host effect receipt is unreadable", effect="unknown"
            ) from exc
        evidence = receipt.get("evidence")
        if (
            receipt.get("schema") != EFFECT_RECEIPT_SCHEMA
            or receipt.get("planDigest") != plan_digest
            or receipt.get("step") != step
            or receipt.get("status") != "observed"
            or not isinstance(evidence, dict)
            or receipt.get("evidenceDigest") != canonical_digest(evidence)
        ):
            raise UpdateHostError(
                "effect_receipt_invalid",
                f"host effect receipt for {step} does not bind its exact effect",
                effect="unknown",
            )
        return receipt

    def _record_effect(
        self,
        plan_digest: str,
        step: str,
        evidence: Mapping[str, Any],
    ) -> dict[str, Any]:
        evidence_digest = canonical_digest(evidence)
        seed = canonical_digest(
            {
                "planDigest": plan_digest,
                "step": step,
                "evidenceDigest": evidence_digest,
            }
        )
        receipt = {
            "schema": EFFECT_RECEIPT_SCHEMA,
            "receiptId": f"host_effect_receipt_{seed.removeprefix('sha256:')[:32]}",
            "planDigest": plan_digest,
            "step": step,
            "status": "observed",
            "evidence": deepcopy(dict(evidence)),
            "evidenceDigest": evidence_digest,
        }
        path = self._receipt_path(plan_digest, step)
        if path.exists() or path.is_symlink():
            existing = self.observe_effect_receipt(plan_digest=plan_digest, step=step)
            if dict(existing) != receipt:
                raise UpdateHostError(
                    "effect_receipt_conflict",
                    f"durable host effect receipt for {step} binds a different effect",
                    effect="unknown",
                )
            return deepcopy(dict(evidence))
        ensure_private_directory(path.parent)
        create_json(path, receipt, "host effect receipt")
        return deepcopy(dict(evidence))

    def _completed_evidence(self, plan_digest: str, step: str) -> dict[str, Any] | None:
        """Return the recorded evidence of a completed effectful step, if any."""

        path = self._receipt_path(plan_digest, step)
        if not path.exists() and not path.is_symlink():
            return None
        receipt = self.observe_effect_receipt(plan_digest=plan_digest, step=step)
        return deepcopy(dict(receipt["evidence"]))

    # ------------------------------------------------------------------
    # durable stage context and release binding
    # ------------------------------------------------------------------

    def _context_path(self, plan_digest: str) -> Path:
        return self._effects_dir(plan_digest) / "context.json"

    def _read_context(self, plan_digest: str) -> dict[str, Any] | None:
        path = self._context_path(plan_digest)
        if not path.exists() and not path.is_symlink():
            return None
        try:
            context = read_json(path, "host stage context")
        except SafeIOError as exc:
            raise UpdateHostError(
                "host_stage_context_missing",
                "host stage context is unreadable",
                effect="unknown",
            ) from exc
        if context.get("schema") != CONTEXT_SCHEMA or context.get("planDigest") != plan_digest:
            raise UpdateHostError(
                "host_stage_context_missing",
                "host stage context does not bind this exact plan",
                effect="unknown",
            )
        return context

    def _context(self, plan_digest: str) -> dict[str, Any]:
        context = self._read_context(plan_digest)
        if context is None:
            raise UpdateHostError(
                "host_stage_context_missing",
                "no durable staged successor exists for this plan",
                effect="unknown",
            )
        return context

    def _release_index(self, plan: Mapping[str, Any], role: str) -> Any:
        identity = plan.get(role)
        if not isinstance(identity, Mapping):
            raise UpdateHostError(
                "host_plan_invalid", f"update plan has no {role} identity", effect="unknown"
            )
        release_id = identity.get("releaseId")
        signed_digest = identity.get("signedPayloadDigest")
        if (
            not isinstance(release_id, str)
            or RELEASE_ID.fullmatch(release_id) is None
            or not isinstance(signed_digest, str)
            or DIGEST.fullmatch(signed_digest) is None
        ):
            raise UpdateHostError(
                "host_plan_invalid", f"update plan {role} identity is invalid", effect="unknown"
            )
        path = self.root / "releases" / f"{release_id}.release-index.json"
        try:
            payload = read_bytes(path, f"{role} release index")
        except SafeIOError as exc:
            raise UpdateHostError(
                "host_release_unavailable",
                f"{role} release bytes are not durable in the updater state root",
                effect="unknown",
            ) from exc
        try:
            index = load_release_index(payload, legacy_predecessor=(role == "current"))
        except ReleaseContractError as exc:
            raise UpdateHostError(
                "host_release_invalid", f"{role} release bytes are invalid", effect="unknown"
            ) from exc
        if index.release_id != release_id or index.signed_digest != signed_digest:
            raise UpdateHostError(
                "host_release_binding_mismatch",
                f"durable {role} release does not bind the exact plan identity",
                effect="unknown",
            )
        return index

    def _genesis_hex(self) -> str:
        """Genesis signed payload hex; installation volume names derive from it."""

        identity_dir = self.root / "installed-authority" / "identity"
        genesis: list[str] = []
        if identity_dir.is_dir():
            for path in sorted(identity_dir.glob("*.json")):
                try:
                    record = read_json(path, "installed identity record")
                except SafeIOError as exc:
                    raise UpdateHostError(
                        "host_layout_unknown",
                        "installed identity chain is unreadable",
                        effect="unknown",
                    ) from exc
                if record.get("predecessorIdentityDigest") is None:
                    digest = record.get("signedPayloadDigest")
                    if isinstance(digest, str) and DIGEST.fullmatch(digest) is not None:
                        genesis.append(digest)
        if len(genesis) != 1:
            raise UpdateHostError(
                "host_layout_unknown",
                "installed identity chain has no unique genesis record",
                effect="unknown",
            )
        return genesis[0].removeprefix("sha256:")

    # ------------------------------------------------------------------
    # runner / live-state primitives
    # ------------------------------------------------------------------

    def _run(
        self,
        argv: Sequence[str],
        *,
        timeout: int,
        code: str,
        effect: str,
    ) -> Completed:
        try:
            completed = self.runner.run(list(argv), timeout=timeout)
        except Exception as exc:
            raise UpdateHostError(code, f"{argv[0]} invocation failed", effect=effect) from exc
        if completed.returncode != 0:
            detail = completed.stderr.strip().splitlines()
            suffix = f": {detail[-1][:200]}" if detail else ""
            raise UpdateHostError(code, f"{' '.join(argv[:2])} failed{suffix}", effect=effect)
        return completed

    def _run_best_effort(self, argv: Sequence[str], *, timeout: int) -> Completed:
        try:
            return self.runner.run(list(argv), timeout=timeout)
        except Exception:
            return Completed(1, "", "invocation failed")

    def _systemctl(self, args: Sequence[str], *, timeout: int, code: str, effect: str) -> Completed:
        return self._run(
            [self.systemctl, "--user", *args], timeout=timeout, code=code, effect=effect
        )

    def _unit_active(self, unit: str) -> bool:
        completed = self._run_best_effort([self.systemctl, "--user", "is-active", unit], timeout=60)
        return completed.returncode == 0 and completed.stdout.strip() == "active"

    def _container_running(self, container: str) -> bool:
        completed = self._run_best_effort(
            [self.podman, "inspect", "--format", "{{.State.Status}}", container], timeout=60
        )
        return completed.returncode == 0 and completed.stdout.strip() == "running"

    def _read_live_unit(self, path: Path) -> str:
        try:
            payload = read_bytes(path, "live quadlet unit", maximum=MAX_UNIT_BYTES)
        except SafeIOError as exc:
            raise UpdateHostError(
                "host_live_layout_unsafe", "live quadlet unit is unreadable", effect="unknown"
            ) from exc
        try:
            return payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise UpdateHostError(
                "host_live_layout_unsafe", "live quadlet unit is not UTF-8", effect="unknown"
            ) from exc

    def _live_unit_files(self) -> list[Path]:
        if not self.quadlet_root.is_dir() or self.quadlet_root.is_symlink():
            return []
        files = sorted(self.quadlet_root.glob("*.container"))
        if len(files) > MAX_UNIT_FILES:
            raise UpdateHostError(
                "host_live_layout_unsafe",
                "live quadlet root exceeds the unit bound",
                effect="unknown",
            )
        return files

    @staticmethod
    def _unit_host_ports(text: str) -> dict[int, int]:
        """Map container port to loopback host port from one live unit file."""

        return {int(container): int(host) for host, container in PUBLISH_PORT.findall(text)}

    def _occupied_ports(self) -> list[dict[str, Any]]:
        """Exact collision inventory: live quadlet publishes plus host listeners."""

        occupied: list[dict[str, Any]] = []
        seen: set[int] = set()
        for path in self._live_unit_files():
            for host_port in self._unit_host_ports(self._read_live_unit(path)).values():
                if host_port in seen:
                    continue
                seen.add(host_port)
                occupied.append(
                    {
                        "class": "current",
                        "port": host_port,
                        "identityDigest": canonical_digest(
                            {
                                "class": "current",
                                "port": host_port,
                                "source": "live-quadlet-publish",
                            }
                        ),
                    }
                )
        for port in self._proc_listeners():
            if port in seen:
                continue
            seen.add(port)
            occupied.append(
                {
                    "class": "observed-host",
                    "port": port,
                    "identityDigest": canonical_digest(
                        {"class": "observed-host", "port": port, "source": "proc-net-tcp-listen"}
                    ),
                }
            )
        return occupied

    @staticmethod
    def _proc_listeners() -> list[int]:
        ports: set[int] = set()
        for table in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                lines = Path(table).read_text(encoding="ascii").splitlines()[1:]
            except OSError:
                continue
            for line in lines:
                fields = line.split()
                if len(fields) > 3 and fields[3] == "0A":
                    try:
                        ports.add(int(fields[1].rsplit(":", 1)[1], 16))
                    except (IndexError, ValueError):
                        continue
        return sorted(ports)

    def _write_live_unit(
        self,
        name: str,
        content: bytes,
        *,
        release_binding: tuple[str, str],
        code: str,
        effect: str,
    ) -> None:
        """Create or convergently replace one stateport-owned live unit file.

        A differing file is replaced only when its signed release labels bind
        the exact same release revision (port or per-plan snapshot drift from
        an earlier plan) and the unit is not running.  Anything else refuses.
        """

        if UNIT_FILE_NAME.fullmatch(name) is None:
            raise UpdateHostError(code, "live unit name is invalid", effect=effect)
        if b"[Install]" in content or b"WantedBy=" in content:
            raise UpdateHostError(code, "live unit requests boot activation", effect=effect)
        if b"@@STATEPORT_" in content:
            raise UpdateHostError(
                code, "live unit has unresolved materialization tokens", effect=effect
            )
        ensure_private_directory(self.quadlet_root)
        path = self.quadlet_root / name
        if path.exists() or path.is_symlink():
            try:
                existing = self._read_live_unit(path)
            except UpdateHostError as exc:
                raise UpdateHostError(
                    code, "live quadlet unit conflicts with staged content", effect=effect
                ) from exc
            if existing.encode("utf-8") == content:
                return
            if _unit_release_binding(existing) != release_binding:
                raise UpdateHostError(
                    code, "live quadlet unit binds a different release", effect=effect
                )
            unit_base = name.removesuffix(".container").removesuffix(".network")
            if name.endswith(".container") and self._unit_active(unit_base):
                raise UpdateHostError(
                    code, "live quadlet unit is running and cannot be replaced", effect=effect
                )
            temporary = create_bytes(
                self.quadlet_root / f".{name}.staged",
                content,
                "live quadlet unit",
                maximum=MAX_UNIT_BYTES,
            )
            del temporary
            os.replace(self.quadlet_root / f".{name}.staged", path)
            return
        create_bytes(path, content, "live quadlet unit", maximum=MAX_UNIT_BYTES)

    def _daemon_reload(self, *, code: str, effect: str) -> None:
        self._systemctl(["daemon-reload"], timeout=120, code=code, effect=effect)

    def _systemd_user_root(self) -> Path:
        if (
            self.quadlet_root.name == "systemd"
            and self.quadlet_root.parent.name == "containers"
        ):
            return self.quadlet_root.parent.parent / "systemd" / "user"
        return self.quadlet_root.parent / "systemd" / "user"

    @staticmethod
    def _activation_target_content(
        units: Sequence[str], *, release_id: str, signed_digest: str
    ) -> bytes:
        if not units:
            raise UpdateHostError(
                "activation_target_invalid", "accepted activation has no units", effect="partial"
            )
        values = sorted(str(unit) for unit in units)
        return (
            "[Unit]\n"
            "Description=StatePort accepted release\n"
            f"X-StatePort-Control-Identity={CONTROL_IDENTITY}\n"
            f"X-StatePort-Release-Id={release_id}\n"
            f"X-StatePort-Signed-Payload={signed_digest}\n"
            f"After={' '.join(values)}\n"
            f"Wants={' '.join(values)}\n\n"
            "[Install]\n"
            "WantedBy=default.target\n"
        ).encode("utf-8")

    def _write_activation_target(
        self,
        units: Sequence[str],
        *,
        release_id: str,
        signed_digest: str,
        code: str,
        effect: str,
    ) -> None:
        content = self._activation_target_content(
            units, release_id=release_id, signed_digest=signed_digest
        )
        root = ensure_private_directory(self._systemd_user_root())
        path = root / ACCEPTED_ACTIVATION_TARGET
        if path.exists() or path.is_symlink():
            if path.is_symlink() or not path.is_file():
                raise UpdateHostError(code, "accepted activation target is unsafe", effect=effect)
            try:
                existing = read_bytes(
                    path, "accepted activation target", maximum=MAX_UNIT_BYTES
                )
            except SafeIOError as exc:
                raise UpdateHostError(
                    code, "accepted activation target is unreadable", effect=effect
                ) from exc
            if existing == content:
                return
            temporary = root / f".{ACCEPTED_ACTIVATION_TARGET}.staged"
            try:
                create_bytes(
                    temporary, content, "accepted activation target", maximum=MAX_UNIT_BYTES
                )
                os.replace(temporary, path)
            except (OSError, SafeIOError) as exc:
                raise UpdateHostError(
                    code, "accepted activation target could not be replaced", effect=effect
                ) from exc
            return
        try:
            create_bytes(path, content, "accepted activation target", maximum=MAX_UNIT_BYTES)
        except SafeIOError as exc:
            raise UpdateHostError(
                code, "accepted activation target could not be created", effect=effect
            ) from exc

    def _enable_activation_target(self, *, code: str, effect: str) -> None:
        if self.require_linger:
            try:
                linger = self.runner.run(
                    ["loginctl", "show-user", str(os.getuid()), "--property=Linger", "--value"],
                    timeout=60,
                )
            except Exception as exc:
                raise UpdateHostError(
                    "control_identity_unavailable",
                    "could not inspect the control user's linger state",
                    effect=effect,
                ) from exc
            if linger.returncode != 0 or linger.stdout.strip().lower() not in {"yes", "true"}:
                raise UpdateHostError(
                    "linger_required",
                    "the control identity must have systemd user linger enabled",
                    effect=effect,
                )
        self._systemctl(
            ["enable", ACCEPTED_ACTIVATION_TARGET],
            timeout=120,
            code=code,
            effect=effect,
        )

    # ------------------------------------------------------------------
    # health probes
    # ------------------------------------------------------------------

    @staticmethod
    def _service_probe_port(service: Mapping[str, Any], ports: Mapping[str, int]) -> int | None:
        health = service["health"]
        health_port = next(
            (
                port
                for port in service["ports"]
                if int(port["containerPort"]) == int(health["containerPort"])
            ),
            service["ports"][0] if service["ports"] else None,
        )
        if health_port is None:
            return None
        return ports.get(str(health_port["name"]))

    def _probe_service_once(
        self,
        service: Mapping[str, Any],
        ports: Mapping[str, int],
        container: str,
    ) -> bool:
        health = service["health"]
        port = self._service_probe_port(service, ports)
        if port is not None and str(health.get("kind")) == "http":
            result = self.fetcher.fetch(
                f"http://127.0.0.1:{port}{health['path']}", timeout=10.0, max_bytes=65536
            )
            return result.status == 200 and bool(result.body)
        completed = self._run_best_effort(
            [
                self.podman,
                "inspect",
                "--format",
                "{{.State.Healthcheck.Status}}",
                container,
            ],
            timeout=60,
        )
        return completed.returncode == 0 and completed.stdout.strip() == "healthy"

    def _health_sweep(
        self,
        services: Sequence[Mapping[str, Any]],
        ports_by_service: Mapping[str, Mapping[str, int]],
        containers: Mapping[str, str],
        *,
        code: str,
        effect: str,
    ) -> None:
        for service in sorted(services, key=lambda item: str(item["serviceId"])):
            # Per-service deadline: services start strictly serially, so one
            # shared budget across the set starves the later services.
            deadline = self.clock() + timedelta(seconds=self.health_timeout_seconds)
            service_id = str(service["serviceId"])
            while not self._probe_service_once(
                service, ports_by_service.get(service_id, {}), containers[service_id]
            ):
                if self.clock() >= deadline:
                    raise UpdateHostError(
                        code,
                        f"service {service_id} did not report healthy in time",
                        effect=effect,
                    )
                time.sleep(min(self.health_poll_seconds, 0.5))

    # ------------------------------------------------------------------
    # UpdateHost protocol
    # ------------------------------------------------------------------

    def preflight(self, release: Any) -> Mapping[str, Any]:
        _require_provisioned_provider_home(release.verified.target)
        self._run(
            [self.podman, "version"],
            timeout=60,
            code="host_preflight_failed",
            effect="not_applied",
        )
        self._run(
            [self.systemctl, "--user", "show", "--property=Version", "--value"],
            timeout=60,
            code="host_preflight_failed",
            effect="not_applied",
        )
        if not self.quadlet_root.is_dir() or self.quadlet_root.is_symlink():
            raise UpdateHostError(
                "host_preflight_failed",
                "live quadlet root is not an installer-managed directory",
                effect="not_applied",
            )
        try:
            updater_compatible = version_key(UPDATER_VERSION) >= version_key(
                release.minimum_updater_version
            )
        except ValueError as exc:
            raise UpdateHostError(
                "host_preflight_failed",
                "release updater version floor is invalid",
                effect="not_applied",
            ) from exc
        available = shutil.disk_usage(self.root).free
        return {
            "schema": "stateport.update-host-preflight/v1",
            "targetId": self.target_id,
            "releaseId": release.release_id,
            "availableBytes": int(available),
            "requiredBytes": release.expected_pull_bytes,
            "imageDigests": list(release.target_image_digests),
            # The host adds no constraint beyond the signed compatibility
            # contract, which the engine checks separately and exactly.
            "updaterCompatible": updater_compatible,
            "migrationCompatible": True,
            "rollbackCompatible": True,
        }

    def backup(self, plan: Mapping[str, Any]) -> Mapping[str, Any]:
        plan_digest = str(plan["planDigest"])
        completed = self._completed_evidence(plan_digest, "backup")
        if completed is not None:
            return completed
        existing = self._read_context(plan_digest)
        if existing is not None and existing.get("phase") == "backup":
            # Converge an interrupted backup to its durable receipt: every
            # snapshot volume must still exist and the accepted route must be
            # active; anything else is an unknown partial effect.
            receipt = existing.get("validationBackupReceipt")
            bindings = (receipt or {}).get("volumeBindings", [])
            for binding in bindings:
                exists = self._run_best_effort(
                    [self.podman, "volume", "exists", str(binding["snapshotVolumeName"])],
                    timeout=60,
                )
                if exists.returncode != 0:
                    raise UpdateHostError(
                        "backup_effect_conflict",
                        "interrupted backup lost its durable snapshot volume",
                        effect="unknown",
                    )
            current = self._release_index(plan, "current")
            if not all(
                self._unit_active(unit)
                for unit in _container_units(
                    current, "accepted", self.target_id
                ).values()
            ):
                raise UpdateHostError(
                    "backup_effect_conflict",
                    "interrupted backup left the accepted route inactive",
                    effect="unknown",
                )
            return self._record_effect(
                plan_digest,
                "backup",
                {
                    "schema": "stateport.update-host-backup/v1",
                    "planDigest": plan_digest,
                    "receiptId": f"backup_{str(existing['backupDigest']).removeprefix('sha256:')[:32]}",
                    "backupDigest": str(existing["backupDigest"]),
                },
            )
        successor = self._release_index(plan, "successor")
        current = self._release_index(plan, "current")
        genesis_hex = self._genesis_hex()
        target = _signed_target(successor, self.target_id)
        snapshot_keys = _installation_volume_keys(target, snapshot_required=True)
        current_units = _container_units(current, "accepted", self.target_id)
        code, effect = "backup_failed", "not_applied"
        work_dir = ensure_private_directory(self._effects_dir(plan_digest) / "work")
        bindings: list[dict[str, Any]] = []
        data_volumes: dict[str, str] = {}
        stopped: list[str] = []
        restored = False
        try:
            # Quiesce the accepted route so the exported snapshot copies are
            # genuinely quiesced; the receipt's consistency claim is only made
            # after every writer was stopped.
            for unit in sorted(current_units.values()):
                self._systemctl(["stop", unit], timeout=300, code=code, effect=effect)
                stopped.append(unit)
            for volume_key in snapshot_keys:
                data_name = _data_volume_name(genesis_hex, volume_key)
                snapshot_name = _snapshot_volume_name(genesis_hex, volume_key, plan_digest)
                exists = self._run_best_effort(
                    [self.podman, "volume", "exists", data_name], timeout=60
                )
                tarball = work_dir / f"{_volume_key_hash(volume_key)}.tar.gz"
                try:
                    if exists.returncode == 0:
                        data_volumes[volume_key] = data_name
                        self._run(
                            [self.podman, "volume", "export", data_name, "--output", str(tarball)],
                            timeout=1800,
                            code=code,
                            effect=effect,
                        )
                        self._ensure_volume(snapshot_name, code=code, effect=effect)
                        self._run(
                            [self.podman, "volume", "import", snapshot_name, str(tarball)],
                            timeout=1800,
                            code=code,
                            effect=effect,
                        )
                    else:
                        # A successor-introduced volume has no current data;
                        # its snapshot copy is an exact empty volume.
                        self._ensure_volume(snapshot_name, code=code, effect=effect)
                finally:
                    tarball.unlink(missing_ok=True)
                bindings.append(
                    {
                        "volumeKey": volume_key,
                        "snapshotVolumeName": snapshot_name,
                        "sourceDataGeneration": None,
                        "readOnly": True,
                    }
                )
        finally:
            for unit in stopped:
                self._run_best_effort([self.systemctl, "--user", "start", unit], timeout=900)
            restored = all(self._unit_active(unit) for unit in stopped)
        if not restored:
            raise UpdateHostError(
                "backup_restore_failed",
                "accepted route was not restored after the quiesced backup",
                effect="unknown",
            )
        evidence_document: dict[str, Any] = {
            "formatVersion": BACKUP_EVIDENCE_FORMAT,
            "rationale": "update backup: the accepted route was stopped, each "
            "snapshot-required data volume was exported into a fresh per-plan "
            "snapshot volume, and the accepted route was restarted and verified active",
            "dataVolumes": dict(sorted(data_volumes.items())),
            "snapshots": bindings,
            "quiescedUnits": sorted(stopped),
            "observedAt": _timestamp(self.clock),
        }
        backup_digest = canonical_digest(evidence_document)
        validation_receipt: dict[str, Any] | None = None
        if bindings:
            validation_receipt = {
                "schema": BACKUP_RECEIPT_SCHEMA,
                "operationPlanDigest": plan_digest,
                "releaseId": successor.release_id,
                "signedPayloadDigest": successor.signed_digest,
                "targetId": str(target["targetId"]),
                "topologyDigest": str(target["topologyDigest"]),
                "backupReceiptDigest": backup_digest,
                "snapshotSetDigest": canonical_digest(bindings),
                "volumeBindings": bindings,
                "createdAt": _timestamp(self.clock),
                "consistencyMode": "quiesced",
                "consistencyEvidenceDigest": canonical_digest(
                    {"quiescence": "accepted-services-stopped-during-export", **evidence_document}
                ),
                "result": "succeeded",
            }
            validation_receipt["receiptDigest"] = revision_contract_digest(
                validation_receipt, digest_field="receiptDigest"
            )
            backup_digest = str(validation_receipt["receiptDigest"])
        context_path = self._context_path(plan_digest)
        ensure_private_directory(context_path.parent)
        create_json(
            context_path,
            {
                "schema": CONTEXT_SCHEMA,
                "planDigest": plan_digest,
                "phase": "backup",
                "backupDigest": backup_digest,
                "validationBackupReceipt": validation_receipt,
            },
            "host stage context",
        )
        return self._record_effect(
            plan_digest,
            "backup",
            {
                "schema": "stateport.update-host-backup/v1",
                "planDigest": plan_digest,
                "receiptId": f"backup_{backup_digest.removeprefix('sha256:')[:32]}",
                "backupDigest": backup_digest,
            },
        )

    def _ensure_volume(self, name: str, *, code: str, effect: str) -> None:
        exists = self._run_best_effort([self.podman, "volume", "exists", name], timeout=60)
        if exists.returncode == 0:
            return
        self._run([self.podman, "volume", "create", name], timeout=120, code=code, effect=effect)

    def pull_images(self, plan: Mapping[str, Any], release: Any) -> Mapping[str, Any]:
        plan_digest = str(plan["planDigest"])
        completed = self._completed_evidence(plan_digest, "pull")
        if completed is not None:
            return completed
        for image in release.target_images:
            reference = str(image["reference"])
            self._run(
                [self.podman, "pull", reference],
                timeout=3600,
                code="pull_failed",
                effect="partial",
            )
            observed = self._run(
                [self.podman, "image", "inspect", "--format", "{{.Digest}}", reference],
                timeout=120,
                code="pull_failed",
                effect="partial",
            )
            if observed.stdout.strip() != str(image["digest"]):
                raise UpdateHostError(
                    "pull_failed",
                    "resolved image digest differs from the signed digest",
                    effect="partial",
                )
        return self._record_effect(
            plan_digest,
            "pull",
            {
                "schema": "stateport.update-host-pull/v1",
                "releaseId": release.release_id,
                "imageDigests": list(release.target_image_digests),
            },
        )

    def stage(self, plan: Mapping[str, Any], release: Any) -> Mapping[str, Any]:
        plan_digest = str(plan["planDigest"])
        completed = self._completed_evidence(plan_digest, "stage")
        if completed is not None:
            context = self._context(plan_digest)
            if (
                context.get("phase") != "staged"
                or not (
                    self.root / "host-staged" / str(context["stagedDir"]) / "marker.json"
                ).is_file()
            ):
                raise UpdateHostError(
                    "stage_effect_lost",
                    "durable stage receipt exists but the staged successor is gone",
                    effect="unknown",
                )
            return completed
        binding = (release.release_id, release.signed_digest)
        backup_context = self._context(plan_digest)
        validation_receipt = backup_context.get("validationBackupReceipt")
        occupied = self._occupied_ports()
        current_entries = [item for item in occupied if item["class"] == "current"]
        observed_entries = [item for item in occupied if item["class"] == "observed-host"]
        empty_inventory = canonical_digest([])
        collision_digests = {
            "current": (
                canonical_digest(sorted(current_entries, key=lambda item: item["port"]))
                if current_entries
                else empty_inventory
            ),
            "predecessor": empty_inventory,
            "candidate": empty_inventory,
            "observedHost": (
                canonical_digest(sorted(observed_entries, key=lambda item: item["port"]))
                if observed_entries
                else empty_inventory
            ),
        }
        host_identity_digest = canonical_digest(
            {
                "formatVersion": HOST_IDENTITY_FORMAT,
                "targetId": release.target_id,
                "containerEngine": "rootless-podman-quadlet",
                "cgroupVersion": "v2",
            }
        )
        try:
            staged = materialize_verified_quadlet_bundle(
                release.verified,
                operation_plan_digest=plan_digest,
                host_identity_digest=host_identity_digest,
                collision_inventory_digests=collision_digests,
                occupied_port_inputs=occupied,
                proposed_at=_timestamp(self.clock),
                validation_backup_receipt=validation_receipt,
            )
        except ReleaseContractError as exc:
            raise UpdateHostError("stage_failed", str(exc)[:300], effect="partial") from exc
        signed_hex = release.signed_digest.removeprefix("sha256:")
        staged_parent = ensure_private_directory(self.root / "host-staged")
        staged_dir = staged_parent / signed_hex
        if staged_dir.exists():
            if not staged_dir.is_dir() or staged_dir.is_symlink():
                raise UpdateHostError(
                    "stage_failed", "staged successor path is unsafe", effect="partial"
                )
            # Only a plan without a stage receipt reaches here, so any prior
            # content is an unrecorded partial stage of the same release.
            shutil.rmtree(staged_dir)
        prefix = f"staged/{signed_hex}/"
        manifest: Mapping[str, Any] | None = None
        for relative, content in sorted(staged.items()):
            if not relative.startswith(prefix):
                raise UpdateHostError(
                    "stage_failed", "staged bundle has an unexpected path", effect="partial"
                )
            local = staged_dir / relative[len(prefix) :]
            ensure_private_directory(local.parent)
            create_bytes(local, content, "staged quadlet artifact")
            if local.name == "materialization.json":
                manifest = json.loads(content)
        if manifest is None:
            raise UpdateHostError("stage_failed", "staged bundle has no manifest", effect="partial")
        validation_files: list[str] = []
        accepted_files: list[str] = []
        for artifact in manifest["artifacts"]:
            unit_name = Path(str(artifact["liveRelativePath"])).name
            if artifact["kind"] not in {"container", "network"}:
                continue
            if artifact["profile"] == "validation":
                source = staged_dir / str(artifact["stagedPath"])[len(prefix) :]
                self._write_live_unit(
                    unit_name,
                    source.read_bytes(),
                    release_binding=binding,
                    code="stage_failed",
                    effect="partial",
                )
                validation_files.append(unit_name)
            elif artifact["profile"] == "accepted":
                accepted_files.append(unit_name)
        self._daemon_reload(code="stage_failed", effect="partial")
        services: list[dict[str, Any]] = []
        target = release.verified.target
        for service in target["services"]:
            service_id = str(service["serviceId"])
            services.append(
                {
                    "serviceId": service_id,
                    "health": {
                        "kind": str(service["health"]["kind"]),
                        "containerPort": int(service["health"]["containerPort"]),
                        "path": str(service["health"]["path"]),
                    },
                    "ports": [
                        {"name": str(port["name"]), "containerPort": int(port["containerPort"])}
                        for port in service["ports"]
                    ],
                    "validationContainer": f"stateport-{_service_name_id(service_id)}-validation-"
                    f"{manifest['revisions'][f'{service_id}:validation']}",
                    "acceptedContainer": f"stateport-{_service_name_id(service_id)}-accepted-"
                    f"{manifest['revisions'][f'{service_id}:accepted']}",
                    "validationPorts": {
                        str(port["name"]): int(
                            manifest["ports"][f"{service_id}:validation:{port['name']}"]
                        )
                        for port in service["ports"]
                    },
                    "acceptedPorts": {
                        str(port["name"]): int(
                            manifest["ports"][f"{service_id}:accepted:{port['name']}"]
                        )
                        for port in service["ports"]
                    },
                }
            )
        compatibility = release.envelope.document["compatibility"]
        network_units = {
            "validation": _network_units(
                release.verified.index, "validation", self.target_id
            ),
            "accepted": _network_units(
                release.verified.index, "accepted", self.target_id
            ),
        }
        context: dict[str, Any] = {
            "schema": CONTEXT_SCHEMA,
            "planDigest": plan_digest,
            "phase": "staged",
            "releaseId": release.release_id,
            "signedDigest": release.signed_digest,
            "runtimeDigest": release.expected_revision_digest(),
            "schemaVersion": int(compatibility["schemaMigrationVersion"]),
            "databaseMigrationVersion": int(compatibility["databaseMigrationVersion"]),
            "dataCompatible": bool(compatibility["rollback"]["dataCompatible"]),
            "stagedDir": signed_hex,
            "services": services,
            "validationUnitFiles": sorted(validation_files),
            "acceptedUnitFiles": sorted(accepted_files),
            "networkUnits": network_units,
            "validationBackupReceipt": validation_receipt,
            "createdAt": _timestamp(self.clock),
        }
        replace_json(self._context_path(plan_digest), context, "host stage context")
        marker = {
            "schema": MARKER_SCHEMA,
            "releaseId": release.release_id,
            "signedPayloadDigest": release.signed_digest,
            "stagedDir": signed_hex,
            "unitFiles": sorted({*validation_files, *accepted_files}),
            "networkUnits": sorted({*network_units["validation"], *network_units["accepted"]}),
            "createdAt": context["createdAt"],
        }
        marker_path = staged_dir / "marker.json"
        if marker_path.exists() or marker_path.is_symlink():
            # The marker is plan-independent: a second plan for the same exact
            # release converges on the first plan's marker.
            existing_marker = read_json(marker_path, "staged release marker")
            if {key: value for key, value in existing_marker.items() if key != "createdAt"} != {
                key: value for key, value in marker.items() if key != "createdAt"
            }:
                raise UpdateHostError(
                    "stage_failed",
                    "staged release marker binds different release material",
                    effect="partial",
                )
        else:
            create_json(marker_path, marker, "staged release marker")
        return self._record_effect(
            plan_digest,
            "stage",
            {
                "schema": "stateport.update-host-stage/v1",
                "releaseId": release.release_id,
                "slot": "successor",
                "bundleDigest": release.quadlet_bundle_digest,
            },
        )

    def dry_run_migrations(self, plan: Mapping[str, Any]) -> Mapping[str, Any]:
        plan_digest = str(plan["planDigest"])
        context = self._context(plan_digest)
        current = self._release_index(plan, "current")
        current_compat = current.document["signed"]["compatibility"]
        if (
            int(context["schemaVersion"]) < int(current_compat["schemaMigrationVersion"])
            or int(context["databaseMigrationVersion"])
            < int(current_compat["databaseMigrationVersion"])
            or context["dataCompatible"] is not True
        ):
            raise UpdateHostError(
                "dry_run_migrations_failed",
                "successor migration declarations are not monotonic and data compatible",
                effect="partial",
            )
        return self._record_effect(
            plan_digest,
            "dry-run-migrations",
            {
                "schema": "stateport.update-host-migration-dry-run/v1",
                "planDigest": plan_digest,
                "status": "passed",
                "schemaMigrationVersion": int(context["schemaVersion"]),
                "databaseMigrationVersion": int(context["databaseMigrationVersion"]),
                "dataCompatible": True,
            },
        )

    def start_successor(self, plan: Mapping[str, Any]) -> Mapping[str, Any]:
        plan_digest = str(plan["planDigest"])
        completed = self._completed_evidence(plan_digest, "start-successor")
        if completed is not None:
            return completed
        context = self._context(plan_digest)
        for service in context["services"]:
            self._systemctl(
                ["start", str(service["validationContainer"])],
                timeout=900,
                code="start_successor_failed",
                effect="partial",
            )
        return self._record_effect(
            plan_digest,
            "start-successor",
            {
                "schema": "stateport.update-host-start/v1",
                "releaseId": str(context["releaseId"]),
                "runtimeDigest": str(context["runtimeDigest"]),
                "status": "started",
            },
        )

    @staticmethod
    def _probe_layout(
        context: Mapping[str, Any], profile: str
    ) -> tuple[list[Mapping[str, Any]], dict[str, Mapping[str, int]], dict[str, str]]:
        services = [
            {
                "serviceId": service["serviceId"],
                "health": service["health"],
                "ports": service["ports"],
            }
            for service in context["services"]
        ]
        ports = {
            str(service["serviceId"]): {
                str(name): int(port) for name, port in service[f"{profile}Ports"].items()
            }
            for service in context["services"]
        }
        containers = {
            str(service["serviceId"]): str(service[f"{profile}Container"])
            for service in context["services"]
        }
        return services, ports, containers

    def health_successor(self, plan: Mapping[str, Any]) -> Mapping[str, Any]:
        plan_digest = str(plan["planDigest"])
        completed = self._completed_evidence(plan_digest, "health-successor")
        if completed is not None:
            return completed
        context = self._context(plan_digest)
        services, ports, containers = self._probe_layout(context, "validation")
        self._health_sweep(
            services,
            ports,
            containers,
            code="health_successor_failed",
            effect="partial",
        )
        return self._record_effect(
            plan_digest,
            "health-successor",
            {
                "schema": "stateport.update-host-health/v1",
                "releaseId": str(context["releaseId"]),
                "runtimeDigest": str(context["runtimeDigest"]),
                "healthy": True,
            },
        )

    def _journey_check(
        self,
        plan: Mapping[str, Any],
        *,
        step: str,
        schema: str,
        check_id: str,
        root_probe: bool = False,
        unit_state: bool = False,
    ) -> Mapping[str, Any]:
        plan_digest = str(plan["planDigest"])
        completed = self._completed_evidence(plan_digest, step)
        if completed is not None:
            return completed
        context = self._context(plan_digest)
        services, ports, containers = self._probe_layout(context, "validation")
        code = f"{step.replace('-', '_')}_failed"
        self._health_sweep(services, ports, containers, code=code, effect="partial")
        if root_probe:
            for service in services:
                service_ports = ports[str(service["serviceId"])]
                if not service_ports:
                    continue
                port = service_ports[sorted(service_ports)[0]]
                result = self.fetcher.fetch(
                    f"http://127.0.0.1:{port}/", timeout=10.0, max_bytes=65536
                )
                if result.status != 200 or not result.body:
                    raise UpdateHostError(
                        code,
                        f"service {service['serviceId']} does not serve its root document",
                        effect="partial",
                    )
        if unit_state:
            for container in containers.values():
                if not self._unit_active(container):
                    raise UpdateHostError(
                        code,
                        f"staged unit {container} is not active",
                        effect="partial",
                    )
        result_digest = canonical_digest(
            {
                "check": check_id,
                "releaseId": str(context["releaseId"]),
                "runtimeDigest": str(context["runtimeDigest"]),
                "services": sorted(str(service["serviceId"]) for service in services),
            }
        )
        return self._record_effect(
            plan_digest,
            step,
            {
                "schema": schema,
                "releaseId": str(context["releaseId"]),
                "status": "passed",
                "resultDigest": result_digest,
            },
        )

    def browser_successor(self, plan: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._journey_check(
            plan,
            step="browser-successor",
            schema="stateport.update-host-browser-check/v1",
            check_id="browser",
            root_probe=True,
        )

    def studystate_successor(self, plan: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._journey_check(
            plan,
            step="studystate-successor",
            schema="stateport.update-host-studystate-check/v1",
            check_id="studystate",
        )

    def state_check_successor(self, plan: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._journey_check(
            plan,
            step="state-check-successor",
            schema="stateport.update-host-state-check/v1",
            check_id="state",
            unit_state=True,
        )

    def switch(self, plan: Mapping[str, Any]) -> Mapping[str, Any]:
        plan_digest = str(plan["planDigest"])
        context = self._context(plan_digest)
        completed = self._completed_evidence(plan_digest, "switch")
        if completed is not None:
            if not all(
                self._unit_active(str(service["acceptedContainer"]))
                for service in context["services"]
            ):
                raise UpdateHostError(
                    "switch_effect_lost",
                    "durable switch receipt exists but the successor is not live",
                    effect="unknown",
                )
            return completed
        binding = (str(context["releaseId"]), str(context["signedDigest"]))
        current = self._release_index(plan, "current")
        genesis_hex = self._genesis_hex()
        signed_hex = str(context["stagedDir"])
        staged_dir = self.root / "host-staged" / signed_hex
        prefix = f"staged/{signed_hex}/"
        try:
            manifest = json.loads(
                read_bytes(staged_dir / "materialization.json", "staged manifest").decode("utf-8")
            )
        except (SafeIOError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UpdateHostError(
                "switch_failed", "staged manifest is unreadable", effect="partial"
            ) from exc
        # Create successor-introduced data volumes exactly once; existing
        # installation volumes are never recreated.
        successor = self._release_index(plan, "successor")
        target = _signed_target(successor, self.target_id)
        _require_provisioned_provider_home(target)
        data_bindings: dict[str, str] = {}
        for volume_key in _installation_volume_keys(target):
            data_name = _data_volume_name(genesis_hex, volume_key)
            self._ensure_volume(data_name, code="switch_failed", effect="partial")
            data_bindings[volume_key] = data_name
        for artifact in manifest["artifacts"]:
            if artifact["profile"] != "accepted" or artifact["kind"] not in {
                "container",
                "network",
            }:
                continue
            source = staged_dir / str(artifact["stagedPath"])[len(prefix) :]
            text = source.read_bytes().decode("utf-8")
            for volume_key, volume_name in sorted(data_bindings.items()):
                text = text.replace(f"@@STATEPORT_ACCEPTED_DATA_VOLUME:{volume_key}@@", volume_name)
            self._write_live_unit(
                Path(str(artifact["liveRelativePath"])).name,
                text.encode("utf-8"),
                release_binding=binding,
                code="switch_failed",
                effect="partial",
            )
        self._daemon_reload(code="switch_failed", effect="partial")
        # From here the accepted route is being replaced; failures are applied.
        current_units = _container_units(current, "accepted", self.target_id)
        for unit in sorted(current_units.values()):
            self._systemctl(["stop", unit], timeout=300, code="switch_failed", effect="applied")
        deadline = self.clock() + timedelta(seconds=60)
        while any(self._unit_active(unit) for unit in current_units.values()):
            if self.clock() >= deadline:
                raise UpdateHostError(
                    "switch_failed",
                    "predecessor accepted units did not stop in time",
                    effect="applied",
                )
            time.sleep(0.2)
        for service in context["services"]:
            self._systemctl(
                ["start", str(service["acceptedContainer"])],
                timeout=900,
                code="switch_failed",
                effect="applied",
            )
        for service in context["services"]:
            self._run_best_effort(
                [self.systemctl, "--user", "stop", str(service["validationContainer"])],
                timeout=300,
            )
        # Publish reboot recovery only after the successor is the live route.
        self._write_activation_target(
            [str(service["acceptedContainer"]) for service in context["services"]],
            release_id=str(context["releaseId"]),
            signed_digest=str(context["signedDigest"]),
            code="switch_failed",
            effect="applied",
        )
        self._daemon_reload(code="switch_failed", effect="applied")
        self._enable_activation_target(code="switch_failed", effect="applied")
        return self._record_effect(
            plan_digest,
            "switch",
            {
                "schema": "stateport.update-host-switch/v1",
                "releaseId": str(context["releaseId"]),
                "signedDigest": str(context["signedDigest"]),
                "runtimeDigest": str(context["runtimeDigest"]),
            },
        )

    def health_accepted_route(self, plan: Mapping[str, Any]) -> Mapping[str, Any]:
        plan_digest = str(plan["planDigest"])
        completed = self._completed_evidence(plan_digest, "health-accepted-route")
        if completed is not None:
            return completed
        context = self._context(plan_digest)
        services, ports, containers = self._probe_layout(context, "accepted")
        self._health_sweep(
            services,
            ports,
            containers,
            code="health_accepted_route_failed",
            effect="applied",
        )
        return self._record_effect(
            plan_digest,
            "health-accepted-route",
            {
                "schema": "stateport.update-host-accepted-health/v1",
                "releaseId": str(context["releaseId"]),
                "runtimeDigest": str(context["runtimeDigest"]),
                "healthy": True,
            },
        )

    def state_check_accepted_route(self, plan: Mapping[str, Any]) -> Mapping[str, Any]:
        plan_digest = str(plan["planDigest"])
        completed = self._completed_evidence(plan_digest, "state-check-accepted-route")
        if completed is not None:
            return completed
        context = self._context(plan_digest)
        services, ports, containers = self._probe_layout(context, "accepted")
        self._health_sweep(
            services,
            ports,
            containers,
            code="state_check_accepted_route_failed",
            effect="applied",
        )
        for container in containers.values():
            if not self._unit_active(container):
                raise UpdateHostError(
                    "state_check_accepted_route_failed",
                    f"accepted unit {container} is not active",
                    effect="applied",
                )
        return self._record_effect(
            plan_digest,
            "state-check-accepted-route",
            {
                "schema": "stateport.update-host-accepted-state/v1",
                "releaseId": str(context["releaseId"]),
                "runtimeDigest": str(context["runtimeDigest"]),
                "status": "passed",
            },
        )

    def observe_accepted_revision(self) -> Mapping[str, Any]:
        running: dict[tuple[str, str], list[str]] = {}
        for path in self._live_unit_files():
            if "-accepted-" not in path.name:
                continue
            container = path.name.removesuffix(".container")
            if not self._container_running(container):
                continue
            binding = _unit_release_binding(self._read_live_unit(path))
            if binding is None:
                raise UpdateHostError(
                    "observation_unavailable",
                    f"running accepted unit {container} lacks signed identity labels",
                    effect="unknown",
                )
            running.setdefault(binding, []).append(container)
        if len(running) != 1:
            raise UpdateHostError(
                "observation_unavailable",
                "accepted route identity is not exactly one running release",
                effect="unknown",
            )
        (release_id, signed_digest), _containers = next(iter(running.items()))
        path = self.root / "releases" / f"{release_id}.release-index.json"
        try:
            index = load_release_index(
                read_bytes(path, "accepted release index"), legacy_predecessor=True
            )
        except (SafeIOError, ReleaseContractError) as exc:
            raise UpdateHostError(
                "observation_unavailable",
                "running accepted release has no durable verified bytes",
                effect="unknown",
            ) from exc
        if index.release_id != release_id or index.signed_digest != signed_digest:
            raise UpdateHostError(
                "observation_unavailable",
                "running accepted release does not match its durable bytes",
                effect="unknown",
            )
        return {
            "schema": "stateport.update-host-observation/v1",
            "releaseId": release_id,
            "signedDigest": signed_digest,
            "runtimeDigest": _expected_revision_digest(index, self.target_id),
        }

    def discard_successor(self, plan: Mapping[str, Any]) -> Mapping[str, Any]:
        plan_digest = str(plan["planDigest"])
        completed = self._completed_evidence(plan_digest, "discard-successor")
        if completed is not None:
            return completed
        successor = self._release_index(plan, "successor")
        for profile in ("accepted", "validation"):
            for unit in sorted(
                _container_units(successor, profile, self.target_id).values()
            ):
                self._run_best_effort([self.systemctl, "--user", "stop", unit], timeout=300)
                self._run_best_effort([self.podman, "rm", "-f", unit], timeout=300)
        unit_files = [
            f"{unit}.container"
            for profile in ("accepted", "validation")
            for unit in _container_units(successor, profile, self.target_id).values()
        ]
        unit_files += [
            f"{unit}.network"
            for unit in (
                _network_units(successor, "accepted", self.target_id)
                + _network_units(successor, "validation", self.target_id)
            )
        ]
        for name in unit_files:
            try:
                unlink_regular(self.quadlet_root / name, "successor quadlet unit")
            except SafeIOError as exc:
                raise UpdateHostError(
                    "discard_successor_failed",
                    "successor runtime unit could not be removed",
                    effect="partial",
                ) from exc
        self._daemon_reload(code="discard_successor_failed", effect="partial")
        inventory = {
            "retainedArtifactIds": [str(successor.release_id)],
            "removedRuntimeReleaseIds": [str(successor.release_id)],
        }
        return self._record_effect(
            plan_digest,
            "discard-successor",
            {
                "schema": "stateport.update-host-discard/v1",
                "releaseId": str(successor.release_id),
                "status": "retained_for_evidence",
                **inventory,
                "inventoryDigest": canonical_digest(inventory),
            },
        )

    def rollback_failed_switch(self, plan: Mapping[str, Any]) -> Mapping[str, Any]:
        plan_digest = str(plan["planDigest"])
        current = self._release_index(plan, "current")
        completed = self._completed_evidence(plan_digest, "automatic-rollback")
        if completed is not None:
            if not all(
                self._unit_active(unit)
                for unit in _container_units(
                    current, "accepted", self.target_id
                ).values()
            ):
                raise UpdateHostError(
                    "rollback_effect_lost",
                    "durable rollback receipt exists but the predecessor is not live",
                    effect="unknown",
                )
            return completed
        context = self._context(plan_digest)
        for service in context["services"]:
            self._run_best_effort(
                [self.systemctl, "--user", "stop", str(service["acceptedContainer"])],
                timeout=300,
            )
            self._run_best_effort(
                [self.systemctl, "--user", "stop", str(service["validationContainer"])],
                timeout=300,
            )
        current_units = _container_units(current, "accepted", self.target_id)
        for unit in sorted(current_units.values()):
            self._systemctl(["start", unit], timeout=900, code="rollback_failed", effect="unknown")
        if not all(self._unit_active(unit) for unit in current_units.values()):
            raise UpdateHostError(
                "rollback_failed",
                "predecessor accepted route did not become active again",
                effect="unknown",
            )
        self._write_activation_target(
            list(current_units.values()),
            release_id=current.release_id,
            signed_digest=current.signed_digest,
            code="rollback_failed",
            effect="unknown",
        )
        self._daemon_reload(code="rollback_failed", effect="unknown")
        self._enable_activation_target(code="rollback_failed", effect="unknown")
        return self._record_effect(
            plan_digest,
            "automatic-rollback",
            {
                "schema": "stateport.update-host-rollback/v1",
                "releaseId": current.release_id,
                "signedDigest": current.signed_digest,
                "runtimeDigest": _expected_revision_digest(current, self.target_id),
                "status": "restored",
            },
        )

    def enforce_retention(
        self,
        *,
        plan_digest: str,
        current_release_id: str,
        required_predecessor_ids: Sequence[str],
        required_failure_evidence_ids: Sequence[str],
        maximum_versions: int,
        maximum_age_days: int,
    ) -> Mapping[str, Any]:
        completed = self._completed_evidence(plan_digest, "retain-predecessor")
        if completed is not None:
            return completed
        markers: dict[str, dict[str, Any]] = {}
        staged_parent = self.root / "host-staged"
        if staged_parent.is_dir():
            for candidate in sorted(staged_parent.iterdir()):
                marker_path = candidate / "marker.json"
                if not candidate.is_dir() or candidate.is_symlink() or not marker_path.is_file():
                    continue
                try:
                    marker = read_json(marker_path, "staged release marker")
                except SafeIOError as exc:
                    raise UpdateHostError(
                        "retention_failed", "staged release marker is unreadable", effect="unknown"
                    ) from exc
                if (
                    marker.get("schema") != MARKER_SCHEMA
                    or marker.get("stagedDir") != candidate.name
                    or not isinstance(marker.get("releaseId"), str)
                ):
                    raise UpdateHostError(
                        "retention_failed",
                        "staged release marker does not bind its directory",
                        effect="unknown",
                    )
                markers[str(marker["releaseId"])] = marker
        required = {str(current_release_id), *(str(item) for item in required_predecessor_ids)}
        retained = set(required)
        now = self.clock()
        budget = max(0, int(maximum_versions) - len(retained))
        extras = sorted(
            (marker for release_id, marker in markers.items() if release_id not in required),
            key=lambda marker: str(marker.get("createdAt", "")),
            reverse=True,
        )
        for marker in extras:
            created = str(marker.get("createdAt", ""))
            age_days = 0.0
            if created:
                try:
                    parsed = datetime.fromisoformat(created.replace("Z", "+00:00"))
                    age_days = (now - parsed).total_seconds() / 86400
                except ValueError:
                    age_days = float("inf")
            if age_days <= int(maximum_age_days) and budget > 0:
                retained.add(str(marker["releaseId"]))
                budget -= 1
        removed = sorted(set(markers) - retained)
        for release_id in removed:
            marker = markers[release_id]
            for name in marker.get("unitFiles", []):
                name = str(name)
                if UNIT_FILE_NAME.fullmatch(name) is None:
                    raise UpdateHostError(
                        "retention_failed", "staged marker unit name is invalid", effect="unknown"
                    )
                try:
                    unlink_regular(self.quadlet_root / name, "retired quadlet unit")
                except SafeIOError as exc:
                    raise UpdateHostError(
                        "retention_failed",
                        "retired unit file could not be removed",
                        effect="unknown",
                    ) from exc
            for network in marker.get("networkUnits", []):
                network = str(network)
                if UNIT_FILE_NAME.fullmatch(network) is None:
                    raise UpdateHostError(
                        "retention_failed",
                        "staged marker network name is invalid",
                        effect="unknown",
                    )
                try:
                    unlink_regular(self.quadlet_root / f"{network}.network", "retired network unit")
                except SafeIOError as exc:
                    raise UpdateHostError(
                        "retention_failed",
                        "retired network unit could not be removed",
                        effect="unknown",
                    ) from exc
            # Per-plan snapshot volumes bind the staged validation backup
            # receipt, which lives inside the retained staged tree until now.
            backup_receipt_path = (
                staged_parent / str(marker["stagedDir"]) / "validation-backup.receipt.json"
            )
            if backup_receipt_path.is_file() and not backup_receipt_path.is_symlink():
                receipt = read_json(backup_receipt_path, "staged validation backup receipt")
                for binding in receipt.get("volumeBindings", []):
                    name = str(binding.get("snapshotVolumeName", ""))
                    if UNIT_FILE_NAME.fullmatch(name) is not None:
                        self._run_best_effort([self.podman, "volume", "rm", name], timeout=300)
            shutil.rmtree(staged_parent / str(marker["stagedDir"]))
        if removed:
            self._daemon_reload(code="retention_failed", effect="unknown")
        inventory = {
            "currentReleaseId": str(current_release_id),
            "retainedReleaseIds": sorted(retained),
            "removedReleaseIds": removed,
            "retainedFailureArtifactIds": sorted(
                str(item) for item in required_failure_evidence_ids
            ),
            "removedFailureArtifactIds": [],
        }
        return self._record_effect(
            plan_digest,
            "retain-predecessor",
            {
                "schema": "stateport.update-host-retention/v1",
                **inventory,
                "inventoryDigest": canonical_digest(inventory),
                "maximumVersions": int(maximum_versions),
                "maximumAgeDays": int(maximum_age_days),
            },
        )
