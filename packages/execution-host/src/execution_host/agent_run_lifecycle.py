"""Authority-gated lifecycle for a single managed agent run.

``AgentRunLifecycle`` is the activation seam for a real managed provider run.
It enforces a typed ``RunAuthority`` (``run_authority``) and a per-workspace
single-in-flight lease *before* any executor contact, and it keeps the
untrusted provider adapter behind a hard gate plus an opaque shim that this
repository intentionally does not ship.  When no grant exists the path is
inert: no adapter is called, no provider handle is created, and no ticket
leaks an execution socket.

A run is refused (never silently allowed) when:

- there is no grant for ``(executor_kind, claimed_image, host)``,
- the grant is revoked,
- the run spec does not bind the exact immutable owner grant identity,
- the image digest is unset or does not equal the grant pin,
- a run is already active for the same workspace (single-in-flight), or
- the lease cannot be created or persisted.

The lease governs the run: a worker must renew it before ``lease_expires_at``;
an expired lease fails the run closed (recorded ``expired``), never silently
releases it.  A revocation observed at any checkpoint terminates the run.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import secrets
import threading
from typing import Any, Callable, Mapping, TypeVar

from runtime_contracts import RunLease

from .run_authority import RunAuthority, RunAuthorityError
from .run_lease import RunLeaseController, RunLeaseError, WorkspaceFileLease

_T = TypeVar("_T")


class RunLifecycleError(RuntimeError):
    """The lifecycle refused to start, renew, or complete a run."""


class RunRefused(RunLifecycleError):
    """A run attempt was refused by the authority or the single-flight gate."""


class RunAdapterUnavailable(RunLifecycleError):
    """The requested provider adapter is not shipped and stays quarantined."""


@dataclass(frozen=True)
class RunTicket:
    """Typed handle returned only after authority and lease validation.

    Deliberately carries no provider handle, token, socket path, or raw adapter
    config.  ``claim_path`` is the on-disk authority claim file for the typed
    ``lease``; ``grant_id`` names the owner grant that authorized it.
    """

    run_id: str
    workspace_id: str
    executor_kind: str
    image_digest: str
    grant_id: str
    authority_grant_digest: str
    started_at: str
    claim_path: str
    lease_expires_at: str
    lease: RunLease


def _now(clock: datetime | None) -> datetime:
    moment = clock if clock is not None else datetime.now(timezone.utc)
    if not isinstance(moment, datetime) or moment.tzinfo is None or moment.utcoffset() is None:
        raise RunLifecycleError("run clock must be timezone-aware")
    return moment.astimezone(timezone.utc)


def _stamp(moment: datetime) -> str:
    return _now(moment).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _atomic_write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(6)}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _require_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise RunRefused(f"{name} is not a valid identifier")
    return value


class ManagedAdapter:
    """Opaque provider-run caller invoked behind the authority gate.

    ``run`` receives only the validated run spec and the typed lease; it never
    receives a raw provider config, and neither input carries a secret, socket,
    or handle.  ``managed_adapter_for`` refuses to resolve one while the
    provider package stays quarantined.
    """

    def run(
        self,
        spec: Mapping[str, Any],
        *,
        lease: RunLease,
        provider: Any = None,
    ) -> Mapping[str, Any]:
        raise RunAdapterUnavailable("no shipped managed adapter exists")


def managed_adapter_for(executor_kind: str) -> ManagedAdapter:
    """Return a managed adapter for a provider kind, or refuse to resolve one.

    The quarantine is ACTIVE for every provider kind: no local-process
    provider adapter is shipped.  Managed execution resolves only through
    the execution host (ephemeral, digest-pinned agent container behind a
    provisioned grant and a run-bound provider gateway), never through a
    caller-supplied local adapter.  Every kind therefore refuses closed
    until such a managed executor is pinned for it.
    """
    if not isinstance(executor_kind, str) or not executor_kind:
        raise RunAdapterUnavailable("executor_kind is invalid")
    raise RunAdapterUnavailable(
        f"no managed adapter shipped for executor_kind={executor_kind}; "
        "managed runs resolve only through the execution-host managed-run path"
    )


class AgentRunLifecycle:
    """Single-in-flight, authority-gated lifecycle for managed agent runs."""

    def __init__(self, authority: RunAuthority, *, state_dir: Path | str, lease_duration_seconds: int = 900) -> None:
        if not isinstance(authority, RunAuthority):
            raise RunLifecycleError("lifecycle requires a typed RunAuthority")
        self._authority = authority
        self._state_dir = Path(state_dir)
        self._leases_dir = self._state_dir / "leases"
        self._leases_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self._leases_dir, 0o700)
        if isinstance(lease_duration_seconds, bool) or not isinstance(lease_duration_seconds, int) or lease_duration_seconds <= 0:
            raise RunLifecycleError("lease_duration_seconds must be a positive integer")
        self._lease_duration = lease_duration_seconds
        self._lock_files: dict[str, WorkspaceFileLease] = {}
        self._lock_files_lock = threading.Lock()
        self._lease_state_lock = threading.RLock()
        self._controller = RunLeaseController(self._leases_dir)

    @property
    def state_dir(self) -> Path:
        return self._state_dir

    def _persist_lease(self, lease: RunLease) -> None:
        with self._lease_state_lock:
            _atomic_write_json(Path(lease.to_dict()["claimPath"]), lease.to_dict())

    def _lease_state(self, ticket: RunTicket) -> str:
        return self._read_lease(ticket).to_dict()["state"]

    def _read_lease(self, ticket: RunTicket) -> RunLease:
        with self._lease_state_lock:
            path = Path(ticket.claim_path)
            if not path.is_file():
                raise RunLifecycleError("lease claim is missing")
            try:
                return RunLease.from_dict(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, ValueError) as exc:
                raise RunLifecycleError("lease claim is invalid") from exc

    def _lock_path(self, workspace_id: str) -> Path:
        return self._leases_dir / f"workspace-{workspace_id}.lock"

    def _acquire_workspace_lock(self, workspace_id: str, claim_path: str) -> None:
        lease = WorkspaceFileLease(self._lock_path(workspace_id))
        try:
            lease.acquire()
        except RunLeaseError as exc:
            if str(exc) == "workspace_lease_busy":
                raise RunRefused("run_single_in_flight") from None
            raise RunRefused("run_lease_lock_failed") from None
        with self._lock_files_lock:
            self._lock_files[claim_path] = lease

    def _release_workspace_lock_path(self, claim_path: str) -> None:
        with self._lock_files_lock:
            lease = self._lock_files.pop(claim_path, None)
        if lease is None:
            return
        lease.release()

    def _release_workspace_lock(self, ticket: RunTicket) -> None:
        self._release_workspace_lock_path(ticket.claim_path)

    def _workspace_lock_is_held(self, workspace_id: str) -> bool:
        try:
            return WorkspaceFileLease.is_held(self._lock_path(workspace_id))
        except RunLeaseError as exc:
            raise RunLifecycleError("run lease lock could not be inspected") from exc

    def active_for(self, workspace_id: str) -> str | None:
        workspace_id = _require_id(workspace_id, "workspaceId")
        for claim_path in sorted(self._leases_dir.glob("lease.*.json")):
            try:
                lease = RunLease.from_dict(json.loads(claim_path.read_text(encoding="utf-8")))
            except (OSError, ValueError) as exc:
                raise RunLifecycleError("lease claim is invalid") from exc
            data = lease.to_dict()
            if data["workspaceId"] == workspace_id and data["state"] in {"granted", "renewed"}:
                if self._workspace_lock_is_held(workspace_id):
                    return data["runId"]
        return None

    def is_active(self, workspace_id: str) -> bool:
        return self.active_for(workspace_id) is not None

    def _assert_granted(
        self,
        *,
        grant_id: str,
        image_digest: str,
        authority_grant_digest: str,
    ) -> None:
        try:
            self._authority.assert_live(
                grant_id,
                image_digest=image_digest,
                authority_grant_digest=authority_grant_digest,
            )
        except RunAuthorityError as exc:
            raise RunRefused(str(exc)) from exc

    def begin_run(
        self,
        spec: Mapping[str, Any],
        *,
        executor_kind: str,
        claimed_image: str,
        host: str,
        clock: datetime | None = None,
    ) -> RunTicket:
        required = {"runId", "workspaceId", "imageDigest", "authorityGrantDigest"}
        if not isinstance(spec, Mapping) or not required.issubset(spec):
            raise RunRefused("run spec is incomplete")
        run_id = _require_id(spec["runId"], "runId")
        workspace_id = _require_id(spec["workspaceId"], "workspaceId")
        image_digest = spec.get("imageDigest")
        if not isinstance(image_digest, str):
            raise RunRefused("run_authority_digest_unset")
        authority_grant_digest = spec.get("authorityGrantDigest")
        if not isinstance(authority_grant_digest, str):
            raise RunRefused("run_authority_grant_identity_unset")

        start = _now(clock)
        started_at = _stamp(start)
        expires_at = _stamp(start + timedelta(seconds=self._lease_duration))
        try:
            grant = self._authority.authorize(
                executor_kind=executor_kind,
                claimed_image=claimed_image,
                host=host,
                image_digest=image_digest,
                authority_grant_digest=authority_grant_digest,
            )
        except RunAuthorityError as exc:
            raise RunRefused(str(exc)) from exc

        lease_id = "lease." + secrets.token_hex(12)
        claim_path = str(self._leases_dir / f"{lease_id}.json")
        try:
            self._acquire_workspace_lock(workspace_id, claim_path)
            lease = RunLease.from_dict(
                {
                    "formatVersion": RunLease.FORMAT,
                    "leaseId": lease_id,
                    "runId": run_id,
                    "workspaceId": workspace_id,
                    "executorKind": _require_id(executor_kind, "executor_kind"),
                    "imageDigest": image_digest,
                    "claimPath": claim_path,
                    "startedAt": started_at,
                    "expiresAt": expires_at,
                    "state": "granted",
                }
            )
            self._persist_lease(lease)
        except RunRefused:
            self._release_workspace_lock_path(claim_path)
            raise
        except Exception:
            self._release_workspace_lock_path(claim_path)
            raise RunRefused("run_lease_persist_failed") from None
        return RunTicket(
            run_id=run_id,
            workspace_id=workspace_id,
            executor_kind=executor_kind,
            image_digest=image_digest,
            grant_id=grant.grant_id,
            authority_grant_digest=authority_grant_digest,
            started_at=started_at,
            claim_path=claim_path,
            lease_expires_at=expires_at,
            lease=lease,
        )

    def is_expired(self, ticket: RunTicket, *, clock: datetime | None = None) -> bool:
        return _now(clock) >= _parse(ticket.lease_expires_at)

    def assert_live(self, ticket: RunTicket, *, clock: datetime | None = None) -> RunTicket:
        """Refuse unless authority and the persisted lease are live now."""
        with self._lease_state_lock:
            self._assert_granted(
                grant_id=ticket.grant_id,
                image_digest=ticket.image_digest,
                authority_grant_digest=ticket.authority_grant_digest,
            )
            if self.is_expired(ticket, clock=clock):
                raise RunRefused("run_lease_expired")
            state = self._lease_state(ticket)
            if state not in {"granted", "renewed"}:
                raise RunRefused(f"run_lease_{state}")
            return ticket

    def perform_if_live(
        self,
        ticket: RunTicket,
        *,
        effect: Callable[[], _T],
        clock: datetime | None = None,
    ) -> _T:
        """Perform one activation effect while lease and authority stay live."""
        if not callable(effect):
            raise RunRefused("run activation effect must be callable")
        with self._lease_state_lock:
            self.assert_live(ticket, clock=clock)
            return self._authority.perform_if_live(
                ticket.grant_id,
                image_digest=ticket.image_digest,
                authority_grant_digest=ticket.authority_grant_digest,
                effect=effect,
            )

    def renew_lease(self, ticket: RunTicket, *, clock: datetime | None = None) -> RunTicket:
        with self._lease_state_lock:
            self._assert_granted(
                grant_id=ticket.grant_id,
                image_digest=ticket.image_digest,
                authority_grant_digest=ticket.authority_grant_digest,
            )
            renew_clock = _now(clock)
            if renew_clock >= _parse(ticket.lease_expires_at):
                self._fail_expired(ticket)
                raise RunRefused("run_lease_expired")
            state = self._lease_state(ticket)
            if state in {"expired", "released", "revoked"}:
                raise RunRefused(f"run_lease_{state}")
            new_expires = _stamp(renew_clock + timedelta(seconds=self._lease_duration))
            current = self._read_lease(ticket)
            base = RunLease.from_dict({**current.to_dict(), "expiresAt": new_expires})
            lease = self._controller.renew(base)
            self._persist_lease(lease)
            return RunTicket(
                run_id=ticket.run_id,
                workspace_id=ticket.workspace_id,
                executor_kind=ticket.executor_kind,
                image_digest=ticket.image_digest,
                grant_id=ticket.grant_id,
                authority_grant_digest=ticket.authority_grant_digest,
                started_at=ticket.started_at,
                claim_path=ticket.claim_path,
                lease_expires_at=new_expires,
                lease=lease,
            )

    def _fail_expired(self, ticket: RunTicket) -> None:
        with self._lease_state_lock:
            current = self._read_lease(ticket)
            expired = self._controller.expire(current)
            try:
                self._persist_lease(expired)
            finally:
                self._release_workspace_lock(ticket)

    def fail_if_expired(self, ticket: RunTicket, *, clock: datetime | None = None) -> RunTicket:
        with self._lease_state_lock:
            if self.is_expired(ticket, clock=clock):
                self._fail_expired(ticket)
                raise RunRefused("run_lease_expired")
            return ticket

    def revoke_run(self, ticket: RunTicket) -> RunTicket:
        with self._lease_state_lock:
            current = self._read_lease(ticket)
            revoked = self._controller.force_release(current)
            try:
                self._persist_lease(revoked)
            finally:
                self._release_workspace_lock(ticket)
            return ticket

    def revoked_during_run(self, ticket: RunTicket) -> bool:
        grant = self._authority.grant(ticket.grant_id)
        return grant is None or grant.revoked

    def cancel(self, ticket: RunTicket) -> RunTicket:
        """Release a not-yet-finished run as cancelled; idempotent on repeat.

        A run cancelled here is never recorded as a success.  The lease state
        settles to ``released`` (or stays ``revoked``/``expired``); the
        ``cancelled`` outcome is recorded at run-evidence level.
        """
        with self._lease_state_lock:
            current = self._read_lease(ticket)
            if current.to_dict()["state"] in {"released", "expired", "revoked"}:
                self._release_workspace_lock(ticket)
                return ticket
            released = self._controller.cancel(current)
            try:
                self._persist_lease(released)
            finally:
                self._release_workspace_lock(ticket)
            return ticket

    def release(self, ticket: RunTicket) -> RunTicket:
        with self._lease_state_lock:
            current = self._read_lease(ticket)
            released = self._controller.release(current)
            try:
                self._persist_lease(released)
            finally:
                self._release_workspace_lock(ticket)
            return ticket

    def invoke(
        self,
        ticket: RunTicket,
        adapter: ManagedAdapter,
        spec: Mapping[str, Any],
        *,
        provider: Any = None,
        clock: datetime | None = None,
    ) -> Mapping[str, Any]:
        """Call the adapter only behind a hard, re-verified authority gate.

        The grant is re-checked and the lease must be live and unexpired before
        the adapter is reached.  A revoked grant, a lapsed lease, or an
        untyped adapter refuses before any contact; a ``ManagedAdapter`` that
        is not shipped raises closed.  ``provider`` is the opaque run-bound
        binding handle, never a secret; it is resolved by the engine, used by
        the adapter, and revoked when the run ends.
        """
        try:
            self._assert_granted(
                grant_id=ticket.grant_id,
                image_digest=ticket.image_digest,
                authority_grant_digest=ticket.authority_grant_digest,
            )
            self.fail_if_expired(ticket, clock=clock)
            if not isinstance(adapter, ManagedAdapter):
                raise RunRefused("run_adapter_is_not_typed")
            return adapter.run(spec, lease=ticket.lease, provider=provider)
        except (RunRefused, RunAdapterUnavailable, RunLifecycleError):
            raise
        except Exception as exc:
            raise RunAdapterUnavailable(f"run adapter failed closed: {type(exc).__name__}") from exc

    @property
    def authority(self) -> RunAuthority:
        return self._authority


__all__ = [
    "AgentRunLifecycle",
    "ManagedAdapter",
    "RunAdapterUnavailable",
    "RunLifecycleError",
    "RunRefused",
    "RunTicket",
    "managed_adapter_for",
]
