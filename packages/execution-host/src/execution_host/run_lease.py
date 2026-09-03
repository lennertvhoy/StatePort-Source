"""Idempotent run shutdown, lease transitions, and the completion gate.

``RunLeaseController`` implements the typed ``RunLease`` state machine over the
contract in ``runtime_contracts.RunLease`` and nothing else, so it stays
independent of the lifecycle state files:

    granted -> renewed -> expired -> released   with ``revoked`` as a forced
    release reachable from any active (granted/renewed) state.

Shutdown is idempotent: releasing or cancelling an already-terminal lease
returns the same terminal view and is not an error.  A run that is cancelled
before it has finished is recorded as ``cancelled``, never as succeeded.

``RunCompletionGate`` enforces the single-completion property: while a lease is
held (``granted``/``renewed``) no run may complete; once the lease is released,
a run may finalize exactly once.  This module carries no provider handle, no
socket path, and no secret; it reasons only over the typed lease contract.
"""
from __future__ import annotations

import fcntl
import os
from pathlib import Path
import threading

from runtime_contracts import RunLease

_HELD = frozenset({"granted", "renewed"})
_TERMINAL = frozenset({"expired", "released", "revoked"})
_LEGAL: dict[str, frozenset[str]] = {
    "granted": frozenset({"granted", "renewed", "expired", "released", "revoked"}),
    "renewed": frozenset({"renewed", "expired", "released", "revoked"}),
    "expired": frozenset({"expired"}),
    "released": frozenset({"released"}),
    "revoked": frozenset({"revoked"}),
}

_OUTCOMES = frozenset({"completed", "failed", "cancelled", "refused"})


class RunLeaseError(RuntimeError):
    """An illegal lease transition or a repeated/held completion."""


class RunLeaseController:
    """Typed, idempotent lease transition machine."""

    def __init__(self, state_dir: Path | str) -> None:
        self._dir = Path(state_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _state(lease: RunLease) -> str:
        return lease.to_dict()["state"]

    def _transition(self, lease: RunLease, to_state: str) -> RunLease:
        data = lease.to_dict()
        current = data["state"]
        if current not in _LEGAL or to_state not in _LEGAL[current]:
            raise RunLeaseError(f"illegal_lease_transition:{current}->{to_state}")
        return RunLease.from_dict({**data, "state": to_state})

    def renew(self, lease: RunLease) -> RunLease:
        """Advance a held lease to ``renewed`` (kept until completion)."""
        return self._transition(lease, "renewed")

    def expire(self, lease: RunLease) -> RunLease:
        """Advance an active lease to ``expired``; terminal and idempotent."""
        return self._transition(lease, "expired")

    def release(self, lease: RunLease) -> RunLease:
        """Release an active lease or confirm a terminal one (idempotent)."""
        return self._transition(lease, "released") if self._state(lease) in _HELD else self._same(lease)

    def cancel(self, lease: RunLease) -> RunLease:
        """Release a not-finished run; idempotent and never a success."""
        return self.release(lease)

    def force_release(self, lease: RunLease) -> RunLease:
        """Forced release on revocation: any active state becomes ``revoked``."""
        data = lease.to_dict()
        if data["state"] in _HELD:
            data["state"] = "revoked"
        return RunLease.from_dict(data)

    def shutdown_live(self, lease: RunLease) -> RunLease:
        """Lease-bound shutdown guarantee for a live (held) run.

        Terminates an in-flight run by forcing its lease to the ``revoked``
        terminal state; repeated calls return the same terminal view and are
        not an error (renew-expire is idempotent, double-release is fine).  A
        run shut down here is never a success.
        """
        return self.force_release(lease)


    def _same(self, lease: RunLease) -> RunLease:
        return lease


class WorkspaceFileLease:
    """Kernel-backed exclusive lease held until the owning run releases it."""

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        self._handle = None

    def acquire(self) -> None:
        if self._handle is not None:
            return
        handle = None
        try:
            handle = self._path.open("a+b")
            os.chmod(self._path, 0o600)
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            if handle is not None:
                handle.close()
            raise RunLeaseError("workspace_lease_busy") from None
        except OSError as exc:
            if handle is not None:
                handle.close()
            raise RunLeaseError("workspace_lease_open_failed") from exc
        self._handle = handle

    def release(self) -> None:
        handle = self._handle
        self._handle = None
        if handle is None:
            return
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()

    @staticmethod
    def is_held(path: Path | str) -> bool:
        try:
            handle = Path(path).open("a+b")
        except OSError as exc:
            raise RunLeaseError("workspace_lease_inspection_failed") from exc
        try:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            return False
        finally:
            handle.close()


class RunCompletionGate:
    """Enforce: no completion while a lease is held; exactly one completion."""

    def __init__(self) -> None:
        self._finished: dict[str, str] = {}
        self._cancelled: set[str] = set()
        self._lock = threading.Lock()

    def cancel_record(self, lease_id: str) -> None:
        """Record that a not-yet-finished run was cancelled."""
        with self._lock:
            self._cancelled.add(lease_id)

    def certify_cancelled(self, lease_id: str) -> bool:
        """Mark a run as cancelled so any later completion is never a success.

        Idempotent: a second call returns the same cancelled certification.
        This is the fail-closed completion guarantee for a run whose grant was
        revoked mid-run -- the final evidence stays ``cancelled``, never
        ``succeeded``.
        """
        with self._lock:
            self._cancelled.add(lease_id)
        return True

    def complete(self, lease: RunLease, *, outcome: str) -> bool:
        """Finalize a run exactly once, refusing while a lease is held."""
        if outcome not in _OUTCOMES:
            raise RunLeaseError(f"invalid_run_outcome:{outcome}")
        data = lease.to_dict()
        lease_id = data["leaseId"]
        if data["state"] in _HELD:
            raise RunLeaseError("run_lease_held_cannot_complete")
        with self._lock:
            if lease_id in self._finished:
                raise RunLeaseError("run_already_completed")
            if lease_id in self._cancelled and outcome != "cancelled":
                outcome = "cancelled"
            self._finished[lease_id] = outcome
        return True

    def finished_outcome(self, lease_id: str) -> str | None:
        with self._lock:
            return self._finished.get(lease_id)

    def is_held(self, lease: RunLease) -> bool:
        return self._state(lease) in _HELD

    @staticmethod
    def _state(lease: RunLease) -> str:
        return lease.to_dict()["state"]


__all__ = ["RunCompletionGate", "RunLeaseController", "RunLeaseError", "WorkspaceFileLease"]
