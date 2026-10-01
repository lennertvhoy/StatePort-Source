"""Typed, instance-scoped authority that gates every managed agent run.

A ``RunAuthority`` holds owner-released grants keyed by the exact execution
triplet ``(executor_kind, claimed_image, host)``.  A run is permitted only
when every binding holds:

- the requested ``executor_kind`` is granted,
- the claimed image reference matches the grant's claimed image,
- the run's image digest equals the grant's pinned digest (never unset,
  never a suffix guess),
- the host matches,
- the grant is not revoked.

The authority fails closed.  A missing grant, a revoked grant, a digest that
is absent or mismatched, or any internal error refuses the run; it never
defaults to allow.  This module holds no provider handle, no socket path, and
no secret, so nothing here can leak an execution path.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
import threading
from typing import Callable, Mapping, TypeVar


_IMAGE_REFERENCE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HOST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_AUTHORITY_FORMAT = "stateport.run-authority-grant/v1"
_T = TypeVar("_T")


class RunAuthorityError(RuntimeError):
    """A run request could not be authorized; nothing was started."""


def _require_id(value, name: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise RunAuthorityError(f"{name} is not a valid identifier")
    return value


def _require_string(value, name: str, *, limit: int = 1024) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise RunAuthorityError(f"{name} must be a bounded non-empty string")
    return value


def _require_digest(value, name: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise RunAuthorityError(f"{name} must be a pinned sha256 digest")
    return value


@dataclass(frozen=True)
class RunGrant:
    """One owner-released authorization to run a managed agent.

    The grant is keyed by ``(executor_kind, claimed_image, host)`` and pins the
    exact image digest it will ever authorize.  ``scope`` is a bounded,
    owner-written description of what the grant is for; it never contains a
    credential or a socket path.  Revocation is monotonic: a revoked grant can
    never be un-revoked.
    """

    grant_id: str
    executor_kind: str
    claimed_image: str
    host: str
    scope: str
    issued_at: str
    digest_pin: str
    revoked: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "grant_id", _require_id(self.grant_id, "grant_id"))
        object.__setattr__(self, "executor_kind", _require_id(self.executor_kind, "executor_kind"))
        object.__setattr__(self, "claimed_image", _require_image_reference(self.claimed_image))
        object.__setattr__(self, "host", _require_id(self.host, "host"))
        object.__setattr__(self, "scope", _require_string(self.scope, "scope"))
        object.__setattr__(self, "issued_at", _require_string(self.issued_at, "issued_at"))
        object.__setattr__(self, "digest_pin", _require_digest(self.digest_pin, "digest_pin"))

    def key(self) -> tuple[str, str, str]:
        return (self.executor_kind, self.claimed_image, self.host)

    @property
    def authority_digest(self) -> str:
        """Bind every immutable authorization field, excluding revocation."""
        identity = {
            "formatVersion": _AUTHORITY_FORMAT,
            "grantId": self.grant_id,
            "executorKind": self.executor_kind,
            "claimedImage": self.claimed_image,
            "host": self.host,
            "scope": self.scope,
            "issuedAt": self.issued_at,
            "digestPin": self.digest_pin,
        }
        canonical = json.dumps(
            identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _require_image_reference(value) -> str:
    if not isinstance(value, str) or _IMAGE_REFERENCE.fullmatch(value) is None:
        raise RunAuthorityError("claimed_image must be a digest-pinned image reference")
    return value


class RunAuthority:
    """Owner-owned grant store with fail-closed authorization checks."""

    def __init__(self, *, host: str) -> None:
        _require_id(host, "host")
        self._host = host
        self._grants: dict[tuple[str, str, str], RunGrant] = {}
        self._by_id: dict[str, RunGrant] = {}
        self._lock = threading.RLock()

    @property
    def host(self) -> str:
        return self._host

    def register(self, grant: RunGrant) -> None:
        """Register an owner-released grant for this authority host.

        The grant's host must equal the authority's host, and a grant id may
        only ever map to one key.  Re-registering the same grant is a no-op;
        registering a different grant under the same id is refused.
        """
        if not isinstance(grant, RunGrant):
            raise RunAuthorityError("a grant must be a typed RunGrant")
        if grant.host != self._host:
            raise RunAuthorityError("grant host does not match the authority host")
        with self._lock:
            existing = self._by_id.get(grant.grant_id)
            if existing is not None and existing.authority_digest != grant.authority_digest:
                raise RunAuthorityError("grant id is already bound to another authorization")
            keyed = self._grants.get(grant.key())
            if keyed is not None and keyed.grant_id != grant.grant_id:
                raise RunAuthorityError("execution key is already bound to another grant id")
            if existing is not None and existing.revoked and not grant.revoked:
                raise RunAuthorityError("a revoked grant cannot be reactivated")
            self._grants[grant.key()] = grant
            self._by_id[grant.grant_id] = grant

    def revoke(self, grant_id: str) -> None:
        """Revoke a grant by id; revocation is monotonic and never re-opens."""
        with self._lock:
            grant = self._by_id.get(_require_id(grant_id, "grant_id"))
            if grant is None or grant.revoked:
                return
            self._grants[grant.key()] = RunGrant(**{**grant.__dict__, "revoked": True})
            self._by_id[grant.grant_id] = self._grants[grant.key()]

    def lookup(self, *, executor_kind: str, claimed_image: str, host: str) -> RunGrant | None:
        key = (
            _require_id(executor_kind, "executor_kind"),
            _require_image_reference(claimed_image),
            _require_id(host, "host"),
        )
        with self._lock:
            return self._grants.get(key)

    def grant(self, grant_id: str) -> RunGrant | None:
        with self._lock:
            return self._by_id.get(_require_id(grant_id, "grant_id"))

    def is_revoked(self, grant_id: str) -> bool:
        with self._lock:
            grant = self._by_id.get(_require_id(grant_id, "grant_id"))
            return grant is None or grant.revoked

    def assert_live(
        self,
        grant_id: str,
        *,
        image_digest: str,
        authority_grant_digest: str,
    ) -> RunGrant:
        """Return the exact live grant or refuse an unverifiable binding."""
        with self._lock:
            return self._assert_live_locked(
                grant_id,
                image_digest=image_digest,
                authority_grant_digest=authority_grant_digest,
            )

    def _assert_live_locked(
        self,
        grant_id: str,
        *,
        image_digest: str,
        authority_grant_digest: str,
    ) -> RunGrant:
        grant = self._by_id.get(_require_id(grant_id, "grant_id"))
        if grant is None:
            raise RunAuthorityError("run_authority_grant_revoked")
        if grant.authority_digest != _require_digest(
            authority_grant_digest, "authority_grant_digest"
        ):
            raise RunAuthorityError("run_authority_grant_identity_mismatch")
        if grant.revoked:
            raise RunAuthorityError("run_authority_grant_revoked")
        if image_digest != grant.digest_pin:
            raise RunAuthorityError("run_authority_digest_mismatch")
        return grant

    def perform_if_live(
        self,
        grant_id: str,
        *,
        image_digest: str,
        authority_grant_digest: str,
        effect: Callable[[], _T],
    ) -> _T:
        """Perform one activation effect atomically with local revocation.

        Revocation waits for an already-admitted effect. A revoke that wins
        the lock first refuses the effect, and a re-entrant withdrawal is
        detected before the result is returned.
        """
        if not callable(effect):
            raise RunAuthorityError("run activation effect must be callable")
        with self._lock:
            self._assert_live_locked(
                grant_id,
                image_digest=image_digest,
                authority_grant_digest=authority_grant_digest,
            )
            result = effect()
            self._assert_live_locked(
                grant_id,
                image_digest=image_digest,
                authority_grant_digest=authority_grant_digest,
            )
            return result

    def authorize(
        self,
        *,
        executor_kind: str,
        claimed_image: str,
        host: str,
        image_digest: str | None,
        authority_grant_digest: str,
    ) -> RunGrant:
        """Authorize one run attempt or refuse it with a typed error.

        Every failure raises ``RunAuthorityError`` with a stable reason; the
        caller must treat any exception as a refusal.  A grant is only
        effective when the image digest is present, pinned, and equal -- an
        unset or mismatched digest always refuses even when a grant exists.
        """
        with self._lock:
            try:
                grant = self.lookup(
                    executor_kind=executor_kind,
                    claimed_image=claimed_image,
                    host=host,
                )
            except RunAuthorityError:
                raise RunAuthorityError("run authorization is not addressable on this host") from None
            if grant is None:
                raise RunAuthorityError("run_authority_no_grant")
            if grant.authority_digest != _require_digest(
                authority_grant_digest, "authority_grant_digest"
            ):
                raise RunAuthorityError("run_authority_grant_identity_mismatch")
            if grant.revoked:
                raise RunAuthorityError("run_authority_grant_revoked")
            if not isinstance(image_digest, str) or _DIGEST.fullmatch(image_digest) is None:
                raise RunAuthorityError("run_authority_digest_unset")
            if image_digest != grant.digest_pin:
                raise RunAuthorityError("run_authority_digest_mismatch")
            return grant

    def grants(self) -> tuple[RunGrant, ...]:
        with self._lock:
            return tuple(self._by_id.values())


__all__ = ["RunAuthority", "RunAuthorityError", "RunGrant"]
