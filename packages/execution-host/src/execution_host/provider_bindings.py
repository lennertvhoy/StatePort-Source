"""Owner-owned provider configuration boundary for managed agent runs.

``ProviderBindingManager`` maps an owner-owned provider configuration to a run
without ever persisting the provider secret:

- provider references are held as an opaque ``config_id``, never the token,
- the token itself is read, when needed, from a runtime environment that is
  separate from the run lease, and the manager hands callers a
  ``ProviderBindingHandle`` -- an opaque handle, not a raw config blob,
- a run binds by grafting the handle only while the typed authority grant is
  valid, and the token is never materialized into ``RunEvidence`` or any
  receipt.

The manager fails closed.  A bind without a valid grant, a bind for an
unconfigured provider, or a resolution that cannot find the token raises and
never yields a usable handle.  ``RunEvidenceService`` finalizes evidence: a
finish whose grant was revoked, or an evidence for a provider that was never
used by the run, is refused -- never a success.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import os
import re
import threading
from typing import Any, Callable, Mapping

from runtime_contracts import RunEvidence, canonical_digest

_SECRET = re.compile(
    r"(?:api[_-]?key|authorization|cookie|credential|password|secret|"
    r"access[_-]?token|refresh[_-]?token|private[_-]?key)",
    re.I,
)
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_CHILD_ENVIRONMENT_KEYS = frozenset({"PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TERM"})


def scrubbed_environment(env: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return the small non-secret environment permitted for a child.

    Provider resolution remains an owner/provider-side operation through the
    typed binding handle.  It is never implemented by copying the owner
    environment into an agent process.
    """

    source = os.environ if env is None else env
    return {
        key: value
        for key, value in source.items()
        if key in _CHILD_ENVIRONMENT_KEYS and isinstance(value, str)
    }


@dataclass(frozen=True)
class ProcessIdentity:
    """Token-free identity of the real executed agent process.

    ``argv_digest`` is the canonical digest of the fixed, non-interpolated
    command array that was actually launched, so an evidence record binds a
    real executed ``argv`` without reprinting it, and without any secret.
    """

    executor_kind: str
    argv_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "executor_kind", _require_id(self.executor_kind, "executor_kind"))
        object.__setattr__(self, "argv_digest", self._require_digest(self.argv_digest))

    @staticmethod
    def _require_digest(value: Any) -> str:
        if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
            raise ProviderBindError("process argv digest must be a pinned sha256 digest")
        return value

    @staticmethod
    def of_argv(executor_kind: str, argv: tuple[str, ...]) -> "ProcessIdentity":
        if not argv or any(not isinstance(item, str) or "\x00" in item for item in argv):
            raise ProviderBindError("process argv must be a bounded non-empty string array")
        return ProcessIdentity(executor_kind=executor_kind, argv_digest=canonical_digest(list(argv)))


class ProviderBindError(RuntimeError):
    """A provider binding could not be created; the run must fail closed."""


class ProviderSecretUnavailable(ProviderBindError):
    """The provider token could not be resolved; the run must fail closed."""


def _require_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ProviderBindError(f"{name} is not a valid identifier")
    return value


def _normalize_executed_process(value: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize a real executed-process record into evidence-safe fields.

    Only the observable, token-free identity is kept: executor kind, the real
    pid (local execution) or the daemon-observed container workload identity
    (managed container execution), the process exit code, duration in whole
    seconds, and the output digest.  The argv itself and every credential are
    deliberately dropped.
    """
    if not isinstance(value, Mapping):
        raise ProviderBindError("executed process must be a mapping")
    required = {"executor", "exitCode", "digestOfOutput"}
    if not required.issubset(value):
        raise ProviderBindError("executed process identity is incomplete")
    executor = _require_id(value["executor"], "executed process.executor")
    pid = value.get("pid")
    container_workload_id = value.get("containerWorkloadId")
    if pid is None and container_workload_id is None:
        raise ProviderBindError("executed process must bind a real pid or a container workload id")
    if pid is not None and (isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0):
        raise ProviderBindError("executed process pid must be a real positive integer")
    exit_code = value["exitCode"]
    if isinstance(exit_code, bool) or not isinstance(exit_code, int):
        raise ProviderBindError("executed process exitCode must be an integer")
    digest = value["digestOfOutput"]
    if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
        raise ProviderBindError("executed process output digest must be pinned")
    duration = value.get("durationSeconds", 0)
    if isinstance(duration, bool) or not isinstance(duration, int) or duration < 0:
        raise ProviderBindError("executed process duration must be a non-negative integer")
    normalized: dict[str, Any] = {
        "executor": executor,
        "pid": pid,
        "exitCode": exit_code,
        "durationSeconds": duration,
        "digestOfOutput": digest,
    }
    if container_workload_id is not None:
        normalized["containerWorkloadId"] = _require_id(
            container_workload_id, "executed process.containerWorkloadId"
        )
    observed_image = value.get("observedImageDigest")
    if observed_image is not None:
        if not isinstance(observed_image, str) or _DIGEST.fullmatch(observed_image) is None:
            raise ProviderBindError("executed process observed image digest must be pinned")
        normalized["observedImageDigest"] = observed_image
    return normalized


@dataclass(frozen=True)
class ProviderConfigRef:
    """Opaque, token-free description of one owner-owned provider."""

    config_id: str
    provider: str
    model: str
    token_env: str
    process_identity: ProcessIdentity | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "config_id", _require_id(self.config_id, "config_id"))
        object.__setattr__(self, "provider", _require_id(self.provider, "provider"))
        object.__setattr__(self, "model", _require_id(self.model, "model"))
        object.__setattr__(self, "token_env", _require_id(self.token_env, "token_env"))
        if _SECRET.search(self.token_env):
            raise ProviderBindError("provider token environment name is suspicious")
        if self.process_identity is not None and not isinstance(self.process_identity, ProcessIdentity):
            raise ProviderBindError("process identity must be typed")


class ProviderBindingHandle:
    """Opaque handle; the token is never stored on this object.

    ``token()`` reads from the owner-owned runtime environment only at call
    time, so the secret is never attached to the handle, persisted, or
    serialized into evidence or receipts.
    """

    __slots__ = ("_config_id", "_reader", "_revoked", "_lock")

    def __init__(self, config_id: str, reader: Callable[[], str]) -> None:
        self._config_id = _require_id(config_id, "config_id")
        self._reader = reader
        self._revoked = False
        self._lock = threading.Lock()

    @property
    def config_id(self) -> str:
        return self._config_id

    def token(self) -> str:
        with self._lock:
            if self._revoked:
                raise ProviderSecretUnavailable("provider binding was revoked; run fails closed")
            value = self._reader()
        if not value or not isinstance(value, str):
            raise ProviderSecretUnavailable("provider token is unavailable; run fails closed")
        return value

    def revoke(self) -> None:
        """Revoke only this run-bound handle, leaving owner config reusable."""
        with self._lock:
            self._revoked = True

    @property
    def revoked(self) -> bool:
        with self._lock:
            return self._revoked

    def __repr__(self) -> str:
        return f"ProviderBindingHandle(config_id={self._config_id!r})"


class _ProcessBoundHandle(ProviderBindingHandle):
    """A binding that also carries the token-free executed process identity."""

    __slots__ = ("_process_identity",)

    def __init__(self, config_id: str, reader: Callable[[], str], process_identity: ProcessIdentity) -> None:
        super().__init__(config_id, reader)
        self._process_identity = process_identity

    @property
    def process_identity(self) -> ProcessIdentity:
        return self._process_identity


class ProviderBindingManager:
    """Config registry + token boundary; never stores a provider secret."""

    def __init__(self, env: Mapping[str, str] | None = None) -> None:
        self._env = dict(os.environ if env is None else env)
        self._configs: dict[str, ProviderConfigRef] = {}
        self._lock = threading.RLock()

    def define_config(self, config_id: str, *, provider: str, model: str, token_env: str, process_identity: ProcessIdentity | None = None) -> str:
        ref = ProviderConfigRef(config_id=config_id, provider=provider, model=model, token_env=token_env, process_identity=process_identity)
        with self._lock:
            existing = self._configs.get(ref.config_id)
            if existing is not None and existing != ref:
                raise ProviderBindError("config_id is already bound to another provider")
            self._configs[ref.config_id] = ref
        return ref.config_id

    def configured(self, config_id: str) -> bool:
        with self._lock:
            return _require_id(config_id, "config_id") in self._configs

    def config(self, config_id: str) -> ProviderConfigRef:
        """Return the immutable owner configuration or fail closed."""
        with self._lock:
            ref = self._configs.get(_require_id(config_id, "config_id"))
            if ref is None:
                raise ProviderBindError("provider_config_unavailable")
            return ref

    def bind(self, *, config_id: str, granted: bool) -> ProviderBindingHandle:
        """Bind a run to an owner provider only while the grant is valid.

        Refuses (fails closed) when the grant is not valid or the config is
        unknown.  Resolution of the token is deferred to handle call time,
        and a revoked binding fails closed at call time as well.
        """
        if not granted:
            raise ProviderBindError("provider_binding_grant_required")
        with self._lock:
            ref = self._configs.get(_require_id(config_id, "config_id"))
            if ref is None:
                raise ProviderBindError("provider_config_unavailable")
            reader = self._reader_for(ref)
            if ref.process_identity is not None:
                return _ProcessBoundHandle(ref.config_id, reader, ref.process_identity)
            return ProviderBindingHandle(ref.config_id, reader)

    def _reader_for(self, ref: "ProviderConfigRef") -> Callable[[], str]:
        def read() -> str:
            with self._lock:
                if self._configs.get(ref.config_id) != ref:
                    raise ProviderSecretUnavailable(
                        "provider configuration was removed or replaced; run fails closed"
                    )
                return self._env.get(ref.token_env, "")

        return read

    @staticmethod
    def revoke(handle: ProviderBindingHandle) -> None:
        """Revoke one run binding without deleting its reusable owner config."""
        if not isinstance(handle, ProviderBindingHandle):
            raise ProviderBindError("provider binding handle must be typed")
        handle.revoke()

    def remove_config(self, config_id: str) -> None:
        """Explicitly remove an owner configuration and invalidate its handles."""
        with self._lock:
            self._configs.pop(_require_id(config_id, "config_id"), None)

    def resolve_token(self, config_id: str) -> str:
        with self._lock:
            ref = self._configs.get(_require_id(config_id, "config_id"))
            if ref is None:
                raise ProviderBindError("provider_config_unavailable")
            value = self._env.get(ref.token_env, "")
            if not value:
                raise ProviderSecretUnavailable("provider token is unavailable; run fails closed")
            return value

    def configs(self) -> tuple[ProviderConfigRef, ...]:
        with self._lock:
            return tuple(self._configs.values())

    def child_environment(self) -> dict[str, str]:
        """Return an explicit secret-free environment for a provider child."""

        return scrubbed_environment(self._env)


class RunEvidenceService:
    """Finalize run evidence; revoked or unused-provider finishes are refused."""

    def __init__(self) -> None:
        self._used: set[tuple[str, str]] = set()
        self._finished: set[str] = set()
        self._lock = threading.Lock()

    def mark_provider_used(self, run_id: str, config_id: str) -> None:
        """Record one observed provider effect for this exact run/config pair."""
        key = (_require_id(run_id, "run_id"), _require_id(config_id, "config_id"))
        with self._lock:
            if key[0] in self._finished:
                raise ProviderBindError("run evidence is already finalized")
            self._used.add(key)

    def provider_used(self, run_id: str, config_id: str) -> bool:
        """Return whether this exact run/config pair observed an effect."""
        key = (_require_id(run_id, "run_id"), _require_id(config_id, "config_id"))
        with self._lock:
            return key in self._used

    def finish_evidence(
        self,
        *,
        run_id: str,
        workspace_id: str,
        executor_kind: str,
        image_digest: str,
        lease_id: str,
        started_at: str,
        ended_at: str,
        outcome: str,
        exit_reason: str,
        digest_of_output: str,
        config_id: str | None,
        grant_revoked: bool,
        provider_use_required: bool = True,
        executed_process: Mapping[str, Any] | None = None,
    ) -> RunEvidence:
        """Record the finished outcome, forcing ``refused`` when dishonest.

        A finish whose grant was revoked at finish is refused, never a success.
        Evidence for a provider config the run never used is also refused.  The
        returned ``RunEvidence`` carries no secret and no handle; ``executed_process``
        binds the real executed agent process (executor, pid, exit code,
        duration, and its own output digest) without ever printing its argv.
        """
        if not isinstance(digest_of_output, str) or _DIGEST.fullmatch(digest_of_output) is None:
            raise ProviderBindError("output digest must be a pinned sha256 digest")
        run_id = _require_id(run_id, "run_id")
        normalized_process = (
            _normalize_executed_process(executed_process)
            if executed_process is not None
            else None
        )
        if config_id is not None:
            config_id = _require_id(config_id, "config_id")
        if not isinstance(provider_use_required, bool):
            raise ProviderBindError("provider_use_required must be boolean")
        with self._lock:
            if run_id in self._finished:
                raise ProviderBindError("run evidence is already finalized")
            provider_used = config_id is not None and (run_id, config_id) in self._used
            if grant_revoked:
                outcome = "refused"
                exit_reason = "authority-grant-revoked"
            elif outcome == "completed" and provider_use_required and not provider_used:
                outcome = "refused"
                exit_reason = "provider-effect-unobserved"
            if outcome not in {"completed", "failed", "cancelled", "refused"}:
                raise ProviderBindError("run evidence outcome is invalid")
            if outcome == "completed" and normalized_process is not None:
                if normalized_process.get("observedImageDigest") != image_digest:
                    outcome = "failed"
                    exit_reason = "observed-image-identity-mismatch"
            if outcome != "completed" and exit_reason == "ok":
                exit_reason = outcome
            record: dict[str, Any] = {
                "formatVersion": RunEvidence.FORMAT,
                "runId": run_id,
                "workspaceId": workspace_id,
                "executorKind": executor_kind,
                "imageDigest": image_digest,
                "startedAt": started_at,
                "endedAt": ended_at,
                "outcome": outcome,
                "exitReason": exit_reason,
                "digestOfOutput": digest_of_output,
                "leaseId": lease_id,
            }
            if normalized_process is not None:
                record["executedProcess"] = normalized_process
            evidence = RunEvidence.from_dict(record)
            self._finished.add(run_id)
            self._used = {item for item in self._used if item[0] != run_id}
            return evidence

    @staticmethod
    def evidence_digest(evidence: RunEvidence) -> str:
        """Recompute the evidence digest purely from the evidence fields."""
        return evidence.digest

    @staticmethod
    def decision_digest(fields: Mapping[str, Any]) -> str:
        """Digest of the final decision fields; contains no secret by design."""
        from runtime_contracts import canonical_digest

        return canonical_digest(fields)


__all__ = [
    "ProcessIdentity",
    "ProviderBindingHandle",
    "ProviderBindingManager",
    "ProviderBindError",
    "ProviderConfigRef",
    "ProviderSecretUnavailable",
    "RunEvidenceService",
    "scrubbed_environment",
]
