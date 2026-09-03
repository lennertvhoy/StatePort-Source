"""A small, deterministic continuation state machine for blocked CI.

This module deliberately has one provider: :class:`FakeCIProvider`.  It is an
in-memory test double and cannot perform GitHub or other remote writes.  The
state machine records remote-CI claims separately from human decisions; an
exact-head override is never represented as ``CI_PASSED``.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Final, Sequence


_FULL_SHA: Final = re.compile(r"^[0-9a-f]{40}$")
_REPOSITORY: Final = re.compile(r"^[^/\s]+/[^/\s]+$")


class StateMachineError(ValueError):
    """Base error for invalid continuation inputs or transitions."""


class BindingMismatchError(StateMachineError):
    """An action or provider observation was for a different PR/head."""


class InvalidTransitionError(StateMachineError):
    """The requested action is not valid in the current state."""


class StaleAuthorizationError(StateMachineError):
    """A human authorization no longer matches the current state revision."""


class ProviderContractError(StateMachineError):
    """The fake provider returned an impossible or mismatched observation."""


class ContinuationState(str, Enum):
    PR_READY = "PR_READY"
    CI_RUNNING = "CI_RUNNING"
    CI_PASSED = "CI_PASSED"
    CI_FAILED = "CI_FAILED"
    CI_BLOCKED_EXTERNAL = "CI_BLOCKED_EXTERNAL"
    AWAITING_HUMAN_DECISION = "AWAITING_HUMAN_DECISION"
    CANCELLED = "CANCELLED"
    EXACT_HEAD_OVERRIDE_APPROVED = "EXACT_HEAD_OVERRIDE_APPROVED"


class CIStatus(str, Enum):
    RUNNING = "RUNNING"
    PASSED = "PASSED"
    FAILED = "FAILED"
    BLOCKED_EXTERNAL = "BLOCKED_EXTERNAL"


class AuthorizationDecision(str, Enum):
    RETRY = "retry"
    CANCEL = "cancel"
    EXACT_HEAD_OVERRIDE = "exact_head_override"


@dataclass(frozen=True)
class ExactHeadBinding:
    """The immutable repository, PR number, and commit identity."""

    repository: str
    pr_number: int
    head_sha: str

    def __post_init__(self) -> None:
        if not isinstance(self.repository, str) or not _REPOSITORY.fullmatch(self.repository):
            raise ValueError("repository must be an exact owner/name value")
        if not isinstance(self.pr_number, int) or isinstance(self.pr_number, bool) or self.pr_number < 1:
            raise ValueError("pr_number must be a positive integer")
        if not isinstance(self.head_sha, str) or not _FULL_SHA.fullmatch(self.head_sha):
            raise ValueError("head_sha must be a lowercase full 40-character commit SHA")

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository": self.repository,
            "prNumber": self.pr_number,
            "headSha": self.head_sha,
        }


@dataclass(frozen=True)
class CIObservation:
    """One fake-provider observation, always bound to the exact head."""

    run_id: str
    binding: ExactHeadBinding
    status: CIStatus
    detail: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, str) or not self.run_id.strip():
            raise ValueError("run_id is required")
        if not isinstance(self.status, CIStatus):
            raise ValueError("status must be a CIStatus")
        if not isinstance(self.detail, str):
            raise ValueError("detail must be a string")

    def to_dict(self) -> dict[str, Any]:
        return {
            "runId": self.run_id,
            **self.binding.to_dict(),
            "status": self.status.value,
            "detail": self.detail,
        }


class FakeCIProvider:
    """Deterministic in-memory CI provider used only by tests.

    ``outcomes`` is consumed in order for one exact binding.  The provider has
    no network, subprocess, Git, or GitHub integration by design.
    """

    provider_id = "fake-ci-provider"

    def __init__(self, outcomes: Sequence[CIStatus | str]) -> None:
        if not outcomes:
            raise ValueError("at least one fake CI outcome is required")
        parsed: list[CIStatus] = []
        for outcome in outcomes:
            try:
                parsed.append(outcome if isinstance(outcome, CIStatus) else CIStatus(outcome))
            except (TypeError, ValueError) as exc:
                raise ValueError(f"invalid fake CI outcome: {outcome!r}") from exc
        if parsed[0] is not CIStatus.RUNNING:
            raise ValueError("the first fake CI outcome must be RUNNING")
        self._outcomes = tuple(parsed)
        self._binding: ExactHeadBinding | None = None
        self._run_id: str | None = None
        self._next_index = 0
        self._run_number = 0
        self.calls: list[tuple[str, str, ExactHeadBinding]] = []

    def start(self, binding: ExactHeadBinding) -> str:
        if self._binding is not None and self._binding != binding:
            raise BindingMismatchError("fake provider is already bound to a different repository/PR/head")
        if self._next_index >= len(self._outcomes) or self._outcomes[self._next_index] is not CIStatus.RUNNING:
            raise ProviderContractError("each fake CI attempt must start with a RUNNING outcome")
        self._binding = binding
        self._run_number += 1
        self._run_id = f"fake-run-{self._run_number:03d}"
        self._next_index += 1
        self.calls.append(("start", self._run_id, binding))
        return self._run_id

    def poll(self, run_id: str, binding: ExactHeadBinding) -> CIObservation:
        if self._binding != binding:
            raise BindingMismatchError("fake provider poll binding does not match the exact head")
        if self._run_id != run_id:
            raise ProviderContractError("unknown fake provider run id")
        if self._next_index >= len(self._outcomes):
            raise ProviderContractError("fake provider outcome script is exhausted")
        status = self._outcomes[self._next_index]
        self._next_index += 1
        self.calls.append(("poll", run_id, binding))
        return CIObservation(run_id, binding, status)


@dataclass(frozen=True)
class DecisionRequest:
    request_id: str
    binding: ExactHeadBinding
    state: ContinuationState
    revision: int
    allowed_decisions: tuple[AuthorizationDecision, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "requestId": self.request_id,
            **self.binding.to_dict(),
            "state": self.state.value,
            "revision": self.revision,
            "allowedDecisions": [decision.value for decision in self.allowed_decisions],
        }


@dataclass(frozen=True)
class HumanAuthorization:
    authorization_id: str
    request_id: str
    binding: ExactHeadBinding
    decision: AuthorizationDecision
    issued_revision: int
    actor: str

    def __post_init__(self) -> None:
        if not self.authorization_id.strip() or not self.request_id.strip():
            raise ValueError("authorization_id and request_id are required")
        if not self.actor.strip():
            raise ValueError("actor is required")

    def to_dict(self) -> dict[str, Any]:
        return {
            "authorizationId": self.authorization_id,
            "requestId": self.request_id,
            **self.binding.to_dict(),
            "decision": self.decision.value,
            "issuedRevision": self.issued_revision,
            "actor": self.actor,
        }


@dataclass(frozen=True)
class AuditRecord:
    sequence: int
    action: str
    from_state: ContinuationState | None
    to_state: ContinuationState
    revision: int
    binding: ExactHeadBinding
    actor: str
    data: dict[str, Any]
    previous_hash: str
    hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "action": self.action,
            "fromState": self.from_state.value if self.from_state else None,
            "toState": self.to_state.value,
            "revision": self.revision,
            **self.binding.to_dict(),
            "actor": self.actor,
            "data": self.data,
            "previousHash": self.previous_hash,
            "hash": self.hash,
        }


class WorkflowContinuation:
    """Own the blocked-CI continuation lifecycle for one exact PR head."""

    def __init__(self, binding: ExactHeadBinding, provider: FakeCIProvider) -> None:
        if not isinstance(provider, FakeCIProvider):
            raise TypeError("only FakeCIProvider is supported; remote providers are out of scope")
        self.binding = binding
        self.provider = provider
        self.state = ContinuationState.PR_READY
        self.revision = 0
        self.attempt = 0
        self.run_id: str | None = None
        self._audit: list[AuditRecord] = []
        self._decision_number = 0
        self._consumed_authorizations: set[str] = set()
        self._record(
            action="created",
            from_state=None,
            to_state=self.state,
            actor="system",
            data={"provider": provider.provider_id, "remoteCiPassed": False},
        )

    @property
    def audit(self) -> tuple[AuditRecord, ...]:
        return tuple(self._audit)

    @property
    def remote_ci_passed(self) -> bool:
        """Always false: this slice has no remote provider or remote write."""

        return False

    def start_ci(self, binding: ExactHeadBinding, *, actor: str = "system") -> CIObservation:
        self._assert_binding(binding)
        if self.state is not ContinuationState.PR_READY:
            raise InvalidTransitionError("CI may start only from PR_READY")
        self.attempt += 1
        self.run_id = self.provider.start(self.binding)
        self._transition(
            action="ci_started",
            to_state=ContinuationState.CI_RUNNING,
            actor=actor,
            data={"attempt": self.attempt, "runId": self.run_id, "provider": self.provider.provider_id},
        )
        return CIObservation(self.run_id, self.binding, CIStatus.RUNNING)

    def poll_ci(self, binding: ExactHeadBinding, *, actor: str = "system") -> CIObservation:
        self._assert_binding(binding)
        if self.state is not ContinuationState.CI_RUNNING or self.run_id is None:
            raise InvalidTransitionError("CI may be polled only from CI_RUNNING")
        observation = self.provider.poll(self.run_id, self.binding)
        if observation.binding != self.binding or observation.run_id != self.run_id:
            raise ProviderContractError("fake provider observation is not bound to the active exact head")
        target = {
            CIStatus.RUNNING: ContinuationState.CI_RUNNING,
            CIStatus.PASSED: ContinuationState.CI_PASSED,
            CIStatus.FAILED: ContinuationState.CI_FAILED,
            CIStatus.BLOCKED_EXTERNAL: ContinuationState.CI_BLOCKED_EXTERNAL,
        }[observation.status]
        self._transition(
            action="ci_observed",
            to_state=target,
            actor=actor,
            data={
                "attempt": self.attempt,
                "runId": self.run_id,
                "provider": self.provider.provider_id,
                "providerStatus": observation.status.value,
                "remoteCiPassed": False,
            },
        )
        return observation

    def await_human(self, binding: ExactHeadBinding, *, actor: str = "system") -> DecisionRequest:
        self._assert_binding(binding)
        if self.state not in {ContinuationState.CI_FAILED, ContinuationState.CI_BLOCKED_EXTERNAL}:
            raise InvalidTransitionError("human decision is available only after failed or externally blocked CI")
        self._transition(
            action="awaiting_human_decision",
            to_state=ContinuationState.AWAITING_HUMAN_DECISION,
            actor=actor,
            data={"attempt": self.attempt, "runId": self.run_id},
        )
        self._decision_number += 1
        return DecisionRequest(
            request_id=f"decision-{self._decision_number:03d}",
            binding=self.binding,
            state=self.state,
            revision=self.revision,
            allowed_decisions=(
                AuthorizationDecision.RETRY,
                AuthorizationDecision.CANCEL,
                AuthorizationDecision.EXACT_HEAD_OVERRIDE,
            ),
        )

    def authorize(
        self,
        request: DecisionRequest,
        decision: AuthorizationDecision | str,
        *,
        actor: str,
    ) -> HumanAuthorization:
        if self.state is not ContinuationState.AWAITING_HUMAN_DECISION:
            raise StaleAuthorizationError("decision request is no longer current")
        self._assert_binding(request.binding)
        if request.revision != self.revision or request.state is not self.state:
            raise StaleAuthorizationError("decision request revision is stale")
        try:
            parsed = decision if isinstance(decision, AuthorizationDecision) else AuthorizationDecision(decision)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"unsupported human decision: {decision!r}") from exc
        if parsed not in request.allowed_decisions:
            raise ValueError("human decision is not allowed by the current request")
        if not isinstance(actor, str) or not actor.strip():
            raise ValueError("actor is required")
        authorization = HumanAuthorization(
            authorization_id=f"authorization-{self._decision_number:03d}-{parsed.value}",
            request_id=request.request_id,
            binding=self.binding,
            decision=parsed,
            issued_revision=self.revision,
            actor=actor,
        )
        self._record(
            action="human_authorized",
            from_state=self.state,
            to_state=self.state,
            actor=actor,
            data={"authorization": authorization.to_dict()},
        )
        return authorization

    def apply_authorization(self, binding: ExactHeadBinding, authorization: HumanAuthorization) -> None:
        self._assert_binding(binding)
        self._validate_authorization(authorization)
        self._consumed_authorizations.add(authorization.authorization_id)
        if authorization.decision is AuthorizationDecision.RETRY:
            self.attempt += 1
            self.run_id = self.provider.start(self.binding)
            self._transition(
                action="retry",
                to_state=ContinuationState.CI_RUNNING,
                actor=authorization.actor,
                data={"attempt": self.attempt, "runId": self.run_id, "provider": self.provider.provider_id},
            )
        elif authorization.decision is AuthorizationDecision.CANCEL:
            self._transition(
                action="cancel",
                to_state=ContinuationState.CANCELLED,
                actor=authorization.actor,
                data={"reason": "human authorization", "remoteCiPassed": False},
            )
        else:
            self._transition(
                action="exact_head_override",
                to_state=ContinuationState.EXACT_HEAD_OVERRIDE_APPROVED,
                actor=authorization.actor,
                data={
                    "authorizationId": authorization.authorization_id,
                    "remoteCiPassed": False,
                    "note": "human override is not a CI pass",
                },
            )

    def retry(self, binding: ExactHeadBinding, authorization: HumanAuthorization) -> None:
        """Apply a retry authorization and start the next fake CI attempt."""

        if authorization.decision is not AuthorizationDecision.RETRY:
            raise InvalidTransitionError("authorization is not a retry decision")
        self.apply_authorization(binding, authorization)

    def cancel(self, binding: ExactHeadBinding, authorization: HumanAuthorization) -> None:
        """Apply a cancellation authorization."""

        if authorization.decision is not AuthorizationDecision.CANCEL:
            raise InvalidTransitionError("authorization is not a cancel decision")
        self.apply_authorization(binding, authorization)

    def exact_head_override(self, binding: ExactHeadBinding, authorization: HumanAuthorization) -> None:
        """Apply an exact-head override without converting it into a CI pass."""

        if authorization.decision is not AuthorizationDecision.EXACT_HEAD_OVERRIDE:
            raise InvalidTransitionError("authorization is not an exact-head override decision")
        self.apply_authorization(binding, authorization)

    def snapshot(self) -> dict[str, Any]:
        return {
            "binding": self.binding.to_dict(),
            "state": self.state.value,
            "revision": self.revision,
            "attempt": self.attempt,
            "runId": self.run_id,
            "provider": self.provider.provider_id,
            "remoteCiPassed": self.remote_ci_passed,
            "auditLength": len(self._audit),
            "auditHead": self._audit[-1].hash,
        }

    def verify_audit(self) -> bool:
        previous = "genesis"
        for sequence, event in enumerate(self._audit, start=1):
            if event.sequence != sequence or event.previous_hash != previous:
                return False
            payload = self._audit_payload(event)
            expected = "sha256:" + hashlib.sha256(self._canonical(payload)).hexdigest()
            if event.hash != expected:
                return False
            previous = event.hash
        return True

    def _assert_binding(self, binding: ExactHeadBinding) -> None:
        if binding != self.binding:
            raise BindingMismatchError(
                "repository, PR number, and head SHA must match the exact continuation binding"
            )

    def _validate_authorization(self, authorization: HumanAuthorization) -> None:
        if self.state is not ContinuationState.AWAITING_HUMAN_DECISION:
            raise StaleAuthorizationError("authorization is no longer usable in the current state")
        if authorization.authorization_id in self._consumed_authorizations:
            raise StaleAuthorizationError("authorization has already been consumed")
        if authorization.binding != self.binding:
            raise StaleAuthorizationError("authorization is bound to a different repository/PR/head")
        if authorization.issued_revision != self.revision:
            raise StaleAuthorizationError("authorization revision is stale")
        if not isinstance(authorization.decision, AuthorizationDecision):
            raise StaleAuthorizationError("authorization decision is invalid")
        expected_prefix = f"authorization-{self._decision_number:03d}-"
        if not authorization.authorization_id.startswith(expected_prefix):
            raise StaleAuthorizationError("authorization was issued for an older decision request")

    def _transition(
        self,
        *,
        action: str,
        to_state: ContinuationState,
        actor: str,
        data: dict[str, Any],
    ) -> None:
        from_state = self.state
        self.revision += 1
        self.state = to_state
        self._record(action=action, from_state=from_state, to_state=to_state, actor=actor, data=data)

    def _record(
        self,
        *,
        action: str,
        from_state: ContinuationState | None,
        to_state: ContinuationState,
        actor: str,
        data: dict[str, Any],
    ) -> None:
        sequence = len(self._audit) + 1
        previous = self._audit[-1].hash if self._audit else "genesis"
        event = AuditRecord(
            sequence=sequence,
            action=action,
            from_state=from_state,
            to_state=to_state,
            revision=self.revision,
            binding=self.binding,
            actor=actor,
            data=json.loads(json.dumps(data, sort_keys=True)),
            previous_hash=previous,
            hash="",
        )
        digest = hashlib.sha256(self._canonical(self._audit_payload(event))).hexdigest()
        self._audit.append(
            AuditRecord(
                sequence=event.sequence,
                action=event.action,
                from_state=event.from_state,
                to_state=event.to_state,
                revision=event.revision,
                binding=event.binding,
                actor=event.actor,
                data=event.data,
                previous_hash=event.previous_hash,
                hash="sha256:" + digest,
            )
        )

    @staticmethod
    def _canonical(value: Any) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _audit_payload(event: AuditRecord) -> dict[str, Any]:
        return {
            "sequence": event.sequence,
            "action": event.action,
            "fromState": event.from_state.value if event.from_state else None,
            "toState": event.to_state.value,
            "revision": event.revision,
            **event.binding.to_dict(),
            "actor": event.actor,
            "data": event.data,
            "previousHash": event.previous_hash,
        }
