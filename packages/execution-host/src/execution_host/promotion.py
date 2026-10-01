"""StatePort-authoritative promotion transaction and durable receipts.

Only lookup-based public methods can mutate a workspace.  Approval, validator
evidence, revision, and diff bindings are observed while both workspace locks
are held, bound into a durable pre-mutation intent, and revalidated immediately
before and after Git mutation.  Intent and receipt files are published from a
complete fsynced temporary file with a no-replace hard-link CAS.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import threading
from typing import Any, Callable, Iterator, Mapping

from runtime_contracts import PromotionReceipt, PromotionSpec, canonical_digest

from .workspace_revisions import (
    WorkspaceIdentity,
    WorkspaceRevisionError,
    WorkspaceRevisionTracker,
)


ROLLBACK_POINT_FORMAT = "stateport.rollback-point/v1"
RECEIPT_FORMAT = PromotionReceipt.FORMAT
INTENT_FORMAT = "stateport.promotion-intent/v1"
_MAX_RECORD_BYTES = 1024 * 1024
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

_workspace_locks: dict[str, threading.Lock] = {}
_workspace_locks_guard = threading.Lock()


def _workspace_lock(workspace_id: str) -> threading.Lock:
    with _workspace_locks_guard:
        lock = _workspace_locks.get(workspace_id)
        if lock is None:
            lock = threading.Lock()
            _workspace_locks[workspace_id] = lock
        return lock


class PromotionError(RuntimeError):
    """Promotion state is conflicting, corrupt, ambiguous, or unsafe."""


def _utc_timestamp(moment: datetime) -> str:
    if not isinstance(moment, datetime) or moment.tzinfo is None or moment.utcoffset() is None:
        raise PromotionError("promotion clock must be timezone-aware")
    return moment.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _json_bytes(payload: Mapping[str, Any]) -> bytes:
    try:
        return (json.dumps(dict(payload), indent=2, sort_keys=True) + "\n").encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PromotionError("promotion record is not JSON serializable") from exc


def _read_record_bytes(path: Path, label: str) -> bytes:
    try:
        if path.is_symlink() or not path.is_file():
            raise PromotionError(f"{label} is missing or unsafe")
        if path.stat().st_size > _MAX_RECORD_BYTES:
            raise PromotionError(f"{label} is oversized")
        return path.read_bytes()
    except PromotionError:
        raise
    except OSError as exc:
        raise PromotionError(f"{label} is unreadable") from exc


def _read_json(path: Path, label: str) -> dict[str, Any]:
    raw = _read_record_bytes(path, label)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PromotionError(f"{label} is malformed JSON") from exc
    if not isinstance(value, dict):
        raise PromotionError(f"{label} must contain a JSON object")
    return value


def _atomic_write_json(path: Path, payload: Mapping[str, Any]) -> None:
    """Write replaceable content-addressed support state atomically."""

    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temporary: Path | None = path.with_name(
        f".{path.name}.{os.getpid()}.{secrets.token_hex(6)}.tmp"
    )
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(_json_bytes(payload))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        _fsync_directory(path.parent)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _publish_json_cas(path: Path, payload: Mapping[str, Any], label: str) -> bool:
    """Publish complete bytes with hard-link CAS; return whether this call won."""

    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    expected = _json_bytes(payload)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(6)}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    published = False
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(expected)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            existing = _read_record_bytes(path, label)
            if existing != expected:
                raise PromotionError(f"{label} already exists with different content") from None
            return False
        except OSError as exc:
            raise PromotionError(f"{label} CAS publication failed") from exc
        published = True
        _fsync_directory(path.parent)
        os.unlink(temporary)
        temporary = None
        _fsync_directory(path.parent)
        return True
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass
        if published and not path.exists():
            raise PromotionError(f"{label} CAS publication was lost")


def _immutable_record(value: Mapping[str, Any] | None, label: str) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise PromotionError(f"{label} lookup returned a non-object record")
    try:
        frozen = json.loads(json.dumps(dict(value), sort_keys=True, separators=(",", ":")))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PromotionError(f"{label} lookup returned a non-JSON record") from exc
    if not isinstance(frozen, dict):
        raise PromotionError(f"{label} lookup returned a non-object record")
    return frozen


def _safe_identifier(value: Any, fallback: str) -> str:
    candidate = str(value) if value is not None else fallback
    return candidate if _IDENTIFIER.fullmatch(candidate) else fallback


def _safe_digest(value: Any, label: str) -> str:
    candidate = str(value) if value is not None else ""
    if _DIGEST.fullmatch(candidate):
        return candidate
    return canonical_digest({"invalid": label, "value": candidate})


@dataclass(frozen=True)
class PromotionObservations:
    """Normalized evidence observed from StatePort-owned stores and Git."""

    current_revision: str
    diff_digest: str
    validator_evidence_digest: str
    validator_id: str
    validator_status: str
    approval_id: str
    approval_status: str
    approval_actor: str
    approval_bound_candidate_id: str
    approval_bound_spec_digest: str


@dataclass(frozen=True)
class _AuthoritativeSnapshot:
    observations: PromotionObservations
    approval_record_digest: str
    validator_record_digest: str
    authority_binding_digest: str


class PromotionService:
    """Record rollback points and perform authoritative, crash-safe promotion."""

    def __init__(self, state_dir: Path | str) -> None:
        self._state_dir = Path(state_dir)
        self._receipts_dir = self._state_dir / "promotions"
        self._rollback_dir = self._state_dir / "rollback-points"
        self._intents_dir = self._state_dir / "promotion-intents"
        for directory in (self._receipts_dir, self._rollback_dir, self._intents_dir):
            directory.mkdir(parents=True, exist_ok=True)
            os.chmod(directory, 0o700)

    @property
    def state_dir(self) -> Path:
        return self._state_dir

    def _receipt_path(self, promotion_id: str) -> Path:
        return self._receipts_dir / f"{promotion_id}.json"

    def _rollback_path(self, digest: str) -> Path:
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            raise PromotionError("rollback point digest is invalid")
        return self._rollback_dir / f"{digest.split(':', 1)[1]}.json"

    def _intent_path(self, promotion_id: str) -> Path:
        return self._intents_dir / f"{promotion_id}.json"

    @contextmanager
    def _locked_workspace(self, workspace_id: str) -> Iterator[None]:
        lock = _workspace_lock(workspace_id)
        if not lock.acquire(blocking=False):
            raise PromotionError("promotion_in_progress")
        lock_file: int | None = None
        try:
            locks_dir = self._receipts_dir / ".locks"
            locks_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(locks_dir, 0o700)
            try:
                lock_file = os.open(
                    locks_dir / f"{workspace_id}.lock",
                    os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise PromotionError("promotion_in_progress") from None
            try:
                yield
            finally:
                fcntl.flock(lock_file, fcntl.LOCK_UN)
        finally:
            if lock_file is not None:
                os.close(lock_file)
            lock.release()

    def record_rollback_point(
        self,
        *,
        workspace_id: str,
        pre_promotion_revision: str,
        observed_at: str,
    ) -> dict[str, Any]:
        body = {
            "formatVersion": ROLLBACK_POINT_FORMAT,
            "workspaceId": workspace_id,
            "prePromotionRevision": pre_promotion_revision,
        }
        digest = canonical_digest(body)
        record = {**body, "recordedAt": observed_at, "rollbackPointDigest": digest}
        path = self._rollback_path(digest)
        if path.is_file():
            existing = _read_json(path, "rollback point")
            if existing.get("rollbackPointDigest") != digest:
                raise PromotionError("rollback point store is inconsistent")
            record = existing
        else:
            _atomic_write_json(path, record)
        return dict(record)

    def verify_rollback_point(self, digest: str) -> dict[str, Any] | None:
        path = self._rollback_path(digest)
        if not path.is_file():
            return None
        record = _read_json(path, "rollback point")
        body = {
            "formatVersion": ROLLBACK_POINT_FORMAT,
            "workspaceId": record.get("workspaceId"),
            "prePromotionRevision": record.get("prePromotionRevision"),
        }
        if canonical_digest(body) != digest or record.get("rollbackPointDigest") != digest:
            return None
        return dict(record)

    def load_receipt(self, promotion_id: str) -> dict[str, Any] | None:
        path = self._receipt_path(promotion_id)
        if not path.is_file():
            return None
        receipt = _read_json(path, f"promotion receipt {promotion_id}")
        try:
            validated = PromotionReceipt.from_dict(receipt).to_dict()
        except (TypeError, ValueError) as exc:
            raise PromotionError(f"promotion receipt {promotion_id} is malformed or corrupt") from exc
        if validated["promotionId"] != promotion_id or not self.verify_receipt_digest(validated):
            raise PromotionError(
                f"promotion receipt {promotion_id} failed identity or digest recomputation"
            )
        return validated

    @staticmethod
    def verify_receipt_digest(receipt: Mapping[str, Any]) -> bool:
        body = {key: value for key, value in receipt.items() if key != "receiptDigest"}
        return canonical_digest(body) == receipt.get("receiptDigest")

    def is_promoted(self, promotion_id: str) -> bool:
        receipt = self.load_receipt(promotion_id)
        return bool(receipt and receipt["promotionDecision"]["decision"] == "promoted")

    def _record_intent(self, promotion_id: str, intent: Mapping[str, Any]) -> dict[str, Any]:
        path = self._intent_path(promotion_id)
        created = _publish_json_cas(path, intent, f"promotion intent {promotion_id}")
        existing = dict(intent) if created else _read_json(path, f"promotion intent {promotion_id}")
        if existing != dict(intent):
            raise PromotionError(
                f"promotion intent {promotion_id} already exists with different content"
            )
        return existing

    def _load_intent(self, promotion_id: str) -> dict[str, Any] | None:
        path = self._intent_path(promotion_id)
        if not path.is_file():
            return None
        intent = _read_json(path, f"promotion intent {promotion_id}")
        expected_keys = {
            "formatVersion",
            "promotionId",
            "workspaceId",
            "specDigest",
            "expectedBaseRevision",
            "candidateRevision",
            "approvalRecordDigest",
            "validatorRecordDigest",
            "authorityBindingDigest",
            "workspacePathDigest",
            "repositoryIdentityDigest",
            "observedAt",
        }
        if set(intent) != expected_keys or intent.get("formatVersion") != INTENT_FORMAT:
            raise PromotionError(f"promotion intent {promotion_id} has an invalid format")
        for name in (
            "specDigest",
            "approvalRecordDigest",
            "validatorRecordDigest",
            "authorityBindingDigest",
            "workspacePathDigest",
            "repositoryIdentityDigest",
        ):
            if not isinstance(intent.get(name), str) or not _DIGEST.fullmatch(intent[name]):
                raise PromotionError(f"promotion intent {promotion_id} has an invalid {name}")
        for name in ("promotionId", "workspaceId"):
            if not isinstance(intent.get(name), str) or not _IDENTIFIER.fullmatch(intent[name]):
                raise PromotionError(f"promotion intent {promotion_id} has an invalid {name}")
        for name in ("expectedBaseRevision", "candidateRevision"):
            value = intent.get(name)
            if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}", value) is None:
                raise PromotionError(f"promotion intent {promotion_id} has an invalid {name}")
        observed_at = intent.get("observedAt")
        if (
            not isinstance(observed_at, str)
            or not observed_at.strip()
            or len(observed_at) > 64
        ):
            raise PromotionError(f"promotion intent {promotion_id} has an invalid observedAt")
        return intent

    @staticmethod
    def _snapshot(
        spec_data: Mapping[str, Any],
        *,
        spec_digest: str,
        observe_revision: Callable[[], str],
        load_approval: Callable[[str], Mapping[str, Any] | None],
        load_validator_evidence: Callable[[str], Mapping[str, Any] | None],
        compute_diff_digest: Callable[[str, str], str],
    ) -> _AuthoritativeSnapshot:
        try:
            current_revision = observe_revision()
            approval = _immutable_record(
                load_approval(spec_data["approvalId"]), "approval"
            )
            evidence = _immutable_record(
                load_validator_evidence(spec_data["validatorEvidenceDigest"]),
                "validator evidence",
            )
            observed_diff = compute_diff_digest(
                spec_data["expectedBaseRevision"], spec_data["candidateRevision"]
            )
        except PromotionError:
            raise
        except Exception as exc:
            raise PromotionError(
                f"authoritative promotion lookup failed: {type(exc).__name__}"
            ) from exc

        if approval is None:
            approval_record: dict[str, Any] = {
                "unavailableApprovalId": spec_data["approvalId"]
            }
            approval_id = spec_data["approvalId"]
            approval_status = "pending"
            approval_actor = "unknown"
            approval_bound = "unknown"
            approval_bound_spec = "unknown"
        else:
            approval_record = approval
            approval_id = _safe_identifier(approval.get("approvalId"), spec_data["approvalId"])
            approval_status = str(approval.get("status") or "pending")
            if approval_status not in {"approved", "rejected", "cancelled", "pending"}:
                approval_status = "pending"
            approval_actor = _safe_identifier(approval.get("actor"), "unknown")
            approval_bound = _safe_identifier(approval.get("boundCandidateId"), "unknown")
            approval_bound_spec = str(approval.get("boundSpecDigest") or "unknown")

        if evidence is None:
            evidence_record: dict[str, Any] = {
                "unavailableEvidenceDigest": spec_data["validatorEvidenceDigest"]
            }
            evidence_digest = canonical_digest(evidence_record)
            validator_id = "unknown"
            validator_status = "unknown"
        else:
            evidence_record = evidence
            evidence_digest = _safe_digest(evidence.get("evidenceDigest"), "validator evidence")
            validator_id = _safe_identifier(evidence.get("validatorId"), "unknown")
            validator_status = str(
                evidence.get("classification") or evidence.get("status") or "unknown"
            )
        diff_digest = _safe_digest(observed_diff, "candidate diff")
        approval_record_digest = canonical_digest(approval_record)
        validator_record_digest = canonical_digest(evidence_record)
        authority_binding_digest = canonical_digest(
            {
                "specDigest": spec_digest,
                "approvalRecordDigest": approval_record_digest,
                "validatorRecordDigest": validator_record_digest,
                "diffDigest": diff_digest,
            }
        )
        return _AuthoritativeSnapshot(
            observations=PromotionObservations(
                current_revision=current_revision,
                diff_digest=diff_digest,
                validator_evidence_digest=evidence_digest,
                validator_id=validator_id,
                validator_status=validator_status,
                approval_id=approval_id,
                approval_status=approval_status,
                approval_actor=approval_actor,
                approval_bound_candidate_id=approval_bound,
                approval_bound_spec_digest=approval_bound_spec,
            ),
            approval_record_digest=approval_record_digest,
            validator_record_digest=validator_record_digest,
            authority_binding_digest=authority_binding_digest,
        )

    @staticmethod
    def authoritative_observations(
        spec_data: Mapping[str, Any],
        *,
        spec_digest: str,
        observe_revision: Callable[[], str],
        load_approval: Callable[[str], Mapping[str, Any] | None],
        load_validator_evidence: Callable[[str], Mapping[str, Any] | None],
        compute_diff_digest: Callable[[str, str], str],
    ) -> PromotionObservations:
        return PromotionService._snapshot(
            spec_data,
            spec_digest=spec_digest,
            observe_revision=observe_revision,
            load_approval=load_approval,
            load_validator_evidence=load_validator_evidence,
            compute_diff_digest=compute_diff_digest,
        ).observations

    def observe_and_promote(
        self,
        spec: Mapping[str, Any],
        *,
        observe_revision: Callable[[], str],
        load_approval: Callable[[str], Mapping[str, Any] | None],
        load_validator_evidence: Callable[[str], Mapping[str, Any] | None],
        compute_diff_digest: Callable[[str, str], str],
        observed_at: str | None = None,
        clock: datetime | None = None,
    ) -> dict[str, Any]:
        promotion = PromotionSpec.from_dict(spec)
        observations = self.authoritative_observations(
            promotion.to_dict(),
            spec_digest=promotion.digest,
            observe_revision=observe_revision,
            load_approval=load_approval,
            load_validator_evidence=load_validator_evidence,
            compute_diff_digest=compute_diff_digest,
        )
        return self.promote(spec, observations=observations, observed_at=observed_at, clock=clock)

    @staticmethod
    def _binding_checks(
        spec_data: Mapping[str, Any],
        observations: PromotionObservations,
        rollback_record: Mapping[str, Any] | None,
        *,
        spec_digest: str,
    ) -> dict[str, bool]:
        return {
            "baseRevision": observations.current_revision == spec_data["expectedBaseRevision"],
            "approval": (
                observations.approval_id == spec_data["approvalId"]
                and observations.approval_status == "approved"
                and observations.approval_bound_candidate_id == spec_data["candidateId"]
                and observations.approval_bound_spec_digest == spec_digest
            ),
            "diffDigest": observations.diff_digest == spec_data["diffDigest"],
            "validatorEvidence": (
                observations.validator_evidence_digest == spec_data["validatorEvidenceDigest"]
                and observations.validator_status == "passed"
            ),
            "rollbackPoint": bool(
                rollback_record is not None
                and rollback_record.get("workspaceId") == spec_data["workspaceId"]
                and rollback_record.get("prePromotionRevision") == observations.current_revision
            ),
        }

    @staticmethod
    def _build_receipt(
        spec_data: Mapping[str, Any],
        observations: PromotionObservations,
        *,
        rollback_record: Mapping[str, Any] | None,
        checks: Mapping[str, bool],
        decision: str,
        reason: str,
        timestamp: str,
    ) -> dict[str, Any]:
        receipt_body: dict[str, Any] = {
            "formatVersion": RECEIPT_FORMAT,
            "promotionId": spec_data["promotionId"],
            "workspaceId": spec_data["workspaceId"],
            "candidateId": spec_data["candidateId"],
            "expectedBaseRevision": spec_data["expectedBaseRevision"],
            "candidateRevision": spec_data["candidateRevision"],
            "diffDigest": spec_data["diffDigest"],
            "validatorEvidenceDigest": spec_data["validatorEvidenceDigest"],
            "approvalId": spec_data["approvalId"],
            "rollbackPointDigest": spec_data["rollbackPointDigest"],
            "specDigest": spec_data["specDigest"],
            "observedAt": timestamp,
            "agentClaim": {
                "baseRevision": spec_data["expectedBaseRevision"],
                "diffDigest": spec_data["diffDigest"],
                "validatorEvidenceDigest": spec_data["validatorEvidenceDigest"],
            },
            "observedProcessResult": {
                "currentRevision": observations.current_revision,
                "diffDigest": observations.diff_digest,
                "baseRevisionMatched": checks["baseRevision"],
            },
            "validatorEvidence": {
                "evidenceDigest": observations.validator_evidence_digest,
                "validatorId": observations.validator_id,
                "evidenceMatched": checks["validatorEvidence"],
            },
            "approval": {
                "approvalId": observations.approval_id,
                "status": observations.approval_status,
                "actor": observations.approval_actor,
                "boundCandidateId": observations.approval_bound_candidate_id,
                "approvalMatched": checks["approval"],
            },
            "rollbackPoint": {
                "digest": spec_data["rollbackPointDigest"],
                "prePromotionRevision": (
                    rollback_record["prePromotionRevision"] if rollback_record else None
                ),
                "rollbackPointMatched": checks["rollbackPoint"],
            },
            "promotionDecision": {
                "decision": decision,
                "reason": reason,
                "checks": dict(checks),
            },
        }
        receipt = {**receipt_body, "receiptDigest": canonical_digest(receipt_body)}
        try:
            return PromotionReceipt.from_dict(receipt).to_dict()
        except (TypeError, ValueError) as exc:
            raise PromotionError("promotion receipt could not be constructed safely") from exc

    def _record_receipt(self, receipt: Mapping[str, Any]) -> dict[str, Any]:
        try:
            validated = PromotionReceipt.from_dict(receipt).to_dict()
        except (TypeError, ValueError) as exc:
            raise PromotionError("promotion receipt is invalid") from exc
        promotion_id = validated["promotionId"]
        path = self._receipt_path(promotion_id)
        created = _publish_json_cas(path, validated, f"promotion receipt {promotion_id}")
        if not created:
            stored = self.load_receipt(promotion_id)
            if stored != validated:
                raise PromotionError(
                    f"promotion receipt {promotion_id} already exists with different content"
                )
        return validated

    @staticmethod
    def _require_receipt_binding(
        receipt: Mapping[str, Any], spec_data: Mapping[str, Any], spec_digest: str
    ) -> None:
        expected = {
            "promotionId": spec_data["promotionId"],
            "workspaceId": spec_data["workspaceId"],
            "expectedBaseRevision": spec_data["expectedBaseRevision"],
            "candidateRevision": spec_data["candidateRevision"],
            "specDigest": spec_digest,
        }
        if any(receipt.get(name) != value for name, value in expected.items()):
            raise PromotionError(
                f"promotionId {spec_data['promotionId']} is bound to a different promotion spec"
            )

    @staticmethod
    def _require_intent_binding(
        intent: Mapping[str, Any],
        spec_data: Mapping[str, Any],
        spec_digest: str,
        identity: WorkspaceIdentity,
    ) -> None:
        expected = {
            "promotionId": spec_data["promotionId"],
            "workspaceId": spec_data["workspaceId"],
            "specDigest": spec_digest,
            "expectedBaseRevision": spec_data["expectedBaseRevision"],
            "candidateRevision": spec_data["candidateRevision"],
            **identity.durable_binding(),
        }
        if any(intent.get(name) != value for name, value in expected.items()):
            raise PromotionError("durable promotion intent does not match the spec or workspace")

    def promote(
        self,
        spec: Mapping[str, Any],
        *,
        observations: PromotionObservations,
        observed_at: str | None = None,
        clock: datetime | None = None,
    ) -> dict[str, Any]:
        """Record a refusal; this low-level method never mutates Git."""

        promotion = PromotionSpec.from_dict(spec)
        spec_data = promotion.to_dict()
        spec_digest = promotion.digest
        promotion_id = spec_data["promotionId"]
        existing = self.load_receipt(promotion_id)
        if existing is not None:
            self._require_receipt_binding(existing, spec_data, spec_digest)
            return existing
        timestamp = observed_at or _utc_timestamp(clock or datetime.now(timezone.utc))
        rollback_record = self.verify_rollback_point(spec_data["rollbackPointDigest"])
        checks = self._binding_checks(
            spec_data, observations, rollback_record, spec_digest=spec_digest
        )
        failed = [name for name, ok in checks.items() if not ok]
        reason = "bindings_failed:" + ",".join(failed) if failed else "physical_transition_required"
        receipt = self._build_receipt(
            {**spec_data, "specDigest": spec_digest},
            observations,
            rollback_record=rollback_record,
            checks=checks,
            decision="refused",
            reason=reason,
            timestamp=timestamp,
        )
        return self._record_receipt(receipt)

    @staticmethod
    def _git_transition_blocked(
        workspace_path: Path | str,
        revision_tracker: WorkspaceRevisionTracker,
        identity: WorkspaceIdentity,
    ) -> str | None:
        executable_config = (
            r"^(filter\.|include|merge\..*\.driver$|diff\..*\.command$|"
            r"core\.(hooksPath|fsmonitor|worktree)$)"
        )
        try:
            result = revision_tracker.run_git(
                workspace_path,
                ("config", "--local", "--get-regexp", executable_config),
                expected_identity=identity,
            )
        except WorkspaceRevisionError:
            return "repository_config_probe_failed"
        if result.returncode == 0 and result.stdout.strip():
            return "repository_configures_executable_or_indirect_behavior"
        if result.returncode != 1 or result.stdout.strip() or result.stderr.strip():
            return "repository_config_probe_failed"
        return None

    @staticmethod
    def _post_transition_safety_error(
        workspace_path: Path | str,
        revision_tracker: WorkspaceRevisionTracker,
        identity: WorkspaceIdentity,
    ) -> str | None:
        blocked = PromotionService._git_transition_blocked(
            workspace_path, revision_tracker, identity
        )
        if blocked is not None:
            return blocked
        try:
            status = revision_tracker.run_git(
                workspace_path,
                ("status", "--porcelain", "--untracked-files=all"),
                expected_identity=identity,
            )
        except WorkspaceRevisionError:
            return "post_transition_workspace_unobservable"
        if status.returncode != 0 or status.stderr.strip():
            return "post_transition_workspace_status_failed"
        if status.stdout.strip():
            return "post_transition_workspace_not_clean"
        return None

    @staticmethod
    def _run_git_transition(
        workspace_path: Path | str,
        candidate_revision: str,
        *,
        revision_tracker: WorkspaceRevisionTracker,
        identity: WorkspaceIdentity,
        before_mutation: Callable[[], str | None],
    ) -> tuple[str, str]:
        blocked = PromotionService._git_transition_blocked(
            workspace_path, revision_tracker, identity
        )
        if blocked is not None:
            return "failed", blocked
        try:
            status = revision_tracker.run_git(
                workspace_path,
                ("status", "--porcelain", "--untracked-files=all"),
                expected_identity=identity,
            )
            if status.returncode != 0 or status.stderr.strip():
                return "failed", "workspace_clean_check_failed"
            if status.stdout.strip():
                return "failed", "workspace_not_clean"
            candidate = revision_tracker.run_git(
                workspace_path,
                ("cat-file", "-e", f"{candidate_revision}^{{commit}}"),
                expected_identity=identity,
            )
            if candidate.returncode != 0 or candidate.stdout.strip() or candidate.stderr.strip():
                return "failed", "candidate_commit_unavailable"
            ancestor = revision_tracker.run_git(
                workspace_path,
                ("merge-base", "--is-ancestor", "HEAD", candidate_revision),
                expected_identity=identity,
            )
            if ancestor.returncode == 1 and not ancestor.stdout.strip() and not ancestor.stderr.strip():
                return "failed", "candidate_is_not_a_fast_forward"
            if ancestor.returncode != 0 or ancestor.stdout.strip() or ancestor.stderr.strip():
                return "failed", "candidate_ancestry_check_failed"
            revalidation_error = before_mutation()
            if revalidation_error is not None:
                return "failed", revalidation_error
            blocked = PromotionService._git_transition_blocked(
                workspace_path, revision_tracker, identity
            )
            if blocked is not None:
                return "failed", blocked
            if revision_tracker.workspace_identity(workspace_path) != identity:
                return "failed", "workspace_identity_changed_before_mutation"
        except WorkspaceRevisionError:
            return "failed", "git_preflight_identity_failed"

        try:
            result = revision_tracker.run_git(
                workspace_path,
                ("merge", "--ff-only", "--no-verify", candidate_revision),
                expected_identity=identity,
            )
        except WorkspaceRevisionError:
            return "interrupted", "git_transition_outcome_unobservable"
        if result.returncode == 0 and not result.stderr.strip():
            return "succeeded", ""
        return "failed", "git_transition_failed"

    @staticmethod
    def _intent_record(
        spec_data: Mapping[str, Any],
        spec_digest: str,
        snapshot: _AuthoritativeSnapshot,
        identity: WorkspaceIdentity,
        timestamp: str,
    ) -> dict[str, Any]:
        return {
            "formatVersion": INTENT_FORMAT,
            "promotionId": spec_data["promotionId"],
            "workspaceId": spec_data["workspaceId"],
            "specDigest": spec_digest,
            "expectedBaseRevision": spec_data["expectedBaseRevision"],
            "candidateRevision": spec_data["candidateRevision"],
            "approvalRecordDigest": snapshot.approval_record_digest,
            "validatorRecordDigest": snapshot.validator_record_digest,
            "authorityBindingDigest": snapshot.authority_binding_digest,
            **identity.durable_binding(),
            "observedAt": timestamp,
        }

    def observe_and_promote_with_transition(
        self,
        spec: Mapping[str, Any],
        *,
        load_approval: Callable[[str], Mapping[str, Any] | None],
        load_validator_evidence: Callable[[str], Mapping[str, Any] | None],
        compute_diff_digest: Callable[[str, str], str],
        workspace_path: Path | str,
        revision_tracker: WorkspaceRevisionTracker,
        observed_at: str | None = None,
        clock: datetime | None = None,
    ) -> dict[str, Any]:
        """Compatibility name for the authoritative mutating surface."""

        return self.promote_with_transition(
            spec,
            load_approval=load_approval,
            load_validator_evidence=load_validator_evidence,
            compute_diff_digest=compute_diff_digest,
            workspace_path=workspace_path,
            revision_tracker=revision_tracker,
            observed_at=observed_at,
            clock=clock,
        )

    def promote_with_transition(
        self,
        spec: Mapping[str, Any],
        *,
        load_approval: Callable[[str], Mapping[str, Any] | None],
        load_validator_evidence: Callable[[str], Mapping[str, Any] | None],
        compute_diff_digest: Callable[[str, str], str],
        workspace_path: Path | str,
        revision_tracker: WorkspaceRevisionTracker,
        observed_at: str | None = None,
        clock: datetime | None = None,
    ) -> dict[str, Any]:
        """Promote using only fresh StatePort-authoritative lookups under locks."""

        promotion = PromotionSpec.from_dict(spec)
        workspace_id = promotion.to_dict()["workspaceId"]
        with self._locked_workspace(workspace_id):
            return self._promote_with_transition_locked(
                promotion,
                load_approval=load_approval,
                load_validator_evidence=load_validator_evidence,
                compute_diff_digest=compute_diff_digest,
                workspace_path=workspace_path,
                revision_tracker=revision_tracker,
                observed_at=observed_at,
                clock=clock,
            )

    def _promote_with_transition_locked(
        self,
        promotion: PromotionSpec,
        *,
        load_approval: Callable[[str], Mapping[str, Any] | None],
        load_validator_evidence: Callable[[str], Mapping[str, Any] | None],
        compute_diff_digest: Callable[[str, str], str],
        workspace_path: Path | str,
        revision_tracker: WorkspaceRevisionTracker,
        observed_at: str | None,
        clock: datetime | None,
    ) -> dict[str, Any]:
        spec_data = promotion.to_dict()
        spec_digest = promotion.digest
        workspace_id = spec_data["workspaceId"]
        promotion_id = spec_data["promotionId"]
        base_revision = spec_data["expectedBaseRevision"]
        candidate_revision = spec_data["candidateRevision"]
        existing = self.load_receipt(promotion_id)
        try:
            identity = revision_tracker.workspace_identity(workspace_path)
            current = revision_tracker.observe_revision(
                workspace_path, expected_identity=identity
            )
        except WorkspaceRevisionError as exc:
            raise PromotionError(f"workspace identity or revision is unobservable: {exc}") from exc
        if existing is not None:
            self._require_receipt_binding(existing, spec_data, spec_digest)
            if (
                existing["promotionDecision"]["decision"] == "refused"
                and current == candidate_revision
            ):
                raise PromotionError(
                    "refused receipt exists but the candidate is physically applied; "
                    "promotion is quarantined"
                )
            if existing["promotionDecision"]["decision"] == "promoted":
                self._require_promoted_workspace_binding(
                    spec_data,
                    spec_digest,
                    identity,
                    revision_tracker,
                )
            return existing
        intent = self._load_intent(promotion_id)
        if intent is not None:
            self._require_intent_binding(intent, spec_data, spec_digest, identity)
        if current == candidate_revision:
            if intent is None:
                raise PromotionError(
                    "candidate is already applied without a matching durable intent; promotion is quarantined"
                )
            return self._recover_and_complete_locked(
                promotion,
                load_approval=load_approval,
                load_validator_evidence=load_validator_evidence,
                compute_diff_digest=compute_diff_digest,
                workspace_path=workspace_path,
                revision_tracker=revision_tracker,
                identity=identity,
                clock=clock,
            )

        def observe() -> str:
            try:
                return revision_tracker.observe_revision(
                    workspace_path, expected_identity=identity
                )
            except WorkspaceRevisionError as exc:
                raise PromotionError(f"workspace revision is unobservable: {exc}") from exc

        first = self._snapshot(
            spec_data,
            spec_digest=spec_digest,
            observe_revision=observe,
            load_approval=load_approval,
            load_validator_evidence=load_validator_evidence,
            compute_diff_digest=compute_diff_digest,
        )
        rollback_record = self.verify_rollback_point(spec_data["rollbackPointDigest"])
        checks = self._binding_checks(
            spec_data, first.observations, rollback_record, spec_digest=spec_digest
        )
        timestamp = observed_at or _utc_timestamp(clock or datetime.now(timezone.utc))
        if not all(checks.values()):
            if intent is not None:
                raise PromotionError(
                    "authoritative bindings no longer match a durable intent; promotion is quarantined"
                )
            failed = [name for name, ok in checks.items() if not ok]
            receipt = self._build_receipt(
                {**spec_data, "specDigest": spec_digest},
                first.observations,
                rollback_record=rollback_record,
                checks=checks,
                decision="refused",
                reason="bindings_failed:" + ",".join(failed),
                timestamp=timestamp,
            )
            return self._record_receipt(receipt)

        second = self._snapshot(
            spec_data,
            spec_digest=spec_digest,
            observe_revision=observe,
            load_approval=load_approval,
            load_validator_evidence=load_validator_evidence,
            compute_diff_digest=compute_diff_digest,
        )
        second_checks = self._binding_checks(
            spec_data, second.observations, rollback_record, spec_digest=spec_digest
        )
        if second.authority_binding_digest != first.authority_binding_digest or not all(
            second_checks.values()
        ):
            raise PromotionError("authoritative bindings changed before durable intent")

        if intent is None:
            intent = self._record_intent(
                promotion_id,
                self._intent_record(spec_data, spec_digest, second, identity, timestamp),
            )
        else:
            if intent.get("authorityBindingDigest") != second.authority_binding_digest:
                raise PromotionError("durable intent authority binding no longer matches")
            timestamp = str(intent["observedAt"])

        latest_snapshot = second

        def revalidate_before_mutation() -> str | None:
            nonlocal latest_snapshot
            try:
                if revision_tracker.workspace_identity(workspace_path) != identity:
                    return "workspace_identity_changed_before_mutation"
                fresh = self._snapshot(
                    spec_data,
                    spec_digest=spec_digest,
                    observe_revision=observe,
                    load_approval=load_approval,
                    load_validator_evidence=load_validator_evidence,
                    compute_diff_digest=compute_diff_digest,
                )
                fresh_checks = self._binding_checks(
                    spec_data,
                    fresh.observations,
                    rollback_record,
                    spec_digest=spec_digest,
                )
            except PromotionError:
                return "authoritative_revalidation_failed_before_mutation"
            if (
                fresh.authority_binding_digest != intent["authorityBindingDigest"]
                or not all(fresh_checks.values())
            ):
                return "authoritative_bindings_changed_before_mutation"
            latest_snapshot = fresh
            return None

        status, reason = self._run_git_transition(
            workspace_path,
            candidate_revision,
            revision_tracker=revision_tracker,
            identity=identity,
            before_mutation=revalidate_before_mutation,
        )
        transition_kwargs = {
            "workspace_id": workspace_id,
            "workspace_path": workspace_path,
            "promotion_id": promotion_id,
            "observed_at": timestamp,
            "expected_identity": identity,
        }
        try:
            post_revision = revision_tracker.observe_revision(
                workspace_path, expected_identity=identity
            )
        except WorkspaceRevisionError as exc:
            try:
                revision_tracker.record_transition(
                    pre_revision=base_revision,
                    post_revision=None,
                    status="interrupted",
                    reason="post_transition_observation_failed",
                    **transition_kwargs,
                )
            except WorkspaceRevisionError:
                pass
            raise PromotionError(
                f"post-transition outcome is unobservable and quarantined: {exc}"
            ) from exc

        if status != "succeeded":
            ambiguous = status == "interrupted" or post_revision != base_revision
            transition_status = "interrupted" if ambiguous else "failed"
            try:
                revision_tracker.record_transition(
                    pre_revision=base_revision,
                    post_revision=post_revision,
                    status=transition_status,
                    reason=f"git_transition_{status}:{reason}",
                    **transition_kwargs,
                )
            except WorkspaceRevisionError as exc:
                raise PromotionError(
                    f"transition outcome could not be recorded and is quarantined: {exc}"
                ) from exc
            if ambiguous or reason.startswith("authoritative_") or reason.startswith(
                "workspace_identity_"
            ):
                raise PromotionError(
                    f"git transition outcome requires recovery and is not refused: {reason}"
                )
            receipt = self._build_receipt(
                {**spec_data, "specDigest": spec_digest},
                latest_snapshot.observations,
                rollback_record=rollback_record,
                checks=second_checks,
                decision="refused",
                reason=f"physical_transition_failed:{reason}",
                timestamp=timestamp,
            )
            self._record_receipt(receipt)
            raise PromotionError(f"git_transition_failed: {reason}")

        if post_revision != candidate_revision:
            revision_tracker.record_transition(
                pre_revision=base_revision,
                post_revision=post_revision,
                status="interrupted",
                reason="post_revision_mismatch",
                **transition_kwargs,
            )
            raise PromotionError("post_revision_mismatch; promotion is quarantined")

        post_safety = self._post_transition_safety_error(
            workspace_path, revision_tracker, identity
        )
        if post_safety is not None:
            revision_tracker.record_transition(
                pre_revision=base_revision,
                post_revision=post_revision,
                status="interrupted",
                reason=f"post_mutation_safety_check_failed:{post_safety}",
                **transition_kwargs,
            )
            raise PromotionError(
                f"post-mutation workspace safety failed ({post_safety}); promotion quarantined"
            )

        try:
            final_snapshot = self._snapshot(
                spec_data,
                spec_digest=spec_digest,
                observe_revision=observe,
                load_approval=load_approval,
                load_validator_evidence=load_validator_evidence,
                compute_diff_digest=compute_diff_digest,
            )
        except PromotionError as exc:
            revision_tracker.record_transition(
                pre_revision=base_revision,
                post_revision=post_revision,
                status="interrupted",
                reason="post_mutation_authority_unobservable",
                **transition_kwargs,
            )
            raise PromotionError("post-mutation authority is unobservable; promotion quarantined") from exc
        if final_snapshot.authority_binding_digest != intent["authorityBindingDigest"]:
            revision_tracker.record_transition(
                pre_revision=base_revision,
                post_revision=post_revision,
                status="interrupted",
                reason="post_mutation_authority_changed",
                **transition_kwargs,
            )
            raise PromotionError("authority changed after mutation; promotion quarantined")

        revision_tracker.record_transition(
            pre_revision=base_revision,
            post_revision=post_revision,
            status="succeeded",
            reason="promoted",
            **transition_kwargs,
        )
        receipt_snapshot = self._snapshot(
            spec_data,
            spec_digest=spec_digest,
            observe_revision=observe,
            load_approval=load_approval,
            load_validator_evidence=load_validator_evidence,
            compute_diff_digest=compute_diff_digest,
        )
        if receipt_snapshot.authority_binding_digest != intent["authorityBindingDigest"]:
            raise PromotionError(
                "authority changed before durable receipt; promotion remains recoverable"
            )
        promoted = self._build_receipt(
            {**spec_data, "specDigest": spec_digest},
            latest_snapshot.observations,
            rollback_record=rollback_record,
            checks=second_checks,
            decision="promoted",
            reason="all_bindings_matched_and_transition_succeeded",
            timestamp=timestamp,
        )
        return self._record_receipt(promoted)

    @staticmethod
    def _transition_binding_error(
        transitions: list[dict[str, Any]],
        spec_data: Mapping[str, Any],
        identity: WorkspaceIdentity,
    ) -> str | None:
        for record in transitions:
            if (
                record.get("workspaceId") != spec_data["workspaceId"]
                or record.get("promotionId") != spec_data["promotionId"]
                or record.get("workspacePathDigest") != identity.workspace_path_digest
                or record.get("repositoryIdentityDigest")
                != identity.repository_identity_digest
                or record.get("prePromotionRevision")
                != spec_data["expectedBaseRevision"]
            ):
                return "transition record does not match workspace, promotion, or base bindings"
            post = record.get("postPromotionRevision")
            if post not in {
                None,
                spec_data["expectedBaseRevision"],
                spec_data["candidateRevision"],
            }:
                return "transition record names an unrelated post-promotion revision"
            if record.get("status") == "succeeded" and post != spec_data["candidateRevision"]:
                return "successful transition record does not bind the candidate revision"
        return None

    def _require_promoted_workspace_binding(
        self,
        spec_data: Mapping[str, Any],
        spec_digest: str,
        identity: WorkspaceIdentity,
        revision_tracker: WorkspaceRevisionTracker,
    ) -> None:
        intent = self._load_intent(spec_data["promotionId"])
        if intent is None:
            raise PromotionError("promoted receipt has no durable workspace-bound intent")
        self._require_intent_binding(intent, spec_data, spec_digest, identity)
        try:
            transitions = [
                record
                for record in revision_tracker.load_transitions(spec_data["workspaceId"])
                if record.get("promotionId") == spec_data["promotionId"]
            ]
        except WorkspaceRevisionError as exc:
            raise PromotionError(f"promoted transition evidence is corrupt: {exc}") from exc
        binding_error = self._transition_binding_error(transitions, spec_data, identity)
        if binding_error is not None:
            raise PromotionError(binding_error)
        if not any(record.get("status") == "succeeded" for record in transitions):
            raise PromotionError("promoted receipt has no successful candidate-bound transition")

    def recover_promotion(
        self,
        spec: Mapping[str, Any],
        *,
        revision_tracker: WorkspaceRevisionTracker,
        workspace_path: Path | str,
    ) -> dict[str, Any]:
        """Classify recovery only after binding spec, workspace, and durable state."""

        promotion = PromotionSpec.from_dict(spec)
        spec_data = promotion.to_dict()
        with self._locked_workspace(spec_data["workspaceId"]):
            try:
                identity = revision_tracker.workspace_identity(workspace_path)
                transitions = [
                    record
                    for record in revision_tracker.load_transitions(spec_data["workspaceId"])
                    if record.get("promotionId") == spec_data["promotionId"]
                ]
                current = revision_tracker.observe_revision(
                    workspace_path, expected_identity=identity
                )
                receipt = self.load_receipt(spec_data["promotionId"])
                intent = self._load_intent(spec_data["promotionId"])
                if receipt is not None:
                    self._require_receipt_binding(receipt, spec_data, promotion.digest)
                if intent is not None:
                    self._require_intent_binding(intent, spec_data, promotion.digest, identity)
            except (PromotionError, WorkspaceRevisionError) as exc:
                return {
                    "classification": "quarantined",
                    "detail": f"durable recovery binding failed: {exc}",
                    "transitions": locals().get("transitions", []),
                }

            transition_error = self._transition_binding_error(transitions, spec_data, identity)
            if transition_error is not None:
                return {
                    "classification": "quarantined",
                    "detail": transition_error,
                    "transitions": transitions,
                }
            if receipt is not None:
                decision = receipt["promotionDecision"]["decision"]
                if decision == "promoted":
                    if intent is None or not any(
                        record.get("status") == "succeeded" for record in transitions
                    ):
                        return {
                            "classification": "quarantined",
                            "detail": "promoted receipt lacks workspace-bound intent or transition",
                            "transitions": transitions,
                        }
                    if current == spec_data["candidateRevision"]:
                        return {
                            "classification": "promoted",
                            "detail": "promotion is durable and observed",
                            "transitions": transitions,
                        }
                    if current == spec_data["expectedBaseRevision"]:
                        return {
                            "classification": "rolled_back",
                            "detail": "workspace observes the bound pre-promotion revision",
                            "transitions": transitions,
                        }
                    return {
                        "classification": "quarantined",
                        "detail": f"promoted receipt exists at unexpected revision {current}",
                        "transitions": transitions,
                    }
                if current == spec_data["candidateRevision"]:
                    return {
                        "classification": "quarantined",
                        "detail": "refused receipt exists but the candidate is physically applied",
                        "transitions": transitions,
                    }
                observed = receipt["observedProcessResult"]["currentRevision"]
                if current != observed:
                    return {
                        "classification": "quarantined",
                        "detail": "workspace drifted after the refused receipt",
                        "transitions": transitions,
                    }
                return {
                    "classification": "refused",
                    "detail": receipt["promotionDecision"]["reason"],
                    "transitions": transitions,
                }

            if intent is None:
                if transitions or current == spec_data["candidateRevision"]:
                    return {
                        "classification": "quarantined",
                        "detail": "physical promotion evidence exists without a matching intent",
                        "transitions": transitions,
                    }
                return {
                    "classification": "unapplied",
                    "detail": "no receipt, intent, or transition attempt is recorded",
                    "transitions": transitions,
                }
            if current == spec_data["candidateRevision"]:
                return {
                    "classification": "applied_unreceipted",
                    "detail": "matching intent exists and the candidate is physically applied",
                    "transitions": transitions,
                }
            interrupted = any(record.get("status") == "interrupted" for record in transitions)
            if current == spec_data["expectedBaseRevision"] and not interrupted:
                return {
                    "classification": "unapplied",
                    "detail": "matching intent exists and the workspace remains at the base",
                    "transitions": transitions,
                }
            return {
                "classification": "quarantined",
                "detail": f"intent exists with an ambiguous or unexpected revision {current}",
                "transitions": transitions,
            }

    def recover_and_complete(
        self,
        spec: Mapping[str, Any],
        *,
        load_approval: Callable[[str], Mapping[str, Any] | None],
        load_validator_evidence: Callable[[str], Mapping[str, Any] | None],
        compute_diff_digest: Callable[[str, str], str],
        workspace_path: Path | str,
        revision_tracker: WorkspaceRevisionTracker,
        clock: datetime | None = None,
    ) -> dict[str, Any]:
        """Complete an applied candidate from fresh authoritative lookups only."""

        promotion = PromotionSpec.from_dict(spec)
        spec_data = promotion.to_dict()
        with self._locked_workspace(spec_data["workspaceId"]):
            try:
                identity = revision_tracker.workspace_identity(workspace_path)
            except WorkspaceRevisionError as exc:
                raise PromotionError(f"workspace identity is unobservable: {exc}") from exc
            return self._recover_and_complete_locked(
                promotion,
                load_approval=load_approval,
                load_validator_evidence=load_validator_evidence,
                compute_diff_digest=compute_diff_digest,
                workspace_path=workspace_path,
                revision_tracker=revision_tracker,
                identity=identity,
                clock=clock,
            )

    def _recover_and_complete_locked(
        self,
        promotion: PromotionSpec,
        *,
        load_approval: Callable[[str], Mapping[str, Any] | None],
        load_validator_evidence: Callable[[str], Mapping[str, Any] | None],
        compute_diff_digest: Callable[[str, str], str],
        workspace_path: Path | str,
        revision_tracker: WorkspaceRevisionTracker,
        identity: WorkspaceIdentity,
        clock: datetime | None,
    ) -> dict[str, Any]:
        spec_data = promotion.to_dict()
        spec_digest = promotion.digest
        promotion_id = spec_data["promotionId"]
        try:
            current = revision_tracker.observe_revision(
                workspace_path, expected_identity=identity
            )
        except WorkspaceRevisionError as exc:
            raise PromotionError(f"workspace revision is unobservable: {exc}") from exc
        existing = self.load_receipt(promotion_id)
        if existing is not None:
            self._require_receipt_binding(existing, spec_data, spec_digest)
            if (
                existing["promotionDecision"]["decision"] == "refused"
                and current == spec_data["candidateRevision"]
            ):
                raise PromotionError(
                    "refused receipt exists but the candidate is physically applied; "
                    "promotion is quarantined"
                )
            if existing["promotionDecision"]["decision"] == "promoted":
                self._require_promoted_workspace_binding(
                    spec_data,
                    spec_digest,
                    identity,
                    revision_tracker,
                )
            return existing
        intent = self._load_intent(promotion_id)
        if intent is None:
            raise PromotionError("no matching durable promotion intent to complete")
        self._require_intent_binding(intent, spec_data, spec_digest, identity)
        if current == spec_data["expectedBaseRevision"]:
            return {
                "classification": "unapplied",
                "detail": "workspace still observes the base revision; nothing to complete",
            }
        if current != spec_data["candidateRevision"]:
            raise PromotionError(
                f"workspace observes {current}, neither base nor candidate; promotion is quarantined"
            )
        safety_error = self._post_transition_safety_error(
            workspace_path, revision_tracker, identity
        )
        if safety_error is not None:
            raise PromotionError(
                f"applied workspace safety check failed ({safety_error}); promotion is quarantined"
            )

        def observe() -> str:
            try:
                return revision_tracker.observe_revision(
                    workspace_path, expected_identity=identity
                )
            except WorkspaceRevisionError as exc:
                raise PromotionError(f"workspace revision is unobservable: {exc}") from exc

        snapshot = self._snapshot(
            spec_data,
            spec_digest=spec_digest,
            observe_revision=observe,
            load_approval=load_approval,
            load_validator_evidence=load_validator_evidence,
            compute_diff_digest=compute_diff_digest,
        )
        if (
            snapshot.authority_binding_digest != intent["authorityBindingDigest"]
            or snapshot.approval_record_digest != intent["approvalRecordDigest"]
            or snapshot.validator_record_digest != intent["validatorRecordDigest"]
        ):
            raise PromotionError(
                "authoritative records drifted after physical application; promotion is quarantined"
            )
        effective = replace(
            snapshot.observations,
            current_revision=spec_data["expectedBaseRevision"],
        )
        rollback_record = self.verify_rollback_point(spec_data["rollbackPointDigest"])
        checks = self._binding_checks(
            spec_data, effective, rollback_record, spec_digest=spec_digest
        )
        if not all(checks.values()):
            failed = [name for name, ok in checks.items() if not ok]
            raise PromotionError(
                "recovery bindings failed after physical application; promotion is quarantined:"
                + ",".join(failed)
            )
        final_snapshot = self._snapshot(
            spec_data,
            spec_digest=spec_digest,
            observe_revision=observe,
            load_approval=load_approval,
            load_validator_evidence=load_validator_evidence,
            compute_diff_digest=compute_diff_digest,
        )
        if final_snapshot.authority_binding_digest != intent["authorityBindingDigest"]:
            raise PromotionError("authority changed during recovery completion; promotion is quarantined")

        timestamp = _utc_timestamp(clock or datetime.now(timezone.utc))
        try:
            revision_tracker.record_transition(
                pre_revision=spec_data["expectedBaseRevision"],
                post_revision=current,
                status="succeeded",
                reason="recovery-completed",
                workspace_id=spec_data["workspaceId"],
                workspace_path=workspace_path,
                promotion_id=promotion_id,
                observed_at=timestamp,
                expected_identity=identity,
            )
        except WorkspaceRevisionError as exc:
            raise PromotionError(f"recovery transition record failed: {exc}") from exc
        receipt_snapshot = self._snapshot(
            spec_data,
            spec_digest=spec_digest,
            observe_revision=observe,
            load_approval=load_approval,
            load_validator_evidence=load_validator_evidence,
            compute_diff_digest=compute_diff_digest,
        )
        if receipt_snapshot.authority_binding_digest != intent["authorityBindingDigest"]:
            raise PromotionError(
                "authority changed before recovery receipt; promotion remains quarantined"
            )
        promoted = self._build_receipt(
            {**spec_data, "specDigest": spec_digest},
            effective,
            rollback_record=rollback_record,
            checks=checks,
            decision="promoted",
            reason="recovery_completed:all_bindings_matched_and_candidate_observed",
            timestamp=timestamp,
        )
        return self._record_receipt(promoted)


__all__ = ["PromotionError", "PromotionObservations", "PromotionService"]
