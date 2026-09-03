"""Durable deployment plans, state, transitions, and immutable receipts."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import shutil
from typing import Any, Callable, Iterator, Mapping, Sequence

from .authority import terminal_authority_data
from .contracts import (
    LIFECYCLE_STATES,
    RECEIPT_SCHEMA,
    STATE_SCHEMA,
    deployment_update_changes,
    validate_plan,
    validate_transition,
)
from .errors import DeploymentRefusal
from .util import (
    COMMIT,
    DIGEST,
    _fsync_directory,
    atomic_json,
    default_state_root,
    digest_value,
    ensure_private_directory,
    existing_exclusive_lock,
    existing_private_directory,
    exclusive_lock,
    read_json,
    relative_posix,
    safe_id,
    timestamp,
)


StateMutation = Callable[[dict[str, Any]], None]
TRANSACTION_SCHEMA = "stateport.deployment-transaction/v1"
EVIDENCE_SCHEMA = "stateport.deployment-evidence/v1"


def _canonical_utc_timestamp(value: object, *, code: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise DeploymentRefusal(code, f"{label} is invalid") from exc
    if (
        not isinstance(value, str)
        or parsed.tzinfo is None
        or parsed.utcoffset() != timezone.utc.utcoffset(parsed)
        or parsed.microsecond
        or value != parsed.isoformat().replace("+00:00", "Z")
    ):
        raise DeploymentRefusal(code, f"{label} is invalid")
    return parsed


class DeploymentStore:
    """Single-writer, create-only evidence store for deployment authority."""

    def __init__(
        self,
        root: Path | str | None = None,
        *,
        failpoint: Callable[[str], None] | None = None,
        create: bool = True,
    ) -> None:
        selected = Path(root) if root is not None else default_state_root()
        self.root = (
            ensure_private_directory(selected)
            if create
            else existing_private_directory(selected)
        )
        self.deployments = (
            ensure_private_directory(self.root / "records")
            if create
            else existing_private_directory(self.root / "records")
        )
        self._failpoint = failpoint

    def _deployment_root(self, deployment_id: str, *, create: bool = False) -> Path:
        deployment_id = safe_id(deployment_id, "deployment id")
        path = self.deployments / deployment_id
        if path.is_symlink():
            raise DeploymentRefusal("unsafe_state_root", "deployment record may not be a symlink")
        if create:
            ensure_private_directory(path)
            for name in ("plans", "receipts", "evidence", "overlays", "build-contexts"):
                ensure_private_directory(path / name)
        elif not path.is_dir():
            raise DeploymentRefusal("deployment_not_found", f"deployment does not exist: {deployment_id}")
        return path

    def _state_path(self, deployment_id: str) -> Path:
        return self._deployment_root(deployment_id) / "state.json"

    def _lock_path(self, deployment_id: str, *, create: bool = False) -> Path:
        return self._deployment_root(deployment_id, create=create) / ".deployment.lock"

    def _plan_path(self, deployment_id: str, plan_id: str) -> Path:
        return self._deployment_root(deployment_id) / "plans" / f"{safe_id(plan_id, 'plan id')}.json"

    def _receipt_path(self, deployment_id: str, receipt_id: str) -> Path:
        return self._deployment_root(deployment_id) / "receipts" / f"{safe_id(receipt_id, 'receipt id')}.json"

    def _evidence_path(self, deployment_id: str, evidence_id: str) -> Path:
        return (
            self._deployment_root(deployment_id)
            / "evidence"
            / f"{safe_id(evidence_id, 'evidence id')}.json"
        )

    def _transaction_path(self, deployment_id: str) -> Path:
        return self._deployment_root(deployment_id) / ".pending-commit.json"

    def _trip(self, name: str) -> None:
        if self._failpoint is not None:
            self._failpoint(name)

    @staticmethod
    def _same_document(path: Path, value: Mapping[str, Any], label: str) -> bool:
        if not path.exists():
            return False
        if read_json(path, label) != dict(value):
            raise DeploymentRefusal(
                "transaction_conflict",
                f"pending deployment transaction conflicts with {label}",
            )
        return True

    def load_state(self, deployment_id: str) -> dict[str, Any]:
        with exclusive_lock(self._lock_path(deployment_id)):
            self._recover_unlocked(deployment_id)
            return self._load_state_unlocked(deployment_id)

    def list_states(self) -> list[dict[str, Any]]:
        """Load every durable deployment state, sorted by deployment id."""

        states: list[dict[str, Any]] = []
        for path in sorted(self.deployments.iterdir()):
            if path.is_symlink() or not path.is_dir():
                raise DeploymentRefusal(
                    "unsafe_state_root",
                    "deployment records contain an unsafe entry",
                )
            states.append(self.load_state(path.name))
        return states

    def peek_authority_run_id(self, deployment_id: str, action: str) -> str:
        """Resolve an action scope without creating state or recovering its WAL."""

        if action not in {
            "observe_deployment",
            "collect_deployment_logs",
            "restart_deployment",
            "remove_deployment_runtime",
            "backup_deployment_data",
            "restore_deployment_data",
            "plan_deployment",
        }:
            raise DeploymentRefusal(
                "invalid_contract", "deployment authority action is not peekable"
            )
        deployment_id = safe_id(deployment_id, "deployment id")
        with existing_exclusive_lock(self._lock_path(deployment_id)):
            pending = self._transaction_path(deployment_id)
            if pending.exists() or pending.is_symlink():
                raise DeploymentRefusal(
                    "deployment_reconciliation_required",
                    "deployment has a pending transaction that must be reconciled after authority is reserved",
                    details={"deploymentId": deployment_id},
                )
            state = self._load_state_unlocked(deployment_id)
            transition = state.get("currentTransition")
            digest: object
            if action in {"restart_deployment", "collect_deployment_logs"}:
                digest = state.get("acceptedRevision")
            elif action == "remove_deployment_runtime":
                digest = (
                    transition.get("planDigest")
                    if isinstance(transition, Mapping)
                    and transition.get("operation") in {"apply", "remove"}
                    else state.get("acceptedRevision")
                )
            elif action == "plan_deployment":
                desired = state.get("desiredRevision")
                desired_plan = (
                    self._load_plan_unlocked(
                        deployment_id, desired, require_unexpired=False
                    )
                    if isinstance(desired, str)
                    else None
                )
                digest = (
                    desired_plan.get("predecessorRevision")
                    if isinstance(desired_plan, Mapping)
                    and desired_plan.get("operation") == "purge_data"
                    else state.get("acceptedRevision")
                    or (
                        state.get("approvedPlanDigest")
                        if state.get("lifecycleState")
                        == "removed_runtime_data_retained"
                        else None
                    )
                    or state.get("desiredRevision")
                )
            else:
                digest = (
                    state.get("approvedPlanDigest")
                    or state.get("desiredRevision")
                    or state.get("acceptedRevision")
                )
            if not isinstance(digest, str):
                raise DeploymentRefusal(
                    "plan_not_found", "deployment has no exact plan for this action"
                )
            plan = self._load_plan_unlocked(
                deployment_id, digest, require_unexpired=False
            )
            return plan["planDigest"]

    def _load_state_unlocked(self, deployment_id: str) -> dict[str, Any]:
        state = read_json(self._state_path(deployment_id), "deployment state")
        self._validate_state(state, deployment_id)
        if "dataBackups" in state:
            return state
        normalized = deepcopy(state)
        normalized["dataBackups"] = {}
        return self._seal_state(normalized)

    def _validate_state(
        self,
        state: Mapping[str, Any],
        deployment_id: str,
        *,
        validate_documents: bool = True,
    ) -> None:
        expected = {
            "schema",
            "deploymentId",
            "applicationId",
            "revision",
            "lifecycleState",
            "sourceIdentity",
            "approvedPlanDigest",
            "acceptedRevision",
            "desiredRevision",
            "observedRevision",
            "imageDigests",
            "serviceHealth",
            "targetIdentity",
            "storageIdentities",
            "dataBackups",
            "secretBindingIdentifiers",
            "currentTransition",
            "transitionHistory",
            "receipts",
            "authorityReceipts",
            "lastSuccessfulObservation",
            "driftStatus",
            "rollbackPredecessor",
            "infrastructureIdentity",
            "removalState",
            "retainedDataState",
            "createdAt",
            "updatedAt",
            "stateDigest",
        }
        state_keys = set(state)
        if (
            state_keys != expected
            and state_keys != expected - {"dataBackups"}
        ) or (
            state.get("schema") != STATE_SCHEMA
            or state.get("deploymentId") != deployment_id
        ):
            raise DeploymentRefusal("state_invalid", "deployment state has an invalid shape or identity")
        try:
            safe_id(state.get("deploymentId"), "deployment id")
            safe_id(state.get("applicationId"), "application id")
        except DeploymentRefusal as exc:
            raise DeploymentRefusal(
                "state_invalid", "deployment state identities are invalid"
            ) from exc
        if (
            isinstance(state.get("revision"), bool)
            or not isinstance(state.get("revision"), int)
            or state["revision"] < 1
        ):
            raise DeploymentRefusal("state_invalid", "deployment state revision is invalid")
        if state.get("lifecycleState") not in LIFECYCLE_STATES:
            raise DeploymentRefusal("state_invalid", "deployment lifecycle state is invalid")
        source = state.get("sourceIdentity")
        target = state.get("targetIdentity")
        if (
            not isinstance(source, Mapping)
            or set(source)
            != {
                "repositoryIdentity",
                "repositoryRoot",
                "projectPath",
                "commit",
                "treeDigest",
                "dirty",
                "dirtyDigest",
                "dirtyPolicy",
                "descriptorDigest",
            }
            or DIGEST.fullmatch(str(source.get("repositoryIdentity"))) is None
            or not isinstance(source.get("repositoryRoot"), str)
            or not source["repositoryRoot"].startswith("/")
            or relative_posix(source.get("projectPath"), "project path")
            != source.get("projectPath")
            or COMMIT.fullmatch(str(source.get("commit"))) is None
            or any(
                DIGEST.fullmatch(str(source.get(name))) is None
                for name in ("treeDigest", "dirtyDigest", "descriptorDigest")
            )
            or source.get("dirty") is not False
            or source.get("dirtyPolicy") != "refuse"
            or not isinstance(target, Mapping)
            or set(target)
            != {"adapter", "targetId", "architecture", "identityDigest"}
            or target.get("adapter") != "rootless-podman-local"
            or target.get("targetId") != "local"
            or target.get("architecture") != "linux-amd64"
            or DIGEST.fullmatch(str(target.get("identityDigest"))) is None
        ):
            raise DeploymentRefusal(
                "state_invalid", "deployment source or target identity is invalid"
            )
        digest_fields = (
            "approvedPlanDigest",
            "acceptedRevision",
            "desiredRevision",
            "observedRevision",
            "rollbackPredecessor",
        )
        if any(
            value is not None and (
                not isinstance(value, str) or DIGEST.fullmatch(value) is None
            )
            for value in (state.get(name) for name in digest_fields)
        ):
            raise DeploymentRefusal(
                "state_invalid", "deployment revision identity is invalid"
            )
        image_digests = state.get("imageDigests")
        service_health = state.get("serviceHealth")
        storage_identities = state.get("storageIdentities")
        data_backups = state.get("dataBackups", {})
        secret_bindings = state.get("secretBindingIdentifiers")
        if (
            not isinstance(image_digests, Mapping)
            or any(
                not isinstance(key, str)
                or not isinstance(value, str)
                or DIGEST.fullmatch(value) is None
                for key, value in image_digests.items()
            )
            or not isinstance(service_health, Mapping)
            or any(
                not isinstance(key, str)
                or not isinstance(value, Mapping)
                or value.get("status")
                not in {"healthy", "unhealthy", "absent", "unknown", "exited"}
                for key, value in service_health.items()
            )
            or not isinstance(storage_identities, Mapping)
            or any(
                not isinstance(key, str)
                or not isinstance(value, str)
                or not value
                or len(value) > 256
                for key, value in storage_identities.items()
            )
            or not isinstance(data_backups, Mapping)
            or not isinstance(secret_bindings, list)
            or secret_bindings != sorted(set(secret_bindings))
            or any(
                not isinstance(item, str)
                or not item.startswith("secret-broker://")
                for item in secret_bindings
            )
        ):
            raise DeploymentRefusal(
                "state_invalid", "deployment observed resource state is invalid"
            )
        for backup_id, backup in data_backups.items():
            try:
                safe_id(backup_id, "backup id")
            except DeploymentRefusal as exc:
                raise DeploymentRefusal(
                    "state_invalid", "deployment backup identity is invalid"
                ) from exc
            storage = backup.get("storage") if isinstance(backup, Mapping) else None
            identity = (
                {
                    "backupId": backup.get("backupId"),
                    "sourceRevision": backup.get("sourceRevision"),
                    "createdAt": backup.get("createdAt"),
                    "storage": storage,
                }
                if isinstance(backup, Mapping)
                else None
            )
            if (
                not isinstance(backup, Mapping)
                or set(backup)
                != {
                    "backupId",
                    "backupDigest",
                    "sourceRevision",
                    "createdAt",
                    "status",
                    "storage",
                    "restoredAt",
                }
                or backup.get("backupId") != backup_id
                or DIGEST.fullmatch(str(backup.get("backupDigest"))) is None
                or backup.get("backupDigest") != digest_value(identity)
                or DIGEST.fullmatch(str(backup.get("sourceRevision"))) is None
                or backup.get("status") not in {"available", "restored_consumed"}
                or not isinstance(storage, Mapping)
                or not storage
            ):
                raise DeploymentRefusal(
                    "state_invalid", "deployment backup record is invalid"
                )
            _canonical_utc_timestamp(
                backup.get("createdAt"),
                code="state_invalid",
                label="deployment backup timestamp",
            )
            restored_at = backup.get("restoredAt")
            if restored_at is not None:
                _canonical_utc_timestamp(
                    restored_at,
                    code="state_invalid",
                    label="deployment restore timestamp",
                )
            if (backup["status"] == "available") != (restored_at is None):
                raise DeploymentRefusal(
                    "state_invalid", "deployment backup status is inconsistent"
                )
            for storage_id, item in storage.items():
                if (
                    not isinstance(storage_id, str)
                    or not isinstance(item, Mapping)
                    or set(item)
                    != {"artifactId", "contentDigest", "fileCount", "bytes"}
                    or item.get("artifactId") != f"{backup_id}/{storage_id}.tar"
                    or DIGEST.fullmatch(str(item.get("contentDigest"))) is None
                    or isinstance(item.get("fileCount"), bool)
                    or not isinstance(item.get("fileCount"), int)
                    or item["fileCount"] < 0
                    or isinstance(item.get("bytes"), bool)
                    or not isinstance(item.get("bytes"), int)
                    or item["bytes"] < 0
                ):
                    raise DeploymentRefusal(
                        "state_invalid", "deployment backup storage is invalid"
                    )
        infrastructure = state.get("infrastructureIdentity")
        if infrastructure is not None and (
            not isinstance(infrastructure, Mapping)
            or set(infrastructure) != {"networks", "volumes"}
            or any(
                not isinstance(infrastructure.get(kind), Mapping)
                or any(
                    not isinstance(resource_id, str)
                    or not isinstance(entry, Mapping)
                    or set(entry) != {"revision", "sourceCommit"}
                    or DIGEST.fullmatch(str(entry.get("revision"))) is None
                    or COMMIT.fullmatch(str(entry.get("sourceCommit"))) is None
                    for resource_id, entry in infrastructure[kind].items()
                )
                for kind in ("networks", "volumes")
            )
        ):
            raise DeploymentRefusal(
                "state_invalid", "deployment infrastructure identity is invalid"
            )
        current_transition = state.get("currentTransition")
        if current_transition is not None:
            required_transition = {
                "operationId",
                "operation",
                "planDigest",
                "phase",
                "startedAt",
                "authorityDecision",
            }
            allowed_transition = required_transition | {
                "failureCode",
                "details",
                "contextDigest",
                "contextCleanup",
            }
            authority = (
                current_transition.get("authorityDecision")
                if isinstance(current_transition, Mapping)
                else None
            )
            if (
                not isinstance(current_transition, Mapping)
                or not required_transition.issubset(current_transition)
                or not set(current_transition).issubset(allowed_transition)
                or current_transition.get("operation")
                not in {
                    "apply",
                    "update",
                    "rollback",
                    "backup_data",
                    "restore_data",
                    "restart",
                    "remove",
                    "purge_data",
                }
                or current_transition.get("phase")
                not in {
                    "executing",
                    "verifying",
                    "failed",
                    "observation_failed",
                    "interrupted_observed",
                }
                or not isinstance(current_transition.get("operationId"), str)
                or not current_transition["operationId"].startswith("operation_")
                or DIGEST.fullmatch(str(current_transition.get("planDigest")))
                is None
                or not isinstance(authority, Mapping)
                or not isinstance(authority.get("requestId"), str)
                or not isinstance(authority.get("claimId"), str)
                or DIGEST.fullmatch(str(authority.get("decisionDigest"))) is None
                or DIGEST.fullmatch(str(authority.get("reservationDigest")))
                is None
                or DIGEST.fullmatch(str(authority.get("claimDigest"))) is None
            ):
                raise DeploymentRefusal(
                    "state_invalid", "deployment transition state is invalid"
                )
            _canonical_utc_timestamp(
                current_transition.get("startedAt"),
                code="state_invalid",
                label="deployment transition timestamp",
            )
        if state["lifecycleState"] in {"applying", "updating", "verifying", "rollback_required", "rolling_back", "reconciliation_required"} and current_transition is None:
            raise DeploymentRefusal(
                "state_invalid", "active deployment lifecycle lacks an exact transition"
            )
        if state["lifecycleState"] == "awaiting_approval" and (
            state.get("desiredRevision") is None
            or state.get("approvedPlanDigest") is not None
            or current_transition is not None
        ):
            raise DeploymentRefusal(
                "state_invalid", "awaiting deployment state is inconsistent"
            )
        if state["lifecycleState"] == "healthy" and (
            state.get("acceptedRevision") is None
            or state.get("desiredRevision") != state.get("acceptedRevision")
            or state.get("approvedPlanDigest") != state.get("acceptedRevision")
            or state.get("observedRevision") != state.get("acceptedRevision")
            or state.get("driftStatus") != "in_sync"
        ):
            raise DeploymentRefusal(
                "state_invalid", "healthy deployment state is inconsistent"
            )
        if state["lifecycleState"] == "removed_runtime_data_retained" and (
            state.get("desiredRevision") is not None
            or state.get("observedRevision") is not None
            or state.get("removalState") != "runtime_removed"
            or state.get("retainedDataState") not in {"retained", "not_applicable"}
        ):
            raise DeploymentRefusal(
                "state_invalid", "removed deployment state is inconsistent"
            )
        if state["lifecycleState"] == "purged" and (
            state.get("desiredRevision") is not None
            or state.get("observedRevision") is not None
            or state.get("storageIdentities") != {}
            or state.get("retainedDataState") != "purged"
            or state.get("removalState") != "runtime_removed_data_purged"
        ):
            raise DeploymentRefusal(
                "state_invalid", "purged deployment state is inconsistent"
            )
        if state.get("driftStatus") not in {
            "not_observed",
            "in_sync",
            "drifted",
            "unknown",
            "runtime_absent_data_may_be_retained",
        } or state.get("removalState") not in {
            "runtime_absent",
            "runtime_present",
            "runtime_removed",
            "runtime_removed_data_purged",
        } or state.get("retainedDataState") not in {
            "not_created",
            "present",
            "not_applicable",
            "retained",
            "retained_after_failed_apply",
            "purged",
        }:
            raise DeploymentRefusal(
                "state_invalid", "deployment lifecycle classifications are invalid"
            )
        parsed_times = [
            _canonical_utc_timestamp(
                state.get(name),
                code="state_invalid",
                label="deployment state timestamp",
            )
            for name in ("createdAt", "updatedAt")
        ]
        if parsed_times[1] < parsed_times[0]:
            raise DeploymentRefusal(
                "state_invalid", "deployment state update precedes creation"
            )
        unsigned = dict(state)
        stored = unsigned.pop("stateDigest", None)
        if stored != digest_value(unsigned):
            raise DeploymentRefusal("state_integrity_failed", "deployment state integrity check failed")
        history = state.get("transitionHistory")
        receipts = state.get("receipts")
        authority_receipts = state.get("authorityReceipts")
        if (
            not isinstance(history, list)
            or not isinstance(receipts, list)
            or len(receipts) != len(set(receipts))
            or not isinstance(authority_receipts, list)
            or any(not isinstance(item, Mapping) for item in authority_receipts)
            or len({item.get("receiptId") for item in authority_receipts})
            != len(authority_receipts)
        ):
            raise DeploymentRefusal("state_invalid", "deployment state history is invalid")
        authority_receipt_keys = {
            "receiptId",
            "receiptDigest",
            "requestId",
            "action",
            "resultStatus",
            "grantId",
            "decisionDigest",
            "reservationId",
            "reservationDigest",
            "claimId",
            "claimDigest",
            "evidence",
        }
        for item in authority_receipts:
            if (
                set(item) != authority_receipt_keys
                or item.get("resultStatus") not in {"succeeded", "failed"}
                or any(
                    not isinstance(item.get(name), str) or not item.get(name)
                    for name in (
                        "receiptId",
                        "requestId",
                        "action",
                        "grantId",
                        "reservationId",
                        "claimId",
                    )
                )
                or any(
                    DIGEST.fullmatch(str(item.get(name))) is None
                    for name in (
                        "receiptDigest",
                        "decisionDigest",
                        "reservationDigest",
                        "claimDigest",
                    )
                )
                or not isinstance(item.get("evidence"), Mapping)
            ):
                raise DeploymentRefusal(
                    "authority_receipt_unbound",
                    "deployment authority receipt reference is malformed",
                )
        for item in history:
            if (
                not isinstance(item, Mapping)
                or set(item) != {"from", "to", "receiptId", "at"}
                or item.get("from") not in LIFECYCLE_STATES
                or item.get("to") not in LIFECYCLE_STATES
                or not isinstance(item.get("receiptId"), str)
                or not item["receiptId"].startswith("receipt_")
            ):
                raise DeploymentRefusal(
                    "state_invalid", "deployment transition history is malformed"
                )
            _canonical_utc_timestamp(
                item.get("at"),
                code="state_invalid",
                label="deployment transition-history timestamp",
            )
            validate_transition(item["from"], item["to"])
        if not validate_documents:
            return
        prior_digest: str | None = None
        evidence_references: dict[str, dict[str, Any]] = {}
        referenced_plan_digests: set[str] = set()
        authority_decisions: dict[str, dict[str, Any]] = {}

        def collect_evidence_references(value: Any) -> None:
            if isinstance(value, Mapping):
                if set(value) == {"evidenceId", "path", "payloadDigest"}:
                    evidence_id = value.get("evidenceId")
                    if not isinstance(evidence_id, str):
                        raise DeploymentRefusal(
                            "evidence_reference_invalid",
                            "deployment evidence reference has no exact identity",
                        )
                    normalized = deepcopy(dict(value))
                    existing = evidence_references.get(evidence_id)
                    if existing is not None and existing != normalized:
                        raise DeploymentRefusal(
                            "evidence_reference_invalid",
                            "deployment evidence references disagree about one identity",
                        )
                    evidence_references[evidence_id] = normalized
                    return
                for nested in value.values():
                    collect_evidence_references(nested)
            elif isinstance(value, list):
                for nested in value:
                    collect_evidence_references(nested)

        for sequence, receipt_id in enumerate(receipts, 1):
            receipt = read_json(self._receipt_path(deployment_id, receipt_id), "deployment receipt")
            self._validate_receipt(receipt, deployment_id)
            if (
                receipt.get("receiptId") != receipt_id
                or receipt.get("sequence") != sequence
                or receipt.get("previousReceiptDigest") != prior_digest
            ):
                raise DeploymentRefusal(
                    "receipt_chain_invalid", "deployment receipt chain is not contiguous"
                )
            prior_digest = receipt["receiptDigest"]
            collect_evidence_references(receipt.get("data"))
            receipt_plan_digest = receipt.get("data", {}).get("planDigest")
            if isinstance(receipt_plan_digest, str):
                referenced_plan_digests.add(receipt_plan_digest)
            decision = receipt.get("data", {}).get("authorityDecision")
            if isinstance(decision, Mapping):
                request_id = decision.get("requestId")
                if not isinstance(request_id, str):
                    raise DeploymentRefusal(
                        "authority_receipt_unbound",
                        "deployment decision has no exact request identity",
                    )
                normalized_decision = deepcopy(dict(decision))
                existing_decision = authority_decisions.get(request_id)
                if (
                    existing_decision is not None
                    and existing_decision != normalized_decision
                ):
                    raise DeploymentRefusal(
                        "authority_receipt_unbound",
                        "deployment receipts disagree about an authority decision",
                    )
                authority_decisions[request_id] = normalized_decision
        collect_evidence_references(authority_receipts)
        for reference in authority_receipts:
            decision = authority_decisions.get(reference["requestId"])
            if (
                decision is None
                or decision.get("action") != reference["action"]
                or decision.get("grantId") != reference["grantId"]
                or decision.get("decisionDigest") != reference["decisionDigest"]
                or decision.get("reservationId") != reference["reservationId"]
                or decision.get("reservationDigest")
                != reference["reservationDigest"]
                or decision.get("claimId") != reference["claimId"]
                or decision.get("claimDigest") != reference["claimDigest"]
            ):
                raise DeploymentRefusal(
                    "authority_receipt_unbound",
                    "deployment authority receipt does not bind its exact decision",
                )
        receipt_files = {
            path.stem
            for path in (self._deployment_root(deployment_id) / "receipts").glob("*.json")
            if path.is_file() and not path.is_symlink()
        }
        if receipt_files != set(receipts):
            raise DeploymentRefusal(
                "receipt_chain_invalid",
                "deployment receipt directory contains missing or orphaned evidence",
            )
        transition_receipts = [item.get("receiptId") for item in history if isinstance(item, Mapping)]
        if any(item not in receipts for item in transition_receipts):
            raise DeploymentRefusal(
                "state_invalid", "deployment transition history references unknown evidence"
            )
        plan_root = self._deployment_root(deployment_id) / "plans"
        plan_files = [
            path
            for path in plan_root.glob("*.json")
            if path.is_file() and not path.is_symlink()
        ]
        plans_by_digest: dict[str, dict[str, Any]] = {}
        for path in plan_files:
            plan = validate_plan(read_json(path, "deployment plan"), now=None)
            if (
                plan["spec"]["metadata"]["deploymentId"] != deployment_id
                or path.stem != plan["planId"]
                or plan["planDigest"] in plans_by_digest
            ):
                raise DeploymentRefusal(
                    "plan_closure_invalid",
                    "deployment plan inventory has a conflicting identity",
                )
            plans_by_digest[plan["planDigest"]] = plan
        if set(plans_by_digest) != referenced_plan_digests:
            raise DeploymentRefusal(
                "plan_closure_invalid",
                "deployment plan inventory contains missing or orphaned plans",
            )
        for name in (
            "approvedPlanDigest",
            "acceptedRevision",
            "desiredRevision",
            "observedRevision",
            "rollbackPredecessor",
        ):
            value = state.get(name)
            if value is not None and value not in plans_by_digest:
                raise DeploymentRefusal(
                    "plan_closure_invalid",
                    f"deployment {name} does not resolve to an immutable plan",
                )
        infrastructure = state.get("infrastructureIdentity")
        if isinstance(infrastructure, Mapping):
            for kind in ("networks", "volumes"):
                for resource_id, entry in infrastructure[kind].items():
                    if entry["revision"] not in plans_by_digest:
                        raise DeploymentRefusal(
                            "plan_closure_invalid",
                            f"deployment infrastructure {kind}:{resource_id} does not resolve to an immutable plan",
                        )
        evidence_root = self._deployment_root(deployment_id) / "evidence"
        evidence_files = {
            path.stem
            for path in evidence_root.glob("*.json")
            if path.is_file() and not path.is_symlink()
        }
        if evidence_files != set(evidence_references):
            raise DeploymentRefusal(
                "evidence_closure_invalid",
                "deployment evidence directory contains missing or orphaned documents",
            )
        for evidence_id, reference in evidence_references.items():
            path = self._evidence_path(deployment_id, evidence_id)
            if (
                reference.get("path") != str(path)
                or DIGEST.fullmatch(str(reference.get("payloadDigest"))) is None
                or path.is_symlink()
                or not path.is_file()
                or path.stat().st_mode & 0o777 != 0o600
            ):
                raise DeploymentRefusal(
                    "evidence_reference_invalid",
                    "deployment evidence reference does not bind a private canonical document",
                )
            document = read_json(path, "deployment evidence")
            self._validate_evidence(document, deployment_id)
            if (
                document.get("evidenceId") != evidence_id
                or document.get("payloadDigest")
                != reference.get("payloadDigest")
            ):
                raise DeploymentRefusal(
                    "evidence_reference_invalid",
                    "deployment evidence reference differs from its document",
                )

    @staticmethod
    def _seal_state(state: Mapping[str, Any]) -> dict[str, Any]:
        unsigned = dict(state)
        unsigned.pop("stateDigest", None)
        return {**unsigned, "stateDigest": digest_value(unsigned)}

    @staticmethod
    def _validate_receipt(receipt: Mapping[str, Any], deployment_id: str) -> None:
        expected = {
            "schema",
            "receiptId",
            "deploymentId",
            "sequence",
            "event",
            "actor",
            "createdAt",
            "data",
            "previousReceiptDigest",
            "receiptDigest",
        }
        if set(receipt) != expected or receipt.get("schema") != RECEIPT_SCHEMA or receipt.get("deploymentId") != deployment_id:
            raise DeploymentRefusal("receipt_invalid", "deployment receipt has an invalid shape")
        if (
            isinstance(receipt.get("sequence"), bool)
            or not isinstance(receipt.get("sequence"), int)
            or receipt["sequence"] < 1
            or not isinstance(receipt.get("receiptId"), str)
            or not receipt["receiptId"].startswith("receipt_")
            or not isinstance(receipt.get("event"), str)
            or not isinstance(receipt.get("actor"), str)
            or not isinstance(receipt.get("data"), Mapping)
            or (
                receipt.get("previousReceiptDigest") is not None
                and DIGEST.fullmatch(str(receipt.get("previousReceiptDigest")))
                is None
            )
        ):
            raise DeploymentRefusal(
                "receipt_invalid", "deployment receipt content is invalid"
            )
        try:
            safe_id(receipt["event"], "receipt event")
            safe_id(receipt["actor"], "receipt actor")
        except DeploymentRefusal as exc:
            raise DeploymentRefusal(
                "receipt_invalid", "deployment receipt identity is invalid"
            ) from exc
        _canonical_utc_timestamp(
            receipt.get("createdAt"),
            code="receipt_invalid",
            label="deployment receipt timestamp",
        )
        unsigned = dict(receipt)
        stored = unsigned.pop("receiptDigest", None)
        if stored != digest_value(unsigned):
            raise DeploymentRefusal("receipt_integrity_failed", "deployment receipt integrity check failed")

    @staticmethod
    def _validate_evidence(
        evidence: Mapping[str, Any], deployment_id: str
    ) -> None:
        expected = {
            "schema",
            "evidenceId",
            "deploymentId",
            "kind",
            "createdAt",
            "payload",
            "payloadDigest",
        }
        evidence_id = evidence.get("evidenceId")
        kind = evidence.get("kind")
        payload = evidence.get("payload")
        payload_digest = evidence.get("payloadDigest")
        if (
            set(evidence) != expected
            or evidence.get("schema") != EVIDENCE_SCHEMA
            or evidence.get("deploymentId") != deployment_id
            or not isinstance(evidence_id, str)
            or not isinstance(kind, str)
            or not isinstance(payload, Mapping)
            or not isinstance(payload_digest, str)
            or DIGEST.fullmatch(payload_digest) is None
        ):
            raise DeploymentRefusal(
                "evidence_invalid", "deployment evidence has an invalid shape"
            )
        safe_id(evidence_id, "evidence id")
        safe_id(kind, "evidence kind")
        if payload_digest != digest_value(payload):
            raise DeploymentRefusal(
                "evidence_integrity_failed",
                "deployment evidence payload digest does not match",
            )
        expected_id = f"evidence_{kind}_{payload_digest[7:23]}"
        if evidence_id != expected_id:
            raise DeploymentRefusal(
                "evidence_integrity_failed",
                "deployment evidence identity does not bind its kind and payload",
            )
        try:
            parsed = datetime.fromisoformat(
                str(evidence.get("createdAt")).replace("Z", "+00:00")
            )
        except (TypeError, ValueError) as exc:
            raise DeploymentRefusal(
                "evidence_invalid", "deployment evidence timestamp is invalid"
            ) from exc
        if (
            parsed.tzinfo is None
            or parsed.utcoffset() != timezone.utc.utcoffset(parsed)
            or parsed.microsecond
            or evidence.get("createdAt")
            != parsed.isoformat().replace("+00:00", "Z")
        ):
            raise DeploymentRefusal(
                "evidence_invalid", "deployment evidence timestamp is invalid"
            )

    def _append_receipt_unlocked(
        self,
        state: dict[str, Any],
        *,
        event: str,
        actor: str,
        data: Mapping[str, Any],
        staged_receipts: list[dict[str, Any]],
    ) -> dict[str, Any]:
        safe_id(event, "receipt event")
        safe_id(actor, "receipt actor")
        sequence = len(state["receipts"]) + 1
        prior_digest: str | None = None
        if state["receipts"]:
            prior = next(
                (
                    item
                    for item in reversed(staged_receipts)
                    if item.get("receiptId") == state["receipts"][-1]
                ),
                None,
            )
            if prior is None:
                prior = read_json(
                    self._receipt_path(
                        state["deploymentId"], state["receipts"][-1]
                    ),
                    "prior deployment receipt",
                )
            self._validate_receipt(prior, state["deploymentId"])
            prior_digest = prior["receiptDigest"]
        receipt_id = f"receipt_{sequence:06d}_{digest_value({'event': event, 'data': data, 'prior': prior_digest})[7:23]}"
        unsigned = {
            "schema": RECEIPT_SCHEMA,
            "receiptId": receipt_id,
            "deploymentId": state["deploymentId"],
            "sequence": sequence,
            "event": event,
            "actor": actor,
            "createdAt": timestamp(),
            "data": deepcopy(dict(data)),
            "previousReceiptDigest": prior_digest,
        }
        receipt = {**unsigned, "receiptDigest": digest_value(unsigned)}
        state["receipts"].append(receipt_id)
        staged_receipts.append(receipt)
        return receipt

    def _next_state_unlocked(self, state: dict[str, Any]) -> dict[str, Any]:
        state["revision"] += 1
        state["updatedAt"] = timestamp()
        return self._seal_state(state)

    def _commit_unlocked(
        self,
        deployment_id: str,
        *,
        base_state: Mapping[str, Any] | None,
        next_state: Mapping[str, Any],
        receipts: Sequence[Mapping[str, Any]],
        plans: Sequence[Mapping[str, Any]] = (),
        evidences: Sequence[Mapping[str, Any]] = (),
    ) -> dict[str, Any]:
        """Publish one complete deployment mutation through a recoverable WAL."""

        self._validate_state(
            next_state, deployment_id, validate_documents=False
        )
        receipt_documents = [deepcopy(dict(item)) for item in receipts]
        for receipt in receipt_documents:
            self._validate_receipt(receipt, deployment_id)
        plan_documents = [deepcopy(dict(item)) for item in plans]
        for plan in plan_documents:
            validate_plan(plan, now=None)
            if plan["spec"]["metadata"]["deploymentId"] != deployment_id:
                raise DeploymentRefusal(
                    "transaction_invalid",
                    "pending deployment plan belongs to another deployment",
                )
        evidence_documents = [deepcopy(dict(item)) for item in evidences]
        for evidence in evidence_documents:
            self._validate_evidence(evidence, deployment_id)
        if len({item["evidenceId"] for item in evidence_documents}) != len(
            evidence_documents
        ):
            raise DeploymentRefusal(
                "transaction_invalid",
                "pending deployment transaction repeats an evidence identity",
            )
        base_reference = (
            {
                "revision": base_state["revision"],
                "stateDigest": base_state["stateDigest"],
            }
            if base_state is not None
            else None
        )
        body = {
            "schema": TRANSACTION_SCHEMA,
            "transactionId": "transaction_"
            + digest_value(
                {
                    "deploymentId": deployment_id,
                    "base": base_reference,
                    "nextStateDigest": next_state["stateDigest"],
                    "receiptDigests": [
                        item["receiptDigest"] for item in receipt_documents
                    ],
                    "planDigests": [item["planDigest"] for item in plan_documents],
                    "evidenceDigests": [
                        item["payloadDigest"] for item in evidence_documents
                    ],
                }
            )[7:31],
            "deploymentId": deployment_id,
            "baseState": base_reference,
            "nextState": deepcopy(dict(next_state)),
            "receipts": receipt_documents,
            "plans": plan_documents,
            "evidences": evidence_documents,
        }
        transaction = {**body, "transactionDigest": digest_value(body)}
        transaction_path = self._transaction_path(deployment_id)
        if transaction_path.exists():
            self._recover_unlocked(deployment_id)
            current = self._load_state_unlocked(deployment_id)
            if current == dict(next_state):
                return current
            raise DeploymentRefusal(
                "transaction_conflict",
                "another deployment transaction was recovered before commit",
            )
        atomic_json(transaction_path, transaction, create_only=True)
        self._trip("after_journal")
        self._publish_transaction_unlocked(transaction, recovery=False)
        return self._load_state_unlocked(deployment_id)

    def _validate_transaction_unlocked(
        self, value: Mapping[str, Any], deployment_id: str
    ) -> dict[str, Any]:
        expected = {
            "schema",
            "transactionId",
            "deploymentId",
            "baseState",
            "nextState",
            "receipts",
            "plans",
            "evidences",
            "transactionDigest",
        }
        body = {key: item for key, item in value.items() if key != "transactionDigest"}
        if (
            set(value) != expected
            or value.get("schema") != TRANSACTION_SCHEMA
            or value.get("deploymentId") != deployment_id
            or value.get("transactionDigest") != digest_value(body)
            or not isinstance(value.get("transactionId"), str)
            or not isinstance(value.get("nextState"), Mapping)
            or not isinstance(value.get("receipts"), list)
            or not isinstance(value.get("plans"), list)
            or not isinstance(value.get("evidences"), list)
        ):
            raise DeploymentRefusal(
                "transaction_invalid",
                "pending deployment transaction is malformed or corrupted",
            )
        base = value.get("baseState")
        if base is not None and (
            not isinstance(base, Mapping)
            or set(base) != {"revision", "stateDigest"}
            or isinstance(base.get("revision"), bool)
            or not isinstance(base.get("revision"), int)
            or not isinstance(base.get("stateDigest"), str)
        ):
            raise DeploymentRefusal(
                "transaction_invalid", "pending transaction base state is invalid"
            )
        transaction = deepcopy(dict(value))
        self._validate_state(
            transaction["nextState"], deployment_id, validate_documents=False
        )
        for receipt in transaction["receipts"]:
            if not isinstance(receipt, Mapping):
                raise DeploymentRefusal(
                    "transaction_invalid", "pending receipt is malformed"
                )
            self._validate_receipt(receipt, deployment_id)
        for plan in transaction["plans"]:
            if not isinstance(plan, Mapping):
                raise DeploymentRefusal(
                    "transaction_invalid", "pending plan is malformed"
                )
            validated = validate_plan(plan, now=None)
            if validated["spec"]["metadata"]["deploymentId"] != deployment_id:
                raise DeploymentRefusal(
                    "transaction_invalid", "pending plan belongs to another deployment"
                )
        evidence_ids: set[str] = set()
        for evidence in transaction["evidences"]:
            if not isinstance(evidence, Mapping):
                raise DeploymentRefusal(
                    "transaction_invalid", "pending evidence is malformed"
                )
            self._validate_evidence(evidence, deployment_id)
            if evidence["evidenceId"] in evidence_ids:
                raise DeploymentRefusal(
                    "transaction_invalid",
                    "pending transaction repeats an evidence identity",
                )
            evidence_ids.add(evidence["evidenceId"])
        return transaction

    def _publish_exact_unlocked(
        self, path: Path, value: Mapping[str, Any], label: str
    ) -> None:
        if self._same_document(path, value, label):
            return
        atomic_json(path, value, create_only=True)

    def _publish_transaction_unlocked(
        self, transaction: Mapping[str, Any], *, recovery: bool
    ) -> None:
        deployment_id = str(transaction["deploymentId"])
        validated = self._validate_transaction_unlocked(
            transaction, deployment_id
        )
        state_path = self._state_path(deployment_id)
        current: dict[str, Any] | None = None
        if state_path.exists():
            current = read_json(state_path, "deployment state")
            self._validate_state(
                current, deployment_id, validate_documents=False
            )
            if "dataBackups" not in current:
                current = self._seal_state({**current, "dataBackups": {}})
        base = validated["baseState"]
        next_state = validated["nextState"]
        current_is_next = current == next_state
        if not current_is_next:
            if base is None:
                if current is not None:
                    raise DeploymentRefusal(
                        "transaction_conflict",
                        "creation transaction conflicts with existing deployment state",
                    )
            elif current is None or (
                current.get("revision") != base["revision"]
                or current.get("stateDigest") != base["stateDigest"]
            ):
                raise DeploymentRefusal(
                    "transaction_conflict",
                    "deployment state matches neither transaction base nor result",
                )
        for index, plan in enumerate(validated["plans"], 1):
            self._publish_exact_unlocked(
                self._plan_path(deployment_id, plan["planId"]),
                plan,
                "deployment plan",
            )
            if not recovery:
                self._trip(f"after_plan_{index}")
            self._publish_overlay_unlocked(
                deployment_id,
                plan,
                recovery=recovery,
                plan_index=index,
            )
        for index, evidence in enumerate(validated["evidences"], 1):
            self._publish_exact_unlocked(
                self._evidence_path(deployment_id, evidence["evidenceId"]),
                evidence,
                "deployment evidence",
            )
            if not recovery:
                self._trip(f"after_evidence_{index}")
        for index, receipt in enumerate(validated["receipts"], 1):
            self._publish_exact_unlocked(
                self._receipt_path(deployment_id, receipt["receiptId"]),
                receipt,
                "deployment receipt",
            )
            if not recovery:
                self._trip(f"after_receipt_{index}")
        if not current_is_next:
            if not recovery:
                self._trip("before_state")
            atomic_json(state_path, next_state, create_only=base is None)
            if not recovery:
                self._trip("after_state")
        published = read_json(state_path, "deployment state")
        if published != next_state:
            raise DeploymentRefusal(
                "transaction_conflict",
                "published deployment state differs from pending transaction",
            )
        self._validate_state(published, deployment_id)
        if not recovery:
            self._trip("before_journal_cleanup")
        self._transaction_path(deployment_id).unlink()
        _fsync_directory(self._deployment_root(deployment_id))

    def _recover_unlocked(self, deployment_id: str) -> bool:
        path = self._transaction_path(deployment_id)
        if not path.exists():
            return False
        transaction = read_json(path, "pending deployment transaction")
        self._publish_transaction_unlocked(transaction, recovery=True)
        return True

    def create_from_plan(
        self,
        plan: Mapping[str, Any],
        *,
        actor: str = "local-owner",
        authority_reference: Mapping[str, Any],
    ) -> dict[str, Any]:
        validated = validate_plan(plan)
        spec = validated["spec"]
        deployment_id = spec["metadata"]["deploymentId"]
        root = self._deployment_root(deployment_id, create=True)
        with exclusive_lock(self._lock_path(deployment_id, create=True)):
            self._recover_unlocked(deployment_id)
            state_path = root / "state.json"
            if state_path.exists():
                raise DeploymentRefusal("duplicate_deployment", f"deployment already exists: {deployment_id}")
            staged_receipts: list[dict[str, Any]] = []
            state: dict[str, Any] = {
                "schema": STATE_SCHEMA,
                "deploymentId": deployment_id,
                "applicationId": spec["metadata"]["applicationId"],
                "revision": 1,
                "lifecycleState": "discovered",
                "sourceIdentity": deepcopy(spec["source"]),
                "approvedPlanDigest": None,
                "acceptedRevision": None,
                "desiredRevision": validated["planDigest"],
                "observedRevision": None,
                "imageDigests": {},
                "serviceHealth": {},
                "targetIdentity": deepcopy(spec["target"]),
                "storageIdentities": {},
                "dataBackups": {},
                "secretBindingIdentifiers": sorted(
                    {secret["binding"] for service in spec["services"] for secret in service["secrets"]}
                ),
                "currentTransition": None,
                "transitionHistory": [],
                "receipts": [],
                "authorityReceipts": [],
                "lastSuccessfulObservation": None,
                "driftStatus": "not_observed",
                "rollbackPredecessor": None,
                "infrastructureIdentity": None,
                "removalState": "runtime_absent",
                "retainedDataState": "not_created",
                "createdAt": timestamp(),
                "updatedAt": timestamp(),
            }
            for target, event in (("planned", "plan_created"), ("awaiting_approval", "approval_required")):
                prior = state["lifecycleState"]
                validate_transition(prior, target)
                receipt_data = {
                    "from": prior,
                    "to": target,
                    "planDigest": validated["planDigest"],
                    "authorityDecision": deepcopy(dict(authority_reference)),
                }
                if target == "awaiting_approval":
                    receipt_data.update(
                        terminal_authority_data(
                            authority_reference,
                            deployment_id=deployment_id,
                            result=validated,
                            status="succeeded",
                            code=None,
                            summary="Exact deployment plan was created and now awaits approval",
                        )
                    )
                receipt = self._append_receipt_unlocked(
                    state,
                    event=event,
                    actor=actor,
                    data=receipt_data,
                    staged_receipts=staged_receipts,
                )
                state["lifecycleState"] = target
                state["transitionHistory"].append(
                    {"from": prior, "to": target, "receiptId": receipt["receiptId"], "at": receipt["createdAt"]}
                )
            sealed = self._seal_state(state)
            return self._commit_unlocked(
                deployment_id,
                base_state=None,
                next_state=sealed,
                receipts=staged_receipts,
                plans=(validated,),
            )

    def load_plan(self, deployment_id: str, plan_digest: str, *, require_unexpired: bool = True) -> dict[str, Any]:
        with exclusive_lock(self._lock_path(deployment_id)):
            self._recover_unlocked(deployment_id)
            return self._load_plan_unlocked(
                deployment_id,
                plan_digest,
                require_unexpired=require_unexpired,
            )

    def _load_plan_unlocked(
        self,
        deployment_id: str,
        plan_digest: str,
        *,
        require_unexpired: bool = True,
    ) -> dict[str, Any]:
        if not isinstance(plan_digest, str):
            raise DeploymentRefusal("plan_not_found", "exact plan digest is required")
        root = self._deployment_root(deployment_id) / "plans"
        for path in sorted(root.glob("*.json")):
            if path.is_symlink():
                raise DeploymentRefusal("record_invalid", "plan store contains a symlink")
            plan = read_json(path, "deployment plan")
            if plan.get("planDigest") == plan_digest:
                return validate_plan(plan, now=None if not require_unexpired else datetime.now(timezone.utc))
        raise DeploymentRefusal("plan_not_found", "exact deployment plan was not found")

    def authority_decision_reference(
        self, deployment_id: str, request_id: str
    ) -> dict[str, Any]:
        """Resolve one canonical decision reference from committed receipts."""

        with exclusive_lock(self._lock_path(deployment_id)):
            self._recover_unlocked(deployment_id)
            matches = [
                reference
                for reference in self._authority_decision_references_unlocked(
                    deployment_id
                )
                if reference.get("requestId") == request_id
            ]
            if len(matches) != 1:
                raise DeploymentRefusal(
                    "authority_receipt_unbound",
                    "canonical authority receipt has no exact deployment decision",
                )
            return matches[0]

    def authority_decision_references(
        self, deployment_id: str
    ) -> list[dict[str, Any]]:
        """Return each exact authority decision embedded in deployment evidence."""

        with exclusive_lock(self._lock_path(deployment_id)):
            self._recover_unlocked(deployment_id)
            return self._authority_decision_references_unlocked(deployment_id)

    def _authority_decision_references_unlocked(
        self, deployment_id: str
    ) -> list[dict[str, Any]]:
        state = self._load_state_unlocked(deployment_id)
        references: dict[str, dict[str, Any]] = {}
        order: list[str] = []
        for receipt_id in state["receipts"]:
            receipt = read_json(
                self._receipt_path(deployment_id, receipt_id),
                "deployment receipt",
            )
            self._validate_receipt(receipt, deployment_id)
            reference = receipt.get("data", {}).get("authorityDecision")
            if not isinstance(reference, Mapping):
                continue
            request_id = reference.get("requestId")
            if not isinstance(request_id, str):
                raise DeploymentRefusal(
                    "authority_receipt_unbound",
                    "deployment authority decision has no exact request identity",
                )
            normalized = deepcopy(dict(reference))
            existing = references.get(request_id)
            if existing is not None and existing != normalized:
                raise DeploymentRefusal(
                    "authority_receipt_unbound",
                    "deployment receipts disagree about an authority decision",
                )
            if existing is None:
                references[request_id] = normalized
                order.append(request_id)
        return [references[request_id] for request_id in order]

    def unlinked_authority_decisions(
        self, deployment_id: str
    ) -> list[dict[str, Any]]:
        """Return committed deployment decisions lacking canonical receipt links."""

        with exclusive_lock(self._lock_path(deployment_id)):
            self._recover_unlocked(deployment_id)
            state = self._load_state_unlocked(deployment_id)
            linked = {
                item.get("requestId")
                for item in state["authorityReceipts"]
                if isinstance(item, Mapping)
            }
            return [
                reference
                for reference in self._authority_decision_references_unlocked(
                    deployment_id
                )
                if reference.get("requestId") not in linked
            ]

    def authority_effect_outcome(
        self, deployment_id: str, request_id: str
    ) -> dict[str, Any] | None:
        """Resolve a durable interruption outcome for one claimed request."""

        with exclusive_lock(self._lock_path(deployment_id)):
            self._recover_unlocked(deployment_id)
            state = self._load_state_unlocked(deployment_id)
            matches: list[dict[str, Any]] = []
            for receipt_id in state["receipts"]:
                receipt = read_json(
                    self._receipt_path(deployment_id, receipt_id),
                    "deployment receipt",
                )
                self._validate_receipt(receipt, deployment_id)
                data = receipt.get("data")
                if not isinstance(data, Mapping):
                    continue
                authority = data.get("authorityDecision")
                if (
                    isinstance(authority, Mapping)
                    and authority.get("requestId") == request_id
                    and isinstance(data.get("authorityOutcome"), Mapping)
                ):
                    matches.append(deepcopy(dict(data["authorityOutcome"])))
                if (
                    data.get("reconciledAuthorityRequestId") == request_id
                    and isinstance(
                        data.get("reconciledAuthorityOutcome"), Mapping
                    )
                ):
                    matches.append(
                        deepcopy(dict(data["reconciledAuthorityOutcome"]))
                    )
            if not matches:
                return None
            if len(matches) != 1:
                raise DeploymentRefusal(
                    "authority_receipt_unbound",
                    "claimed deployment action has conflicting reconciliation outcomes",
                )
            outcome = matches[0]
            if (
                set(outcome) != {"status", "code", "summary", "resource"}
                or outcome.get("status") not in {"succeeded", "failed"}
                or not isinstance(outcome.get("summary"), str)
                or not isinstance(outcome.get("resource"), Mapping)
            ):
                raise DeploymentRefusal(
                    "authority_receipt_unbound",
                    "claimed deployment action reconciliation outcome is invalid",
                )
            return outcome

    def link_authority_receipt(
        self,
        deployment_id: str,
        reference: Mapping[str, Any],
        *,
        actor: str,
        evidence_document: Mapping[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any], bool]:
        """Atomically link one exact canonical receipt, or return its prior link."""

        normalized = deepcopy(dict(reference))
        receipt_id = normalized.get("receiptId")
        if not isinstance(receipt_id, str):
            raise DeploymentRefusal(
                "authority_receipt_invalid", "authority receipt link has no identity"
            )
        with exclusive_lock(self._lock_path(deployment_id)):
            self._recover_unlocked(deployment_id)
            state = self._load_state_unlocked(deployment_id)
            existing = [
                deepcopy(dict(item))
                for item in state["authorityReceipts"]
                if isinstance(item, Mapping) and item.get("receiptId") == receipt_id
            ]
            if existing:
                if len(existing) != 1 or existing[0] != normalized:
                    raise DeploymentRefusal(
                        "authority_receipt_unbound",
                        "linked authority receipt identity conflicts with canonical evidence",
                    )
                link_receipts: list[dict[str, Any]] = []
                for deployment_receipt_id in state["receipts"]:
                    deployment_receipt = read_json(
                        self._receipt_path(deployment_id, deployment_receipt_id),
                        "deployment receipt",
                    )
                    self._validate_receipt(deployment_receipt, deployment_id)
                    if (
                        deployment_receipt.get("event")
                        == "authority_receipt_linked"
                        and deployment_receipt.get("data", {}).get(
                            "authorityReceipt"
                        )
                        == normalized
                    ):
                        link_receipts.append(deployment_receipt)
                if len(link_receipts) != 1:
                    raise DeploymentRefusal(
                        "authority_receipt_unbound",
                        "linked authority receipt has no unique deployment receipt",
                    )
                return state, link_receipts[0], True
            base_state = deepcopy(state)
            staged_receipts: list[dict[str, Any]] = []
            state["authorityReceipts"].append(normalized)
            link_receipt = self._append_receipt_unlocked(
                state,
                event="authority_receipt_linked",
                actor=actor,
                data={"authorityReceipt": normalized},
                staged_receipts=staged_receipts,
            )
            next_state = self._next_state_unlocked(state)
            committed = self._commit_unlocked(
                deployment_id,
                base_state=base_state,
                next_state=next_state,
                receipts=staged_receipts,
                evidences=(evidence_document,),
            )
            return committed, link_receipt, False

    def plan_path(self, deployment_id: str, plan_id: str) -> Path:
        deployment_id = safe_id(deployment_id, "deployment id")
        plan_id = safe_id(plan_id, "plan id")
        deployment_root = self.deployments / deployment_id
        if deployment_root.is_symlink():
            raise DeploymentRefusal("unsafe_state_root", "deployment record may not be a symlink")
        return deployment_root / "plans" / f"{plan_id}.json"

    def add_plan(
        self,
        plan: Mapping[str, Any],
        *,
        actor: str = "local-owner",
        authority_reference: Mapping[str, Any],
    ) -> dict[str, Any]:
        validated = validate_plan(plan)
        deployment_id = validated["spec"]["metadata"]["deploymentId"]
        with exclusive_lock(self._lock_path(deployment_id)):
            self._recover_unlocked(deployment_id)
            state = self._load_state_unlocked(deployment_id)
            base_state = deepcopy(state)
            staged_receipts: list[dict[str, Any]] = []
            allowed = (
                validated["operation"] == "purge_data"
                and (
                    state["lifecycleState"] == "removed_runtime_data_retained"
                    or (
                        state["lifecycleState"] == "failed"
                        and state.get("retainedDataState")
                        == "retained_after_failed_apply"
                    )
                )
            ) or (
                validated["operation"] == "apply"
                and state["lifecycleState"] == "failed"
                and not state["storageIdentities"]
            ) or (
                validated["operation"] in {"update", "rollback"}
                and state["lifecycleState"] in {"healthy", "degraded"}
                and state.get("acceptedRevision")
                == validated["predecessorRevision"]
            ) or (
                validated["operation"] in {"backup_data", "restore_data"}
                and state["lifecycleState"] in {"healthy", "degraded"}
                and state.get("acceptedRevision")
                == validated["predecessorRevision"]
            )
            if (
                not allowed
                and state["lifecycleState"] == "awaiting_approval"
                and state.get("currentTransition") is None
                and state.get("approvedPlanDigest") is None
                and isinstance(state.get("desiredRevision"), str)
            ):
                current = self._load_plan_unlocked(
                    deployment_id,
                    state["desiredRevision"],
                    require_unexpired=False,
                )
                try:
                    validate_plan(current, now=datetime.now(timezone.utc))
                except DeploymentRefusal as exc:
                    allowed = (
                        exc.code == "plan_expired"
                        and current["operation"] == validated["operation"]
                    )
                else:
                    allowed = False
            if not allowed:
                raise DeploymentRefusal(
                    "invalid_transition",
                    "a successor plan is allowed only after a failed apply, retained-data removal, exact plan expiry, or as an exact update of the accepted revision",
                )
            new_spec = validated["spec"]
            if validated["operation"] in {"update", "rollback"}:
                predecessor_plan = self._load_plan_unlocked(
                    deployment_id,
                    validated["predecessorRevision"],
                    require_unexpired=False,
                )
                if validated["changes"] != deployment_update_changes(
                    predecessor_plan["spec"], new_spec
                ):
                    raise DeploymentRefusal(
                        "invalid_contract",
                        "an update plan must name the exact diff against the superseded accepted revision",
                    )
                if validated["operation"] == "rollback":
                    restored_plan = self._load_plan_unlocked(
                        deployment_id,
                        validated["rollbackOf"],
                        require_unexpired=False,
                    )
                    if restored_plan["spec"] != new_spec:
                        raise DeploymentRefusal(
                            "invalid_contract",
                            "a rollback plan must restore the exact specification of the revision it names",
                        )
            prior_source = state["sourceIdentity"]
            if (
                state["applicationId"]
                != new_spec["metadata"]["applicationId"]
                or prior_source["repositoryIdentity"]
                != new_spec["source"]["repositoryIdentity"]
                or prior_source["repositoryRoot"]
                != new_spec["source"]["repositoryRoot"]
                or prior_source["projectPath"]
                != new_spec["source"]["projectPath"]
                or state["targetIdentity"] != new_spec["target"]
            ):
                raise DeploymentRefusal(
                    "deployment_identity_mismatch",
                    "a deployment identity cannot be repurposed for another application, source, or target",
                )
            if state["storageIdentities"]:
                prior_plan_digest = (
                    validated["predecessorRevision"]
                    if validated["operation"] == "purge_data"
                    else state.get("acceptedRevision") or state.get("desiredRevision")
                )
                prior_plan = self._load_plan_unlocked(
                    deployment_id,
                    prior_plan_digest,
                    require_unexpired=False,
                )
                prior_storage = {
                    item["id"]: (item["mountPath"], item["persistence"])
                    for service in prior_plan["spec"]["services"]
                    for item in service["storage"]
                }
                new_storage = {
                    item["id"]: (item["mountPath"], item["persistence"])
                    for service in new_spec["services"]
                    for item in service["storage"]
                }
                if any(
                    new_storage.get(storage_id) != prior_storage.get(storage_id)
                    for storage_id in state["storageIdentities"]
                ):
                    raise DeploymentRefusal(
                        "storage_identity_conflict",
                        "a successor plan cannot repurpose retained storage",
                    )
            if validated["operation"] in {"backup_data", "restore_data"}:
                accepted_storage = sorted(state["storageIdentities"])
                planned_storage = sorted(item["id"] for item in validated["changes"])
                expected_destructive = (
                    []
                    if validated["operation"] == "backup_data"
                    else [
                        {"kind": "volume", "name": name, "irreversible": True}
                        for name in sorted(state["storageIdentities"].values())
                    ]
                )
                if (
                    not accepted_storage
                    or planned_storage != accepted_storage
                    or validated["destructiveEffects"] != expected_destructive
                ):
                    raise DeploymentRefusal(
                        "stale_plan",
                        "data plan effects do not match accepted retained storage",
                    )
            state["desiredRevision"] = validated["planDigest"]
            state["approvedPlanDigest"] = None
            state["sourceIdentity"] = deepcopy(validated["spec"]["source"])
            state["targetIdentity"] = deepcopy(validated["spec"]["target"])
            state["secretBindingIdentifiers"] = sorted(
                {
                    secret["binding"]
                    for service in validated["spec"]["services"]
                    for secret in service["secrets"]
                }
            )
            state["currentTransition"] = None
            state["driftStatus"] = "not_observed"
            prefix = (
                "purge"
                if validated["operation"] == "purge_data"
                else (
                    validated["operation"]
                    if validated["operation"]
                    in {"update", "rollback", "backup_data", "restore_data"}
                    else "recovery"
                )
            )
            first_target = (
                "update_planned"
                if validated["operation"]
                in {"update", "rollback", "backup_data", "restore_data"}
                else "planned"
            )
            for target, event in (
                (first_target, f"{prefix}_plan_created"),
                ("awaiting_approval", f"{prefix}_approval_required"),
            ):
                prior = state["lifecycleState"]
                validate_transition(prior, target)
                receipt_data = {
                    "from": prior,
                    "to": target,
                    "planDigest": validated["planDigest"],
                    "operation": validated["operation"],
                    "authorityDecision": deepcopy(dict(authority_reference)),
                }
                if target == "awaiting_approval":
                    receipt_data.update(
                        terminal_authority_data(
                            authority_reference,
                            deployment_id=deployment_id,
                            result=validated,
                            status="succeeded",
                            code=None,
                            summary="Exact deployment plan was created and now awaits approval",
                        )
                    )
                receipt = self._append_receipt_unlocked(
                    state,
                    event=event,
                    actor=actor,
                    data=receipt_data,
                    staged_receipts=staged_receipts,
                )
                state["lifecycleState"] = target
                state["transitionHistory"].append(
                    {"from": prior, "to": target, "receiptId": receipt["receiptId"], "at": receipt["createdAt"]}
                )
            next_state = self._next_state_unlocked(state)
            return self._commit_unlocked(
                deployment_id,
                base_state=base_state,
                next_state=next_state,
                receipts=staged_receipts,
                plans=(validated,),
            )

    def overlay_root(self, deployment_id: str, plan_id: str, *, create: bool = False) -> Path:
        path = self._deployment_root(deployment_id) / "overlays" / safe_id(plan_id, "plan id")
        if path.is_symlink():
            raise DeploymentRefusal("unsafe_state_root", "deployment overlay is unsafe")
        if create:
            ensure_private_directory(path)
        elif not path.is_dir():
            raise DeploymentRefusal("overlay_missing", "deployment overlay is missing")
        return path

    @staticmethod
    def _overlay_contents(root: Path) -> dict[str, str]:
        observed: dict[str, str] = {}
        if root.is_symlink() or not root.is_dir():
            raise DeploymentRefusal(
                "overlay_integrity_failed",
                "deployment overlay is not a safe directory",
            )
        for path in sorted(root.rglob("*")):
            if path.is_symlink():
                raise DeploymentRefusal(
                    "overlay_integrity_failed",
                    "deployment overlay contains a symlink",
                )
            if path.is_dir():
                continue
            if not path.is_file() or path.stat().st_mode & 0o777 != 0o600:
                raise DeploymentRefusal(
                    "overlay_integrity_failed",
                    "deployment overlay contains an unsafe entry or mode",
                )
            relative = path.relative_to(root).as_posix()
            try:
                observed[relative] = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as exc:
                raise DeploymentRefusal(
                    "overlay_integrity_failed",
                    "deployment overlay could not be verified",
                ) from exc
        return observed

    def _publish_overlay_unlocked(
        self,
        deployment_id: str,
        plan: Mapping[str, Any],
        *,
        recovery: bool,
        plan_index: int,
    ) -> None:
        """Publish the plan-bound overlay before its state becomes visible."""

        plan_id = safe_id(str(plan["planId"]), "plan id")
        expected = dict(plan["overlay"])
        overlays = self._deployment_root(deployment_id) / "overlays"
        ensure_private_directory(overlays)
        final = overlays / plan_id
        staging = overlays / f".pending-{plan_id}"
        if final.exists():
            if self._overlay_contents(final) != expected:
                raise DeploymentRefusal(
                    "overlay_conflict",
                    "pending deployment transaction conflicts with its final overlay",
                )
            if staging.exists():
                if self._overlay_contents(staging) != expected:
                    raise DeploymentRefusal(
                        "overlay_conflict",
                        "pending deployment transaction has conflicting overlay staging",
                    )
                shutil.rmtree(staging)
                _fsync_directory(overlays)
            return
        if staging.is_symlink():
            raise DeploymentRefusal(
                "overlay_conflict", "deployment overlay staging may not be a symlink"
            )
        ensure_private_directory(staging)
        expected_paths = set(expected)
        for file_index, (relative, content) in enumerate(
            sorted(expected.items()), 1
        ):
            safe_relative = relative_posix(
                relative, "overlay path", allow_dot=False
            )
            target = staging / safe_relative
            ensure_private_directory(target.parent)
            pending = target.with_name(target.name + ".stateport-pending")
            if pending.exists():
                if pending.is_symlink() or not pending.is_file():
                    raise DeploymentRefusal(
                        "overlay_conflict",
                        "deployment overlay contains unsafe pending content",
                    )
                pending.unlink()
            if target.exists():
                if (
                    target.is_symlink()
                    or not target.is_file()
                    or target.stat().st_mode & 0o777 != 0o600
                    or target.read_text(encoding="utf-8") != content
                ):
                    raise DeploymentRefusal(
                        "overlay_conflict",
                        "deployment overlay identity changed during publication",
                    )
            else:
                with pending.open("x", encoding="utf-8") as handle:
                    handle.write(content)
                    handle.flush()
                    os.fsync(handle.fileno())
                pending.chmod(0o600)
                pending.replace(target)
                _fsync_directory(target.parent)
            if not recovery:
                self._trip(
                    f"after_overlay_file_{plan_index}_{file_index}"
                )
        observed = self._overlay_contents(staging)
        if set(observed) != expected_paths or observed != expected:
            raise DeploymentRefusal(
                "overlay_conflict",
                "deployment overlay staging differs from the exact plan",
            )
        staging.replace(final)
        _fsync_directory(overlays)
        if not recovery:
            self._trip(f"after_overlay_{plan_index}")

    def write_overlay(self, deployment_id: str, plan_id: str, files: Mapping[str, str]) -> Path:
        root = self.overlay_root(deployment_id, plan_id, create=True)
        for relative, content in sorted(files.items()):
            safe_relative = relative_posix(relative, "overlay path", allow_dot=False)
            target = root / safe_relative
            if target.exists():
                current = target.read_text(encoding="utf-8")
                if current != content:
                    raise DeploymentRefusal("overlay_conflict", "deployment overlay identity changed")
                continue
            ensure_private_directory(target.parent)
            target.write_text(content, encoding="utf-8")
            target.chmod(0o600)
        return root

    def verify_overlay(self, deployment_id: str, plan_id: str, files: Mapping[str, str]) -> Path:
        root = self.overlay_root(deployment_id, plan_id)
        observed = self._overlay_contents(root)
        if observed != dict(files):
            raise DeploymentRefusal(
                "overlay_integrity_failed", "deployment overlay differs from the approved plan"
            )
        return root

    def prepare_evidence(
        self,
        deployment_id: str,
        *,
        kind: str,
        value: Mapping[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Prepare evidence for publication in the caller's state transaction."""

        safe_id(kind, "evidence kind")
        digest = digest_value(value)
        evidence_id = f"evidence_{kind}_{digest[7:23]}"
        with exclusive_lock(self._lock_path(deployment_id)):
            self._recover_unlocked(deployment_id)
            path = self._evidence_path(deployment_id, evidence_id)
            if path.exists():
                document = read_json(path, "deployment evidence")
                self._validate_evidence(document, deployment_id)
                if (
                    document.get("payload") != dict(value)
                    or document.get("payloadDigest") != digest
                ):
                    raise DeploymentRefusal(
                        "identity_conflict",
                        "deployment evidence identity changed",
                    )
            else:
                document = {
                    "schema": EVIDENCE_SCHEMA,
                    "evidenceId": evidence_id,
                    "deploymentId": deployment_id,
                    "kind": kind,
                    "createdAt": timestamp(),
                    "payload": deepcopy(dict(value)),
                    "payloadDigest": digest,
                }
                self._validate_evidence(document, deployment_id)
        reference = {
            "evidenceId": evidence_id,
            "path": str(path),
            "payloadDigest": digest,
        }
        return reference, document

    def build_context_root(self, deployment_id: str, plan_id: str, *, create: bool = False) -> Path:
        path = self._deployment_root(deployment_id) / "build-contexts" / safe_id(plan_id, "plan id")
        if path.is_symlink():
            raise DeploymentRefusal("unsafe_state_root", "deployment build context is unsafe")
        if create:
            ensure_private_directory(path)
        elif not path.is_dir():
            raise DeploymentRefusal("build_context_missing", "deployment build context is missing")
        return path

    def new_build_context_path(self, deployment_id: str, plan_id: str) -> Path:
        """Return a confined path that must not exist before exact materialisation."""
        path = (
            self._deployment_root(deployment_id)
            / "build-contexts"
            / safe_id(plan_id, "plan id")
        )
        if path.is_symlink() or path.exists():
            raise DeploymentRefusal(
                "build_context_conflict",
                "exact deployment build context already exists; reconcile before replay",
            )
        return path

    def cleanup_build_context(
        self,
        deployment_id: str,
        operation_id: str,
        *,
        expected_digest: str | None = None,
        expected_inventory: Sequence[Mapping[str, Any]] | None = None,
        allow_partial: bool = False,
    ) -> dict[str, Any]:
        """Remove one exact generated source copy after inventory verification."""

        path = (
            self._deployment_root(deployment_id)
            / "build-contexts"
            / safe_id(operation_id, "operation id")
        )
        parent = path.parent
        if path.is_symlink():
            raise DeploymentRefusal(
                "build_context_cleanup_unsafe",
                "generated build context may not be a symlink",
            )
        if not path.exists():
            return {
                "operationId": operation_id,
                "status": "already_absent",
                "contextDigest": expected_digest,
                "inventoryComplete": None,
                "filesRemoved": 0,
                "bytesRemoved": 0,
            }
        if not path.is_dir():
            raise DeploymentRefusal(
                "build_context_cleanup_unsafe",
                "generated build context is not a directory",
            )
        inventory: list[dict[str, Any]] = []
        total = 0
        for candidate in sorted(path.rglob("*")):
            if candidate.is_symlink():
                raise DeploymentRefusal(
                    "build_context_cleanup_unsafe",
                    "generated build context contains a symlink",
                )
            if candidate.is_dir():
                continue
            if not candidate.is_file():
                raise DeploymentRefusal(
                    "build_context_cleanup_unsafe",
                    "generated build context contains an unsafe entry",
                )
            content = candidate.read_bytes()
            total += len(content)
            inventory.append(
                {
                    "path": candidate.relative_to(path).as_posix(),
                    "mode": (
                        "100755"
                        if candidate.stat().st_mode & 0o111
                        else "100644"
                    ),
                    "size": len(content),
                    "sha256": "sha256:" + hashlib.sha256(content).hexdigest(),
                }
            )
        observed_digest = digest_value(inventory)
        inventory_complete = True
        if expected_inventory is not None:
            expected_by_path = {
                str(item.get("path")): {
                    "mode": item.get("mode"),
                    "sha256": item.get("contentDigest"),
                }
                for item in expected_inventory
            }
            observed_by_path = {
                item["path"]: {
                    "mode": item["mode"],
                    "sha256": item["sha256"],
                }
                for item in inventory
            }
            if (
                len(expected_by_path) != len(expected_inventory)
                or any(
                    not path_name
                    or value["mode"] not in {"100644", "100755"}
                    or DIGEST.fullmatch(str(value["sha256"])) is None
                    for path_name, value in expected_by_path.items()
                )
                or any(
                    path_name not in expected_by_path
                    or expected_by_path[path_name] != value
                    for path_name, value in observed_by_path.items()
                )
            ):
                raise DeploymentRefusal(
                    "build_context_cleanup_unsafe",
                    "generated build context is outside its exact source inventory",
                )
            inventory_complete = set(observed_by_path) == set(expected_by_path)
            if not allow_partial and not inventory_complete:
                raise DeploymentRefusal(
                    "build_context_cleanup_unsafe",
                    "generated build context is incomplete",
                )
        if (
            expected_digest is not None
            and inventory_complete
            and observed_digest != expected_digest
        ):
            raise DeploymentRefusal(
                "build_context_cleanup_unsafe",
                "generated build context differs from its exact materialization receipt",
                details={
                    "expectedDigest": expected_digest,
                    "observedDigest": observed_digest,
                },
            )
        shutil.rmtree(path)
        _fsync_directory(parent)
        if path.exists():
            raise DeploymentRefusal(
                "build_context_cleanup_failed",
                "generated build context remains after cleanup",
            )
        return {
            "operationId": operation_id,
            "status": "removed",
            "contextDigest": observed_digest,
            "inventoryComplete": inventory_complete,
            "filesRemoved": len(inventory),
            "bytesRemoved": total,
        }

    @contextmanager
    def operation_lock(self, deployment_id: str) -> Iterator[None]:
        """Prevent overlapping external effects for one deployment."""
        path = self._deployment_root(deployment_id) / ".operation.lock"
        with exclusive_lock(path):
            yield

    def mutate(
        self,
        deployment_id: str,
        *,
        event: str,
        actor: str,
        data: Mapping[str, Any],
        mutation: StateMutation,
        transition_to: str | None = None,
        expected_operation_id: str | None = None,
        authority_outcome: Mapping[str, Any] | None = None,
        evidence_documents: Sequence[Mapping[str, Any]] = (),
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        with exclusive_lock(self._lock_path(deployment_id)):
            self._recover_unlocked(deployment_id)
            state = self._load_state_unlocked(deployment_id)
            base_state = deepcopy(state)
            staged_receipts: list[dict[str, Any]] = []
            prior = state["lifecycleState"]
            if expected_operation_id is not None:
                transition = state.get("currentTransition")
                if not isinstance(transition, Mapping) or transition.get("operationId") != expected_operation_id:
                    raise DeploymentRefusal(
                        "operation_identity_mismatch",
                        "deployment transition no longer belongs to this operation",
                    )
            if transition_to is not None:
                validate_transition(prior, transition_to)
            mutation(state)
            receipt_data = deepcopy(dict(data))
            if transition_to is not None:
                receipt_data.update({"from": prior, "to": transition_to})
            if authority_outcome is not None:
                authority_reference = receipt_data.get("authorityDecision")
                if not isinstance(authority_reference, Mapping):
                    raise DeploymentRefusal(
                        "authority_receipt_unbound",
                        "terminal deployment receipt lacks its authority decision",
                    )
                if (
                    set(authority_outcome)
                    not in (
                        {"status", "code", "summary"},
                        {"status", "code", "summary", "resource"},
                    )
                    or authority_outcome.get("status")
                    not in {"succeeded", "failed"}
                    or not isinstance(authority_outcome.get("summary"), str)
                    or (
                        "resource" in authority_outcome
                        and not isinstance(authority_outcome.get("resource"), Mapping)
                    )
                ):
                    raise DeploymentRefusal(
                        "authority_receipt_unbound",
                        "terminal deployment authority outcome is invalid",
                    )
                projected_state = deepcopy(state)
                if transition_to is not None:
                    projected_state["lifecycleState"] = transition_to
                terminal_result: dict[str, Any] = {"state": projected_state}
                if "resource" in authority_outcome:
                    terminal_result["authorityResource"] = deepcopy(
                        dict(authority_outcome["resource"])
                    )
                receipt_data.update(
                    terminal_authority_data(
                        authority_reference,
                        deployment_id=deployment_id,
                        result=terminal_result,
                        status=authority_outcome["status"],
                        code=authority_outcome["code"],
                        summary=authority_outcome["summary"],
                    )
                )
            receipt = self._append_receipt_unlocked(
                state,
                event=event,
                actor=actor,
                data=receipt_data,
                staged_receipts=staged_receipts,
            )
            if transition_to is not None:
                state["lifecycleState"] = transition_to
                state["transitionHistory"].append(
                    {"from": prior, "to": transition_to, "receiptId": receipt["receiptId"], "at": receipt["createdAt"]}
                )
            next_state = self._next_state_unlocked(state)
            committed = self._commit_unlocked(
                deployment_id,
                base_state=base_state,
                next_state=next_state,
                receipts=staged_receipts,
                evidences=evidence_documents,
            )
            return committed, receipt

    def approve_and_reserve(
        self,
        deployment_id: str,
        plan: Mapping[str, Any],
        *,
        actor: str,
        authority_reference: Mapping[str, Any],
    ) -> tuple[dict[str, Any], list[dict[str, Any]], str]:
        """Atomically record exact approval and reserve its external effect."""

        validated = validate_plan(plan)
        digest = validated["planDigest"]
        operation = validated["operation"]
        with exclusive_lock(self._lock_path(deployment_id)):
            self._recover_unlocked(deployment_id)
            validated = validate_plan(
                plan, now=datetime.now(timezone.utc)
            )
            digest = validated["planDigest"]
            operation = validated["operation"]
            state = self._load_state_unlocked(deployment_id)
            base_state = deepcopy(state)
            if state["lifecycleState"] != "awaiting_approval" or state["currentTransition"] is not None:
                raise DeploymentRefusal("invalid_transition", "deployment is not awaiting an exact approval")
            if (
                state["desiredRevision"] != digest
                or state["sourceIdentity"] != validated["spec"]["source"]
                or state["targetIdentity"] != validated["spec"]["target"]
            ):
                raise DeploymentRefusal("stale_plan", "deployment plan no longer matches desired source or target")
            receipts: list[dict[str, Any]] = []
            prior = state["lifecycleState"]
            validate_transition(prior, "approved")
            state["approvedPlanDigest"] = digest
            approval = self._append_receipt_unlocked(
                state,
                event="plan_approved",
                actor=actor,
                data={
                    "from": prior,
                    "to": "approved",
                    "planDigest": digest,
                    "operation": operation,
                    "authorityDecision": deepcopy(dict(authority_reference)),
                },
                staged_receipts=receipts,
            )
            state["lifecycleState"] = "approved"
            state["transitionHistory"].append(
                {"from": prior, "to": "approved", "receiptId": approval["receiptId"], "at": approval["createdAt"]}
            )
            operation_id = "operation_" + digest_value(
                {
                    "deploymentId": deployment_id,
                    "planDigest": digest,
                    "operation": operation,
                    "stateRevision": state["revision"],
                    "approvedAt": approval["createdAt"],
                }
            )[7:31]
            target = (
                "updating"
                if operation
                in {"update", "rollback", "backup_data", "restore_data"}
                else "applying"
            )
            validate_transition("approved", target)
            state["currentTransition"] = {
                "operationId": operation_id,
                "operation": operation,
                "planDigest": digest,
                "phase": "executing",
                "startedAt": timestamp(),
                "authorityDecision": deepcopy(dict(authority_reference)),
            }
            reservation = self._append_receipt_unlocked(
                state,
                event=f"{operation}_reserved",
                actor=actor,
                data={
                    "from": "approved",
                    "to": target,
                    "operationId": operation_id,
                    "planDigest": digest,
                    "authorityDecision": deepcopy(dict(authority_reference)),
                },
                staged_receipts=receipts,
            )
            state["lifecycleState"] = target
            state["transitionHistory"].append(
                {"from": "approved", "to": target, "receiptId": reservation["receiptId"], "at": reservation["createdAt"]}
            )
            next_state = self._next_state_unlocked(state)
            committed = self._commit_unlocked(
                deployment_id,
                base_state=base_state,
                next_state=next_state,
                receipts=receipts,
            )
            return committed, receipts, operation_id

    def reserve_runtime_operation(
        self,
        deployment_id: str,
        *,
        operation: str,
        actor: str,
        allowed_states: set[str],
        plan_digest: str,
        authority_reference: Mapping[str, Any],
        supersede_interrupted: bool = False,
    ) -> tuple[dict[str, Any], dict[str, Any], str]:
        """Reserve restart/remove-like effects without overlapping writers."""

        safe_id(operation, "operation")
        with exclusive_lock(self._lock_path(deployment_id)):
            self._recover_unlocked(deployment_id)
            state = self._load_state_unlocked(deployment_id)
            base_state = deepcopy(state)
            staged_receipts: list[dict[str, Any]] = []
            prior_transition = state.get("currentTransition")
            can_supersede = (
                supersede_interrupted
                and state["lifecycleState"] == "reconciliation_required"
                and isinstance(prior_transition, Mapping)
                and prior_transition.get("operation")
                in {"apply", "remove", "purge_data"}
                and prior_transition.get("planDigest") == plan_digest
                and prior_transition.get("phase")
                in {"failed", "observation_failed", "interrupted_observed"}
            )
            if state["lifecycleState"] not in allowed_states or (
                prior_transition is not None and not can_supersede
            ):
                raise DeploymentRefusal("invalid_transition", f"deployment cannot reserve {operation}")
            operation_id = "operation_" + digest_value(
                {
                    "deploymentId": deployment_id,
                    "operation": operation,
                    "planDigest": plan_digest,
                    "stateRevision": state["revision"],
                    "startedAt": timestamp(),
                }
            )[7:31]
            state["currentTransition"] = {
                "operationId": operation_id,
                "operation": operation,
                "planDigest": plan_digest,
                "phase": "executing",
                "startedAt": timestamp(),
                "authorityDecision": deepcopy(dict(authority_reference)),
            }
            receipt = self._append_receipt_unlocked(
                state,
                event=f"{operation}_reserved",
                actor=actor,
                data={
                    "operationId": operation_id,
                    "planDigest": plan_digest,
                    "authorityDecision": deepcopy(dict(authority_reference)),
                    "supersededTransition": (
                        deepcopy(dict(prior_transition))
                        if can_supersede
                        else None
                    ),
                },
                staged_receipts=staged_receipts,
            )
            next_state = self._next_state_unlocked(state)
            committed = self._commit_unlocked(
                deployment_id,
                base_state=base_state,
                next_state=next_state,
                receipts=staged_receipts,
            )
            return committed, receipt, operation_id

    def transition(
        self,
        deployment_id: str,
        target: str,
        *,
        event: str,
        actor: str,
        data: Mapping[str, Any],
        mutation: StateMutation | None = None,
        expected_operation_id: str | None = None,
        authority_outcome: Mapping[str, Any] | None = None,
        evidence_documents: Sequence[Mapping[str, Any]] = (),
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.mutate(
            deployment_id,
            event=event,
            actor=actor,
            data=data,
            mutation=mutation or (lambda _state: None),
            transition_to=target,
            expected_operation_id=expected_operation_id,
            authority_outcome=authority_outcome,
            evidence_documents=evidence_documents,
        )


__all__ = ["DeploymentStore"]
