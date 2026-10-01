"""Persistent-app bridge for one provider-free governed CTO inspection slice.

This coordinator exposes the existing goal-execution contracts without
starting a model, agent, shell command from a package, or backlog loop.  The
only executable subprocesses are StatePort-owned Git identity and isolated
review-workspace operations.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import threading
from typing import Any, Callable

from .backend import (
    backend_effective_profile,
    backend_effective_read_scope,
    backend_effective_write_scope,
    get_backend,
)
from .bootstrap import BootstrapProposal, prepare_project_bootstrap, prepare_recommended_slice
from .contracts import (
    CtoModePolicy,
    DelegationPlan,
    ExecutionResult,
    GoalBudget,
    GoalExecutionIntent,
    OrchestratorMode,
    OrchestratorProfile,
    ReviewRecord,
    ReviewRequirement,
    canonical_digest,
)
from .review_isolation import verify_review_workspace
from .service import (
    GoalExecutionSession,
    GoalExecutionState,
    GovernanceRefusal,
    InstanceApprovalLeaseRegistry,
)


VIEW_FORMAT = "stateport.goal-execution-view/v1"
RECORD_FORMAT = "stateport.goal-execution-operational-record/v1"
_WRITE_BITS = stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH
_MAX_REVIEW_ENTRIES = 4096


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _git(root: Path, *arguments: str) -> str:
    environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }
    try:
        result = subprocess.run(
            (
                "git", "--no-replace-objects", "-c", "core.hooksPath=/dev/null",
                "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
                "-C", root.as_posix(), *arguments,
            ),
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise GovernanceRefusal("git_identity_unavailable", "exact Git identity is required") from exc
    return result.stdout.strip()


def _git_observed_identity(root: Path) -> tuple[str, str, str]:
    """Observe HEAD plus the bounded working-tree status without mutating it.

    A dirty working tree is valid read-projection state even though it is not a
    valid goal-execution mutation basis.  Keeping observation separate from
    the clean-basis guard lets the UI report drift honestly without weakening
    prepare, approve, execute, review, or close.
    """

    if root.is_symlink() or not root.is_dir():
        raise GovernanceRefusal("instance_root_unavailable", "the selected project root is unavailable")
    commit = _git(root, "rev-parse", "HEAD")
    tree = _git(root, "rev-parse", "HEAD^{tree}")
    status = _git(root, "status", "--porcelain=v2", "--untracked-files=all")
    return commit, tree, status


def _git_identity(root: Path) -> tuple[str, str]:
    commit, tree, status = _git_observed_identity(root)
    if status:
        raise GovernanceRefusal("base_drift", "CTO preparation requires a clean exact project snapshot")
    return commit, tree


def _private_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink() or not path.is_dir():
        raise GovernanceRefusal("operational_store_unavailable", "goal execution storage is unsafe")
    path.chmod(0o700)
    return path.resolve(strict=True)


def _atomic_json(path: Path, value: dict[str, Any], root: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    resolved_parent = path.parent.resolve(strict=True)
    try:
        resolved_parent.relative_to(root)
    except ValueError as exc:
        raise GovernanceRefusal("operational_store_unavailable", "goal execution storage escaped its root") from exc
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise GovernanceRefusal("operational_store_unavailable", "goal execution record path is unsafe")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)


def _review_entries_for_hardening(root: Path) -> list[Path]:
    """Inventory a clone without following a repository-controlled symlink.

    ``Path.chmod`` follows links by default.  The coordinator must therefore
    reject every link and special entry before changing a single mode bit.
    """

    entries = [root, *root.rglob("*")]
    if len(entries) > _MAX_REVIEW_ENTRIES:
        raise ValueError("independent review workspace exceeds its entry bound")
    for path in entries:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise ValueError("independent review workspace could not be inspected") from exc
        if stat.S_ISLNK(metadata.st_mode) or not (
            stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)
        ):
            raise ValueError("independent review workspace contains an unsupported entry")
    return entries


def _chmod_review_entry(path: Path, *, writable: bool) -> None:
    """Change one already-inventoried entry without following replacements."""

    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        raise OSError("review workspace entry changed into a symlink")
    mode = metadata.st_mode | stat.S_IWUSR if writable else metadata.st_mode & ~_WRITE_BITS
    os.chmod(path, mode, follow_symlinks=False)


class GoalExecutionCoordinator:
    """Coordinate one exact provider-free item per selected application.

    ``allow_synthetic_backend`` is the explicit test-only dependency
    injection point: production and release services must never pass it, so
    the synthetic "fake" backend — which fabricates contract-inspection
    results without executing anything — stays unreachable outside tests.
    """

    def __init__(self, *, record_root: Path, allow_synthetic_backend: bool = False) -> None:
        self._root = _private_directory(record_root)
        self._allow_synthetic_backend = allow_synthetic_backend
        self._mutex = threading.RLock()
        self._sessions: dict[str, GoalExecutionSession] = {}
        self._projections: dict[str, dict[str, Any]] = {}
        self._leases = InstanceApprovalLeaseRegistry()

    def _record_path(self, instance_id: str) -> Path:
        if not instance_id or len(instance_id) > 128 or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-" for character in instance_id):
            raise GovernanceRefusal("instance_identity_invalid", "instance identity is invalid")
        return self._root / instance_id / "current.json"

    def _persist(self, instance_id: str, projection: dict[str, Any]) -> dict[str, Any]:
        value = dict(projection)
        previous = self._projections.get(instance_id)
        if previous is None:
            path = self._record_path(instance_id)
            if path.is_file() and not path.is_symlink() and path.stat().st_size <= 2 * 1024 * 1024:
                try:
                    loaded = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, UnicodeError, json.JSONDecodeError):
                    loaded = None
                previous = loaded if isinstance(loaded, dict) else None
        previous_revision = previous.get("revision", 0) if isinstance(previous, dict) else 0
        if isinstance(previous_revision, bool) or not isinstance(previous_revision, int) or previous_revision < 0:
            raise GovernanceRefusal("operational_record_invalid", "goal execution record revision is invalid")
        value["revision"] = previous_revision + 1
        value["recordedAt"] = _now()
        unsigned = {**value, "recordDigest": None}
        value["recordDigest"] = canonical_digest(unsigned)
        _atomic_json(self._record_path(instance_id), value, self._root)
        self._projections[instance_id] = value
        return value

    def _projection(self, session: GoalExecutionSession) -> dict[str, Any]:
        manifest = session.bootstrap.manifest
        selected = next(item for item in manifest.goal_items if item.item_id == session.plan.item_id)
        saved = self._projections.get(session.plan.instance_id, {})
        backend_id = saved.get("backendId")
        return {
            "formatVersion": VIEW_FORMAT,
            "applicationId": session.plan.application_id,
            "instanceId": session.plan.instance_id,
            "mode": session.profile.mode.value,
            "state": session.state.value,
            "providerExecution": bool(backend_id) and backend_id != "fake",
            "backendId": backend_id,
            "backgroundLoop": False,
            "nextItemAutoStart": False,
            "proposal": {
                "manifestDigest": manifest.digest,
                "proposalDigest": session.bootstrap.proposal.digest,
                "proposalOnly": True,
                "networkUsed": False,
                "repositoryRelativePath": manifest.repository_relative_path,
                "architectureBoundaries": list(manifest.architecture_boundaries),
                "risks": list(manifest.risks),
                "backlog": [item.to_dict() for item in manifest.goal_items],
                "recommendedItemId": session.bootstrap.proposal.recommended_item_id,
            },
            "slice": {**session.plan.to_dict(), "planDigest": session.plan.digest},
            "selectedItem": selected.to_dict(),
            "acceptance": session.acceptance.to_dict(),
            "delegation": session.delegation.to_dict(),
            "reviewRequirement": session.review_requirement.to_dict(),
            "approval": session.approval.to_dict() if session.approval else None,
            "executionResult": (
                {**session.execution_result.to_dict(), "executionResultDigest": session.execution_result.digest}
                if session.execution_result else None
            ),
            "review": (
                {**session.review.to_dict(), "reviewDigest": session.review.digest}
                if session.review else None
            ),
            "closure": session.closure.to_dict() if session.closure else None,
            "receipt": session.receipt.to_dict() if session.receipt else None,
            "stop": session.stop_record.to_dict() if session.stop_record else None,
            "canonicalStateEffect": "none",
        }

    def inspect(self, instance_id: str) -> dict[str, Any]:
        with self._mutex:
            session = self._sessions.get(instance_id)
            if session is not None:
                return dict(self._projections.get(instance_id) or self._projection(session))
            path = self._record_path(instance_id)
            if path.is_file() and not path.is_symlink() and path.stat().st_size <= 2 * 1024 * 1024:
                try:
                    value = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                    raise GovernanceRefusal("operational_record_invalid", "goal execution record is invalid") from exc
                if isinstance(value, dict) and value.get("formatVersion") == VIEW_FORMAT:
                    if value.get("state") not in {"closed", "stopped", "off"}:
                        value = {
                            **value,
                            "state": "stopped",
                            "restartStatus": "in_flight_session_not_resumed",
                            "stop": {
                                "formatVersion": "stateport.goal-execution-stop/v1",
                                "code": "service_restart",
                                "message": "In-flight approval did not survive the service process.",
                                "stateBeforeStop": str(value.get("state", "unknown")),
                            },
                        }
                        value = self._persist(instance_id, value)
                    return value
            return {
                "formatVersion": VIEW_FORMAT,
                "instanceId": instance_id,
                "revision": 0,
                "mode": "advisory",
                "state": "not_prepared",
                "providerExecution": False,
                "backgroundLoop": False,
                "nextItemAutoStart": False,
                "canonicalStateEffect": "none",
            }

    def current_identity(self, instance_root: Path) -> dict[str, Any]:
        commit, tree, status = _git_observed_identity(instance_root)
        identity: dict[str, Any] = {
            "baseCommit": commit,
            "baseTree": tree,
            "repositoryClean": not bool(status),
        }
        if status:
            identity.update({
                "reasonCode": "working_tree_dirty",
                # The digest binds the complete porcelain-v2 observation
                # without exposing repository-relative paths in this
                # application projection.
                "workingTreeStatusDigest": canonical_digest({
                    "formatVersion": "stateport.git-working-tree-status/v1",
                    "porcelainV2": status,
                }),
            })
        return identity

    def pending_approval_source(
        self,
        instance_id: str,
        instance_root: Path,
    ) -> dict[str, Any] | None:
        """Return the live proposal accepted by the existing approve route.

        Persisted in-flight records intentionally do not qualify after a
        service restart: approval authority remains bound to the live session
        and its held instance lease.  This read-only projection also withholds
        advisory/ambiguous proposals and exact repository identities that have
        drifted.
        """

        with self._mutex:
            session = self._sessions.get(instance_id)
            if (
                session is None
                or session.state.value != "proposal_ready"
                or session.profile.mode not in {
                    OrchestratorMode.ASSISTED,
                    OrchestratorMode.MANAGED_APPROVED_QUEUE,
                }
                or session.bootstrap.proposal.ambiguities
            ):
                return None
            try:
                commit, tree = _git_identity(instance_root)
            except GovernanceRefusal:
                return None
            if (commit, tree) != (session.plan.base_commit, session.plan.base_tree):
                return None
            projection = self._projections.get(instance_id)
            if (
                not isinstance(projection, dict)
                or projection.get("state") != "proposal_ready"
                or projection.get("instanceId") != instance_id
                or projection.get("mode") != session.profile.mode.value
            ):
                return None
            return dict(projection)

    def _require_revision(self, instance_id: str, expected_revision: int) -> None:
        if isinstance(expected_revision, bool) or not isinstance(expected_revision, int) or expected_revision < 0:
            raise GovernanceRefusal("revision_invalid", "goal execution revision is invalid")
        current = self.inspect(instance_id).get("revision")
        if current != expected_revision:
            raise GovernanceRefusal("revision_stale", "goal execution state changed; inspect it again")

    def _bound_identity(
        self,
        instance_id: str,
        session: GoalExecutionSession,
        instance_root: Path,
    ) -> tuple[str, str]:
        try:
            return _git_identity(instance_root)
        except GovernanceRefusal as exc:
            self._stop_and_persist(
                instance_id,
                session,
                code=exc.code,
                message="the selected project no longer matches its exact clean snapshot",
                cause=exc,
            )
        raise AssertionError("terminal stop must raise")

    def _transition(
        self,
        instance_id: str,
        session: GoalExecutionSession,
        operation: Callable[[], Any],
    ) -> Any:
        """Persist every terminal state transition before returning its refusal."""

        try:
            return operation()
        except GovernanceRefusal as exc:
            if exc.terminal:
                self._persist(instance_id, self._projection(session))
            raise

    def _stop_and_persist(
        self,
        instance_id: str,
        session: GoalExecutionSession,
        *,
        code: str,
        message: str,
        cause: BaseException | None = None,
    ) -> None:
        try:
            session.stop(code=code, message=message)
        except GovernanceRefusal as terminal:
            self._persist(instance_id, self._projection(session))
            if cause is not None:
                raise terminal from cause
            raise
        raise AssertionError("terminal stop must raise")

    def _resolve_backend(self, backend_id: str | None) -> str:
        """Bind the execution backend, failing closed when none is available.

        Production never defaults to the synthetic backend: with no explicit
        test injection the only candidate is the managed container backend,
        and when it is not configured and ready the result is a typed
        unavailable refusal — never a fabricated success.
        """

        if backend_id is None:
            backend_id = "fake" if self._allow_synthetic_backend else "opencode_container"
        if backend_id not in ("fake", "opencode_container"):
            raise GovernanceRefusal("backend_unsupported", f"backend {backend_id} is not supported")
        if backend_id == "fake":
            if not self._allow_synthetic_backend:
                raise GovernanceRefusal(
                    "goal_backend_unavailable",
                    "the synthetic goal-execution backend is test-only and is not enabled "
                    "on this service; no production backend is configured, so governed "
                    "execution is unavailable rather than fabricated",
                )
            return backend_id
        entry = get_backend("opencode_container")
        if entry is None or not entry.get("ready"):
            readiness_detail = (entry or {}).get("error", "unknown")
            raise GovernanceRefusal(
                "goal_backend_unavailable",
                "no production goal-execution backend is available: opencode_container is "
                f"not ready ({readiness_detail}); governed execution stays unavailable "
                "until a governed backend is configured — no result is fabricated",
            )
        return backend_id

    def backend_availability(self) -> dict[str, Any]:
        """Typed availability of governed execution for view projections.

        The view must say upfront when a prepare would refuse: production
        services build the coordinator without the test-only synthetic
        backend, and when no governed backend is configured and ready the
        projection is a plain, actionable unavailable state — not an offer of
        active orchestration that always refuses.
        """

        if self._allow_synthetic_backend:
            return {"status": "available", "backendId": "fake", "testOnly": True}
        entry = get_backend("opencode_container")
        if entry is not None and entry.get("ready"):
            return {"status": "available", "backendId": "opencode_container", "testOnly": False}
        readiness_detail = str((entry or {}).get("error") or "unknown")
        return {
            "status": "unavailable",
            "code": "goal_backend_unavailable",
            "message": (
                "Governed execution is unavailable: no execution backend is "
                f"configured on this host ({readiness_detail}). Nothing can be "
                "prepared, executed, reviewed, or closed, and no result is "
                "fabricated."
            ),
            "nextAction": (
                "No operator action enables execution here. Wait for a "
                "StatePort release that configures a governed execution "
                "backend; turning orchestration off stays available."
            ),
        }

    def prepare(
        self,
        *,
        application_id: str,
        instance_id: str,
        instance_root: Path,
        requested_by: str,
        text: str,
        mode: str,
        expected_revision: int,
        expected_base_commit: str,
        backend_id: str | None = None,
    ) -> dict[str, Any]:
        try:
            selected_mode = OrchestratorMode(mode)
        except ValueError as exc:
            raise GovernanceRefusal("mode_unsupported", "CTO mode is unsupported") from exc
        # Turning CTO mode off is a stop operation: it must stay available even
        # when no execution backend is configured.
        selected_backend = (
            self._resolve_backend(backend_id)
            if selected_mode is not OrchestratorMode.OFF
            else None
        )
        with self._mutex:
            self._require_revision(instance_id, expected_revision)
            if selected_mode is OrchestratorMode.OFF:
                current = self._sessions.get(instance_id)
                stop_record = None
                previous_state = None
                if current is not None and current.state.value not in {"closed", "stopped"}:
                    previous_state = current.state.value
                    try:
                        current.stop(
                            code="operator_disabled",
                            message="the authenticated operator disabled CTO mode",
                        )
                    except GovernanceRefusal as terminal:
                        if not terminal.terminal:
                            raise
                        stop_record = (
                            current.stop_record.to_dict()
                            if current.stop_record is not None else None
                        )
                self._sessions.pop(instance_id, None)
                return self._persist(instance_id, {
                    "formatVersion": VIEW_FORMAT,
                    "applicationId": application_id,
                    "instanceId": instance_id,
                    "mode": "off",
                    "state": "off",
                    "providerExecution": False,
                    "backgroundLoop": False,
                    "nextItemAutoStart": False,
                    "canonicalStateEffect": "none",
                    "previousState": previous_state,
                    "stop": stop_record,
                })
            current = self._sessions.get(instance_id)
            if current is not None and current.state.value not in {"closed", "stopped"}:
                raise GovernanceRefusal("active_item_exists", "one goal item is already active for this application")
            commit, tree = _git_identity(instance_root)
            if expected_base_commit != commit:
                raise GovernanceRefusal("base_drift", "repository base changed before CTO preparation")
            profile = OrchestratorProfile(
                profile_id="development-cto-v1",
                application_id=application_id,
                orchestrator_actor="cto-orchestrator",
                mode=selected_mode,
                capability="cto_orchestration",
            )
            intent = GoalExecutionIntent(
                intent_id="intent-" + canonical_digest({"instanceId": instance_id, "text": text, "mode": mode}).split(":", 1)[1][:24],
                application_id=application_id,
                instance_id=instance_id,
                requested_by=requested_by,
                text=text,
                requested_mode=selected_mode,
            )
            bootstrap = prepare_project_bootstrap(
                intent=intent,
                repo_root=instance_root,
                trusted_root=instance_root.parent,
                base_commit=commit,
                base_tree=tree,
                proposed_by=profile.orchestrator_actor,
                profile=profile,
            )
            exact_snapshot = canonical_digest({"baseCommit": commit, "baseTree": tree, "repositoryDigest": bootstrap.manifest.repository_digest})
            manifest = replace(bootstrap.manifest, state_snapshot_digest=exact_snapshot)
            proposal = replace(bootstrap.proposal, manifest_digest=manifest.digest)
            bootstrap = BootstrapProposal(manifest=manifest, proposal=proposal)
            plan, acceptance = prepare_recommended_slice(bootstrap, proposed_by=profile.orchestrator_actor)
            assert selected_backend is not None  # non-off modes resolve a backend first
            effective_profile = backend_effective_profile(selected_backend)
            delegation = DelegationPlan(
                plan_id=f"delegation-{selected_backend}-v1",
                item_id=plan.item_id,
                implementer_actor="stateport-bounded-inspector",
                reviewer_actor="stateport-independent-reviewer",
                intended_profile=effective_profile,
                actual_profile=effective_profile,
                read_scope=backend_effective_read_scope(selected_backend),
                write_scope=backend_effective_write_scope(selected_backend),
            )
            requirement = ReviewRequirement(
                requirement_id=f"review-{selected_backend}-v1",
                item_id=plan.item_id,
                acceptance_contract_digest=acceptance.digest,
                reviewer_actor=delegation.reviewer_actor,
            )
            session = GoalExecutionSession(
                profile=profile,
                policy=CtoModePolicy(),
                bootstrap=bootstrap,
                plan=plan,
                delegation=delegation,
                acceptance=acceptance,
                review_requirement=requirement,
                effective_capabilities=frozenset({"goal_execution", "cto_orchestration", f"backend_{selected_backend}"}),
                approval_leases=self._leases,
            )
            self._projections.setdefault(instance_id, {}).update({
                "backendId": selected_backend,
                "providerExecution": selected_backend != "fake",
            })
            self._sessions[instance_id] = session
            return self._persist(instance_id, self._projection(session))

    def approve(self, instance_id: str, instance_root: Path, *, expected_revision: int, expected_plan_digest: str, actor: str) -> dict[str, Any]:
        with self._mutex:
            self._require_revision(instance_id, expected_revision)
            session = self._sessions.get(instance_id)
            if session is None:
                raise GovernanceRefusal("proposal_not_prepared", "no CTO proposal is prepared")
            commit, tree = self._bound_identity(instance_id, session, instance_root)
            self._transition(
                instance_id,
                session,
                lambda: session.approve(
                    actor=actor,
                    expected_plan_digest=expected_plan_digest,
                    current_base_commit=commit,
                    current_base_tree=tree,
                    current_state_snapshot_digest=session.plan.state_snapshot_digest,
                    approved_permissions=session.plan.required_permissions,
                    approved_side_effect_class=session.plan.side_effect_class,
                    approved_budget=session.plan.maximum_budget,
                ),
            )
            return self._persist(instance_id, self._projection(session))

    def execute(self, instance_id: str, instance_root: Path, *, expected_revision: int, expected_plan_digest: str) -> dict[str, Any]:
        with self._mutex:
            self._require_revision(instance_id, expected_revision)
            session = self._sessions.get(instance_id)
            if session is None or expected_plan_digest != session.plan.digest:
                raise GovernanceRefusal("plan_identity_mismatch", "execution does not bind the prepared slice")
            commit, tree = self._bound_identity(instance_id, session, instance_root)
            projection = self._projections.get(instance_id, {})
            backend_id = projection.get("backendId")
            if backend_id == "fake" and not self._allow_synthetic_backend:
                raise GovernanceRefusal(
                    "goal_backend_unavailable",
                    "the prepared slice names the test-only synthetic backend, which is "
                    "not enabled on this service; execution is refused rather than fabricated",
                )
            if backend_id not in ("fake", "opencode_container"):
                raise GovernanceRefusal(
                    "goal_backend_unavailable",
                    "the prepared slice does not bind a configured execution backend; "
                    "execution is refused rather than fabricated",
                )
            self._transition(
                instance_id,
                session,
                lambda: session.begin_execution(
                    actor=session.delegation.implementer_actor,
                    current_base_commit=commit,
                    current_base_tree=tree,
                    current_state_snapshot_digest=session.plan.state_snapshot_digest,
                    current_orchestrator_profile_digest=session.profile.digest,
                    current_policy_digest=session.effective_policy_digest,
                    current_delegation_plan_digest=session.delegation.digest,
                    actual_permissions=session.plan.required_permissions,
                    side_effect_class=session.plan.side_effect_class,
                    current_budget_ceiling=session.plan.maximum_budget,
                ),
            )
            try:
                if backend_id == "opencode_container":
                    result = self._execute_opencode(instance_id, instance_root, session, commit, tree)
                else:
                    result = self._execute_fake(instance_id, instance_root, session, commit, tree)
                self._transition(instance_id, session, lambda: session.record_execution(result))
            except GovernanceRefusal as exc:
                # Once execution has begun, a backend refusal must become a
                # durable terminal stop so the approval lease cannot remain
                # held behind an in-memory ``executing`` session. Preserve
                # the original refusal code and message in the stop record.
                if exc.terminal and session.state is GoalExecutionState.STOPPED:
                    # ``_transition`` already persisted terminal refusals
                    # raised by record_execution. Do not write a duplicate
                    # stopped projection or advance the durable revision a
                    # second time.
                    raise
                self._stop_and_persist(
                    instance_id,
                    session,
                    code=exc.code,
                    message=str(exc),
                    cause=exc,
                )
            except Exception as exc:
                try:
                    current = _git_identity(instance_root)
                except GovernanceRefusal:
                    current = None
                code = "base_drift" if current != (session.plan.base_commit, session.plan.base_tree) else "execution_validation_failed"
                self._stop_and_persist(
                    instance_id,
                    session,
                    code=code,
                    message="execution did not retain its exact validated snapshot",
                    cause=exc,
                )
            return self._persist(instance_id, self._projection(session))

    def _execute_fake(
        self, instance_id: str, instance_root: Path, session: GoalExecutionSession, commit: str, tree: str,
    ) -> ExecutionResult:
        verification = prepare_project_bootstrap(
            intent=GoalExecutionIntent(
                intent_id=session.bootstrap.manifest.intent_digest.split(":", 1)[1][:24],
                application_id=session.plan.application_id,
                instance_id=instance_id,
                requested_by="stateport-bounded-inspector",
                text="Reinspect the approved public-safe application contract.",
                requested_mode=session.profile.mode,
            ),
            repo_root=instance_root,
            trusted_root=instance_root.parent,
            base_commit=commit,
            base_tree=tree,
            proposed_by=session.profile.orchestrator_actor,
            profile=session.profile,
        )
        verified_commit, verified_tree = self._bound_identity(instance_id, session, instance_root)
        if (verified_commit, verified_tree) != (commit, tree):
            self._stop_and_persist(
                instance_id, session, code="base_drift",
                message="repository identity changed during fake execution",
            )
        test_digest = canonical_digest({
            "kind": "provider-free-contract-inspection",
            "repositoryDigest": verification.manifest.repository_digest,
            "baseCommit": commit, "baseTree": tree,
            "criteria": list(session.acceptance.criteria),
            "passed": verification.manifest.repository_digest == session.bootstrap.manifest.repository_digest,
        })
        return ExecutionResult(
            result_id="result-fake-inspection-v1",
            item_id=session.plan.item_id,
            plan_digest=session.plan.digest,
            implementer_actor=session.delegation.implementer_actor,
            functional_commit=commit,
            functional_tree=tree,
            test_result_digest=test_digest,
            contract_versions=session.plan.contract_versions,
            actual_permissions=session.plan.required_permissions,
            side_effect_class=session.plan.side_effect_class,
            used_budget=GoalBudget(token=0, cost_minor=0, time_seconds=1, steps=1),
            tests_passed=verification.manifest.repository_digest == session.bootstrap.manifest.repository_digest,
            repository_clean=True,
        )

    def _execute_opencode(
        self, instance_id: str, instance_root: Path, session: GoalExecutionSession, commit: str, tree: str,
    ) -> ExecutionResult:
        backend_info = get_backend("opencode_container")
        if backend_info is None or not backend_info.get("ready"):
            raise GovernanceRefusal("container_backend_unavailable", "opencode_container backend is not ready")
        backend = backend_info["backend"]

        import tempfile
        staging_root = Path(tempfile.mkdtemp(prefix=f"cto-staging-{instance_id}-"))
        try:
            subprocess.run(
                ("git", "clone", "--no-local", instance_root.as_posix(), staging_root.as_posix()),
                check=True, capture_output=True, text=True, timeout=30,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "GIT_CONFIG_GLOBAL": "/dev/null"},
            )

            run_spec = self._make_run_spec(instance_id, session, commit, tree, staging_root)

            events: list[Any] = []
            def event_sink(event: Any) -> None:
                events.append(event)

            op_result = backend.start(run_spec, staging_root, environment={}, event_sink=event_sink)

            if op_result.status != "completed":
                raise GovernanceRefusal(
                    "opencode_execution_failed",
                    f"OpenCode run {op_result.status}: {op_result.failure_classification or 'unknown'}",
                )

            changed_files = self._capture_diff(staging_root, commit)
            tests_passed, test_digest = self._run_validation(staging_root, session)

            subprocess.run(
                ("git", "-C", staging_root.as_posix(), "add", "-A"),
                check=False, capture_output=True, timeout=10,
            )

            return ExecutionResult(
                result_id=f"result-opencode-{instance_id[:16]}",
                item_id=session.plan.item_id,
                plan_digest=session.plan.digest,
                implementer_actor=session.delegation.implementer_actor,
                functional_commit=commit,
                functional_tree=tree,
                test_result_digest=test_digest,
                contract_versions=session.plan.contract_versions,
                actual_permissions=session.plan.required_permissions,
                side_effect_class=session.plan.side_effect_class,
                used_budget=GoalBudget(
                    token=0, cost_minor=0,
                    time_seconds=int(op_result.process.get("timeSeconds", 0)) if op_result.process else 0,
                    steps=len(events),
                ),
                tests_passed=tests_passed,
                repository_clean=True,
            )
        finally:
            import shutil
            shutil.rmtree(staging_root, ignore_errors=True)
            if backend is not None:
                try:
                    backend.cancel(instance_id)
                except Exception:
                    pass

    def _make_run_spec(
        self, instance_id: str, session: GoalExecutionSession, commit: str, tree: str, staging_root: Path,
    ) -> Any:
        from execution_host.contracts import AgentRunSpec, CapabilityRequest
        return AgentRunSpec(
            run_id=f"cto-run-{instance_id[:16]}",
            instance_id=instance_id,
            source_revision=commit,
            objective=session.plan.item_id,
            statepack_reference="sp-cto-v1",
            statepack_digest="sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            required_capabilities=(
                CapabilityRequest("structuredEvents", allow_partial=False),
                CapabilityRequest("nonInteractiveExecution", allow_partial=False),
                CapabilityRequest("cancellation", allow_partial=False),
            ),
            optional_capabilities=("sessionResume",),
            backend_id="opencode",
            adapter_id="opencode-cli",
            adapter_version="1.18.2",
            model_identifier="opencode/deepseek-v4-flash-free",
            authentication_route_class="operator_authenticated_unverified",
            permitted_capabilities=("read_staging", "write_staging"),
            sandbox_profile=session.profile.mode.value if hasattr(session.profile.mode, "value") else "balanced",
            budgets={"token": 10000, "costMinor": 0, "timeSeconds": session.plan.maximum_budget.time_seconds, "steps": 50},
            validation_commands=tuple(session.acceptance.validation_commands),
            required_output_artifacts=(),
            benchmark_configuration={},
            approval_reference=None,
            approval_required_level="task_execution",
            repository_instructions=("Execute inside the staging workspace",),
        )

    def _capture_diff(self, staging_root: Path, base_commit: str) -> list[dict[str, Any]]:
        result = subprocess.run(
            ("git", "-C", staging_root.as_posix(), "diff", "--stat", base_commit),
            capture_output=True, text=True, timeout=10,
        )
        return [{"diffStat": result.stdout.strip()}] if result.stdout.strip() else []

    def _run_validation(self, staging_root: Path, session: GoalExecutionSession) -> tuple[bool, str]:
        # The managed agent owns every byte in ``staging_root``.  Running its
        # modified tests with the host interpreter would escape the staging
        # boundary even with ``shell=False``.  The OpenCode backend therefore
        # remains unavailable until these exact, approval-bound commands can be
        # executed by a separate confined validator.
        del staging_root
        commands = tuple(session.acceptance.validation_commands)
        plan_commands = tuple(session.plan.validation_commands)
        return False, canonical_digest({
            "validation": "not_run",
            "reason": "sandboxed_validation_not_implemented",
            "commandsBoundToPlan": commands == plan_commands,
            "validationCommands": list(commands),
            "passed": False,
        })

    def review(self, instance_id: str, instance_root: Path, *, expected_revision: int, expected_result_digest: str) -> dict[str, Any]:
        with self._mutex:
            self._require_revision(instance_id, expected_revision)
            session = self._sessions.get(instance_id)
            result = session.execution_result if session is not None else None
            if session is None or result is None or expected_result_digest != result.digest:
                raise GovernanceRefusal("execution_identity_mismatch", "review does not bind the exact execution result")
            commit, tree = self._bound_identity(instance_id, session, instance_root)
            if (commit, tree) != (result.functional_commit, result.functional_tree):
                self._stop_and_persist(
                    instance_id,
                    session,
                    code="base_drift",
                    message="repository identity changed before independent review",
                )
            review_parent = _private_directory(self._root / instance_id / "review-workspaces")
            review_root = review_parent / ("review-" + result.functional_commit[:16])
            if review_root.exists():
                raise GovernanceRefusal("review_workspace_exists", "review workspace identity already exists")
            environment = {
                "PATH": "/usr/bin:/bin",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_NOSYSTEM": "1",
            }
            entries: list[Path] = []
            try:
                subprocess.run(
                    ("git", "clone", "--no-local", "--no-hardlinks", "--no-checkout", instance_root.as_posix(), review_root.as_posix()),
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=20,
                    env=environment,
                )
                subprocess.run(
                    ("git", "-C", review_root.as_posix(), "checkout", "--detach", result.functional_commit),
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    env=environment,
                )
                entries = _review_entries_for_hardening(review_root)
                for path in sorted(entries, key=lambda item: len(item.parts), reverse=True):
                    _chmod_review_entry(path, writable=False)
                isolation = verify_review_workspace(
                    review_worktree=review_root,
                    implementation_worktree=instance_root,
                    reviewer_actor=session.delegation.reviewer_actor,
                    expected_commit=result.functional_commit,
                    expected_tree=result.functional_tree,
                )
                review = ReviewRecord(
                    review_id="review-provider-free-inspection-v1",
                    item_id=result.item_id,
                    reviewer_actor=session.delegation.reviewer_actor,
                    functional_commit=result.functional_commit,
                    functional_tree=result.functional_tree,
                    test_result_digest=result.test_result_digest,
                    acceptance_contract_digest=session.acceptance.digest,
                    isolation_evidence_digest=isolation.digest,
                    contract_versions=result.contract_versions,
                    disposition="accepted",
                )
                self._transition(
                    instance_id,
                    session,
                    lambda: session.submit_review(
                        review,
                        review_worktree=review_root,
                        implementation_worktree=instance_root,
                    ),
                )
            except GovernanceRefusal:
                raise
            except Exception as exc:
                self._stop_and_persist(
                    instance_id,
                    session,
                    code="review_isolation_invalid",
                    message="independent review workspace verification failed",
                    cause=exc,
                )
            finally:
                for path in sorted(entries, key=lambda item: len(item.parts)):
                    try:
                        _chmod_review_entry(path, writable=True)
                    except OSError:
                        pass
                if review_root.exists():
                    shutil.rmtree(review_root)
            return self._persist(instance_id, self._projection(session))

    def close(self, instance_id: str, instance_root: Path, *, expected_revision: int, expected_review_digest: str, actor: str) -> dict[str, Any]:
        with self._mutex:
            self._require_revision(instance_id, expected_revision)
            session = self._sessions.get(instance_id)
            if session is None or session.review is None or expected_review_digest != session.review.digest:
                raise GovernanceRefusal("review_identity_mismatch", "closure does not bind the accepted independent review")
            commit, tree = self._bound_identity(instance_id, session, instance_root)
            if (commit, tree) != (session.review.functional_commit, session.review.functional_tree):
                self._stop_and_persist(
                    instance_id,
                    session,
                    code="base_drift",
                    message="repository identity changed before closure",
                )
            def closure_guard() -> bool:
                try:
                    return _git_identity(instance_root) == (
                        session.review.functional_commit,
                        session.review.functional_tree,
                    )
                except GovernanceRefusal:
                    return False

            self._transition(
                instance_id,
                session,
                lambda: session.close(decided_by=actor, closure_guard=closure_guard),
            )
            return self._persist(instance_id, self._projection(session))
