"""Provisioned authority grant store for the execution-host daemon.

Grants are operator-provisioned JSON documents under ``<grants_dir>/<grantId>.json``
validated against the execution-host grant contract.  A request is
authorized only when every binding holds:

- the grant document exists and validates,
- the client-presented ``authorityGrantDigest`` equals the canonical digest
  of the exact stored grant document (fabrication/paraphrase fails),
- the observed peer uid equals the grant's bound peer uid,
- the operation is inside the grant's operation set,
- the target workload is inside the grant's workload scope,
- deployment operations carry an explicit v2 scope binding the canonical
  control-plane authority mode, exact local adapter/target, transfer ceilings,
  and whether irreversible data purge is admitted,
- for ``createWorkload`` the workload kind is granted and the complete
  canonical sealed-spec digest equals the grant's bound digest for that
  workload (binding network profile, shell/exec policy, staging/base
  identity, and cache/volume scope at once), the sealed image equals the
  grant's image and, when the grant binds a base revision, an agent-run or
  workspace workload names exactly it,
- the grant is unexpired, unpaused, and unrevoked (per-id revocation or a
  monotonic revocation epoch),
- workload budgets stay within the grant's full resource ceilings (timeout,
  output, memory, pids, cpu quota, disk) and the grant's active-workload
  action budget.

A missing or corrupt revocation document fails closed: no grant verifies
while revocation state is unknown.  The store is re-read from disk on every
verification, so revocation and pause take effect without a daemon restart.
Files are opened with ``O_NOFOLLOW`` inside a daemon-owned directory;
anything else fails closed.  ``assert_live`` gives supervisor reconciliation
the same revocation/expiry posture for already-running work.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from . import daemon_contract as contract


class GrantRefusal(Exception):
    """A typed authorization refusal; converted into a refusal receipt."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def _read_json_nofollow(path: Path) -> Any:
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (ValueError, OSError, UnicodeError):
        return None


def _parse_instant(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class GrantStore:
    """Fail-closed grant verification against the provisioned grant store."""

    def __init__(self, grants_dir: Path, *, clock: Callable[[], str]) -> None:
        self._grants_dir = Path(grants_dir)
        self._clock = clock

    @property
    def grants_dir(self) -> Path:
        return self._grants_dir

    def _revocation(self) -> Mapping[str, Any]:
        # Fail closed: a missing or unreadable revocation document means the
        # store's revocation state is unknown, so no grant may verify.
        path = self._grants_dir / "revocation.json"
        if not path.exists():
            raise GrantRefusal(
                "revocation-state-missing",
                "the grant store revocation document is absent; refusing to fail open",
            )
        raw = _read_json_nofollow(path)
        if raw is None:
            raise GrantRefusal(
                "grant-store-corrupt",
                "the grant store revocation document is unreadable; refusing to fail open",
            )
        try:
            return contract.validate_revocation_document(raw)
        except ValueError as exc:
            raise GrantRefusal("grant-store-corrupt", f"revocation document is invalid: {exc}") from exc

    def _load_grant(self, grant_id: str) -> Mapping[str, Any]:
        raw = _read_json_nofollow(self._grants_dir / f"{grant_id}.json")
        if raw is None:
            raise GrantRefusal("grant-unknown", "no provisioned grant exists for the presented grant id")
        try:
            grant = contract.validate_grant_document(raw)
        except ValueError as exc:
            raise GrantRefusal("grant-store-corrupt", f"stored grant document is invalid: {exc}") from exc
        if grant["grantId"] != grant_id:
            raise GrantRefusal("grant-store-corrupt", "stored grant id does not match its file name")
        return grant

    def _check_liveness(self, grant: Mapping[str, Any]) -> None:
        """Revocation, pause, epoch, and expiry checks shared by request
        verification and supervisor reconciliation."""
        grant_id = grant["grantId"]
        revocation = self._revocation()
        if grant_id in revocation["revokedGrantIds"]:
            raise GrantRefusal("grant-revoked", "the grant was explicitly revoked")
        if grant["revocationEpoch"] < revocation["revocationEpoch"]:
            raise GrantRefusal("grant-revoked", "the grant predates the current revocation epoch")
        if grant_id in revocation["pausedGrantIds"]:
            raise GrantRefusal("grant-paused", "the grant is currently paused")
        try:
            now = _parse_instant(self._clock())
            expires = _parse_instant(grant["expiresAt"])
        except ValueError as exc:
            raise GrantRefusal("grant-store-corrupt", f"grant timestamps are unparseable: {exc}") from exc
        if now >= expires:
            raise GrantRefusal("grant-expired", "the grant expired")

    def assert_live(
        self, grant_id: str, *, expected_digest: str | None = None
    ) -> Mapping[str, Any]:
        """Raise ``GrantRefusal`` unless the grant exists and is live.

        Used by supervisor reconciliation: active workloads whose authority
        was withdrawn (revoked, paused, expired, epoch-superseded, or an
        unreadable store) must be terminated or quarantined immediately.
        """
        grant = self._load_grant(grant_id)
        if expected_digest is not None and contract.canonical_digest(grant) != expected_digest:
            raise GrantRefusal(
                "grant-digest-mismatch",
                "the live authority grant no longer matches the workload's bound grant digest",
            )
        self._check_liveness(grant)
        return grant

    def verify(
        self,
        *,
        request: Mapping[str, Any],
        peer_uid: int,
        payload: Mapping[str, Any],
        active_count: Callable[[str], int],
    ) -> Mapping[str, Any]:
        """Authorize one validated request or raise ``GrantRefusal``."""

        requester = request["requester"]
        grant_id = requester["grantId"]
        grant = self._load_grant(grant_id)
        # The presented digest binds the exact validated grant document:
        # a fabricated, truncated, or paraphrased grant never matches.
        if contract.canonical_digest(grant) != requester["authorityGrantDigest"]:
            raise GrantRefusal(
                "grant-digest-mismatch",
                "the presented authority grant digest does not equal the stored grant document",
            )
        if grant["peerUid"] != peer_uid:
            raise GrantRefusal("grant-peer-mismatch", "the grant is bound to a different peer uid")
        operation = request["operation"]
        if operation not in grant["operations"]:
            raise GrantRefusal("grant-operation-denied", "the grant does not cover this operation")
        self._check_liveness(grant)

        budgets = grant["budgets"]
        if (
            request["timeoutSeconds"] > budgets["maxTimeoutSeconds"]
            or request["outputByteBound"] > budgets["maxOutputBytes"]
        ):
            raise GrantRefusal(
                "grant-budget-exceeded",
                "request timeout or output bound exceeds the grant budget",
            )

        if operation in contract.DEPLOYMENT_OPERATIONS:
            scope = grant.get("deploymentScope")
            if not isinstance(scope, Mapping):
                raise GrantRefusal(
                    "grant-deployment-scope-missing",
                    "the grant has no explicit deployment authority scope",
                )
            if operation == "purgeDeploymentData" and not scope["allowDataPurge"]:
                raise GrantRefusal(
                    "grant-deployment-purge-denied",
                    "the deployment grant does not admit irreversible data purge",
                )
            if operation != "probeDeploymentTarget":
                plan = payload.get("plan")
                spec = plan.get("spec") if isinstance(plan, Mapping) else payload.get("spec")
                if not isinstance(spec, Mapping):
                    raise GrantRefusal(
                        "grant-deployment-scope-mismatch",
                        "the deployment request has no scope-verifiable specification",
                    )
                target = spec.get("target")
                authority = spec.get("authority")
                if (
                    not isinstance(target, Mapping)
                    or target.get("adapter") != scope["targetAdapter"]
                    or target.get("targetId") != scope["targetId"]
                    or not isinstance(authority, Mapping)
                    or not isinstance(authority.get("grantId"), str)
                    or not authority["grantId"]
                ):
                    raise GrantRefusal(
                        "grant-deployment-scope-mismatch",
                        "the deployment request differs from the grant's authority or target scope",
                    )
                archive = payload.get("sourceArchive")
                if isinstance(archive, Mapping) and (
                    archive.get("archiveBytes", 0) > scope["maxArchiveBytes"]
                    or archive.get("fileCount", 0) > scope["maxFiles"]
                ):
                    raise GrantRefusal(
                        "grant-deployment-budget-exceeded",
                        "the deployment source transfer exceeds the grant scope",
                    )

        workload_id = payload.get("workloadId")
        if operation in {"createWorkload", "runValidator"}:
            spec = payload["workload"]
            workload_id = spec["workloadId"]
            if workload_id not in grant["workloadIds"]:
                raise GrantRefusal("grant-workspace-mismatch", "the grant does not cover this workload id")
            if spec["kind"] not in grant["workloadKinds"]:
                raise GrantRefusal("grant-kind-denied", "the grant does not cover this workload kind")
            if spec["image"]["reference"] != grant["imageReference"]:
                raise GrantRefusal("grant-image-mismatch", "the workload image differs from the grant image")
            if grant["baseRevision"] is not None:
                base = spec["parameters"].get("baseRevision")
                if spec["kind"] not in {"agent-run", "workspace"} or base != grant["baseRevision"]:
                    raise GrantRefusal(
                        "grant-base-revision-mismatch",
                        "the workload does not name the grant's exact base revision",
                    )
            if spec["timeoutSeconds"] > budgets["maxTimeoutSeconds"]:
                raise GrantRefusal("grant-budget-exceeded", "workload timeout exceeds the grant budget")
            if spec["outputByteBound"] > budgets["maxOutputBytes"]:
                raise GrantRefusal("grant-budget-exceeded", "workload output bound exceeds the grant budget")
            if spec["resources"]["memoryMaxBytes"] > budgets["maxMemoryMaxBytes"]:
                raise GrantRefusal("grant-budget-exceeded", "workload memory exceeds the grant budget")
            if spec["resources"]["pidsMax"] > budgets["maxPidsMax"]:
                raise GrantRefusal("grant-budget-exceeded", "workload pids exceed the grant budget")
            parameters = spec["parameters"]
            if spec["kind"] in {"agent-run", "validator-run"}:
                cpu_quota_percent = spec["resources"]["cpuQuotaPercent"]
                disk_max_bytes = spec["resources"]["diskMaxBytes"]
            else:
                cpu_quota_percent = parameters.get("cpuQuotaPercent", 100)
                disk_max_bytes = parameters.get("diskMaxBytes", 16 * 1024 * 1024)
            if cpu_quota_percent > budgets["maxCpuQuotaPercent"]:
                raise GrantRefusal("grant-budget-exceeded", "workload cpu quota exceeds the grant budget")
            if disk_max_bytes > budgets["maxDiskMaxBytes"]:
                raise GrantRefusal("grant-budget-exceeded", "workload disk bound exceeds the grant budget")
            if active_count(grant_id) >= budgets["maxActiveWorkloads"]:
                raise GrantRefusal("grant-budget-exceeded", "the grant's active workload budget is exhausted")
            # The complete sealed spec digest binds every spec field at once:
            # network profile, shell/exec policy, staging/base identity,
            # cache/volume scope, and resource requests.
            bound_digest = grant["workloadSpecDigests"].get(workload_id)
            if bound_digest is None or contract.canonical_digest(spec) != bound_digest:
                raise GrantRefusal(
                    "grant-spec-digest-mismatch",
                    "the complete sealed workload spec does not match the grant's bound spec digest",
                )
        elif workload_id is not None and workload_id not in grant["workloadIds"]:
            raise GrantRefusal("grant-workspace-mismatch", "the grant does not cover this workload id")
        return grant


__all__ = ["GrantRefusal", "GrantStore"]
