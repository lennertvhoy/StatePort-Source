"""Control-plane service that runs one bounded OpenCode objective.

The service is the only web-side orchestrator allowed to drive an agent run.
It never speaks to the execution daemon directly: every preparation and
execution step goes through the sanctioned :class:`ExecutionHostProxy`, so the
same session/CSRF/operator boundary and grant binding apply.

A run is durable.  Before any daemon round trip the service writes a ``running``
receipt under ``<state_dir>/runs/<runId>.json`` and an in-flight marker; a
daemon thread performs the prepare -> start -> exec sequence and finalizes the
receipt with the observed exit status, a digest of the raw output, and a typed
refusal when anything fails.  A thread never dies silently: every exception
becomes a bounded ``refused`` receipt.

Fail-closed rules:

- the operator provider directory is inspected by shape only (presence, owner,
  mode, size); its contents are never read into a projection;
- the agent workspace binding is validated by the proxy against the sealed
  daemon contract before any operation;
- readiness never fabricates availability: a missing proxy, grant, provider
  directory or workspace image is an explicit typed refusal.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .execution_host_proxy import ExecutionHostProxyError

AGENT_WORKSPACE_ID = "agent-workspace"
RECEIPT_FORMAT = "stateport.agent-run-receipt/v1"
MAX_OBJECTIVE_CHARS = 256
MIN_TIMEOUT_SECONDS = 60
MAX_TIMEOUT_SECONDS = 3600
DEFAULT_TIMEOUT_SECONDS = 900
OUTPUT_BYTE_BOUND = 256 * 1024
_IN_PROGRESS_GRACE_SECONDS = 30
_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_TERMINAL_STATUSES = frozenset({"completed", "failed", "refused"})
_REFUSAL_DETAIL_LIMIT = 300


class AgentRunError(RuntimeError):
    """Typed agent-run refusal surfaced as a bounded API error."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: Any) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    return _as_utc(value).strftime("%Y-%m-%dT%H:%M:%SZ")


def _digest_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _last_digest(reference: Any) -> str | None:
    if isinstance(reference, str) and "@sha256:" in reference:
        return "sha256:" + reference.rsplit("@sha256:", 1)[1]
    return None


class AgentRunService:
    """Durable, bounded orchestration of one sealed agent workspace run."""

    def __init__(
        self,
        *,
        execution_host: Any,
        state_dir: str | os.PathLike[str],
        provider_directory: str | None,
        workspace_image_reference: str | None = None,
        timeout_seconds: int | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._execution_host = execution_host
        self._state_dir = Path(state_dir)
        self._runs_dir = self._state_dir / "runs"
        self._provider_directory = provider_directory
        self._workspace_image_reference = workspace_image_reference
        self._timeout_seconds = self._bounded_timeout(timeout_seconds)
        self._clock = clock or _utc_now
        self._mutex = threading.RLock()

    @staticmethod
    def _bounded_timeout(value: int | None) -> int:
        if value is None:
            return DEFAULT_TIMEOUT_SECONDS
        try:
            candidate = int(value)
        except (TypeError, ValueError):
            return DEFAULT_TIMEOUT_SECONDS
        return max(MIN_TIMEOUT_SECONDS, min(MAX_TIMEOUT_SECONDS, candidate))

    # ------------------------------------------------------------ storage

    def _now(self) -> datetime:
        return _as_utc(self._clock())

    def _ensure_runs_dir(self) -> None:
        self._runs_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(self._runs_dir, 0o700)
        except OSError:
            pass

    @staticmethod
    def _atomic_write(path: Path, payload: bytes) -> None:
        directory = path.parent
        fd, temporary = tempfile.mkstemp(dir=str(directory), prefix=".tmp-")
        try:
            os.fchmod(fd, 0o600)
            offset = 0
            while offset < len(payload):
                offset += os.write(fd, payload[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)

    def _write_record(self, record: dict[str, Any]) -> None:
        self._ensure_runs_dir()
        payload = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self._atomic_write(self._runs_dir / f"{record['runId']}.json", payload)

    def _read_record(self, run_id: Any) -> dict[str, Any]:
        if not isinstance(run_id, str) or _RUN_ID.fullmatch(run_id) is None:
            raise AgentRunError("unknown_run", "the agent run was not found")
        path = self._runs_dir / f"{run_id}.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise AgentRunError("unknown_run", "the agent run was not found") from exc
        if not isinstance(data, dict) or data.get("runId") != run_id:
            raise AgentRunError("unknown_run", "the agent run was not found")
        return data

    def _marker_path(self) -> Path:
        return self._runs_dir / ".active"

    def _write_marker(self, run_id: str, created_at: str) -> None:
        self._ensure_runs_dir()
        payload = json.dumps(
            {"runId": run_id, "createdAt": created_at, "pid": os.getpid()},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self._atomic_write(self._marker_path(), payload)

    def _clear_marker(self, run_id: str) -> None:
        marker = self._marker_path()
        try:
            data = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if isinstance(data, dict) and data.get("runId") == run_id:
            try:
                marker.unlink()
            except OSError:
                pass

    # ---------------------------------------------------------- readiness

    @staticmethod
    def _regular_file(path: Path, minimum: int, maximum: int) -> bool:
        try:
            info = os.lstat(path)
        except OSError:
            return False
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            return False
        return minimum <= info.st_size <= maximum

    def _provider_files(self, directory: Path, projection: dict[str, Any]) -> list[dict[str, str]]:
        refusals: list[dict[str, str]] = []
        env_path = directory / "provider.env"
        env_ok = self._regular_file(env_path, 1, 4096)
        if env_ok:
            # The sealed workspace container reads this material as a mapped
            # container uid, so the directory needs traverse bits and the file
            # needs read bits.  Only group/other WRITE bits are refused; the
            # directory stays owned by this user inside the private state root,
            # which is what keeps other local users out.
            env_mode = os.lstat(env_path).st_mode
            if env_mode & 0o022:
                env_ok = False
        if env_ok:
            projection["files"]["providerEnv"] = True
        else:
            refusals.append(
                {
                    "reason": "provider_directory_incomplete",
                    "detail": "provider.env is missing or unsafe",
                }
            )
        if self._regular_file(directory / "opencode.json", 1, 65536):
            projection["files"]["opencodeJson"] = True
        else:
            refusals.append(
                {
                    "reason": "provider_directory_incomplete",
                    "detail": "opencode.json is missing or invalid",
                }
            )
        model_path = directory / "model"
        if model_path.exists() or model_path.is_symlink():
            if self._regular_file(model_path, 1, 256):
                projection["files"]["model"] = True
            else:
                refusals.append(
                    {
                        "reason": "provider_directory_incomplete",
                        "detail": "the optional model file is invalid",
                    }
                )
        return refusals

    def readiness(self) -> dict[str, Any]:
        """Return the bounded preflight projection; nothing is fabricated."""

        refusals: list[dict[str, str]] = []
        projection = {
            "configured": self._provider_directory is not None,
            "present": False,
            "files": {"providerEnv": False, "opencodeJson": False, "model": False},
        }
        directory: Path | None = None
        if not isinstance(self._provider_directory, str) or not self._provider_directory:
            refusals.append(
                {
                    "reason": "provider_directory_unconfigured",
                    "detail": "an operator provider directory is not configured",
                }
            )
        else:
            candidate = Path(self._provider_directory)
            if not candidate.is_absolute():
                refusals.append(
                    {
                        "reason": "provider_directory_unconfigured",
                        "detail": "the operator provider directory must be an absolute path",
                    }
                )
            else:
                directory = candidate

        if directory is not None:
            try:
                info = os.lstat(directory)
            except OSError:
                info = None
            if (
                info is None
                or stat.S_ISLNK(info.st_mode)
                or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o022
            ):
                refusals.append(
                    {
                        "reason": "provider_directory_missing",
                        "detail": "the operator provider directory is missing or unsafe",
                    }
                )
            else:
                projection["present"] = True
                refusals.extend(self._provider_files(directory, projection))

        workspace = {"status": "unavailable", "workloadId": AGENT_WORKSPACE_ID}
        observed: dict[str, Any] | None = None
        try:
            observed = self._execution_host.agent_workspace_status()
        except ExecutionHostProxyError as exc:
            refusals.append({"reason": "execution_unavailable", "detail": exc.code})
        except Exception:  # noqa: BLE001 - a proxy double or transport may fail closed
            refusals.append(
                {"reason": "execution_unavailable", "detail": "execution host is unavailable"}
            )
        else:
            state = observed.get("state") if isinstance(observed, dict) else None
            workspace = {
                "status": state if isinstance(state, str) and state else "absent",
                "workloadId": (
                    observed.get("workloadId")
                    if isinstance(observed, dict) and isinstance(observed.get("workloadId"), str)
                    else AGENT_WORKSPACE_ID
                ),
            }

        reference = self._workspace_image_reference
        if not isinstance(reference, str) or not reference:
            refusals.append(
                {
                    "reason": "agent_workspace_image_mismatch",
                    "detail": "the agent workspace image reference is not configured",
                }
            )
        elif isinstance(observed, dict):
            observed_digest = observed.get("imageDigest")
            expected_digest = _last_digest(reference)
            if (
                isinstance(observed_digest, str)
                and expected_digest is not None
                and observed_digest != expected_digest
            ):
                refusals.append(
                    {
                        "reason": "agent_workspace_image_mismatch",
                        "detail": "the observed agent workspace image does not match the configured image",
                    }
                )

        return {
            "available": not refusals,
            "refusals": refusals,
            "providerDirectory": projection,
            "workspace": workspace,
        }

    # -------------------------------------------------------------- runs

    @staticmethod
    def _validate_objective(objective: Any) -> str:
        if not isinstance(objective, str):
            raise AgentRunError("objective_invalid", "the objective must be a string")
        if not objective.strip():
            raise AgentRunError("objective_invalid", "the objective must not be empty")
        if "\x00" in objective:
            raise AgentRunError("objective_invalid", "the objective must not contain NUL")
        if len(objective) > MAX_OBJECTIVE_CHARS:
            raise AgentRunError(
                "objective_too_long",
                f"the objective exceeds the {MAX_OBJECTIVE_CHARS}-character bound",
            )
        return objective

    def _require_no_live_run(self) -> None:
        """Refuse a second concurrent run, reclaiming only a provably dead one.

        The marker holds the run id, creation time and owning pid.  It is
        reclaimed only when it is older than the timeout plus a grace buffer,
        the recorded pid is absent, and the run record is terminal or missing;
        every other case stays an honest ``agent_run_in_progress`` refusal.
        """

        marker = self._marker_path()
        try:
            raw = marker.read_text(encoding="utf-8")
        except FileNotFoundError:
            return
        except OSError as exc:
            raise AgentRunError(
                "agent_run_in_progress", "an agent run marker is unreadable"
            ) from exc
        try:
            data = json.loads(raw)
            run_id = data["runId"]
            created = datetime.strptime(data["createdAt"], "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc
            )
            pid = data.get("pid")
        except (ValueError, KeyError, TypeError) as exc:
            raise AgentRunError(
                "agent_run_in_progress", "an agent run is already in progress"
            ) from exc
        age = (self._now() - created).total_seconds()
        if age <= self._timeout_seconds + _IN_PROGRESS_GRACE_SECONDS:
            raise AgentRunError("agent_run_in_progress", "an agent run is already in progress")
        pid_alive = False
        if isinstance(pid, int) and not isinstance(pid, bool) and pid > 0:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                pid_alive = False
            except PermissionError:
                pid_alive = True
            except OSError:
                pid_alive = True
            else:
                pid_alive = True
        try:
            previous = self._read_record(run_id)
        except AgentRunError:
            previous = None
        if not pid_alive and (previous is None or previous.get("status") in _TERMINAL_STATUSES):
            try:
                marker.unlink()
            except OSError:
                pass
            return
        raise AgentRunError("agent_run_in_progress", "an agent run is already in progress")

    def start(self, objective: Any) -> dict[str, Any]:
        """Persist a running receipt and spawn the bounded worker quickly."""

        objective = self._validate_objective(objective)
        with self._mutex:
            self._require_no_live_run()
            preflight = self.readiness()
            if not preflight["available"]:
                first = preflight["refusals"][0]
                raise AgentRunError(first["reason"], first["detail"])
            created_at = _timestamp(self._now())
            run_id = "agent-run-" + uuid.uuid4().hex
            record: dict[str, Any] = {
                "formatVersion": RECEIPT_FORMAT,
                "runId": run_id,
                "status": "running",
                "objective": objective,
                "objectiveDigest": _digest_text(objective),
                "workspaceId": AGENT_WORKSPACE_ID,
                "imageReference": None,
                "workspaceSpecDigest": None,
                "grantId": None,
                "authorityGrantDigest": None,
                "createOperationId": None,
                "startOperationId": None,
                "execOperationId": None,
                "exitStatus": None,
                "outputDigest": None,
                "outputBytes": None,
                "truncated": False,
                "refusal": None,
                "startedAt": created_at,
                "finishedAt": None,
                "createdAt": created_at,
                "updatedAt": created_at,
            }
            self._write_record(record)
            self._write_marker(run_id, created_at)
        thread = threading.Thread(
            target=self._execute,
            args=(run_id, objective),
            name=f"agent-run-{run_id}",
            daemon=True,
        )
        thread.start()
        return {
            "runId": run_id,
            "status": "running",
            "objective": objective,
            "workspaceId": AGENT_WORKSPACE_ID,
            "startedAt": created_at,
        }

    def _execute(self, run_id: str, objective: str) -> None:
        """Perform prepare -> start -> exec; any failure becomes a refusal."""

        stage = "prepare"
        create_operation_id: str | None = None
        start_operation_id: str | None = None
        record = self._read_record(run_id)
        try:
            binding = self._execution_host.agent_workspace_binding()
            workload = binding["workload"]
            image_reference = workload["image"]["reference"]
            workspace_spec_digest = workload["parameters"]["workspaceSpecDigest"]
            record["imageReference"] = image_reference
            record["workspaceSpecDigest"] = workspace_spec_digest
            record["grantId"] = binding["grantId"]
            record["authorityGrantDigest"] = binding["authorityGrantDigest"]
            expected_digest = _last_digest(image_reference) or ""
            observed = self._execution_host.agent_workspace_status()
            present = (
                isinstance(observed, dict)
                and observed.get("workloadId") == AGENT_WORKSPACE_ID
                and observed.get("state") not in {"absent", "removed", None}
            )
            if present:
                observed_digest = observed.get("imageDigest")
                if isinstance(observed_digest, str) and observed_digest != expected_digest:
                    raise AgentRunError(
                        "agent_workspace_image_mismatch",
                        "the observed agent workspace image does not match the binding",
                    )
            else:
                receipt = self._execution_host.create_agent_workspace()
                create_operation_id = receipt.get("operationId")
                record["createOperationId"] = create_operation_id
                if receipt.get("accepted") is not True:
                    reason = (receipt.get("refusal") or {}).get("reason") or "create-workload-refused"
                    raise AgentRunError(
                        "workspace_prepare_failed",
                        f"the execution host refused workspace creation: {reason}",
                    )
                observed = self._execution_host.agent_workspace_status()
            if not (isinstance(observed, dict) and observed.get("running") is True):
                receipt = self._execution_host.start_agent_workspace()
                start_operation_id = receipt.get("operationId")
                record["startOperationId"] = start_operation_id
                if receipt.get("accepted") is not True:
                    reason = (receipt.get("refusal") or {}).get("reason") or "start-refused"
                    raise AgentRunError(
                        "workspace_prepare_failed",
                        f"the execution host refused workspace start: {reason}",
                    )
            stage = "exec"
            receipt = self._execution_host.agent_exec(
                objective, timeout_seconds=self._timeout_seconds
            )
            if receipt.get("accepted") is not True:
                reason = (receipt.get("refusal") or {}).get("reason") or "exec-refused"
                raise AgentRunError(
                    "agent_run_failed", f"the execution host refused the run: {reason}"
                )
            result = receipt.get("result") if isinstance(receipt.get("result"), dict) else {}
            output = result.get("output")
            if not isinstance(output, str):
                raise AgentRunError(
                    "agent_run_failed", "the execution host returned no bounded output"
                )
            exit_status = result.get("exitStatus")
            if isinstance(exit_status, bool) or not isinstance(exit_status, int):
                raise AgentRunError(
                    "agent_run_failed", "the execution host returned no exit status"
                )
            raw = output.encode("utf-8")
            stored = raw[:OUTPUT_BYTE_BOUND]
            self._atomic_write(self._runs_dir / f"{run_id}.output", stored)
            record["execOperationId"] = receipt.get("operationId")
            record["exitStatus"] = exit_status
            record["outputDigest"] = _digest_text(output)
            record["outputBytes"] = len(raw)
            record["truncated"] = bool(result.get("truncated")) or len(raw) > OUTPUT_BYTE_BOUND
            record["status"] = "completed" if exit_status == 0 else "failed"
            record["refusal"] = None
        except AgentRunError as exc:
            self._refuse(record, exc.code, exc.detail)
        except ExecutionHostProxyError as exc:
            if stage == "prepare":
                code = (
                    exc.code
                    if exc.code
                    in {
                        "agent_workspace_authority_missing",
                        "agent_workspace_authority_invalid",
                        "agent_workspace_image_mismatch",
                        "execution_unavailable",
                    }
                    else "workspace_prepare_failed"
                )
            else:
                code = (
                    exc.code
                    if exc.code in {"execution_unavailable", "agent_workspace_image_mismatch"}
                    else "agent_run_failed"
                )
            self._refuse(record, code, str(exc) or exc.code)
        except Exception as exc:  # noqa: BLE001 - a worker thread never dies silently
            code = "workspace_prepare_failed" if stage == "prepare" else "agent_run_failed"
            self._refuse(record, code, str(exc) or "agent run failed")
        finally:
            finished_at = _timestamp(self._now())
            record["finishedAt"] = record.get("finishedAt") or finished_at
            record["updatedAt"] = finished_at
            try:
                self._write_record(record)
            finally:
                self._clear_marker(run_id)

    def _refuse(self, record: dict[str, Any], code: str, detail: str) -> None:
        record["status"] = "refused"
        record["refusal"] = {
            "reason": code,
            "detail": (detail or code)[:_REFUSAL_DETAIL_LIMIT],
        }
        record["finishedAt"] = _timestamp(self._now())
        record["updatedAt"] = record["finishedAt"]

    # ---------------------------------------------------------- read APIs

    def status(self, run_id: Any) -> dict[str, Any]:
        return dict(self._read_record(run_id))

    def list_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            limit = 20
        limit = min(limit, 100)
        records: list[dict[str, Any]] = []
        try:
            entries = list(self._runs_dir.iterdir())
        except OSError:
            return records
        for entry in entries:
            if entry.name.startswith(".") or not entry.name.endswith(".json"):
                continue
            try:
                data = json.loads(entry.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(data, dict) and isinstance(data.get("runId"), str):
                records.append(data)
        records.sort(
            key=lambda row: (str(row.get("createdAt", "")), str(row.get("runId", ""))),
            reverse=True,
        )
        return records[:limit]

    def logs(self, run_id: Any) -> dict[str, Any]:
        record = self._read_record(run_id)
        try:
            raw = (self._runs_dir / f"{record['runId']}.output").read_bytes()
        except OSError:
            raw = b""
        if len(raw) > OUTPUT_BYTE_BOUND:
            raw = raw[:OUTPUT_BYTE_BOUND]
        return {
            "runId": record["runId"],
            "output": raw.decode("utf-8", errors="replace"),
            "truncated": bool(record.get("truncated")),
            "outputBytes": record.get("outputBytes"),
        }


__all__ = [
    "AGENT_WORKSPACE_ID",
    "DEFAULT_TIMEOUT_SECONDS",
    "MAX_OBJECTIVE_CHARS",
    "MAX_TIMEOUT_SECONDS",
    "MIN_TIMEOUT_SECONDS",
    "OUTPUT_BYTE_BOUND",
    "RECEIPT_FORMAT",
    "AgentRunError",
    "AgentRunService",
]
