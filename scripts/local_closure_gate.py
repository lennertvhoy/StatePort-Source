#!/usr/bin/env python3
"""Run StatePort's fail-closed, reproducible local-first closure gate.

Local validation is the authoritative path: the command plan in
``default_commands`` is the single source of truth, covers the same closure
boundaries as the GitHub workflow, and runs without any push or workflow
dispatch.  GitHub Actions is optional supplemental remote evidence layered on
top — never the verdict and never a reason to skip local checks.  With
``--remote`` the gate *observes* bounded remote CI via the ``gh`` CLI (an
existing completed run for the exact HEAD, binding-validated for repository,
workflow, event, branch, freshness, required jobs, and runner class) and
records it as supplemental; remote evidence never replaces, skips, or gates
the local plan.  ``--remote-dispatch`` is a separate, explicit, owner-gated
operation that dispatches the workflow (clean worktree and HEAD == remote
``main`` head only) and then waits for the bound result; dispatch never
happens automatically.  A dirty worktree can never claim remote verification:
remote evidence covers committed bytes only, and the local cleanliness gates
always run.  There is no silent success: an obtained remote failure is a gate
failure, and supplemental remote evidence is never labelled as covering the
local worktree.

Profiles: the gate intentionally ships a single authoritative closure plan
(``default_commands``).  cheap/affected/milestone subsets do not fit the
fail-closed abstraction, because closure evidence must cover every boundary.
``--include-service-journey`` appends the heavy release-relevant Compose
service journey (``service_journey_commands``) as an explicit opt-in.

The runner deliberately records only sanitized evidence and never records
environment variable values.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Protocol, Sequence


ROOT = Path(__file__).resolve().parents[1]
GOVERNED_RUNNER_SRC = ROOT / "packages" / "governed-runner" / "src"
if str(GOVERNED_RUNNER_SRC) not in sys.path:
    sys.path.insert(0, str(GOVERNED_RUNNER_SRC))

from governed_runner.workspaces import (  # noqa: E402
    WorkspaceLifecycleError,
    WorkspaceLifecycleManager,
)
FORMAT_VERSION = "stateport.local-closure-gate/v1"
ENVIRONMENT_LABELS = ("active", "fresh", "container")
SOURCE_REPOSITORY_ENV = "STATEPORT_BROWSER_STUDYDD_REPOSITORY"
_SENSITIVE_ENV_NAME = re.compile(
    r"(?:api[_-]?key|auth|bearer|credential|password|secret|token)", re.IGNORECASE
)
_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|authorization|bearer|credential|password|secret|token)"
    r"\s*[:=]\s*([^\s,;]+)"
)
_URI_CREDENTIALS = re.compile(r"([a-z][a-z0-9+.-]*://)[^/@\s:]+(?::[^/@\s]*)?@", re.IGNORECASE)
_HOME_PATH = re.compile(r"(?<![A-Za-z0-9._-])/home/[^/\s]+")
_SAFE_COMMAND_LABEL = re.compile(r"^[A-Za-z0-9_.-]+$")
_LOOPBACK_PORT_PLACEHOLDER = "{loopback_port}"


@dataclass(frozen=True)
class CommandSpec:
    """One argv-only command in the closure plan."""

    label: str
    argv: tuple[str, ...]
    cwd: str = "."
    timeout_seconds: int = 120
    required_environment: tuple[str, ...] = ()
    env: tuple[str, ...] = ()
    browser_artifacts: bool = False


REMOTE_WORKFLOW_FILE = "validate.yml"
REMOTE_REQUIRED_JOBS = (
    "backend",
    "web",
    "canonical-source-browser",
    "security",
    "package-validation",
    "compose-integration",
)
REMOTE_ALLOWED_EVENTS = ("workflow_dispatch", "pull_request")
REMOTE_REQUIRED_RUNNER_LABELS = ("self-hosted", "stateport")
REMOTE_MAX_RUN_AGE_SECONDS = 24 * 3600
REMOTE_DEFAULT_TIMEOUT_SECONDS = 600
REMOTE_MAX_TIMEOUT_SECONDS = 7200
REMOTE_DEFAULT_POLL_INTERVAL_SECONDS = 20
REMOTE_MIN_POLL_INTERVAL_SECONDS = 5
REMOTE_BINDING_REASONS = (
    "wrong_repository",
    "wrong_workflow",
    "wrong_event",
    "wrong_commit",
    "created_at_unparseable",
    "stale_run",
    "missing_jobs",
    "job_not_successful",
    "runner_class_unverified",
)
REMOTE_UNAVAILABLE_REASONS = (
    "gh_cli_unavailable",
    "quota_exhausted",
    "api_unavailable",
    "workflow_disabled",
    "runner_offline",
    "repository_unresolvable",
    "no_completed_run",
    "dirty_worktree",
    "head_not_on_remote_main",
    "dispatch_refused",
    "timeout",
    *REMOTE_BINDING_REASONS,
)
_QUOTA_MARKERS = ("billing", "spending limit", "quota", "rate limit", "api rate limit")


@dataclass(frozen=True)
class RemoteJob:
    """One job inside a remote run: name, conclusion, and runner labels."""

    name: str
    conclusion: str
    labels: tuple[str, ...]


@dataclass(frozen=True)
class RemoteRun:
    """One completed GitHub Actions run with its evidence-binding fields.

    Every field is part of the binding: remote evidence is only usable when
    repository, workflow, event, commit, freshness, required jobs, and runner
    class all validate against expectations.
    """

    run_id: int
    conclusion: str
    url: str
    repository: str
    workflow: str
    event: str
    head_branch: str
    head_sha: str
    created_at: str


@dataclass(frozen=True)
class RemoteAttempt:
    """Bounded remote CI observation or owner-gated dispatch result.

    ``outcome`` is ``verified`` (a binding-validated remote run succeeded —
    supplemental evidence about the exact committed HEAD only), ``failed``
    (an obtained, honest non-success result that fails the gate), or
    ``unavailable`` with a ``reason`` from ``REMOTE_UNAVAILABLE_REASONS``
    (the local plan remains the only evidence).  ``dispatched`` records
    whether an explicit owner-gated dispatch was performed.
    """

    attempted: bool
    outcome: str
    reason: str | None
    run_id: int | None
    conclusion: str | None
    url: str | None
    duration_seconds: float
    dispatched: bool = False
    run: RemoteRun | None = None
    jobs: tuple[RemoteJob, ...] = ()


class GhRemoteCIError(RuntimeError):
    """A ``gh`` CLI or GitHub API boundary failure."""


class RemoteQuotaExhausted(GhRemoteCIError):
    """GitHub Actions is blocked by billing, spending-limit, or rate quota."""


class RemoteCIClient(Protocol):
    """Boundary every remote CI interaction goes through (mockable in tests)."""

    def gh_available(self) -> bool: ...

    def repository(self) -> str: ...

    def workflow_enabled(self) -> bool: ...

    def runner_online(self) -> bool: ...

    def find_completed_run(self, commit: str) -> RemoteRun | None: ...

    def run_jobs(self, run_id: int) -> tuple[RemoteJob, ...]: ...

    def remote_main_head(self) -> str: ...

    def dispatch(self, ref: str) -> None: ...

    def wait_for_run(
        self, commit: str, *, timeout_seconds: int, poll_interval_seconds: int
    ) -> RemoteRun | None: ...


class GhRemoteCIClient:
    """``gh``-backed remote CI boundary; the only network/API access point.

    Credentials are never recorded: only structured fields (run id, conclusion,
    url) leave this class, and stderr text is never propagated into evidence.
    """

    def __init__(
        self,
        repo_root: Path,
        *,
        workflow: str = REMOTE_WORKFLOW_FILE,
        command_timeout_seconds: int = 30,
    ) -> None:
        self._repo_root = repo_root
        self._workflow = workflow
        self._command_timeout_seconds = command_timeout_seconds

    def _gh(self, *args: str) -> str:
        try:
            completed = subprocess.run(
                ["gh", *args],
                cwd=str(self._repo_root),
                check=False,
                capture_output=True,
                text=True,
                timeout=self._command_timeout_seconds,
            )
        except FileNotFoundError as exc:
            raise GhRemoteCIError("gh_cli_unavailable") from exc
        except subprocess.TimeoutExpired as exc:
            raise GhRemoteCIError("gh_command_timed_out") from exc
        if completed.returncode:
            detail = (completed.stderr or "").lower()
            if any(marker in detail for marker in _QUOTA_MARKERS):
                raise RemoteQuotaExhausted("github_actions_quota_exhausted")
            raise GhRemoteCIError(f"gh {args[0]} failed")
        return completed.stdout

    def _gh_json(self, *args: str) -> object:
        try:
            return json.loads(self._gh(*args))
        except json.JSONDecodeError as exc:
            raise GhRemoteCIError("gh_json_unparseable") from exc

    def _name_with_owner(self) -> str:
        return self._gh("repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner").strip()

    def repository(self) -> str:
        return self._name_with_owner()

    def gh_available(self) -> bool:
        if shutil.which("gh") is None:
            return False
        try:
            self._gh("auth", "status")
        except GhRemoteCIError:
            return False
        return True

    def workflow_enabled(self) -> bool:
        state = self._gh("workflow", "view", self._workflow, "--json", "state", "--jq", ".state")
        return state.strip() == "active"

    def runner_online(self) -> bool:
        payload = self._gh_json("api", f"repos/{self._name_with_owner()}/actions/runners")
        if not isinstance(payload, dict):
            raise GhRemoteCIError("runner_list_unparseable")
        runners = payload.get("runners")
        if not isinstance(runners, list):
            raise GhRemoteCIError("runner_list_unparseable")
        for runner in runners:
            if not isinstance(runner, dict) or runner.get("status") != "online":
                continue
            labels = runner.get("labels")
            if isinstance(labels, list) and any(
                isinstance(label, dict) and label.get("name") == "stateport" for label in labels
            ):
                return True
        return False

    def _runs_for_commit(self, commit: str) -> list[RemoteRun]:
        payload = self._gh_json(
            "run",
            "list",
            "--workflow",
            self._workflow,
            "--commit",
            commit,
            "--limit",
            "10",
            "--json",
            "databaseId,status,conclusion,url,headSha,headBranch,event,createdAt",
        )
        if not isinstance(payload, list):
            raise GhRemoteCIError("run_list_unparseable")
        # The query is scoped to this repository and workflow file; record both
        # so binding validation can reject any run that is not exactly that.
        repository = self._name_with_owner()
        runs: list[RemoteRun] = []
        for item in payload:
            if not isinstance(item, dict) or item.get("headSha") != commit:
                continue
            runs.append(
                RemoteRun(
                    run_id=int(item.get("databaseId") or 0),
                    conclusion=str(item.get("conclusion") or ""),
                    url=str(item.get("url") or ""),
                    repository=repository,
                    workflow=self._workflow,
                    event=str(item.get("event") or ""),
                    head_branch=str(item.get("headBranch") or ""),
                    head_sha=str(item.get("headSha") or ""),
                    created_at=str(item.get("createdAt") or ""),
                )
            )
        return runs

    def find_completed_run(self, commit: str) -> RemoteRun | None:
        for run in self._runs_for_commit(commit):
            if run.conclusion:
                return run
        return None

    def run_jobs(self, run_id: int) -> tuple[RemoteJob, ...]:
        payload = self._gh_json(
            "api", f"repos/{self._name_with_owner()}/actions/runs/{run_id}/jobs"
        )
        if not isinstance(payload, dict) or not isinstance(payload.get("jobs"), list):
            raise GhRemoteCIError("job_list_unparseable")
        jobs: list[RemoteJob] = []
        for item in payload["jobs"]:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                raise GhRemoteCIError("job_list_unparseable")
            raw_labels = item.get("labels")
            labels = tuple(
                sorted(label for label in raw_labels if isinstance(label, str))
            ) if isinstance(raw_labels, list) else ()
            jobs.append(
                RemoteJob(
                    name=item["name"],
                    conclusion=str(item.get("conclusion") or ""),
                    labels=labels,
                )
            )
        return tuple(jobs)

    def remote_main_head(self) -> str:
        payload = self._gh_json("api", f"repos/{self._name_with_owner()}/branches/main")
        if not isinstance(payload, dict):
            raise GhRemoteCIError("branch_unparseable")
        commit = payload.get("commit")
        if not isinstance(commit, dict) or not isinstance(commit.get("sha"), str):
            raise GhRemoteCIError("branch_unparseable")
        return commit["sha"]

    def dispatch(self, ref: str) -> None:
        self._gh("workflow", "run", self._workflow, "--ref", ref)

    def wait_for_run(
        self, commit: str, *, timeout_seconds: int, poll_interval_seconds: int
    ) -> RemoteRun | None:
        deadline = time.monotonic() + timeout_seconds
        while True:
            for run in self._runs_for_commit(commit):
                if run.conclusion:
                    return run
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            time.sleep(min(poll_interval_seconds, remaining))


def bind_remote_run(
    run: RemoteRun,
    jobs: tuple[RemoteJob, ...],
    *,
    commit: str,
    repository: str,
    now_seconds: float | None = None,
) -> str | None:
    """Validate that a remote run is usable evidence for the exact HEAD.

    Returns ``None`` when the binding holds, else a reason from
    ``REMOTE_BINDING_REASONS``.  Remote evidence must bind the repository,
    workflow file, event, exact commit, run freshness, the complete required
    job set with successful conclusions, and the privileged runner class.
    """

    if run.repository != repository:
        return "wrong_repository"
    if run.workflow != REMOTE_WORKFLOW_FILE:
        return "wrong_workflow"
    if run.event not in REMOTE_ALLOWED_EVENTS:
        return "wrong_event"
    if run.head_sha != commit:
        return "wrong_commit"
    try:
        created = datetime.fromisoformat(run.created_at.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return "created_at_unparseable"
    current = time.time() if now_seconds is None else now_seconds
    if current - created > REMOTE_MAX_RUN_AGE_SECONDS or created - current > 300:
        return "stale_run"
    by_name = {job.name: job for job in jobs}
    missing = [name for name in REMOTE_REQUIRED_JOBS if name not in by_name]
    if missing:
        return "missing_jobs"
    for name in REMOTE_REQUIRED_JOBS:
        job = by_name[name]
        if job.conclusion != "success":
            return "job_not_successful"
        if not set(REMOTE_REQUIRED_RUNNER_LABELS) <= set(job.labels):
            return "runner_class_unverified"
    return None


def _probe_remote(
    client: RemoteCIClient,
    started: float,
) -> RemoteAttempt | None:
    """Shared availability probes; returns an ``unavailable`` attempt or None."""

    def elapsed() -> float:
        return round(time.monotonic() - started, 3)

    if not client.gh_available():
        return RemoteAttempt(True, "unavailable", "gh_cli_unavailable", None, None, None, elapsed())
    try:
        if not client.workflow_enabled():
            return RemoteAttempt(True, "unavailable", "workflow_disabled", None, None, None, elapsed())
        if not client.runner_online():
            return RemoteAttempt(True, "unavailable", "runner_offline", None, None, None, elapsed())
    except RemoteQuotaExhausted:
        return RemoteAttempt(True, "unavailable", "quota_exhausted", None, None, None, elapsed())
    except GhRemoteCIError:
        return RemoteAttempt(True, "unavailable", "api_unavailable", None, None, None, elapsed())
    return None


def _bound_attempt(
    client: RemoteCIClient,
    run: RemoteRun,
    *,
    commit: str,
    repository: str,
    started: float,
    dispatched: bool,
) -> RemoteAttempt:
    """Bind-validate an obtained run and build the attempt result."""

    elapsed = round(time.monotonic() - started, 3)
    try:
        jobs = client.run_jobs(run.run_id)
    except RemoteQuotaExhausted:
        return RemoteAttempt(True, "unavailable", "quota_exhausted", None, None, None, elapsed, dispatched)
    except GhRemoteCIError:
        return RemoteAttempt(True, "unavailable", "api_unavailable", None, None, None, elapsed, dispatched)
    reason = bind_remote_run(run, jobs, commit=commit, repository=repository)
    if reason is not None:
        return RemoteAttempt(True, "unavailable", reason, None, None, None, elapsed, dispatched)
    outcome = "verified" if run.conclusion == "success" else "failed"
    return RemoteAttempt(
        True, outcome, None, run.run_id, run.conclusion, run.url, elapsed, dispatched, run, jobs
    )


def observe_remote_ci(
    *,
    client: RemoteCIClient,
    commit: str,
    repository: str,
) -> RemoteAttempt:
    """Observe bounded remote CI evidence for the exact HEAD commit.

    Observation only: never dispatches, never pushes.  Looks for an existing
    completed run for the commit and binding-validates it.  Every failure
    mode returns ``unavailable`` with an explicit reason; the local plan
    remains the authoritative evidence.
    """

    started = time.monotonic()
    probe = _probe_remote(client, started)
    if probe is not None:
        return probe
    try:
        existing = client.find_completed_run(commit)
    except RemoteQuotaExhausted:
        return RemoteAttempt(True, "unavailable", "quota_exhausted", None, None, None, round(time.monotonic() - started, 3))
    except GhRemoteCIError:
        return RemoteAttempt(True, "unavailable", "api_unavailable", None, None, None, round(time.monotonic() - started, 3))
    if existing is None:
        return RemoteAttempt(True, "unavailable", "no_completed_run", None, None, None, round(time.monotonic() - started, 3))
    return _bound_attempt(
        client, existing, commit=commit, repository=repository, started=started, dispatched=False
    )


def dispatch_remote_ci(
    *,
    client: RemoteCIClient,
    commit: str,
    repository: str,
    clean: bool,
    timeout_seconds: int,
    poll_interval_seconds: int = REMOTE_DEFAULT_POLL_INTERVAL_SECONDS,
) -> RemoteAttempt:
    """Explicit owner-gated remote dispatch, then a bounded wait for the result.

    Dispatch is never automatic: this operation requires a clean worktree and
    HEAD exactly equal to the remote ``main`` head, so untrusted or unpushed
    code can never reach the privileged self-hosted runner through this path.
    """

    started = time.monotonic()

    def elapsed() -> float:
        return round(time.monotonic() - started, 3)

    if not clean:
        return RemoteAttempt(True, "unavailable", "dirty_worktree", None, None, None, elapsed())
    probe = _probe_remote(client, started)
    if probe is not None:
        return probe
    try:
        if client.remote_main_head() != commit:
            return RemoteAttempt(True, "unavailable", "head_not_on_remote_main", None, None, None, elapsed())
    except RemoteQuotaExhausted:
        return RemoteAttempt(True, "unavailable", "quota_exhausted", None, None, None, elapsed())
    except GhRemoteCIError:
        return RemoteAttempt(True, "unavailable", "api_unavailable", None, None, None, elapsed())
    try:
        client.dispatch("main")
    except RemoteQuotaExhausted:
        return RemoteAttempt(True, "unavailable", "quota_exhausted", None, None, None, elapsed())
    except GhRemoteCIError:
        return RemoteAttempt(True, "unavailable", "dispatch_refused", None, None, None, elapsed())
    try:
        result = client.wait_for_run(
            commit,
            timeout_seconds=timeout_seconds,
            poll_interval_seconds=poll_interval_seconds,
        )
    except RemoteQuotaExhausted:
        return RemoteAttempt(True, "unavailable", "quota_exhausted", None, None, None, elapsed(), True)
    except GhRemoteCIError:
        return RemoteAttempt(True, "unavailable", "api_unavailable", None, None, None, elapsed(), True)
    if result is None:
        return RemoteAttempt(True, "unavailable", "timeout", None, None, None, elapsed(), True)
    return _bound_attempt(
        client, result, commit=commit, repository=repository, started=started, dispatched=True
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git(repo_root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if completed.returncode:
        raise RuntimeError(f"git {' '.join(args)} failed")
    return completed.stdout.strip()


def _redaction_values(
    repo_root: Path,
    output_dir: Path,
    environment: Mapping[str, str],
) -> list[tuple[str, str]]:
    values: list[tuple[str, str]] = [
        (str(repo_root.resolve()), "[REPO]"),
        (str(output_dir.resolve()), "[OUTPUT]"),
        (str(Path.home().resolve()), "[HOME]"),
    ]
    source = environment.get(SOURCE_REPOSITORY_ENV, "")
    if source:
        values.append((source, "[SOURCE_REPOSITORY]"))
    for name, value in environment.items():
        if value and len(value) >= 4 and _SENSITIVE_ENV_NAME.search(name):
            values.append((value, f"[{name}_REDACTED]"))
    return sorted(set(values), key=lambda item: len(item[0]), reverse=True)


def sanitize_text(text: str, redactions: Sequence[tuple[str, str]]) -> str:
    """Remove local paths and common credential shapes from captured output."""

    sanitized = text
    for value, replacement in redactions:
        if value:
            sanitized = sanitized.replace(value, replacement)
    sanitized = _HOME_PATH.sub("[HOME]", sanitized)
    sanitized = _URI_CREDENTIALS.sub(r"\1[REDACTED]@", sanitized)
    sanitized = _SENSITIVE_ASSIGNMENT.sub(lambda match: f"{match.group(1)}=[REDACTED]", sanitized)
    return sanitized


def _execution_environment(environment: Mapping[str, str]) -> dict[str, str]:
    """Drop credentials and host overrides before running validation tools."""

    safe: dict[str, str] = {}
    for name, value in environment.items():
        if name == SOURCE_REPOSITORY_ENV:
            safe[name] = value
            continue
        if _SENSITIVE_ENV_NAME.search(name):
            continue
        if name in {"PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP"}:
            continue
        if name.startswith(("GIT_", "SSH_", "STATEPORT_")):
            continue
        safe[name] = value
    return safe


def default_commands(max_timeout_seconds: int) -> tuple[CommandSpec, ...]:
    """Return the repository-authoritative local closure command plan.

    The plan covers the same boundaries as ``.github/workflows/validate.yml``:
    locked Python environment, Python/Node tool floors, Ruff lint at the
    locked version, repository/state/schema gates, the complete Python suite,
    locked frontend install/typecheck/lint/test/build/budget/dependency
    checks, browser acceptance, the secret scan, and package/compose shape
    validation.  The heavy Compose service journey is the explicit opt-in
    ``service_journey_commands`` boundary.
    """

    def bounded(requested: int) -> int:
        return min(requested, max_timeout_seconds)

    python = "python3"
    wheelhouse = ".stateport-local/updater-build-wheelhouse"
    ruff_pin_check = (
        "import importlib.metadata as m, re, sys; "
        "from pathlib import Path; "
        "lock = Path('requirements/dev-test.txt').read_text(encoding='utf-8'); "
        "pin = re.search(r'^ruff==([0-9.]+)', lock, re.MULTILINE).group(1); "
        "cur = m.version('ruff'); "
        "sys.exit(0 if cur == pin else f'ruff {cur} does not match locked {pin}')"
    )
    node_floor_check = (
        "const [major, minor] = process.versions.node.split('.').map(Number); "
        "if (major < 22 || (major === 22 && minor < 12)) process.exit(1)"
    )
    return (
        CommandSpec(
            "node_floor",
            ("node", "-e", node_floor_check),
            timeout_seconds=bounded(30),
        ),
        # Source, export, state, and authority policy checks are cheap gates
        # and must reject an invalid candidate before dependency or build work.
        CommandSpec("statespec_schema_validation", (python, "scripts/statedd_validate_schema.py"), timeout_seconds=bounded(180)),
        CommandSpec("repository_validation", (python, "scripts/validate_repo.py"), timeout_seconds=bounded(240)),
        CommandSpec(
            "functionality_preservation_validation",
            (python, "scripts/validate_application_experience.py"),
            timeout_seconds=bounded(180),
        ),
        CommandSpec(
            "python_floor",
            (python, "-c", "import sys; assert sys.version_info >= (3, 13), sys.version"),
            timeout_seconds=bounded(30),
        ),
        CommandSpec(
            "locked_python_env",
            (
                python, "-m", "pip", "install",
                "--disable-pip-version-check",
                "--require-hashes",
                "--dry-run",
                "--quiet",
                "--requirement", "requirements/dev-test.txt",
            ),
            timeout_seconds=bounded(300),
        ),
        CommandSpec(
            "ruff_version_lock",
            (python, "-c", ruff_pin_check),
            timeout_seconds=bounded(30),
        ),
        CommandSpec(
            "ruff_lint",
            (python, "-m", "ruff", "check", "apps", "packages", "scripts"),
            timeout_seconds=bounded(240),
        ),
        CommandSpec(
            "web_dependency_install",
            ("npm", "ci", "--ignore-scripts"),
            cwd="apps/web",
            timeout_seconds=bounded(360),
        ),
        CommandSpec(
            "web_build",
            ("npm", "run", "build"),
            cwd="apps/web",
            timeout_seconds=bounded(240),
        ),
        # The mandatory offline updater wheel proof needs the same locked
        # build wheelhouse the CI workflow materializes; the local path
        # builds it from the hash-locked requirements (never a silent skip).
        CommandSpec(
            "updater_build_wheelhouse",
            (
                python, "-m", "pip", "download",
                "--disable-pip-version-check",
                "--require-hashes",
                "--only-binary=:all:",
                "--dest", wheelhouse,
                "--requirement", "packages/updater/build-requirements.lock",
            ),
            timeout_seconds=bounded(300),
        ),
        CommandSpec(
            "complete_pytest",
            (python, "-m", "pytest", "-q"),
            env=(f"STATEPORT_UPDATER_BUILD_WHEELHOUSE={{repo_root}}/{wheelhouse}",),
            timeout_seconds=bounded(900),
        ),
        CommandSpec(
            "python_compileall",
            (python, "-m", "compileall", "-q", "apps", "packages", "scripts"),
            timeout_seconds=bounded(240),
        ),
        CommandSpec("web_typecheck", ("npm", "run", "typecheck"), cwd="apps/web", timeout_seconds=bounded(180)),
        CommandSpec("web_lint", ("npm", "run", "lint"), cwd="apps/web", timeout_seconds=bounded(180)),
        CommandSpec("web_unit_tests", ("npm", "run", "test"), cwd="apps/web", timeout_seconds=bounded(360)),
        CommandSpec(
            "web_bundle_budget",
            ("npm", "run", "check:bundle"),
            cwd="apps/web",
            timeout_seconds=bounded(120),
        ),
        CommandSpec(
            "web_build_isolation",
            ("npm", "run", "test:build-isolation"),
            cwd="apps/web",
            timeout_seconds=bounded(240),
        ),
        CommandSpec(
            "web_dependency_tree",
            ("npm", "run", "check:dependencies"),
            cwd="apps/web",
            timeout_seconds=bounded(180),
        ),
        CommandSpec(
            "web_dependency_audit",
            ("python3", "../../scripts/validate_web_dependency_audit.py"),
            cwd="apps/web",
            timeout_seconds=bounded(240),
        ),
        CommandSpec(
            "web_mock_browser_acceptance",
            ("npm", "run", "test:e2e", "--", "--workers=1", "--retries=0"),
            cwd="apps/web",
            timeout_seconds=bounded(720),
            env=("CI=1", f"STATEPORT_E2E_PORT={_LOOPBACK_PORT_PLACEHOLDER}"),
            browser_artifacts=True,
        ),
        CommandSpec(
            "live_core_browser_acceptance",
            ("npm", "run", "test:live-core-browser"),
            cwd="apps/web",
            timeout_seconds=bounded(720),
            browser_artifacts=True,
        ),
        CommandSpec(
            "canonical_source_browser_acceptance",
            ("npm", "run", "test:canonical-source-browser"),
            cwd="apps/web",
            timeout_seconds=bounded(720),
            required_environment=(SOURCE_REPOSITORY_ENV,),
            browser_artifacts=True,
        ),
        CommandSpec(
            "repository_gitleaks",
            ("bash", "scripts/gitleaks_scan.sh"),
            timeout_seconds=bounded(360),
        ),
        CommandSpec(
            "installer_syntax",
            ("bash", "-n", "scripts/install.sh"),
            timeout_seconds=bounded(60),
        ),
        CommandSpec(
            "dockerfile_copy_sources",
            (python, "scripts/validate_dockerfile_copy_sources.py"),
            timeout_seconds=bounded(120),
        ),
        CommandSpec(
            "compose_shape",
            (python, "scripts/test_compose_shape.py"),
            timeout_seconds=bounded(180),
        ),
        CommandSpec("git_diff_check", ("git", "diff", "--check"), timeout_seconds=bounded(60)),
        CommandSpec(
            "git_status_porcelain",
            ("git", "status", "--porcelain=v2", "--untracked-files=all"),
            timeout_seconds=bounded(60),
        ),
        CommandSpec("git_object_integrity", ("git", "fsck", "--full"), timeout_seconds=bounded(360)),
    )


def service_journey_commands(max_timeout_seconds: int) -> tuple[CommandSpec, ...]:
    """The heavy release-relevant Compose service journey (explicit opt-in).

    Builds the Compose stack from this checkout, starts the services, waits
    for real health, validates the delivered endpoints, and tears down — the
    local equivalent of the workflow's ``compose-integration`` job.
    """

    return (
        CommandSpec(
            "compose_service_journey",
            ("python3", "scripts/compose_service_journey.py"),
            timeout_seconds=min(1800, max_timeout_seconds),
        ),
    )


def _preflight(
    commands: Sequence[CommandSpec], environment: Mapping[str, str]
) -> list[str]:
    blockers: list[str] = []
    executables = sorted({spec.argv[0] for spec in commands if spec.argv})
    for executable in executables:
        if shutil.which(executable) is None:
            blockers.append(f"required executable unavailable: {executable}")
    required_environment = sorted(
        {name for spec in commands for name in spec.required_environment}
    )
    for name in required_environment:
        if not environment.get(name):
            blockers.append(f"required environment variable unavailable: {name}")
    if any(spec.label == "repository_gitleaks" for spec in commands):
        if not any(shutil.which(name) for name in ("gitleaks", "podman", "docker")):
            blockers.append("gitleaks requires gitleaks, podman, or docker")
    return blockers


def _version(
    argv: Sequence[str],
    cwd: Path,
    redactions: Sequence[tuple[str, str]],
    environment: Mapping[str, str],
) -> str:
    try:
        completed = subprocess.run(
            list(argv), cwd=cwd, env=dict(environment), check=False, capture_output=True, text=True, timeout=30
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"
    output = (completed.stdout or completed.stderr).strip().splitlines()
    if completed.returncode or not output:
        return "unavailable"
    return sanitize_text(output[0], redactions)[:240]


def _tool_versions(
    repo_root: Path,
    redactions: Sequence[tuple[str, str]],
    environment: Mapping[str, str],
) -> dict[str, str]:
    versions = {
        "python": _version(("python3", "--version"), repo_root, redactions, environment),
        "pytest": _version(("python3", "-m", "pytest", "--version"), repo_root, redactions, environment),
        "git": _version(("git", "--version"), repo_root, redactions, environment),
        "node": _version(("node", "--version"), repo_root, redactions, environment),
        "npm": _version(("npm", "--version"), repo_root, redactions, environment),
    }
    web_root = repo_root / "apps" / "web"
    playwright = web_root / "node_modules" / ".bin" / "playwright"
    versions["playwright"] = _version((str(playwright), "--version"), web_root, redactions, environment) if playwright.is_file() else "unavailable"
    if shutil.which("gitleaks"):
        versions["gitleaks"] = _version(("gitleaks", "version"), repo_root, redactions, environment)
    elif shutil.which("podman"):
        versions["gitleaksRunner"] = _version(("podman", "--version"), repo_root, redactions, environment)
        versions["gitleaksImage"] = "zricethezav/gitleaks:v8.24.2"
    elif shutil.which("docker"):
        versions["gitleaksRunner"] = _version(("docker", "--version"), repo_root, redactions, environment)
        versions["gitleaksImage"] = "zricethezav/gitleaks:v8.24.2"
    else:
        versions["gitleaks"] = "unavailable"
    return versions


def _terminate(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def _select_loopback_port() -> int:
    """Select an ephemeral IPv4 loopback port without consulting host services."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        address = probe.getsockname()
    port = int(address[1])
    if not 1024 <= port <= 65535:
        raise RuntimeError("operating system returned an invalid loopback port")
    return port


def _loopback_port_available(port: int) -> bool:
    """Return whether a port is free for the browser server on loopback."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def _container_detected(environment: Mapping[str, str]) -> bool:
    return bool(
        environment.get("container")
        or Path("/.dockerenv").is_file()
        or Path("/run/.containerenv").is_file()
    )


def _sanitize_browser_artifacts(
    root: Path,
    redactions: Sequence[tuple[str, str]],
    *,
    artifact_prefix: str,
) -> dict[str, object]:
    """Sanitize text artifacts, hash screenshots, and discard raw traces."""

    if not root.is_dir():
        return {"files": [], "removedUnsafeArtifacts": []}
    text_suffixes = {".json", ".jsonl", ".log", ".md", ".txt", ".xml"}
    image_suffixes = {".jpg", ".jpeg", ".png", ".webp"}
    files: list[dict[str, str]] = []
    removed: list[str] = []
    for path in sorted(root.rglob("*")):
        if path.is_dir():
            continue
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            path.unlink()
            removed.append(relative)
            continue
        suffix = path.suffix.lower()
        if suffix in text_suffixes:
            content = path.read_text(encoding="utf-8", errors="replace")
            path.write_text(sanitize_text(content, redactions), encoding="utf-8")
            path.chmod(0o600)
        elif suffix not in image_suffixes:
            path.unlink()
            removed.append(relative)
            continue
        files.append({"path": f"{artifact_prefix}/{relative}", "sha256": _sha256(path)})
    return {"files": files, "removedUnsafeArtifacts": removed}


def _run_command(
    spec: CommandSpec,
    *,
    repo_root: Path,
    output_dir: Path,
    environment: Mapping[str, str],
    redactions: Sequence[tuple[str, str]],
) -> dict[str, object]:
    cwd = (repo_root / spec.cwd).resolve()
    if not cwd.is_relative_to(repo_root.resolve()) or not cwd.is_dir():
        raise RuntimeError(f"unsafe or missing command cwd for {spec.label}")
    command_environment = dict(environment)
    for assignment in spec.env:
        key, separator, value = assignment.partition("=")
        if not separator:
            raise RuntimeError(f"unsafe env assignment for {spec.label}: {assignment!r}")
        if value == _LOOPBACK_PORT_PLACEHOLDER:
            value = str(_select_loopback_port())
        command_environment[key] = value.replace("{repo_root}", str(repo_root.resolve()))
    browser_root = output_dir / "browser" / spec.label
    if spec.browser_artifacts:
        command_environment["STATEPORT_BROWSER_ARTIFACT_ROOT"] = str(browser_root)
    started_at = _utc_now()
    started = time.monotonic()
    timed_out = False
    browser_port = command_environment.get("STATEPORT_E2E_PORT") if spec.browser_artifacts else None
    if browser_port is not None:
        try:
            parsed_port = int(browser_port)
        except ValueError as exc:
            raise RuntimeError(f"browser acceptance port is not an integer: {browser_port!r}") from exc
        if not 1024 <= parsed_port <= 65535:
            raise RuntimeError(f"browser acceptance port is outside the valid range: {parsed_port}")
        if not _loopback_port_available(parsed_port):
            message = f"browser acceptance refused occupied loopback port {parsed_port}; unrelated server not reused"
            log_path = output_dir / "logs" / f"{spec.label}.log"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.parent.chmod(0o700)
            log_path.write_text(message + "\n", encoding="utf-8")
            log_path.chmod(0o600)
            return {
                "label": spec.label,
                "argv": [sanitize_text(value, redactions) for value in spec.argv],
                "cwd": "[REPO]" if spec.cwd == "." else f"[REPO]/{spec.cwd}",
                "timeoutSeconds": spec.timeout_seconds,
                "startedAt": started_at,
                "durationSeconds": round(time.monotonic() - started, 3),
                "exitCode": None,
                "timedOut": False,
                "passed": False,
                "error": message,
                "log": {"path": f"logs/{log_path.name}", "sha256": _sha256(log_path)},
            }
    process = subprocess.Popen(
        list(spec.argv),
        cwd=cwd,
        env=command_environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    try:
        stdout, _ = process.communicate(timeout=spec.timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        partial = exc.output or b""
        _terminate(process)
        remainder = process.stdout.read() if process.stdout is not None else b""
        stdout = partial + remainder
    except BaseException:
        _terminate(process)
        raise
    duration = time.monotonic() - started
    decoded = stdout.decode("utf-8", errors="replace")
    sanitized = sanitize_text(decoded, redactions)
    log_path = output_dir / "logs" / f"{spec.label}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.parent.chmod(0o700)
    log_path.write_text(sanitized, encoding="utf-8")
    log_path.chmod(0o600)
    exit_code = process.returncode
    passed = exit_code == 0 and not timed_out
    result: dict[str, object] = {
        "label": spec.label,
        "argv": [sanitize_text(value, redactions) for value in spec.argv],
        "cwd": "[REPO]" if spec.cwd == "." else f"[REPO]/{spec.cwd}",
        "timeoutSeconds": spec.timeout_seconds,
        "startedAt": started_at,
        "durationSeconds": round(duration, 3),
        "exitCode": exit_code,
        "timedOut": timed_out,
        "passed": passed,
        "log": {
            "path": f"logs/{log_path.name}",
            "sha256": _sha256(log_path),
        },
    }
    if spec.browser_artifacts:
        result["artifacts"] = _sanitize_browser_artifacts(
            browser_root,
            redactions,
            artifact_prefix=f"browser/{spec.label}",
        )
    return result


def _summary_path(output_dir: Path) -> Path:
    return output_dir / "local_closure_gate.json"


def _write_summary(output_dir: Path, summary: Mapping[str, object]) -> None:
    path = _summary_path(output_dir)
    path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    path.chmod(0o600)


def _expected_repository(repo_root: Path) -> str:
    """Derive the expected ``nameWithOwner`` from the origin remote."""

    url = _git(repo_root, "config", "--get", "remote.origin.url")
    match = re.search(r"github\.com[:/]([^/]+/[^/]+?)(?:\.git)?$", url)
    if not match:
        raise RuntimeError("origin remote is not a parseable GitHub URL")
    return match.group(1)


def run_gate(
    *,
    repo_root: Path,
    output_dir: Path,
    environment_label: str,
    commands: Sequence[CommandSpec] | None = None,
    environment: Mapping[str, str] | None = None,
    max_timeout_seconds: int = 900,
    dry_run: bool = False,
    workspace_state_root: Path | None = None,
    remote: bool = False,
    remote_dispatch: bool = False,
    remote_timeout_seconds: int = REMOTE_DEFAULT_TIMEOUT_SECONDS,
    remote_poll_interval_seconds: int = REMOTE_DEFAULT_POLL_INTERVAL_SECONDS,
    remote_client: RemoteCIClient | None = None,
    remote_repository: str | None = None,
    include_service_journey: bool = False,
) -> dict[str, object]:
    """Run the closure plan. ``commands`` is injectable for bounded unit tests.

    The local plan is authoritative and always executes: remote evidence never
    skips local preflight, workspace, command, or cleanliness checks.
    ``remote=True`` observes an existing binding-validated run for the exact
    HEAD as supplemental evidence (never dispatches).  ``remote_dispatch=True``
    is the separate explicit owner-gated dispatch operation (clean worktree,
    HEAD == remote ``main`` head).  ``remote_client`` and
    ``remote_repository`` are injectable for tests that mock the ``gh``/API
    boundary; the CLI derives the repository from the origin remote.
    """

    repo_root = repo_root.resolve()
    output_dir = output_dir.resolve()
    if environment_label not in ENVIRONMENT_LABELS:
        raise ValueError(f"invalid environment label: {environment_label}")
    if not 1 <= remote_timeout_seconds <= REMOTE_MAX_TIMEOUT_SECONDS:
        raise ValueError(
            f"remote timeout must be within 1..{REMOTE_MAX_TIMEOUT_SECONDS} seconds"
        )
    if remote_poll_interval_seconds < REMOTE_MIN_POLL_INTERVAL_SECONDS:
        raise ValueError(
            f"remote poll interval must be at least {REMOTE_MIN_POLL_INTERVAL_SECONDS} seconds"
        )
    if output_dir == repo_root or output_dir.is_relative_to(repo_root):
        raise ValueError("output directory must be outside the repository")
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError("output directory must be absent or empty")
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    output_dir.chmod(0o700)
    command_plan = tuple(commands) if commands is not None else default_commands(max_timeout_seconds)
    if include_service_journey:
        command_plan = command_plan + service_journey_commands(max_timeout_seconds)
    if not command_plan or any(not item.argv for item in command_plan):
        raise ValueError("closure command plan must contain argv-only commands")
    labels = [item.label for item in command_plan]
    if len(labels) != len(set(labels)):
        raise ValueError("closure command labels must be unique")
    if any(not _SAFE_COMMAND_LABEL.fullmatch(label) for label in labels):
        raise ValueError(
            "closure command labels may contain only letters, digits, dots, dashes, and underscores"
        )
    source_environment = dict(os.environ if environment is None else environment)
    redactions = _redaction_values(repo_root, output_dir, source_environment)
    process_environment = _execution_environment(source_environment)
    started_at = _utc_now()
    started = time.monotonic()
    commit = _git(repo_root, "rev-parse", "HEAD")
    tree = _git(repo_root, "rev-parse", "HEAD^{tree}")
    status_before = _git(repo_root, "status", "--porcelain=v2", "--untracked-files=all")
    clean_before = status_before == ""

    remote_attempt: RemoteAttempt | None = None
    if (remote or remote_dispatch) and not dry_run:
        client = remote_client if remote_client is not None else GhRemoteCIClient(repo_root)
        repository = remote_repository
        if repository is None:
            try:
                repository = _expected_repository(repo_root)
            except RuntimeError:
                repository = None
        if repository is None:
            remote_attempt = RemoteAttempt(
                True, "unavailable", "repository_unresolvable", None, None, None, 0.0
            )
        elif remote_dispatch:
            remote_attempt = dispatch_remote_ci(
                client=client,
                commit=commit,
                repository=repository,
                clean=clean_before,
                timeout_seconds=remote_timeout_seconds,
                poll_interval_seconds=remote_poll_interval_seconds,
            )
        else:
            remote_attempt = observe_remote_ci(
                client=client,
                commit=commit,
                repository=repository,
            )
    remote_verified = remote_attempt is not None and remote_attempt.outcome == "verified"
    remote_failed = remote_attempt is not None and remote_attempt.outcome == "failed"

    # Local evidence is authoritative: preflight, workspace closure,
    # cleanliness, and the command plan run regardless of any remote result.
    blockers = _preflight(command_plan, process_environment)
    workspace_lifecycle: dict[str, object]
    try:
        workspace_lifecycle = WorkspaceLifecycleManager(
            repo_root,
            state_root=workspace_state_root,
        ).assert_repository_closed()
    except (OSError, WorkspaceLifecycleError) as exc:
        code = exc.code if isinstance(exc, WorkspaceLifecycleError) else "inventory_unknown"
        workspace_lifecycle = {"ok": False, "code": code, "detail": str(exc)}
        blockers.append(f"workspace lifecycle closure failed: {code}")
    container_detected = _container_detected(process_environment)
    if environment_label == "container" and not container_detected:
        blockers.append("container environment label was not corroborated by the execution environment")
    if not clean_before:
        blockers.append("Git worktree was not clean before the gate")

    records: list[dict[str, object]] = []
    if dry_run:
        blockers.append("dry run does not execute or validate closure commands")
    elif not blockers:
        for spec in command_plan:
            records.append(
                _run_command(
                    spec,
                    repo_root=repo_root,
                    output_dir=output_dir,
                    environment=process_environment,
                    redactions=redactions,
                )
            )

    status_after = _git(repo_root, "status", "--porcelain=v2", "--untracked-files=all")
    clean_after = status_after == ""
    if not clean_after:
        blockers.append("Git worktree was not clean after the gate")
    if remote_failed:
        blockers.append(f"remote CI run concluded {remote_attempt.conclusion}")
    failed_labels = [str(item["label"]) for item in records if not item["passed"]]
    blockers.extend(f"command failed: {label}" for label in failed_labels)
    tool_versions = _tool_versions(repo_root, redactions, process_environment)
    if commands is None:
        required_versions = ("python", "pytest", "git", "node", "npm", "playwright")
        blockers.extend(
            f"required tool version unavailable: {name}"
            for name in required_versions
            if tool_versions.get(name) == "unavailable"
        )
    completed_at = _utc_now()
    duration_seconds = round(time.monotonic() - started, 3)
    evidence_source = "local"
    passed = (
        not dry_run
        and not blockers
        and len(records) == len(command_plan)
        and all(bool(item["passed"]) for item in records)
        and clean_before
        and clean_after
    )
    required_environment = sorted(
        {name for spec in command_plan for name in spec.required_environment}
    )
    local_part = (
        "locally_closure_validated_from_this_checkout"
        if passed
        else "local_closure_failed_or_not_run"
    )
    if remote_verified:
        suffix = "supplemental_remote_CI_verified_for_exact_committed_HEAD"
        if not clean_before:
            suffix += "; uncommitted_worktree_changes_not_covered_by_remote_evidence"
        remote_statement = (
            "Remote CI evidence for the exact committed HEAD was observed and "
            "binding-validated; it is supplemental only and did not replace any "
            "local check."
        )
    elif remote_failed:
        suffix = f"remote_CI_concluded_{remote_attempt.conclusion}; gate_failed"
        remote_statement = (
            "Remote CI ran for the exact HEAD commit and did not succeed; the gate fails."
        )
    elif remote_attempt is not None:
        suffix = f"remote_CI_unavailable:{remote_attempt.reason}; not_remotely_CI_verified"
        remote_statement = (
            f"Remote CI was attempted but unavailable ({remote_attempt.reason}); "
            "this record is local closure evidence, not remote CI."
        )
    else:
        suffix = "remote_CI_not_run; not_remotely_CI_verified"
        remote_statement = "This record is local closure evidence, not remote CI."
    classification = f"{local_part}; {suffix}"
    remote_block: dict[str, object] = {
        "included": remote_verified or remote_failed,
        "supplementalOnly": True,
        "attempted": remote_attempt is not None,
        "verified": remote_verified,
        "statement": remote_statement,
    }
    if remote_attempt is not None:
        remote_block.update(
            {
                "workflow": REMOTE_WORKFLOW_FILE,
                "outcome": remote_attempt.outcome,
                "fallbackReason": remote_attempt.reason,
                "dispatched": remote_attempt.dispatched,
                "runId": remote_attempt.run_id,
                "conclusion": remote_attempt.conclusion,
                "url": remote_attempt.url,
                "durationSeconds": remote_attempt.duration_seconds,
            }
        )
        if remote_attempt.run is not None:
            run = remote_attempt.run
            remote_block["binding"] = {
                "repository": run.repository,
                "workflow": run.workflow,
                "event": run.event,
                "headBranch": run.head_branch,
                "headSha": run.head_sha,
                "createdAt": run.created_at,
                "jobs": [
                    {"name": job.name, "conclusion": job.conclusion, "labels": list(job.labels)}
                    for job in remote_attempt.jobs
                ],
            }
    summary: dict[str, object] = {
        "formatVersion": FORMAT_VERSION,
        "classification": classification,
        "evidenceSource": evidence_source,
        "environmentLabel": environment_label,
        "environmentIdentity": {
            "hostname": sanitize_text(socket.gethostname(), redactions),
            "os": f"{platform.system()} {platform.release()}",
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "executionContext": {"containerDetected": container_detected},
        "startedAt": started_at,
        "completedAt": completed_at,
        "durationSeconds": duration_seconds,
        "repository": {
            "commit": commit,
            "tree": tree,
            "cleanBefore": clean_before,
            "cleanAfter": clean_after,
        },
        "workspaceLifecycle": workspace_lifecycle,
        "requiredEnvironment": {name: "present" if process_environment.get(name) else "missing" for name in required_environment},
        "toolVersions": tool_versions,
        "commands": records,
        "plannedCommands": [item.label for item in command_plan],
        "maxCommandTimeoutSeconds": max_timeout_seconds,
        "passed": passed,
        "blockers": sorted(set(blockers)),
        "remoteCI": remote_block,
        "privacy": {
            "environmentValuesRecorded": False,
            "sensitiveEnvironmentPassedToCommands": False,
            "credentialsRecorded": False,
            "rawTelegramContentRecorded": False,
            "rawTerminalContentRecorded": False,
        },
    }
    _write_summary(output_dir, summary)
    return summary


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment-label", required=True, choices=ENVIRONMENT_LABELS)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument(
        "--max-command-timeout-seconds",
        type=int,
        default=900,
        help="Upper bound applied to every command timeout (default: 900)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Write a fail-closed plan record without executing commands",
    )
    parser.add_argument(
        "--remote",
        action="store_true",
        help=(
            "Observe supplemental remote CI evidence (GitHub Actions via gh): "
            "an existing binding-validated run for the exact HEAD. Observation "
            "only — never dispatches and never replaces local checks."
        ),
    )
    parser.add_argument(
        "--remote-dispatch",
        action="store_true",
        help=(
            "Explicit owner-gated remote dispatch: dispatch the validation "
            "workflow and wait for the binding-validated result. Requires a "
            "clean worktree and HEAD exactly equal to the remote main head. "
            "Never happens automatically."
        ),
    )
    parser.add_argument(
        "--include-service-journey",
        action="store_true",
        help=(
            "Append the heavy Compose service journey (build, start, health, "
            "endpoint validation, teardown) to the local plan."
        ),
    )
    parser.add_argument(
        "--remote-timeout-seconds",
        type=int,
        default=REMOTE_DEFAULT_TIMEOUT_SECONDS,
        help=(
            "Upper bound for waiting on a remote CI result "
            f"(default: {REMOTE_DEFAULT_TIMEOUT_SECONDS}, max: {REMOTE_MAX_TIMEOUT_SECONDS})"
        ),
    )
    parser.add_argument(
        "--remote-poll-interval-seconds",
        type=int,
        default=REMOTE_DEFAULT_POLL_INTERVAL_SECONDS,
        help=f"Polling interval while waiting on remote CI (default: {REMOTE_DEFAULT_POLL_INTERVAL_SECONDS})",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.max_command_timeout_seconds < 1:
        raise SystemExit("--max-command-timeout-seconds must be positive")
    try:
        summary = run_gate(
            repo_root=ROOT,
            output_dir=args.output_dir,
            environment_label=args.environment_label,
            max_timeout_seconds=args.max_command_timeout_seconds,
            dry_run=args.dry_run,
            remote=args.remote,
            remote_dispatch=args.remote_dispatch,
            remote_timeout_seconds=args.remote_timeout_seconds,
            remote_poll_interval_seconds=args.remote_poll_interval_seconds,
            include_service_journey=args.include_service_journey,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"local closure gate could not start: {exc}", file=sys.stderr)
        return 2
    print("local closure summary: [OUTPUT]/local_closure_gate.json")
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
