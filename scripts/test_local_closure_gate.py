#!/usr/bin/env python3
"""Focused tests for the local closure and human-ready evidence gates."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

from build_human_ready_gate import (  # noqa: E402
    REQUIRED_CHECKS,
    HumanReadyGateError,
    assemble_human_ready_gate,
)
from local_closure_gate import (  # noqa: E402
    REMOTE_REQUIRED_JOBS,
    CommandSpec,
    GhRemoteCIError,
    RemoteJob,
    RemoteQuotaExhausted,
    RemoteRun,
    _loopback_port_available,
    _run_command,
    default_commands,
    run_gate,
    service_journey_commands,
)


COMMIT = "a" * 40
TREE = "b" * 40
DIGEST = "c" * 64


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Closure Test"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "closure@example.invalid"], check=True)
    (repo / "README.md").write_text("fixture\n", encoding="utf-8")
    config = repo / "config"
    config.mkdir()
    (config / "workspace-lifecycle.v1.yaml").write_text(
        (ROOT / "config" / "workspace-lifecycle.v1.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(repo), "add", "README.md", "config/workspace-lifecycle.v1.yaml"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "fixture"], check=True)
    return repo


def test_injected_tiny_gate_passes_and_sanitizes_logs(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    output = tmp_path / "evidence"
    source = tmp_path / "public-source"
    secret = "SENTINEL_" + "CLOSURE_" + "VALUE_987654321"
    code = (
        "import os; from pathlib import Path; "
        "artifacts=Path(os.environ['STATEPORT_BROWSER_ARTIFACT_ROOT']); "
        "artifacts.mkdir(parents=True); "
        f"(artifacts/'results.json').write_text(os.getcwd() + {secret!r}); "
        "(artifacts/'trace.zip').write_bytes(b'raw trace'); "
        "(artifacts/'screen.png').write_bytes(b'public-safe image'); "
        "print(os.getcwd()); "
        "print(os.environ['STATEPORT_BROWSER_STUDYDD_REPOSITORY']); "
        f"print('token=' + {secret!r}); "
        "print('test-token-env=' + str('TEST_TOKEN' in os.environ))"
    )
    environment = dict(os.environ)
    environment.update({"STATEPORT_BROWSER_STUDYDD_REPOSITORY": str(source), "TEST_TOKEN": secret})
    summary = run_gate(
        repo_root=repo,
        output_dir=output,
        environment_label="fresh",
        commands=(
            CommandSpec(
                "tiny",
                (sys.executable, "-c", code),
                timeout_seconds=10,
                required_environment=("STATEPORT_BROWSER_STUDYDD_REPOSITORY",),
                browser_artifacts=True,
            ),
        ),
        environment=environment,
        workspace_state_root=tmp_path / "workspace-state",
    )
    assert summary["passed"] is True
    record = summary["commands"][0]
    log = (output / record["log"]["path"]).read_text(encoding="utf-8")
    assert str(repo) not in log and str(source) not in log and secret not in log
    assert "[REPO]" in log and "[SOURCE_REPOSITORY]" in log and "[REDACTED]" in log
    assert "test-token-env=False" in log
    assert hashlib.sha256(log.encode()).hexdigest() == record["log"]["sha256"]
    results = (output / "browser" / "tiny" / "results.json").read_text(encoding="utf-8")
    assert str(repo) not in results and secret not in results
    assert not (output / "browser" / "tiny" / "trace.zip").exists()
    assert record["artifacts"]["removedUnsafeArtifacts"] == ["trace.zip"]
    assert {item["path"] for item in record["artifacts"]["files"]} == {
        "browser/tiny/results.json", "browser/tiny/screen.png",
    }
    stored = json.loads((output / "local_closure_gate.json").read_text(encoding="utf-8"))
    assert stored["remoteCI"]["verified"] is False
    assert stored["privacy"]["environmentValuesRecorded"] is False
    assert stored["privacy"]["sensitiveEnvironmentPassedToCommands"] is False


def test_gate_fails_closed_for_missing_environment_without_running(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    summary = run_gate(
        repo_root=repo,
        output_dir=tmp_path / "evidence",
        environment_label="active",
        commands=(CommandSpec("never", (sys.executable, "-c", "raise SystemExit(99)"), required_environment=("MISSING_GATE_VALUE",)),),
        environment={"PATH": os.environ["PATH"]},
        workspace_state_root=tmp_path / "workspace-state",
    )
    assert summary["passed"] is False
    assert summary["commands"] == []
    assert summary["requiredEnvironment"] == {"MISSING_GATE_VALUE": "missing"}
    assert "required environment variable unavailable: MISSING_GATE_VALUE" in summary["blockers"]


def test_gate_rejects_command_labels_that_could_escape_evidence_paths(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    with pytest.raises(ValueError, match="command labels"):
        run_gate(
            repo_root=repo,
            output_dir=tmp_path / "evidence",
            environment_label="active",
            commands=(
                CommandSpec(
                    "../escape",
                    (sys.executable, "-c", "raise SystemExit(99)"),
                    browser_artifacts=True,
                ),
            ),
            workspace_state_root=tmp_path / "workspace-state",
        )


def test_authoritative_plan_covers_every_local_closure_boundary() -> None:
    commands = default_commands(75)
    labels = {item.label for item in commands}
    assert labels == {
        "python_floor",
        "locked_python_env",
        "ruff_version_lock",
        "ruff_lint",
        "updater_build_wheelhouse",
        "complete_pytest",
        "statespec_schema_validation",
        "repository_validation",
        "python_compileall",
        "functionality_preservation_validation",
        "node_floor",
        "web_dependency_install",
        "web_typecheck",
        "web_lint",
        "web_unit_tests",
        "web_build",
        "web_bundle_budget",
        "web_build_isolation",
        "web_dependency_tree",
        "web_dependency_audit",
        "web_mock_browser_acceptance",
        "live_core_browser_acceptance",
        "canonical_source_browser_acceptance",
        "repository_gitleaks",
        "installer_syntax",
        "dockerfile_copy_sources",
        "compose_shape",
        "git_diff_check",
        "git_status_porcelain",
        "git_object_integrity",
    }
    assert all(item.timeout_seconds <= 75 for item in commands)
    vitest_config = (ROOT / "apps" / "web" / "vitest.config.ts").read_text(
        encoding="utf-8"
    )
    assert all(
        invariant in vitest_config
        for invariant in (
            "Math.max(1, Math.min(2, availableParallelism()))",
            "pool: 'forks'",
            "isolate: true",
            "maxWorkers,",
            "maxConcurrency: 2",
            "bail: 1",
        )
    )
    playwright_config = (ROOT / "apps" / "web" / "playwright.config.ts").read_text(
        encoding="utf-8"
    )
    assert "Math.max(1, Math.min(2, availableParallelism()))" in playwright_config
    assert "workers: maxWorkers" in playwright_config
    journey = service_journey_commands(1800)
    assert [item.label for item in journey] == ["compose_service_journey"]
    browser = next(item for item in commands if item.label == "canonical_source_browser_acceptance")
    assert browser.required_environment == ("STATEPORT_BROWSER_STUDYDD_REPOSITORY",)
    assert browser.browser_artifacts is True
    assert next(
        item for item in commands if item.label == "live_core_browser_acceptance"
    ).browser_artifacts is True
    mock_browser = next(
        item for item in commands if item.label == "web_mock_browser_acceptance"
    )
    assert mock_browser.argv == (
        "npm",
        "run",
        "test:e2e",
        "--",
        "--workers=1",
        "--retries=0",
    )
    assert mock_browser.env == ("CI=1", "STATEPORT_E2E_PORT={loopback_port}")
    assert "reuseExistingServer: false" in playwright_config
    assert "--strictPort" in playwright_config


def test_authoritative_plan_orders_web_and_wheelhouse_prerequisites() -> None:
    commands = default_commands(75)
    positions = {item.label: index for index, item in enumerate(commands)}

    assert [
        label
        for label in (
            "node_floor",
            "statespec_schema_validation",
            "repository_validation",
            "functionality_preservation_validation",
            "python_floor",
            "locked_python_env",
            "web_dependency_install",
            "web_build",
            "updater_build_wheelhouse",
            "complete_pytest",
        )
    ] == sorted(
        (
            "node_floor",
            "statespec_schema_validation",
            "repository_validation",
            "functionality_preservation_validation",
            "python_floor",
            "locked_python_env",
            "web_dependency_install",
            "web_build",
            "updater_build_wheelhouse",
            "complete_pytest",
        ),
        key=positions.__getitem__,
    )
    complete_pytest = next(item for item in commands if item.label == "complete_pytest")
    assert complete_pytest.env == (
        "STATEPORT_UPDATER_BUILD_WHEELHOUSE={repo_root}/.stateport-local/updater-build-wheelhouse",
    )


def test_browser_command_refuses_an_occupied_stale_server_port(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    output = tmp_path / "evidence"
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen()
    port = int(server.getsockname()[1])
    try:
        assert _loopback_port_available(port) is False
        result = _run_command(
            CommandSpec(
                "browser",
                (sys.executable, "-c", "raise SystemExit(99)"),
                env=(f"STATEPORT_E2E_PORT={port}",),
                browser_artifacts=True,
            ),
            repo_root=repo,
            output_dir=output,
            environment={"PATH": os.environ["PATH"]},
            redactions=(),
        )
    finally:
        server.close()
    assert result["passed"] is False
    assert result["exitCode"] is None
    assert "unrelated server not reused" in result["error"]
    assert "unrelated server not reused" in (output / "logs" / "browser.log").read_text()


def test_mock_browser_suite_honors_the_isolated_evidence_root() -> None:
    config = (ROOT / "apps" / "web" / "playwright.config.ts").read_text(
        encoding="utf-8"
    )
    screenshots = (
        ROOT / "apps" / "web" / "tests" / "e2e" / "screenshots.spec.ts"
    ).read_text(encoding="utf-8")
    assert "STATEPORT_BROWSER_ARTIFACT_ROOT" in config
    assert "path.join(artifactRoot, 'test-results')" in config
    assert "path.join(artifactRoot, 'results.json')" in config
    assert "STATEPORT_BROWSER_ARTIFACT_ROOT" in screenshots
    assert "'screenshots'" in screenshots


def test_gate_records_failure_timeout_and_dirty_worktree(tmp_path: Path) -> None:
    failure_repo = _repo(tmp_path / "failure")
    failed = run_gate(
        repo_root=failure_repo,
        output_dir=tmp_path / "failure-evidence",
        environment_label="active",
        commands=(CommandSpec("failure", (sys.executable, "-c", "raise SystemExit(7)"), timeout_seconds=10),),
        workspace_state_root=tmp_path / "failure-workspace-state",
    )
    assert failed["passed"] is False
    assert failed["commands"][0]["exitCode"] == 7

    timeout_repo = _repo(tmp_path / "timeout")
    timed = run_gate(
        repo_root=timeout_repo,
        output_dir=tmp_path / "timeout-evidence",
        environment_label="fresh",
        commands=(CommandSpec("timeout", (sys.executable, "-c", "import time; time.sleep(5)"), timeout_seconds=1),),
        workspace_state_root=tmp_path / "timeout-workspace-state",
    )
    assert timed["commands"][0]["timedOut"] is True
    assert timed["passed"] is False

    dirty_repo = _repo(tmp_path / "dirty")
    (dirty_repo / "dirty.txt").write_text("dirty\n", encoding="utf-8")
    dirty = run_gate(
        repo_root=dirty_repo,
        output_dir=tmp_path / "dirty-evidence",
        environment_label="active",
        commands=(CommandSpec("never", (sys.executable, "-c", "raise SystemExit(99)")),),
        workspace_state_root=tmp_path / "dirty-workspace-state",
    )
    assert dirty["commands"] == []
    assert dirty["repository"]["cleanBefore"] is False
    assert "Git worktree was not clean before the gate" in dirty["blockers"]


def _evidence() -> dict[str, object]:
    return {
        "functionalCommit": COMMIT,
        "functionalTree": TREE,
        "checks": {
            name: {
                "passed": True,
                "evidence": [{"artifact": f"validation/{name}.json", "sha256": DIGEST}],
            }
            for name in REQUIRED_CHECKS
        },
    }


def test_human_ready_gate_defaults_missing_checks_to_false() -> None:
    gate = assemble_human_ready_gate(
        {"functionalCommit": COMMIT, "functionalTree": TREE},
        generated_at="2026-07-15T00:00:00Z",
    )
    assert gate["readyForHumanAcceptance"] is False
    assert gate["humanSession"]["permitted"] is False
    assert gate["blockers"] == list(REQUIRED_CHECKS)
    assert all(not value["passed"] for value in gate["checks"].values())


def test_human_ready_gate_requires_hashed_evidence_and_all_checks() -> None:
    evidence = _evidence()
    gate = assemble_human_ready_gate(evidence, generated_at="2026-07-15T00:00:00Z")
    assert gate["readyForHumanAcceptance"] is True
    assert gate["humanSession"] == {
        "permitted": True,
        "maximumMinutes": 20,
        "scope": "subjective clarity, control, trust, and acceptance only",
    }
    evidence["checks"]["fullSuitePassed"] = {"passed": True, "evidence": []}
    with pytest.raises(HumanReadyGateError, match="cannot pass without hashed evidence"):
        assemble_human_ready_gate(evidence)


@pytest.mark.parametrize("artifact", ["/absolute.json", "../escape.json", "a/../../escape.json", "a\\b.json"])
def test_human_ready_gate_rejects_unsafe_evidence_paths(artifact: str) -> None:
    evidence = _evidence()
    evidence["checks"]["fullSuitePassed"]["evidence"][0]["artifact"] = artifact
    with pytest.raises(HumanReadyGateError, match="artifact"):
        assemble_human_ready_gate(evidence)


REMOTE_REPO = "lennertvhoy/StatePort"
FRESH_RUN_AT = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
STALE_RUN_AT = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat().replace("+00:00", "Z")


def _jobs(
    *,
    conclusion: str = "success",
    labels: tuple[str, ...] = ("self-hosted", "linux", "x64", "stateport"),
    names: tuple[str, ...] = REMOTE_REQUIRED_JOBS,
) -> tuple[RemoteJob, ...]:
    return tuple(RemoteJob(name=name, conclusion=conclusion, labels=labels) for name in names)


def _remote_run(commit: str, run_id: int = 42, conclusion: str = "success", **over: object) -> RemoteRun:
    fields: dict[str, object] = {
        "run_id": run_id,
        "conclusion": conclusion,
        "url": f"https://example.invalid/runs/{run_id}",
        "repository": REMOTE_REPO,
        "workflow": "validate.yml",
        "event": "workflow_dispatch",
        "head_branch": "main",
        "head_sha": commit,
        "created_at": FRESH_RUN_AT,
    }
    fields.update(over)
    return RemoteRun(**fields)  # type: ignore[arg-type]


class FakeRemoteClient:
    """Scriptable fake for the gh/API boundary; performs no network access."""

    def __init__(
        self,
        *,
        available: bool = True,
        repository: str = REMOTE_REPO,
        workflow_enabled: bool = True,
        runner_online: bool = True,
        completed_run: RemoteRun | None = None,
        jobs: tuple[RemoteJob, ...] | None = None,
        main_head: str | None = None,
        probe_error: Exception | None = None,
        dispatch_error: Exception | None = None,
        wait_result: RemoteRun | None = None,
        wait_jobs: tuple[RemoteJob, ...] | None = None,
        wait_error: Exception | None = None,
    ) -> None:
        self._available = available
        self._repository = repository
        self._workflow_enabled = workflow_enabled
        self._runner_online = runner_online
        self._completed_run = completed_run
        self._jobs = jobs
        self._main_head = main_head
        self._probe_error = probe_error
        self._dispatch_error = dispatch_error
        self._wait_result = wait_result
        self._wait_jobs = wait_jobs
        self._wait_error = wait_error
        self.dispatched: list[str] = []

    def gh_available(self) -> bool:
        return self._available

    def repository(self) -> str:
        return self._repository

    def _probe(self) -> None:
        if self._probe_error is not None:
            raise self._probe_error

    def workflow_enabled(self) -> bool:
        self._probe()
        return self._workflow_enabled

    def runner_online(self) -> bool:
        self._probe()
        return self._runner_online

    def find_completed_run(self, commit: str) -> RemoteRun | None:
        self._probe()
        return self._completed_run

    def run_jobs(self, run_id: int) -> tuple[RemoteJob, ...]:
        self._probe()
        if self._wait_result is not None and self._wait_result.run_id == run_id:
            if self._wait_jobs is not None:
                return self._wait_jobs
        if self._jobs is not None:
            return self._jobs
        return _jobs()

    def remote_main_head(self) -> str:
        self._probe()
        assert self._main_head is not None
        return self._main_head

    def dispatch(self, ref: str) -> None:
        if self._dispatch_error is not None:
            raise self._dispatch_error
        self.dispatched.append(ref)

    def wait_for_run(
        self, commit: str, *, timeout_seconds: int, poll_interval_seconds: int
    ) -> RemoteRun | None:
        if self._wait_error is not None:
            raise self._wait_error
        return self._wait_result


def _head(repo: Path) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
    ).strip()


def _remote_gate(
    tmp_path: Path,
    client: FakeRemoteClient | None = None,
    *,
    client_factory: object = None,
    exit_code: int = 0,
    tag: str = "case",
    dispatch: bool = False,
    dirty: bool = False,
    environment_label: str = "active",
) -> dict[str, object]:
    repo = _repo(tmp_path / tag)
    if client is None:
        assert callable(client_factory)
        client = client_factory(repo)  # type: ignore[operator]
    if dirty:
        (repo / "dirty.txt").write_text("dirty\n", encoding="utf-8")
    return run_gate(
        repo_root=repo,
        output_dir=tmp_path / f"{tag}-evidence",
        environment_label=environment_label,
        commands=(
            CommandSpec(
                "local_probe",
                (sys.executable, "-c", f"raise SystemExit({exit_code})"),
                timeout_seconds=10,
            ),
        ),
        remote=True,
        remote_dispatch=dispatch,
        remote_timeout_seconds=5,
        remote_poll_interval_seconds=5,
        remote_client=client,
        remote_repository=REMOTE_REPO,
        workspace_state_root=tmp_path / f"{tag}-workspace-state",
    )


@pytest.mark.parametrize(
    ("client_kwargs", "reason"),
    [
        ({"available": False}, "gh_cli_unavailable"),
        ({"probe_error": RemoteQuotaExhausted("quota")}, "quota_exhausted"),
        ({"workflow_enabled": False}, "workflow_disabled"),
        ({"runner_online": False}, "runner_offline"),
        ({"probe_error": GhRemoteCIError("api down")}, "api_unavailable"),
        ({}, "no_completed_run"),
    ],
)
def test_remote_unavailable_falls_back_to_labelled_local_evidence(
    tmp_path: Path, client_kwargs: dict[str, object], reason: str
) -> None:
    client = FakeRemoteClient(**client_kwargs)  # type: ignore[arg-type]
    summary = _remote_gate(tmp_path, client, tag=f"unavailable-{reason}")
    assert summary["passed"] is True
    assert summary["evidenceSource"] == "local"
    assert len(summary["commands"]) == 1
    assert summary["commands"][0]["passed"] is True
    remote = summary["remoteCI"]
    assert remote["attempted"] is True
    assert remote["verified"] is False
    assert remote["included"] is False
    assert remote["dispatched"] is False
    assert remote["outcome"] == "unavailable"
    assert remote["fallbackReason"] == reason
    assert f"remote_CI_unavailable:{reason}" in summary["classification"]
    assert "not_remotely_CI_verified" in summary["classification"]
    assert client.dispatched == []


@pytest.mark.parametrize(
    ("run_over", "jobs", "reason"),
    [
        ({"repository": "someone-else/fork"}, None, "wrong_repository"),
        ({"workflow": "other.yml"}, None, "wrong_workflow"),
        ({"event": "push"}, None, "wrong_event"),
        ({"head_sha": "0" * 40}, None, "wrong_commit"),
        ({"created_at": "not-a-timestamp"}, None, "created_at_unparseable"),
        ({"created_at": STALE_RUN_AT}, None, "stale_run"),
        ({}, _jobs(names=REMOTE_REQUIRED_JOBS[:-1]), "missing_jobs"),
        ({}, _jobs(conclusion="failure"), "job_not_successful"),
        ({}, _jobs(labels=("self-hosted", "linux")), "runner_class_unverified"),
    ],
)
def test_remote_binding_failures_make_evidence_unavailable(
    tmp_path: Path, run_over: dict[str, object], jobs: tuple[RemoteJob, ...] | None, reason: str
) -> None:
    repo = _repo(tmp_path / f"binding-{reason}")
    run = _remote_run(_head(repo), **run_over)
    client = FakeRemoteClient(completed_run=run, jobs=jobs)
    summary = run_gate(
        repo_root=repo,
        output_dir=tmp_path / f"binding-{reason}-evidence",
        environment_label="active",
        commands=(
            CommandSpec("local_probe", (sys.executable, "-c", "raise SystemExit(0)"), timeout_seconds=10),
        ),
        remote=True,
        remote_timeout_seconds=5,
        remote_poll_interval_seconds=5,
        remote_client=client,
        remote_repository=REMOTE_REPO,
        workspace_state_root=tmp_path / f"binding-{reason}-workspace-state",
    )
    assert summary["passed"] is True
    assert summary["evidenceSource"] == "local"
    remote = summary["remoteCI"]
    assert remote["verified"] is False
    assert remote["included"] is False
    assert remote["outcome"] == "unavailable"
    assert remote["fallbackReason"] == reason
    assert f"remote_CI_unavailable:{reason}" in summary["classification"]
    assert "not_remotely_CI_verified" in summary["classification"]
    assert client.dispatched == []


def test_remote_fallback_local_failure_is_not_a_silent_success(tmp_path: Path) -> None:
    summary = _remote_gate(
        tmp_path, FakeRemoteClient(available=False), exit_code=7, tag="failing"
    )
    assert summary["passed"] is False
    assert summary["evidenceSource"] == "local"
    assert summary["commands"][0]["exitCode"] == 7
    assert summary["remoteCI"]["fallbackReason"] == "gh_cli_unavailable"
    assert "local_closure_failed_or_not_run" in summary["classification"]


def _verified_factory(run_id: int = 42, conclusion: str = "success") -> object:
    return lambda repo: FakeRemoteClient(
        completed_run=_remote_run(_head(repo), run_id=run_id, conclusion=conclusion)
    )


def test_remote_success_is_supplemental_and_never_skips_local(tmp_path: Path) -> None:
    # A failing local probe proves the local plan still executes: a green
    # remote run for the committed HEAD can never mask local failures.
    summary = _remote_gate(
        tmp_path, client_factory=_verified_factory(), exit_code=99, tag="remote-ok"
    )
    assert summary["passed"] is False
    assert summary["evidenceSource"] == "local"
    assert len(summary["commands"]) == 1
    assert summary["commands"][0]["exitCode"] == 99
    assert "command failed: local_probe" in summary["blockers"]
    remote = summary["remoteCI"]
    assert remote["attempted"] is True
    assert remote["included"] is True
    assert remote["supplementalOnly"] is True
    assert remote["verified"] is True
    assert remote["outcome"] == "verified"
    assert remote["runId"] == 42
    binding = remote["binding"]
    assert binding["repository"] == REMOTE_REPO
    assert binding["workflow"] == "validate.yml"
    assert binding["headSha"] == summary["repository"]["commit"]
    assert {job["name"] for job in binding["jobs"]} == set(REMOTE_REQUIRED_JOBS)
    classification = summary["classification"]
    assert classification.startswith("local_closure_failed_or_not_run; ")
    assert "supplemental_remote_CI_verified_for_exact_committed_HEAD" in classification
    assert summary["workspaceLifecycle"]["ok"] is True


def test_remote_success_with_green_local_passes_as_local_evidence(tmp_path: Path) -> None:
    summary = _remote_gate(tmp_path, client_factory=_verified_factory(), exit_code=0, tag="both-green")
    assert summary["passed"] is True
    assert summary["evidenceSource"] == "local"
    assert summary["classification"] == (
        "locally_closure_validated_from_this_checkout; "
        "supplemental_remote_CI_verified_for_exact_committed_HEAD"
    )
    assert summary["remoteCI"]["verified"] is True


def test_dirty_worktree_cannot_claim_remote_verification(tmp_path: Path) -> None:
    summary = _remote_gate(
        tmp_path, client_factory=_verified_factory(), exit_code=0, tag="dirty-remote", dirty=True
    )
    assert summary["passed"] is False
    assert "Git worktree was not clean before the gate" in summary["blockers"]
    classification = summary["classification"]
    assert "uncommitted_worktree_changes_not_covered_by_remote_evidence" in classification
    assert "locally_closure_validated" not in classification


def test_container_label_requires_corroboration_even_with_green_remote(tmp_path: Path) -> None:
    summary = _remote_gate(
        tmp_path,
        client_factory=_verified_factory(),
        exit_code=0,
        tag="container-label",
        environment_label="container",
    )
    assert summary["passed"] is False
    assert any("container environment label" in blocker for blocker in summary["blockers"])


def test_remote_observation_never_dispatches(tmp_path: Path) -> None:
    client_factory = lambda repo: FakeRemoteClient(  # noqa: E731
        completed_run=None,
        main_head=_head(repo),
        wait_result=_remote_run(_head(repo), run_id=7),
    )
    summary = _remote_gate(tmp_path, client_factory=client_factory, exit_code=0, tag="observe-only")
    remote = summary["remoteCI"]
    assert remote["fallbackReason"] == "no_completed_run"
    assert remote["dispatched"] is False
    assert summary["passed"] is True


def test_remote_dispatch_is_explicit_and_owner_gated(tmp_path: Path) -> None:
    client_factory = lambda repo: FakeRemoteClient(  # noqa: E731
        main_head=_head(repo),
        wait_result=_remote_run(_head(repo), run_id=7),
    )
    summary = _remote_gate(tmp_path, client_factory=client_factory, exit_code=0, tag="dispatch", dispatch=True)
    assert summary["passed"] is True
    assert summary["evidenceSource"] == "local"
    remote = summary["remoteCI"]
    assert remote["verified"] is True
    assert remote["dispatched"] is True
    assert remote["runId"] == 7
    assert len(summary["commands"]) == 1


def test_remote_dispatch_refused_for_dirty_worktree(tmp_path: Path) -> None:
    client_factory = lambda repo: FakeRemoteClient(main_head=_head(repo))  # noqa: E731
    summary = _remote_gate(
        tmp_path, client_factory=client_factory, tag="dispatch-dirty", dispatch=True, dirty=True
    )
    assert summary["remoteCI"]["fallbackReason"] == "dirty_worktree"
    assert summary["remoteCI"]["dispatched"] is False
    assert summary["passed"] is False


def test_remote_dispatch_requires_remote_main_head(tmp_path: Path) -> None:
    summary = _remote_gate(
        tmp_path, FakeRemoteClient(main_head="0" * 40), tag="dispatch-head", dispatch=True
    )
    assert summary["remoteCI"]["fallbackReason"] == "head_not_on_remote_main"
    assert summary["remoteCI"]["dispatched"] is False
    assert summary["passed"] is True


def test_remote_dispatch_timeout_is_unavailable_not_success(tmp_path: Path) -> None:
    client_factory = lambda repo: FakeRemoteClient(main_head=_head(repo), wait_result=None)  # noqa: E731
    summary = _remote_gate(tmp_path, client_factory=client_factory, tag="dispatch-timeout", dispatch=True)
    remote = summary["remoteCI"]
    assert remote["fallbackReason"] == "timeout"
    assert remote["dispatched"] is True
    assert summary["passed"] is True
    assert "not_remotely_CI_verified" in summary["classification"]


def test_remote_failure_is_an_honest_failure_not_a_local_rerun(tmp_path: Path) -> None:
    # A passing local probe must not mask an obtained remote failure.
    summary = _remote_gate(
        tmp_path, client_factory=_verified_factory(run_id=43, conclusion="failure"), exit_code=0, tag="remote-fail"
    )
    assert summary["passed"] is False
    assert summary["evidenceSource"] == "local"
    assert len(summary["commands"]) == 1
    assert summary["commands"][0]["passed"] is True
    assert summary["remoteCI"]["verified"] is False
    assert summary["remoteCI"]["included"] is True
    assert summary["remoteCI"]["conclusion"] == "failure"
    assert "remote CI run concluded failure" in summary["blockers"]
    assert "remote_CI_concluded_failure; gate_failed" in summary["classification"]


def test_default_local_only_never_attempts_remote(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    summary = run_gate(
        repo_root=repo,
        output_dir=tmp_path / "evidence",
        environment_label="active",
        commands=(
            CommandSpec("tiny", (sys.executable, "-c", "raise SystemExit(0)"), timeout_seconds=10),
        ),
        remote_client=FakeRemoteClient(available=False),
        workspace_state_root=tmp_path / "workspace-state",
    )
    assert summary["passed"] is True
    assert summary["evidenceSource"] == "local"
    assert summary["remoteCI"]["attempted"] is False
    assert summary["remoteCI"]["verified"] is False
    assert summary["environmentIdentity"]["hostname"]
    assert summary["environmentIdentity"]["python"]
    assert summary["repository"]["commit"] == _head(repo)
    assert len(summary["repository"]["tree"]) == 40
