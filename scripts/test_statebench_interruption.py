#!/usr/bin/env python3
"""Public-safe tests for forced interruption and repository-only continuation."""

from __future__ import annotations

from dataclasses import fields
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "statebench" / "src"))

from statebench import (  # noqa: E402
    AttemptIdentity,
    ContinuationProtocolError,
    EvidenceReference,
    ForcedInterruptionHarness,
    InterruptionPolicy,
    InterruptionSignal,
    LauncherStageResult,
)


def _run(argv: list[str], *, cwd: Path | None = None) -> str:
    completed = subprocess.run(
        argv, cwd=cwd, check=False, capture_output=True, text=True,
        timeout=10, shell=False,
    )
    if completed.returncode != 0:
        raise AssertionError(f"command failed: {argv!r}\n{completed.stderr}")
    return completed.stdout.strip()


def _bundle(root: Path) -> Path:
    source = root / "public-safe-source"
    _run(["git", "init", "--initial-branch=main", str(source)])
    _run(["git", "config", "user.email", "fixture@example.invalid"], cwd=source)
    _run(["git", "config", "user.name", "Public fixture"], cwd=source)
    (source / "STATEDD.yaml").write_text("format: fixture/v1\n", encoding="utf-8")
    (source / "README.txt").write_text("tiny public-safe benchmark fixture\n", encoding="utf-8")
    _run(["git", "add", "STATEDD.yaml", "README.txt"], cwd=source)
    _run(["git", "commit", "-m", "fixture"], cwd=source)
    bundle = root / "fixture.bundle"
    _run(["git", "bundle", "create", str(bundle), "main"], cwd=source)
    return bundle


def _identity(stage: str, attempt: str, launcher: str, ordinal: int) -> AttemptIdentity:
    return AttemptIdentity(
        parent_benchmark_run="run-18",
        stage=stage,  # type: ignore[arg-type]
        attempt_id=attempt,
        launcher_identity=launcher,
        launcher_identity_classification="ephemeral_local_launcher",
        ordinal=ordinal,
    )


class EventStageA:
    def __init__(self) -> None:
        self.released = False
        self.seen_task = ""
        self.seen_policy: InterruptionPolicy | None = None

    def launch_stage_a(self, request: object, interruption: object) -> LauncherStageResult:
        self.seen_task = request.original_task  # type: ignore[attr-defined]
        self.seen_policy = request.policy  # type: ignore[attr-defined]
        workspace = request.repository  # type: ignore[attr-defined]
        (workspace / "a-uncommitted.txt").write_text("preserve this valid A work\n", encoding="utf-8")
        try:
            interruption.normalized_event("opened")  # type: ignore[attr-defined]
            interruption.normalized_event("edited")  # type: ignore[attr-defined]
            interruption.normalized_event("validated")  # type: ignore[attr-defined]
        except InterruptionSignal:
            return LauncherStageResult(
                result="interrupted_partial",
                interrupted=True,
                evidence_references=(EvidenceReference("a-outcome-1", "launcher_outcome"),),
            )
        raise AssertionError("exact event trigger did not interrupt Stage A")

    def release(self) -> None:
        self.released = True


class CheckpointStageA(EventStageA):
    def launch_stage_a(self, request: object, interruption: object) -> LauncherStageResult:
        self.seen_task = request.original_task  # type: ignore[attr-defined]
        self.seen_policy = request.policy  # type: ignore[attr-defined]
        workspace = request.repository  # type: ignore[attr-defined]
        (workspace / "a-uncommitted.txt").write_text("checkpoint work\n", encoding="utf-8")
        try:
            interruption.normalized_event("opened")  # type: ignore[attr-defined]
            interruption.checkpoint("durable-ready")  # type: ignore[attr-defined]
        except InterruptionSignal:
            return LauncherStageResult("interrupted_checkpoint", True)
        raise AssertionError("explicit checkpoint did not interrupt Stage A")


class StageB:
    def __init__(self, stage_a: EventStageA) -> None:
        self.stage_a = stage_a
        self.seen_uncommitted = False
        self.seen_task = ""
        self.seen_policy: InterruptionPolicy | None = None

    def launch_stage_b(self, request: object) -> LauncherStageResult:
        assert not hasattr(request, "first_attempt_result")
        assert not hasattr(request, "transcript")
        assert not hasattr(request, "session")
        assert {field.name for field in fields(type(request))} == {
            "repository", "durable_statedd_files", "original_task", "policy", "attempt",
        }
        workspace = request.repository  # type: ignore[attr-defined]
        self.seen_uncommitted = (workspace / "a-uncommitted.txt").read_text(encoding="utf-8").startswith(("preserve", "checkpoint"))
        self.seen_task = request.original_task  # type: ignore[attr-defined]
        self.seen_policy = request.policy  # type: ignore[attr-defined]
        assert request.durable_statedd_files == ("STATEDD.yaml",)  # type: ignore[attr-defined]
        (workspace / "b-completed.txt").write_text("repository-only continuation\n", encoding="utf-8")
        _run(["git", "config", "user.email", "fixture@example.invalid"], cwd=workspace)
        _run(["git", "config", "user.name", "Public fixture"], cwd=workspace)
        _run(["git", "add", "b-completed.txt"], cwd=workspace)
        _run(["git", "commit", "-m", "stage b"], cwd=workspace)
        return LauncherStageResult(
            result="eventual_success",
            evidence_references=(EvidenceReference("b-outcome-1", "launcher_outcome"),),
        )


def _assert_raises(text: str, callback: object) -> None:
    try:
        callback()  # type: ignore[operator]
    except ContinuationProtocolError as exc:
        assert text in str(exc), str(exc)
    else:
        raise AssertionError("expected ContinuationProtocolError")


def test_event_count_interrupts_exactly_and_continues_from_repository_only() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        bundle = _bundle(root)
        stage_a = EventStageA()
        stage_b = StageB(stage_a)
        policy = InterruptionPolicy(
            normalized_event_count=3, event_budget=3, tool_budget=2,
            allowed_tools=("filesystem", "git"),
        )
        attempt = ForcedInterruptionHarness().run(
            bundle=bundle, expected_origin=str(bundle), run_root=root / "run-event",
            original_task="complete the tiny public-safe task", policy=policy,
            stage_a=stage_a, stage_a_identity=_identity("A", "attempt-a", "launcher-a", 1),
            stage_b=stage_b, stage_b_identity=_identity("B", "attempt-b", "launcher-b", 2),
            durable_statedd_files=("STATEDD.yaml",),
        )
        assert attempt.interruption.trigger == {"kind": "normalized_event_count", "value": 3}
        assert attempt.interruption.observed_normalized_events == 3
        assert attempt.first_attempt_result == "interrupted_partial"
        assert attempt.eventual_result == "eventual_success"
        assert attempt.stage_a.attempt_id != attempt.stage_b.attempt_id
        assert attempt.stage_a.launcher_identity != attempt.stage_b.launcher_identity
        assert attempt.initial_remote_facts.equal
        assert attempt.remote_facts.equal and attempt.remote_facts.remote_commit == attempt.remote_facts.local_commit
        assert attempt.interruption_record.parent.name == "evidence"
        record = attempt.interruption_record.read_text(encoding="utf-8")
        report = attempt.to_dict()
        assert "tiny public-safe task" not in record and "tiny public-safe task" not in str(report)
        assert "transcript" not in record and "session" not in record and "evaluator" not in record
        assert attempt.continuation_repository.working_tree_digest != attempt.initial_repository.working_tree_digest
        assert attempt.initial_repository.clean is True
        assert attempt.continuation_repository.clean is False
        assert attempt.final_repository.clean is False
        workspace = attempt.interruption_record.parents[1] / "fixture"
        assert (workspace / "a-uncommitted.txt").read_text(encoding="utf-8").startswith("preserve")
        assert "?? a-uncommitted.txt" in _run(["git", "status", "--porcelain=v1"], cwd=workspace)


def test_explicit_checkpoint_trigger_is_deterministic() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        bundle = _bundle(root)
        stage_a = CheckpointStageA()
        stage_b = StageB(stage_a)
        attempt = ForcedInterruptionHarness().run(
            bundle=bundle, expected_origin=str(bundle), run_root=root / "run-checkpoint",
            original_task="continue exactly from files", policy=InterruptionPolicy(
                checkpoint_trigger="durable-ready", event_budget=2, tool_budget=1,
            ),
            stage_a=stage_a, stage_a_identity=_identity("A", "checkpoint-a", "checkpoint-launcher-a", 1),
            stage_b=stage_b, stage_b_identity=_identity("B", "checkpoint-b", "checkpoint-launcher-b", 2),
            durable_statedd_files=("STATEDD.yaml",),
        )
        assert attempt.interruption.trigger == {"kind": "checkpoint", "value": "durable-ready"}
        assert attempt.interruption.observed_normalized_events == 1
        assert attempt.first_attempt_result == "interrupted_checkpoint"
        assert attempt.eventual_result == "eventual_success"


def test_policy_and_identity_reuse_fail_closed() -> None:
    _assert_raises("exactly one", lambda: InterruptionPolicy(event_budget=2))
    _assert_raises("exactly one", lambda: InterruptionPolicy(normalized_event_count=1, checkpoint_trigger="x", event_budget=2))
    _assert_raises("within event_budget", lambda: InterruptionPolicy(normalized_event_count=3, event_budget=2))
    _assert_raises("hidden chat or session", lambda: EvidenceReference("session-copy", "launcher_outcome"))
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        bundle = _bundle(root)
        stage_a = EventStageA()
        stage_b = StageB(stage_a)
        _assert_raises("identity reuse", lambda: ForcedInterruptionHarness().run(
            bundle=bundle, expected_origin=str(bundle), run_root=root / "reuse",
            original_task="public task", policy=InterruptionPolicy(normalized_event_count=1, event_budget=1),
            stage_a=stage_a, stage_a_identity=_identity("A", "same-attempt", "same-launcher", 1),
            stage_b=stage_b, stage_b_identity=_identity("B", "same-attempt", "same-launcher", 2),
        ))
        _assert_raises("launcher/session identity reuse", lambda: ForcedInterruptionHarness().run(
            bundle=bundle, expected_origin=str(bundle), run_root=root / "reuse-launcher",
            original_task="public task", policy=InterruptionPolicy(normalized_event_count=1, event_budget=1),
            stage_a=stage_a, stage_a_identity=_identity("A", "attempt-a", "same-launcher", 1),
            stage_b=stage_b, stage_b_identity=_identity("B", "attempt-b", "same-launcher", 2),
        ))
        _assert_raises("original_task", lambda: ForcedInterruptionHarness().run(
            bundle=bundle, expected_origin=str(bundle), run_root=root / "missing-task",
            original_task="", policy=InterruptionPolicy(normalized_event_count=1, event_budget=1),
            stage_a=stage_a, stage_a_identity=_identity("A", "task-a", "task-launcher-a", 1),
            stage_b=stage_b, stage_b_identity=_identity("B", "task-b", "task-launcher-b", 2),
        ))


class DriftingHarness(ForcedInterruptionHarness):
    def _verify_interruption_record(self, record: Path, *args: object) -> None:
        super()._verify_interruption_record(record, *args)  # type: ignore[arg-type]
        (record.parents[1] / "fixture" / "unexpected-drift.txt").write_text("drift\n", encoding="utf-8")


class MissingRecordHarness(ForcedInterruptionHarness):
    def _persist_interruption(self, **kwargs: object) -> None:
        super()._persist_interruption(**kwargs)  # type: ignore[arg-type]
        Path(kwargs["record"]).unlink()


def test_missing_record_and_snapshot_drift_fail_closed() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        bundle = _bundle(root)
        stage_a = EventStageA()
        stage_b = StageB(stage_a)
        common = dict(
            bundle=bundle, expected_origin=str(bundle), original_task="public task",
            policy=InterruptionPolicy(normalized_event_count=3, event_budget=3),
            stage_a=stage_a, stage_a_identity=_identity("A", "record-a", "record-launcher-a", 1),
            stage_b=stage_b, stage_b_identity=_identity("B", "record-b", "record-launcher-b", 2),
        )
        _assert_raises("persisted interruption record is missing", lambda: MissingRecordHarness().run(
            run_root=root / "missing-record", **common,
        ))
        stage_a = EventStageA()
        stage_b = StageB(stage_a)
        _assert_raises("snapshot drifted", lambda: DriftingHarness().run(
            run_root=root / "drift", **{
                **common, "stage_a": stage_a, "stage_b": stage_b,
                "stage_a_identity": _identity("A", "drift-a", "drift-launcher-a", 1),
                "stage_b_identity": _identity("B", "drift-b", "drift-launcher-b", 2),
            },
        ))


class WaitingStageA(EventStageA):
    def __init__(self, unblock: threading.Event) -> None:
        super().__init__()
        self.unblock = unblock

    def launch_stage_a(self, request: object, interruption: object) -> LauncherStageResult:
        self.unblock.wait(5)
        return LauncherStageResult("late", True)


class CountingStageB(StageB):
    def __init__(self, stage_a: EventStageA) -> None:
        super().__init__(stage_a)
        self.calls = 0

    def launch_stage_b(self, request: object) -> LauncherStageResult:
        self.calls += 1
        return super().launch_stage_b(request)


class WaitingReleaseStageA(EventStageA):
    def __init__(self, unblock: threading.Event) -> None:
        super().__init__()
        self.unblock = unblock

    def launch_stage_a(self, request: object, interruption: object) -> LauncherStageResult:
        try:
            interruption.normalized_event("stop")  # type: ignore[attr-defined]
        except InterruptionSignal:
            return LauncherStageResult("interrupted_partial", True)
        raise AssertionError("interruption was not delivered")

    def release(self) -> None:
        self.unblock.wait(5)
        self.released = True


class DescendantStageA(EventStageA):
    def launch_stage_a(self, request: object, interruption: object) -> LauncherStageResult:
        (request.repository / "a-uncommitted.txt").write_text(  # type: ignore[attr-defined]
            "preserve descendant test work\n", encoding="utf-8",
        )
        marker = request.repository / "late-descendant.txt"  # type: ignore[attr-defined]
        subprocess.Popen([
            sys.executable,
            "-c",
            "import pathlib,sys,time; time.sleep(.3); pathlib.Path(sys.argv[1]).write_text('late')",
            str(marker),
        ])
        try:
            interruption.normalized_event("stop")  # type: ignore[attr-defined]
        except InterruptionSignal:
            return LauncherStageResult("interrupted_partial", True)
        raise AssertionError("interruption was not delivered")


def test_stage_calls_obey_one_absolute_alpha_deadline_and_reap_launcher_groups() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        bundle = _bundle(root)
        unblock = threading.Event()
        stage_a = WaitingStageA(unblock)
        stage_b = CountingStageB(stage_a)
        started = time.monotonic()
        _assert_raises("stage-a exceeded", lambda: ForcedInterruptionHarness(timeout_seconds=0.05).run(
            bundle=bundle, expected_origin=str(bundle), run_root=root / "stage-timeout",
            original_task="public task", policy=InterruptionPolicy(normalized_event_count=1, event_budget=1),
            stage_a=stage_a, stage_a_identity=_identity("A", "slow-a", "slow-launcher-a", 1),
            stage_b=stage_b, stage_b_identity=_identity("B", "slow-b", "slow-launcher-b", 2),
        ))
        assert time.monotonic() - started < 0.5
        assert stage_b.calls == 0

    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        bundle = _bundle(root)
        stage_a = DescendantStageA()
        stage_b = CountingStageB(stage_a)
        attempt = ForcedInterruptionHarness(timeout_seconds=2).run(
            bundle=bundle, expected_origin=str(bundle), run_root=root / "descendant-reap",
            original_task="public task", policy=InterruptionPolicy(normalized_event_count=1, event_budget=1),
            stage_a=stage_a, stage_a_identity=_identity("A", "reap-a", "reap-launcher-a", 1),
            stage_b=stage_b, stage_b_identity=_identity("B", "reap-b", "reap-launcher-b", 2),
            durable_statedd_files=("STATEDD.yaml",),
        )
        time.sleep(0.4)
        workspace = attempt.interruption_record.parents[1] / "fixture"
        assert not (workspace / "late-descendant.txt").exists()


def test_external_launcher_classification_is_rejected_until_process_handles_exist() -> None:
    external_a = AttemptIdentity("run-18", "A", "external-a", "external-launcher-a", "external_launcher", 1)
    external_b = AttemptIdentity("run-18", "B", "external-b", "external-launcher-b", "external_launcher", 2)
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        bundle = _bundle(root)
        stage_a = EventStageA()
        _assert_raises("process-handle contract", lambda: ForcedInterruptionHarness().run(
            bundle=bundle, expected_origin=str(bundle), run_root=root / "external-rejected",
            original_task="public task", policy=InterruptionPolicy(normalized_event_count=1, event_budget=1),
            stage_a=stage_a, stage_a_identity=external_a,
            stage_b=StageB(stage_a), stage_b_identity=external_b,
        ))


if __name__ == "__main__":
    test_event_count_interrupts_exactly_and_continues_from_repository_only()
    test_explicit_checkpoint_trigger_is_deterministic()
    test_policy_and_identity_reuse_fail_closed()
    test_missing_record_and_snapshot_drift_fail_closed()
    print("PASS")
