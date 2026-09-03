from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
for relative in (
    "packages/persistent-app/src",
    "packages/portable-execution/src",
    "packages/execution-host/src",
    "packages/external-engine-runtime/src",
    "packages/codex-adapter/src",
    "packages/run-bundle/src",
    "packages/statedd-core/src",
    "packages/template-validator/src",
    "packages/instance-backup/src",
    "packages/instance-catalog/src",
    "packages/diagnostics/src",
    "apps/runner/src",
):
    sys.path.insert(0, str(ROOT / relative))

from stateport_persistent_app import AppError, LocalLayout, PersistentApp  # noqa: E402
from stateport_portable_execution.runtime import PortableExecutionError, PortableExecutionService  # noqa: E402
from external_engine_runtime import ProcessIdentity, ProcessResult, ProcessRuntimeError  # noqa: E402
import stateport_portable_execution.runtime as portable_runtime  # noqa: E402


def test_typed_action_is_engine_bound_and_transactionally_applied(tmp_path: Path, monkeypatch) -> None:
    mirror = Path(os.environ.get("STATEPORT_STUDYDD_MIRROR", "/tmp/studydd-portable-actions"))
    if not mirror.is_dir():
        return
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("STATEPORT_STUDYDD_MIRROR", str(mirror))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init(source_mirror=str(mirror))
    plan = app.plan_create(source_profile="builtin:studydd-local-alpha", instance_id="portable-study", name="Portable Study", owner_name="Synthetic Owner", owner_handle="synthetic-owner", target_id="demo", seed_mode="synthetic-demo", allow_development_candidate=True)
    app.create(plan, app.approve(plan))
    execution = PortableExecutionService(app, ROOT)
    prepared = execution.prepare("portable-study", "studydd.plan-next-session/v1", "synthetic", {"timeAvailableMinutes": 20, "includeFastDrillProposal": True}, allow_development_candidate=True)
    assert prepared["run"]["status"] == "awaiting_approval"
    assert prepared["run"]["statePack"]["manifest"]["excluded"]
    with __import__("pytest").raises(PortableExecutionError):
        execution.execute(prepared["run"]["runId"])
    run_id = prepared["run"]["runId"]
    execution.approve_run(run_id)
    completed = execution.execute(run_id)
    assert completed["run"]["status"] == "state_change_proposed"
    assert completed["run"]["result"]["canonicalStateUnchanged"] is True
    execution.approve_proposal(run_id)
    applied = execution.apply_proposal(run_id)
    assert applied["run"]["status"] == "applied"
    assert applied["run"]["receipt"]["validation"] == "passed"
    exported = execution.export_instance("portable-study")
    assert exported["manifest"]["engineSessions"]["included"] is False
    imported = execution.import_instance_archive(exported["archive"], app.layout.instances_root / "moved-study", new_instance_id="moved-study")
    assert imported["instanceId"] == "moved-study"
    assert (app.layout.instances_root / "moved-study" / "instance.yaml").is_file()


def test_development_candidate_receipt_is_rechecked_before_execute_and_apply(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mirror = Path(os.environ.get("STATEPORT_STUDYDD_MIRROR", "/tmp/studydd-portable-actions"))
    if not mirror.is_dir():
        return
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("STATEPORT_STUDYDD_MIRROR", str(mirror))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init(source_mirror=str(mirror))
    plan = app.plan_create(
        source_profile="builtin:studydd-local-alpha",
        instance_id="revoked-receipt-study",
        name="Revoked receipt study",
        owner_name="Synthetic Owner",
        owner_handle="synthetic-owner",
        target_id="receipt-test",
        seed_mode="synthetic-demo",
        allow_development_candidate=True,
    )
    app.create(plan, app.approve(plan))
    execution = PortableExecutionService(app, ROOT)
    prepared = execution.prepare(
        "revoked-receipt-study",
        "studydd.plan-next-session/v1",
        "synthetic",
        {"timeAvailableMinutes": 20, "includeFastDrillProposal": True},
        allow_development_candidate=True,
    )
    run_id = prepared["run"]["runId"]
    execution.approve_run(run_id)
    receipt_path = app._source_access_path("revoked-receipt-study")
    receipt_bytes = receipt_path.read_bytes()
    receipt_path.unlink()
    with pytest.raises(PortableExecutionError, match="no longer authorized"):
        execution.execute(run_id)
    assert execution.inspect(run_id)["run"]["status"] == "approved"

    receipt_path.write_bytes(receipt_bytes)
    completed = execution.execute(run_id)
    assert completed["run"]["status"] == "state_change_proposed"
    execution.approve_proposal(run_id)
    before = PortableExecutionService._state_digest(
        app.layout.instances_root / "revoked-receipt-study"
    )
    receipt_path.unlink()
    with pytest.raises(PortableExecutionError, match="no longer authorized"):
        execution.apply_proposal(run_id)
    assert execution.inspect(run_id)["run"]["status"] == "state_change_approved"
    assert PortableExecutionService._state_digest(
        app.layout.instances_root / "revoked-receipt-study"
    ) == before

    receipt_path.write_bytes(receipt_bytes)
    original_authorization = execution._development_candidate_authorization
    authorization_checks = 0
    revoked_at_commit = False

    def revoke_at_commit(
        instance_id: str,
        *,
        expected_receipt_digest: str | None = None,
    ) -> str:
        nonlocal authorization_checks, revoked_at_commit
        authorization_checks += 1
        if execution.inspect(run_id)["run"]["status"] == "applying":
            receipt_path.unlink()
            revoked_at_commit = True
        return original_authorization(
            instance_id,
            expected_receipt_digest=expected_receipt_digest,
        )

    monkeypatch.setattr(
        execution,
        "_development_candidate_authorization",
        revoke_at_commit,
    )
    with pytest.raises(PortableExecutionError, match="no longer authorized"):
        execution.apply_proposal(run_id)
    assert authorization_checks >= 3
    assert revoked_at_commit is True
    assert execution.inspect(run_id)["run"]["status"] == "apply_failed"
    assert PortableExecutionService._state_digest(
        app.layout.instances_root / "revoked-receipt-study"
    ) == before


def test_complete_staged_source_identity_is_rechecked_before_execute_and_apply(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mirror = Path(os.environ.get("STATEPORT_STUDYDD_MIRROR", "/tmp/studydd-portable-actions"))
    if not mirror.is_dir():
        return
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("STATEPORT_STUDYDD_MIRROR", str(mirror))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init(source_mirror=str(mirror))

    def create_run(instance_id: str) -> tuple[PortableExecutionService, str]:
        plan = app.plan_create(
            source_profile="builtin:studydd-local-alpha",
            instance_id=instance_id,
            name=instance_id.replace("-", " ").title(),
            owner_name="Synthetic Owner",
            owner_handle="synthetic-owner",
            target_id="staged-identity",
            seed_mode="synthetic-demo",
            allow_development_candidate=True,
        )
        app.create(plan, app.approve(plan))
        service = PortableExecutionService(app, ROOT)
        prepared = service.prepare(
            instance_id,
            "studydd.plan-next-session/v1",
            "synthetic",
            {"timeAvailableMinutes": 20, "includeFastDrillProposal": True},
            allow_development_candidate=True,
        )
        run_id = prepared["run"]["runId"]
        service.approve_run(run_id)
        return service, run_id

    execution, execute_run = create_run("staged-execute-study")
    original_copy = execution._copy_tree_without_symlinks
    original_run_process = portable_runtime.run_process
    worker_started = False

    def copy_then_tamper(
        source: Path,
        destination: Path,
        *,
        ignore: object = None,
    ) -> None:
        original_copy(source, destination, ignore=ignore)
        if destination.name == "application":
            contract = destination / "contracts/studydd.instance-layout.yaml"
            contract.chmod(0o600)
            contract.write_bytes(contract.read_bytes() + b"\n# staged drift\n")

    def reject_worker_start(*_args: object, **_kwargs: object) -> None:
        nonlocal worker_started
        worker_started = True
        raise AssertionError("worker must not start with drifted staged source bytes")

    monkeypatch.setattr(execution, "_copy_tree_without_symlinks", copy_then_tamper)
    monkeypatch.setattr(portable_runtime, "run_process", reject_worker_start)
    with pytest.raises(PortableExecutionError) as execute_error:
        execution.execute(execute_run)
    assert "staged application source identity drifted" in str(
        execute_error.value.__cause__
    )
    assert worker_started is False

    monkeypatch.setattr(portable_runtime, "run_process", original_run_process)
    apply_execution, apply_run = create_run("staged-apply-study")
    completed = apply_execution.execute(apply_run)
    assert completed["run"]["status"] == "state_change_proposed"
    apply_execution.approve_proposal(apply_run)
    before = PortableExecutionService._state_digest(
        app.layout.instances_root / "staged-apply-study"
    )
    apply_copy = apply_execution._copy_tree_without_symlinks

    def copy_then_tamper_apply(
        source: Path,
        destination: Path,
        *,
        ignore: object = None,
    ) -> None:
        apply_copy(source, destination, ignore=ignore)
        if destination.name == "application":
            contract = destination / "contracts/studydd.instance-layout.yaml"
            contract.chmod(0o600)
            contract.write_bytes(contract.read_bytes() + b"\n# staged apply drift\n")

    monkeypatch.setattr(
        apply_execution,
        "_copy_tree_without_symlinks",
        copy_then_tamper_apply,
    )
    with pytest.raises(
        PortableExecutionError,
        match="staged application source identity drifted",
    ):
        apply_execution.apply_proposal(apply_run)
    assert PortableExecutionService._state_digest(
        app.layout.instances_root / "staged-apply-study"
    ) == before


def test_synthetic_worker_uses_fixed_capable_interpreter_when_path_is_poisoned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mirror = Path(os.environ.get("STATEPORT_STUDYDD_MIRROR", "/tmp/studydd-portable-actions"))
    if not mirror.is_dir():
        return
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("STATEPORT_STUDYDD_MIRROR", str(mirror))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init(source_mirror=str(mirror))
    plan = app.plan_create(
        source_profile="builtin:studydd-local-alpha",
        instance_id="poisoned-path-study",
        name="Poisoned path study",
        owner_name="Synthetic Owner",
        owner_handle="synthetic-owner",
        target_id="path-test",
        seed_mode="synthetic-demo",
        allow_development_candidate=True,
    )
    app.create(plan, app.approve(plan))
    execution = PortableExecutionService(app, ROOT)
    prepared = execution.prepare(
        "poisoned-path-study",
        "studydd.plan-next-session/v1",
        "synthetic",
        {"timeAvailableMinutes": 20, "includeFastDrillProposal": True},
        allow_development_candidate=True,
    )
    run_id = prepared["run"]["runId"]
    execution.approve_run(run_id)
    poisoned = tmp_path / "poisoned-bin"
    poisoned.mkdir()
    fake_python = poisoned / "python3"
    fake_python.write_text("#!/bin/sh\nexit 97\n", encoding="utf-8")
    fake_python.chmod(0o755)
    monkeypatch.setenv("PATH", f"{poisoned}:/usr/bin:/bin")

    completed = execution.execute(run_id)

    assert completed["run"]["status"] == "state_change_proposed"


def test_descriptor_copy_rejects_symlink_replacement_during_copy(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    (source / "payload.txt").write_text("owned\n", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("foreign\n", encoding="utf-8")
    real_open = portable_runtime.os.open
    replaced = False

    def replace_before_open(path: object, flags: int, *args: object, dir_fd: int | None = None, **kwargs: object) -> int:
        nonlocal replaced
        if path == "payload.txt" and dir_fd is not None and not flags & getattr(os, "O_DIRECTORY", 0) and not replaced:
            replaced = True
            (source / "payload.txt").unlink()
            (source / "payload.txt").symlink_to(outside)
        return real_open(path, flags, *args, dir_fd=dir_fd, **kwargs)

    monkeypatch.setattr(portable_runtime.os, "open", replace_before_open)
    with pytest.raises((PortableExecutionError, OSError), match="changed|symlink|symbolic"):
        PortableExecutionService._copy_tree_without_symlinks(source, destination)
    assert not (destination / "payload.txt").exists()


def test_staging_copy_excludes_git_metadata_but_still_rejects_other_hardlinks(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "payload.txt").write_text("owned\n", encoding="utf-8")
    objects = source / ".git" / "objects"
    objects.mkdir(parents=True)
    git_object = objects / "object"
    git_object.write_text("git metadata\n", encoding="utf-8")
    (objects / "linked-object").hardlink_to(git_object)

    destination = tmp_path / "destination"
    PortableExecutionService._copy_tree_without_symlinks(
        source,
        destination,
        ignore=PortableExecutionService._ignore_staging_metadata,
    )
    assert (destination / "payload.txt").read_text(encoding="utf-8") == "owned\n"
    assert not (destination / ".git").exists()

    ordinary_source = tmp_path / "ordinary-source"
    ordinary_source.mkdir()
    ordinary = ordinary_source / "ordinary.txt"
    ordinary.write_text("owned\n", encoding="utf-8")
    (ordinary_source / "linked.txt").hardlink_to(ordinary)
    with pytest.raises(PortableExecutionError, match="unsupported file"):
        PortableExecutionService._copy_tree_without_symlinks(
            ordinary_source,
            tmp_path / "ordinary-destination",
            ignore=PortableExecutionService._ignore_staging_metadata,
        )


def test_environment_gated_engine_fails_closed(tmp_path: Path, monkeypatch) -> None:
    mirror = Path(os.environ.get("STATEPORT_STUDYDD_MIRROR", "/tmp/studydd-portable-actions"))
    if not mirror.is_dir():
        return
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("STATEPORT_STUDYDD_MIRROR", str(mirror))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init(source_mirror=str(mirror))
    plan = app.plan_create(source_profile="builtin:studydd-local-alpha", instance_id="gated-study", name="Gated Study", owner_name="Synthetic Owner", owner_handle="synthetic-owner", target_id="demo", seed_mode="synthetic-demo", allow_development_candidate=True)
    app.create(plan, app.approve(plan))
    execution = PortableExecutionService(app, ROOT)
    try:
        execution.prepare("gated-study", "studydd.plan-next-session/v1", "pi", {}, allow_development_candidate=True)
    except PortableExecutionError as exc:
        assert "capability_negotiation_failed" in str(exc)
    else:
        raise AssertionError("environment-gated Pi preparation must fail closed")


def test_action_list_populates_for_registered_raw_development_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A registered raw development fixture (no install-time lock) lists actions.

    Regression for BL-WORKSPACE-002-actions on ProjectState: the Execution
    Center returned 400 because _source_root required an instance lock that a
    registered raw fixture does not have. Actions must resolve from the immutable
    repository fixture instead.
    """
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    fixture = app.layout.instances_root / "dev-raw-fixture"
    shutil.copytree(ROOT / "fixtures" / "apps" / "development-reference", fixture)
    app.catalog.register(
        fixture,
        instance_id="dev-raw-fixture",
        name="Development raw fixture",
        source={"templateId": "stateport.development-reference"},
    )
    execution = PortableExecutionService(app, ROOT)

    actions = execution.action_list("dev-raw-fixture")

    assert [action["actionId"] for action in actions] == ["stateport.development.inspect-project/v1"]


def test_action_list_returns_empty_when_development_candidate_gate_fires(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A development-candidate-locked instance lists no actions through the normal path.

    The prepare/execute gates stay authoritative; listing reports an honest empty
    result instead of a 400 operation_failed. Regression for
    BL-WORKSPACE-002-actions on StudyState.
    """
    from stateport_portable_execution.runtime import _is_development_candidate_gate

    gate_cause = AppError("the installed source is a development candidate; use the explicit operator testing path")
    gated = PortableExecutionError("application source is unavailable for action preparation")
    gated.__cause__ = gate_cause
    unrelated = PortableExecutionError("application action contract is invalid")

    assert _is_development_candidate_gate(gated) is True
    assert _is_development_candidate_gate(unrelated) is False

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    execution = PortableExecutionService(app, ROOT)

    def _gated_actions(self, instance_id, **_):
        raise gated

    def _broken_actions(self, instance_id, **_):
        raise unrelated

    monkeypatch.setattr(PortableExecutionService, "_actions", _gated_actions)
    assert execution.action_list("anything") == []

    monkeypatch.setattr(PortableExecutionService, "_actions", _broken_actions)
    with pytest.raises(PortableExecutionError):
        execution.action_list("anything")


def test_codex_worker_termination_diagnostics_are_safe_and_distinguishable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every launched-worker failure keeps only bounded termination evidence."""

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    service = PortableExecutionService(app, ROOT)
    service.install_fixture_instance("checklistdd", "termination-fixture")
    codex = portable_runtime.EngineProfile(
        "codex", "codex-cli", "test", "available", "test",
        "operator_authenticated_unverified",
        portable_runtime._caps(
            structuredEvents="supported", nonInteractiveExecution="supported",
            cancellation="supported",
        ),
        "test-model", False,
    )
    monkeypatch.setattr(portable_runtime, "engine_profiles", lambda: [codex])

    marker = "DO_NOT_PERSIST_MODEL_OUTPUT_OR_STDERR"
    calls: list[str] = []
    outcomes = {
        "timeout": ProcessResult((marker,), -15, marker, marker, True, False, False, 119_000, "discarded"),
        "cancelled": ProcessResult((marker,), -15, marker, marker, False, True, False, 41, "discarded"),
        "output_limit": ProcessResult((marker,), -9, marker, marker, False, False, True, 42, "discarded"),
        "worker_nonzero_exit": ProcessResult((marker,), 7, marker, marker, False, False, False, 43, "discarded"),
        "result_artifact_missing": ProcessResult((marker,), 0, '{"type":"agent_message","text":"' + marker + '"}', marker, False, False, False, 44, "discarded"),
    }
    active: dict[str, str] = {"classification": "timeout"}

    def fake_execute(_self, _spec, _staging, **kwargs):
        calls.append(active["classification"])
        kwargs["on_started"](ProcessIdentity(123, 123, "456", "generation." + "a" * 64))
        return outcomes[active["classification"]]

    monkeypatch.setattr(portable_runtime.CodexAdapter, "execute", fake_execute)
    allowed_process_fields = {
        "launchStatus", "exitCode", "terminatingSignal", "durationMs",
        "timedOut", "cancelled", "outputLimited", "resultArtifactPresent",
    }
    for expected in outcomes:
        active["classification"] = expected
        prepared = service.prepare(
            "termination-fixture", "checklistdd.complete-item/v1", "codex",
            {"itemId": "first-item"},
        )
        run_id = prepared["run"]["runId"]
        before = prepared["run"]["canonicalStateBefore"]
        service.approve_run(run_id)
        with pytest.raises(PortableExecutionError):
            service.execute(run_id)
        failed = service.inspect(run_id)["run"]
        assert failed["status"] == ("timed_out" if expected == "timeout" else "cancelled" if expected == "cancelled" else "failed")
        assert failed["canonicalStateBefore"] == before
        assert failed.get("proposal") is None and failed.get("result") is None
        assert failed["runResult"]["terminationClassification"] == expected
        assert failed["runResult"]["failureClassification"] == expected
        assert set(failed["process"]) == allowed_process_fields
        assert failed["process"]["launchStatus"] == "launched"
        assert failed["process"]["durationMs"] == outcomes[expected].duration_ms
        assert failed["process"]["resultArtifactPresent"] is False
        assert failed.get("attempts") == 1
        assert marker not in json.dumps(failed["events"], sort_keys=True)
        bundle_text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in Path(failed["runBundle"]["path"]).rglob("*") if path.is_file()
        )
        assert marker not in bundle_text
    assert calls == list(outcomes)

    def launch_failure(_self, _spec, _staging, **_kwargs):
        raise ProcessRuntimeError("launch marker " + marker)

    monkeypatch.setattr(portable_runtime.CodexAdapter, "execute", launch_failure)
    prepared = service.prepare(
        "termination-fixture", "checklistdd.complete-item/v1", "codex",
        {"itemId": "first-item"},
    )
    run_id = prepared["run"]["runId"]
    service.approve_run(run_id)
    with pytest.raises(PortableExecutionError):
        service.execute(run_id)
    failed = service.inspect(run_id)["run"]
    assert failed["runResult"]["terminationClassification"] == "launch_failure"
    assert failed["process"] == {
        "launchStatus": "not_started", "exitCode": None, "terminatingSignal": None,
        "durationMs": None, "timedOut": False, "cancelled": False,
        "outputLimited": False, "resultArtifactPresent": False,
    }

    def success(_self, _spec, _staging, **kwargs):
        kwargs["on_started"](ProcessIdentity(124, 124, "457", "generation." + "b" * 64))
        result = {"actionId": "checklistdd.plan-next-item/v1", "item": {"id": "first-item"}}
        return ProcessResult(
            (marker,), 0,
            json.dumps({"type": "agent_message", "text": marker}) + "\n" + json.dumps({"type": "stateport.result", "result": result}),
            marker, False, False, False, 45, "discarded",
        )

    monkeypatch.setattr(portable_runtime.CodexAdapter, "execute", success)
    prepared = service.prepare("termination-fixture", "checklistdd.plan-next-item/v1", "codex", {})
    run_id = prepared["run"]["runId"]
    service.approve_run(run_id)
    completed = service.execute(run_id)["run"]
    assert completed["status"] == "result_validating"
    assert completed["runResult"]["terminationClassification"] == "success"
    assert completed["runResult"]["failureClassification"] is None
    assert completed["process"]["resultArtifactPresent"] is True
    assert completed["result"]["canonicalStateUnchanged"] is True
    assert marker not in "\n".join(
        path.read_text(encoding="utf-8")
        for path in Path(completed["runBundle"]["path"]).rglob("*") if path.is_file()
    )
