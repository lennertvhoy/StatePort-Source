"""The core loop: agent/check actions -> one file-change proposal -> approval -> apply + commit.

The model is replaced by a fake sandbox that edits files in the workdir it is
given (the exact interface of docs/design/agent-sandbox.md). Everything else is
the real product path: template import, preparation, StatePort's own diff and
writable-path policy, the pinned ProjectState gate as evaluator, StatePort's
file-change writer under bubblewrap, the template validator and the Git commit.
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
for source_root in sorted((ROOT / "packages").glob("*/src")):
    sys.path.insert(0, str(source_root))

from stateport_persistent_app import LocalLayout, PersistentApp  # noqa: E402
from stateport_persistent_app import agent_sandbox  # noqa: E402
from stateport_persistent_app.model_route_binding import RouteRefusal, resolve_agent_route  # noqa: E402
from stateport_persistent_app.repository_import import (  # noqa: E402
    RepositoryInspector,
    RepositorySourcePolicy,
    _candidate_id,
)
from stateport_portable_execution import EnvironmentGatedExecution, PortableExecutionError  # noqa: E402
from stateport_portable_execution.contracts import ActionContract, digest  # noqa: E402
from stateport_portable_execution.file_changes import FileChangeLimits, WritablePolicy  # noqa: E402
import stateport_portable_execution.runtime as portable_runtime  # noqa: E402
from stateport_portable_execution.runtime import (  # noqa: E402
    GovernedRefusalError,
    PortableExecutionService,
    WorkerRefusedError,
)

from stateport_agent_harness import (  # noqa: E402
    CHECK,
    FakeSandbox,
    NEXT_ACTION,
    ROUTE,
    SETUP_PROJECT,
    commit_repository,
    edit_next_action,
    git,
    import_projectstate,
    import_template,
    make_app,
    make_service,
    native_repository,
    needs_bwrap,
    projectstate_repository,
    run_action,
    studystate_repository,
)


def _git(root: Path, *arguments: str) -> str:
    return git(root, *arguments)


def _commit(root: Path) -> None:
    commit_repository(root)


def _projectstate_repository(root: Path) -> Path:
    return projectstate_repository(root)


def _studystate_repository(root: Path) -> Path:
    return studystate_repository(root)


def _native_repository(root: Path) -> Path:
    return native_repository(root)


def _app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[PersistentApp, Path]:
    return make_app(tmp_path, monkeypatch)


def _import(app: PersistentApp, source: Path, sources: Path, instance_id: str) -> dict:
    return import_template(app, source, sources, instance_id)


def _service(app: PersistentApp, edit, *, route=ROUTE) -> tuple[PortableExecutionService, FakeSandbox]:
    return make_service(app, edit, route=route)


def _projectstate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, edit, instance_id: str = "project-one"):
    return import_projectstate(tmp_path, monkeypatch, edit, instance_id)


def _run(service: PortableExecutionService, instance_id: str, action_id: str, inputs: dict | None = None) -> dict:
    return run_action(service, instance_id, action_id, inputs)


def _edit_next_action(workdir: Path) -> None:
    edit_next_action(workdir)


# --------------------------------------------------------------------------- contract


def _contract(**overrides) -> dict:
    value = {
        "formatVersion": "x.action/v1", "id": "x.a/v1", "displayName": "A", "purpose": "p",
        "contextPolicy": {"id": "c"}, "requiredCapabilities": ["structuredEvents"],
    }
    value.update(overrides)
    return value


@pytest.mark.parametrize(
    "overrides",
    [
        {"networkPolicy": "internet"},
        {"mutationPolicy": "write_anything"},
        {"toolPolicy": "shell"},
        {"executorKind": "plugin"},
        {"executorKind": "agent"},
        {"executorKind": "agent", "instructions": "x" * 4001},
        {"executorKind": "agent", "instructions": "do it", "networkPolicy": "disabled"},
        {"executorKind": "agent", "instructions": "do it", "actionClass": "agent.anything"},
        {"executorKind": "agent", "instructions": "do it", "executorCommand": "scripts/x.py"},
        {"networkPolicy": "model_provider_only"},
        {"instructions": "scripts take no instructions"},
        {"writablePaths": ["state/"]},
        {"executorKind": "agent", "instructions": "do it", "writablePaths": ["../escape"]},
    ],
)
def test_action_contract_policy_vocabularies_are_closed(overrides: dict) -> None:
    with pytest.raises(ValueError):
        ActionContract.from_dict(_contract(**overrides))


def test_agent_contract_defaults_and_digest_stability() -> None:
    agent = ActionContract.from_dict(_contract(executorKind="agent", instructions="Do the next action."))
    assert (agent.mutation_policy, agent.network_policy, agent.tool_policy, agent.action_class) == (
        "propose_only", "model_provider_only", "edit", "agent.edit-state",
    )
    assert agent.to_dict()["instructions"] == "Do the next action."
    script = ActionContract.from_dict(_contract())
    # Pre-existing script contracts keep their exact dict (and approval digests).
    assert "executorKind" not in script.to_dict()


def test_writable_policy_prefix_longest_match_protection_and_narrowing() -> None:
    policy = WritablePolicy.build(
        {"./": "instance", "vendor/": "template", "vendor/local.md": "instance"},
        protected=("PROJECT.md",), narrowing=(),
    )
    assert policy.allows("src/main.py")
    assert policy.allows("vendor/local.md")
    assert policy.refusal_reason("vendor/lib.py") == "not_instance_owned"
    assert policy.refusal_reason("PROJECT.md") == "protected_path"
    for path in (".git/config", ".stateport/managed-incarnation.json", ".statedd/lock.yaml", "sub/.git/hooks/x", ".GIT/config"):
        assert policy.refusal_reason(path) == "protected_path"
    narrowed = WritablePolicy.build({"./": "instance"}, narrowing=("state/", "NEXT.md"))
    assert narrowed.allows("state/x.yaml") and narrowed.allows("NEXT.md")
    assert narrowed.refusal_reason("other.md") == "outside_action_writable_paths"


# --------------------------------------------------------------------------- core loop


@needs_bwrap
def test_agent_action_becomes_one_reviewable_proposal_then_one_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    big_line = "report-" + "x" * 90
    big = (big_line + "\n") * 3_600

    def edit(workdir: Path) -> None:
        _edit_next_action(workdir)
        (workdir / "evidence/first-slice-001/report.txt").write_text(big)

    app, service, fake, root = _projectstate(tmp_path, monkeypatch, edit)
    actions = {item["actionId"]: item for item in service.action_list("project-one")}
    assert actions[NEXT_ACTION]["executorKind"] == "agent"
    assert actions[NEXT_ACTION]["engineIds"] == ["agent-sandbox"]
    assert actions[CHECK]["isEvaluator"] is True
    before_git = _git(root, "rev-parse", "HEAD")
    before_bytes = (root / "STATE.yaml").read_bytes()

    prepared = service.prepare("project-one", NEXT_ACTION, "synthetic", {})["run"]
    spec = prepared["runSpec"]
    assert spec["objective"] == actions[NEXT_ACTION]["instructions"]
    assert spec["benchmarkConfiguration"]["inputsDigest"] == digest({})
    assert spec["benchmarkConfiguration"]["routeDigest"] == prepared["agentRoute"]["digest"]
    assert prepared["engine"]["engineId"] == "agent-sandbox"
    assert prepared["agentRoute"]["model"] == "opencode/test-free"
    with pytest.raises(PortableExecutionError):
        service.execute(prepared["runId"])
    service.approve_run(prepared["runId"])
    run = service.execute(prepared["runId"])["run"]

    assert fake.calls and fake.calls[0]["workdir"] != root
    prompt = fake.calls[0]["prompt"]
    assert prompt.startswith(actions[NEXT_ACTION]["instructions"].strip())
    assert "Inputs from the owner" in prompt
    never = prompt.split("Never change: ", 1)[1].split("\n", 1)[0]
    assert "PROJECT.md" in never and ".git/" in never and "scripts/projectstate_gate.py" in never
    assert run["status"] == "state_change_proposed"
    assert (root / "STATE.yaml").read_bytes() == before_bytes  # nothing reached canonical state
    proposal = run["proposal"]
    assert proposal["formatVersion"] == "stateport.file-change-proposal/v1"
    assert proposal["kind"] == "files"
    assert proposal["preStateDigest"] == run["canonicalStateBefore"]
    assert proposal["baseGit"] == before_git
    changes = {item["path"]: item for item in proposal["files"]}
    assert set(changes) == {"STATE.yaml", "demo.py", "notes/plan.md", "evidence/first-slice-001/report.txt"}
    assert changes["STATE.yaml"]["change"] == "modified"
    assert changes["STATE.yaml"]["additions"] == 1 and changes["STATE.yaml"]["deletions"] == 1
    assert changes["notes/plan.md"]["change"] == "added"
    assert proposal["directories"]["added"] == ["notes"]
    assert '+next_action: "Run python3 demo.py and record the result."' in proposal["patch"]
    assert proposal["patchTruncated"] is True  # the 350 KiB report exceeds the patch bound
    assert run["proposalPaths"] == sorted(changes)
    # Content is stored content-addressed beside the run, never inline in the store.
    store_text = (app.layout.operations_root / "portable-runs.json").read_text()
    assert big_line not in store_text
    report = next(item for item in proposal["operations"] if item["path"].endswith("report.txt"))
    blob = service.blob_root / run["runId"] / report["blobRef"]
    assert blob.read_text() == big and report["contentDigest"] == digest(big.encode())
    # The evaluator ran on the base and on the candidate.
    evaluator = proposal["evaluator"]
    assert evaluator["actionId"] == CHECK
    assert evaluator["before"]["verdict"] == "not_yet"
    assert evaluator["after"]["verdict"] == "not_yet"
    assert evaluator["before"]["execution"] == "host_process_unsandboxed"
    assert any("primary journey is not_run" in item for item in evaluator["after"]["findings"])
    assert proposal["producer"]["route"]["model"] == "opencode/test-free"
    assert run["result"]["agent"]["usage"] == {"input": 120, "output": 40}

    approved = service.approve_proposal(run["runId"])
    assert approved["proposalApproval"]["proposalKind"] == "files"
    applied = service.apply_proposal(run["runId"])["run"]
    assert applied["status"] == "applied" and applied["lifecycleState"] == "CLOSED"
    head = _git(root, "rev-parse", "HEAD")
    assert head != before_git
    assert _git(root, "rev-parse", "HEAD^") == before_git
    assert _git(root, "log", "-1", "--format=%an") == "StatePort"
    message = _git(root, "log", "-1", "--format=%B")
    assert NEXT_ACTION in message and run["runId"] in message and run["proposalDigest"] in message
    assert sorted(_git(root, "show", "--name-only", "--format=", "HEAD").splitlines()) == sorted(changes)
    assert _git(root, "status", "--porcelain") == ""
    receipt = applied["receipt"]
    assert receipt["finalGit"] == head and receipt["commit"]["sha"] == head
    assert receipt["commit"]["parent"] == before_git
    assert applied["applyTransaction"]["finalGit"] == head
    assert applied["postApplyValidation"]["status"] == "passed"
    assert (root / "evidence/first-slice-001/report.txt").read_text() == big
    assert "Run python3 demo.py" in (root / "STATE.yaml").read_text()
    closure = service.closure_receipts("project-one")
    assert [item["finalGit"] for item in closure] == [head]
    assert not (service.blob_root / run["runId"]).exists()

    # The next run starts from the committed state.
    again = service.prepare("project-one", CHECK, "synthetic", {})["run"]
    assert again["baseGit"] == head


@needs_bwrap
@pytest.mark.parametrize(
    "target, code",
    [
        ("PROJECT.md", "protected_path"),
        (".stateport/managed-incarnation.json", "protected_path"),
        ("scripts/projectstate_gate.py", "protected_path"),
        ("sub/.git/config", "protected_path"),
    ],
)
def test_agent_change_outside_the_writable_set_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str, code: str,
) -> None:
    def edit(workdir: Path) -> None:
        _edit_next_action(workdir)
        path = workdir / target
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("changed by the model\n")

    _app_, service, _fake, root = _projectstate(tmp_path, monkeypatch, edit)
    before = {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}
    prepared = service.prepare("project-one", NEXT_ACTION, "agent-sandbox", {})["run"]
    service.approve_run(prepared["runId"])
    with pytest.raises(GovernedRefusalError) as refused:
        service.execute(prepared["runId"])
    assert refused.value.cause_code == code
    run = service.inspect(prepared["runId"])["run"]
    assert run["status"] == "result_rejected"
    assert target in run["stateChangeRefusal"]["paths"]
    assert {path: path.read_bytes() for path in root.rglob("*") if path.is_file()} == before
    assert not (service.blob_root / prepared["runId"]).exists()


def test_git_metadata_changes_by_the_agent_are_ignored_not_proposed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def edit(workdir: Path) -> None:
        _edit_next_action(workdir)
        (workdir / ".git/description").write_text("the model touched git metadata\n")

    _app_, service, _fake, _root = _projectstate(tmp_path, monkeypatch, edit)
    run = _run(service, "project-one", NEXT_ACTION)
    assert run["status"] == "state_change_proposed"
    assert not any(path.startswith(".git") for path in run["proposalPaths"])
    assert run["proposal"]["stats"]["gitMetadataChangesIgnored"] == 1


def test_oversize_change_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def edit(workdir: Path) -> None:
        (workdir / "evidence/big.bin").write_bytes(b"x" * 5000)

    _app_, service, _fake, _root = _projectstate(tmp_path, monkeypatch, edit)
    service.file_change_limits = FileChangeLimits(max_total_bytes=1000)
    prepared = service.prepare("project-one", NEXT_ACTION, "agent-sandbox", {})["run"]
    service.approve_run(prepared["runId"])
    with pytest.raises(GovernedRefusalError) as refused:
        service.execute(prepared["runId"])
    assert refused.value.cause_code == "change_too_large"
    assert service.inspect(prepared["runId"])["run"]["status"] == "result_rejected"


def test_no_change_closes_without_a_proposal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _app_, service, _fake, _root = _projectstate(tmp_path, monkeypatch, lambda _workdir: None)
    run = _run(service, "project-one", NEXT_ACTION)
    assert run["lifecycleState"] == "CLOSED" and run["proposal"] is None
    assert run["result"]["evaluator"]["before"]["verdict"] == "not_yet"


@needs_bwrap
def test_evaluator_invalid_after_shows_in_proposal_and_validation_blocks_apply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def edit(workdir: Path) -> None:
        state = workdir / "STATE.yaml"
        state.write_text(state.read_text().replace("status: planned", "status: wishful"))

    _app_, service, _fake, root = _projectstate(tmp_path, monkeypatch, edit)
    run = _run(service, "project-one", NEXT_ACTION)
    evaluator = run["proposal"]["evaluator"]
    assert (evaluator["before"]["verdict"], evaluator["after"]["verdict"]) == ("not_yet", "invalid")
    before = (root / "STATE.yaml").read_bytes()
    head = _git(root, "rev-parse", "HEAD")
    service.approve_proposal(run["runId"])
    with pytest.raises(PortableExecutionError, match="post-apply validation failed"):
        service.apply_proposal(run["runId"])
    failed = service.inspect(run["runId"])["run"]
    assert failed["status"] == "apply_failed" and failed["rollback"]["byteIdentical"] is True
    assert (root / "STATE.yaml").read_bytes() == before
    assert _git(root, "rev-parse", "HEAD") == head
    # The rollback touched nothing it did not have to: the managed instance
    # keeps its incarnation identity and stays usable.
    assert _app_.catalog.get("project-one")["pathState"] == "present"
    service.prepare("project-one", CHECK, "synthetic", {})


@needs_bwrap
def test_stale_base_voids_the_proposal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _app_, service, _fake, root = _projectstate(tmp_path, monkeypatch, _edit_next_action)
    run = _run(service, "project-one", NEXT_ACTION)
    service.approve_proposal(run["runId"])
    (root / "README.md").write_text("# Edited by the owner meanwhile\n")
    with pytest.raises(GovernedRefusalError) as refused:
        service.apply_proposal(run["runId"])
    assert refused.value.cause_code == "proposal_stale"
    assert (root / "README.md").read_text() == "# Edited by the owner meanwhile\n"
    assert "Write demo.py" in (root / "STATE.yaml").read_text()


def test_route_is_bound_by_the_approval(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _app_, service, fake, _root = _projectstate(tmp_path, monkeypatch, _edit_next_action)
    prepared = service.prepare("project-one", NEXT_ACTION, "agent-sandbox", {})["run"]
    approved = service.approve_run(prepared["runId"])
    assert approved["approval"]["routeDigest"] == prepared["agentRoute"]["digest"]
    other = agent_sandbox.SandboxRoute(
        harness="opencode", harness_binary=Path("/usr/bin/opencode"), model="opencode/other-free",
        allow_hosts=("opencode.ai",), credential_file=None, tools="edit",
    )
    service.agent_route_resolver = lambda _action_class: other
    with pytest.raises(WorkerRefusedError) as refused:
        service.execute(prepared["runId"])
    assert refused.value.cause_code == "route_changed"
    assert fake.calls == []


def test_missing_route_or_sandbox_gates_preparation_durably(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, service, _fake, _root = _projectstate(tmp_path, monkeypatch, _edit_next_action)
    service.agent_route_resolver = lambda _action_class: RouteRefusal("route_not_configured", "No model route.")
    with pytest.raises(EnvironmentGatedExecution) as gated:
        service.prepare("project-one", NEXT_ACTION, "agent-sandbox", {})
    assert gated.value.payload["executionGate"]["code"] == "route_not_configured"
    assert gated.value.payload["run"]["lifecycleState"] == "BLOCKED_CAPABILITY"
    # The shipped modules, unbound (no model routes in this process): the route binding
    # refuses typed, and preparation is gated by whichever boundary is missing first here.
    product = PortableExecutionService(app, ROOT)
    assert resolve_agent_route("agent.edit-state").code == "route_not_configured"
    with pytest.raises(EnvironmentGatedExecution) as stubbed:
        product.prepare("project-one", NEXT_ACTION, "agent-sandbox", {})
    sandbox_ok, _reason = agent_sandbox.sandbox_available()
    expected = "route_not_configured" if sandbox_ok else "sandbox_unavailable"
    assert stubbed.value.payload["executionGate"]["code"] == expected
    engines = {item["engineId"]: item for item in product.engines()}
    assert engines["agent-sandbox"]["availability"] == "environment_gated"
    with pytest.raises(GovernedRefusalError):
        service.prepare("project-one", NEXT_ACTION, "codex", {})
    with pytest.raises(GovernedRefusalError):
        service.prepare("project-one", CHECK, "agent-sandbox", {})


def test_route_binding_refuses_typed_when_it_is_not_configured_consented_or_measured() -> None:
    """The runtime's route seam, unbound: a typed refusal and never a guessed model.

    The consented / measured / class matrix of the real binding is proven in
    scripts/test_model_routes.py::test_resolve_agent_route_typed_refusals_and_sandbox_route.
    """

    refusal = resolve_agent_route("agent.edit-state")
    assert refusal.code == "route_not_configured"
    assert not isinstance(refusal, agent_sandbox.SandboxRoute)
    assert resolve_agent_route("agent.something-else").code == "route_not_configured"


def test_check_action_runs_the_pinned_gate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _app_, service, _fake, root = _projectstate(tmp_path, monkeypatch, lambda _workdir: None)
    prepared = service.prepare("project-one", CHECK, "synthetic", {})["run"]
    service.approve_run(prepared["runId"])
    run = service.execute(prepared["runId"])["run"]
    assert run["lifecycleState"] == "CLOSED"
    assert run["result"]["verdict"] == "not_yet"
    assert run["result"]["evaluator"]["gateRelease"] == "6.4.0"
    assert any("primary journey" in item for item in run["result"]["findings"])
    # The instance's own (editable) gate copy is never what judges it.
    assert (root / "scripts/projectstate_gate.py").read_text() == "raise SystemExit(0)\n"


def test_pinned_gate_hash_is_recorded() -> None:
    script = (ROOT / "fixtures/template-adapters/scripts/template_actions.py").read_text()
    gate = (ROOT / "fixtures/template-adapters/scripts/projectstate_gate.py").read_bytes()
    assert digest(gate)[7:] in script
    assert 'RELEASE = "6.4.0"' in gate.decode()


# --------------------------------------------------------------------------- setup actions


@needs_bwrap
def test_setup_project_inputs_are_validated_bound_and_may_write_the_outcome(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def edit(workdir: Path) -> None:
        (workdir / "PROJECT.md").write_text(
            "# Garden log\n\n## User\n\nA home gardener.\n\n## Outcome\n\nEvery watering is logged.\n\n"
            "## Scope\n\nto be decided by the owner\n\n## Non-goals\n\nto be decided by the owner\n\n"
            "## Durable constraints\n\nto be decided by the owner\n",
        )
        readme = workdir / "README.md"
        readme.write_text("# Garden log\n\nA watering log.\n")

    _app_, service, _fake, root = _projectstate(tmp_path, monkeypatch, edit)
    for bad in ({}, {"project": "x" * 121, "user": "u", "outcome": "o"}, {"project": "p", "user": "u", "outcome": "o", "extra": 1}):
        with pytest.raises(PortableExecutionError):
            service.prepare("project-one", SETUP_PROJECT, "agent-sandbox", bad)
    inputs = {"project": "Garden log", "user": "A home gardener", "outcome": "Every watering is logged."}
    prepared = service.prepare("project-one", SETUP_PROJECT, "agent-sandbox", inputs)["run"]
    assert prepared["runSpec"]["benchmarkConfiguration"]["inputsDigest"] == digest(inputs)
    approved = service.approve_run(prepared["runId"])
    assert approved["approval"]["inputsDigest"] == digest(inputs)
    run = service.execute(prepared["runId"])["run"]
    assert set(run["proposalPaths"]) == {"PROJECT.md", "README.md"}
    service.approve_proposal(run["runId"])
    service.apply_proposal(run["runId"])
    assert (root / "PROJECT.md").read_text().startswith("# Garden log")


def test_setup_project_cannot_touch_agents_md_and_next_action_cannot_touch_the_outcome(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def edit(workdir: Path) -> None:
        (workdir / "AGENTS.md").write_text("# rewritten\n")

    _app_, service, _fake, _root = _projectstate(tmp_path, monkeypatch, edit)
    prepared = service.prepare(
        "project-one", SETUP_PROJECT, "agent-sandbox", {"project": "p", "user": "u", "outcome": "o"},
    )["run"]
    service.approve_run(prepared["runId"])
    with pytest.raises(GovernedRefusalError) as refused:
        service.execute(prepared["runId"])
    assert refused.value.cause_code == "outside_action_writable_paths"


def test_studystate_setup_may_change_the_mode_but_session_planning_may_not(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, sources = _app(tmp_path, monkeypatch)
    _import(app, _studystate_repository(sources / "study"), sources, "study-one")

    def setup(workdir: Path) -> None:
        (workdir / "state/STUDYDD_MODE.yaml").write_text("mode: learner_instance\npersonalized: true\npublic_safe: false\n")
        (workdir / "state/STUDY_STATE.yaml").write_text(
            "learner: {name: to be decided by the owner}\nactive_target_id: first-goal\ntargets: []\n"
            "workflow: {stage: study}\n"
        )
        (workdir / "targets/first-goal").mkdir()
        (workdir / "targets/first-goal/TARGET.yaml").write_text("id: first-goal\ntitle: Pass the exam\n")

    service, _fake = _service(app, setup)
    run = _run(service, "study-one", "stateport.template.studystate.setup-study/v1", {"goal": "Pass the exam", "deadline": "2027-01-31"})
    assert set(run["proposalPaths"]) == {"state/STUDYDD_MODE.yaml", "state/STUDY_STATE.yaml", "targets/first-goal/TARGET.yaml"}
    evaluator = run["proposal"]["evaluator"]
    assert evaluator["before"]["verdict"] == "passed" and evaluator["after"]["verdict"] == "passed"
    with pytest.raises(PortableExecutionError, match="date"):
        service.prepare("study-one", "stateport.template.studystate.setup-study/v1", "agent-sandbox", {"goal": "g", "deadline": "soon"})

    def plan(workdir: Path) -> None:
        (workdir / "state/STUDYDD_MODE.yaml").write_text("mode: bootstrap\n")

    service.agent_sandbox = FakeSandbox(plan)
    prepared = service.prepare("study-one", "stateport.template.studystate.plan-next-session/v1", "agent-sandbox", {})["run"]
    service.approve_run(prepared["runId"])
    with pytest.raises(GovernedRefusalError) as refused:
        service.execute(prepared["runId"])
    assert refused.value.cause_code == "protected_path"


# --------------------------------------------------------------------------- integrity


def test_a_script_cannot_smuggle_a_file_change_proposal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    service = PortableExecutionService(app, ROOT)
    service.install_fixture_instance("checklistdd", "smuggle")
    prepared = service.prepare("smuggle", "checklistdd.complete-item/v1", "synthetic", {"itemId": "first-item"})
    run_id = prepared["run"]["runId"]
    service.approve_run(run_id)
    real = service._execute_in_staging

    def forged(*args, **kwargs):
        result, events, process = real(*args, **kwargs)
        result["stateChangeProposals"] = [{
            "formatVersion": "stateport.file-change-proposal/v1", "kind": "files", "proposalId": "p",
            "operations": [{"operation": "write", "path": "state/CHECKLIST.yaml"}],
        }]
        return result, events, process

    monkeypatch.setattr(service, "_execute_in_staging", forged)
    with pytest.raises(PortableExecutionError, match="producer"):
        service.execute(run_id)
    assert service.inspect(run_id)["run"]["status"] == "result_rejected"


# --------------------------------------------------------------------------- imported native applications


@needs_bwrap
def test_imported_native_application_actions_need_the_reviewed_digest_and_a_sandbox(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, sources = _app(tmp_path, monkeypatch)
    source = _native_repository(sources / "tinylist")
    inspector = RepositoryInspector(RepositorySourcePolicy(app.layout))
    inspected = inspector.inspect_local(source, root=sources) | {"candidateId": _candidate_id(source, sources)}
    review = inspected["template"]["capabilityReview"]
    listed = {item["actionId"]: item for item in review["actions"]}
    assert set(listed) == {"tinylist.check/v1", "tinylist.add-item/v1"}
    assert listed["tinylist.add-item/v1"]["mutationPolicy"] == "propose_only"
    assert listed["tinylist.add-item/v1"]["networkPolicy"] == "disabled"
    assert listed["tinylist.add-item/v1"]["timeoutSeconds"] == 20
    assert listed["tinylist.add-item/v1"]["executor"]["sha256"] == digest((source / "scripts/tinylist.py").read_bytes())
    assert review["evaluatorAction"] == "tinylist.check/v1"
    assert review["validationCommand"].startswith("python3 scripts/tinylist.py")
    plan = app.plan_template_import(inspected, candidate_id=inspected["candidateId"], instance_id="tiny", name="Tiny")
    assert plan["template"]["capabilityReview"]["reviewDigest"] == review["reviewDigest"]
    tampered = json.loads(json.dumps(plan))
    tampered["template"]["capabilityReview"]["actions"][1]["networkPolicy"] = "model_provider_only"
    with pytest.raises(Exception):
        app.install_template(
            tampered, {"decision": "approve", "actorId": "local-user", "planDigest": plan["planDigest"]},
            source_root=source, current_inspection=inspected, actor_id="local-user",
        )
    app.install_template(
        plan, {"decision": "approve", "actorId": "local-user", "planDigest": plan["planDigest"]},
        source_root=source, current_inspection=inspected, actor_id="local-user",
    )
    service = PortableExecutionService(app, ROOT)
    actions = {item["actionId"]: item for item in service.action_list("tiny")}
    assert {"tinylist.check/v1", "tinylist.add-item/v1"} <= set(actions)
    assert actions["tinylist.add-item/v1"]["executorOrigin"] == "instance"
    assert actions["tinylist.check/v1"]["isEvaluator"] is True

    # Without any sandbox the imported script is refused, never run on the host: neither the
    # apply-shape bubblewrap nor the agent sandbox's check interface may be available.
    monkeypatch.setattr(portable_runtime, "probe_executable", lambda _name: None)
    monkeypatch.setattr(agent_sandbox, "sandbox_available", lambda: (False, "disabled for this test"))
    with pytest.raises(EnvironmentGatedExecution) as gated:
        service.prepare("tiny", "tinylist.add-item/v1", "synthetic", {})
    assert gated.value.payload["executionGate"]["code"] == "sandbox_required"
    monkeypatch.undo()
    monkeypatch.setenv("STATEPORT_REPOSITORY_ROOTS", str(sources))

    _entry, root = app._entry("tiny")
    prepared = service.prepare("tiny", "tinylist.add-item/v1", "synthetic", {})["run"]
    assert prepared["capabilityReviewDigest"] == review["reviewDigest"]
    service.approve_run(prepared["runId"])
    run = service.execute(prepared["runId"])["run"]
    assert run["result"]["sandbox"]["executionBoundary"] in {"stateport_bubblewrap", "agent_sandbox_check"}
    assert run["proposalPaths"] == ["state/LIST.yaml"]
    assert run["proposal"]["evaluator"]["before"]["verdict"] == "not_yet"
    assert run["proposal"]["evaluator"]["after"]["verdict"] == "passed"
    assert run["proposal"]["producer"]["kind"] == "instance_script"
    service.approve_proposal(run["runId"])
    applied = service.apply_proposal(run["runId"])["run"]
    assert applied["status"] == "applied"
    assert yaml.safe_load((root / "state/LIST.yaml").read_text()) == {"items": ["alpha", "beta"]}
    assert _git(root, "log", "-1", "--format=%an") == "StatePort"

    # Editing a reviewed script withdraws every reviewed action (fail closed).
    (root / "scripts/tinylist.py").write_text((root / "scripts/tinylist.py").read_text() + "\n# changed\n")
    assert "tinylist.add-item/v1" not in {item["actionId"] for item in service.action_list("tiny")}



def test_an_agent_action_stopped_by_the_free_usage_limit_says_so(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Measured 2026-10-22: OpenCode's anonymous free route answers "Free usage limit reached"; the person must see that."""
    from stateport_agent_harness import FakeSandbox, import_projectstate
    from stateport_portable_execution.runtime import WorkerRefusedError

    class LimitedSandbox(FakeSandbox):
        def run_in_sandbox(self, **kwargs):
            result = super().run_in_sandbox(**kwargs)
            return result.__class__(**{**result.__dict__, "status": "failed", "exit_code": 1,
                                        "final_text": "[stderr]\nAI_APICallError: Free usage limit reached. Subscribe to OpenCode Go"})

    app, service, _fake, root = import_projectstate(tmp_path, monkeypatch, lambda workdir: None)
    service.agent_sandbox = LimitedSandbox(lambda workdir: None)
    before = (root / "STATE.yaml").read_bytes()
    prepared = service.prepare("project-one", NEXT_ACTION, "agent-sandbox", {})["run"]
    service.approve_run(prepared["runId"])
    with pytest.raises(WorkerRefusedError) as refused:
        service.execute(prepared["runId"])
    assert refused.value.cause_code == "free_usage_limit"
    assert "free usage limit" in str(refused.value)
    record = service.store.get(prepared["runId"])
    assert record["status"] == "failed" and "free usage limit" in record["diagnostic"]
    assert (root / "STATE.yaml").read_bytes() == before
