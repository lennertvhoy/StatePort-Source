"""Shared harness for the template-action (check | agent) journeys.

The model is replaced by a fake sandbox that edits the files in the workdir it
is given: the exact interface of ``docs/design/agent-sandbox.md``. Everything
else is the real product path -- template import, preparation, StatePort's own
diff and writable-path policy, the pinned ProjectState gate as evaluator,
StatePort's file-change writer under bubblewrap, the template validator and the
Git commit.

This module holds the fixtures only; the journeys themselves live in the test
files that own them (``test_agent_file_change_proposals.py``,
``test_portable_execution.py``, ``test_portable_apply_integrity.py``,
``test_template_import_lifecycle.py``).
"""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
# Appended, never prepended: the importing test file owns the front of
# sys.path, and this harness must not shadow a package it did not ask for.
for source_root in sorted((ROOT / "packages").glob("*/src")):
    if str(source_root) not in sys.path:
        sys.path.append(str(source_root))

from stateport_persistent_app import LocalLayout, PersistentApp  # noqa: E402
from stateport_persistent_app import agent_sandbox  # noqa: E402
from stateport_persistent_app.repository_import import (  # noqa: E402
    RepositoryInspector,
    RepositorySourcePolicy,
    _candidate_id,
)
from stateport_portable_execution.runtime import PortableExecutionService  # noqa: E402
from external_engine_runtime import probe_executable  # noqa: E402

NEXT_ACTION = "stateport.template.projectstate.next-action/v1"
SETUP_PROJECT = "stateport.template.projectstate.setup-project/v1"
CHECK = "stateport.template.projectstate.check/v1"
STUDY_SETUP = "stateport.template.studystate.setup-study/v1"
STUDY_PLAN = "stateport.template.studystate.plan-next-session/v1"

# The apply path writes inside bubblewrap; without it the journey is not run.
needs_bwrap = pytest.mark.skipif(
    probe_executable("bwrap") is None, reason="bubblewrap is required for apply"
)


def git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *arguments], check=True, text=True, stdout=subprocess.PIPE,
    ).stdout.strip()


def commit_repository(root: Path) -> None:
    git(root, "init", "-q", "--initial-branch=main")
    git(root, "config", "user.name", "Template fixture")
    git(root, "config", "user.email", "template@example.invalid")
    git(root, "add", "--all")
    git(root, "commit", "-q", "-m", "template")


def projectstate_repository(root: Path) -> Path:
    """A minimal but valid ProjectState v6 template repository."""

    root.mkdir(parents=True)
    (root / "PROJECT.md").write_text(
        "# Template project\n\n## User\n\nA template user.\n\n## Outcome\n\nThe template works.\n\n"
        "## Scope\n\nTemplate.\n\n## Non-goals\n\nNone.\n\n## Durable constraints\n\nNone.\n",
        encoding="utf-8",
    )
    (root / "AGENTS.md").write_text("# Agents\n\nFollow PROJECT.md.\n", encoding="utf-8")
    (root / "README.md").write_text("# Template project\n\nA ProjectState template.\n", encoding="utf-8")
    (root / "STATE.yaml").write_text(
        """version: "projectstate-template-v6"
profile: core
project:
  outcome_ref: "PROJECT.md#outcome"
current_slice:
  id: first-slice-001
  objective: "Make the demo work."
  status: planned
  acceptance:
    - "The demo command exits 0."
  primary_journey:
    description: "Run the demo."
    command: "python3 demo.py"
    environment: "local test"
    status: not_run
    evidence: "evidence/first-slice-001/summary.md"
validation:
  primary_journey: not_run
  automated_tests: not_run
  human_acceptance: pending
delivery_boundary:
  name: first_slice
  failed_attempts: []
  simplification_review: null
blockers: []
risks: []
next_action: "Write demo.py and run it."
""",
        encoding="utf-8",
    )
    (root / "evidence/first-slice-001").mkdir(parents=True)
    (root / "evidence/first-slice-001/summary.md").write_text(
        "# first-slice-001\n\n## Primary journey\n\nResult: not_run\n\n## Secondary checks\n\nNone.\n\n"
        "## Artifacts\n\nNone.\n\n## Limitations\n\nNot run yet.\n",
        encoding="utf-8",
    )
    (root / "scripts").mkdir()
    (root / "scripts/projectstate_gate.py").write_text("raise SystemExit(0)\n", encoding="utf-8")
    commit_repository(root)
    return root


def studystate_repository(root: Path) -> Path:
    """A minimal StudyState template repository."""

    (root / "state").mkdir(parents=True)
    (root / "state/STUDYDD_MODE.yaml").write_text(
        "mode: template\npersonalized: false\npublic_safe: true\n", encoding="utf-8",
    )
    (root / "state/STUDY_STATE.yaml").write_text(
        "learner: {name: ''}\nactive_target_id: ''\ntargets: []\nworkflow: {stage: initialize}\n",
        encoding="utf-8",
    )
    (root / "state/STUDYDD_TEMPLATE_VERSION.yaml").write_text("version: 0.12.0\n", encoding="utf-8")
    (root / "NEXT_ACTIONS.md").write_text("# NEXT_ACTIONS\n\n1. Initialize.\n", encoding="utf-8")
    (root / "targets").mkdir()
    (root / "targets/README.md").write_text("# Targets\n", encoding="utf-8")
    commit_repository(root)
    return root


def native_repository(root: Path) -> Path:
    """A third-party native application template (its own application.yaml)."""

    (root / "state").mkdir(parents=True)
    (root / "scripts").mkdir()
    (root / "state/LIST.yaml").write_text("items: [alpha]\n", encoding="utf-8")
    (root / "application.yaml").write_text(
        """formatVersion: stateport.application/v1
applicationId: tinylist
displayName: Tiny list
description: A third-party native application.
actionsPath: actions.yaml
executorCommand: scripts/tinylist.py
evaluatorAction: tinylist.check/v1
stateLayout:
  ownership:
    state/: instance
validationCommand: python3 scripts/tinylist.py --root . --action check --inputs '{}'
""",
        encoding="utf-8",
    )
    common = """    inputSchema: {type: object, additionalProperties: false}
    outputSchema: {type: object}
    contextPolicy: {id: tinylist.context/v1, includeCategories: [], excludeCategories: [credentials]}
    requiredCapabilities: [structuredEvents, nonInteractiveExecution]
    timeoutSeconds: 20
    budgetDefaults: {token: 100, costMinor: 0, timeSeconds: 20, steps: 1}
"""
    (root / "actions.yaml").write_text(
        "formatVersion: tinylist.actions/v1\nactions:\n"
        "  - formatVersion: tinylist.action/v1\n    id: tinylist.check/v1\n    displayName: Check list\n"
        "    purpose: Judge the list.\n    mutationPolicy: none\n    networkPolicy: disabled\n" + common
        + "  - formatVersion: tinylist.action/v1\n    id: tinylist.add-item/v1\n    displayName: Add item\n"
        "    purpose: Add one item.\n    mutationPolicy: propose_only\n    networkPolicy: disabled\n" + common,
        encoding="utf-8",
    )
    (root / "scripts/tinylist.py").write_text(
        """import argparse, json, pathlib
parser = argparse.ArgumentParser()
parser.add_argument('--root'); parser.add_argument('--action'); parser.add_argument('--inputs', default='{}')
args = parser.parse_args()
root = pathlib.Path(args.root)
path = root / 'state/LIST.yaml'
text = path.read_text()
if args.action == 'check':
    count = text.count(',') + 1
    print(json.dumps({'verdict': 'passed' if count >= 2 else 'not_yet', 'summary': f'{count} items', 'findings': []}))
elif args.action == 'add-item':
    path.write_text(text.replace(']', ', beta]'))
    print(json.dumps({'summary': 'added beta'}))
""",
        encoding="utf-8",
    )
    commit_repository(root)
    return root


def make_app(tmp_path: Path, monkeypatch) -> tuple[PersistentApp, Path]:
    sources = tmp_path / "sources"
    sources.mkdir(exist_ok=True)
    monkeypatch.setenv("STATEPORT_REPOSITORY_ROOTS", str(sources))
    monkeypatch.delenv("STATEPORT_AGENT_ROUTE", raising=False)
    monkeypatch.delenv("STATEPORT_AGENT_ROUTE_FILE", raising=False)
    layout = LocalLayout(tmp_path / "config", tmp_path / "data", tmp_path / "state")
    layout.initialize()
    return PersistentApp(layout), sources


def import_template(app: PersistentApp, source: Path, sources: Path, instance_id: str) -> dict:
    inspector = RepositoryInspector(RepositorySourcePolicy(app.layout))
    inspected = inspector.inspect_local(source, root=sources) | {"candidateId": _candidate_id(source, sources)}
    plan = app.plan_template_import(
        inspected, candidate_id=str(inspected["candidateId"]), instance_id=instance_id, name="Imported",
    )
    app.install_template(
        plan, {"decision": "approve", "actorId": "local-user", "planDigest": plan["planDigest"]},
        source_root=source, current_inspection=inspected, actor_id="local-user",
    )
    return plan


ROUTE = agent_sandbox.SandboxRoute(
    harness="opencode", harness_binary=Path("/usr/bin/opencode"), model="opencode/test-free",
    allow_hosts=("opencode.ai",), credential_file=None, tools="edit",
)


class FakeSandbox:
    """The agent-sandbox interface; the 'model' is a function that edits workdir."""

    SandboxRoute = agent_sandbox.SandboxRoute
    SandboxResult = agent_sandbox.SandboxResult

    def __init__(self, edit, *, status: str = "completed") -> None:
        self.edit = edit
        self.status = status
        self.calls: list[dict] = []

    def sandbox_available(self) -> tuple[bool, str]:
        return True, ""

    def run_in_sandbox(self, *, workdir, prompt, route, timeout_seconds=300, output_limit_bytes=1 << 20):
        self.calls.append({"workdir": Path(workdir), "prompt": prompt, "route": route, "timeout": timeout_seconds})
        self.edit(Path(workdir))
        return agent_sandbox.SandboxResult(
            status=self.status, refusal=None, exit_code=0, duration_seconds=0.2,
            final_text="Updated the next action.", events=4, tokens={"input": 120, "output": 40},
            egress=({"host": "opencode.ai", "port": 443, "allowed": True, "bytes_up": 10, "bytes_down": 20},),
            sandbox_digest="sha256:" + "1" * 64,
        )


def make_service(app: PersistentApp, edit, *, route=ROUTE) -> tuple[PortableExecutionService, FakeSandbox]:
    service = PortableExecutionService(app, ROOT)
    fake = FakeSandbox(edit)
    service.agent_sandbox = fake
    service.agent_route_resolver = lambda _action_class: route
    return service, fake


def import_projectstate(tmp_path: Path, monkeypatch, edit, instance_id: str = "project-one"):
    app, sources = make_app(tmp_path, monkeypatch)
    import_template(app, projectstate_repository(sources / "project"), sources, instance_id)
    service, fake = make_service(app, edit)
    _entry, root = app._entry(instance_id)
    return app, service, fake, root


def run_action(service: PortableExecutionService, instance_id: str, action_id: str, inputs: dict | None = None) -> dict:
    prepared = service.prepare(instance_id, action_id, "agent-sandbox", inputs or {})
    run_id = prepared["run"]["runId"]
    service.approve_run(run_id)
    return service.execute(run_id)["run"]


def edit_next_action(workdir: Path) -> None:
    """The change a model makes when it does the recorded next action."""

    state = workdir / "STATE.yaml"
    state.write_text(state.read_text().replace(
        'next_action: "Write demo.py and run it."', 'next_action: "Run python3 demo.py and record the result."',
    ))
    (workdir / "demo.py").write_text("print('demo')\n")
    (workdir / "notes").mkdir()
    (workdir / "notes/plan.md").write_text("# Plan\n\nRun the demo.\n")
