from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
for source_root in sorted((ROOT / "packages").glob("*/src")):
    sys.path.insert(0, str(source_root))

from stateport_persistent_app import AppError, LocalLayout, PersistentApp  # noqa: E402
from stateport_persistent_app.repository_import import (  # noqa: E402
    RepositoryInspector,
    RepositorySourcePolicy,
    _candidate_id,
)
from stateport_persistent_app.template_adapters import TemplateAdapterRegistry  # noqa: E402
from stateport_portable_execution import PortableExecutionService  # noqa: E402


def _git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    return result.stdout.strip()


def _commit(root: Path) -> None:
    _git(root, "init", "-q", "--initial-branch=main")
    _git(root, "config", "user.name", "Template fixture")
    _git(root, "config", "user.email", "template@example.invalid")
    _git(root, "add", "--all")
    _git(root, "commit", "-q", "-m", "template")


def _statespec_repository(root: Path) -> Path:
    root.mkdir()
    (root / "template.yaml").write_text(
        """apiVersion: statedd.stateport.io/v1alpha1
kind: Template
metadata:
  id: checklist-course
  name: Checklist Course
  version: 1.0.0
spec:
  domain: learning
  lifecycle: [draft, active]
  allowedActions: [{name: read_state, level: L0}]
  schemas: []
  agentContract:
    role: assistant
    responsibilities: [Inspect the template]
    forbiddenActions: [Execute untrusted repository commands]
""",
        encoding="utf-8",
    )
    (root / "README.md").write_text("# Checklist Course\n", encoding="utf-8")
    _commit(root)
    return root


def _inspection(
    inspector: RepositoryInspector,
    source: Path,
    allowlisted_root: Path,
) -> dict[str, object]:
    return inspector.inspect_local(source, root=allowlisted_root) | {
        "candidateId": _candidate_id(source, allowlisted_root)
    }


def _install(
    app: PersistentApp,
    inspected: dict[str, object],
    source: Path,
    instance_id: str,
) -> dict[str, object]:
    plan = app.plan_template_import(
        inspected,
        candidate_id=str(inspected["candidateId"]),
        instance_id=instance_id,
        name="Imported template",
    )
    return app.install_template(
        plan,
        {
            "decision": "approve",
            "actorId": "local-user",
            "planDigest": plan["planDigest"],
        },
        source_root=source,
        current_inspection=inspected,
        actor_id="local-user",
    )


def test_registry_recognizes_projectstate_studystate_and_native_templates(
    tmp_path: Path,
) -> None:
    registry = TemplateAdapterRegistry()
    project = tmp_path / "project"
    project.mkdir()
    (project / "PROJECT.md").write_text("# Outcome\n", encoding="utf-8")
    (project / "STATE.yaml").write_text(
        "version: projectstate-template-v6\nprofile: core\ncurrent_slice: {id: one}\n",
        encoding="utf-8",
    )
    assert registry.require(project)["adapterId"] == "projectstate-v6"

    study = tmp_path / "study"
    (study / "state").mkdir(parents=True)
    (study / "state/STUDYDD_MODE.yaml").write_text("mode: template\n", encoding="utf-8")
    (study / "state/STUDY_STATE.yaml").write_text(
        "targets: []\nworkflow: {stage: initialize}\n",
        encoding="utf-8",
    )
    assert registry.require(study)["adapterId"] == "studystate"

    native = _statespec_repository(tmp_path / "native")
    match = registry.require(native)
    assert match["adapterId"] == "statespec-template"
    assert match["applicationId"] == "stateport.template.generic"


def test_template_import_copies_only_the_committed_tree_and_runs_trusted_action(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sources = tmp_path / "sources"
    sources.mkdir()
    source = _statespec_repository(sources / "native")
    committed_readme = (source / "README.md").read_bytes()
    (source / "README.md").write_text("uncommitted private draft\n", encoding="utf-8")
    (source / "untracked-secret.txt").write_text("not imported\n", encoding="utf-8")

    monkeypatch.setenv("STATEPORT_REPOSITORY_ROOTS", str(sources))
    layout = LocalLayout(tmp_path / "config", tmp_path / "data", tmp_path / "state")
    layout.initialize()
    app = PersistentApp(layout)
    inspector = RepositoryInspector(RepositorySourcePolicy(layout))
    inspected = _inspection(inspector, source, sources)
    result = _install(app, inspected, source, "generic-template")

    managed = layout.instances_root / "generic-template"
    assert (source / "README.md").read_text(encoding="utf-8") == "uncommitted private draft\n"
    assert (managed / "README.md").read_bytes() == committed_readme
    assert not (managed / "untracked-secret.txt").exists()
    assert not (managed / ".git").samefile(source / ".git")
    assert result["sourceRepositoryMutated"] is False
    assert result["applicationId"] == "stateport.template.generic"

    execution = PortableExecutionService(app, ROOT)
    action_id = "stateport.template.generic.inspect/v1"
    assert [item["actionId"] for item in execution.action_list("generic-template")] == [
        action_id
    ]
    prepared = execution.prepare("generic-template", action_id, "synthetic", {})
    run = prepared["run"]
    approved = execution.approve_run(
        run["runId"],
        expected_instance_id="generic-template",
        expected_revision=run["revision"],
    )
    completed = execution.execute(
        run["runId"],
        expected_instance_id="generic-template",
        expected_revision=approved["revision"],
    )["run"]
    assert completed["result"]["summary"] == {
        "declaredTemplateId": "checklist-course",
        "declaredVersion": "1.0.0",
        "templateKind": "statespec_template",
    }
    assert completed["result"]["canonicalStateUnchanged"] is True

    reopened = PersistentApp(layout)
    assert reopened.catalog.get("generic-template")["pathState"] == "present"
    assert reopened.managed_template_binding(
        "generic-template",
        adapter_id="statespec-template",
        application_id="stateport.template.generic",
    )[1]["declaredTemplateId"] == "checklist-course"


def test_managed_incarnation_refuses_a_recreated_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sources = tmp_path / "sources"
    sources.mkdir()
    source = _statespec_repository(sources / "native")
    monkeypatch.setenv("STATEPORT_REPOSITORY_ROOTS", str(sources))
    layout = LocalLayout(tmp_path / "config", tmp_path / "data", tmp_path / "state")
    layout.initialize()
    app = PersistentApp(layout)
    inspector = RepositoryInspector(RepositorySourcePolicy(layout))
    _install(app, _inspection(inspector, source, sources), source, "generic-template")

    marker = layout.instances_root / "generic-template/.stateport/managed-incarnation.json"
    value = json.loads(marker.read_text(encoding="utf-8"))
    marker.unlink()
    marker.write_text(json.dumps(value), encoding="utf-8")

    assert app.catalog.get("generic-template")["pathState"] == "stale"
    with pytest.raises(AppError, match="unavailable or changed"):
        app.managed_template_binding(
            "generic-template",
            adapter_id="statespec-template",
            application_id="stateport.template.generic",
        )
