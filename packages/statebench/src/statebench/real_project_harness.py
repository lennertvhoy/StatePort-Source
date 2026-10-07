"""Deterministic medium-project fixture and synthetic workflow harness.

The harness uses local Git, a generated evaluator package outside the
candidate bundle, and fixed synthetic edits. It does not call a model,
provider, network service or background agent.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import textwrap
from typing import Any, Mapping

import yaml

from .evaluator import HELD_CONSTANT_CONFIGURATION
from .git_fixtures import GitBundleFixtureMaterializer, TemporaryBareRemote
from .real_project_models import (
    AttemptAccounting,
    AttemptTrace,
    BacklogDecisionTrace,
    ClosureTrace,
    ContextMetrics,
    DelegationTrace,
    EfficiencyMetrics,
    HandoffArtifact,
    HardOutcomes,
    HumanIntervention,
    OrchestrationMetrics,
    ParentJobAccounting,
    ProjectBootstrapTrace,
    ProjectMilestone,
    RealProjectCalibrationReport,
    RealProjectContractError,
    RealProjectMetrics,
    RealProjectRunResult,
    RealProjectScenario,
    RealProjectTrace,
    RealProjectWorkflowConfiguration,
    RepairTrace,
    ReviewTrace,
    SliceSelectionTrace,
    canonical_digest,
)


REAL_PROJECT_FIXTURE_FORMAT = "statebench.real-project-fixture/v1"
_FIXTURE_FILES = frozenset(
    {
        "README.md",
        "fixture.yaml",
        "operator-notes.txt",
        "public_tests/visible_check.py",
        "src/reference_app/__init__.py",
        "src/reference_app/api.py",
        "src/reference_app/cli.py",
        "src/reference_app/models.py",
        "src/reference_app/persistence.py",
        "src/reference_app/service.py",
        "src/reference_app/web.py",
    }
)
_EXPECTED_MODULES = (
    "reference_app.models",
    "reference_app.api",
    "reference_app.persistence",
    "reference_app.service",
    "reference_app.cli",
    "reference_app.web",
)
_STAGE_A_PATHS = (
    "src/reference_app/models.py",
    "src/reference_app/api.py",
)
_STAGE_B_PATHS = (
    "src/reference_app/__init__.py",
    "src/reference_app/persistence.py",
    "src/reference_app/service.py",
    "src/reference_app/cli.py",
    "src/reference_app/web.py",
)
_PRESERVED_NOTE = "operator-notes.txt"
_PRESERVED_DIRTY_CONTENT = "operator draft retained across both attempts\n"


def _dedent(value: str) -> str:
    return textwrap.dedent(value).lstrip()


_SOLUTION_FILES = {
    "src/reference_app/__init__.py": _dedent(
        '''
        """Public-safe reference task application."""

        from .models import Task, TaskDraft
        from .persistence import JsonTaskStore
        from .service import TaskService

        __all__ = ["JsonTaskStore", "Task", "TaskDraft", "TaskService"]
        '''
    ),
    "src/reference_app/models.py": _dedent(
        '''
        """Typed task records shared by every application surface."""

        from dataclasses import dataclass


        @dataclass(frozen=True)
        class TaskDraft:
            title: str

            def __post_init__(self) -> None:
                if not isinstance(self.title, str) or not self.title.strip():
                    raise ValueError("task title must be non-empty")


        @dataclass(frozen=True)
        class Task:
            task_id: str
            title: str
            created_index: int

            def to_dict(self) -> dict[str, object]:
                return {"taskId": self.task_id, "title": self.title, "createdIndex": self.created_index}
        '''
    ),
    "src/reference_app/api.py": _dedent(
        '''
        """Typed API boundary independent from CLI and web presentation."""

        from typing import Mapping

        from .models import Task, TaskDraft


        def normalize_title(value: str) -> str:
            if not isinstance(value, str):
                raise ValueError("task title must be text")
            return " ".join(value.split())


        def parse_task_payload(payload: Mapping[str, object]) -> TaskDraft:
            if set(payload) != {"title"}:
                raise ValueError("task payload must contain title only")
            title = normalize_title(payload["title"])
            return TaskDraft(title=title)


        def serialize_task(task: Task) -> dict[str, object]:
            return task.to_dict()
        '''
    ),
    "src/reference_app/persistence.py": _dedent(
        '''
        """Atomic local JSON persistence owned by the application."""

        import json
        import os
        from pathlib import Path

        from .models import Task, TaskDraft


        class JsonTaskStore:
            def __init__(self, path: Path) -> None:
                self._path = Path(path)
                if self._path.exists() and self._path.is_symlink():
                    raise ValueError("task database may not be a symlink")

            def list_tasks(self) -> list[Task]:
                if not self._path.exists():
                    return []
                value = json.loads(self._path.read_text(encoding="utf-8"))
                if not isinstance(value, list):
                    raise ValueError("task database must contain a list")
                tasks: list[Task] = []
                for item in value:
                    if not isinstance(item, dict) or set(item) != {"taskId", "title", "createdIndex"}:
                        raise ValueError("task database contains an invalid record")
                    tasks.append(Task(str(item["taskId"]), str(item["title"]), int(item["createdIndex"])))
                return tasks

            def append(self, draft: TaskDraft) -> Task:
                tasks = self.list_tasks()
                created_index = len(tasks) + 1
                task = Task(f"task-{created_index:04d}", draft.title, created_index)
                self._path.parent.mkdir(parents=True, exist_ok=True)
                temporary = self._path.with_name(f".{self._path.name}.tmp")
                temporary.write_text(
                    json.dumps([item.to_dict() for item in (*tasks, task)], sort_keys=True) + "\\n",
                    encoding="utf-8",
                )
                os.replace(temporary, self._path)
                return task
        '''
    ),
    "src/reference_app/service.py": _dedent(
        '''
        """Application service coordinating typed input and persistence."""

        from typing import Mapping

        from .api import parse_task_payload
        from .models import Task
        from .persistence import JsonTaskStore


        class TaskService:
            def __init__(self, store: JsonTaskStore) -> None:
                self._store = store

            def create_task(self, payload: Mapping[str, object]) -> Task:
                return self._store.append(parse_task_payload(payload))

            def list_tasks(self) -> list[Task]:
                return self._store.list_tasks()
        '''
    ),
    "src/reference_app/cli.py": _dedent(
        '''
        """Local CLI adapter over the application service."""

        import argparse
        import json
        from pathlib import Path

        from .persistence import JsonTaskStore
        from .service import TaskService


        def main(argv: list[str] | None = None) -> int:
            parser = argparse.ArgumentParser(prog="reference-task")
            parser.add_argument("--database", type=Path, required=True)
            subcommands = parser.add_subparsers(dest="command", required=True)
            add = subcommands.add_parser("add")
            add.add_argument("title")
            subcommands.add_parser("list")
            args = parser.parse_args(argv)
            service = TaskService(JsonTaskStore(args.database))
            if args.command == "add":
                print(json.dumps(service.create_task({"title": args.title}).to_dict(), sort_keys=True))
            else:
                print(json.dumps([task.to_dict() for task in service.list_tasks()], sort_keys=True))
            return 0


        if __name__ == "__main__":
            raise SystemExit(main())
        '''
    ),
    "src/reference_app/web.py": _dedent(
        '''
        """Small server-owned HTML presentation; no browser code injection."""

        from html import escape
        from typing import Iterable

        from .models import Task


        def render_dashboard(tasks: Iterable[Task]) -> str:
            rows = "".join(
                f'<li data-task-id="{escape(task.task_id, quote=True)}">{escape(task.title)}</li>'
                for task in tasks
            )
            return f"<main><h1>Tasks</h1><ul>{rows}</ul></main>"
        '''
    ),
}


_PROTECTED_EVALUATOR = _dedent(
    """
    import contextlib
    import io
    import json
    from pathlib import Path
    import sys
    import tempfile

    repository = Path(sys.argv[1]).resolve()
    sys.path.insert(0, str(repository / "src"))
    checks = {}
    details = {}
    try:
        from reference_app.api import parse_task_payload
        from reference_app.cli import main as cli_main
        from reference_app.persistence import JsonTaskStore
        from reference_app.service import TaskService
        from reference_app.web import render_dashboard

        checks["typed_api"] = parse_task_payload({"title": "  Durable   task "}).title == "Durable task"
        try:
            parse_task_payload({"title": "   "})
            checks["blank_rejected"] = False
        except ValueError:
            checks["blank_rejected"] = True
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "tasks.json"
            service = TaskService(JsonTaskStore(database))
            first = service.create_task({"title": "First"})
            second = service.create_task({"title": "<unsafe>"})
            reloaded = JsonTaskStore(database).list_tasks()
            checks["stable_ids"] = first.task_id == "task-0001" and second.task_id == "task-0002"
            checks["persistence_reload"] = [item.task_id for item in reloaded] == ["task-0001", "task-0002"]
            checks["atomic_cleanup"] = not (root / ".tasks.json.tmp").exists()
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                cli_status = cli_main(["--database", str(root / "cli.json"), "add", "CLI task"])
                list_status = cli_main(["--database", str(root / "cli.json"), "list"])
            lines = output.getvalue().splitlines()
            checks["cli_surface"] = cli_status == list_status == 0 and len(lines) == 2 and "CLI task" in lines[1]
            rendered = render_dashboard([first, second])
            checks["web_escape"] = "&lt;unsafe&gt;" in rendered and "<unsafe>" not in rendered
        sources = {
            name: (repository / "src" / "reference_app" / f"{name}.py").read_text(encoding="utf-8")
            for name in ("api", "persistence", "service", "cli", "web")
        }
        checks["architecture_layering"] = "from .persistence import JsonTaskStore" in sources["service"] and "from .service import TaskService" in sources["cli"] and "subprocess" not in "".join(sources.values())
    except Exception as error:
        details["errorClass"] = type(error).__name__
    passed = bool(checks) and all(checks.values()) and len(checks) == 8
    print(json.dumps({"formatVersion": "statebench.real-project-hidden-result/v1", "passed": passed, "checks": checks, "details": details}, sort_keys=True))
    raise SystemExit(0 if passed else 1)
    """
)


def _fixed_environment() -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "GIT_AUTHOR_NAME": "StateBench",
        "GIT_AUTHOR_EMAIL": "statebench@example.invalid",
        "GIT_COMMITTER_NAME": "StateBench",
        "GIT_COMMITTER_EMAIL": "statebench@example.invalid",
        "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+0000",
        "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+0000",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
    }


def _run(
    argv: list[str], *, cwd: Path | None = None, expected: tuple[int, ...] = (0,)
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        argv,
        cwd=cwd,
        env=_fixed_environment(),
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
        shell=False,
    )
    if completed.returncode not in expected:
        raise RealProjectContractError(
            f"deterministic command failed ({completed.returncode}): {completed.stderr[-1000:]}"
        )
    return completed


def _git(worktree: Path, *args: str) -> str:
    return _run(["git", "-C", str(worktree), *args]).stdout.strip()


def _sha_bytes(value: bytes) -> str:
    return "sha256:" + sha256(value).hexdigest()


def _sha_file(path: Path) -> str:
    return _sha_bytes(path.read_bytes())


def _tree_digest(root: Path) -> str:
    entries: list[dict[str, str]] = []
    for path in sorted(root.rglob("*")):
        if ".git" in path.relative_to(root).parts:
            continue
        if path.is_symlink():
            raise RealProjectContractError(
                "real-project fixture may not contain symlinks"
            )
        if path.is_file():
            entries.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "digest": _sha_file(path),
                }
            )
    return canonical_digest(entries)


def _atomic_write(root: Path, relative: str, content: str) -> None:
    resolved_root = root.resolve(strict=True)
    relative_path = Path(relative)
    if relative_path.is_absolute() or any(
        part in {"", ".", ".."} for part in relative_path.parts
    ):
        raise RealProjectContractError(
            "synthetic implementation path must be repository-relative"
        )
    destination = resolved_root / relative_path
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        destination.parent.resolve(strict=True).relative_to(resolved_root)
        destination.resolve(strict=False).relative_to(resolved_root)
    except ValueError as exc:
        raise RealProjectContractError(
            "synthetic implementation path escaped the fixture"
        ) from exc
    if destination.is_symlink():
        raise RealProjectContractError(
            "synthetic implementation path escaped the fixture"
        )
    temporary = destination.with_name(f".{destination.name}.statebench.tmp")
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, destination)


def _commit_paths(
    worktree: Path, message: str, paths: tuple[str, ...]
) -> tuple[str, str]:
    _run(["git", "-C", str(worktree), "add", "--", *paths])
    _run(["git", "-C", str(worktree), "commit", "-m", message])
    return _git(worktree, "rev-parse", "HEAD"), _git(
        worktree, "rev-parse", "HEAD^{tree}"
    )


def _public_test(worktree: Path) -> bool:
    code = (
        "import runpy,sys; "
        f"sys.path.insert(0,{str(worktree / 'src')!r}); "
        f"runpy.run_path({str(worktree / 'public_tests' / 'visible_check.py')!r},run_name='__main__')"
    )
    return (
        _run([sys.executable, "-c", code], cwd=worktree, expected=(0, 1)).returncode
        == 0
    )


def _protected_test(evaluator: Path, worktree: Path) -> tuple[bool, str]:
    completed = _run(
        [sys.executable, str(evaluator), str(worktree)],
        cwd=evaluator.parent,
        expected=(0, 1),
    )
    # I3: the protected evaluator is an internal CLI emitter/parser pair; parse
    # its last non-empty line through the single shared helper so the
    # emitter/parser contract cannot drift.  Lazy import keeps `import
    # statebench` usable without release-contracts on the path (the helper is
    # only needed when the harness actually runs the protected evaluator).
    from stateport_release import parse_last_line_json

    result = parse_last_line_json(completed.stdout)
    if not isinstance(result, dict):
        raise RealProjectContractError(
            "protected evaluator emitted invalid output"
        )
    if (
        set(result) != {"formatVersion", "passed", "checks", "details"}
        or result["formatVersion"] != "statebench.real-project-hidden-result/v1"
        or not isinstance(result["passed"], bool)
    ):
        raise RealProjectContractError("protected evaluator result shape is invalid")
    return result["passed"], canonical_digest(result)


def _strict_fixture_manifest(value: object) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "formatVersion",
        "identity",
        "project",
        "architecture",
        "backlog",
        "milestones",
        "feature",
    }:
        raise RealProjectContractError(
            "real-project fixture manifest has an invalid shape"
        )
    if value["formatVersion"] != REAL_PROJECT_FIXTURE_FORMAT:
        raise RealProjectContractError("real-project fixture version is unsupported")
    identity = value["identity"]
    project = value["project"]
    feature = value["feature"]
    if not isinstance(identity, Mapping) or set(identity) != {
        "id",
        "version",
        "privacyClassification",
        "productionEligible",
    }:
        raise RealProjectContractError("real-project fixture identity is invalid")
    if (
        identity["privacyClassification"] != "public_safe"
        or identity["productionEligible"] is not False
    ):
        raise RealProjectContractError(
            "real-project fixture must be public-safe and production-ineligible"
        )
    if (
        not isinstance(project, Mapping)
        or tuple(project.get("modules", ())) != _EXPECTED_MODULES
    ):
        raise RealProjectContractError(
            "real-project fixture must declare the expected module boundaries"
        )
    if not isinstance(feature, Mapping) or tuple(
        feature.get("allowedChangedPaths", ())
    ) != tuple((*_STAGE_B_PATHS[:1], *_STAGE_A_PATHS, *_STAGE_B_PATHS[1:])):
        raise RealProjectContractError("real-project fixture allowed paths drifted")
    if tuple(feature.get("preservedDirtyPaths", ())) != (_PRESERVED_NOTE,):
        raise RealProjectContractError(
            "real-project fixture preservation boundary drifted"
        )
    if not isinstance(value["backlog"], list) or len(value["backlog"]) != 3:
        raise RealProjectContractError(
            "real-project fixture needs a short strategic backlog"
        )
    if not isinstance(value["milestones"], list) or len(value["milestones"]) != 3:
        raise RealProjectContractError("real-project fixture needs three milestones")
    return value


@dataclass(frozen=True, slots=True)
class PreparedRealProjectFixture:
    scenario: RealProjectScenario
    repository_bundle: Path
    source_repository: Path
    protected_evaluator: Path
    allowed_changed_paths: tuple[str, ...]
    preserved_dirty_paths: tuple[str, ...]
    backlog_item_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.repository_bundle.is_file() or self.repository_bundle.is_symlink():
            raise RealProjectContractError("prepared repository bundle is unavailable")
        if not self.source_repository.is_dir() or self.source_repository.is_symlink():
            raise RealProjectContractError("prepared source repository is unavailable")
        if (
            not self.protected_evaluator.is_file()
            or self.protected_evaluator.is_symlink()
        ):
            raise RealProjectContractError("prepared evaluator is unavailable")


class RealProjectFixtureBuilder:
    """Materialize one reviewed public fixture and separated evaluator package."""

    def __init__(self, fixture_root: str | Path) -> None:
        self.fixture_root = Path(fixture_root)

    def materialize(self, destination: str | Path) -> PreparedRealProjectFixture:
        root = Path(destination)
        if root.exists() or root.is_symlink():
            raise RealProjectContractError(
                "real-project materialization destination must be new"
            )
        fixture = self.fixture_root
        if fixture.is_symlink() or not fixture.is_dir():
            raise RealProjectContractError("real-project source fixture is unavailable")
        actual_files = {
            path.relative_to(fixture).as_posix()
            for path in fixture.rglob("*")
            if path.is_file()
        }
        if actual_files != _FIXTURE_FILES or any(
            path.is_symlink() for path in fixture.rglob("*")
        ):
            raise RealProjectContractError("real-project fixture inventory drifted")
        try:
            value = yaml.safe_load(
                (fixture / "fixture.yaml").read_text(encoding="utf-8")
            )
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            raise RealProjectContractError(
                "real-project fixture manifest could not be loaded"
            ) from exc
        manifest = _strict_fixture_manifest(value)

        root.mkdir(parents=True)
        source = root / "source"
        shutil.copytree(fixture, source)
        _run(["git", "init", "--initial-branch=main", str(source)])
        _run(["git", "-C", str(source), "add", "."])
        _run(
            [
                "git",
                "-C",
                str(source),
                "commit",
                "-m",
                "public-safe real-project fixture",
            ]
        )
        initial_commit = _git(source, "rev-parse", "HEAD")
        initial_tree = _git(source, "rev-parse", "HEAD^{tree}")
        initial_state_digest = _tree_digest(source)

        public = root / "candidate-material"
        public.mkdir()
        bundle = public / "reference-task-service.bundle"
        _run(["git", "-C", str(source), "bundle", "create", str(bundle), "main"])
        _run(["git", "bundle", "verify", str(bundle)])

        protected = root / "protected-evaluator"
        protected.mkdir()
        evaluator = protected / "evaluate.py"
        evaluator.write_text(_PROTECTED_EVALUATOR, encoding="utf-8")
        evaluator_digest = _sha_file(evaluator)

        milestones = tuple(
            ProjectMilestone(
                milestone_id=str(item["id"]),
                objective=str(item["objective"]),
                acceptance=tuple(item["acceptance"]),
            )
            for item in manifest["milestones"]
        )
        identity = manifest["identity"]
        scenario = RealProjectScenario(
            scenario_id="project-scenario-reference-task-service",
            version=str(identity["version"]),
            fixture_digest=_tree_digest(fixture),
            repository_bundle_path=bundle.name,
            repository_bundle_digest=_sha_file(bundle),
            initial_state_digest=initial_state_digest,
            initial_commit=initial_commit,
            initial_tree=initial_tree,
            architecture_contract_digest=canonical_digest(manifest["architecture"]),
            backlog_digest=canonical_digest(manifest["backlog"]),
            project_modules=tuple(manifest["project"]["modules"]),
            milestones=milestones,
            execution_mode="agent_native",
            maximum_attempts=4,
            interruption_policy="forced_after_stage_a_checkpoint",
            human_approval_policy="synthetic_explicit_fixture_approval",
            hidden_test_id="statebench.hidden.reference-task-service.v1",
            evaluator_package_digest=evaluator_digest,
            invariant_checks=(
                "typed_api",
                "persistence_reload",
                "cli_surface",
                "web_escape",
                "architecture_layering",
            ),
            git_checks=(
                "functional_changes_committed",
                "remote_head_equal",
                "unrelated_dirty_work_preserved",
            ),
            handoff_checks=(
                "exact_base",
                "exact_final_commit",
                "exact_final_tree",
                "validation_digest",
                "review_digest",
            ),
        )
        return PreparedRealProjectFixture(
            scenario=scenario,
            repository_bundle=bundle,
            source_repository=source,
            protected_evaluator=evaluator,
            allowed_changed_paths=tuple(manifest["feature"]["allowedChangedPaths"]),
            preserved_dirty_paths=tuple(manifest["feature"]["preservedDirtyPaths"]),
            backlog_item_ids=tuple(str(item["id"]) for item in manifest["backlog"]),
        )


class SyntheticRealProjectHarness:
    """Run equal-config synthetic workflow strategies on isolated local Git copies."""

    def run_pair(
        self,
        prepared: PreparedRealProjectFixture,
        destination: str | Path,
    ) -> RealProjectCalibrationReport:
        root = Path(destination)
        if root.exists() or root.is_symlink():
            raise RealProjectContractError("paired run destination must be new")
        root.mkdir(parents=True)
        runs = tuple(
            self._run_strategy(prepared, root / strategy, strategy)
            for strategy in ("single_agent", "cto_orchestrated")
        )
        return RealProjectCalibrationReport(
            scenario=prepared.scenario,
            runs=runs,
            limitations=(
                "synthetic agents prove deterministic harness behavior only",
                "one public-safe fixture is not a representative development corpus",
                "no repeated real-model runs or confidence intervals were produced",
                "evaluator isolation is local process and filesystem separation not a secrecy claim",
                "model time tokens cached tokens monetary cost and wall-time comparisons are unavailable",
            ),
        )

    def _run_strategy(
        self,
        prepared: PreparedRealProjectFixture,
        root: Path,
        strategy: str,
    ) -> RealProjectRunResult:
        root.mkdir()
        worktree = root / "worktree"
        materialized = GitBundleFixtureMaterializer().materialize(
            prepared.repository_bundle,
            worktree,
            expected_origin=str(prepared.repository_bundle),
        )
        if (
            materialized.commit != prepared.scenario.initial_commit
            or materialized.tree != prepared.scenario.initial_tree
        ):
            raise RealProjectContractError("materialized real-project identity drifted")
        remote = TemporaryBareRemote.create(root / "origin.git")
        remote.attach_fresh_fixture(worktree)
        initial_remote = remote.push_branch(worktree, "main")
        if not initial_remote.equal:
            raise RealProjectContractError(
                "initial benchmark remote was not synchronized"
            )

        note = worktree / _PRESERVED_NOTE
        note.write_text(_PRESERVED_DIRTY_CONTENT, encoding="utf-8")
        unrelated_digest = _sha_file(note)
        if not _public_test(worktree):
            raise RealProjectContractError(
                "misleading visible-test fixture no longer passes initially"
            )
        initial_hidden, _ = _protected_test(prepared.protected_evaluator, worktree)
        if initial_hidden:
            raise RealProjectContractError(
                "visible-test trap no longer distinguishes incomplete behavior"
            )

        for relative in _STAGE_A_PATHS:
            _atomic_write(worktree, relative, _SOLUTION_FILES[relative])
        attempt_a_commit, attempt_a_tree = _commit_paths(
            worktree,
            "checkpoint: typed task boundary",
            _STAGE_A_PATHS,
        )
        stage_a_public = _public_test(worktree)
        stage_a_hidden, _ = _protected_test(prepared.protected_evaluator, worktree)
        if not stage_a_public or stage_a_hidden:
            if not stage_a_public:
                raise RealProjectContractError(
                    "stage-A public calibration check drifted"
                )
        attempt_a = AttemptAccounting(
            parent_job_id=f"real-project-{strategy}",
            attempt_id=f"{strategy}-attempt-a",
            ordinal=1,
            outcome="interrupted_checkpoint",
            success=False,
            tool_calls=4,
            terminal_commands=3,
            file_reads=4,
            file_writes=len(_STAGE_A_PATHS),
        )

        for relative in _STAGE_B_PATHS:
            _atomic_write(worktree, relative, _SOLUTION_FILES[relative])
        final_commit, final_tree = _commit_paths(
            worktree,
            "feat: complete durable task workflow",
            _STAGE_B_PATHS,
        )
        final_public = _public_test(worktree)
        final_hidden, hidden_digest = _protected_test(
            prepared.protected_evaluator, worktree
        )
        if not final_public or not final_hidden:
            raise RealProjectContractError(
                "synthetic continuation did not satisfy final checks"
            )
        attempt_b = AttemptAccounting(
            parent_job_id=f"real-project-{strategy}",
            attempt_id=f"{strategy}-attempt-b",
            ordinal=2,
            outcome="recovered_success",
            success=True,
            tool_calls=10,
            terminal_commands=8,
            file_reads=10,
            file_writes=len(_STAGE_B_PATHS),
        )
        accounting = ParentJobAccounting(
            parent_job_id=f"real-project-{strategy}",
            attempts=(attempt_a, attempt_b),
            first_attempt_success=False,
            eventual_success=True,
        )

        final_remote = remote.push_branch(worktree, "main")
        if not final_remote.equal or final_remote.remote_commit != final_commit:
            raise RealProjectContractError(
                "final benchmark branch did not close by fast-forward equality"
            )
        status = _run(
            [
                "git",
                "-C",
                str(worktree),
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ]
        ).stdout.rstrip("\n")
        if status != f" M {_PRESERVED_NOTE}" or _sha_file(note) != unrelated_digest:
            raise RealProjectContractError(
                f"unrelated dirty work was not preserved exactly: {status!r}"
            )

        review_worktree = root / "review-worktree"
        _run(["git", "clone", "--no-local", str(remote.path), str(review_worktree)])
        _run(["git", "-C", str(review_worktree), "switch", "--detach", final_commit])
        if _git(review_worktree, "status", "--porcelain=v1", "--untracked-files=all"):
            raise RealProjectContractError("independent review worktree is not clean")
        review_public = _public_test(review_worktree)
        review_hidden, review_hidden_digest = _protected_test(
            prepared.protected_evaluator, review_worktree
        )
        review_commit = _git(review_worktree, "rev-parse", "HEAD")
        review_tree = _git(review_worktree, "rev-parse", "HEAD^{tree}")
        if (
            not review_public
            or not review_hidden
            or review_commit != final_commit
            or review_tree != final_tree
        ):
            raise RealProjectContractError(
                "independent review did not accept the exact functional identity"
            )
        validation_digest = canonical_digest(
            {
                "public": final_public,
                "protected": final_hidden,
                "protectedDigest": hidden_digest,
                "reviewProtectedDigest": review_hidden_digest,
                "commit": final_commit,
                "tree": final_tree,
            }
        )

        implementer_profile = "synthetic-implementer-v1"
        reviewer_profile = "synthetic-independent-reviewer-v1"
        parent_job_id = f"real-project-{strategy}"
        workflow = RealProjectWorkflowConfiguration(
            strategy=strategy,
            scenario_digest=prepared.scenario.digest,
            runtime_configuration=HELD_CONSTANT_CONFIGURATION,
            model_profiles=(implementer_profile, reviewer_profile),
            evaluator_identity="statebench-real-project-evaluator-v1",
        )
        review = ReviewTrace(
            parent_job_id=parent_job_id,
            sequence=9,
            reviewer_profile=reviewer_profile,
            implementer_profile=implementer_profile,
            commit=review_commit,
            tree=review_tree,
            test_result_digest=validation_digest,
            scenario_digest=prepared.scenario.digest,
            disposition="accepted",
        )
        handoff = HandoffArtifact(
            handoff_id=f"handoff-{strategy}",
            parent_job_id=parent_job_id,
            scenario_digest=prepared.scenario.digest,
            workflow_strategy=strategy,
            base_commit=prepared.scenario.initial_commit,
            final_commit=final_commit,
            final_tree=final_tree,
            completed_milestones=tuple(
                item.milestone_id for item in prepared.scenario.milestones
            ),
            pending_work=(),
            decisions=(
                "preserve the typed service and persistence boundaries",
                "treat the visible test as non-authoritative",
                "stop after the approved synthetic scenario",
            ),
            risks=(
                "synthetic execution does not predict real model behavior",
                "one fixture cannot support scientific conclusions",
            ),
            validation_digest=validation_digest,
            review_digest=review.digest,
            unrelated_work_digest=unrelated_digest,
            next_action="Stop; real repeated model runs require a later approved corpus slice.",
        )
        receipt_digest = canonical_digest(
            {
                "parentJobId": parent_job_id,
                "scenarioDigest": prepared.scenario.digest,
                "finalCommit": final_commit,
                "finalTree": final_tree,
                "validationDigest": validation_digest,
                "reviewDigest": review.digest,
                "handoffDigest": handoff.digest,
            }
        )
        trace = RealProjectTrace(
            parent_job_id=parent_job_id,
            events=(
                ProjectBootstrapTrace(
                    parent_job_id,
                    1,
                    prepared.scenario.digest,
                    prepared.scenario.initial_commit,
                    prepared.scenario.initial_tree,
                ),
                BacklogDecisionTrace(
                    parent_job_id,
                    2,
                    "RP-001",
                    prepared.backlog_item_ids,
                    "dependency_root_first",
                ),
                SliceSelectionTrace(
                    parent_job_id,
                    3,
                    "slice-durable-task-workflow",
                    tuple(item.milestone_id for item in prepared.scenario.milestones),
                    prepared.allowed_changed_paths,
                    prepared.preserved_dirty_paths,
                    "synthetic-explicit-approval-v1",
                ),
                DelegationTrace(
                    parent_job_id,
                    4,
                    strategy,
                    implementer_profile,
                    reviewer_profile,
                    "none" if strategy == "single_agent" else "bounded_plan",
                ),
                AttemptTrace(
                    parent_job_id,
                    5,
                    attempt_a.attempt_id,
                    1,
                    attempt_a.outcome,
                    attempt_a_commit,
                    attempt_a_tree,
                    stage_a_public,
                    stage_a_hidden,
                ),
                HumanIntervention(
                    parent_job_id,
                    6,
                    f"interrupt-{strategy}",
                    "synthetic_forced_interruption",
                    "forced after the durable Stage-A checkpoint",
                ),
                RepairTrace(
                    parent_job_id,
                    7,
                    attempt_a.attempt_id,
                    attempt_b.attempt_id,
                    "visible_test_insufficient_after_interruption",
                    _STAGE_B_PATHS,
                ),
                AttemptTrace(
                    parent_job_id,
                    8,
                    attempt_b.attempt_id,
                    2,
                    attempt_b.outcome,
                    final_commit,
                    final_tree,
                    final_public,
                    final_hidden,
                ),
                review,
                ClosureTrace(
                    parent_job_id,
                    10,
                    final_commit,
                    final_tree,
                    final_remote.remote_commit or "",
                    final_remote.equal,
                    True,
                    handoff.digest,
                    receipt_digest,
                ),
            ),
        )
        totals = accounting.to_dict()["totals"]
        metrics = RealProjectMetrics(
            hard_outcomes=HardOutcomes(
                final_functional_success=True,
                milestone_completion=tuple(True for _ in prepared.scenario.milestones),
                critical_violation_count=0,
                architecture_invariants_passed=True,
                state_integrity_passed=True,
                git_closure_passed=True,
                handoff_truth_passed=True,
                first_attempt_success=accounting.first_attempt_success,
                eventual_success=accounting.eventual_success,
            ),
            efficiency=EfficiencyMetrics(
                total_wall_time_ms=None,
                active_model_time_ms=totals["activeModelTimeMs"],
                input_tokens=totals["inputTokens"],
                output_tokens=totals["outputTokens"],
                cached_tokens=totals["cachedTokens"],
                monetary_cost_minor=totals["monetaryCostMinor"],
                tool_calls=totals["toolCalls"],
                terminal_commands=totals["terminalCommands"],
                file_reads=totals["fileReads"],
                repeated_reads=2,
                failed_attempts=1,
                retries=1,
                model_escalations=0,
                context_compilations=1,
                compactions=0,
                handoffs=1,
            ),
            orchestration=OrchestrationMetrics(
                backlog_selection_precision=None,
                unnecessary_task_generation=0,
                dependency_order_violations=0,
                duplicated_subagent_work=0,
                rejected_subagent_output=0,
                reviewer_findings=0,
                human_corrections=0,
                false_closure_attempts=0,
                preserved_unrelated_work=True,
                time_to_correct_next_action_ms=None,
            ),
            context=ContextMetrics(
                statepack_size_bytes=None,
                relevant_evidence_items=6,
                missing_authoritative_sources=0,
                irrelevant_context_ratio=None,
                compression_events=0,
                handoff_quality_checks_passed=len(prepared.scenario.handoff_checks),
                reconstruction_cost_tokens=None,
            ),
        )
        return RealProjectRunResult(
            parent_job_id=parent_job_id,
            scenario_digest=prepared.scenario.digest,
            workflow=workflow,
            trace=trace,
            accounting=accounting,
            metrics=metrics,
            handoff=handoff,
            final_commit=final_commit,
            final_tree=final_tree,
            receipt_digest=receipt_digest,
        )


def generate_real_project_calibration(
    fixture_root: str | Path,
    destination: str | Path,
) -> RealProjectCalibrationReport:
    """Convenience entry point for one deterministic local calibration proof."""

    root = Path(destination)
    if root.exists() or root.is_symlink():
        raise RealProjectContractError("calibration destination must be new")
    prepared = RealProjectFixtureBuilder(fixture_root).materialize(root / "prepared")
    return SyntheticRealProjectHarness().run_pair(prepared, root / "paired-runs")
