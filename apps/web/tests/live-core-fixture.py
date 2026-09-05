#!/usr/bin/env python3
"""Start a real AppServer with disposable public-safe core-workflow fixtures."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any, Sequence


INFRASTRUCTURE_INSTANCE_ID = "live-core-infra"
UNAVAILABLE_INFRASTRUCTURE_INSTANCE_ID = "live-core-infra-unavailable"


class _InfrastructureFixtureRunner:
    """Deterministic subprocess boundary for browser-live infrastructure tests.

    Git observations still execute against the disposable repository. Host
    libvirt, Nix, SSH, and Make operations never execute: their bounded results
    are supplied here so the real AppServer, adapter, plans, approvals, leases,
    receipts, and browser client can be exercised without touching the host.
    """

    def __init__(self, *, domain_state: str) -> None:
        self.domain_state = domain_state

    def __call__(
        self,
        command: Sequence[str],
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        arguments = tuple(str(item) for item in command)
        if not arguments:
            return subprocess.CompletedProcess(arguments, 127, "", "empty command")

        # Repository and StatePort product identities remain real Git facts.
        if arguments[0] == "git":
            return subprocess.run(arguments, **kwargs)

        if arguments[:3] == ("virsh", "--connect", "qemu:///session"):
            operation = arguments[3] if len(arguments) > 3 else ""
            if operation == "domstate":
                if self.domain_state == "unavailable":
                    return subprocess.CompletedProcess(
                        arguments,
                        1,
                        "",
                        "error: fixture libvirt connection is unavailable\n",
                    )
                return subprocess.CompletedProcess(
                    arguments,
                    0,
                    f"{self.domain_state}\n",
                    "",
                )
            if operation == "domuuid":
                return subprocess.CompletedProcess(
                    arguments,
                    0,
                    "00000000-0000-0000-0000-000000000000\n",
                    "",
                )

        if arguments[0] == "make":
            target = arguments[1] if len(arguments) > 1 else ""
            if target == "vm-persistent-start":
                self.domain_state = "running"
            elif target == "vm-persistent-stop":
                self.domain_state = "shut off"
            return subprocess.CompletedProcess(arguments, 0, "", "")

        if arguments[0] == "nix":
            return subprocess.CompletedProcess(arguments, 0, "", "")

        if arguments[0] == "ssh":
            return subprocess.CompletedProcess(
                arguments,
                0,
                '{"verdict":"pass"}\n',
                "",
            )

        # A browser test must never execute the destructive repository script.
        return subprocess.CompletedProcess(
            arguments,
            126,
            "",
            "command is outside the deterministic live-core fixture boundary\n",
        )


def _source_roots(repo_root: Path) -> None:
    for parent in (repo_root / "packages", repo_root / "apps"):
        for source in sorted(parent.glob("*/src")):
            if source.is_dir():
                sys.path.insert(0, str(source))


def _canonical_instance_files(destination: Path, *, instance_id: str, name: str, source: dict[str, str]) -> None:
    """Write the canonical StateSpec identity files a real materialized
    instance carries, so backup-eligibility is exercised honestly instead of
    bypassed."""
    (destination / "instance.yaml").write_text(
        "apiVersion: statedd.stateport.io/v1alpha1\n"
        "kind: Instance\n"
        "metadata:\n"
        f"  id: {instance_id}\n"
        f"  name: {name}\n"
        "spec:\n"
        "  owner:\n"
        "    handle: live-core\n"
        "    name: Live Core\n"
        "  status: draft\n"
        "  templateRef:\n"
        f"    id: {source['templateId']}\n"
        "    path: fixtures/apps/development-reference\n",
        encoding="utf-8",
    )
    statedd = destination / ".statedd"
    statedd.mkdir()
    (statedd / "lock.yaml").write_text(
        "formatVersion: stateport.instance-lock/v1\n"
        f"instanceId: {instance_id}\n"
        "template:\n"
        "  source:\n"
        f"    templateId: {source['templateId']}\n"
        f"    resolvedCommit: {source['resolvedCommit']}\n"
        f"    resolvedTree: {source['resolvedTree']}\n"
        f"    manifestDigest: {source['manifestDigest']}\n"
        f"    sourceClass: {source['sourceClass']}\n"
        "files: []\n",
        encoding="utf-8",
    )


def _git(root: Path, *arguments: str) -> str:
    environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_AUTHOR_NAME": "StatePort live-core fixture",
        "GIT_AUTHOR_EMAIL": "stateport-live-core@example.invalid",
        "GIT_COMMITTER_NAME": "StatePort live-core fixture",
        "GIT_COMMITTER_EMAIL": "stateport-live-core@example.invalid",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    result = subprocess.run(
        ("/usr/bin/git", "-C", root, *arguments),
        check=True,
        capture_output=True,
        text=True,
        env=environment,
        timeout=15,
    )
    return result.stdout.strip()


def _materialize(
    source: Path,
    destination: Path,
    *,
    add_editable_file: bool = False,
    add_infrastructure_contract: bool = False,
) -> dict[str, str]:
    shutil.copytree(source, destination)
    if add_editable_file:
        (destination / "src").mkdir()
        (destination / "src" / "main.py").write_text("answer = 41\n", encoding="utf-8")
    if add_infrastructure_contract:
        (destination / "flake.nix").write_text(
            '{ description = "public-safe StatePort live-core fixture"; }\n',
            encoding="utf-8",
        )
        (destination / "Makefile").write_text(
            "vm-persistent-create:\n\t@true\n",
            encoding="utf-8",
        )
    _git(destination, "init", "--initial-branch=main", "--template=")
    _git(destination, "add", "--all")
    _git(destination, "-c", "commit.gpgSign=false", "commit", "-m", "public-safe live-core fixture")
    return {
        "resolvedCommit": _git(destination, "rev-parse", "HEAD"),
        "resolvedTree": _git(destination, "rev-parse", "HEAD^{tree}"),
        "manifestDigest": "sha256:" + hashlib.sha256(
            (destination / "application.yaml").read_bytes()
        ).hexdigest(),
        "sourceClass": "synthetic_fixture",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--repo-root", required=True, type=Path)
    args = parser.parse_args(argv)
    repo_root = args.repo_root.resolve(strict=True)
    _source_roots(repo_root)

    from stateport_persistent_app import LocalLayout, PersistentApp
    from stateport_persistent_app.infrastructure import LocalLibvirtAdapter
    from stateport_goal_execution import GoalExecutionCoordinator
    import stateport_persistent_app.service_process as service_process
    from stateport_persistent_app.service_resilient_entry import (
        main as resilient_service_main,
    )

    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()

    project = app.layout.instances_root / "live-core-project"
    project_source = _materialize(
        repo_root / "fixtures" / "apps" / "development-reference",
        project,
        add_editable_file=True,
    )
    # A real materialized instance carries canonical StateSpec identity files;
    # without them the backup subsystem correctly refuses to run.
    _canonical_instance_files(
        project,
        instance_id="live-core-project",
        name="Live Core Project",
        source={"templateId": "stateport.development-reference", **project_source},
    )
    _git(project, "add", "--all")
    _git(project, "-c", "commit.gpgSign=false", "commit", "-m", "canonical instance identity")
    app.catalog.register(
        project,
        instance_id="live-core-project",
        name="Live Core Project",
        source={
            "templateId": "stateport.development-reference",
            **project_source,
        },
    )

    # Use the production fixture installer so revision ownership and lock identity
    # match the runtime's trusted-action checks. A raw directory copy omits them.
    from stateport_portable_execution import PortableExecutionService
    PortableExecutionService(app, repo_root).install_fixture_instance(
        "studystate.sample", "live-core-study", name="Live Core Study"
    )

    # Distinct public-safe repository-import candidate. It stays outside the
    # instance catalog until the browser completes read-only inspection and
    # explicitly approves the exact inspection digest.
    import_root = app.layout.data_root / "live-core-import-candidates"
    import_root.mkdir(parents=True, exist_ok=True)
    _materialize(
        repo_root / "fixtures" / "apps" / "development-reference",
        import_root / "nixos-homelab",
        add_infrastructure_contract=True,
    )
    os.environ["STATEPORT_REPOSITORY_ROOTS"] = str(import_root)

    # Two pre-registered external infrastructure applications exercise both
    # the honest unavailable state and the complete bounded service-fixture
    # lifecycle. The supported repository is intentionally dirty so the
    # browser must display that fact without treating a stopped VM as success.
    infrastructure_root = app.layout.data_root / "live-core-infrastructure"
    available_repository = infrastructure_root / "available" / "nixos-homelab"
    available_source = _materialize(
        repo_root / "fixtures" / "apps" / "development-reference",
        available_repository,
        add_infrastructure_contract=True,
    )
    (available_repository / "local-operator-note.txt").write_text(
        "public-safe uncommitted fixture evidence\n",
        encoding="utf-8",
    )
    app.register_external_repository(
        available_repository,
        instance_id=INFRASTRUCTURE_INSTANCE_ID,
        name="Live Core Infrastructure",
        application_id="nixos-infrastructure",
        source={"sourceKind": "synthetic_fixture", **available_source},
    )

    unavailable_repository = (
        infrastructure_root / "unavailable" / "nixos-homelab"
    )
    unavailable_source = _materialize(
        repo_root / "fixtures" / "apps" / "development-reference",
        unavailable_repository,
        add_infrastructure_contract=True,
    )
    app.register_external_repository(
        unavailable_repository,
        instance_id=UNAVAILABLE_INFRASTRUCTURE_INSTANCE_ID,
        name="Unavailable Live Core Infrastructure",
        application_id="nixos-infrastructure",
        source={"sourceKind": "synthetic_fixture", **unavailable_source},
    )

    fixture_runners = {
        INFRASTRUCTURE_INSTANCE_ID: _InfrastructureFixtureRunner(
            domain_state="shut off"
        ),
        UNAVAILABLE_INFRASTRUCTURE_INSTANCE_ID: _InfrastructureFixtureRunner(
            domain_state="unavailable"
        ),
    }

    def fixture_adapter(
        repository_root: Path | str,
        *,
        instance_id: str,
        state_root: Path | str,
        product_root: Path | str | None = None,
        **_: Any,
    ) -> LocalLibvirtAdapter:
        # Repository imports created during the suite also remain safely
        # environment-gated if their infrastructure view is opened later.
        runner = fixture_runners.setdefault(
            instance_id,
            _InfrastructureFixtureRunner(domain_state="unavailable"),
        )
        return LocalLibvirtAdapter(
            repository_root,
            instance_id=instance_id,
            state_root=state_root,
            product_root=product_root,
            runner=runner,
        )

    # This replacement is process-local to the disposable fixture. Production
    # service code and its real LocalLibvirtAdapter remain unchanged. The
    # resilient entry still delegates all unrelated routes to that same server.
    service_process.LocalLibvirtAdapter = fixture_adapter

    def fixture_goal_execution(*, record_root: Path) -> GoalExecutionCoordinator:
        # Production intentionally refuses synthetic execution. This
        # public-safe browser fixture explicitly opts into the test-only
        # provider-free backend so it can exercise the governed lifecycle.
        return GoalExecutionCoordinator(
            record_root=record_root,
            allow_synthetic_backend=True,
        )

    service_process.GoalExecutionCoordinator = fixture_goal_execution

    return resilient_service_main(
        [
            "--port",
            str(args.port),
            "--repo-root",
            str(repo_root),
            "--actor-role",
            "local_user",
        ]
    )


if __name__ == "__main__":
    raise SystemExit(main())
