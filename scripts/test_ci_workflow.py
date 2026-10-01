#!/usr/bin/env python3
"""Regression checks for the current StatePort CI closure boundaries."""

from __future__ import annotations

from pathlib import Path
import re
import subprocess
import tomllib

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "validate.yml"
PREFLIGHT_WORKFLOW = ROOT / ".github" / "workflows" / "ai-vertical-preflight.yml"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "public-release-driver.yml"
ACTIONLINT_CONFIG = ROOT / ".github" / "actionlint.yaml"
GITLEAKS_CONFIG = ROOT / ".gitleaks.toml"
CHECKOUT_V7_NODE24 = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"


def _workflow() -> dict[str, object]:
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_actionlint_declares_the_exact_private_runner_label() -> None:
    data = yaml.safe_load(ACTIONLINT_CONFIG.read_text(encoding="utf-8"))
    assert data == {"self-hosted-runner": {"labels": ["stateport"]}}


def test_workflows_pin_checkout_v7_node24_exactly() -> None:
    observed: list[str] = []
    for path in (WORKFLOW, PREFLIGHT_WORKFLOW, RELEASE_WORKFLOW):
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(workflow, dict)
        jobs = workflow.get("jobs")
        assert isinstance(jobs, dict)
        for job in jobs.values():
            assert isinstance(job, dict)
            steps = job.get("steps")
            assert isinstance(steps, list)
            for step in steps:
                assert isinstance(step, dict)
                uses = step.get("uses")
                if isinstance(uses, str) and uses.startswith("actions/checkout@"):
                    observed.append(uses)
    assert observed
    assert set(observed) == {CHECKOUT_V7_NODE24}


def _commands(job: dict[str, object]) -> tuple[str, ...]:
    steps = job.get("steps")
    assert isinstance(steps, list)
    commands: list[str] = []
    for step in steps:
        assert isinstance(step, dict)
        command = step.get("run")
        if isinstance(command, str):
            commands.append(command)
    return tuple(commands)


def test_ci_triggers_encode_the_local_first_validation_policy() -> None:
    """GitHub Actions is optional remote evidence, not the validation engine.

    Local validation runs the same commands without any push or dispatch;
    the workflow only adds same-repository pull-request runs and an
    operator-initiated dispatch on top. No automatic push trigger may come
    back: the single self-hosted runner cannot absorb per-push heavy runs.
    """
    workflow = _workflow()
    # PyYAML's YAML 1.1 resolver parses the unquoted GitHub key `on` as True.
    triggers = workflow.get("on", workflow.get(True))
    assert triggers == {
        "pull_request": {"branches": ["main", "agent/alpha-public-legal-boundary-001"]},
        "workflow_dispatch": None,
    }


def test_ci_uses_complete_backend_suite_and_repository_gates() -> None:
    jobs = _workflow()["jobs"]
    assert isinstance(jobs, dict)
    backend = jobs["backend"]
    assert isinstance(backend, dict)
    commands = _commands(backend)

    for expected in (
        "python3 -m venv .venv",
        "--require-hashes -r requirements/dev-test.txt",
        ".venv/bin/python scripts/validate_repo.py",
        ".venv/bin/python scripts/statedd_validate_schema.py",
        ".venv/bin/python scripts/validate_application_experience.py",
        ".venv/bin/python -m compileall -q apps packages scripts",
        'test "$(.venv/bin/ruff --version)" = "ruff 0.16.0"',
        ".venv/bin/ruff check apps packages scripts",
        ".venv/bin/python -m pytest -q",
    ):
        assert any(expected in command for command in commands), f"missing: {expected}"

    assert not any(command.startswith("python3 scripts/test_") for command in commands)


def test_ci_runs_locked_frontend_build_unit_dependency_and_browser_gates() -> None:
    jobs = _workflow()["jobs"]
    assert isinstance(jobs, dict)
    web = jobs["web"]
    assert isinstance(web, dict)
    commands = _commands(web)

    for expected in (
        "npm ci --ignore-scripts",
        "npm run typecheck",
        "npm run lint",
        "npm run test",
        "npm run build",
        "npm run check:bundle",
        "npm run test:build-isolation",
        "npm run check:dependencies",
        "python3 ../../scripts/validate_web_dependency_audit.py",
        "npx playwright install chromium",
        "npm run test:e2e",
    ):
        assert expected in commands

    e2e_port_selection = next(command for command in commands if "STATEPORT_E2E_PORT=" in command)
    # The browser service must not compete for the conventional developer
    # preview port on a shared runner. Keep its deterministic range disjoint
    # from the Compose range below.
    assert "30000 +" in e2e_port_selection
    assert "% 10000" in e2e_port_selection

    defaults = web["defaults"]
    assert isinstance(defaults, dict)
    run_defaults = defaults["run"]
    assert isinstance(run_defaults, dict)
    assert run_defaults["working-directory"] == "apps/web"


def test_self_hosted_jobs_reject_untrusted_fork_code_and_keep_secret_scan() -> None:
    jobs = _workflow()["jobs"]
    assert isinstance(jobs, dict)
    # Fork safety under the local-first policy: a job only runs for an
    # owner-initiated dispatch or a same-repository pull request, so
    # untrusted fork code never executes on the privileged self-hosted
    # runner. The secret scan stays mandatory inside that boundary.
    guard = (
        "github.event_name == 'workflow_dispatch' || "
        "github.event.pull_request.head.repo.full_name == github.repository"
    )
    for job_name in (
        "backend",
        "web",
        "security",
        "package-validation",
        "compose-integration",
    ):
        job = jobs[job_name]
        assert isinstance(job, dict)
        assert job["runs-on"] == ["self-hosted", "linux", "x64", "stateport"]
        assert job["if"] == guard

    canonical = jobs["canonical-source-browser"]
    assert canonical["runs-on"] == ["self-hosted", "linux", "x64", "stateport"]
    assert canonical["if"] == "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'"
    assert canonical["env"] == {
        "STATEPORT_STUDYDD_RECOVERY_ROOT": "/opt/stateport/private/studydd-cffc45a2",
    }

    security = jobs["security"]
    assert isinstance(security, dict)
    assert "./scripts/gitleaks_scan.sh" in _commands(security)


def test_secret_scan_uses_an_exact_tree_and_keeps_staged_review_explicit() -> None:
    script = (ROOT / "scripts" / "gitleaks_scan.sh").read_text(encoding="utf-8")
    assert 'MODE="committed"' in script
    assert 'git -C "$ROOT" archive --format=tar HEAD' in script
    assert 'git -C "$ROOT" checkout-index --all' in script
    assert '"--staged"' in script
    assert '"--working-tree"' in script
    assert '--source="$SCAN_ROOT"' in script
    assert "--no-git" in script


def test_ci_compose_integration_builds_and_validates_delivered_product() -> None:
    jobs = _workflow()["jobs"]
    assert isinstance(jobs, dict)
    compose = jobs["compose-integration"]
    assert isinstance(compose, dict)
    assert compose["timeout-minutes"] == 30
    commands = _commands(compose)

    for expected in (
        "podman compose version",
        "podman-compose",
        "docker compose version",
        "git rev-parse --verify HEAD",
        "STATEPORT_BUILD_SOURCE_COMMIT",
        "STATEPORT_BUILD_SOURCE_TREE",
        "STATEPORT_BUILD_VERSION",
        "STATEPORT_BUILD_CREATED",
        "STATEPORT_BUILD_ADAPTER",
        "$COMPOSE build",
        "$COMPOSE up -d",
        "wait_web_healthy",
        "wait_internal_healthy stateport-api 8790 /readyz",
        "wait_internal_healthy stateport-worker 8791 /readyz",
        "STATEPORT_WEB_PORT",
        "$COMPOSE exec -T stateport-api",
        "$COMPOSE exec -T stateport-worker",
        "v1/capabilities",
        "$COMPOSE images",
        "$COMPOSE down -v --remove-orphans",
    ):
        assert any(expected in command for command in commands), f"missing: {expected}"

    compose_port_selection = next(
        command for command in commands if "COMPOSE_PROJECT_NAME=stateport-ci-" in command
    )
    # Only the authenticated same-origin web endpoint is host-published.
    assert "45000 +" in compose_port_selection
    assert "% 10000" in compose_port_selection
    assert "STATEPORT_WEB_PORT=${BASE_PORT}" in compose_port_selection
    assert "STATEPORT_API_PORT" not in compose_port_selection
    assert "STATEPORT_WORKER_PORT" not in compose_port_selection

    provenance = next(
        command
        for command in commands
        if 'SOURCE_COMMIT="$(git rev-parse --verify HEAD)"' in command
    )
    assert 'SOURCE_TREE="$(git rev-parse --verify "${SOURCE_COMMIT}^{tree}")"' in provenance
    assert 'SOURCE_EPOCH="$(git show -s --format=%ct "$SOURCE_COMMIT")"' in provenance
    assert "STATEPORT_BUILD_VERSION=0.0.0-ci." in provenance
    assert "STATEPORT_BUILD_CREATED=${SOURCE_CREATED}" in provenance
    assert "STATEPORT_BUILD_ADAPTER=github-actions-compose" in provenance
    assert "git rev-parse --verify 'HEAD^{tree}'" not in provenance

    health_contracts = "\n".join(
        command
        for command in commands
        if "API health response valid" in command
        or "Worker health response valid" in command
        or "API capabilities endpoint valid" in command
    )
    for expected in (
        "data.get('ok') is True",
        "result = data.get('result')",
        "result.get('status') == 'standby'",
        "result.get('executionEnabled') is False",
        "'operations' in result",
    ):
        assert expected in health_contracts

    assert any("failure()" in step.get("if", "") for step in compose["steps"])
    assert any("always()" in step.get("if", "") for step in compose["steps"])


def test_ci_package_validation_checks_dockerfiles_and_install_script() -> None:
    jobs = _workflow()["jobs"]
    assert isinstance(jobs, dict)
    pkg = jobs["package-validation"]
    assert isinstance(pkg, dict)
    assert pkg["timeout-minutes"] == 15
    commands = _commands(pkg)

    for expected in (
        "bash -n scripts/install.sh",
        "apps/${svc}/Dockerfile",
        "python3 scripts/validate_dockerfile_copy_sources.py",
        "test_compose_shape.py",
    ):
        assert any(expected in command for command in commands), f"missing: {expected}"

    assert not any("sed -n 's/.*COPY" in command for command in commands)


def test_ci_canonical_source_gate_uses_owner_private_recovery_bundle_and_live_browser() -> None:
    jobs = _workflow()["jobs"]
    assert isinstance(jobs, dict)
    canonical = jobs["canonical-source-browser"]
    assert isinstance(canonical, dict)
    commands = _commands(canonical)
    acceptance = next(
        command for command in commands if "npm run test:canonical-source-browser" in command
    )

    assert "source_recovery_bundle.py verify" in acceptance
    assert "/usr/bin/python3 ../../scripts/source_recovery_bundle.py verify" in acceptance
    assert "sources/profiles/studydd-local-alpha.yaml" in acceptance
    assert 'STATEPORT_BROWSER_STUDYDD_REPOSITORY="$STATEPORT_STUDYDD_RECOVERY_ROOT/source.bundle"' in acceptance
    assert "StudyDD_Template.git" not in acceptance
    assert "STATEPORT_BROWSER_ARTIFACT_ROOT=" in acceptance
    assert "npm run test:canonical-source-browser" in acceptance
    assert "npm run test:live-core-browser" in commands
    assert "npm ci --ignore-scripts" in commands
    assert "npx playwright install chromium" in commands
    assert "TMPDIR" not in canonical["env"]


def test_public_release_driver_is_manual_exact_main_alpha10_and_runs_preflights() -> None:
    workflow = yaml.safe_load(RELEASE_WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict)
    triggers = workflow.get("on", workflow.get(True))
    assert triggers == {"workflow_dispatch": None}
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    source = jobs["source-preflight"]
    builder = jobs["reproducible-builder"]
    assert source["if"] == "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'"
    assert builder["if"] == "needs.source-preflight.result == 'success' && github.ref == 'refs/heads/main'"
    assert builder["env"]["RELEASE_VERSION"] == "0.1.0-alpha.10"
    assert "TMPDIR" not in builder["env"]
    for job in (source, builder):
        checkout = next(step for step in job["steps"] if str(step.get("uses", "")).startswith("actions/checkout@"))
        assert checkout["with"]["ref"] == "${{ github.sha }}"
    preflight = "\n".join(_commands(source))
    for expected in (
        "scripts/test_assemble_release_index.py",
        "scripts/test_candidate_provenance.py",
        "scripts/test_ci_workflow.py",
        "scripts/test_release_scan_exceptions.py",
    ):
        assert expected in preflight


def test_local_closure_plan_covers_every_ci_job_boundary() -> None:
    """The authoritative local plan must not drift from the remote workflow.

    Every GitHub Actions job boundary has a local equivalent in
    ``local_closure_gate.default_commands`` (or the opt-in heavy service
    journey), so local fallback genuinely covers CI when Actions is
    unavailable — and a new CI job without local coverage fails here.
    """
    import sys

    scripts = str(ROOT / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    from local_closure_gate import default_commands, service_journey_commands

    labels = {spec.label for spec in default_commands(900)}
    journey = {spec.label for spec in service_journey_commands(1800)}
    expectations = {
        "backend": {
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
        },
        "web": {
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
        },
        "canonical-source-browser": {
            "live_core_browser_acceptance",
            "canonical_source_browser_acceptance",
        },
        "security": {"repository_gitleaks"},
        "package-validation": {
            "installer_syntax",
            "dockerfile_copy_sources",
            "compose_shape",
        },
        "compose-integration": {"compose_service_journey"},
    }
    jobs = _workflow()["jobs"]
    assert isinstance(jobs, dict)
    assert set(jobs) == set(expectations), "CI job set drifted from local coverage map"
    for job, wanted in expectations.items():
        missing = wanted - labels - journey
        assert not missing, f"{job}: local closure plan drifted, missing {sorted(missing)}"


def test_gitleaks_allowlist_is_exact_and_keeps_default_rules() -> None:
    config = tomllib.loads(GITLEAKS_CONFIG.read_text(encoding="utf-8"))
    assert config["extend"] == {"useDefault": True}
    assert config["allowlist"] == {
        "description": (
            "Ignore one exact keyboard chord and generated Vite copies of scanned source."
        ),
        "regexTarget": "match",
        "regexes": [r"""defaultKeys\s*:\s*['"]mod\+shift\+enter['"]"""],
        "paths": [r"apps/web/dist/", r"apps/web/dist-demo/"],
    }
    rules = [rule for rule in config["rules"] if rule["id"] == "generic-api-key"]
    assert len(rules) == 1
    allowlists = rules[0]["allowlists"]
    assert len(allowlists) == 2
    for allowlist in allowlists:
        assert allowlist["condition"] == "AND"
        assert allowlist["regexTarget"] == "match"
        assert len(allowlist["paths"]) == 1
        assert len(allowlist["regexes"]) == 1
        assert allowlist["paths"][0].startswith("^") and allowlist["paths"][0].endswith("$")
        assert allowlist["regexes"][0].startswith("^") and allowlist["regexes"][0].endswith("$")

    fingerprint = re.search(
        r"--trust-key-fingerprint\s+(sha256:[0-9a-f]{64})",
        (ROOT / "HANDOFF_2026-08-03-FEDORA-ALPHA2.md").read_text(encoding="utf-8"),
    )
    nonce = re.search(
        r'"Sec-WebSocket-Key": "([^"]+)"',
        (ROOT / "scripts/test_preview_gateway_containment.py").read_text(encoding="utf-8"),
    )
    assert fingerprint and nonce

    def allowed(path: str, match: str, rule: str) -> bool:
        return any(
            item["condition"] == "AND"
            and rule == "generic-api-key"
            and any(re.fullmatch(pattern, path) for pattern in item["paths"])
            and any(re.fullmatch(pattern, match) for pattern in item["regexes"])
            for item in allowlists
        )

    assert allowed(
        "HANDOFF_2026-08-03-FEDORA-ALPHA2.md",
        f"--trust-key-fingerprint {fingerprint.group(1)} ",
        "generic-api-key",
    )
    assert allowed(
        "scripts/test_preview_gateway_containment.py",
        f'Sec-WebSocket-Key": "{nonce.group(1)}"',
        "generic-api-key",
    )
    assert not allowed(
        "HANDOFF_2026-08-03-FEDORA-ALPHA2.md",
        f"--trust-key-fingerprint {fingerprint.group(1)[:-1]}0 ",
        "generic-api-key",
    )
    assert not allowed(
        "scripts/test_preview_gateway_containment.py",
        f'Sec-WebSocket-Key": "{nonce.group(1)[:-1]}A"',
        "generic-api-key",
    )
    assert not allowed(
        "docs/other.md",
        f"--trust-key-fingerprint {fingerprint.group(1)} ",
        "generic-api-key",
    )


def test_workflow_runner_context_is_not_used_before_runner_assignment() -> None:
    # GitHub's context table excludes runner from these job-level fields;
    # YAML parsing alone cannot detect this zero-job validation failure.
    for path in (WORKFLOW, RELEASE_WORKFLOW):
        workflow = yaml.safe_load(path.read_text())
        for name, job in workflow["jobs"].items():
            for field in ("env", "if", "name", "runs-on", "timeout-minutes", "defaults", "concurrency", "strategy"):
                value = yaml.safe_dump(job.get(field))
                assert not re.search(r"\brunner\s*(?:\.|\[)", value), (path.name, name, field)


def test_runner_tmpdir_initialization_executes_before_checkout(tmp_path: Path) -> None:
    runner_temp = tmp_path / "runner temporary files"
    runner_temp.mkdir()
    for path, name in ((WORKFLOW, "canonical-source-browser"), (RELEASE_WORKFLOW, "reproducible-builder")):
        job = yaml.safe_load(path.read_text())["jobs"][name]
        first = job["steps"][0]
        assert first["name"] == "Initialize runner temporary directory"
        assert first["shell"] == "bash"
        # This job can default to apps/web, which does not exist pre-checkout.
        assert first["working-directory"] == "${{ runner.temp }}"
        env_file = tmp_path / (path.name + ".env")
        env_file.write_text("EXISTING=preserved\n")
        result = subprocess.run(
            ["/usr/bin/bash", "--noprofile", "--norc", "-c", first["run"]],
            cwd=runner_temp,
            env={"PATH": "/usr/bin:/bin", "RUNNER_TEMP": str(runner_temp), "GITHUB_ENV": str(env_file)},
            capture_output=True, text=True, timeout=5,
        )
        assert result.returncode == 0, result.stderr
        assert env_file.read_text() == f"EXISTING=preserved\nTMPDIR={runner_temp}\n"
        before = env_file.read_bytes()
        refused = subprocess.run(
            ["/usr/bin/bash", "--noprofile", "--norc", "-c", first["run"]],
            cwd=runner_temp,
            env={"PATH": "/usr/bin:/bin", "RUNNER_TEMP": str(tmp_path / "absent"), "GITHUB_ENV": str(env_file)},
            capture_output=True, text=True, timeout=5,
        )
        assert refused.returncode != 0
        assert env_file.read_bytes() == before
