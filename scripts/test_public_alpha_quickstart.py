#!/usr/bin/env python3
"""Regression tests for the deterministic public-alpha quickstart contract."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import stat
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "install.sh"
PREFLIGHT = ROOT / "scripts" / "public_alpha_preflight.py"


def _load_preflight():
    spec = importlib.util.spec_from_file_location("public_alpha_preflight", PREFLIGHT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _catalog(**install_overrides: object) -> dict[str, object]:
    install = {
        "status": "available",
        "reasons": [],
        "confirmationRequired": True,
        "sourceKind": "bundled_public_fixture",
        "networkPolicy": "disabled",
        "requestedCapabilities": [
            "conversation",
            "goal_execution",
            "proactive_notifications",
            "progress_dashboard",
        ],
        **install_overrides,
    }
    return {
        "ok": True,
        "result": {
            "applications": [
                {
                    "applicationId": "studystate.sample",
                    "displayName": "StudyState Sample",
                    "install": install,
                }
            ]
        },
    }


def test_catalog_preflight_accepts_only_the_provider_free_fictional_sample() -> None:
    preflight = _load_preflight()
    entry = preflight.validate_catalog(_catalog())
    assert entry["applicationId"] == "studystate.sample"
    for mutation, message in (
        ({"networkPolicy": "provider"}, "networkPolicy=disabled"),
        ({"status": "unavailable"}, "not installable"),
        ({"sourceKind": "canonical_release"}, "bundled public fixture"),
        ({"confirmationRequired": False}, "explicit installation confirmation"),
        ({"requestedCapabilities": ["conversation", "terminal"]}, "capabilities"),
    ):
        with pytest.raises(preflight.PreflightError, match=message):
            preflight.validate_catalog(_catalog(**mutation))


def test_installer_refuses_missing_container_provider_clearly(tmp_path: Path) -> None:
    result = subprocess.run(
        ["/bin/bash", str(INSTALLER), "--check"],
        cwd=ROOT,
        env={"PATH": str(tmp_path)},
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 1
    assert "no container engine found" in result.stderr
    assert "Podman" in result.stderr and "Docker" in result.stderr


def test_installer_dry_run_constructs_one_exact_compose_command(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    podman = fake_bin / "podman"
    podman.write_text(
        "#!/bin/sh\n"
        "if [ \"$1 $2\" = \"compose version\" ]; then\n"
        "  echo 'podman-compose version 1.6.0'\n"
        "  exit 0\n"
        "fi\n"
        "exit 1\n",
        encoding="utf-8",
    )
    podman.chmod(podman.stat().st_mode | stat.S_IXUSR)
    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    result = subprocess.run(
        ["/bin/bash", str(INSTALLER), "--dry-run"],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.count("dry-run command:") == 1
    assert f"podman compose --in-pod=false -f {ROOT / 'docker-compose.yml'} up -d --build" in result.stdout
    assert "Podman container mode: no shared pod" in result.stdout
    assert "Podman user namespace: keep-id" in result.stdout
    assert "no containers were built or started" in result.stdout


def test_installer_binds_podman_to_the_nested_sandbox_user_namespace() -> None:
    text = INSTALLER.read_text(encoding="utf-8")
    assert 'COMPOSE_PROVIDER="podman"' in text
    assert 'COMPOSE+=("--in-pod=false")' in text
    assert "export PODMAN_USERNS=keep-id" in text
    assert 'if [ "$PODMAN_COMPOSE_IMPLEMENTATION" = "podman-compose" ]' in text


def test_installer_derives_tree_and_epoch_from_one_resolved_commit() -> None:
    text = INSTALLER.read_text(encoding="utf-8")
    assert 'STATEPORT_BUILD_SOURCE_COMMIT="$(git rev-parse --verify HEAD)"' in text
    assert (
        'STATEPORT_BUILD_SOURCE_TREE="$(git rev-parse --verify '
        '"${STATEPORT_BUILD_SOURCE_COMMIT}^{tree}")"'
    ) in text
    assert (
        'STATEPORT_BUILD_SOURCE_DATE_EPOCH="$(git show -s --format=%ct '
        '"$STATEPORT_BUILD_SOURCE_COMMIT")"'
    ) in text
    assert "git rev-parse --verify 'HEAD^{tree}'" not in text


def test_installer_does_not_pass_podman_compose_only_flags_to_other_providers(
    tmp_path: Path,
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    podman = fake_bin / "podman"
    podman.write_text(
        "#!/bin/sh\n"
        "if [ \"$1 $2\" = \"compose version\" ]; then\n"
        "  echo 'Docker Compose version v2.39.0'\n"
        "  exit 0\n"
        "fi\n"
        "exit 1\n",
        encoding="utf-8",
    )
    podman.chmod(podman.stat().st_mode | stat.S_IXUSR)
    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    result = subprocess.run(
        ["/bin/bash", str(INSTALLER), "--dry-run"],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "podman compose -f" in result.stdout
    assert "--in-pod=false" not in result.stdout
    assert "without podman-compose pod flags" in result.stdout


def test_installer_rejects_invalid_or_colliding_ports_before_start() -> None:
    for overrides, message in (
        ({"STATEPORT_WEB_PORT": "not-a-port"}, "must be an integer"),
        ({"STATEPORT_WEB_PORT": "70000"}, "1 to 65535"),
        ({"STATEPORT_WEB_PORT": "8790"}, "must be distinct"),
        ({"STATEPORT_HEALTH_TIMEOUT": "0"}, "positive integer"),
    ):
        env = os.environ.copy()
        env.update(overrides)
        result = subprocess.run(
            ["/bin/bash", str(INSTALLER), "--check"],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 1
        assert message in result.stderr


def test_installer_routes_to_applications_without_silent_fixture_install() -> None:
    text = INSTALLER.read_text(encoding="utf-8")
    assert 'Open: http://127.0.0.1:${WEB_PORT}/#/applications' in text
    assert "/v1/application-fixtures/install" not in text
    assert "explicit browser confirmation" in text
