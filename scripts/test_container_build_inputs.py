from __future__ import annotations

import hashlib
from pathlib import Path
import re

import yaml


ROOT = Path(__file__).resolve().parents[1]


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def test_locked_build_inputs_match_exact_repository_bytes() -> None:
    value = yaml.safe_load((ROOT / "config/container-build-inputs.yaml").read_text())
    assert value["resolvedOn"] == "2026-09-10"
    for lock in value["locks"].values():
        assert _digest(ROOT / lock["path"]) == lock["digest"]
    for path, expected in value["definitions"].items():
        assert _digest(ROOT / path) == expected


def test_ubuntu_packages_are_exact_and_snapshot_bound() -> None:
    value = yaml.safe_load((ROOT / "config/container-build-inputs.yaml").read_text())
    containerfile = (ROOT / "images/stateport-dev-workspace/Containerfile").read_text()
    assert value["ubuntuSnapshot"]["timestamp"] == "20260801T000000Z"
    for package, version in value["ubuntuSnapshot"]["packages"].items():
        assert f"{package}={version}" in containerfile
    assert "apt-get install --no-install-recommends" in containerfile
    assert "|| true" not in containerfile


def test_upstream_tools_are_pinned_in_containerfile() -> None:
    value = yaml.safe_load((ROOT / "config/container-build-inputs.yaml").read_text())
    containerfile = (ROOT / "images/stateport-dev-workspace/Containerfile").read_text()
    tools = value["upstreamTools"]
    assert tools, "upstreamTools must not be empty"
    go = value["buildToolchains"]["go"]
    assert go["version"] == "1.26.7"
    assert go["uri"] in containerfile
    assert go["digest"].removeprefix("sha256:") in containerfile
    for name, tool in tools.items():
        digest = tool["digest"]
        assert digest.startswith("sha256:")
        assert digest.removeprefix("sha256:") in containerfile
        assert tool["uri"] in containerfile
        install_path = tool["installPath"]
        assert install_path.startswith("/usr/local")
        if install_path != "/usr/local":
            # Single-binary tools install to a path named after the tool;
            # prefix installs (e.g. Node.js) target /usr/local itself.
            assert install_path.rsplit("/", 1)[-1] == name
        if "sourceCommit" in tool:
            assert tool["sourceCommit"] in containerfile
            assert tool["buildToolchain"] == "go1.26.7"
    assert tools["gh"] == {
        "version": "2.98.0",
        "sourceCommit": "a255baf71d13fe5947a4eb7ad521ffd412d64cee",
        "uri": "https://github.com/cli/cli.git",
        "digest": "sha256:8774dabd7d3d1a0ee6c8b8231f659d6b8d64a8da8803d63e2a95fba66f2f518f",
        "buildToolchain": "go1.26.7",
        "installPath": "/usr/local/bin/gh",
    }
    assert containerfile.count('go version -m /usr/local/bin/') == 2
    assert containerfile.count('grep -F "go1.26.7"') == 2
    assert 'grep -aqF "golang.org/x/mod/sumdb/note" /usr/local/bin/gh' in containerfile
    assert "sumdb\\.Client|sumdb/client|sumdb/tlog|tlog\\." in containerfile
    assert "GOTOOLCHAIN=local" in containerfile
    assert "/root/.config/go /root/.local/state/gh" in containerfile
    assert "|| true" not in containerfile


def test_playwright_browser_asset_is_exact_and_pinned() -> None:
    value = yaml.safe_load((ROOT / "config/container-build-inputs.yaml").read_text())
    containerfile = (ROOT / "images/stateport-playwright/Containerfile").read_text()
    browser = value["browserAssets"]["chrome-for-testing"]

    assert browser["version"] in containerfile
    assert browser["uri"] in containerfile
    assert browser["digest"].removeprefix("sha256:") in containerfile


def test_alpine_packages_are_exact_and_repository_bound() -> None:
    value = yaml.safe_load((ROOT / "config/container-build-inputs.yaml").read_text())
    dockerfile = (ROOT / "apps/web/Dockerfile").read_text()
    snapshot = value["alpinePackages"]
    assert snapshot["release"] == "3.23"
    assert snapshot["repository"].endswith("/alpine/v3.23/main")
    for package, version in snapshot["packages"].items():
        assert f"{package}={version}" in dockerfile
    assert "apk add --no-cache" in dockerfile
    assert "|| true" not in dockerfile


def test_execution_host_alpine_packages_are_exact_and_fully_pinned() -> None:
    value = yaml.safe_load((ROOT / "config/container-build-inputs.yaml").read_text())
    containerfile = (ROOT / "images/stateport-execution-host/Containerfile").read_text()
    snapshot = value["executionHostAlpine"]
    assert snapshot["repositories"] == [
        "https://dl-cdn.alpinelinux.org/alpine/edge/main",
        "https://dl-cdn.alpinelinux.org/alpine/edge/community",
    ]
    for repository in snapshot["repositories"]:
        assert f"--repository {repository}" in containerfile
    for package, version in snapshot["packages"].items():
        assert f"{package}={version}" in containerfile
    assert "apk add --no-cache" in containerfile
    assert "podman-remote" in containerfile
    assert "podman-remote=5.8.3-r1" not in containerfile
    tool = value["sourceBuiltTools"]["podman-remote"]
    assert tool["uri"] in containerfile
    assert tool["digest"].removeprefix("sha256:") in containerfile
    assert tool["buildToolchain"] == "golang-1.26.6-alpine3.23"
    assert 'go version -m /out/podman-remote | grep -F "go1.26.6"' in containerfile
    assert 'grep -aqF "golang.org/x/crypto/ssh.NewClientConn"' in containerfile
    assert (
        "if grep -aEq 'golang.org/x/crypto/ssh\\.NewServerConn|"
        "golang.org/x/crypto/ssh\\.\\(\\*connection\\)\\.serverAuthenticate' "
        "/out/podman-remote; then \\\n"
        "         exit 1; \\\n"
        "       else \\\n"
        '         status=$?; test "$status" -eq 1; \\\n'
        "       fi"
    ) in containerfile
    assert "|| true" not in containerfile


def test_control_plane_runtime_lock_has_no_provider_sdk_or_best_effort_install() -> None:
    runtime = (ROOT / "requirements/runtime-linux-amd64.txt").read_text()
    assert "--hash=sha256:" in runtime
    assert not re.search(r"openai|anthropic|google-generative|provider", runtime, re.I)
    for path in (ROOT / "apps/api/Dockerfile", ROOT / "apps/worker/Dockerfile"):
        text = path.read_text()
        assert "--require-hashes" in text
        assert "|| true" not in text
        assert "podman" not in text.lower()
        assert "/var/run/docker.sock" not in text.lower()
        assert not re.search(r"(?:apk|apt-get)\s+[^\n]*(?:podman|docker|git)", text, re.I)
