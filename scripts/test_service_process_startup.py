#!/usr/bin/env python3
"""Startup regressions for canonical-root and eager Telegram initialization."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
for source_root in sorted((ROOT / "packages").glob("*/src")):
    sys.path.insert(0, str(source_root))
for source_root in sorted((ROOT / "apps").glob("*/src")):
    sys.path.insert(0, str(source_root))

from stateport_persistent_app import LocalLayout  # noqa: E402
from stateport_persistent_app.service_process import (  # noqa: E402
    AppServer,
    _REQUIRED_PRODUCT_PATHS,
    _select_web_root,
    _unlink_runtime_if_owned,
    _validate_product_root,
)
import stateport_persistent_app.service_process as service_process  # noqa: E402
from service_test_product import service_product_fixture  # noqa: E402


class _FakeTelegramLauncher:
    def __init__(self, *, enabled: bool, instance_id: str | None = None) -> None:
        self.enabled = enabled
        self.instance_id = instance_id
        self.attached = False

    def stop(self) -> None:
        return None


def _layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> LocalLayout:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    layout = LocalLayout.from_environment()
    layout.initialize()
    return layout


def test_product_root_requires_complete_git_clone_or_worktree(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Git clone or worktree"):
        _validate_product_root(tmp_path)


def test_product_root_accepts_a_complete_standard_git_worktree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    main = tmp_path / "main"
    main.mkdir()
    for relative in _REQUIRED_PRODUCT_PATHS:
        required = main / relative
        if required.suffix:
            required.parent.mkdir(parents=True, exist_ok=True)
            required.write_text("fixture\n", encoding="utf-8")
        else:
            required.mkdir(parents=True, exist_ok=True)
            (required / ".stateport-fixture").write_text("fixture\n", encoding="utf-8")
    (main / "README.md").write_text("StatePort fixture\n", encoding="utf-8")
    environment = {
        "PATH": "/usr/bin:/bin",
        "GIT_AUTHOR_NAME": "StatePort fixture",
        "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
        "GIT_COMMITTER_NAME": "StatePort fixture",
        "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    for arguments in (
        ("init", "--quiet", "--initial-branch=main", "--template="),
        ("add", "."),
        ("commit", "--quiet", "--no-verify", "-m", "fixture"),
    ):
        subprocess.run(
            ("git", "-C", str(main), *arguments),
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        )
    worktree = tmp_path / "worktree"
    subprocess.run(
        ("git", "-C", str(main), "worktree", "add", "--quiet", "--detach", str(worktree), "HEAD"),
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert (worktree / ".git").is_file()
    monkeypatch.delenv("STATEPORT_PRODUCT_ROOT", raising=False)

    identity = _validate_product_root(worktree)

    assert identity["repoRoot"] == worktree.as_posix()
    assert identity["gitHead"] == subprocess.run(
        ("git", "-C", str(worktree), "rev-parse", "HEAD"),
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    ).stdout.strip()
    assert identity["gitTree"] == subprocess.run(
        ("git", "-C", str(worktree), "rev-parse", f"{identity['gitHead']}^{{tree}}"),
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    ).stdout.strip()


def test_temporary_static_fixture_can_select_its_build_without_product_marker(
    tmp_path: Path,
) -> None:
    # A fixture may intentionally mirror the apps/web path shape. Without the
    # StatePort package identity it remains a fixture and needs no marker.
    web_root = tmp_path / "apps" / "web"
    built_root = web_root / "dist"
    built_root.mkdir(parents=True)
    (built_root / "index.html").write_text("<!doctype html>\n", encoding="utf-8")

    assert _select_web_root(web_root) == built_root


def _product_web_fixture(tmp_path: Path) -> tuple[Path, Path]:
    product_root = tmp_path / "product"
    web_root = product_root / "apps" / "web"
    built_root = web_root / "dist"
    built_root.mkdir(parents=True)
    (web_root / "package.json").write_text(
        json.dumps({"name": "stateport-frontend"}) + "\n",
        encoding="utf-8",
    )
    (built_root / "index.html").write_text("<!doctype html>\n", encoding="utf-8")
    return web_root, built_root


def test_product_web_root_rejects_source_only_startup(tmp_path: Path) -> None:
    web_root, built_root = _product_web_fixture(tmp_path)
    (built_root / "index.html").unlink()

    with pytest.raises(ValueError, match="production web build is missing"):
        _select_web_root(web_root)


def test_product_web_build_rejects_a_missing_adapter_identity(
    tmp_path: Path,
) -> None:
    web_root, _built_root = _product_web_fixture(tmp_path)

    with pytest.raises(ValueError, match="build identity is missing"):
        _select_web_root(web_root)


@pytest.mark.parametrize(
    "identity",
    [
        {
            "formatVersion": "stateport.web-build/v3",
            "adapter": "mock",
            "mode": "demo",
            "sourceCommit": "a" * 40,
            "sourceTree": "b" * 40,
            "sourceRef": "main",
            "sourceDirty": False,
            "builtAt": "1970-01-01T00:00:00.000Z",
        },
        {
            "formatVersion": "stateport.web-build/v1",
            "adapter": "http",
            "mode": "production",
            "sourceCommit": "a" * 40,
            "sourceTree": "b" * 40,
            "sourceRef": "main",
            "sourceDirty": False,
            "builtAt": "1970-01-01T00:00:00.000Z",
        },
        {
            "formatVersion": "stateport.web-build/v3",
            "adapter": "http",
            "mode": "production",
            "sourceCommit": "a" * 40,
            "sourceTree": "b" * 40,
            "sourceRef": "main",
            "sourceDirty": False,
            "builtAt": "1970-01-01T00:00:00.000Z",
            "unreviewed": True,
        },
        {
            "formatVersion": "stateport.web-build/v3",
            "adapter": "http",
            "mode": "production",
            "sourceCommit": "unknown",
            "sourceTree": "unknown",
            "sourceRef": "unknown",
            "sourceDirty": False,
            "builtAt": "unknown",
        },
        {
            "formatVersion": "stateport.web-build/v3",
            "adapter": "http",
            "mode": "production",
            "sourceCommit": "abc",
            "sourceTree": "b" * 40,
            "sourceRef": "main",
            "sourceDirty": True,
            "builtAt": "unknown",
        },
        {
            "formatVersion": "stateport.web-build/v3",
            "adapter": "http",
            "mode": "production",
            "sourceCommit": "a" * 40,
            "sourceTree": "b" * 40,
            "sourceRef": "has space",
            "sourceDirty": False,
            "builtAt": "unknown",
        },
        {
            "formatVersion": "stateport.web-build/v3",
            "adapter": "http",
            "mode": "production",
            "sourceCommit": "a" * 40,
            "sourceTree": "b" * 40,
            "sourceRef": "main",
            "sourceDirty": False,
            "builtAt": "2026-02-30T00:00:00.000Z",
        },
    ],
)
def test_product_web_build_rejects_a_wrong_adapter_identity(
    tmp_path: Path,
    identity: dict[str, object],
) -> None:
    web_root, built_root = _product_web_fixture(tmp_path)
    (built_root / "stateport-build.json").write_text(
        json.dumps(identity) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="must identify the HTTP adapter"):
        _select_web_root(web_root)


def test_product_web_build_accepts_the_exact_http_adapter_identity(
    tmp_path: Path,
) -> None:
    web_root, built_root = _product_web_fixture(tmp_path)
    (built_root / "stateport-build.json").write_text(
        json.dumps(
            {
                "formatVersion": "stateport.web-build/v3",
                "adapter": "http",
                "mode": "production",
                "sourceCommit": "a" * 40,
                "sourceTree": "b" * 40,
                "sourceRef": "refs/heads/main",
                "sourceDirty": False,
                "builtAt": "1970-01-01T00:00:00.000Z",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    assert (
        _select_web_root(
            web_root,
            expected_source_commit="a" * 40,
            expected_source_tree="b" * 40,
        )
        == built_root
    )


@pytest.mark.parametrize(
    ("expected_commit", "expected_tree"),
    (("b" * 40, "b" * 40), ("a" * 40, "c" * 40)),
)
def test_product_web_build_rejects_a_different_configured_product_identity(
    tmp_path: Path,
    expected_commit: str,
    expected_tree: str,
) -> None:
    web_root, built_root = _product_web_fixture(tmp_path)
    (built_root / "stateport-build.json").write_text(
        json.dumps(
            {
                "formatVersion": "stateport.web-build/v3",
                "adapter": "http",
                "mode": "production",
                "sourceCommit": "a" * 40,
                "sourceTree": "b" * 40,
                "sourceRef": "agent/old-branch",
                "sourceDirty": True,
                "builtAt": "unknown",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="does not match the configured product commit/tree"):
        _select_web_root(
            web_root,
            expected_source_commit=expected_commit,
            expected_source_tree=expected_tree,
        )


@pytest.mark.parametrize(
    ("expected_commit", "expected_tree"),
    (("a" * 40, None), (None, "b" * 40)),
)
def test_product_web_build_rejects_one_sided_expected_identity(
    tmp_path: Path,
    expected_commit: str | None,
    expected_tree: str | None,
) -> None:
    web_root, _built_root = _product_web_fixture(tmp_path)
    with pytest.raises(ValueError, match="must be supplied together"):
        _select_web_root(
            web_root,
            expected_source_commit=expected_commit,
            expected_source_tree=expected_tree,
        )


def test_product_web_build_preserves_honest_unknown_identity_semantics(
    tmp_path: Path,
) -> None:
    web_root, built_root = _product_web_fixture(tmp_path)
    (built_root / "stateport-build.json").write_text(
        json.dumps(
            {
                "formatVersion": "stateport.web-build/v3",
                "adapter": "http",
                "mode": "production",
                "sourceCommit": "unknown",
                "sourceTree": "unknown",
                "sourceRef": "unknown",
                "sourceDirty": True,
                "builtAt": "unknown",
            }
        ),
        encoding="utf-8",
    )

    assert _select_web_root(web_root) == built_root
    with pytest.raises(ValueError, match="configured product commit/tree"):
        _select_web_root(
            web_root,
            expected_source_commit="a" * 40,
            expected_source_tree="b" * 40,
        )


def test_runtime_cleanup_never_unlinks_a_successor_process_record(tmp_path: Path) -> None:
    runtime = tmp_path / "service.json"
    runtime.write_text(
        '{"pid":202,"processStartTicks":22}\n',
        encoding="utf-8",
    )

    _unlink_runtime_if_owned(runtime, 101, 11)
    assert runtime.is_file()

    _unlink_runtime_if_owned(runtime, 202, 22)
    assert not runtime.exists()


def test_daemon_cli_forwards_and_records_the_exact_source_catalog(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = _layout(tmp_path, monkeypatch)
    product_root = tmp_path / "product"
    product_root.mkdir()
    catalog = tmp_path / "custom-source-catalog.yaml"
    catalog.write_text("sourceId: custom\n", encoding="utf-8")
    observed: dict[str, object] = {}

    class FakeServer:
        server_address = ("127.0.0.1", 8790)

        @staticmethod
        def source_app() -> object:
            class FakeSourceApp:
                @staticmethod
                def _service_source_catalog_identity() -> dict[str, str]:
                    return {
                        "canonicalSourceCatalog": catalog.resolve().as_posix(),
                        "canonicalSourceCatalogDigest": "sha256:" + "d" * 64,
                    }

            return FakeSourceApp()

        def serve_forever(self, *, poll_interval: float) -> None:
            observed["pollInterval"] = poll_interval
            runtime = layout.runtime_root / "service.json"
            observed["runtime"] = json.loads(runtime.read_text(encoding="utf-8"))

        @staticmethod
        def shutdown() -> None:
            return None

        @staticmethod
        def server_close() -> None:
            return None

    def fake_server(*_args: object, **kwargs: object) -> FakeServer:
        observed["serverArgs"] = kwargs
        return FakeServer()

    monkeypatch.setattr(
        service_process,
        "_validate_product_root",
        lambda _root: {
            "repoRoot": product_root.as_posix(),
            "gitBranch": "main",
            "gitHead": "a" * 40,
            "gitTree": "b" * 40,
        },
    )
    monkeypatch.setattr(
        service_process,
        "_expected_web_source_identity",
        lambda _identity: ("a" * 40, "b" * 40),
    )
    monkeypatch.setattr(service_process, "AppServer", fake_server)
    monkeypatch.setattr(service_process.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(service_process, "_unlink_runtime_if_owned", lambda *_args: None)
    monkeypatch.setattr(
        service_process.PersistentApp,
        "_process_start_ticks",
        lambda _pid: 123,
    )
    monkeypatch.setattr(
        service_process.PersistentApp,
        "_service_runtime_fingerprint",
        lambda _root: "sha256:" + "c" * 64,
    )

    assert service_process.main([
        "--port", "8790",
        "--repo-root", str(product_root),
        "--canonical-source-catalog", str(catalog),
    ]) == 0

    server_args = observed["serverArgs"]
    runtime = observed["runtime"]
    assert isinstance(server_args, dict) and isinstance(runtime, dict)
    assert server_args["canonical_source_catalog"] == catalog.resolve()
    assert runtime["canonicalSourceCatalog"] == catalog.resolve().as_posix()
    assert runtime["canonicalSourceCatalogDigest"].startswith("sha256:")


def test_platform_operator_role_requires_private_os_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = _layout(tmp_path, monkeypatch)
    web_root = service_product_fixture(tmp_path, ROOT) / "apps" / "web"
    with pytest.raises(ValueError, match="OS-owned platform-operator-authority"):
        AppServer(("127.0.0.1", 0), layout, web_root, actor_role="platform_operator")


def test_fresh_configured_telegram_setup_can_log_before_eager_lookup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    layout = _layout(tmp_path, monkeypatch)
    monkeypatch.setattr(AppServer, "_construct_telegram_launcher", lambda self, layout: _FakeTelegramLauncher(enabled=True, instance_id="missing-instance"))
    monkeypatch.setattr(AppServer, "conversation_for_instance", lambda self, instance_id: (_ for _ in ()).throw(RuntimeError("catalog unavailable")))

    web_root = service_product_fixture(tmp_path, ROOT) / "apps" / "web"
    server = AppServer(("127.0.0.1", 0), layout, web_root)
    try:
        assert "telegram eager setup failed for missing-instance" in (layout.logs_root / "service.log").read_text(encoding="utf-8")
    finally:
        server.server_close()


def test_unconfigured_telegram_and_restart_have_initialized_logs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    layout = _layout(tmp_path, monkeypatch)
    monkeypatch.setattr(AppServer, "_construct_telegram_launcher", lambda self, layout: _FakeTelegramLauncher(enabled=False))
    web_root = service_product_fixture(tmp_path, ROOT) / "apps" / "web"
    first = AppServer(("127.0.0.1", 0), layout, web_root)
    first.server_close()
    second = AppServer(("127.0.0.1", 0), layout, web_root)
    second.server_close()
    assert (layout.logs_root / "service.log").is_file()


def test_launcher_construction_failure_is_recordable_and_does_not_leak_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    layout = _layout(tmp_path, monkeypatch)

    def fail_launcher(self: object, layout: LocalLayout) -> object:
        raise RuntimeError("synthetic launcher construction failure")

    monkeypatch.setattr(AppServer, "_construct_telegram_launcher", fail_launcher)
    web_root = service_product_fixture(tmp_path, ROOT) / "apps" / "web"
    with pytest.raises(RuntimeError, match="synthetic launcher construction failure"):
        AppServer(("127.0.0.1", 0), layout, web_root)
    assert (layout.logs_root / "service.log").is_file()
