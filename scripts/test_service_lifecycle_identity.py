"""Regression coverage for exact local-service identity and bounded shutdown."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
for source_root in sorted((ROOT / "packages").glob("*/src")):
    sys.path.insert(0, str(source_root))
for source_root in sorted((ROOT / "apps").glob("*/src")):
    sys.path.insert(0, str(source_root))

from stateport_persistent_app import LocalLayout, PersistentApp, ServiceError  # noqa: E402
from service_test_product import service_product_fixture  # noqa: E402


def _app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> PersistentApp:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    return app


def _expected(app: PersistentApp, root: Path, *, port: int = 8790, actor_role: str = "local_user") -> dict[str, object]:
    return {
        **app._service_git_identity(root),
        **app._service_source_catalog_identity(),
        "port": port,
        "actorRole": actor_role,
        "runtimeFingerprint": app._service_runtime_fingerprint(root),
    }


def _product(tmp_path: Path, label: str) -> Path:
    container = tmp_path / label
    container.mkdir()
    return service_product_fixture(container, ROOT)


def test_running_service_is_reused_only_for_the_exact_checkout_head_role_and_port(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _app(tmp_path, monkeypatch)
    root = _product(tmp_path, "requested")
    expected = _expected(app, root)
    current = {
        "status": "running",
        "url": "http://127.0.0.1:8790/",
        "pid": 777,
        **expected,
    }
    monkeypatch.setattr(app, "service_status", lambda: dict(current))

    assert app.service_start(port=8790, repo_root=root) == current

    for field, wrong in (
        ("repoRoot", (tmp_path / "other-checkout").as_posix()),
        ("gitBranch", "agent/old-branch"),
        ("gitHead", "0" * 40),
        ("gitTree", "1" * 40),
    ):
        mismatched = dict(current)
        mismatched[field] = wrong
        monkeypatch.setattr(app, "service_status", lambda value=mismatched: dict(value))
        with pytest.raises(ServiceError, match="running service belongs to"):
            app.service_start(port=8790, repo_root=root)

    monkeypatch.setattr(app, "service_status", lambda: dict(current))
    with pytest.raises(ServiceError, match="running service belongs to"):
        app.service_start(port=8791, repo_root=root)
    with pytest.raises(ServiceError, match="running service belongs to"):
        app.service_start(port=8790, repo_root=root, actor_role="platform_operator")


def test_running_service_from_another_checkout_is_not_spawned_over_or_stopped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _app(tmp_path, monkeypatch)
    running_root = _product(tmp_path, "running")
    requested_root = _product(tmp_path, "requested")
    current = {
        "status": "running",
        "url": "http://127.0.0.1:8790/",
        "pid": 888,
        **_expected(app, running_root),
    }
    monkeypatch.setattr(app, "service_status", lambda: dict(current))
    signalled: list[tuple[int, int]] = []
    monkeypatch.setattr(os, "kill", lambda pid, sig: signalled.append((pid, sig)))

    with pytest.raises(ServiceError, match="stop it before starting") as error:
        app.service_start(port=8790, repo_root=requested_root)

    assert running_root.as_posix() in str(error.value)
    assert requested_root.as_posix() in str(error.value)
    assert signalled == []


def test_same_head_runtime_source_change_is_not_reused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _app(tmp_path, monkeypatch)
    root = _product(tmp_path, "requested")
    expected = _expected(app, root)
    current = {
        "status": "running",
        "url": "http://127.0.0.1:8790/",
        "pid": 889,
        **expected,
    }
    monkeypatch.setattr(app, "service_status", lambda: dict(current))
    changed_source = root / "apps" / "fingerprint-fixture" / "src" / "runtime.py"
    changed_source.parent.mkdir(parents=True)
    changed_source.write_text("CHANGED = True\n", encoding="utf-8")

    with pytest.raises(ServiceError, match="loaded a different source or web build"):
        app.service_start(port=8790, repo_root=root)


def test_service_preflight_requires_the_exact_web_commit_and_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _app(tmp_path, monkeypatch)
    root = _product(tmp_path, "requested")
    identity = app._service_git_identity(root)
    web = root / "apps" / "web"
    dist = web / "dist"
    dist.mkdir(parents=True, exist_ok=True)
    (web / "package.json").write_text(
        json.dumps({"name": "stateport-frontend"}) + "\n", encoding="utf-8"
    )
    (dist / "index.html").write_text("<!doctype html>\n", encoding="utf-8")
    marker = dist / "stateport-build.json"
    marker.write_text(
        json.dumps(
            {
                "formatVersion": "stateport.web-build/v3",
                "adapter": "http",
                "mode": "production",
                "sourceCommit": identity["gitHead"],
                "sourceTree": identity["gitTree"],
                "sourceRef": identity["gitBranch"],
                "sourceDirty": True,
                "builtAt": "unknown",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    app._require_matching_web_build(root, identity["gitHead"], identity["gitTree"])
    build_identity = json.loads(marker.read_text(encoding="utf-8"))
    build_identity["sourceTree"] = "0" * 40
    marker.write_text(json.dumps(build_identity) + "\n", encoding="utf-8")

    with pytest.raises(ServiceError, match="requested Git commit/tree"):
        app._require_matching_web_build(root, identity["gitHead"], identity["gitTree"])


def test_stale_runtime_process_identity_is_removed_without_signalling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _app(tmp_path, monkeypatch)
    runtime = app.layout.runtime_root / "service.json"
    runtime.write_text(
        '{"formatVersion":"stateport.service-runtime/v1","pid":321,'
        '"processStartTicks":44,"port":8790,"repoRoot":"/tmp/other"}\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(app, "_owned_service_pid", lambda _pid, **_kwargs: False)
    signalled: list[tuple[int, int]] = []
    monkeypatch.setattr(os, "kill", lambda pid, sig: signalled.append((pid, sig)))

    assert app.service_stop() == {"status": "stopped"}
    assert not runtime.exists()
    assert signalled == []


def test_post_launch_readiness_must_belong_to_the_spawned_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _app(tmp_path, monkeypatch)
    root = _product(tmp_path, "requested")
    expected = _expected(app, root)
    statuses = iter(
        (
            {"status": "stopped"},
            {
                "status": "running",
                "url": "http://127.0.0.1:8790/",
                "pid": 999,
                **expected,
            },
        )
    )
    monkeypatch.setattr(app, "service_status", lambda: dict(next(statuses)))

    class FakeProcess:
        pid = 123

        def __init__(self) -> None:
            self.terminated = False
            self.waited = False

        def poll(self) -> None:
            return None

        def terminate(self) -> None:
            self.terminated = True

        def wait(self, *, timeout: int) -> int:
            self.waited = True
            return 0

        def kill(self) -> None:
            raise AssertionError("graceful synthetic termination should not require kill")

    process = FakeProcess()
    monkeypatch.setattr(
        app,
        "_service_start_request",
        lambda **_kwargs: (root, dict(expected)),
    )
    monkeypatch.setattr(
        "stateport_persistent_app.service_launcher.subprocess.Popen",
        lambda *args, **kwargs: process,
    )
    monkeypatch.setattr("stateport_persistent_app.service_launcher.time.sleep", lambda _seconds: None)

    with pytest.raises(ServiceError, match="unexpected process"):
        app.service_start(port=8790, repo_root=root)
    assert process.terminated is True and process.waited is True


def test_launcher_binds_and_forwards_the_exact_source_catalog(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    catalog = tmp_path / "custom-source-catalog.yaml"
    catalog.write_bytes((ROOT / "sources/canonical/studydd.yaml").read_bytes())
    app = PersistentApp(
        LocalLayout.from_environment(),
        canonical_source_catalog=catalog,
    )
    app.setup_init()
    root = _product(tmp_path, "requested")
    expected = _expected(app, root)
    statuses = iter((
        {"status": "stopped"},
        {
            "status": "running",
            "url": "http://127.0.0.1:8790/",
            "pid": 123,
            **expected,
        },
    ))
    monkeypatch.setattr(app, "service_status", lambda: dict(next(statuses)))
    monkeypatch.setattr(
        app,
        "_service_start_request",
        lambda **_kwargs: (root, dict(expected)),
    )

    class FakeProcess:
        pid = 123

        @staticmethod
        def poll() -> None:
            return None

    observed_command: list[str] = []

    def launch(command: list[str], **_kwargs: object) -> FakeProcess:
        observed_command.extend(command)
        return FakeProcess()

    monkeypatch.setattr(
        "stateport_persistent_app.service_launcher.subprocess.Popen",
        launch,
    )
    monkeypatch.setattr(
        "stateport_persistent_app.service_launcher.time.sleep",
        lambda _seconds: None,
    )

    result = app.service_start(port=8790, repo_root=root)

    assert result["canonicalSourceCatalogDigest"] == expected["canonicalSourceCatalogDigest"]
    flag = observed_command.index("--canonical-source-catalog")
    assert observed_command[flag + 1] == catalog.resolve().as_posix()


def test_stop_allows_the_service_normal_teardown_window(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _app(tmp_path, monkeypatch)
    current = {
        "status": "running",
        "pid": 456,
        "port": 8790,
    }
    monkeypatch.setattr(app, "service_status", lambda: dict(current))
    ownership = iter([True] * 50 + [False])
    monkeypatch.setattr(app, "_owned_service_pid", lambda _pid, **_kwargs: next(ownership))
    monkeypatch.setattr(app, "_service_listener_open", lambda _port: False)
    monkeypatch.setattr("stateport_persistent_app.app.time.sleep", lambda _seconds: None)
    signalled: list[tuple[int, signal.Signals]] = []
    monkeypatch.setattr(os, "kill", lambda pid, sig: signalled.append((pid, sig)))

    assert app.service_stop() == {"status": "stopped", "pid": 456}
    assert signalled == [(456, signal.SIGTERM)]


def test_stop_still_fails_when_the_owned_process_exceeds_the_teardown_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _app(tmp_path, monkeypatch)
    monkeypatch.setattr(
        app,
        "service_status",
        lambda: {"status": "running", "pid": 654, "port": 8790},
    )
    monkeypatch.setattr(app, "_owned_service_pid", lambda _pid, **_kwargs: True)
    monotonic = iter((0.0, 0.0, 11.0))
    monkeypatch.setattr("stateport_persistent_app.app.time.monotonic", lambda: next(monotonic))
    monkeypatch.setattr(os, "kill", lambda _pid, _sig: None)

    with pytest.raises(ServiceError, match="within 10 seconds"):
        app.service_stop()


def test_concurrent_exact_starts_converge_on_one_service_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_app = _app(tmp_path, monkeypatch)
    second_app = PersistentApp(LocalLayout.from_environment())
    root = _product(tmp_path, "requested")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(app.service_start, port=port, repo_root=root)
                for app in (first_app, second_app)
            ]
            results = [future.result(timeout=15) for future in futures]
        assert results[0]["pid"] == results[1]["pid"]
        assert results[0]["runtimeFingerprint"] == results[1]["runtimeFingerprint"]
    finally:
        first_app.service_stop()


def test_failed_startup_is_reaped_before_an_immediate_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _app(tmp_path, monkeypatch)
    root = _product(tmp_path, "requested")
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", 0))
    blocker.listen()
    port = int(blocker.getsockname()[1])

    with pytest.raises(ServiceError, match="did not become ready"):
        app.service_start(port=port, repo_root=root)
    blocker.close()

    try:
        status = app.service_start(port=port, repo_root=root)
        assert status["status"] == "running"
    finally:
        app.service_stop()


def test_service_launches_from_a_real_linked_git_worktree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _app(tmp_path, monkeypatch)
    main = _product(tmp_path, "main-product")
    subprocess.run(
        (
            "git",
            "-C",
            str(main),
            "add",
            "packages",
            "apps",
            "config",
            "fixtures",
            "instances",
            "schemas",
            "sources",
            "templates",
            "VERSION",
        ),
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    subprocess.run(
        (
            "git",
            "-C",
            str(main),
            "-c",
            "user.name=StatePort service test",
            "-c",
            "user.email=service-test@example.invalid",
            "-c",
            "commit.gpgSign=false",
            "commit",
            "--quiet",
            "-m",
            "track worktree fixture",
        ),
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    worktree = tmp_path / "linked-product"
    subprocess.run(
        ("git", "-C", str(main), "worktree", "add", "--quiet", "--detach", str(worktree), "HEAD"),
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert (worktree / ".git").is_file()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])

    try:
        status = app.service_start(port=port, repo_root=worktree)
        assert status["status"] == "running"
        assert status["repoRoot"] == worktree.as_posix()
        assert status["gitTree"] == subprocess.run(
            ("git", "-C", str(worktree), "rev-parse", "HEAD^{tree}"),
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        assert status["processStartTicks"] > 0
    finally:
        app.service_stop()
