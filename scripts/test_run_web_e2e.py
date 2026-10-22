#!/usr/bin/env python3
"""Focused tests for the owned web E2E launcher."""

from __future__ import annotations

import os
import signal
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import run_web_e2e  # noqa: E402


class _FakeProcess:
    pid = 24680

    def __init__(self, *, interrupted: bool = False) -> None:
        self.interrupted = interrupted
        self.wait_calls: list[float | None] = []

    def wait(self, timeout: float | None = None) -> int:
        self.wait_calls.append(timeout)
        if self.interrupted and len(self.wait_calls) == 1:
            raise KeyboardInterrupt
        return 0


def test_inherited_port_sets_explicit_url_and_forwards_arguments(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cli = tmp_path / "playwright"
    cli.write_text("", encoding="utf-8")
    process = _FakeProcess()
    captured: dict[str, object] = {}

    def fake_popen(argv: list[str], **kwargs: object) -> _FakeProcess:
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return process

    monkeypatch.setattr(run_web_e2e.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(run_web_e2e, "_port_available", lambda port: True)
    environment = {"STATEPORT_E2E_PORT": "43127", "PATH": os.environ["PATH"]}

    assert run_web_e2e.run_playwright(
        ("--workers=1", "--retries=0"),
        cwd=tmp_path,
        environment=environment,
        playwright_cli=cli,
    ) == 0
    assert captured["argv"] == [str(cli), "test", "--workers=1", "--retries=0"]
    kwargs = captured["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs["start_new_session"] is True
    child_environment = kwargs["env"]
    assert isinstance(child_environment, dict)
    assert child_environment["STATEPORT_E2E_PORT"] == "43127"
    assert child_environment["STATEPORT_E2E_BASE_URL"] == "http://127.0.0.1:43127"


def test_occupied_inherited_port_is_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cli = tmp_path / "playwright"
    cli.write_text("", encoding="utf-8")
    monkeypatch.setattr(run_web_e2e, "_port_available", lambda port: False)

    with pytest.raises(RuntimeError, match="occupied"):
        run_web_e2e.run_playwright(
            (),
            cwd=tmp_path,
            environment={"STATEPORT_E2E_PORT": "43127"},
            playwright_cli=cli,
        )


def test_missing_port_is_leased_ephemerally(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cli = tmp_path / "playwright"
    cli.write_text("", encoding="utf-8")
    process = _FakeProcess()
    captured: dict[str, object] = {}

    def fake_popen(argv: list[str], **kwargs: object) -> _FakeProcess:
        captured["kwargs"] = kwargs
        return process

    monkeypatch.setattr(run_web_e2e.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(run_web_e2e, "_port_available", lambda port: True)

    assert run_web_e2e.run_playwright(
        (), cwd=tmp_path, environment={}, playwright_cli=cli
    ) == 0
    child_environment = captured["kwargs"]["env"]
    assert isinstance(child_environment, dict)
    port = int(child_environment["STATEPORT_E2E_PORT"])
    assert port != 4173
    assert child_environment["STATEPORT_E2E_BASE_URL"] == f"http://127.0.0.1:{port}"


def test_interruption_terminates_only_the_owned_process_group(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cli = tmp_path / "playwright"
    cli.write_text("", encoding="utf-8")
    process = _FakeProcess(interrupted=True)
    killed: list[tuple[int, signal.Signals]] = []

    def fake_killpg(process_group: int, signum: signal.Signals) -> None:
        killed.append((process_group, signum))

    monkeypatch.setattr(run_web_e2e.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(run_web_e2e, "_port_available", lambda port: True)
    monkeypatch.setattr(run_web_e2e.os, "killpg", fake_killpg)

    with pytest.raises(KeyboardInterrupt):
        run_web_e2e.run_playwright(
            (),
            cwd=tmp_path,
            environment={"STATEPORT_E2E_PORT": "43127"},
            playwright_cli=cli,
        )
    assert killed == [(process.pid, run_web_e2e.signal.SIGTERM)]
    assert process.wait_calls == [None, 5]
