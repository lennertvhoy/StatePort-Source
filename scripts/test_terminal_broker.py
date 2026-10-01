#!/usr/bin/env python3
"""Adversarial tests for the governed local terminal broker."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import time

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "terminal-broker" / "src"))

import stateport_terminal_broker.broker as broker_module  # noqa: E402
from stateport_terminal_broker import (  # noqa: E402
    AuthenticatedTerminalGateway,
    GatewayActor,
    TerminalAccessDenied,
    TerminalBrokerError,
    TerminalCapabilities,
    TerminalConnectionProfile,
    TerminalQuarantined,
    TerminalSessionBroker,
    TerminalTarget,
    TerminalTargetUnavailable,
    TerminalTokenError,
)


ORIGIN = "https://stateport.example"


class Clock:
    def __init__(self, value: float = 1_800_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def _capabilities(target_class: str, available: bool = True) -> TerminalCapabilities:
    return TerminalCapabilities(
        target_class,
        available,
        available,
        available,
        available,
        available,
        True,
    )


def _profile(
    root: Path,
    *,
    replay_limit: int = 65_536,
    output_limit: int = 1_048_576,
    idle: int = 60,
    lifetime: int = 300,
    elevated: bool = False,
) -> TerminalConnectionProfile:
    return TerminalConnectionProfile(
        "profile.local.demo",
        TerminalTarget(
            "target.local.demo", "local_pty", "Project shell", "available",
            _capabilities("local_pty"),
        ),
        ("instance.demo",),
        root,
        ("/bin/sh",),
        idle_timeout_seconds=idle,
        maximum_lifetime_seconds=lifetime,
        replay_limit_bytes=replay_limit,
        output_limit_bytes=output_limit,
        elevated=elevated,
    )


def _broker(
    tmp_path: Path,
    *,
    profile: TerminalConnectionProfile | None = None,
    clock: Clock | None = None,
    token_ttl: int = 30,
) -> tuple[TerminalSessionBroker, Path]:
    project = tmp_path / "project"
    project.mkdir(exist_ok=True)
    selected = profile or _profile(project)
    state = tmp_path / "broker-state"
    return (
        TerminalSessionBroker(
            (selected,),
            state_directory=state,
            allowed_origins=(ORIGIN, "http://127.0.0.1:4317"),
            token_ttl_seconds=token_ttl,
            clock=clock,
        ),
        project,
    )


def _open(broker: TerminalSessionBroker, project: Path):
    prepared = broker.prepare_session(
        "profile.local.demo",
        actor_id="actor.alice",
        instance_id="instance.demo",
        selected_root=project,
        origin=ORIGIN,
    )
    return broker.open_session(
        prepared.value,
        actor_id="actor.alice",
        instance_id="instance.demo",
        selected_root=project,
        origin=ORIGIN,
    )


def _read_until(
    broker: TerminalSessionBroker,
    session_id: str,
    marker: bytes,
    *,
    timeout: float = 3.0,
) -> bytes:
    result = bytearray()
    deadline = time.monotonic() + timeout
    while marker not in result and time.monotonic() < deadline:
        frame = broker.read_output(
            session_id,
            actor_id="actor.alice",
            instance_id="instance.demo",
            origin=ORIGIN,
            timeout_seconds=0.1,
        )
        result.extend(frame.data)
        if frame.eof:
            break
    assert marker in result, result
    return bytes(result)


def _read_until_pattern(
    broker: TerminalSessionBroker,
    session_id: str,
    pattern: bytes,
    *,
    minimum_matches: int = 1,
    timeout: float = 3.0,
) -> bytes:
    result = bytearray()
    deadline = time.monotonic() + timeout
    compiled = re.compile(pattern)
    while len(compiled.findall(result)) < minimum_matches and time.monotonic() < deadline:
        frame = broker.read_output(
            session_id,
            actor_id="actor.alice",
            instance_id="instance.demo",
            origin=ORIGIN,
            timeout_seconds=0.1,
        )
        result.extend(frame.data)
        if frame.eof:
            break
    assert len(compiled.findall(result)) >= minimum_matches, result
    return bytes(result)


def _wait_gone(pid: int, timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while Path(f"/proc/{pid}").exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not Path(f"/proc/{pid}").exists(), f"process {pid} survived"


def test_contracts_are_versioned_and_non_local_targets_are_typed_environment_gated(tmp_path):
    ssh = TerminalTarget(
        "target.ssh.demo", "ssh", "SSH test target", "environment_gated",
        _capabilities("ssh", False), "no sanctioned SSH target is configured",
    )
    herdr = TerminalTarget(
        "target.herdr.demo", "herdr_attach", "Herdr", "unavailable",
        _capabilities("herdr_attach", False), "Herdr is not installed",
    )
    profiles = (
        TerminalConnectionProfile("profile.ssh.demo", ssh, ("instance.demo",), None),
        TerminalConnectionProfile("profile.herdr.demo", herdr, ("instance.demo",), None),
    )
    broker = TerminalSessionBroker(
        profiles,
        state_directory=tmp_path / "state",
        allowed_origins=(ORIGIN,),
    )
    try:
        assert {target.target_class for target in broker.targets()} == {"ssh", "herdr_attach"}
        assert all(target.to_dict()["formatVersion"] == "stateport.terminal/v1" for target in broker.targets())
        with pytest.raises(TerminalTargetUnavailable, match="sanctioned SSH"):
            broker.prepare_session(
                "profile.ssh.demo", actor_id="actor.alice", instance_id="instance.demo",
                selected_root=tmp_path, origin=ORIGIN,
            )
    finally:
        broker.close()


@pytest.mark.parametrize("origin", ["*", "http://example.com", "https://example.com/path", "https://user@example.com"])
def test_broker_rejects_unsafe_origin_configuration(tmp_path, origin):
    project = tmp_path / "project"
    project.mkdir()
    with pytest.raises(ValueError, match="origins"):
        TerminalSessionBroker(
            (_profile(project),), state_directory=tmp_path / "state",
            allowed_origins=(origin,),
        )


def test_local_profile_rejects_home_root_relative_root_symlink_and_state_overlap(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", home.as_posix())
    with pytest.raises(ValueError, match="home-directory"):
        TerminalSessionBroker(
            (_profile(home),), state_directory=tmp_path / "outside",
            allowed_origins=(ORIGIN,),
        )

    project = tmp_path / "project"
    project.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(project, target_is_directory=True)
    with pytest.raises(ValueError, match="non-symlink"):
        TerminalSessionBroker(
            (_profile(linked),), state_directory=tmp_path / "outside-two",
            allowed_origins=(ORIGIN,),
        )
    with pytest.raises(ValueError, match="absolute"):
        TerminalSessionBroker(
            (_profile(Path("relative-project")),), state_directory=tmp_path / "outside-three",
            allowed_origins=(ORIGIN,),
        )
    (project / ".stateport").mkdir()
    with pytest.raises(ValueError, match="outside"):
        TerminalSessionBroker(
            (_profile(project),), state_directory=project / ".stateport" / "terminal",
            allowed_origins=(ORIGIN,),
        )


def test_prepare_is_bound_to_exact_actor_instance_origin_root_and_one_use_value(tmp_path):
    broker, project = _broker(tmp_path)
    try:
        with pytest.raises(TerminalTokenError):
            broker.open_session(
                "not-a-real-one-use-value", actor_id="actor.alice",
                instance_id="instance.demo", selected_root=Path("/"), origin=ORIGIN,
            )
        token = broker.prepare_session(
            "profile.local.demo", actor_id="actor.alice", instance_id="instance.demo",
            selected_root=project, origin=ORIGIN,
        )
        with pytest.raises(TerminalTokenError):
            broker.open_session(
                token.value, actor_id="actor.mallory", instance_id="instance.demo",
                selected_root=project, origin=ORIGIN,
            )
        with pytest.raises(TerminalTokenError):
            broker.open_session(
                token.value, actor_id="actor.alice", instance_id="instance.demo",
                selected_root=project, origin=ORIGIN,
            )

        with pytest.raises(TerminalAccessDenied):
            broker.prepare_session(
                "profile.local.demo", actor_id="actor.alice", instance_id="instance.other",
                selected_root=project, origin=ORIGIN,
            )
        with pytest.raises(TerminalAccessDenied):
            broker.prepare_session(
                "profile.local.demo", actor_id="actor.alice", instance_id="instance.demo",
                selected_root=project, origin="https://evil.example",
            )
        other = tmp_path / "other"
        other.mkdir()
        with pytest.raises(TerminalAccessDenied):
            broker.prepare_session(
                "profile.local.demo", actor_id="actor.alice", instance_id="instance.demo",
                selected_root=other, origin=ORIGIN,
            )
    finally:
        broker.close()


def test_configured_root_identity_rejects_same_path_replacement(tmp_path):
    broker, project = _broker(tmp_path)
    original = tmp_path / "original-project"
    project.rename(original)
    project.mkdir()
    try:
        with pytest.raises(TerminalAccessDenied):
            broker.prepare_session(
                "profile.local.demo", actor_id="actor.alice", instance_id="instance.demo",
                selected_root=project, origin=ORIGIN,
            )
    finally:
        broker.close()


def test_one_use_value_expires_without_starting_a_process(tmp_path):
    clock = Clock()
    broker, project = _broker(tmp_path, clock=clock, token_ttl=5)
    try:
        token = broker.prepare_session(
            "profile.local.demo", actor_id="actor.alice", instance_id="instance.demo",
            selected_root=project, origin=ORIGIN,
        )
        clock.advance(6)
        with pytest.raises(TerminalTokenError):
            broker.open_session(
                token.value, actor_id="actor.alice", instance_id="instance.demo",
                selected_root=project, origin=ORIGIN,
            )
        assert broker.list_sessions(actor_id="actor.alice", instance_id="instance.demo", origin=ORIGIN) == ()
    finally:
        broker.close()


def test_real_local_pty_starts_in_exact_root_supports_io_resize_and_no_transcript_state(tmp_path):
    broker, project = _broker(tmp_path)
    try:
        session, opened = _open(broker, project)
        assert session.connected and session.state == "connected"
        assert opened.action == "created" and opened.input_bytes == 0
        resize = broker.resize(
            session.session_id, 111, 37,
            actor_id="actor.alice", instance_id="instance.demo", origin=ORIGIN,
        )
        assert (resize.columns, resize.rows) == (111, 37)

        marker = "PTY_MARKER_2fe81b"
        command = f"pwd; printf '{marker}\\n'\n".encode()
        acknowledgement = broker.write_input(
            session.session_id, command,
            actor_id="actor.alice", instance_id="instance.demo", origin=ORIGIN,
        )
        assert acknowledgement.byte_count == len(command)
        output = _read_until(broker, session.session_id, project.as_posix().encode())
        assert project.as_posix().encode() in output
        assert marker.encode() in output

        persisted = (tmp_path / "broker-state" / "terminal-broker-state.json").read_text(encoding="utf-8")
        assert marker not in persisted
        assert "pwd;" not in persisted
        assert tokenish_material_absent(persisted)

        exit_contract, receipt = broker.close_session(
            session.session_id,
            actor_id="actor.alice", instance_id="instance.demo", origin=ORIGIN,
        )
        assert exit_contract.cleanup in {"terminated", "already_exited"}
        encoded_receipt = json.dumps(receipt.to_dict(), sort_keys=True)
        assert marker not in encoded_receipt and "data" not in encoded_receipt.lower()
    finally:
        broker.close()


def test_default_local_pty_is_project_scoped_and_hides_sibling_host_data(tmp_path):
    outside = tmp_path / "outside-private.txt"
    outside.write_text("must-not-be-visible\n", encoding="utf-8")
    broker, project = _broker(tmp_path)
    try:
        session, _ = _open(broker, project)
        marker = "PROJECT_SCOPE_CONFIRMED_7b9e"
        command = (
            f"if test -e '{outside.as_posix()}'; then cat '{outside.as_posix()}'; "
            f"else printf '{marker}\\n'; fi\n"
        ).encode()
        broker.write_input(
            session.session_id,
            command,
            actor_id="actor.alice",
            instance_id="instance.demo",
            origin=ORIGIN,
        )
        output = _read_until(broker, session.session_id, marker.encode())
        assert marker.encode() in output
        assert b"must-not-be-visible" not in output
        assert outside.read_text(encoding="utf-8") == "must-not-be-visible\n"
    finally:
        broker.close()


def test_project_sandbox_retains_the_dedicated_pty_for_job_control(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    command = broker_module._project_sandbox_command(
        Path("/usr/bin/bwrap"),
        project.resolve(),
        ("/bin/bash", "--noprofile", "--norc"),
    )
    assert "--unshare-all" in command
    assert "--new-session" not in command
    assert command[-3:] == ("/bin/bash", "--noprofile", "--norc")


def test_project_sandbox_interactive_shell_has_controlling_terminal_and_job_control(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    profile = TerminalConnectionProfile(
        "profile.local.demo",
        TerminalTarget(
            "target.local.demo", "local_pty", "Project shell", "available",
            _capabilities("local_pty"),
        ),
        ("instance.demo",),
        project,
        ("/bin/bash", "--noprofile", "--norc", "-i"),
    )
    broker, project = _broker(tmp_path, profile=profile)
    try:
        session, _ = _open(broker, project)
        marker = b"STATEPORT_JOB_CONTROL_OK"
        broker.write_input(
            session.session_id,
            b"set -o | grep '^monitor'; printf 'STATEPORT_%s\\n' 'JOB_CONTROL_OK'\n",
            actor_id="actor.alice", instance_id="instance.demo", origin=ORIGIN,
        )
        output = _read_until(broker, session.session_id, marker, timeout=5.0)
        lowered = output.lower()
        assert b"cannot set terminal process group" not in lowered
        assert b"no job control" not in lowered
        assert re.search(rb"monitor\s+on", output)
    finally:
        broker.close()


def test_project_terminal_does_not_write_shell_history_into_repository(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    profile = TerminalConnectionProfile(
        "profile.local.demo",
        TerminalTarget(
            "target.local.demo", "local_pty", "Project shell", "available",
            _capabilities("local_pty"),
        ),
        ("instance.demo",),
        project,
        ("/bin/bash", "--noprofile", "--norc", "-i"),
    )
    broker, project = _broker(tmp_path, profile=profile)
    try:
        session, _ = _open(broker, project)
        broker.write_input(
            session.session_id,
            b"pwd; printf 'STATEPORT_HISTORY_GUARD\\n'\n",
            actor_id="actor.alice", instance_id="instance.demo", origin=ORIGIN,
        )
        _read_until(broker, session.session_id, b"STATEPORT_HISTORY_GUARD", timeout=5.0)
    finally:
        broker.close()
    assert not (project / ".bash_history").exists()


def test_pre_exec_gate_ignores_project_controlled_python_startup_hooks(tmp_path, monkeypatch):
    outside_marker = tmp_path / "outside-pre-gate-marker.txt"
    broker, project = _broker(tmp_path)
    user_site = (
        project
        / ".local"
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
    )
    user_site.mkdir(parents=True)
    (user_site / "sitecustomize.py").write_text(
        "from pathlib import Path\n"
        f"Path({outside_marker.as_posix()!r}).write_text('escaped before gate', encoding='utf-8')\n",
        encoding="utf-8",
    )

    def refuse_ownership_after_startup(*_args, **_kwargs):
        deadline = time.monotonic() + 0.5
        while not outside_marker.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        return None

    monkeypatch.setattr(broker_module, "_observe_started_identity", refuse_ownership_after_startup)
    try:
        prepared = broker.prepare_session(
            "profile.local.demo",
            actor_id="actor.alice",
            instance_id="instance.demo",
            selected_root=project,
            origin=ORIGIN,
        )
        with pytest.raises(TerminalBrokerError, match="ownership could not be proven before exec"):
            broker.open_session(
                prepared.value,
                actor_id="actor.alice",
                instance_id="instance.demo",
                selected_root=project,
                origin=ORIGIN,
            )
        assert not outside_marker.exists()
        assert broker.list_sessions(
            actor_id="actor.alice", instance_id="instance.demo", origin=ORIGIN,
        ) == ()
    finally:
        broker.close()


def test_explicit_elevated_profile_is_the_only_host_filesystem_scope(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    profile = _profile(project, elevated=True)
    encoded = profile.to_dict()
    assert encoded["elevated"] is True
    assert encoded["filesystemScope"] == "host"
    assert encoded["networkAccess"] is True

    normal = _profile(project).to_dict()
    assert normal["elevated"] is False
    assert normal["filesystemScope"] == "project_root"
    assert normal["networkAccess"] is False


def test_default_profile_fails_closed_when_project_sandbox_is_unavailable(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.setattr("stateport_terminal_broker.broker.shutil.which", lambda _name: None)
    with pytest.raises(ValueError, match="project-scoped terminal sandbox is unavailable"):
        TerminalSessionBroker(
            (_profile(project),),
            state_directory=tmp_path / "normal-state",
            allowed_origins=(ORIGIN,),
        )

    elevated = TerminalSessionBroker(
        (_profile(project, elevated=True),),
        state_directory=tmp_path / "elevated-state",
        allowed_origins=(ORIGIN,),
    )
    elevated.close()


def tokenish_material_absent(persisted: str) -> bool:
    state = json.loads(persisted)
    return all("value" not in receipt and "data" not in receipt for receipt in state["auditReceipts"])


def test_bounded_replay_reports_dropped_offset_and_reconnect_requires_exact_access(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    profile = _profile(project, replay_limit=32, output_limit=4096)
    broker, project = _broker(tmp_path, profile=profile)
    try:
        session, _ = _open(broker, project)
        broker.write_input(
            session.session_id, b"printf 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\\n'\n",
            actor_id="actor.alice", instance_id="instance.demo", origin=ORIGIN,
        )
        _read_until(broker, session.session_id, b"0123456789")
        replay = broker.replay_output(
            session.session_id, 0,
            actor_id="actor.alice", instance_id="instance.demo", origin=ORIGIN,
        )
        assert len(replay.data) <= 32
        assert replay.replayed and replay.dropped_before_offset > 0

        broker.disconnect_session(
            session.session_id,
            actor_id="actor.alice", instance_id="instance.demo", origin=ORIGIN,
        )
        reconnect = broker.prepare_reconnect(
            session.session_id,
            actor_id="actor.alice", instance_id="instance.demo", origin=ORIGIN,
        )
        with pytest.raises(TerminalTokenError):
            broker.reconnect_session(
                reconnect.value,
                actor_id="actor.mallory", instance_id="instance.demo",
                selected_root=project, origin=ORIGIN,
            )
        with pytest.raises(TerminalTokenError):
            broker.reconnect_session(
                reconnect.value,
                actor_id="actor.alice", instance_id="instance.demo",
                selected_root=project, origin=ORIGIN,
            )

        replacement = broker.prepare_reconnect(
            session.session_id,
            actor_id="actor.alice", instance_id="instance.demo", origin=ORIGIN,
        )
        resumed, receipt = broker.reconnect_session(
            replacement.value,
            actor_id="actor.alice", instance_id="instance.demo",
            selected_root=project, origin=ORIGIN,
        )
        assert resumed.connected and receipt.action == "reconnected"
    finally:
        broker.close()


def test_session_ids_are_not_enumerable_across_actors_and_errors_are_uniform(tmp_path):
    broker, project = _broker(tmp_path)
    try:
        session, _ = _open(broker, project)
        assert len(session.session_id) > 40
        assert broker.list_sessions(actor_id="actor.mallory", instance_id="instance.demo", origin=ORIGIN) == ()
        messages = []
        for candidate in (session.session_id, "terminal." + "0" * 48):
            with pytest.raises(TerminalAccessDenied) as caught:
                broker.write_input(
                    candidate, b"x",
                    actor_id="actor.mallory", instance_id="instance.demo", origin=ORIGIN,
                )
            messages.append(str(caught.value))
        assert messages == ["terminal access denied", "terminal access denied"]
    finally:
        broker.close()


def test_input_output_and_resize_frames_are_bounded(tmp_path):
    broker, project = _broker(tmp_path)
    try:
        session, _ = _open(broker, project)
        with pytest.raises(ValueError, match="64KiB"):
            broker.write_input(
                session.session_id, b"x" * 65_537,
                actor_id="actor.alice", instance_id="instance.demo", origin=ORIGIN,
            )
        with pytest.raises(ValueError, match="maximum_bytes"):
            broker.read_output(
                session.session_id,
                actor_id="actor.alice", instance_id="instance.demo", origin=ORIGIN,
                maximum_bytes=65_537,
            )
        with pytest.raises(ValueError, match="columns"):
            broker.resize(
                session.session_id, 0, 20,
                actor_id="actor.alice", instance_id="instance.demo", origin=ORIGIN,
            )
    finally:
        broker.close()


def test_total_output_limit_closes_session_without_persisting_terminal_bytes(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    broker, project = _broker(
        tmp_path,
        profile=_profile(project, replay_limit=32, output_limit=96),
    )
    marker = "OUTPUT_LIMIT_PRIVATE_MARKER"
    try:
        session, _ = _open(broker, project)
        broker.write_input(
            session.session_id,
            ("printf '" + marker + ("x" * 256) + "\\n'\n").encode(),
            actor_id="actor.alice", instance_id="instance.demo", origin=ORIGIN,
        )
        with pytest.raises(TerminalBrokerError, match="output limit"):
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                broker.read_output(
                    session.session_id,
                    actor_id="actor.alice", instance_id="instance.demo", origin=ORIGIN,
                    timeout_seconds=0.1,
                )
        exit_contract = broker.poll_exit(
            session.session_id,
            actor_id="actor.alice", instance_id="instance.demo", origin=ORIGIN,
        )
        assert exit_contract.reason == "output_limit"
        persisted = (tmp_path / "broker-state" / "terminal-broker-state.json").read_text(encoding="utf-8")
        assert marker not in persisted
    finally:
        broker.close()


def test_idle_and_maximum_lifetime_are_enforced_by_sweep(tmp_path):
    clock = Clock()
    project = tmp_path / "project"
    project.mkdir()
    broker, project = _broker(tmp_path, profile=_profile(project, idle=5, lifetime=10), clock=clock)
    try:
        first, _ = _open(broker, project)
        clock.advance(6)
        expired = broker.sweep_expired()
        assert [item.reason for item in expired] == ["idle_timeout"]
        assert broker.poll_exit(
            first.session_id,
            actor_id="actor.alice", instance_id="instance.demo", origin=ORIGIN,
        ).reason == "idle_timeout"

        second, _ = _open(broker, project)
        for _ in range(2):
            clock.advance(4)
            broker.resize(
                second.session_id, 80, 24,
                actor_id="actor.alice", instance_id="instance.demo", origin=ORIGIN,
            )
        clock.advance(3)
        expired = broker.sweep_expired()
        assert [item.reason for item in expired] == ["maximum_lifetime"]
    finally:
        broker.close()


def test_cleanup_terminates_same_session_child_and_detached_generation_descendant(tmp_path):
    broker, project = _broker(tmp_path)
    host_pids: list[int] = []
    try:
        session, _ = _open(broker, project)
        generation = broker._live[session.session_id].prepared.generation
        script = (
            "import os,time; pid=os.fork(); "
            "(time.sleep(60) if pid else (os.setsid(), print('DETACHED_PID',os.getpid(),flush=True), time.sleep(60)))"
        )
        # The terminal runs inside a project sandbox. The pytest interpreter
        # may be a host-only virtualenv path that is deliberately not mounted
        # there, so resolve the sandbox's supported Python from its own PATH.
        command = f"python3 -c {shlex.quote(script)} & sleep 60 & echo SAME_PID=$!\n"
        broker.write_input(
            session.session_id, command.encode(),
            actor_id="actor.alice", instance_id="instance.demo", origin=ORIGIN,
        )
        # Wait for numeric output, not the terminal's echoed command line.
        output = _read_until_pattern(
            broker,
            session.session_id,
            rb"(?:DETACHED_PID\s+\d+|SAME_PID=\d+)",
            minimum_matches=2,
        )
        assert len(set(re.findall(rb"(?:DETACHED_PID\s+|SAME_PID=)(\d+)", output))) >= 2, output
        members = broker_module._exact_generation_members(generation)
        assert members is not None and len(members) >= 3
        host_pids = [item[0] for item in members]
        exit_contract, _ = broker.close_session(
            session.session_id,
            actor_id="actor.alice", instance_id="instance.demo", origin=ORIGIN,
        )
        assert exit_contract.cleanup == "terminated"
        for pid in set(host_pids):
            _wait_gone(pid)
    finally:
        broker.close()


def test_unresolved_cleanup_quarantines_only_exact_root_and_survives_restart(tmp_path, monkeypatch):
    broker, project = _broker(tmp_path)
    session, _ = _open(broker, project)
    live_process = broker._live[session.session_id].process  # exact test cleanup identity
    live_pid = live_process.pid
    original = broker_module._exact_generation_members
    monkeypatch.setattr(broker_module, "_exact_generation_members", lambda _generation: None)
    try:
        exit_contract, receipt = broker.close_session(
            session.session_id,
            actor_id="actor.alice", instance_id="instance.demo", origin=ORIGIN,
        )
        assert exit_contract.cleanup == "cleanup_failed"
        assert receipt.outcome == "cleanup_failed"
        assert broker.quarantine()[0]["rootDigest"].startswith("sha256:")
        with pytest.raises(TerminalQuarantined):
            broker.prepare_session(
                "profile.local.demo", actor_id="actor.alice", instance_id="instance.demo",
                selected_root=project, origin=ORIGIN,
            )
    finally:
        monkeypatch.setattr(broker_module, "_exact_generation_members", original)
        try:
            os.killpg(live_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            live_process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass
        broker.close()
    _wait_gone(live_pid)

    restarted, _ = _broker(tmp_path)
    try:
        with pytest.raises(TerminalQuarantined):
            restarted.prepare_session(
                "profile.local.demo", actor_id="actor.alice", instance_id="instance.demo",
                selected_root=project, origin=ORIGIN,
            )
    finally:
        restarted.close()


def test_restart_reconciles_generation_owned_process_without_recovering_lost_pty(tmp_path):
    broker, project = _broker(tmp_path)
    state_path = tmp_path / "broker-state" / "terminal-broker-state.json"
    broker.close()

    generation = "generation." + "a" * 64
    environment = dict(os.environ)
    environment["STATEPORT_PROCESS_GENERATION"] = generation
    process = subprocess.Popen(
        ["/bin/sh", "-c", "sleep 60"], cwd=project, env=environment,
        start_new_session=True,
    )
    identity = broker_module._process_identity(process.pid)
    assert identity is not None and identity[1] == process.pid and identity[2] == process.pid
    value = json.loads(state_path.read_text(encoding="utf-8"))
    value["activeSessions"] = [{
        "sessionId": "terminal." + "b" * 48,
        "profileId": "profile.local.demo",
        "targetId": "target.local.demo",
        "actorId": "actor.alice",
        "instanceId": "instance.demo",
        "root": project.as_posix(),
        "rootDevice": project.stat().st_dev,
        "rootInode": project.stat().st_ino,
        "generation": generation,
        "createdAt": time.time(),
        "expiresAt": time.time() + 60,
        "lastActivity": time.time(),
        "pid": process.pid,
        "processGroupId": process.pid,
        "processSessionId": process.pid,
        "startTimeTicks": identity[3],
    }]
    state_path.write_text(json.dumps(value), encoding="utf-8")
    try:
        recovered, _ = _broker(tmp_path)
        try:
            process.wait(timeout=3)
            receipts = recovered.audit_receipts(
                actor_id="actor.alice", instance_id="instance.demo", origin=ORIGIN,
            )
            assert receipts[-1].action == "recovered"
            assert receipts[-1].cleanup == "terminated"
            assert recovered.list_sessions(
                actor_id="actor.alice", instance_id="instance.demo", origin=ORIGIN,
            ) == ()
        finally:
            recovered.close()
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)


def test_state_directory_has_single_broker_owner(tmp_path):
    broker, project = _broker(tmp_path)
    try:
        with pytest.raises(Exception, match="another terminal broker"):
            TerminalSessionBroker(
                (_profile(project),), state_directory=tmp_path / "broker-state",
                allowed_origins=(ORIGIN,),
            )
    finally:
        broker.close()


def test_gateway_requires_authenticated_instance_grant_and_has_no_public_listener(tmp_path):
    broker, project = _broker(tmp_path)
    gateway = AuthenticatedTerminalGateway(broker)
    alice = GatewayActor("actor.alice", frozenset({"instance.demo"}), "oidc")
    denied = GatewayActor("actor.mallory", frozenset({"instance.other"}), "bearer")
    try:
        status = gateway.capability.to_dict()
        assert status["availability"] == "available"
        assert status["reason"] == "authenticated_loopback_adapter"
        assert status["authenticationRequired"] is True
        assert status["originValidationRequired"] is True
        assert status["publicListener"] is False
        with pytest.raises(TerminalAccessDenied):
            gateway.prepare(
                denied, profile_id="profile.local.demo", instance_id="instance.demo",
                selected_root=project, origin=ORIGIN,
            )
        token = gateway.prepare(
            alice, profile_id="profile.local.demo", instance_id="instance.demo",
            selected_root=project, origin=ORIGIN,
        )
        session, _ = gateway.accept(
            alice, one_use_value=token.value, instance_id="instance.demo",
            selected_root=project, origin=ORIGIN,
        )
        assert session.actor_id == "actor.alice"
    finally:
        broker.close()
