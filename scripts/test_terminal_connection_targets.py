#!/usr/bin/env python3
"""Security and capability tests for terminal transport, SSH, and Herdr."""

from __future__ import annotations

import base64
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "terminal-broker" / "src"))

from stateport_terminal_broker import (  # noqa: E402
    CAPSULE_REASON_CODES,
    AuthenticatedTerminalGateway,
    CapsuleTargetProfile,
    CapsuleTargetRegistry,
    ExternalTerminalAuditReceipt,
    GatewayActor,
    GatewayFrame,
    GatewayHandshake,
    SshTargetProfile,
    SshTargetRegistry,
    TARGET_CLASSES,
    TerminalAccessDenied,
    TerminalCapabilities,
    TerminalConnectionProfile,
    TerminalSessionBroker,
    TerminalTarget,
    TerminalTargetUnavailable,
    assert_no_browser_secret_fields,
    assess_herdr_capability,
    build_ssh_launch_plan,
    classify_ssh_failure,
    probe_herdr_version,
)


ORIGIN = "https://stateport.example"
TARGET_ID = "terminal_target_" + "a" * 32
HOST_KEY_BLOB = bytes(range(32))
HOST_KEY_DATA = base64.b64encode(HOST_KEY_BLOB).decode("ascii")
HOST_KEY_IDENTITY = "SHA256:" + base64.b64encode(hashlib.sha256(HOST_KEY_BLOB).digest()).decode("ascii").rstrip("=")


def _ssh_profile(tmp_path: Path, **changes: object) -> SshTargetProfile:
    root = tmp_path / "ssh-policy"
    root.mkdir(mode=0o700, exist_ok=True)
    root.chmod(0o700)
    known_hosts = root / "known_hosts"
    identity = root / "identity"
    known_hosts.write_text(f"stateport-staging ssh-ed25519 {HOST_KEY_DATA}\n", encoding="utf-8")
    identity.write_text("test fixture only\n", encoding="utf-8")
    known_hosts.chmod(0o600)
    identity.chmod(0o600)
    values = {
        "target_id": TARGET_ID,
        "display_name": "Staging shell",
        "connection_label": "Deploy user · staging",
        "hostname": "staging.internal",
        "username": "deploy",
        "port": 2222,
        "host_key_alias": "stateport-staging",
        "host_key_identity": HOST_KEY_IDENTITY,
        "authentication_route": "configured_key_reference",
        "configuration_root": root,
        "known_hosts_file": known_hosts,
        "identity_file": identity,
        "instance_ids": ("instance.demo",),
    }
    values.update(changes)
    return SshTargetProfile(**values)


def test_ssh_plan_ignores_ambient_configuration_agent_and_forwarding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/ambient-agent")
    profile = _ssh_profile(tmp_path)
    plan = build_ssh_launch_plan(profile, instance_id="instance.demo")
    assert plan.argv[:3] == ("/usr/bin/ssh", "-F", "none")
    options = {plan.argv[index + 1] for index, value in enumerate(plan.argv[:-1]) if value == "-o"}
    required = {
        "StrictHostKeyChecking=yes", "GlobalKnownHostsFile=none",
        "UpdateHostKeys=no", "VerifyHostKeyDNS=no", "CheckHostIP=no",
        "ProxyCommand=none", "ProxyJump=none", "ControlMaster=no",
        "ControlPath=none", "ControlPersist=no", "ClearAllForwardings=yes",
        "ForwardAgent=no", "ForwardX11=no", "ForwardX11Trusted=no",
        "GSSAPIAuthentication=no", "GSSAPIDelegateCredentials=no", "Tunnel=no",
        "PermitLocalCommand=no", "LocalCommand=none", "EnableEscapeCommandline=no",
        "EscapeChar=none", "CanonicalizeHostname=no", "BatchMode=yes",
        "NumberOfPasswordPrompts=0", "PasswordAuthentication=no",
        "KbdInteractiveAuthentication=no", "IdentityAgent=none", "IdentitiesOnly=yes",
        "RequestTTY=force", "TCPKeepAlive=no", "ConnectTimeout=10",
        "ServerAliveInterval=15", "ServerAliveCountMax=3",
    }
    assert required <= options
    assert any(item.startswith("UserKnownHostsFile=") for item in options)
    assert any(item.startswith("IdentityFile=") for item in options)
    assert f"HostKeyAlias={profile.host_key_alias}" in options
    assert plan.argv[-3:] == ("-p", "2222", "deploy@staging.internal")
    assert dict(plan.environment) == {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TERM": "xterm-256color"}
    assert "SSH_AUTH_SOCK" not in plan.environment and "HOME" not in plan.environment
    assert not hasattr(plan, "to_dict")
    assert "staging.internal" not in repr(plan) and profile.identity_file.as_posix() not in repr(plan)


@pytest.mark.skipif(not Path("/usr/bin/ssh").is_file(), reason="OpenSSH client is unavailable")
def test_installed_openssh_accepts_the_compiled_server_only_plan(tmp_path: Path) -> None:
    plan = build_ssh_launch_plan(_ssh_profile(tmp_path), instance_id="instance.demo")
    result = subprocess.run(
        (*plan.argv[:-1], "-G", plan.argv[-1]),
        env=dict(plan.environment), capture_output=True, text=True, check=False, timeout=5,
    )
    assert result.returncode == 0, result.stderr
    effective = result.stdout.lower()
    assert "stricthostkeychecking true" in effective
    assert "forwardagent no" in effective
    assert "clearallforwardings yes" in effective


def test_browser_sees_only_opaque_allowlisted_ssh_metadata(tmp_path: Path) -> None:
    profile = _ssh_profile(tmp_path)
    registry = SshTargetRegistry((profile,))
    public = registry.public_targets(instance_id="instance.demo")
    assert len(public) == 1
    assert public[0]["targetId"] == TARGET_ID
    assert public[0]["knownHostIdentity"] == HOST_KEY_IDENTITY
    assert public[0]["availability"] == "environment_gated"
    assert public[0]["reasonCode"] == "ssh_live_connection_not_validated"
    assert public[0]["capabilities"] == {
        "formatVersion": "stateport.terminal/v1",
        "targetClass": "ssh",
        "input": False,
        "output": False,
        "resize": False,
        "reconnect": False,
        "replay": False,
        "serverSideAuthentication": False,
        "transcriptCapture": False,
        "reconnectScope": "none",
    }
    assert public[0]["capabilities"]["reconnectScope"] == "none"
    encoded = json.dumps(public)
    for secret in ("staging.internal", profile.known_hosts_file.as_posix(), profile.identity_file.as_posix(), "deploy@"):
        assert secret not in encoded
    assert_no_browser_secret_fields(public[0])
    assert registry.resolve(TARGET_ID, instance_id="instance.demo") is profile
    messages = []
    for candidate, instance_id in (("terminal_target_" + "0" * 32, "instance.demo"), (TARGET_ID, "instance.other")):
        with pytest.raises(TerminalTargetUnavailable) as caught:
            registry.resolve(candidate, instance_id=instance_id)
        messages.append(str(caught.value))
    assert messages == ["ssh_target_not_allowlisted", "ssh_target_not_allowlisted"]


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("target_id", "target.ssh.enumerable", "opaque"),
        ("hostname", "-oProxyCommand=evil", "hostname"),
        ("hostname", "host;touch", "hostname"),
        ("username", "-root", "username"),
        ("host_key_alias", "alias=bad", "HostKeyAlias"),
        ("host_key_identity", "SHA256:not-a-fingerprint", "host-key"),
        ("port", 0, "port"),
    ],
)
def test_ssh_profile_rejects_argument_injection(tmp_path: Path, field: str, value: object, match: str) -> None:
    profile = _ssh_profile(tmp_path)
    with pytest.raises(ValueError, match=match):
        replace(profile, **{field: value})


def test_ssh_profile_rejects_known_hosts_or_key_outside_controlled_root(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.write_text("fixture", encoding="utf-8")
    outside.chmod(0o600)
    with pytest.raises(ValueError, match="inside"):
        _ssh_profile(tmp_path, known_hosts_file=outside)
    with pytest.raises(ValueError, match="inside"):
        _ssh_profile(tmp_path, identity_file=outside)


def test_ssh_displayed_host_key_is_bound_to_exact_trusted_entry_and_rechecked(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="does not match"):
        _ssh_profile(tmp_path, host_key_identity="SHA256:" + "A" * 43)
    profile = _ssh_profile(tmp_path)
    profile.known_hosts_file.write_text(f"stateport-staging ssh-ed25519 {base64.b64encode(b'replacement').decode('ascii')}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="changed"):
        build_ssh_launch_plan(profile, instance_id="instance.demo")


@pytest.mark.parametrize(
    "extra_entry",
    [
        f"* ssh-ed25519 {HOST_KEY_DATA}\n",
        f"other-target ssh-ed25519 {HOST_KEY_DATA}\n",
        f"stateport-staging,other-target ssh-ed25519 {HOST_KEY_DATA}\n",
        f"@cert-authority stateport-staging ssh-ed25519 {HOST_KEY_DATA}\n",
    ],
)
def test_ssh_known_hosts_rejects_any_second_or_indirect_trust_path(tmp_path: Path, extra_entry: str) -> None:
    profile = _ssh_profile(tmp_path)
    profile.known_hosts_file.write_text(
        f"stateport-staging ssh-ed25519 {HOST_KEY_DATA}\n{extra_entry}", encoding="utf-8",
    )
    with pytest.raises(ValueError, match="only the exact target alias"):
        build_ssh_launch_plan(profile, instance_id="instance.demo")


def test_ssh_configuration_rejects_group_writable_intermediate_directory(tmp_path: Path) -> None:
    profile = _ssh_profile(tmp_path)
    nested = profile.configuration_root / "nested"
    nested.mkdir(mode=0o700)
    known_hosts = nested / "known_hosts"
    known_hosts.write_text(f"stateport-staging ssh-ed25519 {HOST_KEY_DATA}\n", encoding="utf-8")
    known_hosts.chmod(0o600)
    nested.chmod(0o770)
    with pytest.raises(ValueError, match="parent directories"):
        replace(profile, known_hosts_file=known_hosts)


@pytest.mark.parametrize(
    ("diagnostic", "return_code", "expected"),
    [
        ("REMOTE HOST IDENTIFICATION HAS CHANGED!", 255, "ssh_host_key_mismatch"),
        ("Host key verification failed.", 255, "ssh_host_key_verification_failed"),
        ("Permission denied (publickey).", 255, "ssh_authentication_failed"),
        ("Connection timed out", 255, "ssh_connection_timed_out"),
        ("Connection refused", 255, "ssh_connection_refused"),
        ("unexpected", 255, "ssh_connection_failed"),
    ],
)
def test_ssh_diagnostics_reduce_to_typed_non_secret_reasons(diagnostic: str, return_code: int, expected: str) -> None:
    assert classify_ssh_failure(diagnostic, return_code) == expected


def test_herdr_071_is_truthfully_environment_gated_and_never_claims_machine_stream() -> None:
    value = assess_herdr_capability(installed=True, version_output="herdr 0.7.1")
    assert value.observed_version == "0.7.1"
    assert value.availability == "environment_gated"
    assert value.reason_code == "herdr_machine_stream_unsupported"
    public = value.to_dict(target_id="terminal_target_" + "b" * 32)
    assert public["requiredVersion"] == "0.7.2"
    assert public["machineStreamConformance"] is False
    assert not any(public["capabilities"][key] for key in ("input", "output", "resize", "reconnect", "replay"))
    assert public["capabilities"]["serverSideAuthentication"] is False


def test_herdr_missing_new_unverified_and_conforming_states_remain_honest() -> None:
    assert assess_herdr_capability(installed=False, version_output=None).reason_code == "herdr_not_installed"
    assert assess_herdr_capability(installed=True, version_output="0.7.2").reason_code == "herdr_machine_stream_unverified"
    accepted_protocol = assess_herdr_capability(installed=True, version_output="0.7.2", machine_stream_conformance=True)
    assert accepted_protocol.availability == "environment_gated"
    assert accepted_protocol.reason_code == "herdr_adapter_not_implemented"


def test_herdr_probe_invokes_only_documented_bounded_version_query(tmp_path: Path) -> None:
    executable = tmp_path / "herdr"
    executable.write_text("fixture executable", encoding="utf-8")
    executable.chmod(0o700)
    observed: dict[str, object] = {}

    def runner(argv: tuple[str, ...], **kwargs: object) -> subprocess.CompletedProcess[str]:
        observed["argv"] = argv
        observed["kwargs"] = kwargs
        return subprocess.CompletedProcess(argv, 0, "herdr 0.7.1\n", "")

    value = probe_herdr_version(executable, runner=runner)
    assert observed["argv"] == (executable.as_posix(), "--version")
    assert set(observed["kwargs"]) == {"check", "capture_output", "text", "timeout", "cwd", "env"}
    assert value.reason_code == "herdr_machine_stream_unsupported"


def test_external_receipt_separates_adapter_detach_from_remote_cleanup() -> None:
    receipt = ExternalTerminalAuditReceipt(
        "receipt.demo", "terminal.external", "terminal_target_" + "c" * 32,
        "herdr_attach", "actor.alice", "instance.demo", "detached", "completed",
        "2026-07-14T20:00:00Z", "detached", "unverified",
        "same_actor_instance_and_herdr_machine_stream_identity",
    ).to_dict()
    assert receipt["localAdapterCleanup"] == "detached"
    assert receipt["remoteProcessCleanup"] == "unverified"
    assert "transcript" not in json.dumps(receipt).lower()


def _local_gateway(tmp_path: Path) -> tuple[TerminalSessionBroker, AuthenticatedTerminalGateway, Path]:
    project = tmp_path / "project"
    project.mkdir()
    target = TerminalTarget(
        "target.local.demo", "local_pty", "Project shell", "available",
        TerminalCapabilities("local_pty", True, True, True, True, True, True),
    )
    profile = TerminalConnectionProfile(
        "profile.local.demo", target, ("instance.demo",), project, ("/bin/sh",),
    )
    broker = TerminalSessionBroker(
        (profile,), state_directory=tmp_path / "terminal-state", allowed_origins=(ORIGIN,),
    )
    return broker, AuthenticatedTerminalGateway(broker), project


def test_gateway_handshake_is_authenticated_origin_bound_url_clean_and_frame_bounded(tmp_path: Path) -> None:
    broker, gateway, project = _local_gateway(tmp_path)
    alice = GatewayActor("actor.alice", frozenset({"instance.demo"}), "oidc")
    mallory = GatewayActor("actor.mallory", frozenset({"instance.other"}), "bearer")
    handshake = GatewayHandshake(alice, "instance.demo", ORIGIN)
    try:
        with pytest.raises(ValueError, match="URL"):
            GatewayHandshake(alice, "instance.demo", ORIGIN, request_target="/v1/terminal/socket?token=secret")
        with pytest.raises(ValueError, match="64KiB"):
            GatewayFrame("input", b"x" * 65_537)
        with pytest.raises(TerminalAccessDenied):
            gateway.handle_frame(GatewayHandshake(mallory, "instance.other", ORIGIN), session_id="terminal." + "0" * 48, frame=GatewayFrame("input", b"x"))
        token = gateway.prepare(
            alice, profile_id="profile.local.demo", instance_id="instance.demo",
            selected_root=project, origin=ORIGIN,
        )
        session, receipt = gateway.accept_handshake(
            handshake, one_use_value=token.value, selected_root=project,
        )
        assert receipt.to_dict()["localAdapterCleanup"] == "not_required"
        assert receipt.to_dict()["remoteProcessCleanup"] == "not_applicable"
        assert receipt.to_dict()["reconnectScope"] == "same_actor_instance_origin_generation_until_process_exit"
        resize = gateway.handle_frame(
            handshake, session_id=session.session_id,
            frame=GatewayFrame("resize", columns=120, rows=40),
        )
        assert (resize.columns, resize.rows) == (120, 40)
        closed, close_receipt = gateway.handle_frame(
            handshake, session_id=session.session_id, frame=GatewayFrame("close"),
        )
        assert closed.cleanup in {"terminated", "already_exited"}
        assert close_receipt.to_dict()["localAdapterCleanup"] == closed.cleanup
        assert close_receipt.to_dict()["reconnectScope"] == "none"
    finally:
        broker.close()


def test_public_secret_guard_rejects_future_path_command_and_socket_fields() -> None:
    for value in ({"command": ["ssh"]}, {"identityFile": "/secret"}, {"socketUrl": "ws://example"}):
        with pytest.raises(ValueError, match="server-only"):
            assert_no_browser_secret_fields(value)


CAPSULE_TARGET_ID = "terminal_target_" + "c" * 32
CAPSULE_DIGEST = "sha256:" + "d" * 64


def _capsule_profile(**changes: object) -> CapsuleTargetProfile:
    values = {
        "target_id": CAPSULE_TARGET_ID,
        "display_name": "Demo capsule",
        "connection_label": "StatePort demo · capsule",
        "capsule_id": "capsule.demo",
        "capsule_display_digest": CAPSULE_DIGEST,
        "execution_host_socket": Path("/run/stateport/execution-control/control.sock"),
        "instance_ids": ("instance.demo",),
    }
    values.update(changes)
    return CapsuleTargetProfile(**values)


def test_capsule_target_is_environment_gated_contract_without_live_adapter() -> None:
    profile = _capsule_profile()
    registry = CapsuleTargetRegistry((profile,))
    public = registry.public_targets(instance_id="instance.demo")
    assert len(public) == 1
    assert public[0]["targetId"] == CAPSULE_TARGET_ID
    assert public[0]["targetClass"] == "capsule"
    assert public[0]["capsuleId"] == "capsule.demo"
    assert public[0]["capsuleDigest"] == CAPSULE_DIGEST
    assert public[0]["availability"] == "environment_gated"
    assert public[0]["reasonCode"] == "capsule_live_exec_not_validated"
    assert public[0]["capabilities"]["targetClass"] == "capsule"
    assert public[0]["capabilities"]["input"] is False
    assert public[0]["capabilities"]["reconnectScope"] == "none"
    encoded = json.dumps(public)
    assert profile.execution_host_socket.as_posix() not in encoded
    assert_no_browser_secret_fields(public[0])
    assert registry.resolve(CAPSULE_TARGET_ID, instance_id="instance.demo") is profile


def test_capsule_registry_refuses_unknown_or_disallowed_targets() -> None:
    profile = _capsule_profile()
    registry = CapsuleTargetRegistry((profile,))
    for candidate, instance_id in (("terminal_target_" + "0" * 32, "instance.demo"), (CAPSULE_TARGET_ID, "instance.other")):
        with pytest.raises(TerminalTargetUnavailable) as caught:
            registry.resolve(candidate, instance_id=instance_id)
        assert str(caught.value) == "capsule_target_not_allowlisted"


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("target_id", "capsule.enumerable", "opaque"),
        ("capsule_id", "capsule;evil", "contract identifier"),
        ("capsule_display_digest", "not-a-digest", "sha256"),
        ("execution_host_socket", Path("relative/socket.sock"), "absolute"),
    ],
)
def test_capsule_profile_rejects_invalid_identity(tmp_path: Path, field: str, value: object, match: str) -> None:
    profile = _capsule_profile()
    with pytest.raises(ValueError, match=match):
        replace(profile, **{field: value})


def test_capsule_external_receipt_accepts_capsule_target_class() -> None:
    receipt = ExternalTerminalAuditReceipt(
        receipt_id="receipt." + "a" * 16,
        session_id="session." + "a" * 16,
        target_id=CAPSULE_TARGET_ID,
        target_class="capsule",
        actor_id="actor.demo",
        instance_id="instance.demo",
        action="prepared",
        outcome="environment_gated",
        occurred_at="2026-08-03T00:00:00Z",
        local_adapter_cleanup="not_started",
        remote_process_cleanup="not_applicable",
        reconnect_scope="none_until_live_exec_adapter_is_validated",
    )
    assert receipt.to_dict()["targetClass"] == "capsule"


def test_capsule_target_class_registered_in_contracts() -> None:
    assert "capsule" in TARGET_CLASSES
