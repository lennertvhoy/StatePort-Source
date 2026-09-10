"""Source boundary tests; account tables/process results are explicit fixtures."""
from copy import deepcopy
import json
import hashlib
from pathlib import Path
import sys
from types import SimpleNamespace, MappingProxyType

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages/release-contracts/src"))
sys.path.insert(0, str(ROOT / "packages/execution-host/src"))

from stateport_release import updater_provisioning as bridge
from stateport_release import execution_host_provisioning as host
from stateport_release.cosign import CosignVerificationError


def _context_fixture(monkeypatch):
    operator = {"user": "operator", "uid": 1000, "gid": 1000}
    code = {"helperDigest": "sha256:" + "a" * 64, "moduleManifestDigest": "sha256:" + "b" * 64}
    fields = {"releaseId": "test-release", "signedPayloadDigest": "sha256:" + "c" * 64}
    unit = {"path": host.CONTROL_QUADLET_DIR + "/test.container", "contentDigest": host.canonical_digest("unit"), **fields}
    context = {"formatVersion": host.WORKSPACE_CONTEXT_FORMAT, "operator": operator,
               "codeIdentity": code, "controlUid": host.CONTROL_UID, "executionUid": host.EXEC_UID,
               "webUnit": unit, **fields}
    context["contextDigest"] = host.canonical_digest(context)
    monkeypatch.setattr(host, "_workspace_operator", lambda accounts: dict(operator))
    monkeypatch.setattr(host, "_workspace_json", lambda *args, **kw: (deepcopy(context), "unused"))
    monkeypatch.setattr(host, "_workspace_code_identity", lambda layout: code)
    monkeypatch.setattr(host, "_workspace_unit_fields", lambda content: fields)
    metadata = SimpleNamespace(st_uid=host.CONTROL_UID, st_gid=host.CONTROL_GID, st_nlink=1, st_mode=0o100600)
    monkeypatch.setattr(host, "_read_regular_file", lambda *args, **kw: (b"unit", metadata))
    account = SimpleNamespace(uid=host.CONTROL_UID, gid=host.CONTROL_GID, home=host.CONTROL_HOME)
    accounts = SimpleNamespace(user=lambda name: account)
    return context, accounts, metadata


@pytest.mark.parametrize("mutation", [None, "operator", "context_digest", "code", "uid", "account", "unit_owner", "unit_path", "unit_content", "release"])
def test_operator_context_refuses_changed_identity_before_any_command(monkeypatch, mutation):
    context, accounts, metadata = _context_fixture(monkeypatch)
    if mutation == "operator":
        context["operator"] = {"user": "foreign", "uid": 1001, "gid": 1001}
    elif mutation == "context_digest":
        context["contextDigest"] = "sha256:" + "d" * 64
    elif mutation == "code":
        context["codeIdentity"] = {}
    elif mutation == "uid":
        context["controlUid"] = 1000
    elif mutation == "account":
        accounts.user = lambda name: None
    elif mutation == "unit_owner":
        metadata.st_uid = 1000
    elif mutation == "unit_path":
        context["webUnit"]["path"] = "/tmp/foreign.container"
    elif mutation == "unit_content":
        context["webUnit"]["contentDigest"] = "sha256:" + "d" * 64
    elif mutation == "release":
        context["releaseId"] = "foreign"
    if mutation != "context_digest":
        context["contextDigest"] = host.canonical_digest({k: v for k, v in context.items() if k != "contextDigest"})
    if mutation is None:
        assert bridge.operator_context(accounts=accounts, layout=host.HostLayout()) == context
    else:
        with pytest.raises(host.ProvisioningRefusal):
            bridge.operator_context(accounts=accounts, layout=host.HostLayout())


@pytest.mark.parametrize("mutation", [None, "not_root", "not_helper", "authority_changed", "child_failed", "child_identity"])
def test_initializer_clears_environment_and_checks_control_result(monkeypatch, mutation):
    monkeypatch.setattr(bridge.os, "geteuid", lambda: 1000 if mutation == "not_root" else 0)
    monkeypatch.setenv("STATEPORT_ROOT_HELPER", "0" if mutation == "not_helper" else "1")
    monkeypatch.setenv("STATEPORT_UPDATER_CONTROL_PLANE", "foreign:factory")
    monkeypatch.setenv("PYTHONPATH", "/operator/code")
    monkeypatch.setenv("STATEPORT_QUADLET_ROOT", "/operator/units")
    contexts = iter([{"bound": True}, {"bound": mutation != "authority_changed"}])
    monkeypatch.setattr(bridge, "operator_context", lambda **kw: next(contexts))
    index = SimpleNamespace(release_id="release", index_digest="sha256:" + "a" * 64, signed_digest="sha256:" + "b" * 64)
    monkeypatch.setattr(host, "_verify_cli", lambda args: SimpleNamespace(index=index))
    request = {"publicData": "fixture"}
    monkeypatch.setattr(bridge, "bootstrap_request", lambda *args: request)
    calls = []
    def child(command, payload, **kwargs):
        kwargs["input"] = payload
        calls.append((command, kwargs))
        response = {"schema": "stateport.control-updater-genesis/v1", "status": "initialized",
                    "releaseId": "foreign" if mutation == "child_identity" else "release",
                    "releaseIndexDigest": index.index_digest, "signedPayloadDigest": index.signed_digest,
                    "installedIdentityDigest": "sha256:" + "c" * 64, "admissionDigest": "sha256:" + "d" * 64}
        return SimpleNamespace(returncode=1 if mutation == "child_failed" else 0, stdout=json.dumps(response).encode())
    monkeypatch.setattr(bridge, "_run_control_command", child)
    if mutation is None:
        assert bridge.initialize(SimpleNamespace())["releaseId"] == "release"
    else:
        with pytest.raises(host.ProvisioningRefusal):
            bridge.initialize(SimpleNamespace())
    if mutation in {"not_root", "not_helper", "authority_changed"}:
        assert not calls
    else:
        command, kwargs = calls[0]
        assert command[:6] == ["/usr/sbin/runuser", "-u", host.CONTROL_USER, "--", "/usr/bin/env", "-i"]
        assert command[-4:] == ["/usr/bin/python3", "-I", "-c", bridge._CONTROL_PROGRAM]
        assert "HOME=" + host.CONTROL_HOME in command
        assert "XDG_RUNTIME_DIR=/run/user/65531" in command
        assert not any("/operator/" in value or "foreign:factory" in value for value in command)
        assert kwargs["timeout"] == 900
        assert json.loads(kwargs["input"]) == request


@pytest.mark.parametrize("mutation", [None, "bundle_bytes", "bundle_symlink", "release", "oversized"])
def test_bootstrap_transport_binds_exact_bounded_public_bytes(tmp_path, monkeypatch, mutation):
    content = b'{"signed":"fixture"}\n'
    signature = {"bundle": {"uri": "https://example.test/release-index.sigstore.json",
                            "digest": "sha256:" + hashlib.sha256(content).hexdigest(), "size": len(content)}}
    path = tmp_path / "release-index.sigstore.json"
    path.write_bytes(content)
    index = SimpleNamespace(release_id="release", signed_digest="sha256:" + "b" * 64,
                            index_digest="sha256:" + "a" * 64,
                            document=MappingProxyType({"signatures": (MappingProxyType(signature),),
                                                       "signed": MappingProxyType({"images": ()})}))
    context = {"releaseId": "release", "signedPayloadDigest": index.signed_digest,
               "operator": {"user": "operator", "uid": 1000, "gid": 1000}}
    monkeypatch.setattr(bridge, "embedded_predecessor_index", lambda value: None)
    monkeypatch.setattr(bridge, "CosignVerifier", lambda **kw: object())
    if mutation == "bundle_bytes":
        path.write_bytes(b"altered")
    elif mutation == "bundle_symlink":
        path.unlink()
        target = tmp_path / "other"
        target.write_bytes(content)
        path.symlink_to(target)
    elif mutation == "release":
        context["releaseId"] = "foreign"
    elif mutation == "oversized":
        monkeypatch.setattr(bridge, "MAX_BUNDLE_BYTES", 1)
    args = SimpleNamespace(bundle_root=tmp_path, release_index=tmp_path / "release-index.json", channel="alpha")
    verified = SimpleNamespace(index=index, target={"targetId": host.WSL2_TARGET_ID})
    if mutation is None:
        result = bridge.bootstrap_request(args, verified, context)
        assert result["releaseIndex"] == json.loads(bridge.canonical_json_bytes(index.document))
        assert result["targetId"] == host.WSL2_TARGET_ID
        assert result["actorId"] == "local-owner-operator"
        custom = bridge.bootstrap_request(SimpleNamespace(**vars(args), actor_id="custom-owner"), verified, context)
        assert custom["actorId"] == "custom-owner"
        assert bridge.base64.b64decode(result["bundles"][0]["contentBase64"]) == content
        assert str(tmp_path) not in json.dumps(result)
    else:
        with pytest.raises((host.ReleaseContractError, CosignVerificationError)):
            bridge.bootstrap_request(args, verified, context)

@pytest.mark.parametrize("mutation", [None, "operator_injection", "bad_argv", "not_root", "authority_changed"])
def test_update_command_authenticates_operator_and_executes_only_fixed_control(monkeypatch, mutation):
    monkeypatch.setattr(bridge.os, "geteuid", lambda: 1000 if mutation == "not_root" else 0)
    monkeypatch.setenv("STATEPORT_ROOT_HELPER", "1")
    operator = {"user": "operator", "uid": 1000, "gid": 1000}
    contexts = iter([{"operator": operator}, {"operator": {} if mutation == "authority_changed" else operator}])
    def context(**kwargs):
        assert kwargs["require_accepted_unit"] is False
        return next(contexts)
    monkeypatch.setattr(bridge, "operator_context", context)
    request = {"schema": "stateport.control-updater-command/v1", "argv": ["status"], "release": None, "authorization": None}
    if mutation == "operator_injection":
        request["operator"] = operator
    if mutation == "bad_argv":
        request["argv"] = [1]
    calls = []
    def child(command, payload, **kwargs):
        kwargs["input"] = payload
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout=b'{"status":"fixture"}\n')
    monkeypatch.setattr(bridge, "_run_control_command", child)
    if mutation is None:
        assert bridge.execute_update(json.dumps(request).encode()) == (0, b'{"status":"fixture"}\n')
        command, kwargs = calls[0]
        assert command[:6] == ["/usr/sbin/runuser", "-u", host.CONTROL_USER, "--", "/usr/bin/env", "-i"]
        assert command[-1] == bridge._CONTROL_COMMAND_PROGRAM
        assert "STATEPORT_COSIGN=" + host.ROOT_COSIGN_PATH in command
        assert "STATEPORT_QUADLET_ROOT=" + host.CONTROL_QUADLET_DIR in command
        assert json.loads(kwargs["input"]) == {**request, "operator": operator}
        assert kwargs["timeout"] == 3600
    else:
        with pytest.raises(host.ProvisioningRefusal):
            bridge.execute_update(json.dumps(request).encode())
        assert not calls


def test_command_authority_survives_changed_revision_but_requires_root_operator_binding(monkeypatch):
    context, accounts, metadata = _context_fixture(monkeypatch)
    metadata.st_uid = 1000  # A changed unit is not the operator authentication source.
    assert bridge.operator_context(accounts=accounts, layout=host.HostLayout(), require_accepted_unit=False) == context
    context["operator"] = {**context["operator"], "uid": 1001}
    context["contextDigest"] = host.canonical_digest({k: v for k, v in context.items() if k != "contextDigest"})
    with pytest.raises(host.ProvisioningRefusal):
        bridge.operator_context(accounts=accounts, layout=host.HostLayout(), require_accepted_unit=False)


@pytest.mark.parametrize("timeout", [False, True])
def test_control_process_group_is_owned_and_stopped_on_timeout(monkeypatch, timeout):
    calls = []
    class Process:
        pid = 34567
        returncode = 0
        count = 0
        def communicate(self, payload=None, *, timeout=None):
            self.count += 1
            calls.append(("communicate", payload, timeout))
            if self.count == 1 and should_timeout:
                raise bridge.subprocess.TimeoutExpired(["control"], timeout)
            return b"result", b""
    should_timeout = timeout
    def popen(command, **kwargs):
        calls.append(("spawn", command, kwargs))
        return Process()
    monkeypatch.setattr(bridge.subprocess, "Popen", popen)
    monkeypatch.setattr(bridge.os, "killpg", lambda pid, sig: calls.append(("signal", pid, sig)))
    if timeout:
        with pytest.raises(bridge.subprocess.TimeoutExpired):
            bridge._run_control_command(["fixed-control"], b"bounded", timeout=1)
        assert ("signal", 34567, bridge.signal.SIGTERM) in calls
        assert calls[-1] == ("communicate", None, 5)
    else:
        result = bridge._run_control_command(["fixed-control"], b"bounded", timeout=1)
        assert result.stdout == b"result" and result.returncode == 0
        assert not any(call[0] == "signal" for call in calls)
    kwargs = calls[0][2]
    assert kwargs["stderr"] == bridge.subprocess.DEVNULL
    assert kwargs["start_new_session"] is True
    assert kwargs["env"] == host._ROOT_COMMAND_ENV and kwargs["cwd"] == "/"
