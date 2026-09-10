"""Bounded operator/control updater transport tests.

Release signatures in these tests are structural fixtures; they do not claim
production cryptographic verification.
"""

from __future__ import annotations

import base64
from copy import deepcopy
import io
import json
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
for source in (ROOT, ROOT / "packages/release-contracts/src", ROOT / "packages/updater/src"):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from stateport_release import canonical_json_bytes  # noqa: E402
from stateport_updater import control_cli, operator_cli  # noqa: E402
from stateport_updater.installed import AUTHORIZATION_BUNDLE_SCHEMA  # noqa: E402
from scripts.test_stateport_updater_bootstrap import _request  # noqa: E402


def test_operator_parser_preserves_flags_but_rejects_unsafe_entries() -> None:
    assert operator_cli._parse_argv(["status"]) == ["status"]
    assert operator_cli._parse_argv(["plan", "--rollback"]) == ["plan", "--rollback"]
    with pytest.raises(operator_cli.OperatorTransportRefusal):
        operator_cli._parse_argv(["serve"])
    with pytest.raises(operator_cli.OperatorTransportRefusal):
        operator_cli._parse_argv(["status", "--state-root", "/tmp/foreign"])


def test_operator_invoke_uses_fixed_root_command_and_bounded_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    class Completed:
        returncode = 0
        stdout = b'{"result":"ok"}\n'

    def run(command, **kwargs):
        observed["command"] = command
        observed.update(kwargs)
        return Completed()

    monkeypatch.setattr(operator_cli.subprocess, "run", run)
    response = operator_cli._invoke(
        operator_cli._root_request(["status"], {}, None)
    )
    assert response == (0, b'{"result":"ok"}\n')
    assert observed["command"] == list(operator_cli.ROOT_COMMAND)
    assert observed["cwd"] == "/"
    assert observed["env"] == {"PATH": "/usr/bin:/bin"}
    assert b"--state-root" not in observed["input"]


def test_operator_authorize_writes_child_bundle_create_only(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    bundle = {
        "schema": AUTHORIZATION_BUNDLE_SCHEMA,
        "decision": {"requestId": "request"},
        "reservation": {"reservationId": "reservation"},
    }
    monkeypatch.setattr(operator_cli, "_invoke", lambda _request: (0, canonical_json_bytes(bundle) + b"\n"))
    output = tmp_path / "authorization.json"
    assert operator_cli.main(["authorize", "--plan-id", "plan", "--output", str(output)]) == 0
    assert json.loads(output.read_text()) == bundle
    assert json.loads(capsysbinary.readouterr().out) == {
        "schema": "stateport.updater-result/v1",
        "result": "authorization_reserved",
        "planId": "plan",
    }


def test_operator_release_transport_is_bounded_and_public(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    request = _request()
    index_path = tmp_path / "release-index.json"
    index_path.write_bytes(canonical_json_bytes(request["releaseIndex"]))
    index_path.chmod(0o644)
    for item in request["bundles"]:
        signature = item["signature"]
        name = operator_cli.signature_bundle_name(signature)
        (tmp_path / name).write_bytes(base64.b64decode(item["contentBase64"]))
        (tmp_path / name).chmod(0o644)
    release = operator_cli._release_transport(index_path)
    assert release["expectedSignedPayloadDigest"] == request["expectedSignedPayloadDigest"]


def test_operator_accepts_authorize_stdout(monkeypatch: pytest.MonkeyPatch) -> None:
    bundle = {
        "schema": AUTHORIZATION_BUNDLE_SCHEMA,
        "decision": {"requestId": "request"},
        "reservation": {"reservationId": "reservation"},
    }
    monkeypatch.setattr(operator_cli, "_invoke", lambda _request: (0, canonical_json_bytes(bundle) + b"\n"))
    assert operator_cli.main(["authorize", "--plan-id", "plan", "--output", "-"]) == 0


def test_control_stage_rejects_mismatched_release_binding(tmp_path: Path) -> None:
    request = _request()
    release = {
        "releaseIndex": request["releaseIndex"],
        "expectedIndexDigest": "sha256:" + "0" * 64,
        "expectedSignedPayloadDigest": request["expectedSignedPayloadDigest"],
        "channel": request["channel"],
        "targetId": request["targetId"],
        "bundles": request["bundles"],
        "imageManifests": request["imageManifests"],
    }
    with pytest.raises(control_cli.ControlTransportRefusal):
        control_cli._stage_release(release, tmp_path)


def test_control_check_requires_release_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(control_cli, "_validate_operator_record", lambda _operator: None)
    monkeypatch.setattr(control_cli.os, "getuid", lambda: control_cli.CONTROL_UID)
    monkeypatch.setattr(control_cli.os, "geteuid", lambda: control_cli.CONTROL_UID)
    monkeypatch.setattr(control_cli.os, "getgid", lambda: control_cli.CONTROL_GID)
    monkeypatch.setattr(control_cli.os, "getegid", lambda: control_cli.CONTROL_GID)
    request = {
        "schema": control_cli.REQUEST_SCHEMA,
        "argv": ["check", "--release-index", "/operator/private/index.json"],
        "release": {},
        "authorization": None,
        "operator": {"user": "operator", "uid": 1000, "gid": 1000},
    }
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(canonical_json_bytes(request))))
    assert control_cli.main() == 77


def test_control_cli_rejects_caller_environment_and_state_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(control_cli.os, "getuid", lambda: control_cli.CONTROL_UID)
    monkeypatch.setattr(control_cli.os, "geteuid", lambda: control_cli.CONTROL_UID)
    monkeypatch.setattr(control_cli.os, "getgid", lambda: control_cli.CONTROL_GID)
    monkeypatch.setattr(control_cli.os, "getegid", lambda: control_cli.CONTROL_GID)
    monkeypatch.setenv("STATEPORT_UPDATER_CONTROL_PLANE", "caller:factory")
    request = {
        "schema": control_cli.REQUEST_SCHEMA,
        "argv": ["status"],
        "release": {},
        "authorization": None,
        "operator": {"user": "operator", "uid": 1000, "gid": 1000},
    }
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(canonical_json_bytes(request))))
    assert control_cli.main() == 77


def test_control_cli_injects_fixed_state_and_operator_binding(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.delenv("STATEPORT_UPDATER_CONTROL_PLANE", raising=False)
    monkeypatch.setattr(control_cli, "CONTROL_STATE_ROOT", tmp_path / "control")
    root = tmp_path / "control" / "trust"
    root.mkdir(parents=True)
    (tmp_path / "control").chmod(0o700)
    root.chmod(0o700)
    operator_record = root / "operator.json"
    operator_record.write_text(
        json.dumps(
            {
                "schema": "stateport.control-updater-operator/v1",
                "operator": {"user": "operator", "uid": 1000, "gid": 1000},
                "actorId": "operator",
            }
        )
    )
    operator_record.chmod(0o600)
    monkeypatch.setattr(control_cli.os, "getuid", lambda: control_cli.CONTROL_UID)
    monkeypatch.setattr(control_cli.os, "geteuid", lambda: control_cli.CONTROL_UID)
    monkeypatch.setattr(control_cli.os, "getgid", lambda: control_cli.CONTROL_GID)
    monkeypatch.setattr(control_cli.os, "getegid", lambda: control_cli.CONTROL_GID)
    monkeypatch.setattr(control_cli, "_validate_operator_record", lambda _operator: None)
    captured: dict[str, object] = {}

    def fake_main(argv, *, control_plane=None):
        captured["argv"] = argv
        captured["control_plane"] = control_plane
        return 0

    monkeypatch.setattr(control_cli.cli, "main", fake_main)
    request = {
        "schema": control_cli.REQUEST_SCHEMA,
        "argv": ["status"],
        "release": {},
        "authorization": None,
        "operator": {"user": "operator", "uid": 1000, "gid": 1000},
    }
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(canonical_json_bytes(request))))
    assert control_cli.main() == 0
    assert captured["argv"] == ["--state-root", str(tmp_path / "control"), "status"]


@pytest.mark.parametrize("argv", [
    ["--state", "/tmp/foreign", "status"],
    ["check", "--release-i", "/tmp/foreign"],
    ["authorize", "--plan-id", "plan", "--out", "/tmp/foreign"],
    ["apply", "--plan-id", "plan", "--author", "/tmp/foreign"],
    ["policy", "set", "--mod", "manual"],
])
def test_transport_rejects_abbreviated_paths_before_execution(argv, monkeypatch):
    called = []
    monkeypatch.setattr(operator_cli, "_invoke", lambda request: called.append(request))
    assert operator_cli.main(argv) == 77
    assert called == []
    with pytest.raises(control_cli.ControlTransportRefusal):
        control_cli._argv(argv)


@pytest.mark.parametrize("code", [1, 3, 77])
def test_operator_preserves_control_failure_result(code, monkeypatch, capsysbinary):
    response = canonical_json_bytes({"schema": "stateport.updater-error/v1", "code": "retained_failure", "status": "failed"}) + b"\n"
    monkeypatch.setattr(operator_cli, "_invoke", lambda _request: (code, response))
    assert operator_cli.main(["status"]) == code
    assert capsysbinary.readouterr().out == response


def test_operator_does_not_claim_no_effect_after_lost_control_result(monkeypatch, capsysbinary):
    def interrupted(_request):
        raise OSError("fixture interrupted after submission")
    monkeypatch.setattr(operator_cli, "_invoke", interrupted)
    assert operator_cli.main(["status"]) == 77
    assert json.loads(capsysbinary.readouterr().out)["status"] == "outcome_unknown"


def test_release_budget_refuses_before_base64_allocation(tmp_path: Path, monkeypatch) -> None:
    request = _request()
    content = canonical_json_bytes(request["releaseIndex"])
    # Enough for the index, but not a single large signature. Subsequent
    # signature files must never be read and no base64 copy may be allocated.
    monkeypatch.setattr(operator_cli, "MAX_REQUEST_BYTES", 2 * (len(content) + 2048))
    reads = []
    def read(path, maximum):
        reads.append(path)
        return content if len(reads) == 1 else b"x" * 4096
    monkeypatch.setattr(operator_cli, "_file_bytes", read)
    def encode(_value):
        pytest.fail("oversized bundle must refuse before encoding")
    monkeypatch.setattr(operator_cli.base64, "b64encode", encode)
    with pytest.raises(operator_cli.OperatorTransportRefusal, match="byte bound"):
        operator_cli._release_transport(tmp_path / "index.json")
    assert len(reads) == 2


def test_file_growth_after_stat_is_still_bounded(tmp_path: Path, monkeypatch) -> None:
    tmp_path.chmod(0o700)
    path = tmp_path / "bundle"
    path.write_bytes(b"x" * 100)
    observed = path.lstat()
    from types import SimpleNamespace
    monkeypatch.setattr(Path, "lstat", lambda self: SimpleNamespace(
        st_mode=observed.st_mode, st_uid=observed.st_uid, st_size=0))
    with pytest.raises(operator_cli.OperatorTransportRefusal, match="byte bound"):
        operator_cli._file_bytes(path, 10)


def test_control_late_failure_does_not_claim_no_execution(tmp_path: Path, monkeypatch, capsysbinary) -> None:
    monkeypatch.setattr(control_cli.os, "getuid", lambda: control_cli.CONTROL_UID)
    monkeypatch.setattr(control_cli.os, "geteuid", lambda: control_cli.CONTROL_UID)
    monkeypatch.setattr(control_cli.os, "getgid", lambda: control_cli.CONTROL_GID)
    monkeypatch.setattr(control_cli.os, "getegid", lambda: control_cli.CONTROL_GID)
    monkeypatch.setattr(control_cli, "_validate_operator_record", lambda _value: None)
    monkeypatch.setattr(control_cli, "_validate_environment", lambda: None)
    marker = tmp_path / "durable-effect"
    def failed_command(*_args, **_kwargs):
        marker.write_text("effect happened")
        raise OSError("response failed after effect")
    monkeypatch.setattr(control_cli.cli, "main", failed_command)
    request = {"schema": control_cli.REQUEST_SCHEMA, "argv": ["status"], "release": {},
               "authorization": None, "operator": {"user": "operator", "uid": 1000, "gid": 1000}}
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(canonical_json_bytes(request))))
    assert control_cli.main() == 77
    assert marker.read_text() == "effect happened"
    assert json.loads(capsysbinary.readouterr().out)["status"] == "outcome_unknown"
