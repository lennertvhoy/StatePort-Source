"""Host regressions for safe startup of the retained Windows qualification VM."""
import importlib.util
import json
import shutil
import socket
import subprocess
import threading
import hashlib
import time
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location("guest_choreography", Path(__file__).parent / "qualification/guest_choreography.py")
guest = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guest)


def test_launch_does_not_destroy_retained_guest_state():
    command = guest.stage_command("a" * 64)
    assert "--unregister" not in command
    assert "Remove-Item" not in command
    assert "REHEARSAL_DISTRO_EXISTS" in command
    assert "RETAINED_GUEST_EVIDENCE_EXISTS" in command
    assert command.index("NOT_ELEVATED") < command.index("Get-Volume")
    assert command.index("STAGE_HASH_MISMATCH") < command.index(";& $s}")
    assert "D:\\" not in command  # resolve the actual mounted seed drive
    assert all(c in guest.KEYS for c in command)


@pytest.mark.parametrize("digest", ["", "a" * 63, "A" * 64, "'; Remove-Item C:\\ -Recurse;"])
def test_untrusted_digest_cannot_be_typed(digest):
    with pytest.raises(ValueError):
        guest.stage_command(digest)


def test_real_powershell_parser_accepts_exact_command(tmp_path):
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell syntax parser unavailable")
    path = tmp_path / "launch.ps1"
    path.write_text(guest.stage_command("a" * 64))
    # Parse only: never execute Windows actions on this host.
    check = tmp_path / "parse.ps1"
    check.write_text("param($Path)\n$t=$null;$e=$null;[System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$t,[ref]$e) | Out-Null;if($e.Count){$e | Out-String | Write-Error;exit 1}")
    result = subprocess.run([pwsh, "-NoProfile", "-File", str(check), str(path)], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr


def test_no_console_observation_means_no_socket_or_input(monkeypatch):
    monkeypatch.setattr(guest, "Qmp", lambda *args: pytest.fail("socket opened without observed console"))
    with pytest.raises(SystemExit) as caught:
        guest.main(["--stage-sha256", "a" * 64, "--socket", "/tmp/unused-qmp.sock"])
    assert caught.value.code == 2


def test_qmp_matches_replies_and_refuses_errors(tmp_path):
    tmp_path.chmod(0o700)
    path = tmp_path / "qmp.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.listen(1)
    errors = []
    def serve():
        try:
            conn, _ = server.accept()
            with conn, conn.makefile("rwb") as stream:
                stream.write(b'{"QMP":{}}\n'); stream.flush()
                for step in range(2):
                    req = json.loads(stream.readline())
                    stream.write(b'{"event":"RESUME"}\n')
                    reply = {"id": req["id"]} | ({"return": {}} if step == 0 else {"error": {"class": "GenericError"}})
                    stream.write((json.dumps(reply) + "\n").encode()); stream.flush()
        except Exception as exc:
            errors.append(exc)
        finally:
            server.close()
    worker = threading.Thread(target=serve, daemon=True); worker.start()
    client = guest.Qmp(path)
    try:
        with pytest.raises(ValueError, match="refused"):
            client.key("ret", True)
    finally:
        client.close()
    worker.join(timeout=3)
    assert not worker.is_alive()
    assert not errors


def test_submit_requires_fresh_complete_echo_observation(tmp_path):
    image = tmp_path / "typed.png"
    image.write_bytes(b"fixture")
    report = {"scope": "guest_screen_observation", "image_sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
              "observed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "expected_stage_sha256": "a" * 64,
              "observation": {"state": "elevated_powershell", "command_matches": "yes"}}
    path = tmp_path / "observation.json"
    path.write_text(json.dumps(report))
    guest.validate_submission(path, image, "a" * 64)
    for key, value in (("scope", "archived_image_test"), ("image_sha256", "x"), ("observed_at", "2000-01-01T00:00:00Z")):
        path.write_text(json.dumps(report | {key: value}))
        with pytest.raises(ValueError):
            guest.validate_submission(path, image, "a" * 64)
    path.write_text(json.dumps(report | {"observation": {"state": "powershell", "command_matches": "unknown"}}))
    with pytest.raises(ValueError):
        guest.validate_submission(path, image, "a" * 64)


def test_typing_captures_echo_without_pressing_enter(tmp_path, monkeypatch):
    calls = []
    class FakeQmp:
        def __init__(self, path): pass
        def type_text(self, text): calls.append(("text", text))
        def combo(self, *keys): pytest.fail("Enter before echo verification")
        def call(self, name, args): calls.append((name, args))
        def close(self): pass
    monkeypatch.setattr(guest, "Qmp", FakeQmp)
    monkeypatch.setattr(guest.time, "sleep", lambda _: None)
    assert guest.main(["--socket", "/tmp/unused", "--observed-elevated-console", "--stage-sha256", "a"*64,
                       "--capture", str(tmp_path / "new.png")]) == 0
    assert "".join(v for k, v in calls if k == "text") == guest.stage_command("a"*64)
    assert all(len(v) <= 64 for k, v in calls if k == "text")
    assert calls[-1][0] == "screendump"
