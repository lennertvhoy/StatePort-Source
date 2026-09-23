"""The visual bridge cannot silently substitute stale or malformed evidence."""
import importlib.util
import json
import os
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location("observe_guest", Path(__file__).parent / "qualification/observe_guest.py")
observer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(observer)


def fake_codex(tmp_path, *, bad=False, hang=False):
    path = tmp_path / "codex-fixture"
    answer = {"state": "lock_screen", "description": "Fixture only", "focused_control": "unknown",
              "password_masked": "not_applicable", "elevation_evidence": "none", "uncertainty": "fixture", "command_matches": "not_requested"}
    if bad:
        answer["state"] = "release_passed"
    path.write_text("#!/usr/bin/env python3\nimport json, pathlib, sys, time\n"
                    "args=sys.argv[1:]\n"
                    "assert '--ignore-user-config' in args and '--ephemeral' in args\n"
                    "assert args[args.index('--sandbox')+1]=='read-only'\n"
                    "assert 'shell_tool' in args and 'apps' in args\n"
                    "assert 'approval_policy=\"never\"' in args\n"
                    "assert 'web_search=\"disabled\"' in args\n"
                    "assert '--ignore-rules' not in args\n"
                    + ("time.sleep(60)\n" if hang else "")
                    + f"pathlib.Path(args[args.index('--output-last-message')+1]).write_text({json.dumps(answer)!r})\n")
    path.chmod(0o700)
    return str(path)


def test_stale_pixels_never_invoke_a_model(tmp_path):
    image = tmp_path / "guest.png"
    image.write_bytes(b"fixture")
    os.utime(image, (0, 0))
    with pytest.raises(ValueError, match="fresh"):
        observer.observe(image, codex="/nonexistent")


def test_archived_observation_is_explicitly_not_current_or_qualification(tmp_path):
    image = tmp_path / "guest.png"
    image.write_bytes(b"fixture")
    os.utime(image, (0, 0))
    result = observer.observe(image, codex=fake_codex(tmp_path), archived=True)
    assert result["scope"] == "archived_image_test"
    assert result["qualification_pass"] is False
    assert result["observation"]["state"] == "lock_screen"
    assert len(result["image_sha256"]) == 64


def test_schema_violation_cannot_become_screen_evidence(tmp_path):
    image = tmp_path / "guest.png"
    image.write_bytes(b"fixture")
    with pytest.raises(ValueError, match="invalid guest observation"):
        observer.observe(image, codex=fake_codex(tmp_path, bad=True))


def test_model_timeout_terminates_owned_observer(tmp_path):
    image = tmp_path / "guest.png"
    image.write_bytes(b"fixture")
    with pytest.raises(RuntimeError, match="timed out"):
        observer.observe(image, codex=fake_codex(tmp_path, hang=True), timeout=.1)
