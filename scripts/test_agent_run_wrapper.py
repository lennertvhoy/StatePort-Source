"""Focused tests for images/bin/stateport-agent-run.

The wrapper is the image-side entrypoint that turns a read-only operator
provider mount into one OpenCode run inside the read-only-root workspace
container. These tests execute the real script against a fake opencode shim
and temporary provider/state directories; no container, credential, or network
is involved.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "images/bin/stateport-agent-run"

FAKE_KEY = "stateport-test-not-a-real-credential-0001"
SECOND_KEY = "stateport-test-not-a-real-credential-0002"

SHIM = """#!/bin/sh
{
    printf 'ARGC=%s\\n' "$#"
    for a in "$@"; do
        printf 'ARG=%s\\n' "$a"
    done
    env
} > "$STATEPORT_TEST_SHIM_OUT"
exit 0
"""


def _make_shim(path: Path) -> Path:
    path.write_text(SHIM, encoding="utf-8")
    path.chmod(0o755)
    return path


def _base_env(provider: Path, shim: Path, state: Path, out: Path) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "STATEPORT_TEST_SHIM_OUT": str(out),
        "STATEPORT_AGENT_PROVIDER_DIR": str(provider),
        "STATEPORT_AGENT_OPENCODE_BIN": str(shim),
        "STATEPORT_AGENT_STATE_DIR": str(state),
    }


def _run(
    args: list[str], env: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(WRAPPER), *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _shim_result(out: Path) -> tuple[int, list[str], dict[str, str]]:
    lines = out.read_text(encoding="utf-8").splitlines()
    argc = int(next(line.split("=", 1)[1] for line in lines if line.startswith("ARGC=")))
    argv = [line[len("ARG="):] for line in lines if line.startswith("ARG=")]
    env: dict[str, str] = {}
    for line in lines:
        if line.startswith(("ARGC=", "ARG=")):
            continue
        name, _, value = line.partition("=")
        if name:
            env[name] = value
    return argc, argv, env


def test_happy_path_exports_provider_key_state_dirs_and_config(tmp_path: Path) -> None:
    provider = tmp_path / "provider"
    provider.mkdir()
    (provider / "provider.env").write_text(
        f"OPENROUTER_API_KEY={FAKE_KEY}\n", encoding="utf-8"
    )
    (provider / "opencode.json").write_text('{"theme":"dark"}\n', encoding="utf-8")
    model = "openrouter/anthropic/claude-sonnet-test"
    (provider / "model").write_text(model + "\n", encoding="utf-8")
    state = tmp_path / "state"
    out = tmp_path / "shim.out"
    shim = _make_shim(tmp_path / "opencode")
    objective = "summarize README.md and report the result"

    result = _run([objective], _base_env(provider, shim, state, out))

    assert result.returncode == 0, result.stderr
    argc, argv, env = _shim_result(out)
    assert argc == 8
    assert argv == [
        "run",
        "--format",
        "json",
        "--model",
        model,
        "--dir",
        "/workspace",
        objective,
    ]
    assert env["OPENROUTER_API_KEY"] == FAKE_KEY
    assert env["XDG_DATA_HOME"] == str(state / "data")
    assert env["XDG_CONFIG_HOME"] == str(state / "config")
    assert env["HOME"] == str(state / "home")
    assert env["OPENCODE_CONFIG"] == str(provider / "opencode.json")
    for directory in (state, state / "data", state / "config", state / "home"):
        assert directory.is_dir()
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert FAKE_KEY not in result.stdout
    assert FAKE_KEY not in result.stderr


def test_env_model_is_used_when_no_model_file(tmp_path: Path) -> None:
    provider = tmp_path / "provider"
    provider.mkdir()
    state = tmp_path / "state"
    out = tmp_path / "shim.out"
    shim = _make_shim(tmp_path / "opencode")
    env = _base_env(provider, shim, state, out)
    env["STATEPORT_AGENT_MODEL"] = "openrouter/google/gemini-test"

    result = _run(["do the thing"], env)

    assert result.returncode == 0, result.stderr
    _, argv, shim_env = _shim_result(out)
    assert argv[4] == "openrouter/google/gemini-test"
    assert "OPENROUTER_API_KEY" not in shim_env


def test_provider_env_first_valid_line_wins_skipping_blanks_and_comments(
    tmp_path: Path,
) -> None:
    provider = tmp_path / "provider"
    provider.mkdir()
    (provider / "provider.env").write_text(
        "# operator provider material\n"
        "\n"
        f"OPENROUTER_API_KEY={FAKE_KEY}\n"
        f"OPENROUTER_API_KEY={SECOND_KEY}\n",
        encoding="utf-8",
    )
    state = tmp_path / "state"
    out = tmp_path / "shim.out"
    shim = _make_shim(tmp_path / "opencode")
    env = _base_env(provider, shim, state, out)
    env["STATEPORT_AGENT_MODEL"] = "some/model"

    result = _run(["objective"], env)

    assert result.returncode == 0, result.stderr
    _, _, shim_env = _shim_result(out)
    assert shim_env["OPENROUTER_API_KEY"] == FAKE_KEY
    assert shim_env.get("OPENROUTER_API_KEY") != SECOND_KEY
    assert SECOND_KEY not in result.stdout + result.stderr


def test_missing_model_is_refused_before_exec(tmp_path: Path) -> None:
    provider = tmp_path / "provider"
    provider.mkdir()
    state = tmp_path / "state"
    out = tmp_path / "shim.out"
    shim = _make_shim(tmp_path / "opencode")

    result = _run(["objective"], _base_env(provider, shim, state, out))

    assert result.returncode == 2
    assert "no model configured" in result.stderr
    assert not out.exists()


def test_missing_or_non_executable_binary_is_refused(tmp_path: Path) -> None:
    provider = tmp_path / "provider"
    provider.mkdir()
    state = tmp_path / "state"
    out = tmp_path / "shim.out"
    absent = tmp_path / "absent-opencode"
    env = _base_env(provider, absent, state, out)
    env["STATEPORT_AGENT_MODEL"] = "some/model"

    result = _run(["objective"], env)
    assert result.returncode == 2
    assert "missing or not executable" in result.stderr
    assert not out.exists()

    not_executable = tmp_path / "not-executable"
    not_executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    not_executable.chmod(0o644)
    env = _base_env(provider, not_executable, state, out)
    env["STATEPORT_AGENT_MODEL"] = "some/model"

    result = _run(["objective"], env)
    assert result.returncode == 2
    assert "missing or not executable" in result.stderr
    assert not out.exists()


def _malformed_provider_env_cases() -> list[tuple[str, str]]:
    return [
        ("lowercase-key", f"openrouter_api_key={FAKE_KEY}\n"),
        ("leading-digit-key", f"1KEY={FAKE_KEY}\n"),
        ("empty-value", "OPENROUTER_API_KEY=\n"),
        ("crlf-line", f"OPENROUTER_API_KEY={FAKE_KEY}\r\n"),
        ("leading-space", f" OPENROUTER_API_KEY={FAKE_KEY}\n"),
        ("no-equals", f"OPENROUTER_API_KEY {FAKE_KEY}\n"),
    ]


def test_malformed_provider_env_is_refused_without_export_or_leak(
    tmp_path: Path,
) -> None:
    for name, content in _malformed_provider_env_cases():
        case = tmp_path / name
        case.mkdir()
        provider = case / "provider"
        provider.mkdir()
        (provider / "provider.env").write_text(content, encoding="utf-8")
        state = case / "state"
        out = case / "shim.out"
        shim = _make_shim(case / "opencode")
        env = _base_env(provider, shim, state, out)
        env["STATEPORT_AGENT_MODEL"] = "some/model"

        result = _run(["objective"], env)

        assert result.returncode == 2, (name, result.stderr)
        assert "malformed" in result.stderr, (name, result.stderr)
        assert not out.exists(), name
        assert FAKE_KEY not in result.stdout, name
        assert FAKE_KEY not in result.stderr, name


def test_provider_env_without_usable_line_is_refused(tmp_path: Path) -> None:
    for name, content in (
        ("empty", ""),
        ("comments-only", "# only a comment\n\n"),
    ):
        case = tmp_path / name
        case.mkdir()
        provider = case / "provider"
        provider.mkdir()
        (provider / "provider.env").write_text(content, encoding="utf-8")
        out = case / "shim.out"
        shim = _make_shim(case / "opencode")
        env = _base_env(provider, shim, case / "state", out)
        env["STATEPORT_AGENT_MODEL"] = "some/model"

        result = _run(["objective"], env)

        assert result.returncode == 2, (name, result.stderr)
        assert "no usable" in result.stderr, (name, result.stderr)
        assert not out.exists(), name


def test_argument_count_is_enforced(tmp_path: Path) -> None:
    provider = tmp_path / "provider"
    provider.mkdir()
    (provider / "model").write_text("some/model\n", encoding="utf-8")
    state = tmp_path / "state"
    out = tmp_path / "shim.out"
    shim = _make_shim(tmp_path / "opencode")
    env = _base_env(provider, shim, state, out)

    for args in ([], ["first", "second"]):
        result = _run(args, env)
        assert result.returncode == 2, args
        assert "usage: stateport-agent-run <objective>" in result.stderr
        assert not out.exists()


def test_wrapper_source_never_enables_tracing_and_is_posix_shell() -> None:
    text = WRAPPER.read_text(encoding="utf-8")
    assert text.startswith("#!/bin/sh\n")
    assert "set -x" not in text
    assert "xtrace" not in text
