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


def test_adopted_signin_is_copied_not_linked_and_never_exported_or_echoed(tmp_path: Path) -> None:
    canary = "SECRET_CANARY_adopted_wrapper"
    provider = tmp_path / "provider"
    provider.mkdir()
    auth = provider / "auth.json"
    auth.write_text('{"opencode-go":{"type":"api","key":"%s"}}\n' % canary, encoding="utf-8")
    auth.chmod(0o644)
    (provider / "model").write_text("opencode-go/glm-5\n", encoding="utf-8")
    state = tmp_path / "state"
    out = tmp_path / "shim.out"
    shim = _make_shim(tmp_path / "opencode")

    result = _run(["summarize"], _base_env(provider, shim, state, out))

    assert result.returncode == 0, result.stderr
    copy = state / "data" / "opencode" / "auth.json"
    info = os.lstat(copy)
    assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
    assert info.st_ino != os.lstat(auth).st_ino and info.st_nlink == 1
    assert copy.read_bytes() == auth.read_bytes()
    assert stat.S_IMODE((state / "data" / "opencode").stat().st_mode) == 0o700
    assert not list((state / "data" / "opencode").glob(".auth*"))
    _, argv, shim_env = _shim_result(out)
    assert argv[4] == "opencode-go/glm-5"
    assert shim_env["XDG_DATA_HOME"] == str(state / "data")
    assert canary not in "".join(f"{k}={v}" for k, v in shim_env.items())  # a file, not an environment value
    assert canary not in result.stdout and canary not in result.stderr
    # The runtime refreshes its copy, never the read-only original.
    assert auth.read_text() == copy.read_text()


def test_adopted_signin_symlink_is_ignored_and_stale_copy_is_replaced(tmp_path: Path) -> None:
    provider = tmp_path / "provider"
    provider.mkdir()
    real = tmp_path / "elsewhere.json"
    real.write_text('{"x":{"type":"api","key":"k"}}', encoding="utf-8")
    (provider / "auth.json").symlink_to(real)
    (provider / "model").write_text("m/x\n", encoding="utf-8")
    state = tmp_path / "state"
    stale = state / "data" / "opencode"
    stale.mkdir(parents=True)
    (stale / "auth.json").write_text("old", encoding="utf-8")
    out = tmp_path / "shim.out"
    shim = _make_shim(tmp_path / "opencode")

    assert _run(["go"], _base_env(provider, shim, state, out)).returncode == 0
    assert (stale / "auth.json").read_text() == "old"  # a symlinked source is never followed

    (provider / "auth.json").unlink()
    (provider / "auth.json").write_text('{"y":{"type":"api","key":"new"}}', encoding="utf-8")
    assert _run(["go"], _base_env(provider, shim, state, out)).returncode == 0
    assert (stale / "auth.json").read_text() == '{"y":{"type":"api","key":"new"}}'
    assert not (stale / "auth.json").is_symlink()


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


# --- first run in a fresh workspace volume (measured in the dev loop, 2026-10-02) -------------------------------
#
# OpenCode resolves the model against its catalog cache ($HOME/.cache/opencode/models.json). A fresh workspace
# volume has none, and the first `opencode run` raced the background catalog fetch: it exited 1 with
# `ProviderModelNotFoundError` surfaced to the user as "Unexpected server error", and only the SECOND run worked.
# Measured with the real opencode 1.18.31 in the real sealed container: 4 of 4 first runs failed, 4 of 4 later runs
# succeeded; `opencode models --refresh` (2 s) before the first run removes the failure.

CATALOG_SHIM = """#!/bin/sh
# records every invocation; `run` fails like the real opencode unless the model catalog cache exists
printf '%s\\n' "$*" >> "$STATEPORT_TEST_CALLS"
cache="$HOME/.cache/opencode/models.json"
case "$1" in
  models)
    [ -n "${STATEPORT_TEST_MODELS_SLEEP:-}" ] && sleep "$STATEPORT_TEST_MODELS_SLEEP"
    [ "${STATEPORT_TEST_MODELS_FAIL:-0}" = 1 ] && { echo "offline: $STATEPORT_TEST_CANARY" >&2; echo "offline: $STATEPORT_TEST_CANARY"; exit 1; }
    mkdir -p "$(dirname "$cache")" && echo '{}' > "$cache"
    echo "models cache refreshed: $STATEPORT_TEST_CANARY"
    exit 0 ;;
  run)
    [ -s "$cache" ] || { echo '{"type":"error","error":{"name":"UnknownError","data":{"message":"Unexpected server error."}}}'; exit 1; }
    echo '{"type":"text","part":{"text":"done"}}'
    exit 0 ;;
esac
exit 3
"""


def _catalog_case(tmp_path: Path, **extra: str) -> tuple[dict[str, str], Path, Path]:
    provider = tmp_path / "provider"
    provider.mkdir()
    (provider / "model").write_text("opencode-go/space-bunny-free\n", encoding="utf-8")
    state = tmp_path / "state"
    shim = tmp_path / "opencode"
    shim.write_text(CATALOG_SHIM, encoding="utf-8")
    shim.chmod(0o755)
    calls = tmp_path / "calls.log"
    env = _base_env(provider, shim, state, tmp_path / "shim.out")
    env.update({"STATEPORT_TEST_CALLS": str(calls), "STATEPORT_TEST_CANARY": "SECRET_CANARY_catalog_warmup", **extra})
    return env, state, calls


def test_first_run_in_a_fresh_workspace_warms_the_model_catalog_before_running(tmp_path: Path) -> None:
    env, state, calls = _catalog_case(tmp_path)

    result = _run(["Create a file hello.txt containing hello."], env)

    assert result.returncode == 0, (result.stdout, result.stderr)
    invocations = calls.read_text(encoding="utf-8").splitlines()
    assert invocations[0] == "models --refresh"
    assert invocations[1].startswith("run --format json --model opencode-go/space-bunny-free --dir /workspace ")
    assert len(invocations) == 2
    assert (state / "home" / ".cache" / "opencode" / "models.json").is_file()
    assert '"done"' in result.stdout  # the run's own output still goes straight to the caller
    assert "SECRET_CANARY_catalog_warmup" not in result.stdout + result.stderr  # the warm-up's output is not relayed


def test_a_cached_catalog_is_not_refreshed_again(tmp_path: Path) -> None:
    env, state, calls = _catalog_case(tmp_path)
    cache = state / "home" / ".cache" / "opencode"
    cache.mkdir(parents=True)
    (cache / "models.json").write_text("{}", encoding="utf-8")

    result = _run(["go"], env)

    assert result.returncode == 0, result.stderr
    assert [line.split()[0] for line in calls.read_text(encoding="utf-8").splitlines()] == ["run"]


def test_an_offline_catalog_refresh_does_not_block_the_run_or_leak_its_output(tmp_path: Path) -> None:
    env, _state, calls = _catalog_case(tmp_path, STATEPORT_TEST_MODELS_FAIL="1")

    result = _run(["go"], env)

    # the run is still attempted and reports its OWN error: the wrapper never turns a failed warm-up into a refusal
    assert [line.split()[0] for line in calls.read_text(encoding="utf-8").splitlines()] == ["models", "run"]
    assert result.returncode == 1 and "Unexpected server error" in result.stdout
    assert "SECRET_CANARY_catalog_warmup" not in result.stdout + result.stderr


def test_a_hanging_catalog_refresh_is_bounded(tmp_path: Path) -> None:
    import time

    env, _state, calls = _catalog_case(tmp_path, STATEPORT_TEST_MODELS_SLEEP="25", STATEPORT_AGENT_WARMUP_SECONDS="1")
    began = time.monotonic()

    result = _run(["go"], env)

    assert time.monotonic() - began < 15
    assert [line.split()[0] for line in calls.read_text(encoding="utf-8").splitlines()] == ["models", "run"]
    assert result.returncode == 1  # no catalog, so the shim's run fails like the real one would; the bound only protects the caller
