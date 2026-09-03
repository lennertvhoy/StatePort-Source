from __future__ import annotations

import os
from pathlib import Path
import sys
import threading
import time

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "external-engine-runtime" / "src"))

from external_engine_runtime import (  # noqa: E402
    ProcessSpec,
    TemporaryWorkspace,
    decode_jsonl,
    filtered_environment,
    run_process,
)
from external_engine_runtime.runtime import ProcessRuntimeError  # noqa: E402


def test_environment_is_allowlisted_and_jsonl_is_strict(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STATEPORT_TEST_SECRET", "must-not-cross-boundary")
    env = filtered_environment(source=os.environ, allow=("PATH",))
    assert "STATEPORT_TEST_SECRET" not in env
    assert filtered_environment(source={}, allow=("PATH",)) == {}
    with pytest.raises(ValueError, match="explicitly allowlisted"):
        filtered_environment(source={}, allow=("PATH",), overrides={"HOME": str(tmp_path)})
    assert decode_jsonl('{"type":"started"}\n{"type":"completed"}\n')[1]["type"] == "completed"
    with pytest.raises(ProcessRuntimeError, match="malformed"):
        decode_jsonl('{"type":"started"}\nnot-json\n')


def test_process_runtime_captures_output_and_enforces_limits(tmp_path: Path) -> None:
    result = run_process(ProcessSpec(("python3", "-c", "print('ok')"), tmp_path, environment=filtered_environment()))
    assert result.ok and result.stdout.strip() == "ok" and result.cleanup == "not_required"
    limited = run_process(ProcessSpec(("python3", "-c", "import os; os.write(1, b'x' * 1000)"), tmp_path, max_output_bytes=32, environment=filtered_environment()))
    assert limited.output_limited and limited.cleanup in {"terminated", "killed", "already_exited"}
    assert len(limited.stdout.encode("utf-8")) == 32
    assert limited.stderr == ""

    stderr_limited = run_process(ProcessSpec(("python3", "-c", "import os; os.write(2, b'y' * 1000)"), tmp_path, max_output_bytes=31, environment=filtered_environment()))
    assert stderr_limited.output_limited
    assert stderr_limited.stdout == ""
    assert len(stderr_limited.stderr.encode("utf-8")) == 31

    combined = run_process(ProcessSpec(
        (sys.executable, "-c", "import os; os.write(1, b'a' * 20); os.write(2, b'b' * 20)"),
        tmp_path,
        max_output_bytes=31,
        environment={},
    ))
    assert combined.output_limited
    assert len(combined.stdout.encode("utf-8")) + len(combined.stderr.encode("utf-8")) <= 31

    invalid_utf8 = run_process(ProcessSpec((sys.executable, "-c", "import os; os.write(1, b'\\xff' * 1000)"), tmp_path, max_output_bytes=32, environment={}))
    assert invalid_utf8.output_limited
    assert len(invalid_utf8.stdout.encode("utf-8")) <= 32


def test_process_runtime_honours_an_explicitly_empty_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", "/public-test-sentinel")
    result = run_process(ProcessSpec((sys.executable, "-c", "import os; print(os.environ.get('PATH', 'missing'))"), tmp_path, environment={}))
    assert result.ok
    assert result.stdout.strip() == "missing"


def test_process_runtime_bounds_and_delivers_explicit_stdin(tmp_path: Path) -> None:
    result = run_process(ProcessSpec(
        (sys.executable, "-c", "import sys; print(sys.stdin.read())"),
        tmp_path,
        stdin_text="typed proposal",
        environment={},
    ))
    assert result.ok
    assert result.stdout.strip() == "typed proposal"
    with pytest.raises(ValueError, match="64KiB"):
        ProcessSpec((sys.executable, "-c", "pass"), tmp_path, stdin_text="x" * 65_537)


def test_supervision_registration_gate_precedes_requested_program_execution(
    tmp_path: Path,
) -> None:
    executed = tmp_path / "executed"
    registered = tmp_path / "registered"

    def on_started(_identity: object) -> None:
        assert not executed.exists()
        registered.write_text("durable-before-exec\n", encoding="utf-8")

    result = run_process(ProcessSpec(
        (
            sys.executable, "-c",
            "from pathlib import Path; Path('executed').write_text('after-gate\\n')",
        ),
        tmp_path,
        environment={},
        on_started=on_started,
    ))
    assert result.ok and registered.is_file() and executed.is_file()

    refused = tmp_path / "must-not-execute"
    with pytest.raises(ProcessRuntimeError, match="could not be persisted"):
        run_process(ProcessSpec(
            (
                sys.executable, "-c",
                "from pathlib import Path; Path('must-not-execute').write_text('unsafe')",
            ),
            tmp_path,
            environment={},
            on_started=lambda _identity: (_ for _ in ()).throw(RuntimeError("ledger unavailable")),
        ))
    assert not refused.exists()


def test_output_limit_reaps_child_and_never_retains_an_oversized_final_chunk(tmp_path: Path) -> None:
    code = (
        "import os,subprocess,sys,time; "
        "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
        "print(p.pid, flush=True); os.write(1, b'z' * 10000); time.sleep(30)"
    )
    result = run_process(ProcessSpec(("python3", "-c", code), tmp_path, max_output_bytes=64, environment=filtered_environment()))
    assert result.output_limited
    assert len(result.stdout.encode("utf-8")) == 64
    pid = int(result.stdout.splitlines()[0])
    for _ in range(100):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.01)
    else:
        raise AssertionError("output-limited child process was not reaped")


def test_process_runtime_timeout_and_cancellation_kill_process_group(tmp_path: Path) -> None:
    timed = run_process(ProcessSpec(("python3", "-c", "import time; time.sleep(2)"), tmp_path, timeout_seconds=0.05, environment=filtered_environment()))
    assert timed.timed_out and not timed.ok
    cancel = threading.Event()
    def set_cancel() -> None:
        time.sleep(0.05)
        cancel.set()
    threading.Thread(target=set_cancel, daemon=True).start()
    cancelled = run_process(ProcessSpec(("python3", "-c", "import time; time.sleep(2)"), tmp_path, timeout_seconds=2, environment=filtered_environment()), cancel_event=cancel)
    assert cancelled.cancelled and not cancelled.ok


def test_temporary_workspace_is_removed(tmp_path: Path) -> None:
    with TemporaryWorkspace(tmp_path) as workspace:
        marker = workspace / "marker"
        marker.write_text("staging", encoding="utf-8")
        assert marker.is_file()
    assert not workspace.exists()
