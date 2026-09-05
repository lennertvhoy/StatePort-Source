"""Real local subprocess fixtures for log capture; never invokes Podman/workloads."""
from pathlib import Path
import sys
import time
import tracemalloc
import pytest
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'packages/execution-host/src'))
from execution_host.engine import PodmanCliEngine, EngineError
import execution_host.engine as engine_module


def fixture_engine(tmp_path, program):
    executable = tmp_path / 'fixture-log-producer'
    executable.write_text('#!' + sys.executable + '\n' + program + '\n')
    executable.chmod(0o700)
    def forbid_whole_capture(*args, **kwargs):
        raise AssertionError('logs must not use whole-output subprocess.run capture')
    return PodmanCliEngine(binary=str(executable), runner=forbid_whole_capture)


def test_large_output_has_bounded_memory_and_an_explicit_prefix(tmp_path):
    engine = fixture_engine(tmp_path, 'import os\nfor _ in range(512): os.write(1, b"x" * 65536)')
    tracemalloc.start()
    try:
        result = engine.logs('fixture', max_bytes=1024)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert result == {'bytes': 'x' * 1024, 'byteCount': 1024, 'truncated': True}
    assert peak < 1024 * 1024  # 32 MiB producer; at most one chunk + prefix retained.


@pytest.mark.parametrize('payload,bound,truncated', [('', 10, False), ('abcd', 4, False), ('abcde', 4, True), ('éé', 3, True)])
def test_empty_exact_and_utf8_boundary_outputs(tmp_path, payload, bound, truncated):
    engine = fixture_engine(tmp_path, 'import os\nos.write(1, ' + repr(payload.encode()) + ')')
    result = engine.logs('fixture', max_bytes=bound)
    assert result['byteCount'] == len(result['bytes'].encode()) <= bound
    assert result['truncated'] is truncated
    if not truncated:
        assert result['bytes'] == payload


def test_nonzero_after_large_stdout_and_stderr_remains_a_redacted_error(tmp_path):
    engine = fixture_engine(tmp_path, 'import os,sys\nfor _ in range(32):\n os.write(1, b"x" * 65536)\n os.write(2, b"SECRET_LOG_ERROR_CANARY" * 4096)\nsys.exit(2)')
    with pytest.raises(EngineError, match='workload logs failed') as error:
        engine.logs('fixture', max_bytes=16)
    assert 'SECRET_LOG_ERROR_CANARY' not in str(error.value)


def test_stalled_reader_times_out_and_is_reaped(tmp_path, monkeypatch):
    pid_path = tmp_path / 'fixture.pid'
    engine = fixture_engine(tmp_path, 'import os,time\nopen(' + repr(str(pid_path)) + ', "w").write(str(os.getpid()))\ntime.sleep(60)')
    monkeypatch.setattr(engine_module, 'MAX_REQUEST_TIMEOUT_SECONDS', 0.2)
    started = time.monotonic()
    with pytest.raises(EngineError, match='timed out'):
        engine.logs('fixture', max_bytes=16)
    assert time.monotonic() - started < 2
    assert not Path('/proc', pid_path.read_text()).exists()


def test_missing_binary_is_redacted(tmp_path):
    engine = PodmanCliEngine(binary=str(tmp_path / 'SECRET_PATH_CANARY'))
    with pytest.raises(EngineError, match='could not start') as error:
        engine.logs('fixture', max_bytes=16)
    assert 'SECRET_PATH_CANARY' not in str(error.value)


def test_successful_stderr_only_output_keeps_empty_stdout_contract(tmp_path):
    engine = fixture_engine(tmp_path, 'import os\nos.write(2, b"diagnostic-only")')
    assert engine.logs('fixture', max_bytes=16) == {'bytes': '', 'byteCount': 0, 'truncated': False}


def test_orphan_pipe_holder_is_reaped_on_timeout(tmp_path, monkeypatch):
    child_pid = tmp_path / 'child.pid'
    program = ('import subprocess,sys\nchild = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(60)"])\n'
               + 'open(' + repr(str(child_pid)) + ', "w").write(str(child.pid))')
    engine = fixture_engine(tmp_path, program)
    monkeypatch.setattr(engine_module, 'MAX_REQUEST_TIMEOUT_SECONDS', 0.2)
    with pytest.raises(EngineError, match='timed out'):
        engine.logs('fixture', max_bytes=16)
    # A reparented child can briefly remain a zombie awaiting init's reap, but
    # it must no longer execute or hold the pipe after the group cleanup.
    stat = Path('/proc', child_pid.read_text(), 'stat')
    deadline = time.monotonic() + 1
    while stat.exists() and not stat.read_text().split(') ', 1)[1].startswith('Z '):
        assert time.monotonic() < deadline, 'log reader child remained executing'
        time.sleep(0.01)


@pytest.mark.parametrize('bound', [True, 0, -1, 4194305])
def test_invalid_bound_is_refused_before_start(tmp_path, bound):
    with pytest.raises(EngineError, match='bound is outside policy'):
        PodmanCliEngine(binary=str(tmp_path / 'never-start')).logs('fixture', max_bytes=bound)
