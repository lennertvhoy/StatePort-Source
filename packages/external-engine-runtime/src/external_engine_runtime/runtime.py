from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import selectors
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Iterable, Mapping


class ProcessRuntimeError(RuntimeError):
    """A process could not be started or its output was invalid."""


@dataclass(frozen=True)
class ProcessIdentity:
    """Kernel-observed identity used to reconcile an abandoned process group."""

    pid: int
    process_group_id: int | None
    start_time_ticks: str | None
    process_generation: str | None


@dataclass(frozen=True)
class ProcessSpec:
    command: tuple[str, ...]
    cwd: Path
    timeout_seconds: float = 30.0
    max_output_bytes: int = 1_048_576
    environment: Mapping[str, str] | None = None
    stdin_text: str | None = None
    on_started: Callable[[ProcessIdentity], None] | None = None
    on_finished: Callable[[ProcessIdentity], None] | None = None
    process_generation: str | None = None

    def __post_init__(self) -> None:
        if not self.command or any(not isinstance(item, str) or not item for item in self.command):
            raise ValueError("command must contain non-empty strings")
        if not self.cwd.is_absolute() or not self.cwd.is_dir() or self.cwd.is_symlink():
            raise ValueError("cwd must be an existing non-symlink directory")
        if self.timeout_seconds <= 0 or self.max_output_bytes <= 0:
            raise ValueError("timeout and output limits must be positive")
        if self.stdin_text is not None:
            if not isinstance(self.stdin_text, str):
                raise ValueError("stdin_text must be text when supplied")
            if len(self.stdin_text.encode("utf-8")) > 65_536:
                raise ValueError("stdin_text exceeds the 64KiB process-input bound")
        if self.on_started is not None and not callable(self.on_started):
            raise ValueError("on_started must be callable when supplied")
        if self.on_finished is not None and not callable(self.on_finished):
            raise ValueError("on_finished must be callable when supplied")
        if self.process_generation is not None and not re.fullmatch(
            r"generation\.[0-9a-f]{64}", self.process_generation,
        ):
            raise ValueError("process_generation must be a bounded generated identity")


@dataclass(frozen=True)
class ProcessResult:
    command: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool
    cancelled: bool
    output_limited: bool
    duration_ms: int
    cleanup: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.cancelled and not self.output_limited


def filtered_environment(
    *,
    source: Mapping[str, str] | None = None,
    allow: Iterable[str] = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR"),
    overrides: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return a small environment without inheriting secret-rich variables."""

    source = os.environ if source is None else source
    allowed = {name for name in allow}
    result = {name: str(value) for name, value in source.items() if name in allowed}
    for name, value in (overrides or {}).items():
        if not isinstance(name, str) or not name or not isinstance(value, str):
            raise ValueError("environment overrides must be string pairs")
        if name not in allowed:
            raise ValueError("environment overrides must be explicitly allowlisted")
        result[name] = value
    return result


def probe_executable(executable: str) -> str | None:
    """Resolve an executable without executing it."""

    if not executable or "/" in executable:
        candidate = Path(executable)
        return candidate.as_posix() if candidate.is_file() and os.access(candidate, os.X_OK) else None
    return shutil.which(executable)


def _terminate(process: subprocess.Popen[str]) -> str:
    """Terminate the complete process group, with a bounded hard-kill fallback."""

    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
        process.wait(timeout=1.0)
        if os.name == "posix":
            # A child can be forked concurrently with the first group signal.
            # Re-signal the group after the leader is reaped so no late
            # descendant can keep inherited stdout/stderr pipes open.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        return "terminated"
    except subprocess.TimeoutExpired:
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
            process.wait(timeout=1.0)
            return "killed"
        except Exception:  # noqa: BLE001 - cleanup is reported, never leaked
            return "cleanup_failed"
    except ProcessLookupError:
        return "already_exited"


def _start_time_ticks(pid: int) -> str | None:
    """Read Linux procfs process-start identity without treating PID as identity."""

    try:
        value = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        fields = value.rsplit(")", 1)[1].strip().split()
        result = fields[19]
        return result if result.isdigit() else None
    except (OSError, IndexError):
        return None


def run_process(spec: ProcessSpec, *, cancel_event: Any | None = None) -> ProcessResult:
    """Run one external process with strict lifetime, environment and output bounds."""

    environment = dict(filtered_environment() if spec.environment is None else spec.environment)
    process_generation = spec.process_generation or (
        "generation." + secrets.token_hex(32)
    )
    # This is a non-credential ownership marker. It is created by the
    # supervisor, never inherited from its own environment, and lets restart
    # reconciliation distinguish descendants from a reused numeric PID/PGID.
    environment["STATEPORT_PROCESS_GENERATION"] = process_generation
    start = time.monotonic()
    gate_read: int | None = None
    gate_write: int | None = None
    command = list(spec.command)
    pass_fds: tuple[int, ...] = ()
    if spec.on_started is not None and os.name == "posix":
        # The tiny exec gate makes durable supervision registration happen
        # before the requested program can execute.  EOF (including abrupt
        # supervisor death before registration) fails closed without exec.
        gate_read, gate_write = os.pipe()
        gate_program = (
            "import os,sys; fd=int(sys.argv[1]); "
            "allowed=os.read(fd,1)==b'1'; os.close(fd); "
            "os.execvpe(sys.argv[2],sys.argv[2:],os.environ) if allowed else sys.exit(125)"
        )
        command = [sys.executable, "-c", gate_program, str(gate_read), *command]
        pass_fds = (gate_read,)
    try:
        process = subprocess.Popen(
            command,
            cwd=spec.cwd,
            env=environment,
            stdin=subprocess.PIPE if spec.stdin_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            start_new_session=os.name == "posix",
            pass_fds=pass_fds,
        )
    except OSError as exc:
        for descriptor in (gate_read, gate_write):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        raise ProcessRuntimeError(f"could not start external process: {spec.command[0]}") from exc
    if gate_read is not None:
        os.close(gate_read)
        gate_read = None

    try:
        process_group_id = os.getpgid(process.pid) if os.name == "posix" else None
    except OSError:
        process_group_id = None
    identity = ProcessIdentity(
        process.pid, process_group_id, _start_time_ticks(process.pid),
        process_generation,
    )
    if spec.on_started is not None:
        try:
            spec.on_started(identity)
            if gate_write is not None:
                os.write(gate_write, b"1")
        except Exception as exc:  # noqa: BLE001 - supervision registration is fail-closed
            if gate_write is not None:
                os.close(gate_write)
                gate_write = None
            _terminate(process)
            raise ProcessRuntimeError("process supervision identity could not be persisted") from exc
        finally:
            if gate_write is not None:
                os.close(gate_write)
                gate_write = None

    if spec.stdin_text is not None:
        assert process.stdin is not None
        try:
            process.stdin.write(spec.stdin_text.encode("utf-8"))
            process.stdin.close()
        except (BrokenPipeError, OSError):
            # A writer may reject the input and exit before consuming it. Its
            # bounded return code/stdout/stderr remain the authoritative fact.
            try:
                process.stdin.close()
            except OSError:
                pass

    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    streams: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    retained_total = 0
    timed_out = cancelled = output_limited = False
    cleanup = "not_required"
    open_streams = 2
    finish_error: Exception | None = None
    try:
        while open_streams:
            elapsed = time.monotonic() - start
            if not cancelled and not timed_out:
                if cancel_event is not None and cancel_event.is_set():
                    cancelled = True
                    cleanup = _terminate(process)
                elif elapsed >= spec.timeout_seconds:
                    timed_out = True
                    cleanup = _terminate(process)

            for key, _ in selector.select(timeout=0.05):
                # BufferedReader.read(size) may wait for ``size`` bytes even
                # after select reports a short pipe write, which would make a
                # chatty process temporarily immune to timeout/cancellation.
                # A single os.read returns the bytes currently available.
                try:
                    chunk = os.read(key.fileobj.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    open_streams -= 1
                    continue
                retained = streams[key.data]
                remaining = spec.max_output_bytes - retained_total
                if remaining > 0:
                    kept = chunk[:remaining]
                    retained.extend(kept)
                    retained_total += len(kept)
                if len(chunk) > remaining:
                    output_limited = True
                    cleanup = _terminate(process)
                    # The configured bound applies to stdout and stderr
                    # together, including when the final OS read is itself
                    # oversized.
                    # Drain no more bytes; terminate and close below.
                    for registered in list(selector.get_map().values()):
                        selector.unregister(registered.fileobj)
                        registered.fileobj.close()
                    open_streams = 0
                    break

        if process.poll() is None:
            process.wait(timeout=1.0)
    finally:
        selector.close()
        if process.poll() is None:
            cleanup = _terminate(process)
        if spec.on_finished is not None:
            try:
                spec.on_finished(identity)
            except Exception as exc:  # noqa: BLE001 - a stale active ledger must fail closed
                finish_error = exc

    if finish_error is not None:
        raise ProcessRuntimeError("process completion could not be persisted") from finish_error

    def decoded(stream: bytearray, limit: int) -> str:
        """Keep replacement-decoded UTF-8 inside its remaining byte budget."""

        value = bytes(stream).decode("utf-8", errors="replace")
        encoded = value.encode("utf-8")
        if len(encoded) <= limit:
            return value
        return encoded[:limit].decode("utf-8", errors="ignore")

    stdout = decoded(streams["stdout"], spec.max_output_bytes)
    stderr_budget = spec.max_output_bytes - len(stdout.encode("utf-8"))
    stderr = decoded(streams["stderr"], stderr_budget)

    return ProcessResult(
        tuple(spec.command),
        process.returncode,
        stdout,
        stderr,
        timed_out,
        cancelled,
        output_limited,
        int((time.monotonic() - start) * 1000),
        cleanup,
    )


def decode_jsonl(text: str, *, max_events: int = 10_000) -> tuple[dict[str, Any], ...]:
    """Decode strict JSONL events and reject malformed or oversized streams."""

    events: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        if len(events) >= max_events:
            raise ProcessRuntimeError("structured event limit exceeded")
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ProcessRuntimeError(f"malformed structured event at line {line_number}") from exc
        if not isinstance(value, dict):
            raise ProcessRuntimeError(f"structured event at line {line_number} is not an object")
        events.append(value)
    return tuple(events)


class TemporaryWorkspace:
    """A disposable staging workspace that never mounts canonical state."""

    def __init__(self, parent: Path, prefix: str = "stateport-engine-"):
        if not parent.is_absolute() or not parent.is_dir() or parent.is_symlink():
            raise ValueError("workspace parent must be an existing absolute directory")
        self.parent = parent
        self.prefix = prefix
        self.path: Path | None = None

    def __enter__(self) -> Path:
        self.path = Path(tempfile.mkdtemp(prefix=self.prefix, dir=self.parent))
        return self.path

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        if self.path is not None:
            shutil.rmtree(self.path, ignore_errors=True)
            self.path = None
