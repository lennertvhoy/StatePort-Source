"""Bubblewrap-confined execution for governed goal slices.

Nothing here is agent-owned content on the host: the approved commit is
exported (without ``.git``) into a private staging directory, optional
operator-configured agent steps and every approved validation command run
inside a network-less, environment-less bubblewrap jail, and the host only
ever walks the result with ``lstat``.  The host project is read, never written.
"""

from __future__ import annotations

import difflib
import fcntl
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

SANDBOX_BACKEND_ID = "sandbox_bwrap"
SANDBOX_PYTHON = "/usr/bin/python3"
VALIDATOR_MOUNT = "/stateport-validators"
AGENT_COMMAND_ENV = "STATEPORT_GOAL_AGENT_COMMAND"

MAX_ENTRIES = 4096
MAX_DEPTH = 16
MAX_TOTAL_BYTES = 16 * 1024 * 1024
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_OUTPUT_BYTES = 64 * 1024
MAX_PATCH_BYTES = 256 * 1024
TAIL_BYTES = 2048
_FSIZE_LIMIT = 8 * 1024 * 1024
# Applied INSIDE the jail (see _LIMIT_SHIM), where RLIMIT_NPROC counts the jail's
# own user namespace instead of every process the service uid owns on the host.
_AS_LIMIT = 1024 * 1024 * 1024
_NOFILE_LIMIT = 256
_NPROC_LIMIT = 128
_TMPFS_BYTES = 32 * 1024 * 1024
# Whole-run staging growth is polled while the agent runs; the authoritative
# post-run bound stays MAX_ENTRIES / MAX_TOTAL_BYTES, this one only keeps a
# hostile step from filling the host disk before that check can run.
_RUNNING_MAX_ENTRIES = 2 * 4096
_RUNNING_MAX_BYTES = 2 * 16 * 1024 * 1024
_POLL_SECONDS = 0.2
EXPORT_DEADLINE_SECONDS = 60.0
_RUN_LOCK_NAME = ".run.lock"
_ORPHAN_GRACE_SECONDS = 60.0
_PROBE_TTL_OK = 300.0
_PROBE_TTL_FAIL = 15.0
_PROBE_TIMEOUT = 10.0
_VALIDATOR_FILE = Path(__file__).resolve().parent / "validators" / "contract_boundary.py"
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-_]")


class SandboxError(RuntimeError):
    """Typed sandbox refusal; ``code`` is a stable machine-readable reason."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


# ------------------------------------------------------------------ binding


def validator_sha256() -> str:
    return hashlib.sha256(_VALIDATOR_FILE.read_bytes()).hexdigest()


def validator_command() -> str:
    """The approval-bound validation command; it embeds the validator's sha256."""

    return (
        f"python3 -I {VALIDATOR_MOUNT}/contract_boundary.{validator_sha256()[:16]}.py /workspace"
    )


def parse_agent_command(raw: str | None) -> tuple[str, ...] | None:
    """Parse the operator's (test/dev-only) agent argv; never from a request."""

    if raw is None or not raw.strip():
        return None
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SandboxError("agent_command_invalid", f"{AGENT_COMMAND_ENV} is not a JSON argv list") from exc
    if (
        not isinstance(value, list)
        or not value
        or len(value) > 64
        or not all(isinstance(item, str) and item and "\x00" not in item and len(item) <= 4096 for item in value)
        or not value[0].startswith("/usr/")
    ):
        raise SandboxError(
            "agent_command_invalid",
            f"{AGENT_COMMAND_ENV} must be a JSON list of strings whose executable is below /usr",
        )
    return tuple(value)


def agent_command_digest(argv: Sequence[str] | None) -> str | None:
    if argv is None:
        return None
    return hashlib.sha256(json.dumps(list(argv), separators=(",", ":")).encode("utf-8")).hexdigest()


# -------------------------------------------------------------------- probe

_probe_lock = threading.Lock()
_probe_cache: dict[str, Any] = {"at": 0.0, "value": None}


def _bwrap() -> str | None:
    return shutil.which("bwrap", path="/usr/bin:/bin:/usr/local/bin")


_size_support: dict[str, bool] = {}


def _supports_tmpfs_size(bwrap: str) -> bool:
    """Whether this bwrap has ``--size`` (>= 0.8); older ones get an unbounded /tmp."""
    if bwrap not in _size_support:
        try:
            completed = subprocess.run(
                (bwrap, "--help"), stdin=subprocess.DEVNULL, capture_output=True, timeout=_PROBE_TIMEOUT, check=False,
            )
            _size_support[bwrap] = b"--size" in completed.stdout + completed.stderr
        except (OSError, subprocess.SubprocessError):
            _size_support[bwrap] = False
    return _size_support[bwrap]


def _bwrap_args(
    bwrap: str,
    *,
    staging: Path | None,
    writable: bool,
    extra_ro: Sequence[tuple[Path, str]] = (),
) -> list[str]:
    arguments = [
        bwrap, "--unshare-all", "--die-with-parent", "--new-session", "--clearenv",
        "--setenv", "PATH", "/usr/bin",
        "--setenv", "HOME", "/home",
        "--setenv", "TMPDIR", "/tmp",
        "--setenv", "LANG", "C.UTF-8",
        "--setenv", "LC_ALL", "C.UTF-8",
        "--setenv", "PYTHONDONTWRITEBYTECODE", "1",
        "--ro-bind", "/usr", "/usr",
    ]
    for system_path in ("/lib", "/lib64"):
        if Path(system_path).exists():
            arguments.extend(("--ro-bind", system_path, system_path))
    # Same device shape as portable-execution's boundary: no --proc/--dev
    # (they fail in nested rootless Podman), just four character devices.
    if _supports_tmpfs_size(bwrap):
        arguments.extend(("--size", str(_TMPFS_BYTES)))
    arguments.extend((
        "--tmpfs", "/tmp", "--dir", "/home", "--dir", "/dev",
        "--dev-bind", "/dev/null", "/dev/null",
        "--dev-bind", "/dev/zero", "/dev/zero",
        "--dev-bind", "/dev/random", "/dev/random",
        "--dev-bind", "/dev/urandom", "/dev/urandom",
    ))
    if staging is not None:
        arguments.extend(("--bind" if writable else "--ro-bind", str(staging), "/workspace", "--chdir", "/workspace"))
    for source, target in extra_ro:
        arguments.extend(("--ro-bind", str(source), target))
    return arguments


def probe(*, force: bool = False) -> tuple[bool, str]:
    """Return (usable, reason).  A real smoke run, cached with a short failure TTL."""

    now = time.monotonic()
    with _probe_lock:
        cached = _probe_cache["value"]
        if not force and cached is not None:
            ttl = _PROBE_TTL_OK if cached[0] else _PROBE_TTL_FAIL
            if now - _probe_cache["at"] < ttl:
                return cached
        result = _probe_uncached()
        _probe_cache.update(at=time.monotonic(), value=result)
        return result


def _probe_uncached() -> tuple[bool, str]:
    bwrap = _bwrap()
    if bwrap is None:
        return False, "bubblewrap_missing"
    if not Path(SANDBOX_PYTHON).is_file():
        return False, "sandbox_python_missing"
    command = _bwrap_args(bwrap, staging=None, writable=False) + [
        "--", SANDBOX_PYTHON, "-I", "-c", "import yaml",
    ]
    try:
        completed = subprocess.run(
            command, stdin=subprocess.DEVNULL, capture_output=True, timeout=_PROBE_TIMEOUT, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False, "sandbox_launch_failed"
    if completed.returncode != 0:
        tail = completed.stderr.decode("utf-8", "replace")
        if "yaml" in tail:
            return False, "sandbox_yaml_missing"
        return False, "user_namespaces_unavailable"
    return True, "ok"


# ------------------------------------------------------------------ staging


def _git_env() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "GIT_NO_REPLACE_OBJECTS": "1",
    }


def _git(root: Path, *arguments: str, stdin: bytes | None = None, timeout: float = 20.0) -> bytes:
    try:
        completed = subprocess.run(
            ("git", "--no-replace-objects", "-c", "core.hooksPath=/dev/null", "-C", root.as_posix(), *arguments),
            input=stdin, capture_output=True, timeout=max(0.5, min(20.0, timeout)), check=True, env=_git_env(),
        )
    except subprocess.TimeoutExpired as exc:
        raise SandboxError("staging_export_timeout", "exporting the approved commit took too long") from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise SandboxError("staging_export_failed", "the approved commit could not be exported") from exc
    return completed.stdout


def _safe_relative(name: str) -> Path:
    path = Path(name)
    if (
        not name or path.is_absolute() or "\x00" in name
        or any(part in ("", ".", "..", ".git") for part in path.parts)
        or len(path.parts) > MAX_DEPTH
    ):
        raise SandboxError("unsafe_staging_entry", "the project contains an unsafe path")
    return path


def export_commit(
    repo_root: Path, commit: str, destination: Path, *, deadline_seconds: float = EXPORT_DEADLINE_SECONDS,
) -> None:
    """Materialise ``commit`` into ``destination`` without .git, attributes or links.

    The whole export (one git process per file, up to MAX_ENTRIES) shares one
    wall-clock deadline.
    """

    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit):
        raise SandboxError("staging_export_failed", "commit identity is invalid")
    deadline = time.monotonic() + deadline_seconds

    def remaining() -> float:
        left = deadline - time.monotonic()
        if left <= 0:
            raise SandboxError("staging_export_timeout", "exporting the approved commit took too long")
        return left

    listing = _git(repo_root, "ls-tree", "-r", "-z", "--full-tree", commit, timeout=remaining())
    records = [item for item in listing.split(b"\x00") if item]
    if len(records) > MAX_ENTRIES:
        raise SandboxError("staging_too_large", "the project exceeds the sandbox entry bound")
    entries: list[tuple[Path, str, bool]] = []
    for record in records:
        meta, _, raw_name = record.partition(b"\t")
        mode, kind, object_id = meta.decode("ascii").split(" ")
        try:
            name = raw_name.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise SandboxError(
                "unsafe_staging_entry", "the project contains a file name that is not valid UTF-8"
            ) from exc
        if kind != "blob" or mode not in ("100644", "100755"):
            raise SandboxError(
                "unsupported_project_entry",
                "the project contains a symlink or submodule; the sandbox only stages regular files",
            )
        entries.append((_safe_relative(name), object_id, mode == "100755"))
    destination.mkdir(mode=0o700)
    total = 0
    for relative, object_id, executable in entries:
        data = _git(repo_root, "cat-file", "blob", object_id, timeout=remaining())
        total += len(data)
        if len(data) > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
            raise SandboxError("staging_too_large", "the project exceeds the sandbox size bound")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o755 if executable else 0o644)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
    # Directories must be traversable by the mapped sandbox user only.
    for directory in [destination, *[p for p in destination.rglob("*") if p.is_dir()]]:
        os.chmod(directory, 0o755)


@dataclass(frozen=True)
class FileState:
    digest: str
    executable: bool
    size: int


def manifest(root: Path) -> dict[str, FileState]:
    """Bounded lstat-only walk; links, special files or unreadable entries are refused.

    MAX_ENTRIES bounds EVERY directory entry (files and directories alike) in
    one counter, and names that are not valid UTF-8 are refused with a typed
    error (they cannot be rendered into the retained patch or JSON records).
    """

    result: dict[str, FileState] = {}
    total = 0
    entries = 0

    def walk(directory: Path, depth: int) -> None:
        nonlocal total, entries
        if depth > MAX_DEPTH:
            raise SandboxError("unsafe_staging_entry", "staging is nested too deeply")
        children = []
        try:
            with os.scandir(directory) as iterator:
                for child in iterator:
                    entries += 1
                    if entries > MAX_ENTRIES:
                        raise SandboxError("staging_too_large", "staging exceeds the entry bound")
                    children.append(child)
        except OSError as exc:
            raise SandboxError("unsafe_staging_entry", "a staging directory became unreadable") from exc
        children.sort(key=lambda entry: entry.name)
        for child in children:
            try:
                child.name.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise SandboxError(
                    "unsafe_staging_entry",
                    "the sandbox produced a file name that is not valid UTF-8 "
                    f"({os.fsencode(child.name)[:40]!r})",
                ) from exc
            try:
                info = child.stat(follow_symlinks=False)
            except OSError as exc:
                raise SandboxError("unsafe_staging_entry", "a staging entry could not be inspected") from exc
            relative = Path(child.path).relative_to(root).as_posix()
            if stat.S_ISDIR(info.st_mode):
                walk(Path(child.path), depth + 1)
            elif stat.S_ISREG(info.st_mode):
                total += info.st_size
                if info.st_size > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
                    raise SandboxError("staging_too_large", "staging exceeds the size bound")
                try:
                    descriptor = os.open(child.path, os.O_RDONLY | os.O_NOFOLLOW)
                    with os.fdopen(descriptor, "rb") as handle:
                        data = handle.read()
                except OSError as exc:
                    raise SandboxError("unsafe_staging_entry", "a staging file became unreadable") from exc
                result[relative] = FileState(hashlib.sha256(data).hexdigest(), bool(info.st_mode & 0o111), len(data))
            else:
                raise SandboxError(
                    "unsafe_staging_entry",
                    f"the sandbox produced a link or special file ({relative[:80]!r})",
                )

    walk(root, 0)
    return result


def manifest_digest(state: dict[str, FileState]) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps({k: [v.digest, v.executable] for k, v in sorted(state.items())}, separators=(",", ":")).encode()
    ).hexdigest()


def diff_manifests(
    before: dict[str, FileState], after: dict[str, FileState], root: Path
) -> dict[str, Any]:
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    modified = sorted(k for k in set(before) & set(after) if before[k] != after[k])
    return {
        "added": added[:200], "modified": modified[:200], "deleted": removed[:200],
        "counts": {"added": len(added), "modified": len(modified), "deleted": len(removed)},
        "changed": bool(added or modified or removed),
        "afterDigest": manifest_digest(after),
        "beforeDigest": manifest_digest(before),
    }


def build_patch(
    before_root: Path | None, after_root: Path, changes: dict[str, Any], before: dict[str, FileState],
) -> tuple[str, bool]:
    """Bounded unified diff of text changes; returns (patch, truncated)."""

    chunks: list[str] = []
    size = 0
    truncated = False
    for name in sorted(set(changes["added"]) | set(changes["modified"]) | set(changes["deleted"])):
        def _read(root: Path | None, present: bool) -> list[str] | None:
            if root is None or not present:
                return []
            try:
                return (root / name).read_bytes().decode("utf-8").splitlines(keepends=True)
            except (OSError, UnicodeDecodeError):
                return None
        old = _read(before_root, name in before)
        new = _read(after_root, name not in changes["deleted"])
        if old is None or new is None:
            piece = f"Binary or unreadable change: {name}\n"
        else:
            piece = "".join(difflib.unified_diff(old, new, f"a/{name}", f"b/{name}"))
        size += len(piece.encode("utf-8"))
        if size > MAX_PATCH_BYTES:
            truncated = True
            break
        chunks.append(piece)
    return "".join(chunks), truncated


def snapshot_tree(source: Path, destination: Path) -> None:
    """Private pre-agent copy used only to render the retained patch."""

    shutil.copytree(source, destination, symlinks=True)


# ------------------------------------------------------------------- running


@dataclass
class RunOutcome:
    argv: tuple[str, ...]
    exit_code: int | None
    timed_out: bool
    truncated: bool
    seconds: float
    output_digest: str
    tail: str

    def passed(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.truncated

    def to_public(self, label: str) -> dict[str, Any]:
        return {
            "label": label,
            "exitCode": self.exit_code,
            "timedOut": self.timed_out,
            "outputTruncated": self.truncated,
            "seconds": round(self.seconds, 2),
            "outputDigest": self.output_digest,
            "tail": self.tail,
            "tailIsUntrusted": True,
        }


def _clean_tail(data: bytes) -> str:
    text = data[-TAIL_BYTES:].decode("utf-8", "replace")
    text = _ANSI.sub("", text)
    return "".join(ch if ch in "\n\t" or (ch.isprintable()) else "?" for ch in text)


# Runs inside the jail as the first process (no preexec_fn in the threaded
# service): sets the limits, then replaces itself with the real command.
_LIMIT_SHIM = (
    "import os,resource,sys\n"
    "fsize,cpu,addr,nofile,nproc=map(int,sys.argv[1:6])\n"
    "for name,value in (('RLIMIT_FSIZE',fsize),('RLIMIT_CPU',cpu),('RLIMIT_AS',addr),"
    "('RLIMIT_NOFILE',nofile),('RLIMIT_NPROC',nproc),('RLIMIT_CORE',0)):\n"
    "    resource.setrlimit(getattr(resource,name),(value,value))\n"
    "os.execv(sys.argv[6],sys.argv[6:])\n"
)


def _shimmed(argv: Sequence[str], timeout: float) -> list[str]:
    cpu = int(timeout) + 5
    return [
        SANDBOX_PYTHON, "-I", "-c", _LIMIT_SHIM,
        str(_FSIZE_LIMIT), str(cpu), str(_AS_LIMIT), str(_NOFILE_LIMIT), str(_NPROC_LIMIT), *argv,
    ]


def staging_usage_exceeds(root: Path, max_entries: int, max_bytes: int) -> bool:
    """Bounded lstat walk: True as soon as entries or allocated bytes pass a bound."""

    entries = 0
    used = 0
    pending = [str(root)]
    while pending:
        try:
            with os.scandir(pending.pop()) as iterator:
                for child in iterator:
                    entries += 1
                    if entries > max_entries:
                        return True
                    try:
                        info = child.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if stat.S_ISDIR(info.st_mode):
                        pending.append(child.path)
                    elif stat.S_ISREG(info.st_mode):
                        used += max(info.st_size, getattr(info, "st_blocks", 0) * 512)
                        if used > max_bytes:
                            return True
        except OSError:
            continue
    return False


def run_confined(
    argv: Sequence[str],
    staging: Path,
    *,
    writable: bool,
    timeout: float,
    scratch: Path,
    extra_ro: Sequence[tuple[Path, str]] = (),
) -> RunOutcome:
    bwrap = _bwrap()
    if bwrap is None:
        raise SandboxError("sandbox_unavailable", "bubblewrap is not available")
    command = _bwrap_args(bwrap, staging=staging, writable=writable, extra_ro=extra_ro) + [
        "--", *_shimmed(argv, timeout),
    ]
    out_path = scratch / f"out-{os.urandom(6).hex()}"
    started = time.monotonic()
    timed_out = False
    over_budget = False
    descriptor = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as sink:
            try:
                process = subprocess.Popen(
                    command, stdin=subprocess.DEVNULL, stdout=sink, stderr=subprocess.STDOUT,
                    start_new_session=True, env={"PATH": "/usr/bin:/bin"},
                )
            except OSError as exc:
                raise SandboxError("sandbox_launch_failed", "the sandbox could not be started") from exc
            deadline = started + timeout
            while True:
                try:
                    process.wait(timeout=max(0.01, min(_POLL_SECONDS, deadline - time.monotonic())))
                    break
                except subprocess.TimeoutExpired:
                    pass
                if time.monotonic() >= deadline:
                    timed_out = True
                elif writable and staging_usage_exceeds(staging, _RUNNING_MAX_ENTRIES, _RUNNING_MAX_BYTES):
                    over_budget = True
                else:
                    continue
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    pass
                process.wait()
                break
        data = out_path.read_bytes()
    finally:
        out_path.unlink(missing_ok=True)
    if over_budget:
        raise SandboxError(
            "staging_too_large", "the sandboxed step grew the workspace past the size bound and was stopped"
        )
    return RunOutcome(
        argv=tuple(argv),
        exit_code=None if timed_out else process.returncode,
        timed_out=timed_out,
        truncated=len(data) > MAX_OUTPUT_BYTES,
        seconds=time.monotonic() - started,
        output_digest="sha256:" + hashlib.sha256(data).hexdigest(),
        tail=_clean_tail(data),
    )


def validator_mount(command: str, scratch: Path) -> tuple[list[str], list[tuple[Path, str]]]:
    """Resolve an approved validation command into sandbox argv plus its read-only mounts.

    Only the exact StatePort validator whose sha256 prefix is embedded in the
    approved command is accepted; the mounted file is a private copy whose
    hash is re-verified here.
    """

    try:
        argv = shlex.split(command)
    except ValueError as exc:
        raise SandboxError("validation_command_unsupported", "validation command is not parseable") from exc
    expected = validator_command()
    if command != expected:
        raise SandboxError(
            "validation_command_unsupported",
            "this host only runs the StatePort-owned contract validator named in the approved plan",
        )
    data = _VALIDATOR_FILE.read_bytes()
    if hashlib.sha256(data).hexdigest()[:16] not in argv[2]:
        raise SandboxError("validator_identity_mismatch", "validator identity changed")
    private = scratch / "validator.py"
    private.write_bytes(data)
    os.chmod(private, 0o644)
    return [SANDBOX_PYTHON, "-I", argv[2], argv[3]], [(private, argv[2])]


def remove_tree(path: Path) -> None:
    """Remove a tree an agent may have chmod'ed, without following links."""

    for current, directories, files in os.walk(path, topdown=True, followlinks=False):
        for name in [*directories, *files]:
            item = os.path.join(current, name)
            try:
                if not os.path.islink(item):
                    os.chmod(item, 0o700 if os.path.isdir(item) else 0o600)
            except OSError:
                pass
        try:
            os.chmod(current, 0o700)
        except OSError:
            pass
    shutil.rmtree(path, ignore_errors=True)


_held_locks: dict[str, int] = {}


def staging_root(base: Path) -> Path:
    """A private per-run directory holding an flock marker for the run's lifetime.

    ``sweep_orphans`` only removes a run directory whose marker it can lock,
    so another live run on the same record root is never deleted.
    """
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(base, 0o700)
    run_dir = Path(tempfile.mkdtemp(prefix="run-", dir=base))
    descriptor = os.open(run_dir / _RUN_LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.write(descriptor, f"{os.getpid()}\n".encode())
    except OSError:
        os.close(descriptor)
        raise
    _held_locks[str(run_dir)] = descriptor
    return run_dir


def release_staging(run_dir: Path) -> None:
    """Remove a finished run directory and drop its liveness marker."""
    descriptor = _held_locks.pop(str(run_dir), None)
    remove_tree(run_dir)
    if descriptor is not None:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _is_live(child: Path) -> bool:
    """True when another process (or coordinator) still holds this run's marker."""
    marker = child / _RUN_LOCK_NAME
    try:
        descriptor = os.open(marker, os.O_RDWR | os.O_NOFOLLOW)
    except FileNotFoundError:
        # Created by mkdtemp a moment ago and not yet marked: leave it alone while it is young.
        try:
            return time.time() - child.stat().st_mtime < _ORPHAN_GRACE_SECONDS
        except OSError:
            return False
    except OSError:
        return False
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return True
    finally:
        os.close(descriptor)
    return False


def sweep_orphans(base: Path) -> None:
    """Remove run directories left by dead runs; never one whose marker is held."""
    if base.is_dir() and not base.is_symlink():
        for child in base.iterdir():
            if not child.is_symlink() and child.is_dir() and str(child) not in _held_locks and not _is_live(child):
                remove_tree(child)
