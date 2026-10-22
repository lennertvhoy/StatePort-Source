"""Agent sandbox with allowlisted egress (docs/design/agent-sandbox.md).

One module, used by chat, agent actions, the model suite and template checks.
Every agent harness run happens inside bubblewrap with all namespaces
unshared (network included), a read-only system tree, a fresh per-run HOME
and the caller's ``workdir`` bound at ``/work``. Nothing else of the web
service is visible: no state directory, no other instance, no provider home
(an account route gets one copied credential file), no control socket and no
loopback of the control plane.

Egress: the sandbox has no network. ``sandbox_forwarder.py`` (shipped next to
this file, bound read-only into the sandbox) listens on the sandbox's own
loopback ``127.0.0.1:3128`` and relays to one bind-mounted UNIX socket. Behind
that socket this process runs a per-run HTTP CONNECT proxy that admits only
``host:443`` for hosts on the route's allowlist, resolves DNS itself, refuses
names that resolve to loopback/private/link-local/reserved addresses, prefers
IPv4, and logs every connection (host, port, allowed, bytes up/down) for the
run receipt. Everything else gets a 403.

Layout seen by the harness: ``/work`` = ``workdir`` (the only path it may
change; the harness runs with ``--dir /work``), ``/home/agent`` = a fresh
per-run HOME outside ``workdir`` (so the harness's own config, cache and
session files never show up in the caller's diff), ``/tmp`` = a private
tmpfs. The root is remounted read-only. Diffing, path policy and proposals are
the caller's job, never the sandbox's.

Two measured constraints shape the details (opencode 1.18.31, 2026-10-21):

* The OpenCode free tier answers 403 ("can only be used from within
  OpenCode") when a request carries no tools, and also when ``read`` is
  missing. ``tools="none"`` therefore keeps ``bash`` and ``read`` registered
  but denies every call with a catch-all rule, keeping only an allow rule for
  an unguessable per-run pattern that contains a NUL byte (no command or path
  can ever match it).
* With a cold HOME the harness answers from its embedded model snapshot and
  refreshes the catalogue in the background, so newly listed free models
  fail as "Model not found". Each run's HOME is seeded with a ``models.json``
  the web service fetched itself from the same catalogue URL (refreshed at
  most every 15 minutes, only for routes that allow the catalogue host, never
  copied back from a run); its fresh mtime also stops the in-run refetch.

Inside the rootless web container bwrap can mount a fresh ``/proc`` only when
the container runs with ``Unmask=ALL`` (see the Quadlet renderer); the
container's own ``/proc`` is never bound in. Podman's masks are re-applied in
the sandbox's proc by binding ``/dev/null`` over each masked file.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Iterable, Sequence


# --------------------------------------------------------------------------- interface


@dataclass(frozen=True)
class SandboxRoute:            # what may leave the sandbox
    harness: str               # "opencode"
    harness_binary: Path       # the pinned opencode binary
    model: str                 # e.g. "opencode/<id>-free"
    allow_hosts: tuple[str, ...]   # exact host names (or "*.suffix"), port 443 only
    credential_file: Path | None   # None for the free route
    tools: str                 # "none" (chat) | "edit" (agent actions: read/edit/write/list/grep/glob/bash, no webfetch)


@dataclass(frozen=True)
class SandboxResult:
    status: str                # "completed" | "failed" | "timeout" | "refused"
    refusal: str | None        # typed code when refused (e.g. "sandbox_unavailable", "route_not_consented")
    exit_code: int | None
    duration_seconds: float
    final_text: str            # the agent's last text event, bounded to 8 KiB
    events: int                # JSON events seen
    tokens: dict[str, int]     # if the harness reports them
    egress: tuple[dict, ...]   # proxy log entries: {host, port, allowed, bytes_up, bytes_down}
    sandbox_digest: str        # sha256 of the exact bwrap argv template + bwrap version
    stdout: str = ""           # run_check_in_sandbox only: the command's full stdout (already capped by output_limit_bytes)


@dataclass(frozen=True)
class SandboxRun:
    """``run_in_sandbox``'s result plus what the chat path needs to classify it.

    ``process`` is the supervisor's ``ProcessResult`` (stdout, stderr,
    returncode, timed_out, cancelled, output_limited); ``None`` when refused.
    ``events`` are all decoded JSON events, not only the final text.
    """

    result: SandboxResult
    process: Any | None
    events: tuple[dict[str, Any], ...]


# --------------------------------------------------------------------------- constants

PINNED_OPENCODE_VERSION = "1.19.3"
# Measured for the OpenCode free route on 1.18.31: inference and the session
# title request go to opencode.ai, the model catalogue to models.opencode.ai.
OPENCODE_FREE_ROUTE_HOSTS = ("opencode.ai", "models.opencode.ai")
OPENCODE_CATALOGUE_HOSTS = ("models.opencode.ai",)
OPENCODE_BINARY_ENV = "STATEPORT_OPENCODE_BINARY"
RUNTIME_DIR_ENV = "STATEPORT_SANDBOX_RUNTIME_DIR"
TOOLS = ("none", "edit")
FINAL_TEXT_LIMIT_BYTES = 8 * 1024

_WORK = "/work"
_HOME = "/home/agent"
_BIN_INSIDE = "/opt/stateport/bin"
_FORWARDER_INSIDE = "/opt/stateport/forwarder.py"
_PROBE_INSIDE = "/opt/stateport/selftest_probe.py"
_HARNESS_INSIDE = "/opt/stateport/harness/opencode"
_EGRESS_DIR_INSIDE = "/run/stateport-egress"
_EGRESS_SOCKET = "egress.sock"
_PROXY_PORT = 3128
_ENV_FILE_INSIDE = _HOME + "/.stateport/credential.env"
_FORWARDER_SOURCE = Path(__file__).with_name("sandbox_forwarder.py")
_PROBE_SOURCE = Path(__file__).with_name("sandbox_selftest_probe.py")

# Podman's masked /proc files, re-applied inside the sandbox's fresh procfs.
_PROC_MASKS = (
    "/proc/kcore", "/proc/keys", "/proc/kallsyms", "/proc/latency_stats",
    "/proc/timer_list", "/proc/timer_stats", "/proc/sched_debug", "/proc/sysrq-trigger",
)
_TMPFS_BYTES = 256 * 1024 * 1024
_MAX_CONCURRENT_RUNS = 8
_MAX_PROMPT_BYTES = 120 * 1024
_MAX_CREDENTIAL_BYTES = 64 * 1024
_MAX_CATALOGUE_BYTES = 32 * 1024 * 1024
_CATALOGUE_TTL_SECONDS = 15 * 60
_CATALOGUE_MAX_AGE_SECONDS = 24 * 3600
_CATALOGUE_RETRY_SECONDS = 120
_PROBE_TTL_OK = 3600.0
_PROBE_TTL_FAIL = 60.0

_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}$")
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOSTNAME = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(?:\.{_LABEL})*$")
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_VERSION = re.compile(r"(\d+\.\d+(?:\.\d+)?)")
_SECRETISH = re.compile(r"(?:sk-[A-Za-z0-9_-]{6,}|[A-Za-z0-9+/_=-]{32,})")

# Environment for every OpenCode run. Each flag was checked against the
# 1.18.31 binary's own flag list; together they stop auto-update, npm plugin
# installs, project-supplied config/plugins/agents, LSP downloads, sharing and
# the external skill scans.
_OPENCODE_ENV = {
    "OPENCODE_DISABLE_AUTOUPDATE": "1",
    "OPENCODE_DISABLE_DEFAULT_PLUGINS": "1",
    "OPENCODE_PURE": "1",
    "OPENCODE_DISABLE_PROJECT_CONFIG": "1",
    "OPENCODE_DISABLE_LSP_DOWNLOAD": "1",
    "OPENCODE_DISABLE_SHARE": "1",
    "OPENCODE_DISABLE_CLAUDE_CODE": "1",
    "OPENCODE_DISABLE_CLAUDE_CODE_PROMPT": "1",
    "OPENCODE_DISABLE_CLAUDE_CODE_SKILLS": "1",
    "OPENCODE_DISABLE_EXTERNAL_SKILLS": "1",
    "OPENCODE_DISABLE_EMBEDDED_WEB_UI": "1",
}


class _Refusal(Exception):
    def __init__(self, code: str, reason: str) -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason


# --------------------------------------------------------------------------- small helpers


def _under(path: str, root: str) -> bool:
    root = root.rstrip("/") or "/"
    return path == root or root == "/" or path.startswith(root + "/")


def _bounded(text: str, limit: int, *, tail: bool = False) -> str:
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text
    part = encoded[-limit:] if tail else encoded[:limit]
    return part.decode("utf-8", errors="ignore")


def _redact(text: str) -> str:
    return _SECRETISH.sub("[redacted]", text)


def _private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise _Refusal("sandbox_unavailable", f"sandbox runtime directory {path} is not a private directory")
    if stat.S_IMODE(info.st_mode) & 0o077:
        os.chmod(path, 0o700)
    return path


def _runtime_root() -> Path:
    configured = os.environ.get(RUNTIME_DIR_ENV, "").strip()
    if configured:
        root = Path(configured)
        if not root.is_absolute():
            raise _Refusal("sandbox_unavailable", f"{RUNTIME_DIR_ENV} must be absolute")
    else:
        root = Path("/tmp") / f"stateport-sandbox-{os.geteuid()}"
    return _private_dir(root)


def _remove_tree(path: Path) -> None:
    def fix(function: Callable[..., Any], target: str, _info: Any) -> None:
        try:
            os.chmod(os.path.dirname(target), 0o700)
            if os.path.isdir(target) and not os.path.islink(target):
                os.chmod(target, 0o700)
            function(target)
        except OSError:
            pass
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=fix)
    else:  # pragma: no cover - Python 3.11
        shutil.rmtree(path, onerror=fix)


def _write_private(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)


# --------------------------------------------------------------------------- bubblewrap probe


@dataclass(frozen=True)
class _Bwrap:
    executable: str
    version: str
    features: frozenset[str]


@dataclass(frozen=True)
class _Interpreter:
    executable: str
    bind: str | None


_probe_lock = threading.Lock()
_probe_state: dict[str, Any] = {"at": 0.0, "value": None, "bwrap": None}
_run_slots = threading.BoundedSemaphore(_MAX_CONCURRENT_RUNS)


def _bwrap_info() -> _Bwrap:
    executable = shutil.which("bwrap", path="/usr/bin:/bin:/usr/local/bin")
    if executable is None:
        raise _Refusal("sandbox_unavailable", "bubblewrap (bwrap) is not installed")
    executable = os.path.realpath(executable)
    try:
        version_run = subprocess.run(
            (executable, "--version"), stdin=subprocess.DEVNULL, capture_output=True,
            timeout=10, check=False, env={"PATH": "/usr/bin:/bin"},
        )
        help_run = subprocess.run(
            (executable, "--help"), stdin=subprocess.DEVNULL, capture_output=True,
            timeout=10, check=False, env={"PATH": "/usr/bin:/bin"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise _Refusal("sandbox_unavailable", f"bubblewrap could not run: {exc.__class__.__name__}") from None
    match = _VERSION.search(version_run.stdout.decode("utf-8", "replace"))
    if version_run.returncode != 0 or match is None:
        raise _Refusal("sandbox_unavailable", "bubblewrap did not report a version")
    text = help_run.stdout.decode("utf-8", "replace") + help_run.stderr.decode("utf-8", "replace")
    features = frozenset(
        flag for flag in ("--size", "--disable-userns", "--cap-drop", "--remount-ro", "--clearenv")
        if flag in text
    )
    for required in ("--remount-ro", "--clearenv"):
        if required not in features:
            raise _Refusal("sandbox_unavailable", f"bubblewrap {match.group(1)} lacks {required}")
    return _Bwrap(executable, match.group(1), features)


def _interpreter() -> _Interpreter:
    executable = os.path.realpath(sys.executable)
    if not os.path.isfile(executable) or not os.access(executable, os.X_OK):
        raise _Refusal("sandbox_unavailable", "the service's Python interpreter cannot be resolved")
    prefix = os.path.realpath(sys.base_prefix)
    if _under(executable, "/usr") and _under(prefix, "/usr"):
        return _Interpreter(executable, None)
    # A Python outside /usr (for example a mise or pyenv build on a dev host):
    # bind its installation prefix read-only at the same path.
    if not _under(executable, prefix) or prefix.count("/") < 3:
        raise _Refusal(
            "sandbox_unavailable",
            "the service's Python lives outside /usr and outside a bindable installation prefix",
        )
    return _Interpreter(executable, prefix)


def _system_args(bwrap: _Bwrap) -> list[str]:
    args = ["--ro-bind", "/usr", "/usr"]
    for path in ("/bin", "/sbin", "/lib", "/lib64", "/lib32", "/libx32"):
        if os.path.islink(path):
            args += ["--symlink", os.readlink(path), path]
        elif os.path.isdir(path):
            args += ["--ro-bind", path, path]
    # CA bundle. On Arch /etc/ssl/certs links into /etc/ca-certificates.
    for path in ("/etc/ssl", "/etc/ca-certificates", "/etc/pki"):
        if os.path.isdir(path) and not os.path.islink(path):
            args += ["--ro-bind", path, path]
    # Devices: the same shape portable-execution uses on the reference machine
    # (individual character devices, no devpts), plus the fd symlinks and shm.
    args += ["--dir", "/dev"]
    for name in ("null", "zero", "full", "random", "urandom"):
        device = f"/dev/{name}"
        if os.path.exists(device):
            args += ["--dev-bind", device, device]
    args += [
        "--symlink", "/proc/self/fd", "/dev/fd",
        "--symlink", "/proc/self/fd/0", "/dev/stdin",
        "--symlink", "/proc/self/fd/1", "/dev/stdout",
        "--symlink", "/proc/self/fd/2", "/dev/stderr",
    ]
    size = ["--size", str(_TMPFS_BYTES)] if "--size" in bwrap.features else []
    args += [*size, "--tmpfs", "/dev/shm"]
    # A fresh procfs for the sandbox's own pid namespace (never the
    # container's /proc), with podman's masks re-applied.
    args += ["--proc", "/proc"]
    for path in _PROC_MASKS:
        if os.path.exists(path):
            args += ["--ro-bind", "/dev/null", path]
    args += [*size, "--tmpfs", "/tmp"]
    return args


def _probe_uncached() -> tuple[bool, str, _Bwrap | None]:
    if not sys.platform.startswith("linux"):
        return False, "the agent sandbox needs Linux namespaces", None
    try:
        bwrap = _bwrap_info()
        interpreter = _interpreter()
        root = _runtime_root()
        workdir = Path(tempfile.mkdtemp(prefix="probe-", dir=root))
        try:
            execution = _execute(
                bwrap=bwrap, interpreter=interpreter, workdir=workdir, workdir_writable=False,
                command=[interpreter.executable, "-I", "-B", "-c",
                         "import os;print('stateport-sandbox-ok', sum(p.isdigit() for p in os.listdir('/proc')))"],
                env=_base_env(home=None), network_hosts=None, home_setup=None, extra_ro=(),
                timeout=20, output_limit=65536,
            )
        finally:
            _remove_tree(workdir)
    except _Refusal as refusal:
        return False, refusal.reason, None
    process = execution.process
    if process.returncode == 0 and process.stdout.startswith("stateport-sandbox-ok"):
        return True, f"bubblewrap {bwrap.version}: user, pid, net, ipc, uts namespaces and a private /proc", bwrap
    detail = (process.stderr or process.stdout or "").strip().splitlines()
    first = detail[0] if detail else f"exit {process.returncode}"
    hint = ""
    if "proc" in first.lower():
        hint = " (inside the rootless web container this needs Unmask=ALL)"
    return False, _bounded(f"bubblewrap sandbox probe failed: {first}{hint}", 400), None


def sandbox_available() -> tuple[bool, str]:
    """Probe bwrap + user namespaces + a private /proc once; reason when False."""
    now = time.monotonic()
    with _probe_lock:
        cached = _probe_state["value"]
        if cached is not None:
            ttl = _PROBE_TTL_OK if cached[0] else _PROBE_TTL_FAIL
            if now - _probe_state["at"] < ttl:
                return cached
        ok, reason, bwrap = _probe_uncached()
        _probe_state.update(at=time.monotonic(), value=(ok, reason), bwrap=bwrap)
        return ok, reason


def _available_bwrap() -> _Bwrap:
    ok, reason = sandbox_available()
    bwrap = _probe_state.get("bwrap")
    if not ok or bwrap is None:
        raise _Refusal("sandbox_unavailable", reason)
    return bwrap


def _reset_probe_cache() -> None:
    """Forget cached probes (tests, or after the operator fixed the host)."""
    with _probe_lock:
        _probe_state.update(at=0.0, value=None, bwrap=None)
    _harness_versions.clear()


# --------------------------------------------------------------------------- egress proxy


class _Deny(Exception):
    def __init__(self, reason: str, status: bytes = b"403 Forbidden") -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status


def _valid_host_pattern(pattern: object) -> bool:
    if not isinstance(pattern, str):
        return False
    name = pattern[2:] if pattern.startswith("*.") else pattern
    return _HOSTNAME.fullmatch(name) is not None and "." in name and not _is_ip_literal(name)


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def _host_allowed(host: str, allow: Iterable[str]) -> bool:
    for pattern in allow:
        if pattern.startswith("*."):
            if host.endswith(pattern[1:]) and host != pattern[2:]:
                return True
        elif host == pattern:
            return True
    return False


_TLS_HELLO_LIMIT = 64 * 1024


def _client_hello_complete(data: bytes) -> bool:
    """Whether ``data`` (TLS records from the client) holds one whole ClientHello handshake message."""

    payload = _handshake_payload(data)
    return len(payload) >= 4 and len(payload) >= 4 + int.from_bytes(payload[1:4], "big")


def _handshake_payload(data: bytes) -> bytes:
    """Concatenate the handshake bytes of the leading TLS records (a ClientHello may span records)."""

    payload = b""
    offset = 0
    while offset + 5 <= len(data):
        if data[offset] != 0x16 or data[offset + 1] != 0x03:
            raise _Deny("not_tls")
        length = int.from_bytes(data[offset + 3:offset + 5], "big")
        if length == 0 or length > 18432:
            raise _Deny("not_tls")
        payload += data[offset + 5:offset + 5 + length]
        offset += 5 + length
    return payload


def _client_hello_sni(data: bytes) -> str | None:
    """The server name a TLS ClientHello asks for (RFC 6066), or None when it names none.

    The CONNECT host alone proves nothing: allowlisted names share CDN addresses
    with every other customer of that CDN, so a client could open a tunnel "to"
    an allowlisted host and then speak TLS to any other name served there.
    """

    payload = _handshake_payload(data)
    if len(payload) < 4 or payload[0] != 0x01:
        raise _Deny("not_tls")
    body = payload[4:4 + int.from_bytes(payload[1:4], "big")]
    try:
        offset = 2 + 32                                   # legacy version, random
        offset += 1 + body[offset]                        # session id
        offset += 2 + int.from_bytes(body[offset:offset + 2], "big")  # cipher suites
        offset += 1 + body[offset]                        # compression methods
        if offset == len(body):
            return None
        end = offset + 2 + int.from_bytes(body[offset:offset + 2], "big")
        offset += 2
        while offset + 4 <= end:
            kind = int.from_bytes(body[offset:offset + 2], "big")
            size = int.from_bytes(body[offset + 2:offset + 4], "big")
            data_start = offset + 4
            if kind == 0x0000:                            # server_name
                names_end = data_start + 2 + int.from_bytes(body[data_start:data_start + 2], "big")
                cursor = data_start + 2
                while cursor + 3 <= names_end:
                    name_type = body[cursor]
                    name_len = int.from_bytes(body[cursor + 1:cursor + 3], "big")
                    name = body[cursor + 3:cursor + 3 + name_len]
                    if name_type == 0 and len(name) == name_len:
                        return name.decode("ascii").lower().rstrip(".")
                    cursor += 3 + name_len
                return None
            offset = data_start + size
    except (IndexError, UnicodeDecodeError):
        raise _Deny("not_tls") from None
    return None


def _resolve_public(host: str, port: int) -> list[tuple[int, tuple[Any, ...]]]:
    """Resolve outside the sandbox; refuse any non-public answer; IPv4 first."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    except OSError:
        raise _Deny("dns_failed", b"502 Bad Gateway") from None
    if not infos:
        raise _Deny("dns_failed", b"502 Bad Gateway")
    candidates: list[tuple[int, tuple[Any, ...]]] = []
    for family, _type, _proto, _name, address in infos:
        try:
            ip = ipaddress.ip_address(str(address[0]).split("%", 1)[0])
        except ValueError:
            raise _Deny("non_public_address") from None
        mapped = getattr(ip, "ipv4_mapped", None)
        if not ip.is_global or ip.is_multicast or (mapped is not None and not mapped.is_global):
            raise _Deny("non_public_address")
        if (family, address) not in candidates:
            candidates.append((family, address))
    candidates.sort(key=lambda item: 0 if item[0] == socket.AF_INET else 1)
    return candidates


class _EgressProxy:
    """Per-run allowlisting CONNECT proxy on a UNIX socket (runs in this process)."""

    MAX_ACTIVE = 16
    MAX_TOTAL = 512
    MAX_LOG = 256
    HEADER_BYTES = 8192
    HEADER_TIMEOUT = 10.0
    CONNECT_TIMEOUT = 10.0
    IDLE_TIMEOUT = 120.0
    MAX_BYTES_UP = 64 * 1024 * 1024
    MAX_BYTES_DOWN = 512 * 1024 * 1024

    def __init__(self, directory: Path, allow_hosts: Sequence[str],
                 resolver: Callable[[str, int], list[tuple[int, tuple[Any, ...]]]] | None = None) -> None:
        self.directory = directory
        self.allow = tuple(allow_hosts)
        self.resolver = resolver or _resolve_public
        self._lock = threading.Lock()
        self._stopping = threading.Event()
        self._listener: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._handlers: set[threading.Thread] = set()
        self._sockets: set[socket.socket] = set()
        self._entries: list[dict[str, Any]] = []
        self._dropped = 0
        self._total = 0
        self._up = 0
        self._down = 0
        self._start = time.monotonic()

    @property
    def socket_path(self) -> Path:
        return self.directory / _EGRESS_SOCKET

    def start(self) -> None:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # AF_UNIX paths are limited to ~107 bytes. Bind through a short
        # /proc/self/fd path to the directory instead of chdir (this process
        # is multithreaded); always unlink a stale socket first.
        directory_fd = os.open(self.directory, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            try:
                os.unlink(_EGRESS_SOCKET, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            listener.bind(f"/proc/self/fd/{directory_fd}/{_EGRESS_SOCKET}")
        except OSError:
            listener.close()
            raise
        finally:
            os.close(directory_fd)
        os.chmod(self.socket_path, 0o600)
        listener.listen(64)
        listener.settimeout(0.25)
        self._listener = listener
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="stateport-sandbox-egress", daemon=True
        )
        self._accept_thread.start()

    def stop(self) -> None:
        self._stopping.set()
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=2.0)
        with self._lock:
            sockets = list(self._sockets)
            handlers = list(self._handlers)
        for item in sockets:
            try:
                item.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        deadline = time.monotonic() + 5.0
        for handler in handlers:
            handler.join(timeout=max(deadline - time.monotonic(), 0.05))

    def entries(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            entries = [dict(item) for item in self._entries]
            if self._dropped:
                entries.append({
                    "host": None, "port": None, "allowed": False, "bytes_up": 0,
                    "bytes_down": 0, "reason": f"log_truncated:{self._dropped}",
                })
        return tuple(entries)

    def _log(self, entry: dict[str, Any]) -> None:
        with self._lock:
            if len(self._entries) < self.MAX_LOG:
                self._entries.append(entry)
            else:
                self._dropped += 1

    def _track(self, *items: socket.socket, add: bool = True) -> None:
        with self._lock:
            for item in items:
                (self._sockets.add if add else self._sockets.discard)(item)

    def _accept_loop(self) -> None:
        assert self._listener is not None
        while not self._stopping.is_set():
            try:
                client, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self._lock:
                self._handlers = {item for item in self._handlers if item.is_alive()}
                refused = len(self._handlers) >= self.MAX_ACTIVE or self._total >= self.MAX_TOTAL
                if not refused:
                    self._total += 1
            if refused:
                try:
                    client.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
                except OSError:
                    pass
                client.close()
                self._log({"host": None, "port": None, "allowed": False, "bytes_up": 0,
                           "bytes_down": 0, "reason": "connection_limit"})
                continue
            handler = threading.Thread(target=self._handle, args=(client,), daemon=True)
            with self._lock:
                self._handlers.add(handler)
            handler.start()

    def _read_head(self, client: socket.socket) -> tuple[bytes, bytes]:
        client.settimeout(self.HEADER_TIMEOUT)
        buffer = b""
        while b"\r\n\r\n" not in buffer:
            if len(buffer) > self.HEADER_BYTES:
                raise _Deny("header_too_large")
            chunk = client.recv(4096)
            if not chunk:
                raise _Deny("client_closed")
            buffer += chunk
        head, rest = buffer.split(b"\r\n\r\n", 1)
        return head, rest

    def _read_client_hello(self, client: socket.socket, buffered: bytes) -> bytes:
        client.settimeout(self.HEADER_TIMEOUT)
        data = buffered
        while not _client_hello_complete(data):
            if len(data) > _TLS_HELLO_LIMIT:
                raise _Deny("not_tls")
            chunk = client.recv(16384)
            if not chunk:
                raise _Deny("client_closed")
            data += chunk
        return data

    def _handle(self, client: socket.socket) -> None:
        entry: dict[str, Any] = {
            "host": None, "port": None, "allowed": False, "bytes_up": 0, "bytes_down": 0,
            "reason": None, "at": round(time.monotonic() - self._start, 3),
        }
        upstream: socket.socket | None = None
        self._track(client)
        try:
            head, rest = self._read_head(client)
            line = head.split(b"\r\n", 1)[0].decode("latin-1")
            parts = line.split(" ")
            if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
                raise _Deny("request_malformed")
            method, target = parts[0], parts[1]
            if method != "CONNECT":
                host = re.sub(r"^[a-z]+://", "", target.lower()).split("/", 1)[0].rsplit(":", 1)[0]
                entry["host"] = host[:253] or None
                raise _Deny("method_not_allowed")
            host, _, port_text = target.rpartition(":")
            host = host.strip().lower().rstrip(".")
            entry["host"] = host[:253] or None
            if not port_text.isdigit():
                raise _Deny("port_not_allowed")
            port = int(port_text)
            entry["port"] = port
            if port != 443:
                raise _Deny("port_not_allowed")
            if _is_ip_literal(host) or _HOSTNAME.fullmatch(host) is None:
                raise _Deny("host_invalid")
            if not _host_allowed(host, self.allow):
                raise _Deny("host_not_allowlisted")
            # The tunnel opens only for TLS that names the allowlisted host: read the ClientHello first,
            # compare its server name, and only then resolve and connect.
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            entry["tunnel"] = True
            hello = self._read_client_hello(client, rest)
            sni = _client_hello_sni(hello)
            if sni != host:
                entry["sni"] = (sni or "")[:253] or None
                raise _Deny("sni_mismatch")
            rest = hello
            candidates = self.resolver(host, port)
            last_error = "upstream_unreachable"
            for family, address in candidates:
                attempt = socket.socket(family, socket.SOCK_STREAM)
                attempt.settimeout(self.CONNECT_TIMEOUT)
                try:
                    attempt.connect(address)
                except OSError:
                    attempt.close()
                    continue
                upstream = attempt
                break
            if upstream is None:
                raise _Deny(last_error, b"502 Bad Gateway")
            self._track(upstream)
            entry["allowed"] = True
            if rest:
                if not self._account(entry, "bytes_up", len(rest)):
                    raise _Deny("byte_cap_exceeded")
                upstream.sendall(rest)
            entry["reason"] = self._relay(client, upstream, entry)
        except _Deny as denial:
            entry["reason"] = denial.reason
            if not entry["allowed"] and not entry.get("tunnel") and denial.reason != "client_closed":
                try:
                    client.sendall(b"HTTP/1.1 " + denial.status + b"\r\nContent-Length: 0\r\n\r\n")
                except OSError:
                    pass
        except (OSError, UnicodeError, ValueError) as exc:
            entry["reason"] = entry["reason"] or f"error:{exc.__class__.__name__}"
        finally:
            for item in (client, upstream):
                if item is None:
                    continue
                self._track(item, add=False)
                try:
                    item.close()
                except OSError:
                    pass
            entry.pop("tunnel", None)
            if entry["host"] is not None or entry["reason"] not in {None, "client_closed"}:
                self._log(entry)

    def _account(self, entry: dict[str, Any], key: str, amount: int) -> bool:
        with self._lock:
            if key == "bytes_up":
                if self._up + amount > self.MAX_BYTES_UP:
                    return False
                self._up += amount
            else:
                if self._down + amount > self.MAX_BYTES_DOWN:
                    return False
                self._down += amount
        entry[key] += amount
        return True

    def _relay(self, client: socket.socket, upstream: socket.socket, entry: dict[str, Any]) -> str | None:
        client.settimeout(self.IDLE_TIMEOUT)
        upstream.settimeout(self.IDLE_TIMEOUT)
        selector = selectors.DefaultSelector()
        selector.register(client, selectors.EVENT_READ, (upstream, "bytes_up"))
        selector.register(upstream, selectors.EVENT_READ, (client, "bytes_down"))
        open_sides = 2
        try:
            while open_sides:
                if self._stopping.is_set():
                    return "run_finished"
                ready = selector.select(min(self.IDLE_TIMEOUT, 1.0))
                if not ready:
                    if time.monotonic() - entry.setdefault("_last", time.monotonic()) > self.IDLE_TIMEOUT:
                        return "idle_timeout"
                    continue
                entry["_last"] = time.monotonic()
                for key, _ in ready:
                    source = key.fileobj
                    target, counter = key.data
                    try:
                        data = source.recv(65536)  # type: ignore[union-attr]
                    except OSError:
                        data = b""
                    if not data:
                        selector.unregister(source)
                        open_sides -= 1
                        try:
                            target.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        continue
                    if not self._account(entry, counter, len(data)):
                        return "byte_cap_exceeded"
                    target.sendall(data)
            return None
        finally:
            selector.close()
            entry.pop("_last", None)


# --------------------------------------------------------------------------- execution core


@dataclass(frozen=True)
class _Execution:
    process: Any
    egress: tuple[dict[str, Any], ...]
    digest: str


def _base_env(*, home: str | None) -> dict[str, str]:
    env = {
        "PATH": f"{_BIN_INSIDE}:/usr/local/bin:/usr/bin:/bin",
        "TMPDIR": "/tmp",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "TERM": "dumb",
        "NO_COLOR": "1",
        "HOME": home or "/tmp",
        "USER": "agent",
        "LOGNAME": "agent",
    }
    if home is not None:
        env.update(
            XDG_CONFIG_HOME=f"{home}/.config",
            XDG_DATA_HOME=f"{home}/.local/share",
            XDG_CACHE_HOME=f"{home}/.cache",
            XDG_STATE_HOME=f"{home}/.local/state",
        )
    return env


def _proxy_env() -> dict[str, str]:
    proxy = f"http://127.0.0.1:{_PROXY_PORT}"
    return {
        "HTTPS_PROXY": proxy, "HTTP_PROXY": proxy, "https_proxy": proxy, "http_proxy": proxy,
        "NO_PROXY": "localhost,127.0.0.1,::1", "no_proxy": "localhost,127.0.0.1,::1",
    }


def _execute(
    *,
    bwrap: _Bwrap,
    interpreter: _Interpreter,
    workdir: Path,
    workdir_writable: bool,
    command: list[str],
    env: dict[str, str],
    network_hosts: Sequence[str] | None,
    home_setup: Callable[[Path], None] | None,
    extra_ro: Sequence[tuple[str, str]],
    timeout: float,
    output_limit: int,
    cancel_event: Any | None = None,
    on_started: Callable[[Any], None] | None = None,
    on_finished: Callable[[Any], None] | None = None,
    process_generation: str | None = None,
    placeholders: Sequence[tuple[str, str]] = (),
    resolver: Callable[[str, int], list[tuple[int, tuple[Any, ...]]]] | None = None,
    forwarder_flags: Sequence[str] = (),
) -> _Execution:
    """Run ``command`` in the sandbox shape; ``network_hosts`` None means no egress at all."""
    from external_engine_runtime import ProcessSpec, run_process

    run_dir = Path(tempfile.mkdtemp(prefix="run-", dir=_runtime_root()))
    proxy: _EgressProxy | None = None
    try:
        etc = run_dir / "etc"
        etc.mkdir(mode=0o700)
        uid, gid = os.getuid(), os.getgid()
        (etc / "passwd").write_text(f"agent:x:{uid}:{gid}:agent:{_HOME}:/bin/sh\n", encoding="utf-8")
        (etc / "group").write_text(f"agent:x:{gid}:\n", encoding="utf-8")
        (etc / "hosts").write_text("127.0.0.1 localhost\n::1 localhost\n", encoding="utf-8")
        args = [bwrap.executable, "--unshare-all", "--unshare-user"]
        if "--disable-userns" in bwrap.features:
            args.append("--disable-userns")
        args += ["--die-with-parent", "--new-session", "--clearenv"]
        if "--cap-drop" in bwrap.features:
            args += ["--cap-drop", "ALL"]
        args += _system_args(bwrap)
        for name in ("passwd", "group", "hosts"):
            args += ["--ro-bind", str(etc / name), f"/etc/{name}"]
        if interpreter.bind is not None:
            args += ["--ro-bind", interpreter.bind, interpreter.bind]
        args += ["--dir", _BIN_INSIDE, "--symlink", interpreter.executable, f"{_BIN_INSIDE}/python3"]
        if network_hosts is not None:
            egress = run_dir / "egress"
            egress.mkdir(mode=0o700)
            proxy = _EgressProxy(egress, network_hosts, resolver=resolver)
            proxy.start()
            args += ["--ro-bind", str(_FORWARDER_SOURCE), _FORWARDER_INSIDE,
                     "--ro-bind", str(egress), _EGRESS_DIR_INSIDE]
        for source, target in extra_ro:
            args += ["--ro-bind", source, target]
        if home_setup is not None:
            home = run_dir / "home"
            home.mkdir(mode=0o700)
            home_setup(home)
            args += ["--bind", str(home), _HOME]
        args += ["--bind" if workdir_writable else "--ro-bind", str(workdir), _WORK, "--chdir", _WORK]
        args += ["--remount-ro", "/"]
        for name in sorted(env):
            args += ["--setenv", name, env[name]]
        if network_hosts is not None:
            # The forwarder listens first, then starts ``command`` as its child.
            command = [
                interpreter.executable, "-I", "-B", _FORWARDER_INSIDE,
                "--socket", f"{_EGRESS_DIR_INSIDE}/{_EGRESS_SOCKET}", "--listen", str(_PROXY_PORT),
                *forwarder_flags, "--", *command,
            ]
        argv = args + ["--", *command]
        substitutions = sorted(
            [(str(run_dir), "{run}"), (str(workdir), "{workdir}"), *placeholders],
            key=lambda item: len(item[0]), reverse=True,
        )
        template = []
        for item in argv:
            whole = next((label for value, label in substitutions if value and item == value), None)
            if whole is not None:
                template.append(whole)
                continue
            for value, label in substitutions:
                if value and len(value) > 3:
                    item = item.replace(value, label)
            template.append(item)
        digest = "sha256:" + hashlib.sha256(
            json.dumps({"bwrapVersion": bwrap.version, "argv": template}, separators=(",", ":")).encode()
        ).hexdigest()
        process = run_process(
            ProcessSpec(
                tuple(argv), run_dir, timeout_seconds=float(timeout),
                max_output_bytes=int(output_limit),
                environment={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                on_started=on_started, on_finished=on_finished,
                process_generation=process_generation,
            ),
            cancel_event=cancel_event,
        )
    finally:
        if proxy is not None:
            proxy.stop()
        _remove_tree(run_dir)
    return _Execution(process, proxy.entries() if proxy is not None else (), digest)


def _validated_workdir(workdir: Path | str) -> Path:
    path = Path(workdir)
    if not path.is_absolute():
        raise _Refusal("workdir_invalid", "workdir must be an absolute path")
    real = os.path.realpath(path)
    if real != os.path.normpath(str(path)):
        raise _Refusal("workdir_invalid", "workdir must not traverse a symbolic link")
    if not os.path.isdir(real):
        raise _Refusal("workdir_invalid", "workdir must be an existing directory")
    protected = {
        "/", "/usr", "/etc", "/proc", "/sys", "/dev", "/run", "/home", "/root", "/var", "/var/lib",
        "/tmp", "/opt", "/srv", "/mnt", "/media",
    }
    if real in protected or real == os.path.realpath(Path.home()):
        raise _Refusal("workdir_invalid", "workdir must be a dedicated directory StatePort created")
    sensitive = [str(_runtime_root()), "/var/lib/stateport", "/var/lib/stateport-provider"]
    for variable, suffix in (("XDG_STATE_HOME", "stateport"), ("XDG_CONFIG_HOME", "stateport"),
                             ("XDG_DATA_HOME", "stateport"), ("STATEPORT_OPENCODE_HOME", "")):
        value = os.environ.get(variable, "").strip()
        if value and os.path.isabs(value):
            sensitive.append(os.path.realpath(os.path.join(value, suffix)) if suffix else os.path.realpath(value))
    for root in sensitive:
        if _under(root, real):
            raise _Refusal("workdir_invalid", "workdir must not contain StatePort state or runtime directories")
    return Path(real)


class _RunSlot:
    def __enter__(self) -> "_RunSlot":
        if not _run_slots.acquire(timeout=30.0):
            raise _Refusal("sandbox_busy", "too many sandboxed runs are active; retry later")
        return self

    def __exit__(self, *_exc: object) -> None:
        _run_slots.release()


# --------------------------------------------------------------------------- harness (OpenCode)


_harness_lock = threading.Lock()
_harness_versions: dict[tuple[Any, ...], str | None] = {}


def _harness_version(binary: Path) -> str | None:
    """The harness's own ``--version``, run inside the sandbox; cached by file identity."""
    try:
        real = os.path.realpath(binary)
        info = os.stat(real)
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode) or not os.access(real, os.X_OK):
        return None
    key = (real, info.st_ino, info.st_size, info.st_mtime_ns)
    with _harness_lock:
        if key in _harness_versions:
            return _harness_versions[key]
    bwrap = _available_bwrap()
    interpreter = _interpreter()
    workdir = Path(tempfile.mkdtemp(prefix="version-", dir=_runtime_root()))
    try:
        env = _base_env(home=_HOME)
        env.update(_OPENCODE_ENV)
        execution = _execute(
            bwrap=bwrap, interpreter=interpreter, workdir=workdir, workdir_writable=False,
            command=[_HARNESS_INSIDE, "--version"], env=env, network_hosts=None,
            home_setup=lambda _home: None, extra_ro=((real, _HARNESS_INSIDE),),
            timeout=30, output_limit=65536,
        )
    finally:
        _remove_tree(workdir)
    process = execution.process
    lines = (process.stdout or "").strip().splitlines()
    version = None
    if process.returncode == 0 and lines:
        match = re.fullmatch(r"v?(\d+\.\d+\.\d+)", lines[-1].strip())
        version = match.group(1) if match else None
    with _harness_lock:
        _harness_versions[key] = version
    return version


def resolve_harness_binary(harness: str = "opencode") -> Path | None:
    """Find the pinned harness binary; ``None`` when no pinned build is present.

    ``STATEPORT_OPENCODE_BINARY`` (explicit configuration) is the only
    candidate when set. Otherwise: the web image's ``/usr/local/bin/opencode``,
    ``opencode`` on PATH, then the dev-loop cache
    ``$XDG_CACHE_HOME/stateport/opencode/<version>/opencode``. A candidate is
    accepted only when it reports exactly ``PINNED_OPENCODE_VERSION`` from
    inside the sandbox (so a version-manager shim or a newer release is never
    used silently).
    """
    if harness != "opencode":
        return None
    configured = os.environ.get(OPENCODE_BINARY_ENV, "").strip()
    if configured:
        candidates = [Path(configured)]
    else:
        cache_home = os.environ.get("XDG_CACHE_HOME", "").strip() or str(Path.home() / ".cache")
        candidates = [Path("/usr/local/bin/opencode")]
        found = shutil.which("opencode")
        if found:
            candidates.append(Path(found))
        candidates.append(Path(cache_home) / "stateport" / "opencode" / PINNED_OPENCODE_VERSION / "opencode")
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate.is_absolute() or not candidate.exists():
            continue
        real = os.path.realpath(candidate)
        if real in seen:
            continue
        seen.add(real)
        try:
            if _harness_version(Path(real)) == PINNED_OPENCODE_VERSION:
                return Path(real)
        except _Refusal:
            return None
    return None


def _validate_route(route: SandboxRoute) -> None:
    if not isinstance(route, SandboxRoute):
        raise _Refusal("route_invalid", "route must be a SandboxRoute")
    if route.harness != "opencode":
        raise _Refusal("route_invalid", f"harness {route.harness!r} is not supported")
    if route.tools not in TOOLS:
        raise _Refusal("route_invalid", f"tools must be one of {TOOLS}")
    if not isinstance(route.model, str) or _MODEL.fullmatch(route.model) is None:
        raise _Refusal("route_invalid", "model identifier is invalid")
    if not isinstance(route.allow_hosts, (tuple, list)) or len(route.allow_hosts) > 32:
        raise _Refusal("route_invalid", "allow_hosts must be a tuple of at most 32 host names")
    for pattern in route.allow_hosts:
        if not _valid_host_pattern(pattern):
            raise _Refusal("route_invalid", f"allow_hosts entry {pattern!r} is not a host name or *.suffix")
    if not isinstance(route.harness_binary, Path) or not route.harness_binary.is_absolute():
        raise _Refusal("route_invalid", "harness_binary must be an absolute Path")
    if route.credential_file is not None and not isinstance(route.credential_file, Path):
        raise _Refusal("route_invalid", "credential_file must be a Path or None")


def _verified_harness(binary: Path) -> str:
    real = os.path.realpath(binary)
    version = _harness_version(Path(real))
    if version != PINNED_OPENCODE_VERSION:
        raise _Refusal(
            "sandbox_unavailable",
            f"the harness binary is not the pinned opencode {PINNED_OPENCODE_VERSION}"
            + (f" (it reports {version})" if version else ""),
        )
    return real


def _credential_setup(source: Path, model: str) -> tuple[Callable[[Path], None], bool]:
    """Copy exactly one credential into the per-run HOME.

    ``auth.json`` (OpenCode's own sign-in) is reduced to the one record of the
    model's provider and placed where OpenCode reads it; any other file must be
    ``NAME=value`` lines (StatePort's ``provider.env``) and is handed to the
    forwarder, which exports it to the harness and deletes it. The copy dies
    with the run directory and is never copied back (a refreshed OAuth token
    stays inside that run).
    """
    try:
        info = os.lstat(source)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_CREDENTIAL_BYTES:
            raise OSError("unsafe")
        data = source.read_bytes()
    except OSError:
        raise _Refusal("credential_unavailable", "the route's credential file is missing or unsafe") from None
    if source.name == "auth.json":
        provider = model.partition("/")[0]
        try:
            records = json.loads(data)
            if not isinstance(records, dict):
                raise ValueError
        except ValueError:
            raise _Refusal("credential_unavailable", "the route's auth.json is not a JSON object") from None
        if provider not in records:
            raise _Refusal("credential_unavailable", f"the route's auth.json has no sign-in for {provider!r}")
        reduced = json.dumps({provider: records[provider]}).encode("utf-8")

        def install_auth(home: Path) -> None:
            _write_private(home / ".local" / "share" / "opencode" / "auth.json", reduced)

        return install_auth, False
    try:
        lines = [line for line in data.decode("utf-8").splitlines() if line.strip()]
    except UnicodeDecodeError:
        raise _Refusal("credential_unavailable", "the route's credential file is not text") from None
    if not lines or any(_ENV_NAME.fullmatch(line.partition("=")[0]) is None or "=" not in line for line in lines):
        raise _Refusal("credential_unavailable", "the route's credential file is not NAME=value lines")

    def install_env(home: Path) -> None:
        _write_private(home / ".stateport" / "credential.env", ("\n".join(lines) + "\n").encode("utf-8"))

    return install_env, True


def _seed_opencode_config(home: Path) -> None:
    """Stop 1.18.31's background ``npm install @opencode-ai/plugin`` into its config dir.

    Measured: ``--pure`` / ``OPENCODE_PURE`` do not stop it; its
    ``Npm.install`` returns early when ``node_modules`` exists and
    ``package-lock.json`` already lists every wanted dependency. External
    plugins are disabled, so nothing ever imports that package. The
    attempt would only be denied by the proxy anyway; this removes the
    request and the warning.
    """
    config = home / ".config" / "opencode"
    (config / "node_modules").mkdir(parents=True, mode=0o700)
    dependency = {"@opencode-ai/plugin": PINNED_OPENCODE_VERSION}
    _write_private(config / "package.json", json.dumps({"dependencies": dependency}).encode())
    _write_private(config / "package-lock.json", json.dumps({
        "name": "opencode-config", "lockfileVersion": 3, "requires": True,
        "packages": {"": {"dependencies": dependency}},
    }).encode())


def _permission(tools: str, never: str) -> str:
    if tools == "none":
        rules: dict[str, Any] = {
            "*": "deny",
            "bash": {"*": "deny", never: "allow"},
            "read": {"*": "deny", never: "allow"},
        }
    else:
        rules = {
            "*": "deny",
            "read": "allow", "edit": "allow", "glob": "allow", "grep": "allow",
            "list": "allow", "bash": "allow",
            "webfetch": "deny", "websearch": "deny", "external_directory": "deny",
        }
    return json.dumps(rules, separators=(",", ":"))


# Shared, refreshed model catalogue (see module docstring).
_catalogue_lock = threading.Lock()
_catalogue_state: dict[str, float] = {"failedAt": 0.0}


def _catalogue_path() -> Path:
    return _private_dir(_runtime_root() / "catalogue") / "opencode-models.json"


def _catalogue_age(path: Path) -> float | None:
    try:
        return max(time.time() - path.stat().st_mtime, 0.0)
    except OSError:
        return None


_CATALOGUE_URL = "https://models.opencode.ai/api.json"


def _fetch_catalogue() -> bytes | None:
    """GET the exact catalogue URL opencode 1.18.31 uses (``$OPENCODE_MODELS_URL/api.json``).

    Measured on 1.18.31: with no cache file the harness answers from its
    embedded snapshot and refreshes in the background, so a cold per-run HOME
    races (and ``opencode models`` exits before the refresh writes). The web
    service therefore fetches the catalogue itself, data only, no prompt or
    credential, and seeds every run with it.
    """
    import urllib.request

    request = urllib.request.Request(_CATALOGUE_URL, headers={"User-Agent": "stateport-sandbox/1"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310 - fixed https URL
            if response.status != 200:
                return None
            data = response.read(_MAX_CATALOGUE_BYTES + 1)
    except (OSError, ValueError):
        return None
    if not data or len(data) > _MAX_CATALOGUE_BYTES:
        return None
    try:
        value = json.loads(data)
    except ValueError:
        return None
    return data if isinstance(value, dict) and value else None


def _refresh_catalogue(target: Path) -> bool:
    data = _fetch_catalogue()
    if data is None:
        return False
    temporary = target.with_name(f".{target.name}.{secrets.token_hex(6)}")
    _write_private(temporary, data)
    os.replace(temporary, target)
    return True


# Tests replace this to avoid the network; production keeps the real fetch.
_catalogue_fetcher: Callable[[Path], bool] = _refresh_catalogue


def _catalogue_seed(route: SandboxRoute) -> bytes | None:
    path = _catalogue_path()
    age = _catalogue_age(path)
    if age is None or age > _CATALOGUE_TTL_SECONDS:
        allowed = any(_host_allowed(host, route.allow_hosts) for host in OPENCODE_CATALOGUE_HOSTS)
        if allowed and _catalogue_lock.acquire(timeout=60.0):
            try:
                age = _catalogue_age(path)
                retry_due = time.monotonic() - _catalogue_state["failedAt"] > _CATALOGUE_RETRY_SECONDS
                if (age is None or age > _CATALOGUE_TTL_SECONDS) and retry_due:
                    if not _catalogue_fetcher(path):
                        _catalogue_state["failedAt"] = time.monotonic()
                age = _catalogue_age(path)
            finally:
                _catalogue_lock.release()
    if age is None or age > _CATALOGUE_MAX_AGE_SECONDS:
        return None
    try:
        data = path.read_bytes()
    except OSError:
        return None
    return data if 0 < len(data) <= _MAX_CATALOGUE_BYTES else None


def _decode_events(stdout: str) -> tuple[dict[str, Any], ...]:
    events: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict):
            events.append(value)
            if len(events) >= 20_000:
                break
    return tuple(events)


def _text_of(event: dict[str, Any]) -> str | None:
    part = event.get("part")
    if event.get("type") == "text" and isinstance(part, dict) and part.get("type") == "text":
        text = part.get("text")
        if isinstance(text, str) and text.strip():
            return text
    return None


def _error_of(event: dict[str, Any]) -> str | None:
    if event.get("type") != "error":
        return None
    error = event.get("error")
    if isinstance(error, dict):
        name = error.get("name") if isinstance(error.get("name"), str) else "Error"
        data = error.get("data")
        message = data.get("message") if isinstance(data, dict) else error.get("message")
        return f"{name}: {message}" if isinstance(message, str) and message else name
    if isinstance(error, str):
        return error
    return "error"


def _tokens(events: Sequence[dict[str, Any]]) -> dict[str, int]:
    totals: dict[str, int] = {}
    for event in events:
        part = event.get("part")
        if event.get("type") != "step_finish" or not isinstance(part, dict):
            continue
        tokens = part.get("tokens")
        if not isinstance(tokens, dict):
            continue
        cache = tokens.get("cache") if isinstance(tokens.get("cache"), dict) else {}
        for key, value in (
            ("input", tokens.get("input")), ("output", tokens.get("output")),
            ("reasoning", tokens.get("reasoning")), ("total", tokens.get("total")),
            ("cache_read", cache.get("read")), ("cache_write", cache.get("write")),
        ):
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                totals[key] = totals.get(key, 0) + value
    return totals


def _refused(code: str, reason: str, started: float, digest: str = "") -> SandboxResult:
    return SandboxResult(
        status="refused", refusal=code, exit_code=None,
        duration_seconds=round(time.monotonic() - started, 3),
        final_text=_bounded(reason, 1024), events=0, tokens={}, egress=(), sandbox_digest=digest,
    )


_LOG_ERROR = re.compile(r'\berror="((?:[^"\\]|\\.)*)"')


def _log_error(stderr: str) -> str | None:
    """The cause from the harness's last ERROR log line (``--print-logs --log-level ERROR``).

    The JSON error event often only says "Unexpected server error" while the
    log line names the real cause ("Model not found: ...").
    """
    for line in reversed(stderr.splitlines()):
        if "level=ERROR" not in line:
            continue
        match = _LOG_ERROR.search(line)
        if match:
            return match.group(1).replace('\\"', '"').replace("\\n", " ").strip() or None
    return None


def _harness_status(process: Any, events: Sequence[dict[str, Any]], output_limit: int) -> tuple[str, str]:
    last_text_index = max((index for index, event in enumerate(events) if _text_of(event)), default=-1)
    last_error_index = max((index for index, event in enumerate(events) if _error_of(event)), default=-1)
    final = _text_of(events[last_text_index]) if last_text_index >= 0 else ""
    event_error = _error_of(events[last_error_index]) if last_error_index >= 0 else None
    log_error = _log_error(process.stderr or "")
    causes = [item for item in (event_error, log_error) if item]
    error = " | ".join(dict.fromkeys(causes)) if causes else None
    stderr_lines = [line.strip() for line in (process.stderr or "").splitlines() if line.strip()]
    stderr_hint = next(
        (line for line in reversed(stderr_lines) if "error" in line.lower() or line.startswith("bwrap:")),
        stderr_lines[-1] if stderr_lines else "",
    )
    if process.timed_out:
        return "timeout", final or "the harness exceeded its wall-clock limit and its process tree was killed"
    if process.cancelled:
        return "failed", "cancelled"
    if process.output_limited:
        return "failed", f"output_limit_exceeded: the harness wrote more than {output_limit} bytes"
    if process.returncode != 0:
        detail = error or stderr_hint or f"the harness exited with code {process.returncode}"
        return "failed", _redact(_bounded(detail, 2048))
    if event_error is not None and last_error_index > last_text_index:
        return "failed", _redact(_bounded(error or event_error, 2048))
    return "completed", final


def run_harness_in_sandbox(
    *,
    workdir: Path,
    prompt: str,
    route: SandboxRoute,
    timeout_seconds: int | float = 300,
    output_limit_bytes: int = 1 << 20,
    cancel_event: Any | None = None,
    on_started: Callable[[Any], None] | None = None,
    on_finished: Callable[[Any], None] | None = None,
    process_generation: str | None = None,
    diagnostic_logs: bool = True,
    _resolver: Callable[[str, int], list[tuple[int, tuple[Any, ...]]]] | None = None,
) -> SandboxRun:
    """``run_in_sandbox`` plus cancellation, process-identity callbacks and the event stream.

    The chat path uses this so durable cancellation and restart
    reconciliation keep working; ``run_in_sandbox`` is exactly this with the
    defaults and returns only ``.result``.
    """
    started = time.monotonic()
    try:
        _validate_route(route)
        if not isinstance(prompt, str) or not prompt.strip():
            raise _Refusal("route_invalid", "prompt is empty")
        if len(prompt.encode("utf-8")) > _MAX_PROMPT_BYTES or "\x00" in prompt:
            raise _Refusal("route_invalid", "prompt exceeds the argument bound or contains NUL")
        if not 1 <= float(timeout_seconds) <= 3600:
            raise _Refusal("route_invalid", "timeout_seconds must be between 1 and 3600")
        if not 4096 <= int(output_limit_bytes) <= 64 * 1024 * 1024:
            raise _Refusal("route_invalid", "output_limit_bytes must be between 4 KiB and 64 MiB")
        bwrap = _available_bwrap()
        interpreter = _interpreter()
        harness = _verified_harness(route.harness_binary)
        real_workdir = _validated_workdir(workdir)
        installers: list[Callable[[Path], None]] = [_seed_opencode_config]
        uses_env_file = False
        if route.credential_file is not None:
            installer, uses_env_file = _credential_setup(route.credential_file, route.model)
            installers.append(installer)
        with _RunSlot():
            seed = _catalogue_seed(route)
            if seed is not None:
                # A fresh mtime also stops the harness's own background
                # refetch (it skips when the cache is younger than 5 minutes).
                installers.append(lambda home: _write_private(home / ".cache" / "opencode" / "models.json", seed))
            never = "\x00stateport-never-" + secrets.token_hex(16)
            env = _base_env(home=_HOME)
            env.update(_OPENCODE_ENV)
            env.update(_proxy_env())
            env["OPENCODE_PERMISSION"] = _permission(route.tools, never)
            harness_argv = [
                _HARNESS_INSIDE, "run", "--format", "json", "--pure", "--title", "stateport",
                "--model", route.model, "--dir", _WORK,
            ]
            if diagnostic_logs:
                harness_argv += ["--print-logs", "--log-level", "ERROR"]
            message = prompt if not prompt.startswith("-") else " " + prompt
            harness_argv.append(message)

            def prepare_home(home: Path) -> None:
                for install in installers:
                    install(home)

            execution = _execute(
                bwrap=bwrap, interpreter=interpreter, workdir=real_workdir, workdir_writable=True,
                command=harness_argv, env=env, network_hosts=tuple(route.allow_hosts),
                forwarder_flags=("--env-file", _ENV_FILE_INSIDE) if uses_env_file else (),
                home_setup=prepare_home,
                extra_ro=((harness, _HARNESS_INSIDE),), timeout=float(timeout_seconds),
                output_limit=int(output_limit_bytes), cancel_event=cancel_event,
                on_started=on_started, on_finished=on_finished, process_generation=process_generation,
                placeholders=(
                    (harness, "{harness}"), (message, "{prompt}"), (route.model, "{model}"),
                    (json.dumps(never)[1:-1], "{never}"),
                ),
                resolver=_resolver,
            )
    except _Refusal as refusal:
        return SandboxRun(_refused(refusal.code, refusal.reason, started), None, ())
    process = execution.process
    events = _decode_events(process.stdout or "")
    status, text = _harness_status(process, events, int(output_limit_bytes))
    result = SandboxResult(
        status=status,
        refusal=None,
        exit_code=process.returncode,
        duration_seconds=round(time.monotonic() - started, 3),
        final_text=_bounded(text, FINAL_TEXT_LIMIT_BYTES),
        events=len(events),
        tokens=_tokens(events),
        egress=tuple(
            {key: entry.get(key) for key in ("host", "port", "allowed", "bytes_up", "bytes_down", "reason")}
            for entry in execution.egress
        ),
        sandbox_digest=execution.digest,
    )
    return SandboxRun(result, process, events)


def run_in_sandbox(*, workdir: Path, prompt: str, route: SandboxRoute, timeout_seconds: int = 300,
                   output_limit_bytes: int = 1 << 20) -> SandboxResult:
    """Run the route's harness on ``workdir`` (seen as ``/work``) with allowlisted egress."""
    return run_harness_in_sandbox(
        workdir=workdir, prompt=prompt, route=route, timeout_seconds=timeout_seconds,
        output_limit_bytes=output_limit_bytes,
    ).result


# --------------------------------------------------------------------------- template checks


def run_check_in_sandbox(*, workdir: Path, argv: Sequence[str], timeout_seconds: int | float,
                         output_limit_bytes: int, writable: bool = False) -> SandboxResult:
    """Run a template's check command on a read-only ``/work`` with no network at all.

    ``writable=True`` binds ``/work`` read-write, for an imported application's propose-only
    script that writes its candidate into the staged copy StatePort created; the network stays
    absent either way, and StatePort, not the script, turns the changes into a proposal.

    ``status`` is ``completed`` whenever the command ran and exited (its exit
    code is the verdict input), ``timeout`` when it hit the wall clock (the
    whole tree is killed), ``failed`` when the sandbox could not start the
    command or the output cap was hit, ``refused`` before any process.
    ``final_text`` is the bounded tail of stdout, followed by the stderr tail
    when the exit code is non-zero. ``python3`` resolves to the service's own
    interpreter inside the sandbox.
    """
    started = time.monotonic()
    try:
        if isinstance(argv, (str, bytes)) or not isinstance(argv, Sequence) or not 1 <= len(argv) <= 256:
            raise _Refusal("route_invalid", "argv must be a list of 1-256 strings")
        if any(not isinstance(item, str) or not item or "\x00" in item or len(item) > 32768 for item in argv):
            raise _Refusal("route_invalid", "argv items must be non-empty strings without NUL")
        if sum(len(item) for item in argv) > _MAX_PROMPT_BYTES:
            raise _Refusal("route_invalid", "argv exceeds the argument bound")
        if not 1 <= float(timeout_seconds) <= 3600:
            raise _Refusal("route_invalid", "timeout_seconds must be between 1 and 3600")
        if not 1024 <= int(output_limit_bytes) <= 64 * 1024 * 1024:
            raise _Refusal("route_invalid", "output_limit_bytes must be between 1 KiB and 64 MiB")
        bwrap = _available_bwrap()
        interpreter = _interpreter()
        real_workdir = _validated_workdir(workdir)
        with _RunSlot():
            execution = _execute(
                bwrap=bwrap, interpreter=interpreter, workdir=real_workdir, workdir_writable=bool(writable),
                command=list(argv), env=_base_env(home=None), network_hosts=None, home_setup=None,
                extra_ro=(), timeout=float(timeout_seconds), output_limit=int(output_limit_bytes),
            )
    except _Refusal as refusal:
        return _refused(refusal.code, refusal.reason, started)
    process = execution.process
    stdout = process.stdout or ""
    stderr = process.stderr or ""
    if process.timed_out:
        status = "timeout"
    elif process.cancelled or process.output_limited:
        status = "failed"
    elif process.returncode != 0 and stderr.startswith("bwrap:"):
        status = "failed"
    else:
        status = "completed"
    text = _bounded(stdout, FINAL_TEXT_LIMIT_BYTES, tail=True)
    if process.returncode not in (0, None) and stderr.strip():
        room = FINAL_TEXT_LIMIT_BYTES - len(text.encode("utf-8")) - 16
        if room > 64:
            text = (text + ("\n" if text and not text.endswith("\n") else "")
                    + "[stderr]\n" + _bounded(stderr, room, tail=True))
    if process.output_limited:
        text = _bounded(f"output_limit_exceeded: more than {output_limit_bytes} bytes\n" + text,
                        FINAL_TEXT_LIMIT_BYTES)
    events = sum(1 for line in stdout.splitlines() if line.strip().startswith("{") and _is_json_object(line))
    return SandboxResult(
        status=status, refusal=None, exit_code=process.returncode,
        duration_seconds=round(time.monotonic() - started, 3), final_text=text, events=events,
        tokens={}, egress=(), sandbox_digest=execution.digest, stdout=stdout,
    )


def _is_json_object(line: str) -> bool:
    try:
        return isinstance(json.loads(line), dict)
    except ValueError:
        return False


# --------------------------------------------------------------------------- self-test


SELFTEST_FORMAT = "stateport.sandbox-selftest/v1"
_SELFTEST_ALLOW = ("selftest.stateport.invalid",)
_SELFTEST_DENIED_HOST = "example.com"
_selftest_lock = threading.Lock()
_selftest_cache: dict[str, Any] = {"at": 0.0, "key": None, "value": None}


def _check(identifier: str, passed: bool, detail: str) -> dict[str, Any]:
    return {"id": identifier, "passed": bool(passed), "detail": _bounded(detail, 600)}


def selftest(*, control_port: int | None = None, outside_paths: Sequence[str] = ()) -> dict[str, Any]:
    """Prove the boundary from inside the same sandbox shape agent work uses.

    (a) direct TCP to the control plane's loopback port (and to a canary
    listener this process opens) fails; (b) a CONNECT to a non-allowlisted host
    and to an IP literal is refused by the proxy; (c) paths outside ``/work``
    (a canary file, StatePort's state roots) cannot be read; (d) ``/proc``
    shows only the sandbox's own processes. Also: no StatePort or secret-like
    environment variable is visible and the system tree is read-only.
    """
    started = time.monotonic()
    measured_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    available, reason = sandbox_available()
    report: dict[str, Any] = {
        "formatVersion": SELFTEST_FORMAT, "measuredAt": measured_at, "available": available,
        "reason": reason, "ok": False, "checks": [], "egress": [], "sandboxDigest": "",
        "bwrapVersion": getattr(_probe_state.get("bwrap"), "version", None),
    }
    if not available:
        report["durationSeconds"] = round(time.monotonic() - started, 3)
        return report
    try:
        scratch = Path(tempfile.mkdtemp(prefix="selftest-", dir=_runtime_root()))
    except _Refusal as refusal:
        report.update(available=False, reason=refusal.reason)
        return report
    # A loopback listener in this (the control plane's) network namespace: the
    # sandbox must not reach it, exactly like the control API port.
    canary_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    canary_listener.bind(("127.0.0.1", 0))
    canary_listener.listen(4)
    canary_port = canary_listener.getsockname()[1]
    try:
        workdir = scratch / "work"
        workdir.mkdir(mode=0o700)
        canary = scratch / "outside-canary.txt"
        canary.write_text("stateport selftest canary\n", encoding="utf-8")
        candidates = [str(canary), *outside_paths, "/var/lib/stateport", "/var/lib/stateport-provider"]
        for variable, suffix in (("XDG_STATE_HOME", "stateport"), ("XDG_CONFIG_HOME", "stateport"),
                                 ("STATEPORT_OPENCODE_HOME", "")):
            value = os.environ.get(variable, "").strip()
            if value and os.path.isabs(value):
                candidates.append(os.path.join(value, suffix) if suffix else value)
        socket_path = os.environ.get("STATEPORT_EXECUTION_SOCKET", "").strip()
        if socket_path and os.path.isabs(socket_path):
            candidates.append(socket_path)
        # Host paths the sandbox deliberately shares (read-only system tree);
        # /tmp, /proc and HOME inside are the sandbox's own, not the host's.
        interpreter = _interpreter()
        visible_roots = ("/usr", "/etc/ssl", "/etc/ca-certificates", "/etc/pki", "/proc", "/dev",
                         *([interpreter.bind] if interpreter.bind else []))
        outside: list[str] = []
        for candidate in candidates:
            real = os.path.realpath(candidate)
            if os.path.exists(real) and not any(_under(real, item) for item in visible_roots) \
                    and real not in outside:
                outside.append(real)
        ports = [canary_port] + ([int(control_port)] if control_port else [])
        spec = json.dumps({
            "loopbackPorts": ports, "outsidePaths": outside, "proxyPort": _PROXY_PORT,
            "deniedHost": _SELFTEST_DENIED_HOST, "allowedHost": _SELFTEST_ALLOW[0],
        }, separators=(",", ":"))
        bwrap = _available_bwrap()
        env = _base_env(home=_HOME)
        env.update(_proxy_env())
        with _RunSlot():
            execution = _execute(
                bwrap=bwrap, interpreter=interpreter, workdir=workdir, workdir_writable=True,
                command=[interpreter.executable, "-I", "-B", _PROBE_INSIDE, spec], env=env,
                network_hosts=_SELFTEST_ALLOW, home_setup=lambda _home: None,
                extra_ro=((str(_PROBE_SOURCE), _PROBE_INSIDE),), timeout=60, output_limit=1 << 20,
                placeholders=((spec, "{probe_spec}"),),
            )
    except _Refusal as refusal:
        report.update(available=False, reason=refusal.reason,
                      durationSeconds=round(time.monotonic() - started, 3))
        return report
    finally:
        canary_listener.close()
        _remove_tree(scratch)
    process = execution.process
    report["sandboxDigest"] = execution.digest
    report["egress"] = list(execution.egress)
    try:
        observed = json.loads((process.stdout or "").strip().splitlines()[-1])
    except (ValueError, IndexError):
        report["checks"] = [_check("probe_ran", False, _bounded((process.stderr or "no output").strip(), 400))]
        report["durationSeconds"] = round(time.monotonic() - started, 3)
        return report
    loopback = observed.get("loopback", {})
    checks = [
        _check("control_plane_loopback_unreachable",
               bool(loopback) and all(str(value).startswith("refused") for value in loopback.values()),
               "; ".join(f"127.0.0.1:{port} {value}" for port, value in loopback.items())),
        _check("direct_egress_blocked", str(observed.get("directInternet", "")).startswith("refused"),
               f"1.1.1.1:443 {observed.get('directInternet')}"),
        _check("proxy_refuses_unlisted_host",
               " 403 " in f" {observed.get('proxyDenied', '')} "
               and any(entry.get("host") == _SELFTEST_DENIED_HOST and entry.get("allowed") is False
                       for entry in execution.egress),
               f"CONNECT {_SELFTEST_DENIED_HOST}:443 -> {observed.get('proxyDenied')}"),
        _check("proxy_refuses_ip_literal", " 403 " in f" {observed.get('proxyLoopbackLiteral', '')} ",
               f"CONNECT 127.0.0.1:443 -> {observed.get('proxyLoopbackLiteral')}"),
        # A tunnel to an allowlisted name that then speaks TLS to another name (a CDN shares its addresses)
        # is closed before any upstream connection; the matching name gets as far as name resolution.
        _check("proxy_refuses_mismatched_tls_name",
               any(entry.get("host") == _SELFTEST_ALLOW[0] and entry.get("reason") == "sni_mismatch"
                   and entry.get("sni") == _SELFTEST_DENIED_HOST and entry.get("allowed") is False
                   for entry in execution.egress),
               f"CONNECT {_SELFTEST_ALLOW[0]}:443 then TLS for {_SELFTEST_DENIED_HOST} -> "
               f"{observed.get('proxySniMismatch')}"),
        _check("proxy_passes_matching_tls_name",
               any(entry.get("host") == _SELFTEST_ALLOW[0] and entry.get("reason") == "dns_failed"
                   for entry in execution.egress),
               f"CONNECT {_SELFTEST_ALLOW[0]}:443 then TLS for the same name -> {observed.get('proxySniMatch')}"),
    ]
    paths = observed.get("outsidePaths", {})
    checks.append(_check(
        "outside_paths_unreadable",
        bool(paths) and all(str(value).startswith("refused") for value in paths.values()),
        "; ".join(f"{path}: {value}" for path, value in paths.items()),
    ))
    processes = observed.get("processes", [])
    allowed_names = {"bwrap", os.path.basename(interpreter.executable), "python3"}
    checks.append(_check(
        "proc_shows_only_sandbox_processes",
        0 < len(processes) <= 4 and all(item.get("argv0") in allowed_names for item in processes),
        f"{len(processes)} processes: " + ", ".join(f"{item.get('pid')}={item.get('argv0')}" for item in processes),
    ))
    names = observed.get("environmentNames", [])
    leaked = [name for name in names if name.startswith("STATEPORT_")
              or re.search(r"KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|COOKIE", name)]
    checks.append(_check("environment_scrubbed", not leaked,
                         "no StatePort or secret-like variables" if not leaked else "visible: " + ", ".join(leaked)))
    checks.append(_check(
        "system_tree_read_only",
        str(observed.get("rootWrite", "")).startswith("refused") and observed.get("workWrite") == "written",
        f"/etc write {observed.get('rootWrite')}; /work write {observed.get('workWrite')}",
    ))
    report["checks"] = checks
    report["ok"] = all(item["passed"] for item in checks)
    report["durationSeconds"] = round(time.monotonic() - started, 3)
    return report


def cached_selftest(*, control_port: int | None = None, max_age_seconds: float = 60.0) -> dict[str, Any]:
    """``selftest`` for the read-only HTTP route: one run at a time, reused briefly."""
    key = int(control_port) if control_port else None
    with _selftest_lock:
        cached = _selftest_cache["value"]
        if (cached is not None and _selftest_cache["key"] == key
                and time.monotonic() - _selftest_cache["at"] < max_age_seconds):
            return dict(cached)
        value = selftest(control_port=key)
        _selftest_cache.update(at=time.monotonic(), key=key, value=value)
        return dict(value)


__all__ = [
    "OPENCODE_BINARY_ENV",
    "OPENCODE_CATALOGUE_HOSTS",
    "OPENCODE_FREE_ROUTE_HOSTS",
    "PINNED_OPENCODE_VERSION",
    "RUNTIME_DIR_ENV",
    "SandboxResult",
    "SandboxRoute",
    "SandboxRun",
    "cached_selftest",
    "resolve_harness_binary",
    "run_check_in_sandbox",
    "run_harness_in_sandbox",
    "run_in_sandbox",
    "sandbox_available",
    "selftest",
]
