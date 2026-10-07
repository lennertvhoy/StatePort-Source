"""Execution-host-backed persistent workspace commands for the admin CLI.

The governed-runner ``workspace`` command owns the local Git worktree
lifecycle; this module exposes the separate execution-host-backed surface
(create, list, observe, attach, and typed exec inside a sealed workspace
workload) under the top-level ``exec-workspace`` command so the two never
collide.

Every command speaks the confined execution-host daemon through
``ExecutionHostClient``.  Terminal sessions are full-duplex PTY relays with
raw mode, SIGWINCH propagation, and byte-transparent Ctrl-C; ``exec`` is a
typed argv operation (never shell-joined) whose process exit status is the
command's own exit status.  Socket paths, container identifiers, and host
paths are redacted from every printed receipt.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import sys
import termios
import tty
import uuid
from typing import Any, Mapping

from execution_host.client import (
    ExecutionHostClient,
    ExecutionHostRefusal,
    ExecutionHostTransportError,
)
from execution_host.workspaces import WorkspaceRuntime, WorkspaceRuntimeError


_WORKSPACE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SENSITIVE_KEY = re.compile(
    r"(socketpath|containerid|hostpath|socket|container|credential|secret|password|token|apikey|access_?key|hostmounts|executorpid)",
    re.I,
)
MAX_EXEC_TIMEOUT_SECONDS = 600
_MAX_RELAY_BUFFER_BYTES = 1_048_576
_RELAY_CHUNK_BYTES = 65_536
_TERMINAL_CONNECT_TIMEOUT_SECONDS = 5


__all__ = [
    "register_exec_workspace_parser",
    "create_cmd",
    "list_cmd",
    "status_cmd",
    "shell_cmd",
    "exec_cmd",
]


def _emit_error(code: str, detail: str) -> int:
    payload = {"ok": False, "code": code, "detail": detail}
    print(json.dumps(payload, sort_keys=True), file=sys.stderr)
    return 2


def _emit_ok(result: Mapping[str, Any]) -> int:
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _require_credentials(args: Any) -> int | None:
    if not getattr(args, "execution_host_socket", None):
        return _emit_error(
            "execution_host_socket_required",
            "the confined execution-host socket path is required "
            "(STATEPORT_EXECUTION_SOCKET or --execution-host-socket)",
        )
    if not getattr(args, "authority_grant_digest", None):
        return _emit_error(
            "authority_grant_required",
            "an authority grant digest binding this session is required",
        )
    return None


def _validate_workspace_id(workspace_id: Any) -> int | None:
    if not isinstance(workspace_id, str) or _WORKSPACE_ID.fullmatch(workspace_id) is None:
        return _emit_error(
            "invalid_workspace_id",
            "workspace id must match the daemon identifier grammar",
        )
    return None


def _client_from_args(args: Any) -> ExecutionHostClient:
    return ExecutionHostClient(
        args.execution_host_socket,
        grant_id=args.grant_id,
        authority_grant_digest=args.authority_grant_digest,
        timeout_seconds=args.timeout_seconds,
        output_byte_bound=args.output_byte_bound,
    )


def _runtime_from_args(args: Any) -> WorkspaceRuntime:
    return WorkspaceRuntime(_client_from_args(args), image_reference=args.image_reference)


def _result_view(receipt: Mapping[str, Any]) -> Mapping[str, Any]:
    result = receipt.get("result")
    return result if isinstance(result, Mapping) else {}


def _observed_view(receipt: Mapping[str, Any]) -> Mapping[str, Any]:
    observed = receipt.get("observed")
    return observed if isinstance(observed, Mapping) else {}


def _redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _redact(item) for key, item in value.items() if not _SENSITIVE_KEY.search(str(key))}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _map_refusal(exc: ExecutionHostRefusal, *, running_reason: bool = False) -> int:
    if "unknown" in exc.reason:
        code = "unknown_workspace"
    elif running_reason and exc.reason == "workspace-not-running":
        code = "workspace_not_running"
    else:
        code = "execution_host_refusal"
    return _emit_error(code, f"execution host refused: {exc.reason}")


def _unreachable() -> int:
    return _emit_error(
        "execution_host_unreachable",
        "execution-host socket is absent or refused; the daemon is not reachable",
    )


# ------------------------------------------------------------------ commands


def create_cmd(args: Any) -> int:
    """Create one persistent workspace from a canonical WorkspaceSpec document."""

    bad = _require_credentials(args)
    if bad is not None:
        return bad
    try:
        document = json.loads(Path(args.workspace_spec).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return _emit_error("invalid_workspace_spec", f"workspace spec is unreadable: {exc}")
    runtime = _runtime_from_args(args)
    try:
        receipt = runtime.create(document, base_revision=args.base_revision)
    except WorkspaceRuntimeError as exc:
        return _emit_error("invalid_workspace_spec", str(exc))
    except ExecutionHostTransportError:
        return _unreachable()
    except ExecutionHostRefusal as exc:
        return _map_refusal(exc)
    return _emit_ok(_redact({"ok": True, "result": _result_view(receipt)}))


def list_cmd(args: Any) -> int:
    """Enumerate workspaces from real daemon state (grant-scoped)."""

    bad = _require_credentials(args)
    if bad is not None:
        return bad
    client = _client_from_args(args)
    try:
        receipt = client.list_workloads()
    except ExecutionHostTransportError:
        return _unreachable()
    except ExecutionHostRefusal as exc:
        return _map_refusal(exc)
    workloads = [
        {
            "workspaceId": item["workloadId"],
            "kind": item["kind"],
            "state": item["state"],
            "engineStatus": item["engineStatus"],
            "running": item["running"],
            "imageDigest": item.get("imageDigest"),
            "createdAt": item.get("createdAt"),
            "lastActivityAt": item.get("lastActivityAt"),
        }
        for item in _result_view(receipt).get("workloads", [])
    ]
    return _emit_ok({"ok": True, "workloads": _redact(workloads)})


def status_cmd(args: Any) -> int:
    """Print a redacted status receipt for one execution-host workspace."""

    bad = _require_credentials(args)
    if bad is not None:
        return bad
    bad = _validate_workspace_id(args.workspace_id)
    if bad is not None:
        return bad
    client = _client_from_args(args)
    try:
        receipt = client.status(args.workspace_id)
    except ExecutionHostTransportError:
        return _unreachable()
    except ExecutionHostRefusal as exc:
        return _map_refusal(exc)
    result = _result_view(receipt)
    observed = _observed_view(receipt)
    redacted = {
        "ok": True,
        "workspaceId": result.get("workloadId") or args.workspace_id,
        "state": result.get("state"),
        "exitStatus": result.get("exitStatus"),
        "engineStatus": result.get("engineStatus"),
        "imageDigest": observed.get("imageDigest"),
        "startedAt": observed.get("startedAt"),
        "finishedAt": observed.get("finishedAt"),
    }
    return _emit_ok(_redact(redacted))


def _lifecycle_cmd(args: Any, operation: str) -> int:
    bad = _require_credentials(args)
    if bad is not None:
        return bad
    bad = _validate_workspace_id(args.workspace_id)
    if bad is not None:
        return bad
    client = _client_from_args(args)
    try:
        receipt = getattr(client, operation)(args.workspace_id)
    except ExecutionHostTransportError:
        return _unreachable()
    except ExecutionHostRefusal as exc:
        return _map_refusal(exc)
    return _emit_ok(_redact({"ok": True, "result": _result_view(receipt)}))


def start_cmd(args: Any) -> int:
    """Start (or reattach) a persistent workspace."""
    return _lifecycle_cmd(args, "start")


def stop_cmd(args: Any) -> int:
    """Stop a workspace; its container and data volume are preserved."""
    return _lifecycle_cmd(args, "stop")


def remove_cmd(args: Any) -> int:
    """Remove the workspace container; the daemon-owned volume is preserved."""
    return _lifecycle_cmd(args, "remove_workload")


# --------------------------------------------------------------------- shell


def _session_socket_path(open_receipt: Mapping[str, Any]) -> str:
    result = open_receipt.get("result") if isinstance(open_receipt, Mapping) else None
    if isinstance(result, Mapping) and isinstance(result.get("socketPath"), str):
        return result["socketPath"]
    raise ExecutionHostTransportError("terminal session socket was not provided by the execution host")


def _connect_session(socket_path: str, timeout_seconds: int) -> socket.socket:
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or timeout_seconds <= 0
    ):
        raise ExecutionHostTransportError("terminal session timeout is invalid")
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        connection.settimeout(min(timeout_seconds, _TERMINAL_CONNECT_TIMEOUT_SECONDS))
        connection.connect(socket_path)
        connection.settimeout(None)
    except OSError as exc:
        connection.close()
        raise ExecutionHostTransportError("terminal session socket is not reachable") from exc
    return connection


def _run_interactive_shell(
    client: ExecutionHostClient,
    workspace_id: str,
    *,
    columns: int,
    rows: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    """Full-duplex PTY relay: raw mode, SIGWINCH propagation, transparent Ctrl-C.

    Every byte flows through the daemon-owned session socket; the CLI never
    touches the container engine.  In raw mode Ctrl-C is delivered as the
    literal byte and the container PTY line discipline raises SIGINT in the
    foreground process group.  There is no artificial session timeout: the
    relay ends on stdin EOF, session hangup, or workspace stop.
    """

    session_id = f"cli-session-{uuid.uuid4().hex[:12]}"
    connection: socket.socket | None = None
    stdin_fd: int | None = None
    stdout_fd: int | None = None
    saved_attributes: list[Any] | None = None
    saved_winch: Any = None
    saved_flags: dict[int, int] = {}
    open_attempted = False
    resize_pending = False

    def _propagate_size() -> None:
        if stdin_fd is None:
            return
        try:
            size = os.get_terminal_size(stdin_fd)
            if size.columns < 1 or size.lines < 1:
                return
            client.resize_terminal(session_id, columns=size.columns, rows=size.lines)
        except (OSError, ValueError, ExecutionHostRefusal, ExecutionHostTransportError):
            pass

    def _on_winch(_signum: int, _frame: Any) -> None:
        nonlocal resize_pending
        resize_pending = True

    try:
        open_attempted = True
        open_receipt = client.open_terminal(
            workspace_id, session_id, columns=columns, rows=rows
        )
        socket_path = _session_socket_path(open_receipt)
        connection = _connect_session(socket_path, timeout_seconds)
        stdin_fd = sys.stdin.fileno()
        stdout_fd = sys.stdout.fileno()
        is_tty = os.isatty(stdin_fd)
        saved_attributes = termios.tcgetattr(stdin_fd) if is_tty else None
        for descriptor in {stdin_fd, stdout_fd}:
            saved_flags[descriptor] = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        if is_tty:
            tty.setraw(stdin_fd)
            saved_winch = signal.signal(signal.SIGWINCH, _on_winch)
            resize_pending = True
        for descriptor, flags in saved_flags.items():
            fcntl.fcntl(descriptor, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        connection.setblocking(False)

        pending_input = bytearray()
        pending_output = bytearray()
        stdin_open = True
        socket_open = True
        write_shutdown = False
        while socket_open or pending_output:
            if resize_pending:
                resize_pending = False
                _propagate_size()

            read_targets: list[int | socket.socket] = []
            write_targets: list[int | socket.socket] = []
            if stdin_open and len(pending_input) < _MAX_RELAY_BUFFER_BYTES:
                read_targets.append(stdin_fd)
            if socket_open and len(pending_output) < _MAX_RELAY_BUFFER_BYTES:
                read_targets.append(connection)
            if socket_open and pending_input:
                write_targets.append(connection)
            if pending_output:
                write_targets.append(stdout_fd)
            if not read_targets and not write_targets:
                break

            try:
                readable, writable, _ = select.select(
                    read_targets, write_targets, [], 0.25
                )
            except InterruptedError:
                continue
            except (OSError, ValueError):
                break

            if stdin_fd in readable:
                try:
                    data = os.read(stdin_fd, _RELAY_CHUNK_BYTES)
                except BlockingIOError:
                    data = None
                except OSError:
                    data = b""
                if data is None:
                    pass
                elif data:
                    pending_input.extend(data)
                else:
                    stdin_open = False

            if connection in readable:
                try:
                    data = connection.recv(_RELAY_CHUNK_BYTES)
                except BlockingIOError:
                    data = None
                except OSError:
                    data = b""
                if data is None:
                    pass
                elif data:
                    pending_output.extend(data)
                else:
                    socket_open = False

            if connection in writable and pending_input:
                try:
                    written = connection.send(bytes(pending_input[:_RELAY_CHUNK_BYTES]))
                except BlockingIOError:
                    written = None
                except OSError:
                    written = 0
                if written is None:
                    pass
                elif written > 0:
                    del pending_input[:written]
                else:
                    socket_open = False

            if stdout_fd in writable and pending_output:
                try:
                    written = os.write(stdout_fd, bytes(pending_output[:_RELAY_CHUNK_BYTES]))
                except BlockingIOError:
                    written = None
                except OSError:
                    break
                if written is not None and written > 0:
                    del pending_output[:written]
                elif written == 0:
                    break

            if not stdin_open and not pending_input and socket_open and not write_shutdown:
                try:
                    connection.shutdown(socket.SHUT_WR)
                except OSError:
                    socket_open = False
                write_shutdown = True
            if not socket_open:
                pending_input.clear()
    finally:
        active_error = sys.exc_info()[0] is not None
        restoration_error: ExecutionHostTransportError | None = None
        for descriptor, flags in saved_flags.items():
            try:
                fcntl.fcntl(descriptor, fcntl.F_SETFL, flags)
            except OSError as exc:
                if restoration_error is None:
                    restoration_error = ExecutionHostTransportError(
                        f"terminal descriptor flags could not be restored: {exc}"
                    )
        if stdin_fd is not None and saved_attributes is not None:
            try:
                termios.tcsetattr(stdin_fd, termios.TCSANOW, saved_attributes)
            except OSError as exc:
                if restoration_error is None:
                    restoration_error = ExecutionHostTransportError(
                        f"terminal attributes could not be restored: {exc}"
                    )
        if saved_winch is not None:
            try:
                signal.signal(signal.SIGWINCH, saved_winch)
            except (OSError, ValueError) as exc:
                if restoration_error is None:
                    restoration_error = ExecutionHostTransportError(
                        f"SIGWINCH handler could not be restored: {exc}"
                    )
        if connection is not None:
            try:
                connection.close()
            except OSError:
                pass
        if open_attempted:
            try:
                client.close_terminal(session_id)
            except Exception:
                pass
        if restoration_error is not None and not active_error:
            raise restoration_error
    return {"sessionId": session_id}


def shell_cmd(args: Any) -> int:
    """Attach an interactive terminal to a running execution-host workspace."""

    bad = _require_credentials(args)
    if bad is not None:
        return bad
    bad = _validate_workspace_id(args.workspace_id)
    if bad is not None:
        return bad
    client = _client_from_args(args)
    try:
        session = _run_interactive_shell(
            client,
            args.workspace_id,
            columns=80,
            rows=24,
            timeout_seconds=args.timeout_seconds,
        )
    except ExecutionHostTransportError:
        return _unreachable()
    except ExecutionHostRefusal as exc:
        return _map_refusal(exc, running_reason=True)
    print(file=sys.stderr)
    return _emit_ok({"ok": True, "sessionId": session["sessionId"], "closed": True})


# ---------------------------------------------------------------------- exec


def exec_cmd(args: Any) -> int:
    """Run one typed argv inside a running workspace and mirror its exit status.

    Pass options before the workspace identifier and a ``--`` separator before
    the command argv, for example::

        exec-workspace exec --execution-host-socket X --authority-grant-digest D \
            workspace.demo -- echo hello

    The argv is sent to the daemon as a typed list and executed directly:
    tokens are never shell-joined, so shell metacharacters are literal argv
    text.  The CLI exit code is the command's own exit status; the declared
    per-operation timeout (default 600s, the daemon request bound) is the only
    time limit — output draining never cuts a live command off.
    """

    bad = _require_credentials(args)
    if bad is not None:
        return bad
    bad = _validate_workspace_id(args.workspace_id)
    if bad is not None:
        return bad
    command = list(getattr(args, "command", None) or [])
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        return _emit_error("invalid_command", "at least one command token is required")
    if any("\x00" in token for token in command):
        return _emit_error("invalid_command", "command tokens may not contain NUL bytes")
    client = _client_from_args(args)
    timeout = min(args.timeout_seconds, MAX_EXEC_TIMEOUT_SECONDS)
    try:
        receipt = client.exec_workload(args.workspace_id, command, timeout_seconds=timeout)
    except ExecutionHostTransportError:
        return _unreachable()
    except ExecutionHostRefusal as exc:
        return _map_refusal(exc, running_reason=True)
    result = _result_view(receipt)
    output = str(result.get("output", ""))
    sys.stdout.write(output)
    sys.stdout.flush()
    exit_status = result.get("exitStatus")
    if not isinstance(exit_status, int):
        return _emit_error("execution_host_contract", "the daemon did not report an exit status")
    metadata = {
        "ok": exit_status == 0,
        "exitStatus": exit_status,
        "byteCount": result.get("byteCount"),
        "truncated": result.get("truncated"),
        "outputDigest": "sha256:" + hashlib.sha256(output.encode("utf-8")).hexdigest(),
    }
    print(json.dumps(metadata, sort_keys=True), file=sys.stderr)
    return exit_status if 0 <= exit_status <= 255 else 1


# ------------------------------------------------------------------- parsers


def _add_common_options(parser: Any, *, image: bool = False) -> None:
    parser.add_argument(
        "--execution-host-socket",
        default=os.environ.get("STATEPORT_EXECUTION_SOCKET"),
        dest="execution_host_socket",
        help="path to the confined execution-host daemon socket "
        "(default: STATEPORT_EXECUTION_SOCKET)",
    )
    parser.add_argument(
        "--authority-grant-digest",
        required=True,
        dest="authority_grant_digest",
        help="sha256 digest binding the authority grant for this session",
    )
    parser.add_argument(
        "--grant-id",
        default="admin-cli.workspace",
        dest="grant_id",
        help="grant identifier presented to the daemon",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=MAX_EXEC_TIMEOUT_SECONDS,
        dest="timeout_seconds",
        help="per-operation timeout in seconds (daemon request bound: 600)",
    )
    parser.add_argument(
        "--output-byte-bound",
        type=int,
        default=1048576,
        dest="output_byte_bound",
        help="bounded output byte ceiling",
    )
    if image:
        parser.add_argument(
            "--image-reference",
            required=True,
            dest="image_reference",
            help="digest-pinned OCI reference matching the WorkspaceSpec imageDigest",
        )
        parser.add_argument(
            "--base-revision",
            default=None,
            dest="base_revision",
            help="optional exact base git sha recorded in the workspace record",
        )


def register_exec_workspace_parser(subparsers: Any) -> None:
    """Register the execution-host-backed ``exec-workspace`` CLI commands."""

    parser = subparsers.add_parser(
        "exec-workspace",
        help="Operate execution-host-backed persistent workspaces",
    )
    nested = parser.add_subparsers(dest="exec_workspace_command", required=True)

    create_parser = nested.add_parser(
        "create",
        help="create one persistent workspace from a WorkspaceSpec document",
    )
    create_parser.add_argument("workspace_spec", help="path to a stateport.workspace-spec/v1 JSON document")
    _add_common_options(create_parser, image=True)
    create_parser.set_defaults(func=create_cmd)

    list_parser = nested.add_parser(
        "list",
        help="enumerate workspaces from real daemon state (grant-scoped)",
    )
    _add_common_options(list_parser)
    list_parser.set_defaults(func=list_cmd)

    for name, handler, help_text in (
        ("status", status_cmd, "print a redacted status receipt for one workspace"),
        ("start", start_cmd, "start or reattach a persistent workspace"),
        ("stop", stop_cmd, "stop a workspace; container and volume are preserved"),
        ("remove", remove_cmd, "remove the workspace container; the volume is preserved"),
    ):
        sub = nested.add_parser(name, help=help_text)
        sub.add_argument("workspace_id", help="execution-host workspace identifier")
        _add_common_options(sub)
        sub.set_defaults(func=handler)

    shell_parser = nested.add_parser(
        "shell",
        help="attach an interactive terminal to a running workspace",
    )
    shell_parser.add_argument("workspace_id", help="execution-host workspace identifier")
    _add_common_options(shell_parser)
    shell_parser.set_defaults(func=shell_cmd)

    exec_parser = nested.add_parser(
        "exec",
        help="run one typed argv inside a running workspace",
    )
    exec_parser.add_argument("workspace_id", help="execution-host workspace identifier")
    exec_parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="typed command argv after a -- separator",
    )
    _add_common_options(exec_parser)
    exec_parser.set_defaults(func=exec_cmd)
