#!/usr/bin/env python3
"""Launch the web Playwright suite with an owned loopback port and process group."""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
from pathlib import Path
from typing import Mapping, Sequence


MIN_PORT = 1024
MAX_PORT = 65535


def _parse_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise ValueError("STATEPORT_E2E_PORT must be an integer between 1024 and 65535") from exc
    if not MIN_PORT <= port <= MAX_PORT:
        raise ValueError("STATEPORT_E2E_PORT must be an integer between 1024 and 65535")
    return port


def _port_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def _lease_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])
    if not MIN_PORT <= port <= MAX_PORT:
        raise RuntimeError("operating system returned an invalid loopback port")
    return port


def _owned_environment(environment: Mapping[str, str]) -> dict[str, str]:
    port_value = environment.get("STATEPORT_E2E_PORT")
    port = _lease_port() if not port_value else _parse_port(port_value)
    if not _port_available(port):
        raise RuntimeError(
            f"STATEPORT_E2E_PORT {port} is occupied; refusing to reuse an existing server"
        )
    owned = dict(environment)
    owned["STATEPORT_E2E_PORT"] = str(port)
    owned["STATEPORT_E2E_BASE_URL"] = f"http://127.0.0.1:{port}"
    return owned


def _terminate_owned_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def run_playwright(
    arguments: Sequence[str],
    *,
    cwd: Path | None = None,
    environment: Mapping[str, str] | None = None,
    playwright_cli: Path | None = None,
) -> int:
    working_directory = (cwd or Path.cwd()).resolve()
    cli = playwright_cli or working_directory / "node_modules" / ".bin" / "playwright"
    if not cli.is_file():
        raise RuntimeError(f"Playwright CLI is unavailable: {cli}")
    owned_environment = _owned_environment(dict(os.environ if environment is None else environment))
    process = subprocess.Popen(
        [str(cli), "test", *arguments],
        cwd=working_directory,
        env=owned_environment,
        start_new_session=True,
    )
    try:
        return process.wait()
    except BaseException:
        _terminate_owned_group(process)
        raise


def main(arguments: Sequence[str] | None = None) -> int:
    try:
        return run_playwright(tuple(sys.argv[1:] if arguments is None else arguments))
    except (OSError, RuntimeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
