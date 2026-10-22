"""In-sandbox launcher and egress forwarder (runs INSIDE the agent sandbox only).

``agent_sandbox`` bind-mounts this file read-only into the bubblewrap sandbox
and runs it as the sandbox's first program::

    python3 -I -B forwarder.py --socket /run/stateport-egress/egress.sock \
        --listen 3128 [--env-file FILE] -- <harness argv...>

It listens on the sandbox's own loopback (the sandbox has its own network
namespace, so this is not the control plane's loopback), relays every
accepted TCP connection to the one bind-mounted UNIX socket behind which the
web service runs the allowlisting CONNECT proxy, then starts the harness as a
child with the proxy environment the sandbox already carries and exits with
the harness's exit status. Listening happens before the harness starts, so
there is no start-up race.

``--env-file`` names a file with ``NAME=value`` lines (an account route's
provider credential). The values are added to the harness environment and the
file is deleted before the harness starts, so the secret never appears in any
argv. Standard library only; this file never imports StatePort code.
"""

from __future__ import annotations

import os
import re
import selectors
import socket
import subprocess
import sys
import threading
from typing import NoReturn

_MAX_CONNECTIONS = 32
_IDLE_SECONDS = 300.0
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_MAX_ENV_FILE_BYTES = 65536


def _fail(message: str) -> NoReturn:
    sys.stderr.write(f"stateport-sandbox-forwarder: {message}\n")
    sys.stderr.flush()
    raise SystemExit(126)


def _relay(a: socket.socket, b: socket.socket) -> None:
    selector = selectors.DefaultSelector()
    try:
        selector.register(a, selectors.EVENT_READ, b)
        selector.register(b, selectors.EVENT_READ, a)
        open_sides = 2
        while open_sides:
            ready = selector.select(_IDLE_SECONDS)
            if not ready:
                return
            for key, _ in ready:
                source, target = key.fileobj, key.data
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
                try:
                    target.sendall(data)
                except OSError:
                    return
    finally:
        selector.close()
        for item in (a, b):
            try:
                item.close()
            except OSError:
                pass


def _serve(client: socket.socket, socket_path: str, slots: threading.BoundedSemaphore) -> None:
    upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        upstream.settimeout(10.0)
        upstream.connect(socket_path)
        upstream.settimeout(_IDLE_SECONDS)
        client.settimeout(_IDLE_SECONDS)
    except OSError:
        for item in (client, upstream):
            try:
                item.close()
            except OSError:
                pass
        slots.release()
        return
    try:
        _relay(client, upstream)
    finally:
        slots.release()


def _accept_loop(listener: socket.socket, socket_path: str) -> None:
    slots = threading.BoundedSemaphore(_MAX_CONNECTIONS)
    while True:
        try:
            client, _ = listener.accept()
        except OSError:
            return
        if not slots.acquire(blocking=False):
            client.close()
            continue
        threading.Thread(target=_serve, args=(client, socket_path, slots), daemon=True).start()


def _load_env_file(path: str) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        with open(path, "rb") as handle:
            raw = handle.read(_MAX_ENV_FILE_BYTES + 1)
    except OSError:
        _fail("credential environment file is unreadable")
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    if len(raw) > _MAX_ENV_FILE_BYTES:
        _fail("credential environment file is too large")
    for line in raw.decode("utf-8", errors="strict").splitlines():
        name, separator, value = line.partition("=")
        if not separator or _ENV_NAME.fullmatch(name) is None:
            _fail("credential environment file is malformed")
        values[name] = value
    return values


def main(argv: list[str]) -> int:
    socket_path = ""
    port = 0
    env_file = ""
    index = 0
    while index < len(argv) and argv[index] != "--":
        flag = argv[index]
        if index + 1 >= len(argv):
            _fail(f"flag {flag} needs a value")
        value = argv[index + 1]
        if flag == "--socket":
            socket_path = value
        elif flag == "--listen":
            port = int(value)
        elif flag == "--env-file":
            env_file = value
        else:
            _fail(f"unknown flag {flag}")
        index += 2
    command = argv[index + 1:]
    if not command:
        _fail("no command after --")
    environment = dict(os.environ)
    if env_file:
        environment.update(_load_env_file(env_file))
    if socket_path:
        if not 0 < port < 65536:
            _fail("listen port is invalid")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(64)
        threading.Thread(target=_accept_loop, args=(listener, socket_path), daemon=True).start()
    try:
        child = subprocess.Popen(command, env=environment, stdin=subprocess.DEVNULL)
    except OSError as exc:
        _fail(f"harness could not start: {exc.strerror or exc.__class__.__name__}")
    code = child.wait()
    return code if code >= 0 else 128 - code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
