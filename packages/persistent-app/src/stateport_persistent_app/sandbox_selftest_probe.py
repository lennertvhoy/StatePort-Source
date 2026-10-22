"""Sandbox self-test probe (runs INSIDE the agent sandbox only).

``agent_sandbox.selftest`` runs this file in exactly the sandbox shape used for
agent work (network mode: own network namespace, in-sandbox forwarder, the
allowlisting proxy outside) and reads one JSON object from stdout. Every probe
is an attempt that must FAIL for the boundary to hold; the outside side decides
pass/fail. Standard library only; never imports StatePort code.

argv: <json spec> with keys loopbackPorts (list[int]), outsidePaths (list[str]),
proxyPort (int), deniedHost (str), allowedHost (str).
"""

from __future__ import annotations

import json
import os
import socket
import sys


def _connect(host: str, port: int) -> str:
    try:
        with socket.create_connection((host, port), timeout=3):
            return "connected"
    except OSError as exc:
        return f"refused: {exc.__class__.__name__}: {exc.strerror or exc}"


def _connect_via_proxy(proxy_port: int, target: str) -> str:
    try:
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=5) as conn:
            conn.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode("ascii"))
            conn.settimeout(10)
            data = b""
            while b"\r\n" not in data and len(data) < 4096:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            return data.split(b"\r\n", 1)[0].decode("latin-1") or "closed"
    except OSError as exc:
        return f"error: {exc.__class__.__name__}"


def _tls_via_proxy(proxy_port: int, target: str, server_name: str) -> str:
    """Open a tunnel to ``target`` and start TLS naming ``server_name``; the proxy decides on the name."""

    import ssl

    try:
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=5) as conn:
            conn.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode("ascii"))
            conn.settimeout(10)
            head = b""
            while b"\r\n\r\n" not in head and len(head) < 4096:
                chunk = conn.recv(4096)
                if not chunk:
                    return "closed before tunnel"
                head += chunk
            status = head.split(b"\r\n", 1)[0].decode("latin-1")
            if " 200 " not in f" {status} ":
                return status
            context = ssl.create_default_context()
            try:
                with context.wrap_socket(conn, server_hostname=server_name) as tls:
                    tls.do_handshake()
                    return "handshake completed"
            except (ssl.SSLError, OSError) as exc:
                return f"{status}; then closed: {exc.__class__.__name__}"
    except OSError as exc:
        return f"error: {exc.__class__.__name__}"


def _read(path: str) -> str:
    try:
        if os.path.isdir(path):
            os.listdir(path)
            return "listed"
        with open(path, "rb") as handle:
            handle.read(16)
        return "read"
    except OSError as exc:
        return f"refused: {exc.__class__.__name__}"


def _processes() -> list[dict[str, object]]:
    entries = []
    for name in sorted(os.listdir("/proc"), key=lambda item: (len(item), item)):
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/cmdline", "rb") as handle:
                argv = [part.decode("utf-8", "replace") for part in handle.read(4096).split(b"\0") if part]
        except OSError:
            argv = []
        entries.append({"pid": int(name), "argv0": os.path.basename(argv[0]) if argv else ""})
    return entries


def main() -> int:
    spec = json.loads(sys.argv[1])
    write_outside = "/etc/stateport-selftest-write"
    try:
        with open(write_outside, "w") as handle:
            handle.write("x")
        root_write = "written"
    except OSError as exc:
        root_write = f"refused: {exc.__class__.__name__}"
    try:
        with open("/work/.selftest-write", "w") as handle:
            handle.write("x")
        os.unlink("/work/.selftest-write")
        work_write = "written"
    except OSError as exc:
        work_write = f"refused: {exc.__class__.__name__}"
    result = {
        "loopback": {str(port): _connect("127.0.0.1", int(port)) for port in spec["loopbackPorts"]},
        "directInternet": _connect("1.1.1.1", 443),
        "proxyDenied": _connect_via_proxy(int(spec["proxyPort"]), f"{spec['deniedHost']}:443"),
        "proxyLoopbackLiteral": _connect_via_proxy(int(spec["proxyPort"]), "127.0.0.1:443"),
        "proxySniMismatch": _tls_via_proxy(int(spec["proxyPort"]), f"{spec['allowedHost']}:443", spec["deniedHost"]),
        "proxySniMatch": _tls_via_proxy(int(spec["proxyPort"]), f"{spec['allowedHost']}:443", spec["allowedHost"]),
        "outsidePaths": {path: _read(path) for path in spec["outsidePaths"]},
        "processes": _processes(),
        "environmentNames": sorted(os.environ),
        "rootWrite": root_write,
        "workWrite": work_write,
    }
    sys.stdout.write(json.dumps(result, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
