"""No-authentication probe payload executed inside a consuming runtime image.

The rehearsal controller sends this source to the exact verified container.
It creates only a private temporary tree and never opens provider credentials.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile


def probe(runtime: str = "web") -> dict:
    if runtime not in {"web", "workspace"}:
        raise ValueError("unsupported provider runtime")
    expected_uid = 65532 if runtime == "web" else 10001
    if os.getuid() != expected_uid or os.getgid() != expected_uid:
        raise RuntimeError("provider sandbox probe requires the signed service identity")
    # Keep the sibling outside target out of /tmp, which workspace-write permits.
    temporary_root = "/var/lib/stateport/data" if runtime == "web" else "/workspace"
    with tempfile.TemporaryDirectory(prefix=".sandbox-probe-", dir=temporary_root) as temporary:
        root = Path(temporary)
        workspace = root / "workspace"
        outside = root / "outside"
        home = root / "home"
        for path in (workspace, outside, home):
            path.mkdir(mode=0o700)
        (outside / "baseline").write_text("preserve\n")
        (workspace / "escape").symlink_to(outside, target_is_directory=True)
        env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(home), "CODEX_HOME": str(home),
            "TMPDIR": "/tmp", "LANG": "C.UTF-8",
        }
        version = subprocess.check_output(
            ["/usr/local/bin/codex", "--version"], env=env,
            stdin=subprocess.DEVNULL, text=True, timeout=45,
        ).strip()
        # This same UID can write the sibling before sandboxing. A denial
        # cannot be falsely credited to container read-only mounts or DAC.
        (outside / "writable-before").write_text("yes")
        (outside / "writable-before").unlink()
        # Socket creation must work in the parent so an outer container's
        # seccomp policy cannot masquerade as the provider's network denial.
        # No connection is made.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM):
            pass
        namespaces = {name: os.readlink("/proc/self/ns/" + name)
                      for name in ("pid", "user", "mnt", "net")}
        child = r'''
import errno, json, os, pathlib, socket, subprocess, sys
outside = pathlib.Path(sys.argv[1])
for name, parent in json.loads(sys.argv[2]).items():
    assert os.readlink("/proc/self/ns/" + name) != parent, name + " namespace was shared"
pathlib.Path("result").write_text("inside permitted\n")
assert (outside / "baseline").read_text() == "preserve\n"
for path in (outside / "blocked", outside / "baseline", pathlib.Path("escape/blocked")):
    try:
        with path.open("a") as stream:
            stream.write("must refuse")
    except OSError as error:
        assert error.errno in (errno.EROFS, errno.EACCES, errno.EPERM), error
    else:
        raise RuntimeError("sandbox permitted outside write")
try:
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except OSError as error:
    assert error.errno in (errno.EPERM, errno.EACCES), error
else:
    connection.close()
    raise RuntimeError("sandbox permitted an Internet socket")
assert subprocess.check_output(["/bin/sh", "-ec", "printf child-process"]) == b"child-process"
print("sandbox-boundaries-passed")
'''
        command = ["/usr/local/bin/codex", "-c", 'sandbox_mode="workspace-write"',
                   "sandbox", "--", sys.executable, "-c", child, str(outside),
                   json.dumps(namespaces)]
        result = subprocess.run(command, cwd=workspace, env=env, stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=45)
        # Diagnostics are from our fixed command and empty HOME only.
        if result.returncode or result.stdout.strip() != "sandbox-boundaries-passed":
            raise RuntimeError(f"provider sandbox failed ({result.returncode}): {result.stderr[-2000:]}")
        if (outside / "baseline").read_text() != "preserve\n" or (outside / "blocked").exists():
            raise RuntimeError("provider sandbox changed the outside baseline")
        if (workspace / "result").read_text() != "inside permitted\n":
            raise RuntimeError("provider sandbox did not produce its workspace result")
        return {"result": "passed", "insideWrite": "passed", "outsideWrite": "refused",
                "symlinkEscape": "refused", "networkSocket": "refused",
                "childProcess": "passed", "namespaces": "isolated",
                "parentNetworkSocket": "permitted",
                "authentication": "not attempted", "runtime": runtime,
                "providerVersion": version}


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", choices=("web", "workspace"), default="web")
    print(json.dumps(probe(parser.parse_args().runtime), sort_keys=True))
