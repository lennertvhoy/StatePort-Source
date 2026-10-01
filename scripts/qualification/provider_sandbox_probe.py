"""No-authentication provider smoke executed inside a consuming runtime image.

The rehearsal controller sends this source to the exact verified container.
It creates only a private temporary tree and never opens provider credentials.

Alpha.18 ships upstream OpenCode as the only provider executable.  OpenCode
has no per-command OS sandbox, so the enforcement layer for a provider child
process is the container itself: a read-only root filesystem, only the
declared writable mounts, and dropped capabilities.  This probe therefore:

* runs the shipped ``/usr/local/bin/opencode`` and records its version;
* proves a provider-style child process can write inside the runtime's
  writable root and execute a child, while a write to a directory this same
  uid owns on the read-only rootfs -- directly and through a symlink -- is
  refused by the container boundary;
* records the container's network posture: the signed topology attaches the
  web service to an ``Internal=true`` network, so a provider-style child
  cannot establish an external TCP connection, while socket creation itself
  stays permitted (no seccomp denial masquerades as the network boundary).
  Container namespace isolation from the guest is asserted by the rehearsal
  controller from outside the container, where it is observable.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile


# The provider executable the signed images install.  Probing any other
# executable would not exercise what the release ships.
PROVIDER_NAME = "opencode"
PROVIDER_EXECUTABLE = "/usr/local/bin/opencode"

# Per-runtime identity and paths.  ``readOnlyOwned`` is a directory this uid
# owns that lives on the container's read-only root filesystem, so a refused
# write there is attributable to the mount boundary rather than to
# discretionary access control.
_RUNTIMES = {
    "web": {
        "uid": 65532,
        "temporaryRoot": "/var/lib/stateport/data",
        "readOnlyOwned": "/workspace",
    },
    "workspace": {
        "uid": 10001,
        "temporaryRoot": "/workspace",
        "readOnlyOwned": "/home/stateport",
    },
}

_PROVIDER_VERSION = re.compile(
    r"(?:opencode\s+)?([0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]+)?)"
)

# Runs as the service identity inside the container boundary; the parent
# supplies the exact paths.  A symlink escape into the read-only rootfs and a
# direct write there must both be refused for this same uid, which has already
# proven it can write its own declared writable root.  The network check uses
# a literal public address (no DNS) and requires that no connection can be
# established; the signed topology places this service on an internal network.
_BOUNDARY_CHILD = r'''
import errno, pathlib, socket, subprocess, sys
readonly_target = pathlib.Path(sys.argv[1])
symlink_target = pathlib.Path(sys.argv[2])
pathlib.Path("result").write_text("inside permitted\n")
for path in (readonly_target, symlink_target):
    try:
        with path.open("a") as stream:
            stream.write("must refuse")
    except OSError as error:
        assert error.errno in (errno.EROFS, errno.EACCES, errno.EPERM), error
    else:
        raise RuntimeError("container boundary permitted an outside write")
try:
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except OSError as error:
    raise RuntimeError("container refused socket creation") from error
connection.settimeout(4)
try:
    connection.connect(("1.1.1.1", 443))
except OSError:
    pass
else:
    raise RuntimeError("container permitted an external connection")
finally:
    connection.close()
assert subprocess.check_output(["/bin/sh", "-ec", "printf child-process"]) == b"child-process"
print("sandbox-boundaries-passed")
'''


def normalise_provider_version(output: str) -> str:
    """Return ``opencode <version>``; refuse any foreign or malformed CLI."""
    match = _PROVIDER_VERSION.fullmatch(output.strip()) if isinstance(output, str) else None
    if match is None:
        raise RuntimeError("provider executable did not report an OpenCode version")
    return f"{PROVIDER_NAME} {match.group(1)}"


def _effective_capabilities() -> str:
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith("CapEff:"):
            return line.split(":", 1)[1].strip()
    raise RuntimeError("cannot read the runtime effective capabilities")


def probe(runtime: str = "web") -> dict:
    if runtime not in _RUNTIMES:
        raise ValueError("unsupported provider runtime")
    identity = _RUNTIMES[runtime]
    expected_uid = identity["uid"]
    if os.getuid() != expected_uid or os.getgid() != expected_uid:
        raise RuntimeError("provider smoke probe requires the signed service identity")
    with tempfile.TemporaryDirectory(prefix=".sandbox-probe-", dir=identity["temporaryRoot"]) as temporary:
        root = Path(temporary)
        workspace = root / "workspace"
        control_root = root / "control"
        home = root / "home"
        for path in (workspace, control_root, home):
            path.mkdir(mode=0o700)
        read_only_target = Path(identity["readOnlyOwned"]) / ".stateport-sandbox-probe"
        (workspace / "escape").symlink_to(identity["readOnlyOwned"], target_is_directory=True)
        env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(home), "STATEPORT_OPENCODE_HOME": str(home),
            "TMPDIR": "/tmp", "LANG": "C.UTF-8",
        }
        try:
            version = normalise_provider_version(subprocess.check_output(
                [PROVIDER_EXECUTABLE, "--version"], env=env,
                stdin=subprocess.DEVNULL, text=True, timeout=45,
            ))
        except (OSError, subprocess.SubprocessError) as error:
            raise RuntimeError(
                "provider executable is missing or unusable: " + PROVIDER_EXECUTABLE
            ) from error
        # This same uid can write its declared writable root, so the refusals
        # below cannot be credited to a blanket read-only identity.
        (control_root / "writable-before").write_text("yes")
        (control_root / "writable-before").unlink()
        # Socket creation must work in the parent as well, so the network
        # refusal below cannot be a seccomp artifact.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM):
            pass
        capabilities = _effective_capabilities()
        if capabilities != "0" * 16:
            raise RuntimeError("provider runtime retains effective capabilities")
        result = subprocess.run(
            [sys.executable, "-c", _BOUNDARY_CHILD, str(read_only_target),
             str(workspace / "escape" / ".stateport-sandbox-probe")],
            cwd=workspace, env=env, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=45,
        )
        # Diagnostics are from our fixed command and empty HOME only.
        if result.returncode or result.stdout.strip() != "sandbox-boundaries-passed":
            raise RuntimeError(f"container boundary failed ({result.returncode}): {result.stderr[-2000:]}")
        if (workspace / "result").read_text() != "inside permitted\n":
            raise RuntimeError("container boundary did not produce its workspace result")
        if read_only_target.exists():
            raise RuntimeError("container boundary accepted an outside write")
        return {
            "result": "passed",
            "provider": PROVIDER_NAME,
            "providerVersion": version,
            "providerExecutable": PROVIDER_EXECUTABLE,
            "sandboxLayer": "container",
            "insideWrite": "passed",
            "outsideWrite": "refused",
            "symlinkEscape": "refused",
            "childProcess": "passed",
            "capabilities": "dropped",
            "parentNetworkSocket": "permitted",
            "networkSocket": "refused",
            "networkPolicy": "container-internal",
            "authentication": "not attempted",
            "runtime": runtime,
        }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", choices=tuple(_RUNTIMES), default="web")
    print(json.dumps(probe(parser.parse_args().runtime), sort_keys=True))
