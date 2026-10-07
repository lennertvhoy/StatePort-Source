#!/usr/bin/env python3
"""Decisive local reproduction of the StatePort agent-readiness authority wall.

The vm-r24/r25/r26 installed rounds all failed the ``agent-readiness`` step with
``execution_unavailable`` -> ``agent_workspace_authority_invalid``.  That gate
lives in :meth:`ExecutionHostProxy.agent_workspace_binding`, which reads
``/etc/stateport/workspace-authority/agent-workspace.json`` through
:meth:`ExecutionHostProxy._authority_document`.

On the guest that directory is ``root:root`` and the binding is written
``0644`` (see ``execution_host_provisioning.py``), so inside the *rootless*
control-plane container the file projects as the unmapped uid ``65534``.  The
pre-fix trusted-owner check rejected exactly that identity.  Because the
deployed bindings format is ``TRANSPORT_FORMAT``
(``stateport.application-workspace-bindings/v2``), the owner check is skipped
for ``issuer.json`` but *not* for ``agent-workspace.json`` -- an asymmetry that
made the wall invisible to a repro that only exercised the issuer path.

This script runs the REAL control-plane code inside the REAL runtime image,
rootless, against a host-root-owned fixture that mirrors the guest, and reports
the exact refusal for HEAD and for the pre-``798ee95f`` owner check.  It costs
seconds, not a 4.5-hour VM round, and is the required first step before
admitting any diagnostic round at this boundary.

Usage:
    python3 scripts/qualification/local_authority_repro.py
    python3 scripts/qualification/local_authority_repro.py --image <ref>
    python3 scripts/qualification/local_authority_repro.py --keep

Exit status is 0 when the harness ran and produced a projection (it does not
assert the product is fixed; read the JSON).
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DEFAULT_IMAGE = "127.0.0.1:5046/stateport-alpha/stateport-web:0.1.0-alpha.19-build1"

DRIVER = r'''
import json, os, sys
from pathlib import Path
for pkg in ("persistent-app", "execution-host", "release-contracts", "runtime-contracts", "deployment"):
    sys.path.insert(0, f"/workspace/packages/{pkg}/src")
from stateport_persistent_app import execution_host_proxy as ehp
from stateport_persistent_app.execution_host_proxy import ExecutionHostProxy, ExecutionHostProxyError

AUTHORITY = os.environ.get("SP_AUTHORITY", "/probe")

def _stat(path):
    try:
        st = os.lstat(path)
        return f"uid={st.st_uid} gid={st.st_gid} mode={oct(st.st_mode & 0o777)}"
    except OSError as exc:
        return f"OSError {exc}"

def probe(label, fmt):
    proxy = ExecutionHostProxy(authority_directory=AUTHORITY, bindings_format=fmt,
                               bindings_owner_uid=os.geteuid())
    out = {"label": label, "bindings_format": fmt, "container_euid": os.geteuid(),
           "stat_authority_dir": _stat(AUTHORITY),
           "stat_agent_binding": _stat(f"{AUTHORITY}/agent-workspace.json"),
           "stat_issuer": _stat(f"{AUTHORITY}/issuer.json")}
    try:
        doc = proxy._authority_document(Path(f"{AUTHORITY}/agent-workspace.json"))
        out["read_agent_binding_raw"] = ["OK", sorted(doc)[:4]]
    except Exception as exc:
        out["read_agent_binding_raw"] = [type(exc).__name__, str(exc)]
    try:
        out["agent_workspace_binding"] = ["OK", proxy.agent_workspace_binding()["grantId"]]
    except ExecutionHostProxyError as exc:
        out["agent_workspace_binding"] = ["REFUSED", exc.code]
    except Exception as exc:
        out["agent_workspace_binding"] = ["ERROR", f"{type(exc).__name__}: {exc}"]
    try:
        proxy._workspace_issuer()
        out["workspace_issuer"] = ["OK"]
    except Exception as exc:
        out["workspace_issuer"] = [type(exc).__name__, str(exc)]
    return out

# HEAD in transport format = the deployed product after the fail-closed fix:
# the agent path skips the in-namespace-unverifiable owner check, so the gate
# passes; writability and digest layers still enforce.
results = [probe("HEAD transport-format (deployed path)", ehp.TRANSPORT_FORMAT)]
# Bindings format keeps the strict owner check, which rejects the unmapped
# host-root projection (65534) exactly as the pre-fix agent path did — the
# r24/r25/r26 wall.
results.append(probe("strict bindings-format (pre-fix wall)", ehp.BINDINGS_FORMAT))
print(json.dumps(results, indent=1))
'''

FIXTURE_GEN = r'''
import json, sys
from pathlib import Path
REPO, OUT = Path(sys.argv[1]), Path(sys.argv[2])
for pkg in ("persistent-app", "execution-host", "release-contracts", "runtime-contracts", "deployment"):
    sys.path.insert(0, str(REPO / "packages" / pkg / "src"))
from stateport_persistent_app import execution_host_proxy as ehp
from execution_host import daemon_contract
IMAGE_REFERENCE = "ghcr.io/stateport/agent-workspace@sha256:" + "a" * 64
GRANT_DIGEST = "sha256:" + "b" * 64
SPEC_DIGEST = "sha256:" + "c" * 64
def agent_workload():
    return daemon_contract.validate_workload_spec({
        "kind": "workspace", "workloadId": ehp.AGENT_WORKSPACE_ID,
        "image": {"reference": IMAGE_REFERENCE},
        "parameters": {
            "workspaceId": ehp.AGENT_WORKSPACE_ID, "workspaceSpecDigest": SPEC_DIGEST,
            "volumeName": "stateport-workspace-" + ehp.AGENT_WORKSPACE_ID,
            "stopAfterIdle": True, "shell": ["/bin/sh"], "networkMode": "developer",
            "cacheVolumes": [], "cpuQuotaPercent": 100, "diskMaxBytes": 256 * 1024 * 1024,
            "workSeconds": 0, "emitBytes": 0,
            "agentProviderProfile": daemon_contract.AGENT_PROVIDER_PROFILE},
        "timeoutSeconds": 3600, "outputByteBound": 65536,
        "resources": {"memoryMaxBytes": 256 * 1024 * 1024, "pidsMax": 128}})
OUT.mkdir(parents=True, exist_ok=True)
(OUT / "agent-workspace.json").write_text(json.dumps({
    "formatVersion": ehp.AGENT_WORKSPACE_BINDING_FORMAT, "grantId": "grant-agent",
    "authorityGrantDigest": GRANT_DIGEST, "workload": agent_workload()},
    indent=2, sort_keys=True) + "\n", encoding="utf-8")
(OUT / "issuer.json").write_text(json.dumps({
    "formatVersion": "stateport.workspace-issuer-public/v1",
    "issuerContextDigest": "sha256:" + "d" * 64,
    "profileId": "stateport.empty-workspace/v1",
    "profileDigest": "sha256:" + "e" * 64, "sourceMode": "empty", "profile": {},
    "grantExpiresAtLimit": "2027-01-01T00:00:00Z", "operator": "root"},
    indent=2, sort_keys=True) + "\n", encoding="utf-8")
'''


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument("--keep", action="store_true", help="keep the temp fixture dir")
    parser.add_argument(
        "--no-root-fixture",
        action="store_true",
        help="skip the sudo chown that reproduces the unmapped-uid projection",
    )
    args = parser.parse_args()

    work = Path(tempfile.mkdtemp(prefix="sp-authority-repro-"))
    fixture = work / "fixture"
    driver = work / "driver.py"
    gen = work / "gen_fixture.py"
    try:
        driver.write_text(DRIVER, encoding="utf-8")
        gen.write_text(FIXTURE_GEN, encoding="utf-8")

        subprocess.run(
            [sys.executable, str(gen), str(REPO), str(fixture)],
            check=True,
        )
        if not args.no_root_fixture:
            subprocess.run(["sudo", "chown", "-R", "root:root", str(fixture)], check=True)
            subprocess.run(["sudo", "chmod", "0755", str(fixture)], check=True)
            for item in fixture.glob("*.json"):
                subprocess.run(["sudo", "chmod", "0644", str(item)], check=True)

        result = subprocess.run(
            [
                "podman", "run", "--rm",
                "-v", f"{REPO}:/workspace:ro",
                "-v", f"{fixture}:/probe:ro",
                "-v", f"{driver}:/driver.py:ro",
                "--entrypoint", "python3",
                args.image, "/driver.py",
            ],
            check=False,
        )
        return result.returncode
    finally:
        if args.keep:
            print(f"fixture kept at {work}", file=sys.stderr)
        else:
            subprocess.run(["sudo", "rm", "-rf", str(work)], check=False)
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
