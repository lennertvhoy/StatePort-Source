#!/usr/bin/env python3
"""Local reproduction of the FULL installed agent-readiness gate.

``run_agent_result_stage.py`` refuses to run the agent-result journey unless
``AgentRunService.readiness()`` reports ``available: true``.  On the guest that
gate aggregates:

  1. the operator provider directory (``provider.env`` / ``opencode.json``), and
  2. ``ExecutionHostProxy.agent_workspace_status()`` -> ``agent_workspace_binding()``
     (the authority document) -> the confined Unix-socket ``listWorkloads`` call.

``local_authority_repro.py`` covers (2)'s authority read in the real rootless
container.  This script covers the rest -- the authority *schema* validation,
the socket transport, the daemon grant check and the readiness aggregation --
by booting the REAL execution-host daemon in-process with a no-op backend and
driving the REAL ``AgentRunService`` against the REAL provisioned grant/binding
documents from ``execution_host_provisioning._agent_workspace_documents``.

It reports one happy path plus three negative controls, so a green result means
the gate genuinely detects the failures it is supposed to.  Cost: seconds.

Usage:
    python3 scripts/qualification/local_readiness_repro.py
    python3 scripts/qualification/local_readiness_repro.py --keep
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
import tempfile
import threading
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
for _pkg in ("persistent-app", "execution-host", "release-contracts", "runtime-contracts", "deployment"):
    sys.path.insert(0, str(REPO / "packages" / _pkg / "src"))

from execution_host.application_workspaces import TRANSPORT_FORMAT  # noqa: E402
from execution_host.daemon import DaemonConfig, ExecutionHostDaemon  # noqa: E402
from stateport_persistent_app.agent_run import AgentRunService  # noqa: E402
from stateport_persistent_app.execution_host_proxy import ExecutionHostProxy  # noqa: E402
from stateport_release import execution_host_provisioning as provisioning  # noqa: E402

IMAGE_REFERENCE = "ghcr.io/stateport/agent-workspace@sha256:" + "a" * 64


class _NoopEngine:
    """Readiness only enumerates the daemon ledger, so the backend is a no-op."""

    identity = {"engine": "local-readiness-repro", "engineVersion": "0"}

    def version(self) -> dict[str, str]:
        return dict(self.identity)

    def list_managed(self) -> list:
        return []

    def inspect(self, workload_id: str) -> dict:
        return {"present": False}


def _write(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _case(
    root: Path,
    *,
    name: str,
    grant: dict,
    binding: dict,
    break_authority: bool = False,
    break_binding_digest: bool = False,
    break_provider_env: bool = False,
) -> dict:
    authority = root / name / "authority"
    authority.mkdir(parents=True)
    if not break_authority:
        document = copy.deepcopy(binding)
        if break_binding_digest:
            document["authorityGrantDigest"] = "sha256:" + "0" * 64
        _write(authority / "agent-workspace.json", document)

    provider = root / name / "provider"
    provider.mkdir(mode=0o700)
    if not break_provider_env:
        (provider / "provider.env").write_text("STATEPORT_FAKE=1\n", encoding="utf-8")
    (provider / "opencode.json").write_text("{}\n", encoding="utf-8")

    socket_path = root / "execution-control" / "control.sock"
    proxy = ExecutionHostProxy(
        authority_directory=str(authority),
        socket_path=str(socket_path),
        bindings_format=TRANSPORT_FORMAT,
        bindings_owner_uid=os.geteuid(),
    )
    service = AgentRunService(
        execution_host=proxy,
        state_dir=root / name / "agent-runs",
        provider_directory=str(provider),
        workspace_image_reference=IMAGE_REFERENCE,
    )
    readiness = service.readiness()
    return {
        "name": name,
        "available": readiness["available"],
        "refusals": readiness["refusals"],
        "providerDirectory": readiness["providerDirectory"],
        "workspace": readiness["workspace"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true", help="keep the temp state directory")
    args = parser.parse_args()

    root = Path(tempfile.mkdtemp(prefix=f"sp-readiness-repro-{uuid.uuid4().hex[:8]}-"))
    socket_dir = root / "execution-control"
    socket_dir.mkdir()
    os.chmod(socket_dir, 0o750)

    daemon = ExecutionHostDaemon(
        DaemonConfig(
            socket_path=socket_dir / "control.sock",
            state_dir=root / "state",
            socket_group_gid=os.getegid(),
            supervise_interval_seconds=0.05,
        ),
        _NoopEngine(),
    )
    daemon.boot()
    threading.Thread(target=daemon.serve_forever, daemon=True).start()

    try:
        grant, binding = provisioning._agent_workspace_documents(
            IMAGE_REFERENCE,
            peer_uid=os.geteuid(),
            issued_at="2026-01-01T00:00:00Z",
            expires_at="2099-01-01T00:00:00Z",
        )
        grants_dir = root / "state" / "grants"
        grants_dir.mkdir(parents=True, exist_ok=True)
        _write(grants_dir / f"{grant['grantId']}.json", grant)

        cases = [
            _case(root, name="happy_path", grant=grant, binding=binding),
            _case(root, name="authority_missing", grant=grant, binding=binding, break_authority=True),
            _case(
                root,
                name="grant_digest_mismatch",
                grant=grant,
                binding=binding,
                break_binding_digest=True,
            ),
            _case(root, name="provider_env_missing", grant=grant, binding=binding, break_provider_env=True),
        ]

        expected = {
            "happy_path": True,
            "authority_missing": False,
            "grant_digest_mismatch": False,
            "provider_env_missing": False,
        }
        all_expected = all(case["available"] is expected[case["name"]] for case in cases)
        print(json.dumps({"all_expected": all_expected, "cases": cases}, indent=1))
        return 0 if all_expected else 1
    finally:
        daemon.shutdown()
        if args.keep:
            print(f"state kept at {root}", file=sys.stderr)
        else:
            import shutil

            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
