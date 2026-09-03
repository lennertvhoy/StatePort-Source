#!/usr/bin/env python3
"""Focused projection tests for the global approvals inbox."""

from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
for source_root in sorted((ROOT / "packages").glob("*/src")):
    sys.path.insert(0, str(source_root))
for source_root in sorted((ROOT / "apps").glob("*/src")):
    sys.path.insert(0, str(source_root))

from stateport_persistent_app.service_process import AppServer  # noqa: E402


PLAN_DIGEST = "sha256:" + "a" * 64
GRANT_DIGEST = "sha256:" + "b" * 64


class _Execution:
    @staticmethod
    def pending_approval_sources() -> list[dict[str, object]]:
        return []


class _App:
    @staticmethod
    def instance_list() -> list[dict[str, object]]:
        return [{
            "instanceId": "infra-one",
            "applicationId": "nixos-infrastructure",
            "metadata": {"externalRepository": True},
        }]


class _Infrastructure:
    @staticmethod
    def pending_approval_sources() -> list[dict[str, object]]:
        return [
            {
                "type": "infrastructure_plan",
                "plan": {
                    "planDigest": PLAN_DIGEST,
                    "createdAt": "2026-07-19T08:00:00Z",
                    "expiresAt": "2026-07-19T08:30:00Z",
                    "operation": "stop",
                    "target": {
                        "targetId": "libvirt-persistent",
                        "domain": "stateport-test-vm",
                    },
                    "repository": {
                        "branch": "main",
                        "headCommit": "c" * 40,
                        "headTree": "d" * 40,
                    },
                    "domainBefore": {"state": "running"},
                },
            },
            {
                "type": "authorization_grant",
                "grant": {
                    "grantId": "local-nix-daily-driver",
                    "proposalDigest": GRANT_DIGEST,
                    "createdAt": "2026-07-19T07:00:00Z",
                    "target": {
                        "targetId": "libvirt-persistent",
                        "domain": "stateport-test-vm",
                    },
                    "allowedOperations": ["vm.observe", "vm.stop.graceful"],
                },
            },
        ]


def test_projection_formats_fresh_infrastructure_and_grant_authorities() -> None:
    server = object.__new__(AppServer)
    server.actor_id = "local-user"
    server.execution = _Execution()
    server.source_app = lambda: _App()
    server.pending_template_upgrade_approvals = lambda: []
    server.infrastructure_adapter = lambda _instance_id: _Infrastructure()

    def no_goal(_instance_id: str) -> tuple[str, Path]:
        raise PermissionError("goal execution unavailable")

    server.goal_execution_binding = no_goal
    projection = AppServer.approvals_projection(server)

    assert projection["formatVersion"] == "stateport.approval-index/v1"
    assert projection["identity"] == "local-user"
    approvals = {item["kind"]: item for item in projection["approvals"]}
    assert approvals["infrastructure_plan"]["decision"] == {
        "kind": "infrastructure_plan",
        "expectedInstanceId": "infra-one",
        "expectedDigest": PLAN_DIGEST,
    }
    assert approvals["infrastructure_plan"]["expiresAt"] == "2026-07-19T08:30:00Z"
    assert approvals["authorization_grant"]["decision"] == {
        "kind": "authorization_grant",
        "expectedInstanceId": "infra-one",
        "expectedDigest": GRANT_DIGEST,
    }
    assert "expiresAt" not in approvals["authorization_grant"]
