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
from stateport_persistent_app.infrastructure import InfrastructureError  # noqa: E402

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
    #: The reader records why it dropped a plan; a stand-in that does not would make the
    #: projection's diagnostic untestable, which is how the silent drop survived review.
    last_skipped_plans: list[dict[str, object]] = []

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


# ── the drop must be READABLE in the response, and the response must not widen ────
#
# MEASURED 2026-09-28: a governed run returned 200 with itemCount 0 while the surface had
# already reported a plan as awaiting approval. The reader now names the filter that
# dropped each plan; these tests pin that the reason REACHES the response, and -- just as
# important -- that carrying it changes nothing about which approvals are offered. A
# diagnostic that widened the actionable set would be a weakening wearing a diagnostic's
# clothes, which is the trap the previous increment's tests were written to avoid too.


def _server(adapter: object) -> AppServer:
    server = object.__new__(AppServer)
    server.actor_id = "local-user"
    server.execution = _Execution()
    server.source_app = lambda: _App()
    server.pending_template_upgrade_approvals = lambda: []
    server.infrastructure_adapter = lambda _instance_id: adapter

    def no_goal(_instance_id: str) -> tuple[str, Path]:
        raise PermissionError("goal execution unavailable")

    server.goal_execution_binding = no_goal
    return server


def test_an_inbox_with_plans_and_no_drops_is_unchanged_apart_from_the_new_key() -> None:
    baseline = _Infrastructure()
    with_plans = AppServer.approvals_projection(_server(baseline))
    assert with_plans["approvals"], "the fixture must offer a plan, or this proves nothing"
    assert with_plans["droppedPlans"] == []

    # The actionable set is the set this surface offered before the diagnostic existed:
    # the key is additive and nothing else moved.
    #
    # FALSIFIABLE, unlike the form this replaced. Asserting the filtered-out key is absent
    # proved nothing -- it was removed by construction -- and comparing
    # len(without_key["approvals"]) with len(with_plans["approvals"]) compared ONE LIST WITH
    # ITSELF, because without_key is a shallow copy. Neither could fail, so the additive
    # property was asserted by code incapable of detecting a violation of it. These can:
    #   * the key SET is pinned, so a second additive key fails and a renamed key fails;
    #   * the actionable set is pinned by CONTENT, so widening OR narrowing it fails.
    assert set(with_plans) == {"formatVersion", "identity", "approvals", "droppedPlans"}
    assert set(with_plans) - {"droppedPlans"} == {"formatVersion", "identity", "approvals"}
    actionable = {item["kind"]: item for item in with_plans["approvals"]}
    assert set(actionable) == {"infrastructure_plan", "authorization_grant"}
    assert actionable["infrastructure_plan"]["decision"]["expectedDigest"] == PLAN_DIGEST
    assert actionable["authorization_grant"]["decision"]["expectedDigest"] == GRANT_DIGEST


def test_a_drop_is_reported_with_its_filter_reason_and_instance() -> None:
    dropping = _Infrastructure()
    dropping.last_skipped_plans = [{
        "planDigest": "sha256:" + "c" * 64,
        "reason": "repository-identity-changed",
        "detail": None,
    }]
    projection = AppServer.approvals_projection(_server(dropping))
    assert projection["droppedPlans"] == [{
        "instanceId": "infra-one",
        "planDigest": "sha256:" + "c" * 64,
        "reason": "repository-identity-changed",
        "detail": None,
    }]


def test_an_empty_inbox_with_no_drops_and_an_empty_inbox_with_drops_are_distinguishable() -> None:
    class _Empty(_Infrastructure):
        last_skipped_plans: list[dict[str, object]] = []

        @staticmethod
        def pending_approval_sources() -> list[dict[str, object]]:
            return []

    class _Dropped(_Empty):
        last_skipped_plans = [{"planDigest": "sha256:" + "d" * 64, "reason": "plan-not-current",
                               "detail": "the VM target changed after the plan was prepared"}]

    nothing = AppServer.approvals_projection(_server(_Empty()))
    dropped = AppServer.approvals_projection(_server(_Dropped()))
    assert nothing["approvals"] == dropped["approvals"] == []
    assert nothing["droppedPlans"] == []
    assert len(dropped["droppedPlans"]) == 1
    assert dropped["droppedPlans"][0]["reason"] == "plan-not-current"
    # This is the distinction the governed run could not make.
    assert nothing != dropped


def test_an_unavailable_adapter_is_reported_rather_than_silently_empty() -> None:
    class _Broken:
        last_skipped_plans: list[dict[str, object]] = []

    server = object.__new__(AppServer)
    server.actor_id = "local-user"
    server.execution = _Execution()
    server.source_app = lambda: _App()
    server.pending_template_upgrade_approvals = lambda: []

    def unavailable(_instance_id: str) -> object:
        raise InfrastructureError("infrastructure_unavailable", "no adapter for this instance")

    server.infrastructure_adapter = unavailable

    def no_goal(_instance_id: str) -> tuple[str, Path]:
        raise PermissionError("goal execution unavailable")

    server.goal_execution_binding = no_goal
    projection = AppServer.approvals_projection(server)
    assert projection["approvals"] == []
    assert projection["droppedPlans"][0]["reason"] == "infrastructure-unavailable"
