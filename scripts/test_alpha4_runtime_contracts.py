#!/usr/bin/env python3
"""Focused tests for the alpha.4 local-rootless contract boundary."""
from __future__ import annotations

from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "runtime-contracts" / "src"))

from runtime_contracts import (  # noqa: E402
    AgentRunSpec,
    PersistentWorkspaceSpec,
    PromotionSpec,
    RuntimeHealthProjection,
    ValidatorSpec,
    WorkspaceRuntimeIdentity,
)


DIGEST = "sha256:" + "a" * 64
SHA = "a" * 40


def resources():
    return {"memoryMaxBytes": 268435456, "cpuQuotaPercent": 100, "pidsMax": 128, "diskMaxBytes": 1073741824}


def workspace():
    return {
        "formatVersion": "stateport.workspace-spec/v1",
        "workspaceId": "workspace.demo",
        "imageDigest": DIGEST,
        "workspacePath": "/workspace",
        "shell": ["/bin/sh"],
        "resources": resources(),
        "networkProfile": {"mode": "developer", "allowlist": ["registry.example"]},
        "cacheVolumes": [{"volumeId": "cache", "mountPath": "/workspace/.cache", "readOnly": False}],
        "lifecyclePolicy": {"idleTimeoutSeconds": 900, "stopAfterIdle": True, "preserveDataOnRemove": True},
    }


def test_workspace_contract_round_trips_and_is_digestable():
    contract = PersistentWorkspaceSpec.from_dict(workspace())
    assert contract.to_dict() == workspace()
    assert contract.digest == PersistentWorkspaceSpec.from_dict(contract.to_dict()).digest


def test_workspace_rejects_unpinned_image_and_data_loss():
    value = workspace()
    value["imageDigest"] = "latest"
    with pytest.raises(ValueError):
        PersistentWorkspaceSpec.from_dict(value)
    value = workspace()
    value["lifecyclePolicy"]["preserveDataOnRemove"] = False
    with pytest.raises(ValueError, match="preserved"):
        PersistentWorkspaceSpec.from_dict(value)


def test_managed_run_rejects_persistent_workspace_as_staging():
    value = {
        "formatVersion": "stateport.managed-agent-run/v1",
        "runId": "run.demo",
        "workspaceId": "workspace.demo",
        "baseRevision": SHA,
        "stagingPath": "/workspace",
        "imageDigest": DIGEST,
        "provider": "opencode",
        "model": "provider/model",
        "networkProfile": {"mode": "model-gateway-only", "allowlist": []},
        "authorityGrantDigest": DIGEST,
        "budgets": {"timeSeconds": 60, "token": 1000, "costMinor": 10, "steps": 10},
        "resources": resources(),
        "validationCommands": [["python3", "-m", "pytest"]],
    }
    with pytest.raises(ValueError, match="persistent workspace"):
        AgentRunSpec.from_dict(value)


def test_validator_is_independent_and_confined():
    value = {
        "formatVersion": "stateport.validator-spec/v1",
        "validatorId": "validator.demo",
        "imageDigest": DIGEST,
        "stagingPath": "/run/staging",
        "commands": [["python3", "-m", "pytest"]],
        "resources": resources(),
        "timeoutSeconds": 300,
        "outputByteBound": 1048576,
        "network": "disabled",
        "stagingReadOnly": True,
        "providerAccess": False,
        "runtimeSocketAccess": False,
        "hostMounts": [],
    }
    assert ValidatorSpec.from_dict(value).to_dict() == value
    value["network"] = "enabled"
    with pytest.raises(ValueError, match="disabled"):
        ValidatorSpec.from_dict(value)


def test_promotion_requires_approval_and_exact_digests():
    value = {
        "formatVersion": "stateport.promotion-spec/v1",
        "promotionId": "promotion.demo",
        "workspaceId": "workspace.demo",
        "candidateId": "candidate.demo",
        "expectedBaseRevision": SHA,
        "candidateRevision": "b" * 40,
        "diffDigest": DIGEST,
        "validatorEvidenceDigest": DIGEST,
        "approvalId": "approval.demo",
        "rollbackPointDigest": DIGEST,
    }
    assert PromotionSpec.from_dict(value).to_dict() == value
    value["approvalId"] = ""
    with pytest.raises(ValueError):
        PromotionSpec.from_dict(value)


def test_health_projection_can_report_unavailable_prerequisites():
    value = {
        "formatVersion": "stateport.runtime-health-projection/v1",
        "executionHost": {"status": "absent", "socketPresent": False, "identity": "unknown", "detail": "not provisioned"},
        "workspace": None,
        "modelProvider": {"status": "unverified", "detail": "operator configuration required"},
        "modelGateway": {"status": "unavailable", "detail": "no run-bound route"},
        "validator": {"status": "unavailable", "detail": "not configured"},
        "currentRun": None,
        "pendingApproval": None,
        "promotion": None,
    }
    assert RuntimeHealthProjection.from_dict(value).to_dict() == value
