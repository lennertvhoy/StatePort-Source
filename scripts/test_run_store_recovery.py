from __future__ import annotations

from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "portable-execution" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "persistent-app" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "statedd-core" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "template-validator" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "external-engine-runtime" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "codex-adapter" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "run-bundle" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "execution-host" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "instance-backup" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "instance-catalog" / "src"))

from stateport_portable_execution.contracts import LIFECYCLE_STATES, allowed_lifecycle_transition  # noqa: E402
from stateport_portable_execution.store import RunStore  # noqa: E402


def test_explicit_lifecycle_contract_is_central_and_persisted(tmp_path: Path) -> None:
    required = {"DRAFT", "COMPILED", "BLOCKED_CAPABILITY", "AWAITING_RUN_APPROVAL", "APPROVED", "STARTING", "RUNNING", "SUCCEEDED", "FAILED", "CANCELLED", "INTERRUPTED", "TIMED_OUT", "RESULT_VALIDATED", "NO_MUTATION", "PROPOSAL_CREATED", "AWAITING_PROPOSAL_APPROVAL", "PROPOSAL_REJECTED", "APPLYING", "APPLIED", "POST_VALIDATED", "CLOSED", "ROLLED_BACK"}
    assert required <= set(LIFECYCLE_STATES)
    assert allowed_lifecycle_transition("DRAFT", "COMPILED")
    assert not allowed_lifecycle_transition("CLOSED", "RUNNING")
    store = RunStore(tmp_path / "runs.json")
    store.create({"runId": "run:lifecycle", "status": "requested"})
    assert store.get("run:lifecycle")["lifecycleState"] == "DRAFT"
    store.transition("run:lifecycle", "planned")
    assert store.get("run:lifecycle")["lifecycleState"] == "COMPILED"


def test_restart_recovery_records_explicit_interruption(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "runs.json")
    store.create({"runId": "run:one", "status": "requested", "instanceId": "instance:one"})
    store.transition("run:one", "planned")
    store.transition("run:one", "awaiting_approval")
    store.transition("run:one", "approved")
    store.transition("run:one", "preparing")
    store.transition("run:one", "prepared")
    store.transition("run:one", "running")
    recovered = store.recover_orphans()
    assert recovered[0]["status"] == "interrupted"
    assert recovered[0]["events"][-1]["reason"] == "service restart found no live process"


def test_illegal_transition_and_idempotent_update_fail_closed(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "runs.json")
    store.create({"runId": "run:two", "status": "requested"})
    with pytest.raises(ValueError, match="invalid run transition"):
        store.transition("run:two", "applied")
    assert store.update("run:two", note="durable")['note'] == "durable"


def test_restart_recovers_apply_transaction_as_explicit_failure(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "runs.json")
    store.create({"runId": "run:apply", "status": "requested"})
    for target in ("planned", "awaiting_approval", "approved", "preparing", "prepared", "running", "completed", "result_validating", "state_change_proposed", "state_change_approved", "applying"):
        store.transition("run:apply", target)
    recovered = store.recover_orphans()
    assert recovered[0]["status"] == "interrupted"
    assert recovered[0]["lifecycleState"] == "INTERRUPTED"
    assert recovered[0]["rollback"] == {
        "status": "unknown",
        "byteIdentical": False,
        "operatorInspectionRequired": True,
    }
    assert "rollback is unproven" in recovered[0]["events"][-1]["reason"]
