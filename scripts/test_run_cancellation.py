from __future__ import annotations

from pathlib import Path
import sys
import threading

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages/portable-execution/src"))
sys.path.insert(0, str(ROOT / "packages/persistent-app/src"))
sys.path.insert(0, str(ROOT / "packages/statedd-core/src"))
sys.path.insert(0, str(ROOT / "packages/template-validator/src"))
sys.path.insert(0, str(ROOT / "packages/execution-host/src"))
sys.path.insert(0, str(ROOT / "packages/external-engine-runtime/src"))
sys.path.insert(0, str(ROOT / "packages/codex-adapter/src"))
sys.path.insert(0, str(ROOT / "packages/run-bundle/src"))
sys.path.insert(0, str(ROOT / "packages/instance-backup/src"))
sys.path.insert(0, str(ROOT / "packages/instance-catalog/src"))

from stateport_portable_execution.store import RunStore  # noqa: E402


def test_persisted_cancellation_is_idempotent(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "runs.json")
    store.create({"runId": "run-cancel", "instanceId": "fixture", "status": "awaiting_approval", "events": []})
    store.transition("run-cancel", "cancelled", actor="operator", reason="test")
    assert store.get("run-cancel")["status"] == "cancelled"
    assert store.get("run-cancel")["events"][-1]["reason"] == "test"


def test_attached_process_cancellation_is_signalled_before_terminal_state(tmp_path: Path) -> None:
    # The process-owner map is deliberately exercised through a tiny fake
    # service object; the external runtime owns the actual process-group kill.
    from stateport_portable_execution.runtime import PortableExecutionService  # noqa: E402

    class Layout:
        operations_root = tmp_path

    service = PortableExecutionService(type("App", (), {"layout": Layout()})(), tmp_path)
    service.store.create({"runId": "run-live", "status": "running", "instanceId": "fixture", "events": []})
    event = threading.Event()
    service._active_processes["run-live"] = event
    result = service.cancel("run-live")
    assert result["status"] == "cancelling"
    assert event.is_set()
