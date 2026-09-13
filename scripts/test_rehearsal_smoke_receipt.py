"""Rehearsal receipt on installed-service smoke failure.

A smoke exception inside installed_service_smoke used to crash main() before
the receipt write and before the --keep-vm hold. The failure path must record
a failed rehearsal receipt (phase detail, snapshots as feasible) and return
normally so main() writes the receipt and honors the hold.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from infra.qualification.wsl2_rehearsal import VM  # noqa: E402


def test_rehearsal_smoke_failure_writes_failed_receipt_and_snapshots() -> None:
    calls: list[str] = []

    class StubVM:
        _record_smoke_failure = VM._record_smoke_failure

        def _collect_failure_snapshots(self, receipt):  # noqa: ANN001
            calls.append("snapshots")
            receipt["failureSnapshots"] = {"guest": "captured"}

        def _collect_diagnostics(self, receipt):  # noqa: ANN001
            calls.append("diagnostics")

    receipt: dict[str, Any] = {"result": "running", "phases": {"install-services": {"ok": False}}}
    StubVM()._record_smoke_failure(
        receipt, "install-services", ValueError("installed execution host unavailable")
    )
    assert receipt["result"] == "failed"
    phase = receipt["phases"]["install-services"]
    assert phase["ok"] is False and "installed execution host unavailable" in phase["error"]
    assert receipt["failureSnapshots"] == {"guest": "captured"}
    assert calls == ["snapshots", "diagnostics"]

    # Snapshot collection failure never masks the failed receipt.
    receipt2: dict[str, Any] = {"result": "running", "phases": {}}

    class FailingSnapshots(StubVM):
        def _collect_failure_snapshots(self, receipt):  # noqa: ANN001
            raise RuntimeError("ssh down")

    FailingSnapshots()._record_smoke_failure(receipt2, "install-services", ValueError("x"))
    assert receipt2["result"] == "failed"
    assert "ssh down" in receipt2["failureSnapshotsError"]
    assert receipt2["phases"]["install-services"]["ok"] is False
