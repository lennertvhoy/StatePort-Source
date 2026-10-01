#!/usr/bin/env python3
"""Crash-durability regression tests for control-plane state writes.

The backend audit (2026-08-02) found that canonical YAML state was written
with plain ``write_text`` and that the approval and run stores replaced files
atomically but without fsync. These tests pin the repaired contract: staged
write, file fsync, atomic replace, directory fsync, original preserved and
staging cleaned when a crash interrupts the write.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for rel in [
    "packages/statedd-core/src",
    "packages/approval-gate/src",
    "packages/governed-runner/src",
]:
    source = ROOT / rel
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from approval_gate.gate import ApprovalGate
from governed_runner.ledger import RunLedger
from statedd_core import LifecycleError
from statedd_core import lifecycle as statedd_lifecycle


def _crash_replace(*_args, **_kwargs):
    raise RuntimeError("simulated crash before rename")


def test_write_yaml_keeps_original_when_replace_fails(tmp_path, monkeypatch):
    target = tmp_path / "lock.yaml"
    statedd_lifecycle._write_yaml(target, {"format": "v1"})
    original = target.read_text(encoding="utf-8")
    monkeypatch.setattr(os, "replace", _crash_replace)
    with pytest.raises(RuntimeError, match="simulated crash"):
        statedd_lifecycle._write_yaml(target, {"format": "v2"})
    assert target.read_text(encoding="utf-8") == original
    assert not list(tmp_path.glob("*.tmp"))


def test_write_yaml_fsyncs_file_and_directory(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(os, "fsync", lambda fd: calls.append(fd))
    statedd_lifecycle._write_yaml(tmp_path / "instance.yaml", {"format": "v1"})
    assert len(calls) == 2  # staged file, then the directory rename itself


def test_write_yaml_refuses_symlink_target(tmp_path):
    real = tmp_path / "real.yaml"
    real.write_text("untouched\n", encoding="utf-8")
    link = tmp_path / "lock.yaml"
    link.symlink_to(real)
    with pytest.raises(LifecycleError, match="symlink"):
        statedd_lifecycle._write_yaml(link, {"format": "v1"})
    assert real.read_text(encoding="utf-8") == "untouched\n"


def test_approval_persist_keeps_original_when_replace_fails(tmp_path, monkeypatch):
    gate = ApprovalGate(tmp_path / "approvals.json")
    gate._requests["req-1"] = _approval_request("req-1")
    gate._persist()
    original = gate.path.read_text(encoding="utf-8")
    monkeypatch.setattr(os, "replace", _crash_replace)
    with pytest.raises(RuntimeError, match="simulated crash"):
        gate._persist()
    assert gate.path.read_text(encoding="utf-8") == original
    assert not list(tmp_path.glob("*.tmp"))


def test_approval_persist_fsyncs_file_and_directory(tmp_path, monkeypatch):
    gate = ApprovalGate(tmp_path / "approvals.json")
    gate._requests["req-1"] = _approval_request("req-1")
    calls = []
    monkeypatch.setattr(os, "fsync", lambda fd: calls.append(fd))
    gate._persist()
    assert len(calls) == 2


def test_run_ledger_persist_keeps_original_when_replace_fails(tmp_path, monkeypatch):
    ledger = RunLedger(tmp_path / "runs.json")
    ledger._records["run:1"] = {"runId": "run:1", "status": "planned"}
    ledger._persist()
    original = ledger.path.read_text(encoding="utf-8")
    monkeypatch.setattr(os, "replace", _crash_replace)
    with pytest.raises(RuntimeError, match="simulated crash"):
        ledger._persist()
    assert ledger.path.read_text(encoding="utf-8") == original
    assert not list(tmp_path.glob("*.tmp"))


def test_run_ledger_persist_fsyncs_file_and_directory(tmp_path, monkeypatch):
    ledger = RunLedger(tmp_path / "runs.json")
    ledger._records["run:1"] = {"runId": "run:1", "status": "planned"}
    calls = []
    monkeypatch.setattr(os, "fsync", lambda fd: calls.append(fd))
    ledger._persist()
    assert len(calls) == 2


def _approval_request(request_id: str):
    from approval_gate.gate import ApprovalRequest

    return ApprovalRequest(
        id=request_id,
        operation="mutate",
        capability="state.mutate",
        instance_id="instance-1",
        actor="tester",
        reason="durability test",
    )
