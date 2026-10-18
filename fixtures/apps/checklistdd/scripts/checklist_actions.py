#!/usr/bin/env python3
"""Public-safe typed ChecklistState actions for the generic StatePort fixture."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any

import yaml


FORMAT = "checklistdd.action-result/v1"
PROPOSAL_FORMAT = "checklistdd.state-change-proposal/v1"


def _digest(value: Any) -> str:
    payload = value if isinstance(value, bytes) else json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _state(root: Path) -> dict[str, Any]:
    path = root / "state/CHECKLIST.yaml"
    value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(value, dict) or not isinstance(value.get("items"), list):
        raise ValueError("ChecklistState state is invalid")
    return value


def state_digest(root: Path) -> str:
    values = {}
    for relative in ("instance.yaml", ".statedd/lock.yaml", "state/CHECKLIST.yaml"):
        path = root / relative
        if path.is_file() and not path.is_symlink():
            values[relative] = _digest(path.read_bytes())
    return _digest(values)


def plan(root: Path, action: str, inputs: dict[str, Any]) -> dict[str, Any]:
    checklist = _state(root)
    items = [item for item in checklist["items"] if isinstance(item, dict)]
    if action == "plan-next-item":
        item = next((item for item in items if item.get("completed") is not True), None)
        return {"formatVersion": FORMAT, "actionId": "checklistdd.plan-next-item/v1", "item": item, "stateChangeProposals": [], "canonicalStateDigest": state_digest(root)}
    if action != "complete-item":
        raise ValueError("unknown ChecklistState action")
    item_id = inputs.get("itemId")
    if not isinstance(item_id, str) or not item_id:
        raise ValueError("itemId is required")
    item = next((item for item in items if item.get("id") == item_id), None)
    if item is None:
        raise ValueError("checklist item does not exist")
    before = state_digest(root)
    proposal = {"formatVersion": PROPOSAL_FORMAT, "proposalId": "proposal-" + hashlib.sha256((item_id + before).encode()).hexdigest()[:16], "applicationAction": "checklistdd.complete-item/v1", "preStateDigest": before, "operation": {"type": "complete_item", "path": "state/CHECKLIST.yaml", "itemId": item_id}}
    return {"formatVersion": FORMAT, "actionId": "checklistdd.complete-item/v1", "item": item, "stateChangeProposals": [proposal], "canonicalStateDigest": before}


def apply(root: Path, proposal: dict[str, Any]) -> dict[str, Any]:
    if proposal.get("formatVersion") != PROPOSAL_FORMAT or proposal.get("operation", {}).get("type") != "complete_item":
        raise ValueError("invalid ChecklistState proposal")
    before = state_digest(root)
    if proposal.get("preStateDigest") != before:
        raise ValueError("proposal pre-state digest does not match the current instance")
    checklist = _state(root)
    target = str(proposal["operation"].get("itemId"))
    found = False
    for item in checklist["items"]:
        if isinstance(item, dict) and item.get("id") == target:
            item["completed"] = True
            found = True
    if not found:
        raise ValueError("checklist item does not exist")
    path = root / "state/CHECKLIST.yaml"
    previous = path.read_bytes()
    descriptor, temporary_name = tempfile.mkstemp(prefix=".checklist-", dir=path.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        temporary.write_bytes(yaml.safe_dump(checklist, sort_keys=False).encode())
        temporary.replace(path)
        after = state_digest(root)
        return {"formatVersion": "checklistdd.state-change-receipt/v1", "proposalId": proposal.get("proposalId"), "preStateDigest": before, "postStateDigest": after, "validation": "passed"}
    except Exception:
        path.write_bytes(previous)
        raise
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--action", choices=("plan-next-item", "complete-item"))
    parser.add_argument("--inputs", default="{}")
    parser.add_argument("--apply-proposal", action="store_true")
    args = parser.parse_args()
    if args.apply_proposal:
        print(json.dumps(apply(args.root, json.load(__import__("sys").stdin)), sort_keys=True))
    else:
        print(json.dumps(plan(args.root, str(args.action), json.loads(args.inputs)), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
