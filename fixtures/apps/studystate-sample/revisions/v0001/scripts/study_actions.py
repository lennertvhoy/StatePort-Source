#!/usr/bin/env python3
"""Public-safe typed actions for the StudyState sample application."""

from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any

import yaml


FORMAT = "studystate.sample.action-result/v1"
PROPOSAL_FORMAT = "studystate.sample.state-change-proposal/v1"
ACTIVITY_STATUSES = {"planned", "in_progress", "paused", "completed"}
CONTROL_ACTIONS = {
    "start-activity": ("studystate.sample.start-activity/v1", "start_activity"),
    "pause-activity": ("studystate.sample.pause-activity/v1", "pause_activity"),
    "redirect-activity": ("studystate.sample.redirect-activity/v1", "redirect_activity"),
}


def _digest(value: Any) -> str:
    payload = value if isinstance(value, bytes) else json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def plan_digest(learning: dict[str, Any]) -> str:
    goal = learning.get("goal") if isinstance(learning.get("goal"), dict) else {}
    activities = learning.get("activities") if isinstance(learning.get("activities"), list) else []
    plan = {
        "goal": {"id": goal.get("id"), "label": goal.get("label")},
        "activities": [
            {
                "id": item.get("id"),
                "label": item.get("label"),
                "reason": item.get("reason"),
                "status": item.get("status"),
            }
            for item in activities
            if isinstance(item, dict)
        ],
    }
    canonical = (json.dumps(plan, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
    return _digest(canonical)


def _state(root: Path) -> dict[str, Any]:
    path = root / "state/LEARNING.yaml"
    value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(value, dict) or not isinstance(value.get("activities"), list) or not isinstance(value.get("evidence"), list):
        raise ValueError("StudyState sample state is invalid")
    activity_ids: set[str] = set()
    active_count = 0
    for item in value["activities"]:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("id"), str)
            or not item["id"]
            or not isinstance(item.get("label"), str)
            or not item["label"]
            or item.get("status") not in ACTIVITY_STATUSES
        ):
            raise ValueError("StudyState sample activity state is invalid")
        if item["id"] in activity_ids:
            raise ValueError("StudyState sample activity identities must be unique")
        activity_ids.add(item["id"])
        active_count += item["status"] == "in_progress"
    if active_count > 1:
        raise ValueError("StudyState sample may have only one active activity")
    return value


def _activity(activities: list[dict[str, Any]], activity_id: Any, field: str = "activityId") -> dict[str, Any]:
    if not isinstance(activity_id, str) or not activity_id or len(activity_id) > 80:
        raise ValueError(f"{field} is required and must be at most 80 characters")
    item = next((candidate for candidate in activities if candidate.get("id") == activity_id), None)
    if item is None:
        raise ValueError(f"{field} does not identify a learning activity")
    return item


def _control_plan(
    root: Path,
    learning: dict[str, Any],
    action: str,
    inputs: dict[str, Any],
) -> dict[str, Any]:
    action_id, operation_type = CONTROL_ACTIONS[action]
    activities = [item for item in learning["activities"] if isinstance(item, dict)]
    expected_plan = inputs.get("expectedPlanDigest")
    before_plan = plan_digest(learning)
    if not isinstance(expected_plan, str) or expected_plan != before_plan:
        raise ValueError("expectedPlanDigest must match the current durable plan")

    operation: dict[str, Any] = {
        "type": operation_type,
        "path": "state/LEARNING.yaml",
        "expectedPlanDigest": before_plan,
    }
    after_learning = deepcopy(learning)
    after_activities = [item for item in after_learning["activities"] if isinstance(item, dict)]
    if action == "start-activity":
        current = _activity(activities, inputs.get("activityId"))
        if current.get("status") not in {"planned", "paused"}:
            raise ValueError("only a planned or paused activity can be started")
        if any(item.get("status") == "in_progress" for item in activities):
            raise ValueError("pause or redirect the active activity before starting another")
        after = _activity(after_activities, current["id"])
        after["status"] = "in_progress"
        operation.update({
            "activityId": current["id"],
            "activityTitle": current["label"],
            "priorStatus": current["status"],
            "resultingStatus": "in_progress",
        })
    elif action == "pause-activity":
        current = _activity(activities, inputs.get("activityId"))
        if current.get("status") != "in_progress":
            raise ValueError("only the active activity can be paused")
        after = _activity(after_activities, current["id"])
        after["status"] = "paused"
        operation.update({
            "activityId": current["id"],
            "activityTitle": current["label"],
            "priorStatus": "in_progress",
            "resultingStatus": "paused",
        })
    else:
        source = _activity(activities, inputs.get("fromActivityId"), "fromActivityId")
        target = _activity(activities, inputs.get("toActivityId"), "toActivityId")
        if source["id"] == target["id"]:
            raise ValueError("redirect source and target activities must differ")
        if source.get("status") != "in_progress":
            raise ValueError("redirect source must be the active activity")
        if target.get("status") not in {"planned", "paused"}:
            raise ValueError("redirect target must be planned or paused")
        after_source = _activity(after_activities, source["id"])
        after_target = _activity(after_activities, target["id"])
        after_source["status"] = "paused"
        after_target["status"] = "in_progress"
        operation.update({
            "fromActivityId": source["id"],
            "fromActivityTitle": source["label"],
            "fromPriorStatus": "in_progress",
            "fromResultingStatus": "paused",
            "toActivityId": target["id"],
            "toActivityTitle": target["label"],
            "toPriorStatus": target["status"],
            "toResultingStatus": "in_progress",
        })

    after_plan = plan_digest(after_learning)
    operation["resultingPlanDigest"] = after_plan
    before_state = state_digest(root)
    proposal = {
        "formatVersion": PROPOSAL_FORMAT,
        "proposalId": "proposal-" + hashlib.sha256(
            (action_id + before_state + json.dumps(operation, sort_keys=True, separators=(",", ":"))).encode()
        ).hexdigest()[:16],
        "applicationAction": action_id,
        "preStateDigest": before_state,
        "operation": operation,
    }
    return {
        "formatVersion": FORMAT,
        "actionId": action_id,
        "stateChangeProposals": [proposal],
        "canonicalStateDigest": before_state,
        "planDigest": before_plan,
        "resultingPlanDigest": after_plan,
    }


def state_digest(root: Path) -> str:
    values = {}
    for relative in ("instance.yaml", ".statedd/lock.yaml", "state/LEARNING.yaml"):
        path = root / relative
        if path.is_file() and not path.is_symlink():
            values[relative] = _digest(path.read_bytes())
    return _digest(values)


def plan(root: Path, action: str, inputs: dict[str, Any]) -> dict[str, Any]:
    learning = _state(root)
    activities = [item for item in learning["activities"] if isinstance(item, dict)]
    if action == "plan-next-activity":
        activity = next((item for item in activities if item.get("status") != "completed"), None)
        return {
            "formatVersion": FORMAT,
            "actionId": "studystate.sample.plan-next-activity/v1",
            "activity": activity,
            "stateChangeProposals": [],
            "canonicalStateDigest": state_digest(root),
            "planDigest": plan_digest(learning),
        }
    if action in CONTROL_ACTIONS:
        return _control_plan(root, learning, action, inputs)
    if action == "undo-last-evidence":
        expected = inputs.get("expectedPlanDigest")
        current_plan = plan_digest(learning)
        transition = learning.get("lastTransition")
        if not isinstance(expected, str) or expected != current_plan:
            raise ValueError("expectedPlanDigest must match the current durable plan")
        if (
            not isinstance(transition, dict)
            or transition.get("kind") != "evidence_applied"
            or transition.get("afterPlanDigest") != current_plan
        ):
            raise ValueError("the last durable transition is not undoable")
        transition_activity = next(
            (item for item in activities if item.get("id") == transition.get("activityId")),
            None,
        )
        transition_evidence = next(
            (
                item for item in learning["evidence"]
                if isinstance(item, dict) and item.get("id") == transition.get("evidenceId")
            ),
            None,
        )
        if (
            not isinstance(transition_activity, dict)
            or not isinstance(transition_activity.get("label"), str)
            or not isinstance(transition_evidence, dict)
            or not isinstance(transition_evidence.get("summary"), str)
        ):
            raise ValueError("the last durable transition lacks exact review data")
        restore_status = transition.get("priorStatus")
        if restore_status not in {"planned", "in_progress", "paused"}:
            raise ValueError("the last durable transition has an invalid restore state")
        proposal = {
            "formatVersion": PROPOSAL_FORMAT,
            "proposalId": "proposal-" + hashlib.sha256(("undo" + current_plan).encode()).hexdigest()[:16],
            "applicationAction": "studystate.sample.undo-last-evidence/v1",
            "preStateDigest": state_digest(root),
            "operation": {
                "type": "undo_last_evidence",
                "path": "state/LEARNING.yaml",
                "activityId": transition.get("activityId"),
                "activityTitle": transition_activity["label"],
                "evidenceId": transition.get("evidenceId"),
                "reflection": transition_evidence["summary"],
                "restoreStatus": restore_status,
                "expectedCurrentPlanDigest": current_plan,
                "restoredPlanDigest": transition.get("beforePlanDigest"),
                "appliedProposalId": transition.get("proposalId"),
            },
        }
        return {
            "formatVersion": FORMAT,
            "actionId": "studystate.sample.undo-last-evidence/v1",
            "activity": transition_activity,
            "stateChangeProposals": [proposal],
            "canonicalStateDigest": state_digest(root),
            "planDigest": current_plan,
        }
    if action != "record-evidence":
        raise ValueError("unknown StudyState sample action")
    activity_id = inputs.get("activityId")
    summary = inputs.get("evidenceSummary")
    if not isinstance(activity_id, str) or not activity_id or len(activity_id) > 80:
        raise ValueError("activityId is required and must be at most 80 characters")
    if not isinstance(summary, str) or not summary.strip() or len(summary) > 280:
        raise ValueError("evidenceSummary is required and must be at most 280 characters")
    activity = next((item for item in activities if item.get("id") == activity_id), None)
    if activity is None:
        raise ValueError("learning activity does not exist")
    if activity.get("status") == "completed":
        raise ValueError("learning activity is already completed")
    activity_title = activity.get("label")
    if not isinstance(activity_title, str) or not activity_title:
        raise ValueError("learning activity title is invalid")
    before = state_digest(root)
    before_plan = plan_digest(learning)
    after_learning = deepcopy(learning)
    after_activity = next(
        item for item in after_learning["activities"]
        if isinstance(item, dict) and item.get("id") == activity_id
    )
    prior_status = str(after_activity.get("status", "planned"))
    after_activity["status"] = "completed"
    after_plan = plan_digest(after_learning)
    evidence_id = "evidence-" + hashlib.sha256((activity_id + summary.strip()).encode()).hexdigest()[:12]
    proposal = {
        "formatVersion": PROPOSAL_FORMAT,
        "proposalId": "proposal-" + hashlib.sha256((activity_id + summary.strip() + before).encode()).hexdigest()[:16],
        "applicationAction": "studystate.sample.record-evidence/v1",
        "preStateDigest": before,
        "operation": {
            "type": "record_evidence",
            "path": "state/LEARNING.yaml",
            "activityId": activity_id,
            "activityTitle": activity_title,
            "summary": summary.strip(),
            "reflection": summary.strip(),
            "evidenceId": evidence_id,
            "priorStatus": prior_status,
            "beforePlanDigest": before_plan,
            "afterPlanDigest": after_plan,
        },
    }
    return {
        "formatVersion": FORMAT,
        "actionId": "studystate.sample.record-evidence/v1",
        "activity": activity,
        "stateChangeProposals": [proposal],
        "canonicalStateDigest": before,
    }


def _apply_control(learning: dict[str, Any], operation: dict[str, Any]) -> None:
    activities = [item for item in learning["activities"] if isinstance(item, dict)]
    operation_type = operation["type"]
    if operation_type in {"start_activity", "pause_activity"}:
        activity = _activity(activities, operation.get("activityId"))
        if activity.get("label") != operation.get("activityTitle"):
            raise ValueError("control proposal activity title no longer matches durable state")
        expected = "in_progress" if operation_type == "pause_activity" else operation.get("priorStatus")
        resulting = "paused" if operation_type == "pause_activity" else "in_progress"
        if operation_type == "start_activity" and expected not in {"planned", "paused"}:
            raise ValueError("start proposal prior state is invalid")
        if operation.get("priorStatus") != expected or operation.get("resultingStatus") != resulting:
            raise ValueError("control proposal transition is invalid")
        if activity.get("status") != expected:
            raise ValueError("control proposal activity state changed before apply")
        if operation_type == "start_activity" and any(
            item.get("status") == "in_progress" for item in activities
        ):
            raise ValueError("another activity is already active")
        activity["status"] = resulting
        activity["updatedAt"] = _now()
    else:
        source = _activity(activities, operation.get("fromActivityId"), "fromActivityId")
        target = _activity(activities, operation.get("toActivityId"), "toActivityId")
        if source["id"] == target["id"]:
            raise ValueError("redirect source and target activities must differ")
        if source.get("label") != operation.get("fromActivityTitle") or target.get("label") != operation.get("toActivityTitle"):
            raise ValueError("redirect proposal titles no longer match durable state")
        expected_fields = {
            "fromPriorStatus": "in_progress",
            "fromResultingStatus": "paused",
            "toPriorStatus": target.get("status"),
            "toResultingStatus": "in_progress",
        }
        if target.get("status") not in {"planned", "paused"}:
            raise ValueError("redirect target state changed before apply")
        if source.get("status") != "in_progress":
            raise ValueError("redirect source is no longer active")
        if any(operation.get(key) != value for key, value in expected_fields.items()):
            raise ValueError("redirect proposal transition is invalid")
        source["status"] = "paused"
        source["updatedAt"] = _now()
        target["status"] = "in_progress"
        target["updatedAt"] = _now()


def apply(root: Path, proposal: dict[str, Any]) -> dict[str, Any]:
    operation = proposal.get("operation", {})
    action_by_operation = {
        "record_evidence": "studystate.sample.record-evidence/v1",
        "undo_last_evidence": "studystate.sample.undo-last-evidence/v1",
        "start_activity": "studystate.sample.start-activity/v1",
        "pause_activity": "studystate.sample.pause-activity/v1",
        "redirect_activity": "studystate.sample.redirect-activity/v1",
    }
    if not isinstance(operation, dict):
        raise ValueError("invalid StudyState sample proposal")
    operation_type = operation.get("type")
    if (
        proposal.get("formatVersion") != PROPOSAL_FORMAT
        or operation_type not in action_by_operation
        or proposal.get("applicationAction") != action_by_operation[operation_type]
    ):
        raise ValueError("invalid StudyState sample proposal")
    before = state_digest(root)
    if proposal.get("preStateDigest") != before:
        raise ValueError("proposal pre-state digest does not match the current instance")
    learning = _state(root)
    current_plan = plan_digest(learning)
    if operation.get("type") in {"start_activity", "pause_activity", "redirect_activity"}:
        if operation.get("expectedPlanDigest") != current_plan:
            raise ValueError("control proposal plan identity changed before apply")
        _apply_control(learning, operation)
        resulting_plan = plan_digest(learning)
        if operation.get("resultingPlanDigest") != resulting_plan:
            raise ValueError("control proposal resulting plan identity is invalid")
        transition_kind = operation["type"].removesuffix("_activity") + "_applied"
        learning["lastTransition"] = {
            "kind": transition_kind,
            "proposalId": proposal.get("proposalId"),
            **({"activityId": operation.get("activityId")} if operation.get("activityId") else {}),
            **({"fromActivityId": operation.get("fromActivityId")} if operation.get("fromActivityId") else {}),
            **({"toActivityId": operation.get("toActivityId")} if operation.get("toActivityId") else {}),
            "beforePlanDigest": current_plan,
            "afterPlanDigest": resulting_plan,
            "updatedAt": _now(),
        }
    else:
        activity_id = str(operation.get("activityId"))
        activity = next((item for item in learning["activities"] if isinstance(item, dict) and item.get("id") == activity_id), None)
        if activity is None:
            raise ValueError("learning activity does not exist")
    if operation.get("type") == "record_evidence":
        summary = operation.get("summary")
        reflection = operation.get("reflection")
        activity_title = operation.get("activityTitle")
        evidence_id = operation.get("evidenceId")
        if not isinstance(summary, str) or not summary or len(summary) > 280:
            raise ValueError("proposal evidence summary is invalid")
        if reflection != summary:
            raise ValueError("proposal reflection does not match the exact submitted reflection")
        if activity_title != activity.get("label"):
            raise ValueError("proposal activity title does not match the selected durable activity")
        if not isinstance(evidence_id, str) or not evidence_id.startswith("evidence-"):
            raise ValueError("proposal evidence identity is invalid")
        if operation.get("beforePlanDigest") != current_plan:
            raise ValueError("proposal plan identity changed before apply")
        prior_status = str(activity.get("status", "planned"))
        if prior_status != operation.get("priorStatus"):
            raise ValueError("proposal activity state changed before apply")
        activity["status"] = "completed"
        activity["updatedAt"] = _now()
        learning["evidence"].append({
            "id": evidence_id,
            "activityId": activity_id,
            "summary": summary,
            "kind": "public_safe_fixture",
            "assessment": {"status": "not_assessed", "basis": "learner_self_reflection"},
            "updatedAt": _now(),
        })
        after_plan = plan_digest(learning)
        if operation.get("afterPlanDigest") != after_plan:
            raise ValueError("proposal after-plan identity is invalid")
        learning["lastTransition"] = {
            "kind": "evidence_applied",
            "proposalId": proposal.get("proposalId"),
            "activityId": activity_id,
            "evidenceId": evidence_id,
            "priorStatus": prior_status,
            "beforePlanDigest": current_plan,
            "afterPlanDigest": after_plan,
            "updatedAt": _now(),
        }
    elif operation.get("type") == "undo_last_evidence":
        transition = learning.get("lastTransition")
        restore_status = operation.get("restoreStatus")
        if (
            not isinstance(transition, dict)
            or transition.get("kind") != "evidence_applied"
            or transition.get("proposalId") != operation.get("appliedProposalId")
            or transition.get("afterPlanDigest") != current_plan
            or operation.get("expectedCurrentPlanDigest") != current_plan
        ):
            raise ValueError("undo proposal no longer matches the last durable transition")
        if restore_status not in {"planned", "in_progress", "paused"}:
            raise ValueError("undo proposal restore state is invalid")
        evidence_id = operation.get("evidenceId")
        activity_title = operation.get("activityTitle")
        reflection = operation.get("reflection")
        evidence = learning.get("evidence")
        if not isinstance(evidence, list):
            raise ValueError("undo evidence state is invalid")
        evidence_target = next(
            (
                item for item in evidence
                if isinstance(item, dict) and item.get("id") == evidence_id
            ),
            None,
        )
        if not isinstance(evidence_target, dict):
            raise ValueError("undo evidence target is missing")
        if activity_title != activity.get("label"):
            raise ValueError("undo activity title does not match the durable activity")
        if reflection != evidence_target.get("summary"):
            raise ValueError("undo reflection does not match the durable evidence")
        learning["evidence"] = [
            item for item in evidence
            if not (isinstance(item, dict) and item.get("id") == evidence_id)
        ]
        activity["status"] = restore_status
        activity["updatedAt"] = _now()
        restored_plan = plan_digest(learning)
        if operation.get("restoredPlanDigest") != restored_plan:
            raise ValueError("undo did not restore the approved prior plan digest")
        learning["lastTransition"] = {
            "kind": "undo_applied",
            "proposalId": proposal.get("proposalId"),
            "undidProposalId": operation.get("appliedProposalId"),
            "activityId": activity_id,
            "restoredPlanDigest": restored_plan,
            "updatedAt": _now(),
        }
    path = root / "state/LEARNING.yaml"
    previous = path.read_bytes()
    descriptor, temporary_name = tempfile.mkstemp(prefix=".studystate-", dir=path.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        temporary.write_bytes(yaml.safe_dump(learning, sort_keys=False).encode())
        temporary.replace(path)
        after = state_digest(root)
        return {
            "formatVersion": "studystate.sample.state-change-receipt/v1",
            "proposalId": proposal.get("proposalId"),
            "preStateDigest": before,
            "postStateDigest": after,
            "validation": "passed",
            "planDigestBefore": current_plan,
            "planDigestAfter": plan_digest(learning),
            "restoredPlanDigest": operation.get("restoredPlanDigest") if operation.get("type") == "undo_last_evidence" else None,
        }
    except Exception:
        path.write_bytes(previous)
        raise
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument(
        "--action",
        choices=(
            "plan-next-activity", "record-evidence", "start-activity", "pause-activity",
            "redirect-activity", "undo-last-evidence",
        ),
    )
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
