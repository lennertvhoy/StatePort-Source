from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import shutil
from types import ModuleType

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
ACTION_SCRIPT = ROOT / "fixtures/apps/studystate-sample/scripts/study_actions.py"
ACTION_SOURCE = ACTION_SCRIPT.read_bytes()
study_actions = ModuleType("studystate_sample_actions")
study_actions.__file__ = str(ACTION_SCRIPT)
exec(compile(ACTION_SOURCE, str(ACTION_SCRIPT), "exec"), study_actions.__dict__)


def test_action_loader_does_not_mutate_canonical_fixture_tree() -> None:
    assert ACTION_SCRIPT.read_bytes() == ACTION_SOURCE
    assert not (ACTION_SCRIPT.parent / "__pycache__").exists()


def instance(tmp_path: Path) -> Path:
    root = tmp_path / "instance"
    root.mkdir(parents=True)
    shutil.copy2(ROOT / "fixtures/apps/studystate-sample/state/LEARNING.yaml", root / "LEARNING.yaml")
    state = root / "state"
    state.mkdir()
    (root / "LEARNING.yaml").replace(state / "LEARNING.yaml")
    (root / "instance.yaml").write_text("kind: StudyState\n", encoding="utf-8")
    lock = root / ".statedd"
    lock.mkdir()
    (lock / "lock.yaml").write_text("formatVersion: fixture/v1\n", encoding="utf-8")
    return root


def learning(root: Path) -> dict[str, object]:
    value = yaml.safe_load((root / "state/LEARNING.yaml").read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def statuses(root: Path) -> dict[str, str]:
    return {item["id"]: item["status"] for item in learning(root)["activities"]}  # type: ignore[index]


def proposal(root: Path, action: str, inputs: dict[str, str]) -> dict[str, object]:
    result = study_actions.plan(root, action, inputs)
    proposals = result["stateChangeProposals"]
    assert isinstance(proposals, list) and len(proposals) == 1
    value = proposals[0]
    assert isinstance(value, dict)
    return value


def test_start_pause_and_redirect_are_exact_durable_transitions(tmp_path: Path) -> None:
    root = instance(tmp_path)
    initial_plan = study_actions.plan_digest(learning(root))

    start = proposal(root, "start-activity", {
        "activityId": "evidence-practice",
        "expectedPlanDigest": initial_plan,
    })
    assert start["applicationAction"] == "studystate.sample.start-activity/v1"
    assert start["preStateDigest"] == study_actions.state_digest(root)
    assert start["operation"] == {
        "type": "start_activity",
        "path": "state/LEARNING.yaml",
        "expectedPlanDigest": initial_plan,
        "activityId": "evidence-practice",
        "activityTitle": "Complete one evidence-backed practice activity",
        "priorStatus": "planned",
        "resultingStatus": "in_progress",
        "resultingPlanDigest": start["operation"]["resultingPlanDigest"],  # type: ignore[index]
    }
    start_receipt = study_actions.apply(root, start)
    assert start_receipt["formatVersion"] == "studystate.sample.state-change-receipt/v1"
    assert start_receipt["proposalId"] == start["proposalId"]
    assert start_receipt["validation"] == "passed"
    assert start_receipt["planDigestBefore"] == initial_plan
    assert start_receipt["planDigestAfter"] == start["operation"]["resultingPlanDigest"]  # type: ignore[index]
    assert start_receipt["preStateDigest"] != start_receipt["postStateDigest"]
    assert statuses(root) == {"evidence-practice": "in_progress", "explain-back": "planned"}

    pause_plan = study_actions.plan_digest(learning(root))
    pause = proposal(root, "pause-activity", {
        "activityId": "evidence-practice",
        "expectedPlanDigest": pause_plan,
    })
    pause_receipt = study_actions.apply(root, pause)
    assert pause_receipt["planDigestBefore"] == pause_plan
    assert statuses(root) == {"evidence-practice": "paused", "explain-back": "planned"}
    assert learning(root)["lastTransition"]["kind"] == "pause_applied"  # type: ignore[index]

    restart_plan = study_actions.plan_digest(learning(root))
    study_actions.apply(root, proposal(root, "start-activity", {
        "activityId": "evidence-practice",
        "expectedPlanDigest": restart_plan,
    }))
    redirect_plan = study_actions.plan_digest(learning(root))
    redirect = proposal(root, "redirect-activity", {
        "fromActivityId": "evidence-practice",
        "toActivityId": "explain-back",
        "expectedPlanDigest": redirect_plan,
    })
    redirect_operation = redirect["operation"]
    assert redirect_operation["fromActivityTitle"] == "Complete one evidence-backed practice activity"  # type: ignore[index]
    assert redirect_operation["toActivityTitle"] == "Explain the governance loop in your own words"  # type: ignore[index]
    redirect_receipt = study_actions.apply(root, redirect)
    assert redirect_receipt["planDigestBefore"] == redirect_plan
    assert redirect_receipt["planDigestAfter"] == redirect_operation["resultingPlanDigest"]  # type: ignore[index]
    assert statuses(root) == {"evidence-practice": "paused", "explain-back": "in_progress"}
    transition = learning(root)["lastTransition"]  # type: ignore[index]
    assert transition["kind"] == "redirect_applied"
    assert transition["fromActivityId"] == "evidence-practice"
    assert transition["toActivityId"] == "explain-back"


def test_stale_digest_and_invalid_transitions_do_not_mutate_state(tmp_path: Path) -> None:
    root = instance(tmp_path)
    before = (root / "state/LEARNING.yaml").read_bytes()
    digest = study_actions.plan_digest(learning(root))

    with pytest.raises(ValueError, match="expectedPlanDigest must match"):
        study_actions.plan(root, "start-activity", {
            "activityId": "evidence-practice",
            "expectedPlanDigest": "sha256:" + "0" * 64,
        })
    with pytest.raises(ValueError, match="does not identify"):
        study_actions.plan(root, "start-activity", {
            "activityId": "missing",
            "expectedPlanDigest": digest,
        })
    with pytest.raises(ValueError, match="only the active activity"):
        study_actions.plan(root, "pause-activity", {
            "activityId": "evidence-practice",
            "expectedPlanDigest": digest,
        })
    with pytest.raises(ValueError, match="redirect source must be the active"):
        study_actions.plan(root, "redirect-activity", {
            "fromActivityId": "evidence-practice",
            "toActivityId": "explain-back",
            "expectedPlanDigest": digest,
        })
    assert (root / "state/LEARNING.yaml").read_bytes() == before

    start = proposal(root, "start-activity", {
        "activityId": "evidence-practice",
        "expectedPlanDigest": digest,
    })
    study_actions.apply(root, start)
    active_bytes = (root / "state/LEARNING.yaml").read_bytes()
    active_digest = study_actions.plan_digest(learning(root))
    with pytest.raises(ValueError, match="pause or redirect"):
        study_actions.plan(root, "start-activity", {
            "activityId": "explain-back",
            "expectedPlanDigest": active_digest,
        })
    with pytest.raises(ValueError, match="must differ"):
        study_actions.plan(root, "redirect-activity", {
            "fromActivityId": "evidence-practice",
            "toActivityId": "evidence-practice",
            "expectedPlanDigest": active_digest,
        })
    assert (root / "state/LEARNING.yaml").read_bytes() == active_bytes


def test_apply_refuses_stale_or_forged_proposal_without_partial_mutation(tmp_path: Path) -> None:
    root = instance(tmp_path)
    digest = study_actions.plan_digest(learning(root))
    start = proposal(root, "start-activity", {
        "activityId": "evidence-practice",
        "expectedPlanDigest": digest,
    })
    stale = deepcopy(start)
    state = learning(root)
    state["goal"]["label"] = "A changed fictional goal"  # type: ignore[index]
    (root / "state/LEARNING.yaml").write_text(yaml.safe_dump(state, sort_keys=False), encoding="utf-8")
    changed = (root / "state/LEARNING.yaml").read_bytes()
    with pytest.raises(ValueError, match="pre-state digest"):
        study_actions.apply(root, stale)
    assert (root / "state/LEARNING.yaml").read_bytes() == changed

    root = instance(tmp_path / "second")
    digest = study_actions.plan_digest(learning(root))
    forged = deepcopy(proposal(root, "start-activity", {
        "activityId": "evidence-practice",
        "expectedPlanDigest": digest,
    }))
    forged["operation"]["resultingPlanDigest"] = "sha256:" + "f" * 64  # type: ignore[index]
    before = (root / "state/LEARNING.yaml").read_bytes()
    with pytest.raises(ValueError, match="resulting plan identity"):
        study_actions.apply(root, forged)
    assert (root / "state/LEARNING.yaml").read_bytes() == before


def test_invalid_durable_multiple_active_state_fails_closed(tmp_path: Path) -> None:
    root = instance(tmp_path)
    state = learning(root)
    for item in state["activities"]:  # type: ignore[index]
        item["status"] = "in_progress"
    before = yaml.safe_dump(state, sort_keys=False).encode()
    (root / "state/LEARNING.yaml").write_bytes(before)
    with pytest.raises(ValueError, match="only one active"):
        study_actions.plan(root, "plan-next-activity", {})
    assert (root / "state/LEARNING.yaml").read_bytes() == before
