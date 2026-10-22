#!/usr/bin/env python3
from __future__ import annotations

"""Actions supplied by StatePort for managed repository templates.

`inspect` summarizes a template; `check` is the template's deterministic
evaluator (ADR-0007): it returns a verdict (passed | not_yet | invalid) with a
summary and findings and always exits 0 when it could judge. ProjectState is
judged by StatePort's pinned copy of the ProjectState v6.4.0 gate, never by the
instance's own (editable) copy. `--validate KIND` is the post-apply validator:
exit 0 when the template is still recognised and not invalid.

Nothing here writes to the instance or executes repository-supplied code.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any

import yaml

# Pinned evaluator: ProjectState_Template v6.4.0 (tag commit
# 237f1d04603f68b40a78e353c2a6a4a8f043f79b), scripts/projectstate_gate.py.
GATE_FILE = "projectstate_gate.py"
GATE_RELEASE = "6.4.0"
GATE_SHA256 = "d0db4d913ff282c942b23fd796264422107418d7338911b324e4d0676f200861"
MAX_FINDINGS = 50
MAX_FINDING_CHARS = 500
STUDYSTATE_MODES = {"template", "bootstrap", "learner_instance"}


def _digest(value: Any) -> str:
    payload = (
        value
        if isinstance(value, bytes)
        else json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _yaml(root: Path, relative: str) -> dict[str, Any]:
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"required template marker is missing: {relative}")
    value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(value, dict):
        raise ValueError(f"template marker must be a mapping: {relative}")
    return value


def _is_studystate(root: Path) -> bool:
    return (root / "state/STUDYDD_MODE.yaml").is_file() or (root / "state/STUDY_STATE.yaml").is_file()


def _is_projectstate(root: Path) -> bool:
    return (root / "PROJECT.md").is_file() and (root / "STATE.yaml").is_file()


def inspect(root: Path) -> dict[str, Any]:
    # Same precedence as the adapter registry: StudyState embeds the
    # ProjectState v6 core, so its more specific markers are probed first.
    if _is_studystate(root):
        mode = _yaml(root, "state/STUDYDD_MODE.yaml")
        state = _yaml(root, "state/STUDY_STATE.yaml")
        if mode.get("mode") not in STUDYSTATE_MODES:
            raise ValueError("StudyState mode is unsupported")
        targets = state.get("targets")
        if not isinstance(targets, list):
            raise ValueError("StudyState target collection is invalid")
        summary = {
            "templateKind": "studystate",
            "mode": mode.get("mode"),
            "targetCount": len(targets),
            "activeTargetId": state.get("active_target_id"),
            "workflowStage": (state.get("workflow") or {}).get("stage"),
        }
        action_id = "stateport.template.studystate.inspect/v1"
    elif _is_projectstate(root):
        state = _yaml(root, "STATE.yaml")
        if state.get("version") != "projectstate-template-v6":
            raise ValueError("ProjectState version is unsupported")
        current = state.get("current_slice")
        if not isinstance(current, dict):
            raise ValueError("ProjectState current slice is missing")
        summary = {
            "templateKind": "projectstate_v6",
            "profile": state.get("profile"),
            "sliceId": current.get("id"),
            "sliceStatus": current.get("status"),
            "primaryJourneyStatus": (current.get("primary_journey") or {}).get("status"),
        }
        action_id = "stateport.template.projectstate.inspect/v1"
    else:
        descriptor_path = "application.yaml" if (root / "application.yaml").is_file() else "template.yaml"
        descriptor = _yaml(root, descriptor_path)
        if descriptor_path == "application.yaml":
            if descriptor.get("formatVersion") != "stateport.application/v1":
                raise ValueError("native application descriptor is unsupported")
            declared_id = descriptor.get("applicationId")
            version = descriptor.get("version") or descriptor.get("formatVersion")
            kind = "native_application"
        else:
            if descriptor.get("apiVersion") != "statedd.stateport.io/v1alpha1" or descriptor.get("kind") != "Template":
                raise ValueError("StateSpec template descriptor is unsupported")
            metadata = descriptor.get("metadata") or {}
            declared_id = metadata.get("id")
            version = metadata.get("version")
            kind = "statespec_template"
        summary = {
            "templateKind": kind,
            "declaredTemplateId": declared_id,
            "declaredVersion": version,
        }
        action_id = "stateport.template.generic.inspect/v1"
    return {
        "formatVersion": "stateport.template-action-result/v1",
        "actionId": action_id,
        "digest": _digest(summary),
        "summary": summary,
        "stateChangeProposals": [],
    }


def _load_gate() -> Any:
    path = Path(__file__).resolve().parent / GATE_FILE
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != GATE_SHA256:
        raise ValueError("the pinned ProjectState gate does not match its recorded sha256")
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("stateport_pinned_projectstate_gate", path)
    if spec is None or spec.loader is None:
        raise ValueError("the pinned ProjectState gate cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _bounded(items: list[str]) -> list[str]:
    return [str(item)[:MAX_FINDING_CHARS] for item in items[:MAX_FINDINGS]]


def _gate(root: Path) -> dict[str, Any]:
    gate = _load_gate()
    errors, blockers, warnings, human = gate._validate(root.resolve())
    exit_code = 2 if errors else 1 if blockers else 0
    return {
        "exitCode": exit_code,
        "errors": list(errors),
        "blockers": list(blockers),
        "warnings": list(warnings),
        "ownerDecision": human,
    }


def _studystate_marker_findings(root: Path) -> list[str]:
    findings: list[str] = []
    try:
        mode = _yaml(root, "state/STUDYDD_MODE.yaml")
    except ValueError as exc:
        return [str(exc)]
    try:
        state = _yaml(root, "state/STUDY_STATE.yaml")
    except ValueError as exc:
        return [str(exc)]
    if mode.get("mode") not in STUDYSTATE_MODES:
        findings.append("state/STUDYDD_MODE.yaml: mode must be template, bootstrap or learner_instance")
    if not isinstance(state.get("targets"), list):
        findings.append("state/STUDY_STATE.yaml: targets must be a list")
    if not isinstance(state.get("workflow"), dict):
        findings.append("state/STUDY_STATE.yaml: workflow must be a mapping")
    # Mirrors StudyState's own scripts/check_studydd.py rules for the mode
    # lifecycle and the active target.
    active = state.get("active_target_id")
    if isinstance(active, str) and active:
        if "/" in active or active in {".", ".."} or not (root / "targets" / active / "TARGET.yaml").is_file():
            findings.append(f"active target {active!r} needs targets/{active}/TARGET.yaml")
    if mode.get("mode") == "learner_instance":
        learner = state.get("learner") if isinstance(state.get("learner"), dict) else {}
        if not learner.get("name"):
            findings.append("learner_instance mode requires learner.name in state/STUDY_STATE.yaml")
        if not active:
            findings.append("learner_instance mode requires an active_target_id in state/STUDY_STATE.yaml")
        if mode.get("personalized") is not True:
            findings.append("learner_instance mode requires personalized: true in state/STUDYDD_MODE.yaml")
    elif mode.get("mode") == "template" and mode.get("personalized") is True:
        findings.append("template mode must have personalized: false")
    if not (root / "NEXT_ACTIONS.md").is_file():
        findings.append("NEXT_ACTIONS.md is missing")
    return findings


def check(root: Path) -> dict[str, Any]:
    findings: list[str] = []
    gate: dict[str, Any] | None = None
    if _is_studystate(root):
        kind = "studystate"
        action_id = "stateport.template.studystate.check/v1"
        marker_findings = _studystate_marker_findings(root)
        findings.extend(marker_findings)
        if _is_projectstate(root):
            gate = _gate(root)
        invalid = bool(marker_findings) or (gate is not None and gate["exitCode"] == 2)
        not_yet = gate is not None and gate["exitCode"] == 1
    elif _is_projectstate(root):
        kind = "projectstate_v6"
        action_id = "stateport.template.projectstate.check/v1"
        gate = _gate(root)
        invalid = gate["exitCode"] == 2
        not_yet = gate["exitCode"] == 1
    else:
        raise ValueError("check is defined only for ProjectState v6 and StudyState instances")
    if gate is not None:
        findings.extend(f"gate: {item}" for item in gate["errors"])
        findings.extend(f"blocker: {item}" for item in gate["blockers"])
        findings.extend(f"warning: {item}" for item in gate["warnings"])
    verdict = "invalid" if invalid else "not_yet" if not_yet else "passed"
    summaries = {
        ("projectstate_v6", "passed"): "The ProjectState gate validates the recorded outcome.",
        ("projectstate_v6", "not_yet"): "The project state is honest but the outcome is not validated yet.",
        ("projectstate_v6", "invalid"): "The ProjectState core is invalid.",
        ("studystate", "passed"): "The StudyState markers are valid and its project core passes the gate.",
        ("studystate", "not_yet"): "The StudyState markers are valid; its project core is not validated yet.",
        ("studystate", "invalid"): "The StudyState state files are invalid.",
    }
    return {
        "formatVersion": "stateport.template-action-result/v1",
        "actionId": action_id,
        "verdict": verdict,
        "summary": summaries[(kind, verdict)],
        "findings": _bounded(findings),
        "evaluator": {
            "templateKind": kind,
            "gateRelease": GATE_RELEASE if gate is not None else None,
            "gateSha256": GATE_SHA256 if gate is not None else None,
            "gateExitCode": gate["exitCode"] if gate is not None else None,
        },
        "stateChangeProposals": [],
    }


def validate(root: Path, kind: str) -> int:
    detected = inspect(root)["summary"]["templateKind"]
    expected = {"projectstate": "projectstate_v6", "studystate": "studystate"}[kind]
    if detected != expected:
        print(f"template kind changed: expected {expected}, found {detected}", file=sys.stderr)
        return 1
    verdict = check(root)
    if verdict["verdict"] == "invalid":
        for finding in verdict["findings"][:10]:
            print(finding, file=sys.stderr)
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--action", choices=("inspect", "check"))
    parser.add_argument("--inputs", default="{}")
    parser.add_argument("--validate", choices=("projectstate", "studystate"))
    args = parser.parse_args()
    if args.validate:
        return validate(args.root, args.validate)
    if args.action is None:
        parser.error("--action or --validate is required")
    inputs = json.loads(args.inputs)
    if inputs != {}:
        raise ValueError("template actions do not accept input fields")
    result = inspect(args.root) if args.action == "inspect" else check(args.root)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
