#!/usr/bin/env python3
from __future__ import annotations

"""Read-only actions supplied by StatePort for managed repository templates."""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

import yaml


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


def inspect(root: Path) -> dict[str, Any]:
    if (root / "PROJECT.md").is_file() and (root / "STATE.yaml").is_file():
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
    elif (root / "state/STUDYDD_MODE.yaml").is_file() and (root / "state/STUDY_STATE.yaml").is_file():
        mode = _yaml(root, "state/STUDYDD_MODE.yaml")
        state = _yaml(root, "state/STUDY_STATE.yaml")
        if mode.get("mode") not in {"template", "bootstrap", "learner_instance"}:
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--action", choices=("inspect",), required=True)
    parser.add_argument("--inputs", default="{}")
    args = parser.parse_args()
    inputs = json.loads(args.inputs)
    if inputs != {}:
        raise ValueError("template inspection does not accept input fields")
    print(json.dumps(inspect(args.root), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
