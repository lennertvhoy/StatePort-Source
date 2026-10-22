from __future__ import annotations

"""Trusted adapters for importing repository-native templates.

Imported repositories are data, never plugins.  Detection reads a small set of
bounded declarative marker files and maps them to StatePort-owned application
contracts.  No command, hook, action, or Python module from the repository is
loaded or executed by this module.
"""

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Callable, Mapping

import yaml

from template_validator.checks import check_template_schema


_MAX_MARKER_BYTES = 256 * 1024
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class TemplateAdapterError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


def _regular_file_bytes(root: Path, relative: str) -> bytes | None:
    """Read one confined regular marker without following links."""

    candidate = Path(relative)
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        raise TemplateAdapterError("template_marker_unsafe", "template marker path is unsafe")
    directory_flags = (
        os.O_RDONLY
        | os.O_CLOEXEC
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    directories: list[int] = []
    descriptor = -1
    try:
        directories.append(os.open(root, directory_flags))
        for part in candidate.parts[:-1]:
            try:
                directories.append(os.open(part, directory_flags, dir_fd=directories[-1]))
            except FileNotFoundError:
                return None
        try:
            descriptor = os.open(candidate.parts[-1], file_flags, dir_fd=directories[-1])
        except FileNotFoundError:
            return None
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise TemplateAdapterError("template_marker_unsafe", "template marker is not a single-link regular file")
        if info.st_size > _MAX_MARKER_BYTES:
            raise TemplateAdapterError("template_marker_too_large", "template marker exceeds the supported size bound")
        payload = bytearray()
        while len(payload) <= _MAX_MARKER_BYTES:
            chunk = os.read(descriptor, min(64 * 1024, _MAX_MARKER_BYTES + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
        if (
            info.st_dev,
            info.st_ino,
            info.st_size,
            info.st_mtime_ns,
            info.st_nlink,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_nlink,
        ):
            raise TemplateAdapterError("template_marker_changed", "template marker changed while it was inspected")
        return bytes(payload)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        for directory in reversed(directories):
            os.close(directory)


def _yaml_mapping(root: Path, relative: str) -> dict[str, Any] | None:
    raw = _regular_file_bytes(root, relative)
    if raw is None:
        return None
    try:
        value = yaml.safe_load(raw.decode("utf-8")) or {}
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise TemplateAdapterError("template_marker_invalid", f"{relative} is not valid bounded YAML") from exc
    if not isinstance(value, dict):
        raise TemplateAdapterError("template_marker_invalid", f"{relative} must contain a YAML mapping")
    return value


def _text_present(root: Path, relative: str) -> bool:
    raw = _regular_file_bytes(root, relative)
    return raw is not None and bool(raw.strip())


@dataclass(frozen=True)
class TemplateAdapter:
    adapter_id: str
    application_id: str
    display_name: str
    description: str
    marker_files: tuple[str, ...]
    requested_capabilities: tuple[str, ...]
    action_ids: tuple[str, ...]
    detector: Callable[[Path], Mapping[str, Any] | None]

    def inspect(self, root: Path) -> dict[str, Any] | None:
        details = self.detector(root)
        if details is None:
            return None
        review = details.get("capabilityReview")
        reviewed = (
            {
                # The operator approves this exact list with the import plan.
                "capabilityReview": review,
                "reviewedActionIds": [item["actionId"] for item in review.get("actions", [])],
            }
            if isinstance(review, Mapping)
            else {}
        )
        return {
            **reviewed,
            "formatVersion": "stateport.template-adapter-match/v1",
            "adapterId": self.adapter_id,
            "applicationId": self.application_id,
            "displayName": str(details.get("displayName") or self.display_name),
            "description": self.description,
            "templateKind": str(details.get("templateKind") or self.adapter_id),
            "declaredTemplateId": details.get("declaredTemplateId"),
            "declaredVersion": details.get("declaredVersion"),
            "markerFiles": list(self.marker_files),
            "requestedCapabilities": list(self.requested_capabilities),
            "trustedActionIds": list(self.action_ids),
            "executionTrust": "stateport_owned_adapter_only",
            "repositoryCommandsExecuted": False,
            "validation": {"status": "passed", "issues": []},
        }


def _projectstate_v6(root: Path) -> Mapping[str, Any] | None:
    if not _text_present(root, "PROJECT.md"):
        return None
    state = _yaml_mapping(root, "STATE.yaml")
    if state is None or state.get("version") != "projectstate-template-v6":
        return None
    if state.get("profile") not in {"core", "hardened"} or not isinstance(state.get("current_slice"), dict):
        raise TemplateAdapterError("projectstate_contract_invalid", "ProjectState v6 STATE.yaml is incomplete")
    return {
        "displayName": "ProjectState",
        "templateKind": "projectstate_v6",
        "declaredTemplateId": "projectstate",
        "declaredVersion": state["version"],
    }


def _studystate(root: Path) -> Mapping[str, Any] | None:
    mode = _yaml_mapping(root, "state/STUDYDD_MODE.yaml")
    state = _yaml_mapping(root, "state/STUDY_STATE.yaml")
    if mode is None and state is None:
        return None
    if mode is None or state is None:
        raise TemplateAdapterError("studystate_contract_invalid", "StudyState mode and state markers must both be present")
    if mode.get("mode") not in {"template", "bootstrap", "learner_instance"}:
        raise TemplateAdapterError("studystate_contract_invalid", "StudyState mode is unsupported")
    if not isinstance(state.get("targets"), list) or not isinstance(state.get("workflow"), dict):
        raise TemplateAdapterError("studystate_contract_invalid", "StudyState state marker is incomplete")
    metadata = state.get("metadata") if isinstance(state.get("metadata"), dict) else {}
    version = metadata.get("template_version")
    return {
        "displayName": "StudyState",
        "templateKind": "studystate",
        "declaredTemplateId": "studystate",
        "declaredVersion": str(version) if version is not None else None,
    }


CAPABILITY_REVIEW_FORMAT = "stateport.imported-capability-review/v1"
_MAX_REVIEWED_ACTIONS = 32
_OWNERSHIP_VALUES = {"instance", "template", "generated"}


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _review_digest(value: Any) -> str:
    return _sha256((json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode())


def _review_path(value: Any, label: str, *, allow_prefix: bool = False) -> str:
    if not isinstance(value, str) or not value or value.startswith("/") or "\\" in value:
        raise TemplateAdapterError("application_template_invalid", f"{label} is not a safe relative path")
    if value in {".", "./"}:
        if allow_prefix:
            return "./"
        raise TemplateAdapterError("application_template_invalid", f"{label} is not a safe relative path")
    prefix = value.endswith("/")
    if prefix and not allow_prefix:
        raise TemplateAdapterError("application_template_invalid", f"{label} must name a file")
    body = value[:-1] if prefix else value
    if any(part in {"", ".", ".."} for part in body.split("/")):
        raise TemplateAdapterError("application_template_invalid", f"{label} is not a safe relative path")
    return value


def native_capability_review(root: Path) -> dict[str, Any]:
    """List every declared action of an imported native application for review.

    The review is part of the template match, so it is part of the import plan
    digest the operator approves. Repository scripts are hashed, never run.
    """

    descriptor_raw = _regular_file_bytes(root, "application.yaml")
    descriptor = _yaml_mapping(root, "application.yaml")
    if descriptor_raw is None or descriptor is None:
        raise TemplateAdapterError("application_template_invalid", "application.yaml is missing")
    application_id = str(descriptor.get("applicationId", ""))
    actions_path = descriptor.get("actionsPath")
    reviewed: list[dict[str, Any]] = []
    actions_sha256: str | None = None
    script_ids: dict[str, str] = {}
    if actions_path is not None:
        actions_path = _review_path(actions_path, "actionsPath")
        actions_raw = _regular_file_bytes(root, actions_path)
        document = _yaml_mapping(root, actions_path)
        if actions_raw is None or document is None:
            raise TemplateAdapterError("application_template_invalid", "the declared actions file is missing")
        actions_sha256 = _sha256(actions_raw)
        items = document.get("actions")
        if not isinstance(items, list) or len(items) > _MAX_REVIEWED_ACTIONS:
            raise TemplateAdapterError(
                "application_template_invalid",
                f"the actions file must list at most {_MAX_REVIEWED_ACTIONS} actions",
            )
        try:
            from stateport_portable_execution.contracts import ActionContract, digest
        except ImportError as exc:  # pragma: no cover - the product ships both packages
            raise TemplateAdapterError("application_template_unreviewable", "action contracts cannot be reviewed here") from exc
        for raw_item in items:
            if not isinstance(raw_item, dict):
                raise TemplateAdapterError("application_template_invalid", "every action must be a mapping")
            item = dict(raw_item)
            if (
                item.get("executorKind", "script") == "script"
                and "executorCommand" not in item
                and isinstance(descriptor.get("executorCommand"), str)
            ):
                item["executorCommand"] = descriptor["executorCommand"]
            try:
                action = ActionContract.from_dict(item)
            except (KeyError, TypeError, ValueError) as exc:
                raise TemplateAdapterError("application_template_invalid", f"action contract is invalid: {exc}") from exc
            prefix = application_id + "."
            if not action.action_id.startswith(prefix) or not action.action_id.endswith("/v1"):
                raise TemplateAdapterError(
                    "application_template_invalid",
                    "action ids must have the form <applicationId>.<name>/v1",
                )
            name = action.action_id[len(prefix):-len("/v1")]
            if not name or not _SAFE_IDENTIFIER.fullmatch(name):
                raise TemplateAdapterError("application_template_invalid", "action name is unsafe")
            executor: dict[str, str] | None = None
            if action.executor_kind == "script":
                executor_path = _review_path(action.executor_command, "executorCommand")
                executor_raw = _regular_file_bytes(root, executor_path)
                if executor_raw is None:
                    raise TemplateAdapterError("application_template_invalid", f"executor {executor_path} is missing")
                executor = {"path": executor_path, "sha256": _sha256(executor_raw)}
                script_ids[action.action_id] = action.mutation_policy
            reviewed.append({
                "actionId": action.action_id,
                "actionName": name,
                "displayName": action.display_name,
                "executorKind": action.executor_kind,
                "mutationPolicy": action.mutation_policy,
                "networkPolicy": action.network_policy,
                "toolPolicy": action.tool_policy,
                "timeoutSeconds": action.timeout_seconds,
                "actionClass": action.action_class,
                "writablePaths": list(action.writable_paths) if action.writable_paths else "all instance-owned paths",
                "protectedPaths": list(action.protected_paths),
                "instructionsSha256": _sha256(action.instructions.encode()) if action.instructions else None,
                "executor": executor,
                "contractDigest": digest(action.to_dict()),
            })
    state_layout = descriptor.get("stateLayout") if isinstance(descriptor.get("stateLayout"), dict) else {}
    ownership_raw = state_layout.get("ownership", {}) if isinstance(state_layout, dict) else {}
    if not isinstance(ownership_raw, dict):
        raise TemplateAdapterError("application_template_invalid", "stateLayout.ownership must be a mapping")
    ownership: dict[str, str] = {}
    for key, owner in ownership_raw.items():
        if owner not in _OWNERSHIP_VALUES:
            raise TemplateAdapterError(
                "application_template_invalid",
                "stateLayout.ownership values must be instance, template or generated",
            )
        ownership[_review_path(key, "stateLayout.ownership key", allow_prefix=True)] = str(owner)
    protected_raw = state_layout.get("protectedPaths", []) if isinstance(state_layout, dict) else []
    if not isinstance(protected_raw, list):
        raise TemplateAdapterError("application_template_invalid", "stateLayout.protectedPaths must be a list")
    protected = [_review_path(item, "stateLayout.protectedPaths entry", allow_prefix=True) for item in protected_raw]
    evaluator = descriptor.get("evaluatorAction")
    if evaluator is not None and script_ids.get(str(evaluator)) != "none":
        raise TemplateAdapterError(
            "application_template_invalid",
            "evaluatorAction must name a declared read-only script action",
        )
    validation = descriptor.get("validationCommand")
    if validation is not None and (not isinstance(validation, str) or not validation.strip() or len(validation) > 2000):
        raise TemplateAdapterError("application_template_invalid", "validationCommand must be a bounded command")
    review: dict[str, Any] = {
        "formatVersion": CAPABILITY_REVIEW_FORMAT,
        "applicationId": application_id,
        "descriptorSha256": _sha256(descriptor_raw),
        "actionsPath": actions_path,
        "actionsSha256": actions_sha256,
        "evaluatorAction": evaluator,
        "validationCommand": validation,
        "stateLayout": {"ownership": ownership, "protectedPaths": protected},
        "actions": reviewed,
        "execution": {
            "scripts": "repository scripts run only in a no-network sandbox on a staged copy",
            "agents": "agent actions run only in the agent sandbox with model-provider egress",
            "changes": "every change is one file-change proposal applied only after a separate approval",
        },
    }
    review["reviewDigest"] = _review_digest(review)
    return review


def _native_application(root: Path) -> Mapping[str, Any] | None:
    value = _yaml_mapping(root, "application.yaml")
    if value is None:
        return None
    application_id = value.get("applicationId")
    if value.get("formatVersion") != "stateport.application/v1" or not isinstance(application_id, str) or not _SAFE_IDENTIFIER.fullmatch(application_id):
        raise TemplateAdapterError("application_template_invalid", "application.yaml is not a valid StatePort application descriptor")
    display_name = value.get("displayName")
    return {
        "displayName": display_name if isinstance(display_name, str) and display_name.strip() else "StatePort template",
        "templateKind": "native_application",
        "declaredTemplateId": application_id,
        "declaredVersion": value.get("version") if isinstance(value.get("version"), str) else value.get("formatVersion"),
        "capabilityReview": native_capability_review(root),
    }


def _native_statespec(root: Path) -> Mapping[str, Any] | None:
    value = _yaml_mapping(root, "template.yaml")
    if value is None:
        return None
    metadata = value.get("metadata") if isinstance(value.get("metadata"), dict) else None
    template_id = metadata.get("id") if isinstance(metadata, dict) else None
    name = metadata.get("name") if isinstance(metadata, dict) else None
    version = metadata.get("version") if isinstance(metadata, dict) else None
    if (
        value.get("apiVersion") != "statedd.stateport.io/v1alpha1"
        or value.get("kind") != "Template"
        or not isinstance(template_id, str)
        or not _SAFE_IDENTIFIER.fullmatch(template_id)
        or not isinstance(version, str)
        or not version
    ):
        raise TemplateAdapterError("statespec_template_invalid", "template.yaml is not a valid StateSpec template descriptor")
    issues = check_template_schema(value)
    if issues:
        # Reuse the public contract checks rather than treating recognition of
        # metadata as validation. Repository actions remain declarative data.
        raise TemplateAdapterError(
            "statespec_template_invalid",
            "template.yaml does not satisfy the StateSpec contract: "
            + "; ".join(f"{issue.path}: {issue.message}" for issue in issues[:8]),
        )
    return {
        "displayName": name if isinstance(name, str) and name.strip() else template_id,
        "templateKind": "statespec_template",
        "declaredTemplateId": template_id,
        "declaredVersion": version,
    }


class TemplateAdapterRegistry:
    """Resolve one reviewed adapter for a repository template."""

    def __init__(self) -> None:
        common = ("conversation", "progress_dashboard", "goal_execution", "proactive_notifications")
        # Order is precedence: the first adapter whose markers match wins. StudyState
        # (and every instance cast from it) embeds the ProjectState v6 core
        # (PROJECT.md + STATE.yaml), so the more specific StudyState markers must be
        # probed before the generic ProjectState core.
        self._adapters = (
            TemplateAdapter(
                "studystate",
                "stateport.template.studystate",
                "StudyState",
                "An isolated StudyState learner workspace with StatePort-owned validation and session inspection.",
                ("state/STUDYDD_MODE.yaml", "state/STUDY_STATE.yaml"),
                common,
                (
                    "stateport.template.studystate.inspect/v1",
                    "stateport.template.studystate.check/v1",
                    "stateport.template.studystate.setup-study/v1",
                    "stateport.template.studystate.plan-next-session/v1",
                ),
                _studystate,
            ),
            TemplateAdapter(
                "projectstate-v6",
                "stateport.template.projectstate",
                "ProjectState",
                "An isolated ProjectState workspace with StatePort-owned validation and inspection actions.",
                ("PROJECT.md", "STATE.yaml"),
                common + ("file_viewer", "workbench", "terminal", "editor", "backup"),
                (
                    "stateport.template.projectstate.inspect/v1",
                    "stateport.template.projectstate.check/v1",
                    "stateport.template.projectstate.setup-project/v1",
                    "stateport.template.projectstate.next-action/v1",
                ),
                _projectstate_v6,
            ),
            TemplateAdapter(
                "native-application",
                "stateport.template.generic",
                "StatePort template",
                "An isolated native StatePort application template using the generic trusted adapter.",
                ("application.yaml",),
                common + ("file_viewer", "backup"),
                ("stateport.template.generic.inspect/v1",),
                _native_application,
            ),
            TemplateAdapter(
                "statespec-template",
                "stateport.template.generic",
                "StateSpec template",
                "An isolated declarative StateSpec template using the generic trusted adapter.",
                ("template.yaml",),
                common + ("file_viewer", "backup"),
                ("stateport.template.generic.inspect/v1",),
                _native_statespec,
            ),
        )
        self._by_id = {adapter.adapter_id: adapter for adapter in self._adapters}

    def inspect(self, root: Path) -> dict[str, Any] | None:
        for adapter in self._adapters:
            match = adapter.inspect(root)
            if match is not None:
                return match
        return None

    def require(self, root: Path, adapter_id: str | None = None) -> dict[str, Any]:
        match = self.inspect(root)
        if match is None:
            raise TemplateAdapterError(
                "template_adapter_unavailable",
                "repository does not contain a supported ProjectState, StudyState, native application, or StateSpec template contract",
            )
        if adapter_id is not None and match["adapterId"] != adapter_id:
            raise TemplateAdapterError("template_adapter_changed", "template adapter identity changed after planning")
        return match
