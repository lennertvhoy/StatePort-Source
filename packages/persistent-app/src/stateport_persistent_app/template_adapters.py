from __future__ import annotations

"""Trusted adapters for importing repository-native templates.

Imported repositories are data, never plugins.  Detection reads a small set of
bounded declarative marker files and maps them to StatePort-owned application
contracts.  No command, hook, action, or Python module from the repository is
loaded or executed by this module.
"""

from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat
from typing import Any, Callable, Mapping

import yaml


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
        return {
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
        self._adapters = (
            TemplateAdapter(
                "projectstate-v6",
                "stateport.template.projectstate",
                "ProjectState",
                "An isolated ProjectState workspace with StatePort-owned validation and inspection actions.",
                ("PROJECT.md", "STATE.yaml"),
                common + ("file_viewer", "workbench", "terminal", "editor", "backup"),
                ("stateport.template.projectstate.inspect/v1",),
                _projectstate_v6,
            ),
            TemplateAdapter(
                "studystate",
                "stateport.template.studystate",
                "StudyState",
                "An isolated StudyState learner workspace with StatePort-owned validation and session inspection.",
                ("state/STUDYDD_MODE.yaml", "state/STUDY_STATE.yaml"),
                common,
                ("stateport.template.studystate.inspect/v1",),
                _studystate,
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
