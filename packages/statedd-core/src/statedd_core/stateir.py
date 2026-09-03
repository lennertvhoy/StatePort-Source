"""Source-linked, derived StateIR for canonical StateDD files.

StateIR deliberately does not replace canonical YAML or Markdown.  It is a
small, deterministic view assembled from the lifecycle manifest and lock so
that later context compilation can carry provenance and privacy decisions.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from statedd_core.lifecycle import (
    LOCK_FORMAT,
    _all_manifest_files,
    _lock_owner_matches_manifest,
    describe_template_source,
    load_template_manifest,
)
from statedd_core.models import Instance
from statedd_core.yaml import StateDDYamlError, parse_yaml_text


STATEIR_FORMAT = "statedd.state-ir/v1"
_DEFAULT_SENSITIVITIES = frozenset({"public", "internal", "private"})
_ALL_SENSITIVITIES = frozenset({"public", "internal", "private", "secret"})


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _safe_file(root: Path, relative: str, label: str) -> Path:
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts or "." in candidate.parts:
        raise ValueError(f"{label} must be a safe relative path")
    current = root
    for part in candidate.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"{label} contains a symlink: {relative}")
    resolved = current.resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise ValueError(f"{label} escapes its root")
    if not resolved.is_file():
        raise ValueError(f"{label} is not a regular file: {relative}")
    return resolved


def _read_mapping(path: Path, label: str) -> dict[str, Any]:
    try:
        value = parse_yaml_text(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, StateDDYamlError, ValueError) as exc:
        raise ValueError(f"could not read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain a mapping")
    return value


def _json_pointer(parts: Iterable[str]) -> str:
    escaped = [str(part).replace("~", "~0").replace("/", "~1") for part in parts]
    return "/" + "/".join(escaped) if escaped else "/"


def _flatten(value: Any, parts: tuple[str, ...] = ()) -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        if not value:
            yield _json_pointer(parts), value
            return
        for key in sorted(value, key=str):
            yield from _flatten(value[key], parts + (str(key),))
        return
    if isinstance(value, list):
        if not value:
            yield _json_pointer(parts), value
            return
        for index, item in enumerate(value):
            yield from _flatten(item, parts + (str(index),))
        return
    yield _json_pointer(parts), value


def _fact_id(source_file: str, pointer: str) -> str:
    payload = f"{source_file}\0{pointer}".encode("utf-8")
    return "fact:" + hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class SourceRef:
    path: str
    kind: str
    sha256: str
    pointer: str = "/"
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "kind": self.kind,
            "sha256": self.sha256,
            "pointer": self.pointer,
            "line": self.line,
        }


@dataclass(frozen=True)
class StateFact:
    path: str
    value: Any
    source_file: str | None = None
    sensitivity: str = "private"
    lossiness: str = "lossless"
    source: SourceRef | None = None
    id: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            source_file = self.source_file or (self.source.path if self.source else "")
            pointer = self.source.pointer if self.source else self.path
            object.__setattr__(self, "id", _fact_id(source_file, pointer))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "path": self.path,
            "value": self.value,
            "sourceFile": self.source_file,
            "sensitivity": self.sensitivity,
            "lossiness": self.lossiness,
            "source": self.source.to_dict() if self.source else None,
        }


@dataclass(frozen=True)
class StateIR:
    instance_id: str
    source_revision: str
    source_hashes: dict[str, str]
    facts: tuple[StateFact, ...] = ()
    included_files: tuple[str, ...] = ()
    excluded_files: tuple[str, ...] = ()
    stale: bool = False
    format_version: str = STATEIR_FORMAT

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": self.format_version,
            "instanceId": self.instance_id,
            "sourceRevision": self.source_revision,
            "sourceHashes": dict(sorted(self.source_hashes.items())),
            "includedFiles": list(self.included_files),
            "excludedFiles": list(self.excluded_files),
            "stale": self.stale,
            "facts": [fact.to_dict() for fact in self.facts],
        }


def _load_lock(instance_root: Path) -> dict[str, Any]:
    lock_path = _safe_file(instance_root, ".statedd/lock.yaml", "lockfile")
    lock = _read_mapping(lock_path, "lock.yaml")
    if lock.get("formatVersion") != LOCK_FORMAT:
        raise ValueError(f"lock formatVersion must be {LOCK_FORMAT!r}")
    if not isinstance(lock.get("template"), dict):
        raise ValueError("lock.template must be a mapping")
    if not isinstance(lock.get("files"), list):
        raise ValueError("lock.files must be a list")
    return lock


def _template_root(instance_root: Path, lock: dict[str, Any], template_path: Path | str | None) -> Path:
    if template_path is not None:
        root = Path(template_path)
    else:
        template = lock["template"]
        source = template.get("source")
        if isinstance(source, dict):
            source_path = source.get("path", source.get("checkoutLocation"))
        else:
            source_path = template.get("sourcePath")
        if not isinstance(source_path, str) or not source_path:
            raise ValueError("lock does not identify a local template source")
        root = Path(source_path)
    if not root.is_dir():
        raise ValueError(f"template source is not a directory: {root}")
    return root


def _decode_file(path: Path, relative: str, sensitivity: str) -> list[StateFact]:
    content = path.read_text(encoding="utf-8")
    digest = _sha256(path)
    suffix = path.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        try:
            value = parse_yaml_text(content)
        except (StateDDYamlError, ValueError) as exc:
            # StudyDD templates legitimately use document markers and YAML
            # constructs outside StateDD's small dependency-free parser. Use
            # PyYAML's safe loader when available; never fall back to unsafe
            # object construction.
            try:
                import yaml

                # BaseLoader keeps timestamps as strings, avoiding
                # non-JSON-native date objects in portable StateIR.
                value = yaml.load(content, Loader=yaml.BaseLoader)
            except ImportError:
                raise ValueError(f"could not parse canonical YAML {relative}: {exc}") from exc
            except Exception as fallback_exc:
                raise ValueError(f"could not parse canonical YAML {relative}: {fallback_exc}") from fallback_exc
        facts: list[StateFact] = []
        for pointer, item in _flatten(value):
            source = SourceRef(relative, "yaml", digest, pointer)
            facts.append(
                StateFact(
                    path=f"{relative}#{pointer}",
                    value=item,
                    source_file=relative,
                    sensitivity=sensitivity,
                    source=source,
                )
            )
        return facts
    if suffix in {".md", ".markdown", ".txt"}:
        source = SourceRef(relative, "markdown", digest, "/text")
        return [
            StateFact(
                path=f"{relative}#/text",
                value=content,
                source_file=relative,
                sensitivity=sensitivity,
                source=source,
            )
        ]
    raise ValueError(f"unsupported canonical source format: {relative}")


def build_state_ir(
    instance_path: Path | str,
    template_path: Path | str | None = None,
    allowed_sensitivities: Iterable[str] | None = None,
    *,
    template_sensitivities: Iterable[str] | None = None,
    instance_granted_sensitivities: Iterable[str] | None = None,
    operator_allowed_sensitivities: Iterable[str] | None = None,
) -> StateIR:
    """Normalize manifest-owned canonical files into deterministic StateIR.

    The optional three policy sets make the effective access boundary explicit:
    template request ∩ instance grant ∩ operator policy.  The legacy
    ``allowed_sensitivities`` argument is retained as an operator-policy alias.
    """
    instance_root = Path(instance_path)
    if not instance_root.is_dir():
        raise ValueError(f"instance is not a directory: {instance_root}")
    lock = _load_lock(instance_root)
    instance_data = _read_mapping(_safe_file(instance_root, "instance.yaml", "instance.yaml"), "instance.yaml")
    try:
        instance = Instance.from_dict(instance_data)
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError(f"invalid instance.yaml: {exc}") from exc
    if lock.get("instanceId") != instance.metadata.id:
        raise ValueError("lock instanceId does not match instance.yaml")

    template_root = _template_root(instance_root, lock, template_path)
    manifest = load_template_manifest(template_root)
    if lock["template"].get("id") != manifest["templateId"]:
        raise ValueError("lock template id does not match manifest")
    # Lifecycle locks expand template-owned tree declarations into their
    # concrete files. StateIR must use the same expanded ownership view or a
    # valid tree-backed template will be rejected as a false lock mismatch.
    manifest_files = _all_manifest_files(template_root, manifest)
    lock_files = {
        item.get("path"): item for item in lock["files"] if isinstance(item, dict)
    }
    if set(manifest_files) != set(lock_files):
        raise ValueError("lock and manifest file ownership sets do not match")
    for path, item in manifest_files.items():
        locked = lock_files[path]
        for field in ("owner", "merge", "required", "sensitivity"):
            if field == "owner" and _lock_owner_matches_manifest(item, locked.get(field)):
                continue
            if locked.get(field) != item.get(field):
                raise ValueError(f"lock and manifest disagree for {path}: {field}")
    locked_revision = lock["template"].get("sourceRevision")
    source_description = describe_template_source(template_root)
    current_revision = source_description.get(
        "identity", source_description.get("sourceDigest")
    )
    if not isinstance(current_revision, str):
        raise ValueError("template source descriptor has no revision")
    stale = locked_revision != current_revision
    operator_input = (
        operator_allowed_sensitivities
        if operator_allowed_sensitivities is not None
        else allowed_sensitivities
    )
    template_policy = set(
        _ALL_SENSITIVITIES if template_sensitivities is None else template_sensitivities
    )
    instance_policy = set(
        _ALL_SENSITIVITIES
        if instance_granted_sensitivities is None
        else instance_granted_sensitivities
    )
    operator_policy = set(
        _DEFAULT_SENSITIVITIES if operator_input is None else operator_input
    )
    invalid = (template_policy | instance_policy | operator_policy) - _ALL_SENSITIVITIES
    if invalid:
        raise ValueError(f"unsupported sensitivities: {sorted(invalid)}")
    allowed = template_policy & instance_policy & operator_policy

    source_hashes: dict[str, str] = {}
    facts: list[StateFact] = []
    included: list[str] = []
    excluded: list[str] = []
    for item in manifest_files.values():
        relative = item["path"]
        if relative == ".statedd/lock.yaml" or item["owner"] == "generated":
            continue
        target_candidate = instance_root / relative
        if not target_candidate.exists():
            if item["required"]:
                raise ValueError(f"required canonical source is missing: {relative}")
            excluded.append(relative)
            continue
        target = _safe_file(instance_root, relative, f"instance source {relative}")
        source_hashes[relative] = _sha256(target)
        if item["sensitivity"] not in allowed:
            excluded.append(relative)
            continue
        if Path(relative).suffix.lower() not in {".yaml", ".yml", ".md", ".markdown", ".txt"}:
            # Lifecycle ownership may cover binaries, shell scripts, and
            # extensionless operator files. They remain hashed for provenance
            # but are not canonical StateIR value sources.
            excluded.append(relative)
            continue
        included.append(relative)
        facts.extend(_decode_file(target, relative, item["sensitivity"]))

    return StateIR(
        instance_id=instance.metadata.id,
        source_revision=str(locked_revision or current_revision),
        source_hashes=dict(sorted(source_hashes.items())),
        facts=tuple(sorted(facts, key=lambda fact: (fact.path, fact.id))),
        included_files=tuple(sorted(included)),
        excluded_files=tuple(sorted(excluded)),
        stale=stale,
    )


__all__ = [
    "STATEIR_FORMAT",
    "SourceRef",
    "StateFact",
    "StateIR",
    "build_state_ir",
]
