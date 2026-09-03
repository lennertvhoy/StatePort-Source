"""Read-only validation of StudyDD's generated compatibility views.

StudyDD keeps ``instance.yaml``, ``.statedd/lock.yaml``, and the two
``STATE_MANIFEST`` fragments authoritative.  The three files under
``state/`` are a compatibility surface for existing StudyDD consumers.  This
adapter validates that surface without importing StudyDD or executing its
generator.

The manifest projection is intentionally explicit: only the documented
top-level and file-entry fields are copied from the template base and the
instance overlay.  It is not a general-purpose YAML merge engine.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

STUDYDD_VIEW_FORMAT = "stateport.studydd-compatibility-view/v1"
STUDYDD_GENERATOR = "scripts/generate_compatibility_views.py"
MODE_VIEW = "state/STUDYDD_MODE.yaml"
VERSION_VIEW = "state/STUDYDD_TEMPLATE_VERSION.yaml"
MANIFEST_VIEW = "state/STATE_MANIFEST.yaml"
MANIFEST_BASE = "state/STATE_MANIFEST.template.yaml"
MANIFEST_OVERLAY = "state/STATE_MANIFEST.instance.yaml"
AUTHORITATIVE_INPUTS = (
    "instance.yaml",
    ".statedd/lock.yaml",
    MANIFEST_BASE,
    MANIFEST_OVERLAY,
)
COMPATIBILITY_VIEW_PATHS = frozenset({MODE_VIEW, VERSION_VIEW, MANIFEST_VIEW})

_MANIFEST_TOP_LEVEL_KEYS = {"manifest_version", "last_updated", "files"}
_MANIFEST_OVERLAY_KEYS = {"files", "extensions"}
_MANIFEST_ENTRY_KEYS = {
    "role",
    "load_default",
    "protected",
    "indexed_by",
    "summarized_by",
    "generated_by",
    "gitignore",
    "owner",
    "boundary",
}
_BOUNDARIES = {"template", "instance", "generated"}
_VIEW_METADATA_KEYS = {"schema_version", "view_version", "source_digest"}
_VIEW_SCHEMA = "studydd.compatibility-view/v1"


class CompatibilityViewError(ValueError):
    """Raised when a StudyDD view or one of its authorities is unsafe."""


def _safe_relative_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or value.startswith("/") or "\\" in value:
        raise CompatibilityViewError(f"{label} must be a relative POSIX path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise CompatibilityViewError(f"{label} contains an unsafe path component")
    return value


def _required_string(parent: dict[str, Any], key: str, label: str) -> str:
    value = parent.get(key)
    if not isinstance(value, str) or not value.strip():
        raise CompatibilityViewError(f"{label}.{key} must be a non-empty string")
    return value


def _optional_string(parent: dict[str, Any], key: str, label: str) -> str:
    value = parent.get(key, "")
    if value is None:
        return ""
    if not isinstance(value, str):
        raise CompatibilityViewError(f"{label}.{key} must be a string when present")
    return value


def _portable_path(value: str) -> str:
    if value.startswith("/") or re.match(r"^[A-Za-z]:[/\\]", value):
        return ""
    return value.replace("\\", "/")


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CompatibilityViewError(f"{label} must be a mapping")
    return value


def _normalize_indentless_sequences(text: str) -> str:
    """Make StudyDD's valid indentless lists readable by StateDD's strict parser."""
    lines = text.splitlines()
    normalized: list[str] = []
    sequence_indent: int | None = None
    for line in lines:
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))
        if sequence_indent is not None:
            if stripped.startswith("-") and indent == sequence_indent:
                normalized.append("  " + line)
                continue
            sequence_indent = None
        normalized.append(line)
        if re.match(r"^\s*[^:#][^:]*:\s*$", line):
            sequence_indent = indent
    return "\n".join(normalized)


def _read_mapping(root: Path, relative: str) -> dict[str, Any]:
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise CompatibilityViewError(f"{relative} must be a regular file")
    try:
        # Keep the older JSON-only compatibility adapter importable without
        # the StatePort core package.  Generated-view loading uses the core's
        # strict parser only when this feature is invoked.
        from statedd_core.yaml import StateDDYamlError, parse_yaml_text

        text = path.read_text(encoding="utf-8")
        # The StateDD parser deliberately accepts a small YAML subset.  YAML
        # document markers carry no data and are safe to discard here.
        text = "\n".join(
            line for line in text.splitlines() if line.strip() not in {"---", "..."}
        )
        try:
            value = parse_yaml_text(text)
        except StateDDYamlError:
            # StudyDD's generator uses the YAML-legal form ``modules:\n- x``.
            # Normalize only that presentation detail; the parsed structure
            # still goes through StateDD's duplicate-key and scalar checks.
            value = parse_yaml_text(_normalize_indentless_sequences(text))
    except ModuleNotFoundError as exc:
        raise CompatibilityViewError(
            "generated-view loading requires the StatePort core YAML parser"
        ) from exc
    except (OSError, UnicodeDecodeError, StateDDYamlError) as exc:
        raise CompatibilityViewError(f"could not read YAML {relative}: {exc}") from exc
    return _mapping(value, relative)


def _digest_sources(root: Path, paths: Iterable[str]) -> str:
    def normalize(value: Any, key: str = "") -> Any:
        if isinstance(value, dict):
            return {name: normalize(value[name], name) for name in sorted(value)}
        if isinstance(value, list):
            return [normalize(item, key) for item in value]
        if isinstance(value, str) and key in {"path", "sourcePath", "checkoutLocation", "template_source_path"}:
            if value.startswith("/") or re.match(r"^[A-Za-z]:[/\\]", value):
                return ""
            return value.replace("\\", "/")
        return value

    values: list[dict[str, Any]] = []
    for relative in sorted(paths):
        value = _read_mapping(root, relative)
        values.append({"path": relative, "value": normalize(value)})
    encoded = json.dumps(values, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _file_digest(root: Path, relative: str) -> str:
    try:
        return "sha256:" + hashlib.sha256((root / relative).read_bytes()).hexdigest()
    except OSError as exc:
        raise CompatibilityViewError(f"could not read generated view {relative}: {exc}") from exc


def _expected_mode(data: dict[str, Any]) -> dict[str, Any]:
    spec = _mapping(data.get("spec"), "instance.yaml.spec")
    mode = _required_string(spec, "mode", "instance.yaml.spec")
    if mode not in {"template", "bootstrap", "learner_instance"}:
        raise CompatibilityViewError(f"instance.yaml.spec.mode is unsupported: {mode!r}")
    origin = spec.get("templateOrigin", spec.get("templateRemote", ""))
    if not isinstance(origin, str):
        raise CompatibilityViewError("instance.yaml.spec.templateOrigin must be a string")
    personalized = spec.get("personalized")
    public_safe = spec.get("publicSafe")
    if not isinstance(personalized, bool) or not isinstance(public_safe, bool):
        raise CompatibilityViewError(
            "instance.yaml.spec.personalized and publicSafe must be booleans"
        )
    result: dict[str, Any] = {
        "mode": mode,
        "template_remote": origin,
        "personalized": personalized,
        "public_safe": public_safe,
    }
    modules = spec.get("modules")
    if modules is not None:
        if not isinstance(modules, list) or any(not isinstance(item, str) for item in modules):
            raise CompatibilityViewError("instance.yaml.spec.modules must be a list of strings")
        if len(set(modules)) != len(modules):
            raise CompatibilityViewError("instance.yaml.spec.modules must not contain duplicates")
        result["modules"] = copy.deepcopy(modules)
    return result


def _expected_version(data: dict[str, Any]) -> dict[str, Any]:
    template = _mapping(data.get("template"), ".statedd/lock.yaml.template")
    instance = data.get("instance", {})
    if not isinstance(instance, dict):
        raise CompatibilityViewError(".statedd/lock.yaml.instance must be a mapping")
    source_revision = _optional_string(template, "sourceRevision", ".statedd/lock.yaml.template")
    release_status = _optional_string(template, "releaseStatus", ".statedd/lock.yaml.template")
    source = template.get("source")
    if source is not None and not isinstance(source, dict):
        raise CompatibilityViewError(".statedd/lock.yaml.template.source must be a mapping")
    descriptor_digest = _optional_string(source or {}, "sourceDigest", ".statedd/lock.yaml.template.source")
    created_version = _optional_string(instance, "createdFromTemplateVersion", ".statedd/lock.yaml.instance")
    created_commit = _optional_string(instance, "createdFromTemplateCommit", ".statedd/lock.yaml.instance")
    result = {
        "template_version": _required_string(template, "version", ".statedd/lock.yaml.template"),
        "template_commit": _optional_string(template, "sourceCommit", ".statedd/lock.yaml.template")
        or source_revision,
        "template_source_digest": source_revision or descriptor_digest,
        "template_source_path": _portable_path(_optional_string(template, "sourcePath", ".statedd/lock.yaml.template")),
        "instance_created_from_template_version": created_version,
        "instance_created_from_template_commit": created_commit,
        "instance_created_from_template_source": {
            "origin": _portable_path(_optional_string(template, "sourcePath", ".statedd/lock.yaml.template")),
            "version": created_version,
            "commit": created_commit,
            "digest": source_revision or descriptor_digest,
        },
        "last_template_upgrade_version": _optional_string(
            instance, "lastTemplateUpgradeVersion", ".statedd/lock.yaml.instance"
        ),
        "last_template_upgrade_commit": _optional_string(
            instance, "lastTemplateUpgradeCommit", ".statedd/lock.yaml.instance"
        ),
    }
    history = instance.get("upgradeHistory", [])
    if not isinstance(history, list):
        raise CompatibilityViewError(".statedd/lock.yaml.instance.upgradeHistory must be a list")
    result["upgrade_history"] = copy.deepcopy(history)
    if release_status:
        result["release_status"] = release_status
    return result


def _validate_manifest_entry(path: str, value: Any, source: str) -> dict[str, Any]:
    _safe_relative_path(path, f"{source}.files path")
    entry = _mapping(value, f"{source}.files[{path!r}]")
    unknown = set(entry) - _MANIFEST_ENTRY_KEYS
    if unknown:
        raise CompatibilityViewError(
            f"{source}.files[{path!r}] has unknown key(s): {', '.join(sorted(unknown))}"
        )
    for field in ("owner", "boundary"):
        if field in entry and entry[field] not in _BOUNDARIES:
            raise CompatibilityViewError(
                f"{source}.files[{path!r}].{field} has unsupported value {entry[field]!r}"
            )
    if "owner" in entry and "boundary" in entry and entry["owner"] != entry["boundary"]:
        raise CompatibilityViewError(
            f"{source}.files[{path!r}] has conflicting owner and boundary"
        )
    return copy.deepcopy(entry)


def _expected_manifest(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    unknown_base = set(base) - _MANIFEST_TOP_LEVEL_KEYS
    unknown_overlay = set(overlay) - _MANIFEST_OVERLAY_KEYS
    if unknown_base:
        raise CompatibilityViewError(
            "state/STATE_MANIFEST.template.yaml has unknown top-level key(s): "
            + ", ".join(sorted(unknown_base))
        )
    if unknown_overlay:
        raise CompatibilityViewError(
            "state/STATE_MANIFEST.instance.yaml has unknown top-level key(s): "
            + ", ".join(sorted(unknown_overlay))
        )
    base_files = _mapping(base.get("files"), "state/STATE_MANIFEST.template.yaml.files")
    overlay_files = overlay.get("files", {})
    if not isinstance(overlay_files, dict):
        raise CompatibilityViewError("state/STATE_MANIFEST.instance.yaml.files must be a mapping")

    files: dict[str, dict[str, Any]] = {}
    for path in sorted(base_files):
        files[path] = _validate_manifest_entry(path, base_files[path], MANIFEST_BASE)
    for path in sorted(overlay_files):
        overlay_entry = _validate_manifest_entry(path, overlay_files[path], MANIFEST_OVERLAY)
        if path in files:
            # Explicit field assignment is the compatibility contract.  No
            # nested mapping is merged, and unknown fields were rejected above.
            for field in sorted(_MANIFEST_ENTRY_KEYS):
                if field in overlay_entry:
                    files[path][field] = overlay_entry[field]
        else:
            missing = {"role", "owner", "boundary"} - set(overlay_entry)
            if missing:
                raise CompatibilityViewError(
                    f"{MANIFEST_OVERLAY}.files[{path!r}] is missing key(s): "
                    + ", ".join(sorted(missing))
                )
            files[path] = overlay_entry

    result: dict[str, Any] = {}
    for field in ("manifest_version", "last_updated"):
        if field in base:
            result[field] = copy.deepcopy(base[field])
    result["generated_by"] = STUDYDD_GENERATOR
    result["files"] = files
    base_extensions = base.get("extensions", {})
    overlay_extensions = overlay.get("extensions", {})
    if not isinstance(base_extensions, dict) or not isinstance(overlay_extensions, dict):
        raise CompatibilityViewError("manifest extensions must be mappings")
    extensions = copy.deepcopy(base_extensions)
    for key, value in sorted(overlay_extensions.items()):
        if key in extensions and extensions[key] != value:
            raise CompatibilityViewError(f"manifest extension conflict: {key}")
        extensions[key] = copy.deepcopy(value)
    if extensions:
        result["extensions"] = extensions
    return result


def _assert_view_matches(relative: str, actual: dict[str, Any], expected: dict[str, Any]) -> None:
    if actual != expected:
        raise CompatibilityViewError(
            f"generated view {relative} is stale, manually modified, or conflicts with its authority"
        )


def _view_payload(actual: dict[str, Any], relative: str, source_digest: str) -> dict[str, Any]:
    if actual.get("schema_version") != _VIEW_SCHEMA or actual.get("view_version") != 1:
        raise CompatibilityViewError(f"generated view {relative} has an unsupported schema")
    if actual.get("source_digest") != source_digest:
        raise CompatibilityViewError(f"generated view {relative} has a conflicting source digest")
    return {key: value for key, value in actual.items() if key not in _VIEW_METADATA_KEYS}


def _validate_generated_manifest(manifest: dict[str, Any]) -> None:
    files = _mapping(manifest.get("files"), f"{MANIFEST_VIEW}.files")
    for path in COMPATIBILITY_VIEW_PATHS:
        entry = files.get(path)
        if not isinstance(entry, dict):
            raise CompatibilityViewError(f"{MANIFEST_VIEW} does not classify {path}")
        if entry.get("owner") != "generated" or entry.get("boundary") != "generated":
            raise CompatibilityViewError(f"{MANIFEST_VIEW} conflicts with generated ownership for {path}")
        if entry.get("generated_by") != STUDYDD_GENERATOR:
            raise CompatibilityViewError(f"{MANIFEST_VIEW} has an unsupported generator for {path}")


def _validate_ejections(manifest: dict[str, Any], ejected_paths: Iterable[str]) -> tuple[str, ...]:
    files = _mapping(manifest.get("files"), f"{MANIFEST_VIEW}.files")
    normalized: list[str] = []
    for value in ejected_paths:
        path = _safe_relative_path(value, "ejection path")
        if path in COMPATIBILITY_VIEW_PATHS:
            raise CompatibilityViewError(f"generated compatibility view cannot be ejected: {path}")
        entry = files.get(path)
        if entry is None or entry.get("owner") != "template" or entry.get("boundary") != "template":
            raise CompatibilityViewError(
                f"ejection must name a template-owned exact file: {path}"
            )
        normalized.append(path)
    if len(set(normalized)) != len(normalized):
        raise CompatibilityViewError("ejection paths must not contain duplicates")
    return tuple(sorted(normalized))


@dataclass(frozen=True)
class StudyDDCompatibilityViews:
    """Validated, StatePort-owned projection of StudyDD compatibility views."""

    mode: dict[str, Any]
    template_version: dict[str, Any]
    manifest: dict[str, Any]
    source_digest: str
    view_digests: tuple[tuple[str, str], ...]
    ejections: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": STUDYDD_VIEW_FORMAT,
            "adapter": "stateport.studydd-generated-views/1",
            "sourceDigest": self.source_digest,
            "viewDigests": {path: digest for path, digest in self.view_digests},
            "ejections": list(self.ejections),
            "views": {
                MODE_VIEW: copy.deepcopy(self.mode),
                VERSION_VIEW: copy.deepcopy(self.template_version),
                MANIFEST_VIEW: copy.deepcopy(self.manifest),
            },
        }


def load_studydd_compatibility_views(
    root: Path | str, *, ejected_paths: Iterable[str] = ()
) -> StudyDDCompatibilityViews:
    """Load and validate StudyDD generated views without writing any file.

    The returned ``source_digest`` binds the four authoritative inputs.  View
    bytes are reported separately so callers can cache or audit the exact
    generated artifacts without treating them as lifecycle truth.
    """

    project = Path(root)
    authorities = {relative: _read_mapping(project, relative) for relative in AUTHORITATIVE_INPUTS}
    expected_mode = _expected_mode(authorities["instance.yaml"])
    expected_version = _expected_version(authorities[".statedd/lock.yaml"])
    expected_manifest = _expected_manifest(
        authorities[MANIFEST_BASE], authorities[MANIFEST_OVERLAY]
    )

    actual_mode = _read_mapping(project, MODE_VIEW)
    actual_version = _read_mapping(project, VERSION_VIEW)
    actual_manifest = _read_mapping(project, MANIFEST_VIEW)
    source_digests = {actual.get("source_digest") for actual in (actual_mode, actual_version, actual_manifest)}
    if len(source_digests) != 1 or not next(iter(source_digests), "").startswith("sha256:"):
        raise CompatibilityViewError("generated views do not share one valid source digest")
    source_digest = next(iter(source_digests))
    _assert_view_matches(MODE_VIEW, _view_payload(actual_mode, MODE_VIEW, source_digest), expected_mode)
    version_payload = _view_payload(actual_version, VERSION_VIEW, source_digest)
    # Older instances may have a generated view from before the explicit
    # source-digest projection was introduced; preserve read compatibility
    # while requiring the new fields whenever the authority/view supports it.
    for optional in ("template_source_digest", "instance_created_from_template_source"):
        if optional not in version_payload:
            expected_version.pop(optional, None)
    _assert_view_matches(VERSION_VIEW, version_payload, expected_version)
    _assert_view_matches(MANIFEST_VIEW, _view_payload(actual_manifest, MANIFEST_VIEW, source_digest), expected_manifest)
    _validate_generated_manifest(actual_manifest)
    ejections = _validate_ejections(actual_manifest, ejected_paths)

    return StudyDDCompatibilityViews(
        mode=copy.deepcopy(actual_mode),
        template_version=copy.deepcopy(actual_version),
        manifest=copy.deepcopy(actual_manifest),
        source_digest=source_digest,
        view_digests=tuple(
            (relative, _file_digest(project, relative))
            for relative in sorted(COMPATIBILITY_VIEW_PATHS)
        ),
        ejections=ejections,
    )


# Short aliases keep the adapter convenient for lifecycle callers while the
# longer name remains the contract-facing API.
validate_studydd_compatibility_views = load_studydd_compatibility_views
map_studydd_views_to_stateport = load_studydd_compatibility_views
