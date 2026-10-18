from __future__ import annotations

import copy
import difflib
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any, Mapping


BUNDLE_FORMAT = "stateport.contribution-bundle/v2"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SECRET_LIKE = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|secret|credential)\b\s*[:=]\s*[\"']?[A-Za-z0-9_./+=:-]{16,}"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
)


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def content_digest(value: bytes | bytearray | str) -> str:
    """Return the content digest used by the v2 bundle contract."""

    if isinstance(value, str):
        value = value.encode("utf-8")
    return _sha256(bytes(value))


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def bundle_digest(bundle: Mapping[str, Any]) -> str:
    """Digest a bundle excluding its self-referential ``bundleDigest`` field."""

    payload = copy.deepcopy(dict(bundle))
    payload.pop("bundleDigest", None)
    return _sha256(_canonical(payload))


def _safe_path(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError(f"{field} must be a non-empty POSIX relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"{field} must be a normalized relative path")
    return path.as_posix()


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError(f"{field} must be a sha256 digest")
    return value


def _read_structured(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if text.lstrip().startswith(("{", "[")):
        return json.loads(text)
    try:
        from statedd_core.yaml import parse_yaml_text

        return parse_yaml_text(text)
    except ImportError:
        return json.loads(path.read_text(encoding="utf-8"))


def _file(root: Path, relative: str, field: str) -> Path:
    path = root / relative
    if path.is_symlink():
        raise ValueError(f"{field} is symlinked")
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{field} escapes its root") from exc
    if not path.is_file():
        raise ValueError(f"{field} is not a regular file")
    return path


def _tree_files(root: Path) -> list[tuple[str, bytes]]:
    if not root.is_dir() or root.is_symlink():
        raise ValueError("tree root must be a real directory")
    records: list[tuple[str, bytes]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if relative == ".git" or relative.startswith(".git/"):
            continue
        if path.is_symlink():
            raise ValueError(f"tree contains symlink: {relative}")
        if path.is_file():
            records.append((relative, path.read_bytes()))
        elif not path.is_dir():
            raise ValueError(f"tree contains unsupported entry: {relative}")
    return records


def tree_digest(root: Path | str, replacements: Mapping[str, bytes] | None = None) -> str:
    """Digest a tree by normalized path and bytes, without following symlinks."""

    root_path = Path(root).resolve()
    records = dict(_tree_files(root_path))
    for relative, value in (replacements or {}).items():
        records[_safe_path(relative, "replacement path")] = bytes(value)
    encoded = b"".join(
        relative.encode("utf-8") + b"\0" + content_digest(value).encode("ascii") + b"\n"
        for relative, value in sorted(records.items())
    )
    return _sha256(encoded)


def _source_descriptor(root: Path) -> dict[str, Any]:
    try:
        from statedd_core.lifecycle import describe_template_source

        return dict(describe_template_source(root))
    except (ImportError, ValueError):
        manifest = root / ".statedd" / "manifest.yaml"
        return {
            "formatVersion": "stateport.source/v1",
            "kind": "local",
            "sourceClass": "synthetic_fixture",
            "productionEligible": False,
            "sourceDigest": tree_digest(root),
            "manifestDigest": content_digest(manifest.read_bytes()) if manifest.is_file() else None,
        }


def _source_matches(expected: Mapping[str, Any], actual: Mapping[str, Any], field: str, issues: list[str]) -> None:
    for key in (
        "formatVersion",
        "kind",
        "sourceClass",
        "productionEligible",
        "repository",
        "requestedRef",
        "resolvedCommit",
        "resolvedTree",
        "manifestDigest",
        "sourceDigest",
    ):
        if key in expected and expected.get(key) != actual.get(key):
            issues.append(f"{field}.{key} does not match the inspected source")


def _lock_asset(lock: Mapping[str, Any], path: str) -> Mapping[str, Any] | None:
    files = lock.get("files")
    if isinstance(files, list):
        for entry in files:
            if isinstance(entry, Mapping) and entry.get("path") == path:
                return entry
    trees = lock.get("trees")
    if isinstance(trees, list):
        candidates: list[Mapping[str, Any]] = []
        for entry in trees:
            if not isinstance(entry, Mapping) or not isinstance(entry.get("path"), str):
                continue
            root = entry["path"].rstrip("/")
            if path == root or path.startswith(root + "/"):
                candidates.append(entry)
        if candidates:
            return max(candidates, key=lambda entry: len(str(entry["path"])))
    return None


def _secret_like(value: str) -> bool:
    return any(pattern.search(value) for pattern in _SECRET_LIKE)


def _apply_patch(original: bytes, patch: str, path: str) -> bytes:
    """Apply one strict, text-only unified diff in memory."""

    if "\r" in patch:
        raise ValueError("patch must use LF line endings")
    if not patch.startswith(f"--- a/{path}\n+++ b/{path}\n"):
        raise ValueError("patch headers do not name the selected path exactly")
    original_lines = original.decode("utf-8").splitlines(keepends=True)
    lines = patch.splitlines(keepends=True)
    if len(lines) < 3:
        raise ValueError("patch has no hunks")
    result: list[str] = []
    cursor = 0
    index = 2
    while index < len(lines):
        header = lines[index]
        match = re.fullmatch(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@.*\n", header)
        if not match:
            raise ValueError("patch contains an invalid hunk header")
        old_start = int(match.group(1)) - 1
        if old_start < cursor or old_start > len(original_lines):
            raise ValueError("patch hunk is out of range")
        result.extend(original_lines[cursor:old_start])
        cursor = old_start
        index += 1
        while index < len(lines) and not lines[index].startswith("@@ "):
            line = lines[index]
            if line.startswith("\\ No newline at end of file"):
                index += 1
                continue
            if not line:
                raise ValueError("patch contains an empty hunk line")
            marker, text = line[0], line[1:]
            if marker == " ":
                if cursor >= len(original_lines) or original_lines[cursor] != text:
                    raise ValueError("patch context does not match the synthetic baseline")
                result.append(text)
                cursor += 1
            elif marker == "-":
                if cursor >= len(original_lines) or original_lines[cursor] != text:
                    raise ValueError("patch removal does not match the synthetic baseline")
                cursor += 1
            elif marker == "+":
                result.append(text)
            else:
                raise ValueError("patch contains an unsupported hunk line")
            index += 1
    result.extend(original_lines[cursor:])
    return "".join(result).encode("utf-8")


def _issue(issues: list[str], message: str) -> None:
    issues.append(message)


def validate_bundle(
    bundle: Mapping[str, Any],
    *,
    instance_root: Path | str,
    source_root: Path | str,
    baseline_root: Path | str,
    synthetic_root: Path | str,
) -> dict[str, Any]:
    """Validate a v2 bundle without mutating any supplied root.

    ``source_root`` is the exact checkout named by the instance lock;
    ``baseline_root`` is the exact historical source baseline; and
    ``synthetic_root`` is a separate clean, invented fixture. All patch
    application happens in memory and the returned report is non-authoritative.
    """

    issues: list[str] = []
    if not isinstance(bundle, Mapping):
        return {"valid": False, "issues": ["bundle must be a mapping"], "automaticApply": False, "upstreamApplied": False}
    if bundle.get("formatVersion") != BUNDLE_FORMAT:
        _issue(issues, f"formatVersion must be {BUNDLE_FORMAT}")
    if bundle.get("automaticApply") is not False:
        _issue(issues, "automaticApply must be false")
    if bundle.get("upstreamApplied") is not False:
        _issue(issues, "upstreamApplied must be false")
    declared_digest = bundle.get("bundleDigest")
    if not isinstance(declared_digest, str) or declared_digest != bundle_digest(bundle):
        _issue(issues, "bundleDigest does not match the exact bundle document")

    instance = Path(instance_root).resolve()
    source = Path(source_root).resolve()
    baseline = Path(baseline_root).resolve()
    synthetic = Path(synthetic_root).resolve()
    if len({instance, source, baseline, synthetic}) != 4:
        _issue(issues, "instance, source, baseline, and synthetic roots must be distinct")

    lock_record = bundle.get("lock")
    lock_document: Mapping[str, Any] | None = None
    lock_path = instance / ".statedd" / "lock.yaml"
    try:
        if not isinstance(lock_record, Mapping):
            raise ValueError("lock must be a mapping")
        lock_document = lock_record.get("document")
        if not isinstance(lock_document, Mapping):
            raise ValueError("lock.document must be a mapping")
        lock_file = _file(instance, ".statedd/lock.yaml", "instance lock")
        if _digest(lock_record.get("digest"), "lock.digest") != content_digest(lock_file.read_bytes()):
            raise ValueError("lock.digest does not match the exact lock bytes")
        actual_lock = _read_structured(lock_path)
        if actual_lock != dict(lock_document):
            raise ValueError("lock.document is not the exact instance lock")
    except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        _issue(issues, str(exc))

    template = lock_document.get("template") if lock_document else None
    lock_source = template.get("source") if isinstance(template, Mapping) else None
    if not isinstance(template, Mapping):
        _issue(issues, "lock.template must be a mapping")
        template = {}
    if not isinstance(lock_source, Mapping):
        _issue(issues, "lock.template.source must be a mapping")
        lock_source = {}
    if bundle.get("templateId") != template.get("id"):
        _issue(issues, "templateId does not match the exact lock")
    source_record = bundle.get("source")
    if not isinstance(source_record, Mapping) or dict(source_record) != dict(lock_source):
        _issue(issues, "source must exactly reproduce lock.template.source")

    try:
        actual_source = _source_descriptor(source)
        _source_matches(lock_source, actual_source, "source", issues)
        actual_baseline = _source_descriptor(baseline)
        _source_matches(lock_source, actual_baseline, "baseline", issues)
        if lock_source.get("checkoutLocation") and Path(str(lock_source["checkoutLocation"])).resolve() != source:
            _issue(issues, "locked source checkoutLocation does not name source_root")
    except (OSError, ValueError, KeyError) as exc:
        _issue(issues, str(exc))

    try:
        expected_baseline = bundle.get("baseline")
        if not isinstance(expected_baseline, Mapping):
            raise ValueError("baseline must be a mapping")
        _digest(expected_baseline.get("rootDigest"), "baseline.rootDigest")
        if expected_baseline.get("rootDigest") != tree_digest(baseline):
            raise ValueError("baseline.rootDigest does not match the exact baseline tree")
        if expected_baseline.get("sourceDigest") != lock_source.get("sourceDigest"):
            raise ValueError("baseline.sourceDigest does not match the locked source")
        if expected_baseline.get("templateId") != template.get("id"):
            raise ValueError("baseline.templateId does not match the exact lock")
    except (OSError, ValueError) as exc:
        _issue(issues, str(exc))

    selected = bundle.get("selectedPaths")
    selected_entries: list[Mapping[str, Any]] = []
    if not isinstance(selected, list) or not selected:
        _issue(issues, "selectedPaths must be a non-empty list")
    else:
        previous = ""
        seen: set[str] = set()
        for index, raw in enumerate(selected):
            try:
                if not isinstance(raw, Mapping):
                    raise ValueError(f"selectedPaths[{index}] must be a mapping")
                path = _safe_path(raw.get("path"), f"selectedPaths[{index}].path")
                if path in seen:
                    raise ValueError(f"selectedPaths contains duplicate path {path}")
                if path <= previous:
                    raise ValueError("selectedPaths must be sorted and explicitly selected")
                previous = path
                seen.add(path)
                selected_entries.append(raw)
            except ValueError as exc:
                _issue(issues, str(exc))

    replacements: dict[str, bytes] = {}
    reproduction_records: dict[str, Mapping[str, Any]] = {}
    reproduction = bundle.get("reproduction")
    if not isinstance(reproduction, Mapping):
        _issue(issues, "reproduction must be a mapping")
        reproduction = {}
    if reproduction.get("clean") is not True:
        _issue(issues, "reproduction.clean must be true")
    if reproduction.get("sourceClass") != "synthetic_fixture" or reproduction.get("productionEligible") is not False:
        _issue(issues, "reproduction must identify a non-production synthetic fixture")
    try:
        synthetic_root_digest = tree_digest(synthetic)
        if reproduction.get("baselineRootDigest") != synthetic_root_digest:
            raise ValueError("reproduction.baselineRootDigest does not match the clean synthetic tree")
    except (OSError, ValueError) as exc:
        _issue(issues, str(exc))
    raw_reproduction_paths = reproduction.get("paths")
    if isinstance(raw_reproduction_paths, list):
        for raw in raw_reproduction_paths:
            if isinstance(raw, Mapping) and isinstance(raw.get("path"), str):
                reproduction_records[raw["path"]] = raw
    else:
        _issue(issues, "reproduction.paths must be a list")

    for index, entry in enumerate(selected_entries):
        try:
            path = _safe_path(entry.get("path"), f"selectedPaths[{index}].path")
            asset = _lock_asset(lock_document or {}, path)
            if asset is None:
                raise ValueError(f"selected path is unknown to the exact lock: {path}")
            if asset.get("owner") != "template":
                raise ValueError(f"selected path is not template-owned: {path}")
            if asset.get("sensitivity") != "public":
                raise ValueError(f"selected path is not public-safe: {path}")
            if asset.get("generator") or asset.get("provision") in {"generated", "generated_output"} or asset.get("provisionPolicy") == "generated_output":
                raise ValueError(f"generated content is structurally excluded: {path}")
            if entry.get("owner") != "template" or entry.get("sensitivity") != "public":
                raise ValueError(f"selected path ownership/sensitivity is not an exact public template claim: {path}")
            provenance = entry.get("provenance")
            if not isinstance(provenance, Mapping):
                raise ValueError(f"provenance is required: {path}")
            if provenance.get("authority") != "locked_template_source":
                raise ValueError(f"provenance authority is not lock-bound: {path}")
            if provenance.get("sourceRevision") != template.get("sourceRevision"):
                raise ValueError(f"provenance sourceRevision does not match lock: {path}")
            source_path = _safe_path(provenance.get("sourcePath"), f"provenance.sourcePath for {path}")
            expected_source_path = str(asset.get("source") or asset.get("path") or path)
            if source_path != expected_source_path:
                raise ValueError(f"provenance sourcePath is not the declared source path: {path}")
            if provenance.get("baselineRootDigest") != bundle.get("baseline", {}).get("rootDigest"):
                raise ValueError(f"provenance baselineRootDigest is not exact: {path}")
            baseline_file = _file(baseline, source_path, f"baseline content {path}")
            instance_file = _file(instance, path, f"instance content {path}")
            baseline_bytes = baseline_file.read_bytes()
            instance_bytes = instance_file.read_bytes()
            if entry.get("baselineContentDigest") != content_digest(baseline_bytes):
                raise ValueError(f"baseline content digest does not match: {path}")
            if entry.get("contentDigest") != content_digest(instance_bytes):
                raise ValueError(f"content digest does not match the selected instance content: {path}")
            patch = entry.get("patch")
            if not isinstance(patch, str) or not patch:
                raise ValueError(f"patch is required: {path}")
            if _secret_like(patch):
                raise ValueError(f"secret-like content is structurally excluded: {path}")
            if entry.get("patchDigest") != content_digest(patch):
                raise ValueError(f"patchDigest does not match: {path}")
            reproduced = _apply_patch(baseline_bytes, patch, source_path)
            if reproduced != instance_bytes:
                raise ValueError(f"patch does not reproduce the selected content: {path}")
            synthetic_record = reproduction_records.get(path)
            if synthetic_record is None:
                raise ValueError(f"clean reproduction is missing selected path: {path}")
            synthetic_file = _file(synthetic, path, f"synthetic content {path}")
            synthetic_bytes = synthetic_file.read_bytes()
            if synthetic_record.get("baselineContentDigest") != content_digest(synthetic_bytes):
                raise ValueError(f"synthetic baseline digest does not match: {path}")
            synthetic_result = _apply_patch(synthetic_bytes, patch, path)
            if synthetic_record.get("resultContentDigest") != content_digest(synthetic_result):
                raise ValueError(f"synthetic result digest does not match: {path}")
            replacements[path] = synthetic_result
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            _issue(issues, str(exc))

    if set(reproduction_records) != {entry.get("path") for entry in selected_entries if isinstance(entry.get("path"), str)}:
        _issue(issues, "synthetic reproduction paths must exactly equal selected paths")
    try:
        if reproduction.get("resultRootDigest") != tree_digest(synthetic, replacements):
            _issue(issues, "reproduction.resultRootDigest does not match the in-memory clean reproduction")
    except (OSError, ValueError) as exc:
        _issue(issues, str(exc))

    return {
        "formatVersion": "stateport.contribution-validation/v1",
        "valid": not issues,
        "issues": issues,
        "automaticApply": False,
        "upstreamApplied": False,
        "selectedPaths": [entry.get("path") for entry in selected_entries],
        "bundleDigest": declared_digest,
    }


def make_patch(path: str, before: bytes, after: bytes) -> str:
    """Small test/helper utility for deterministic one-file unified patches."""

    old = before.decode("utf-8").splitlines(keepends=True)
    new = after.decode("utf-8").splitlines(keepends=True)
    return "".join(difflib.unified_diff(old, new, fromfile=f"a/{path}", tofile=f"b/{path}"))
