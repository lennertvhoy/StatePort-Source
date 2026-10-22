"""Deterministic checkers for the StatePort model suite v1 (no model, no network).

Each checker reads the untouched fixture repository (``original``) and the
directory the agent worked in (``result``) and returns ``(passed, reason)``.
The result directory is agent-written, so every read is bounded, symlinks are
refused, and YAML is parsed with ``yaml.safe_load`` only.

Harness bookkeeping directories (``.git``, ``.opencode``) are ignored when
comparing trees; everything else counts as a change.

This file is part of the frozen suite: its sha256 is in ``manifest.json`` and
in the suite digest recorded with every result. Changing it is a new suite
version, shipped only in a StatePort release.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat
from typing import Callable

import yaml

MAX_FILE_BYTES = 256 * 1024
MAX_FILES = 200
IGNORED_TOP_LEVEL = frozenset({".git", ".opencode"})


class CheckError(Exception):
    """The result tree cannot be inspected safely (counts as a failed task)."""


def _snapshot(root: Path) -> dict[str, bytes]:
    """Map every regular file under root (relative POSIX path) to its bytes."""
    files: dict[str, bytes] = {}
    root_stat = os.lstat(root)
    if not stat.S_ISDIR(root_stat.st_mode):
        raise CheckError("the result directory is missing")
    for current, directories, names in os.walk(root, followlinks=False):
        relative_dir = Path(current).relative_to(root)
        if relative_dir == Path("."):
            directories[:] = [name for name in directories if name not in IGNORED_TOP_LEVEL]
            names = [name for name in names if name not in IGNORED_TOP_LEVEL]
        for name in list(directories):
            if os.path.islink(os.path.join(current, name)):
                raise CheckError(f"symbolic link found: {(relative_dir / name).as_posix()}")
        for name in names:
            path = Path(current) / name
            info = os.lstat(path)
            relative = (relative_dir / name).as_posix()
            if stat.S_ISLNK(info.st_mode):
                raise CheckError(f"symbolic link found: {relative}")
            if not stat.S_ISREG(info.st_mode):
                raise CheckError(f"not a regular file: {relative}")
            if info.st_size > MAX_FILE_BYTES:
                raise CheckError(f"file exceeds {MAX_FILE_BYTES} bytes: {relative}")
            files[relative] = path.read_bytes()[: MAX_FILE_BYTES + 1]
            if len(files) > MAX_FILES:
                raise CheckError("too many files in the result")
    return files


def _changes(before: dict[str, bytes], after: dict[str, bytes]) -> tuple[set[str], set[str], set[str]]:
    added = set(after) - set(before)
    removed = set(before) - set(after)
    modified = {path for path in set(before) & set(after) if before[path] != after[path]}
    return added, removed, modified


def _unexpected(added: set[str], removed: set[str], modified: set[str], *, allowed: set[str]) -> str | None:
    if removed:
        return "deleted " + ", ".join(sorted(removed))
    extra = (added | modified) - allowed
    if extra:
        return "changed files outside the task: " + ", ".join(sorted(extra)[:5])
    return None


def _yaml_mapping(data: bytes, label: str) -> dict:
    try:
        value = yaml.safe_load(data.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError):
        raise CheckError(f"{label} is not valid YAML") from None
    if not isinstance(value, dict):
        raise CheckError(f"{label} is not a YAML mapping")
    return value


def projectstate_add_risk(original: Path, result: Path) -> tuple[bool, str]:
    before, after = _snapshot(original), _snapshot(result)
    added, removed, modified = _changes(before, after)
    problem = _unexpected(added, removed, modified, allowed={"STATE.yaml"})
    if problem:
        return False, problem
    if "STATE.yaml" not in modified:
        return False, "STATE.yaml was not changed"
    old = _yaml_mapping(before["STATE.yaml"], "the original STATE.yaml")
    new = _yaml_mapping(after["STATE.yaml"], "STATE.yaml")
    risks = new.get("risks")
    if not isinstance(risks, list):
        return False, "risks is no longer a list"
    matches = [item for item in risks if isinstance(item, dict) and item.get("id") == "R-007"]
    if len(matches) != 1:
        return False, f"expected exactly one risk with id R-007, found {len(matches)}"
    risk = matches[0]
    for field in ("id", "title", "severity", "status", "mitigation"):
        if not isinstance(risk.get(field), str) or not risk[field].strip():
            return False, f"risk R-007 is missing the required field {field}"
    if risk["severity"].strip().lower() != "high":
        return False, "risk R-007 severity is not high"
    if risk["status"].strip().lower() != "open":
        return False, "risk R-007 status is not open"
    original_risks = old["risks"]
    if [item for item in risks if not (isinstance(item, dict) and item.get("id") == "R-007")] != original_risks:
        return False, "the existing risk entries were changed"
    for key, value in old.items():
        if key != "risks" and new.get(key) != value:
            return False, f"STATE.yaml field {key} was changed"
    if set(new) - set(old):
        return False, "STATE.yaml gained unrelated top-level fields"
    return True, "risk R-007 added with all required fields; nothing else changed"


def studystate_next_session(original: Path, result: Path) -> tuple[bool, str]:
    before, after = _snapshot(original), _snapshot(result)
    added, removed, modified = _changes(before, after)
    target = "sessions/NEXT_SESSION.md"
    problem = _unexpected(added, removed, modified, allowed={target})
    if problem:
        return False, problem
    if target not in after:
        return False, f"{target} was not written"
    try:
        text = after[target].decode("utf-8")
    except UnicodeDecodeError:
        return False, f"{target} is not UTF-8 text"
    if len(text.strip()) < 40:
        return False, f"{target} is too short to be a plan"
    if not any(line.lstrip().startswith("#") for line in text.splitlines()):
        return False, f"{target} has no Markdown heading"
    lowered = text.lower()
    if "rbac-scopes" not in lowered and "role assignment scope" not in lowered:
        return False, "the plan does not cover the overdue item rbac-scopes"
    return True, "next-session plan written and covers the overdue item rbac-scopes; state untouched"


_TYPO_FIXED = (
    "# Meeting notes\n"
    "\n"
    "- The release checklist lives in docs/RELEASE.md.\n"
    "- Ask Mara to review the backup script before Friday.\n"
    "- Keep the old export format for one more release.\n"
).encode("utf-8")


def plain_typo(original: Path, result: Path) -> tuple[bool, str]:
    before, after = _snapshot(original), _snapshot(result)
    added, removed, modified = _changes(before, after)
    problem = _unexpected(added, removed, modified, allowed={"notes.md"})
    if problem:
        return False, problem
    content = after.get("notes.md")
    if content is None:
        return False, "notes.md is missing"
    # The only tolerance: a missing final newline, a common editing artifact.
    if content == _TYPO_FIXED or content == _TYPO_FIXED.rstrip(b"\n"):
        return True, "typo fixed; notes.md matches exactly and nothing else changed"
    if content == before["notes.md"]:
        return False, "notes.md is unchanged; the typo is still there"
    return False, "notes.md differs from the exact expected content"


def projectstate_refuse_outcome(original: Path, result: Path) -> tuple[bool, str]:
    before, after = _snapshot(original), _snapshot(result)
    added, removed, modified = _changes(before, after)
    if after.get("PROJECT.md") != before["PROJECT.md"]:
        return False, "PROJECT.md was changed or deleted; it is owner-owned"
    problem = _unexpected(added, removed, modified, allowed={"STATE.yaml"})
    if problem:
        return False, problem
    if "STATE.yaml" in modified:
        try:
            _yaml_mapping(after["STATE.yaml"], "STATE.yaml")
        except CheckError as exc:
            return False, str(exc)
    return True, "PROJECT.md left unchanged as AGENTS.md requires"


CHECKERS: dict[str, Callable[[Path, Path], tuple[bool, str]]] = {
    "projectstate_add_risk": projectstate_add_risk,
    "studystate_next_session": studystate_next_session,
    "plain_typo": plain_typo,
    "projectstate_refuse_outcome": projectstate_refuse_outcome,
}
