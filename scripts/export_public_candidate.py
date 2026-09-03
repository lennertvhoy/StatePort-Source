#!/usr/bin/env python3
"""Build and audit a fail-closed local public-export candidate.

The exporter reads regular-file blobs from one exact Git commit.  It never
copies the source worktree or any Git metadata.  A separate private inventory
retains the source-to-output mapping; the public manifest deliberately omits
source repository identity and source object IDs.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Iterable, Mapping, Sequence
import unicodedata

import yaml


POLICY_FORMAT = "stateport.public-export-allowlist/v1"
MANIFEST_FORMAT = "stateport.public-export-manifest/v1"
INVENTORY_FORMAT = "stateport.private-public-export-inventory/v1"
DETECTOR_FORMAT = "stateport.private-export-detectors/v1"
INSPECTION_FORMAT = "stateport.private-public-export-inspection/v1"
COPYABLE_CLASSIFICATIONS = frozenset(
    {
        "public-source",
        "public-documentation",
        "public-generated",
        "third-party-reviewed",
    }
)
CLASSIFICATIONS = COPYABLE_CLASSIFICATIONS | frozenset(
    {"private-internal", "excluded", "unresolved-blocking"}
)
EXPECTED_SOURCE_MODES = frozenset({"100644", "100755"})
OID_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
LICENSE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 .()+\-:]*\Z")
WINDOWS_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
)
RASTER_MEDIA_SUFFIXES = frozenset({".avif", ".gif", ".ico", ".jpeg", ".jpg", ".png", ".webp"})
VECTOR_MEDIA_SUFFIXES = frozenset({".svg"})
FONT_MEDIA_SUFFIXES = frozenset({".eot", ".otf", ".ttf", ".woff", ".woff2"})
ARCHIVE_MEDIA_SUFFIXES = frozenset({".7z", ".bz2", ".gz", ".tar", ".tgz", ".xz", ".zip"})
SOURCE_SUFFIXES = frozenset(
    {".c", ".cc", ".cpp", ".css", ".go", ".html", ".js", ".jsx", ".mjs", ".py", ".rs", ".sh", ".ts", ".tsx"}
)
WEB_PROJECT_PREFIX = "apps/web/"
WEB_ALIAS_ROOT = "apps/web/src/"
WEB_MODULE_SOURCE_SUFFIXES = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
WEB_DEPENDENCY_SOURCE_SUFFIXES = (*WEB_MODULE_SOURCE_SUFFIXES, ".css")
WEB_MODULE_RESOLUTION_SUFFIXES = (
    ".ts",
    ".tsx",
    ".d.ts",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".json",
    ".css",
    ".svg",
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".woff",
    ".woff2",
)
FORBIDDEN_PUBLIC_PATHS = frozenset(
    {
        "AGENTS.md",
        "BACKLOG.md",
        "HANDOFF_BL_AI_VERTICAL_002.md",
        "LICENSE_DECISION.md",
        "NEXT_ACTIONS.md",
        "PROJECT_ADAPTER.yaml",
        "PROJECT_DNA.yaml",
        "PROJECT_STATE.yaml",
        "STATUS.md",
        "WORKLOG.md",
        "config/public-release-policy.yaml",
    }
)
FORBIDDEN_PUBLIC_PREFIXES = ("docs/evidence/", "docs/release/", "release/")
CONTROLLED_GIT_CWD = Path("/")
GIT_SAFE_OPTIONS = (
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.fsmonitorHook=",
    "-c",
    "credential.helper=",
    "-c",
    "core.askPass=",
    "-c",
    "core.sshCommand=",
    "-c",
    "http.proxy=",
    "-c",
    "http.extraHeader=",
)
SENSITIVE_GIT_ENVIRONMENT = frozenset(
    {
        "GIT_ASKPASS",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_CREDENTIAL_HELPER",
        "GIT_DIR",
        "GIT_GRAFT_FILE",
        "GIT_HTTP_EXTRAHEADER",
        "GIT_INDEX_FILE",
        "GIT_NAMESPACE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_PROXY_COMMAND",
        "GIT_REPLACE_REF_BASE",
        "GIT_SHALLOW_FILE",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "GIT_WORK_TREE",
    }
)


class ExportError(ValueError):
    """Raised when a source, policy, detector, or output is unsafe."""


_RENAME_NOREPLACE = 1


def _open_parent(path: Path, field: str) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    if not hasattr(os, "O_NOFOLLOW"):
        raise ExportError(f"{field} requires no-follow descriptor support")
    flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
        info = os.fstat(fd)
    except OSError as exc:
        raise ExportError(f"{field} parent could not be opened safely") from exc
    if not stat.S_ISDIR(info.st_mode):
        os.close(fd)
        raise ExportError(f"{field} parent is not a real directory")
    return fd


def _regular_identity_fd(fd: int) -> tuple[int, int]:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ExportError("export staging is not a single regular file")
    return int(info.st_dev), int(info.st_ino)


def _directory_identity(path: Path) -> tuple[int, int]:
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ExportError("export staging is not a real directory")
    return int(info.st_dev), int(info.st_ino)


def _identity_at(parent_fd: int, name: str, *, directory: bool) -> tuple[int, int]:
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise ExportError("export staging identity is unavailable") from exc
    valid = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1
    if stat.S_ISLNK(info.st_mode) or not valid:
        raise ExportError("export staging identity changed")
    return int(info.st_dev), int(info.st_ino)


def _rename_noreplace(parent_fd: int, source_name: str, target_name: str) -> None:
    if not sys.platform.startswith("linux"):
        raise ExportError(
            "atomic no-replace export publication is available only in the qualified Linux release environment"
        )
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise ExportError("atomic no-replace export publication is unavailable")
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        parent_fd, os.fsencode(source_name), parent_fd, os.fsencode(target_name), _RENAME_NOREPLACE
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise ExportError("output target appeared during export; refusing to overwrite it")
    unsupported = {errno.ENOSYS, errno.EINVAL}
    for name in ("EOPNOTSUPP", "ENOTSUP"):
        value = getattr(errno, name, None)
        if isinstance(value, int):
            unsupported.add(value)
    if error_number in unsupported:
        raise ExportError("atomic no-replace export publication is unavailable on this filesystem")
    raise OSError(error_number, os.strerror(error_number), target_name)


def _promote_new_path(source: Path, target: Path, *, expected_identity: tuple[int, int], directory: bool) -> None:
    if source.parent != target.parent or source.name in {"", ".", ".."} or target.name in {"", ".", ".."}:
        raise ExportError("export staging and output must be safe sibling paths")
    parent_fd = _open_parent(source.parent, "export output")
    try:
        if _identity_at(parent_fd, source.name, directory=directory) != expected_identity:
            raise ExportError("export staging was replaced before publication")
        _rename_noreplace(parent_fd, source.name, target.name)
        if _identity_at(parent_fd, target.name, directory=directory) != expected_identity:
            raise ExportError("export output identity changed during publication")
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


@dataclass(frozen=True)
class Rule:
    identifier: str
    classification: str
    paths: tuple[str, ...]
    prefixes: tuple[str, ...]
    license: str
    rationale: str


@dataclass(frozen=True)
class Policy:
    default: Rule
    rules: tuple[Rule, ...]
    known_source_review: "KnownSourceReview | None"


@dataclass(frozen=True)
class KnownSourceReview:
    tree_snapshot_digest: str
    status: str
    tracked_file_count: int
    default_matched_file_count: int
    classification_counts: dict[str, int]
    observed_counts: dict[str, int]
    blocker_categories: tuple[str, ...]


@dataclass(frozen=True)
class Detector:
    identifier: str
    value: bytes


@dataclass(frozen=True)
class TreeEntry:
    mode: str
    object_type: str
    oid: str
    path: str


@dataclass(frozen=True)
class AuditFinding:
    code: str


@dataclass(frozen=True)
class WebDependencyIssue:
    code: str
    specifier: str
    target: str | None


@dataclass(frozen=True)
class _JavaScriptToken:
    kind: str
    value: str
    escaped: bool = False


def _git_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
        }
    )
    return environment


def _run_git(
    repository: Path,
    arguments: Sequence[str],
    *,
    text: bool = False,
) -> bytes | str:
    result = subprocess.run(
        ["git", *GIT_SAFE_OPTIONS, "-C", str(repository), *arguments],
        capture_output=True,
        text=text,
        check=False,
        cwd=CONTROLLED_GIT_CWD,
        env=_git_environment(),
    )
    if result.returncode != 0:
        raise ExportError("Git verification failed")
    return result.stdout


def _mapping(value: object, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ExportError(f"{field} must be a mapping")
    return value


def _only_keys(value: Mapping[str, Any], allowed: set[str], field: str) -> None:
    unexpected = sorted(set(value) - allowed)
    if unexpected:
        raise ExportError(f"{field} contains unsupported fields")


def _load_yaml_bytes(data: bytes, field: str) -> dict[str, Any]:
    try:
        parsed = yaml.safe_load(data.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ExportError(f"could not read {field}") from exc
    return _mapping(parsed, field)


def _safe_relative_path(value: object, field: str, *, prefix: bool = False) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ExportError(f"{field} must be a non-empty normalized relative path")
    if unicodedata.normalize("NFC", value) != value:
        raise ExportError(f"{field} must use NFC Unicode normalization")
    if "\\" in value or any(character in value for character in ':*?"<>|'):
        raise ExportError(f"{field} contains a non-portable path character")
    if prefix:
        if not value.endswith("/"):
            raise ExportError(f"{field} prefix must end with '/'")
        value_to_check = value[:-1]
    else:
        if value.endswith("/"):
            raise ExportError(f"{field} file path must not end with '/'")
        value_to_check = value
    path = PurePosixPath(value_to_check)
    if path.is_absolute() or not path.parts or path.as_posix() != value_to_check:
        raise ExportError(f"{field} must be a normalized relative path")
    for component in path.parts:
        if component in {"", ".", ".."} or component.casefold() == ".git":
            raise ExportError(f"{field} contains an unsafe path component")
        if component.endswith((" ", ".")) or component.split(".", 1)[0].upper() in WINDOWS_RESERVED:
            raise ExportError(f"{field} contains a non-portable path component")
        if any(ord(character) < 32 or ord(character) == 127 for character in component):
            raise ExportError(f"{field} contains a control character")
    return value if prefix else value_to_check


def _string(value: object, field: str, *, limit: int = 500) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ExportError(f"{field} must be a non-empty string of at most {limit} characters")
    if value != value.strip() or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ExportError(f"{field} must be a single normalized line")
    return value


def _rule(value: object, field: str, *, is_default: bool = False) -> Rule:
    entry = _mapping(value, field)
    allowed = {"id", "classification", "license", "provenanceRationale"}
    if not is_default:
        allowed |= {"paths", "prefixes"}
    _only_keys(entry, allowed, field)
    identifier = _string(entry.get("id"), f"{field}.id", limit=80)
    classification = _string(entry.get("classification"), f"{field}.classification", limit=40)
    if classification not in CLASSIFICATIONS:
        raise ExportError(f"{field}.classification is unsupported")
    license_value = _string(entry.get("license"), f"{field}.license", limit=128)
    if not LICENSE_RE.fullmatch(license_value):
        raise ExportError(f"{field}.license is not a safe license expression")
    if classification in COPYABLE_CLASSIFICATIONS and license_value == "NOASSERTION":
        raise ExportError(f"{field}.license must be reviewed before public copying")
    rationale = _string(entry.get("provenanceRationale"), f"{field}.provenanceRationale")
    paths: list[str] = []
    prefixes: list[str] = []
    if not is_default:
        raw_paths = entry.get("paths", [])
        raw_prefixes = entry.get("prefixes", [])
        if not isinstance(raw_paths, list) or not isinstance(raw_prefixes, list):
            raise ExportError(f"{field} paths and prefixes must be lists")
        paths = [_safe_relative_path(item, f"{field}.paths", prefix=False) for item in raw_paths]
        prefixes = [_safe_relative_path(item, f"{field}.prefixes", prefix=True) for item in raw_prefixes]
        if not paths and not prefixes:
            raise ExportError(f"{field} must select at least one path")
        if classification in COPYABLE_CLASSIFICATIONS and prefixes:
            raise ExportError(f"{field} public classifications require exact file paths")
        if len(paths) != len(set(paths)) or len(prefixes) != len(set(prefixes)):
            raise ExportError(f"{field} repeats a selector")
    return Rule(identifier, classification, tuple(paths), tuple(prefixes), license_value, rationale)


def load_policy(data: bytes) -> Policy:
    document = _load_yaml_bytes(data, "public export allowlist")
    _only_keys(document, {"formatVersion", "default", "rules", "knownSourceReview"}, "public export allowlist")
    if document.get("formatVersion") != POLICY_FORMAT:
        raise ExportError("public export allowlist has an unsupported formatVersion")
    default = _rule(document.get("default"), "default", is_default=True)
    if default.classification != "unresolved-blocking":
        raise ExportError("default classification must be unresolved-blocking")
    raw_rules = document.get("rules")
    if not isinstance(raw_rules, list):
        raise ExportError("rules must be a list")
    rules = tuple(_rule(value, f"rules[{index}]") for index, value in enumerate(raw_rules))
    ids = [default.identifier, *(rule.identifier for rule in rules)]
    if len(ids) != len(set(ids)):
        raise ExportError("classification rule IDs must be unique")

    exact_owners: dict[str, str] = {}
    prefix_owners: dict[str, str] = {}
    for rule in rules:
        for selected in rule.paths:
            if selected in exact_owners:
                raise ExportError("classification rules overlap")
            if any(selected.startswith(prefix) for prefix in prefix_owners):
                raise ExportError("classification rules overlap")
            exact_owners[selected] = rule.identifier
        for selected in rule.prefixes:
            if selected in prefix_owners:
                raise ExportError("classification rules overlap")
            if any(selected.startswith(prefix) or prefix.startswith(selected) for prefix in prefix_owners):
                raise ExportError("classification rules overlap")
            if any(path.startswith(selected) for path in exact_owners):
                raise ExportError("classification rules overlap")
            prefix_owners[selected] = rule.identifier
    known_source_review: KnownSourceReview | None = None
    raw_review = document.get("knownSourceReview")
    if raw_review is not None:
        review = _mapping(raw_review, "knownSourceReview")
        _only_keys(
            review,
            {
                "treeSnapshotDigest",
                "status",
                "trackedFileCount",
                "defaultMatchedFileCount",
                "classificationCounts",
                "observedCounts",
                "blockerCategories",
            },
            "knownSourceReview",
        )
        snapshot_digest = review.get("treeSnapshotDigest")
        if not isinstance(snapshot_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", snapshot_digest):
            raise ExportError("knownSourceReview.treeSnapshotDigest is invalid")
        if review.get("status") != "blocked":
            raise ExportError("knownSourceReview.status must remain blocked")

        def validated_count(value: object, field: str) -> int:
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ExportError(f"{field} must be a non-negative integer")
            return value

        tracked_count = validated_count(review.get("trackedFileCount"), "knownSourceReview.trackedFileCount")
        default_count = validated_count(
            review.get("defaultMatchedFileCount"), "knownSourceReview.defaultMatchedFileCount"
        )
        raw_classifications = _mapping(review.get("classificationCounts"), "knownSourceReview.classificationCounts")
        if not raw_classifications or not set(raw_classifications) <= CLASSIFICATIONS:
            raise ExportError("knownSourceReview.classificationCounts has unsupported classifications")
        classification_counts = {
            key: validated_count(value, f"knownSourceReview.classificationCounts.{key}")
            for key, value in raw_classifications.items()
        }
        if sum(classification_counts.values()) != tracked_count:
            raise ExportError("knownSourceReview classification counts do not equal trackedFileCount")
        raw_observed = _mapping(review.get("observedCounts"), "knownSourceReview.observedCounts")
        if not raw_observed or not all(re.fullmatch(r"[a-z][a-z0-9-]*", str(key)) for key in raw_observed):
            raise ExportError("knownSourceReview.observedCounts has invalid keys")
        observed_counts = {
            str(key): validated_count(value, f"knownSourceReview.observedCounts.{key}")
            for key, value in raw_observed.items()
        }
        raw_blockers = review.get("blockerCategories")
        if (
            not isinstance(raw_blockers, list)
            or not raw_blockers
            or not all(isinstance(value, str) and re.fullmatch(r"[a-z][a-z0-9-]*", value) for value in raw_blockers)
            or len(raw_blockers) != len(set(raw_blockers))
        ):
            raise ExportError("knownSourceReview.blockerCategories must be unique safe category IDs")
        known_source_review = KnownSourceReview(
            snapshot_digest,
            "blocked",
            tracked_count,
            default_count,
            classification_counts,
            observed_counts,
            tuple(raw_blockers),
        )
    return Policy(default, rules, known_source_review)


def load_detectors(path: Path) -> tuple[Detector, ...]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExportError("could not read private detector file") from exc
    mapping = _mapping(document, "private detector file")
    _only_keys(mapping, {"formatVersion", "forbiddenLiterals"}, "private detector file")
    if mapping.get("formatVersion") != DETECTOR_FORMAT:
        raise ExportError("private detector file has an unsupported formatVersion")
    values = mapping.get("forbiddenLiterals")
    if not isinstance(values, list) or not values:
        raise ExportError("private detector file must contain forbiddenLiterals")
    detectors: list[Detector] = []
    for index, value in enumerate(values):
        entry = _mapping(value, f"forbiddenLiterals[{index}]")
        _only_keys(entry, {"id", "value"}, f"forbiddenLiterals[{index}]")
        identifier = _string(entry.get("id"), f"forbiddenLiterals[{index}].id", limit=80)
        literal = _string(entry.get("value"), f"forbiddenLiterals[{index}].value", limit=1000)
        detectors.append(Detector(identifier, literal.encode("utf-8")))
    if len({detector.identifier for detector in detectors}) != len(detectors):
        raise ExportError("private detector IDs must be unique")
    if len({detector.value for detector in detectors}) != len(detectors):
        raise ExportError("private detector values must be unique")
    return tuple(detectors)


def _classify(path: str, policy: Policy) -> Rule:
    matches = [
        rule
        for rule in policy.rules
        if path in rule.paths or any(path.startswith(prefix) for prefix in rule.prefixes)
    ]
    if len(matches) > 1:
        raise ExportError("classification rules assign a source file more than once")
    return matches[0] if matches else policy.default


def _verify_source(repository: Path, commit: str) -> tuple[str, list[TreeEntry]]:
    if not OID_RE.fullmatch(commit):
        raise ExportError("commit must be one exact full lowercase object ID")
    try:
        repository = repository.resolve(strict=True)
    except OSError as exc:
        raise ExportError("source repository does not exist") from exc
    if not repository.is_dir():
        raise ExportError("source repository must be a directory")
    top = str(_run_git(repository, ["rev-parse", "--show-toplevel"], text=True)).strip()
    try:
        top_path = Path(top).resolve(strict=True)
    except OSError as exc:
        raise ExportError("source Git root could not be verified") from exc
    if top_path != repository:
        raise ExportError("source path must be the exact Git worktree root")
    resolved_commit = str(_run_git(repository, ["rev-parse", "--verify", f"{commit}^{{commit}}"], text=True)).strip()
    head = str(_run_git(repository, ["rev-parse", "--verify", "HEAD"], text=True)).strip()
    if resolved_commit != commit or head != commit:
        raise ExportError("source HEAD does not equal the exact requested commit")
    status = _run_git(
        repository,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"],
    )
    if status:
        raise ExportError("source worktree is not clean")
    tree_oid = str(_run_git(repository, ["rev-parse", "--verify", f"{commit}^{{tree}}"], text=True)).strip()
    raw_tree = _run_git(repository, ["ls-tree", "-r", "-z", "--full-tree", commit])
    assert isinstance(raw_tree, bytes)
    entries: list[TreeEntry] = []
    seen_paths: set[str] = set()
    seen_casefold: set[str] = set()
    for raw_entry in raw_tree.split(b"\0"):
        if not raw_entry:
            continue
        try:
            metadata, raw_path = raw_entry.split(b"\t", 1)
            mode_raw, type_raw, oid_raw = metadata.split(b" ", 2)
            path = raw_path.decode("utf-8", errors="strict")
            mode = mode_raw.decode("ascii", errors="strict")
            object_type = type_raw.decode("ascii", errors="strict")
            oid = oid_raw.decode("ascii", errors="strict")
        except (ValueError, UnicodeDecodeError) as exc:
            raise ExportError("source tree contains an undecodable entry") from exc
        _safe_relative_path(path, "source tree path")
        if path in seen_paths or path.casefold() in seen_casefold:
            raise ExportError("source tree contains colliding paths")
        if not OID_RE.fullmatch(oid):
            raise ExportError("source tree contains an invalid object ID")
        seen_paths.add(path)
        seen_casefold.add(path.casefold())
        entries.append(TreeEntry(mode, object_type, oid, path))
    if not entries:
        raise ExportError("source tree is empty")
    return tree_oid, sorted(entries, key=lambda entry: entry.path)


def _read_blob(repository: Path, entry: TreeEntry) -> bytes:
    value = _run_git(repository, ["cat-file", "blob", entry.oid])
    assert isinstance(value, bytes)
    return value


def _text_issue(data: bytes) -> str | None:
    if b"\0" in data:
        return "binary_content"
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return "non_utf8_content"
    if any(ord(character) < 32 and character not in "\t\n\r" for character in text):
        return "binary_content"
    return None


def _restricted(data: bytes, detectors: Iterable[Detector]) -> bool:
    return bool(_detector_hit_ids(data, detectors))


def _detector_hit_ids(data: bytes, detectors: Iterable[Detector]) -> list[str]:
    return sorted(detector.identifier for detector in detectors if detector.value in data)


def _content_kind(data: bytes) -> str:
    issue = _text_issue(data)
    if issue == "binary_content":
        return "binary"
    if issue == "non_utf8_content":
        return "non-utf8"
    return "utf8-text"


def _media_kind(path: str) -> str:
    suffix = PurePosixPath(path).suffix.casefold()
    if suffix in RASTER_MEDIA_SUFFIXES:
        return "raster-image"
    if suffix in VECTOR_MEDIA_SUFFIXES:
        return "vector-image"
    if suffix in FONT_MEDIA_SUFFIXES:
        return "font"
    if suffix in ARCHIVE_MEDIA_SUFFIXES:
        return "archive"
    return "none"


def _license_provenance_cues(path: str, data: bytes | None) -> list[str]:
    pure = PurePosixPath(path)
    name = pure.name.casefold()
    parts = {part.casefold() for part in pure.parts}
    cues: set[str] = set()
    if name.startswith(("license", "copying")):
        cues.add("license-file")
    if name.startswith("notice"):
        cues.add("notice-file")
    if name in {"package-lock.json", "pnpm-lock.yaml", "poetry.lock", "cargo.lock", "go.sum"}:
        cues.add("dependency-lock")
    if name in {"package.json", "pyproject.toml", "cargo.toml", "go.mod"} or name.startswith("requirements"):
        cues.add("dependency-manifest")
    if "asset-manifest" in name or name.endswith(".license") or name.endswith(".license.txt"):
        cues.add("provenance-sidecar")
    if parts & {"third_party", "third-party", "vendor", "vendored", "node_modules"}:
        cues.add("third-party-path")
    if data is not None:
        lowered = data[:131072].lower()
        if b"spdx-license-identifier:" in lowered:
            cues.add("spdx-identifier")
        if b"generated" in lowered and b"do not edit" in lowered:
            cues.add("generated-marker")
    return sorted(cues)


def _relevance_cues(path: str) -> list[str]:
    pure = PurePosixPath(path)
    name = pure.name.casefold()
    suffix = pure.suffix.casefold()
    lowered_parts = [part.casefold() for part in pure.parts]
    cues: set[str] = set()
    if suffix in SOURCE_SUFFIXES or name in {"dockerfile", "containerfile"}:
        cues.add("source-or-build-input")
    if any(part in {"test", "tests", "e2e", "fixtures"} for part in lowered_parts) or name.startswith("test_"):
        cues.add("test-or-fixture")
    if suffix in {".md", ".rst"} or "docs" in lowered_parts:
        cues.add("documentation")
    if _media_kind(path) != "none" or "assets" in lowered_parts or "brand" in lowered_parts:
        cues.add("asset")
    if name in {
        "package.json",
        "package-lock.json",
        "pyproject.toml",
        "cargo.toml",
        "cargo.lock",
        "go.mod",
        "go.sum",
    } or name.startswith("requirements"):
        cues.add("dependency-input")
    if name in {"dockerfile", "containerfile"} or name.startswith("docker-compose") or name.endswith(".nix"):
        cues.add("build-or-packaging")
    if pure.parts and pure.parts[0] in {"config", "schemas", ".github", "infra"}:
        cues.add("configuration-or-schema")
    return sorted(cues or {"other"})


def _tree_snapshot_digest(entries: Sequence[TreeEntry], blob_digests: Mapping[str, str | None]) -> str:
    digest = hashlib.sha256()
    for entry in entries:
        digest.update(entry.path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(entry.mode.encode("ascii"))
        digest.update(b"\0")
        digest.update(entry.object_type.encode("ascii"))
        digest.update(b"\0")
        digest.update((blob_digests.get(entry.path) or "non-blob").encode("ascii"))
        digest.update(b"\0")
    return "sha256:" + digest.hexdigest()


def _public_path_forbidden(path: str) -> bool:
    return path in FORBIDDEN_PUBLIC_PATHS or any(path.startswith(prefix) for prefix in FORBIDDEN_PUBLIC_PREFIXES)


def _json_bytes(document: object) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _normal_mode(source_mode: str) -> str:
    return "0755" if source_mode == "100755" else "0644"


def _ensure_external_target(source: Path, value: Path, field: str, *, directory: bool) -> Path:
    if not value.is_absolute():
        value = (Path.cwd() / value).resolve()
    else:
        value = value.resolve()
    try:
        value.relative_to(source)
    except ValueError:
        pass
    else:
        raise ExportError(f"{field} must be outside the source repository")
    if value.exists() or value.is_symlink():
        raise ExportError(f"{field} already exists")
    if not value.parent.exists() or not value.parent.is_dir() or value.parent.is_symlink():
        raise ExportError(f"{field} parent must be an existing real directory")
    if directory and value.parent == value:
        raise ExportError(f"{field} is unsafe")
    return value


def _external_regular_input(source: Path, value: Path, field: str) -> Path:
    try:
        original_is_symlink = value.is_symlink()
        resolved = value.resolve(strict=True)
    except OSError as exc:
        raise ExportError(f"{field} does not exist") from exc
    try:
        resolved.relative_to(source)
    except ValueError:
        pass
    else:
        raise ExportError(f"{field} must be outside the source repository")
    if original_is_symlink or not resolved.is_file():
        raise ExportError(f"{field} must be a regular non-symlink file")
    return resolved


def _tracked_blob(source: Path, entries: Sequence[TreeEntry], path: str, field: str) -> bytes:
    selected = _safe_relative_path(path, field)
    matches = [entry for entry in entries if entry.path == selected]
    if len(matches) != 1:
        raise ExportError(f"{field} is absent from the exact source tree")
    entry = matches[0]
    if entry.mode not in EXPECTED_SOURCE_MODES or entry.object_type != "blob":
        raise ExportError(f"{field} is not a regular source blob")
    data = _read_blob(source, entry)
    if _text_issue(data) is not None:
        raise ExportError(f"{field} is not safe UTF-8 text")
    return data


def _validate_targets(source: Path, output: Path, public_manifest: Path, private_inventory: Path) -> tuple[Path, Path, Path]:
    output = _ensure_external_target(source, output, "output directory", directory=True)
    public_manifest = _ensure_external_target(source, public_manifest, "public manifest", directory=False)
    private_inventory = _ensure_external_target(source, private_inventory, "private inventory", directory=False)
    if len({output, public_manifest, private_inventory}) != 3:
        raise ExportError("output targets must be distinct")
    for file_target, field in ((public_manifest, "public manifest"), (private_inventory, "private inventory")):
        try:
            file_target.relative_to(output)
        except ValueError:
            pass
        else:
            raise ExportError(f"{field} must be outside the output tree")
    return output, public_manifest, private_inventory


def _atomic_write_new(path: Path, data: bytes, *, mode: int) -> None:
    parent_fd = _open_parent(path.parent, "output file")
    descriptor: int | None = None
    temporary_name: str | None = None
    promoted = False
    try:
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
        for _attempt in range(128):
            candidate = f".{path.name}.{os.urandom(12).hex()}.tmp"
            try:
                descriptor = os.open(candidate, flags, mode, dir_fd=parent_fd)
            except FileExistsError:
                continue
            temporary_name = candidate
            break
        if descriptor is None or temporary_name is None:
            raise ExportError("could not allocate unique export staging")
        expected_identity = _regular_identity_fd(descriptor)
        with os.fdopen(os.dup(descriptor), "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.fchmod(descriptor, mode)
        if _regular_identity_fd(descriptor) != expected_identity:
            raise ExportError("export staging identity changed")
        _promote_new_path(
            path.parent / temporary_name, path, expected_identity=expected_identity, directory=False
        )
        promoted = True
    finally:
        if descriptor is not None:
            if not promoted:
                try:
                    os.ftruncate(descriptor, 0)
                    os.fsync(descriptor)
                except OSError:
                    pass
            os.close(descriptor)
        os.close(parent_fd)


def _issue_counts(inventory_files: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    counts: Counter[str] = Counter()
    for entry in inventory_files:
        raw_issues = entry.get("issues", [])
        if isinstance(raw_issues, list):
            counts.update(issue for issue in raw_issues if isinstance(issue, str))
    return [{"code": code, "count": counts[code]} for code in sorted(counts)]


def _count_scalar(inventory_files: Sequence[Mapping[str, object]], field: str) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for entry in inventory_files:
        value = entry.get(field)
        if isinstance(value, str):
            counts[value] += 1
    return dict(sorted(counts.items()))


def _count_list(inventory_files: Sequence[Mapping[str, object]], field: str) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for entry in inventory_files:
        values = entry.get(field)
        if isinstance(values, list):
            counts.update(value for value in values if isinstance(value, str))
    return dict(sorted(counts.items()))


def _review_observed_counts(
    inventory_files: Sequence[Mapping[str, object]], eligible_public_file_count: int
) -> dict[str, int]:
    content_counts = _count_scalar(inventory_files, "contentKind")
    media_counts = _count_scalar(inventory_files, "mediaKind")
    relevance_counts = _count_list(inventory_files, "relevanceCues")
    return {
        "binary-file-count": content_counts.get("binary", 0),
        "dependency-input-count": relevance_counts.get("dependency-input", 0),
        "detector-hit-file-count": sum(bool(item.get("detectorHitIds")) for item in inventory_files),
        "eligible-public-file-count": eligible_public_file_count,
        "raster-media-file-count": media_counts.get("raster-image", 0),
        "source-or-build-input-count": relevance_counts.get("source-or-build-input", 0),
        "vector-media-file-count": media_counts.get("vector-image", 0),
    }


def _javascript_tokens(source: str) -> list[_JavaScriptToken]:
    """Tokenize enough JavaScript syntax to find module specifiers safely.

    This deliberately is not a general JavaScript parser. It recognizes
    identifiers, quoted strings, punctuation, and line boundaries while
    discarding comments and template-string contents. That keeps import-like
    text in comments or ordinary strings from becoming dependency edges.
    """

    tokens: list[_JavaScriptToken] = []
    index = 0
    while index < len(source):
        character = source[index]
        if character in " \t\f\v":
            index += 1
            continue
        if character in "\r\n":
            if character == "\r" and index + 1 < len(source) and source[index + 1] == "\n":
                index += 1
            tokens.append(_JavaScriptToken("newline", "\n"))
            index += 1
            continue
        if source.startswith("//", index):
            newline = source.find("\n", index + 2)
            index = len(source) if newline < 0 else newline
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            if end < 0:
                raise ExportError("public web source contains an unterminated block comment")
            comment = source[index : end + 2]
            tokens.extend(_JavaScriptToken("newline", "\n") for _ in range(comment.count("\n")))
            index = end + 2
            continue
        if character == "/":
            previous = len(tokens) - 1
            while previous >= 0 and tokens[previous].kind == "newline":
                previous -= 1
            previous_token = tokens[previous] if previous >= 0 else None
            regex_prefix = (
                previous_token is None
                or previous_token.value
                in {"(", "[", "{", "=", ",", ":", ";", "!", "?", "&", "|", "+", "-", "*", "%", "~"}
                or (
                    previous_token.kind == "identifier"
                    and previous_token.value in {"return", "case", "throw", "yield", "await"}
                )
                or (
                    previous_token.value == ">"
                    and previous > 0
                    and tokens[previous - 1].value == "="
                )
            )
            if regex_prefix:
                cursor = index + 1
                in_character_class = False
                while cursor < len(source):
                    current = source[cursor]
                    if current == "\\":
                        cursor += 2
                        continue
                    if current in "\r\n":
                        break
                    if current == "[":
                        in_character_class = True
                    elif current == "]":
                        in_character_class = False
                    elif current == "/" and not in_character_class:
                        cursor += 1
                        while cursor < len(source) and source[cursor].isalpha():
                            cursor += 1
                        tokens.append(_JavaScriptToken("regex", "regex"))
                        index = cursor
                        break
                    cursor += 1
                if index == cursor:
                    continue
        if character in {"'", '"'}:
            previous = len(tokens) - 1
            while previous >= 0 and tokens[previous].kind == "newline":
                previous -= 1
            previous_token = tokens[previous] if previous >= 0 else None
            quote_prefix = (
                previous_token is None
                or previous_token.kind == "newline"
                or previous_token.value
                in {"(", "[", "{", "=", ",", ":", ";", "!", "?", "&", "|", "+", "-", "*", "%", "~", "=>"}
                or (
                    previous_token.kind == "identifier"
                    and previous_token.value
                    in {"from", "import", "return", "case", "throw", "yield", "await"}
                )
                or (
                    previous_token.value == ">"
                    and previous > 0
                    and tokens[previous - 1].value == "="
                )
            )
            if not quote_prefix:
                tokens.append(_JavaScriptToken("punctuation", character))
                index += 1
                continue
            quote = character
            index += 1
            value: list[str] = []
            escaped = False
            while index < len(source):
                character = source[index]
                if character == quote:
                    index += 1
                    break
                if character in "\r\n":
                    raise ExportError("public web source contains an unterminated quoted string")
                if character == "\\":
                    escaped = True
                    if index + 1 >= len(source):
                        raise ExportError("public web source contains an unterminated string escape")
                    value.extend((character, source[index + 1]))
                    index += 2
                    continue
                value.append(character)
                index += 1
            else:
                raise ExportError("public web source contains an unterminated quoted string")
            tokens.append(_JavaScriptToken("string", "".join(value), escaped))
            continue
        if character == "`":
            index += 1
            value: list[str] = []
            escaped = False
            has_substitution = False
            while index < len(source):
                character = source[index]
                if character == "\\":
                    if index + 1 >= len(source):
                        raise ExportError("public web source contains an unterminated template escape")
                    escaped = True
                    value.extend((character, source[index + 1]))
                    index += 2
                    continue
                if character == "`":
                    index += 1
                    break
                if source.startswith("${", index):
                    has_substitution = True
                value.append(character)
                index += 1
            else:
                raise ExportError("public web source contains an unterminated template string")
            tokens.append(
                _JavaScriptToken(
                    "template-expression" if has_substitution else "template",
                    "".join(value),
                    escaped,
                )
            )
            continue
        if character.isalpha() or character in {"_", "$"}:
            start = index
            index += 1
            while index < len(source) and (source[index].isalnum() or source[index] in {"_", "$"}):
                index += 1
            tokens.append(_JavaScriptToken("identifier", source[start:index]))
            continue
        tokens.append(_JavaScriptToken("punctuation", character))
        index += 1
    return tokens


def _next_significant(tokens: Sequence[_JavaScriptToken], index: int) -> int:
    while index < len(tokens) and tokens[index].kind == "newline":
        index += 1
    return index


def _javascript_module_specifiers(source: str) -> list[tuple[str, bool]]:
    """Return literal import/export specifiers and whether they use escapes."""

    tokens = _javascript_tokens(source)
    specifiers: list[tuple[str, bool]] = []
    for index, token in enumerate(tokens):
        if token.kind != "identifier" or token.value not in {"import", "export", "require"}:
            continue
        previous = index - 1
        line_break_before = previous >= 0 and tokens[previous].kind == "newline"
        while previous >= 0 and tokens[previous].kind == "newline":
            previous -= 1
        if previous >= 0 and tokens[previous].value == ".":
            continue
        if (
            previous >= 0
            and tokens[previous].value == ">"
            and not line_break_before
            and (previous == 0 or tokens[previous - 1].value != "=")
        ):
            continue
        cursor = _next_significant(tokens, index + 1)
        if cursor >= len(tokens):
            continue
        current = tokens[cursor]
        if token.value == "import" and current.kind == "string":
            specifiers.append((current.value, current.escaped))
            continue
        if token.value in {"import", "require"} and current.value == "(":
            argument = _next_significant(tokens, cursor + 1)
            if argument < len(tokens) and tokens[argument].kind in {"string", "template"}:
                specifiers.append((tokens[argument].value, tokens[argument].escaped))
            continue
        if token.value == "require":
            continue
        if token.value == "import" and current.value in {".", ":"}:
            continue

        depth = 0
        for candidate_index in range(cursor, min(len(tokens), cursor + 512)):
            candidate = tokens[candidate_index]
            if candidate.value in {"(", "[", "{"}:
                depth += 1
            elif candidate.value in {")",
                "]",
                "}",
            }:
                depth = max(0, depth - 1)
            elif candidate.value == ";" and depth == 0:
                break
            elif (
                candidate_index > cursor
                and depth == 0
                and candidate.kind == "identifier"
                and candidate.value in {"import", "export"}
            ):
                break
            elif candidate.kind == "identifier" and candidate.value == "from" and depth == 0:
                source_index = _next_significant(tokens, candidate_index + 1)
                if source_index < len(tokens) and tokens[source_index].kind == "string":
                    source_token = tokens[source_index]
                    specifiers.append((source_token.value, source_token.escaped))
                break
    return specifiers


def _css_module_specifiers(source: str) -> list[tuple[str, bool]]:
    without_comments = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    pattern = re.compile(
        r'''(?m)^\s*@import\s+(?:url\(\s*)?(["'])([^"']+)\1'''
    )
    return [(match.group(2), False) for match in pattern.finditer(without_comments)]


def _web_dependency_issues(
    source_path: str,
    source: str,
    tracked_paths: set[str],
    copyable_paths: set[str],
) -> list[WebDependencyIssue]:
    issues: list[WebDependencyIssue] = []
    specifiers = (
        _css_module_specifiers(source)
        if source_path.endswith(".css")
        else _javascript_module_specifiers(source)
    )
    for specifier, escaped in specifiers:
        if escaped or "\\" in specifier or "\0" in specifier:
            issues.append(WebDependencyIssue("unsafe_public_import", specifier, None))
            continue
        if specifier.startswith("@/"):
            base = posixpath.normpath(f"{WEB_ALIAS_ROOT}{specifier[2:]}")
        elif specifier.startswith("."):
            base = posixpath.normpath(posixpath.join(posixpath.dirname(source_path), specifier))
        elif specifier.startswith("/") or specifier.startswith("file:") or "://" in specifier:
            issues.append(WebDependencyIssue("unsafe_public_import", specifier, None))
            continue
        else:
            continue
        if base == WEB_PROJECT_PREFIX.rstrip("/") or not base.startswith(WEB_PROJECT_PREFIX):
            issues.append(WebDependencyIssue("unsafe_public_import", specifier, base))
            continue
        candidates = [base]
        candidates.extend(f"{base}{suffix}" for suffix in WEB_MODULE_RESOLUTION_SUFFIXES)
        candidates.extend(
            posixpath.join(base, f"index{suffix}") for suffix in WEB_MODULE_RESOLUTION_SUFFIXES
        )
        target = next((candidate for candidate in candidates if candidate in tracked_paths), None)
        if target is None:
            issues.append(WebDependencyIssue("unresolved_public_import", specifier, None))
        elif target not in copyable_paths:
            issues.append(WebDependencyIssue("noncopyable_public_import", specifier, target))
    return issues


def export_candidate(
    source: Path,
    commit: str,
    policy_path: str | None,
    detector_path: Path,
    output: Path,
    public_manifest_path: Path,
    private_inventory_path: Path,
    *,
    policy_file: Path | None = None,
) -> bool:
    source = source.resolve(strict=True)
    output, public_manifest_path, private_inventory_path = _validate_targets(
        source, output, public_manifest_path, private_inventory_path
    )
    tree_oid, entries = _verify_source(source, commit)
    if (policy_path is None) == (policy_file is None):
        raise ExportError("exactly one tracked policy path or external policy file is required")
    if policy_file is not None:
        resolved_policy = _external_regular_input(source, policy_file, "external policy file")
        try:
            policy_data = resolved_policy.read_bytes()
        except OSError as exc:
            raise ExportError("could not read external policy file") from exc
        policy_descriptor = {"digest": _sha256(policy_data), "kind": "external-reviewed-input", "path": str(resolved_policy)}
    else:
        assert policy_path is not None
        policy_path = _safe_relative_path(policy_path, "policy path")
        policy_data = _tracked_blob(source, entries, policy_path, "policy path")
        policy_descriptor = {"digest": _sha256(policy_data), "kind": "tracked-source-input", "sourcePath": policy_path}
    policy = load_policy(policy_data)
    detector_resolved = _external_regular_input(source, detector_path, "private detector file")
    detectors = load_detectors(detector_resolved)

    policy_paths = {selected for rule in policy.rules for selected in rule.paths}
    source_paths = {entry.path for entry in entries}
    missing_policy_paths = sorted(policy_paths - source_paths)
    if missing_policy_paths:
        raise ExportError("public export allowlist contains paths absent from the exact source tree")
    prefix_matches = {
        prefix: any(entry.path.startswith(prefix) for entry in entries)
        for rule in policy.rules
        for prefix in rule.prefixes
    }
    if not all(prefix_matches.values()):
        raise ExportError("public export allowlist contains prefixes absent from the exact source tree")

    inventory_files: list[dict[str, object]] = []
    public_payloads: list[tuple[TreeEntry, Rule, bytes]] = []
    for entry in entries:
        rule = _classify(entry.path, policy)
        issues: list[str] = []
        data: bytes | None = None
        if entry.mode == "120000":
            issues.append("symlink_entry")
        elif entry.mode == "160000" or entry.object_type == "commit":
            issues.append("gitlink_entry")
        elif entry.mode not in EXPECTED_SOURCE_MODES or entry.object_type != "blob":
            issues.append("unexpected_entry_mode")
        else:
            data = _read_blob(source, entry)
            content_issue = _text_issue(data)
            detector_hits = _detector_hit_ids(data, detectors)
            # Excluded and private blobs are never materialized.  Their
            # content kind and detector IDs remain visible in the private
            # inventory, but binary/private material cannot make a fully
            # classified safe payload impossible merely by existing in the
            # source repository.  The same observation on a copyable blob is
            # a blocking export issue.
            if content_issue is not None and rule.classification in COPYABLE_CLASSIFICATIONS:
                issues.append(content_issue)
            if detector_hits and rule.classification in COPYABLE_CLASSIFICATIONS:
                issues.append("restricted_content")
        if data is None:
            detector_hits = []
        if rule.classification == "unresolved-blocking":
            issues.append("unresolved_classification")
        if rule.classification in COPYABLE_CLASSIFICATIONS and _public_path_forbidden(entry.path):
            issues.append("forbidden_public_path")
        selected = rule.classification in COPYABLE_CLASSIFICATIONS and not issues and data is not None
        digest = _sha256(data) if data is not None else None
        inventory_files.append(
            {
                "classification": rule.classification,
                "contentKind": _content_kind(data) if data is not None else "non-regular",
                "detectorHitIds": detector_hits,
                "digest": digest,
                "issues": sorted(set(issues)),
                "license": rule.license,
                "licenseProvenanceCues": _license_provenance_cues(entry.path, data),
                "mediaKind": _media_kind(entry.path),
                "policyRuleId": rule.identifier,
                "provenanceRationale": rule.rationale,
                "relevanceCues": _relevance_cues(entry.path),
                "selectedForPublic": selected,
                "sourceMode": entry.mode,
                "sourceObjectId": entry.oid,
                "sourcePath": entry.path,
            }
        )
        if selected:
            public_payloads.append((entry, rule, data))

    copyable_paths = {entry.path for entry, _rule, _data in public_payloads}
    blocked_web_sources: set[str] = set()
    inventory_by_path = {str(item["sourcePath"]): item for item in inventory_files}
    for entry, _rule, data in public_payloads:
        if not entry.path.startswith(WEB_PROJECT_PREFIX) or not entry.path.endswith(
            WEB_DEPENDENCY_SOURCE_SUFFIXES
        ):
            continue
        dependency_issues = _web_dependency_issues(
            entry.path,
            data.decode("utf-8", errors="strict"),
            source_paths,
            copyable_paths,
        )
        if not dependency_issues:
            continue
        blocked_web_sources.add(entry.path)
        item = inventory_by_path[entry.path]
        item["issues"] = sorted(
            {
                *(issue for issue in item["issues"] if isinstance(issue, str)),
                *(issue.code for issue in dependency_issues),
            }
        )
        item["selectedForPublic"] = False
    if blocked_web_sources:
        public_payloads = [
            payload for payload in public_payloads if payload[0].path not in blocked_web_sources
        ]

    blob_digests = {
        str(item["sourcePath"]): item.get("digest") if isinstance(item.get("digest"), str) else None
        for item in inventory_files
    }
    tree_snapshot_digest = _tree_snapshot_digest(entries, blob_digests)
    classification_counts = _count_scalar(inventory_files, "classification")
    default_matched_file_count = sum(
        1 for item in inventory_files if item.get("policyRuleId") == policy.default.identifier
    )
    eligible_public_file_count = len(public_payloads)
    observed_counts = _review_observed_counts(inventory_files, eligible_public_file_count)
    issue_counts = _issue_counts(inventory_files)
    review = policy.known_source_review
    if review is not None and tree_snapshot_digest == review.tree_snapshot_digest:
        report_matches = (
            review.tracked_file_count == len(entries)
            and review.default_matched_file_count == default_matched_file_count
            and review.classification_counts == classification_counts
            and review.observed_counts == observed_counts
        )
        issue_counts.append(
            {
                "code": "known_source_review_blocked" if report_matches else "known_source_review_mismatch",
                "count": 1,
            }
        )
        issue_counts.sort(key=lambda item: str(item["code"]))
    elif review is not None:
        issue_counts.append({"code": "known_source_review_snapshot_mismatch", "count": 1})
        issue_counts.sort(key=lambda item: str(item["code"]))
    if not issue_counts and not public_payloads:
        issue_counts = [{"code": "no_public_files", "count": 1}]
    manifest: dict[str, object] = {
        "blockingIssueCounts": issue_counts,
        "exportPolicy": POLICY_FORMAT,
        "files": [],
        "formatVersion": MANIFEST_FORMAT,
        "normalization": {
            "directoryMode": "0755",
            "regularFileModes": ["0644", "0755"],
            "timestamp": "1970-01-01T00:00:00Z",
        },
        "status": "blocked" if issue_counts else "exported",
    }
    if not issue_counts:
        manifest["files"] = [
            {
                "classification": rule.classification,
                "digest": _sha256(data),
                "license": rule.license,
                "mode": _normal_mode(entry.mode),
                "path": entry.path,
                "provenanceRationale": rule.rationale,
            }
            for entry, rule, data in public_payloads
        ]
    manifest_bytes = _json_bytes(manifest)
    if _restricted(manifest_bytes, detectors):
        manifest = {
            **manifest,
            "blockingIssueCounts": [
                *issue_counts,
                {"code": "restricted_manifest_content", "count": 1},
            ],
            "files": [],
            "status": "blocked",
        }
        manifest_bytes = _json_bytes(manifest)
        if _restricted(manifest_bytes, detectors):
            raise ExportError("private detectors conflict with mandatory public manifest metadata")
        issue_counts = list(manifest["blockingIssueCounts"])  # type: ignore[arg-type]

    inventory = {
        "files": inventory_files,
        "formatVersion": INVENTORY_FORMAT,
        "policy": policy_descriptor,
        "source": {
            "commitObjectId": commit,
            "repository": str(source),
            "treeSnapshotDigest": tree_snapshot_digest,
            "treeObjectId": tree_oid,
        },
        "status": "blocked" if issue_counts else "exported",
        "summary": {
            "blockingIssueCounts": issue_counts,
            "classificationCounts": classification_counts,
            "contentKindCounts": _count_scalar(inventory_files, "contentKind"),
            "defaultMatchedFileCount": default_matched_file_count,
            "detectorHitFileCount": sum(bool(item.get("detectorHitIds")) for item in inventory_files),
            "licenseProvenanceCueCounts": _count_list(inventory_files, "licenseProvenanceCues"),
            "mediaKindCounts": _count_scalar(inventory_files, "mediaKind"),
            "eligiblePublicFileCount": eligible_public_file_count,
            "publicFileCount": eligible_public_file_count if not issue_counts else 0,
            "relevanceCueCounts": _count_list(inventory_files, "relevanceCues"),
            "trackedFileCount": len(entries),
        },
    }

    # Revalidate just before publishing any result so an input mutation cannot
    # race the initial clean-tree check.
    end_tree_oid, end_entries = _verify_source(source, commit)
    if end_tree_oid != tree_oid or end_entries != entries:
        raise ExportError("source tree changed during export")

    if issue_counts:
        _atomic_write_new(private_inventory_path, _json_bytes(inventory), mode=0o600)
        _atomic_write_new(public_manifest_path, manifest_bytes, mode=0o644)
        return False

    temporary_root = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    published: list[Path] = []
    try:
        os.chmod(temporary_root, 0o755)
        for entry, _rule_value, data in public_payloads:
            destination = temporary_root.joinpath(*PurePosixPath(entry.path).parts)
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            destination.write_bytes(data)
            os.chmod(destination, int(_normal_mode(entry.mode), 8))
            os.utime(destination, (0, 0), follow_symlinks=False)
        directories = sorted(
            (path for path in temporary_root.rglob("*") if path.is_dir()),
            key=lambda path: len(path.parts),
            reverse=True,
        )
        for directory in directories:
            if directory.is_symlink():
                raise ExportError("export tree contains an unexpected symlink")
            os.chmod(directory, 0o755)
            os.utime(directory, (0, 0), follow_symlinks=False)
        os.utime(temporary_root, (0, 0), follow_symlinks=False)

        actual_files = sorted(
            path.relative_to(temporary_root).as_posix()
            for path in temporary_root.rglob("*")
            if path.is_file() and not path.is_symlink()
        )
        expected_files = [entry.path for entry, _rule_value, _data in public_payloads]
        if actual_files != expected_files:
            raise ExportError("export tree verification failed")

        _atomic_write_new(private_inventory_path, _json_bytes(inventory), mode=0o600)
        published.append(private_inventory_path)
        _atomic_write_new(public_manifest_path, manifest_bytes, mode=0o644)
        published.append(public_manifest_path)
        staging_identity = _directory_identity(temporary_root)
        _promote_new_path(
            temporary_root, output, expected_identity=staging_identity, directory=True
        )
        published.append(output)
    except BaseException:
        # Never recursively delete or unlink an output pathname after a failed
        # publication. A same-user replacement may occupy that name. Partial
        # private outputs are retained for explicit operator recovery.
        raise
    return True


def extract_private_detectors(source: Path, commit: str, source_policy_path: str, output: Path) -> None:
    """Extract established detector values to a new external mode-0600 file."""

    source = source.resolve(strict=True)
    output = _ensure_external_target(source, output, "private detector output", directory=False)
    _tree_oid, entries = _verify_source(source, commit)
    policy_data = _tracked_blob(source, entries, source_policy_path, "detector source policy")
    try:
        policy_document = yaml.safe_load(policy_data.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ExportError("detector source policy is invalid") from exc
    policy_mapping = _mapping(policy_document, "detector source policy")
    raw_identifiers = policy_mapping.get("forbiddenIdentifiers")
    if not isinstance(raw_identifiers, list) or not raw_identifiers:
        raise ExportError("detector source policy has no forbiddenIdentifiers")
    literals: list[dict[str, str]] = []
    for index, raw_identifier in enumerate(raw_identifiers):
        entry = _mapping(raw_identifier, f"forbiddenIdentifiers[{index}]")
        identifier = _string(entry.get("id"), f"forbiddenIdentifiers[{index}].id", limit=80)
        value = _string(entry.get("value"), f"forbiddenIdentifiers[{index}].value", limit=1000)
        literals.append({"id": identifier, "value": value})
    if len({item["id"] for item in literals}) != len(literals):
        raise ExportError("detector source policy contains duplicate IDs")
    if len({item["value"] for item in literals}) != len(literals):
        raise ExportError("detector source policy contains duplicate values")
    _verify_source(source, commit)
    _atomic_write_new(
        output,
        _json_bytes({"forbiddenLiterals": literals, "formatVersion": DETECTOR_FORMAT}),
        mode=0o600,
    )


def inspect_source(source: Path, commit: str, detector_path: Path, output: Path) -> dict[str, object]:
    """Write a deterministic private inspection of every exact source entry."""

    source = source.resolve(strict=True)
    output = _ensure_external_target(source, output, "private inspection output", directory=False)
    tree_oid, entries = _verify_source(source, commit)
    detectors = load_detectors(_external_regular_input(source, detector_path, "private detector file"))
    files: list[dict[str, object]] = []
    blob_digests: dict[str, str | None] = {}
    for entry in entries:
        issues: list[str] = []
        data: bytes | None = None
        if entry.mode == "120000":
            issues.append("symlink_entry")
        elif entry.mode == "160000" or entry.object_type == "commit":
            issues.append("gitlink_entry")
        elif entry.mode not in EXPECTED_SOURCE_MODES or entry.object_type != "blob":
            issues.append("unexpected_entry_mode")
        else:
            data = _read_blob(source, entry)
            content_issue = _text_issue(data)
            if content_issue is not None:
                issues.append(content_issue)
        digest = _sha256(data) if data is not None else None
        blob_digests[entry.path] = digest
        files.append(
            {
                "contentKind": _content_kind(data) if data is not None else "non-regular",
                "detectorHitIds": _detector_hit_ids(data, detectors) if data is not None else [],
                "digest": digest,
                "issues": sorted(issues),
                "licenseProvenanceCues": _license_provenance_cues(entry.path, data),
                "mediaKind": _media_kind(entry.path),
                "relevanceCues": _relevance_cues(entry.path),
                "sizeBytes": len(data) if data is not None else None,
                "sourceMode": entry.mode,
                "sourceObjectId": entry.oid,
                "sourcePath": entry.path,
                "sourceType": entry.object_type,
            }
        )
    inspection = {
        "files": files,
        "formatVersion": INSPECTION_FORMAT,
        "source": {
            "commitObjectId": commit,
            "repository": str(source),
            "treeObjectId": tree_oid,
            "treeSnapshotDigest": _tree_snapshot_digest(entries, blob_digests),
        },
        "summary": {
            "contentKindCounts": _count_scalar(files, "contentKind"),
            "detectorHitFileCount": sum(bool(item["detectorHitIds"]) for item in files),
            "licenseProvenanceCueCounts": _count_list(files, "licenseProvenanceCues"),
            "mediaKindCounts": _count_scalar(files, "mediaKind"),
            "relevanceCueCounts": _count_list(files, "relevanceCues"),
            "trackedFileCount": len(entries),
        },
    }
    end_tree_oid, end_entries = _verify_source(source, commit)
    if end_tree_oid != tree_oid or end_entries != entries:
        raise ExportError("source tree changed during inspection")
    _atomic_write_new(output, _json_bytes(inspection), mode=0o600)
    return inspection


def _git_result(repository: Path, arguments: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *GIT_SAFE_OPTIONS, "-C", str(repository), *arguments],
        capture_output=True,
        text=False,
        check=False,
        cwd=CONTROLLED_GIT_CWD,
        env=_git_environment(),
    )


def _has_files(path: Path) -> bool:
    try:
        return path.is_file() or path.is_symlink() or (
            path.is_dir() and any(item.is_file() or item.is_symlink() for item in path.rglob("*"))
        )
    except OSError:
        return True


def audit_fresh_git(repository: Path) -> list[AuditFinding]:
    """Audit a later, local fresh-root repository and return value-free codes."""

    findings: set[str] = set()
    try:
        root = repository.resolve(strict=True)
    except OSError:
        return [AuditFinding("repository_unavailable")]
    if not root.is_dir():
        return [AuditFinding("repository_not_directory")]
    if any(os.environ.get(name) for name in SENSITIVE_GIT_ENVIRONMENT) or any(
        key.startswith("GIT_CONFIG_") and value for key, value in os.environ.items()
    ):
        findings.add("sensitive_git_environment")
    git_marker = root / ".git"
    if not git_marker.is_dir() or git_marker.is_symlink():
        findings.add("git_directory_not_self_contained")
        return [AuditFinding(code) for code in sorted(findings)]
    try:
        if any(path.is_symlink() for path in git_marker.rglob("*")):
            findings.add("git_metadata_symlink")
    except OSError:
        findings.add("git_metadata_unverifiable")
    object_store = git_marker / "objects"
    if not object_store.is_dir() or object_store.is_symlink():
        findings.add("object_store_not_self_contained")
    for parent in root.parents:
        if (parent / ".git").exists() or (parent / ".git").is_symlink():
            findings.add("parent_git_boundary")
            break

    top = _git_result(root, ["rev-parse", "--show-toplevel"])
    if top.returncode != 0:
        findings.add("git_root_unverifiable")
    else:
        try:
            if Path(top.stdout.decode("utf-8", errors="strict").strip()).resolve(strict=True) != root:
                findings.add("git_root_mismatch")
        except (OSError, UnicodeDecodeError):
            findings.add("git_root_unverifiable")

    common = _git_result(root, ["rev-parse", "--git-common-dir"])
    git_dir = _git_result(root, ["rev-parse", "--absolute-git-dir"])
    if common.returncode != 0 or git_dir.returncode != 0:
        findings.add("git_storage_unverifiable")
    else:
        try:
            common_path = Path(common.stdout.decode("utf-8", errors="strict").strip())
            if not common_path.is_absolute():
                common_path = (root / common_path).resolve(strict=True)
            else:
                common_path = common_path.resolve(strict=True)
            git_dir_path = Path(git_dir.stdout.decode("utf-8", errors="strict").strip()).resolve(strict=True)
            if common_path != git_marker.resolve(strict=True) or git_dir_path != git_marker.resolve(strict=True):
                findings.add("shared_git_storage")
        except (OSError, UnicodeDecodeError):
            findings.add("git_storage_unverifiable")

    worktrees = _git_result(root, ["worktree", "list", "--porcelain"])
    if worktrees.returncode != 0:
        findings.add("worktree_inventory_unverifiable")
    else:
        records = [record for record in worktrees.stdout.split(b"\n\n") if record.strip()]
        if len(records) != 1:
            findings.add("additional_worktrees")
        elif not records[0].startswith(b"worktree "):
            findings.add("worktree_inventory_unverifiable")
        else:
            try:
                worktree_path = Path(records[0].split(b"\n", 1)[0][len(b"worktree ") :].decode("utf-8")).resolve(strict=True)
                if worktree_path != root:
                    findings.add("worktree_root_mismatch")
            except (OSError, UnicodeDecodeError):
                findings.add("worktree_inventory_unverifiable")

    if _has_files(git_marker / "logs"):
        findings.add("reflogs_present")
    if _has_files(git_marker / "refs" / "replace"):
        findings.add("replace_refs_present")
    replace_refs = _git_result(root, ["for-each-ref", "--format=%(refname)", "refs/replace"])
    if replace_refs.returncode != 0 or replace_refs.stdout.strip():
        findings.add("replace_refs_present")
    if _has_files(git_marker / "objects" / "info" / "alternates"):
        findings.add("alternates_present")
    if _has_files(git_marker / "objects" / "info" / "http-alternates"):
        findings.add("alternates_present")
    if _has_files(git_marker / "info" / "grafts"):
        findings.add("grafts_present")
    if _has_files(git_marker / "shallow"):
        findings.add("shallow_history_present")

    refs = _git_result(root, ["for-each-ref", "--format=%(refname)"])
    sole_local_head: bytes | None = None
    if refs.returncode != 0:
        findings.add("refs_unverifiable")
    else:
        ref_names = [line for line in refs.stdout.splitlines() if line]
        local_heads = [line for line in ref_names if line.startswith(b"refs/heads/")]
        if len(local_heads) != 1 or len(ref_names) != 1:
            findings.add("unexpected_refs")
        else:
            sole_local_head = local_heads[0]
    symbolic_head = _git_result(root, ["symbolic-ref", "-q", "HEAD"])
    if symbolic_head.returncode != 0 or sole_local_head is None or symbolic_head.stdout.strip() != sole_local_head:
        findings.add("head_not_single_local_branch")

    status = _git_result(
        root,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"],
    )
    if status.returncode != 0 or status.stdout:
        findings.add("worktree_not_clean")
    remotes = _git_result(root, ["remote"])
    if remotes.returncode != 0 or remotes.stdout.strip():
        findings.add("remotes_present")

    roots = _git_result(root, ["rev-list", "--max-parents=0", "--all"])
    commits = _git_result(root, ["rev-list", "--all"])
    head_parents = _git_result(root, ["rev-list", "--parents", "--max-count=1", "HEAD"])
    if roots.returncode != 0 or len(roots.stdout.splitlines()) != 1:
        findings.add("root_commit_count_not_one")
    if commits.returncode != 0 or len(commits.stdout.splitlines()) != 1:
        findings.add("commit_count_not_one")
    if head_parents.returncode != 0 or len(head_parents.stdout.split()) != 1:
        findings.add("head_has_parent")

    fsck = _git_result(root, ["fsck", "--strict", "--full", "--no-reflogs", "--unreachable"])
    if fsck.returncode != 0:
        findings.add("object_graph_invalid")
    if b"unreachable " in fsck.stdout or b"dangling " in fsck.stdout or b"unreachable " in fsck.stderr or b"dangling " in fsck.stderr:
        findings.add("unreachable_objects_present")

    return [AuditFinding(code) for code in sorted(findings)]


def _audit_document(findings: Sequence[AuditFinding]) -> dict[str, object]:
    return {
        "findings": [{"code": finding.code} for finding in findings],
        "formatVersion": "stateport.fresh-git-audit/v1",
        "status": "passed" if not findings else "blocked",
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    export_parser = subparsers.add_parser("export", help="export one exact clean commit to local private outputs")
    export_parser.add_argument("--source", type=Path, required=True)
    export_parser.add_argument("--commit", required=True)
    policy_group = export_parser.add_mutually_exclusive_group(required=True)
    policy_group.add_argument("--policy", help="tracked policy path within the exact source commit")
    policy_group.add_argument("--policy-file", type=Path, help="reviewed policy file outside the source repository")
    export_parser.add_argument("--private-detectors", type=Path, required=True)
    export_parser.add_argument("--output", type=Path, required=True)
    export_parser.add_argument("--public-manifest", type=Path, required=True)
    export_parser.add_argument("--private-inventory", type=Path, required=True)
    detector_parser = subparsers.add_parser(
        "extract-private-detectors",
        help="extract established detector values to a new private external file",
    )
    detector_parser.add_argument("--source", type=Path, required=True)
    detector_parser.add_argument("--commit", required=True)
    detector_parser.add_argument("--source-policy", required=True)
    detector_parser.add_argument("--output", type=Path, required=True)
    inspect_parser = subparsers.add_parser("inspect", help="inventory exact committed inputs into a private report")
    inspect_parser.add_argument("--source", type=Path, required=True)
    inspect_parser.add_argument("--commit", required=True)
    inspect_parser.add_argument("--private-detectors", type=Path, required=True)
    inspect_parser.add_argument("--private-inventory", type=Path, required=True)
    audit_parser = subparsers.add_parser("audit-fresh-git", help="audit a later local fresh-root candidate")
    audit_parser.add_argument("--repository", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "export":
            exported = export_candidate(
                arguments.source,
                arguments.commit,
                arguments.policy,
                arguments.private_detectors,
                arguments.output,
                arguments.public_manifest,
                arguments.private_inventory,
                policy_file=arguments.policy_file,
            )
            print(json.dumps({"status": "exported" if exported else "blocked"}, sort_keys=True))
            return 0 if exported else 2
        if arguments.command == "extract-private-detectors":
            extract_private_detectors(
                arguments.source,
                arguments.commit,
                arguments.source_policy,
                arguments.output,
            )
            print(json.dumps({"status": "created"}, sort_keys=True))
            return 0
        if arguments.command == "inspect":
            inspection = inspect_source(
                arguments.source,
                arguments.commit,
                arguments.private_detectors,
                arguments.private_inventory,
            )
            summary = inspection["summary"]
            assert isinstance(summary, dict)
            print(
                json.dumps(
                    {
                        "detectorHitFileCount": summary["detectorHitFileCount"],
                        "status": "inspected",
                        "trackedFileCount": summary["trackedFileCount"],
                    },
                    sort_keys=True,
                )
            )
            return 0
        findings = audit_fresh_git(arguments.repository)
        print(json.dumps(_audit_document(findings), indent=2, sort_keys=True))
        return 0 if not findings else 2
    except ExportError as exc:
        print(json.dumps({"error": str(exc), "status": "error"}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
