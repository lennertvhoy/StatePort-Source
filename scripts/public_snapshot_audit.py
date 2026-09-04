#!/usr/bin/env python3
"""Fail-closed, read-only audit of a materialized public snapshot candidate.

The audit takes an external descriptor so the exact candidate Git HEAD can be
bound without placing self-referential identity inside the commit.  Reports
contain finding codes and counts only: candidate paths and matched values are
never copied into the report.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
from typing import Any, Mapping, Sequence
import unicodedata

import yaml


ROOT = Path(__file__).resolve().parents[1]
GATEWAY_SRC = ROOT / "packages" / "sensitive-data-gateway" / "src"
if str(GATEWAY_SRC) not in sys.path:
    sys.path.insert(0, str(GATEWAY_SRC))

from stateport_sensitive_data import DeterministicScanner, SensitiveDataPolicy  # noqa: E402


FORMAT = "stateport.public-snapshot-audit/v1"
INPUT_FORMAT = "stateport.public-snapshot-audit-input/v1"
RIGHTS_FORMAT = "stateport.rights-inventory/v1"
MAX_DESCRIPTOR_BYTES = 64 * 1024
MAX_INVENTORY_BYTES = 2 * 1024 * 1024
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_FILES = 20_000
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
INCLUDED_RIGHTS_CATEGORIES = frozenset(
    {
        "owned_code",
        "owned_documentation",
        "generated_owned_output",
        "third_party_redistributable",
    }
)
INTERNAL_ONLY_PATHS = frozenset(
    {
        "AGENTS.md",
        "BACKLOG.md",
        "STATE.yaml",
        "WORKLOG.md",
    }
)
INTERNAL_ONLY_PREFIXES = (
    ".stateport/",
    "docs/evidence/",
    "docs/history/",
    "docs/release/",
    "evidence/",
    "instances/",
    "output/",
    "release-output/",
)
SECRET_PATH_COMPONENTS = frozenset(
    {
        ".env",
        ".env.local",
        "credentials",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
        "secrets",
    }
)
ASSIGNED_SECRET = re.compile(
    r"(?im)\b(?:api[_-]?key|authorization|credential|password|secret|token)\b\s*[:=]\s*"
    r"(?:['\"][A-Za-z0-9+/=_\-.]{16,}['\"]|[A-Za-z0-9+/=_\-.]{16,}\s*(?=$|[,}\]]))"
)
LOCAL_PATH = re.compile(
    r"(?:/(?:home|Users)/[A-Za-z0-9._-]+(?:/[^\s'\"<>]*)?|[A-Z]:\\Users\\[^\s'\"<>]+)"
)
# Well-known public home-account prefixes that are not owner-private:
# "linuxbrew" is the standard Homebrew-on-Linux prefix pinned by the release
# toolchain, "stateport" is the release images' declared service account,
# "stateport-qualification" and "rehearsal" are the isolated Ubuntu
# qualification fixture/guest identities, and "operator" is the generic
# synthetic account used by redaction fixtures.
# Owner-private absolute paths and all other accounts remain blocking.
PUBLIC_HOME_ACCOUNTS = frozenset(
    {"linuxbrew", "operator", "rehearsal", "stateport", "stateport-qualification"}
)


def _has_private_local_path(text: str) -> bool:
    for match in LOCAL_PATH.finditer(text):
        parts = PurePosixPath(match.group(0)).parts
        if (
            len(parts) >= 3
            and parts[0] == "/"
            and parts[1] == "home"
            and parts[2] in PUBLIC_HOME_ACCOUNTS
        ):
            continue
        return True
    return False


# The repository's known private canary is high-confidence. Generic phrases
# such as "learner data" are privacy guidance, schema names, and source-code
# policy labels; treating those words as leaked records produced false blocks
# without detecting actual personal content.
LEARNER_DATA = re.compile(r"(?i)\b(?:study|life)[_-]lenny\b")
HEAD_RE = re.compile(r"[0-9a-f]{40}\Z")
SPDXISH_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+()\-: ]{0,255}\Z")


@dataclass(frozen=True)
class CandidateFile:
    path: str
    filesystem_path: Path
    size: int


@dataclass(frozen=True)
class AuditResult:
    report: dict[str, object]

    @property
    def passed(self) -> bool:
        return self.report["status"] == "passed"


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


def _git(repository: Path, arguments: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *GIT_SAFE_OPTIONS, "-C", str(repository), *arguments],
        capture_output=True,
        check=False,
        cwd=CONTROLLED_GIT_CWD,
        env=_git_environment(),
    )


def _safe_relative_path(value: object) -> str | None:
    if not isinstance(value, str) or not value or value != value.strip():
        return None
    if unicodedata.normalize("NFC", value) != value or "\\" in value or "\x00" in value:
        return None
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        return None
    return value


def _regular_external_file(base: Path, relative: object, maximum: int) -> tuple[Path, bytes] | None:
    normalized = _safe_relative_path(relative)
    if normalized is None:
        return None
    current = base
    try:
        for component in PurePosixPath(normalized).parts:
            current = current / component
            info = os.lstat(current)
            if stat.S_ISLNK(info.st_mode):
                return None
        info = os.lstat(current)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
            return None
        resolved_base = base.resolve(strict=True)
        resolved = current.resolve(strict=True)
        if not resolved.is_relative_to(resolved_base):
            return None
        return resolved, resolved.read_bytes()
    except OSError:
        return None


def _descriptor(path: Path, findings: Counter[str]) -> tuple[dict[str, Any] | None, Path | None]:
    try:
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            findings["audit_metadata_unsafe"] += 1
            return None, None
        if info.st_size > MAX_DESCRIPTOR_BYTES:
            findings["audit_metadata_oversized"] += 1
            return None, None
        data = path.read_bytes()
        value = json.loads(data.decode("utf-8", errors="strict"))
    except FileNotFoundError:
        findings["audit_metadata_missing"] += 1
        return None, None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        findings["audit_metadata_invalid"] += 1
        return None, None
    if not isinstance(value, dict) or set(value) != {"formatVersion", "git", "rightsInventory"}:
        findings["audit_metadata_invalid"] += 1
        return None, None
    if value.get("formatVersion") != INPUT_FORMAT:
        findings["audit_metadata_invalid"] += 1
        return None, None
    git_value = value.get("git")
    rights = value.get("rightsInventory")
    valid_git = (
        isinstance(git_value, dict)
        and set(git_value) == {"expectedBranch", "expectedHead"}
        and isinstance(git_value.get("expectedBranch"), str)
        and 0 < len(git_value["expectedBranch"]) <= 255
        and "\x00" not in git_value["expectedBranch"]
        and HEAD_RE.fullmatch(str(git_value.get("expectedHead", ""))) is not None
    )
    valid_rights = (
        isinstance(rights, dict)
        and set(rights) == {"digest", "path"}
        and isinstance(rights.get("digest"), str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", rights["digest"]) is not None
        and _safe_relative_path(rights.get("path")) is not None
    )
    if not valid_git or not valid_rights:
        findings["audit_metadata_invalid"] += 1
        return None, None
    return value, path.resolve(strict=True)


def _candidate_root(path: Path, metadata: Path | None, findings: Counter[str]) -> Path | None:
    try:
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode):
            findings["candidate_root_symlink"] += 1
            return None
        if not stat.S_ISDIR(info.st_mode):
            findings["candidate_root_invalid"] += 1
            return None
        root = path.resolve(strict=True)
    except OSError:
        findings["candidate_root_unavailable"] += 1
        return None
    if metadata is not None and (metadata == root or metadata.is_relative_to(root)):
        findings["audit_metadata_inside_candidate"] += 1
    return root


def _walk_candidate(root: Path, findings: Counter[str]) -> list[CandidateFile]:
    files: list[CandidateFile] = []
    seen_portable: set[str] = set()
    total_bytes = 0

    def visit(directory: Path, prefix: tuple[str, ...]) -> None:
        nonlocal total_bytes
        try:
            entries = sorted(
                os.scandir(directory),
                key=lambda item: item.name.encode("utf-8", errors="surrogateescape"),
            )
        except OSError:
            findings["candidate_tree_unreadable"] += 1
            return
        for entry in entries:
            relative_parts = (*prefix, entry.name)
            relative = PurePosixPath(*relative_parts).as_posix()
            if prefix == () and entry.name == ".git":
                continue
            if entry.name.casefold() == ".git":
                findings["nested_git_metadata"] += 1
                continue
            if unicodedata.normalize("NFC", relative) != relative or any(
                ord(char) < 32 for char in relative
            ):
                findings["nonportable_path"] += 1
                continue
            portable_key = unicodedata.normalize("NFC", relative).casefold()
            if portable_key in seen_portable:
                findings["portable_path_collision"] += 1
            seen_portable.add(portable_key)
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError:
                findings["candidate_entry_unreadable"] += 1
                continue
            if stat.S_ISLNK(info.st_mode):
                findings["symlink_entry"] += 1
            elif stat.S_ISDIR(info.st_mode):
                visit(Path(entry.path), relative_parts)
            elif stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1:
                    findings["hardlinked_file"] += 1
                    continue
                if len(files) >= MAX_FILES:
                    findings["candidate_file_limit_exceeded"] += 1
                    continue
                total_bytes += int(info.st_size)
                if info.st_size > MAX_FILE_BYTES:
                    findings["candidate_file_too_large_to_scan"] += 1
                if total_bytes > MAX_TOTAL_BYTES:
                    findings["candidate_total_size_exceeded"] += 1
                files.append(CandidateFile(relative, Path(entry.path), int(info.st_size)))
            else:
                findings["special_file_entry"] += 1

    visit(root, ())
    if not files:
        findings["candidate_has_no_files"] += 1
    return files


def _audit_git(
    root: Path, metadata: Mapping[str, Any] | None, findings: Counter[str]
) -> str | None:
    git_marker = root / ".git"
    try:
        marker = os.lstat(git_marker)
    except OSError:
        findings["git_metadata_missing"] += 1
        return None
    if stat.S_ISLNK(marker.st_mode) or not stat.S_ISDIR(marker.st_mode):
        findings["git_metadata_not_self_contained"] += 1
        return None
    if any(os.environ.get(name) for name in SENSITIVE_GIT_ENVIRONMENT) or any(
        key.startswith("GIT_CONFIG_") and value for key, value in os.environ.items()
    ):
        findings["git_sensitive_environment"] += 1
    try:
        if any(path.is_symlink() for path in git_marker.rglob("*")):
            findings["git_metadata_symlink"] += 1
    except OSError:
        findings["git_metadata_unverifiable"] += 1
    for relative, code in (
        ("objects/info/alternates", "git_alternates_present"),
        ("objects/info/http-alternates", "git_alternates_present"),
        ("info/grafts", "git_grafts_present"),
        ("shallow", "git_shallow_history_present"),
    ):
        try:
            selected = git_marker / relative
            if selected.exists() or selected.is_symlink():
                findings[code] += 1
        except OSError:
            findings["git_metadata_unverifiable"] += 1
    top = _git(root, ["rev-parse", "--show-toplevel"])
    head = _git(root, ["rev-parse", "--verify", "HEAD"])
    branch = _git(root, ["symbolic-ref", "--quiet", "--short", "HEAD"])
    status_result = _git(
        root,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"],
    )
    remotes = _git(root, ["remote"])
    refs = _git(root, ["for-each-ref", "--format=%(refname)"])
    replace_refs = _git(root, ["for-each-ref", "--format=%(refname)", "refs/replace"])
    fsck = _git(root, ["fsck", "--strict", "--full", "--no-reflogs", "--unreachable"])
    try:
        top_path = Path(top.stdout.decode("utf-8", errors="strict").strip()).resolve(strict=True)
    except (OSError, UnicodeDecodeError):
        top_path = None
    if top.returncode != 0 or top_path != root:
        findings["git_root_mismatch"] += 1
    observed_head: str | None = None
    try:
        candidate_head = head.stdout.decode("ascii", errors="strict").strip()
        if head.returncode == 0 and HEAD_RE.fullmatch(candidate_head):
            observed_head = candidate_head
        else:
            findings["git_head_unverifiable"] += 1
    except UnicodeDecodeError:
        findings["git_head_unverifiable"] += 1
    expected_git = metadata.get("git") if isinstance(metadata, Mapping) else None
    if isinstance(expected_git, Mapping):
        if observed_head != expected_git.get("expectedHead"):
            findings["git_head_mismatch"] += 1
        try:
            observed_branch = branch.stdout.decode("utf-8", errors="strict").strip()
        except UnicodeDecodeError:
            observed_branch = ""
        if branch.returncode != 0 or observed_branch != expected_git.get("expectedBranch"):
            findings["git_branch_mismatch"] += 1
    else:
        findings["git_identity_metadata_missing"] += 1
    if status_result.returncode != 0:
        findings["git_status_unverifiable"] += 1
    elif status_result.stdout:
        findings["git_worktree_dirty"] += 1
    if remotes.returncode != 0:
        findings["git_remotes_unverifiable"] += 1
    elif remotes.stdout.strip():
        findings["git_remotes_present"] += 1
    if refs.returncode != 0:
        findings["git_refs_unverifiable"] += 1
    else:
        ref_names = [item for item in refs.stdout.splitlines() if item]
        local = [item for item in ref_names if item.startswith(b"refs/heads/")]
        if len(ref_names) != 1 or len(local) != 1:
            findings["git_unexpected_refs"] += 1
    if replace_refs.returncode != 0 or replace_refs.stdout.strip():
        findings["git_replace_refs_present"] += 1
    if fsck.returncode != 0:
        findings["git_object_graph_invalid"] += 1
    if any(
        marker in fsck.stdout or marker in fsck.stderr for marker in (b"unreachable ", b"dangling ")
    ):
        findings["git_unreachable_objects_present"] += 1
    return observed_head


def _audit_content(files: Sequence[CandidateFile], findings: Counter[str]) -> int:
    scanner = DeterministicScanner()
    policy = SensitiveDataPolicy()
    scanned_bytes = 0
    for item in files:
        folded_parts = {part.casefold() for part in PurePosixPath(item.path).parts}
        if folded_parts & SECRET_PATH_COMPONENTS:
            findings["secret_risk_path"] += 1
        if item.path in INTERNAL_ONLY_PATHS or item.path.startswith(INTERNAL_ONLY_PREFIXES):
            findings["internal_only_artifact"] += 1
        if item.size > MAX_FILE_BYTES or scanned_bytes + item.size > MAX_TOTAL_BYTES:
            continue
        try:
            data = item.filesystem_path.read_bytes()
        except OSError:
            findings["candidate_file_unreadable"] += 1
            continue
        scanned_bytes += len(data)
        if b"\x00" in data:
            findings["unscannable_binary_content"] += 1
            continue
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            findings["unscannable_non_utf8_content"] += 1
            continue
        sensitive = scanner.scan(text, source_kind="public_snapshot_file", policy=policy)
        blocked_categories = {
            item.category
            for item in sensitive
            if item.confidence in {"confirmed_sensitive", "high_confidence"}
        }
        for _category in blocked_categories:
            findings["high_risk_credential_content"] += 1
        if ASSIGNED_SECRET.search(text):
            findings["assigned_secret_content"] += 1
        if _has_private_local_path(text):
            findings["local_private_path_content"] += 1
        if LEARNER_DATA.search(text):
            findings["learner_data_marker_content"] += 1
    return scanned_bytes


def _load_rights(
    metadata_document: Mapping[str, Any] | None,
    metadata_path: Path | None,
    candidate: Path | None,
    findings: Counter[str],
) -> dict[str, Any] | None:
    if not isinstance(metadata_document, Mapping) or metadata_path is None:
        findings["rights_inventory_metadata_missing"] += 1
        return None
    rights_descriptor = metadata_document.get("rightsInventory")
    if not isinstance(rights_descriptor, Mapping):
        findings["rights_inventory_metadata_missing"] += 1
        return None
    loaded = _regular_external_file(
        metadata_path.parent, rights_descriptor.get("path"), MAX_INVENTORY_BYTES
    )
    if loaded is None:
        findings["rights_inventory_missing_or_unsafe"] += 1
        return None
    path, data = loaded
    if candidate is not None and (path == candidate or path.is_relative_to(candidate)):
        findings["rights_inventory_inside_candidate"] += 1
    if "sha256:" + sha256(data).hexdigest() != rights_descriptor.get("digest"):
        findings["rights_inventory_digest_mismatch"] += 1
    try:
        document = yaml.safe_load(data.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, yaml.YAMLError):
        findings["rights_inventory_invalid"] += 1
        return None
    if not isinstance(document, dict):
        findings["rights_inventory_invalid"] += 1
        return None
    return document


def _audit_rights(
    document: Mapping[str, Any] | None, files: Sequence[CandidateFile], findings: Counter[str]
) -> int:
    if document is None:
        return 0
    if (
        set(document) != {"formatVersion", "metadata", "files"}
        or document.get("formatVersion") != RIGHTS_FORMAT
    ):
        findings["rights_inventory_invalid"] += 1
        return 0
    metadata = document.get("metadata")
    if not isinstance(metadata, dict) or set(metadata) != {
        "created",
        "scope",
        "completeness",
        "notes",
    }:
        findings["rights_inventory_invalid"] += 1
    elif not (
        isinstance(metadata.get("created"), str)
        and re.fullmatch(r"\d{4}-\d{2}-\d{2}", metadata["created"]) is not None
        and isinstance(metadata.get("scope"), str)
        and 1 <= len(metadata["scope"]) <= 2048
        and isinstance(metadata.get("completeness"), str)
        and 1 <= len(metadata["completeness"]) <= 1024
        and isinstance(metadata.get("notes"), str)
        and 1 <= len(metadata["notes"]) <= 4096
    ):
        findings["rights_inventory_invalid"] += 1
    entries = document.get("files")
    if not isinstance(entries, list):
        findings["rights_inventory_invalid"] += 1
        return 0
    inventory_paths: list[str] = []
    required = {
        "path",
        "category",
        "proposedLicence",
        "source",
        "attribution",
        "redistributable",
        "publicExportDecision",
        "evidence",
        "reviewerStatus",
    }
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != required:
            findings["rights_inventory_entry_invalid"] += 1
            continue
        path = _safe_relative_path(entry.get("path"))
        if path is None or len(path) > 1024:
            findings["rights_inventory_path_invalid"] += 1
            continue
        inventory_paths.append(path)
        strings_valid = all(
            isinstance(entry.get(field), str)
            and bool(str(entry[field]).strip())
            and len(str(entry[field])) <= maximum
            for field, maximum in (
                ("proposedLicence", 256),
                ("source", 1024),
                ("attribution", 1024),
                ("evidence", 2048),
            )
        )
        licence = entry.get("proposedLicence")
        licence_valid = (
            isinstance(licence, str)
            and SPDXISH_RE.fullmatch(licence) is not None
            and licence.casefold() not in {"none", "noassertion", "proprietary", "unknown"}
        )
        if not strings_valid or not licence_valid:
            findings["rights_license_or_provenance_invalid"] += 1
        if (
            entry.get("category") not in INCLUDED_RIGHTS_CATEGORIES
            or entry.get("redistributable") is not True
            or entry.get("publicExportDecision") != "include"
            or entry.get("reviewerStatus") not in {"reviewed_internal", "reviewed_independent"}
        ):
            findings["rights_entry_not_publicly_cleared"] += 1
    inventory_counter = Counter(inventory_paths)
    if any(count > 1 for count in inventory_counter.values()):
        findings["rights_inventory_duplicate_path"] += 1
    candidate_paths = {item.path for item in files}
    inventory_set = set(inventory_paths)
    if candidate_paths - inventory_set:
        findings["rights_inventory_missing_files"] += 1
    if inventory_set - candidate_paths:
        findings["rights_inventory_unknown_files"] += 1
    return len(entries)


def _checks(findings: Counter[str]) -> list[dict[str, object]]:
    groups = {
        "candidate_tree": (
            "candidate_",
            "hardlinked_",
            "nested_git_",
            "nonportable_",
            "portable_",
            "special_",
            "symlink_",
        ),
        "content_safety": (
            "assigned_",
            "high_risk_",
            "internal_",
            "learner_",
            "local_",
            "secret_",
            "unscannable_",
        ),
        "git_identity": ("git_",),
        "rights_and_provenance": ("rights_",),
        "audit_metadata": ("audit_",),
    }
    checks: list[dict[str, object]] = []
    for identifier, prefixes in groups.items():
        count = sum(value for code, value in findings.items() if code.startswith(prefixes))
        checks.append(
            {
                "findingCount": count,
                "id": identifier,
                "status": "passed" if count == 0 else "blocked",
            }
        )
    return checks


def audit_public_snapshot(candidate: Path, metadata: Path) -> AuditResult:
    findings: Counter[str] = Counter()
    metadata_document, metadata_path = _descriptor(metadata, findings)
    root = _candidate_root(candidate, metadata_path, findings)
    files: list[CandidateFile] = []
    observed_head: str | None = None
    scanned_bytes = 0
    if root is not None:
        files = _walk_candidate(root, findings)
        observed_head = _audit_git(root, metadata_document, findings)
        scanned_bytes = _audit_content(files, findings)
    rights = _load_rights(metadata_document, metadata_path, root, findings)
    inventory_entries = _audit_rights(rights, files, findings)
    expected_git = metadata_document.get("git") if isinstance(metadata_document, Mapping) else None
    verified_head = (
        observed_head
        if isinstance(expected_git, Mapping)
        and observed_head == expected_git.get("expectedHead")
        and "git_head_mismatch" not in findings
        else None
    )
    finding_counts = [{"code": code, "count": findings[code]} for code in sorted(findings)]
    report: dict[str, object] = {
        "checks": _checks(findings),
        "findingCounts": finding_counts,
        "formatVersion": FORMAT,
        "gitIdentity": {"verifiedHead": verified_head},
        "status": "passed" if not findings else "blocked",
        "summary": {
            "auditedByteCount": scanned_bytes,
            "auditedFileCount": len(files),
            "rightsInventoryEntryCount": inventory_entries,
        },
    }
    return AuditResult(report)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--candidate", type=Path, required=True, help="materialized candidate Git root"
    )
    parser.add_argument(
        "--metadata", type=Path, required=True, help="external public-snapshot audit descriptor"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    result = audit_public_snapshot(arguments.candidate, arguments.metadata)
    print(json.dumps(result.report, indent=2, sort_keys=True))
    return 0 if result.passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
