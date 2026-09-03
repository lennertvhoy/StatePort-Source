"""Small, deterministic template materialisation and locking primitives.

The lifecycle contract deliberately lives beside the StateDD models.  A
template manifest describes ownership and materialisation policy; the lock
file records the exact source revision and the hashes observed at creation.
Neither file grants a template runtime permissions.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import fcntl
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Literal
from urllib.parse import urlsplit

from statedd_core.models import Instance, Template
from statedd_core.lifecycle_errors import LifecycleError
from statedd_core.lifecycle_v2 import (
    MANIFEST_V2_FORMAT,
    assert_fixture_use_allowed,
    assert_materializable_v2,
    load_instance_overrides,
    normalize_manifest_v1,
    normalize_manifest_v2,
)
from statedd_core.schema_registry import (
    LOCK_SCHEMA_ID,
    SchemaRegistryError,
    find_builtin_schema_registry,
)
from statedd_core.yaml import StateDDYamlError, parse_yaml_text


MANIFEST_FORMAT = "statedd.template-manifest/v1"
LOCK_FORMAT = "statedd.lock/v1"
SOURCE_DESCRIPTOR_FORMAT = "statedd.source/v1"
SOURCE_DESCRIPTOR_V2_FORMAT = "statedd.source/v2"
OVERRIDE_REPORT_FORMAT = "statedd.override-report/v1"
UPGRADE_PLAN_FORMAT = "statedd.upgrade-plan/v1"
UPGRADE_RECEIPT_FORMAT = "statedd.upgrade-receipt/v1"
UPGRADE_APPROVAL_FORMAT = "statedd.upgrade-approval/v1"
OWNERS = {"template", "instance", "generated"}
PROVISIONS = {"copy", "create", "generate"}
MERGES = {"replace", "preserve", "append_only"}
GENERATORS = {"none", "materializer", "runner"}
SENSITIVITIES = {"public", "internal", "private", "secret"}
RETIREMENT_POLICIES = {"retain", "remove_if_unmodified"}
UPGRADE_ACTIONS = {"preserve", "replace", "add", "retain", "remove", "block"}
_ACTION_FOR_CLASSIFICATION = {
    "unchanged": "preserve",
    "overridden": "block",
    "added": "add",
    "removed": "block",
    "changed": "replace",
    "blocked": "block",
    "retained_unmodified": "retain",
    "retained_modified": "retain",
    "retired": "remove",
}
CLASSIFICATIONS = {
    "unchanged",
    "overridden",
    "added",
    "removed",
    "changed",
    "blocked",
    "retained_unmodified",
    "retained_modified",
    "retired",
}
Classification = Literal[
    "unchanged",
    "overridden",
    "added",
    "removed",
    "changed",
    "blocked",
    "retained_unmodified",
    "retained_modified",
    "retired",
]


def _retirement_policy(value: Any, name: str, *, owner: str, provision: str) -> str:
    """Validate a narrow, explicit removal policy for generated output."""
    if value is None:
        return "retain"
    if value == "remove":
        value = "remove_if_unmodified"
    if value not in RETIREMENT_POLICIES:
        raise LifecycleError(f"{name} must be one of {sorted(RETIREMENT_POLICIES)}")
    if value == "remove_if_unmodified" and (
        owner != "generated" or provision != "generate"
    ):
        raise LifecycleError(
            f"{name} removal is allowed only for generated files using generate provision"
        )
    return value


def _require_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LifecycleError(f"{name} must be a non-empty string")
    return value


def _safe_relative_path(value: Any, name: str) -> str:
    path = _require_string(value, name)
    if "\\" in path:
        raise LifecycleError(f"{name} must use portable '/' separators")
    candidate = Path(path)
    if candidate.is_absolute() or path.startswith("/") or (len(path) > 1 and path[1] == ":"):
        raise LifecycleError(f"{name} must be a relative path")
    if any(part == ".." for part in candidate.parts):
        raise LifecycleError(f"{name} must not traverse parent directories")
    if "." in candidate.parts:
        raise LifecycleError(f"{name} must not contain an explicit '.' path component")
    return candidate.as_posix()


def _confined(root: Path, relative_path: str, label: str) -> Path:
    root_resolved = root.resolve()
    candidate = (root / relative_path).resolve()
    if not candidate.is_relative_to(root_resolved):
        raise LifecycleError(f"{label} escapes its root")
    return candidate


def _safe_target_path(root: Path, relative_path: str, label: str) -> Path:
    """Confine a write target and reject existing symlinks on its path."""
    if root.is_symlink():
        raise LifecycleError("instance root symlink is not safe")
    current = root
    for part in Path(relative_path).parts:
        current = current / part
        if current.is_symlink():
            raise LifecycleError(f"{label} uses a symlink, which is not safe")
    return _confined(root, relative_path, label)


def _read_yaml(path: Path, label: str) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        if lines and lines[0].strip() == "---":
            text = "\n".join(lines[1:]) + "\n"
        data = parse_yaml_text(text)
    except (OSError, UnicodeDecodeError, StateDDYamlError) as exc:
        raise LifecycleError(f"could not read {label}: {exc}") from exc
    if not isinstance(data, dict):
        raise LifecycleError(f"{label} must contain a mapping")
    return data


def _validate_manifest_v1_data(data: dict[str, Any]) -> dict[str, Any]:
    if data.get("formatVersion") != MANIFEST_FORMAT:
        raise LifecycleError(f"formatVersion must be {MANIFEST_FORMAT!r}")
    template_id = _require_string(data.get("templateId"), "templateId")
    template_version = _require_string(data.get("templateVersion"), "templateVersion")
    files = data.get("files")
    if not isinstance(files, list) or not files:
        raise LifecycleError("files must be a non-empty list")

    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(files):
        if not isinstance(raw, dict):
            raise LifecycleError(f"files[{index}] must be a mapping")
        path = _safe_relative_path(raw.get("path"), f"files[{index}].path")
        if path in seen:
            raise LifecycleError(f"files contains duplicate path {path!r}")
        seen.add(path)
        owner = raw.get("owner")
        if owner not in OWNERS:
            raise LifecycleError(f"files[{index}].owner must be one of {sorted(OWNERS)}")
        provision = raw.get("provision")
        if provision not in PROVISIONS:
            raise LifecycleError(
                f"files[{index}].provision must be one of {sorted(PROVISIONS)}"
            )
        merge = raw.get("merge")
        if merge not in MERGES:
            raise LifecycleError(f"files[{index}].merge must be one of {sorted(MERGES)}")
        generation = raw.get("generation", "none")
        if generation not in GENERATORS:
            raise LifecycleError(
                f"files[{index}].generation must be one of {sorted(GENERATORS)}"
            )
        sensitivity = raw.get("sensitivity")
        if sensitivity not in SENSITIVITIES:
            raise LifecycleError(
                f"files[{index}].sensitivity must be one of {sorted(SENSITIVITIES)}"
            )
        required = raw.get("required")
        if not isinstance(required, bool):
            raise LifecycleError(f"files[{index}].required must be a boolean")
        retirement_policy = _retirement_policy(
            raw.get("retirementPolicy", raw.get("removalPolicy")),
            f"files[{index}].retirementPolicy",
            owner=owner,
            provision=provision,
        )
        schema_id = raw.get("schema")
        if schema_id is not None:
            schema_id = _require_string(schema_id, f"files[{index}].schema")
        source = raw.get("source", path)
        if source is not None:
            source = _safe_relative_path(source, f"files[{index}].source")
        if provision == "copy" and source is None:
            raise LifecycleError(f"files[{index}] copy provision requires source")
        if provision == "generate" and generation == "none":
            raise LifecycleError(
                f"files[{index}] generate provision requires a generator"
            )
        if owner == "generated" and provision != "generate":
            raise LifecycleError("generated files must use generate provision")
        if owner == "template" and merge == "preserve":
            raise LifecycleError("template-owned files cannot use preserve merge")
        if owner == "instance" and merge == "replace":
            raise LifecycleError("instance-owned files cannot use replace merge")
        normalized.append(
            {
                "path": path,
                "source": source,
                "owner": owner,
                "provision": provision,
                "merge": merge,
                "generation": generation,
                "required": required,
                "schema": schema_id,
                "sensitivity": sensitivity,
                "retirementPolicy": retirement_policy,
            }
        )
    return {
        "formatVersion": MANIFEST_FORMAT,
        "templateId": template_id,
        "templateVersion": template_version,
        "files": sorted(normalized, key=lambda item: item["path"]),
    }


def load_template_manifest(template_path: Path | str) -> dict[str, Any]:
    """Load a v1 or v2 lifecycle manifest into one normalized representation."""
    root = _safe_root_path(template_path, "template root")
    manifest_path = _confined(root, ".statedd/manifest.yaml", "manifest")
    raw_data = _read_yaml(manifest_path, "manifest.yaml")
    if raw_data.get("formatVersion") == MANIFEST_FORMAT:
        data = normalize_manifest_v1(_validate_manifest_v1_data(raw_data))
    elif raw_data.get("formatVersion") == MANIFEST_V2_FORMAT:
        data = normalize_manifest_v2(raw_data, root)
    else:
        raise LifecycleError(
            f"formatVersion must be {MANIFEST_FORMAT!r} or {MANIFEST_V2_FORMAT!r}"
        )
    template_path = _confined(root, "template.yaml", "template metadata")
    if data["formatVersion"] == MANIFEST_FORMAT or template_path.exists():
        template_data = _read_yaml(template_path, "template.yaml")
        try:
            template = Template.from_dict(template_data)
        except (AttributeError, TypeError, ValueError) as exc:
            raise LifecycleError(f"invalid template.yaml: {exc}") from exc
        if data["templateId"] != template.metadata.id:
            raise LifecycleError(
                f"manifest templateId {data['templateId']!r} does not match "
                f"template metadata.id {template.metadata.id!r}"
            )
        if data["templateVersion"] != template.metadata.version:
            raise LifecycleError(
                f"manifest templateVersion {data['templateVersion']!r} does not match "
                f"template metadata.version {template.metadata.version!r}"
            )
    for item in data["files"]:
        if item["provision"] == "copy":
            source = _confined(root, item["source"], f"files.{item['path']}.source")
            if not source.is_file():
                raise LifecycleError(f"manifest source file is missing: {item['source']}")
    return data


def _hash_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _hash_file(path: Path) -> str:
    try:
        return _hash_bytes(path.read_bytes())
    except OSError as exc:
        raise LifecycleError(f"could not hash {path}: {exc}") from exc


_FULL_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_FULL_TREE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _safe_root_path(value: Path | str, label: str) -> Path:
    """Return an absolute root without following symlinked ancestors.

    ``Path.resolve()`` is deliberately not used for the check: resolving first
    would erase the evidence that the caller supplied an unsafe path.  The
    returned path is absolute but still unresolved, so a later replacement of
    the root cannot silently change the transaction target.
    """
    raw = Path(value)
    absolute = Path(os.path.abspath(raw))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink():
            raise LifecycleError(
                f"{label} or an ancestor is a symlink: {absolute}",
                code="unsafe_path",
            )
    return absolute


def _instance_root_identity(instance_root: Path) -> dict[str, Any]:
    """Capture the path and filesystem identity bound by a plan."""
    root = _safe_root_path(instance_root, "instance root")
    if root.is_symlink() or not root.is_dir():
        raise LifecycleError("instance root is not a regular directory", code="unsafe_path")
    try:
        stat = root.stat()
    except OSError as exc:
        raise LifecycleError(f"could not inspect instance root: {exc}", code="unsafe_path") from exc
    return {"path": root.as_posix(), "device": stat.st_dev, "inode": stat.st_ino}


def _assert_instance_root_binding(plan: dict[str, Any], instance_root: Path) -> None:
    expected = plan.get("current", {}).get("rootIdentity")
    actual = _instance_root_identity(instance_root)
    if expected != actual:
        raise LifecycleError(
            "instance root is not the exact root used for planning",
            code="stale_instance_root",
        )


def _git(args: list[str], cwd: Path | None = None, *, timeout: int = 60) -> str:
    """Run a bounded Git command without invoking a shell."""
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise LifecycleError(f"git {' '.join(args[:3])} failed: {detail}")
    return result.stdout.strip()


def _safe_git_ref(value: str) -> str:
    ref = _require_string(value, "requested_ref")
    if ref.startswith("-") or any(token in ref for token in ("..", "@{", "\\", "\n", "\r")):
        raise LifecycleError("requested_ref is not a safe Git ref")
    try:
        _git(["check-ref-format", "--allow-onelevel", ref])
    except LifecycleError:
        if ref != "HEAD":
            raise LifecycleError("requested_ref is not a valid Git ref")
    return ref


def _git_root(path: Path) -> Path | None:
    try:
        return Path(_git(["rev-parse", "--show-toplevel"], path)).resolve()
    except LifecycleError:
        return None


def _reject_secret_bearing_repository(value: str) -> None:
    """Reject credentials before a repository identity becomes durable."""
    parsed = urlsplit(value)
    if parsed.password is not None:
        raise LifecycleError("repository URL must not contain credentials")
    if parsed.username is not None and parsed.scheme in {"http", "https", "file", "ssh"}:
        raise LifecycleError("repository URL must not contain embedded credentials")


def _assert_clean_git_checkout(root: Path) -> None:
    status = _git(["status", "--porcelain", "--untracked-files=all"], root)
    if status:
        raise LifecycleError("canonical Git source checkout must be clean")


def resolve_git_source(
    repository: Path | str,
    requested_ref: str = "HEAD",
    *,
    checkout_path: Path | str | None = None,
    expected_commit: str | None = None,
) -> dict[str, Any]:
    """Resolve a canonical template source to one immutable Git commit.

    Local repositories are inspected without changing their checkout. Remote
    repositories require an explicit checkout path, are cloned without a
    shell, and are detached at the resolved commit. A branch or tag is only a
    request; the returned commit and tree are the durable identity.
    """
    requested_ref = _safe_git_ref(requested_ref)
    repository_text = _require_string(str(repository), "repository")
    _reject_secret_bearing_repository(repository_text)
    descriptor_repository = repository_text
    is_local = not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", repository_text) and not repository_text.startswith(("git@", "ssh:"))
    if checkout_path is not None and Path(checkout_path).expanduser().exists() and _git_root(Path(checkout_path).expanduser()) is not None:
        # Verification of an already materialised checkout must not clone or
        # mutate it, even when the durable repository field is a remote URL.
        root = _safe_root_path(Path(checkout_path).expanduser(), "Git checkout")
    elif is_local:
        root = _safe_root_path(Path(repository_text).expanduser(), "Git source")
        if _git_root(root) is None:
            raise LifecycleError(f"repository is not a Git checkout: {repository_text}")
        if checkout_path is not None and Path(checkout_path).resolve() != root:
            raise LifecycleError("checkout_path must match a local repository")
        try:
            descriptor_repository = _git(["remote", "get-url", "origin"], root)
        except LifecycleError:
            descriptor_repository = root.as_posix()
        _reject_secret_bearing_repository(descriptor_repository)
    else:
        if checkout_path is None:
            raise LifecycleError("remote Git resolution requires checkout_path")
        root = _safe_root_path(Path(checkout_path).expanduser(), "Git checkout")
        if root.exists() and any(root.iterdir()):
            raise LifecycleError(f"checkout_path is not empty: {root}")
        root.parent.mkdir(parents=True, exist_ok=True)
        _git(["clone", "--no-checkout", repository_text, root.as_posix()])
    commit = _git(["rev-parse", "--verify", f"{requested_ref}^{{commit}}"], root)
    if not _FULL_COMMIT.fullmatch(commit):
        raise LifecycleError("Git resolution did not return a full commit id")
    if expected_commit is not None:
        expected = _require_string(expected_commit, "expected_commit").lower()
        if not _FULL_COMMIT.fullmatch(expected) or commit != expected:
            raise LifecycleError("resolved Git commit does not match expected_commit")
    head = _git(["rev-parse", "--verify", "HEAD^{commit}"], root)
    if head != commit:
        if is_local:
            raise LifecycleError(
                "local Git source is not checked out at the requested immutable commit"
            )
        _git(["checkout", "--detach", commit], root)
        head = _git(["rev-parse", "--verify", "HEAD^{commit}"], root)
    if head != commit:
        raise LifecycleError("Git source checkout does not match resolved commit")
    _assert_clean_git_checkout(root)
    tree = _git(["rev-parse", "--verify", f"{commit}^{{tree}}"], root)
    if not _FULL_TREE.fullmatch(tree):
        raise LifecycleError("Git resolution did not return a full tree id")
    manifest = load_template_manifest(root)
    if manifest.get("sourceClass") != "canonical_source" or not manifest.get("productionEligible"):
        raise LifecycleError("Git source is not a production-eligible canonical source")
    declared_repository = manifest.get("source", {}).get("repository")
    if declared_repository:
        _reject_secret_bearing_repository(declared_repository)
        if declared_repository != descriptor_repository:
            raise LifecycleError("canonical manifest repository does not match Git origin")
    manifest_path = _confined(root, ".statedd/manifest.yaml", "manifest")
    return {
        "formatVersion": SOURCE_DESCRIPTOR_V2_FORMAT,
        "kind": "git",
        "sourceClass": "canonical_source",
        "productionEligible": True,
        "repository": descriptor_repository,
        "requestedRef": requested_ref,
        "resolvedCommit": commit,
        "resolvedTree": tree,
        "checkoutLocation": root.as_posix(),
        "manifestDigest": _hash_file(manifest_path),
        "sourceDigest": _source_revision(root, manifest),
    }


def _immutable_git_tree_id(root: Path) -> str:
    """Recompute the Git tree ID for a bounded regular-file snapshot."""

    files: list[tuple[str, str, str]] = []
    total_bytes = 0
    observed_directories: set[str] = set()

    def observed(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
        return (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
        )

    for current, directories, filenames in os.walk(root, topdown=True, followlinks=False):
        directories.sort()
        filenames.sort()
        current_path = Path(current)
        for name in directories:
            directory = current_path / name
            info = os.lstat(directory)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise LifecycleError("immutable Git snapshot contains an unsafe directory")
            observed_directories.add(directory.relative_to(root).as_posix())
        for name in filenames:
            path = current_path / name
            before = os.lstat(path)
            if (
                stat.S_ISLNK(before.st_mode)
                or not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size > 64 * 1024 * 1024
            ):
                raise LifecycleError("immutable Git snapshot may contain only bounded regular files")
            descriptor = -1
            try:
                descriptor = os.open(
                    path,
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                )
                opened = os.fstat(descriptor)
                if observed(before) != observed(opened):
                    raise LifecycleError("immutable Git snapshot changed while it was opened")
                payload = bytearray()
                while len(payload) <= 64 * 1024 * 1024:
                    chunk = os.read(descriptor, min(1024 * 1024, 64 * 1024 * 1024 + 1 - len(payload)))
                    if not chunk:
                        break
                    payload.extend(chunk)
                data = bytes(payload)
            except OSError as exc:
                raise LifecycleError("immutable Git snapshot could not be read") from exc
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
            after = os.lstat(path)
            if len(data) > 64 * 1024 * 1024:
                raise LifecycleError("immutable Git snapshot file exceeds the supported size bound")
            if observed(before) != observed(after) or len(data) != before.st_size:
                raise LifecycleError("immutable Git snapshot changed while it was read")
            total_bytes += len(data)
            if total_bytes > 512 * 1024 * 1024 or len(files) >= 32_768:
                raise LifecycleError("immutable Git snapshot exceeds the supported resource bound")
            relative = path.relative_to(root).as_posix()
            mode = "100755" if before.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH) else "100644"
            blob = hashlib.sha1(
                b"blob " + str(len(data)).encode("ascii") + b"\0" + data,
                usedforsecurity=False,
            ).hexdigest()
            files.append((relative, mode, blob))
    if not files:
        raise LifecycleError("immutable Git snapshot contains no regular files")
    tracked_directories = {
        Path(relative).parents[index].as_posix()
        for relative, _mode, _blob in files
        for index in range(len(Path(relative).parents) - 1)
    }
    if observed_directories != tracked_directories:
        raise LifecycleError("immutable Git snapshot contains untracked directories")

    tree: dict[str, tuple[str, Any]] = {}
    for relative, mode, blob in files:
        node = tree
        parts = Path(relative).parts
        for part in parts[:-1]:
            existing = node.get(part)
            if existing is None:
                child: dict[str, tuple[str, Any]] = {}
                node[part] = ("tree", child)
                node = child
            elif existing[0] == "tree":
                node = existing[1]
            else:
                raise LifecycleError("immutable Git snapshot paths overlap")
        if parts[-1] in node:
            raise LifecycleError("immutable Git snapshot paths overlap")
        node[parts[-1]] = ("file", (mode, blob))

    def encode(node: dict[str, tuple[str, Any]]) -> str:
        entries: list[tuple[bytes, bytes]] = []
        for name, (kind, value) in node.items():
            try:
                name_bytes = name.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise LifecycleError("immutable Git snapshot path is not UTF-8") from exc
            if kind == "tree":
                entry_mode = b"40000"
                object_id = encode(value)
                sort_key = name_bytes + b"/"
            else:
                entry_mode = value[0].encode("ascii")
                object_id = value[1]
                sort_key = name_bytes
            entry = entry_mode + b" " + name_bytes + b"\0" + bytes.fromhex(object_id)
            entries.append((sort_key, entry))
        payload = b"".join(entry for _key, entry in sorted(entries, key=lambda item: item[0]))
        return hashlib.sha1(
            b"tree " + str(len(payload)).encode("ascii") + b"\0" + payload,
            usedforsecurity=False,
        ).hexdigest()

    return encode(tree)


def _verify_immutable_git_snapshot(
    root: Path,
    source_descriptor: dict[str, Any],
    manifest: dict[str, Any],
) -> None:
    checkout = source_descriptor.get("checkoutLocation")
    try:
        checkout_root = Path(str(checkout)).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise LifecycleError("immutable Git snapshot checkout identity is invalid") from exc
    if (
        checkout_root != root
        or not _DIGEST.fullmatch(str(source_descriptor.get("cacheDigest", "")))
        or not re.fullmatch(r"[0-9a-f]{40}", str(source_descriptor.get("resolvedCommit", "")))
        or _immutable_git_tree_id(root) != source_descriptor.get("resolvedTree")
        or _hash_file(_confined(root, ".statedd/manifest.yaml", "manifest"))
        != source_descriptor.get("manifestDigest")
        or _source_revision(root, manifest) != source_descriptor.get("sourceDigest")
    ):
        raise LifecycleError("immutable Git snapshot does not match its source descriptor")


def _source_revision(root: Path, manifest: dict[str, Any]) -> str:
    # The identity is deliberately independent of the local checkout path.  It
    # covers ownership and materialisation semantics as well as copied bytes,
    # so changing a file's role cannot be mistaken for a content-only update.
    if manifest.get("formatVersion") == MANIFEST_V2_FORMAT:
        assets: list[dict[str, Any]] = []
        for item in manifest["assets"]:
            asset = dict(item)
            if asset.get("retirementPolicy") == "retain":
                # The default is backward-compatible metadata.  Do not make
                # every pre-retirement v2 lock stale merely because the
                # normalizer now exposes that default explicitly.
                asset.pop("retirementPolicy", None)
            if item.get("provisionPolicy") == "copy_from_template":
                asset["sourceHash"] = _hash_file(
                    _confined(root, item["source"], "manifest source")
                )
            elif item.get("kind") == "tree" and item.get("owner") == "template":
                asset["treeHash"] = _tree_digest(root, item["path"])
            assets.append(asset)
        payload = {
            "manifestFormat": MANIFEST_V2_FORMAT,
            "template": manifest["template"],
            "sourceClass": manifest["sourceClass"],
            "productionEligible": manifest["productionEligible"],
            "modules": manifest["modules"],
            "assets": sorted(assets, key=lambda item: (item["path"], item["id"])),
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return _hash_bytes(encoded)
    files: list[dict[str, Any]] = []
    for item in manifest["files"]:
        source_hash = None
        if item["provision"] == "copy":
            source_hash = _hash_file(
                _confined(root, item["source"], "manifest source")
            )
        entry = {
            "path": item["path"],
            "source": item["source"],
            "owner": item["owner"],
            "provision": item["provision"],
            "merge": item["merge"],
            "generation": item["generation"],
            "retirementPolicy": item["retirementPolicy"],
            "required": item["required"],
            "schema": item["schema"],
            "sensitivity": item["sensitivity"],
            "sourceHash": source_hash,
        }
        if entry["retirementPolicy"] == "retain":
            entry.pop("retirementPolicy")
        files.append(entry)
    payload = {
        "templateHash": _hash_file(
            _confined(root, "template.yaml", "template metadata")
        ),
        "files": files,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _hash_bytes(encoded)


def template_source_revision(template_path: Path | str) -> str:
    """Return the path-independent content contract bound into lifecycle locks."""

    root = _safe_root_path(template_path, "template root")
    return _source_revision(root, load_template_manifest(root))


def describe_template_source(template_path: Path | str) -> dict[str, Any]:
    """Return a stable, offline-capable descriptor for a local template source.

    v1 retains its legacy ``path``/``identity`` descriptor. v2 records the
    local checkout separately from its content digest and leaves
    ``resolvedCommit`` null: this parser never resolves Git references.
    """
    root = _safe_root_path(template_path, "template root")
    if not root.is_dir():
        raise LifecycleError(f"template source is not a directory: {root}")
    manifest = load_template_manifest(root)
    source_revision = _source_revision(root, manifest)
    if (
        manifest.get("formatVersion") == MANIFEST_V2_FORMAT
        and manifest.get("sourceClass") == "canonical_source"
        and manifest.get("productionEligible")
        and _git_root(root) is not None
    ):
        return resolve_git_source(root, "HEAD")
    if manifest.get("formatVersion") == MANIFEST_V2_FORMAT:
        return {
            "formatVersion": SOURCE_DESCRIPTOR_V2_FORMAT,
            "kind": "local_development",
            "sourceClass": manifest["sourceClass"],
            "productionEligible": manifest["productionEligible"],
            "checkoutLocation": root.resolve().as_posix(),
            "sourceDigest": source_revision,
            "resolvedCommit": None,
        }
    return {
        "formatVersion": SOURCE_DESCRIPTOR_FORMAT,
        "kind": "local",
        "path": root.resolve().as_posix(),
        "identity": source_revision,
    }


def _source_descriptor_identity(source: dict[str, Any]) -> dict[str, Any]:
    """Return provenance fields that identify bytes, not checkout observations."""
    return {
        key: value
        for key, value in source.items()
        if key not in {"checkoutLocation", "requestedRef"}
    }


def _source_descriptors_match(left: dict[str, Any], right: dict[str, Any]) -> bool:
    """Compare source identity without treating path/ref observations as identity."""
    return _source_descriptor_identity(left) == _source_descriptor_identity(right)


# More explicit spelling for callers that treat source descriptors as a
# resolution operation.  Keep both names additive and intentionally identical.
resolve_template_source = describe_template_source


def _quote(value: str) -> str:
    # Lifecycle-generated values are controlled identifiers, paths, hashes, and
    # user-provided display fields. Double quotes keep spaces unambiguous for the
    # deliberately small StateDD YAML subset.
    return '"' + value.replace('"', "'") + '"'


def _dump_yaml(value: Any, indent: int = 0) -> list[str]:
    lines: list[str] = []
    prefix = " " * indent
    if isinstance(value, dict):
        for key in sorted(value):
            nested = value[key]
            if isinstance(nested, dict) and not nested:
                lines.append(f"{prefix}{key}: {{}}")
            elif isinstance(nested, list) and not nested:
                lines.append(f"{prefix}{key}: []")
            elif isinstance(nested, (dict, list)):
                lines.append(f"{prefix}{key}:")
                lines.extend(_dump_yaml(nested, indent + 2))
            elif nested is None:
                lines.append(f"{prefix}{key}: null")
            elif isinstance(nested, bool):
                lines.append(f"{prefix}{key}: {'true' if nested else 'false'}")
            elif isinstance(nested, int):
                lines.append(f"{prefix}{key}: {nested}")
            else:
                lines.append(f"{prefix}{key}: {_quote(str(nested))}")
    elif isinstance(value, list):
        for nested in value:
            if isinstance(nested, dict):
                keys = sorted(nested)
                first = keys[0]
                first_value = nested[first]
                if isinstance(first_value, dict) and not first_value:
                    lines.append(f"{prefix}- {first}: {{}}")
                elif isinstance(first_value, list) and not first_value:
                    lines.append(f"{prefix}- {first}: []")
                elif isinstance(first_value, (dict, list)):
                    lines.append(f"{prefix}- {first}:")
                    lines.extend(_dump_yaml(first_value, indent + 4))
                else:
                    rendered = "null" if first_value is None else (
                        "true" if first_value is True else "false" if first_value is False else str(first_value)
                    )
                    if isinstance(first_value, str):
                        rendered = _quote(first_value)
                    lines.append(f"{prefix}- {first}: {rendered}")
                for key in keys[1:]:
                    nested_value = nested[key]
                    if isinstance(nested_value, dict) and not nested_value:
                        lines.append(f"{prefix}  {key}: {{}}")
                    elif isinstance(nested_value, list) and not nested_value:
                        lines.append(f"{prefix}  {key}: []")
                    elif isinstance(nested_value, (dict, list)):
                        lines.append(f"{prefix}  {key}:")
                        lines.extend(_dump_yaml(nested_value, indent + 4))
                    elif nested_value is None:
                        lines.append(f"{prefix}  {key}: null")
                    elif isinstance(nested_value, bool):
                        lines.append(f"{prefix}  {key}: {'true' if nested_value else 'false'}")
                    else:
                        rendered = _quote(str(nested_value)) if isinstance(nested_value, str) else str(nested_value)
                        lines.append(f"{prefix}  {key}: {rendered}")
            elif nested is None:
                lines.append(f"{prefix}- null")
            elif isinstance(nested, bool):
                lines.append(f"{prefix}- {'true' if nested else 'false'}")
            else:
                rendered = _quote(str(nested)) if isinstance(nested, str) else str(nested)
                lines.append(f"{prefix}- {rendered}")
    return lines


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_yaml(path: Path, data: dict[str, Any]) -> None:
    # Canonical state (lock.yaml, instance.yaml, upgrade receipts) must
    # survive a crash at any point: stage beside the target, fsync the file,
    # atomically replace, then fsync the directory so the rename itself is
    # durable. A plain write_text leaves a truncated-file crash window.
    if path.is_symlink():
        raise LifecycleError(f"refusing to write canonical state through a symlink: {path.name}")
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = "\n".join(_dump_yaml(data)) + "\n"
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _read_instance(instance_path: Path) -> Instance:
    instance = Instance.from_dict(_read_yaml(instance_path / "instance.yaml", "instance.yaml"))
    return instance


def _instance_identity(instance_path: Path) -> tuple[str, str | None]:
    """Read both StatePort and canonical-template instance descriptors."""
    data = _read_yaml(instance_path / "instance.yaml", "instance.yaml")
    try:
        instance = Instance.from_dict(data)
    except (TypeError, ValueError, AttributeError):
        metadata = data.get("metadata")
        if not isinstance(metadata, dict):
            raise LifecycleError("instance.yaml has no readable metadata")
        instance_id = _require_string(metadata.get("id"), "instance.metadata.id")
        spec = data.get("spec")
        template_ref = spec.get("templateRef") if isinstance(spec, dict) else None
        template_id = template_ref.get("id") if isinstance(template_ref, dict) else None
        return instance_id, template_id
    return instance.metadata.id, instance.spec.template_ref.id


def _manifest_files(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    files = manifest.get("files")
    if not isinstance(files, list):
        raise LifecycleError("manifest files must be a list")
    result: dict[str, dict[str, Any]] = {}
    folded: dict[str, str] = {}
    for item in files:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise LifecycleError("manifest contains an invalid file entry")
        path = item["path"]
        if path in result:
            raise LifecycleError(f"manifest contains duplicate path {path!r}")
        previous = folded.get(path.casefold())
        if previous is not None and previous != path:
            raise LifecycleError(f"manifest contains case-colliding paths {previous!r} and {path!r}")
        folded[path.casefold()] = path
        result[path] = item
    return result


def _effective_tree_owner(tree: dict[str, Any]) -> str:
    """Normalize the legacy durable-state tree declaration without changing its digest."""

    if (
        tree.get("owner") == "template"
        and tree.get("role") == "durable_state"
        and tree.get("provisionPolicy") == "create_if_missing"
        and tree.get("updatePolicy") == "preserve"
    ):
        return "instance"
    return str(tree.get("owner"))


def _lock_owner_matches_manifest(item: dict[str, Any], locked_owner: Any) -> bool:
    if locked_owner == item.get("owner"):
        return True
    return bool(
        locked_owner == "template"
        and item.get("owner") == "instance"
        and item.get("legacyDurableTree") is True
    )


def _tree_manifest_files(root: Path, manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Expand declared template-seeded trees into deterministic file assets.

    Tree declarations remain the ownership boundary; expansion only considers
    regular files already present in the canonical source tree and never
    discovers files outside a declared tree.
    """
    result: dict[str, dict[str, Any]] = {}
    folded: dict[str, str] = {}
    for tree in manifest.get("trees", []):
        if tree.get("owner") != "template":
            continue
        tree_root = _confined(root, tree["path"], f"source tree {tree['path']}")
        if not tree_root.is_dir() or tree_root.is_symlink():
            raise LifecycleError(f"template tree source is not a safe directory: {tree['path']}")
        for source in sorted(tree_root.rglob("*")):
            relative = source.relative_to(tree_root).as_posix()
            path = f"{tree['path']}/{relative}"
            if source.is_symlink():
                raise LifecycleError(f"template tree contains a symlink: {path}")
            if not source.is_file():
                continue
            if path in result:
                raise LifecycleError(f"tree assets overlap at {path}")
            previous = folded.get(path.casefold())
            if previous is not None and previous != path:
                raise LifecycleError(f"tree contains case-colliding paths {previous!r} and {path!r}")
            folded[path.casefold()] = path
            if path in _manifest_files(manifest):
                raise LifecycleError(f"exact asset overlaps declared tree at {path}")
            effective_owner = _effective_tree_owner(tree)
            result[path] = {
                "path": path,
                "source": path,
                "owner": effective_owner,
                "provision": "copy",
                "merge": "preserve",
                "generation": "none",
                "required": bool(tree.get("required")),
                "schema": tree.get("schema"),
                "sensitivity": tree.get("sensitivity"),
                "tree": tree["path"],
                "legacyDurableTree": effective_owner != tree.get("owner"),
                "retirementPolicy": tree.get("retirementPolicy", "retain"),
            }
    return result


def _all_manifest_files(root: Path, manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return exact assets plus files within declared template-owned trees."""
    exact = _manifest_files(manifest)
    trees = _tree_manifest_files(root, manifest)
    overlap = set(exact).intersection(trees)
    if overlap:
        raise LifecycleError(f"manifest exact/tree collision at {sorted(overlap)[0]}")
    folded: dict[str, str] = {}
    for path in [*exact, *trees]:
        previous = folded.get(path.casefold())
        if previous is not None and previous != path:
            raise LifecycleError(f"manifest contains case-colliding paths {previous!r} and {path!r}")
        folded[path.casefold()] = path
    return {**exact, **trees}


def _tree_digest(root: Path, tree_path: str) -> str:
    tree_root = _confined(root, tree_path, f"tree {tree_path}")
    if tree_root.is_symlink() or not tree_root.is_dir():
        raise LifecycleError(f"tree is not a safe directory: {tree_path}")
    records: list[dict[str, str]] = []
    for candidate in sorted(tree_root.rglob("*")):
        relative = candidate.relative_to(tree_root).as_posix()
        if candidate.is_symlink():
            raise LifecycleError(f"tree contains a symlink: {tree_path}/{relative}")
        if candidate.is_file():
            records.append({"path": relative, "hash": _hash_file(candidate)})
        elif not candidate.is_dir():
            raise LifecycleError(f"tree contains an unsupported entry: {tree_path}/{relative}")
    return _canonical_digest(records)


def _validate_lock(lock: dict[str, Any]) -> dict[str, Any]:
    """Validate the safety-critical shape of a lock before inspecting it."""
    if lock.get("formatVersion") != LOCK_FORMAT:
        raise LifecycleError(f"lock formatVersion must be {LOCK_FORMAT!r}")
    _require_string(lock.get("instanceId"), "lock.instanceId")
    template = lock.get("template")
    if not isinstance(template, dict):
        raise LifecycleError("lock.template must be a mapping")
    _require_string(template.get("id"), "lock.template.id")
    _require_string(template.get("version"), "lock.template.version")
    source_revision = _require_string(template.get("sourceRevision"), "lock.template.sourceRevision")
    if not _DIGEST.fullmatch(source_revision):
        raise LifecycleError(
            "lock.template.sourceRevision must be a sha256 digest",
            code="incomplete_source_identity",
        )
    source_path = template.get("sourcePath")
    if source_path is not None:
        _require_string(source_path, "lock.template.sourcePath")
    source = template.get("source")
    if source is not None:
        if not isinstance(source, dict):
            raise LifecycleError("lock.template.source must be a mapping")
        if source.get("formatVersion") == SOURCE_DESCRIPTOR_FORMAT:
            if source.get("kind") != "local":
                raise LifecycleError("only local lock sources are supported")
            _require_string(source.get("path"), "lock.template.source.path")
            identity = _require_string(source.get("identity"), "lock.template.source.identity")
            if not _DIGEST.fullmatch(identity):
                raise LifecycleError(
                    "lock.template.source.identity must be a sha256 digest",
                    code="incomplete_source_identity",
                )
            if source["identity"] != template["sourceRevision"]:
                raise LifecycleError(
                    "lock source identity does not match sourceRevision",
                    code="source_provenance_mismatch",
                )
            if source_path != source["path"]:
                raise LifecycleError(
                    "lock source path does not match sourcePath",
                    code="source_provenance_mismatch",
                )
        elif source.get("formatVersion") == SOURCE_DESCRIPTOR_V2_FORMAT:
            if source.get("kind") not in {"local_development", "git"}:
                raise LifecycleError("unsupported v2 lock source kind")
            _require_string(source.get("checkoutLocation"), "lock.template.source.checkoutLocation")
            source_digest = _require_string(source.get("sourceDigest"), "lock.template.source.sourceDigest")
            if not _DIGEST.fullmatch(source_digest):
                raise LifecycleError(
                    "lock.template.source.sourceDigest must be a sha256 digest",
                    code="incomplete_source_identity",
                )
            if source.get("sourceClass") not in {"canonical_source", "synthetic_fixture", "compatibility_fixture"}:
                raise LifecycleError("lock.template.source.sourceClass is invalid")
            if not isinstance(source.get("productionEligible"), bool):
                raise LifecycleError("lock.template.source.productionEligible must be a boolean")
            if source.get("kind") == "git":
                if source.get("sourceClass") != "canonical_source" or not source.get("productionEligible"):
                    raise LifecycleError("Git lock sources must be canonical and production eligible")
                for field, pattern in (("resolvedCommit", _FULL_COMMIT), ("resolvedTree", _FULL_TREE)):
                    value = _require_string(source.get(field), f"lock.template.source.{field}").lower()
                    if not pattern.fullmatch(value):
                        raise LifecycleError(f"lock.template.source.{field} must be a full Git id")
                _require_string(source.get("repository"), "lock.template.source.repository")
                _safe_git_ref(_require_string(source.get("requestedRef"), "lock.template.source.requestedRef"))
                manifest_digest = _require_string(source.get("manifestDigest"), "lock.template.source.manifestDigest")
                if not _DIGEST.fullmatch(manifest_digest):
                    raise LifecycleError(
                        "lock.template.source.manifestDigest must be a sha256 digest",
                        code="incomplete_source_identity",
                    )
            elif "resolvedCommit" not in source or source.get("resolvedCommit") is not None:
                raise LifecycleError(
                    "local v2 lock source must explicitly declare resolvedCommit: null",
                    code="incomplete_source_identity",
                )
            if source_path != source["checkoutLocation"]:
                raise LifecycleError(
                    "lock source checkoutLocation does not match sourcePath",
                    code="source_provenance_mismatch",
                )
            if source["sourceDigest"] != template["sourceRevision"]:
                raise LifecycleError(
                    "lock source digest does not match sourceRevision",
                    code="source_provenance_mismatch",
                )
        else:
            raise LifecycleError("lock.template.source.formatVersion is unsupported")
    files = lock.get("files")
    if not isinstance(files, list) or not files:
        raise LifecycleError("lock.files must be a non-empty list")
    seen: set[str] = set()
    for index, entry in enumerate(files):
        if not isinstance(entry, dict):
            raise LifecycleError(f"lock.files[{index}] must be a mapping")
        path = _safe_relative_path(entry.get("path"), f"lock.files[{index}].path")
        if path in seen:
            raise LifecycleError(f"lock.files contains duplicate path {path!r}")
        seen.add(path)
        if entry.get("owner") not in OWNERS:
            raise LifecycleError(f"lock.files[{index}].owner is invalid")
        if entry.get("merge") not in MERGES:
            raise LifecycleError(f"lock.files[{index}].merge is invalid")
        if not isinstance(entry.get("required"), bool):
            raise LifecycleError(f"lock.files[{index}].required must be a boolean")
        if entry.get("sensitivity") not in SENSITIVITIES:
            raise LifecycleError(f"lock.files[{index}].sensitivity is invalid")
        retirement_policy = entry.get("retirementPolicy", "retain")
        if retirement_policy not in RETIREMENT_POLICIES:
            raise LifecycleError(f"lock.files[{index}].retirementPolicy is invalid")
        if retirement_policy == "remove_if_unmodified" and entry.get("owner") != "generated":
            raise LifecycleError(
                f"lock.files[{index}].retirementPolicy removal requires generated ownership"
            )
        for hash_name in ("sourceHash", "materializedHash"):
            value = entry.get(hash_name)
            if value is not None:
                _require_string(value, f"lock.files[{index}].{hash_name}")
    trees = lock.get("trees", [])
    if not isinstance(trees, list):
        raise LifecycleError("lock.trees must be a list")
    seen_trees: set[str] = set()
    for index, entry in enumerate(trees):
        if not isinstance(entry, dict):
            raise LifecycleError(f"lock.trees[{index}] must be a mapping")
        path = _safe_relative_path(entry.get("path"), f"lock.trees[{index}].path")
        if path in seen_trees:
            raise LifecycleError(f"lock.trees contains duplicate path {path!r}")
        seen_trees.add(path)
        if entry.get("owner") not in OWNERS:
            raise LifecycleError(f"lock.trees[{index}].owner is invalid")
        if entry.get("sensitivity") not in SENSITIVITIES:
            raise LifecycleError(f"lock.trees[{index}].sensitivity is invalid")
        for hash_name in ("baselineHash", "materializedHash"):
            value = entry.get(hash_name)
            if value is not None:
                _require_string(value, f"lock.trees[{index}].{hash_name}")
    retired = lock.get("retired", [])
    if not isinstance(retired, list):
        raise LifecycleError("lock.retired must be a list")
    retired_paths: set[str] = set()
    for index, entry in enumerate(retired):
        if not isinstance(entry, dict):
            raise LifecycleError(f"lock.retired[{index}] must be a mapping")
        path = _safe_relative_path(entry.get("path"), f"lock.retired[{index}].path")
        if path in retired_paths or path in seen:
            raise LifecycleError(f"lock.retired contains duplicate path {path!r}")
        retired_paths.add(path)
        if entry.get("owner") not in OWNERS:
            raise LifecycleError(f"lock.retired[{index}].owner is invalid")
        policy = entry.get("retirementPolicy", "retain")
        if policy not in RETIREMENT_POLICIES:
            raise LifecycleError(f"lock.retired[{index}].retirementPolicy is invalid")
        if policy == "remove_if_unmodified" and entry.get("owner") != "generated":
            raise LifecycleError(
                f"lock.retired[{index}].retirementPolicy removal requires generated ownership"
            )
        disposition = entry.get("disposition")
        if disposition not in {"retained", "removed"}:
            raise LifecycleError(f"lock.retired[{index}].disposition is invalid")
        for hash_name in ("baselineHash", "currentHash"):
            value = entry.get(hash_name)
            if value is not None:
                _require_string(value, f"lock.retired[{index}].{hash_name}")
    history = lock.get("history", [])
    if not isinstance(history, list) or any(not isinstance(item, dict) for item in history):
        raise LifecycleError("lock.history must be a list of mappings")
    return lock


def _read_lock(lock_path: Path) -> dict[str, Any]:
    return _validate_lock(_read_yaml(lock_path, "lock.yaml"))


def validate_lifecycle_lock(lock: dict[str, Any]) -> dict[str, Any]:
    """Validate and return one lifecycle lock without reading or mutating disk."""

    if not isinstance(lock, dict):
        raise LifecycleError("lock must be a mapping")
    return _validate_lock(lock)


def validate_lifecycle_lock_against_manifest(
    lock: dict[str, Any],
    manifest: dict[str, Any],
    template_root: Path,
) -> None:
    """Require a validated lock to preserve the selected manifest ownership sets."""

    validated = validate_lifecycle_lock(lock)
    _validate_lock_against_manifest(validated, manifest, template_root)


def _locked_source(lock: dict[str, Any]) -> dict[str, Any]:
    template = lock["template"]
    source = template.get("source")
    if isinstance(source, dict):
        if source.get("formatVersion") == SOURCE_DESCRIPTOR_V2_FORMAT:
            return {
                "formatVersion": SOURCE_DESCRIPTOR_V2_FORMAT,
                "path": source["checkoutLocation"],
                "identity": source["sourceDigest"],
                "descriptor": dict(source),
            }
        return dict(source)
    # v1 locks created before source descriptors were added remain readable.
    return {
        "formatVersion": SOURCE_DESCRIPTOR_FORMAT,
        "kind": "local",
        "path": _require_string(template.get("sourcePath"), "lock.template.sourcePath"),
        "identity": template["sourceRevision"],
    }


def _validate_lock_against_manifest(
    lock: dict[str, Any], manifest: dict[str, Any], root: Path | None = None
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    manifest_files = _all_manifest_files(root, manifest) if root is not None else _manifest_files(manifest)
    lock_files = {entry["path"]: entry for entry in lock["files"]}
    if set(manifest_files) != set(lock_files):
        raise LifecycleError("lock and manifest file ownership sets do not match")
    retired = lock.get("retired", [])
    if any(entry.get("path") in manifest_files for entry in retired):
        raise LifecycleError("retired lock path is active in the manifest")
    for path, item in manifest_files.items():
        entry = lock_files[path]
        for field in ("owner", "merge", "required", "sensitivity"):
            if field == "owner" and _lock_owner_matches_manifest(item, entry.get(field)):
                continue
            if entry.get(field) != item.get(field):
                raise LifecycleError(f"lock and manifest disagree for {path}: {field}")
        if entry.get("retirementPolicy", "retain") != item.get("retirementPolicy", "retain"):
            raise LifecycleError(f"lock and manifest disagree for {path}: retirementPolicy")
    manifest_trees = {item["path"]: item for item in manifest.get("trees", [])}
    lock_trees = {entry["path"]: entry for entry in lock.get("trees", [])}
    if set(manifest_trees) != set(lock_trees):
        raise LifecycleError("lock and manifest tree ownership sets do not match")
    for path, item in manifest_trees.items():
        entry = lock_trees[path]
        effective_owner = _effective_tree_owner(item)
        for field in ("owner", "required", "sensitivity", "updatePolicy"):
            expected = effective_owner if field == "owner" else item.get(field)
            if field == "owner" and entry.get(field) in {item.get(field), effective_owner}:
                continue
            if entry.get(field) != expected:
                raise LifecycleError(f"lock and manifest disagree for tree {path}: {field}")
        if entry.get("retirementPolicy", "retain") != item.get("retirementPolicy", "retain"):
            raise LifecycleError(f"lock and manifest disagree for tree {path}: retirementPolicy")
    return manifest_files, lock_files


def _instance_file_hash(instance_root: Path, path: str) -> tuple[bool, str | None, str | None]:
    """Return (exists, hash, safety_error) for a manifest-owned path."""
    try:
        target = _confined(instance_root, path, f"instance file {path}")
    except LifecycleError as exc:
        return False, None, str(exc)
    if not target.exists():
        return False, None, None
    if target.is_symlink():
        return True, None, "symlinked instance files are not safe to classify"
    if not target.is_file():
        return True, None, "manifest-owned path is not a regular file"
    try:
        return True, _hash_file(target), None
    except LifecycleError as exc:
        return True, None, str(exc)


def _instance_paths(instance_root: Path) -> set[str]:
    """List regular files without following links, failing on unsafe links."""
    paths: set[str] = set()
    try:
        for candidate in instance_root.rglob("*"):
            relative = candidate.relative_to(instance_root).as_posix()
            if candidate.is_symlink():
                raise LifecycleError(f"symlinked instance path is not safe: {relative}")
            if candidate.is_file():
                paths.add(relative)
    except OSError as exc:
        raise LifecycleError(f"could not inspect instance files: {exc}") from exc
    return paths


def _report_entry(
    *,
    path: str,
    classification: Classification,
    owner: str | None = None,
    locked_hash: str | None = None,
    current_hash: str | None = None,
    reason: str = "",
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "path": path,
        "classification": classification,
        "owner": owner,
        "lockedHash": locked_hash,
        "currentHash": current_hash,
        "reason": reason,
    }
    return entry


def _summary(entries: list[dict[str, Any]]) -> dict[str, int]:
    return {classification: sum(
        1 for entry in entries if entry.get("classification") == classification
    ) for classification in sorted(CLASSIFICATIONS)}


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return _hash_bytes(encoded)


def _normalize_migration_set(value: Any) -> list[dict[str, str]]:
    """Normalize the declarative migration identities bound to one plan."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise LifecycleError("migration_set must be a list")
    result: list[dict[str, str]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise LifecycleError(f"migration_set[{index}] must be a mapping")
        if set(item) != {"migrationId", "contractDigest"}:
            raise LifecycleError(
                f"migration_set[{index}] must contain migrationId and contractDigest only"
            )
        migration_id = _require_string(item.get("migrationId"), f"migration_set[{index}].migrationId")
        contract_digest = _require_string(
            item.get("contractDigest"), f"migration_set[{index}].contractDigest"
        )
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", contract_digest):
            raise LifecycleError(f"migration_set[{index}].contractDigest must be a sha256 digest")
        result.append({"migrationId": migration_id, "contractDigest": contract_digest})
    result.sort(key=lambda item: item["migrationId"])
    if len({item["migrationId"] for item in result}) != len(result):
        raise LifecycleError("migration_set must not contain duplicate migration IDs")
    return result


def plan_digest(plan: dict[str, Any]) -> str:
    """Return the digest of a plan excluding its self-referential digest."""
    def stable(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: stable(item)
                for key, item in value.items()
                if key not in {"planDigest", "checkoutLocation", "instancePath"}
            }
        if isinstance(value, list):
            return [stable(item) for item in value]
        return value

    payload = stable({key: value for key, value in plan.items() if key != "planDigest"})
    return _canonical_digest(payload)


def _validate_upgrade_plan(plan: Any) -> dict[str, Any]:
    """Validate the typed, closed action vocabulary before trusting a plan."""
    if not isinstance(plan, dict):
        raise LifecycleError("upgrade plan must be a mapping")
    if plan.get("formatVersion") != UPGRADE_PLAN_FORMAT:
        raise LifecycleError("upgrade plan format is unsupported")
    if not isinstance(plan.get("files"), list) or plan.get("entries") != plan.get("files"):
        raise LifecycleError("upgrade plan files and entries must be the same list")
    if not isinstance(plan.get("blocked"), bool) or not isinstance(plan.get("safe"), bool):
        raise LifecycleError("upgrade plan blocked and safe must be booleans")
    if plan["safe"] == plan["blocked"]:
        raise LifecycleError("upgrade plan safe must be the inverse of blocked")
    current = plan.get("current")
    if not isinstance(current, dict):
        raise LifecycleError("upgrade plan current state is missing")
    root_identity = current.get("rootIdentity")
    if not isinstance(root_identity, dict):
        raise LifecycleError("upgrade plan instance root identity is missing")
    if (
        not isinstance(root_identity.get("path"), str)
        or not root_identity["path"]
        or isinstance(root_identity.get("device"), bool)
        or not isinstance(root_identity.get("device"), int)
        or isinstance(root_identity.get("inode"), bool)
        or not isinstance(root_identity.get("inode"), int)
    ):
        raise LifecycleError("upgrade plan instance root identity is invalid")
    for index, entry in enumerate(plan["files"]):
        if not isinstance(entry, dict):
            raise LifecycleError(f"upgrade plan entry {index} must be a mapping")
        path = _safe_relative_path(entry.get("path"), f"upgrade plan entry {index}.path")
        if path != entry["path"]:
            raise LifecycleError(f"upgrade plan entry {index}.path is not canonical")
        if entry.get("actionType") not in {"file", "tree_file"}:
            raise LifecycleError(f"upgrade plan entry {path} has an invalid actionType")
        classification = entry.get("classification")
        action = entry.get("action")
        if classification not in _ACTION_FOR_CLASSIFICATION:
            raise LifecycleError(f"upgrade plan entry {path} has an invalid classification")
        if action not in UPGRADE_ACTIONS:
            raise LifecycleError(f"upgrade plan entry {path} has an invalid action")
        if action != _ACTION_FOR_CLASSIFICATION[classification]:
            raise LifecycleError(
                f"upgrade plan entry {path} action does not match its classification"
            )
        for field in ("lockedHash", "currentHash", "targetHash"):
            value = entry.get(field)
            if value is not None and (
                not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value)
            ):
                raise LifecycleError(f"upgrade plan entry {path}.{field} is not a sha256 digest")
        if action == "remove" and (
            entry.get("owner") != "generated"
            or entry.get("retirementPolicy") != "remove_if_unmodified"
            or classification != "retired"
        ):
            raise LifecycleError(f"upgrade plan entry {path} has an unsafe retirement action")
        if action == "retain" and classification not in {"retained_unmodified", "retained_modified"}:
            raise LifecycleError(f"upgrade plan entry {path} has an invalid retention action")
    retirements = plan.get("retirements")
    retirement = plan.get("retirement")
    if not isinstance(retirements, list) or not isinstance(retirement, dict):
        raise LifecycleError("upgrade plan retirement binding is missing")
    if retirement.get("entries") != retirements:
        raise LifecycleError("upgrade plan retirement entries are not bound")
    expected_retirements = [
        entry for entry in plan["files"] if entry.get("action") in {"retain", "remove"}
    ]
    if retirements != expected_retirements:
        raise LifecycleError("upgrade plan retirements do not match typed actions")
    trees = plan.get("trees")
    if not isinstance(trees, list):
        raise LifecycleError("upgrade plan tree actions are missing")
    for index, tree in enumerate(trees):
        if not isinstance(tree, dict) or tree.get("actionType") != "tree":
            raise LifecycleError(f"upgrade plan tree action {index} is not typed")
        _safe_relative_path(tree.get("path"), f"upgrade plan tree action {index}.path")
        for field in ("currentHash", "lockedHash", "targetHash"):
            value = tree.get(field)
            if value is not None and (
                not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value)
            ):
                raise LifecycleError(f"upgrade plan tree {tree['path']}.{field} is not a sha256 digest")
    migrations = _normalize_migration_set(plan.get("migrationSet"))
    if migrations != plan.get("migrationSet"):
        raise LifecycleError("upgrade plan migration set is not canonical")
    if plan.get("migrationSetDigest") != _canonical_digest(migrations):
        raise LifecycleError("upgrade plan migration set digest is invalid")
    if plan.get("retirementDigest") != _canonical_digest(retirements):
        raise LifecycleError("upgrade plan retirement digest is invalid")
    digest = plan.get("planDigest")
    if not isinstance(digest, str) or digest != plan_digest(plan):
        raise LifecycleError("upgrade plan digest is missing or invalid")
    return plan


def _receipt_digest(receipt: dict[str, Any]) -> str:
    payload = {key: value for key, value in receipt.items() if key != "receiptDigest"}
    return _canonical_digest(payload)


def _valid_applied_receipt(receipt: Any, instance_root: Path) -> bool:
    if not isinstance(receipt, dict) or receipt.get("formatVersion") != UPGRADE_RECEIPT_FORMAT:
        return False
    if receipt.get("status") != "applied" or receipt.get("receiptDigest") != _receipt_digest(receipt):
        return False
    approval = receipt.get("approval")
    if not isinstance(approval, dict) or approval.get("planDigest") != receipt.get("planDigest"):
        return False
    try:
        lock = _read_lock(_safe_target_path(instance_root, ".statedd/lock.yaml", "lockfile"))
    except LifecycleError:
        return False
    target = receipt.get("target")
    template = lock.get("template", {})
    current = receipt.get("current")
    try:
        actual_root_identity = _instance_root_identity(instance_root)
    except LifecycleError:
        return False
    if not isinstance(current, dict) or current.get("rootIdentity") != actual_root_identity:
        return False
    if receipt.get("lockDigest") != _canonical_digest(lock):
        return False
    for entry in lock.get("files", []):
        expected = entry.get("materializedHash")
        if expected is None or entry.get("owner") == "instance":
            continue
        exists, current, safety_error = _instance_file_hash(instance_root, entry["path"])
        if safety_error or not exists or current != expected:
            return False
    for entry in lock.get("trees", []):
        expected = entry.get("materializedHash")
        if expected is None or entry.get("owner") == "instance":
            continue
        try:
            if _tree_digest(instance_root, entry["path"]) != expected:
                return False
        except LifecycleError:
            return False
    return (
        isinstance(target, dict)
        and target.get("id") == template.get("id")
        and target.get("version") == template.get("version")
        and target.get("source") == template.get("source")
    )


def _upgrade_lease_path(instance_root: Path) -> Path:
    return instance_root.parent / f".{instance_root.name}.upgrade-in-progress"


def _upgrade_journal_path(instance_root: Path) -> Path:
    return instance_root.parent / f".{instance_root.name}.upgrade-transaction.yaml"


def _upgrade_stage_path(instance_root: Path) -> Path:
    return instance_root.parent / f".{instance_root.name}.upgrade-stage"


def _upgrade_backup_path(instance_root: Path) -> Path:
    return instance_root.parent / f".{instance_root.name}.upgrade-backup"


@contextmanager
def _upgrade_writer_lease(instance_root: Path) -> Iterator[None]:
    lease_path = _upgrade_lease_path(instance_root)
    if lease_path.is_symlink() or (lease_path.exists() and not lease_path.is_file()):
        raise LifecycleError("upgrade lease path is not a safe regular file")
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    try:
        lease_fd = os.open(lease_path, flags, 0o600)
    except OSError as exc:
        raise LifecycleError("could not open upgrade writer lease") from exc
    try:
        lease_stat = os.fstat(lease_fd)
        if (
            not stat.S_ISREG(lease_stat.st_mode)
            or lease_stat.st_nlink != 1
            or lease_stat.st_uid != os.geteuid()
            or lease_stat.st_mode & 0o077
        ):
            raise LifecycleError("upgrade lease path is not a private owned regular file")
        try:
            fcntl.flock(lease_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise LifecycleError("another upgrade transaction is already in progress") from exc
        _fsync_directory(instance_root.parent)
        try:
            yield
        finally:
            try:
                try:
                    path_stat = lease_path.lstat()
                except FileNotFoundError:
                    path_stat = None
                if path_stat is not None and (
                    path_stat.st_dev,
                    path_stat.st_ino,
                ) == (lease_stat.st_dev, lease_stat.st_ino):
                    lease_path.unlink()
                    _fsync_directory(instance_root.parent)
            finally:
                fcntl.flock(lease_fd, fcntl.LOCK_UN)
    finally:
        os.close(lease_fd)


def _safe_transaction_directory(path: Path, label: str) -> None:
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        raise LifecycleError(f"{label} is not a safe directory; manual recovery is required")


def _recover_interrupted_upgrade(instance_root: Path) -> None:
    journal_path = _upgrade_journal_path(instance_root)
    if journal_path.is_symlink() or (journal_path.exists() and not journal_path.is_file()):
        raise LifecycleError("upgrade journal is unsafe; manual recovery is required")
    journal = _read_optional_mapping(journal_path)
    legacy_journal_path = _safe_target_path(
        instance_root, ".statedd/upgrade-transaction.yaml", "upgrade journal"
    )
    if journal is None and legacy_journal_path.exists():
        journal = _read_optional_mapping(legacy_journal_path)
    if journal is None:
        for orphan, label in (
            (_upgrade_stage_path(instance_root), "upgrade stage"),
            (_upgrade_backup_path(instance_root), "upgrade backup"),
        ):
            if orphan.exists() or orphan.is_symlink():
                raise LifecycleError(f"orphaned {label} requires manual recovery")
        return
    if not isinstance(journal, dict):
        raise LifecycleError("upgrade journal is invalid; manual recovery is required")
    parent = instance_root.parent
    stage_name = journal.get("stageName")
    backup_name = journal.get("backupName")
    expected_stage_prefix = ".statedd-upgrade-"
    expected_stage_name = _upgrade_stage_path(instance_root).name
    expected_backup_name = f".{instance_root.name}.upgrade-backup"
    if (
        not isinstance(stage_name, str)
        or Path(stage_name).name != stage_name
        or not (
            stage_name.startswith(expected_stage_prefix)
            or stage_name == expected_stage_name
        )
        or not isinstance(backup_name, str)
        or Path(backup_name).name != backup_name
        or backup_name != expected_backup_name
    ):
        raise LifecycleError("upgrade journal paths are invalid; manual recovery is required")
    stage = parent / stage_name
    backup = parent / backup_name
    _safe_transaction_directory(stage, "upgrade stage")
    _safe_transaction_directory(backup, "upgrade backup")
    receipt_path = _safe_target_path(instance_root, ".statedd/upgrade-receipt.yaml", "upgrade receipt")
    receipt = _read_optional_mapping(receipt_path)
    if (
        _valid_applied_receipt(receipt, instance_root)
        and receipt.get("planDigest") == journal.get("planDigest")
    ):
        if stage.exists():
            shutil.rmtree(stage)
        if backup.exists():
            shutil.rmtree(backup)
        if legacy_journal_path.exists():
            legacy_journal_path.unlink()
        if journal_path.exists():
            journal_path.unlink()
        _fsync_directory(parent)
        return
    if backup.exists():
        if instance_root.exists():
            _safe_transaction_directory(instance_root, "published instance")
            shutil.rmtree(instance_root)
        os.replace(backup, instance_root)
        _fsync_directory(parent)
    elif not instance_root.is_dir():
        raise LifecycleError("upgrade recovery has no original instance backup")
    if stage.exists():
        shutil.rmtree(stage)
    if legacy_journal_path.exists():
        legacy_journal_path.unlink()
    if journal_path.exists():
        journal_path.unlink()
    _fsync_directory(parent)


def _lock_for_existing(
    lock_path: Path,
    instance_path: Path,
    root: Path,
    manifest: dict[str, Any],
    source_descriptor: dict[str, Any] | None = None,
) -> dict[str, Any]:
    lock = _read_lock(lock_path)
    instance_id, _ = _instance_identity(instance_path)
    if lock.get("instanceId") != instance_id:
        raise LifecycleError(
            "lock instanceId does not match instance.yaml",
            code="instance_identity_mismatch",
        )
    _validate_lock_against_manifest(lock, manifest, root)
    if lock.get("template", {}).get("sourceRevision") != _source_revision(root, manifest):
        raise LifecycleError("existing lockfile source revision does not match template")
    current_source = describe_template_source(root)
    locked_source = lock.get("template", {}).get("source")
    if not isinstance(locked_source, dict):
        locked_source = _locked_source(lock)
    if not _source_descriptors_match(current_source, locked_source):
        raise LifecycleError(
            "existing lock source descriptor does not match template provenance",
            code="source_provenance_mismatch",
        )
    if source_descriptor is not None:
        if not _source_descriptors_match(locked_source, source_descriptor):
            raise LifecycleError(
                "existing lock source descriptor does not match resolved source",
                code="source_provenance_mismatch",
            )
    ejected = set()
    if manifest.get("formatVersion") == MANIFEST_V2_FORMAT:
        ejected = {item["path"] for item in load_instance_overrides(instance_path, manifest)["ejections"]}
    effective_files = _all_manifest_files(root, manifest)
    for entry in lock.get("files", []):
        expected_item = effective_files.get(entry.get("path"))
        if expected_item is not None and expected_item.get("owner") == "template":
            if entry.get("path") in ejected:
                continue
            target = _confined(instance_path, entry["path"], "locked template file")
            if not target.is_file() or _hash_file(target) != entry.get("materializedHash"):
                raise LifecycleError(f"template-owned file changed: {entry.get('path')}")
    return lock


def materialize_instance(
    template_path: Path | str,
    instance_path: Path | str,
    *,
    allow_fixture: bool = False,
    source_descriptor: dict[str, Any] | None = None,
    refresh_generated: bool = False,
) -> dict[str, Any]:
    """Materialise a validated template into an instance and write its lock.

    Template-owned files are copied exactly and cannot be silently replaced.
    Instance-owned files are created only when absent and are otherwise
    preserved. Generated files are treated as opaque, checked-in compatibility
    baselines; StatePort never executes a template-provided generator. During
    a staged upgrade, declared generated baselines are refreshed from the
    exact target source before the staged lock is written.
    """
    root = _safe_root_path(template_path, "template root")
    target_root = _safe_root_path(instance_path, "instance root")
    manifest = load_template_manifest(root)
    try:
        registry = find_builtin_schema_registry()
        for asset in manifest.get("assets", []):
            schema_id = asset.get("schema")
            if isinstance(schema_id, str) and schema_id.startswith("statedd.stateport.io/"):
                registry.schema(schema_id)
        if manifest.get("formatVersion") == MANIFEST_V2_FORMAT:
            instance_schema = manifest.get("template", {}).get("instanceSchemaVersion")
            if isinstance(instance_schema, str) and instance_schema.startswith("statedd.stateport.io/"):
                registry.schema(instance_schema)
    except (OSError, UnicodeError, ValueError, SchemaRegistryError) as exc:
        raise LifecycleError(f"template schema binding is unresolved: {exc}") from exc
    assert_materializable_v2(manifest, allow_generated_baseline=manifest.get("sourceClass") == "canonical_source")
    assert_fixture_use_allowed(manifest, allow_fixture)
    if source_descriptor is not None:
        if source_descriptor.get("kind") != "git":
            raise LifecycleError("materialization source descriptor must be an immutable Git descriptor")
        if _git_root(root) is None and source_descriptor.get("cacheDigest") is not None:
            _verify_immutable_git_snapshot(root, source_descriptor, manifest)
        else:
            verified = resolve_git_source(
                source_descriptor.get("repository", root.as_posix()),
                source_descriptor.get("requestedRef", "HEAD"),
                checkout_path=root,
                expected_commit=source_descriptor.get("resolvedCommit"),
            )
            if not _source_descriptors_match(verified, source_descriptor):
                raise LifecycleError("resolved Git source descriptor does not match materialization checkout")
    instance_id, instance_template_id = _instance_identity(target_root)
    if instance_template_id is not None and instance_template_id != manifest["templateId"]:
        raise LifecycleError("instance templateRef.id does not match manifest templateId")
    lock_path = _confined(target_root, ".statedd/lock.yaml", "lockfile")
    target_root.mkdir(parents=True, exist_ok=True)
    if lock_path.exists():
        return _lock_for_existing(lock_path, target_root, root, manifest, source_descriptor)

    source_revision = _source_revision(root, manifest)
    ejected_paths = {
        item["path"]
        for item in load_instance_overrides(target_root, manifest).get("ejections", [])
    }
    for tree in manifest.get("trees", []):
        target = _safe_target_path(target_root, tree["path"], f"target tree {tree['path']}")
        already_present = target.exists()
        if target.exists() and not target.is_dir():
            raise LifecycleError(f"materialized tree path is not a directory: {tree['path']}")
        target.mkdir(parents=True, exist_ok=True)
        if tree.get("owner") == "template":
            if already_present:
                # ``preserve`` is an explicit tree policy.  A release may
                # change files inside the tree, but StatePort must not infer
                # ownership for those paths or recursively merge them.
                continue
            source_tree = _confined(root, tree["path"], f"source tree {tree['path']}")
            if not source_tree.is_dir() or source_tree.is_symlink():
                raise LifecycleError(f"template tree source is not a safe directory: {tree['path']}")
            for source in sorted(source_tree.rglob("*")):
                relative = source.relative_to(source_tree).as_posix()
                destination = _safe_target_path(target, relative, f"template tree file {tree['path']}/{relative}")
                if source.is_symlink():
                    raise LifecycleError(f"template tree contains a symlink: {tree['path']}/{relative}")
                if source.is_dir():
                    destination.mkdir(parents=True, exist_ok=True)
                    continue
                if not source.is_file():
                    raise LifecycleError(f"template tree contains a non-file entry: {tree['path']}/{relative}")
                destination.parent.mkdir(parents=True, exist_ok=True)
                if destination.exists() and destination.read_bytes() != source.read_bytes():
                    raise LifecycleError(f"template-owned tree file already differs: {tree['path']}/{relative}")
                if not destination.exists():
                    destination.write_bytes(source.read_bytes())
    entries: list[dict[str, Any]] = []
    materialized_assets = _all_manifest_files(root, manifest)
    for item in sorted(materialized_assets.values(), key=lambda value: value["path"]):
        target = _safe_target_path(target_root, item["path"], f"target {item['path']}")
        target.parent.mkdir(parents=True, exist_ok=True)
        if item["provision"] == "copy":
            source = _confined(root, item["source"], f"source {item['source']}")
            source_hash = _hash_file(source)
            if target.exists():
                if item["merge"] == "append_only":
                    raise LifecycleError(f"append_only merge is not implemented: {item['path']}")
                if item["owner"] == "template" and _hash_file(target) != source_hash:
                    if item["path"] not in ejected_paths:
                        raise LifecycleError(f"template-owned file already differs: {item['path']}")
            else:
                target.write_bytes(source.read_bytes())
            materialized_hash = _hash_file(target)
        elif item["provision"] == "create":
            source_hash = None
            if not target.exists():
                target.touch()
            if not target.is_file():
                raise LifecycleError(f"materialized path is not a file: {item['path']}")
            materialized_hash = _hash_file(target)
        else:
            source_hash = None
            # A canonical source may publish generated compatibility views.
            # Copy only the checked-in baseline from the already-resolved
            # source; never execute a template-provided generator. On upgrade,
            # refresh the output so an old generated view cannot survive under
            # a new lock. Required outputs without a baseline fail closed.
            generated_source = _confined(root, item["path"], f"generated baseline {item['path']}")
            if generated_source.is_symlink():
                raise LifecycleError(f"generated baseline is a symlink: {item['path']}")
            if generated_source.is_file() and (refresh_generated or not target.exists()):
                if target.exists() and not target.is_file():
                    raise LifecycleError(f"generated output is not a regular file: {item['path']}")
                target.write_bytes(generated_source.read_bytes())
            elif refresh_generated and item.get("required") and item["path"] != ".statedd/lock.yaml":
                raise LifecycleError(f"required generated baseline is missing: {item['path']}")
            # Keep generated outputs opaque to ordinary override detection,
            # but retain a baseline when the manifest explicitly authorizes a
            # future remove-if-unmodified retirement check.
            materialized_hash = (
                _hash_file(target)
                if item.get("retirementPolicy") == "remove_if_unmodified" and target.is_file()
                else None
            )
        entries.append(
            {
                "path": item["path"],
                "owner": item["owner"],
                "merge": item["merge"],
                "required": item["required"],
                "sensitivity": item["sensitivity"],
                "retirementPolicy": item.get("retirementPolicy", "retain"),
                "tree": item.get("tree"),
                "sourceHash": source_hash,
                "materializedHash": materialized_hash,
            }
        )

    source_descriptor = dict(source_descriptor or describe_template_source(root))
    # Cache identity authorizes verification of a detached immutable snapshot;
    # it is local storage metadata, not part of the portable source lock schema.
    source_descriptor.pop("cacheDigest", None)
    template_lock: dict[str, Any] = {
        "id": manifest["templateId"],
        "version": manifest["templateVersion"],
        "sourcePath": root.resolve().as_posix(),
        "sourceRevision": source_revision,
        "source": source_descriptor,
    }
    if manifest.get("formatVersion") == MANIFEST_V2_FORMAT:
        template_lock.update(
            {
                "manifestFormatVersion": MANIFEST_V2_FORMAT,
                "stateddSpecVersion": manifest["template"]["stateddSpecVersion"],
                "instanceSchemaVersion": manifest["template"]["instanceSchemaVersion"],
                "selectedModules": manifest["selectedModules"],
            }
        )
    tree_entries: list[dict[str, Any]] = []
    for tree in sorted(manifest.get("trees", []), key=lambda value: value["path"]):
        tree_path = tree["path"]
        target_tree = _confined(target_root, tree_path, f"materialized tree {tree_path}")
        tree_entries.append(
            {
                "path": tree_path,
                "owner": _effective_tree_owner(tree),
                "required": tree["required"],
                "sensitivity": tree["sensitivity"],
                "updatePolicy": tree["updatePolicy"],
                "retirementPolicy": tree.get("retirementPolicy", "retain"),
                "baselineHash": _tree_digest(root, tree_path)
                if _effective_tree_owner(tree) == "template"
                and _confined(root, tree_path, f"source tree {tree_path}").is_dir()
                else None,
                "materializedHash": _tree_digest(target_root, tree_path)
                if target_tree.exists()
                else None,
            }
        )
    lock = {
        "formatVersion": LOCK_FORMAT,
        "instanceId": instance_id,
        "template": template_lock,
        "files": entries,
        "trees": tree_entries,
        "retired": [],
        "history": [],
    }
    lock_issues = registry.validate(LOCK_SCHEMA_ID, lock)
    if lock_issues:
        first = lock_issues[0]
        raise LifecycleError(
            f"generated lock failed {LOCK_SCHEMA_ID} at {first.path}: {first.message}"
        )
    _validate_lock(lock)
    _write_yaml(lock_path, lock)
    return lock


def _load_override_inputs(
    template_path: Path | str, instance_path: Path | str | None
) -> tuple[Path, Path, dict[str, Any], dict[str, Any], dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    if instance_path is None:
        # Convenience form: classify_overrides(instance_path), resolving the
        # locked local source.  The lock remains authoritative for this form.
        instance_root = _safe_root_path(template_path, "instance root")
        lock_path = _confined(instance_root, ".statedd/lock.yaml", "lockfile")
        lock = _read_lock(lock_path)
        source_path = Path(_locked_source(lock)["path"])
        template_root = _safe_root_path(source_path, "locked template root")
    else:
        template_root = _safe_root_path(template_path, "template root")
        instance_root = _safe_root_path(instance_path, "instance root")
        lock_path = _confined(instance_root, ".statedd/lock.yaml", "lockfile")
        lock = _read_lock(lock_path)
    instance_id, _ = _instance_identity(instance_root)
    if lock["instanceId"] != instance_id:
        raise LifecycleError("lock instanceId does not match instance.yaml")
    manifest = load_template_manifest(template_root)
    manifest_files, lock_files = _validate_lock_against_manifest(lock, manifest, template_root)
    if lock["template"]["id"] != manifest["templateId"]:
        raise LifecycleError("lock template id does not match manifest")
    if lock["template"]["version"] != manifest["templateVersion"]:
        raise LifecycleError("lock template version does not match manifest")
    if lock["template"]["sourceRevision"] != _source_revision(template_root, manifest):
        raise LifecycleError("locked source revision does not match template source")
    locked_descriptor = lock["template"].get("source")
    current_descriptor = describe_template_source(template_root)
    if not isinstance(locked_descriptor, dict):
        locked_descriptor = _locked_source(lock)
    if not _source_descriptors_match(current_descriptor, locked_descriptor):
        raise LifecycleError(
            "locked source descriptor does not match template provenance",
            code="source_provenance_mismatch",
        )
    return template_root, instance_root, lock, manifest, manifest_files, lock_files


def classify_overrides(
    template_path: Path | str,
    instance_path: Path | str | None = None,
) -> dict[str, Any]:
    """Classify local instance files against a locked manifest without writing.

    Template-owned drift is ``overridden``; expected private instance-state
    drift is ``changed``.  Unknown files and unsafe paths are surfaced as
    ``added``/``blocked`` and make the report unsafe for an automatic action.
    """
    template_root, instance_root, lock, manifest, manifest_files, lock_files = (
        _load_override_inputs(template_path, instance_path)
    )
    entries: list[dict[str, Any]] = []
    blocked = False
    ejected: set[str] = set()
    if manifest.get("formatVersion") == MANIFEST_V2_FORMAT:
        ejected = {
            item["path"]
            for item in load_instance_overrides(instance_root, manifest)["ejections"]
        }
    for path in sorted(manifest_files):
        item = manifest_files[path]
        locked = lock_files[path]
        exists, current_hash, safety_error = _instance_file_hash(instance_root, path)
        if safety_error:
            entries.append(
                _report_entry(
                    path=path,
                    classification="blocked",
                    owner=item["owner"],
                    locked_hash=locked.get("materializedHash"),
                    current_hash=current_hash,
                    reason=safety_error,
                )
            )
            blocked = True
            continue
        if not exists:
            entries.append(
                _report_entry(
                    path=path,
                    classification="removed",
                    owner=item["owner"],
                    locked_hash=locked.get("materializedHash"),
                    reason="required manifest file is missing"
                    if item["required"]
                    else "optional manifest file is missing",
                )
            )
            if item["required"]:
                blocked = True
            continue
        locked_hash = locked.get("materializedHash")
        if item["owner"] == "generated" and locked_hash is None:
            classification: Classification = "unchanged"
            reason = "generated artifact is present; content is not an override baseline"
        elif locked_hash is None:
            entries.append(
                _report_entry(
                    path=path,
                    classification="blocked",
                    owner=item["owner"],
                    current_hash=current_hash,
                    reason="lock has no materialized hash for a non-generated file",
                )
            )
            blocked = True
            continue
        elif current_hash == locked_hash:
            classification = "unchanged"
            reason = "matches locked materialization" if path not in ejected else "ejected file matches its pre-ejection baseline"
        elif path in ejected:
            classification = "changed"
            reason = "ejected file is instance-owned and excluded from upstream replacement"
        elif item["owner"] == "template":
            classification = "overridden"
            reason = "template-owned file differs from locked materialization"
        elif item["owner"] == "instance":
            classification = "changed"
            reason = "instance-owned state differs from creation baseline"
        else:
            classification = "blocked"
            reason = "generated artifact differs from its locked baseline"
        entries.append(
            _report_entry(
                path=path,
                classification=classification,
                owner="instance" if path in ejected else item["owner"],
                locked_hash=locked_hash,
                current_hash=current_hash,
                reason=reason,
            )
        )
        if classification in {"blocked", "overridden"}:
            blocked = True

    declared = set(manifest_files)
    # Lifecycle receipts are StatePort-owned generated history for both v1 and
    # v2 manifests; they are not unknown instance content.
    declared.add(".statedd/upgrade-receipt.yaml")
    if manifest.get("formatVersion") == MANIFEST_V2_FORMAT:
        declared.add(".statedd/overrides.yaml")
    for retired in lock.get("retired", []):
        path = retired["path"]
        exists, current_hash, safety_error = _instance_file_hash(instance_root, path)
        if safety_error:
            entries.append(
                _report_entry(
                    path=path,
                    classification="blocked",
                    owner=retired.get("owner"),
                    locked_hash=retired.get("baselineHash"),
                    current_hash=current_hash,
                    reason=safety_error,
                )
            )
            blocked = True
            declared.add(path)
            continue
        baseline_hash = retired.get("baselineHash")
        if not exists and retired.get("disposition") == "removed":
            classification: Classification = "retired"
            reason = "generated artifact was explicitly retired and removed"
        elif baseline_hash is not None and current_hash == baseline_hash:
            classification = "retained_unmodified"
            reason = "retired path is retained and matches its historical baseline"
        else:
            classification = "retained_modified"
            reason = "retired path is retained because it differs from its historical baseline"
        entries.append(
            _report_entry(
                path=path,
                classification=classification,
                owner=retired.get("owner"),
                locked_hash=baseline_hash,
                current_hash=current_hash,
                reason=reason,
            )
        )
        declared.add(path)
    for path in sorted(_instance_paths(instance_root) - declared):
        if path == ".git" or path.startswith(".git/"):
            # The instance's Git repository is StatePort-owned infrastructure
            # created after materialization; its internals are never template
            # content, learner drift, or upgrade inputs.
            continue
        tree_owner = next(
            (
                _effective_tree_owner(item)
                for item in manifest.get("trees", [])
                if path.startswith(item["path"] + "/") or path == item["path"]
            ),
            None,
        )
        if tree_owner == "instance":
            continue
        entries.append(
            _report_entry(
                path=path,
                classification="added",
                owner=tree_owner,
                reason="file is not declared by the manifest; ownership is unknown",
            )
        )
        blocked = True
    result = {
        "formatVersion": OVERRIDE_REPORT_FORMAT,
        "ok": True,
        "dryRun": True,
        "instancePath": instance_root.resolve().as_posix(),
        "template": {
            "id": manifest["templateId"],
            "version": manifest["templateVersion"],
            "source": describe_template_source(template_root),
        },
        "blocked": blocked,
        "safe": not blocked,
        "files": entries,
        "entries": entries,
        "summary": _summary(entries),
    }
    return result


def detect_overrides(
    instance_path: Path | str,
    template_path: Path | str,
) -> dict[str, Any]:
    """Return deterministic local-drift classifications for an instance."""
    return classify_overrides(template_path, instance_path)


def _manifest_fingerprint(root: Path, item: dict[str, Any]) -> str:
    source_hash = None
    if item["provision"] == "copy":
        source_hash = _hash_file(_confined(root, item["source"], "manifest source"))
    payload = {
        "path": item["path"],
        "source": item["source"],
        "owner": item["owner"],
        "provision": item["provision"],
        "merge": item["merge"],
        "generation": item["generation"],
        "retirementPolicy": item["retirementPolicy"],
        "required": item["required"],
        "schema": item["schema"],
        "sensitivity": item["sensitivity"],
        "sourceHash": source_hash,
    }
    return _hash_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())


def _version_key(value: str) -> tuple[int, ...] | None:
    # The lifecycle contract currently uses numeric dotted versions.  Refuse
    # to order an unknown scheme instead of making an unsafe upgrade guess.
    parts = value.split(".")
    if not parts or any(not part.isdigit() for part in parts):
        return None
    return tuple(int(part) for part in parts)


def _plan_upgrade(
    template_path: Path | str,
    instance_path: Path | str,
    newer_template_path: Path | str,
    *,
    migration_set: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Create a non-mutating, fail-closed plan for a newer local template."""
    old_root, instance_root, lock, old_manifest, old_files, lock_files = (
        _load_override_inputs(template_path, instance_path)
    )
    new_root = _safe_root_path(newer_template_path, "template root")
    new_manifest = load_template_manifest(new_root)
    assert_materializable_v2(
        new_manifest,
        allow_generated_baseline=new_manifest.get("sourceClass") == "canonical_source",
    )
    new_files = _all_manifest_files(new_root, new_manifest)
    old_version = old_manifest["templateVersion"]
    new_version = new_manifest["templateVersion"]
    version_key = _version_key(old_version)
    new_version_key = _version_key(new_version)
    current_source = describe_template_source(old_root)
    target_source = describe_template_source(new_root)
    plan_entries: list[dict[str, Any]] = []
    retirements: list[dict[str, Any]] = []
    normalized_migrations = _normalize_migration_set(migration_set)
    blocked = False
    plan_reasons: list[str] = []

    if old_manifest["templateId"] != new_manifest["templateId"]:
        blocked = True
        plan_reasons.append("template ids differ")
    if version_key is None or new_version_key is None or new_version_key <= version_key:
        blocked = True
        plan_reasons.append("target template version is not a higher numeric version")

    try:
        local_report = classify_overrides(old_root, instance_root)
    except LifecycleError as exc:
        local_report = None
        blocked = True
        plan_reasons.append(str(exc))
    local_by_path = {
        entry["path"]: entry for entry in (local_report["files"] if local_report else [])
    }
    ejected_paths = {
        item["path"]
        for item in load_instance_overrides(instance_root, new_manifest).get("ejections", [])
    }
    target_instance_trees = {
        tree["path"]
        for tree in new_manifest.get("trees", [])
        if isinstance(tree, dict) and _effective_tree_owner(tree) == "instance"
    }
    target_instance_files = {
        path for path, item in new_files.items() if item.get("owner") == "instance"
    }

    def _is_target_instance_tree_path(path: str) -> bool:
        return path in target_instance_files or any(
            path == tree or path.startswith(tree + "/") for tree in target_instance_trees
        )

    if local_report and local_report.get("blocked"):
        unsafe_local = [
            entry
            for entry in local_report.get("files", [])
            if entry.get("classification") in {"blocked", "overridden"}
            or (
                entry.get("classification") == "added"
                and not _is_target_instance_tree_path(entry.get("path", ""))
            )
        ]
        if not unsafe_local:
            local_report["blocked"] = False
            local_report["safe"] = True

    def _existing_instance_file(path: str) -> Path | None:
        candidate = _safe_target_path(instance_root, path, f"instance path {path}")
        return candidate if candidate.is_file() and not candidate.is_symlink() else None

    retired_paths = {entry["path"] for entry in lock.get("retired", [])}

    all_paths = set(old_files) | set(new_files) | set(local_by_path)
    for path in sorted(all_paths):
        if path in retired_paths and path not in old_files and path not in new_files:
            # A prior plan already recorded this path.  Its lock record is the
            # durable retirement history; do not turn it into a new collision.
            continue
        old_item = old_files.get(path)
        new_item = new_files.get(path)
        local = local_by_path.get(path)
        existing_instance_file = _existing_instance_file(path)
        current_hash = (
            local.get("currentHash") if local and local.get("currentHash") is not None
            else (_hash_file(existing_instance_file) if existing_instance_file else None)
        )
        old_locked_hash = lock_files.get(path, {}).get("materializedHash")
        base: dict[str, Any] = {
            "path": path,
            "actionType": "tree_file" if (old_item or new_item or {}).get("tree") else "file",
            "owner": old_item.get("owner") if old_item else None,
            "newOwner": new_item.get("owner") if new_item else None,
            "currentHash": current_hash,
            "lockedHash": old_locked_hash,
            "targetHash": (
                _hash_file(_confined(new_root, new_item["source"], f"target source {path}"))
                if new_item is not None
                and new_item.get("owner") == "template"
                and new_item.get("provision") == "copy"
                else None
            ),
            "action": "block",
            "reason": "",
            "retirementPolicy": (
                old_item.get("retirementPolicy", "retain") if old_item else "retain"
            ),
        }
        classification: Classification
        if old_item is None and new_item is None:
            if existing_instance_file and _is_target_instance_tree_path(path):
                classification = "unchanged"
                base["newOwner"] = "instance"
                base["action"] = "preserve"
                base["reason"] = "existing data under a newly declared instance-owned tree is preserved"
            else:
                classification = "blocked"
                base["reason"] = "local file is not declared by either manifest"
        elif old_item is None:
            if local and local.get("currentHash") is not None:
                classification = "blocked"
                base["reason"] = "new template path collides with an existing local file"
            elif new_item["owner"] != "template":
                if existing_instance_file and new_item["owner"] == "instance":
                    classification = "unchanged"
                    base["action"] = "preserve"
                    base["reason"] = "existing target instance-owned state is preserved"
                else:
                    classification = "blocked"
                    base["reason"] = "upgrade cannot create instance or generated state automatically"
            else:
                classification = "added"
                base["action"] = "add"
                base["reason"] = "new manifest-owned file"
        elif new_item is None:
            policy = old_item.get("retirementPolicy", "retain")
            if (
                old_item["owner"] == "generated"
                and policy == "remove_if_unmodified"
                and old_locked_hash is not None
                and current_hash == old_locked_hash
            ):
                classification = "retired"
                base["action"] = "remove"
                base["reason"] = (
                    "generated artifact is explicitly removable and matches its locked baseline"
                )
            elif (
                old_item["owner"] == "generated"
                and policy == "remove_if_unmodified"
                and current_hash is None
            ):
                classification = "retired"
                base["action"] = "remove"
                base["reason"] = "generated artifact is already absent under explicit removal policy"
            else:
                if old_locked_hash is not None and current_hash == old_locked_hash:
                    classification = "retained_unmodified"
                    base["reason"] = "removed asset is retained by the default retirement policy"
                else:
                    classification = "retained_modified"
                    base["reason"] = (
                        "removed asset is retained because it is locally modified or has no removable baseline"
                    )
                base["action"] = "retain"
                if policy == "remove_if_unmodified" and old_item["owner"] == "generated":
                    blocked = True
                    base["reason"] = (
                        "generated removal is explicit but the current output differs from its locked baseline"
                    )
        elif old_item["owner"] != new_item["owner"]:
            classification = "blocked"
            base["reason"] = "file ownership changes across upgrade"
        elif path in ejected_paths and old_item["owner"] == "template" and new_item["owner"] == "template":
            classification = "unchanged"
            base["action"] = "preserve"
            base["reason"] = "explicit instance ejection preserves the locally owned file"
        elif local and local.get("classification") in {"blocked", "overridden"}:
            classification = local["classification"]
            base["reason"] = local["reason"]
        elif _manifest_fingerprint(old_root, old_item) == _manifest_fingerprint(new_root, new_item):
            classification = "unchanged"
            base["action"] = "preserve"
            base["reason"] = "manifest source and ownership are unchanged"
        elif old_item["owner"] == "template":
            if old_locked_hash is None or current_hash != old_locked_hash:
                classification = "overridden"
                base["reason"] = "template source changed while local file is overridden"
            else:
                classification = "changed"
                base["action"] = "replace"
                base["reason"] = "template-owned source changed and local file matches lock"
        elif old_item["owner"] == "instance":
            classification = "unchanged"
            base["action"] = "preserve"
            base["reason"] = "instance-owned data is preserved across template changes"
        else:
            classification = "blocked"
            base["reason"] = "generated artifact changed and has no safe upgrade baseline"
        base["classification"] = classification
        if old_item is not None and new_item is None:
            retirements.append(dict(base))
        plan_entries.append(base)
        if classification in {"blocked", "overridden"}:
            blocked = True

    if local_report and local_report["blocked"]:
        blocked = True
        plan_reasons.append("current instance has unsafe local drift or unknown files")
    if not plan_reasons and blocked:
        plan_reasons.append("one or more upgrade actions are unsafe")
    tree_states: list[dict[str, Any]] = []
    for tree in sorted(
        {item["path"]: item for item in [*old_manifest.get("trees", []), *new_manifest.get("trees", [])]}.values(),
        key=lambda item: item["path"],
    ):
        path = tree["path"]
        old_tree = next((item for item in old_manifest.get("trees", []) if item["path"] == path), None)
        new_tree = next((item for item in new_manifest.get("trees", []) if item["path"] == path), None)
        current_hash = _tree_digest(instance_root, path) if old_tree and _confined(instance_root, path, f"instance tree {path}").is_dir() else None
        target_hash = _tree_digest(new_root, path) if new_tree and _confined(new_root, path, f"target tree {path}").is_dir() else None
        locked_hash = next((item.get("materializedHash") for item in lock.get("trees", []) if item["path"] == path), None)
        tree_states.append(
            {
                "path": path,
                "actionType": "tree",
                "owner": _effective_tree_owner(old_tree) if old_tree else None,
                "newOwner": _effective_tree_owner(new_tree) if new_tree else None,
                "action": "preserve" if (old_tree and _effective_tree_owner(old_tree) == "instance") else "refresh",
                "currentHash": current_hash,
                "lockedHash": locked_hash,
                "targetHash": target_hash,
            }
        )
    result = {
        "formatVersion": UPGRADE_PLAN_FORMAT,
        "ok": True,
        "dryRun": True,
        "applied": False,
        "instancePath": instance_root.resolve().as_posix(),
        "current": {
            "id": old_manifest["templateId"],
            "version": old_version,
            "source": current_source,
            "instanceId": lock["instanceId"],
            "lockDigest": _canonical_digest(lock),
            "rootIdentity": _instance_root_identity(instance_root),
        },
        "target": {
            "id": new_manifest["templateId"],
            "version": new_version,
            "source": target_source,
        },
        "blocked": blocked,
        "safe": not blocked,
        "reasons": plan_reasons,
        "retirements": retirements,
        "retirement": {
            "defaultPolicy": "retain",
            "entries": retirements,
        },
        "files": plan_entries,
        "entries": plan_entries,
        "trees": tree_states,
        "migrationSet": normalized_migrations,
        "migrationSetDigest": _canonical_digest(normalized_migrations),
        "retirementDigest": _canonical_digest(retirements),
        "summary": _summary(plan_entries),
    }
    result["planDigest"] = plan_digest(result)
    _validate_upgrade_plan(result)
    return result


def plan_upgrade(
    instance_path: Path | str,
    new_template_path: Path | str,
    *,
    migration_set: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Plan an upgrade from the instance's locked local source, without writes."""
    instance_root = _safe_root_path(instance_path, "instance root")
    lock = _read_lock(_confined(instance_root, ".statedd/lock.yaml", "lockfile"))
    current_source = _locked_source(lock)
    return _plan_upgrade(
        current_source["path"],
        instance_root,
        new_template_path,
        migration_set=migration_set,
    )


plan_template_upgrade = _plan_upgrade


def approve_upgrade_plan(
    plan: dict[str, Any],
    *,
    approved_by: str,
    reason: str = "",
    approved_at: str | None = None,
) -> dict[str, Any]:
    """Create an approval record bound to one exact, safe plan digest."""
    _validate_upgrade_plan(plan)
    if plan.get("blocked"):
        raise LifecycleError("only an unblocked upgrade plan can be approved")
    digest = plan["planDigest"]
    return {
        "formatVersion": UPGRADE_APPROVAL_FORMAT,
        "planDigest": digest,
        "instanceId": plan["current"]["instanceId"],
        "migrationSetDigest": plan["migrationSetDigest"],
        "retirementDigest": plan["retirementDigest"],
        "targetSource": plan["target"]["source"],
        "approved": True,
        "approvedBy": _require_string(approved_by, "approved_by"),
        "approvedAt": approved_at or datetime.now(timezone.utc).isoformat(),
        "reason": reason,
    }


def _read_optional_mapping(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    value = _read_yaml(path, path.name)
    return value


def _apply_plan_to_stage(
    stage: Path,
    target_root: Path,
    target_manifest: dict[str, Any],
    entries: list[dict[str, Any]],
) -> None:
    target_files = _all_manifest_files(target_root, target_manifest)
    for entry in entries:
        classification = entry.get("classification")
        action = entry.get("action")
        if action not in UPGRADE_ACTIONS or action != _ACTION_FOR_CLASSIFICATION.get(classification):
            raise LifecycleError(f"upgrade entry has an invalid typed action: {entry.get('path')}")
        path = _safe_relative_path(entry.get("path"), "upgrade entry.path")
        item = target_files.get(path)
        destination = _safe_target_path(stage, path, f"staged target {path}")
        if action == "remove":
            if destination.exists():
                if (
                    item is not None
                    or entry.get("owner") != "generated"
                    or entry.get("retirementPolicy") != "remove_if_unmodified"
                    or entry.get("classification") != "retired"
                ):
                    raise LifecycleError(f"refusing to remove non-explicit-generated path: {path}")
                destination.unlink()
            continue
        if action not in {"replace", "add"}:
            continue
        if item is None:
            raise LifecycleError(f"upgrade entry has no target manifest asset: {path}")
        if item.get("owner") != "template":
            raise LifecycleError(f"automatic upgrade may only write template-owned files: {path}")
        if item.get("provision") == "copy":
            expected_hash = entry.get("targetHash")
            source = _confined(target_root, item.get("source"), f"upgrade source {path}")
            if expected_hash != _hash_file(source):
                raise LifecycleError(f"upgrade target source changed since planning: {path}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if item.get("provision") == "copy":
            if not source.is_file() or source.is_symlink():
                raise LifecycleError(f"upgrade source is not a regular file: {path}")
            destination.write_bytes(source.read_bytes())
        elif item.get("provision") == "create":
            destination.touch(exist_ok=True)
        else:
            raise LifecycleError(f"unsupported staged upgrade provision for {path}")


def apply_upgrade(
    instance_path: Path | str,
    new_template_path: Path | str,
    *,
    plan: dict[str, Any] | None = None,
    approval: dict[str, Any] | None = None,
    validation_command: list[str] | None = None,
    allow_fixture: bool = False,
    migration_set: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Apply one approved upgrade through an isolated directory transaction.

    The live instance is replaced only after staged files materialize and the
    optional validator succeeds. The new lock becomes visible with the staged
    replacement and the receipt is written last. A matching successful receipt
    makes a rerun a no-op.
    """
    instance_root = _safe_root_path(instance_path, "instance root")
    with _upgrade_writer_lease(instance_root):
        _recover_interrupted_upgrade(instance_root)
        return _apply_upgrade_locked(
            instance_root,
            new_template_path,
            plan=plan,
            approval=approval,
            validation_command=validation_command,
            allow_fixture=allow_fixture,
            migration_set=migration_set,
        )


def _apply_upgrade_locked(
    instance_path: Path | str,
    new_template_path: Path | str,
    *,
    plan: dict[str, Any] | None,
    approval: dict[str, Any] | None,
    validation_command: list[str] | None,
    allow_fixture: bool,
    migration_set: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    instance_root = _safe_root_path(instance_path, "instance root")
    target_root = _safe_root_path(new_template_path, "template root")
    receipt_path = _safe_target_path(instance_root, ".statedd/upgrade-receipt.yaml", "upgrade receipt")
    supplied_plan = plan
    existing_receipt = _read_optional_mapping(receipt_path)
    if existing_receipt is not None and not _valid_applied_receipt(existing_receipt, instance_root):
        raise LifecycleError("existing upgrade receipt is invalid or no longer matches the instance")
    if supplied_plan is not None:
        _validate_upgrade_plan(supplied_plan)
        if (
            not isinstance(approval, dict)
            or approval.get("formatVersion") != UPGRADE_APPROVAL_FORMAT
            or approval.get("approved") is not True
            or approval.get("planDigest") != supplied_plan.get("planDigest")
            or approval.get("instanceId") != supplied_plan["current"].get("instanceId")
            or approval.get("migrationSetDigest") != supplied_plan.get("migrationSetDigest")
            or approval.get("retirementDigest") != supplied_plan.get("retirementDigest")
            or approval.get("targetSource") != supplied_plan["target"].get("source")
            or not isinstance(approval.get("approvedBy"), str)
            or not approval.get("approvedBy", "").strip()
            or not isinstance(approval.get("approvedAt"), str)
            or not approval.get("approvedAt", "").strip()
        ):
            raise LifecycleError("approval is not bound to exact plan digest")
        target_descriptor = describe_template_source(target_root)
        if supplied_plan.get("target", {}).get("source") != target_descriptor:
            raise LifecycleError("supplied upgrade plan target source is stale")
    if _valid_applied_receipt(existing_receipt, instance_root):
        if supplied_plan is None or existing_receipt.get("planDigest") == supplied_plan.get("planDigest"):
            result = dict(existing_receipt)
            result["idempotent"] = True
            return result

    if supplied_plan is not None:
        _assert_instance_root_binding(supplied_plan, instance_root)

    fresh_plan = plan_upgrade(instance_root, target_root, migration_set=migration_set)
    if supplied_plan is not None:
        if supplied_plan.get("planDigest") != fresh_plan.get("planDigest"):
            raise LifecycleError("supplied upgrade plan is stale or does not match current state")
    plan_value = fresh_plan
    _validate_upgrade_plan(plan_value)
    if plan_value.get("blocked") or not plan_value.get("safe"):
        raise LifecycleError("upgrade plan is blocked and cannot be applied")
    if not isinstance(approval, dict):
        raise LifecycleError("an approval bound to the exact plan digest is required")
    if (
        approval.get("formatVersion") != UPGRADE_APPROVAL_FORMAT
        or approval.get("approved") is not True
        or approval.get("planDigest") != plan_value.get("planDigest")
        or approval.get("instanceId") != plan_value["current"].get("instanceId")
        or approval.get("migrationSetDigest") != plan_value.get("migrationSetDigest")
        or approval.get("retirementDigest") != plan_value.get("retirementDigest")
        or approval.get("targetSource") != plan_value["target"].get("source")
        or not isinstance(approval.get("approvedBy"), str)
        or not approval.get("approvedBy", "").strip()
        or not isinstance(approval.get("approvedAt"), str)
        or not approval.get("approvedAt", "").strip()
    ):
        raise LifecycleError("approval is not bound to exact plan digest")
    expires_at = approval.get("expiresAt")
    if expires_at is not None:
        try:
            expiry = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
        except ValueError as exc:
            raise LifecycleError("approval expiresAt is invalid") from exc
        if expiry <= datetime.now(timezone.utc):
            raise LifecycleError("approval has expired")

    existing_receipt = _read_optional_mapping(receipt_path)
    if _valid_applied_receipt(existing_receipt, instance_root):
        if existing_receipt.get("planDigest") == plan_value.get("planDigest"):
            result = dict(existing_receipt)
            result["idempotent"] = True
            return result

    target_manifest = load_template_manifest(target_root)
    target_source = plan_value["target"]["source"]
    previous_lock = _read_lock(
        _safe_target_path(instance_root, ".statedd/lock.yaml", "lockfile")
    )
    parent = instance_root.parent
    stage_dir = _upgrade_stage_path(instance_root)
    backup_dir = _upgrade_backup_path(instance_root)
    journal_path = _upgrade_journal_path(instance_root)
    journal = {
        "formatVersion": "statedd.upgrade-transaction/v2",
        "planDigest": plan_value["planDigest"],
        "stageName": stage_dir.name,
        "backupName": backup_dir.name,
        "phase": "staging",
    }
    _write_yaml(journal_path, journal)
    committed = False
    try:
        shutil.copytree(instance_root, stage_dir, symlinks=True)
        _fsync_directory(parent)
        _apply_plan_to_stage(stage_dir, target_root, target_manifest, plan_value["entries"])
        old_stage_lock = stage_dir / ".statedd" / "lock.yaml"
        if old_stage_lock.exists():
            old_stage_lock.unlink()
        source_descriptor = target_source if target_source.get("kind") == "git" else None
        materialize_instance(
            target_root,
            stage_dir,
            source_descriptor=source_descriptor,
            allow_fixture=allow_fixture,
            refresh_generated=True,
        )
        staged_lock_path = _safe_target_path(stage_dir, ".statedd/lock.yaml", "staged lockfile")
        staged_lock = _read_lock(staged_lock_path)
        active_target_paths = set(_all_manifest_files(target_root, target_manifest))
        prior_retired = [
            dict(entry)
            for entry in previous_lock.get("retired", [])
            if entry.get("path") not in active_target_paths
        ]
        new_retired = {
            entry["path"]: entry for entry in prior_retired
        }
        for retirement in plan_value.get("retirements", []):
            path = retirement["path"]
            staged_target = _safe_target_path(stage_dir, path, f"retired path {path}")
            current_hash = _hash_file(staged_target) if staged_target.is_file() else None
            new_retired[path] = {
                "path": path,
                "owner": retirement["owner"],
                "retirementPolicy": retirement.get("retirementPolicy", "retain"),
                "disposition": "removed" if retirement.get("action") == "remove" else "retained",
                "baselineHash": retirement.get("lockedHash"),
                "currentHash": current_hash,
                "reason": retirement.get("reason", ""),
            }
        applied_at = datetime.now(timezone.utc).isoformat()
        history_event = {
            "event": "upgrade",
            "planDigest": plan_value["planDigest"],
            "from": plan_value["current"],
            "target": plan_value["target"],
            "retirements": plan_value.get("retirements", []),
            "appliedAt": applied_at,
        }
        staged_lock["retired"] = [
            new_retired[path] for path in sorted(new_retired)
        ]
        staged_lock["history"] = [
            *previous_lock.get("history", []),
            history_event,
        ]
        _write_yaml(staged_lock_path, staged_lock)
        if validation_command is not None:
            if not validation_command or any(not isinstance(item, str) or not item for item in validation_command):
                raise LifecycleError("validation_command must be a non-empty argument list")
            if not allow_fixture and (
                validation_command[0] not in {sys.executable, "python3", "python"}
                or len(validation_command) < 2
                or validation_command[1] in {"-c", "-m"}
                or Path(validation_command[1]).is_absolute()
                or ".." in Path(validation_command[1]).parts
                or not (stage_dir / validation_command[1]).is_file()
            ):
                raise LifecycleError(
                    "production validation_command must invoke a checked-in relative script"
                )
            result = subprocess.run(
                validation_command,
                cwd=stage_dir,
                capture_output=True,
                text=True,
                check=False,
                timeout=300,
            )
            if result.returncode:
                detail = (result.stdout + result.stderr).strip()
                raise LifecycleError(f"staged validation failed: {detail}")

        os.replace(instance_root, backup_dir)
        _fsync_directory(parent)
        journal["phase"] = "original_moved"
        _write_yaml(journal_path, journal)
        os.replace(stage_dir, instance_root)
        _fsync_directory(parent)
        journal["phase"] = "stage_published"
        _write_yaml(journal_path, journal)
        receipt = {
            "formatVersion": UPGRADE_RECEIPT_FORMAT,
            "status": "applied",
            "idempotent": False,
            "planDigest": plan_value["planDigest"],
            "lockDigest": _canonical_digest(staged_lock),
            "approval": {
                "planDigest": approval["planDigest"],
                "approvedBy": approval.get("approvedBy"),
                "approvedAt": approval.get("approvedAt"),
            },
            "appliedAt": applied_at,
            "current": {
                **plan_value["current"],
                # Promotion replaces the directory inode.  The plan binds the
                # pre-apply root; the receipt binds the committed post-apply
                # root for safe idempotent reruns.
                "rootIdentity": _instance_root_identity(instance_root),
            },
            "target": plan_value["target"],
            "files": plan_value["entries"],
            "retirements": plan_value.get("retirements", []),
            "history": [history_event],
        }
        receipt["receiptDigest"] = _receipt_digest(receipt)
        _write_yaml(instance_root / ".statedd" / "upgrade-receipt.yaml", receipt)
        committed = True
        try:
            journal["phase"] = "receipt_committed"
            _write_yaml(journal_path, journal)
            shutil.rmtree(backup_dir)
            legacy_journal = _safe_target_path(
                instance_root, ".statedd/upgrade-transaction.yaml", "upgrade journal"
            )
            if legacy_journal.exists():
                legacy_journal.unlink()
            if journal_path.exists():
                journal_path.unlink()
            _fsync_directory(parent)
        except (OSError, LifecycleError):
            # The valid receipt is the commit point. Keep the parent journal so
            # the next locked invocation can finish cleanup without rolling back.
            pass
        return receipt
    except Exception:
        if committed:
            raise
        try:
            _recover_interrupted_upgrade(instance_root)
        except Exception as recovery_exc:
            raise LifecycleError(
                f"upgrade failed and automatic recovery failed: {recovery_exc}"
            ) from recovery_exc
        raise


def create_instance(
    template_path: Path | str,
    instance_path: Path | str,
    *,
    instance_id: str,
    name: str,
    owner_name: str,
    owner_handle: str,
    status: str = "draft",
    allow_fixture: bool = False,
    source_descriptor: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a minimal instance document, materialise it, and lock provenance."""
    instance_id = _require_string(instance_id, "instance_id")
    name = _require_string(name, "name")
    owner_name = _require_string(owner_name, "owner_name")
    owner_handle = _require_string(owner_handle, "owner_handle")
    if status not in {"active", "archived", "draft"}:
        raise LifecycleError("status must be active, archived, or draft")
    root = _safe_root_path(template_path, "template root")
    target = _safe_root_path(instance_path, "instance root")
    manifest = load_template_manifest(root)
    assert_fixture_use_allowed(manifest, allow_fixture)
    if target.exists() and not target.is_dir():
        raise LifecycleError("instance destination must be a directory")
    if target.exists() and any(target.iterdir()):
        raise LifecycleError(f"instance destination is not empty: {target}")
    target.mkdir(parents=True, exist_ok=True)
    template_ref_path = Path(os.path.relpath(root, target)).as_posix()
    instance_data = {
        "apiVersion": "statedd.stateport.io/v1alpha1",
        "kind": "Instance",
        "metadata": {"id": instance_id, "name": name},
        "spec": {
            "templateRef": {"id": manifest["templateId"], "path": template_ref_path},
            "status": status,
            "owner": {"name": owner_name, "handle": owner_handle},
        },
    }
    _write_yaml(target / "instance.yaml", instance_data)
    return materialize_instance(
        root,
        target,
        allow_fixture=allow_fixture,
        source_descriptor=source_descriptor,
    )
