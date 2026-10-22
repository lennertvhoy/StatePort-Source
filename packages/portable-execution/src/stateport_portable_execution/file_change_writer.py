#!/usr/bin/env python3
"""StatePort-owned writer for ``stateport.file-change-proposal/v1``.

This file runs only inside the apply bubblewrap sandbox (no network, a
writable *staging copy* of the instance at ``/instance``, the run's content
store read-only at ``/blobs``). It imports nothing but the standard library so
it can run under the read-only system Python. StatePort re-checks every effect
it claims from outside the sandbox; this writer is defence in depth, not the
authority.

    file_change_writer.py apply  --root /instance --blobs /blobs   < proposal.json
    file_change_writer.py commit --root /instance                  < commit.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any

PROPOSAL_FORMAT = "stateport.file-change-proposal/v1"
RECEIPT_FORMAT = "stateport.file-change-writer-receipt/v1"
COMMIT_FORMAT = "stateport.file-change-commit/v1"
PROTECTED_ROOTS = {".git", ".stateport", ".statedd"}


def _sha256(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _digest(value: Any) -> str:
    return _sha256((json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode())


def _safe(path: str) -> str:
    if not isinstance(path, str) or not path or path.startswith("/") or "\\" in path or "\x00" in path:
        raise ValueError("unsafe proposal path")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("unsafe proposal path")
    if parts[0].casefold() in PROTECTED_ROOTS or any(part.casefold() == ".git" for part in parts):
        raise ValueError("protected proposal path")
    return path


def _parent_directory(root: Path, relative: str, *, create: bool, missing_ok: bool = False) -> Path | None:
    """Walk to the parent without following a link at any component."""

    cursor = root
    for part in relative.split("/")[:-1]:
        cursor = cursor / part
        try:
            info = os.lstat(cursor)
        except FileNotFoundError:
            if missing_ok:
                return None
            if not create:
                raise ValueError("proposal parent directory is missing")
            os.mkdir(cursor, 0o755)
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ValueError("proposal parent is not a plain directory")
    return cursor


def _current(path: Path) -> bytes | None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("proposal target is not a private regular file")
    return path.read_bytes()


def apply(root: Path, blobs: Path, proposal: dict[str, Any]) -> dict[str, Any]:
    if proposal.get("formatVersion") != PROPOSAL_FORMAT or proposal.get("kind") != "files":
        raise ValueError("unsupported proposal format")
    operations = proposal.get("operations")
    if not isinstance(operations, list) or not operations:
        raise ValueError("proposal has no operations")
    # Pass 1: verify every pre-image and blob before the first write.
    planned: list[tuple[str, str, bytes | None, int]] = []
    for item in operations:
        relative = _safe(str(item.get("path")))
        operation = item.get("operation")
        parent = _parent_directory(root, relative, create=False, missing_ok=True)
        target = (parent / Path(relative).name) if parent is not None else None
        current = _current(target) if target is not None else None
        previous = item.get("previousDigest")
        if (current is None) != (previous is None) or (current is not None and _sha256(current) != previous):
            raise ValueError("proposal pre-image does not match the staged instance")
        mode = stat.S_IMODE(os.lstat(target).st_mode) if current is not None and target is not None else 0o644
        if operation == "write":
            content_digest = str(item.get("contentDigest", ""))
            blob = blobs / "sha256" / content_digest[7:]
            if not content_digest.startswith("sha256:") or blob.is_symlink() or not blob.is_file():
                raise ValueError("proposal content is unavailable")
            content = blob.read_bytes()
            if _sha256(content) != content_digest:
                raise ValueError("proposal content digest mismatch")
            planned.append((relative, "write", content, mode))
        elif operation == "delete":
            if current is None:
                raise ValueError("proposal deletes a missing file")
            planned.append((relative, "delete", None, mode))
        else:
            raise ValueError("unsupported proposal operation")
    # Pass 2: write.
    for index, (relative, operation, content, mode) in enumerate(planned):
        if operation == "write":
            parent = _parent_directory(root, relative, create=True)
            assert parent is not None
            temporary = parent / f".stateport-write-{os.getpid()}-{index}.tmp"
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
            try:
                view = memoryview(content or b"")
                while view:
                    view = view[os.write(descriptor, view):]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.chmod(temporary, mode)
            os.replace(temporary, parent / Path(relative).name)
        else:
            parent = _parent_directory(root, relative, create=False)
            assert parent is not None
            os.unlink(parent / Path(relative).name)
    removed = (proposal.get("directories") or {}).get("removed", [])
    for directory in sorted((str(item) for item in removed), key=lambda value: value.count("/"), reverse=True):
        _safe(directory)
        target = root / directory
        info = os.lstat(target)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ValueError("proposal directory removal target is unsafe")
        os.rmdir(target)
    post = {
        relative: (_sha256(content) if operation == "write" else None)
        for relative, operation, content, _mode in planned
    }
    return {
        "formatVersion": RECEIPT_FORMAT,
        "proposalId": proposal.get("proposalId"),
        "preStateDigest": proposal.get("preStateDigest"),
        "postStateDigest": _digest(post),
        "operations": len(planned),
        "validation": "passed",
    }


def _git(root: Path, arguments: list[str], *, environment: dict[str, str], stdin: str | None = None) -> str:
    completed = subprocess.run(
        [
            "git", "-C", str(root),
            "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
            "-c", "commit.gpgSign=false", "-c", f"safe.directory={root}",
            *arguments,
        ],
        input=stdin, capture_output=True, text=True, timeout=60,
        env=environment, check=False,
    )
    if completed.returncode != 0:
        raise ValueError("git " + arguments[0] + " failed")
    return completed.stdout.strip()


def commit(root: Path, request: dict[str, Any]) -> dict[str, Any]:
    paths = request.get("paths")
    message = request.get("message")
    parent = request.get("parent")
    if not isinstance(paths, list) or not paths or not isinstance(message, str) or not message.strip():
        raise ValueError("commit request is invalid")
    for path in paths:
        _safe(str(path))
    environment = {
        "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/home", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_AUTHOR_NAME": "StatePort", "GIT_AUTHOR_EMAIL": "stateport@example.invalid",
        "GIT_COMMITTER_NAME": "StatePort", "GIT_COMMITTER_EMAIL": "stateport@example.invalid",
    }
    head = _git(root, ["rev-parse", "--verify", "HEAD"], environment=environment)
    if head != parent:
        raise ValueError("instance HEAD is not the proposal base")
    # A private index: the operator's own staged changes are never swept into
    # StatePort's commit, and only the proposal's paths change in the tree.
    private_index = {**environment, "GIT_INDEX_FILE": "/tmp/stateport-commit-index"}
    _git(root, ["read-tree", head], environment=private_index)
    _git(root, ["update-index", "--add", "--remove", "--", *paths], environment=private_index)
    tree = _git(root, ["write-tree"], environment=private_index)
    created = _git(root, ["commit-tree", "--no-gpg-sign", tree, "-p", head], environment=environment, stdin=message)
    _git(root, ["update-ref", "-m", "stateport: apply file-change proposal", "HEAD", created, head], environment=environment)
    _git(root, ["update-index", "--add", "--remove", "--", *paths], environment=environment)
    return {"formatVersion": COMMIT_FORMAT, "commit": created, "parent": head, "tree": tree}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("apply", "commit"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--blobs", type=Path)
    args = parser.parse_args()
    request = json.load(sys.stdin)
    if args.mode == "apply":
        if args.blobs is None:
            raise ValueError("--blobs is required")
        result = apply(args.root, args.blobs, request)
    else:
        result = commit(args.root, request)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
