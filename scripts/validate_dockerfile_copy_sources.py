#!/usr/bin/env python3
"""Validate local Dockerfile COPY sources without misparsing multi-source COPY."""

from __future__ import annotations

import argparse
import glob
import json
from pathlib import Path
import shlex
import sys


class DockerfileCopyError(ValueError):
    pass


def logical_lines(text: str) -> list[str]:
    lines: list[str] = []
    pending = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        pending = f"{pending} {stripped}".strip() if pending else stripped
        if pending.endswith("\\"):
            pending = pending[:-1].rstrip()
            continue
        lines.append(pending)
        pending = ""
    if pending:
        raise DockerfileCopyError("Dockerfile ends with an incomplete continuation")
    return lines


def copy_sources(instruction: str) -> list[str] | None:
    if not instruction.upper().startswith("COPY "):
        return None
    body = instruction[5:].strip()
    if not body:
        raise DockerfileCopyError("COPY instruction is empty")

    if body.startswith("["):
        try:
            values = json.loads(body)
        except json.JSONDecodeError as exc:
            raise DockerfileCopyError("COPY JSON form is invalid") from exc
        if not isinstance(values, list) or len(values) < 2 or any(
            not isinstance(value, str) or not value for value in values
        ):
            raise DockerfileCopyError("COPY JSON form must contain sources and a destination")
        return values[:-1]

    try:
        tokens = shlex.split(body, posix=True)
    except ValueError as exc:
        raise DockerfileCopyError("COPY shell form is invalid") from exc
    flags: list[str] = []
    while tokens and tokens[0].startswith("--"):
        flags.append(tokens.pop(0))
    if any(flag == "--from" or flag.startswith("--from=") for flag in flags):
        return []
    if len(tokens) < 2:
        raise DockerfileCopyError("COPY shell form must contain sources and a destination")
    return tokens[:-1]


def validate_dockerfile(path: Path, context_root: Path) -> list[str]:
    if not path.is_file() or path.is_symlink():
        return [f"{path}: Dockerfile is missing or unsafe"]
    errors: list[str] = []
    for instruction in logical_lines(path.read_text(encoding="utf-8")):
        try:
            sources = copy_sources(instruction)
        except DockerfileCopyError as exc:
            errors.append(f"{path}: {exc}: {instruction}")
            continue
        if sources is None:
            continue
        for source in sources:
            if "$" in source:
                errors.append(
                    f"{path}: COPY source uses an unresolved variable and cannot be verified: {source}"
                )
                continue
            candidate_pattern = context_root / source
            matches = [Path(item) for item in glob.glob(str(candidate_pattern), recursive=True)]
            if not matches:
                errors.append(f"{path}: COPY source does not exist: {source}")
                continue
            for candidate in matches:
                try:
                    candidate.resolve().relative_to(context_root.resolve())
                except ValueError:
                    errors.append(f"{path}: COPY source escapes the build context: {source}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("dockerfiles", nargs="*", type=Path)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    dockerfiles = args.dockerfiles or sorted(root.glob("apps/*/Dockerfile"))
    errors: list[str] = []
    for dockerfile in dockerfiles:
        path = dockerfile if dockerfile.is_absolute() else root / dockerfile
        errors.extend(validate_dockerfile(path, root))
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"OK: validated COPY sources in {len(dockerfiles)} Dockerfiles")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
