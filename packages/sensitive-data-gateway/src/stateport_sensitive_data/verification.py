"""Value-free negative persistence verification for bounded local roots."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import os
from pathlib import Path
from typing import Any, Iterable


_EXCLUDED_DIRECTORY_NAMES = frozenset(
    {".git", ".pytest_cache", ".venv", "__pycache__", "node_modules"}
)
_MAX_FILES = 100_000
_MAX_BYTES = 2 * 1024 * 1024 * 1024


@dataclass(frozen=True)
class NegativePersistenceReceipt:
    roots_scanned: int
    files_scanned: int
    bytes_scanned: int
    excluded_directories: int
    symlinks_skipped: int
    forbidden_value_count: int
    outcome: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def verify_values_absent(roots: Iterable[Path], forbidden_values: Iterable[bytes]) -> NegativePersistenceReceipt:
    """Scan regular files without returning values, excerpts, or machine paths."""

    selected_roots = tuple(roots)
    values = tuple(forbidden_values)
    if not selected_roots or not values or any(not value for value in values):
        raise ValueError("bounded roots and non-empty forbidden values are required")
    files = 0
    byte_count = 0
    excluded_directories = 0
    symlinks_skipped = 0
    found = False
    for root in selected_roots:
        if not root.is_absolute() or root.is_symlink() or not root.is_dir():
            raise ValueError("persistence scan root must be an absolute real directory")
        for directory, names, filenames in os.walk(root, followlinks=False):
            retained: list[str] = []
            for name in sorted(names):
                path = Path(directory) / name
                if name in _EXCLUDED_DIRECTORY_NAMES:
                    excluded_directories += 1
                elif path.is_symlink():
                    symlinks_skipped += 1
                else:
                    retained.append(name)
            names[:] = retained
            for name in sorted(filenames):
                path = Path(directory) / name
                if path.is_symlink():
                    symlinks_skipped += 1
                    continue
                if not path.is_file():
                    continue
                size = path.stat().st_size
                if files >= _MAX_FILES or byte_count + size > _MAX_BYTES:
                    raise ValueError("persistence scan exceeds its bounded file or byte limit")
                payload = path.read_bytes()
                files += 1
                byte_count += len(payload)
                if any(value in payload for value in values):
                    found = True
    return NegativePersistenceReceipt(
        roots_scanned=len(selected_roots),
        files_scanned=files,
        bytes_scanned=byte_count,
        excluded_directories=excluded_directories,
        symlinks_skipped=symlinks_skipped,
        forbidden_value_count=len(values),
        outcome="detected" if found else "absent",
    )
