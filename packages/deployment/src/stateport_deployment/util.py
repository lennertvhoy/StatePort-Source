"""Small, fail-closed filesystem and identity helpers for deployment state."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
from typing import Any, Iterator, Mapping

from .errors import DeploymentRefusal


SAFE_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40,64}\Z")
MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
MAX_DOCUMENT_DEPTH = 64
MAX_DOCUMENT_NODES = 100_000


def timestamp(value: datetime | None = None) -> str:
    return (value or datetime.now(timezone.utc)).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _bounded_document(value: object, *, label: str) -> None:
    nodes = 0

    def visit(item: object, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_DOCUMENT_NODES or depth > MAX_DOCUMENT_DEPTH:
            raise DeploymentRefusal(
                "document_too_complex", f"{label} exceeds bounded complexity"
            )
        if isinstance(item, Mapping):
            for key, child in item.items():
                visit(key, depth + 1)
                visit(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                visit(child, depth + 1)

    visit(value, 0)


def strict_mapping_document(
    text: str,
    *,
    format_name: str,
    label: str,
    error_code: str = "descriptor_invalid",
) -> dict[str, Any]:
    """Parse a bounded mapping with no duplicate keys, aliases, or NaN."""

    if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_DOCUMENT_BYTES:
        raise DeploymentRefusal(error_code, f"{label} exceeds the document size limit")

    def duplicate_safe_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate key: {key}")
            result[key] = value
        return result

    try:
        if format_name == "json":
            value = json.loads(
                text,
                object_pairs_hook=duplicate_safe_object,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    ValueError(f"non-finite value: {value}")
                ),
            )
        elif format_name == "yaml":
            import yaml

            class StrictSafeLoader(yaml.SafeLoader):
                def __init__(self, stream: str) -> None:
                    super().__init__(stream)
                    self._stateport_depth = 0
                    self._stateport_nodes = 0

                def compose_node(self, parent: Any, index: Any) -> Any:
                    if self.check_event(yaml.AliasEvent):
                        raise yaml.YAMLError("aliases are not permitted")
                    self._stateport_depth += 1
                    self._stateport_nodes += 1
                    try:
                        if (
                            self._stateport_depth > MAX_DOCUMENT_DEPTH
                            or self._stateport_nodes > MAX_DOCUMENT_NODES
                        ):
                            raise yaml.YAMLError("document complexity exceeded")
                        return super().compose_node(parent, index)
                    finally:
                        self._stateport_depth -= 1

            def construct_mapping(
                loader: StrictSafeLoader, node: Any, deep: bool = False
            ) -> dict[Any, Any]:
                if not isinstance(node, yaml.MappingNode):
                    raise yaml.YAMLError("mapping node required")
                result: dict[Any, Any] = {}
                for key_node, value_node in node.value:
                    key = loader.construct_object(key_node, deep=deep)
                    try:
                        duplicate = key in result
                    except TypeError as exc:
                        raise yaml.YAMLError("mapping key is not scalar") from exc
                    if duplicate:
                        raise yaml.YAMLError(f"duplicate key: {key}")
                    result[key] = loader.construct_object(value_node, deep=deep)
                return result

            StrictSafeLoader.add_constructor(
                yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
                construct_mapping,
            )
            value = yaml.load(text, Loader=StrictSafeLoader)
        else:
            raise ValueError("unsupported document format")
        _bounded_document(value, label=label)
    except DeploymentRefusal:
        raise
    except (ImportError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise DeploymentRefusal(error_code, f"{label} could not be parsed safely") from exc
    except Exception as exc:
        # PyYAML exceptions are deliberately kept outside the module import
        # surface.  They are still converted to a typed fail-closed refusal.
        raise DeploymentRefusal(error_code, f"{label} could not be parsed safely") from exc
    if not isinstance(value, dict):
        raise DeploymentRefusal(error_code, f"{label} must contain an object")
    return value


def digest_value(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def safe_id(value: object, label: str) -> str:
    if not isinstance(value, str) or SAFE_ID.fullmatch(value) is None:
        raise DeploymentRefusal("invalid_identity", f"{label} is invalid")
    return value


def relative_posix(value: object, label: str, *, allow_dot: bool = True) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise DeploymentRefusal("unsafe_path", f"{label} must be a relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".."} for part in path.parts):
        raise DeploymentRefusal("unsafe_path", f"{label} must stay inside the project")
    normalized = path.as_posix()
    if normalized == "." and not allow_dot:
        raise DeploymentRefusal("unsafe_path", f"{label} may not be the project root")
    return normalized


def confined(root: Path, relative: str, label: str, *, must_exist: bool = True) -> Path:
    relative = relative_posix(relative, label)
    if root.is_symlink() or not root.is_dir():
        raise DeploymentRefusal("unsafe_path", f"{label} root is missing or unsafe")
    cursor = root
    if relative != ".":
        for part in PurePosixPath(relative).parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise DeploymentRefusal("symlink_escape", f"{label} may not traverse a symlink")
    if must_exist and not cursor.exists():
        raise DeploymentRefusal("unsafe_path", f"{label} does not exist")
    try:
        resolved = cursor.resolve(strict=must_exist)
        resolved.relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise DeploymentRefusal("path_escape", f"{label} escapes the project") from exc
    return resolved


def ensure_private_directory(path: Path) -> Path:
    """Create a private directory without chmodding caller-owned ancestors."""

    path = path.absolute()
    missing: list[Path] = []
    cursor = path
    while True:
        try:
            metadata = cursor.lstat()
        except FileNotFoundError:
            missing.append(cursor)
        else:
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise DeploymentRefusal(
                    "unsafe_state_root",
                    "deployment state path traverses a symlink or non-directory",
                )
        parent = cursor.parent
        if parent == cursor:
            break
        cursor = parent
    for candidate in reversed(missing):
        try:
            candidate.mkdir(mode=0o700)
        except FileExistsError:
            pass
        metadata = candidate.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise DeploymentRefusal(
                "unsafe_state_root", "new deployment state directory is not private"
            )
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise DeploymentRefusal(
            "unsafe_state_root",
            "existing deployment state directory must already be owner-private",
        )
    return path


def existing_private_directory(path: Path) -> Path:
    """Validate an existing private directory without materialising any path."""

    path = path.absolute()
    cursor = path
    while True:
        try:
            metadata = cursor.lstat()
        except FileNotFoundError as exc:
            raise DeploymentRefusal(
                "deployment_not_found", "deployment state directory does not exist"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise DeploymentRefusal(
                "unsafe_state_root",
                "deployment state path traverses a symlink or non-directory",
            )
        parent = cursor.parent
        if parent == cursor:
            break
        cursor = parent
    metadata = path.lstat()
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise DeploymentRefusal(
            "unsafe_state_root",
            "existing deployment state directory must be owner-private",
        )
    return path


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_json(path: Path, value: Mapping[str, Any], *, create_only: bool = False) -> None:
    ensure_private_directory(path.parent)
    if path.is_symlink():
        raise DeploymentRefusal("unsafe_state_file", "deployment state file may not be a symlink")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(canonical_bytes(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        if create_only:
            try:
                os.link(temporary, path, follow_symlinks=False)
            except FileExistsError as exc:
                raise DeploymentRefusal(
                    "identity_conflict", f"immutable deployment record already exists: {path.name}"
                ) from exc
            temporary.unlink()
            temporary = None
        else:
            os.replace(temporary, path)
            temporary = None
        _fsync_directory(path.parent)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def read_json(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise DeploymentRefusal("record_not_found", f"{label} is missing or unsafe")
    try:
        raw = path.read_bytes()
        if len(raw) > MAX_DOCUMENT_BYTES:
            raise DeploymentRefusal(
                "record_invalid", f"{label} exceeds the document size limit"
            )
        text = raw.decode("utf-8")
        return strict_mapping_document(
            text,
            format_name="json",
            label=label,
            error_code="record_invalid",
        )
    except DeploymentRefusal:
        raise
    except (OSError, UnicodeError) as exc:
        raise DeploymentRefusal("record_invalid", f"{label} could not be read safely") from exc


@contextmanager
def exclusive_lock(path: Path) -> Iterator[None]:
    ensure_private_directory(path.parent)
    if path.is_symlink():
        raise DeploymentRefusal("unsafe_lock", "deployment lock may not be a symlink")
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise DeploymentRefusal(
                "deployment_busy", "another writer owns this deployment"
            ) from exc
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


@contextmanager
def existing_exclusive_lock(path: Path) -> Iterator[None]:
    """Lock an existing record without creating or repairing any state."""

    if path.is_symlink() or not path.is_file():
        raise DeploymentRefusal(
            "record_not_found", "deployment lock is missing or unsafe"
        )
    try:
        descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
    except OSError as exc:
        raise DeploymentRefusal(
            "record_invalid", "deployment lock could not be opened safely"
        ) from exc
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise DeploymentRefusal(
                "deployment_busy", "another writer owns this deployment"
            ) from exc
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def default_state_root() -> Path:
    xdg = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return xdg / "stateport" / "deployments"


__all__ = [
    "COMMIT",
    "DIGEST",
    "atomic_json",
    "canonical_bytes",
    "confined",
    "default_state_root",
    "digest_bytes",
    "digest_value",
    "ensure_private_directory",
    "existing_private_directory",
    "existing_exclusive_lock",
    "exclusive_lock",
    "read_json",
    "relative_posix",
    "safe_id",
    "strict_mapping_document",
    "timestamp",
]
