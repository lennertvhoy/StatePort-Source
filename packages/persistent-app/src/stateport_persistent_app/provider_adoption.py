"""Adopt an already signed-in OpenCode into the managed provider home.

OpenCode keeps every sign-in it performs, stock providers and OpenCode Go
alike, in one file: ``$XDG_DATA_HOME/opencode/auth.json`` (default
``~/.local/share/opencode/auth.json``), a JSON object keyed by provider id
whose values are ``{"type": "api", "key": ...}`` or ``{"type": "oauth", ...}``
records. ``opencode.json`` under ``$XDG_CONFIG_HOME/opencode`` is user
configuration (plugins, MCP servers, permissions), not a sign-in, and it can
carry unrelated or secret settings, so it is deliberately never adopted.

Adoption is a one-way COPY of the SELECTED provider records of that file into
the StatePort provider home, where the managed OpenCode subprocess already
looks for it (``<home>/data/opencode/auth.json``, see
``opencode_subprocess_environment``):

* only the record(s) of the selected provider id(s) are written; unrelated
  providers (for example an OAuth login for another vendor) are never copied.
  Selection order: an explicit id list (each must be present in the source),
  else the provider named by the model currently selected in StatePort
  (``<provider>/<model>``), else ``opencode-go`` / ``opencode`` when present,
  else the adoption is refused and the detected NAMES are listed;
* the copy is a regular file written with mode 0600 by the service's own
  uid inside a 0700 directory chain; a symbolic link is never created and a
  symbolic-linked source is refused. Every destination component is opened
  with O_NOFOLLOW relative to a directory descriptor, so a path component
  swapped for a symbolic link while adopting cannot redirect the write;
* the source is parsed in memory; the only things ever recorded or returned
  are presence, a timestamp, the source path and the provider NAMES (map keys);
* OAuth caveat: OpenCode rotates an OAuth refresh token whenever it refreshes
  one. A copied OAuth record that refreshes inside StatePort can invalidate the
  original OpenCode sign-in. Prefer API-key providers (opencode-go) for adoption;
* values are never logged, returned, written to a receipt or transmitted, and
  no error text embeds file content.

The module is standard-library only so the host-side installer helper can
load it by file path without importing the application package.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import stat

AUTH_FILE_NAME = "auth.json"
ADOPTION_MARKER_NAME = "adopted-signin.json"
SOURCE_OVERRIDE_ENV = "STATEPORT_OPENCODE_ADOPT_SOURCE"
MAX_AUTH_BYTES = 65536
_PROVIDER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_MAX_PROVIDER_NAMES = 32
DEFAULT_PROVIDER_IDS = ("opencode-go", "opencode")
OAUTH_ROTATION_CAVEAT = (
    "OAuth sign-ins rotate their refresh token when they refresh: if the copy refreshes, the original "
    "OpenCode sign-in may be signed out. Prefer an API-key provider such as opencode-go."
)


class AdoptionError(ValueError):
    """A bounded, fixed-code refusal. The detail names paths, never contents."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def destination_auth_path(home: Path) -> Path:
    """Where managed OpenCode (``XDG_DATA_HOME=<home>/data``) reads auth.json."""
    return Path(home) / "data" / "opencode" / AUTH_FILE_NAME


def candidate_source_directories(source: Mapping[str, str] | None = None) -> list[Path]:
    """OpenCode data directories that may hold an existing sign-in, in order.

    The list is fixed: an explicit installer-provided mount first, then the
    service user's own XDG and home locations. No request ever supplies a
    path, so adoption can never be turned into an arbitrary file read.
    """
    environment = os.environ if source is None else source
    found: list[Path] = []

    def add(raw: object) -> None:
        text = str(raw or "").strip()
        if not text:
            return
        candidate = Path(text)
        if candidate.is_absolute() and candidate not in found:
            found.append(candidate)

    add(environment.get(SOURCE_OVERRIDE_ENV))
    xdg = str(environment.get("XDG_DATA_HOME", "") or "").strip()
    if xdg:
        add(Path(xdg) / "opencode" if Path(xdg).is_absolute() else "")
    home = str(environment.get("HOME", "") or "").strip()
    if home:
        add(Path(home) / ".local" / "share" / "opencode")
    return found


def read_signin_file(path: Path) -> tuple[bytes, list[str]]:
    """Read one auth.json safely; return (verbatim bytes, provider names).

    Callers that WRITE a copy must pass the bytes through ``select_signin``;
    the verbatim bytes of every provider are never a valid thing to copy.

    Refuses symbolic links, non-regular files, empty or oversized files and
    anything that is not a non-empty JSON object of objects. Exceptions carry
    the path and a fixed reason only.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as exc:
        raise AdoptionError("adoption_source_missing", f"no OpenCode sign-in file at {path}") from exc
    except OSError as exc:
        raise AdoptionError(
            "adoption_source_unsafe",
            f"the OpenCode sign-in file at {path} is a symbolic link or cannot be opened",
        ) from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise AdoptionError("adoption_source_unsafe", f"{path} is not a regular file")
        if info.st_size < 2 or info.st_size > MAX_AUTH_BYTES:
            raise AdoptionError(
                "adoption_source_invalid",
                f"{path} is empty or larger than the {MAX_AUTH_BYTES}-byte bound",
            )
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(MAX_AUTH_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > MAX_AUTH_BYTES:
        raise AdoptionError("adoption_source_invalid", f"{path} is larger than the {MAX_AUTH_BYTES}-byte bound")
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise AdoptionError("adoption_source_invalid", f"{path} is not a JSON object") from exc
    if not isinstance(parsed, dict) or not parsed or not all(isinstance(value, dict) for value in parsed.values()):
        raise AdoptionError("adoption_source_invalid", f"{path} holds no OpenCode sign-in records")
    names = sorted(name for name in parsed if isinstance(name, str) and _PROVIDER_NAME.fullmatch(name))
    return raw, names[:_MAX_PROVIDER_NAMES]


def select_provider_ids(
    detected: list[str], requested: list[str] | None = None, selected_hint: str | None = None
) -> list[str]:
    """Choose which provider records to copy; never "all of them".

    ``requested`` (explicit) must be a non-empty list of detected ids; else
    ``selected_hint`` (the provider selected in StatePort) when detected; else
    the default ids that are present; else refuse naming the detected ids.
    """
    if requested is not None:
        if (
            not isinstance(requested, (list, tuple)) or not requested or len(requested) > _MAX_PROVIDER_NAMES
            or not all(isinstance(name, str) and _PROVIDER_NAME.fullmatch(name) for name in requested)
        ):
            raise AdoptionError("adoption_provider_invalid", "providers must be a non-empty list of provider ids")
        missing = [name for name in requested if name not in detected]
        if missing:
            raise AdoptionError(
                "adoption_provider_not_found",
                f"the sign-in file holds no record for: {', '.join(missing)}. "
                f"Detected providers: {', '.join(detected) or 'none'}.",
            )
        return sorted(set(requested))
    if selected_hint and selected_hint in detected:
        return [selected_hint]
    defaults = [name for name in DEFAULT_PROVIDER_IDS if name in detected]
    if defaults:
        return defaults
    raise AdoptionError(
        "adoption_provider_unselected",
        "No provider to adopt was selected and the sign-in file holds neither "
        f"{' nor '.join(DEFAULT_PROVIDER_IDS)}. Detected providers: {', '.join(detected) or 'none'}. "
        "Choose the provider ids to adopt explicitly.",
    )


def select_signin(raw: bytes, provider_ids: list[str]) -> bytes:
    """Serialise ONLY the records of ``provider_ids`` (values untouched)."""
    parsed = json.loads(raw.decode("utf-8"))
    chosen = {name: parsed[name] for name in provider_ids if isinstance(parsed, dict) and name in parsed}
    if not chosen or set(chosen) != set(provider_ids):
        raise AdoptionError("adoption_provider_not_found", "the selected provider records are missing")
    return (json.dumps(chosen, indent=2) + "\n").encode("utf-8")


def marker_bytes(source: Path, providers: list[str], now: datetime | None = None) -> bytes:
    """The only record kept: timestamp, source path and provider names."""
    stamp = (now or datetime.now(timezone.utc)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return json.dumps(
        {"adoptedAt": stamp, "source": str(source), "providers": providers},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


def _open_directory_chain(
    directory: Path, base: Path | None, *, create: bool, directory_mode: int,
    uid: int | None, gid: int | None,
) -> int:
    """Open ``directory`` and return a descriptor, never following a symlink.

    ``base`` (default ``/``) is opened normally, trusting everything above it;
    every component below it is opened with O_NOFOLLOW|O_DIRECTORY relative to
    the previous descriptor (and created with mkdirat when ``create``), so a
    component swapped for a symbolic link at any moment cannot redirect the
    traversal: the caller keeps working on the directory it actually opened.
    """
    base = Path(base) if base is not None else Path("/")
    try:
        relative = directory.relative_to(base)
    except ValueError as exc:
        raise AdoptionError("adoption_home_unsafe", f"{directory} is not below {base}") from exc
    if create and not os.path.lexists(base):
        try:
            base.mkdir(mode=directory_mode, parents=True, exist_ok=True)  # trusted prefix (test roots)
        except OSError as exc:
            raise AdoptionError("adoption_home_unwritable", f"cannot create {base}") from exc
    try:
        current = os.open(base, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise AdoptionError("adoption_home_unwritable", f"cannot open {base}") from exc
    try:
        for component in relative.parts:
            if component in {"", ".", ".."}:
                raise AdoptionError("adoption_home_unsafe", f"{directory} is not a normalised path")
            try:
                following = os.open(component, _DIRECTORY_FLAGS, dir_fd=current)
            except FileNotFoundError:
                if not create:
                    raise AdoptionError("adoption_home_unwritable", f"cannot open {directory}")
                try:
                    os.mkdir(component, directory_mode, dir_fd=current)
                    following = os.open(component, _DIRECTORY_FLAGS, dir_fd=current)
                except OSError as exc:
                    raise AdoptionError("adoption_home_unwritable", f"cannot create {directory}") from exc
                try:
                    os.fchmod(following, directory_mode)
                    if uid is not None or gid is not None:
                        os.fchown(following, -1 if uid is None else uid, -1 if gid is None else gid)
                except OSError as exc:
                    os.close(following)
                    raise AdoptionError("adoption_home_unwritable", f"cannot create {directory}") from exc
            except OSError as exc:
                # ELOOP (symbolic link), ENOTDIR (not a directory) and the rest
                # all mean the same thing here: this is not a private directory.
                raise AdoptionError("adoption_home_unsafe", f"{directory} is not a private directory") from exc
            os.close(current)
            current = following
        return current
    except BaseException:
        os.close(current)
        raise


def write_private_file(
    destination: Path, data: bytes, *, mode: int = 0o600, directory_mode: int = 0o700,
    uid: int | None = None, gid: int | None = None, base: Path | None = None,
    file_gid: int | None = None,
) -> os.stat_result:
    """Atomically place ``data`` at ``destination`` as a regular file.

    Everything is done relative to a directory descriptor obtained by an
    O_NOFOLLOW walk (see ``_open_directory_chain``): the temporary file is
    created with O_EXCL|O_NOFOLLOW beside the target, set to ``mode`` before
    any content lands, optionally chowned through its descriptor (installer
    side, as root) and renamed with renameat over the target. A symlinked
    parent component or target is refused. ``base`` bounds the trusted prefix
    (default: ``/``, i.e. every component is checked). ``file_gid`` overrides
    ``gid`` for the file only (directories keep ``gid``).
    """
    parent = destination.parent
    dirfd = _open_directory_chain(
        parent, base, create=True, directory_mode=directory_mode, uid=uid, gid=gid
    )
    temporary = f".adopt.{secrets.token_hex(8)}.tmp"
    created = False
    try:
        try:
            existing = os.lstat(destination.name, dir_fd=dirfd)
        except FileNotFoundError:
            existing = None
        if existing is not None and stat.S_ISLNK(existing.st_mode):
            raise AdoptionError("adoption_home_unsafe", f"{destination} is a symbolic link")
        try:
            descriptor = os.open(
                temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=dirfd,
            )
            created = True
            with os.fdopen(descriptor, "wb") as handle:
                os.fchmod(handle.fileno(), mode)
                group = gid if file_gid is None else file_gid
                if uid is not None or group is not None:
                    os.fchown(handle.fileno(), -1 if uid is None else uid, -1 if group is None else group)
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
                written = os.fstat(handle.fileno())
            os.rename(temporary, destination.name, src_dir_fd=dirfd, dst_dir_fd=dirfd)
            created = False
            return written
        except PermissionError as exc:
            raise AdoptionError(
                "adoption_home_unwritable",
                f"{parent} is not writable by uid {os.geteuid()}; it must be owned by the service uid with mode 0700",
            ) from exc
        except OSError as exc:
            raise AdoptionError("adoption_home_unwritable", f"cannot write {destination}") from exc
    finally:
        if created:
            try:
                os.unlink(temporary, dir_fd=dirfd)
            except OSError:
                pass
        os.close(dirfd)


class OpenCodeAdoption:
    """Presence-only view and adopt/forget actions for one provider home."""

    def __init__(
        self, home: Path, environment: Mapping[str, str] | None = None,
        selected_provider: Callable[[], str | None] | None = None,
    ) -> None:
        self.home = Path(home)
        # Returns the auth.json provider id StatePort currently has selected
        # (the ``<provider>`` of the saved ``<provider>/<model>``), or None.
        self._selected_provider = selected_provider
        self.auth_path = destination_auth_path(self.home)
        self.marker_path = self.home / ADOPTION_MARKER_NAME
        self._environment = environment

    # ---------------------------------------------------------------- query

    def _present(self) -> bool:
        try:
            info = os.lstat(self.auth_path)
        except OSError:
            return False
        return stat.S_ISREG(info.st_mode) and 2 <= info.st_size <= MAX_AUTH_BYTES

    def _marker(self) -> dict[str, object]:
        try:
            if self.marker_path.is_symlink() or self.marker_path.stat().st_size > 4096:
                return {}
            data = json.loads(self.marker_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def _source_file(self) -> Path | None:
        """First candidate that exists as a plain file (presence only)."""
        for directory in candidate_source_directories(self._environment):
            candidate = directory / AUTH_FILE_NAME
            try:
                info = os.lstat(candidate)
            except OSError:
                continue
            if stat.S_ISREG(info.st_mode) and not self._is_destination(candidate):
                return candidate
        return None

    def _is_destination(self, candidate: Path) -> bool:
        try:
            return os.path.samefile(candidate, self.auth_path)
        except OSError:
            return False

    def status(self) -> dict[str, object]:
        """Names, presence and timestamps only; never a value."""
        adopted = self._present()
        marker = self._marker() if adopted else {}
        providers = marker.get("providers")
        source = self._source_file() if not adopted else None
        return {
            "adoptionStatus": "adopted" if adopted else "not_adopted",
            "adoptionSourceAvailable": source is not None,
            "adoptedAt": marker.get("adoptedAt") if isinstance(marker.get("adoptedAt"), str) else None,
            "adoptedSource": marker.get("source") if isinstance(marker.get("source"), str) else None,
            "adoptionSourceProviders": self.source_providers() if source is not None else [],
            "adoptedProviders": [
                name for name in providers if isinstance(name, str) and _PROVIDER_NAME.fullmatch(name)
            ] if isinstance(providers, list) else [],
        }

    # -------------------------------------------------------------- actions

    def source_providers(self) -> list[str]:
        """Provider NAMES found in the first candidate sign-in file (never values)."""
        source = self._source_file()
        if source is None:
            return []
        try:
            return read_signin_file(source)[1]
        except AdoptionError:
            return []

    def adopt(
        self, *, providers: list[str] | None = None, now: datetime | None = None
    ) -> dict[str, object]:
        searched = [directory / AUTH_FILE_NAME for directory in candidate_source_directories(self._environment)]
        source = None
        for candidate in searched:
            if os.path.lexists(candidate) and not self._is_destination(candidate):
                source = candidate
                break
        if source is None:
            names = ", ".join(str(path) for path in searched) or "no candidate location is configured"
            raise AdoptionError(
                "adoption_source_missing",
                "No existing OpenCode sign-in was found. Looked for: "
                f"{names}. Sign in with OpenCode in this environment, or run the host-side adopt helper "
                "(scripts/adopt_opencode_signin.py) which copies it into "
                f"{self.auth_path}.",
            )
        raw, detected = read_signin_file(source)
        hint = None
        if self._selected_provider is not None:
            try:
                hint = self._selected_provider()
            except Exception:  # noqa: BLE001 - an unreadable profile only loses the hint
                hint = None
        chosen = select_provider_ids(detected, providers, hint)
        data = select_signin(raw, chosen)
        self._guard_home()
        base = self.home.parent
        written = write_private_file(self.auth_path, data, base=base)
        self._verify_destination(written)
        write_private_file(self.marker_path, marker_bytes(source, chosen, now), base=base)
        return self.status()

    def forget(self) -> dict[str, object]:
        """Delete only StatePort's copy. The source sign-in is never touched."""
        for path in (self.auth_path, self.marker_path):
            try:
                dirfd = _open_directory_chain(
                    path.parent, self.home.parent, create=False, directory_mode=0o700, uid=None, gid=None
                )
            except AdoptionError:
                continue  # nothing (or nothing safe to follow) to remove
            try:
                os.unlink(path.name, dir_fd=dirfd)
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise AdoptionError(
                    "adoption_home_unwritable", f"cannot remove {path}; it must be owned by uid {os.geteuid()}"
                ) from exc
            finally:
                os.close(dirfd)
        return self.status()

    # -------------------------------------------------------------- helpers

    def _guard_home(self) -> None:
        if self.home.is_symlink():
            raise AdoptionError("adoption_home_unsafe", f"{self.home} is a symbolic link")
        if self.home.exists():
            info = os.lstat(self.home)
            if not stat.S_ISDIR(info.st_mode):
                raise AdoptionError("adoption_home_unsafe", f"{self.home} is not a directory")
            if info.st_uid != os.geteuid():
                raise AdoptionError(
                    "adoption_home_unwritable",
                    f"{self.home} is owned by uid {info.st_uid} but the service runs as uid {os.geteuid()}; "
                    "give the provider home to the service uid with mode 0700, or use the host-side adopt helper",
                )

    def _verify_destination(self, info: os.stat_result) -> None:
        # ``info`` is the descriptor-level stat of the file that was renamed into place.
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid():
            raise AdoptionError(
                "adoption_home_unsafe", f"{self.auth_path} did not end up a private regular file"
            )


__all__ = [
    "ADOPTION_MARKER_NAME",
    "AUTH_FILE_NAME",
    "AdoptionError",
    "DEFAULT_PROVIDER_IDS",
    "MAX_AUTH_BYTES",
    "OAUTH_ROTATION_CAVEAT",
    "OpenCodeAdoption",
    "SOURCE_OVERRIDE_ENV",
    "candidate_source_directories",
    "destination_auth_path",
    "marker_bytes",
    "read_signin_file",
    "select_provider_ids",
    "select_signin",
    "write_private_file",
]
