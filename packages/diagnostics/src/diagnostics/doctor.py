"""Read-only diagnostics checks for a StatePort checkout."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import platform
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any, Callable, Mapping
from urllib.error import URLError
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

from diagnostics.model import (
    CODE_COMPONENT,
    Component,
    Diagnostic,
    DiagnosticCode,
    DoctorReport,
    Severity,
)


ReadinessProbe = Callable[[str, float], int]


@dataclass(frozen=True)
class DoctorConfig:
    """Inputs for :class:`Doctor`; all paths are read-only inputs."""

    repo_root: Path
    config_paths: tuple[Path, ...] = (Path("PROJECT_STATE.yaml"), Path("PROJECT_ADAPTER.yaml"))
    adapter_fixture: Path = Path("fixtures/host/synthetic-capabilities.json")
    ui_url: str | None = None
    api_url: str | None = None
    timeout_seconds: float = 1.0
    read_only: bool = True

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if not self.read_only:
            raise ValueError("doctor checks are read-only; read_only must remain true")


class Doctor:
    """Run bounded, deterministic health checks without changing the checkout."""

    def __init__(self, config: DoctorConfig, *, readiness_probe: ReadinessProbe | None = None) -> None:
        self.config = config
        self._readiness_probe = readiness_probe or _http_readiness_probe

    @property
    def read_only(self) -> bool:
        return self.config.read_only

    def run(self) -> DoctorReport:
        diagnostics: list[Diagnostic] = []
        diagnostics.extend(self.check_runtime())
        root_diagnostics = self.check_root()
        diagnostics.extend(root_diagnostics)
        blocking_root = next((item for item in root_diagnostics if item.is_failure), None)
        if blocking_root is not None:
            return DoctorReport(
                tuple(diagnostics),
                skipped_checks=tuple(
                    {"check": name, "status": "skipped", "blockedBy": blocking_root.code.value}
                    for name in ("paths", "config", "adapter_fixture", "readiness", "git")
                ),
            )
        diagnostics.extend(self.check_paths())
        diagnostics.extend(self.check_config())
        diagnostics.extend(self.check_adapter_fixture())
        diagnostics.extend(self.check_readiness())
        diagnostics.extend(self.check_git())
        return DoctorReport(tuple(diagnostics))

    def check_runtime(self) -> tuple[Diagnostic, ...]:
        version = sys.version_info
        supported = version >= (3, 10)
        return (
            Diagnostic(
                DiagnosticCode.ENV,
                Severity.INFO if supported else Severity.ERROR,
                Component.ENVIRONMENT,
                "Python runtime is available for StatePort diagnostics."
                if supported
                else "Python runtime is older than the supported minimum.",
                {"pythonMajor": version.major, "pythonMinor": version.minor, "platform": platform.system()},
                "Use Python 3.10 or newer to run StatePort.",
                ("sys.version_info",),
            ),
        )

    def check_root(self) -> tuple[Diagnostic, ...]:
        """Validate the operator-supplied root before inspecting its files."""

        root = self.config.repo_root
        details: dict[str, Any] = {"suppliedRoot": _safe_path_value(root)}
        try:
            root_stat = root.stat()
        except FileNotFoundError:
            return (
                Diagnostic(
                    DiagnosticCode.INSTANCE_ROOT_NOT_FOUND,
                    Severity.ERROR,
                    Component.INSTANCE,
                    "The supplied StatePort root does not exist.",
                    details,
                    "Provide an existing StatePort checkout or instance root; doctor will not create it.",
                    ("path.stat",),
                ),
            )
        except PermissionError:
            return (
                Diagnostic(
                    DiagnosticCode.INSTANCE_ROOT_INACCESSIBLE,
                    Severity.ERROR,
                    Component.INSTANCE,
                    "The supplied StatePort root cannot be accessed.",
                    details,
                    "Grant read and directory-traversal access to the root, then run doctor again.",
                    ("path.stat",),
                ),
            )
        except OSError as exc:
            details["errorType"] = type(exc).__name__
            return (
                Diagnostic(
                    DiagnosticCode.INSTANCE_ROOT_INACCESSIBLE,
                    Severity.ERROR,
                    Component.INSTANCE,
                    "The supplied StatePort root cannot be accessed.",
                    details,
                    "Make the root readable and traversable, then run doctor again.",
                    ("path.stat",),
                ),
            )

        if not stat.S_ISDIR(root_stat.st_mode):
            details["rootKind"] = "file"
            return (
                Diagnostic(
                    DiagnosticCode.INSTANCE_ROOT_NOT_DIRECTORY,
                    Severity.ERROR,
                    Component.INSTANCE,
                    "The supplied StatePort root is not a directory.",
                    details,
                    "Provide a directory containing the StatePort checkout or instance files.",
                    ("path.stat",),
                ),
            )

        readable = bool(root_stat.st_mode & (stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH))
        traversable = bool(root_stat.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        if not readable or not traversable or not os.access(root, os.R_OK | os.X_OK):
            details["rootKind"] = "inaccessible-directory"
            return (
                Diagnostic(
                    DiagnosticCode.INSTANCE_ROOT_INACCESSIBLE,
                    Severity.ERROR,
                    Component.INSTANCE,
                    "The supplied StatePort root is not readable and traversable.",
                    details,
                    "Grant read and directory-traversal access to the root, then run doctor again.",
                    ("path.stat", "os.access"),
                ),
            )
        return ()

    def check_paths(self) -> tuple[Diagnostic, ...]:
        root = self.config.repo_root
        paths = [*self.config.config_paths, self.config.adapter_fixture]
        problems: list[str] = []
        checked: list[str] = []
        if root.is_symlink():
            problems.append("repo root is a symlink")
        if not root.is_dir():
            problems.append("repo root is not a directory")
        try:
            root_resolved = root.resolve(strict=True)
        except OSError as exc:
            root_resolved = root.resolve()
            problems.append(f"repo root cannot be resolved: {type(exc).__name__}")
        for configured in paths:
            path = configured if configured.is_absolute() else root / configured
            label = _safe_relative_label(path, root)
            checked.append(label)
            if not _is_within(path, root_resolved):
                problems.append(f"path escapes repository: {label}")
                continue
            if _has_symlink_component(path, root):
                problems.append(f"path contains a symlink: {label}")
            if not path.exists():
                problems.append(f"path does not exist: {label}")
            elif not path.is_file():
                problems.append(f"path is not a regular file: {label}")
        severity = Severity.ERROR if problems else Severity.INFO
        return (
            Diagnostic(
                DiagnosticCode.SOURCE,
                severity,
                Component.SOURCE,
                "Configured source paths are contained and symlink-safe."
                if not problems
                else "Configured source paths are not safe to inspect.",
                {"checkedPaths": checked, "problems": problems},
                "Use regular files inside the repository and remove escaping or symlinked paths.",
                ("path.resolve", "path.is_symlink"),
            ),
        )

    def check_config(self) -> tuple[Diagnostic, ...]:
        problems: list[str] = []
        files: list[dict[str, Any]] = []
        for configured in self.config.config_paths:
            path = self._repo_path(configured)
            label = _safe_relative_label(path, self.config.repo_root)
            if not self._safe_input_path(path):
                problems.append(f"{label}: path rejected by path-safety policy")
                continue
            try:
                text = path.read_text(encoding="utf-8")
                if not text.strip():
                    raise ValueError("file is empty")
                parsed = _parse_config(path, text)
                if not isinstance(parsed, Mapping):
                    raise ValueError("top-level value must be a mapping")
                files.append({"path": label, "bytes": len(text.encode("utf-8")), "topLevelKeys": sorted(parsed)})
            except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
                problems.append(f"{label}: {type(exc).__name__}: {_safe_error(str(exc))}")
        return (
            Diagnostic(
                DiagnosticCode.INSTANCE,
                Severity.ERROR if problems else Severity.INFO,
                Component.INSTANCE,
                "StatePort configuration files can be read and parsed."
                if not problems
                else "One or more StatePort configuration files are invalid.",
                {"files": files, "problems": problems},
                "Repair the reported configuration file and validate it again.",
                tuple(item["path"] for item in files) or ("configured config paths",),
            ),
        )

    def check_adapter_fixture(self) -> tuple[Diagnostic, ...]:
        path = self._repo_path(self.config.adapter_fixture)
        label = _safe_relative_label(path, self.config.repo_root)
        problems: list[str] = []
        details: dict[str, Any] = {"path": label}
        try:
            if not self._safe_input_path(path):
                raise ValueError("path rejected by path-safety policy")
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, Mapping):
                raise ValueError("fixture top-level value must be a mapping")
            required = {"formatVersion", "backend", "adapter", "integrationTier", "capabilities", "authenticationRouteClasses", "adapterPermissions"}
            missing = sorted(required - set(data))
            if missing:
                raise ValueError(f"missing fields: {', '.join(missing)}")
            adapter = data["adapter"]
            if not isinstance(adapter, Mapping) or adapter.get("testOnly") is not True or adapter.get("productionEligible") is not False:
                raise ValueError("fixture must be explicitly test-only and production-ineligible")
            if data["formatVersion"] != "stateport.backend-capabilities/v1":
                raise ValueError("unsupported capabilities format")
            backend = data["backend"]
            if not isinstance(backend, Mapping) or not isinstance(backend.get("id"), str) or not backend["id"].strip():
                raise ValueError("backend.id must be a non-empty string")
            if not isinstance(adapter.get("id"), str) or not isinstance(adapter.get("version"), str):
                raise ValueError("adapter id and version must be strings")
            if not isinstance(data["capabilities"], Mapping) or not data["capabilities"]:
                raise ValueError("capabilities must be a non-empty mapping")
            if any(not isinstance(key, str) or not isinstance(value, str) for key, value in data["capabilities"].items()):
                raise ValueError("capabilities must be a string mapping")
            if not isinstance(data["authenticationRouteClasses"], list) or not isinstance(data["adapterPermissions"], list):
                raise ValueError("authentication routes and permissions must be lists")
            details.update({"backend": backend["id"], "adapter": adapter["id"], "testOnly": True})
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
            problems.append(f"{type(exc).__name__}: {_safe_error(str(exc))}")
        return (
            Diagnostic(
                DiagnosticCode.HOST,
                Severity.ERROR if problems else Severity.INFO,
                Component.HOST,
                "The adapter fixture is explicit, parseable, and production-ineligible."
                if not problems
                else "The adapter fixture cannot be trusted for local host checks.",
                {**details, "problems": problems},
                "Repair the fixture or mark it explicitly as test-only and production-ineligible.",
                (label,),
            ),
        )

    def check_readiness(self) -> tuple[Diagnostic, ...]:
        diagnostics: list[Diagnostic] = []
        for target, url in (("ui", self.config.ui_url), ("api", self.config.api_url)):
            if url is None:
                continue
            safe_url = _safe_url(url)
            try:
                status = self._readiness_probe(url, self.config.timeout_seconds)
                healthy = 200 <= status < 400
                diagnostics.append(
                    Diagnostic(
                        DiagnosticCode.RUN,
                        Severity.INFO if healthy else Severity.WARNING,
                        Component.RUN,
                        f"Optional {target.upper()} readiness probe succeeded."
                        if healthy
                        else f"Optional {target.upper()} readiness probe returned HTTP {status}.",
                        {"target": target, "url": safe_url, "httpStatus": status},
                        f"Start the {target} service or verify its readiness URL."
                        if not healthy
                        else "No action required.",
                        (safe_url,),
                    )
                )
            except (OSError, URLError, ValueError) as exc:
                diagnostics.append(
                    Diagnostic(
                        DiagnosticCode.RUN,
                        Severity.WARNING,
                        Component.RUN,
                        f"Optional {target.upper()} readiness probe was unavailable.",
                        {"target": target, "url": safe_url, "error": _safe_error(str(exc))},
                        f"Start the {target} service or verify its readiness URL.",
                        (safe_url,),
                    )
                )
        return tuple(diagnostics)

    def check_git(self) -> tuple[Diagnostic, ...]:
        details: dict[str, Any] = {"readOnly": self.read_only}
        problems: list[str] = []
        try:
            top = _git(self.config.repo_root, "rev-parse", "--show-toplevel")
            branch = _git(self.config.repo_root, "branch", "--show-current") or "(detached HEAD)"
            status = _git(self.config.repo_root, "status", "--porcelain=v1", "--untracked-files=no")
            expected = self.config.repo_root.resolve(strict=True)
            if Path(top).resolve() != expected:
                problems.append("git top-level directory differs from repo root")
            details.update({"branch": branch, "worktree": "clean" if not status else "modified", "topLevel": _safe_relative_label(Path(top), expected)})
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            problems.append(f"git check failed: {type(exc).__name__}: {_safe_error(str(exc))}")
        return (
            Diagnostic(
                DiagnosticCode.CI,
                Severity.ERROR if problems else Severity.INFO,
                Component.CI,
                "The checkout is an identifiable Git worktree."
                if not problems
                else "The checkout cannot be verified as the expected Git worktree.",
                {**details, "problems": problems},
                "Run the doctor from the repository root and repair the Git checkout if needed.",
                ("git rev-parse", "git status --porcelain"),
            ),
        )

    def _repo_path(self, path: Path) -> Path:
        return path if path.is_absolute() else self.config.repo_root / path

    def _safe_input_path(self, path: Path) -> bool:
        try:
            root = self.config.repo_root.resolve(strict=True)
        except OSError:
            return False
        return _is_within(path, root) and not _has_symlink_component(path, self.config.repo_root)


def _parse_config(path: Path, text: str) -> Any:
    if path.suffix.lower() == ".json":
        return json.loads(text)
    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError:
        raise ValueError("YAML parser is unavailable")
    return yaml.safe_load(text)


def _git(cwd: Path, *args: str) -> str:
    env = {"GIT_OPTIONAL_LOCKS": "0"}
    completed = subprocess.run(
        ["git", *args],
        cwd=cwd,
        env={**__import__("os").environ, **env},
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    return completed.stdout.strip()


def _http_readiness_probe(url: str, timeout: float) -> int:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.netloc or parts.username or parts.password:
        raise ValueError("readiness URL must be an http(s) URL without embedded credentials")
    with urlopen(Request(url, method="GET"), timeout=timeout) as response:  # noqa: S310 - explicit read-only probe
        return int(response.status)


def _safe_error(value: str) -> str:
    return " ".join(value.replace("\n", " ").split())[:240]


def _safe_path_value(value: Path) -> str:
    """Keep operator input printable and JSON-safe without resolving it."""

    return os.fsdecode(os.fsencode(str(value)))


def _safe_url(value: str) -> str:
    parts = urlsplit(value)
    if parts.username or parts.password:
        netloc = f"<redacted>@{parts.hostname or '<invalid>'}"
    else:
        netloc = parts.netloc
    query = urlencode([
        (key, "<redacted>" if key.lower() in {"api_key", "apikey", "authorization", "credential", "password", "secret", "token"} else item)
        for key, item in parse_qsl(parts.query, keep_blank_values=True)
    ])
    return urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root)
        return True
    except ValueError:
        return False


def _has_symlink_component(path: Path, root: Path) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return True
    current = root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            return True
    return False


def _safe_relative_label(path: Path, root: Path) -> str:
    try:
        return path.resolve(strict=False).relative_to(root.resolve(strict=False)).as_posix()
    except ValueError:
        return "<outside-repository>"
