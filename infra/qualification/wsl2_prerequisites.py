#!/usr/bin/env python3
"""Read-only Windows 11 + WSL2 + Ubuntu 24.04 prerequisite probe."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
from typing import Mapping, Protocol, Sequence


FORMAT = "stateport.wsl2-prerequisite-observation/v1"
TARGET_ID = "wsl2-ubuntu2404-linux-amd64-rootless-podman-quadlet"
PODMAN_MINIMUM = (5, 0, 0)
QUADLET_CANDIDATES = (
    Path("/usr/libexec/podman/quadlet"),
    Path("/usr/lib/podman/quadlet"),
    Path("/usr/lib/systemd/user-generators/podman-user-generator"),
)


@dataclass(frozen=True)
class Completed:
    returncode: int
    stdout: str
    stderr: str


class Runner(Protocol):
    def run(self, argv: Sequence[str], *, timeout: int) -> Completed: ...


class SubprocessRunner:
    def run(self, argv: Sequence[str], *, timeout: int) -> Completed:
        completed = subprocess.run(
            list(argv),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            stdin=subprocess.DEVNULL,
        )
        return Completed(completed.returncode, completed.stdout, completed.stderr)


def _os_release(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for line in lines:
        key, separator, value = line.partition("=")
        if separator and re.fullmatch(r"[A-Z_]+", key):
            values[key] = value.strip().strip('"')
    return values


def _mapping(path: Path, username: str) -> bool:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return False
    for line in lines:
        fields = line.split(":")
        if (
            len(fields) == 3
            and fields[0] == username
            and fields[1].isdigit()
            and fields[2].isdigit()
            and int(fields[2]) >= 65536
        ):
            return True
    return False


def _version(value: str) -> tuple[int, int, int] | None:
    match = re.match(r"^\s*(\d+)\.(\d+)\.(\d+)", value)
    return tuple(int(part) for part in match.groups()) if match else None


def _run(runner: Runner, argv: Sequence[str]) -> Completed:
    try:
        return runner.run(argv, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        return Completed(127, "", str(exc))


def observe(
    *,
    runner: Runner,
    os_release_path: Path = Path("/etc/os-release"),
    cgroup_controllers: Path = Path("/sys/fs/cgroup/cgroup.controllers"),
    subuid_path: Path = Path("/etc/subuid"),
    subgid_path: Path = Path("/etc/subgid"),
    quadlet_candidates: Sequence[Path] = QUADLET_CANDIDATES,
    environment: Mapping[str, str] | None = None,
    username: str | None = None,
    home: Path | None = None,
) -> dict[str, object]:
    environment = os.environ if environment is None else environment
    account = pwd.getpwuid(os.getuid())
    username = account.pw_name if username is None else username
    home = Path(account.pw_dir) if home is None else home

    kernel = _run(runner, ("uname", "-s"))
    architecture = _run(runner, ("uname", "-m"))
    kernel_release = _run(runner, ("uname", "-r"))
    pid_one = _run(runner, ("ps", "-p", "1", "-o", "comm="))
    podman = _run(runner, ("podman", "version", "--format", "{{.Client.Version}}"))
    rootless = _run(runner, ("podman", "info", "--format", "{{.Host.Security.Rootless}}"))
    systemd_user = _run(runner, ("systemctl", "--user", "show-environment"))
    windows = _run(
        runner,
        (
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$o=Get-CimInstance Win32_OperatingSystem;"
            "[ordered]@{caption=$o.Caption;version=$o.Version;"
            "buildNumber=[int]$o.BuildNumber;productType=[int]$o.ProductType}"
            "|ConvertTo-Json -Compress",
        ),
    )
    try:
        windows_identity = json.loads(windows.stdout.strip()) if windows.returncode == 0 else {}
    except json.JSONDecodeError:
        windows_identity = {}
    if not isinstance(windows_identity, dict):
        windows_identity = {}

    release = kernel_release.stdout.strip()
    distro = _os_release(os_release_path)
    podman_version = podman.stdout.strip()
    build = windows_identity.get("buildNumber")
    windows_11 = (
        isinstance(build, int)
        and build >= 22000
        and windows_identity.get("productType") == 1
    )
    facts = {
        "targetId": TARGET_ID,
        "kernel": kernel.stdout.strip(),
        "kernelRelease": release,
        "architecture": architecture.stdout.strip(),
        "wsl2": "microsoft" in release.casefold() and "wsl2" in release.casefold(),
        "wslInteropPresent": bool(environment.get("WSL_INTEROP")),
        "wslDistroName": environment.get("WSL_DISTRO_NAME"),
        "distribution": distro.get("ID", ""),
        "distributionVersion": distro.get("VERSION_ID", ""),
        "windows": windows_identity,
        "windows11": windows_11,
        "systemdPid1": pid_one.returncode == 0 and pid_one.stdout.strip() == "systemd",
        "cgroupV2": cgroup_controllers.is_file(),
        "podmanVersion": podman_version,
        "podmanVersionMeetsFloor": (
            _version(podman_version) is not None
            and _version(podman_version) >= PODMAN_MINIMUM  # type: ignore[operator]
        ),
        "rootlessPodman": rootless.returncode == 0 and rootless.stdout.strip().lower() == "true",
        "quadlet": any(path.is_file() for path in quadlet_candidates),
        "systemdUser": systemd_user.returncode == 0,
        "subuidMapping": _mapping(subuid_path, username),
        "subgidMapping": _mapping(subgid_path, username),
        "linuxFilesystemHome": not home.as_posix().startswith("/mnt/"),
    }
    requirements = {
        "linux_kernel_required": facts["kernel"] == "Linux",
        "linux_amd64_required": facts["architecture"] in {"x86_64", "amd64"},
        "wsl2_required": facts["wsl2"] is True,
        "windows11_required": facts["windows11"] is True,
        "ubuntu_2404_required": (
            facts["distribution"] == "ubuntu" and facts["distributionVersion"] == "24.04"
        ),
        "systemd_pid1_required": facts["systemdPid1"] is True,
        "cgroup_v2_required": facts["cgroupV2"] is True,
        "podman_version_floor": facts["podmanVersionMeetsFloor"] is True,
        "rootless_podman_required": facts["rootlessPodman"] is True,
        "quadlet_required": facts["quadlet"] is True,
        "systemd_user_required": facts["systemdUser"] is True,
        "subuid_mapping_required": facts["subuidMapping"] is True,
        "subgid_mapping_required": facts["subgidMapping"] is True,
        "linux_filesystem_home_required": facts["linuxFilesystemHome"] is True,
    }
    refusals = [code for code, passed in requirements.items() if not passed]
    return {
        "formatVersion": FORMAT,
        "eligible": not refusals,
        "refusalCodes": refusals,
        "facts": facts,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    document = observe(runner=SubprocessRunner())
    serialized = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        print(serialized, end="")
    else:
        args.output.write_text(serialized, encoding="utf-8")
    return 0 if document["eligible"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
