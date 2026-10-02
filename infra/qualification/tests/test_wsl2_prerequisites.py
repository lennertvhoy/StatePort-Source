from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Sequence


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "infra/qualification"))

import wsl2_prerequisites as probe  # noqa: E402


class Runner:
    def __init__(self, *, kernel_release: str = "6.6.87.2-microsoft-standard-WSL2") -> None:
        self.kernel_release = kernel_release

    def run(self, argv: Sequence[str], *, timeout: int) -> probe.Completed:
        command = tuple(argv)
        outputs = {
            ("uname", "-s"): "Linux\n",
            ("uname", "-m"): "x86_64\n",
            ("uname", "-r"): self.kernel_release + "\n",
            ("ps", "-p", "1", "-o", "comm="): "systemd\n",
            ("podman", "version", "--format", "{{.Client.Version}}"): "5.0.0\n",
            ("podman", "info", "--format", "{{.Host.Security.Rootless}}"): "true\n",
            ("systemctl", "--user", "show-environment"): "HOME=/home/operator\n",
        }
        if command[0] == "powershell.exe":
            return probe.Completed(
                0,
                json.dumps(
                    {
                        "caption": "Microsoft Windows 11 Pro",
                        "version": "10.0.26100",
                        "buildNumber": 26100,
                        "productType": 1,
                    }
                ),
                "",
            )
        return probe.Completed(0, outputs[command], "")


def _files(tmp_path: Path) -> dict[str, object]:
    os_release = tmp_path / "os-release"
    os_release.write_text('ID=ubuntu\nVERSION_ID="24.04"\n', encoding="utf-8")
    cgroup = tmp_path / "cgroup.controllers"
    cgroup.write_text("cpu memory pids\n", encoding="utf-8")
    subuid = tmp_path / "subuid"
    subgid = tmp_path / "subgid"
    subuid.write_text("test:100000:65536\n", encoding="utf-8")
    subgid.write_text("test:100000:65536\n", encoding="utf-8")
    quadlet = tmp_path / "quadlet"
    quadlet.write_text("fixture\n", encoding="utf-8")
    return {
        "os_release_path": os_release,
        "cgroup_controllers": cgroup,
        "subuid_path": subuid,
        "subgid_path": subgid,
        "quadlet_candidates": (quadlet,),
        "environment": {"WSL_INTEROP": "/run/WSL/1_interop", "WSL_DISTRO_NAME": "Ubuntu-24.04"},
        "username": "test",
        "home": Path("/home/operator"),
    }


def test_exact_windows11_wsl2_ubuntu2404_prerequisites_pass(tmp_path: Path) -> None:
    result = probe.observe(runner=Runner(), **_files(tmp_path))
    assert result["eligible"] is True
    assert result["refusalCodes"] == []
    assert result["facts"]["targetId"] == probe.TARGET_ID
    assert result["facts"]["windows"]["buildNumber"] == 26100


def test_wsl1_and_windows_filesystem_home_fail_closed(tmp_path: Path) -> None:
    inputs = _files(tmp_path)
    inputs["home"] = Path("/mnt/c/stateport-fixture")
    result = probe.observe(
        runner=Runner(kernel_release="4.4.0-19041-Microsoft"), **inputs
    )
    assert result["eligible"] is False
    assert "wsl2_required" in result["refusalCodes"]
    assert "linux_filesystem_home_required" in result["refusalCodes"]


def test_missing_runtime_capabilities_are_reported_together(tmp_path: Path) -> None:
    inputs = _files(tmp_path)
    Path(inputs["cgroup_controllers"]).unlink()
    Path(inputs["subgid_path"]).write_text("", encoding="utf-8")
    inputs["quadlet_candidates"] = (tmp_path / "missing-quadlet",)
    result = probe.observe(runner=Runner(), **inputs)
    assert result["eligible"] is False
    assert {"cgroup_v2_required", "quadlet_required", "subgid_mapping_required"} <= set(
        result["refusalCodes"]
    )
