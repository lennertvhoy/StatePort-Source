"""Adversarial tests for the execution-host provisioning path.

EVIDENCE LABEL — everything in this file is *locally-simulated*:

- the host is a tmpdir layout (``HostLayout.root``), fake account tables
  (``SimAccounts``), and an in-process command interpreter (``SimRunner``);
  no real users/groups are created, no image is pulled, no unit is started;
- protocol-health tests perform a REAL AF_UNIX ``describeCapabilities``
  round trip against an in-process fake daemon speaking the exact receipt
  contract — that exercises the probe, never the production daemon;
- receipts produced here must carry ``evidenceClass: locally-simulated``.

Clean-host proof (real root apply on a fresh VM) is BLOCKED and is not
claimed anywhere in this file.
"""

from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
from typing import Any, Sequence

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "packages" / "release-contracts" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "execution-host" / "src"))

from execution_host import daemon_contract as daemon_contract  # noqa: E402
from stateport_release import execution_host_provisioning as prov  # noqa: E402
from stateport_release.contract import (  # noqa: E402
    ReleaseContractError,
    validate_contract_document,
    verify_release_index,
)
import test_release_contracts as fixtures  # noqa: E402


# ---------------------------------------------------------------------------
# Verified-release fixture
# ---------------------------------------------------------------------------


def _verified(target_id: str = "linux-amd64-rootless-podman-quadlet"):
    document = fixtures.release_index()
    if target_id != "linux-amd64-rootless-podman-quadlet":
        document = deepcopy(document)
        target = document["signed"]["targets"][0]
        target["targetId"] = target_id
        target["hostBaseline"] = target_id
        target["topologyDigest"] = fixtures.topology_digest(target)
        target["quadletBundleDigest"] = fixtures.quadlet_bundle_digest(
            fixtures.render_quadlet_bundle(target, document["signed"]["images"])
        )
        document["signatures"] = [
            fixtures._signature(
                fixtures.canonical_digest(document["signed"]), "release-index"
            )
        ]
    return verify_release_index(
        document,
        policy=fixtures._policy(expected_target=target_id),
        verifier=fixtures._EphemeralTestVerifier(),
    )


def _plan() -> dict[str, Any]:
    verified = _verified()
    return prov.render_provisioning_plan(
        verified.target,
        verified.index.document["signed"]["images"],
        verification_basis="signature-verified-test",
    )


# ---------------------------------------------------------------------------
# Simulated host: accounts, layout, command interpreter, fake daemon
# ---------------------------------------------------------------------------


class SimAccounts:
    """Fake passwd/group tables; every numeric id is the test process's own
    uid/gid so real chown/chmod calls in the apply path succeed non-root."""

    def __init__(self) -> None:
        self.uid = os.getuid()
        self.gid = os.getgid()
        self.users: dict[str, prov.Account] = {
            "root": prov.Account("root", self.uid, self.gid, "/root", "/bin/bash"),
            # The control-plane client user pre-exists on a real host; the
            # provisioning only confines it into the socket group.
            "stateport-control": prov.Account(
                "stateport-control",
                self.uid,
                self.gid,
                "/var/lib/stateport-control",
                prov.DEFAULT_NOLOGIN_SHELL,
            ),
        }
        self.groups: dict[str, prov.Group] = {
            prov.CONTROL_USER: prov.Group(prov.CONTROL_USER, self.gid, ()),
        }
        self.primary_groups: dict[str, str] = {
            "root": "root",
            "stateport-control": "stateport-control",
        }

    def user(self, name: str) -> prov.Account | None:
        return self.users.get(name)

    def group(self, name: str) -> prov.Group | None:
        return self.groups.get(name)

    def primary_group_users(self, group_name: str) -> tuple[str, ...]:
        return tuple(
            sorted(name for name, primary in self.primary_groups.items() if primary == group_name)
        )

    def add_group(self, name: str, *, gid: int | None = None) -> None:
        self.groups[name] = prov.Group(name, self.gid if gid is None else gid, ())

    def add_user(
        self,
        name: str,
        *,
        gid: int,
        home: str,
        shell: str,
        primary_group: str | None = None,
    ) -> None:
        self.users[name] = prov.Account(name, self.uid, gid, home, shell)
        if primary_group is not None:
            self.primary_groups[name] = primary_group
        elif name in self.groups and self.groups[name].gid == gid:
            self.primary_groups[name] = name

    def add_member(self, group: str, user: str) -> None:
        record = self.groups[group]
        self.groups[group] = prov.Group(
            record.name, record.gid, tuple(sorted({*record.members, user}))
        )

    def drop_member(self, group: str, user: str) -> None:
        record = self.groups[group]
        self.groups[group] = prov.Group(
            record.name, record.gid, tuple(m for m in record.members if m != user)
        )


class SimHost:
    """In-process effects for the privileged commands the apply runs."""

    def __init__(self, root: Path, accounts: SimAccounts) -> None:
        self.root = root
        self.accounts = accounts
        self.units: dict[str, bool] = {}
        self.user_managers: set[str] = set()
        self.user_manager_states: dict[str, str] = {}
        self.enabled_units: set[str] = set()
        self.image_store: dict[str, str] = {}
        self.root_image_store: dict[str, str] = {}
        self.networks: dict[str, dict[str, Any]] = {}
        self.pull_into_wrong_store = False
        self.inspect_digest_override: str | None = None
        self.storage_graph_root = f"{prov.EXEC_HOME}/.local/share/containers/storage"
        self.storage_run_root = f"/run/user/{accounts.uid}/containers"
        self.storage_mode = 0o700
        self.oci_runtime = "runc"
        self.socket_dir_mode = 0o2750
        for relative in (
            "etc/tmpfiles.d",
            "usr/lib/systemd/user",
            "var/lib",
            "run",
            "var/lib/systemd/linger",
        ):
            (self.root / relative).mkdir(parents=True, exist_ok=True)
        (self.root / "usr/lib/systemd/user/podman.socket").write_text(
            "[Socket]\nListenStream=%t/podman/podman.sock\n", encoding="utf-8"
        )

    def resolve(self, absolute: str) -> Path:
        return self.root / absolute.lstrip("/")

    def execute(self, argv: Sequence[str]) -> prov.Completed:
        argv = list(argv)
        head = Path(argv[0]).name
        if head == "groupadd":
            name = argv[-1]
            if name in self.accounts.groups:
                return prov.Completed(9, "", f"groupadd: group '{name}' already exists")
            requested_gid = int(argv[argv.index("--gid") + 1])
            self.accounts.add_group(
                name,
                gid=(self.accounts.gid if self.root != Path("/") else requested_gid),
            )
            return prov.Completed(0, "", "")
        if head == "useradd":
            name = argv[-1]
            if name in self.accounts.users:
                return prov.Completed(9, "", f"useradd: user '{name}' already exists")
            home = argv[argv.index("--home-dir") + 1]
            shell = argv[argv.index("--shell") + 1]
            assert "--uid" in argv and "--gid" in argv
            requested_uid = int(argv[argv.index("--uid") + 1])
            requested_gid = int(argv[argv.index("--gid") + 1])
            assert requested_uid > 0 and requested_gid > 0
            if self.accounts.group(name) is None:
                self.accounts.add_group(name)  # user-private group
            group = self.accounts.group(name)
            assert group is not None
            self.accounts.add_user(name, gid=group.gid, home=home, shell=shell)
            self.resolve(home).mkdir(parents=True, exist_ok=True)
            return prov.Completed(0, "", "")
        if head == "usermod":
            group_name, user = argv[-2], argv[-1]
            if user not in self.accounts.users:
                return prov.Completed(6, "", f"usermod: user '{user}' does not exist")
            self.accounts.add_member(group_name, user)
            return prov.Completed(0, "", "")
        if head == "gpasswd":
            self.accounts.drop_member(argv[-1], argv[-2])
            return prov.Completed(0, "", "")
        if head == "userdel":
            self.accounts.users.pop(argv[-1], None)
            self.accounts.primary_groups.pop(argv[-1], None)
            return prov.Completed(0, "", "")
        if head == "groupdel":
            self.accounts.groups.pop(argv[-1], None)
            return prov.Completed(0, "", "")
        if head == "systemd-tmpfiles":
            socket_dir = self.resolve("/run/stateport/execution-control")
            socket_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(self.resolve("/run/stateport"), 0o755)
            os.chmod(socket_dir, self.socket_dir_mode)
            return prov.Completed(0, "", "")
        if head == "loginctl":
            marker = self.resolve(f"/var/lib/systemd/linger/{argv[-1]}")
            if argv[1] == "enable-linger":
                marker.parent.mkdir(parents=True, exist_ok=True)
                marker.touch()
                if argv[-1] == prov.EXEC_USER:
                    self.user_managers.add(f"user@{prov.EXEC_UID}.service")
                elif argv[-1] == prov.CONTROL_USER:
                    self.user_managers.add(f"user@{prov.CONTROL_UID}.service")
            else:
                marker.unlink(missing_ok=True)
                uid = prov.EXEC_UID if argv[-1] == prov.EXEC_USER else prov.CONTROL_UID
                unit = f"user@{uid}.service"
                self.user_managers.discard(unit)
                self.user_manager_states.pop(unit, None)
            return prov.Completed(0, "", "")
        if head == "systemctl":
            action = argv[1]
            unit = argv[-1]
            if action == "is-active":
                state = self.user_manager_states.get(unit)
                if state is not None:
                    return prov.Completed(0, state + "\n", "")
                if unit in self.user_managers:
                    return prov.Completed(0, "active\n", "")
                return prov.Completed(3, "inactive\n", "")
            if action == "start":
                self.user_managers.add(unit)
                return prov.Completed(0, "", "")
            if action == "stop":
                self.user_managers.discard(unit)
                self.user_manager_states.pop(unit, None)
                return prov.Completed(0, "", "")
        if head == "runuser":
            assert argv[1] == "-u" and argv[3] == "--"
            user_name = argv[2]
            command = argv[4:]
            assert Path(command[0]).name == "env"
            command = command[1:]
            if command and command[0] == "-i":
                command = command[1:]
            environment: dict[str, str] = {}
            while command and "=" in command[0] and not command[0].startswith("/"):
                key, value = command[0].split("=", 1)
                environment[key] = value
                command = command[1:]
            return self.execute_as_user(user_name, command, environment)
        raise AssertionError(f"unexpected privileged command: {argv}")

    def _materialize_daemon_unit(self) -> None:
        account = self.accounts.user(prov.EXEC_USER)
        if account is None:
            return
        source = self.resolve(
            "/var/lib/stateport-exec/.config/containers/systemd/stateport-execution-host.container"
        )
        if not source.is_file():
            return
        generator = self.resolve(f"/run/user/{account.uid}/systemd/generator")
        generator.mkdir(parents=True, exist_ok=True)
        (generator / prov.DAEMON_UNIT).write_text(
            "[Unit]\nSourcePath=" + prov.QUADLET_DIR + "/stateport-execution-host.container\n",
            encoding="utf-8",
        )
        wants = generator / "default.target.wants"
        wants.mkdir(exist_ok=True)
        link = wants / prov.DAEMON_UNIT
        if not link.exists() and not link.is_symlink():
            link.symlink_to(f"../{prov.DAEMON_UNIT}")

    def execute_as_user(
        self, user_name: str, argv: Sequence[str], environment: dict[str, str]
    ) -> prov.Completed:
        argv = list(argv)
        head = Path(argv[0]).name
        if head.startswith("python") and "-c" in argv:
            account = self.accounts.user(user_name)
            assert account is not None
            groups = [account.gid]
            groups.extend(
                group.gid
                for group in self.accounts.groups.values()
                if user_name in group.members
            )
            return prov.Completed(
                0,
                json.dumps(
                    {
                        "uid": account.uid,
                        "gid": account.gid,
                        "groups": sorted(set(groups)),
                        "environment": environment,
                    }
                )
                + "\n",
                "",
            )
        if head == "systemctl":
            assert argv[1] == "--user"
            action = argv[2]
            if action == "show-environment":
                account = self.accounts.user(user_name)
                assert account is not None
                unit = f"user@{prov.EXEC_UID if user_name == prov.EXEC_USER else prov.CONTROL_UID}.service"
                if unit not in self.user_managers:
                    return prov.Completed(1, "", "Failed to connect to bus")
                return prov.Completed(0, "PATH=/usr/bin:/bin\n", "")
            account = self.accounts.user(user_name)
            assert account is not None
            manager_unit = f"user@{prov.EXEC_UID if user_name == prov.EXEC_USER else prov.CONTROL_UID}.service"
            if manager_unit not in self.user_managers:
                return prov.Completed(1, "", "Failed to connect to bus")
            if action == "daemon-reload":
                self._materialize_daemon_unit()
                return prov.Completed(0, "", "")
            unit = argv[-1]
            if action == "is-active":
                if self.units.get(unit):
                    return prov.Completed(0, "active\n", "")
                return prov.Completed(3, "inactive\n", "")
            if action == "is-enabled":
                if unit == prov.DAEMON_UNIT and self.resolve(
                    f"/run/user/{self.accounts.uid}/systemd/generator/default.target.wants/{unit}"
                ).is_symlink():
                    return prov.Completed(0, "generated\n", "")
                if unit in self.enabled_units:
                    return prov.Completed(0, "enabled\n", "")
                return prov.Completed(1, "disabled\n", "")
            if action == "show":
                property_arg = next(item for item in argv if item.startswith("--property="))
                property_name = property_arg.split("=", 1)[1]
                if unit == prov.DAEMON_UNIT:
                    values = {
                        "FragmentPath": f"/run/user/{self.accounts.uid}/systemd/generator/{unit}",
                        "SourcePath": f"{prov.QUADLET_DIR}/stateport-execution-host.container",
                    }
                else:
                    values = {
                        "FragmentPath": "/usr/lib/systemd/user/podman.socket",
                        "SourcePath": "",
                    }
                return prov.Completed(0, values[property_name] + "\n", "")
            if action == "enable":
                self.units[unit] = True
                self.enabled_units.add(unit)
                account = self.accounts.user(user_name)
                assert account is not None
                target_name = (
                    "sockets.target" if unit == prov.ENGINE_SOCKET_UNIT else "default.target"
                )
                wants = self.resolve(
                    f"{account.home}/.config/systemd/user/{target_name}.wants"
                )
                wants.mkdir(parents=True, exist_ok=True)
                link = wants / unit
                if not link.exists() and not link.is_symlink():
                    link.symlink_to(
                        "/usr/lib/systemd/user/podman.socket"
                        if unit == prov.ENGINE_SOCKET_UNIT
                        else f"../{unit}"
                    )
                return prov.Completed(0, "", "")
            if action == "disable":
                self.units[unit] = False
                self.enabled_units.discard(unit)
                account = self.accounts.user(user_name)
                if account is not None:
                    target_name = (
                        "sockets.target" if unit == prov.ENGINE_SOCKET_UNIT else "default.target"
                    )
                    self.resolve(
                        f"{account.home}/.config/systemd/user/{target_name}.wants/{unit}"
                    ).unlink(missing_ok=True)
                return prov.Completed(0, "", "")
            if action == "start":
                self.units[unit] = True
                if user_name == prov.CONTROL_USER and unit.endswith("-network"):
                    network_path = self.resolve(
                        f"{prov.CONTROL_QUADLET_DIR}/{unit.removesuffix('-network')}.network"
                    )
                    if network_path.is_file():
                        network_name = ""
                        labels: dict[str, str] = {}
                        internal = False
                        for line in network_path.read_text(encoding="utf-8").splitlines():
                            if line.startswith("NetworkName="):
                                network_name = line.split("=", 1)[1].strip()
                            elif line.startswith("Label="):
                                key, value = line.split("=", 1)[1].split("=", 1)
                                labels[key] = value
                            elif line == "Internal=true":
                                internal = True
                        if network_name and network_name not in self.networks:
                            self.networks[network_name] = {
                                "name": network_name,
                                "internal": internal,
                                "labels": labels,
                            }
                return prov.Completed(0, "", "")
            if action == "restart":
                self.units[unit] = True
                return prov.Completed(0, "", "")
            if action == "stop":
                self.units[unit] = False
                return prov.Completed(0, "", "")
        if head == "journalctl":
            return prov.Completed(0, "", "")
        if head == "podman":
            if argv[1] == "info":
                account = self.accounts.user(prov.EXEC_USER)
                assert account is not None
                for storage_path in (self.storage_graph_root, self.storage_run_root):
                    resolved = self.resolve(storage_path)
                    resolved.mkdir(parents=True, exist_ok=True)
                    os.chmod(resolved, self.storage_mode)
                return prov.Completed(
                    0,
                    f"{self.storage_graph_root}|{self.storage_run_root}|{self.oci_runtime}\n",
                    "",
                )
            if argv[1] == "pull":
                reference = argv[-1]
                store = self.root_image_store if self.pull_into_wrong_store else self.image_store
                store[reference] = reference.split("@", 1)[1]
                return prov.Completed(0, "", "")
            if argv[1:3] == ["image", "inspect"]:
                reference = argv[-1]
                if self.inspect_digest_override is not None:
                    return prov.Completed(0, self.inspect_digest_override + "\n", "")
                if reference not in self.image_store:
                    return prov.Completed(1, "", "no such image")
                return prov.Completed(0, self.image_store[reference] + "\n", "")
            if argv[1:3] == ["network", "create"]:
                network_name = argv[-1]
                if network_name not in self.networks:
                    labels = {
                        item.removeprefix("--label=").split("=", 1)[0]:
                        item.removeprefix("--label=").split("=", 1)[1]
                        for item in argv
                        if item.startswith("--label=")
                    }
                    self.networks[network_name] = {
                        "name": network_name,
                        "internal": "--internal" in argv,
                        "labels": labels,
                    }
                return prov.Completed(0, network_name + "\n", "")
            if argv[1:3] == ["network", "rm"]:
                network_name = argv[-1]
                if network_name not in self.networks:
                    return prov.Completed(1, "", "network not found")
                self.networks.pop(network_name)
                return prov.Completed(0, network_name + "\n", "")
            if argv[1:3] == ["network", "exists"]:
                network_name = argv[-1]
                return prov.Completed(0 if network_name in self.networks else 1, "", "")
            if argv[1:3] == ["network", "inspect"]:
                network_name = argv[-1]
                if network_name not in self.networks:
                    return prov.Completed(1, "", "network not found")
                return prov.Completed(0, json.dumps([self.networks[network_name]]) + "\n", "")
        if "-m" in argv and "stateport_release.execution_host_provisioning" in argv:
            socket_path = argv[argv.index("--socket") + 1]
            result = prov.probe_protocol_health(self.resolve(socket_path))
            return prov.Completed(0 if result["healthy"] else 1, json.dumps(result) + "\n", "")
        raise AssertionError(f"unexpected exec-user command: {argv}")


class SimRunner:
    def __init__(self, host: SimHost) -> None:
        self.host = host
        self.calls: list[list[str]] = []
        self.fail_on = None
        self.on_call = None

    def run(self, argv: Sequence[str], *, timeout: int) -> prov.Completed:
        argv = [str(item) for item in argv]
        self.calls.append(argv)
        if self.on_call is not None:
            self.on_call(argv)
        if self.fail_on is not None:
            forced = self.fail_on(argv)
            if forced is not None:
                return forced
        return self.host.execute(argv)


class FakeDaemon:
    """In-process AF_UNIX peer speaking the exact daemon receipt contract."""

    def __init__(
        self,
        socket_path: Path,
        *,
        refuse_reason: str | None = None,
        garbage: bool = False,
        socket_mode: int = 0o660,
    ) -> None:
        self._path = socket_path
        self._refuse_reason = refuse_reason
        self._garbage = garbage
        self._socket_mode = socket_mode
        self._listener: socket.socket | None = None

    def start(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if self._path.exists() or self._path.is_symlink():
            self._path.unlink()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(self._path))
        os.chmod(self._path, self._socket_mode)
        listener.listen(4)
        self._listener = listener
        threading.Thread(target=self._serve, daemon=True).start()

    def close_leave_stale_inode(self) -> None:
        if self._listener is not None:
            # shutdown rejects new connects immediately; close alone leaves the
            # socket connectable while the accept thread holds the description.
            self._listener.shutdown(socket.SHUT_RDWR)
            self._listener.close()

    def _serve(self) -> None:
        listener = self._listener
        assert listener is not None
        while True:
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            try:
                buffer = b""
                while b"\n" not in buffer:
                    chunk = connection.recv(65536)
                    if not chunk:
                        break
                    buffer += chunk
                if self._garbage:
                    connection.sendall(b"this is not a receipt\n")
                    continue
                request = json.loads(buffer.split(b"\n", 1)[0])
                digest = daemon_contract.canonical_digest(request)
                now = "2026-08-09T00:00:00Z"
                peer = {
                    "uid": os.getuid(),
                    "gid": os.getgid(),
                    "pid": os.getpid(),
                    "grantId": request["requester"]["grantId"],
                }
                if self._refuse_reason is not None:
                    receipt: dict[str, Any] = {
                        "formatVersion": "stateport.execution-host-receipt/v1",
                        "operationId": request["operationId"],
                        "requestDigest": digest,
                        "accepted": False,
                        "refusal": {
                            "reason": self._refuse_reason,
                            "detail": "simulated daemon refusal",
                        },
                        "requester": peer,
                        "result": None,
                        "observed": {
                            "engine": None,
                            "engineVersion": None,
                            "imageDigest": None,
                            "exitStatus": None,
                            "startedAt": None,
                            "finishedAt": None,
                        },
                        "cleanup": {
                            "outcome": "not-required",
                            "detail": "request refused before execution",
                        },
                        "timestamps": {"receivedAt": now, "completedAt": now},
                    }
                else:
                    receipt = {
                        "formatVersion": "stateport.execution-host-receipt/v1",
                        "operationId": request["operationId"],
                        "requestDigest": digest,
                        "accepted": True,
                        "refusal": None,
                        "requester": peer,
                        "result": {
                            "formatVersion": "stateport.execution-host-contract/v1",
                            "contractVersion": 1,
                            "clientCompatibility": {"minimum": 1, "maximum": 2},
                            "transport": "confined-host-unix-socket",
                            "workloadKinds": ["workspace"],
                            "operations": ["describeCapabilities"],
                            "sealedWorkloadsOnly": True,
                            "limits": {
                                "maxTimeoutSeconds": 86400,
                                "maxOutputBytes": 4194304,
                                "maxWorkloads": 64,
                            },
                        },
                        "observed": {
                            "engine": "sim-podman",
                            "engineVersion": "4.9.3",
                            "imageDigest": None,
                            "exitStatus": None,
                            "startedAt": None,
                            "finishedAt": None,
                        },
                        "cleanup": {"outcome": "not-required", "detail": "read-only operation"},
                        "timestamps": {"receivedAt": now, "completedAt": now},
                    }
                connection.sendall((json.dumps(receipt) + "\n").encode("utf-8"))
            except (OSError, ValueError, KeyError):
                pass
            finally:
                try:
                    connection.close()
                except OSError:
                    pass


@pytest.fixture
def sim(tmp_path: Path):
    accounts = SimAccounts()
    # AF_UNIX sun_path is bounded (~108 bytes): the layout root must be short,
    # so it lives under a mkdtemp root rather than the deep pytest tmp_path.
    short_root = Path(tempfile.mkdtemp(prefix="spp-"))
    host = SimHost(short_root / "h", accounts)
    runner = SimRunner(host)
    socket_path = "/run/stateport/execution-control/control.sock"
    daemon = FakeDaemon(host.resolve(socket_path))
    try:
        yield accounts, host, runner, daemon
    finally:
        shutil.rmtree(short_root, ignore_errors=True)


def _apply(sim, *, revalidate=None, receipt_path=None, verified=None, **client):
    accounts, host, runner, _daemon = sim
    verified = verified or _verified()
    return prov.apply_verified_plan(
        verified,
        revalidate=revalidate or (lambda: verified),
        runner=runner,
        accounts=accounts,
        layout=prov.HostLayout(host.root),
        euid=0,
        receipt_path=receipt_path,
        rootless_group_probe=lambda plan: {
            "supported": True,
            "mechanism": "simulated-runc-keep-groups-and-host-gid-map",
            "detail": "simulated support seam",
        },
        **client,
    )


def _seed_existing_identity(sim) -> None:
    accounts, host, _runner, _daemon = sim
    accounts.add_group(prov.EXEC_GROUP)
    accounts.add_group(prov.EXEC_USER)
    private_group = accounts.group(prov.EXEC_USER)
    assert private_group is not None
    accounts.add_user(
        prov.EXEC_USER,
        gid=private_group.gid,
        home=prov.EXEC_HOME,
        shell=prov.DEFAULT_NOLOGIN_SHELL,
    )
    accounts.add_member(prov.EXEC_GROUP, prov.EXEC_USER)
    accounts.add_member(prov.EXEC_GROUP, "stateport-control")
    host.resolve(prov.EXEC_HOME).mkdir(parents=True, exist_ok=True)
    for name in ("subuid", "subgid"):
        (host.root / "etc" / name).write_text(
            f"{prov.EXEC_USER}:100000:{prov.SUBID_RANGE_SIZE}\n", encoding="utf-8"
        )


# ---------------------------------------------------------------------------
# Plan rendering (evidence: plan-rendered)
# ---------------------------------------------------------------------------


def test_plan_binds_identity_contract_subids_and_steps() -> None:
    plan = _plan()
    assert plan["schema"] == "stateport.execution-host-provisioning/v2"
    assert plan["evidenceClass"] == "plan-rendered"
    assert plan["executionUser"] == "stateport-exec"
    assert plan["executionControlGroup"] == "stateport-execution-control"
    assert plan["allowedClientUser"] == "stateport-control"
    assert plan["socketDirectory"] == "/run/stateport/execution-control"
    assert plan["socketDirectoryMode"] == "2750"
    assert plan["socketMode"] == "0660"
    assert plan["socketPath"] == "/run/stateport/execution-control/control.sock"
    assert plan["grantsDirectory"].endswith("/state/grants")
    assert plan["controlUid"] == plan["controlGid"] == 65531
    assert plan["executionUid"] == plan["executionGid"] == 65532
    assert plan["executionControlGroupGid"] == 65530
    assert plan["subordinateIds"] == {
        "user": "stateport-exec",
        "uid": 65532,
        "gid": 65532,
        "rangeSize": 65536,
        "files": ["/etc/subuid", "/etc/subgid"],
    }
    image = plan["image"]
    assert image["reference"].endswith("@" + image["digest"])

    directory_paths = [entry["path"] for entry in plan["directories"]]
    assert directory_paths == [
        "/var/lib/stateport-exec",
        "/var/lib/stateport-exec/.config",
        "/var/lib/stateport-exec/.config/containers",
        "/var/lib/stateport-exec/.config/containers/systemd",
        "/var/lib/stateport-exec/.config/systemd",
        "/var/lib/stateport-exec/.config/systemd/user",
        "/var/lib/stateport-exec/.config/systemd/user/sockets.target.wants",
        "/var/lib/stateport-exec/stateport-execution-host",
        "/var/lib/stateport-exec/stateport-execution-host/state",
        "/var/lib/stateport-exec/stateport-execution-host/state/grants",
        "/var/lib/stateport-control",
        "/var/lib/stateport-control/.config",
        "/var/lib/stateport-control/.config/containers",
        "/var/lib/stateport-control/.config/containers/systemd",
        "/var/lib/stateport-control/.config/systemd",
        "/var/lib/stateport-control/.config/systemd/user",
        "/var/lib/stateport-control/.config/systemd/user/sockets.target.wants",
    ]
    order = [step["step"] for step in plan["steps"]]
    assert order == [
        "verify-rootless-supplementary-group-contract",
        "ensure-execution-control-group",
        "ensure-stateport-control-user",
        "ensure-stateport-exec-user",
        "confine-execution-user-group",
        "confine-control-plane-client",
        "establish-subordinate-mappings",
        "create-host-directories",
        "write-confined-socket-tmpfiles",
        "enable-control-user-linger",
        "enable-exec-user-linger",
        "install-stable-host-quadlets",
        "provision-execution-host-grant",
        "install-control-plane-units",
        "pull-control-plane-images",
        "pull-execution-host-image",
        "start-exec-user-engine-socket",
        "start-execution-host-daemon",
        "verify-protocol-health",
        "start-control-plane-units",
        "record-provisioning-receipt",
    ]
    health = next(step["health"] for step in plan["steps"] if "health" in step)
    assert health == {
        "kind": "describeCapabilities",
        "socketPath": plan["socketPath"],
        "peerUsers": ["stateport-exec", "stateport-control"],
    }
    tmpfiles = next(write for write in plan["writes"] if write["path"].endswith(".conf"))
    assert "d /run/stateport/execution-control 2750 stateport-exec stateport-execution-control -\n" in tmpfiles["content"]
    quadlets = [write for write in plan["writes"] if write["path"].endswith(".container")]
    assert len(quadlets) == 1 and quadlets[0]["owner"] == "stateport-exec:stateport-exec"
    assert "PodmanArgs=--runtime=/usr/libexec/stateport/crun" in quadlets[0]["content"]
    assert "PodmanArgs=--group-add=keep-groups" in quadlets[0]["content"]
    assert "GroupAdd=" not in quadlets[0]["content"]
    assert "UserNS=keep-id:uid=65532,gid=65532" in quadlets[0]["content"]
    assert "Environment=STATEPORT_EXECUTION_HOST_USER_NAMESPACE=keep-id" in quadlets[0]["content"]
    assert "Environment=STATEPORT_EXECUTION_HOST_SOCKET_DIRECTORY_MODE=2750" in quadlets[0]["content"]
    assert "Environment=STATEPORT_EXECUTION_HOST_GRANTS_DIR=/var/lib/stateport/execution-host/grants" in quadlets[0]["content"]
    for name, value in {
        "STATEPORT_EXECUTION_HOST_REQUIRE_NUMERIC_HANDOFF": "1",
        "STATEPORT_EXECUTION_HOST_SOCKET_GROUP_GID": "65530",
        "STATEPORT_EXECUTION_HOST_ALLOWED_CLIENT_UID": "65531",
        "STATEPORT_EXECUTION_HOST_ALLOWED_CLIENT_GID": "65531",
        "STATEPORT_EXECUTION_HOST_RUNTIME_UID": "65532",
        "STATEPORT_EXECUTION_HOST_RUNTIME_GID": "65532",
    }.items():
        assert f"Environment={name}={value}" in quadlets[0]["content"]
    assert quadlets[0]["contentDigest"]
    rollback_actions = [entry["action"] for entry in plan["rollback"]]
    assert rollback_actions[:2] == ["disable-unit", "disable-unit"]
    assert "remove-subordinate-id-mappings" in rollback_actions
    assert "stop-user-manager" in rollback_actions
    assert rollback_actions == [
        "disable-unit",
        "disable-unit",
        "stop-user-manager",
        "stop-user-manager",
        "disable-linger",
        "disable-linger",
        "restore-user-manager",
        "restore-user-manager",
        "preserve",
        "remove-files",
        "restore-or-remove-directories",
        "remove-subordinate-id-mappings",
        "unconfine-client",
        "unconfine-client",
        "delete-user",
        "delete-group",
        "delete-user",
        "delete-group",
        "delete-group",
        "preserve",
    ]
    exec_linger = next(step for step in plan["steps"] if step["step"] == "enable-exec-user-linger")
    exec_probe = exec_linger["commands"][-1]
    assert "/usr/bin/env" in exec_probe and "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/65532/bus" in exec_probe
    # Deterministic for a fixed verified release.
    assert _plan()["planDigest"] == plan["planDigest"]


def test_plan_provisions_template_import_root_for_bound_installer_client() -> None:
    document = fixtures.release_index()
    target = deepcopy(document["signed"]["targets"][0])
    web = next(service for service in target["services"] if service["serviceId"] == "stateport-web")
    web["readOnlyHostMounts"] = [
        {
            "name": "template-sources",
            "hostPath": "/var/lib/stateport/imports",
            "mountPath": "/imports",
            "purpose": "template-sources",
            "sourceOwner": "installer-client",
            "sourceGroup": "stateport-execution-control",
            "mode": "ro",
            "environmentVariable": "STATEPORT_REPOSITORY_ROOTS",
        }
    ]
    plan = prov.render_provisioning_plan(
        target,
        document["signed"]["images"],
        verification_basis="signature-verified-test",
        client_user="operator",
        client_uid=1000,
        client_gid=1000,
    )
    assert plan["directories"][-2:] == [
        {"path": "/var/lib/stateport", "mode": "0755", "owner": "root:root"},
        {
            "path": "/var/lib/stateport/imports",
            "mode": "0750",
            "owner": "operator:stateport-execution-control",
        },
    ]
    assert "/var/lib/stateport/imports" in next(
        step["directories"]
        for step in plan["steps"]
        if step["step"] == "create-host-directories"
    )


def test_provider_home_plan_is_fixed_private_and_not_installer_owned() -> None:
    document = fixtures.release_index()
    target = deepcopy(document["signed"]["targets"][0])
    web = next(service for service in target["services"] if service["serviceId"] == "stateport-web")
    web["providerHome"] = dict(prov.PROVIDER_HOME_CONTRACT)
    plan = prov.render_provisioning_plan(target, document["signed"]["images"], verification_basis="test", client_user="operator", client_uid=1000, client_gid=1000)
    assert plan["directories"][-2:] == [
        {"path": "/var/lib/stateport-control/provider-auth", "mode": "0700", "owner": "stateport-control:stateport-control"},
        {"path": prov.PROVIDER_HOME_CONTRACT["hostPath"], "mode": "0700", "owner": "stateport-control:stateport-control"},
    ]
    web["providerHome"]["hostPath"] = "/home/operator/.codex"
    with pytest.raises(ReleaseContractError, match="provider home contract"):
        prov.render_provisioning_plan(target, document["signed"]["images"], verification_basis="test")


def test_provider_directory_reuses_exact_identity_without_reading_contents(tmp_path: Path) -> None:
    from types import SimpleNamespace

    context = SimpleNamespace(layout=prov.HostLayout(tmp_path), journal=[])
    path = "/var/lib/stateport-control/provider-auth/codex"
    args = {"mode": 0o700, "uid": os.getuid(), "gid": os.getgid(), "step": "create-host-directories", "refuse_existing_mismatch": True}
    assert prov._ensure_directory_converged(context, path, **args)
    leaf = tmp_path / path.lstrip("/")
    # An unreadable synthetic child proves reuse does not enumerate or copy
    # provider-owned content. This is not an authentication fixture.
    marker = leaf / "provider-owned-synthetic-state"
    marker.write_text("retained across restart")
    marker.chmod(0)
    identity = marker.stat().st_ino
    assert prov._ensure_directory_converged(context, path, **args) is False
    assert marker.stat().st_ino == identity
    assert stat.S_IMODE(marker.stat().st_mode) == 0
    with pytest.raises(prov.StepFailed, match="refusing to take it over"):
        prov._ensure_directory_converged(context, path, **(args | {"uid": os.getuid() + 1}))
    assert leaf.stat().st_uid == os.getuid()
    leaf.chmod(0o755)
    with pytest.raises(prov.StepFailed, match="refusing to take it over"):
        prov._ensure_directory_converged(context, path, **args)
    assert stat.S_IMODE(leaf.stat().st_mode) == 0o755


def test_provider_directory_refuses_symlink_without_touching_target(tmp_path: Path) -> None:
    from types import SimpleNamespace

    context = SimpleNamespace(layout=prov.HostLayout(tmp_path), journal=[])
    target = tmp_path / "foreign"
    target.mkdir()
    (tmp_path / "provider").symlink_to(target, target_is_directory=True)
    with pytest.raises(prov.StepFailed, match="not a real directory"):
        prov._ensure_directory_converged(context, "/provider", mode=0o700, uid=os.getuid(), gid=os.getgid(), step="create-host-directories", refuse_existing_mismatch=True)
    assert list(target.iterdir()) == []


def test_plan_refuses_a_target_without_stable_execution_host() -> None:
    value = fixtures.release_index()
    target = value["signed"]["targets"][0]
    target["executionHostMode"] = "none"
    target["executionContract"] = None
    target["hostServices"] = []
    with pytest.raises(ReleaseContractError, match="no stable execution host"):
        prov.render_provisioning_plan(
            target, value["signed"]["images"], verification_basis="test"
        )


def test_plan_binds_control_plane_materialization_under_control_user() -> None:
    """Fail-old/pass-new: the plan must carry the accepted control-plane units
    into the stateport-control user's Quadlet root and start them under that
    user's systemd manager.

    Fail-old: the plan only wrote the exec-host units and the control plane
    ran under the invoking user, so the daemon refused its peer identity and
    container execution was unreachable. Pass-new: the control units are
    written to /var/lib/stateport-control/.config/containers/systemd, the
    control images are pulled into that user's store, and the units start
    under the control user manager.
    """
    materialization = {
        "accepted/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/stateport-control/stateport-web.container": (
            "[Container]\nContainerName=stateport-web\nImage=ghcr.io/lennertvhoy/"
            "stateport-web@sha256:967657d89a53014a6cb708964d77d8b9ee4913f8414da63a3135696b8b7e05b7\n"
            "User=65532\nUserNS=keep-id:uid=65532,gid=65532\n"
            "PodmanArgs=--group-add=keep-groups\n"
            "Volume=/run/stateport/execution-control:/run/stateport-execution:ro\n"
            "Environment=STATEPORT_EXECUTION_SOCKET=/run/stateport-execution/control.sock\n"
            "Environment=STATEPORT_EXECUTION_PEER_POLICY=unix-peer-credentials-required\n"
        ).encode("utf-8"),
        "accepted/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/stateport-control/stateport-web.network": (
            "[Network]\nNetworkName=stateport-web-net\n"
        ).encode("utf-8"),
    }
    plan = prov.render_provisioning_plan(
        _verified().target,
        _verified().index.document["signed"]["images"],
        verification_basis="signature-verified-test",
        control_plane_materialization=materialization,
        control_grant_digest="sha256:" + "ab" * 32,
    )
    control_writes = [
        write for write in plan["writes"] if write["path"].startswith(prov.CONTROL_QUADLET_DIR + "/")
    ]
    assert len(control_writes) == 2
    assert all(write["owner"] == "stateport-control:stateport-control" for write in control_writes)
    assert all(write["mode"] == "0640" for write in control_writes)
    assert plan["controlPlaneMaterialization"] is not None
    assert plan["controlGrantDigest"] == "sha256:" + "ab" * 32
    step_names = [step["step"] for step in plan["steps"]]
    assert "install-control-plane-units" in step_names
    assert "pull-control-plane-images" in step_names
    assert "start-control-plane-units" in step_names
    install_step = next(step for step in plan["steps"] if step["step"] == "install-control-plane-units")
    assert all(
        path.startswith(prov.CONTROL_QUADLET_DIR + "/")
        for path in install_step["writes"]
    )
    start_step = next(step for step in plan["steps"] if step["step"] == "start-control-plane-units")
    assert start_step["units"] == ["stateport-web.container", "stateport-web.network"]
    images_step = next(step for step in plan["steps"] if step["step"] == "pull-control-plane-images")
    assert any(image["imageId"] == "stateport-web" for image in images_step["images"])


def test_control_network_start_targets_the_generated_network_service(
    sim, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fail-old/pass-new regression for the Quadlet network unit start name.

    A Quadlet ``foo.network`` source file generates the systemd unit
    ``foo-network.service`` (the ``.network`` suffix maps to ``-network``).
    Fail-old (587b05b6): ``_step_control_start`` stripped ``.network`` and ran
    ``systemctl --user start foo``, which resolves to the nonexistent
    ``foo.service`` and fails with "Failed to start ... Unit not found".
    Pass-new: the start command targets ``foo-network`` so the generated
    network unit actually starts before the container units.
    """
    _accounts, host, runner, daemon = sim
    verified = _verified("wsl2-ubuntu2404-linux-amd64-rootless-podman-quadlet")
    monkeypatch.setattr(
        prov,
        "observe_linux_substrate",
        lambda: type("Substrate", (), {"substrate": "wsl2"})(),
    )
    daemon.start()
    materialization = {
        "accepted/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/stateport-control/stateport-web.container": (
            "[Container]\nContainerName=stateport-web\nImage=ghcr.io/lennertvhoy/"
            "stateport-web@sha256:967657d89a53014a6cb708964d77d8b9ee4913f8414da63a3135696b8b7e05b7\n"
            "User=65532\nUserNS=keep-id:uid=65532,gid=65532\n"
            "PodmanArgs=--group-add=keep-groups\n"
            "Volume=/run/stateport/execution-control:/run/stateport-execution:ro\n"
            "Environment=STATEPORT_EXECUTION_SOCKET=/run/stateport-execution/control.sock\n"
            "Environment=STATEPORT_EXECUTION_PEER_POLICY=unix-peer-credentials-required\n"
        ).encode("utf-8"),
        "accepted/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/stateport-control/stateport-web.network": (
            "[Network]\nNetworkName=stateport-web-net\n"
            "Label=io.stateport.managed=true\nInternal=true\n"
        ).encode("utf-8"),
    }
    receipt = _apply(
        sim,
        verified=verified,
        revalidate=lambda: verified,
        control_plane_materialization=materialization,
    )
    assert receipt["result"] == "succeeded"
    network_starts = [
        call
        for call in runner.calls
        if "stateport-control" in call
        and any("systemctl" in str(item) for item in call)
        and "--user" in call
        and "start" in call
        and call[-3:-1] == ["--user", "start"]
        and call[-1] != f"user@{prov.CONTROL_UID}.service"
    ]
    assert network_starts, "apply must start units under the stateport-control user manager"
    network_unit_starts = [
        call for call in network_starts if call[-1].endswith("-network")
    ]
    assert network_unit_starts, (
        "apply must start the generated Quadlet network unit (foo-network); "
        "starting the bare foo would resolve to the missing foo.service"
    )
    for call in network_unit_starts:
        assert "stateport-web-network" in call
    # Quadlet owns normal network creation. A second direct
    # `podman network create --ignore` can split netavark state from the
    # generated network unit during container init.
    network_ensures = [
        call
        for call in runner.calls
        if "stateport-control" in call
        and any("podman" in str(item) for item in call)
        and "network" in call
        and "create" in call
        and "--ignore" in call
    ]
    assert not network_ensures, "normal startup must not directly create the Quadlet-owned network"
    network_inspects = [
        call
        for call in runner.calls
        if "stateport-control" in call
        and any("podman" in str(item) for item in call)
        and call[-3:-1] == ["network", "inspect"]
    ]
    assert network_inspects, "apply must inspect the ensured network before container start"
    # Fail-old/pass-new: the control container start mounts the confined
    # execution socket directory read-only; a missing directory fails the
    # rootless start with "statfs .../execution-control: no such file or
    # directory".  The apply must ensure the socket directory exists (with
    # its 0755 parent) immediately before the container unit start.
    socket_dir = host.resolve("/run/stateport/execution-control")
    assert socket_dir.is_dir(), (
        "apply must ensure the control socket directory exists before "
        "starting the container units"
    )
    assert stat.S_IMODE(socket_dir.stat().st_mode) == 0o2750
    activation = host.resolve(
        "/var/lib/stateport-control/.config/systemd/user/stateport-accepted.target"
    )
    activation_text = activation.read_text(encoding="utf-8")
    assert f"X-StatePort-Signed-Payload={verified.index.signed_digest}" in activation_text
    assert "stateport-web-network.service" in activation_text
    assert "stateport-web.service" in activation_text
    assert ".container" not in activation_text and ".network" not in activation_text
    assert "stateport-accepted.target" in host.enabled_units
    target_link = host.resolve(
        "/var/lib/stateport-control/.config/systemd/user/"
        "default.target.wants/stateport-accepted.target"
    )
    assert target_link.is_symlink()
    assert os.readlink(target_link) == "../stateport-accepted.target"


def test_later_failure_rolls_back_control_activation(sim, monkeypatch: pytest.MonkeyPatch) -> None:
    _accounts, host, runner, daemon = sim
    verified = _verified("wsl2-ubuntu2404-linux-amd64-rootless-podman-quadlet")
    monkeypatch.setattr(
        prov,
        "observe_linux_substrate",
        lambda: type("Substrate", (), {"substrate": "wsl2"})(),
    )
    daemon.start()
    materialization = {
        "accepted/revision/stateport-control/stateport-web.container": (
            "[Container]\nContainerName=stateport-web\nImage=example.invalid/web@sha256:"
            + "a" * 64
            + "\n"
        ).encode(),
    }
    runner.fail_on = lambda argv: (
        prov.Completed(1, "", "simulated control image pull failure")
        if "stateport-control" in argv and "podman" in " ".join(argv) and "pull" in argv
        else None
    )
    receipt = _apply(
        sim,
        verified=verified,
        revalidate=lambda: verified,
        control_plane_materialization=materialization,
    )
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "pull-control-plane-images"
    assert "stateport-accepted.target" not in host.enabled_units
    target_link = host.resolve(
        "/var/lib/stateport-control/.config/systemd/user/"
        "default.target.wants/stateport-accepted.target"
    )
    assert not target_link.exists() and not target_link.is_symlink()
    assert any(
        action["action"] == "restore-control-unit-state"
        and action["target"] == "stateport-accepted.target"
        and action["result"] == "done"
        for action in receipt["rollback"]["actions"]
    )


def test_control_start_refuses_a_foreign_same_name_network(
    sim, monkeypatch: pytest.MonkeyPatch
) -> None:
    _accounts, host, _runner, daemon = sim
    verified = _verified("wsl2-ubuntu2404-linux-amd64-rootless-podman-quadlet")
    monkeypatch.setattr(
        prov,
        "observe_linux_substrate",
        lambda: type("Substrate", (), {"substrate": "wsl2"})(),
    )
    daemon.start()
    materialization = {
        "accepted/revision/stateport-control/stateport-web.container": (
            "[Container]\nContainerName=stateport-web\nImage=example.invalid/web@sha256:"
            + "a" * 64
            + "\n"
        ).encode(),
        "accepted/revision/stateport-control/stateport-web.network": (
            "[Network]\nNetworkName=stateport-web-net\n"
            "Label=io.stateport.managed=true\n"
            "Label=io.stateport.release.id=release-fixture\n"
            "Internal=true\n"
        ).encode(),
    }
    host.networks["stateport-web-net"] = {
        "name": "stateport-web-net",
        "internal": False,
        "labels": {"io.stateport.managed": "true"},
    }
    receipt = _apply(
        sim,
        verified=verified,
        revalidate=lambda: verified,
        control_plane_materialization=materialization,
    )
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "start-control-plane-units"
    assert "does not match the signed internal labels" in receipt["failure"]["detail"]


def test_control_start_recovers_exact_ipam_network_not_found_once(
    sim, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The retained J1 Podman split gets one narrow, signed-network recovery."""
    _accounts, host, runner, daemon = sim
    verified = _verified("wsl2-ubuntu2404-linux-amd64-rootless-podman-quadlet")
    monkeypatch.setattr(
        prov,
        "observe_linux_substrate",
        lambda: type("Substrate", (), {"substrate": "wsl2"})(),
    )
    initial_start_failed = False
    network_removed = False

    def observe_call(argv: list[str]) -> None:
        nonlocal network_removed
        if "network" in argv and "rm" in argv and argv[-1] == "stateport-web-net":
            network_removed = True
        if (
            network_removed
            and any(Path(item).name == "systemctl" for item in argv)
            and "start" in argv
            and argv[-1] == "stateport-web-network"
        ):
            host.networks["stateport-web-net"] = {
                "name": "stateport-web-net",
                "internal": True,
                "labels": {"io.stateport.managed": "true"},
            }

    def ipam_split(argv: list[str]) -> prov.Completed | None:
        nonlocal initial_start_failed
        if (
            Path(argv[-1]).name == "stateport-web"
            and "start" in argv
            and not network_removed
        ):
            initial_start_failed = True
            return prov.Completed(1, "", "control process exited with status 127")
        if (
            initial_start_failed
            and not network_removed
            and argv[-1] == "stateport-web"
            and "is-active" in argv
        ):
            return prov.Completed(3, "failed\n", "")
        if any(Path(item).name == "journalctl" for item in argv):
            return prov.Completed(
                0,
                'Error: netavark: IPAM error: could not find network "stateport-web-net"\n',
                "",
            )
        return None

    runner.on_call = observe_call
    runner.fail_on = ipam_split
    daemon.start()
    materialization = {
        "accepted/revision/stateport-control/stateport-web.container": (
            "[Container]\nContainerName=stateport-web\nImage=example.invalid/web@sha256:"
            + "a" * 64
            + "\nNetwork=stateport-web.network\n"
        ).encode(),
        "accepted/revision/stateport-control/stateport-web.network": (
            "[Network]\nNetworkName=stateport-web-net\n"
            "Label=io.stateport.managed=true\nInternal=true\n"
        ).encode(),
    }

    receipt = _apply(
        sim,
        verified=verified,
        revalidate=lambda: verified,
        control_plane_materialization=materialization,
    )

    assert receipt["result"] == "succeeded"
    assert sum(
        any(Path(item).name == "journalctl" for item in call)
        for call in runner.calls
    ) == 1
    assert sum(
        "network" in call and "create" in call and "stateport-web-net" in call
        for call in runner.calls
    ) == 0
    container_stops = [
        index
        for index, call in enumerate(runner.calls)
        if "stop" in call and call[-1] == "stateport-web"
    ]
    network_stop = next(
        index
        for index, call in enumerate(runner.calls)
        if "stop" in call and call[-1] == "stateport-web-network"
    )
    network_remove = next(
        index
        for index, call in enumerate(runner.calls)
        if "network" in call and "rm" in call and call[-1] == "stateport-web-net"
    )
    network_start = max(
        index
        for index, call in enumerate(runner.calls)
        if "start" in call and call[-1] == "stateport-web-network"
    )
    recovery_start = max(
        index
        for index, call in enumerate(runner.calls)
        if "start" in call and call[-1] == "stateport-web"
    )
    assert len(container_stops) == 1
    assert (
        container_stops[0]
        < network_stop
        < network_remove
        < network_start
        < recovery_start
    )
    assert not any(
        "network" in call
        and "create" in call
        and call[-1] == "stateport-web-net"
        and "--ignore" not in call
        for call in runner.calls
    )
    assert not any(
        "restart" in call and call[-1] == "stateport-web" for call in runner.calls
    )
    validate_contract_document(receipt, expected_schema=prov.RECEIPT_SCHEMA)


def test_control_start_does_not_recover_an_unrelated_failure(
    sim, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed container without the exact signed-network error stays failed closed."""
    _accounts, _host, runner, daemon = sim
    verified = _verified("wsl2-ubuntu2404-linux-amd64-rootless-podman-quadlet")
    monkeypatch.setattr(
        prov,
        "observe_linux_substrate",
        lambda: type("Substrate", (), {"substrate": "wsl2"})(),
    )
    start_failed = False

    def unrelated_failure(argv: list[str]) -> prov.Completed | None:
        nonlocal start_failed
        if Path(argv[-1]).name == "stateport-web" and "start" in argv:
            start_failed = True
            return prov.Completed(1, "", "unrelated failure")
        if start_failed and argv[-1] == "stateport-web" and "is-active" in argv:
            return prov.Completed(3, "failed\n", "")
        if any(Path(item).name == "journalctl" for item in argv):
            return prov.Completed(0, "application configuration is invalid\n", "")
        return None

    runner.fail_on = unrelated_failure
    daemon.start()
    materialization = {
        "accepted/revision/stateport-control/stateport-web.container": (
            "[Container]\nContainerName=stateport-web\nImage=example.invalid/web@sha256:"
            + "a" * 64
            + "\nNetwork=stateport-web.network\n"
        ).encode(),
        "accepted/revision/stateport-control/stateport-web.network": (
            "[Network]\nNetworkName=stateport-web-net\n"
            "Label=io.stateport.managed=true\nInternal=true\n"
        ).encode(),
    }

    receipt = _apply(
        sim,
        verified=verified,
        revalidate=lambda: verified,
        control_plane_materialization=materialization,
    )

    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "start-control-plane-units"
    assert not any(
        "restart" in call and call[-1] == "stateport-web-network"
        for call in runner.calls
    )


def test_control_start_fails_closed_when_socket_metadata_cannot_converge(
    sim, monkeypatch: pytest.MonkeyPatch
) -> None:
    _accounts, _host, _runner, daemon = sim
    verified = _verified("wsl2-ubuntu2404-linux-amd64-rootless-podman-quadlet")
    monkeypatch.setattr(
        prov,
        "observe_linux_substrate",
        lambda: type("Substrate", (), {"substrate": "wsl2"})(),
    )
    original = prov._ensure_directory_converged

    def refuse_socket_metadata(ctx, path, *, mode, uid, gid, step):
        if step == "start-control-plane-units" and path.endswith("/execution-control"):
            raise prov.StepFailed(step, "simulated socket metadata refusal")
        return original(ctx, path, mode=mode, uid=uid, gid=gid, step=step)

    monkeypatch.setattr(prov, "_ensure_directory_converged", refuse_socket_metadata)
    daemon.start()
    materialization = {
        "accepted/revision/stateport-control/stateport-web.container": (
            "[Container]\nContainerName=stateport-web\nImage=example.invalid/web@sha256:"
            + "a" * 64
            + "\n"
        ).encode(),
    }
    receipt = _apply(
        sim,
        verified=verified,
        revalidate=lambda: verified,
        control_plane_materialization=materialization,
    )
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "start-control-plane-units"
    assert "simulated socket metadata refusal" in receipt["failure"]["detail"]


def test_control_start_accepts_bounded_auto_restart_convergence(
    sim, monkeypatch: pytest.MonkeyPatch
) -> None:
    _accounts, _host, runner, daemon = sim
    verified = _verified("wsl2-ubuntu2404-linux-amd64-rootless-podman-quadlet")
    monkeypatch.setattr(
        prov,
        "observe_linux_substrate",
        lambda: type("Substrate", (), {"substrate": "wsl2"})(),
    )
    monkeypatch.setattr(prov.time, "sleep", lambda _seconds: None)
    started = False
    observations = 0

    def transient_start(argv: list[str]) -> prov.Completed | None:
        nonlocal started, observations
        if argv[-1] != "stateport-web":
            return None
        if "start" in argv:
            started = True
            return prov.Completed(1, "", "control process exited with status 127")
        if started and "is-active" in argv:
            observations += 1
            if observations <= 40:
                return prov.Completed(3, "activating\n", "")
            return prov.Completed(0, "active\n", "")
        return None

    runner.fail_on = transient_start
    daemon.start()
    materialization = {
        "accepted/revision/stateport-control/stateport-web.container": (
            "[Container]\nContainerName=stateport-web\nImage=example.invalid/web@sha256:"
            + "a" * 64
            + "\n"
        ).encode(),
    }
    receipt = _apply(
        sim,
        verified=verified,
        revalidate=lambda: verified,
        control_plane_materialization=materialization,
    )

    assert receipt["result"] == "succeeded"
    assert observations == 41
    start_step = next(
        entry for entry in receipt["steps"] if entry["step"] == "start-control-plane-units"
    )
    assert len(start_step["commands"]) <= 32
    validate_contract_document(receipt, expected_schema=prov.RECEIPT_SCHEMA)


def test_apply_installs_control_plane_under_control_user(
    sim, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pass-new: the root transaction installs the control-plane units into
    the stateport-control user's Quadlet root and starts them under that
    user's systemd manager.

    Fail-old: control units went to the invoking user's root, the container
    peer identity was not the daemon's allowed client, and execution was
    unreachable. Pass-new: units land under /var/lib/stateport-control, the
    grant is written to the daemon store, and the control units start.
    """
    _accounts, host, runner, daemon = sim
    verified = _verified("wsl2-ubuntu2404-linux-amd64-rootless-podman-quadlet")
    monkeypatch.setattr(
        prov,
        "observe_linux_substrate",
        lambda: type("Substrate", (), {"substrate": "wsl2"})(),
    )
    daemon.start()
    materialization = {
        "accepted/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/stateport-control/stateport-web.container": (
            "[Container]\nContainerName=stateport-web\nImage=ghcr.io/lennertvhoy/"
            "stateport-web@sha256:967657d89a53014a6cb708964d77d8b9ee4913f8414da63a3135696b8b7e05b7\n"
            "User=65532\nUserNS=keep-id:uid=65532,gid=65532\n"
            "PodmanArgs=--group-add=keep-groups\n"
            "Volume=/run/stateport/execution-control:/run/stateport-execution:ro\n"
            "Environment=STATEPORT_EXECUTION_SOCKET=/run/stateport-execution/control.sock\n"
            "Environment=STATEPORT_EXECUTION_PEER_POLICY=unix-peer-credentials-required\n"
        ).encode("utf-8")
    }
    receipt = _apply(
        sim,
        verified=verified,
        revalidate=lambda: verified,
        control_plane_materialization=materialization,
    )
    assert receipt["result"] == "succeeded"
    control_unit = host.root / "var/lib/stateport-control/.config/containers/systemd/stateport-web.container"
    assert control_unit.is_file()
    unit_text = control_unit.read_text(encoding="utf-8")
    assert "STATEPORT_EXECUTION_SOCKET=" in unit_text
    assert (
        f"STATEPORT_EXECUTION_GRANT_DIGEST={receipt['controlGrant']['grantDigest']}"
        in unit_text
    )
    grant_file = host.root / "var/lib/stateport-exec/stateport-execution-host/state/grants/control-plane-default.json"
    assert grant_file.is_file()
    assert receipt.get("controlGrant", {}).get("grantId") == "control-plane-default"
    assert receipt["controlGrant"]["workloadId"] == "default-dev"


def test_control_plane_environment_injects_into_hashed_api_unit(
    sim, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pass-new: per-service control-plane environment is injected into the
    control unit matched by its Label=io.stateport.service.id line, not by
    the unit filename (which is a content-addressed hash on the installed
    guest).  Fail-old: the path-based service detection never matched the
    hashed api filename, so the installed api ran with no identities and
    every governed mutation refused identity_required.
    """
    _accounts, host, runner, daemon = sim
    verified = _verified("wsl2-ubuntu2404-linux-amd64-rootless-podman-quadlet")
    monkeypatch.setattr(
        prov,
        "observe_linux_substrate",
        lambda: type("Substrate", (), {"substrate": "wsl2"})(),
    )
    daemon.start()
    hashed_name = "stateport-f544857680bc-accepted-32cc11ab6f2acccef16111f977795a4eb9070e34d4037d5e506f782f235cb795.container"
    materialization = {
        f"accepted/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/stateport-control/{hashed_name}": (
            "[Container]\n"
            "ContainerName=stateport-f544857680bc\n"
            "Image=ghcr.io/lennertvhoy/stateport-api@sha256:ab72d37baf9e90922057269b9d6ebb519f3f5f557923f94352fc22976f63d6d7\n"
            "User=65532\nUserNS=keep-id:uid=65532,gid=65532\n"
            "PodmanArgs=--group-add=keep-groups\n"
            "Label=io.stateport.service.id=stateport-api\n"
            "HealthCmd=[\"/usr/local/bin/stateport-healthcheck\", \"--kind\", \"http\", \"--host\", \"127.0.0.1\", \"--port\", \"8790\", \"--path\", \"/readyz\"]\n"
        ).encode("utf-8")
    }
    environment = {
        "stateport-api.STATEPORT_IDENTITIES_JSON": '{"local-operator": {"roles": ["operator", "approver"], "instances": ["*"]}}',
        "stateport-api.STATEPORT_AUTH_TOKENS_JSON": '{"local-operator": "test-token"}',
        "stateport-api.STATEPORT_OPERATOR_CAPABILITIES": "execute_container,approve,write_state",
    }
    receipt = _apply(
        sim,
        verified=verified,
        revalidate=lambda: verified,
        control_plane_materialization=materialization,
        control_plane_environment=environment,
    )
    assert receipt["result"] == "succeeded"
    control_unit = host.root / f"var/lib/stateport-control/.config/containers/systemd/{hashed_name}"
    assert control_unit.is_file()
    unit_text = control_unit.read_text(encoding="utf-8")
    # The JSON env values must be emitted as quoted, escaped systemd
    # Environment= lines (the api identity/auth JSON would otherwise break
    # the Quadlet line and the container fails with status=2/INVALIDARGUMENT).
    assert 'Environment="STATEPORT_IDENTITIES_JSON={\\"local-operator\\": ' in unit_text
    assert (
        'Environment="STATEPORT_AUTH_TOKENS_JSON={\\"local-operator\\": \\"test-token\\"}"'
        in unit_text
    )
    assert "Environment=\"STATEPORT_OPERATOR_CAPABILITIES=execute_container,approve,write_state\"" in unit_text


def test_plan_refuses_a_non_digest_pinned_image_reference() -> None:
    value = fixtures.release_index()
    images = value["signed"]["images"]
    for image in images:
        if image["imageId"] == "stateport-execution-host":
            image["reference"] = image["reference"].split("@", 1)[0] + ":latest"
    with pytest.raises(ReleaseContractError, match="imageReference|digest-pinned"):
        prov.render_provisioning_plan(
            value["signed"]["targets"][0], images, verification_basis="test"
        )


def test_plan_binds_the_real_client_and_keeps_the_control_account() -> None:
    decorative = _plan()
    bound = prov.render_provisioning_plan(
        _verified().target,
        _verified().index.document["signed"]["images"],
        verification_basis="signature-verified-test",
        client_user="operator",
        client_uid=1000,
        client_gid=1000,
    )
    # The signed contract's decorative account is ALWAYS provisioned: it is
    # the peer identity the control-plane containers run as. The bound real
    # client is additionally confined and identity-filed for operator CLI use.
    assert bound["allowedClientUser"] == "operator"
    assert bound["controlClient"] == {"user": "operator", "uid": 1000, "gid": 1000}
    step_names = [step["step"] for step in bound["steps"]]
    assert "ensure-stateport-control-user" in step_names
    assert "enable-control-user-linger" in step_names
    assert "confine-control-plane-client" in step_names
    confine = next(
        step for step in bound["steps"] if step["step"] == "confine-control-plane-client"
    )
    assert confine["commands"][0][-1] == "operator"
    assert confine["commands"][0][-2:] == ["stateport-execution-control", "operator"]
    health = next(step for step in bound["steps"] if "health" in step)
    assert health["health"]["peerUsers"] == ["stateport-exec", "operator"]
    # The confined client identity travels to the confined daemon.
    identity_write = next(
        write
        for write in bound["writes"]
        if write["path"].endswith("/" + prov.CLIENT_IDENTITY_FILE)
    )
    assert identity_write["content"] == "1000:1000\n"
    assert identity_write["mode"] == "0640"
    assert identity_write["owner"] == "root:stateport-execution-control"
    # Rollback unconfines the real client and still removes the created
    # decorative control account (it is always provisioned).
    rollback_users = {entry.get("user") for entry in bound["rollback"]}
    assert "operator" in rollback_users
    assert "stateport-control" in rollback_users
    # A bound plan is a materially different transaction than the decorative one.
    assert bound["planDigest"] != decorative["planDigest"]


def test_plan_refuses_unsafe_client_identities() -> None:
    verified = _verified()
    target = verified.target
    images = verified.index.document["signed"]["images"]
    for bad in ("root", prov.EXEC_USER, prov.CONTROL_USER, "UPPER", "-lead", "a" * 40):
        with pytest.raises(ReleaseContractError, match="control-plane client user"):
            prov.render_provisioning_plan(
                target,
                images,
                verification_basis="test",
                client_user=bad,
                client_uid=1000,
                client_gid=1000,
            )
    for uid, gid in ((0, 1000), (1000, 0), (1000, None), (None, 1000)):
        with pytest.raises(ReleaseContractError, match="numeric identity"):
            prov.render_provisioning_plan(
                target,
                images,
                verification_basis="test",
                client_user="operator",
                client_uid=uid,
                client_gid=gid,
            )


def test_resolve_client_identity_binds_the_invoking_user(monkeypatch) -> None:
    record = pwd.getpwuid(os.getuid())
    monkeypatch.delenv("SUDO_USER", raising=False)
    monkeypatch.delenv("STATEPORT_CONTROL_CLIENT_USER", raising=False)
    monkeypatch.setattr(prov.os, "getuid", lambda: record.pw_uid)
    assert prov.resolve_client_identity() == (record.pw_name, record.pw_uid, record.pw_gid)

    monkeypatch.setattr(prov.os, "getuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", record.pw_name)
    assert prov.resolve_client_identity() == (record.pw_name, record.pw_uid, record.pw_gid)

    monkeypatch.delenv("SUDO_USER", raising=False)
    assert prov.resolve_client_identity() is None

    monkeypatch.setenv("STATEPORT_CONTROL_CLIENT_USER", record.pw_name)
    assert prov.resolve_client_identity() == (record.pw_name, record.pw_uid, record.pw_gid)


# ---------------------------------------------------------------------------
# Pre-transaction gates
# ---------------------------------------------------------------------------


def test_apply_requires_root(sim) -> None:
    accounts, host, runner, _daemon = sim
    with pytest.raises(prov.ProvisioningRefusal, match="as root"):
        prov.apply_verified_plan(
            _verified(),
            revalidate=lambda: _verified(),
            runner=runner,
            accounts=accounts,
            layout=prov.HostLayout(host.root),
            euid=1000,
        )


def test_apply_requires_a_verified_release(sim) -> None:
    accounts, host, runner, _daemon = sim
    with pytest.raises(prov.ProvisioningRefusal, match="verified release"):
        prov.apply_verified_plan(
            object(),
            revalidate=lambda: _verified(),
            runner=runner,
            accounts=accounts,
            layout=prov.HostLayout(host.root),
            euid=0,
        )


def test_revalidation_runs_exactly_once_before_any_privileged_write(sim) -> None:
    accounts, host, runner, _daemon = sim
    calls: list[bool] = []

    def revalidate():
        # No privileged write may have happened yet.
        calls.append(True)
        assert not (host.root / "etc" / "subuid").exists()
        assert not (host.root / "etc" / "tmpfiles.d" / "stateport-execution-control.conf").exists()
        assert not host.units, "no unit may be started before revalidation"
        return _verified()

    _daemon.start()
    receipt = _apply(sim, revalidate=revalidate)
    assert receipt["result"] == "succeeded"
    assert calls == [True]
    assert receipt["revalidatedImmediatelyBeforeWrites"] is True


def test_revalidation_divergence_refuses_without_writes(sim) -> None:
    _accounts, host, _runner, _daemon = sim
    with pytest.raises(prov.ProvisioningRefusal, match="revalidation"):
        _apply(sim, revalidate=lambda: object())
    assert not (host.root / "etc" / "subuid").exists()
    assert list((host.root / "etc" / "tmpfiles.d").iterdir()) == []


def test_apply_refuses_wsl_before_revalidation_or_writes(
    sim, monkeypatch: pytest.MonkeyPatch
) -> None:
    _accounts, host, _runner, _daemon = sim
    revalidated = False

    def revalidate():
        nonlocal revalidated
        revalidated = True
        return _verified()

    monkeypatch.setattr(
        prov,
        "observe_linux_substrate",
        lambda: type("Substrate", (), {"substrate": "wsl2"})(),
    )
    with pytest.raises(prov.ProvisioningRefusal, match="wsl_substrate_unqualified"):
        _apply(sim, revalidate=revalidate)
    assert revalidated is False
    assert not (host.root / "etc/subuid").exists()
    assert not host.units


def test_apply_refuses_wsl1_before_revalidation_or_writes(
    sim, monkeypatch: pytest.MonkeyPatch
) -> None:
    _accounts, host, _runner, _daemon = sim
    monkeypatch.setattr(
        prov,
        "observe_linux_substrate",
        lambda: type("Substrate", (), {"substrate": "wsl1"})(),
    )
    with pytest.raises(prov.ProvisioningRefusal, match="wsl1_substrate_unsupported"):
        _apply(sim)
    assert not (host.root / "etc/subuid").exists()
    assert not host.units


def test_apply_accepts_the_exact_wsl2_target(
    sim, monkeypatch: pytest.MonkeyPatch
) -> None:
    _accounts, _host, _runner, daemon = sim
    verified = _verified("wsl2-ubuntu2404-linux-amd64-rootless-podman-quadlet")
    monkeypatch.setattr(
        prov,
        "observe_linux_substrate",
        lambda: type("Substrate", (), {"substrate": "wsl2"})(),
    )
    daemon.start()
    receipt = _apply(sim, verified=verified, revalidate=lambda: verified)
    assert receipt["result"] == "succeeded"
    assert receipt["targetId"] == verified.target["targetId"]


def test_real_apply_contract_uses_host_numeric_group_mapping(
    sim, tmp_path: Path
) -> None:
    accounts, host, runner, daemon = sim
    daemon.start()
    verified = _verified()
    receipt = prov.apply_verified_plan(
        verified,
        revalidate=lambda: verified,
        runner=runner,
        accounts=accounts,
        layout=prov.HostLayout(host.root),
        euid=0,
        receipt_path=tmp_path / "supported-receipt.json",
    )
    assert receipt["result"] == "succeeded"
    assert receipt["steps"][0]["result"] == "already-present"
    assert receipt["image"]["status"] == "verified"


@pytest.mark.parametrize(
    "defect",
    ["missing-private-group", "login-shell", "foreign-member", "foreign-primary-user"],
)
def test_existing_exec_identity_requires_private_group_and_nologin(sim, defect: str) -> None:
    accounts, host, _runner, daemon = sim
    daemon.start()
    accounts.add_group(prov.EXEC_GROUP)
    if defect != "missing-private-group":
        accounts.add_group(prov.EXEC_USER)
    private = accounts.group(prov.EXEC_USER)
    accounts.add_user(
        prov.EXEC_USER,
        gid=accounts.gid if private is None else private.gid,
        home=prov.EXEC_HOME,
        shell="/bin/bash" if defect == "login-shell" else prov.DEFAULT_NOLOGIN_SHELL,
    )
    if defect == "foreign-member":
        accounts.add_member(prov.EXEC_USER, "foreign-user")
    if defect == "foreign-primary-user":
        assert private is not None
        accounts.add_user(
            "foreign-user",
            gid=private.gid,
            home="/var/lib/foreign-user",
            shell=prov.DEFAULT_NOLOGIN_SHELL,
            primary_group=prov.EXEC_USER,
        )
    host.resolve(prov.EXEC_HOME).mkdir(parents=True, exist_ok=True)
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "ensure-stateport-exec-user"
    assert "required private-group/nologin system identity" in receipt["failure"]["detail"]
    assert not (host.root / "etc/subuid").exists()


def test_preexisting_control_group_with_foreign_member_is_refused_before_identity_changes(
    sim,
) -> None:
    accounts, host, _runner, daemon = sim
    daemon.start()
    accounts.add_group(prov.EXEC_GROUP)
    accounts.add_member(prov.EXEC_GROUP, "foreign-user")
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "ensure-execution-control-group"
    assert "foreign members ['foreign-user']" in receipt["failure"]["detail"]
    assert accounts.user(prov.EXEC_USER) is None
    assert not (host.root / "etc/subuid").exists()


def test_preexisting_control_group_with_foreign_primary_user_is_refused(sim) -> None:
    accounts, host, _runner, daemon = sim
    daemon.start()
    accounts.add_group(prov.EXEC_GROUP)
    group = accounts.group(prov.EXEC_GROUP)
    assert group is not None
    accounts.add_user(
        "foreign-user",
        gid=group.gid,
        home="/var/lib/foreign-user",
        shell=prov.DEFAULT_NOLOGIN_SHELL,
        primary_group=prov.EXEC_GROUP,
    )
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "ensure-execution-control-group"
    assert "primary-group socket access" in receipt["failure"]["detail"]
    assert accounts.user(prov.EXEC_USER) is None
    assert not (host.root / "etc/subuid").exists()


def test_malformed_identity_created_by_successful_useradd_is_rolled_back(sim) -> None:
    accounts, host, runner, daemon = sim
    daemon.start()

    def malformed_useradd(argv: list[str]):
        if Path(argv[0]).name == "useradd":
            accounts.add_group(prov.EXEC_USER)
            private = accounts.group(prov.EXEC_USER)
            assert private is not None
            accounts.add_user(
                prov.EXEC_USER,
                gid=private.gid,
                home=prov.EXEC_HOME,
                shell="/bin/bash",
            )
            host.resolve(prov.EXEC_HOME).mkdir(parents=True, exist_ok=True)
            return prov.Completed(0, "", "")
        return None

    runner.fail_on = malformed_useradd
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "ensure-stateport-exec-user"
    assert accounts.user(prov.EXEC_USER) is None
    assert accounts.group(prov.EXEC_USER) is None
    actions = {(entry["action"], entry["target"]) for entry in receipt["rollback"]["actions"]}
    assert ("delete-user", prov.EXEC_USER) in actions
    assert ("delete-group", prov.EXEC_USER) in actions


def test_nonzero_but_converged_group_is_not_deleted_as_transaction_owned(sim) -> None:
    accounts, _host, runner, daemon = sim
    daemon.start()
    converged = False

    def converge_then_fail(argv: list[str]):
        nonlocal converged
        if Path(argv[0]).name == "groupadd" and not converged:
            converged = True
            accounts.add_group(prov.EXEC_GROUP)
            return prov.Completed(9, "", "concurrently created")
        if "start" in argv and prov.DAEMON_UNIT in argv:
            return prov.Completed(1, "", "simulated daemon start failure")
        return None

    runner.fail_on = converge_then_fail
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert accounts.group(prov.EXEC_GROUP) is not None
    assert not any(
        entry["action"] == "delete-group" and entry["target"] == prov.EXEC_GROUP
        for entry in receipt["rollback"]["actions"]
    )


def test_command_timeout_after_group_mutation_still_rolls_back_owned_effect(
    sim, monkeypatch: pytest.MonkeyPatch
) -> None:
    accounts, host, runner, daemon = sim
    daemon.start()
    original_run = runner.run
    timed_out = False

    def mutate_then_timeout(argv: Sequence[str], *, timeout: int):
        nonlocal timed_out
        if Path(argv[0]).name == "groupadd" and not timed_out:
            timed_out = True
            host.execute(argv)
            raise TimeoutError("simulated timeout after group creation")
        return original_run(argv, timeout=timeout)

    monkeypatch.setattr(runner, "run", mutate_then_timeout)
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "ensure-execution-control-group"
    assert accounts.group(prov.EXEC_GROUP) is None
    assert any(
        entry["action"] == "delete-group"
        and entry["target"] == prov.EXEC_GROUP
        and entry["result"] == "done"
        for entry in receipt["rollback"]["actions"]
    )


def test_control_membership_step_rechecks_exec_membership_before_files(sim) -> None:
    accounts, host, runner, daemon = sim
    daemon.start()
    attacked = False

    def remove_exec_during_client_membership(argv: list[str]) -> None:
        nonlocal attacked
        if (
            Path(argv[0]).name == "usermod"
            and argv[-1] == "stateport-control"
            and not attacked
        ):
            attacked = True
            accounts.drop_member(prov.EXEC_GROUP, prov.EXEC_USER)

    runner.on_call = remove_exec_during_client_membership
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "confine-control-plane-client"
    assert "missing required members ['stateport-exec']" in receipt["failure"]["detail"]
    assert not (host.root / "etc/subuid").exists()


def test_preexisting_directory_metadata_is_restored_after_later_failure(sim) -> None:
    accounts, host, runner, daemon = sim
    _seed_existing_identity(sim)
    state_dir = host.resolve(prov.STATE_DIR)
    state_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(host.resolve(prov.EXEC_HOME), 0o755)
    os.chmod(state_dir, 0o755)
    daemon.start()
    runner.fail_on = lambda argv: (
        prov.Completed(1, "", "simulated daemon start failure")
        if "start" in argv and prov.DAEMON_UNIT in argv
        else None
    )
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert stat.S_IMODE(host.resolve(prov.EXEC_HOME).stat().st_mode) == 0o755
    assert stat.S_IMODE(state_dir.stat().st_mode) == 0o755
    assert accounts.user(prov.EXEC_USER) is not None
    restored = {
        action["target"]
        for action in receipt["rollback"]["actions"]
        if action["action"] == "restore-directory-metadata"
    }
    assert prov.EXEC_HOME in restored
    assert prov.STATE_DIR in restored


def test_rollback_preserves_foreign_directory_metadata_change(sim) -> None:
    _accounts, host, runner, daemon = sim
    _seed_existing_identity(sim)
    state_dir = host.resolve(prov.STATE_DIR)
    state_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(state_dir, 0o755)
    daemon.start()
    attacked = False

    def change_mode_before_failure(argv: list[str]) -> None:
        nonlocal attacked
        if "start" in argv and prov.DAEMON_UNIT in argv and not attacked:
            attacked = True
            os.chmod(state_dir, 0o711)

    runner.on_call = change_mode_before_failure
    runner.fail_on = lambda argv: (
        prov.Completed(1, "", "simulated daemon start failure")
        if "start" in argv and prov.DAEMON_UNIT in argv
        else None
    )
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert stat.S_IMODE(state_dir.stat().st_mode) == 0o711
    assert receipt["rollback"]["status"] == "incomplete"
    assert any(
        action["action"] == "directory-metadata"
        and action["result"] == "failed"
        and "foreign state preserved" in action["detail"]
        for action in receipt["rollback"]["actions"]
    )


# ---------------------------------------------------------------------------
# Happy path + idempotency (evidence: locally-simulated)
# ---------------------------------------------------------------------------


def test_apply_happy_path_simulated(sim) -> None:
    accounts, host, runner, daemon = sim
    daemon.start()
    receipt = _apply(sim)
    assert receipt["result"] == "succeeded"
    assert receipt["evidenceClass"] == "locally-simulated"
    validate_contract_document(
        receipt, expected_schema="stateport.execution-host-provisioning-receipt/v1"
    )

    # Identity before files, observed numerically.
    assert accounts.user("stateport-exec").uid == os.getuid()
    assert set(accounts.group("stateport-execution-control").members) == {
        "stateport-control",
        "stateport-exec",
    }
    # Exact subordinate id lines in both files.
    for name in ("subuid", "subgid"):
        content = (host.root / "etc" / name).read_text(encoding="utf-8")
        assert content == (
            "stateport-exec:100000:65536\n"
            "stateport-control:165536:65536\n"
        )
    assert receipt["subordinateIds"]["start"] == 100000
    assert receipt["controlSubordinateIds"] == {
        "user": "stateport-control",
        "start": 165536,
        "count": 65536,
        "files": ["/etc/subuid", "/etc/subgid"],
    }
    # Quadlet written with exact mode and owner; tmpfiles conf root-owned 0644.
    quadlet = host.root / "var/lib/stateport-exec/.config/containers/systemd/stateport-execution-host.container"
    assert stat.S_IMODE(quadlet.stat().st_mode) == 0o640
    conf = host.root / "etc/tmpfiles.d/stateport-execution-control.conf"
    assert stat.S_IMODE(conf.stat().st_mode) == 0o644
    # Grants directory exists, daemon-owned, 0700.
    grants = host.root / "var/lib/stateport-exec/stateport-execution-host/state/grants"
    assert stat.S_IMODE(grants.stat().st_mode) == 0o700
    # Socket directory per the signed contract.
    socket_dir = host.root / "run/stateport/execution-control"
    assert stat.S_IMODE(socket_dir.stat().st_mode) == 0o2750
    # Linger marker and user-systemd environment are deliberate.
    assert (host.root / "var/lib/systemd/linger/stateport-exec").is_file()
    daemon_reload = [call for call in runner.calls if "daemon-reload" in call]
    assert daemon_reload and all("XDG_RUNTIME_DIR=/run/user/" in " ".join(call) for call in daemon_reload)
    manager_start = next(i for i, call in enumerate(runner.calls) if call[1:3] == ["start", f"user@{prov.EXEC_UID}.service"])
    bus_probe = next(i for i, call in enumerate(runner.calls) if "show-environment" in call)
    assert manager_start < bus_probe < runner.calls.index(daemon_reload[0])
    # Image observed in the stateport-exec rootless store.
    assert receipt["image"]["status"] == "verified"
    assert host.image_store and not host.root_image_store
    # Units started; protocol health is a real describeCapabilities round trip.
    assert host.units["podman.socket"] and host.units[prov.DAEMON_UNIT]
    assert receipt["health"]["healthy"] is True
    assert receipt["health"]["contractVersion"] == 1
    assert {probe["peerUser"] for probe in receipt["health"]["probes"]} == {
        "stateport-exec",
        "stateport-control",
    }
    # Rollback/uninstall information and no rollback on success.
    assert receipt["rollback"] == {
        "performed": False,
        "status": "not-reached",
        "actions": [],
        "failures": [],
    }
    receipt_path = host.resolve(receipt["receiptPath"])
    assert json.loads(receipt_path.read_text(encoding="utf-8")) == receipt
    assert stat.S_IMODE(receipt_path.stat().st_mode) == 0o600
    assert not Path(str(receipt_path) + ".intent").exists()
    assert all(step["result"] != "not-reached" for step in receipt["steps"])
    assert any("userdel stateport-exec" in command for command in receipt["uninstall"])
    assert any("stateport-control:<assigned-start>" in command for command in receipt["uninstall"])
    assert any("disable --now stateport-accepted.target" in command for command in receipt["uninstall"])
    assert any("rm -f " + prov.CONTROL_SYSTEMD_USER_DIR in command for command in receipt["uninstall"])


def test_apply_binds_the_real_client_and_receipts_it(sim) -> None:
    accounts, host, runner, daemon = sim
    daemon.start()
    accounts.add_user(
        "operator",
        gid=accounts.gid,
        home="/home/operator",
        shell="/bin/bash",
        primary_group="operator",
    )
    accounts.add_group("operator")
    verified = _verified()
    receipt = _apply(
        sim,
        verified=verified,
        client_user="operator",
        client_uid=os.getuid(),
        client_gid=os.getgid(),
    )
    assert receipt["result"] == "succeeded"
    assert receipt["allowedClientUser"] == "operator"
    assert receipt["controlUser"] == prov.CONTROL_USER  # signed contract label is stable
    # The real client is confined into the socket group; the control account
    # is still provisioned because the control-plane units run under it.
    assert set(accounts.group(prov.EXEC_GROUP).members) == {"operator", "stateport-exec"}
    step_names = [step["step"] for step in receipt["steps"]]
    assert "ensure-stateport-control-user" in step_names
    assert "enable-control-user-linger" in step_names
    usermod = [
        call for call in runner.calls if Path(call[0]).name == "usermod" and call[-1] == "operator"
    ]
    assert usermod, "the real client must be confined into the socket group"
    # Protocol health is a real round trip executed AS the real client.
    assert {probe["peerUser"] for probe in receipt["health"]["probes"]} == {
        "stateport-exec",
        "operator",
    }
    runuser_clients = [
        call
        for call in runner.calls
        if Path(call[0]).name == "runuser" and call[1:3] == ["-u", "operator"]
    ]
    assert runuser_clients, "health must probe as the bound real client"
    # The root-owned identity file travels to the confined daemon.
    identity_path = host.root / "run/stateport/execution-control" / prov.CLIENT_IDENTITY_FILE
    assert identity_path.read_text(encoding="utf-8") == f"{os.getuid()}:{os.getgid()}\n"
    assert identity_path.stat().st_uid == os.getuid()  # root in the sim
    assert stat.S_IMODE(identity_path.stat().st_mode) == 0o640
    # Rollback never claims to delete a user the transaction did not create.
    rollback_users = {entry.get("user") for entry in receipt["rollback"]["actions"] or []}
    assert "stateport-control" not in rollback_users


def test_apply_is_idempotent_on_rerun(sim) -> None:
    _accounts, host, _runner, daemon = sim
    daemon.start()
    first = _apply(sim)
    assert first["result"] == "succeeded"
    second = _apply(sim)
    assert second["result"] == "succeeded"
    results = {step["step"]: step["result"] for step in second["steps"]}
    converged = {
        "ensure-execution-control-group",
        "ensure-stateport-exec-user",
        "confine-execution-user-group",
        "confine-control-plane-client",
        "establish-subordinate-mappings",
        "create-host-directories",
        "enable-exec-user-linger",
        "install-stable-host-quadlets",
        "pull-execution-host-image",
        "start-exec-user-engine-socket",
        "start-execution-host-daemon",
    }
    for step in converged:
        assert results[step] == "already-present", step
    # No duplicate subordinate id lines after a rerun.
    for name in ("subuid", "subgid"):
        content = (host.root / "etc" / name).read_text(encoding="utf-8")
        assert content.count("stateport-exec:") == 1


def test_existing_subordinate_ids_are_reused_and_range_extends(sim) -> None:
    accounts, host, runner, daemon = sim
    daemon.start()
    (host.root / "etc" / "subuid").write_text("other:100000:65536\n", encoding="utf-8")
    (host.root / "etc" / "subgid").write_text("other:100000:65536\n", encoding="utf-8")
    receipt = _apply(sim)
    assert receipt["result"] == "succeeded"
    assert receipt["subordinateIds"]["start"] == 165536
    for name in ("subuid", "subgid"):
        lines = (host.root / "etc" / name).read_text(encoding="utf-8").splitlines()
        assert lines == [
            "other:100000:65536",
            "stateport-exec:165536:65536",
            "stateport-control:231072:65536",
        ]


def test_receipt_is_durable_create_only_and_mode_0600(sim, tmp_path: Path) -> None:
    _accounts, _host, _runner, daemon = sim
    daemon.start()
    receipt_path = tmp_path / "receipts" / "provision.json"
    receipt = _apply(sim, receipt_path=receipt_path)
    on_disk = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert on_disk == receipt
    assert stat.S_IMODE(receipt_path.stat().st_mode) == 0o600
    # A rerun with the identical proven plan adopts the existing receipt
    # instead of overwriting evidence or re-executing the transaction.
    with pytest.raises(prov.ProvisioningConverged) as converged:
        _apply(sim, receipt_path=receipt_path)
    assert converged.value.receipt["receiptId"] == receipt["receiptId"]
    assert json.loads(receipt_path.read_text(encoding="utf-8")) == receipt


def test_receipt_rerun_refuses_failed_or_foreign_evidence(sim, tmp_path: Path) -> None:
    _accounts, _host, _runner, daemon = sim
    daemon.start()
    receipt_path = tmp_path / "receipts" / "provision.json"
    receipt = _apply(sim, receipt_path=receipt_path)
    for mutation in (
        {"planDigest": "sha256:" + "0" * 64},
        {"schema": "stateport.foreign/v9"},
    ):
        drifted = dict(receipt)
        drifted.update(mutation)
        receipt_path.write_text(json.dumps(drifted) + "\n", encoding="utf-8")
        with pytest.raises(prov.ProvisioningRefusal, match="refusing to overwrite evidence"):
            _apply(sim, receipt_path=receipt_path)


def test_failed_same_plan_receipt_is_archived_and_retried(sim, tmp_path: Path) -> None:
    """F6: a failed receipt for the SAME plan no longer refuses every rerun
    forever; it is archived aside (evidence preserved) and the retry runs."""
    _accounts, _host, _runner, daemon = sim
    daemon.start()
    receipt_path = tmp_path / "receipts" / "provision.json"
    receipt = _apply(sim, receipt_path=receipt_path)
    unhealthy = dict(receipt)
    unhealthy["health"] = {**dict(receipt["health"]), "healthy": False}
    for drifted in ({**receipt, "result": "failed"}, unhealthy):
        receipt_path.write_text(json.dumps(drifted) + "\n", encoding="utf-8")
        retried = _apply(sim, receipt_path=receipt_path)
        assert retried["result"] == "succeeded"
        archived = list(receipt_path.parent.glob(receipt_path.name + ".failed-*"))
        assert len(archived) == 1, archived
        assert json.loads(archived[0].read_text(encoding="utf-8"))["result"] == drifted["result"]
        receipt_path.unlink()
        archived[0].rename(receipt_path)
        receipt = retried


def test_crash_remnant_pending_intent_is_adopted_on_rerun(sim, tmp_path: Path) -> None:
    """F7: a crash between intent creation and receipt publication leaves a
    pending intent with a per-run startedAt; the identical rerun adopts it."""
    _accounts, _host, _runner, daemon = sim
    daemon.start()
    receipt_path = tmp_path / "receipts" / "provision.json"
    receipt = _apply(sim, receipt_path=receipt_path)
    intent_path = Path(str(receipt_path) + ".intent")
    assert not intent_path.exists()
    # Simulate the crash window: pending intent, no receipt.
    receipt_path.unlink()
    intent_path.write_text(
        json.dumps(
            {
                "schema": "stateport.execution-host-provisioning-intent/v1",
                "planDigest": receipt["planDigest"],
                "receiptPath": str(receipt_path),
                "state": "pending",
                "startedAt": "2026-01-01T00:00:00+00:00",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    retried = _apply(sim, receipt_path=receipt_path)
    assert retried["result"] == "succeeded"
    assert not intent_path.exists()

    # A foreign pending intent still refuses closed.
    receipt_path.unlink()
    intent_path.write_text(
        json.dumps(
            {
                "schema": "stateport.execution-host-provisioning-intent/v1",
                "planDigest": "sha256:" + "0" * 64,
                "receiptPath": str(receipt_path),
                "state": "pending",
                "startedAt": "2026-01-01T00:00:00+00:00",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(prov.ProvisioningRefusal, match="refusing to overwrite evidence"):
        _apply(sim, receipt_path=receipt_path)
    intent_path.unlink()
    intent_path.write_bytes(b"not json\n")
    with pytest.raises(prov.ProvisioningRefusal, match="refusing to overwrite evidence"):
        _apply(sim, receipt_path=receipt_path)


# ---------------------------------------------------------------------------
# Adversarial: symlinks
# ---------------------------------------------------------------------------


def test_symlink_parent_directory_refused(sim) -> None:
    _accounts, host, _runner, daemon = sim
    daemon.start()
    (host.root / "var/lib/stateport-exec").symlink_to(host.root / "etc")
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "create-host-directories"
    assert "not a real directory" in receipt["failure"]["detail"]
    assert receipt["rollback"]["performed"] is True


def test_symlink_write_destination_refused(sim) -> None:
    _accounts, host, runner, daemon = sim
    daemon.start()
    quadlet = host.root / "var/lib/stateport-exec/.config/containers/systemd/stateport-execution-host.container"

    def attack(argv: list[str]) -> None:
        if Path(argv[0]).name == "systemd-tmpfiles" and not quadlet.exists() and not quadlet.is_symlink():
            quadlet.symlink_to(host.root / "etc" / "subuid")

    runner.on_call = attack
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "install-stable-host-quadlets"
    assert "symlink" in receipt["failure"]["detail"]


def test_symlink_subordinate_id_file_refused(sim) -> None:
    _accounts, host, _runner, daemon = sim
    daemon.start()
    (host.root / "etc" / "real-subuid").write_text("other:100000:65536\n", encoding="utf-8")
    (host.root / "etc" / "subuid").symlink_to(host.root / "etc" / "real-subuid")
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "establish-subordinate-mappings"
    assert "not a regular file" in receipt["failure"]["detail"]


def test_parent_swap_during_create_is_detected_from_anchored_descriptors(
    sim, monkeypatch: pytest.MonkeyPatch
) -> None:
    _accounts, host, _runner, daemon = sim
    daemon.start()
    quadlet_dir = host.resolve(prov.QUADLET_DIR)
    moved = quadlet_dir.with_name("systemd-moved-by-racer")
    original_link = prov.os.link
    attacked = False

    def racing_link(source, destination, *args, **kwargs):
        nonlocal attacked
        if destination == "stateport-execution-host.container" and not attacked:
            attacked = True
            quadlet_dir.rename(moved)
            quadlet_dir.symlink_to(host.root / "etc", target_is_directory=True)
        return original_link(source, destination, *args, **kwargs)

    monkeypatch.setattr(prov.os, "link", racing_link)
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "install-stable-host-quadlets"
    assert "swapped" in receipt["failure"]["detail"]
    assert not (host.root / "etc/stateport-execution-host.container").exists()
    assert (moved / "stateport-execution-host.container").is_file()


def test_no_destination_create_race_never_overwrites_foreign_file(
    sim, monkeypatch: pytest.MonkeyPatch
) -> None:
    _accounts, host, _runner, daemon = sim
    daemon.start()
    original_link = prov.os.link
    attacked = False
    foreign = b"foreign-racing-quadlet\n"

    def racing_link(source, destination, *args, **kwargs):
        nonlocal attacked
        if destination == "stateport-execution-host.container" and not attacked:
            attacked = True
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o640,
                dir_fd=kwargs["dst_dir_fd"],
            )
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(foreign)
        return original_link(source, destination, *args, **kwargs)

    monkeypatch.setattr(prov.os, "link", racing_link)
    receipt = _apply(sim)
    quadlet = host.resolve(f"{prov.QUADLET_DIR}/stateport-execution-host.container")
    assert receipt["result"] == "failed"
    assert "create-only publish" in receipt["failure"]["detail"]
    assert quadlet.read_bytes() == foreign


def test_existing_file_swap_loses_cas_without_overwriting_racer(
    sim, monkeypatch: pytest.MonkeyPatch
) -> None:
    _accounts, host, _runner, daemon = sim
    daemon.start()
    quadlet = host.resolve(f"{prov.QUADLET_DIR}/stateport-execution-host.container")
    quadlet.parent.mkdir(parents=True, exist_ok=True)
    quadlet.write_bytes(b"pre-transaction-quadlet\n")
    os.chmod(quadlet, 0o640)
    original_exchange = prov._renameat2
    attacked = False

    def racing_exchange(dir_fd: int, source: str, destination: str, flags: int) -> None:
        nonlocal attacked
        if (
            destination == quadlet.name
            and flags == prov._RENAME_EXCHANGE
            and not attacked
        ):
            attacked = True
            os.rename(
                destination,
                "attacker-saved-prior",
                src_dir_fd=dir_fd,
                dst_dir_fd=dir_fd,
            )
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o640,
                dir_fd=dir_fd,
            )
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(b"racer-won\n")
        original_exchange(dir_fd, source, destination, flags)

    monkeypatch.setattr(prov, "_renameat2", racing_exchange)
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert "inode/state CAS" in receipt["failure"]["detail"]
    assert quadlet.read_bytes() == b"racer-won\n"
    assert (quadlet.parent / "attacker-saved-prior").read_bytes() == (
        b"pre-transaction-quadlet\n"
    )


def test_post_exchange_racer_is_preserved_with_recoverable_prior(
    sim, monkeypatch: pytest.MonkeyPatch
) -> None:
    _accounts, host, _runner, daemon = sim
    daemon.start()
    quadlet = host.resolve(f"{prov.QUADLET_DIR}/stateport-execution-host.container")
    quadlet.parent.mkdir(parents=True, exist_ok=True)
    prior = b"pre-transaction-quadlet\n"
    foreign = b"post-exchange-racer\n"
    quadlet.write_bytes(prior)
    os.chmod(quadlet, 0o640)
    original_exchange = prov._renameat2
    attacked = False

    def racing_after_exchange(dir_fd: int, source: str, destination: str, flags: int) -> None:
        nonlocal attacked
        original_exchange(dir_fd, source, destination, flags)
        if (
            destination == quadlet.name
            and flags == prov._RENAME_EXCHANGE
            and not attacked
        ):
            attacked = True
            os.rename(
                destination,
                "attacker-saved-transaction",
                src_dir_fd=dir_fd,
                dst_dir_fd=dir_fd,
            )
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o640,
                dir_fd=dir_fd,
            )
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(foreign)

    monkeypatch.setattr(prov, "_renameat2", racing_after_exchange)
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert "changed after CAS publish" in receipt["failure"]["detail"]
    assert quadlet.read_bytes() == foreign
    recovery = list(quadlet.parent.glob(f".{quadlet.name}.provision-*"))
    assert len(recovery) == 1
    assert recovery[0].read_bytes() == prior
    assert receipt["rollback"]["status"] == "incomplete"
    recovery_path = f"{prov.QUADLET_DIR}/{recovery[0].name}"
    assert any(
        recovery_path in action["detail"]
        for action in receipt["rollback"]["actions"]
        if action["result"] == "failed"
    )


# ---------------------------------------------------------------------------
# Adversarial: wrong ownership/mode, wrong store, missing subids
# ---------------------------------------------------------------------------


def test_wrong_socket_directory_mode_is_observed(sim) -> None:
    _accounts, host, _runner, daemon = sim
    daemon.start()
    host.socket_dir_mode = 0o755
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "write-confined-socket-tmpfiles"
    assert "observation failed" in receipt["failure"]["detail"]


def test_image_pulled_into_the_wrong_store_fails(sim) -> None:
    _accounts, host, _runner, daemon = sim
    daemon.start()
    host.pull_into_wrong_store = True
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    # The control-plane pull is the first pull step and shares the same
    # exec-user store simulation, so a wrong-store pull is caught there.
    assert receipt["failure"]["step"] == "pull-control-plane-images"
    assert host.root_image_store, "the simulated wrong-store pull happened"
    assert receipt["image"]["status"] == "not-reached"


def test_image_with_tampered_digest_in_store_fails(sim) -> None:
    _accounts, host, _runner, daemon = sim
    daemon.start()
    host.inspect_digest_override = "sha256:" + "f" * 64
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "pull-control-plane-images"
    assert "!= signed" in receipt["failure"]["detail"]


def test_root_subprocess_runner_uses_only_minimal_explicit_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured.update(kwargs)
        return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setenv("LD_PRELOAD", "/tmp/inject.so")
    monkeypatch.setenv("CONTAINER_HOST", "unix:///tmp/root.sock")
    monkeypatch.setenv("REGISTRY_AUTH_FILE", "/tmp/root-auth.json")
    monkeypatch.setattr(prov.subprocess, "run", fake_run)
    completed = prov.SubprocessRunner().run(["/usr/bin/true"], timeout=3)
    assert completed.returncode == 0
    assert captured["env"] == {
        "HOME": "/root",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "LOGNAME": "root",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "USER": "root",
    }
    assert captured["shell"] is False
    assert captured["cwd"] == Path("/")


def test_root_subprocess_runner_rejects_user_controlled_executable_path(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "trusted-looking-tool"
    executable.symlink_to("/usr/bin/true")
    with pytest.raises(prov.ProvisioningRefusal, match="not root-controlled"):
        prov.SubprocessRunner().run([str(executable)], timeout=3)


def test_exec_commands_clear_ambient_injection_and_use_trusted_executables(
    sim, monkeypatch: pytest.MonkeyPatch
) -> None:
    _accounts, _host, runner, daemon = sim
    monkeypatch.setenv("LD_PRELOAD", "/tmp/inject.so")
    monkeypatch.setenv("CONTAINER_HOST", "unix:///tmp/root.sock")
    monkeypatch.setenv("REGISTRY_AUTH_FILE", "/tmp/root-auth.json")
    daemon.start()
    receipt = _apply(sim)
    assert receipt["result"] == "succeeded"
    assert all(Path(call[0]).is_absolute() for call in runner.calls)
    exec_calls = [call for call in runner.calls if Path(call[0]).name == "runuser"]
    assert exec_calls and all("-i" in call for call in exec_calls)
    joined = "\n".join(" ".join(call) for call in exec_calls)
    assert "LD_PRELOAD=" not in joined
    assert "CONTAINER_HOST=" not in joined
    assert "REGISTRY_AUTH_FILE=" not in joined
    assert f"HOME={prov.EXEC_HOME}" in joined
    assert f"XDG_CONFIG_HOME={prov.EXEC_CONFIG_DIR}" in joined


@pytest.mark.parametrize(
    ("attribute", "value"),
    [
        ("storage_graph_root", "/root/.local/share/containers/storage"),
        ("storage_run_root", "/run/user/0/containers"),
        ("oci_runtime", "crun"),
    ],
)
def test_exec_rootless_storage_identity_must_be_exact(sim, attribute: str, value: str) -> None:
    _accounts, host, _runner, daemon = sim
    daemon.start()
    setattr(host, attribute, value)
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "pull-execution-host-image"
    assert "storage/runtime identity is not exact" in receipt["failure"]["detail"]


def test_exec_rootless_storage_directories_must_be_private(sim) -> None:
    _accounts, host, _runner, daemon = sim
    daemon.start()
    host.storage_mode = 0o755
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "pull-execution-host-image"
    assert "rootless storage directory is not private" in receipt["failure"]["detail"]


def test_active_but_disabled_engine_socket_is_not_already_present(sim) -> None:
    _accounts, host, _runner, daemon = sim
    daemon.start()
    host.units[prov.ENGINE_SOCKET_UNIT] = True
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "start-exec-user-engine-socket"
    assert "not durably enabled" in receipt["failure"]["detail"]


def test_foreign_generated_unit_source_is_refused(sim) -> None:
    _accounts, _host, runner, daemon = sim
    daemon.start()

    def foreign_source(argv: list[str]):
        if (
            Path(argv[0]).name == "runuser"
            and "--property=SourcePath" in argv
            and prov.DAEMON_UNIT in argv
        ):
            return prov.Completed(0, "/foreign/stateport-execution-host.container\n", "")
        return None

    runner.fail_on = foreign_source
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "start-execution-host-daemon"
    assert "fragment/source identity diverges" in receipt["failure"]["detail"]


def test_writable_vendor_engine_unit_is_refused(sim) -> None:
    _accounts, host, _runner, daemon = sim
    daemon.start()
    os.chmod(host.resolve("/usr/lib/systemd/user/podman.socket"), 0o666)
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "start-exec-user-engine-socket"
    assert "vendor fragment ownership/mode is not trusted" in receipt["failure"]["detail"]


def test_writable_generated_daemon_fragment_is_refused(
    sim, monkeypatch: pytest.MonkeyPatch
) -> None:
    _accounts, host, _runner, daemon = sim
    daemon.start()
    original_materialize = host._materialize_daemon_unit

    def materialize_writable_fragment() -> None:
        original_materialize()
        account = host.accounts.user(prov.EXEC_USER)
        if account is not None:
            fragment = host.resolve(
                f"/run/user/{account.uid}/systemd/generator/{prov.DAEMON_UNIT}"
            )
            if fragment.exists():
                os.chmod(fragment, 0o666)

    monkeypatch.setattr(host, "_materialize_daemon_unit", materialize_writable_fragment)
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "start-execution-host-daemon"
    assert "source identity is not exact" in receipt["failure"]["detail"]


def test_insufficient_existing_subid_range_refused(sim) -> None:
    _accounts, host, _runner, daemon = sim
    daemon.start()
    for name in ("subuid", "subgid"):
        (host.root / "etc" / name).write_text("stateport-exec:100000:1024\n", encoding="utf-8")
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "establish-subordinate-mappings"
    assert "exact count 65536" in receipt["failure"]["detail"]


def test_subid_append_preserves_comments_blank_lines_and_exact_foreign_bytes(sim) -> None:
    _accounts, host, _runner, daemon = sim
    daemon.start()
    foreign = b"# managed by account tooling\r\n\r\nother:100000:65536\n  # retained\n"
    for name in ("subuid", "subgid"):
        (host.root / "etc" / name).write_bytes(foreign)
    receipt = _apply(sim)
    assert receipt["result"] == "succeeded"
    expected = foreign + b"stateport-exec:165536:65536\nstateport-control:231072:65536\n"
    for name in ("subuid", "subgid"):
        assert (host.root / "etc" / name).read_bytes() == expected


@pytest.mark.parametrize(
    ("subuid", "subgid", "detail"),
    [
        (
            "stateport-exec:100000:131072\n",
            "stateport-exec:100000:131072\n",
            "exact count 65536",
        ),
        (
            "stateport-exec:100000:65536\n",
            "stateport-exec:200000:65536\n",
            "incoherent",
        ),
    ],
)
def test_existing_subids_must_be_exact_and_coherent(
    sim, subuid: str, subgid: str, detail: str
) -> None:
    _accounts, host, _runner, daemon = sim
    daemon.start()
    (host.root / "etc/subuid").write_text(subuid, encoding="utf-8")
    (host.root / "etc/subgid").write_text(subgid, encoding="utf-8")
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "establish-subordinate-mappings"
    assert detail in receipt["failure"]["detail"]
    assert "/etc/subuid=" in receipt["failure"]["detail"]
    assert "/etc/subgid=" in receipt["failure"]["detail"]


def test_subid_recheck_detects_cross_file_overlap_before_second_publish(
    sim, monkeypatch: pytest.MonkeyPatch
) -> None:
    _accounts, host, _runner, daemon = sim
    daemon.start()
    original_write = prov._write_file_converged
    attacked = False

    def racing_write(ctx, path, content, **kwargs):
        nonlocal attacked
        if path == prov.SUBUID_PATH and kwargs.get("journal_kind") == "subid-line-added" and not attacked:
            attacked = True
            (host.root / "etc/subgid").write_text(
                "racer:100000:65536\n", encoding="utf-8"
            )
        return original_write(ctx, path, content, **kwargs)

    monkeypatch.setattr(prov, "_write_file_converged", racing_write)
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "establish-subordinate-mappings"
    assert (host.root / "etc/subgid").read_text(encoding="utf-8") == (
        "racer:100000:65536\n"
    )
    assert not (host.root / "etc/subuid").exists()


def test_subid_rollback_removes_only_transaction_line_and_preserves_later_append(sim) -> None:
    _accounts, host, runner, daemon = sim
    daemon.start()
    appended = False

    def append_then_fail(argv: list[str]) -> None:
        nonlocal appended
        if "start" in argv and prov.DAEMON_UNIT in argv and not appended:
            appended = True
            for name in ("subuid", "subgid"):
                with (host.root / "etc" / name).open("ab") as handle:
                    handle.write(b"foreign-later:300000:65536\n")

    runner.on_call = append_then_fail
    runner.fail_on = lambda argv: (
        prov.Completed(1, "", "simulated daemon start failure")
        if "start" in argv and prov.DAEMON_UNIT in argv
        else None
    )
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    for name in ("subuid", "subgid"):
        assert (host.root / "etc" / name).read_bytes() == (
            b"foreign-later:300000:65536\n"
        )
    assert receipt["rollback"]["status"] == "succeeded"


# ---------------------------------------------------------------------------
# Adversarial: stale sockets, empty dirs, wrong peer identity
# ---------------------------------------------------------------------------


def test_stale_socket_inode_is_not_health(
    sim, monkeypatch: pytest.MonkeyPatch
) -> None:
    _accounts, _host, _runner, daemon = sim
    daemon.start()
    daemon.close_leave_stale_inode()
    monkeypatch.setattr(prov, "READINESS_TIMEOUT_SECONDS", 0.0)
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "verify-protocol-health"
    assert "inode is stale" in receipt["failure"]["detail"]


def test_empty_socket_directory_times_out_and_rolls_back(
    sim, monkeypatch: pytest.MonkeyPatch
) -> None:
    # No daemon ever starts: tmpfiles creates the directory and nothing else.
    _accounts, host, _runner, _daemon = sim
    monkeypatch.setattr(prov, "READINESS_TIMEOUT_SECONDS", 0.0)
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "verify-protocol-health"
    assert "startup readiness timed out" in receipt["failure"]["detail"]
    assert receipt["rollback"]["status"] == "succeeded"
    assert host.units.get(prov.DAEMON_UNIT) is False


def test_delayed_socket_readiness_retries_then_requires_both_peers(
    sim, monkeypatch: pytest.MonkeyPatch
) -> None:
    _accounts, _host, runner, daemon = sim
    started = False

    def start_daemon(_seconds: float) -> None:
        nonlocal started
        if not started:
            daemon.start()
            started = True

    monkeypatch.setattr(prov.time, "sleep", start_daemon)
    receipt = _apply(sim)
    health_calls = [call for call in runner.calls if "health-probe" in call]
    assert receipt["result"] == "succeeded"
    assert [probe["peerUser"] for probe in receipt["health"]["probes"]] == [
        prov.EXEC_USER,
        prov.CONTROL_USER,
    ]
    assert len(health_calls) == 2
    for call in health_calls:
        assert call[call.index("--socket") + 1] == "/run/stateport/execution-control/control.sock"
        assert call[call.index("--expected-uid") + 1] == str(
            sim[0].user(prov.EXEC_USER).uid
        )
        assert call[call.index("--expected-gid") + 1] == str(
            sim[0].group(prov.EXEC_GROUP).gid
        )
        assert call[call.index("--expected-mode") + 1] == "0660"
        assert call[call.index("--expected-contract-version") + 1] == "1"


def test_slow_daemon_readiness_keeps_receipt_commands_bounded(
    sim, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A slow first start must not overflow the receipt schema.

    The readiness loop polls until the daemon answers; every attempt runs
    recorded commands. The receipt schema caps steps[].commands at 32, so the
    loop may only record the final attempt — otherwise a cold guest (many
    polls) produces a receipt that fails schema validation and the install
    can never complete (rehearsal-dca1aa54-v1: provisioning refused with
    "steps[15].commands: array has too many items" at 40+ polls).
    """
    _accounts, _host, _runner, daemon = sim
    polls = 0

    def start_after_forty_polls(_seconds: float) -> None:
        nonlocal polls
        polls += 1
        if polls > 40:
            daemon.start()

    monkeypatch.setattr(prov.time, "sleep", start_after_forty_polls)
    receipt = _apply(sim)
    assert receipt["result"] == "succeeded"
    assert polls > 40
    health_step = next(
        entry for entry in receipt["steps"] if entry["step"] == "verify-protocol-health"
    )
    assert len(health_step["commands"]) <= 32
    validate_contract_document(receipt, expected_schema=prov.RECEIPT_SCHEMA)


def _redigest(receipt: dict[str, Any]) -> dict[str, Any]:
    receipt["receiptDigest"] = prov.revision_contract_digest(receipt, digest_field="receiptDigest")
    return receipt


def test_provisioning_receipt_emission_stays_within_schema_caps_at_worst_case(sim) -> None:
    """I4: worst-case emission stays within every schema cap.

    The receipt schema bounds array sizes (maxItems) and string lengths
    (maxLength).  This property test drives a real provisioning apply, then
    checks that boundary values are accepted and one-past-the-cap values are
    rejected, so an emitter that overflows a cap (max polls, max retries,
    longest paths) is caught by validation instead of producing an
    unwriteable receipt.
    """
    _accounts, _host, _runner, daemon = sim
    daemon.start()
    receipt = _apply(sim)
    assert receipt["result"] == "succeeded"
    validate_contract_document(receipt, expected_schema=prov.RECEIPT_SCHEMA)

    # Longest paths: exactly at maxLength validates, one character over refuses.
    for field, maximum in (("receiptPath", 500),):
        at_cap = deepcopy(receipt)
        at_cap[field] = "/" + "p" * (maximum - 1)
        validate_contract_document(_redigest(at_cap), expected_schema=prov.RECEIPT_SCHEMA)
        over_cap = deepcopy(receipt)
        over_cap[field] = "/" + "p" * maximum
        with pytest.raises(ReleaseContractError):
            validate_contract_document(_redigest(over_cap), expected_schema=prov.RECEIPT_SCHEMA)

    # health.socketPath maxLength 300 boundary.
    at_cap = deepcopy(receipt)
    at_cap["health"]["socketPath"] = "/" + "s" * 299
    validate_contract_document(_redigest(at_cap), expected_schema=prov.RECEIPT_SCHEMA)
    over_cap = deepcopy(receipt)
    over_cap["health"]["socketPath"] = "/" + "s" * 300
    with pytest.raises(ReleaseContractError):
        validate_contract_document(_redigest(over_cap), expected_schema=prov.RECEIPT_SCHEMA)

    # Array caps: maxItems accepted, one over rejected.
    rollback_failure = "f" * 300
    at_cap = deepcopy(receipt)
    at_cap["rollback"]["failures"] = [rollback_failure] * 16
    at_cap["rollback"]["status"] = "incomplete"
    validate_contract_document(_redigest(at_cap), expected_schema=prov.RECEIPT_SCHEMA)
    over_cap = deepcopy(receipt)
    over_cap["rollback"]["failures"] = [rollback_failure] * 17
    over_cap["rollback"]["status"] = "incomplete"
    with pytest.raises(ReleaseContractError):
        validate_contract_document(_redigest(over_cap), expected_schema=prov.RECEIPT_SCHEMA)

    # rollback.actions maxItems 64 boundary with max-length strings.
    action = {
        "action": "a" * 60,
        "target": "/" + "t" * 299,
        "result": "done",
        "detail": "d" * 300,
    }
    at_cap = deepcopy(receipt)
    at_cap["rollback"]["actions"] = [dict(action) for _ in range(64)]
    validate_contract_document(_redigest(at_cap), expected_schema=prov.RECEIPT_SCHEMA)
    over_cap = deepcopy(receipt)
    over_cap["rollback"]["actions"] = [dict(action) for _ in range(65)]
    with pytest.raises(ReleaseContractError):
        validate_contract_document(_redigest(over_cap), expected_schema=prov.RECEIPT_SCHEMA)

    # uninstall maxItems 32 boundary.
    at_cap = deepcopy(receipt)
    at_cap["uninstall"] = ["systemctl --user disable x"] * 32
    validate_contract_document(_redigest(at_cap), expected_schema=prov.RECEIPT_SCHEMA)
    over_cap = deepcopy(receipt)
    over_cap["uninstall"] = ["systemctl --user disable x"] * 33
    with pytest.raises(ReleaseContractError):
        validate_contract_document(_redigest(over_cap), expected_schema=prov.RECEIPT_SCHEMA)


def test_provisioning_emitters_truncate_detail_strings_within_schema_caps(sim) -> None:
    """I4 (longest paths): emitters bound free-text fields to their maxLength.

    Rollback details are truncated ([:280]/[:300]) so a pathological path or
    error message can never push a receipt string past its schema cap.  Drive
    a failing step with an over-long detail and confirm the recorded receipt
    still validates instead of overflowing maxLength.
    """
    _accounts, _host, _runner, daemon = sim
    daemon.start()
    receipt = _apply(sim)
    assert receipt["result"] == "succeeded"
    # Every recorded string field is within its schema cap even though the
    # simulation feeds real commands and paths through the emitters.
    for step in receipt["steps"]:
        assert len(step["step"]) <= 80
        assert len(step["detail"]) <= 300
        for command in step["commands"]:
            assert len(command) <= 48
            assert all(len(part) <= 300 for part in command)
    for action in receipt["rollback"]["actions"]:
        assert len(action["action"]) <= 60
        assert len(action["target"]) <= 300
        assert len(action["detail"]) <= 300
    assert all(len(item) <= 300 for item in receipt["rollback"]["failures"])
    validate_contract_document(receipt, expected_schema=prov.RECEIPT_SCHEMA)


def test_daemon_exit_during_readiness_fails_without_retry(
    sim, monkeypatch: pytest.MonkeyPatch
) -> None:
    _accounts, host, runner, daemon = sim
    daemon.start()
    daemon_active_checks = 0

    def stop_before_health(argv: list[str]) -> None:
        nonlocal daemon_active_checks
        if "is-active" in argv and prov.DAEMON_UNIT in argv:
            daemon_active_checks += 1
            if daemon_active_checks == 3:
                host.units[prov.DAEMON_UNIT] = False

    runner.on_call = stop_before_health
    monkeypatch.setattr(
        prov.time,
        "sleep",
        lambda _seconds: pytest.fail("service exit must not be retried"),
    )
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert "exited during startup readiness" in receipt["failure"]["detail"]
    assert not any("health-probe" in call for call in runner.calls)


def test_wrong_peer_identity_refusal_is_not_health(
    sim, monkeypatch: pytest.MonkeyPatch
) -> None:
    _accounts, _host, runner, daemon = sim
    daemon._refuse_reason = "peer-not-authorized"
    daemon.start()
    monkeypatch.setattr(
        prov.time,
        "sleep",
        lambda _seconds: pytest.fail("permanent daemon refusal must not be retried"),
    )
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "verify-protocol-health"
    assert "peer-not-authorized" in receipt["failure"]["detail"]
    assert len([call for call in runner.calls if "health-probe" in call]) == 1


def test_health_requires_the_actual_allowed_client_to_connect(sim) -> None:
    _accounts, _host, runner, daemon = sim
    daemon.start()

    def refuse_control_probe(argv: list[str]):
        if (
            Path(argv[0]).name == "runuser"
            and argv[2] == "stateport-control"
            and "health-probe" in argv
        ):
            return prov.Completed(
                1,
                json.dumps(
                    {
                        "healthy": False,
                        "reason": "socket-permission-denied",
                        "detail": "the allowed control client cannot connect",
                    }
                )
                + "\n",
                "",
            )
        return None

    runner.fail_on = refuse_control_probe
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "verify-protocol-health"
    assert receipt["health"]["status"] == "failed"
    assert receipt["health"]["probes"] == [
        {
            "peerUser": "stateport-exec",
            "healthy": True,
            "contractVersion": 1,
            "reason": None,
        },
        {
            "peerUser": "stateport-control",
            "healthy": False,
            "contractVersion": None,
            "reason": "socket-permission-denied",
        },
    ]


def test_socket_with_wrong_mode_is_not_health(sim) -> None:
    _accounts, _host, _runner, daemon = sim
    daemon._socket_mode = 0o644
    daemon.start()
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "verify-protocol-health"
    assert "ownership/mode mismatch" in receipt["failure"]["detail"]


def test_garbage_protocol_peer_is_not_health(sim) -> None:
    _accounts, _host, _runner, daemon = sim
    daemon._garbage = True
    daemon.start()
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "verify-protocol-health"


# ---------------------------------------------------------------------------
# Adversarial: partial failure rollback correctness
# ---------------------------------------------------------------------------


def test_partial_failure_at_daemon_start_rolls_back_exactly(sim) -> None:
    accounts, host, runner, daemon = sim
    daemon.start()

    def fail_on(argv: list[str]):
        if "start" in argv and prov.DAEMON_UNIT in argv:
            return prov.Completed(1, "", "simulated unit start failure")
        return None

    runner.fail_on = fail_on
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "start-execution-host-daemon"
    rollback = receipt["rollback"]
    assert rollback["performed"] is True and rollback["failures"] == []
    actions = {(entry["action"], entry["result"]) for entry in rollback["actions"]}
    assert ("restore-unit-state", "done") in actions  # podman.socket was enabled by us
    assert ("preserve-image", "skipped") in actions  # image cache is preserved
    assert ("delete-user", "done") in actions
    assert ("delete-group", "done") in actions
    assert ("disable-linger", "done") in actions
    assert ("stop-user-manager", "done") in actions
    # Everything this transaction created is gone.
    assert not (host.root / "etc/tmpfiles.d/stateport-execution-control.conf").exists()
    assert not (host.root / "var/lib/stateport-exec/.config/containers/systemd/stateport-execution-host.container").exists()
    assert not (host.root / "var/lib/systemd/linger/stateport-exec").exists()
    assert "stateport-exec" not in (host.root / "etc/subuid").read_text(encoding="utf-8") if (host.root / "etc/subuid").exists() else True
    assert accounts.user("stateport-exec") is None
    assert accounts.group("stateport-execution-control") is None
    results = {step["step"]: step["result"] for step in receipt["steps"]}
    assert results["start-execution-host-daemon"] == "failed"
    assert results["verify-protocol-health"] == "not-reached"
    assert results["record-provisioning-receipt"] == "applied"
    assert receipt["health"]["status"] == "not-reached"
    assert receipt["rollback"]["status"] == "succeeded"
    validate_contract_document(
        receipt, expected_schema="stateport.execution-host-provisioning-receipt/v1"
    )


def test_exec_user_manager_bus_failure_rolls_back_before_quadlet_reload(sim) -> None:
    accounts, host, runner, _daemon = sim

    def fail_on(argv: list[str]):
        if "show-environment" in argv:
            return prov.Completed(1, "", "simulated missing user bus")
        return None

    runner.fail_on = fail_on
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "enable-exec-user-linger"
    assert "manager bus is unavailable" in receipt["failure"]["detail"]
    assert not any("daemon-reload" in call for call in runner.calls)
    actions = {(entry["action"], entry["result"]) for entry in receipt["rollback"]["actions"]}
    assert ("stop-user-manager", "done") in actions
    assert ("disable-linger", "done") in actions
    assert accounts.user(prov.EXEC_USER) is None
    assert not host.user_managers


def test_preexisting_exec_user_manager_is_preserved_on_failure(sim) -> None:
    accounts, host, runner, _daemon = sim
    unit = f"user@{prov.EXEC_UID}.service"
    host.user_managers.add(unit)

    def fail_on(argv: list[str]):
        if "show-environment" in argv:
            return prov.Completed(1, "", "simulated user bus failure")
        return None

    runner.fail_on = fail_on
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert unit in host.user_managers
    assert not any(
        entry["action"] == "stop-user-manager" and entry["target"] == unit
        for entry in receipt["rollback"]["actions"]
    )


def test_preexisting_manager_without_linger_is_restored_after_rollback(sim) -> None:
    _accounts, host, runner, _daemon = sim
    unit = f"user@{prov.EXEC_UID}.service"
    host.user_managers.add(unit)

    def fail_on(argv: list[str]):
        if "show-environment" in argv:
            return prov.Completed(1, "", "trigger rollback")
        return None

    runner.fail_on = fail_on
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert unit in host.user_managers
    actions = {(entry["action"], entry["target"], entry["result"]) for entry in receipt["rollback"]["actions"]}
    assert ("settle-user-manager", unit, "done") in actions
    assert ("restore-user-manager", unit, "done") in actions
    settle_index = next(
        i
        for i, entry in enumerate(receipt["rollback"]["actions"])
        if entry["action"] == "settle-user-manager" and entry["target"] == unit
    )
    restore_index = next(
        i
        for i, entry in enumerate(receipt["rollback"]["actions"])
        if entry["action"] == "restore-user-manager" and entry["target"] == unit
    )
    assert settle_index < restore_index


def test_reloading_exec_user_manager_is_treated_as_active(sim) -> None:
    _accounts, host, runner, _daemon = sim
    unit = f"user@{prov.EXEC_UID}.service"
    host.user_managers.add(unit)
    host.user_manager_states[unit] = "reloading"

    def fail_on(argv: list[str]):
        if "show-environment" in argv:
            return prov.Completed(1, "", "simulated user bus failure")
        return None

    runner.fail_on = fail_on
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert unit in host.user_managers
    probe_index = next(i for i, call in enumerate(runner.calls) if "show-environment" in call)
    restart_indices = [
        i for i, call in enumerate(runner.calls) if call[1:3] == ["start", unit]
    ]
    assert restart_indices and min(restart_indices) > probe_index


def test_effectful_nonzero_linger_is_rolled_back(sim) -> None:
    _accounts, host, runner, _daemon = sim

    def effect(argv: list[str]) -> None:
        if Path(argv[0]).name == "loginctl" and argv[1:] == ["enable-linger", prov.EXEC_USER]:
            marker = host.resolve(f"{prov.LINGER_DIR}/{prov.EXEC_USER}")
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.touch()
            host.user_managers.add(f"user@{prov.EXEC_UID}.service")

    def fail_on(argv: list[str]):
        if Path(argv[0]).name == "loginctl" and argv[1:] == ["enable-linger", prov.EXEC_USER]:
            return prov.Completed(1, "", "effectful failure")
        if "show-environment" in argv:
            return prov.Completed(1, "", "stop after linger")
        return None

    runner.on_call = effect
    runner.fail_on = fail_on
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert not host.resolve(f"{prov.LINGER_DIR}/{prov.EXEC_USER}").exists()
    assert not host.user_managers


def test_failed_manager_stop_preserves_identity_and_linger(sim) -> None:
    accounts, host, runner, _daemon = sim

    def fail_on(argv: list[str]):
        if "show-environment" in argv:
            return prov.Completed(1, "", "trigger rollback")
        if argv[1:3] == ["stop", f"user@{prov.EXEC_UID}.service"]:
            return prov.Completed(1, "", "manager would not stop")
        return None

    runner.fail_on = fail_on
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert receipt["rollback"]["status"] == "incomplete"
    assert accounts.user(prov.EXEC_USER) is not None
    assert host.resolve(f"{prov.LINGER_DIR}/{prov.EXEC_USER}").exists()
    assert f"user@{prov.EXEC_UID}.service" in host.user_managers
    assert not any(
        entry["action"] == "delete-user"
        for entry in receipt["rollback"]["actions"]
    )


def test_failed_linger_cleanup_preserves_identity_and_mappings(sim) -> None:
    accounts, host, runner, _daemon = sim

    def fail_on(argv: list[str]):
        if "show-environment" in argv:
            return prov.Completed(1, "", "trigger rollback")
        if Path(argv[0]).name == "loginctl" and argv[1:] == ["disable-linger", prov.EXEC_USER]:
            return prov.Completed(1, "", "linger marker retained")
        return None

    runner.fail_on = fail_on
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert receipt["rollback"]["status"] == "incomplete"
    assert accounts.user(prov.EXEC_USER) is not None
    assert host.resolve(f"{prov.LINGER_DIR}/{prov.EXEC_USER}").exists()
    assert "stateport-exec:" in host.resolve(prov.SUBUID_PATH).read_text(encoding="utf-8")
    assert not any(entry["action"] == "delete-user" for entry in receipt["rollback"]["actions"])


def test_initial_receipt_write_failure_rolls_back_and_publishes_failure(
    sim, monkeypatch: pytest.MonkeyPatch
) -> None:
    accounts, host, _runner, daemon = sim
    daemon.start()
    original_write = prov._write_receipt
    attempts = 0

    def fail_once(target, document):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError("simulated fsync failure")
        return original_write(target, document)

    monkeypatch.setattr(prov, "_write_receipt", fail_once)
    receipt = _apply(sim)
    assert attempts == 2
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "record-provisioning-receipt"
    assert receipt["rollback"]["status"] == "succeeded"
    assert accounts.user(prov.EXEC_USER) is None
    receipt_path = host.resolve(receipt["receiptPath"])
    assert json.loads(receipt_path.read_text(encoding="utf-8")) == receipt
    assert not Path(str(receipt_path) + ".intent").exists()


def test_receipt_destination_race_preserves_foreign_file_and_pending_intent(
    sim, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    accounts, _host, _runner, daemon = sim
    daemon.start()
    target_path = tmp_path / "receipt.json"
    foreign = b"foreign evidence\n"
    original_write = prov._write_receipt
    raced = False

    def race_destination(target, document):
        nonlocal raced
        if not raced:
            raced = True
            target_path.write_bytes(foreign)
        return original_write(target, document)

    monkeypatch.setattr(prov, "_write_receipt", race_destination)
    with pytest.raises(prov.ProvisioningRefusal, match="pending intent"):
        _apply(sim, receipt_path=target_path)
    assert target_path.read_bytes() == foreign
    intent_path = Path(str(target_path) + ".intent")
    intent = json.loads(intent_path.read_text(encoding="utf-8"))
    assert intent["state"] == "pending"
    assert intent["receiptPath"] == str(target_path)
    assert accounts.user(prov.EXEC_USER) is None


def test_rollback_restores_foreign_preexisting_bytes(sim) -> None:
    _accounts, host, runner, daemon = sim
    daemon.start()
    foreign = host.root / "etc" / "subuid"
    foreign.write_text("other:100000:65536\n", encoding="utf-8")
    foreign_gid = host.root / "etc" / "subgid"
    foreign_gid.write_text("other:100000:65536\n", encoding="utf-8")

    def fail_on(argv: list[str]):
        if "start" in argv and prov.DAEMON_UNIT in argv:
            return prov.Completed(1, "", "simulated unit start failure")
        return None

    runner.fail_on = fail_on
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    # The pre-existing foreign lines are restored exactly, not deleted.
    assert foreign.read_text(encoding="utf-8") == "other:100000:65536\n"
    assert foreign_gid.read_text(encoding="utf-8") == "other:100000:65536\n"
    restored = [
        entry
        for entry in receipt["rollback"]["actions"]
        if entry["action"] == "remove-subordinate-id-line"
    ]
    assert len(restored) == 2


def test_failure_before_files_rolls_back_identity(sim) -> None:
    accounts, host, runner, daemon = sim
    daemon.start()

    def fail_on(argv: list[str]):
        if Path(argv[0]).name == "systemd-tmpfiles":
            return prov.Completed(1, "", "simulated tmpfiles failure")
        return None

    runner.fail_on = fail_on
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "write-confined-socket-tmpfiles"
    assert accounts.user("stateport-exec") is None
    assert accounts.group("stateport-execution-control") is None
    assert not (host.root / "etc/subuid").exists()
    assert not (host.root / "var/lib/stateport-exec/stateport-execution-host").exists()


def test_no_substring_already_exists_success(sim) -> None:
    """The rejected substring heuristic: a failed command whose effect is
    absent is a FAILURE even when stderr says 'already exists'."""

    _accounts, _host, runner, daemon = sim
    daemon.start()

    def fail_on(argv: list[str]):
        if Path(argv[0]).name == "groupadd":
            return prov.Completed(
                1, "", "groupadd: group 'stateport-execution-control' already exists"
            )
        return None

    runner.fail_on = fail_on
    receipt = _apply(sim)
    assert receipt["result"] == "failed"
    assert receipt["failure"]["step"] == "ensure-execution-control-group"


# ---------------------------------------------------------------------------
# Protocol probe unit tests (real AF_UNIX round trip, in-process peer)
# ---------------------------------------------------------------------------


def test_probe_healthy_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "run" / "control.sock"
    daemon = FakeDaemon(path)
    daemon.start()
    result = prov.probe_protocol_health(path)
    assert result["healthy"] is True
    assert result["contractVersion"] == 1
    assert result["transport"] == "confined-host-unix-socket"


def test_probe_rejects_contract_version_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "run" / "control.sock"
    daemon = FakeDaemon(path)
    daemon.start()
    result = prov.probe_protocol_health(path, expected_contract_version=2)
    assert result["healthy"] is False
    assert result["reason"] == "contract-version-mismatch"
    assert result["detail"] == "daemon contract 1 != expected 2"


def test_probe_rejects_empty_directory(tmp_path: Path) -> None:
    result = prov.probe_protocol_health(tmp_path / "run" / "control.sock")
    assert result["healthy"] is False
    assert result["reason"] == "socket-directory-absent"
    (tmp_path / "run").mkdir()
    result = prov.probe_protocol_health(tmp_path / "run" / "control.sock")
    assert result["reason"] == "socket-absent"


def test_probe_rejects_symlink_and_wrong_owner(tmp_path: Path) -> None:
    path = tmp_path / "run" / "control.sock"
    path.parent.mkdir()
    path.symlink_to(tmp_path / "elsewhere")
    assert prov.probe_protocol_health(path)["reason"] == "socket-is-symlink"
    path.unlink()
    daemon = FakeDaemon(path)
    daemon.start()
    result = prov.probe_protocol_health(path, expected_uid=os.getuid() + 1)
    assert result["reason"] == "socket-owner-mismatch"
    result = prov.probe_protocol_health(path, expected_mode=0o644)
    assert result["reason"] == "socket-mode-mismatch"


def test_probe_rejects_stale_inode_and_refusal(tmp_path: Path) -> None:
    path = tmp_path / "run" / "control.sock"
    daemon = FakeDaemon(path)
    daemon.start()
    daemon.close_leave_stale_inode()
    assert prov.probe_protocol_health(path)["reason"] == "stale-socket-inode"
    refusing = FakeDaemon(tmp_path / "run2" / "control.sock", refuse_reason="peer-not-authorized")
    refusing.start()
    result = prov.probe_protocol_health(tmp_path / "run2" / "control.sock")
    assert result["healthy"] is False
    assert result["reason"] == "daemon-refused"
    assert "peer-not-authorized" in result["detail"]


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def test_health_probe_cli(tmp_path: Path, capsys) -> None:
    path = tmp_path / "run" / "control.sock"
    daemon = FakeDaemon(path)
    daemon.start()
    assert (
        prov.main(
            [
                "health-probe",
                "--socket",
                str(path),
                "--expected-contract-version",
                "1",
            ]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["healthy"] is True
    assert prov.main(["health-probe", "--socket", str(tmp_path / "none" / "x.sock")]) == 1


def test_health_probe_real_cli_stdout_parses_through_step_health(sim) -> None:
    """Regression for the alpha.6 stop-line defect (OD-2026-08-15-ALPHA6-
    HEALTHPROBE-CANDIDATE): the health-probe CLI emitted multi-line
    ``indent=2`` JSON while ``_step_health`` parses only the LAST stdout line,
    so every real probe was unparseable. The in-process SimHost mock fed the
    parser compact single-line JSON, hiding the mismatch. This test replaces
    ONLY the probe transport with the real CLI subprocess; ``_step_health``
    and its parse path run unmodified. It fails when the CLI emits multi-line
    JSON and passes on the compact emitter.
    """
    _accounts, host, runner, daemon = sim
    daemon.start()
    observed_stdouts: list[str] = []

    def real_probe(argv: list[str]) -> prov.Completed | None:
        if "health-probe" not in argv:
            return None
        cli = [str(item) for item in argv[argv.index("health-probe") :]]
        socket_index = cli.index("--socket") + 1
        cli[socket_index] = str(host.resolve(cli[socket_index]))
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "stateport_release.execution_host_provisioning",
                *cli,
            ],
            capture_output=True,
            text=True,
            env={
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "PYTHONPATH": prov._probe_pythonpath(),
            },
            timeout=60,
            check=False,
        )
        observed_stdouts.append(completed.stdout)
        return prov.Completed(completed.returncode, completed.stdout, completed.stderr)

    runner.fail_on = real_probe
    receipt = _apply(sim)
    assert receipt["result"] == "succeeded"
    assert receipt["health"]["status"] == "healthy"
    assert [probe["healthy"] for probe in receipt["health"]["probes"]] == [True, True]
    # Emitter-side transport contract: exactly one JSON line on stdout.
    assert len(observed_stdouts) == 2
    for stdout in observed_stdouts:
        lines = [line for line in stdout.splitlines() if line.strip()]
        assert len(lines) == 1
        assert json.loads(lines[0])["healthy"] is True


def test_emit_plan_cli_structural_only(tmp_path: Path, capsys) -> None:
    index_path = tmp_path / "release-index.json"
    index_path.write_text(json.dumps(fixtures.release_index()) + "\n", encoding="utf-8")
    assert prov.main(["emit-plan", "--release-index", str(index_path)]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["schema"] == "stateport.execution-host-provisioning/v2"
    assert "structural-only" in plan["verificationBasis"]


def test_apply_cli_requires_trust_pins(tmp_path: Path) -> None:
    index_path = tmp_path / "release-index.json"
    index_path.write_text(json.dumps(fixtures.release_index()) + "\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        prov.main(["apply", "--release-index", str(index_path)])
