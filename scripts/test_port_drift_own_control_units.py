"""Focused regression: a rerun must reproduce this release's OWN control-plane ports.

Measured defect (genuine Win11 25H2 + WSL2 guest, shipped Alpha.22 candidate,
the Alpha.22 qualification receipt of 2026-10-02):
``apiPort`` 18561 against ``manifestApiPort`` 18578.  The derivation is
deterministic, so for stateport-api:accepted:http on that exact signed payload
18561 is probe attempt 0 and 18578 is attempt 1: one probe step.

Mechanism: a partial failure left two installer invocations.  Invocation 1
derived 18561 and the root provisioning transaction started the control-plane
units on it.  Invocation 2 re-gathered the collision inventory, but
``_own_live_unit_ports`` scans only the invoking user's live Quadlet root while
the control-plane units live in root-owned mode-0700
``/var/lib/stateport-control/.config/containers/systemd``.  The release's own api
listener was therefore classified ``observed-host``, the probe stepped once, and
the staged materialization manifest recorded a port no unit publishes.

These tests pin the fix and, just as importantly, pin what must NOT change: a
genuinely foreign listener must still land in the collision inventory and must
still push the derivation off the port.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
from typing import Any, Sequence

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "packages/release-contracts/src"))

import install_no_checkout as installer  # noqa: E402

SIGNED_DIGEST = "sha256:" + hashlib.sha256(b"stateport-alpha-22-port-drift-fixture").hexdigest()
SIGNED_HEX = SIGNED_DIGEST.removeprefix("sha256:")
API_UNIT = "stateport-f544857680bc-accepted-657e423ad4aab69.container"
WEB_UNIT = "stateport-ae4a67f11969-accepted-456fa2e6dc0d9892a50020ea25808.container"
# Probe attempt 0 (the hashed port) and attempt 1 (one probeStep later) for
# stateport-api:accepted:http on the real Alpha.22 signed payload.
OWN_API_PORT = 18561
STEPPED_API_PORT = 18578


def _port_policy() -> dict[str, Any]:
    """The signed port policy, read from the real topology (no hardcoded copy)."""

    document = yaml.safe_load(
        (ROOT / "config/release-topology.v1.yaml").read_text(encoding="utf-8")
    )
    targets = [
        t for t in document["targets"] if "stateport-api" in [s["serviceId"] for s in t["services"]]
    ]
    assert len(targets) == 1, targets
    policy = targets[0]["runtimeDerivation"]["portPolicy"]
    assert policy["algorithm"] == "sha256-full-revision-service-port-modulo-probe-v1"
    return policy


def _unit_text(port: int, digest: str = SIGNED_DIGEST) -> str:
    return (
        "Label=io.stateport.release.signed-payload="
        f"{digest}\n"
        "Label=io.stateport.service.id=stateport-api\n"
        "Label=io.stateport.profile=accepted\n"
        f"PublishPort=127.0.0.1:{port}:8790\n"
    )


def _staged_manifest(state_root: Path, names: Sequence[str]) -> Path:
    path = state_root / "releases" / "staged" / SIGNED_HEX / "materialization.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "formatVersion": "stateport.quadlet-materialization/v2",
                "artifacts": [
                    {
                        "kind": "container",
                        "profile": "accepted",
                        "owner": "stateport-control",
                        "liveRelativePath": name,
                        "stagedPath": f"staged/{SIGNED_HEX}/{name}",
                    }
                    for name in names
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


class RecordingRunner:
    """Records every argv; answers ``sudo -n cat`` from a fixture dictionary."""

    def __init__(self, texts: dict[str, str] | None = None, *, failure: str = "denied") -> None:
        self.texts = texts or {}
        self.failure = failure
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv: Sequence[str], *, timeout: int) -> installer.Completed:
        call = tuple(str(item) for item in argv)
        self.calls.append(call)
        if call[:3] == ("sudo", "-n", "cat"):
            if self.failure == "raise-timeout":
                raise subprocess.TimeoutExpired(cmd=list(call), timeout=timeout)
            path = call[-1]
            if path in self.texts:
                return installer.Completed(0, self.texts[path], "")
            return installer.Completed(1, "", f"cat: {path}: Permission denied ({self.failure})")
        raise AssertionError(f"no other privileged call is permitted: {call}")


class _ProcNetProbe:
    """The exact /proc/net/tcp listen inventory the real probe returns."""

    def __init__(self, ports: Sequence[int]) -> None:
        self._ports = list(ports)

    def occupied_ports(self) -> list[int]:
        return sorted(self._ports)


def _inventory(
    probe_ports: Sequence[int],
    own_ports: set[int],
    release: Any,
) -> list[dict[str, Any]]:
    """The installer's own inventory loop (install_no_checkout.py:4161-4172)."""

    occupied: list[dict[str, Any]] = []
    for port in sorted(probe_ports):
        if port in own_ports:
            continue
        occupied.append(
            {
                "class": "observed-host",
                "port": port,
                "identityDigest": release.canonical_digest(
                    {"class": "observed-host", "port": port, "source": "proc-net-tcp-listen"}
                ),
            }
        )
    return occupied


def test_rerun_excludes_this_releases_own_control_plane_ports(tmp_path):
    """The measured defect: own api listener 18561 must not shift the derivation."""

    import stateport_release as release

    state_root = tmp_path / "state"
    control_root = tmp_path / "control-systemd"
    control_root.mkdir()
    unit_path = control_root / API_UNIT
    unit_path.write_text(_unit_text(OWN_API_PORT), encoding="utf-8")
    _staged_manifest(state_root, [API_UNIT])

    runner = RecordingRunner()  # the unit is directly readable in this fixture world
    own = installer._own_control_unit_ports(
        state_root, SIGNED_DIGEST, runner, control_root=control_root
    )

    assert own == {OWN_API_PORT}
    # The rerun sees 18561 bound (its own container) plus the two other services'
    # own ports.  With the exclusion the api candidate stays at attempt 0, so the
    # staged manifest names the port the started unit actually publishes.
    probe_ports = [OWN_API_PORT, 18947, 18241]
    occupied = _inventory(probe_ports, own, release)
    assert [item["port"] for item in occupied] == [18241, 18947]
    assert OWN_API_PORT not in {item["port"] for item in occupied}


def test_foreign_listener_is_still_a_collision_and_still_refuses(tmp_path):
    """The collision-refusal invariant must survive the fix untouched."""

    import stateport_release as release

    policy = _port_policy()
    range_start = int(policy["rangeStart"])
    span = int(policy["rangeEnd"]) - range_start + 1
    probe_step = int(policy["probeStep"])
    assert (probe_step, range_start, span) == (17, 18000, 1000)

    state_root = tmp_path / "state"
    control_root = tmp_path / "control-systemd"
    control_root.mkdir()
    (control_root / API_UNIT).write_text(_unit_text(OWN_API_PORT), encoding="utf-8")
    _staged_manifest(state_root, [API_UNIT])
    runner = RecordingRunner()
    own = installer._own_control_unit_ports(
        state_root, SIGNED_DIGEST, runner, control_root=control_root
    )

    # PART 1 - the invariant.  A foreign listener on a port no own unit
    # publishes is still observed-host, and the derivation still steps off it.
    foreign_only = STEPPED_API_PORT
    occupied = _inventory([foreign_only, 18947], own, release)
    assert [item["port"] for item in occupied] == [foreign_only, 18947]
    assert all(item["class"] == "observed-host" for item in occupied)

    # contract.py:1918-1934, verbatim arithmetic with the real policy values:
    # a service whose hashed port is the foreign listener never gets it.
    hashed = foreign_only  # seed % span for this service lands on the foreign port
    used = {item["port"] for item in occupied}
    selected, attempts = None, 0
    for attempt in range(int(policy["maximumAttempts"])):
        candidate = range_start + ((hashed - range_start) % span + attempt * probe_step) % span
        if candidate not in used:
            selected, attempts = candidate, attempt
            break
    assert selected == foreign_only + probe_step
    assert attempts == 1
    assert selected not in used

    # PART 2 - the residual the fix does NOT resolve, pinned so it stays
    # visible: a foreign squatter holding the port our OWN retained unit already
    # publishes.  The exclusion cannot tell the two apart, so the derivation
    # keeps its own port and the container start fails loudly instead of the
    # product silently moving to a port the user was never given.
    assert OWN_API_PORT in own
    assert _inventory([OWN_API_PORT], own, release) == []


def test_range_exhaustion_still_raises_rather_than_guessing(tmp_path):
    """When every probed port is taken the derivation still refuses."""

    import stateport_release as release
    from stateport_release.contract import ReleaseContractError

    policy = _port_policy()
    range_start, probe_step = int(policy["rangeStart"]), int(policy["probeStep"])
    span = int(policy["rangeEnd"]) - range_start + 1
    maximum_attempts = int(policy["maximumAttempts"])

    state_root = tmp_path / "state"
    control_root = tmp_path / "control-systemd"
    control_root.mkdir()
    (control_root / API_UNIT).write_text(_unit_text(OWN_API_PORT), encoding="utf-8")
    _staged_manifest(state_root, [API_UNIT])
    own = installer._own_control_unit_ports(
        state_root,
        SIGNED_DIGEST,
        RecordingRunner(),
        control_root=control_root,
    )
    # Every candidate port this service could ever reach is taken by a foreign
    # listener.  The only port the own-unit exclusion removes is the one our own
    # unit publishes, which is reachable at attempt 0.
    reachable = {
        range_start + ((OWN_API_PORT - range_start) + attempt * probe_step) % span
        for attempt in range(maximum_attempts)
    }
    occupied = _inventory(sorted(reachable | {18947}), own, release)
    used = {item["port"] for item in occupied}
    # The own-unit exclusion is the ONLY reason attempt 0 is free, so the loop
    # selects the port our own retained unit already publishes: the rerun
    # reproduces the retained allocation instead of stepping away from it.
    selected = None
    for attempt in range(maximum_attempts):
        candidate = range_start + ((OWN_API_PORT - range_start) + attempt * probe_step) % span
        if candidate not in used:
            selected = candidate
            break
    assert selected == OWN_API_PORT

    # And with that port genuinely gone too, the derivation refuses exactly as
    # contract.py:1930-1931 does: no port is ever guessed.
    with pytest.raises(ReleaseContractError):
        used |= {OWN_API_PORT}
        for attempt in range(maximum_attempts):
            candidate = range_start + ((OWN_API_PORT - range_start) + attempt * probe_step) % span
            if candidate not in used:
                raise AssertionError(f"unexpectedly selected {candidate}")
        raise ReleaseContractError("deterministic revision port range is exhausted")


def test_unreadable_control_root_falls_back_to_todays_inventory(tmp_path):
    """sudo -n refused, absent unit, missing manifest, no runner: no crash, no change."""

    import stateport_release as release

    state_root = tmp_path / "state"
    control_root = tmp_path / "control-systemd"
    control_root.mkdir()
    _staged_manifest(state_root, [API_UNIT])
    unit_path = control_root / API_UNIT  # exists, but only root may read it

    denied = RecordingRunner(failure="denied")
    assert (
        installer._own_control_unit_ports(
            state_root, SIGNED_DIGEST, denied, control_root=control_root
        )
        == set()
    )
    assert denied.calls == [("sudo", "-n", "cat", str(unit_path))]

    # Unreadable is never treated as free: the port stays a collision.
    occupied = _inventory([OWN_API_PORT], set(), release)
    assert [item["port"] for item in occupied] == [OWN_API_PORT]
    assert occupied[0]["identityDigest"] == release.canonical_digest(
        {"class": "observed-host", "port": OWN_API_PORT, "source": "proc-net-tcp-listen"}
    )

    # A privileged read that times out is contained, not fatal.
    timing_out = RecordingRunner(failure="raise-timeout")
    assert (
        installer._own_control_unit_ports(
            state_root, SIGNED_DIGEST, timing_out, control_root=control_root
        )
        == set()
    )

    # No runner at all (a caller that never had a subprocess seam).
    assert (
        installer._own_control_unit_ports(
            state_root, SIGNED_DIGEST, None, control_root=control_root
        )
        == set()
    )

    # No staged manifest: a first install has no retained units, so there is
    # nothing to exclude and today's inventory stands.
    empty = tmp_path / "empty-state"
    assert (
        installer._own_control_unit_ports(
            empty, SIGNED_DIGEST, RecordingRunner(), control_root=control_root
        )
        == set()
    )

    # A corrupt manifest is contained too.
    corrupt = state_root / "releases" / "staged" / SIGNED_HEX / "materialization.json"
    corrupt.write_text("{not json", encoding="utf-8")
    assert (
        installer._own_control_unit_ports(
            state_root, SIGNED_DIGEST, RecordingRunner(), control_root=control_root
        )
        == set()
    )


def test_only_this_releases_own_units_are_excluded(tmp_path):
    """A foreign release's control-plane unit keeps its ports in the inventory."""

    import stateport_release as release

    state_root = tmp_path / "state"
    control_root = tmp_path / "control-systemd"
    control_root.mkdir()
    other = "sha256:" + hashlib.sha256(b"some-other-release").hexdigest()
    (control_root / WEB_UNIT).write_text(_unit_text(18947, digest=other), encoding="utf-8")
    (control_root / API_UNIT).write_text(_unit_text(OWN_API_PORT), encoding="utf-8")
    _staged_manifest(state_root, [API_UNIT, WEB_UNIT])

    own = installer._own_control_unit_ports(
        state_root, SIGNED_DIGEST, RecordingRunner(), control_root=control_root
    )
    assert own == {OWN_API_PORT}
    occupied = _inventory([OWN_API_PORT, 18947], own, release)
    assert [item["port"] for item in occupied] == [18947]


def test_validation_profile_and_network_artifacts_are_ignored(tmp_path):
    """Only accepted control-owned container units can publish a host port."""

    state_root = tmp_path / "state"
    control_root = tmp_path / "control-systemd"
    control_root.mkdir()
    (control_root / API_UNIT).write_text(_unit_text(OWN_API_PORT), encoding="utf-8")
    path = state_root / "releases" / "staged" / SIGNED_HEX / "materialization.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "artifacts": [
                    {
                        "kind": "container",
                        "profile": "validation",
                        "owner": "stateport-control",
                        "liveRelativePath": API_UNIT,
                    },
                    {
                        "kind": "network",
                        "profile": "accepted",
                        "owner": "stateport-control",
                        "liveRelativePath": "stateport-999343ab.network",
                    },
                    {
                        "kind": "container",
                        "profile": "accepted",
                        "owner": "stateport-exec",
                        "liveRelativePath": "stateport-execution-host.container",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    runner = RecordingRunner()
    assert (
        installer._own_control_unit_ports(
            state_root, SIGNED_DIGEST, runner, control_root=control_root
        )
        == set()
    )
    assert runner.calls == []
