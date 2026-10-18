#!/usr/bin/env python3
"""The root helper must not install caller-supplied Quadlet bytes unverified (audit S1-06).

``provision --plan`` reads ``controlPlaneMaterialization`` from a user-writable
plan file and the root transaction installs those bytes as the control user's
Quadlet units.  The old "divergence" check compared the plan's ``planDigest``
with a digest recomputed from the SAME plan content, so a consistently edited
plan always passed.  The unit bytes must instead be checked against the signed
Quadlet templates (whose digest the verified release index pins) before any
privileged write.  These tests drive the real ``provision`` CLI path with the
release verification and the privileged transaction replaced by seams, and use
the installer's own derivation as the source of genuine unit bytes.
"""

from __future__ import annotations

import base64
import datetime
import json
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
for part in (
    "scripts",
    "packages/release-contracts/src",
    "packages/execution-host/src",
    "packages/runtime-contracts/src",
):
    sys.path.insert(0, str(ROOT / part))

import install_no_checkout as installer  # noqa: E402
import stateport_release  # noqa: E402
import test_provision_execution_host as provision_fixtures  # noqa: E402
from stateport_release import execution_host_provisioning as prov  # noqa: E402

CLIENT = ("tester", 1000, 1000)


def _genuine_units(verified) -> dict[str, bytes]:
    return installer._derive_control_plane_materialization(  # noqa: SLF001
        release=stateport_release,
        verified=verified,
        index=verified.index,
        target=verified.target,
        images=verified.index.document["signed"]["images"],
        plan_digest="sha256:" + "11" * 32,
        host_identity_digest="sha256:" + "22" * 32,
        collision_digests={
            name: "sha256:" + "44" * 32
            for name in ("current", "predecessor", "candidate", "observedHost")
        },
        occupied=[],
        state_root=Path("/nonexistent"),
        clock=lambda: datetime.datetime(2026, 8, 9, tzinfo=datetime.timezone.utc),
    )


class _Harness:
    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.verified = provision_fixtures._verified()  # noqa: SLF001
        self.tmp_path = tmp_path
        self.applied: list[dict[str, Any]] = []
        monkeypatch.setenv("STATEPORT_ROOT_HELPER", "1")
        monkeypatch.setattr(prov, "_verify_cli", lambda args: self.verified)
        monkeypatch.setattr(prov, "resolve_client_identity", lambda: CLIENT)

        def fake_apply(verified, **kwargs):
            self.applied.append(kwargs)
            return {"result": "succeeded"}

        monkeypatch.setattr(prov, "apply_verified_plan", fake_apply)

    def provision(
        self,
        units: dict[str, bytes],
        environment: dict[str, str] | None = None,
    ) -> int:
        # The plan is rendered exactly as the installer renders it, so its
        # planDigest is internally consistent even when the units are forged.
        plan = prov.render_provisioning_plan(
            self.verified.target,
            self.verified.index.document["signed"]["images"],
            verification_basis="signature-verified-install",
            client_user=CLIENT[0],
            client_uid=CLIENT[1],
            client_gid=CLIENT[2],
            control_plane_materialization=units,
            control_plane_environment=environment,
        )
        plan_path = self.tmp_path / "plan.json"
        plan_path.write_text(json.dumps(plan), encoding="utf-8")
        return prov.main(
            [
                "provision",
                "--release-index", str(self.tmp_path / "release-index.json"),
                "--cosign", "/x", "--trust-public-key", "/x",
                "--trust-key-id", "k", "--trust-key-fingerprint", "f",
                "--bundle-root", str(self.tmp_path),
                "--plan", str(plan_path),
                "--receipt-out", str(self.tmp_path / "receipt.json"),
            ]
        )


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> _Harness:
    return _Harness(tmp_path, monkeypatch)


def _container_key(units: dict[str, bytes]) -> str:
    return next(key for key in units if key.endswith(".container"))


def test_genuine_installer_units_are_accepted(harness: _Harness) -> None:
    units = _genuine_units(harness.verified)
    assert harness.provision(units) == 0
    assert len(harness.applied) == 1
    assert harness.applied[0]["control_plane_materialization"] == units


def test_genuine_units_with_other_host_ports_are_accepted(harness: _Harness) -> None:
    """Ports are chosen from the host's occupied set, so they legitimately vary."""
    units = _genuine_units(harness.verified)
    key = _container_key(units)
    text = units[key].decode()
    assert text.count("18343") == 2  # PublishPort and STATEPORT_EXTERNAL_LOOPBACK_PORT
    units[key] = text.replace("18343", "18344").encode()
    assert harness.provision(units) == 0


def test_inconsistent_or_out_of_range_ports_are_refused(harness: _Harness) -> None:
    units = _genuine_units(harness.verified)
    key = _container_key(units)
    text = units[key].decode()
    # One signed port token is one value: the two uses must agree.
    units[key] = text.replace("STATEPORT_EXTERNAL_LOOPBACK_PORT=18343", "STATEPORT_EXTERNAL_LOOPBACK_PORT=18344").encode()
    assert harness.provision(units) == 2
    # And the value must lie inside the signed port policy range.
    units[key] = text.replace("18343", "22").encode()
    assert harness.provision(units) == 2
    assert harness.applied == []


@pytest.mark.parametrize(
    "tamper",
    [
        pytest.param(lambda t: t.replace("User=65532", "User=0"), id="user-root"),
        pytest.param(lambda t: t.replace("Pull=never", "Pull=never\nVolume=/:/host:rw"), id="host-volume"),
        pytest.param(lambda t: t.replace("[Container]", "[Container]\nPodmanArgs=--privileged"), id="privileged"),
        pytest.param(lambda t: t.replace("Image=ghcr.io/stateport/", "Image=evil.example/"), id="image"),
        pytest.param(lambda t: t + "\nExecStartPre=/bin/sh -c id\n", id="appended-line"),
    ],
)
def test_tampered_unit_bytes_are_refused_even_with_a_consistent_plan_digest(
    harness: _Harness, tamper, capsys: pytest.CaptureFixture[str]
) -> None:
    units = _genuine_units(harness.verified)
    key = _container_key(units)
    changed = tamper(units[key].decode())
    assert changed != units[key].decode()
    units[key] = changed.encode()
    assert harness.provision(units) == 2
    assert harness.applied == [], "tampered unit bytes reached the privileged transaction"
    assert "signed Quadlet template" in capsys.readouterr().err


def test_extra_or_missing_units_are_refused(harness: _Harness, capsys: pytest.CaptureFixture[str]) -> None:
    units = _genuine_units(harness.verified)
    extra = dict(units)
    prefix = _container_key(units).rsplit("/", 1)[0]
    extra[prefix + "/rogue.container"] = b"[Container]\nContainerName=stateport-rogue\nImage=evil\n"
    assert harness.provision(extra) == 2
    missing = dict(units)
    missing.pop(_container_key(units))
    assert harness.provision(missing) == 2
    assert harness.applied == []


def test_environment_cannot_inject_unit_lines(harness: _Harness) -> None:
    units = _genuine_units(harness.verified)
    assert harness.provision(units, {"stateport-web.STATEPORT_OK": "fine value"}) == 0
    harness.applied.clear()
    assert harness.provision(units, {'stateport-web.X"\nImage=evil\n#': "v"}) == 2
    assert harness.provision(units, {"stateport-web.GOOD": "a\nImage=evil"}) == 2
    assert harness.applied == []


def test_volume_name_formula_matches_the_installer() -> None:
    from stateport_release.contract import accepted_data_volume_name

    signed_hex = "ab" * 32
    assert accepted_data_volume_name(signed_hex, "svc:vol") == installer._volume_names(signed_hex, "svc:vol")[0]  # noqa: SLF001
