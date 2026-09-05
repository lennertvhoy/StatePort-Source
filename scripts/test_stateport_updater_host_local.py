"""Local Podman host driver coverage: real engine against a fake podman/systemd."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
for source in (
    ROOT,
    ROOT / "packages/release-contracts/src",
    ROOT / "packages/governed-runner/src",
    ROOT / "packages/updater/src",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from stateport_release import (  # noqa: E402
    canonical_digest,
    load_release_index,
    quadlet_bundle_digest,
    release_identity_from_verified,
    render_quadlet_bundle,
    revision_volume_key,
    to_updater_release_envelope,
    topology_digest,
    verify_release_index,
)
from stateport_updater import (  # noqa: E402
    UpdateEngine,
    UpdateError,
    UpdateHostError,
    UpdatePolicy,
    UpdateStore,
)
from stateport_updater.host_local import (  # noqa: E402
    Completed,
    FetchResult,
    LocalPodmanHost,
    _installation_volume_keys,
    _container_units,
    _require_provisioned_provider_home,
    _data_volume_name,
)
import stateport_updater.host_local as host_module
from stateport_release.contract import PROVIDER_HOME_CONTRACT
from stateport_updater.installed import InstalledAuthorityAdapter  # noqa: E402
from scripts.test_release_contracts import (  # noqa: E402
    _EphemeralTestVerifier,
    _pinned_key_signature,
    release_index,
)
from scripts.test_stateport_updater import (  # noqa: E402
    NOW,
    PINNED_POLICY,
    FixtureAuthority,
    OneShotCrash,
    SimulatedCrash,
    pinned_envelope,
    planned,
)


CURRENT_ID = "stateport-alpha-0.1.0-rc.1"
SUCCESSOR_ID = "stateport-alpha-0.2.0-rc.1"


@pytest.mark.parametrize("problem", ["missing", "symlink", "mode", "owner"])
def test_provider_home_preflight_refuses_before_any_runtime_effect(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, problem: str) -> None:
    fake_root = tmp_path / "host"
    home = fake_root / str(PROVIDER_HOME_CONTRACT["hostPath"]).lstrip("/")
    home.mkdir(parents=True, mode=0o700)
    home.parent.chmod(0o700)
    if problem == "missing":
        home.rmdir()
    elif problem == "symlink":
        home.rmdir()
        home.symlink_to(tmp_path, target_is_directory=True)
    elif problem == "mode":
        home.chmod(0o755)
    original_open, original_fstat = os.open, os.fstat
    monkeypatch.setattr(host_module.os, "open", lambda path, flags, **kwargs: original_open(fake_root if path == "/" else path, flags, **kwargs))
    def observed(fd):
        parts = list(original_fstat(fd))
        parts[4] = 65530 if problem == "owner" else 65531
        parts[5] = 65531
        return os.stat_result(parts)
    monkeypatch.setattr(host_module.os, "fstat", observed)
    runner = HostRunner()
    host = _local_host(tmp_path, runner)
    release = SimpleNamespace(verified=SimpleNamespace(target={"services": [{"providerHome": dict(PROVIDER_HOME_CONTRACT)}]}))
    with pytest.raises(UpdateHostError, match="signature-verified StatePort provisioner") as error:
        host.preflight(release)
    assert error.value.code == "provider_home_provisioning_required"
    assert runner.calls == []


def test_provider_home_preflight_reads_no_provider_files_and_legacy_needs_no_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_root = tmp_path / "host"
    home = fake_root / str(PROVIDER_HOME_CONTRACT["hostPath"]).lstrip("/")
    home.mkdir(parents=True, mode=0o700)
    home.parent.chmod(0o700)
    marker = home / "synthetic-provider-state"
    marker.write_text("not authentication data")
    marker.chmod(0)
    opened = []
    original_open, original_fstat = os.open, os.fstat
    def confined_open(path, flags, **kwargs):
        opened.append(str(path))
        return original_open(fake_root if path == "/" else path, flags, **kwargs)
    def observed(fd):
        parts = list(original_fstat(fd)); parts[4] = parts[5] = 65531
        return os.stat_result(parts)
    monkeypatch.setattr(host_module.os, "open", confined_open)
    monkeypatch.setattr(host_module.os, "fstat", observed)
    _require_provisioned_provider_home({"services": [{"providerHome": dict(PROVIDER_HOME_CONTRACT)}]})
    assert marker.name not in opened
    assert opened == ["/", "var", "lib", "stateport-control", "provider-auth", "codex"]
    opened.clear()
    _require_provisioned_provider_home({"services": [{}]})
    assert opened == []


def test_switch_rechecks_missing_provider_home_before_stopping_predecessor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runner = HostRunner()
    host = _local_host(tmp_path, runner)
    signed_hex = "a" * 64
    context = {"releaseId": SUCCESSOR_ID, "signedDigest": "sha256:" + signed_hex, "stagedDir": signed_hex}
    stage = host.root / "host-staged" / signed_hex
    stage.mkdir(parents=True)
    (stage / "materialization.json").write_text("{}")
    target = {"targetId": host.target_id, "services": [{"providerHome": dict(PROVIDER_HOME_CONTRACT)}]}
    index = SimpleNamespace(document={"signed": {"targets": [target]}})
    monkeypatch.setattr(host, "_context", lambda _: context)
    monkeypatch.setattr(host, "_completed_evidence", lambda *_: None)
    monkeypatch.setattr(host, "_release_index", lambda *_: index)
    monkeypatch.setattr(host, "_genesis_hex", lambda: "b" * 64)
    monkeypatch.setattr(host_module, "read_bytes", lambda *_: b'{}')
    fake_root = tmp_path / "empty-host"
    fake_root.mkdir()
    original_open = os.open
    monkeypatch.setattr(host_module.os, "open", lambda path, flags, **kwargs: original_open(fake_root if path == "/" else path, flags, **kwargs))
    with pytest.raises(UpdateHostError, match="signature-verified StatePort provisioner"):
        host.switch({"planDigest": "sha256:" + "c" * 64})
    assert runner.calls == []
VOLUME_KEY = "stateport-web:stateport-data"
SHARED_VOLUME_KEY = "stateport-shared:stateport-operations"
APPLY_STEPS = (
    "backup",
    "pull",
    "stage",
    "dry-run-migrations",
    "start-successor",
    "health-successor",
    "browser-successor",
    "studystate-successor",
    "state-check-successor",
    "switch",
    "health-accepted-route",
    "state-check-accepted-route",
    "retain-predecessor",
)


def _materializable_envelope(
    release_id: str, version: str, *, predecessor: Mapping[str, Any] | None
) -> tuple[Any, dict[str, Any], dict[str, Any]]:
    """``pinned_envelope`` whose Quadlet digest is re-derived after the id change.

    The shared fixture renames the release without recomputing the signed
    Quadlet template digest, which embeds the release id; materialization
    rejects that stale digest, so the local host needs the honest rebind.
    """

    _envelope, document, _identity = pinned_envelope(release_id, version, predecessor=predecessor)
    signed = document["signed"]
    for target in signed["targets"]:
        target["quadletBundleDigest"] = quadlet_bundle_digest(
            render_quadlet_bundle(target, signed["images"])
        )
        target["topologyDigest"] = topology_digest(target)
    document["signatures"] = [
        _pinned_key_signature(canonical_digest(signed), f"release-index-{release_id}")
    ]
    verified = verify_release_index(
        document, policy=PINNED_POLICY, verifier=_EphemeralTestVerifier()
    )
    return to_updater_release_envelope(verified), document, release_identity_from_verified(verified)


def _with_shared_operations(document: dict[str, Any]) -> None:
    signed = document["signed"]
    target = signed["targets"][0]
    web = target["services"][0]
    api = deepcopy(web)
    api.update({"serviceId": "stateport-api", "imageId": "stateport-api"})
    api["writableVolumes"][0].update(
        {"name": "stateport-operations", "mountPath": "/workspace/.stateport"}
    )
    worker = deepcopy(api)
    worker.update({"serviceId": "stateport-worker", "imageId": "stateport-worker"})
    target["services"].extend([api, worker])
    target["sharedWritableVolumes"] = [
        {
            "volumeKey": SHARED_VOLUME_KEY,
            "volumeName": "stateport-operations",
            "members": ["stateport-api", "stateport-worker"],
            "writerCoordination": "sqlite-immediate-and-posix-advisory-locks",
        }
    ]
    for image_id in ("stateport-api", "stateport-worker"):
        image = deepcopy(signed["images"][0])
        image.update(
            {"imageId": image_id, "reference": f"ghcr.io/stateport/{image_id}@{image['digest']}"}
        )
        signed["images"].append(image)


def test_shared_operations_volume_has_one_lifecycle_identity() -> None:
    document = release_index()
    _with_shared_operations(document)
    target = document["signed"]["targets"][0]
    assert {
        revision_volume_key(target, str(service["serviceId"]), str(volume["name"]))
        for service in target["services"]
        for volume in service["writableVolumes"]
        if volume["name"] == "stateport-operations"
    } == {SHARED_VOLUME_KEY}
    assert _installation_volume_keys(target, snapshot_required=True) == [
        SHARED_VOLUME_KEY,
        VOLUME_KEY,
    ]


class HostRunner:
    """Exact fake for the podman/systemd subprocess seam."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.volumes: set[str] = set()
        self.active_units: set[str] = set()
        self.image_digest_override: str | None = None
        self.fail_starts = False

    def run(self, argv: Sequence[str], *, timeout: int) -> Completed:
        del timeout
        call = tuple(argv)
        self.calls.append(call)
        if call[:2] == ("podman", "version"):
            return Completed(0, "Client: 5.4.0\n", "")
        if call[:2] == ("podman", "pull"):
            return Completed(0, "", "")
        if call[:3] == ("podman", "image", "inspect"):
            reference = call[-1]
            digest = self.image_digest_override or reference.rsplit("@", 1)[-1]
            return Completed(0, f"{digest}\n", "")
        if call[:3] == ("podman", "volume", "exists"):
            return Completed(0 if call[3] in self.volumes else 1, "", "")
        if call[:3] == ("podman", "volume", "create"):
            self.volumes.add(call[3])
            return Completed(0, "", "")
        if call[:3] in {("podman", "volume", "export"), ("podman", "volume", "import")}:
            if call[3] not in self.volumes:
                return Completed(1, "", "no such volume")
            return Completed(0, "", "")
        if call[:3] == ("podman", "volume", "rm"):
            self.volumes.discard(call[3])
            return Completed(0, "", "")
        if call[:2] == ("podman", "inspect"):
            container = call[-1]
            running = container in self.active_units
            return Completed(0, f"{'running' if running else 'exited'}\n", "")
        if call[:2] == ("podman", "rm"):
            return Completed(0, "", "")
        if call[:3] == ("systemctl", "--user", "show"):
            return Completed(0, "255\n", "")
        if call[:2] == ("loginctl", "show-user"):
            return Completed(0, "yes\n", "")
        if call[:3] == ("systemctl", "--user", "daemon-reload"):
            return Completed(0, "", "")
        if call[:3] == ("systemctl", "--user", "enable"):
            return Completed(0, "", "")
        if call[:3] == ("systemctl", "--user", "stop"):
            self.active_units.discard(call[3])
            return Completed(0, "", "")
        if call[:3] == ("systemctl", "--user", "start"):
            if self.fail_starts:
                return Completed(1, "", "start refused by fixture")
            self.active_units.add(call[3])
            return Completed(0, "", "")
        if call[:3] == ("systemctl", "--user", "is-active"):
            active = call[3] in self.active_units
            return Completed(0 if active else 3, f"{'active' if active else 'inactive'}\n", "")
        raise AssertionError(f"unexpected subprocess argv: {call}")


class LoopbackFetcher:
    def fetch(self, url: str, *, timeout: float, max_bytes: int) -> FetchResult:
        del timeout, max_bytes
        assert url.startswith("http://127.0.0.1:")
        return FetchResult(200, b'{"status":"ok"}')


def _store_root(tmp_path: Path) -> Path:
    return tmp_path / "updater"


def _local_host(
    tmp_path: Path, runner: HostRunner, *, quadlet_root: Path | None = None
) -> LocalPodmanHost:
    root = quadlet_root or (tmp_path / "quadlets")
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o700)
    return LocalPodmanHost(
        _store_root(tmp_path),
        runner=runner,
        fetcher=LoopbackFetcher(),
        clock=lambda: NOW,
        quadlet_root=root,
    )


def _installed_engine(
    tmp_path: Path,
    *,
    runner: HostRunner | None = None,
    failpoint: Any | None = None,
) -> tuple[UpdateEngine, HostRunner, FixtureAuthority, Any, Any]:
    """Engine + local host on the installer genesis layout (r1 installed)."""

    selected_runner = runner or HostRunner()
    authority = FixtureAuthority()
    host = _local_host(tmp_path, selected_runner)
    current, _document, current_identity = _materializable_envelope(
        CURRENT_ID, "0.1.0-rc.1", predecessor=None
    )
    successor, successor_document, _successor_identity = _materializable_envelope(
        SUCCESSOR_ID, "0.2.0-rc.1", predecessor=current_identity
    )
    engine = UpdateEngine(
        UpdateStore.create(_store_root(tmp_path)),
        host,
        authority,
        verification_policy=PINNED_POLICY,
        signature_verifier=_EphemeralTestVerifier(),
        clock=lambda: NOW,
        failpoint=failpoint,
    )
    engine.initialize(current, UpdatePolicy(mode="download-and-notify", channel="alpha"))
    InstalledAuthorityAdapter.install(
        UpdateStore.open_existing(_store_root(tmp_path)),
        installer_digest="sha256:" + "0" * 64,
        installer_origin="https://stateport.invalid/installer/no-checkout",
        installer_version="0.1.0",
        actor_id="stateport-installer",
        clock=lambda: NOW,
    )
    # Genesis truth the installer would have left behind: the current accepted
    # route is running and its installation data volume exists.
    index = load_release_index(
        (_store_root(tmp_path) / "releases" / f"{CURRENT_ID}.release-index.json").read_bytes()
    )
    selected_runner.active_units.update(_container_units(index, "accepted").values())
    genesis_hex = current_identity["signedPayloadDigest"].removeprefix("sha256:")
    selected_runner.volumes.add(_data_volume_name(genesis_hex, VOLUME_KEY))
    return engine, selected_runner, authority, successor, successor_document


def _reopened_engine(
    tmp_path: Path, runner: HostRunner, authority: FixtureAuthority
) -> UpdateEngine:
    return UpdateEngine(
        UpdateStore.open_existing(_store_root(tmp_path)),
        _local_host(tmp_path, runner),
        authority,
        verification_policy=PINNED_POLICY,
        signature_verifier=_EphemeralTestVerifier(),
        clock=lambda: NOW,
    )


def _facts(engine: UpdateEngine, envelope: Any) -> Any:
    return engine._facts(envelope, channel="alpha")


def test_health_sweep_gives_each_service_a_full_budget(tmp_path: Path) -> None:
    """F9: updater health sweeps run over strictly-serial services; one shared
    deadline across the set starves the later services."""
    host = _local_host(tmp_path, HostRunner())
    state = {"now": NOW}
    host.clock = lambda: state["now"]
    host.health_timeout_seconds = 5.0
    host.health_poll_seconds = 0.01
    calls: dict[str, int] = {}

    class SlowFetcher:
        def fetch(self, url: str, *, timeout: float, max_bytes: int) -> FetchResult:
            service = "api" if ":19000" in url else "web"
            calls[service] = calls.get(service, 0) + 1
            if calls[service] >= 3:  # two 2s stalls, then healthy
                return FetchResult(200, b"ok")
            state["now"] += timedelta(seconds=2.0)
            return FetchResult(0, b"")

    host.fetcher = SlowFetcher()
    services = [
        {
            "serviceId": "api",
            "health": {"kind": "http", "containerPort": 9000, "path": "/readyz"},
            "ports": [{"containerPort": 9000, "name": "http"}],
        },
        {
            "serviceId": "web",
            "health": {"kind": "http", "containerPort": 8080, "path": "/health"},
            "ports": [{"containerPort": 8080, "name": "http"}],
        },
    ]
    host._health_sweep(
        services,
        {"api": {"http": 19000}, "web": {"http": 18080}},
        {"api": "stateport-api", "web": "stateport-web"},
        code="update_health_timeout",
        effect="none",
    )
    # Together the services consumed 8s — beyond one shared 5s budget — yet
    # each individually stayed within its own 5s budget.
    assert calls == {"api": 3, "web": 3}
    assert state["now"] == NOW + timedelta(seconds=8.0)


def test_full_apply_drives_podman_systemd_and_persists_effect_receipts(
    tmp_path: Path,
) -> None:
    engine, runner, authority, successor, _document = _installed_engine(tmp_path)
    plan, authorization = planned(engine, authority, successor)

    receipt = engine.apply(plan["planId"], authorization)

    assert receipt["result"] == "accepted"
    status = engine.status()
    assert status["current"]["releaseId"] == SUCCESSOR_ID
    assert status["retainedPredecessor"]["releaseId"] == CURRENT_ID

    # Every effectful step persisted its create-only receipt before returning.
    effects = _store_root(tmp_path) / "host-effects" / plan["planDigest"].removeprefix("sha256:")
    for step in APPLY_STEPS:
        record = json.loads((effects / f"{step}.json").read_text(encoding="utf-8"))
        assert record["schema"] == "stateport.update-host-effect-receipt/v1"
        assert record["planDigest"] == plan["planDigest"]
        assert record["step"] == step
        assert record["evidenceDigest"] == canonical_digest(record["evidence"])

    # The backup genuinely quiesced, exported, and restored the accepted route.
    stops = [call for call in runner.calls if call[:3] == ("systemctl", "--user", "stop")]
    exports = [call for call in runner.calls if call[:3] == ("podman", "volume", "export")]
    imports = [call for call in runner.calls if call[:3] == ("podman", "volume", "import")]
    assert exports and imports
    first_export = runner.calls.index(exports[0])
    assert any(runner.calls.index(call) < first_export for call in stops)
    snapshot_volumes = [call[3] for call in imports]
    assert all(name.startswith("stateport-s") for name in snapshot_volumes)

    # Pulls resolved to the exact signed digest and units went live.
    pulls = [call for call in runner.calls if call[:2] == ("podman", "pull")]
    assert pulls and all("@sha256:" in call[-1] for call in pulls)
    live_units = {path.name for path in (tmp_path / "quadlets").glob("*.container")}
    assert any("-validation-" in name for name in live_units)
    accepted_units = {name for name in live_units if "-accepted-" in name}
    assert accepted_units
    assert all(name.removesuffix(".container") in runner.active_units for name in accepted_units)
    # Validation units were stopped after the switch.
    validation_units = {name for name in live_units if "-validation-" in name}
    assert not any(
        name.removesuffix(".container") in runner.active_units for name in validation_units
    )
    # The staged tree and its plan-independent marker are durable.
    markers = list((_store_root(tmp_path) / "host-staged").glob("*/marker.json"))
    assert len(markers) == 1
    marker = json.loads(markers[0].read_text(encoding="utf-8"))
    assert marker["releaseId"] == SUCCESSOR_ID

    # Host observation binds the exact accepted runtime identity.
    observation = engine.host.observe_accepted_revision()
    assert observation["releaseId"] == SUCCESSOR_ID
    assert observation["runtimeDigest"] == _facts(engine, successor).expected_revision_digest()


def test_interrupted_switch_reconciles_through_durable_host_receipts(
    tmp_path: Path,
) -> None:
    engine, runner, authority, successor, _document = _installed_engine(
        tmp_path, failpoint=OneShotCrash("after_journal_switch")
    )
    plan, authorization = planned(engine, authority, successor)
    with pytest.raises(SimulatedCrash):
        engine.apply(plan["planId"], authorization)

    recovered = _reopened_engine(tmp_path, runner, authority)
    receipt = recovered.reconcile()

    assert receipt["result"] == "accepted"
    assert recovered.status()["current"]["releaseId"] == SUCCESSOR_ID
    # The switch effect converged from its durable receipt; it was not replayed.
    accepted = {
        path.name.removesuffix(".container")
        for path in (tmp_path / "quadlets").glob("*-accepted-*.container")
    }
    assert accepted
    starts = [
        call
        for call in runner.calls
        if call[:3] == ("systemctl", "--user", "start") and call[3] in accepted
    ]
    assert len(starts) == len(accepted)
    assert not (_store_root(tmp_path) / "pending.json").exists()


def test_rollback_restores_the_retained_predecessor(tmp_path: Path) -> None:
    engine, runner, authority, successor, _document = _installed_engine(tmp_path)
    plan, authorization = planned(engine, authority, successor)
    assert engine.apply(plan["planId"], authorization)["result"] == "accepted"

    engine = _reopened_engine(tmp_path, runner, authority)
    rollback = engine.plan(operation="rollback")
    receipt = engine.apply(rollback["planId"], authority.reserve(rollback))

    assert receipt["operation"] == "rollback"
    assert receipt["accepted"]["releaseId"] == CURRENT_ID
    assert engine.status()["current"]["releaseId"] == CURRENT_ID
    observation = engine.host.observe_accepted_revision()
    assert observation["releaseId"] == CURRENT_ID
    # Both releases stay staged and retained for evidence.
    markers = list((_store_root(tmp_path) / "host-staged").glob("*/marker.json"))
    assert len(markers) == 2


def test_pull_digest_mismatch_refuses_before_any_switch(tmp_path: Path) -> None:
    runner = HostRunner()
    runner.image_digest_override = "sha256:" + "9" * 64
    engine, runner, authority, successor, _document = _installed_engine(tmp_path, runner=runner)
    plan, authorization = planned(engine, authority, successor)

    with pytest.raises(UpdateError) as failure:
        engine.apply(plan["planId"], authorization)

    assert failure.value.code == "reconciliation_required"
    assert engine.status()["current"]["releaseId"] == CURRENT_ID
    effects = _store_root(tmp_path) / "host-effects" / plan["planDigest"].removeprefix("sha256:")
    assert not (effects / "pull.json").exists()
    assert not any((tmp_path / "quadlets").glob("*.container"))


def test_stage_converges_to_identical_evidence_for_the_exact_plan(tmp_path: Path) -> None:
    engine, _runner, authority, successor, _document = _installed_engine(tmp_path)
    plan, _authorization = planned(engine, authority, successor)
    host = engine.host
    facts = _facts(engine, successor)

    host.backup(plan)
    first = host.stage(plan, facts)
    second = host.stage(plan, facts)

    assert first == second
    staged_dirs = list((_store_root(tmp_path) / "host-staged").iterdir())
    assert len(staged_dirs) == 1


def test_backup_restore_failure_is_an_unknown_effect(tmp_path: Path) -> None:
    runner = HostRunner()
    engine, _runner, authority, successor, _document = _installed_engine(tmp_path, runner=runner)
    plan, _authorization = planned(engine, authority, successor)
    runner.fail_starts = True

    with pytest.raises(UpdateHostError) as failure:
        engine.host.backup(plan)

    assert failure.value.code == "backup_restore_failed"
    assert failure.value.effect == "unknown"
    # The backup receipt was never persisted; the plan step did not happen.
    effects = _store_root(tmp_path) / "host-effects" / plan["planDigest"].removeprefix("sha256:")
    assert not (effects / "backup.json").exists()


def test_observe_effect_receipt_missing_and_conflict(tmp_path: Path) -> None:
    runner = HostRunner()
    host = _local_host(tmp_path, runner)
    plan_digest = "sha256:" + "0" * 64

    with pytest.raises(UpdateHostError) as missing:
        host.observe_effect_receipt(plan_digest=plan_digest, step="backup")
    assert missing.value.code == "effect_receipt_missing"

    evidence: Mapping[str, Any] = {
        "schema": "stateport.update-host-backup/v1",
        "planDigest": plan_digest,
        "receiptId": "backup_fixture",
        "backupDigest": "sha256:" + "b" * 64,
    }
    host._record_effect(plan_digest, "backup", evidence)
    observed = host.observe_effect_receipt(plan_digest=plan_digest, step="backup")
    assert observed["evidence"] == dict(evidence)

    tampered = dict(evidence, backupDigest="sha256:" + "c" * 64)
    with pytest.raises(UpdateHostError) as conflict:
        host._record_effect(plan_digest, "backup", tampered)
    assert conflict.value.code == "effect_receipt_conflict"

    effects = _store_root(tmp_path) / "host-effects" / plan_digest.removeprefix("sha256:")
    receipt_file = effects / "backup.json"
    payload = json.loads(receipt_file.read_text(encoding="utf-8"))
    payload["evidence"] = tampered
    receipt_file.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(UpdateHostError) as invalid:
        host.observe_effect_receipt(plan_digest=plan_digest, step="backup")
    assert invalid.value.code == "effect_receipt_invalid"
