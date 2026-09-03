"""Installed-authority adapter and updater CLI control-plane seam tests."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import inspect
import json
import os
from pathlib import Path
import shutil
import sys
from typing import Any, Callable, Mapping

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
    load_release_index_file,
    to_updater_release_envelope,
    validate_update_authority_link,
    validate_update_receipt,
    validate_update_status,
    validate_release_index,
    verify_release_index,
)
from stateport_release.cosign import (  # noqa: E402
    bundle_slot,
    retain_bundle,
    signature_bundle_name,
)
from stateport_updater import (
    UpdateEngine,
    UpdateError,
    UpdatePolicy,
    UpdateStore,
)  # noqa: E402
from stateport_updater.authority import UpdateAuthorityError, _validate_receipt  # noqa: E402
from stateport_updater.cli import main  # noqa: E402
from stateport_updater.engine import TARGET_ID  # noqa: E402
from stateport_updater.installed import (  # noqa: E402
    AUTHORIZATION_BUNDLE_SCHEMA,
    IDENTITY_SCHEMA,
    ControlPlaneBinding,
    InstalledAuthorityAdapter,
)
from scripts.test_stateport_updater import (  # noqa: E402
    NOW,
    POLICY,
    FixtureAuthority,
    FixtureHost,
    OneShotCrash,
    SimulatedCrash,
    _EphemeralTestVerifier,
    initialized_engine,
    initialized_pinned_engine,
)
from scripts.test_release_contracts import (  # noqa: E402
    _signature,
    release_index,
    topology_digest,
)


INSTALLER_DIGEST = "sha256:" + "0" * 64
INSTALLER_ORIGIN = "https://github.com/stateport/stateport-installer.git"
INSTALLER_VERSION = "0.1.0"
INSTALLER_ACTOR = "stateport-installer"
UPDATER_ROOT = "updater"


def inject(tmp_path: Path) -> dict[str, Any]:
    store = UpdateStore.open_existing(tmp_path / UPDATER_ROOT)
    return InstalledAuthorityAdapter.install(
        store,
        installer_digest=INSTALLER_DIGEST,
        installer_origin=INSTALLER_ORIGIN,
        installer_version=INSTALLER_VERSION,
        actor_id=INSTALLER_ACTOR,
        clock=lambda: NOW,
    )


def adapter_engine(
    tmp_path: Path,
    host: FixtureHost,
    *,
    failpoint: Callable[[str], None] | None = None,
) -> tuple[UpdateEngine, InstalledAuthorityAdapter]:
    store = UpdateStore.open_existing(tmp_path / UPDATER_ROOT)
    adapter = InstalledAuthorityAdapter(store, clock=lambda: NOW)
    engine = UpdateEngine(
        store,
        host,
        adapter,
        verification_policy=POLICY,
        signature_verifier=_EphemeralTestVerifier(),
        clock=lambda: NOW,
        failpoint=failpoint,
    )
    return engine, adapter


def binding(host: FixtureHost) -> ControlPlaneBinding:
    return ControlPlaneBinding(
        host=host,
        signature_verifier=_EphemeralTestVerifier(),
        verification_policy=POLICY,
        clock=lambda: NOW,
        transport_verifier_factory=lambda _root: _EphemeralTestVerifier(),
    )


def cli_args(tmp_path: Path, *argv: str) -> list[str]:
    return ["--state-root", str(tmp_path / UPDATER_ROOT), *argv]


def payload(capsysbinary: pytest.CaptureFixture[bytes]) -> Any:
    return json.loads(capsysbinary.readouterr().out)


def test_install_injects_genesis_identity_from_durable_truth(tmp_path: Path) -> None:
    updater, _host, _authority, _successor, _document = initialized_engine(tmp_path)
    record = inject(tmp_path)
    store = UpdateStore.open_existing(tmp_path / UPDATER_ROOT)
    status = updater.status()
    native = os.lstat(store.root)

    assert record["schema"] == IDENTITY_SCHEMA
    assert record["installationId"] == store.installation_id
    assert record["releaseId"] == status["current"]["releaseId"]
    assert record["version"] == status["current"]["version"]
    assert record["signedPayloadDigest"] == status["current"]["signedPayloadDigest"]
    assert record["targetId"] == TARGET_ID
    assert record["channel"] == "alpha"
    assert "stateRootDevice" not in record
    assert record["stateRootInode"] == int(native.st_ino)
    assert record["installerDigest"] == INSTALLER_DIGEST
    assert record["installerOrigin"] == INSTALLER_ORIGIN
    assert record["installerVersion"] == INSTALLER_VERSION
    assert record["actorId"] == INSTALLER_ACTOR
    assert record["predecessorReleaseId"] is None
    assert record["predecessorSignedPayloadDigest"] is None
    assert record["predecessorIdentityDigest"] is None
    body = {
        key: value for key, value in record.items() if key not in {"identityId", "identityDigest"}
    }
    assert canonical_digest(body) == record["identityDigest"]
    assert record["identityId"] == (
        f"installed_identity_{record['identityDigest'].removeprefix('sha256:')[:32]}"
    )
    admission = json.loads(
        next((tmp_path / UPDATER_ROOT / "release-admissions").glob("*.json")).read_text()
    )
    assert record["releaseIndexDigest"] == admission["releaseIndexDigest"]

    adapter = InstalledAuthorityAdapter(store, clock=lambda: NOW)
    identity_files = list(adapter.identity_dir.glob("*.json"))
    assert len(identity_files) == 1
    assert identity_files[0].stat().st_mode & 0o777 == 0o600
    assert adapter._current_identity() == record


def test_install_refuses_before_durable_status(tmp_path: Path) -> None:
    UpdateStore.create(tmp_path / UPDATER_ROOT)
    with pytest.raises(UpdateAuthorityError) as failure:
        inject(tmp_path)
    assert failure.value.code == "installed_status_missing"
    assert not (tmp_path / UPDATER_ROOT / "installed-authority").exists()


def test_install_injects_genesis_identity_for_pinned_admission(tmp_path: Path) -> None:
    initialized_pinned_engine(tmp_path)
    record = inject(tmp_path)
    admission = json.loads(
        next((tmp_path / UPDATER_ROOT / "release-admissions").glob("*.json")).read_text()
    )
    assert admission["trustMode"] == "pinned-public-key"
    assert record["releaseId"] == admission["releaseId"]
    assert record["releaseIndexDigest"] == admission["releaseIndexDigest"]
    assert record["signedPayloadDigest"] == admission["signedPayloadDigest"]


def test_install_refuses_second_injection(tmp_path: Path) -> None:
    initialized_engine(tmp_path)
    inject(tmp_path)
    with pytest.raises(UpdateAuthorityError) as failure:
        inject(tmp_path)
    assert failure.value.code == "installed_identity_exists"
    adapter = InstalledAuthorityAdapter(UpdateStore.open_existing(tmp_path / UPDATER_ROOT))
    assert len(list(adapter.identity_dir.glob("*.json"))) == 1


def test_installed_update_roundtrip_advances_identity_chain(tmp_path: Path) -> None:
    _updater, host, _authority, successor, _document = initialized_engine(tmp_path)
    store = UpdateStore.open_existing(tmp_path / UPDATER_ROOT)
    genesis = inject(tmp_path)
    engine, adapter = adapter_engine(tmp_path, host)

    plan = engine.plan(successor)
    authorization = adapter.reserve(plan)
    decision = authorization["decision"]
    assert decision["action"] == "apply_update"
    assert decision["actorId"] == INSTALLER_ACTOR
    assert decision["authorizedBy"] == {
        "type": "grant",
        "id": f"grant_installed_{store.installation_id}",
        "digest": genesis["identityDigest"],
    }
    assert decision["scope"] == {
        "repository": {
            "origin": INSTALLER_ORIGIN,
            "repositoryKey": store.installation_id,
            "repositoryRoot": str(store.root),
        },
        "branch": None,
        "sliceId": None,
        "applicationId": "stateport",
        "runId": plan["planDigest"],
        "paths": [str(store.root)],
    }
    assert decision["profile"] == "balanced"
    assert decision["configuredPolicy"] == decision["policy"] == "auto_with_receipt"

    receipt = engine.apply(plan["planId"], authorization)
    assert validate_update_receipt(receipt).document["result"] == "accepted"
    status = validate_update_status(engine.status()).document
    assert status["current"]["releaseId"].endswith("0.2.0-rc.1")

    head = adapter._current_identity()
    assert head["releaseId"] == status["current"]["releaseId"]
    assert head["signedPayloadDigest"] == status["current"]["signedPayloadDigest"]
    assert head["predecessorReleaseId"] == genesis["releaseId"]
    assert head["predecessorSignedPayloadDigest"] == genesis["signedPayloadDigest"]
    assert head["predecessorIdentityDigest"] == genesis["identityDigest"]
    assert head["releaseIndexDigest"] == receipt["releaseIndexDigest"]
    assert len(list(adapter.identity_dir.glob("*.json"))) == 2

    request_id = decision["requestId"]
    assert adapter.recover_claim(request_id) is not None
    terminal = adapter.terminal_receipt(request_id)
    assert terminal is not None
    _validate_receipt(terminal)
    assert terminal["result"] == {
        "status": "succeeded",
        "code": None,
        "summary": "StatePort accepted the exact verified successor",
        "resource": terminal["result"]["resource"],
    }
    assert terminal["authorizedBy"]["digest"] == genesis["identityDigest"]
    record = json.loads((adapter.reservations_dir / f"{request_id}.json").read_text())
    assert record["identityDigest"] == genesis["identityDigest"]

    links = list((tmp_path / UPDATER_ROOT / "authority-links").glob("*.json"))
    assert len(links) == 1
    assert validate_update_authority_link(json.loads(links[0].read_text())).digest


def test_accepted_update_advances_the_install_trust_record(tmp_path: Path) -> None:
    """F5: after an accepted update the install-trust record names the
    accepted release and identity head, so the uninstall/purge union sees the
    current release from both durable records."""
    _updater, host, _authority, successor, _document = initialized_engine(tmp_path)
    store = UpdateStore.open_existing(tmp_path / UPDATER_ROOT)
    genesis = inject(tmp_path)
    engine, adapter = adapter_engine(tmp_path, host)

    trust_dir = tmp_path / UPDATER_ROOT / "trust"
    trust_dir.mkdir(parents=True, mode=0o700)
    trust_dir.chmod(0o700)
    trust_path = trust_dir / "install-trust.json"
    seed = {
        "schema": "stateport.internal-install-trust/v1",
        "trustRootId": "update_trust_root_" + "0" * 32,
        "trustRootDigest": "sha256:" + "0" * 64,
        "mode": "pinned-public-key",
        "keyId": "alpha-2026-08",
        "publicKeyFingerprint": "ab" * 32,
        "channel": "alpha",
        "targetId": TARGET_ID,
        "releaseId": genesis["releaseId"],
        "releaseIndexDigest": genesis["releaseIndexDigest"],
        "signedPayloadDigest": genesis["signedPayloadDigest"],
        "admissionId": "release_admission_" + "1" * 32,
        "admissionDigest": "sha256:" + "1" * 64,
        "installedIdentityId": genesis["identityId"],
        "installedIdentityDigest": genesis["identityDigest"],
        "installerDigest": INSTALLER_DIGEST,
        "createdAt": "2026-08-01T12:00:00Z",
    }
    trust_path.write_text(json.dumps(seed, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    trust_path.chmod(0o600)

    plan = engine.plan(successor)
    authorization = adapter.reserve(plan)
    receipt = engine.apply(plan["planId"], authorization)
    assert validate_update_receipt(receipt).document["result"] == "accepted"

    head = adapter._current_identity()
    advanced = json.loads(trust_path.read_text(encoding="utf-8"))
    assert advanced["releaseId"] == head["releaseId"] != seed["releaseId"]
    assert advanced["signedPayloadDigest"] == head["signedPayloadDigest"]
    assert advanced["releaseIndexDigest"] == receipt["releaseIndexDigest"]
    assert advanced["installedIdentityId"] == head["identityId"]
    assert advanced["installedIdentityDigest"] == head["identityDigest"]
    # Genesis provenance is preserved.
    for field in (
        "trustRootId",
        "trustRootDigest",
        "mode",
        "keyId",
        "publicKeyFingerprint",
        "channel",
        "targetId",
        "admissionId",
        "admissionDigest",
        "installerDigest",
        "createdAt",
    ):
        assert advanced[field] == seed[field], field


def test_installed_rollback_roundtrip_returns_identity_to_predecessor(tmp_path: Path) -> None:
    _updater, host, _authority, successor, _document = initialized_engine(tmp_path)
    genesis = inject(tmp_path)
    engine, adapter = adapter_engine(tmp_path, host)
    plan = engine.plan(successor)
    receipt = engine.apply(plan["planId"], adapter.reserve(plan))
    assert receipt["result"] == "accepted"
    host.current = host.accepted
    successor_identity = adapter._current_identity()

    rollback = engine.plan(operation="rollback")
    rollback_authorization = adapter.reserve(rollback)
    assert rollback_authorization["decision"]["action"] == "rollback_update"
    rollback_receipt = engine.apply(rollback["planId"], rollback_authorization)
    assert validate_update_receipt(rollback_receipt).document["operation"] == "rollback"
    status = validate_update_status(engine.status()).document
    assert status["current"]["releaseId"].endswith("0.1.0-rc.1")

    head = adapter._current_identity()
    assert head["releaseId"] == genesis["releaseId"]
    assert head["signedPayloadDigest"] == genesis["signedPayloadDigest"]
    assert head["identityDigest"] != genesis["identityDigest"]
    assert head["predecessorReleaseId"] == successor_identity["releaseId"]
    assert head["predecessorIdentityDigest"] == successor_identity["identityDigest"]
    assert len(list(adapter.identity_dir.glob("*.json"))) == 3
    terminal = adapter.terminal_receipt(rollback_authorization["decision"]["requestId"])
    assert terminal is not None
    _validate_receipt(terminal)


def test_copied_state_root_is_refused_as_foreign(tmp_path: Path) -> None:
    updater, host, _authority, successor, _document = initialized_engine(tmp_path)
    inject(tmp_path)
    copied = tmp_path / "copied-updater"
    shutil.copytree(tmp_path / UPDATER_ROOT, copied)
    foreign = InstalledAuthorityAdapter(
        UpdateStore.open_existing(copied),
        clock=lambda: NOW,
    )
    with pytest.raises(UpdateAuthorityError) as failure:
        foreign._current_identity()
    assert failure.value.code == "foreign_state_refused"

    plan = updater.plan(successor)
    with pytest.raises(UpdateAuthorityError) as reserve_failure:
        foreign.reserve(plan)
    assert reserve_failure.value.code == "foreign_state_refused"

    engine, adapter = adapter_engine(tmp_path, host)
    original = engine.plan(successor)
    assert adapter.reserve(original)["decision"]["action"] == "apply_update"


def test_wsl2_reattach_device_renumbering_does_not_break_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """WSL2 reassigns st_dev on reattach; the installed identity must not
    bind it (F8).  A same-inode root with a new device number is the SAME
    installation, not a foreign one."""
    updater, host, _authority, successor, _document = initialized_engine(tmp_path)
    inject(tmp_path)
    store_root = tmp_path / UPDATER_ROOT
    store_root_forms = {str(store_root), str(store_root.resolve())}

    real_lstat = os.lstat

    def reattached_lstat(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        result = real_lstat(path, *args, **kwargs)
        # Only the durable-identity read in installed.py observes the
        # reattach; within-run lstat/fstat TOCTOU pairs must stay consistent.
        frame = inspect.currentframe().f_back
        if (
            frame is not None
            and frame.f_code.co_filename.endswith("stateport_updater/installed.py")
            and str(path) in store_root_forms
        ):
            values = list(result)
            values[2] = result.st_dev + 0xF00D  # st_dev reassigned by WSL2
            return os.stat_result(values)
        return result

    monkeypatch.setattr(os, "lstat", reattached_lstat)

    engine, adapter = adapter_engine(tmp_path, host)
    identity = adapter._current_identity()
    assert identity["stateRootInode"] == int(real_lstat(store_root).st_ino)
    plan = engine.plan(successor)
    assert adapter.reserve(plan)["decision"]["action"] == "apply_update"


def test_forged_authorization_without_durable_reservation_is_refused(tmp_path: Path) -> None:
    _updater, host, _authority, successor, _document = initialized_engine(tmp_path)
    inject(tmp_path)
    engine, adapter = adapter_engine(tmp_path, host)
    plan = engine.plan(successor)
    forged_decision = adapter._decision(
        action="apply_update",
        run_id=plan["planDigest"],
        identity=adapter._current_identity(),
        decided_at="2026-08-01T12:00:00Z",
        estimated_seconds=3600,
    )
    forged_reservation = adapter._reservation(
        forged_decision,
        reserved_at="2026-08-01T12:00:00Z",
    )
    with pytest.raises(UpdateAuthorityError) as failure:
        adapter.validate_reservation(
            plan,
            {"decision": forged_decision, "reservation": forged_reservation},
        )
    assert failure.value.code == "authority_reservation_unknown"


def test_stale_authorization_after_accepted_update_is_refused(tmp_path: Path) -> None:
    _updater, host, _authority, successor, _document = initialized_engine(tmp_path)
    inject(tmp_path)
    engine, adapter = adapter_engine(tmp_path, host)
    plan = engine.plan(successor)
    authorization = adapter.reserve(plan)
    assert engine.apply(plan["planId"], authorization)["result"] == "accepted"

    with pytest.raises(UpdateError) as failure:
        engine.apply(plan["planId"], authorization)
    assert failure.value.code == "installed_identity_changed"
    with pytest.raises(UpdateAuthorityError) as refusal:
        adapter.reserve(plan)
    assert refusal.value.code == "authority_terminal_conflict"


def test_refused_reservation_is_receipted_not_executed(tmp_path: Path) -> None:
    _updater, host, _authority, successor, _document = initialized_engine(tmp_path)
    inject(tmp_path)
    engine, adapter = adapter_engine(tmp_path, host)
    plan = deepcopy(engine.plan(successor))
    plan["policy"]["channel"] = "stable"

    with pytest.raises(UpdateAuthorityError) as failure:
        adapter.reserve(plan)
    assert failure.value.code == "channel_mismatch"
    receipt = failure.value.receipt
    assert receipt is not None
    _validate_receipt(receipt)
    assert receipt["decision"] == "denied"
    assert receipt["result"]["status"] == "not_executed"
    assert receipt["result"]["code"] == "channel_mismatch"
    assert adapter.terminal_receipt(receipt["requestId"]) == receipt


def test_tampered_identity_record_breaks_status_binding(tmp_path: Path) -> None:
    _updater, host, _authority, successor, _document = initialized_engine(tmp_path)
    inject(tmp_path)
    engine, adapter = adapter_engine(tmp_path, host)
    plan = engine.plan(successor)

    identity_path = next(adapter.identity_dir.glob("*.json"))
    record = json.loads(identity_path.read_text())
    record["releaseId"] = "stateport-alpha-9.9.9-rc.9"
    record["version"] = "9.9.9-rc.9"
    body = {
        key: value for key, value in record.items() if key not in {"identityId", "identityDigest"}
    }
    digest = canonical_digest(body)
    identity_path.unlink()
    record["identityDigest"] = digest
    record["identityId"] = f"installed_identity_{digest.removeprefix('sha256:')[:32]}"
    replacement = adapter.identity_dir / f"{record['identityId']}.json"
    replacement.write_text(json.dumps(record), encoding="utf-8")
    replacement.chmod(0o600)

    with pytest.raises(UpdateAuthorityError) as failure:
        adapter.reserve(plan)
    assert failure.value.code == "installed_identity_unresolved"


def test_installed_crash_after_claim_recovers_through_reconcile(tmp_path: Path) -> None:
    _updater, host, _authority, successor, _document = initialized_engine(tmp_path)
    inject(tmp_path)
    engine, adapter = adapter_engine(
        tmp_path,
        host,
        failpoint=OneShotCrash("after_authority_claim_before_journal"),
    )
    plan = engine.plan(successor)
    authorization = adapter.reserve(plan)
    request_id = authorization["decision"]["requestId"]
    with pytest.raises(SimulatedCrash):
        engine.apply(plan["planId"], authorization)
    assert adapter.recover_claim(request_id) is not None
    assert adapter.terminal_receipt(request_id) is None
    assert len(list(adapter.identity_dir.glob("*.json"))) == 1

    reopened, _adapter = adapter_engine(tmp_path, host)
    recovered = reopened.reconcile()
    assert recovered["accepted"]["releaseId"].endswith("0.2.0-rc.1")
    terminal = adapter.terminal_receipt(request_id)
    assert terminal is not None
    _validate_receipt(terminal)
    assert len(list(adapter.identity_dir.glob("*.json"))) == 2
    assert len(list(adapter.receipts_dir.glob("*.json"))) == 1


def test_installed_crash_after_finalize_reconciles_without_duplicates(tmp_path: Path) -> None:
    _updater, host, _authority, successor, _document = initialized_engine(tmp_path)
    inject(tmp_path)
    engine, adapter = adapter_engine(
        tmp_path,
        host,
        failpoint=OneShotCrash("after_authority_finalize_before_journal"),
    )
    plan = engine.plan(successor)
    authorization = adapter.reserve(plan)
    request_id = authorization["decision"]["requestId"]
    with pytest.raises(SimulatedCrash):
        engine.apply(plan["planId"], authorization)
    persisted = adapter.terminal_receipt(request_id)
    assert persisted is not None
    assert len(list(adapter.identity_dir.glob("*.json"))) == 2

    reopened, _adapter = adapter_engine(tmp_path, host)
    recovered = reopened.reconcile()
    assert recovered["accepted"]["releaseId"].endswith("0.2.0-rc.1")
    assert adapter.terminal_receipt(request_id) == persisted
    assert len(list(adapter.receipts_dir.glob("*.json"))) == 1
    assert len(list(adapter.claims_dir.glob("*.json"))) == 1
    assert len(list(adapter.identity_dir.glob("*.json"))) == 2
    links = list((tmp_path / UPDATER_ROOT / "authority-links").glob("*.json"))
    assert len(links) == 1
    assert validate_update_authority_link(json.loads(links[0].read_text())).digest


def test_apply_rollback_refuse_without_authorization_before_state_root(
    tmp_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    absent = tmp_path / "absent"
    for command in ("apply", "rollback"):
        assert (
            main(
                [
                    "--state-root",
                    str(absent),
                    command,
                    "--plan-id",
                    "update_plan_" + "a" * 32,
                ]
            )
            == 3
        )
        assert payload(capsysbinary) == {
            "schema": "stateport.updater-error/v1",
            "code": "installed_authority_adapter_required",
            "status": "not_executed",
        }
    assert not absent.exists()


@pytest.mark.parametrize(
    "argv",
    [
        ["check", "--release-index", "candidate.release-index.json"],
        ["plan", "--release-index", "candidate.release-index.json"],
        ["plan", "--rollback"],
        ["reconcile"],
    ],
)
def test_control_plane_commands_fail_closed_without_binding(
    tmp_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
    argv: list[str],
) -> None:
    initialized_engine(tmp_path)
    inject(tmp_path)
    assert main(cli_args(tmp_path, *argv)) == 3
    assert payload(capsysbinary) == {
        "schema": "stateport.updater-error/v1",
        "code": "installed_authority_adapter_required",
        "status": "not_executed",
    }


def test_apply_with_authorization_still_requires_control_plane(
    tmp_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    _updater, host, _authority, successor, _document = initialized_engine(tmp_path)
    inject(tmp_path)
    engine, adapter = adapter_engine(tmp_path, host)
    plan = engine.plan(successor)
    bundle = tmp_path / "authorization.json"
    bundle.write_text(
        json.dumps({"schema": AUTHORIZATION_BUNDLE_SCHEMA, **adapter.reserve(plan)}),
        encoding="utf-8",
    )
    bundle.chmod(0o600)
    assert (
        main(
            cli_args(
                tmp_path,
                "apply",
                "--plan-id",
                plan["planId"],
                "--authorization",
                str(bundle),
            )
        )
        == 3
    )
    assert payload(capsysbinary) == {
        "schema": "stateport.updater-error/v1",
        "code": "installed_authority_adapter_required",
        "status": "not_executed",
    }


def test_cli_check_plan_authorize_apply_roundtrip(
    tmp_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    _updater, host, _authority, successor, document = initialized_engine(tmp_path)
    genesis = inject(tmp_path)
    state_root = tmp_path / UPDATER_ROOT
    index = tmp_path / "successor.release-index.json"
    index.write_text(json.dumps(document), encoding="utf-8")

    def snapshot() -> dict[Path, bytes]:
        return {
            path.relative_to(state_root): path.read_bytes()
            for path in sorted(state_root.rglob("*"))
            if path.is_file()
        }

    before = snapshot()
    assert (
        main(
            cli_args(tmp_path, "check", "--release-index", str(index)),
            control_plane=binding(host),
        )
        == 0
    )
    checked = payload(capsysbinary)
    assert checked["result"] == "update_available"
    assert checked["successor"]["releaseId"].endswith("0.2.0-rc.1")
    assert snapshot() == before

    assert (
        main(
            cli_args(tmp_path, "plan", "--release-index", str(index)),
            control_plane=binding(host),
        )
        == 0
    )
    plan = payload(capsysbinary)
    assert plan["operation"] == "update"
    assert plan["authority"]["runId"] == plan["planDigest"]

    bundle = tmp_path / "authorization.json"
    assert (
        main(
            cli_args(
                tmp_path,
                "authorize",
                "--plan-id",
                plan["planId"],
                "--output",
                str(bundle),
            )
        )
        == 0
    )
    assert payload(capsysbinary)["result"] == "authorization_reserved"
    written = json.loads(bundle.read_text())
    assert written["schema"] == AUTHORIZATION_BUNDLE_SCHEMA
    assert bundle.stat().st_mode & 0o777 == 0o600

    replay = tmp_path / "authorization-replay.json"
    assert (
        main(
            cli_args(
                tmp_path,
                "authorize",
                "--plan-id",
                plan["planId"],
                "--output",
                str(replay),
            )
        )
        == 0
    )
    payload(capsysbinary)
    assert json.loads(replay.read_text()) == written

    assert (
        main(
            cli_args(
                tmp_path,
                "apply",
                "--plan-id",
                plan["planId"],
                "--authorization",
                str(bundle),
            ),
            control_plane=binding(host),
        )
        == 0
    )
    assert payload(capsysbinary)["result"] == "accepted"

    assert main(cli_args(tmp_path, "status")) == 0
    status = payload(capsysbinary)
    assert status["current"]["releaseId"].endswith("0.2.0-rc.1")
    adapter = InstalledAuthorityAdapter(UpdateStore.open_existing(state_root))
    head = adapter._current_identity()
    assert head["releaseId"] == status["current"]["releaseId"]
    assert head["predecessorIdentityDigest"] == genesis["identityDigest"]

    assert main(cli_args(tmp_path, "plan", "--rollback"), control_plane=binding(host)) == 0
    assert payload(capsysbinary)["operation"] == "rollback"


def test_cli_policy_show_and_set_roundtrip(
    tmp_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    initialized_engine(tmp_path)
    inject(tmp_path)
    assert main(cli_args(tmp_path, "policy")) == 0
    assert payload(capsysbinary)["mode"] == "download-and-notify"

    assert (
        main(
            cli_args(
                tmp_path,
                "policy",
                "set",
                "--mode",
                "scheduled",
                "--schedule-days",
                "1,3,5",
                "--schedule-start-minute",
                "120",
            )
        )
        == 0
    )
    changed = payload(capsysbinary)
    assert changed["policy"]["mode"] == "scheduled"
    assert changed["policy"]["schedule"] == {
        "daysOfWeek": [1, 3, 5],
        "startMinuteUtc": 120,
    }
    assert main(cli_args(tmp_path, "policy")) == 0
    assert payload(capsysbinary)["mode"] == "scheduled"

    adapter = InstalledAuthorityAdapter(UpdateStore.open_existing(tmp_path / UPDATER_ROOT))
    receipts = [json.loads(path.read_text()) for path in adapter.receipts_dir.glob("*.json")]
    assert len(receipts) == 1
    _validate_receipt(receipts[0])
    assert receipts[0]["action"] == "modify_update_policy"
    assert receipts[0]["result"]["status"] == "succeeded"


def test_cli_policy_set_requires_schedule_for_scheduled_mode(
    tmp_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    initialized_engine(tmp_path)
    inject(tmp_path)
    assert main(cli_args(tmp_path, "policy", "set", "--mode", "scheduled")) == 2
    assert payload(capsysbinary) == {
        "schema": "stateport.updater-error/v1",
        "code": "policy_invalid",
        "status": "not_executed",
    }


def test_cli_policy_set_requires_installed_authority(
    tmp_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    initialized_engine(tmp_path)
    assert main(cli_args(tmp_path, "policy", "set", "--mode", "notify")) == 3
    assert payload(capsysbinary) == {
        "schema": "stateport.updater-error/v1",
        "code": "installed_authority_adapter_required",
        "status": "not_executed",
    }


def test_cli_reconcile_converges_installed_crash(
    tmp_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    _updater, host, _authority, successor, _document = initialized_engine(tmp_path)
    inject(tmp_path)
    engine, adapter = adapter_engine(
        tmp_path,
        host,
        failpoint=OneShotCrash("after_authority_claim_before_journal"),
    )
    plan = engine.plan(successor)
    authorization = adapter.reserve(plan)
    with pytest.raises(SimulatedCrash):
        engine.apply(plan["planId"], authorization)
    assert adapter.terminal_receipt(authorization["decision"]["requestId"]) is None

    assert main(cli_args(tmp_path, "reconcile"), control_plane=binding(host)) == 0
    recovered = payload(capsysbinary)
    assert recovered["accepted"]["releaseId"].endswith("0.2.0-rc.1")
    assert adapter.terminal_receipt(authorization["decision"]["requestId"]) is not None


def test_control_plane_environment_seam(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    _updater, _host, _authority, _successor, document = initialized_engine(tmp_path)
    inject(tmp_path)
    module = tmp_path / "fixture_control_plane.py"
    module.write_text(
        "\n".join(
            [
                "from scripts.test_stateport_updater import (",
                "    NOW,",
                "    POLICY,",
                "    FixtureHost,",
                "    _EphemeralTestVerifier,",
                ")",
                "from stateport_updater.installed import ControlPlaneBinding",
                "",
                "",
                "def build_binding(state_root):",
                "    return ControlPlaneBinding(",
                "        host=FixtureHost(),",
                "        signature_verifier=_EphemeralTestVerifier(),",
                "        verification_policy=POLICY,",
                "        clock=lambda: NOW,",
                "        transport_verifier_factory=lambda _root: _EphemeralTestVerifier(),",
                "    )",
                "",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.setenv(
        "STATEPORT_UPDATER_CONTROL_PLANE",
        "fixture_control_plane:build_binding",
    )
    index = tmp_path / "successor.release-index.json"
    index.write_text(json.dumps(document), encoding="utf-8")
    assert main(cli_args(tmp_path, "check", "--release-index", str(index))) == 0
    assert payload(capsysbinary)["result"] == "update_available"


def test_control_plane_environment_seam_rejects_malformed_spec(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    initialized_engine(tmp_path)
    inject(tmp_path)
    monkeypatch.setenv("STATEPORT_UPDATER_CONTROL_PLANE", "not-a-module-spec")
    assert main(cli_args(tmp_path, "reconcile")) == 3
    assert payload(capsysbinary) == {
        "schema": "stateport.updater-error/v1",
        "code": "control_plane_binding_invalid",
        "status": "not_executed",
    }


def test_control_plane_binding_without_host_seam_is_refused(
    tmp_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    initialized_engine(tmp_path)
    inject(tmp_path)
    broken = ControlPlaneBinding(
        host=object(),
        signature_verifier=_EphemeralTestVerifier(),
        verification_policy=POLICY,
    )
    assert main(cli_args(tmp_path, "reconcile"), control_plane=broken) == 3
    assert payload(capsysbinary) == {
        "schema": "stateport.updater-error/v1",
        "code": "control_plane_binding_invalid",
        "status": "not_executed",
    }


# ---------------------------------------------------------------------------
# CLI content-addressed signature-bundle retention
# ---------------------------------------------------------------------------

SUCCESSOR_BUNDLE = (
    b'{"mediaType":"application/vnd.sigstore.bundle.v0.3+json","fixture":"successor"}\n'
)
FOREIGN_BUNDLE = b'{"mediaType":"application/vnd.sigstore.bundle.v0.3+json","fixture":"foreign"}\n'


class _RetainingTestVerifier(_EphemeralTestVerifier):
    """Ephemeral proofs, but real create-only content-addressed retention."""

    def __init__(self, bundle_root: Path) -> None:
        super().__init__()
        self._bundle_root = bundle_root

    def retain_bundle(self, source: Path, signature: Mapping[str, Any]) -> Path:
        return retain_bundle(self._bundle_root, source, signature)


def _retaining_binding(host: FixtureHost, bundle_root: Path) -> ControlPlaneBinding:
    return ControlPlaneBinding(
        host=host,
        signature_verifier=_RetainingTestVerifier(bundle_root),
        verification_policy=POLICY,
        clock=lambda: NOW,
        bundle_root=bundle_root,
        transport_verifier_factory=lambda root: _RetainingTestVerifier(root),
    )


def _staged_successor(
    tmp_path: Path,
    document: dict[str, Any],
    *,
    bundle_bytes: bytes = SUCCESSOR_BUNDLE,
    record_bytes: bytes | None = None,
    signatures_layout: bool = False,
) -> tuple[Path, dict[str, Any]]:
    staged_document = deepcopy(document)
    recorded = staged_document["signatures"][0]["bundle"]
    bound = bundle_bytes if record_bytes is None else record_bytes
    recorded["digest"] = "sha256:" + hashlib.sha256(bound).hexdigest()
    recorded["size"] = len(bound)
    staging = tmp_path / "release-successor"
    staging.mkdir()
    (staging / signature_bundle_name(staged_document["signatures"][0])).write_bytes(bundle_bytes)
    image_dir = staging / "signatures" if signatures_layout else staging
    if signatures_layout:
        image_dir.mkdir()
    for image in staged_document["signed"]["images"]:
        signature = image.get("signature")
        if not isinstance(signature, Mapping):
            continue
        signature["bundle"]["digest"] = "sha256:" + hashlib.sha256(bundle_bytes).hexdigest()
        signature["bundle"]["size"] = len(bundle_bytes)
        (image_dir / signature_bundle_name(signature)).write_bytes(bundle_bytes)
    staged_document["signatures"][0]["subjectDigest"] = canonical_digest(
        staged_document["signed"]
    )
    index = staging / "release-index.json"
    index.write_text(json.dumps(staged_document), encoding="utf-8")
    return index, staged_document


def test_cli_check_is_read_only_and_plan_retains_the_successor_bundle(
    tmp_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    _updater, host, _authority, _successor, document = initialized_engine(tmp_path)
    inject(tmp_path)
    state_root = tmp_path / UPDATER_ROOT
    durable = state_root / "bundles"
    durable.mkdir()
    index, staged = _staged_successor(tmp_path, document)

    assert (
        main(
            cli_args(tmp_path, "check", "--release-index", str(index)),
            control_plane=_retaining_binding(host, durable),
        )
        == 0
    )
    assert payload(capsysbinary)["result"] == "update_available"
    slot = bundle_slot(durable, staged["signatures"][0])
    assert not slot.exists()

    assert (
        main(
            cli_args(tmp_path, "plan", "--release-index", str(index)),
            control_plane=_retaining_binding(host, durable),
        )
        == 0
    )
    payload(capsysbinary)
    assert slot.is_file() and not slot.is_symlink()
    assert slot.read_bytes() == SUCCESSOR_BUNDLE
    assert slot.stat().st_mode & 0o777 == 0o600

    assert slot.read_bytes() == SUCCESSOR_BUNDLE


def test_cli_check_refuses_a_successor_bundle_that_diverges_from_the_record(
    tmp_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    _updater, host, _authority, _successor, document = initialized_engine(tmp_path)
    inject(tmp_path)
    durable = tmp_path / UPDATER_ROOT / "bundles"
    durable.mkdir()
    index, _staged = _staged_successor(tmp_path, document, record_bytes=FOREIGN_BUNDLE)

    assert (
        main(
            cli_args(tmp_path, "plan", "--release-index", str(index)),
            control_plane=_retaining_binding(host, durable),
        )
        == 3
    )
    assert payload(capsysbinary) == {
        "schema": "stateport.updater-error/v1",
        "code": "release_bundle_retention_refused",
        "status": "not_executed",
    }
    assert list(durable.iterdir()) == []


def test_cli_check_refuses_a_tampered_retained_bundle_slot(
    tmp_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    _updater, host, _authority, _successor, document = initialized_engine(tmp_path)
    inject(tmp_path)
    durable = tmp_path / UPDATER_ROOT / "bundles"
    durable.mkdir()
    index, staged = _staged_successor(tmp_path, document)
    slot = bundle_slot(durable, staged["signatures"][0])
    slot.parent.mkdir(parents=True)
    slot.write_bytes(b'{"tampered":true}\n')

    assert (
        main(
            cli_args(tmp_path, "plan", "--release-index", str(index)),
            control_plane=_retaining_binding(host, durable),
        )
        == 3
    )
    assert payload(capsysbinary)["code"] == "release_bundle_retention_refused"


def test_cli_check_resolves_image_bundles_from_the_published_signatures_layout(
    tmp_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    _updater, host, _authority, _successor, document = initialized_engine(tmp_path)
    inject(tmp_path)
    durable = tmp_path / UPDATER_ROOT / "bundles"
    durable.mkdir()
    index, staged = _staged_successor(tmp_path, document, signatures_layout=True)

    assert (
        main(
            cli_args(tmp_path, "check", "--release-index", str(index)),
            control_plane=_retaining_binding(host, durable),
        )
        == 0
    )
    assert payload(capsysbinary)["result"] == "update_available"
    assert not bundle_slot(durable, staged["signatures"][0]).exists()

    assert (
        main(
            cli_args(tmp_path, "plan", "--release-index", str(index)),
            control_plane=_retaining_binding(host, durable),
        )
        == 0
    )
    payload(capsysbinary)
    slot = bundle_slot(durable, staged["signatures"][0])
    assert slot.is_file() and not slot.is_symlink()
    assert slot.read_bytes() == SUCCESSOR_BUNDLE


def test_cli_check_refuses_when_image_bundles_are_absent_from_every_supported_layout(
    tmp_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    _updater, host, _authority, _successor, document = initialized_engine(tmp_path)
    inject(tmp_path)
    durable = tmp_path / UPDATER_ROOT / "bundles"
    durable.mkdir()
    index, _staged = _staged_successor(tmp_path, document, signatures_layout=True)
    removed: set[str] = set()
    for image in _staged["signed"]["images"]:
        signature = image.get("signature")
        if not isinstance(signature, Mapping):
            continue
        name = signature_bundle_name(signature)
        if name in removed:
            continue
        removed.add(name)
        (index.parent / "signatures" / name).unlink()

    assert (
        main(
            cli_args(tmp_path, "check", "--release-index", str(index)),
            control_plane=_retaining_binding(host, durable),
        )
        == 3
    )
    assert payload(capsysbinary) == {
        "schema": "stateport.updater-error/v1",
        "code": "release_bundle_retention_refused",
        "status": "not_executed",
    }
    assert list(durable.iterdir()) == []


def test_cli_plan_resolves_image_bundles_from_the_durable_slot_when_staging_is_gone(
    tmp_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    _updater, host, _authority, _successor, document = initialized_engine(tmp_path)
    inject(tmp_path)
    durable = tmp_path / UPDATER_ROOT / "bundles"
    durable.mkdir()
    index, staged = _staged_successor(tmp_path, document, signatures_layout=True)

    assert (
        main(
            cli_args(tmp_path, "plan", "--release-index", str(index)),
            control_plane=_retaining_binding(host, durable),
        )
        == 0
    )
    payload(capsysbinary)
    slot = bundle_slot(durable, staged["signatures"][0])
    assert slot.is_file()

    shutil.rmtree(index.parent / "signatures")
    for image in staged["signed"]["images"]:
        signature = image.get("signature")
        if not isinstance(signature, Mapping):
            continue
        name = signature_bundle_name(signature)
        if (index.parent / name).exists():
            (index.parent / name).unlink()
    assert (
        main(
            cli_args(tmp_path, "plan", "--release-index", str(index)),
            control_plane=_retaining_binding(host, durable),
        )
        == 0
    )
    payload(capsysbinary)
    assert slot.is_file() and not slot.is_symlink()


def _predecessor_successor_documents(
    predecessor_version: str = "0.1.0-alpha.5",
    successor_version: str = "0.1.0-alpha.6",
) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    """Build a valid signed predecessor index and a successor index that
    declares that predecessor in ``signed.successor``, mirroring the real
    alpha.5 -> alpha.6 successor chain that the R1 rehearsal stages."""

    def _base(release_id: str, version: str) -> tuple[dict[str, Any], Any]:
        document = deepcopy(release_index())
        signed = document["signed"]
        signed["release"]["releaseId"] = release_id
        signed["release"]["version"] = version
        for target in signed["targets"]:
            target["releaseId"] = release_id
            target["topologyDigest"] = topology_digest(target)
        signed["compatibility"]["predecessor"] = None
        signed["compatibility"]["rollback"]["supported"] = False
        signed["compatibility"]["rollback"]["minimumPredecessorVersion"] = None
        return document, signed

    predecessor_id = f"stateport-alpha-{predecessor_version}"
    successor_id = f"stateport-alpha-{successor_version}"
    pred_document, _pred_signed = _base(predecessor_id, predecessor_version)
    predecessor_signature = _signature(
        canonical_digest(pred_document["signed"]), "release-index-predecessor"
    )
    predecessor_signature["bundle"]["digest"] = (
        "sha256:" + hashlib.sha256(SUCCESSOR_BUNDLE).hexdigest()
    )
    predecessor_signature["bundle"]["size"] = len(SUCCESSOR_BUNDLE)
    pred_document["signatures"] = [predecessor_signature]
    predecessor_index = validate_release_index(pred_document, require_signatures=True)
    predecessor_bytes = predecessor_index.canonical_index_bytes

    successor_document, signed = _base(successor_id, successor_version)
    signed["compatibility"]["predecessor"] = {
        "releaseId": predecessor_index.release_id,
        "version": predecessor_index.version,
        "signedPayloadDigest": predecessor_index.signed_digest,
    }
    signed["compatibility"]["rollback"]["supported"] = True
    signed["compatibility"]["rollback"]["minimumPredecessorVersion"] = predecessor_version
    observations = [
        {
            "imageId": image["imageId"],
            "digest": image["digest"],
            "databaseBuiltAt": image["scan"]["databaseBuiltAt"],
            "scannedAt": image["scan"]["scannedAt"],
        }
        for image in sorted(signed["images"], key=lambda item: item["imageId"])
    ]
    event_payload = {
        "formatVersion": "stateport.release-qualification/v1",
        "releaseId": successor_id,
        "version": successor_version,
        "qualifiedAt": "2026-08-01T09:00:00Z",
        "result": "qualified",
        "freshnessBasis": "scan-and-database-checked-at-qualification",
        "images": observations,
    }
    qualification_event = {
        **event_payload,
        "eventId": canonical_digest(event_payload),
    }
    predecessor_claim = {
        "formatVersion": "stateport.release-predecessor/v1",
        "releaseId": predecessor_index.release_id,
        "version": predecessor_index.version,
        "signedPayloadDigest": predecessor_index.signed_digest,
        "indexDigest": predecessor_index.index_digest,
        "signature": json.loads(json.dumps(predecessor_signature)),
        "rawIndex": json.loads(predecessor_bytes),
    }
    signed["successor"] = {
        "formatVersion": "stateport.release-successor/v1",
        "freshnessEnforcement": "qualification-and-signing-time",
        "qualificationEvent": qualification_event,
        "disposition": {
            "formatVersion": "stateport.release-disposition/v2",
            "signedBy": "stateport.release-index/v1",
            "sequence": 1,
            "status": "active",
            "at": None,
            "reason": None,
            "previousDispositionDigest": None,
        },
        "predecessor": predecessor_claim,
        "versionBindings": {
            "releaseVersion": successor_version,
            "buildReceiptFormatVersion": "stateport.release-image-build-receipt/v1",
            "buildReceiptVersion": successor_version,
            "imageEvidenceFormatVersion": "stateport.release-image-evidence/v1",
            "qualificationEventFormatVersion": "stateport.release-qualification/v1",
        },
    }
    successor_document["signatures"] = [
        _signature(canonical_digest(signed), "release-index-successor")
    ]
    validate_release_index(successor_document, require_signatures=True)
    return (
        predecessor_index,
        successor_document,
        predecessor_bytes,
        signature_bundle_name(predecessor_claim["signature"]),
    )


def test_store_persists_an_immutable_predecessor_index_at_genesis(
    tmp_path: Path,
) -> None:
    _predecessor, _successor_document, predecessor_bytes, _bundle_name = (
        _predecessor_successor_documents()
    )
    store = UpdateStore.create(tmp_path / UPDATER_ROOT)
    with store.transaction() as session:
        session.save_release_index_bytes(
            "stateport-alpha-0.1.0-alpha.5", predecessor_bytes
        )
    slot = store.releases / "stateport-alpha-0.1.0-alpha.5.release-index.json"
    assert slot.is_file() and not slot.is_symlink()
    assert slot.read_bytes() == predecessor_bytes

    with store.transaction() as session:
        session.save_release_index_bytes(
            "stateport-alpha-0.1.0-alpha.5", predecessor_bytes
        )
    from stateport_updater.store import StoreError

    with pytest.raises(StoreError) as failure:
        with store.transaction() as session:
            session.save_release_index_bytes(
                "stateport-alpha-0.1.0-alpha.5", b"different-bytes"
            )
    assert failure.value.code == "immutable_record_conflict"


def test_predecessor_index_slot_loads_with_legacy_semantics(
    tmp_path: Path,
) -> None:
    predecessor_index, _successor_document, _bytes, _bundle_name = (
        _predecessor_successor_documents()
    )
    store = UpdateStore.create(tmp_path / UPDATER_ROOT)
    with store.transaction() as session:
        session.save_release_index_bytes(
            predecessor_index.release_id, predecessor_index.canonical_index_bytes
        )
    slot = store.releases / f"{predecessor_index.release_id}.release-index.json"
    loaded = load_release_index_file(slot, legacy_predecessor=True)
    assert loaded.release_id == predecessor_index.release_id
    assert loaded.index_digest == predecessor_index.index_digest
    assert loaded.canonical_index_bytes == predecessor_index.canonical_index_bytes


def _r1_cli_fixture(
    tmp_path: Path,
    *,
    persist_predecessor: bool,
) -> tuple[FixtureHost, Path, Path]:
    predecessor_index, successor_document, predecessor_bytes, predecessor_bundle_name = (
        _predecessor_successor_documents()
    )
    verified = verify_release_index(
        successor_document,
        policy=POLICY,
        verifier=_EphemeralTestVerifier(),
        predecessor=predecessor_index,
    )
    envelope = to_updater_release_envelope(verified)
    host = FixtureHost()
    store = UpdateStore.create(tmp_path / UPDATER_ROOT)
    updater = UpdateEngine(
        store,
        host,
        FixtureAuthority(),
        verification_policy=POLICY,
        signature_verifier=_EphemeralTestVerifier(),
        clock=lambda: NOW,
    )
    updater.initialize(
        envelope,
        UpdatePolicy(mode="download-and-notify", channel="alpha"),
    )
    host.current = updater._facts(envelope, channel="alpha")
    host.accepted = host.current
    host.release_inventory.add(host.current.release_id)
    inject(tmp_path)

    if persist_predecessor:
        with store.transaction() as session:
            session.save_release_index_bytes(
                predecessor_index.release_id,
                predecessor_bytes,
            )

    index, _staged = _staged_successor(tmp_path, successor_document)
    predecessor_bundle = index.parent / "predecessor-bundle"
    predecessor_bundle.mkdir()
    (predecessor_bundle / predecessor_bundle_name).write_bytes(SUCCESSOR_BUNDLE)
    durable = store.root / "bundles"
    durable.mkdir()
    return host, index, durable


def test_cli_check_accepts_a_durable_successor_predecessor(
    tmp_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    host, index, durable = _r1_cli_fixture(tmp_path, persist_predecessor=True)

    assert (
        main(
            cli_args(tmp_path, "check", "--release-index", str(index)),
            control_plane=_retaining_binding(host, durable),
        )
        == 2
    )
    assert payload(capsysbinary)["code"] == "downgrade_refused"


def test_cli_check_reports_an_unavailable_successor_predecessor(
    tmp_path: Path,
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    host, index, durable = _r1_cli_fixture(tmp_path, persist_predecessor=False)

    assert (
        main(
            cli_args(tmp_path, "check", "--release-index", str(index)),
            control_plane=_retaining_binding(host, durable),
        )
        == 3
    )
    assert payload(capsysbinary)["code"] == "release_predecessor_unavailable"
