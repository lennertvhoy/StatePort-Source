"""Canonical release, authority, WAL, and crash coverage for the updater."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from threading import Barrier, Event, Thread
import time
from typing import Any, Callable, Mapping

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
for source in (
    ROOT,
    ROOT / "packages/release-contracts/src",
    ROOT / "packages/governed-runner/src",
    ROOT / "packages/updater/src",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from governed_runner.authority import (  # noqa: E402
    AuthorityManager,
    AuthorityPolicy,
    grant_template,
)
from stateport_release import (  # noqa: E402
    ReleaseContractError,
    ReleaseVerificationPolicy,
    canonical_digest,
    quadlet_bundle_digest,
    release_identity_from_verified,
    render_quadlet_bundle,
    to_updater_release_envelope,
    topology_digest,
    validate_update_authority_link,
    validate_update_failure_evidence,
    validate_update_plan,
    validate_update_receipt,
    validate_update_status,
    verify_release_index,
)
from stateport_updater import (  # noqa: E402
    AuthorityManagerAdapter,
    AuthorityScope,
    UpdateEngine,
    UpdateError,
    UpdateHostError,
    UpdatePolicy,
    UpdateStore,
)
from stateport_updater.authority import UpdateAuthorityError  # noqa: E402
from stateport_updater.models import ReleaseFacts  # noqa: E402
import stateport_updater.safe_io as updater_safe_io  # noqa: E402
import stateport_updater.cli as updater_cli  # noqa: E402
import stateport_updater.store as updater_store  # noqa: E402
from stateport_updater.store import StoreError, journal_digest  # noqa: E402
from scripts.test_release_contracts import (  # noqa: E402
    PINNED_KEY,
    SIGNER,
    _EphemeralTestVerifier,
    _pinned_key_signature,
    _signature,
    release_index,
)


NOW = datetime(2026, 8, 1, 12, 0, tzinfo=timezone.utc)
POLICY = ReleaseVerificationPolicy(
    expected_channel="alpha",
    expected_target="linux-amd64-rootless-podman-quadlet",
    updater_version="0.1.0",
    accepted_signers=frozenset({SIGNER}),
    expected_trust_mode="keyless-certificate",
    now=NOW,
    allow_candidate=True,
)
PINNED_POLICY = ReleaseVerificationPolicy(
    expected_channel="alpha",
    expected_target="linux-amd64-rootless-podman-quadlet",
    updater_version="0.1.0",
    accepted_signers=frozenset(),
    accepted_public_keys=frozenset({PINNED_KEY}),
    expected_trust_mode="pinned-public-key",
    now=NOW,
    allow_candidate=True,
)


def envelope(
    release_id: str,
    version: str,
    *,
    predecessor: Mapping[str, Any] | None,
    include_non_target_image: bool = False,
) -> tuple[Any, dict[str, Any], dict[str, Any]]:
    document = deepcopy(release_index())
    signed = document["signed"]
    signed["release"]["releaseId"] = release_id
    signed["release"]["version"] = version
    for target in signed["targets"]:
        target["releaseId"] = release_id
        target["topologyDigest"] = topology_digest(target)
    signed["compatibility"]["predecessor"] = (
        None
        if predecessor is None
        else {
            "releaseId": predecessor["releaseId"],
            "version": predecessor["version"],
            "signedPayloadDigest": predecessor["signedPayloadDigest"],
        }
    )
    if predecessor is None:
        signed["compatibility"]["rollback"]["supported"] = False
        signed["compatibility"]["rollback"]["minimumPredecessorVersion"] = None
    else:
        signed["compatibility"]["rollback"]["minimumPredecessorVersion"] = "0.1.0-rc.1"
    if include_non_target_image:
        extra = deepcopy(signed["images"][0])
        extra["imageId"] = "stateport-unselected-tooling"
        extra["role"] = "optional-profile"
        extra["reference"] = "ghcr.io/stateport/unselected@sha256:" + "9" * 64
        extra["digest"] = "sha256:" + "9" * 64
        extra["signature"]["subjectDigest"] = extra["digest"]
        signed["images"].append(extra)
    document["signatures"] = [_signature(canonical_digest(signed), f"release-index-{release_id}")]
    verifier = _EphemeralTestVerifier()
    verified = verify_release_index(document, policy=POLICY, verifier=verifier)
    identity = release_identity_from_verified(verified)
    return to_updater_release_envelope(verified), document, identity


def pinned_envelope(
    release_id: str,
    version: str,
    *,
    predecessor: Mapping[str, Any] | None,
) -> tuple[Any, dict[str, Any], dict[str, Any]]:
    """Pinned-public-key counterpart of ``envelope`` for the alpha trust line."""

    document = deepcopy(release_index())
    signed = document["signed"]
    signed["release"]["releaseId"] = release_id
    signed["release"]["version"] = version
    for target in signed["targets"]:
        target["releaseId"] = release_id
        target["topologyDigest"] = topology_digest(target)
    signed["compatibility"]["predecessor"] = (
        None
        if predecessor is None
        else {
            "releaseId": predecessor["releaseId"],
            "version": predecessor["version"],
            "signedPayloadDigest": predecessor["signedPayloadDigest"],
        }
    )
    if predecessor is None:
        signed["compatibility"]["rollback"]["supported"] = False
        signed["compatibility"]["rollback"]["minimumPredecessorVersion"] = None
    else:
        signed["compatibility"]["rollback"]["minimumPredecessorVersion"] = "0.1.0-rc.1"
    signed["signaturePolicy"]["trustMode"] = "pinned-public-key"
    for image in signed["images"]:
        image["signature"] = _pinned_key_signature(str(image["digest"]), str(image["imageId"]))
    document["signatures"] = [
        _pinned_key_signature(canonical_digest(signed), f"release-index-{release_id}")
    ]
    verifier = _EphemeralTestVerifier()
    verified = verify_release_index(document, policy=PINNED_POLICY, verifier=verifier)
    identity = release_identity_from_verified(verified)
    return to_updater_release_envelope(verified), document, identity


class FixtureHost:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.available_bytes = 10_000_000
        self.current: ReleaseFacts | None = None
        self.accepted: ReleaseFacts | None = None
        self.staged: ReleaseFacts | None = None
        self.fail_before: dict[str, int] = {}
        self.fail_after: dict[str, int] = {}
        self.observe_failures = 0
        self.wrong_runtime_digest = False
        self.retention_failures = 0
        self.retention_history: list[dict[str, Any]] = []
        self.release_inventory: set[str] = set()
        self.failure_artifact_inventory: set[str] = set()
        self.effect_receipts: dict[tuple[str, str], dict[str, Any]] = {}

    def _failure(self, name: str, *, after: bool, effect: str) -> None:
        failures = self.fail_after if after else self.fail_before
        if failures.get(name, 0) > 0:
            failures[name] -= 1
            raise UpdateHostError(
                f"{name.replace('-', '_')}_failed",
                f"fixture failure: {name}",
                effect=effect,
            )

    def _begin(self, name: str, *, effect: str = "partial") -> None:
        self.calls.append(name)
        self._failure(name, after=False, effect=effect)

    def _end(self, name: str, *, effect: str = "partial") -> None:
        self._failure(name, after=True, effect=effect)

    def _record_effect(
        self,
        plan_digest: str,
        step: str,
        evidence: Mapping[str, Any],
    ) -> dict[str, Any]:
        evidence_digest = canonical_digest(evidence)
        seed = canonical_digest(
            {
                "planDigest": plan_digest,
                "step": step,
                "evidenceDigest": evidence_digest,
            }
        )
        receipt = {
            "schema": "stateport.update-host-effect-receipt/v1",
            "receiptId": f"host_effect_receipt_{seed.removeprefix('sha256:')[:32]}",
            "planDigest": plan_digest,
            "step": step,
            "status": "observed",
            "evidence": deepcopy(dict(evidence)),
            "evidenceDigest": evidence_digest,
        }
        key = (plan_digest, step)
        existing = self.effect_receipts.setdefault(key, receipt)
        if existing != receipt:
            raise UpdateHostError(
                "effect_receipt_conflict",
                "fixture effect receipt changed",
                effect="unknown",
            )
        return deepcopy(dict(evidence))

    def observe_effect_receipt(self, *, plan_digest: str, step: str) -> Mapping[str, Any]:
        self.calls.append(f"observe-effect:{step}")
        receipt = self.effect_receipts.get((plan_digest, step))
        if receipt is None:
            raise UpdateHostError(
                "effect_receipt_missing",
                "fixture effect receipt does not exist",
                effect="unknown",
            )
        return deepcopy(receipt)

    def preflight(self, release: ReleaseFacts) -> Mapping[str, Any]:
        self._begin("preflight", effect="not_applied")
        return {
            "schema": "stateport.update-host-preflight/v1",
            "targetId": "linux-amd64-rootless-podman-quadlet",
            "releaseId": release.release_id,
            "availableBytes": self.available_bytes,
            "requiredBytes": release.expected_pull_bytes,
            "imageDigests": list(release.target_image_digests),
            "updaterCompatible": True,
            "migrationCompatible": True,
            "rollbackCompatible": True,
        }

    def backup(self, plan: Mapping[str, Any]) -> Mapping[str, Any]:
        self._begin("backup", effect="not_applied")
        self._end("backup", effect="not_applied")
        return self._record_effect(
            plan["planDigest"],
            "backup",
            {
                "schema": "stateport.update-host-backup/v1",
                "planDigest": plan["planDigest"],
                "receiptId": "backup_fixture",
                "backupDigest": "sha256:" + "b" * 64,
            },
        )

    def pull_images(self, plan: Mapping[str, Any], release: ReleaseFacts) -> Mapping[str, Any]:
        self._begin("pull")
        self._end("pull")
        return self._record_effect(
            plan["planDigest"],
            "pull",
            {
                "schema": "stateport.update-host-pull/v1",
                "releaseId": release.release_id,
                "imageDigests": list(release.target_image_digests),
            },
        )

    def stage(self, plan: Mapping[str, Any], release: ReleaseFacts) -> Mapping[str, Any]:
        self._begin("stage")
        self.staged = release
        self.release_inventory.add(release.release_id)
        self._end("stage")
        return self._record_effect(
            plan["planDigest"],
            "stage",
            {
                "schema": "stateport.update-host-stage/v1",
                "releaseId": release.release_id,
                "slot": "successor",
                "bundleDigest": release.quadlet_bundle_digest,
            },
        )

    def dry_run_migrations(self, plan: Mapping[str, Any]) -> Mapping[str, Any]:
        self._begin("dry-run-migrations")
        self._end("dry-run-migrations")
        assert self.staged is not None
        return self._record_effect(
            plan["planDigest"],
            "dry-run-migrations",
            {
                "schema": "stateport.update-host-migration-dry-run/v1",
                "planDigest": plan["planDigest"],
                "status": "passed",
                "schemaMigrationVersion": self.staged.schema_version,
                "databaseMigrationVersion": self.staged.database_migration_version,
                "dataCompatible": True,
            },
        )

    def start_successor(self, plan: Mapping[str, Any]) -> Mapping[str, Any]:
        self._begin("start-successor")
        self._end("start-successor")
        assert self.staged is not None
        return self._record_effect(
            plan["planDigest"],
            "start-successor",
            {
                "schema": "stateport.update-host-start/v1",
                "releaseId": self.staged.release_id,
                "runtimeDigest": self.staged.expected_revision_digest(),
                "status": "started",
            },
        )

    def health_successor(self, plan: Mapping[str, Any]) -> Mapping[str, Any]:
        self._begin("health-successor")
        self._end("health-successor")
        assert self.staged is not None
        return self._record_effect(
            plan["planDigest"],
            "health-successor",
            {
                "schema": "stateport.update-host-health/v1",
                "releaseId": self.staged.release_id,
                "runtimeDigest": self.staged.expected_revision_digest(),
                "healthy": True,
            },
        )

    def browser_successor(self, plan: Mapping[str, Any]) -> Mapping[str, Any]:
        self._begin("browser-successor")
        self._end("browser-successor")
        assert self.staged is not None
        return self._record_effect(
            plan["planDigest"],
            "browser-successor",
            {
                "schema": "stateport.update-host-browser-check/v1",
                "releaseId": self.staged.release_id,
                "status": "passed",
                "resultDigest": "sha256:" + "1" * 64,
            },
        )

    def studystate_successor(self, plan: Mapping[str, Any]) -> Mapping[str, Any]:
        self._begin("studystate-successor")
        self._end("studystate-successor")
        assert self.staged is not None
        return self._record_effect(
            plan["planDigest"],
            "studystate-successor",
            {
                "schema": "stateport.update-host-studystate-check/v1",
                "releaseId": self.staged.release_id,
                "status": "passed",
                "resultDigest": "sha256:" + "2" * 64,
            },
        )

    def state_check_successor(self, plan: Mapping[str, Any]) -> Mapping[str, Any]:
        self._begin("state-check-successor")
        self._end("state-check-successor")
        assert self.staged is not None
        return self._record_effect(
            plan["planDigest"],
            "state-check-successor",
            {
                "schema": "stateport.update-host-state-check/v1",
                "releaseId": self.staged.release_id,
                "status": "passed",
                "resultDigest": "sha256:" + "3" * 64,
            },
        )

    def switch(self, plan: Mapping[str, Any]) -> Mapping[str, Any]:
        self._begin("switch", effect="applied")
        assert self.staged is not None
        self.current = self.accepted
        self.accepted = self.staged
        self._end("switch", effect="applied")
        return self._record_effect(
            plan["planDigest"],
            "switch",
            {
                "schema": "stateport.update-host-switch/v1",
                "releaseId": self.accepted.release_id,
                "signedDigest": self.accepted.signed_digest,
                "runtimeDigest": self.accepted.expected_revision_digest(),
            },
        )

    def health_accepted_route(self, plan: Mapping[str, Any]) -> Mapping[str, Any]:
        self._begin("health-accepted-route", effect="applied")
        self._end("health-accepted-route", effect="applied")
        assert self.accepted is not None
        return self._record_effect(
            plan["planDigest"],
            "health-accepted-route",
            {
                "schema": "stateport.update-host-accepted-health/v1",
                "releaseId": self.accepted.release_id,
                "runtimeDigest": self.accepted.expected_revision_digest(),
                "healthy": True,
            },
        )

    def state_check_accepted_route(self, plan: Mapping[str, Any]) -> Mapping[str, Any]:
        self._begin("state-check-accepted-route", effect="applied")
        self._end("state-check-accepted-route", effect="applied")
        assert self.accepted is not None
        return self._record_effect(
            plan["planDigest"],
            "state-check-accepted-route",
            {
                "schema": "stateport.update-host-accepted-state/v1",
                "releaseId": self.accepted.release_id,
                "runtimeDigest": self.accepted.expected_revision_digest(),
                "status": "passed",
            },
        )

    def observe_accepted_revision(self) -> Mapping[str, Any]:
        self.calls.append("observe")
        if self.observe_failures:
            self.observe_failures -= 1
            raise UpdateHostError(
                "observation_unavailable",
                "fixture observation unavailable",
                effect="unknown",
            )
        assert self.accepted is not None
        runtime = self.accepted.expected_revision_digest()
        if self.wrong_runtime_digest:
            runtime = "sha256:" + "0" * 64
        return {
            "schema": "stateport.update-host-observation/v1",
            "releaseId": self.accepted.release_id,
            "signedDigest": self.accepted.signed_digest,
            "runtimeDigest": runtime,
        }

    def discard_successor(self, plan: Mapping[str, Any]) -> Mapping[str, Any]:
        self._begin("discard-successor")
        self.staged = None
        self._end("discard-successor")
        inventory = {
            "retainedArtifactIds": [plan["successor"]["releaseId"]],
            "removedRuntimeReleaseIds": [plan["successor"]["releaseId"]],
        }
        return self._record_effect(
            plan["planDigest"],
            "discard-successor",
            {
                "schema": "stateport.update-host-discard/v1",
                "releaseId": plan["successor"]["releaseId"],
                "status": "retained_for_evidence",
                **inventory,
                "inventoryDigest": canonical_digest(inventory),
            },
        )

    def rollback_failed_switch(self, plan: Mapping[str, Any]) -> Mapping[str, Any]:
        self._begin("automatic-rollback", effect="applied")
        assert self.current is not None
        self.accepted = self.current
        self._end("automatic-rollback", effect="applied")
        return self._record_effect(
            plan["planDigest"],
            "automatic-rollback",
            {
                "schema": "stateport.update-host-rollback/v1",
                "releaseId": self.current.release_id,
                "signedDigest": self.current.signed_digest,
                "runtimeDigest": self.current.expected_revision_digest(),
                "status": "restored",
            },
        )

    def enforce_retention(
        self,
        *,
        plan_digest: str,
        current_release_id: str,
        required_predecessor_ids: list[str],
        required_failure_evidence_ids: list[str],
        maximum_versions: int,
        maximum_age_days: int,
    ) -> Mapping[str, Any]:
        self.calls.append("retention")
        if self.retention_failures:
            self.retention_failures -= 1
            raise UpdateHostError(
                "retention_failed",
                "fixture retention failure",
                effect="unknown",
            )
        retained_releases = {
            current_release_id,
            *required_predecessor_ids,
        }
        retained_failures = set(required_failure_evidence_ids)
        removed_releases = self.release_inventory - retained_releases
        removed_failures = self.failure_artifact_inventory - retained_failures
        self.release_inventory = set(retained_releases)
        self.failure_artifact_inventory = set(retained_failures)
        inventory = {
            "currentReleaseId": current_release_id,
            "retainedReleaseIds": sorted(self.release_inventory),
            "removedReleaseIds": sorted(removed_releases),
            "retainedFailureArtifactIds": sorted(self.failure_artifact_inventory),
            "removedFailureArtifactIds": sorted(removed_failures),
        }
        evidence = {
            "schema": "stateport.update-host-retention/v1",
            **inventory,
            "inventoryDigest": canonical_digest(inventory),
            "maximumVersions": maximum_versions,
            "maximumAgeDays": maximum_age_days,
        }
        self.retention_history.append(deepcopy(evidence))
        return self._record_effect(plan_digest, "retain-predecessor", evidence)


class FixtureAuthority:
    def __init__(self) -> None:
        self.claims: dict[str, dict[str, Any]] = {}
        self.receipts: dict[str, dict[str, Any]] = {}
        self.finalize_calls = 0
        self.fail_finalize = 0

    @staticmethod
    def reserve(plan: Mapping[str, Any]) -> dict[str, Any]:
        suffix = plan["planDigest"].removeprefix("sha256:")[:32]
        request_id = f"authority_request_{suffix}"
        decision = {
            "schema": "stateport.authority-decision/v1",
            "requestId": request_id,
            "action": plan["authority"]["action"],
            "actorId": "fixture-updater",
            "authorizedBy": {
                "type": "grant",
                "id": "grant_fixture_updater",
                "digest": "sha256:" + "a" * 64,
            },
            "scope": {
                "repository": {
                    "origin": "https://github.com/stateport/stateport.git",
                    "repositoryKey": "b" * 32,
                    "repositoryRoot": "/tmp/stateport-fixture",
                },
                "branch": "agent/fixture",
                "sliceId": "BL-FIXTURE",
                "applicationId": "stateport",
                "runId": plan["planDigest"],
                "paths": ["packages/updater"],
            },
            "profile": "balanced",
            "configuredPolicy": "auto_with_receipt",
            "policy": "auto_with_receipt",
            "decision": "authorized",
            "reason": "standing_scope_approved",
            "missingAssurances": [],
            "estimatedCostUsd": 0,
            "estimatedDurationSeconds": 3600,
            "requestedCapabilities": {
                "domains": [],
                "provider": None,
                "secretCapabilities": [],
                "assurances": [],
                "sourceIdentity": None,
            },
            "decidedAt": "2026-08-01T12:00:00Z",
            "decisionDigest": "sha256:" + "c" * 64,
        }
        reservation = {
            "schema": "stateport.authority-action-reservation/v1",
            "reservationId": f"authority_reservation_{suffix}",
            "requestId": request_id,
            "decision": deepcopy(decision),
            "reservedAt": "2026-08-01T12:00:00Z",
            "reservationDigest": "sha256:" + "d" * 64,
        }
        return {"decision": decision, "reservation": reservation}

    def validate_reservation(
        self, plan: Mapping[str, Any], authorization: Mapping[str, Any]
    ) -> dict[str, Any]:
        expected = self.reserve(plan)
        if dict(authorization) != expected:
            raise RuntimeError("fixture authority mismatch")
        return expected

    def claim(self, binding: Mapping[str, Any]) -> dict[str, Any]:
        request_id = binding["decision"]["requestId"]
        suffix = request_id.removeprefix("authority_request_")
        claim = {
            "schema": "stateport.authority-action-claim/v1",
            "claimId": f"authority_claim_{suffix}",
            "requestId": request_id,
            "reservationId": binding["reservation"]["reservationId"],
            "reservationDigest": binding["reservation"]["reservationDigest"],
            "decisionDigest": binding["decision"]["decisionDigest"],
            "claimedAt": "2026-08-01T12:00:00Z",
            "claimDigest": "sha256:" + "e" * 64,
        }
        existing = self.claims.setdefault(request_id, claim)
        if existing != claim:
            raise RuntimeError("claim conflict")
        return existing

    def recover_claim(self, request_id: str) -> dict[str, Any] | None:
        return self.claims.get(request_id)

    def terminal_receipt(self, request_id: str) -> dict[str, Any] | None:
        return self.receipts.get(request_id)

    def finalize(
        self,
        binding: Mapping[str, Any],
        *,
        result_status: str,
        code: str | None,
        summary: str,
        resource: Mapping[str, Any],
        started_at: datetime,
    ) -> dict[str, Any]:
        self.finalize_calls += 1
        if self.fail_finalize:
            self.fail_finalize -= 1
            raise RuntimeError("fixture finalization unavailable")
        request_id = binding["decision"]["requestId"]
        suffix = request_id.removeprefix("authority_request_")
        body = {
            "receiptId": f"authority_receipt_{suffix}",
            "receiptDigest": "sha256:" + "f" * 64,
            "completedAt": "2026-08-01T12:00:00Z",
            "decisionDigest": binding["decision"]["decisionDigest"],
            "claim": {"claimId": binding["claim"]["claimId"]},
            "result": {"status": result_status, "code": code, "resource": dict(resource)},
            "summary": summary,
            "startedAt": started_at.isoformat(),
        }
        existing = self.receipts.setdefault(request_id, body)
        if existing != body:
            raise RuntimeError("authority terminal conflict")
        return existing


class SimulatedCrash(BaseException):
    pass


class OneShotCrash:
    def __init__(self, phase: str) -> None:
        self.phase = phase
        self.fired = False

    def __call__(self, phase: str) -> None:
        if phase == self.phase and not self.fired:
            self.fired = True
            raise SimulatedCrash(phase)


class SequenceCrash:
    def __init__(self, phases: list[str]) -> None:
        self.phases = list(phases)

    def __call__(self, phase: str) -> None:
        if self.phases and phase == self.phases[0]:
            self.phases.pop(0)
            raise SimulatedCrash(phase)


def test_torn_genesis_initialize_adopts_the_existing_admission(tmp_path: Path) -> None:
    """F4: a crash between save_admission and initialize_status must not turn
    the rerun into a permanent updater_genesis_conflict.  The rerun adopts
    the existing admission and restores the exact status it binds."""
    updater, _host, _authority, _successor, _document = initialized_engine(tmp_path)
    store_root = tmp_path / "updater"
    status_path = store_root / "status.json"
    status_bytes = status_path.read_bytes()
    admissions = sorted((store_root / "release-admissions").glob("*.json"))
    assert len(admissions) == 1
    admission_bytes = admissions[0].read_bytes()

    # Simulate the crash window: admission persisted, status never written.
    status_path.unlink()

    later = NOW + timedelta(hours=1)  # wall clock moved: verifiedAt diverges
    reopened = UpdateEngine(
        UpdateStore.open_existing(store_root),
        FixtureHost(),
        FixtureAuthority(),
        verification_policy=POLICY,
        signature_verifier=_EphemeralTestVerifier(),
        clock=lambda: later,
    )
    current, _doc, _identity = envelope(
        "stateport-alpha-0.1.0-rc.1", "0.1.0-rc.1", predecessor=None
    )
    reopened.initialize(current, UpdatePolicy(mode="download-and-notify", channel="alpha"))

    assert status_path.read_bytes() == status_bytes
    remaining = sorted((store_root / "release-admissions").glob("*.json"))
    assert [path.read_bytes() for path in remaining] == [admission_bytes]


def test_torn_genesis_admission_for_another_release_refuses(tmp_path: Path) -> None:
    updater, _host, _authority, _successor, _document = initialized_engine(tmp_path)
    store_root = tmp_path / "updater"
    (store_root / "status.json").unlink()
    reopened = UpdateEngine(
        UpdateStore.open_existing(store_root),
        FixtureHost(),
        FixtureAuthority(),
        verification_policy=POLICY,
        signature_verifier=_EphemeralTestVerifier(),
        clock=lambda: NOW,
    )
    other, _doc, _identity = envelope(
        "stateport-alpha-0.9.0-rc.9", "0.9.0-rc.9", predecessor=None
    )
    with pytest.raises(UpdateError) as failure:
        reopened.initialize(other, UpdatePolicy(mode="download-and-notify", channel="alpha"))
    assert failure.value.code in {"admission_conflict", "already_initialized"}
    assert not (store_root / "status.json").exists()


def initialized_engine(
    tmp_path: Path,
    *,
    host: FixtureHost | None = None,
    authority: Any | None = None,
    failpoint: Any | None = None,
    update_policy: UpdatePolicy | None = None,
    clock: Callable[[], datetime] | None = None,
) -> tuple[UpdateEngine, FixtureHost, Any, Any, Any]:
    selected_host = host or FixtureHost()
    selected_authority = authority or FixtureAuthority()
    current, _document, current_identity = envelope(
        "stateport-alpha-0.1.0-rc.1", "0.1.0-rc.1", predecessor=None
    )
    successor, successor_document, _successor_identity = envelope(
        "stateport-alpha-0.2.0-rc.1",
        "0.2.0-rc.1",
        predecessor=current_identity,
    )
    updater = UpdateEngine(
        UpdateStore.create(tmp_path / "updater"),
        selected_host,
        selected_authority,
        verification_policy=POLICY,
        signature_verifier=_EphemeralTestVerifier(),
        clock=clock or (lambda: NOW),
        failpoint=failpoint,
    )
    updater.initialize(
        current,
        update_policy or UpdatePolicy(mode="download-and-notify", channel="alpha"),
    )
    selected_host.current = updater._facts(current, channel="alpha")
    selected_host.accepted = selected_host.current
    selected_host.release_inventory.add(selected_host.current.release_id)
    return updater, selected_host, selected_authority, successor, successor_document


def initialized_pinned_engine(
    tmp_path: Path,
    *,
    host: FixtureHost | None = None,
    authority: Any | None = None,
) -> tuple[UpdateEngine, FixtureHost, Any, Any, Any]:
    selected_host = host or FixtureHost()
    selected_authority = authority or FixtureAuthority()
    current, _document, current_identity = pinned_envelope(
        "stateport-alpha-0.1.0-rc.1", "0.1.0-rc.1", predecessor=None
    )
    successor, successor_document, _successor_identity = pinned_envelope(
        "stateport-alpha-0.2.0-rc.1",
        "0.2.0-rc.1",
        predecessor=current_identity,
    )
    updater = UpdateEngine(
        UpdateStore.create(tmp_path / "updater"),
        selected_host,
        selected_authority,
        verification_policy=PINNED_POLICY,
        signature_verifier=_EphemeralTestVerifier(),
        clock=lambda: NOW,
    )
    updater.initialize(
        current,
        UpdatePolicy(mode="download-and-notify", channel="alpha"),
    )
    selected_host.current = updater._facts(current, channel="alpha")
    selected_host.accepted = selected_host.current
    selected_host.release_inventory.add(selected_host.current.release_id)
    return updater, selected_host, selected_authority, successor, successor_document


def reopened_engine(
    tmp_path: Path,
    host: FixtureHost,
    authority: Any,
    *,
    failpoint: Any | None = None,
    clock: Callable[[], datetime] | None = None,
) -> UpdateEngine:
    return UpdateEngine(
        UpdateStore.open_existing(tmp_path / "updater"),
        host,
        authority,
        verification_policy=POLICY,
        signature_verifier=_EphemeralTestVerifier(),
        clock=clock or (lambda: NOW),
        failpoint=failpoint,
    )


def planned(
    updater: UpdateEngine,
    authority: Any,
    successor: Any,
) -> tuple[dict[str, Any], dict[str, Any]]:
    plan = updater.plan(successor)
    return plan, authority.reserve(plan)


def rewrite_pending(tmp_path: Path, mutate: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    path = tmp_path / "updater/pending.json"
    journal = json.loads(path.read_text())
    mutate(journal)
    journal["journalDigest"] = journal_digest(journal)
    path.write_text(json.dumps(journal), encoding="utf-8")
    return journal


def test_happy_update_persists_only_canonical_index_and_validated_contracts(
    tmp_path: Path,
) -> None:
    updater, host, authority, successor, _document = initialized_engine(tmp_path)
    plan, authorization = planned(updater, authority, successor)
    receipt = updater.apply(plan["planId"], authorization)

    assert validate_update_plan(plan, now=NOW).digest == plan["planDigest"]
    assert validate_update_receipt(receipt).document["result"] == "accepted"
    assert (
        validate_update_status(updater.status())
        .document["current"]["releaseId"]
        .endswith("0.2.0-rc.1")
    )
    assert updater.status()["retainedPredecessor"]["releaseId"].endswith("0.1.0-rc.1")
    release_files = sorted((tmp_path / "updater/releases").iterdir())
    assert len(release_files) == 2
    assert all(item.name.endswith(".release-index.json") for item in release_files)
    assert not any(item.name.endswith(".verified.json") for item in release_files)
    assert authority.finalize_calls == 1
    assert host.calls.count("observe") == 1
    links = list((tmp_path / "updater/authority-links").glob("*.json"))
    assert len(links) == 1
    assert validate_update_authority_link(json.loads(links[0].read_text())).digest


def test_admission_projects_only_the_exact_release_signature_that_verified(
    tmp_path: Path,
) -> None:
    document = release_index()
    accepted = deepcopy(document["signatures"][0])
    rejected = deepcopy(accepted)
    rejected["bundle"]["uri"] = "operator://release/rejected.sigstore.json"
    rejected["bundle"]["digest"] = "sha256:" + "1" * 64
    document["signatures"] = [rejected, accepted]

    class SelectiveVerifier:
        def __init__(self) -> None:
            self._delegate = _EphemeralTestVerifier()

        def _reject(self, signature: Mapping[str, Any]) -> None:
            if signature["bundle"]["uri"].endswith("rejected.sigstore.json"):
                raise ValueError("fixture rejects this exact bundle")

        def verify_blob(self, payload: bytes, signature: Mapping[str, Any]) -> Any:
            assert payload
            self._reject(signature)
            return self._delegate.verify_blob(payload, dict(signature))

        def verify_image(self, reference: str, signature: Mapping[str, Any]) -> Any:
            self._reject(signature)
            return self._delegate.verify_image(reference, dict(signature))

    verifier = SelectiveVerifier()
    # The evolved release contract fails closed when any signed signature
    # cannot be verified, so the two-signature document is refused outright.
    with pytest.raises(ReleaseContractError):
        verify_release_index(document, policy=POLICY, verifier=verifier)
    document["signatures"] = [accepted]
    verified = verify_release_index(document, policy=POLICY, verifier=verifier)
    updater = UpdateEngine(
        UpdateStore.create(tmp_path / "updater"),
        FixtureHost(),
        FixtureAuthority(),
        verification_policy=POLICY,
        signature_verifier=verifier,
        clock=lambda: NOW,
    )
    updater.initialize(
        to_updater_release_envelope(verified),
        UpdatePolicy(mode="download-and-notify", channel="alpha"),
    )

    admission_path = next((tmp_path / "updater/release-admissions").glob("*.json"))
    admission = json.loads(admission_path.read_text())
    release_proofs = [
        proof for proof in admission["signatureProofs"] if proof["subjectKind"] == "release-index"
    ]
    assert [proof["signatureDescriptorDigest"] for proof in release_proofs] == [
        canonical_digest(accepted)
    ]
    assert canonical_digest(rejected) not in {
        proof["signatureDescriptorDigest"] for proof in admission["signatureProofs"]
    }


PINNED_PROOF_FIELDS = {
    "trustMode",
    "keyId",
    "publicKeyDigest",
    "scheme",
    "subjectKind",
    "subjectId",
    "subjectDigest",
    "bundleDigest",
    "signatureDescriptorDigest",
    "transparencyLog",
    "verificationState",
}


def test_pinned_initialize_admission_roundtrips_store_revalidation(tmp_path: Path) -> None:
    updater, _host, _authority, successor, _document = initialized_pinned_engine(tmp_path)

    admission_path = next((tmp_path / "updater/release-admissions").glob("*.json"))
    admission = updater_store._validated_admission(json.loads(admission_path.read_text()))
    assert admission["kind"] == "installed-initialize"
    assert admission["trustMode"] == "pinned-public-key"
    expected_signers = [
        {
            "mode": "pinned-public-key",
            "keyId": PINNED_KEY.key_id,
            "publicKeyDigest": PINNED_KEY.public_key_fingerprint,
        }
    ]
    assert admission["verificationPolicy"]["acceptedSigners"] == expected_signers
    assert admission["verifiedSigners"] == expected_signers
    proofs = admission["signatureProofs"]
    assert all(set(proof) == PINNED_PROOF_FIELDS for proof in proofs)
    assert all(proof["trustMode"] == "pinned-public-key" for proof in proofs)
    assert all(proof["keyId"] == PINNED_KEY.key_id for proof in proofs)
    assert all(proof["publicKeyDigest"] == PINNED_KEY.public_key_fingerprint for proof in proofs)
    assert all(proof["transparencyLog"] == "not-uploaded-private-candidate" for proof in proofs)
    release_proofs = [proof for proof in proofs if proof["subjectKind"] == "release-index"]
    assert len(release_proofs) == 1
    assert release_proofs[0]["verificationState"] == "verified"
    image_proofs = [proof for proof in proofs if proof["subjectKind"] == "image"]
    assert image_proofs
    assert all(proof["verificationState"] == "signed-index-declaration" for proof in image_proofs)

    # Historic re-authentication of the exact persisted bytes succeeds.
    plan = updater.plan(successor)
    assert plan["current"]["releaseId"].endswith("0.1.0-rc.1")


def test_pinned_update_apply_persists_pinned_successor_admission(tmp_path: Path) -> None:
    updater, _host, authority, successor, _document = initialized_pinned_engine(tmp_path)
    plan, authorization = planned(updater, authority, successor)
    receipt = updater.apply(plan["planId"], authorization)

    assert validate_update_receipt(receipt).document["result"] == "accepted"
    assert (
        validate_update_status(updater.status())
        .document["current"]["releaseId"]
        .endswith("0.2.0-rc.1")
    )
    records = [
        updater_store._validated_admission(json.loads(path.read_text()))
        for path in sorted((tmp_path / "updater/release-admissions").glob("*.json"))
    ]
    assert len(records) == 2
    assert all(record["trustMode"] == "pinned-public-key" for record in records)
    update = next(record for record in records if record["kind"] == "update-apply")
    assert update["releaseId"].endswith("0.2.0-rc.1")
    assert update["planDigest"] == plan["planDigest"]
    assert update["verifiedSigners"] == [
        {
            "mode": "pinned-public-key",
            "keyId": PINNED_KEY.key_id,
            "publicKeyDigest": PINNED_KEY.public_key_fingerprint,
        }
    ]
    assert all(set(proof) == PINNED_PROOF_FIELDS for proof in update["signatureProofs"])


def test_pinned_admission_refusal_matrix(tmp_path: Path) -> None:
    initialized_pinned_engine(tmp_path)
    admission_path = next((tmp_path / "updater/release-admissions").glob("*.json"))
    base = json.loads(admission_path.read_text())

    def refuse(mutate: Callable[[dict[str, Any]], None], code: str) -> None:
        admission = deepcopy(base)
        mutate(admission)
        with pytest.raises(StoreError) as failure:
            updater_store._validated_admission(admission)
        assert failure.value.code == code

    # Tampered body: the verification policy digest no longer matches.
    refuse(
        lambda admission: admission.update({"verifiedAt": "2026-08-01T13:00:00Z"}),
        "admission_tampered",
    )
    # A proof naming the wrong key id does not bind the verified signers.
    refuse(
        lambda admission: admission["signatureProofs"][0].update({"keyId": "attacker-key"}),
        "admission_invalid",
    )
    # A proof naming the wrong public-key digest does not bind the signers.
    refuse(
        lambda admission: admission["signatureProofs"][0].update(
            {"publicKeyDigest": "sha256:" + "8" * 64}
        ),
        "admission_invalid",
    )
    # A raw key can never claim keyless transparency-log authority.
    refuse(
        lambda admission: admission["signatureProofs"][0].update(
            {"transparencyLog": "required-public-release"}
        ),
        "admission_invalid",
    )
    # A keyless signer mapping inside a pinned admission is mixed trust.
    refuse(
        lambda admission: admission.update(
            {
                "verifiedSigners": [
                    {
                        "mode": "keyless",
                        "certificateIdentity": SIGNER.certificate_identity,
                        "oidcIssuer": SIGNER.oidc_issuer,
                    }
                ]
            }
        ),
        "admission_invalid",
    )
    # Verified signers outside the accepted policy are not historic authority.
    refuse(
        lambda admission: admission["verifiedSigners"][0].update({"keyId": "attacker-key"}),
        "admission_invalid",
    )

    # The release index itself must carry a verified signature proof.
    def demote_release_proof(admission: dict[str, Any]) -> None:
        for proof in admission["signatureProofs"]:
            if proof["subjectKind"] == "release-index":
                proof["verificationState"] = "signed-index-declaration"

    refuse(demote_release_proof, "admission_invalid")


def test_pinned_signer_refused_inside_keyless_admission(tmp_path: Path) -> None:
    initialized_engine(tmp_path)
    admission_path = next((tmp_path / "updater/release-admissions").glob("*.json"))
    admission = json.loads(admission_path.read_text())
    admission["verifiedSigners"][0]["mode"] = "pinned-public-key"
    with pytest.raises(StoreError) as failure:
        updater_store._validated_admission(admission)
    assert failure.value.code == "admission_invalid"


def test_pinned_self_digested_forged_local_admission_fails_exact_reverification(
    tmp_path: Path,
) -> None:
    updater, _host, _authority, successor, _document = initialized_pinned_engine(tmp_path)
    admission_path = next((tmp_path / "updater/release-admissions").glob("*.json"))
    admission = json.loads(admission_path.read_text())
    proof = next(
        item for item in admission["signatureProofs"] if item["subjectKind"] == "release-index"
    )
    proof["bundleDigest"] = "sha256:" + "9" * 64
    body = {
        key: value
        for key, value in admission.items()
        if key not in {"admissionId", "admissionDigest"}
    }
    admission["admissionDigest"] = canonical_digest(body)
    admission["admissionId"] = (
        "release_admission_" + admission["admissionDigest"].removeprefix("sha256:")[:32]
    )
    admission_path.unlink()
    forged_path = admission_path.with_name(f"{admission['admissionId']}.json")
    forged_path.write_text(json.dumps(admission), encoding="utf-8")
    forged_path.chmod(0o600)

    with pytest.raises(UpdateError) as failure:
        updater.plan(successor)
    assert failure.value.code == "historic_authentication_failed"


def test_historic_policy_rebuilds_pinned_trust_from_pinned_admission(tmp_path: Path) -> None:
    initialized_pinned_engine(tmp_path)
    store = UpdateStore.open_existing(tmp_path / "updater")
    policy = updater_cli._historic_verification_policy(store)
    assert policy.expected_trust_mode == "pinned-public-key"
    assert policy.accepted_signers == frozenset()
    assert policy.accepted_public_keys == frozenset({PINNED_KEY})


def test_repeat_initialize_refuses_without_any_persistent_residue(tmp_path: Path) -> None:
    updater, _host, _authority, _successor, _document = initialized_engine(tmp_path)
    replacement, _replacement_document, _replacement_identity = envelope(
        "stateport-alpha-9.9.9-rc.1",
        "9.9.9-rc.1",
        predecessor=None,
    )
    root = tmp_path / "updater"

    def snapshot() -> dict[str, bytes]:
        return {
            path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob("*")
            if path.is_file()
        }

    before = snapshot()
    with pytest.raises(UpdateError) as failure:
        updater.initialize(
            replacement,
            UpdatePolicy(mode="notify", channel="alpha"),
        )
    after = snapshot()

    assert failure.value.code == "already_initialized"
    assert after == before
    assert not any("9.9.9" in name for name in after)


def test_concurrent_initialize_allows_one_exact_release_without_loser_residue(
    tmp_path: Path,
) -> None:
    first, _first_document, _first_identity = envelope(
        "stateport-alpha-0.1.0-rc.1",
        "0.1.0-rc.1",
        predecessor=None,
    )
    second, _second_document, _second_identity = envelope(
        "stateport-alpha-9.9.9-rc.1",
        "9.9.9-rc.1",
        predecessor=None,
    )
    rendezvous = Barrier(2)

    class BlockingVerifier(_EphemeralTestVerifier):
        def verify_blob(self, payload: bytes, signature: dict[str, object]) -> Any:
            proof = super().verify_blob(payload, signature)
            rendezvous.wait(timeout=5)
            return proof

    root = tmp_path / "updater"
    engines = [
        UpdateEngine(
            store,
            FixtureHost(),
            FixtureAuthority(),
            verification_policy=POLICY,
            signature_verifier=BlockingVerifier(),
            clock=lambda: NOW,
        )
        for store in (UpdateStore.create(root), UpdateStore.open_existing(root))
    ]
    results: list[object] = []

    def initialize(engine: UpdateEngine, candidate: Any) -> None:
        try:
            results.append(
                engine.initialize(
                    candidate,
                    UpdatePolicy(mode="download-and-notify", channel="alpha"),
                )
            )
        except Exception as exc:  # asserted as one exact typed loser below
            results.append(exc)

    threads = [
        Thread(target=initialize, args=(engine, candidate))
        for engine, candidate in zip(engines, (first, second), strict=True)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
        assert not thread.is_alive()

    assert len([item for item in results if isinstance(item, dict)]) == 1
    failures = [item for item in results if isinstance(item, UpdateError)]
    assert len(failures) == 1 and failures[0].code == "already_initialized"
    assert len(list((root / "releases").glob("*.json"))) == 1
    assert len(list((root / "release-admissions").glob("*.json"))) == 1


def test_self_digested_forged_local_admission_fails_exact_reverification(
    tmp_path: Path,
) -> None:
    updater, _host, _authority, successor, _document = initialized_engine(tmp_path)
    admission_path = next((tmp_path / "updater/release-admissions").glob("*.json"))
    admission = json.loads(admission_path.read_text())
    proof = next(
        item for item in admission["signatureProofs"] if item["subjectKind"] == "release-index"
    )
    proof["bundleDigest"] = "sha256:" + "9" * 64
    body = {
        key: value
        for key, value in admission.items()
        if key not in {"admissionId", "admissionDigest"}
    }
    admission["admissionDigest"] = canonical_digest(body)
    admission["admissionId"] = (
        "release_admission_" + admission["admissionDigest"].removeprefix("sha256:")[:32]
    )
    admission_path.unlink()
    forged_path = admission_path.with_name(f"{admission['admissionId']}.json")
    forged_path.write_text(json.dumps(admission), encoding="utf-8")
    forged_path.chmod(0o600)

    with pytest.raises(UpdateError) as failure:
        updater.plan(successor)
    assert failure.value.code == "historic_authentication_failed"


def test_original_nested_release_mapping_mutation_cannot_change_verified_envelope(
    tmp_path: Path,
) -> None:
    updater, _host, _authority, successor, source_document = initialized_engine(tmp_path)
    expected_id = successor.document["release"]["releaseId"]
    source_document["signed"]["release"]["releaseId"] = "attacker-mutated"
    checked = updater.check(successor)
    assert checked["successor"]["releaseId"] == expected_id


def test_split_store_to_shared_store_refuses_before_host_preflight(tmp_path: Path) -> None:
    updater, host, _authority, _successor, _document = initialized_engine(tmp_path)
    before = {
        path.relative_to(tmp_path): path.read_bytes()
        for path in sorted(tmp_path.rglob("*"))
        if path.is_file()
    }
    current = updater.status()["current"]
    successor, document, _identity = envelope(
        "stateport-alpha-0.2.0-rc.1",
        "0.2.0-rc.1",
        predecessor=current,
    )
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
            "volumeKey": "stateport-shared:stateport-operations",
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
    target["topologyDigest"] = topology_digest(target)
    target["quadletBundleDigest"] = quadlet_bundle_digest(
        render_quadlet_bundle(target, signed["images"])
    )
    document["signatures"] = [
        _signature(canonical_digest(signed), "release-index-stateport-alpha-0.2.0-rc.1")
    ]
    verified = verify_release_index(document, policy=POLICY, verifier=_EphemeralTestVerifier())
    successor = to_updater_release_envelope(verified)

    with pytest.raises(UpdateError) as failure:
        updater.check(successor)

    assert failure.value.code == "shared_volume_migration_required"
    assert "preflight" not in host.calls
    after = {
        path.relative_to(tmp_path): path.read_bytes()
        for path in sorted(tmp_path.rglob("*"))
        if path.is_file()
    }
    assert after == before


def test_plan_and_pull_select_only_images_referenced_by_exact_target(tmp_path: Path) -> None:
    updater, host, authority, _successor, _document = initialized_engine(tmp_path)
    current = updater.status()["current"]
    successor, _document, _identity = envelope(
        "stateport-alpha-0.2.0-rc.1",
        "0.2.0-rc.1",
        predecessor=current,
        include_non_target_image=True,
    )
    facts = updater._facts(successor, channel="alpha")
    assert len(facts.images) == 3
    assert len(facts.target_images) == 1
    plan, authorization = planned(updater, authority, successor)
    assert plan["estimatedPullBytes"] == facts.target_images[0]["sizeBytes"]
    updater.apply(plan["planId"], authorization)
    archived = next((tmp_path / "updater/journals").glob("*.json"))
    journal = json.loads(archived.read_text())
    pull_record = next(item["evidence"] for item in journal["steps"] if item["step"] == "pull")
    pull = pull_record["evidence"]
    assert pull["imageDigests"] == [facts.target_images[0]["digest"]]
    assert host.calls.count("pull") == 1


def test_historic_accepted_release_requires_canonical_terminal_authority_receipt(
    tmp_path: Path,
) -> None:
    updater, _host, authority, successor, _document = initialized_engine(tmp_path)
    plan, authorization = planned(updater, authority, successor)
    updater.apply(plan["planId"], authorization)
    current = updater.status()["current"]
    next_release, _next_document, _next_identity = envelope(
        "stateport-alpha-0.3.0-rc.1",
        "0.3.0-rc.1",
        predecessor=current,
    )

    authority.receipts.clear()
    with pytest.raises(UpdateError) as failure:
        updater.plan(next_release)

    assert failure.value.code == "release_admission_missing"


def test_tampered_persisted_canonical_index_fails_reverification(tmp_path: Path) -> None:
    updater, _host, authority, successor, _document = initialized_engine(tmp_path)
    plan, _authorization = planned(updater, authority, successor)
    release_path = next(
        item for item in (tmp_path / "updater/releases").iterdir() if "0.2.0" in item.name
    )
    value = json.loads(release_path.read_text())
    value["signed"]["release"]["version"] = "9.9.9"
    release_path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(UpdateError, match="signature|digest|bound|canonical"):
        updater.apply(plan["planId"], authority.reserve(plan))


def test_exact_runtime_digest_mismatch_is_not_accepted(tmp_path: Path) -> None:
    host = FixtureHost()
    host.wrong_runtime_digest = True
    updater, _host, authority, successor, _document = initialized_engine(tmp_path, host=host)
    plan, authorization = planned(updater, authority, successor)
    with pytest.raises(UpdateError) as failure:
        updater.apply(plan["planId"], authorization)
    assert failure.value.code == "reconciliation_required"
    assert updater.status()["lastReceipt"] is None
    assert authority.finalize_calls == 0


@pytest.mark.parametrize(
    "phase",
    [
        "after_receipt_save_before_journal",
        "after_state_flip_before_journal",
        "after_authority_finalize_before_journal",
        "after_authority_journal_before_link",
        "after_link_before_journal",
        "after_retention_before_journal",
    ],
)
def test_terminal_crash_matrix_recovers_once_without_duplicate_receipts(
    tmp_path: Path,
    phase: str,
) -> None:
    crash = OneShotCrash(phase)
    updater, _host, authority, successor, _document = initialized_engine(tmp_path, failpoint=crash)
    plan, authorization = planned(updater, authority, successor)
    with pytest.raises(SimulatedCrash):
        updater.apply(plan["planId"], authorization)

    receipt = updater.reconcile()
    assert receipt["result"] == "accepted"
    assert len(list((tmp_path / "updater/receipts").glob("*.json"))) == 1
    assert len(list((tmp_path / "updater/authority-links").glob("*.json"))) == 1
    assert len(list((tmp_path / "updater/journals").glob("*.json"))) == 1
    assert not (tmp_path / "updater/pending.json").exists()
    assert authority.finalize_calls in {1, 2}
    assert len(authority.receipts) == 1


def test_terminal_status_write_failure_recovers_without_reapplying_host_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    updater, host, authority, successor, _document = initialized_engine(tmp_path)
    plan, authorization = planned(updater, authority, successor)
    original = updater_store.replace_json
    failed = False

    def fail_terminal_status(
        path: Path,
        value: Mapping[str, Any],
        label: str,
    ) -> None:
        nonlocal failed
        if label == "update status" and value.get("lastReceipt") is not None and not failed:
            failed = True
            raise updater_safe_io.SafeIOError(
                "state_write_failed",
                "fixture terminal status write failed",
            )
        original(path, value, label)

    monkeypatch.setattr(updater_store, "replace_json", fail_terminal_status)
    with pytest.raises(UpdateError) as failure:
        updater.apply(plan["planId"], authorization)
    assert failure.value.code == "state_write_failed"
    calls = {
        step: host.calls.count(step)
        for step in ("backup", "pull", "stage", "start-successor", "switch")
    }

    monkeypatch.setattr(updater_store, "replace_json", original)
    recovered = reopened_engine(tmp_path, host, authority).reconcile()

    assert recovered["result"] == "accepted"
    assert {
        step: host.calls.count(step)
        for step in ("backup", "pull", "stage", "start-successor", "switch")
    } == calls
    assert len(list((tmp_path / "updater/receipts").glob("*.json"))) == 1
    assert authority.finalize_calls == 1


def test_reconcile_rejects_reordered_wal_steps_even_with_recomputed_digest(
    tmp_path: Path,
) -> None:
    crash = OneShotCrash("after_journal_stage")
    updater, host, authority, successor, _document = initialized_engine(
        tmp_path,
        failpoint=crash,
    )
    plan, authorization = planned(updater, authority, successor)
    with pytest.raises(SimulatedCrash):
        updater.apply(plan["planId"], authorization)

    def reorder(journal: dict[str, Any]) -> None:
        by_name = {item["step"]: position for position, item in enumerate(journal["steps"])}
        left, right = by_name["backup"], by_name["pull"]
        journal["steps"][left], journal["steps"][right] = (
            journal["steps"][right],
            journal["steps"][left],
        )

    rewrite_pending(tmp_path, reorder)
    calls = list(host.calls)
    with pytest.raises(UpdateError) as failure:
        updater.reconcile()

    assert failure.value.code == "journal_semantic_invalid"
    assert host.calls == calls
    assert authority.finalize_calls == 0


def test_reconcile_rechecks_forged_completed_gate_instead_of_skipping_it(
    tmp_path: Path,
) -> None:
    crash = OneShotCrash("after_journal_browser-successor")
    updater, host, authority, successor, _document = initialized_engine(
        tmp_path,
        failpoint=crash,
    )
    plan, authorization = planned(updater, authority, successor)
    with pytest.raises(SimulatedCrash):
        updater.apply(plan["planId"], authorization)

    def forge_gate(journal: dict[str, Any]) -> None:
        browser = next(item for item in journal["steps"] if item["step"] == "browser-successor")
        browser["evidence"]["evidence"]["resultDigest"] = "sha256:" + "8" * 64

    rewrite_pending(tmp_path, forge_gate)
    with pytest.raises(UpdateError) as failure:
        updater.reconcile()

    assert failure.value.code == "host_effect_receipt_invalid"
    assert "studystate-successor" not in host.calls
    assert "switch" not in host.calls
    assert authority.finalize_calls == 0


def test_reconcile_rejects_fabricated_backup_prefix_without_host_receipt(
    tmp_path: Path,
) -> None:
    crash = OneShotCrash("before_effect_backup")
    updater, host, authority, successor, _document = initialized_engine(
        tmp_path,
        failpoint=crash,
    )
    plan, authorization = planned(updater, authority, successor)
    with pytest.raises(SimulatedCrash):
        updater.apply(plan["planId"], authorization)

    def fabricate_backup(journal: dict[str, Any]) -> None:
        evidence = {
            "schema": "stateport.update-host-backup/v1",
            "planDigest": plan["planDigest"],
            "receiptId": "backup_forged",
            "backupDigest": "sha256:" + "b" * 64,
        }
        evidence_digest = canonical_digest(evidence)
        seed = canonical_digest(
            {
                "planDigest": plan["planDigest"],
                "step": "backup",
                "evidenceDigest": evidence_digest,
            }
        )
        journal["steps"].append(
            {
                "step": "backup",
                "at": NOW.isoformat().replace("+00:00", "Z"),
                "evidence": {
                    "schema": "stateport.internal-update-step-record/v1",
                    "evidence": evidence,
                    "hostReceipt": {
                        "schema": "stateport.update-host-effect-receipt/v1",
                        "receiptId": ("host_effect_receipt_" + seed.removeprefix("sha256:")[:32]),
                        "planDigest": plan["planDigest"],
                        "step": "backup",
                        "status": "observed",
                        "evidence": evidence,
                        "evidenceDigest": evidence_digest,
                    },
                },
            }
        )
        journal["phase"] = "backup"
        journal["intent"] = None

    rewrite_pending(tmp_path, fabricate_backup)
    with pytest.raises(UpdateError) as failure:
        updater.reconcile()

    assert failure.value.code == "journal_effect_revalidation_failed"
    assert "pull" not in host.calls
    assert authority.finalize_calls == 0


def test_forged_wal_authority_receipt_cannot_skip_canonical_finalization(
    tmp_path: Path,
) -> None:
    crash = OneShotCrash("after_authority_finalize_before_journal")
    updater, _host, authority, successor, _document = initialized_engine(
        tmp_path,
        failpoint=crash,
    )
    plan, authorization = planned(updater, authority, successor)
    with pytest.raises(SimulatedCrash):
        updater.apply(plan["planId"], authorization)
    canonical = deepcopy(authority.receipts[authorization["decision"]["requestId"]])

    def forge_authority(journal: dict[str, Any]) -> None:
        forged = deepcopy(canonical)
        forged["receiptDigest"] = "sha256:" + "0" * 64
        journal["canonicalAuthorityReceipt"] = forged
        journal["phase"] = "authority_finalized"

    rewrite_pending(tmp_path, forge_authority)
    with pytest.raises(UpdateError) as failure:
        updater.reconcile()

    assert failure.value.code == "authority_receipt_conflict"
    assert authority.finalize_calls == 2
    assert not list((tmp_path / "updater/authority-links").glob("*.json"))


def test_cross_plan_prepared_receipt_substitution_is_rejected_before_replay(
    tmp_path: Path,
) -> None:
    crash = OneShotCrash("before_receipt_save")
    updater, host, authority, successor, _document = initialized_engine(
        tmp_path,
        failpoint=crash,
    )
    first_plan, first_authorization = planned(updater, authority, successor)
    other, _other_document, _other_identity = envelope(
        "stateport-alpha-0.3.0-rc.1",
        "0.3.0-rc.1",
        predecessor=updater.status()["current"],
    )
    other_plan = updater.plan(other)
    with pytest.raises(SimulatedCrash):
        updater.apply(first_plan["planId"], first_authorization)

    def substitute(journal: dict[str, Any]) -> None:
        receipt = journal["preparedReceipt"]
        receipt["planId"] = other_plan["planId"]
        receipt["planDigest"] = other_plan["planDigest"]
        receipt["attempted"] = deepcopy(other_plan["successor"])
        receipt["releaseIndexDigest"] = other_plan["releaseIndexDigest"]

    rewrite_pending(tmp_path, substitute)
    calls = list(host.calls)
    with pytest.raises(UpdateError) as failure:
        updater.reconcile()
    assert failure.value.code == "journal_invalid"
    assert host.calls == calls


def test_failed_successor_discard_never_finalizes_until_cleanup_is_observed(
    tmp_path: Path,
) -> None:
    host = FixtureHost()
    host.fail_before["health-successor"] = 1
    host.fail_before["discard-successor"] = 2
    updater, _host, authority, successor, _document = initialized_engine(
        tmp_path,
        host=host,
    )
    plan, authorization = planned(updater, authority, successor)

    with pytest.raises(UpdateError) as first:
        updater.apply(plan["planId"], authorization)
    assert first.value.code == "cleanup_reconciliation_required"
    assert updater.status()["lastReceipt"] is None
    assert authority.finalize_calls == 0

    with pytest.raises(UpdateError) as second:
        updater.reconcile()
    assert second.value.code == "operator_resolution_required"
    assert updater.status()["lastReceipt"] is None
    assert authority.finalize_calls == 0
    assert not list((tmp_path / "updater/receipts").glob("*.json"))

    with pytest.raises(UpdateError) as third:
        updater.reconcile(resolution="retry_cleanup")
    assert third.value.code == "cleanup_reconciliation_required"

    receipt = updater.reconcile(resolution="retry_cleanup")
    assert receipt["result"] == "failed_safe"
    assert host.calls.count("discard-successor") == 3
    assert authority.finalize_calls == 1


def test_discard_failure_after_possible_side_effect_requires_reconciliation(
    tmp_path: Path,
) -> None:
    host = FixtureHost()
    host.fail_before["health-successor"] = 1
    host.fail_after["discard-successor"] = 1
    updater, _host, authority, successor, _document = initialized_engine(
        tmp_path,
        host=host,
    )
    plan, authorization = planned(updater, authority, successor)

    with pytest.raises(UpdateError) as failure:
        updater.apply(plan["planId"], authorization)
    assert failure.value.code == "cleanup_reconciliation_required"
    assert authority.finalize_calls == 0
    pending = json.loads((tmp_path / "updater/pending.json").read_text())
    assert pending["effectDisposition"] == "unknown"
    assert pending["intent"]["step"] == "discard-successor"

    with pytest.raises(UpdateError) as unresolved:
        updater.reconcile()
    assert unresolved.value.code == "operator_resolution_required"
    receipt = updater.reconcile(resolution="retry_cleanup")
    assert receipt["result"] == "failed_safe"
    archived = next((tmp_path / "updater/journals").glob("*.json"))
    journal = json.loads(archived.read_text())
    cleanup = next(
        item["evidence"]["evidence"]
        for item in journal["steps"]
        if item["step"] == "discard-successor"
    )
    assert cleanup["retainedArtifactIds"] == [plan["successor"]["releaseId"]]
    assert cleanup["removedRuntimeReleaseIds"] == [plan["successor"]["releaseId"]]
    assert cleanup["inventoryDigest"] == canonical_digest(
        {
            "retainedArtifactIds": cleanup["retainedArtifactIds"],
            "removedRuntimeReleaseIds": cleanup["removedRuntimeReleaseIds"],
        }
    )
    assert authority.finalize_calls == 1


@pytest.mark.parametrize(
    "phase",
    ["after_authority_claim_before_journal", "after_journal_stage"],
)
def test_claimed_update_recovery_survives_plan_expiry(
    tmp_path: Path,
    phase: str,
) -> None:
    now = [NOW]
    crash = OneShotCrash(phase)
    updater, _host, authority, successor, _document = initialized_engine(
        tmp_path,
        failpoint=crash,
        clock=lambda: now[0],
    )
    plan, authorization = planned(updater, authority, successor)
    with pytest.raises(SimulatedCrash):
        updater.apply(plan["planId"], authorization)

    now[0] = NOW + timedelta(days=2)
    receipt = updater.reconcile()

    assert receipt["result"] == "accepted"
    assert len(authority.claims) == 1
    assert authority.finalize_calls == 1


def test_apply_rechecks_plan_expiry_after_slow_preflight_before_claim(
    tmp_path: Path,
) -> None:
    now = [NOW]

    class ExpiringPreflightHost(FixtureHost):
        calls_to_preflight = 0

        def preflight(self, release: ReleaseFacts) -> Mapping[str, Any]:
            evidence = super().preflight(release)
            self.calls_to_preflight += 1
            if self.calls_to_preflight == 2:
                now[0] = NOW + timedelta(hours=25)
            return evidence

    host = ExpiringPreflightHost()
    updater, _host, authority, successor, _document = initialized_engine(
        tmp_path,
        host=host,
        clock=lambda: now[0],
    )
    plan, authorization = planned(updater, authority, successor)

    with pytest.raises(UpdateError) as failure:
        updater.apply(plan["planId"], authorization)

    assert failure.value.code == "plan_invalid"
    assert authority.claims == {}
    assert not (tmp_path / "updater/pending.json").exists()


def test_switch_effect_before_wal_completion_is_observed_then_rolled_back(
    tmp_path: Path,
) -> None:
    crash = OneShotCrash("after_effect_before_journal_switch")
    updater, host, authority, successor, _document = initialized_engine(tmp_path, failpoint=crash)
    plan, authorization = planned(updater, authority, successor)
    with pytest.raises(SimulatedCrash):
        updater.apply(plan["planId"], authorization)
    assert host.accepted is not None and host.accepted.release_id.endswith("0.2.0-rc.1")

    receipt = updater.reconcile()
    assert receipt["result"] == "rolled_back"
    assert host.accepted is host.current
    assert host.calls.count("switch") == 1
    assert host.calls.count("automatic-rollback") == 1


def test_staged_effect_before_wal_completion_is_discarded_before_safe_terminal(
    tmp_path: Path,
) -> None:
    crash = OneShotCrash("after_effect_before_journal_stage")
    updater, host, authority, successor, _document = initialized_engine(
        tmp_path,
        failpoint=crash,
    )
    plan, authorization = planned(updater, authority, successor)

    with pytest.raises(SimulatedCrash):
        updater.apply(plan["planId"], authorization)
    assert host.staged is not None
    assert host.calls.count("stage") == 1

    receipt = updater.reconcile()

    assert receipt["result"] == "failed_safe"
    assert host.staged is None
    assert host.calls.count("stage") == 1
    assert host.calls.count("discard-successor") == 1
    archived = next((tmp_path / "updater/journals").glob("*.json"))
    journal = json.loads(archived.read_text())
    cleanup = next(item for item in journal["steps"] if item["step"] == "discard-successor")
    assert (
        cleanup["evidence"]["hostReceipt"]
        == host.effect_receipts[(plan["planDigest"], "discard-successor")]
    )
    assert journal["preparedFailureEvidence"]["failedStep"] == "stage"


def test_double_crash_recovers_cleanup_receipt_without_replaying_unknown_effect(
    tmp_path: Path,
) -> None:
    crash = SequenceCrash(
        [
            "after_effect_before_journal_stage",
            "after_effect_before_journal_discard-successor",
        ]
    )
    updater, host, authority, successor, _document = initialized_engine(
        tmp_path,
        failpoint=crash,
    )
    plan, authorization = planned(updater, authority, successor)

    with pytest.raises(SimulatedCrash):
        updater.apply(plan["planId"], authorization)
    with pytest.raises(SimulatedCrash):
        updater.reconcile()
    assert host.staged is None
    assert host.calls.count("stage") == 1
    assert host.calls.count("discard-successor") == 1
    pending = json.loads((tmp_path / "updater/pending.json").read_text())
    assert pending["intent"]["step"] == "discard-successor"

    receipt = updater.reconcile()

    assert receipt["result"] == "failed_safe"
    assert host.calls.count("stage") == 1
    assert host.calls.count("discard-successor") == 1
    assert not crash.phases


def test_unresolved_stage_intent_survives_ambiguous_observation_without_replay(
    tmp_path: Path,
) -> None:
    host = FixtureHost()
    host.observe_failures = 1
    crash = OneShotCrash("after_effect_before_journal_stage")
    updater, _host, authority, successor, _document = initialized_engine(
        tmp_path,
        host=host,
        failpoint=crash,
    )
    plan, authorization = planned(updater, authority, successor)

    with pytest.raises(SimulatedCrash):
        updater.apply(plan["planId"], authorization)
    with pytest.raises(UpdateError) as unresolved:
        updater.reconcile()
    assert unresolved.value.code == "reconciliation_required"
    pending = json.loads((tmp_path / "updater/pending.json").read_text())
    assert pending["intent"]["step"] == "stage"
    assert host.calls.count("stage") == 1

    receipt = updater.reconcile()

    assert receipt["result"] == "failed_safe"
    assert host.calls.count("stage") == 1
    assert host.calls.count("discard-successor") == 1
    assert host.staged is None


def test_ambiguous_external_effect_leaves_claim_open_and_no_terminal_receipt(
    tmp_path: Path,
) -> None:
    host = FixtureHost()
    host.fail_after["switch"] = 1
    host.observe_failures = 1
    updater, _host, authority, successor, _document = initialized_engine(tmp_path, host=host)
    plan, authorization = planned(updater, authority, successor)
    with pytest.raises(UpdateError) as failure:
        updater.apply(plan["planId"], authorization)
    assert failure.value.code == "reconciliation_required"
    assert len(authority.claims) == 1
    assert authority.receipts == {}
    assert not list((tmp_path / "updater/receipts").glob("*.json"))

    receipt = updater.reconcile()
    assert receipt["result"] == "rolled_back"
    assert len(authority.receipts) == 1


def test_more_than_130_ambiguous_observations_remain_bounded_and_recoverable(
    tmp_path: Path,
) -> None:
    host = FixtureHost()
    host.fail_after["switch"] = 1
    host.observe_failures = 1_000
    updater, _host, authority, successor, _document = initialized_engine(tmp_path, host=host)
    plan, authorization = planned(updater, authority, successor)
    with pytest.raises(UpdateError) as initial:
        updater.apply(plan["planId"], authorization)
    assert initial.value.code == "reconciliation_required"

    for _ in range(130):
        with pytest.raises(UpdateError) as repeated:
            updater.reconcile()
        assert repeated.value.code == "reconciliation_required"
    pending = json.loads((tmp_path / "updater/pending.json").read_text())
    observations = [
        item for item in pending["steps"] if item["step"] == "accepted-route-observation"
    ]
    assert len(observations) == 1
    assert len(pending["steps"]) < 32

    host.observe_failures = 0
    receipt = updater.reconcile()
    assert receipt["result"] == "rolled_back"
    assert authority.finalize_calls == 1


def test_unknown_rollback_is_not_replayed_without_typed_operator_resolution(
    tmp_path: Path,
) -> None:
    host = FixtureHost()
    host.fail_after["switch"] = 1
    host.fail_before["automatic-rollback"] = 1
    updater, _host, authority, successor, _document = initialized_engine(tmp_path, host=host)
    plan, authorization = planned(updater, authority, successor)
    with pytest.raises(UpdateError) as first:
        updater.apply(plan["planId"], authorization)
    assert first.value.code == "rollback_reconciliation_required"
    calls = host.calls.count("automatic-rollback")
    with pytest.raises(UpdateError) as second:
        updater.reconcile()
    assert second.value.code == "operator_resolution_required"
    assert host.calls.count("automatic-rollback") == calls

    receipt = updater.reconcile(resolution="retry_rollback")
    assert receipt["result"] == "rolled_back"
    assert host.calls.count("automatic-rollback") == calls + 1


def test_transient_observation_recovers_without_replaying_failed_stage(tmp_path: Path) -> None:
    host = FixtureHost()
    host.fail_before["stage"] = 1
    host.observe_failures = 1
    updater, _host, authority, successor, _document = initialized_engine(tmp_path, host=host)
    plan, authorization = planned(updater, authority, successor)
    with pytest.raises(UpdateError) as failure:
        updater.apply(plan["planId"], authorization)
    assert failure.value.code == "reconciliation_required"
    stage_calls = host.calls.count("stage")
    receipt = updater.reconcile()
    assert receipt["result"] == "failed_safe"
    assert host.calls.count("stage") == stage_calls


def test_retention_failure_preserves_acceptance_and_recovers_boundedly(
    tmp_path: Path,
) -> None:
    host = FixtureHost()
    host.retention_failures = 1
    updater, _host, authority, successor, _document = initialized_engine(tmp_path, host=host)
    plan, authorization = planned(updater, authority, successor)
    with pytest.raises(UpdateError) as failure:
        updater.apply(plan["planId"], authorization)
    assert failure.value.code == "retention_reconciliation_required"
    pending_status = updater.status()
    assert pending_status["current"]["releaseId"].endswith("0.1.0-rc.1")
    assert pending_status["stagedSuccessor"]["releaseId"].endswith("0.2.0-rc.1")
    assert pending_status["phase"] == "validating"
    assert pending_status["lastReceipt"] is None

    receipt = updater.reconcile()
    assert receipt["result"] == "accepted"
    assert host.calls.count("retention") == 2
    assert updater.status()["current"]["releaseId"].endswith("0.2.0-rc.1")


def test_retention_recovery_revalidates_every_persisted_host_effect_receipt(
    tmp_path: Path,
) -> None:
    host = FixtureHost()
    host.retention_failures = 1
    updater, _host, authority, successor, _document = initialized_engine(tmp_path, host=host)
    plan, authorization = planned(updater, authority, successor)

    with pytest.raises(UpdateError) as initial:
        updater.apply(plan["planId"], authorization)
    assert initial.value.code == "retention_reconciliation_required"
    retention_calls = host.calls.count("retention")
    del host.effect_receipts[(plan["planDigest"], "backup")]

    with pytest.raises(UpdateError) as failure:
        updater.reconcile()

    assert failure.value.code == "journal_effect_revalidation_failed"
    assert host.calls.count("retention") == retention_calls
    assert authority.finalize_calls == 0
    assert updater.status()["lastReceipt"] is None


def test_canonical_finalize_failure_retries_without_reapplying_host_effects(
    tmp_path: Path,
) -> None:
    authority = FixtureAuthority()
    authority.fail_finalize = 1
    updater, host, _authority, successor, _document = initialized_engine(
        tmp_path, authority=authority
    )
    plan, authorization = planned(updater, authority, successor)
    with pytest.raises(UpdateError) as failure:
        updater.apply(plan["planId"], authorization)
    assert failure.value.code == "authority_finalization_pending"
    switch_calls = host.calls.count("switch")

    receipt = updater.reconcile()
    assert receipt["result"] == "accepted"
    assert host.calls.count("switch") == switch_calls
    assert len(authority.receipts) == 1


def test_failed_successor_evidence_uses_canonical_schema(tmp_path: Path) -> None:
    host = FixtureHost()
    host.fail_before["health-successor"] = 1
    updater, _host, authority, successor, _document = initialized_engine(tmp_path, host=host)
    plan, authorization = planned(updater, authority, successor)
    receipt = updater.apply(plan["planId"], authorization)
    assert receipt["result"] == "failed_safe"
    evidence_path = next((tmp_path / "updater/failure-evidence").glob("*.json"))
    evidence = json.loads(evidence_path.read_text())
    assert validate_update_failure_evidence(evidence).document["failedStep"] == "health-successor"
    assert updater.status()["failedSuccessorEvidence"] == evidence["failureId"]


def test_plan_tamper_and_expired_plan_fail_before_authority_claim(tmp_path: Path) -> None:
    updater, _host, authority, successor, _document = initialized_engine(tmp_path)
    plan, _authorization = planned(updater, authority, successor)
    plan_path = tmp_path / "updater/plans" / f"{plan['planId']}.json"
    value = json.loads(plan_path.read_text())
    value["estimatedPullBytes"] += 1
    plan_path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(UpdateError):
        updater.apply(plan["planId"], authority.reserve(plan))
    assert authority.claims == {}


def test_two_successive_updates_have_distinct_receipts_and_no_stale_state_conflict(
    tmp_path: Path,
) -> None:
    updater, host, authority, successor, _document = initialized_engine(tmp_path)
    first_plan, first_authorization = planned(updater, authority, successor)
    first_receipt = updater.apply(first_plan["planId"], first_authorization)

    second, _second_document, _second_identity = envelope(
        "stateport-alpha-0.3.0-rc.1",
        "0.3.0-rc.1",
        predecessor=updater._facts(successor, channel="alpha").identity,
    )
    second_plan, second_authorization = planned(updater, authority, second)
    second_receipt = updater.apply(second_plan["planId"], second_authorization)

    assert first_receipt["receiptId"] != second_receipt["receiptId"]
    assert second_receipt["from"]["releaseId"].endswith("0.2.0-rc.1")
    assert second_receipt["accepted"]["releaseId"].endswith("0.3.0-rc.1")
    assert updater.status()["lastReceipt"] == second_receipt["receiptId"]
    assert len(list((tmp_path / "updater/receipts").glob("*.json"))) == 2
    assert len(list((tmp_path / "updater/authority-links").glob("*.json"))) == 2
    assert not (tmp_path / "updater/pending.json").exists()
    assert host.calls.count("switch") == 2


def test_restart_crash_second_update_manual_rollback_and_forward_update(
    tmp_path: Path,
) -> None:
    crash = OneShotCrash("after_authority_finalize_before_journal")
    updater, host, authority, successor, _document = initialized_engine(
        tmp_path,
        failpoint=crash,
    )
    first_plan, first_authorization = planned(updater, authority, successor)
    with pytest.raises(SimulatedCrash):
        updater.apply(first_plan["planId"], first_authorization)

    updater = reopened_engine(tmp_path, host, authority)
    assert updater.reconcile()["accepted"]["releaseId"].endswith("0.2.0-rc.1")
    host.current = host.accepted

    second, _second_document, _second_identity = envelope(
        "stateport-alpha-0.3.0-rc.1",
        "0.3.0-rc.1",
        predecessor=updater.status()["current"],
    )
    second_plan, second_authorization = planned(updater, authority, second)
    assert updater.apply(second_plan["planId"], second_authorization)["result"] == "accepted"
    host.current = host.accepted

    updater = reopened_engine(tmp_path, host, authority)
    rollback = updater.plan(operation="rollback")
    rollback_receipt = updater.apply(rollback["planId"], authority.reserve(rollback))
    assert rollback_receipt["operation"] == "rollback"
    assert rollback_receipt["accepted"]["releaseId"].endswith("0.2.0-rc.1")
    host.current = host.accepted

    updater = reopened_engine(tmp_path, host, authority)
    forward, _forward_document, _forward_identity = envelope(
        "stateport-alpha-0.4.0-rc.1",
        "0.4.0-rc.1",
        predecessor=updater.status()["current"],
    )
    forward_plan, forward_authorization = planned(updater, authority, forward)
    final = updater.apply(forward_plan["planId"], forward_authorization)

    assert final["accepted"]["releaseId"].endswith("0.4.0-rc.1")
    assert len(list((tmp_path / "updater/receipts").glob("*.json"))) == 4
    inventory = host.retention_history[-1]
    assert inventory["retainedReleaseIds"] == [
        "stateport-alpha-0.2.0-rc.1",
        "stateport-alpha-0.4.0-rc.1",
    ]
    assert inventory["removedReleaseIds"] == ["stateport-alpha-0.3.0-rc.1"]
    assert inventory["inventoryDigest"] == canonical_digest(
        {
            key: inventory[key]
            for key in (
                "currentReleaseId",
                "retainedReleaseIds",
                "removedReleaseIds",
                "retainedFailureArtifactIds",
                "removedFailureArtifactIds",
            )
        }
    )


def test_reconstructed_process_policy_cas_refuses_stale_writer(tmp_path: Path) -> None:
    updater, host, authority, _successor, _document = initialized_engine(tmp_path)
    competing = reopened_engine(tmp_path, host, authority)
    expected = canonical_digest(updater.status())

    def mutate(
        action: str,
        *,
        run_id: str,
        operation: Any,
        resource_from_result: Any,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        assert action == "modify_update_policy"
        assert run_id == expected
        result = operation()
        assert resource_from_result(result)["statusDigest"] == canonical_digest(result)
        return result, {"receiptId": "fixture-policy-receipt"}

    updater.set_policy(
        UpdatePolicy(mode="notify", channel="alpha"),
        expected_status_digest=expected,
        mutate=mutate,
    )
    with pytest.raises(UpdateError) as stale:
        competing.set_policy(
            UpdatePolicy(mode="manual", channel="alpha"),
            expected_status_digest=expected,
            mutate=mutate,
        )
    assert stale.value.code == "approval_digest_mismatch"
    assert competing.status()["policy"]["mode"] == "notify"


def test_retention_enforces_two_exact_predecessors_and_two_failure_receipts(
    tmp_path: Path,
) -> None:
    policy = UpdatePolicy(
        mode="download-and-notify",
        channel="alpha",
        accepted_predecessors=2,
        failed_successors=2,
        maximum_versions=5,
        maximum_age_days=30,
    )
    updater, host, authority, successor, _document = initialized_engine(
        tmp_path / "accepted",
        update_policy=policy,
    )
    first, first_authorization = planned(updater, authority, successor)
    updater.apply(first["planId"], first_authorization)
    second, _document2, _identity2 = envelope(
        "stateport-alpha-0.3.0-rc.1",
        "0.3.0-rc.1",
        predecessor=updater._facts(successor, channel="alpha").identity,
    )
    second_plan, second_authorization = planned(updater, authority, second)
    updater.apply(second_plan["planId"], second_authorization)
    assert host.retention_history[-1]["retainedReleaseIds"] == [
        "stateport-alpha-0.1.0-rc.1",
        "stateport-alpha-0.2.0-rc.1",
        "stateport-alpha-0.3.0-rc.1",
    ]

    failing_host = FixtureHost()
    failing_host.fail_before["health-successor"] = 2
    failed_updater, _host, failed_authority, failed_one, _document = initialized_engine(
        tmp_path / "failed",
        host=failing_host,
        update_policy=policy,
    )
    failed_plan_one, failed_auth_one = planned(
        failed_updater,
        failed_authority,
        failed_one,
    )
    assert (
        failed_updater.apply(failed_plan_one["planId"], failed_auth_one)["result"] == "failed_safe"
    )
    # A second distinct successor can still target the exact retained current.
    failed_two, _document3, _identity3 = envelope(
        "stateport-alpha-0.3.0-rc.1",
        "0.3.0-rc.1",
        predecessor=failed_one.document["compatibility"]["predecessor"],
    )
    failed_plan_two, failed_auth_two = planned(
        failed_updater,
        failed_authority,
        failed_two,
    )
    assert (
        failed_updater.apply(failed_plan_two["planId"], failed_auth_two)["result"] == "failed_safe"
    )
    retained_failures = failing_host.retention_history[-1]["retainedFailureArtifactIds"]
    assert len(retained_failures) == 2
    assert len(set(retained_failures)) == 2


def test_stale_current_and_predecessor_require_actual_admission_and_still_rollback(
    tmp_path: Path,
) -> None:
    now = [NOW]
    host = FixtureHost()
    authority = FixtureAuthority()
    current, _current_document, current_identity = envelope(
        "stateport-alpha-0.1.0-rc.1", "0.1.0-rc.1", predecessor=None
    )
    successor, _successor_document, _successor_identity = envelope(
        "stateport-alpha-0.2.0-rc.1",
        "0.2.0-rc.1",
        predecessor=current_identity,
    )
    updater = UpdateEngine(
        UpdateStore.create(tmp_path / "updater"),
        host,
        authority,
        verification_policy=POLICY,
        signature_verifier=_EphemeralTestVerifier(),
        clock=lambda: now[0],
    )
    updater.initialize(current, UpdatePolicy(mode="download-and-notify", channel="alpha"))
    host.current = updater._facts(current, channel="alpha")
    host.accepted = host.current
    forward, forward_authorization = planned(updater, authority, successor)
    updater.apply(forward["planId"], forward_authorization)

    # Both release indexes and scans are stale by this point.  Historic use is
    # authorized by the exact initialize proof or accepted receipt+authority
    # link, never by guessing a formerly feasible verification time.
    now[0] = NOW + timedelta(days=70)
    rollback = updater.plan(operation="rollback")
    receipt = updater.apply(rollback["planId"], authority.reserve(rollback))
    assert receipt["operation"] == "rollback"
    assert receipt["accepted"]["releaseId"].endswith("0.1.0-rc.1")


def test_update_admission_without_terminal_authority_link_is_not_historic_authority(
    tmp_path: Path,
) -> None:
    updater, _host, authority, successor, _document = initialized_engine(tmp_path)
    plan, authorization = planned(updater, authority, successor)
    updater.apply(plan["planId"], authorization)
    link = next((tmp_path / "updater/authority-links").glob("*.json"))
    link.unlink()

    third, _third_document, _third_identity = envelope(
        "stateport-alpha-0.3.0-rc.1",
        "0.3.0-rc.1",
        predecessor=updater._facts(successor, channel="alpha").identity,
    )
    with pytest.raises(UpdateError) as failure:
        updater.plan(third)
    assert failure.value.code == "release_admission_missing"


def test_orphan_installed_initialize_admission_is_not_historic_authority(
    tmp_path: Path,
) -> None:
    updater, _host, _authority, _successor, _document = initialized_engine(tmp_path)
    release_id = updater.status()["current"]["releaseId"]

    # Copy the exact durable release bytes and re-issue the installed-
    # initialize admission for the orphan's own installation identity, but
    # leave out the durable status: the admission is well-formed yet the
    # release was never installed there.
    orphan = UpdateStore.create(tmp_path / "orphan")
    root = tmp_path / "updater"
    for item in (root / "releases").iterdir():
        shutil.copy2(item, tmp_path / "orphan/releases" / item.name)
    source_admission = json.loads(next((root / "release-admissions").glob("*.json")).read_text())
    admission = {
        key: value
        for key, value in source_admission.items()
        if key not in {"admissionId", "admissionDigest"}
    }
    admission["installationId"] = orphan.installation_id
    digest = canonical_digest(admission)
    admission["admissionId"] = f"release_admission_{digest.removeprefix('sha256:')[:32]}"
    admission["admissionDigest"] = digest
    with orphan.transaction() as session:
        session.save_admission(admission)
    orphan_engine = UpdateEngine(
        UpdateStore.open_existing(orphan.root),
        FixtureHost(),
        FixtureAuthority(),
        verification_policy=POLICY,
        signature_verifier=_EphemeralTestVerifier(),
        clock=lambda: NOW,
    )
    with orphan_engine.store.transaction() as session:
        with pytest.raises(UpdateError) as failure:
            orphan_engine._load_facts(session, release_id, channel="alpha")
    assert failure.value.code == "release_admission_missing"

    # Once a durable status binds the release as installed state, the same
    # admission is historic authority again.  The orphan store initializes
    # its own installation identity; the identical admission content is
    # create-only and therefore converges without conflict.
    current, _current_document, _current_identity = envelope(
        "stateport-alpha-0.1.0-rc.1", "0.1.0-rc.1", predecessor=None
    )
    orphan_engine.initialize(
        current,
        UpdatePolicy(mode="download-and-notify", channel="alpha"),
    )
    with orphan_engine.store.transaction() as session:
        assert orphan_engine._load_facts(session, release_id, channel="alpha").release_id == (
            release_id
        )


def test_foreign_installation_records_are_refused(tmp_path: Path) -> None:
    updater, _host, authority, successor, _document = initialized_engine(tmp_path)
    plan, authorization = planned(updater, authority, successor)
    updater.apply(plan["planId"], authorization)
    root = tmp_path / "updater"

    # A second installation with its own create-only identity receives a raw
    # copy of the first installation's durable records.  (Copying the whole
    # state directory, manifest included, is the supported backup/restore
    # clone; mixing records WITHOUT the manifest is the anomaly under test.)
    other = UpdateStore.create(tmp_path / "other")
    assert other.installation_id != updater.store.installation_id
    for directory in ("releases", "release-admissions", "receipts", "plans"):
        for item in (root / directory).iterdir():
            shutil.copy2(item, tmp_path / "other" / directory / item.name)
    shutil.copy2(root / "status.json", tmp_path / "other/status.json")
    other_engine = UpdateEngine(
        UpdateStore.open_existing(other.root),
        FixtureHost(),
        FixtureAuthority(),
        verification_policy=POLICY,
        signature_verifier=_EphemeralTestVerifier(),
        clock=lambda: NOW,
    )

    with pytest.raises(UpdateError) as status_failure:
        other_engine.status()
    assert status_failure.value.code == "status_invalid"

    with other_engine.store.transaction() as session:
        with pytest.raises(StoreError) as receipt_failure:
            session.list_receipts()
    assert receipt_failure.value.code == "receipt_invalid"
    assert "different installation" in str(receipt_failure.value)

    release_id = plan["current"]["releaseId"]
    with other_engine.store.transaction() as session:
        with pytest.raises(StoreError) as admission_failure:
            session.list_admissions(release_id)
    assert admission_failure.value.code == "admission_invalid"
    assert "different installation" in str(admission_failure.value)

    with other_engine.store.transaction() as session:
        with pytest.raises(StoreError) as plan_failure:
            session.load_plan(plan["planId"])
    assert plan_failure.value.code == "plan_invalid"
    assert "different installation" in str(plan_failure.value)


def test_policy_change_invalidates_exact_plan_before_claim(tmp_path: Path) -> None:
    updater, _host, authority, successor, _document = initialized_engine(tmp_path)
    plan, authorization = planned(updater, authority, successor)
    status_digest = canonical_digest(updater.status())

    def mutate(
        action: str,
        *,
        run_id: str,
        operation: Any,
        resource_from_result: Any,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        assert action == "modify_update_policy"
        assert run_id == status_digest
        result = operation()
        assert resource_from_result(result)["statusDigest"] == canonical_digest(result)
        return result, {"receiptId": "fixture-policy-receipt"}

    updater.set_policy(
        UpdatePolicy(mode="notify", channel="alpha"),
        expected_status_digest=status_digest,
        mutate=mutate,
    )
    with pytest.raises(UpdateError) as failure:
        updater.apply(plan["planId"], authorization)
    assert failure.value.code == "update_policy_changed"
    assert authority.claims == {}


def test_compatibility_change_refuses_before_authority_claim(tmp_path: Path) -> None:
    class FlippingCompatibilityHost(FixtureHost):
        preflight_count = 0

        def preflight(self, release: ReleaseFacts) -> Mapping[str, Any]:
            evidence = dict(super().preflight(release))
            self.preflight_count += 1
            if self.preflight_count > 1:
                evidence["migrationCompatible"] = False
            return evidence

    host = FlippingCompatibilityHost()
    updater, _host, authority, successor, _document = initialized_engine(
        tmp_path,
        host=host,
    )
    plan, authorization = planned(updater, authority, successor)
    with pytest.raises(UpdateError) as failure:
        updater.apply(plan["planId"], authorization)
    assert failure.value.code == "compatibility_refused"
    assert authority.claims == {}
    assert not (tmp_path / "updater/pending.json").exists()


def test_claim_refusal_archives_terminal_pre_effect_wal(tmp_path: Path) -> None:
    class RefusingClaimAuthority(FixtureAuthority):
        def claim(self, binding: Mapping[str, Any]) -> dict[str, Any]:
            del binding
            raise UpdateAuthorityError("claim_refused", "fixture claim refusal")

    authority = RefusingClaimAuthority()
    updater, host, _authority, successor, _document = initialized_engine(
        tmp_path,
        authority=authority,
    )
    plan, authorization = planned(updater, authority, successor)
    calls_before = list(host.calls)
    with pytest.raises(UpdateError) as failure:
        updater.apply(plan["planId"], authorization)
    assert failure.value.code == "claim_refused"
    assert not (tmp_path / "updater/pending.json").exists()
    journal_path = next((tmp_path / "updater/journals").glob("*.json"))
    assert json.loads(journal_path.read_text())["phase"] == "claim_not_acquired"
    assert host.calls == [*calls_before, "preflight"]


def test_status_read_is_not_starved_by_long_host_effect(tmp_path: Path) -> None:
    entered = Event()
    release = Event()

    class BlockingHost(FixtureHost):
        def backup(self, plan: Mapping[str, Any]) -> Mapping[str, Any]:
            entered.set()
            assert release.wait(timeout=5)
            return super().backup(plan)

    host = BlockingHost()
    updater, _host, authority, successor, _document = initialized_engine(
        tmp_path,
        host=host,
    )
    plan, authorization = planned(updater, authority, successor)
    outcome: list[object] = []

    def run_apply() -> None:
        try:
            outcome.append(updater.apply(plan["planId"], authorization))
        except BaseException as exc:  # pragma: no cover - asserted below
            outcome.append(exc)

    thread = Thread(target=run_apply)
    thread.start()
    assert entered.wait(timeout=5)
    started = time.monotonic()
    pending = updater.status()
    elapsed = time.monotonic() - started
    release.set()
    thread.join(timeout=10)
    assert not thread.is_alive()
    assert elapsed < 0.5
    assert pending["phase"] in {"approved", "validating"}
    assert len(outcome) == 1 and isinstance(outcome[0], dict)


def test_host_evidence_rejects_secret_fields_and_absolute_paths(tmp_path: Path) -> None:
    class UnsafeEvidenceHost(FixtureHost):
        def backup(self, plan: Mapping[str, Any]) -> Mapping[str, Any]:
            del plan
            self.calls.append("backup")
            return {
                "schema": "stateport.update-host-backup/v1",
                "planDigest": "sha256:" + "a" * 64,
                "receiptId": "backup_fixture",
                "backupDigest": "sha256:" + "b" * 64,
                "secretPath": "/tmp/private",
            }

    updater, _host, authority, successor, _document = initialized_engine(
        tmp_path,
        host=UnsafeEvidenceHost(),
    )
    plan, authorization = planned(updater, authority, successor)
    receipt = updater.apply(plan["planId"], authorization)
    assert receipt["result"] == "failed_safe"
    assert "private" not in json.dumps(receipt)


def test_repository_policy_does_not_pretend_update_actions_are_installed() -> None:
    policy = yaml.safe_load((ROOT / "config/authority-policy.v1.yaml").read_text())
    for action in (
        "observe_update",
        "plan_update",
        "apply_update",
        "rollback_update",
        "modify_update_policy",
    ):
        assert action not in policy["actionPolicies"]


def test_policy_shape_enforces_schedule_download_and_retention_contract() -> None:
    dogfood = UpdatePolicy(
        mode="automatic-with-rollback",
        channel="owner-dogfood",
        schedule_days=(1, 3, 5),
        schedule_start_minute_utc=120,
        accepted_predecessors=1,
        failed_successors=1,
        maximum_versions=3,
        maximum_age_days=60,
    )
    assert UpdatePolicy.from_mapping(dogfood.to_mapping()) == dogfood
    with pytest.raises(Exception):
        UpdatePolicy(mode="scheduled", channel="alpha").to_mapping()


def _run(repository: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def authority_manager_adapter(tmp_path: Path) -> AuthorityManagerAdapter:
    repository = tmp_path / "authority-repository"
    repository.mkdir()
    _run(repository, "init", "-q", "--initial-branch=agent/update-fixture")
    _run(repository, "config", "user.email", "updater@example.invalid")
    _run(repository, "config", "user.name", "Updater Fixture")
    _run(repository, "remote", "add", "origin", "https://github.com/stateport/stateport.git")
    (repository / "config").mkdir()
    shutil.copyfile(
        ROOT / "config/authority-policy.v1.yaml",
        repository / "config/authority-policy.v1.yaml",
    )
    (repository / "README.md").write_text("fixture\n", encoding="utf-8")
    _run(repository, "add", ".")
    _run(repository, "commit", "-qm", "fixture")

    policy_value = yaml.safe_load((ROOT / "config/authority-policy.v1.yaml").read_text())
    for action, risk, reversible in (
        ("observe_update", "low", True),
        ("plan_update", "medium", True),
        ("apply_update", "high", True),
        ("rollback_update", "high", True),
        ("modify_update_policy", "medium", True),
    ):
        policy_value["actionPolicies"][action] = {
            "risk": risk,
            "reversible": reversible,
            "localMutation": True,
            "processLaunch": action in {"apply_update", "rollback_update"},
            "remoteSideEffect": False,
        }
        policy_value["profiles"]["balanced"]["autoWithReceipt"].append(action)
    policy = AuthorityPolicy.from_mapping(policy_value)
    manager = AuthorityManager(
        repository,
        state_root=tmp_path / "authority-state",
        policy=policy,
        clock=lambda: NOW,
    )
    grant = grant_template(
        manager,
        grant_id="grant_updater_fixture",
        profile="balanced",
        actor_id="updater-fixture",
        role="primary",
        branch_pattern="agent/update-fixture",
        slice_id="BL-UPDATE-FIXTURE",
        application_id="stateport",
        run_id=None,
        paths=("packages/updater",),
        allow=(
            "observe_update",
            "plan_update",
            "apply_update",
            "rollback_update",
            "modify_update_policy",
        ),
        require_approval=(),
        forbid=(),
        owner_directive_id="OD-UPDATE-FIXTURE",
        expires_when="slice_closed",
        max_actions=100,
        max_duration_seconds=7200,
        max_cost_usd=0,
    )
    manager.activate_grant(grant, owner_actor_id="owner-fixture")
    return AuthorityManagerAdapter(
        manager,
        AuthorityScope(
            actor_id="updater-fixture",
            grant_id="grant_updater_fixture",
            branch="agent/update-fixture",
            slice_id="BL-UPDATE-FIXTURE",
            application_id="stateport",
            paths=("packages/updater",),
        ),
    )


def test_real_authority_manager_reserve_claim_finalize_and_link(tmp_path: Path) -> None:
    adapter = authority_manager_adapter(tmp_path)
    updater, _host, _authority, successor, _document = initialized_engine(
        tmp_path, authority=adapter
    )
    plan = updater.plan(successor)
    receipt = updater.apply(plan["planId"], adapter.reserve(plan))

    assert receipt["authority"]["runId"] == plan["planDigest"]
    canonical = adapter.manager.get_receipt_for_request(receipt["authority"]["requestId"])
    assert canonical is not None and canonical["result"]["status"] == "succeeded"
    link_path = next((tmp_path / "updater/authority-links").glob("*.json"))
    link = validate_update_authority_link(json.loads(link_path.read_text())).as_dict()
    assert link["authority"]["receiptId"] == canonical["receiptId"]


def test_real_authority_execute_scoped_signature_updates_policy(tmp_path: Path) -> None:
    adapter = authority_manager_adapter(tmp_path)
    updater, _host, _authority, _successor, _document = initialized_engine(
        tmp_path / "updater",
        authority=adapter,
    )
    status_digest = canonical_digest(updater.status())
    changed = updater.set_policy(
        UpdatePolicy(mode="notify", channel="alpha"),
        expected_status_digest=status_digest,
        mutate=adapter.execute_scoped,
    )
    assert changed["policy"]["mode"] == "notify"
    receipts = [
        json.loads(path.read_text()) for path in adapter.manager.receipts_root.glob("*.json")
    ]
    receipt = next(item for item in receipts if item["action"] == "modify_update_policy")
    assert receipt["result"]["status"] == "succeeded"
    assert receipt["scope"]["runId"] == status_digest


def test_real_authority_finalize_before_local_link_recovers_idempotently(
    tmp_path: Path,
) -> None:
    crash = OneShotCrash("after_authority_finalize_before_journal")
    adapter = authority_manager_adapter(tmp_path)
    updater, host, _authority, successor, _document = initialized_engine(
        tmp_path, authority=adapter, failpoint=crash
    )
    plan = updater.plan(successor)
    authorization = adapter.reserve(plan)
    with pytest.raises(SimulatedCrash):
        updater.apply(plan["planId"], authorization)
    request_id = authorization["decision"]["requestId"]
    before = adapter.manager.get_receipt_for_request(request_id)
    assert before is not None
    switch_calls = host.calls.count("switch")

    receipt = updater.reconcile()
    after = adapter.manager.get_receipt_for_request(request_id)
    assert after == before
    assert receipt["result"] == "accepted"
    assert host.calls.count("switch") == switch_calls


def test_conflicting_recovered_terminal_authority_receipt_fails_closed(
    tmp_path: Path,
) -> None:
    crash = OneShotCrash("after_authority_finalize_before_journal")
    adapter = authority_manager_adapter(tmp_path)
    updater, _host, _authority, successor, _document = initialized_engine(
        tmp_path / "updater",
        authority=adapter,
        failpoint=crash,
    )
    plan = updater.plan(successor)
    authorization = adapter.reserve(plan)
    with pytest.raises(SimulatedCrash):
        updater.apply(plan["planId"], authorization)
    request_id = authorization["decision"]["requestId"]
    receipt_path = next(
        path
        for path in adapter.manager.receipts_root.glob("*.json")
        if json.loads(path.read_text())["requestId"] == request_id
    )
    receipt = json.loads(receipt_path.read_text())
    receipt["result"]["resource"]["acceptedReleaseId"] = "attacker-release"
    body = {key: value for key, value in receipt.items() if key != "receiptDigest"}
    receipt["receiptDigest"] = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                body,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode()
        ).hexdigest()
    )
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    with pytest.raises(UpdateError) as failure:
        updater.reconcile()
    assert failure.value.code == "authority_finalization_pending"
    assert not list((tmp_path / "updater/updater/authority-links").glob("*.json"))


def test_scoped_authority_redacts_domain_failure_with_exact_terminal_receipt(
    tmp_path: Path,
) -> None:
    adapter = authority_manager_adapter(tmp_path)

    class DomainFailure(RuntimeError):
        code = "domain_fixture_failed"

    def operation() -> dict[str, Any]:
        raise DomainFailure("private detail must not become adapter identity")

    with pytest.raises(UpdateAuthorityError) as failure:
        adapter.execute_scoped(
            "modify_update_policy",
            run_id="sha256:" + "1" * 64,
            operation=operation,
        )
    receipt = failure.value.receipt
    assert failure.value.code == "domain_fixture_failed"
    assert "private detail" not in str(failure.value)
    assert receipt is not None
    assert receipt["schema"] == "stateport.authority-action-receipt/v1"
    assert receipt["result"]["status"] == "failed"
    assert receipt["result"]["code"] == "domain_fixture_failed"


def test_repository_authority_adapter_refuses_tampered_manager_output(
    tmp_path: Path,
) -> None:
    adapter = authority_manager_adapter(tmp_path)
    updater, _host, _authority, successor, _document = initialized_engine(
        tmp_path / "updater-fixture"
    )
    plan = updater.plan(successor)
    decision, reservation = adapter.manager.reserve_action(
        "apply_update",
        actor_id=adapter.scope.actor_id,
        grant_id=adapter.scope.grant_id,
        branch=adapter.scope.branch,
        slice_id=adapter.scope.slice_id,
        application_id=adapter.scope.application_id,
        run_id=plan["planDigest"],
        paths=adapter.scope.paths,
        estimated_duration_seconds=3600,
    )
    tampered = deepcopy(decision)
    tampered["scope"]["branch"] = "agent/attacker"
    with pytest.raises(UpdateAuthorityError) as failure:
        adapter.validate_reservation(
            plan,
            {"decision": tampered, "reservation": reservation},
        )
    assert failure.value.code == "authority_contract_invalid"


def test_canonical_status_file_rejects_symlink_and_hardlink_substitution(
    tmp_path: Path,
) -> None:
    updater, _host, _authority, _successor, _document = initialized_engine(tmp_path)
    status_path = tmp_path / "updater/status.json"
    backup = tmp_path / "status-copy.json"
    shutil.copyfile(status_path, backup)
    status_path.unlink()
    status_path.symlink_to(backup)
    with pytest.raises(Exception):
        updater.status()


def test_store_open_is_explicit_and_read_only_open_creates_nothing(tmp_path: Path) -> None:
    absent = tmp_path / "absent-state"
    with pytest.raises(TypeError, match="create.*open_existing"):
        UpdateStore(absent)
    store = UpdateStore.open_existing(absent)
    assert not absent.exists()
    with pytest.raises(StoreError):
        store.snapshot()
    assert not absent.exists()


def test_store_refuses_root_and_lock_mode_drift(tmp_path: Path) -> None:
    updater, _host, _authority, _successor, _document = initialized_engine(tmp_path)
    root = tmp_path / "updater"
    root.chmod(0o750)
    with pytest.raises(UpdateError) as root_failure:
        updater.status()
    assert root_failure.value.code == "unsafe_state_root"
    root.chmod(0o700)

    lock = root / ".update.lock"
    lock.chmod(0o660)
    with pytest.raises(UpdateError) as lock_failure:
        updater.status()
    assert lock_failure.value.code == "unsafe_state_file"
    lock.chmod(0o600)


def test_lock_metadata_is_revalidated_after_flock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = UpdateStore.create(tmp_path / "state")
    original = updater_safe_io.fcntl.flock
    changed = False

    def chmod_after_lock(descriptor: int, operation: int) -> None:
        nonlocal changed
        original(descriptor, operation)
        if operation & updater_safe_io.fcntl.LOCK_EX and not changed:
            changed = True
            os.fchmod(descriptor, 0o660)

    monkeypatch.setattr(updater_safe_io.fcntl, "flock", chmod_after_lock)
    with pytest.raises(StoreError) as failure:
        with store.transaction():
            pass
    assert failure.value.code == "unsafe_state_file"
    store.lock_path.chmod(0o600)


def test_session_oserror_inside_lock_keeps_real_identity(tmp_path: Path) -> None:
    store = UpdateStore.create(tmp_path / "state")
    with pytest.raises(OSError) as failure:
        with store.transaction():
            raise OSError("session body failure")
    assert not isinstance(failure.value, StoreError)
    assert str(failure.value) == "session body failure"

    # The lock was still released and acquisition errors still translate.
    with store.transaction():
        pass
    with pytest.raises(StoreError) as lock_failure:
        with store.transaction(timeout_seconds=30.1):
            pass
    assert lock_failure.value.code == "update_state_busy"


def test_no_parallel_provisional_release_or_receipt_schema_remains() -> None:
    package = ROOT / "packages/updater/src/stateport_updater"
    source = "\n".join(path.read_text(encoding="utf-8") for path in package.glob("*.py"))
    assert "stateport.internal-update-plan/v0" not in source
    assert "stateport.internal-update-outcome/v0" not in source
    assert "class VerifiedRelease" not in source
    assert "changed_by" not in source
