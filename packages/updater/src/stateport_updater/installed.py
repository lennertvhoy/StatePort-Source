"""Installed-authority adapter bound to the exact no-checkout installation.

The repository development adapter (:mod:`stateport_updater.authority`) binds
updater effects to a Git-backed standing grant.  An installed StatePort runtime
has no checkout, so its updater authority is anchored in a create-only
installed-identity chain inside the owner-private updater state root.  Every
decision binds, through the grant digest of one validated identity record, the
exact installed release, installation id, release-index digest, installer
digest, target identity, accepted image digests, state-root identity, channel,
and exact predecessor.  A state directory copied to another device or inode
fails the state-root binding and obtains no authority; records that name
another installation fail the manifest binding.

The adapter is the system of record for installed update authority.  It keeps
decisions, reservations, claims, and terminal receipts as create-only,
self-digested documents and re-reads them before any reservation, claim,
recovery, or finalization is honoured, so a fabricated or stale authorization
bundle cannot acquire effect authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import stat
from typing import Any, Callable, Mapping, Sequence, TypeVar

from stateport_release import (
    ReleaseContractError,
    ReleaseVerificationPolicy,
    canonical_digest,
    load_release_index,
    validate_update_receipt,
    validate_update_status,
)

from .authority import (
    AUTHORITY_CLAIM,
    AUTHORITY_DIGEST,
    AUTHORITY_RECEIPT,
    AUTHORITY_REQUEST,
    AUTHORITY_RESERVATION,
    BOUNDARY_CODE,
    UpdateAuthorityError,
    _authority_digest,
    _validate_claim,
    _validate_decision,
    _validate_receipt,
    _validate_reservation,
)
from .models import UPDATE_CHANNELS, version_key
from .safe_io import (
    SafeIOError,
    create_json,
    ensure_private_directory,
    read_bytes,
    read_json,
    replace_json,
)
from .store import DIGEST, INSTALLATION_ID, UpdateStore, _validated_admission


T = TypeVar("T")

IDENTITY_SCHEMA = "stateport.internal-installed-identity/v1"
INSTALL_TRUST_SCHEMA = "stateport.internal-install-trust/v1"
RESERVATION_RECORD_SCHEMA = "stateport.internal-installed-reservation/v1"
AUTHORIZATION_BUNDLE_SCHEMA = "stateport.update-authorization/v1"
IDENTITY_ID = re.compile(r"installed_identity_[0-9a-f]{32}\Z")
UPDATE_RECEIPT_ID = re.compile(r"update_receipt_[0-9a-f]{32}\Z")
SAFE_TEXT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
INSTALLER_ORIGIN = re.compile(r"https://[^\s?#]+(?:\.git)?\Z")
TARGET_ID = re.compile(r"[a-z0-9][a-z0-9._-]{2,127}\Z")
ACTION = re.compile(r"[a-z][a-z0-9_]{0,127}\Z")
APPLICATION_ID = "stateport"
AUTHORITY_PROFILE = "balanced"
AUTHORITY_POLICY = "auto_with_receipt"

HOST_METHODS = (
    "preflight",
    "backup",
    "pull_images",
    "stage",
    "dry_run_migrations",
    "start_successor",
    "health_successor",
    "browser_successor",
    "studystate_successor",
    "state_check_successor",
    "switch",
    "health_accepted_route",
    "state_check_accepted_route",
    "observe_accepted_revision",
    "discard_successor",
    "rollback_failed_switch",
    "observe_effect_receipt",
    "enforce_retention",
)
VERIFIER_METHODS = ("verify_blob", "verify_image", "retain_bundle")


@dataclass(frozen=True)
class ControlPlaneBinding:
    """Typed control-plane seam for the installed updater.

    The wheel ships no execution host and no signature verifier; the installed
    control plane injects both, together with the release trust policy, when it
    drives check, plan, apply, rollback, or reconcile.  Authority itself is
    never injected through this object: it derives only from the durable
    installed-identity chain.
    """

    host: Any
    signature_verifier: Any
    verification_policy: ReleaseVerificationPolicy
    clock: Callable[[], datetime] | None = None
    bundle_root: Path | None = None
    transport_verifier_factory: Callable[[Path], Any] | None = None

    def validated(self, *, expected_target: str) -> "ControlPlaneBinding":
        for name in (*HOST_METHODS, *VERIFIER_METHODS):
            target = self.host if name in HOST_METHODS else self.signature_verifier
            if not callable(getattr(target, name, None)):
                raise UpdateAuthorityError(
                    "control_plane_binding_invalid",
                    "control-plane binding does not implement the typed updater seam",
                )
        if not isinstance(self.verification_policy, ReleaseVerificationPolicy):
            raise UpdateAuthorityError(
                "control_plane_binding_invalid",
                "control-plane binding has no typed release verification policy",
            )
        if self.verification_policy.expected_target != expected_target:
            raise UpdateAuthorityError(
                "control_plane_binding_invalid",
                "control-plane trust policy does not bind the updater target",
            )
        if not callable(self.transport_verifier_factory):
            raise UpdateAuthorityError(
                "control_plane_binding_invalid",
                "control-plane binding has no read-only transport verifier factory",
            )
        return self


def _timestamp(clock: Callable[[], datetime]) -> str:
    value = clock().astimezone(timezone.utc).replace(microsecond=0)
    return value.isoformat().replace("+00:00", "Z")


def _timestamp_text(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise UpdateAuthorityError("authority_record_invalid", f"{label} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise UpdateAuthorityError("authority_record_invalid", f"{label} is invalid") from exc
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() != timezone.utc.utcoffset(parsed)
        or parsed.microsecond
        or parsed.isoformat().replace("+00:00", "Z") != value
    ):
        raise UpdateAuthorityError("authority_record_invalid", f"{label} is invalid")
    return value


def _digest_field(value: object, label: str) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise UpdateAuthorityError("authority_record_invalid", f"{label} is invalid")
    return value


def _semver_text(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise UpdateAuthorityError("authority_record_invalid", f"{label} is invalid")
    try:
        version_key(value)
    except ValueError as exc:
        raise UpdateAuthorityError("authority_record_invalid", f"{label} is invalid") from exc
    return value


def _validate_identity(raw: object) -> dict[str, Any]:
    expected = {
        "schema",
        "identityId",
        "installationId",
        "releaseId",
        "version",
        "signedPayloadDigest",
        "releaseIndexDigest",
        "installerDigest",
        "targetId",
        "topologyDigest",
        "quadletBundleDigest",
        "acceptedImageDigests",
        "stateRootInode",
        "channel",
        "predecessorReleaseId",
        "predecessorSignedPayloadDigest",
        "predecessorIdentityDigest",
        "installerOrigin",
        "installerVersion",
        "actorId",
        "createdAt",
        "identityDigest",
    }
    if not isinstance(raw, Mapping) or set(raw) != expected or raw.get("schema") != IDENTITY_SCHEMA:
        raise UpdateAuthorityError(
            "authority_record_invalid", "installed identity record is malformed"
        )
    record = dict(raw)
    installation_id = record.get("installationId")
    if not isinstance(installation_id, str) or INSTALLATION_ID.fullmatch(installation_id) is None:
        raise UpdateAuthorityError(
            "authority_record_invalid", "installed identity installation id is invalid"
        )
    if (
        not isinstance(record.get("identityId"), str)
        or IDENTITY_ID.fullmatch(record["identityId"]) is None
    ):
        raise UpdateAuthorityError("authority_record_invalid", "installed identity id is invalid")
    if (
        not isinstance(record.get("releaseId"), str)
        or SAFE_TEXT.fullmatch(record["releaseId"]) is None
    ):
        raise UpdateAuthorityError(
            "authority_record_invalid", "installed identity release id is invalid"
        )
    _semver_text(record.get("version"), "installed identity version")
    _semver_text(record.get("installerVersion"), "installed identity installer version")
    for field in (
        "signedPayloadDigest",
        "releaseIndexDigest",
        "installerDigest",
        "topologyDigest",
        "quadletBundleDigest",
    ):
        _digest_field(record.get(field), f"installed identity {field}")
    if (
        not isinstance(record.get("targetId"), str)
        or TARGET_ID.fullmatch(record["targetId"]) is None
    ):
        raise UpdateAuthorityError(
            "authority_record_invalid", "installed identity target is invalid"
        )
    images = record.get("acceptedImageDigests")
    if (
        not isinstance(images, list)
        or not 1 <= len(images) <= 32
        or any(DIGEST.fullmatch(str(item)) is None for item in images)
        or images != sorted(set(images))
    ):
        raise UpdateAuthorityError(
            "authority_record_invalid", "installed identity accepted image digests are invalid"
        )
    value = record.get("stateRootInode")
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise UpdateAuthorityError(
            "authority_record_invalid", "installed identity state-root identity is invalid"
        )
    if record.get("channel") not in UPDATE_CHANNELS:
        raise UpdateAuthorityError(
            "authority_record_invalid", "installed identity channel is invalid"
        )
    predecessor_release = record.get("predecessorReleaseId")
    predecessor_digest = record.get("predecessorSignedPayloadDigest")
    predecessor_identity = record.get("predecessorIdentityDigest")
    if predecessor_release is None:
        if predecessor_digest is not None or predecessor_identity is not None:
            raise UpdateAuthorityError(
                "authority_record_invalid", "genesis identity names a predecessor"
            )
    else:
        if (
            not isinstance(predecessor_release, str)
            or SAFE_TEXT.fullmatch(predecessor_release) is None
        ):
            raise UpdateAuthorityError(
                "authority_record_invalid", "installed identity predecessor is invalid"
            )
        _digest_field(predecessor_digest, "installed identity predecessor digest")
        _digest_field(predecessor_identity, "installed identity predecessor identity digest")
    origin = record.get("installerOrigin")
    if not isinstance(origin, str) or INSTALLER_ORIGIN.fullmatch(origin) is None:
        raise UpdateAuthorityError(
            "authority_record_invalid", "installed identity installer origin is invalid"
        )
    actor = record.get("actorId")
    if not isinstance(actor, str) or not 1 <= len(actor) <= 128:
        raise UpdateAuthorityError(
            "authority_record_invalid", "installed identity actor is invalid"
        )
    _timestamp_text(record.get("createdAt"), "installed identity creation time")
    body = {
        key: value for key, value in record.items() if key not in {"identityId", "identityDigest"}
    }
    digest = canonical_digest(body)
    if (
        record.get("identityDigest") != digest
        or record["identityId"] != f"installed_identity_{digest.removeprefix('sha256:')[:32]}"
    ):
        raise UpdateAuthorityError(
            "authority_record_tampered", "installed identity digest does not match"
        )
    return record


def _validate_reservation_record(raw: object) -> dict[str, Any]:
    expected = {"schema", "installationId", "identityDigest", "decision", "reservation"}
    if (
        not isinstance(raw, Mapping)
        or set(raw) != expected
        or raw.get("schema") != RESERVATION_RECORD_SCHEMA
    ):
        raise UpdateAuthorityError(
            "authority_record_invalid", "installed authority reservation record is malformed"
        )
    record = dict(raw)
    installation_id = record.get("installationId")
    if not isinstance(installation_id, str) or INSTALLATION_ID.fullmatch(installation_id) is None:
        raise UpdateAuthorityError(
            "authority_record_invalid", "installed reservation installation id is invalid"
        )
    _digest_field(record.get("identityDigest"), "installed reservation identity digest")
    decision = _validate_decision(record.get("decision"))
    reservation = _validate_reservation(record.get("reservation"))
    if reservation["requestId"] != decision["requestId"] or reservation["decision"] != decision:
        raise UpdateAuthorityError(
            "authority_record_invalid",
            "installed reservation record does not bind its exact decision",
        )
    return {
        "schema": RESERVATION_RECORD_SCHEMA,
        "installationId": installation_id,
        "identityDigest": record["identityDigest"],
        "decision": decision,
        "reservation": reservation,
    }


class InstalledAuthorityAdapter:
    """Installed-subject authority bound to the exact no-checkout identity.

    Reads never take the store lock: every record is create-only or published
    by atomic replace, and the engine's operation lease serializes writers.
    The adapter never fabricates installation identity; the installer injects
    the genesis record once through :meth:`install` after the durable updater
    status and release admission exist.
    """

    authority_subject = "installed-no-checkout-v1"

    def __init__(
        self,
        store: UpdateStore,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.store = store
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    @property
    def authority_root(self) -> Path:
        return self.store.root / "installed-authority"

    @property
    def identity_dir(self) -> Path:
        return self.authority_root / "identity"

    @property
    def reservations_dir(self) -> Path:
        return self.authority_root / "reservations"

    @property
    def claims_dir(self) -> Path:
        return self.authority_root / "claims"

    @property
    def receipts_dir(self) -> Path:
        return self.authority_root / "receipts"

    def _ensure_directories(self) -> None:
        ensure_private_directory(self.authority_root)
        for directory in (
            self.identity_dir,
            self.reservations_dir,
            self.claims_dir,
            self.receipts_dir,
        ):
            ensure_private_directory(directory)

    def _native_state(self) -> int:
        """Inode of the durable updater state root.

        The kernel device number (``st_dev``) is deliberately NOT bound:
        WSL2 reassigns it on every reattach, which would make every updater
        authority operation refuse ``foreign_state_refused`` after
        ``wsl --shutdown``.  The inode plus the random installation id still
        refuse copied or foreign state roots on the same filesystem.
        """
        try:
            metadata = os.lstat(self.store.root)
        except OSError as exc:
            raise UpdateAuthorityError(
                "installed_state_unavailable", "updater state root could not be inspected"
            ) from exc
        if not stat.S_ISDIR(metadata.st_mode):
            raise UpdateAuthorityError(
                "foreign_state_refused", "updater state root is not a real directory"
            )
        return int(metadata.st_ino)

    def _read_record(self, path: Path, label: str) -> dict[str, Any]:
        try:
            return read_json(path, label)
        except SafeIOError as exc:
            raise UpdateAuthorityError(str(exc.code), str(exc)) from exc

    def _bind_native(self, record: Mapping[str, Any]) -> None:
        inode = self._native_state()
        if (
            record["stateRootInode"] != inode
            or record["installationId"] != self.store.installation_id
        ):
            raise UpdateAuthorityError(
                "foreign_state_refused",
                "installed authority record belongs to a copied or foreign state root",
            )

    def _load_identities(self) -> list[dict[str, Any]]:
        if not self.identity_dir.is_dir():
            return []
        records: list[dict[str, Any]] = []
        for path in sorted(self.identity_dir.glob("*.json")):
            record = _validate_identity(self._read_record(path, "installed identity record"))
            if path.stem != record["identityId"]:
                raise UpdateAuthorityError(
                    "authority_record_tampered",
                    "installed identity filename does not match its immutable identity",
                )
            self._bind_native(record)
            records.append(record)
        return records

    def _chain_head(self, records: Sequence[dict[str, Any]]) -> dict[str, Any]:
        by_digest = {str(record["identityDigest"]): record for record in records}
        if len(by_digest) != len(records):
            raise UpdateAuthorityError(
                "installed_identity_chain_broken", "installed identity chain repeats a record"
            )
        referenced = {
            str(record["predecessorIdentityDigest"])
            for record in records
            if record["predecessorIdentityDigest"] is not None
        }
        if not referenced.issubset(by_digest):
            raise UpdateAuthorityError(
                "installed_identity_chain_broken",
                "installed identity chain names an unknown predecessor",
            )
        heads = [record for record in records if str(record["identityDigest"]) not in referenced]
        if len(heads) != 1:
            raise UpdateAuthorityError(
                "installed_identity_chain_broken",
                "installed identity chain has no unique head",
            )
        head = heads[0]
        seen = {str(head["identityDigest"])}
        cursor = head
        while cursor["predecessorIdentityDigest"] is not None:
            predecessor = by_digest[str(cursor["predecessorIdentityDigest"])]
            if (
                predecessor["releaseId"] != cursor["predecessorReleaseId"]
                or predecessor["signedPayloadDigest"] != cursor["predecessorSignedPayloadDigest"]
            ):
                raise UpdateAuthorityError(
                    "installed_identity_chain_broken",
                    "installed identity does not bind its exact predecessor",
                )
            if str(predecessor["identityDigest"]) in seen:
                raise UpdateAuthorityError(
                    "installed_identity_chain_broken", "installed identity chain cycles"
                )
            seen.add(str(predecessor["identityDigest"]))
            cursor = predecessor
        return head

    def _status(self) -> dict[str, Any]:
        try:
            validated = validate_update_status(
                self._read_record(self.store.status_path, "update status")
            ).as_dict()
        except ReleaseContractError as exc:
            raise UpdateAuthorityError("installed_status_invalid", str(exc)) from exc
        if validated.get("installationId") != self.store.installation_id:
            raise UpdateAuthorityError(
                "foreign_state_refused", "update status belongs to a different installation"
            )
        return validated

    def _current_identity(self) -> dict[str, Any]:
        records = self._load_identities()
        if not records:
            raise UpdateAuthorityError(
                "installed_authority_adapter_required",
                "installed authority was never injected into this state root",
            )
        head = self._chain_head(records)
        status = self._status()
        current = status.get("current")
        if (
            not isinstance(current, Mapping)
            or status.get("accepted") != current
            or head["releaseId"] != current["releaseId"]
            or head["signedPayloadDigest"] != current["signedPayloadDigest"]
        ):
            raise UpdateAuthorityError(
                "installed_identity_unresolved",
                "installed identity chain head does not bind the durable installed release",
            )
        return head

    def _identity_by_digest(self, digest: object) -> dict[str, Any]:
        if not isinstance(digest, str) or AUTHORITY_DIGEST.fullmatch(digest) is None:
            raise UpdateAuthorityError(
                "authority_identity_unknown", "authority record names no installed identity"
            )
        records = self._load_identities()
        self._chain_head(records)
        for record in records:
            if record["identityDigest"] == digest:
                return record
        raise UpdateAuthorityError(
            "authority_identity_unknown",
            "authority record names an identity outside the installed chain",
        )

    def _load_reservation_record(self, request_id: str) -> dict[str, Any] | None:
        if AUTHORITY_REQUEST.fullmatch(request_id) is None:
            raise UpdateAuthorityError(
                "authority_reservation_invalid", "authority request id is invalid"
            )
        path = self.reservations_dir / f"{request_id}.json"
        if not path.exists() and not path.is_symlink():
            return None
        record = _validate_reservation_record(self._read_record(path, "installed reservation"))
        if (
            record["decision"]["requestId"] != request_id
            or record["installationId"] != self.store.installation_id
        ):
            raise UpdateAuthorityError(
                "authority_record_invalid",
                "installed reservation record does not bind this installation and request",
            )
        self._identity_by_digest(record["identityDigest"])
        return record

    def _request_id(self, action: str, run_id: str) -> str:
        seed = canonical_digest({"action": action, "runId": run_id})
        return f"authority_request_{seed.removeprefix('sha256:')[:32]}"

    @staticmethod
    def _action(plan: Mapping[str, Any]) -> str:
        operation = plan.get("operation")
        if operation == "update":
            return "apply_update"
        if operation == "rollback":
            return "rollback_update"
        raise UpdateAuthorityError("plan_invalid", "update plan operation is invalid")

    def _decision(
        self,
        *,
        action: str,
        run_id: str,
        identity: Mapping[str, Any],
        decided_at: str,
        estimated_seconds: int,
        outcome: str = "authorized",
        reason: str = "standing_scope_approved",
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "schema": "stateport.authority-decision/v1",
            "requestId": self._request_id(action, run_id),
            "action": action,
            "actorId": identity["actorId"],
            "authorizedBy": {
                "type": "grant",
                "id": f"grant_installed_{identity['installationId']}",
                "digest": identity["identityDigest"],
            },
            "scope": {
                "repository": {
                    "origin": identity["installerOrigin"],
                    "repositoryKey": identity["installationId"],
                    "repositoryRoot": str(self.store.root),
                },
                "branch": None,
                "sliceId": None,
                "applicationId": APPLICATION_ID,
                "runId": run_id,
                "paths": [str(self.store.root)],
            },
            "profile": AUTHORITY_PROFILE,
            "configuredPolicy": AUTHORITY_POLICY,
            "policy": AUTHORITY_POLICY,
            "decision": outcome,
            "reason": reason,
            "missingAssurances": [],
            "estimatedCostUsd": 0,
            "estimatedDurationSeconds": estimated_seconds,
            "requestedCapabilities": {
                "domains": [],
                "provider": None,
                "secretCapabilities": [],
                "assurances": [],
                "sourceIdentity": None,
            },
            "decidedAt": decided_at,
        }
        return {**body, "decisionDigest": _authority_digest(body)}

    def _reservation(
        self,
        decision: Mapping[str, Any],
        *,
        reserved_at: str,
    ) -> dict[str, Any]:
        suffix = str(decision["requestId"]).removeprefix("authority_request_")
        body: dict[str, Any] = {
            "schema": "stateport.authority-action-reservation/v1",
            "reservationId": f"authority_reservation_{suffix}",
            "requestId": decision["requestId"],
            "decision": dict(decision),
            "reservedAt": reserved_at,
        }
        return {**body, "reservationDigest": _authority_digest(body)}

    def _claim(self, binding: Mapping[str, Any], *, claimed_at: str) -> dict[str, Any]:
        decision = binding["decision"]
        reservation = binding["reservation"]
        suffix = str(decision["requestId"]).removeprefix("authority_request_")
        body: dict[str, Any] = {
            "schema": "stateport.authority-action-claim/v1",
            "claimId": f"authority_claim_{suffix}",
            "requestId": decision["requestId"],
            "reservationId": reservation["reservationId"],
            "reservationDigest": reservation["reservationDigest"],
            "decisionDigest": decision["decisionDigest"],
            "claimedAt": claimed_at,
        }
        return {**body, "claimDigest": _authority_digest(body)}

    def _receipt(
        self,
        decision: Mapping[str, Any],
        *,
        result_status: str,
        code: str | None,
        summary: str,
        resource: Mapping[str, Any],
        started_at: str,
        completed_at: str,
        reservation: Mapping[str, Any] | None,
        claim: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        suffix = str(decision["requestId"]).removeprefix("authority_request_")
        body: dict[str, Any] = {
            "schema": "stateport.authority-action-receipt/v1",
            "receiptId": f"authority_receipt_{suffix}",
            "requestId": decision["requestId"],
            "action": decision["action"],
            "actorId": decision["actorId"],
            "authorizedBy": dict(decision["authorizedBy"]),
            "scope": dict(decision["scope"]),
            "profile": decision["profile"],
            "configuredPolicy": decision["configuredPolicy"],
            "policy": decision["policy"],
            "decision": decision["decision"],
            "result": {
                "status": result_status,
                "code": code,
                "summary": summary.strip(),
                "resource": dict(resource),
            },
            "startedAt": started_at,
            "completedAt": completed_at,
            "estimatedCostUsd": 0,
            "actualCostUsd": 0,
            "decisionDigest": decision["decisionDigest"],
            "reservation": (
                None
                if reservation is None
                else {
                    "reservationId": reservation["reservationId"],
                    "reservationDigest": reservation["reservationDigest"],
                }
            ),
            "claim": (
                None
                if claim is None
                else {
                    "claimId": claim["claimId"],
                    "claimDigest": claim["claimDigest"],
                }
            ),
        }
        return {**body, "receiptDigest": _authority_digest(body)}

    def _persist_receipt(self, receipt: Mapping[str, Any]) -> dict[str, Any]:
        validated = _validate_receipt(receipt)
        self._identity_by_digest(validated["authorizedBy"]["digest"])
        self._ensure_directories()
        path = self.receipts_dir / f"{validated['receiptId']}.json"
        if path.exists() or path.is_symlink():
            persisted = _validate_receipt(self._read_record(path, "installed authority receipt"))
            if persisted != validated:
                raise UpdateAuthorityError(
                    "authority_terminal_conflict",
                    "installed authority receipt conflicts with an existing terminal record",
                )
            return persisted
        create_json(path, validated, "installed authority receipt")
        return validated

    def _refuse_with_receipt(
        self,
        decision: Mapping[str, Any],
        *,
        code: str,
        summary: str,
    ) -> UpdateAuthorityError:
        receipt = self._persist_receipt(
            self._receipt(
                decision,
                result_status="not_executed",
                code=code,
                summary=summary,
                resource={},
                started_at=_timestamp(self.clock),
                completed_at=_timestamp(self.clock),
                reservation=None,
                claim=None,
            )
        )
        return UpdateAuthorityError(code, summary, receipt=receipt)

    def reserve(self, plan: Mapping[str, Any]) -> dict[str, Any]:
        """Reserve an installed update action; refusals are terminally receipted.

        The reservation binds the exact plan digest as its authority run and
        the exact installed identity as its grant.  Re-reserving the same plan
        returns the durable create-only record, so an interrupted or retried
        control-plane hand-off converges without a second decision.
        """

        digest = plan.get("planDigest")
        if not isinstance(digest, str) or DIGEST.fullmatch(digest) is None:
            raise UpdateAuthorityError("plan_invalid", "update plan digest is invalid")
        action = self._action(plan)
        identity = self._current_identity()
        if plan.get("authority", {}).get("runId") != digest:
            raise UpdateAuthorityError(
                "authority_scope_mismatch", "plan does not bind its exact authority run"
            )
        request_id = self._request_id(action, digest)
        if self.terminal_receipt(request_id) is not None:
            raise UpdateAuthorityError(
                "authority_terminal_conflict",
                "installed update action already has a terminal receipt",
            )
        binding_failures: list[str] = []
        if plan.get("installationId") != self.store.installation_id:
            binding_failures.append("authority_scope_mismatch")
        policy = plan.get("policy")
        current = plan.get("current")
        if not isinstance(policy, Mapping) or policy.get("channel") != identity["channel"]:
            binding_failures.append("channel_mismatch")
        if (
            not isinstance(current, Mapping)
            or current.get("releaseId") != identity["releaseId"]
            or current.get("signedPayloadDigest") != identity["signedPayloadDigest"]
        ):
            binding_failures.append("installed_identity_changed")
        if binding_failures:
            code = binding_failures[0]
            raise self._refuse_with_receipt(
                self._decision(
                    action=action,
                    run_id=digest,
                    identity=identity,
                    decided_at=_timestamp(self.clock),
                    estimated_seconds=3600,
                    outcome="denied",
                    reason=code,
                ),
                code=code,
                summary="Installed update reservation was refused and not executed",
            )
        record = self._load_reservation_record(request_id)
        if record is not None:
            if record["decision"]["action"] != action:
                raise UpdateAuthorityError(
                    "authority_record_conflict",
                    "installed reservation record binds a different action",
                )
            return {"decision": record["decision"], "reservation": record["reservation"]}
        decision = self._decision(
            action=action,
            run_id=digest,
            identity=identity,
            decided_at=_timestamp(self.clock),
            estimated_seconds=3600,
        )
        reservation = self._reservation(decision, reserved_at=_timestamp(self.clock))
        self._ensure_directories()
        create_json(
            self.reservations_dir / f"{request_id}.json",
            {
                "schema": RESERVATION_RECORD_SCHEMA,
                "installationId": self.store.installation_id,
                "identityDigest": identity["identityDigest"],
                "decision": decision,
                "reservation": reservation,
            },
            "installed authority reservation",
        )
        return {"decision": decision, "reservation": reservation}

    def _validate_bound_decision(
        self,
        decision: Mapping[str, Any],
        *,
        action: str,
        run_id: str,
    ) -> dict[str, Any]:
        authorized_by = decision.get("authorizedBy")
        scope = decision.get("scope")
        if (
            decision.get("action") != action
            or decision.get("decision") != "authorized"
            or decision.get("profile") != AUTHORITY_PROFILE
            or decision.get("configuredPolicy") != AUTHORITY_POLICY
            or decision.get("policy") != AUTHORITY_POLICY
            or not isinstance(authorized_by, Mapping)
            or authorized_by.get("type") != "grant"
        ):
            raise UpdateAuthorityError(
                "authority_scope_mismatch",
                "installed authority decision does not bind the exact updater scope",
            )
        identity = self._identity_by_digest(authorized_by.get("digest"))
        repository = scope.get("repository") if isinstance(scope, Mapping) else None
        if (
            authorized_by.get("id") != f"grant_installed_{identity['installationId']}"
            or decision.get("actorId") != identity["actorId"]
            or not isinstance(scope, Mapping)
            or not isinstance(repository, Mapping)
            or repository.get("origin") != identity["installerOrigin"]
            or repository.get("repositoryKey") != self.store.installation_id
            or repository.get("repositoryRoot") != str(self.store.root)
            or scope.get("branch") is not None
            or scope.get("sliceId") is not None
            or scope.get("applicationId") != APPLICATION_ID
            or scope.get("runId") != run_id
            or scope.get("paths") != [str(self.store.root)]
        ):
            raise UpdateAuthorityError(
                "authority_scope_mismatch",
                "installed authority decision does not bind the exact installed identity",
            )
        return identity

    def validate_reservation(
        self,
        plan: Mapping[str, Any],
        authorization: Mapping[str, Any],
    ) -> dict[str, Any]:
        if not isinstance(authorization, Mapping) or set(authorization) != {
            "decision",
            "reservation",
        }:
            raise UpdateAuthorityError(
                "authority_reservation_invalid", "update authorization is malformed"
            )
        decision = _validate_decision(authorization.get("decision"))
        reservation = _validate_reservation(authorization.get("reservation"))
        action = self._action(plan)
        digest = plan.get("planDigest")
        self._validate_bound_decision(decision, action=action, run_id=str(digest))
        if (
            decision.get("scope", {}).get("runId") != digest
            or reservation.get("requestId") != decision.get("requestId")
            or reservation.get("decision") != dict(decision)
        ):
            raise UpdateAuthorityError(
                "authority_reservation_mismatch",
                "installed reservation does not bind the exact update plan",
            )
        record = self._load_reservation_record(str(decision["requestId"]))
        if record is None or record["decision"] != decision or record["reservation"] != reservation:
            raise UpdateAuthorityError(
                "authority_reservation_unknown",
                "update authorization has no exact durable installed reservation",
            )
        return {"decision": decision, "reservation": reservation}

    def claim(self, binding: Mapping[str, Any]) -> dict[str, Any]:
        decision = _validate_decision(binding.get("decision"))
        reservation = _validate_reservation(binding.get("reservation"))
        record = self._load_reservation_record(str(decision["requestId"]))
        if record is None or record["decision"] != decision or record["reservation"] != reservation:
            raise UpdateAuthorityError(
                "authority_claim_invalid",
                "authority claim has no exact durable installed reservation",
            )
        path = self.claims_dir / f"{decision['requestId']}.json"
        if path.exists() or path.is_symlink():
            claim = _validate_claim(self._read_record(path, "installed authority claim"))
            if (
                claim["requestId"] != decision["requestId"]
                or claim["reservationId"] != reservation["reservationId"]
                or claim["reservationDigest"] != reservation["reservationDigest"]
                or claim["decisionDigest"] != decision["decisionDigest"]
            ):
                raise UpdateAuthorityError(
                    "authority_claim_mismatch",
                    "persisted installed authority claim does not bind the exact reservation",
                )
            return claim
        if self.terminal_receipt(str(decision["requestId"])) is not None:
            raise UpdateAuthorityError(
                "authority_terminal_conflict",
                "authority claim follows a terminal installed receipt",
            )
        claim = self._claim(
            {"decision": decision, "reservation": reservation},
            claimed_at=_timestamp(self.clock),
        )
        self._ensure_directories()
        create_json(path, claim, "installed authority claim")
        return claim

    def recover_claim(self, request_id: str) -> dict[str, Any] | None:
        if AUTHORITY_REQUEST.fullmatch(request_id) is None:
            raise UpdateAuthorityError("authority_claim_invalid", "authority request id is invalid")
        path = self.claims_dir / f"{request_id}.json"
        if not path.exists() and not path.is_symlink():
            return None
        claim = _validate_claim(self._read_record(path, "installed authority claim"))
        if claim["requestId"] != request_id:
            raise UpdateAuthorityError(
                "authority_claim_mismatch", "persisted installed claim names another request"
            )
        record = self._load_reservation_record(request_id)
        if (
            record is None
            or claim["reservationId"] != record["reservation"]["reservationId"]
            or claim["reservationDigest"] != record["reservation"]["reservationDigest"]
            or claim["decisionDigest"] != record["decision"]["decisionDigest"]
        ):
            raise UpdateAuthorityError(
                "authority_claim_mismatch",
                "persisted installed claim has no exact durable reservation",
            )
        return claim

    def terminal_receipt(self, request_id: str) -> dict[str, Any] | None:
        if AUTHORITY_REQUEST.fullmatch(request_id) is None:
            raise UpdateAuthorityError(
                "authority_receipt_invalid", "authority request id is invalid"
            )
        if not self.receipts_dir.is_dir():
            return None
        found: dict[str, Any] | None = None
        for path in sorted(self.receipts_dir.glob("*.json")):
            receipt = _validate_receipt(self._read_record(path, "installed authority receipt"))
            if path.stem != receipt["receiptId"]:
                raise UpdateAuthorityError(
                    "authority_record_tampered",
                    "installed authority receipt filename does not match its identity",
                )
            if receipt["requestId"] != request_id:
                continue
            self._identity_by_digest(receipt["authorizedBy"]["digest"])
            if found is not None:
                raise UpdateAuthorityError(
                    "authority_record_conflict",
                    "installed authority has two terminal receipts for one request",
                )
            found = receipt
        return found

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
        decision = _validate_decision(binding.get("decision"))
        reservation = _validate_reservation(binding.get("reservation"))
        claim = _validate_claim(binding.get("claim"))
        record = self._load_reservation_record(str(decision["requestId"]))
        if (
            record is None
            or record["decision"] != decision
            or record["reservation"] != reservation
            or claim["requestId"] != decision["requestId"]
            or claim["reservationId"] != reservation["reservationId"]
            or claim["reservationDigest"] != reservation["reservationDigest"]
            or claim["decisionDigest"] != decision["decisionDigest"]
        ):
            raise UpdateAuthorityError(
                "authority_claim_invalid",
                "installed authority finalization does not bind exact durable records",
            )
        recovered = self.recover_claim(str(decision["requestId"]))
        if recovered != claim:
            raise UpdateAuthorityError(
                "authority_claim_mismatch",
                "installed authority finalization claim differs from its durable record",
            )
        # A retried finalization must converge on its exact durable terminal
        # receipt; rebuilding one would only invent a new completion instant.
        existing = self.terminal_receipt(str(decision["requestId"]))
        if existing is not None:
            result = existing["result"]
            if (
                existing["decisionDigest"] != decision["decisionDigest"]
                or existing["reservation"]
                != {
                    "reservationId": reservation["reservationId"],
                    "reservationDigest": reservation["reservationDigest"],
                }
                or existing["claim"]
                != {
                    "claimId": claim["claimId"],
                    "claimDigest": claim["claimDigest"],
                }
                or result["status"] != result_status
                or result["code"] != code
                or result["resource"] != dict(resource)
            ):
                raise UpdateAuthorityError(
                    "authority_terminal_conflict",
                    "installed authority retry conflicts with its terminal receipt",
                )
            receipt = existing
        else:
            receipt = self._persist_receipt(
                self._receipt(
                    decision,
                    result_status=result_status,
                    code=code,
                    summary=summary,
                    resource=resource,
                    started_at=(
                        started_at.astimezone(timezone.utc)
                        .replace(microsecond=0)
                        .isoformat()
                        .replace("+00:00", "Z")
                    ),
                    completed_at=_timestamp(self.clock),
                    reservation=reservation,
                    claim=claim,
                )
            )
        if result_status == "succeeded":
            self._ensure_advanced_identity(resource)
        return receipt

    def execute_scoped(
        self,
        action: str,
        *,
        run_id: str,
        operation: Callable[[], T],
        resource_from_result: Callable[[T], Mapping[str, Any]] | None = None,
    ) -> tuple[T, dict[str, Any]]:
        """Execute one installed control-plane operation with an exact receipt.

        Used for observe/plan/policy operations such as
        ``modify_update_policy``.  The scoped run binds the caller-supplied
        compare-and-swap digest; the operation result is returned with the
        canonical installed terminal receipt.
        """

        if ACTION.fullmatch(action) is None or DIGEST.fullmatch(run_id) is None:
            raise UpdateAuthorityError(
                "authority_scope_mismatch", "scoped installed action or run is invalid"
            )
        identity = self._current_identity()
        request_id = self._request_id(action, run_id)
        if self.terminal_receipt(request_id) is not None:
            raise UpdateAuthorityError(
                "authority_terminal_conflict",
                "scoped installed run already has a terminal receipt",
            )
        record = self._load_reservation_record(request_id)
        if record is None:
            decision = self._decision(
                action=action,
                run_id=run_id,
                identity=identity,
                decided_at=_timestamp(self.clock),
                estimated_seconds=300,
            )
            reservation = self._reservation(decision, reserved_at=_timestamp(self.clock))
            self._ensure_directories()
            create_json(
                self.reservations_dir / f"{request_id}.json",
                {
                    "schema": RESERVATION_RECORD_SCHEMA,
                    "installationId": self.store.installation_id,
                    "identityDigest": identity["identityDigest"],
                    "decision": decision,
                    "reservation": reservation,
                },
                "installed authority reservation",
            )
        else:
            if record["decision"]["action"] != action:
                raise UpdateAuthorityError(
                    "authority_record_conflict",
                    "installed reservation record binds a different action",
                )
            decision = record["decision"]
            reservation = record["reservation"]
        claim = self.claim({"decision": decision, "reservation": reservation})
        started_at = _timestamp(self.clock)
        try:
            result = operation()
        except Exception as exc:
            failure_code = getattr(exc, "code", None)
            if not isinstance(failure_code, str) or BOUNDARY_CODE.fullmatch(failure_code) is None:
                failure_code = "operation_failed"
            receipt = self._persist_receipt(
                self._receipt(
                    decision,
                    result_status="failed",
                    code=failure_code,
                    summary="Scoped installed operation failed",
                    resource={},
                    started_at=started_at,
                    completed_at=_timestamp(self.clock),
                    reservation=reservation,
                    claim=claim,
                )
            )
            raise UpdateAuthorityError(
                failure_code,
                "scoped installed operation failed",
                receipt=receipt,
            ) from exc
        resource = {} if resource_from_result is None else dict(resource_from_result(result))
        receipt = self._persist_receipt(
            self._receipt(
                decision,
                result_status="succeeded",
                code=None,
                summary="Scoped installed operation succeeded",
                resource=resource,
                started_at=started_at,
                completed_at=_timestamp(self.clock),
                reservation=reservation,
                claim=claim,
            )
        )
        return result, receipt

    def _release_target_facts(
        self,
        release_id: str,
        *,
        expected_index_digest: str,
        expected_target_id: str,
    ) -> dict[str, Any]:
        try:
            payload = read_bytes(
                self.store.releases / f"{release_id}.release-index.json",
                "canonical release index",
            )
            index = load_release_index(payload, legacy_predecessor=True)
        except (SafeIOError, ReleaseContractError) as exc:
            code = getattr(exc, "code", "release_index_invalid")
            raise UpdateAuthorityError(str(code), str(exc)) from exc
        if index.index_digest != expected_index_digest:
            raise UpdateAuthorityError(
                "installed_identity_conflict",
                "canonical release bytes do not match the exact update receipt",
            )
        signed = index.document["signed"]
        targets = [
            target for target in signed["targets"] if target.get("targetId") == expected_target_id
        ]
        if len(targets) != 1:
            raise UpdateAuthorityError(
                "installed_identity_conflict",
                "canonical release does not resolve the exact installed target",
            )
        target = targets[0]
        image_by_id = {str(image["imageId"]): image for image in signed["images"]}
        digests: list[str] = []
        for service in target["services"]:
            image = image_by_id.get(str(service["imageId"]))
            if image is None:
                raise UpdateAuthorityError(
                    "installed_identity_conflict",
                    "canonical release target does not resolve every service image",
                )
            digests.append(str(image["digest"]))
        return {
            "targetId": expected_target_id,
            "topologyDigest": str(target["topologyDigest"]),
            "quadletBundleDigest": str(target["quadletBundleDigest"]),
            "acceptedImageDigests": sorted(digests),
            "channel": str(signed["release"]["channel"]),
        }

    def _ensure_advanced_identity(self, resource: Mapping[str, Any]) -> dict[str, Any]:
        """Chain the installed identity to the just-accepted exact release.

        Runs after the durable status commit inside canonical finalization.
        Both the receipt and the identity advance are create-only, so a crash
        between them is recovered by the idempotent finalize retry rather than
        by inventing authority.
        """

        receipt_id = resource.get("updateReceiptId")
        accepted_release_id = resource.get("acceptedReleaseId")
        if (
            not isinstance(receipt_id, str)
            or UPDATE_RECEIPT_ID.fullmatch(receipt_id) is None
            or not isinstance(accepted_release_id, str)
            or SAFE_TEXT.fullmatch(accepted_release_id) is None
            or DIGEST.fullmatch(str(resource.get("updateReceiptDigest", ""))) is None
        ):
            raise UpdateAuthorityError(
                "authority_resource_invalid",
                "installed authority resource does not name an exact update receipt",
            )
        status = self._status()
        current = status.get("current")
        if (
            status.get("lastReceipt") != receipt_id
            or not isinstance(current, Mapping)
            or status.get("accepted") != current
            or current.get("releaseId") != accepted_release_id
        ):
            raise UpdateAuthorityError(
                "installed_identity_conflict",
                "durable installed state does not match the finalized update outcome",
            )
        try:
            receipt = validate_update_receipt(
                self._read_record(self.store.receipts / f"{receipt_id}.json", "update receipt")
            ).as_dict()
        except ReleaseContractError as exc:
            raise UpdateAuthorityError("installed_identity_conflict", str(exc)) from exc
        accepted = receipt.get("accepted")
        previous = receipt.get("from")
        if (
            receipt.get("installationId") != self.store.installation_id
            or receipt.get("result") != "accepted"
            or not isinstance(accepted, Mapping)
            or not isinstance(previous, Mapping)
            or accepted.get("releaseId") != accepted_release_id
            or accepted.get("releaseId") != current.get("releaseId")
            or accepted.get("version") != current.get("version")
            or accepted.get("signedPayloadDigest") != current.get("signedPayloadDigest")
            or canonical_digest(receipt) != resource["updateReceiptDigest"]
        ):
            raise UpdateAuthorityError(
                "installed_identity_conflict",
                "update receipt does not bind the exact accepted installed release",
            )
        records = self._load_identities()
        head = self._chain_head(records)
        if (
            head["releaseId"] == accepted["releaseId"]
            and head["signedPayloadDigest"] == accepted["signedPayloadDigest"]
        ):
            # The identity already advanced: a retried finalization converges
            # only when the head binds the exact update predecessor.
            if head["predecessorReleaseId"] == previous.get("releaseId") and head[
                "predecessorSignedPayloadDigest"
            ] == previous.get("signedPayloadDigest"):
                self._advance_install_trust(accepted=accepted, receipt=receipt, head=head)
                return head
            raise UpdateAuthorityError(
                "installed_identity_conflict",
                "installed identity advanced to a different predecessor",
            )
        if head["releaseId"] != previous.get("releaseId") or head[
            "signedPayloadDigest"
        ] != previous.get("signedPayloadDigest"):
            raise UpdateAuthorityError(
                "installed_identity_conflict",
                "installed identity chain head is not the exact update predecessor",
            )
        facts = self._release_target_facts(
            str(accepted["releaseId"]),
            expected_index_digest=str(receipt["releaseIndexDigest"]),
            expected_target_id=str(head["targetId"]),
        )
        if facts["channel"] != head["channel"]:
            raise UpdateAuthorityError(
                "installed_identity_conflict",
                "accepted release channel differs from the installed channel",
            )
        inode = self._native_state()
        body: dict[str, Any] = {
            "schema": IDENTITY_SCHEMA,
            "installationId": self.store.installation_id,
            "releaseId": str(accepted["releaseId"]),
            "version": str(accepted["version"]),
            "signedPayloadDigest": str(accepted["signedPayloadDigest"]),
            "releaseIndexDigest": str(receipt["releaseIndexDigest"]),
            "installerDigest": head["installerDigest"],
            "targetId": facts["targetId"],
            "topologyDigest": facts["topologyDigest"],
            "quadletBundleDigest": facts["quadletBundleDigest"],
            "acceptedImageDigests": facts["acceptedImageDigests"],
            "stateRootInode": inode,
            "channel": head["channel"],
            "predecessorReleaseId": str(previous["releaseId"]),
            "predecessorSignedPayloadDigest": str(previous["signedPayloadDigest"]),
            "predecessorIdentityDigest": head["identityDigest"],
            "installerOrigin": head["installerOrigin"],
            "installerVersion": head["installerVersion"],
            "actorId": head["actorId"],
            "createdAt": _timestamp(self.clock),
        }
        digest = canonical_digest(body)
        record = {
            **body,
            "identityId": f"installed_identity_{digest.removeprefix('sha256:')[:32]}",
            "identityDigest": digest,
        }
        self._ensure_directories()
        create_json(
            self.identity_dir / f"{record['identityId']}.json",
            record,
            "installed identity record",
        )
        self._advance_install_trust(accepted=accepted, receipt=receipt, head=record)
        return record

    def _advance_install_trust(
        self,
        *,
        accepted: Mapping[str, Any],
        receipt: Mapping[str, Any],
        head: Mapping[str, Any],
    ) -> None:
        """Advance the installer's durable trust record to the accepted release.

        Uninstall/purge derives its removal plan from the UNION of this record
        and the updater status, so after an accepted update the record must
        name the current accepted release and the identity chain head.  An
        absent record (updater store without installer genesis) is skipped;
        a foreign record refuses closed.  Genesis provenance fields (trust
        root, key, admission, installer digest) are preserved.
        """
        path = self.store.root / "trust" / "install-trust.json"
        if not path.exists() and not path.is_symlink():
            return
        try:
            record = read_json(path, "install trust record")
        except SafeIOError as exc:
            raise UpdateAuthorityError(str(exc.code), str(exc)) from exc
        if record.get("schema") != INSTALL_TRUST_SCHEMA:
            raise UpdateAuthorityError(
                "install_trust_conflict",
                "updater trust directory holds a foreign install trust record",
            )
        if (
            record.get("releaseId") == str(accepted["releaseId"])
            and record.get("signedPayloadDigest") == str(accepted["signedPayloadDigest"])
            and record.get("installedIdentityDigest") == str(head["identityDigest"])
        ):
            return
        advanced = {
            **record,
            "releaseId": str(accepted["releaseId"]),
            "releaseIndexDigest": str(receipt["releaseIndexDigest"]),
            "signedPayloadDigest": str(accepted["signedPayloadDigest"]),
            "installedIdentityId": str(head["identityId"]),
            "installedIdentityDigest": str(head["identityDigest"]),
        }
        try:
            replace_json(path, advanced, "install trust record")
        except SafeIOError as exc:
            raise UpdateAuthorityError(str(exc.code), str(exc)) from exc

    @classmethod
    def install(
        cls,
        store: UpdateStore,
        *,
        installer_digest: str,
        installer_origin: str,
        installer_version: str,
        actor_id: str,
        clock: Callable[[], datetime] | None = None,
    ) -> dict[str, Any]:
        """Inject the genesis installed identity once, from durable install truth.

        The installer calls this exactly once after ``UpdateEngine.initialize``
        committed the durable status.  Every identity field derives from the
        durable status, the installed-initialize admission, and the canonical
        release bytes; the installer contributes only its own digest, origin,
        version, and actor identity.  A second injection, a missing or advanced
        status, or a pending update refuses without writing anything.
        """

        _digest_field(installer_digest, "installer digest")
        if INSTALLER_ORIGIN.fullmatch(installer_origin) is None:
            raise UpdateAuthorityError("installer_identity_invalid", "installer origin is invalid")
        _semver_text(installer_version, "installer version")
        if not isinstance(actor_id, str) or not 1 <= len(actor_id) <= 128:
            raise UpdateAuthorityError("installer_identity_invalid", "installer actor is invalid")
        adapter = cls(store, clock=clock)
        if adapter._load_identities():
            raise UpdateAuthorityError(
                "installed_identity_exists",
                "installed authority was already injected into this state root",
            )
        try:
            status = adapter._status()
        except UpdateAuthorityError as exc:
            raise UpdateAuthorityError(
                "installed_status_missing",
                "installed authority cannot precede durable update status",
            ) from exc
        current = status.get("current")
        if (
            status.get("sequence") != 0
            or status.get("phase") != "idle"
            or not isinstance(current, Mapping)
            or status.get("accepted") != current
            or status.get("retainedPredecessor") is not None
            or status.get("stagedSuccessor") is not None
            or status.get("failedSuccessorEvidence") is not None
            or status.get("lastReceipt") is not None
            or store.pending_path.exists()
            or store.pending_path.is_symlink()
        ):
            raise UpdateAuthorityError(
                "installed_identity_incomplete",
                "durable installed state is not an exact fresh installation",
            )
        admissions: list[dict[str, Any]] = []
        if store.admissions.is_dir():
            for path in sorted(store.admissions.glob("*.json")):
                admission = _validated_admission(adapter._read_record(path, "release admission"))
                if (
                    admission["kind"] == "installed-initialize"
                    and admission["releaseId"] == current["releaseId"]
                    and admission["signedPayloadDigest"] == current["signedPayloadDigest"]
                    and admission["installationId"] == store.installation_id
                ):
                    admissions.append(admission)
        if len(admissions) != 1:
            raise UpdateAuthorityError(
                "installed_identity_incomplete",
                "installed release has no exact installed-initialize admission",
            )
        admission = admissions[0]
        facts = adapter._release_target_facts(
            str(current["releaseId"]),
            expected_index_digest=str(admission["releaseIndexDigest"]),
            expected_target_id=str(admission["targetId"]),
        )
        if facts["channel"] != admission["channel"]:
            raise UpdateAuthorityError(
                "installed_identity_incomplete",
                "installed release channel does not match its admission",
            )
        inode = adapter._native_state()
        body: dict[str, Any] = {
            "schema": IDENTITY_SCHEMA,
            "installationId": store.installation_id,
            "releaseId": str(current["releaseId"]),
            "version": str(current["version"]),
            "signedPayloadDigest": str(current["signedPayloadDigest"]),
            "releaseIndexDigest": str(admission["releaseIndexDigest"]),
            "installerDigest": installer_digest,
            "targetId": facts["targetId"],
            "topologyDigest": facts["topologyDigest"],
            "quadletBundleDigest": facts["quadletBundleDigest"],
            "acceptedImageDigests": facts["acceptedImageDigests"],
            "stateRootInode": inode,
            "channel": facts["channel"],
            "predecessorReleaseId": None,
            "predecessorSignedPayloadDigest": None,
            "predecessorIdentityDigest": None,
            "installerOrigin": installer_origin,
            "installerVersion": installer_version,
            "actorId": actor_id,
            "createdAt": _timestamp(adapter.clock),
        }
        digest = canonical_digest(body)
        record = {
            **body,
            "identityId": f"installed_identity_{digest.removeprefix('sha256:')[:32]}",
            "identityDigest": digest,
        }
        adapter._ensure_directories()
        create_json(
            adapter.identity_dir / f"{record['identityId']}.json",
            record,
            "installed identity record",
        )
        return record
