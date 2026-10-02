"""Fail-closed persistence for canonical update contracts and recovery WAL."""

from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import secrets
from typing import Any, Iterator, Mapping

from stateport_release import (
    ReleaseContractError,
    UpdaterReleaseEnvelope,
    canonical_digest,
    validate_contract_document,
    validate_update_authority_link,
    validate_update_failure_evidence,
    validate_update_receipt,
    validate_update_status,
)

from .safe_io import (
    SafeIOError,
    create_bytes,
    create_json,
    ensure_private_directory,
    exclusive_lock,
    read_bytes,
    read_json,
    replace_json,
    unlink_regular,
)


JOURNAL_SCHEMA = "stateport.internal-update-journal/v1"
ADMISSION_SCHEMA = "stateport.internal-release-admission/v1"
MANIFEST_SCHEMA = "stateport.internal-updater-store-manifest/v1"
SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
GIT_OBJECT = re.compile(r"[0-9a-f]{40,64}\Z")
INSTALLATION_ID = re.compile(r"[0-9a-f]{32}\Z")
JOURNAL_PLAN_STEPS = {
    "verify",
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
}
JOURNAL_INTERNAL_STEPS = {
    "accepted-route-observation",
    "automatic-rollback",
    "discard-successor",
}
JOURNAL_STEPS = JOURNAL_PLAN_STEPS | JOURNAL_INTERNAL_STEPS


class StoreError(ValueError):
    """Updater state is missing, unsafe, corrupt, or conflicting."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _safe_id(value: object, label: str) -> str:
    if not isinstance(value, str) or SAFE_ID.fullmatch(value) is None:
        raise StoreError("invalid_identity", f"{label} is invalid")
    return value


def _journal_digest(value: Mapping[str, Any]) -> str:
    # Canonical authority receipts intentionally contain exact JSON monetary
    # floats (for example 0.0).  The private WAL therefore uses the authority
    # engine's stable JSON form rather than the release contract's no-float
    # canonical form.
    payload = json.dumps(
        {key: item for key, item in value.items() if key != "journalDigest"},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _utc_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise StoreError("journal_invalid", f"{label} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise StoreError("journal_invalid", f"{label} is invalid") from exc
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() != timezone.utc.utcoffset(parsed)
        or parsed.microsecond
        or parsed.isoformat().replace("+00:00", "Z") != value
    ):
        raise StoreError("journal_invalid", f"{label} is invalid")
    return parsed


def _validated_manifest(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the create-only installed-identity manifest of one store."""

    if not isinstance(raw, Mapping):
        raise StoreError("manifest_invalid", "updater store manifest is invalid")
    manifest = dict(raw)
    if (
        set(manifest) != {"schema", "installationId", "createdAt"}
        or manifest.get("schema") != MANIFEST_SCHEMA
    ):
        raise StoreError("manifest_invalid", "updater store manifest has an invalid shape")
    installation_id = manifest.get("installationId")
    if not isinstance(installation_id, str) or INSTALLATION_ID.fullmatch(installation_id) is None:
        raise StoreError("manifest_invalid", "updater store installation id is invalid")
    try:
        _utc_timestamp(manifest.get("createdAt"), "manifest creation time")
    except StoreError as exc:
        raise StoreError("manifest_invalid", str(exc)) from exc
    return manifest


def _check_installation(
    document: Mapping[str, Any],
    *,
    installation_id: str,
    code: str,
    label: str,
) -> None:
    if document.get("installationId") != installation_id:
        raise StoreError(code, f"{label} belongs to a different installation")


def _validated_admission(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Validate create-only proof that an exact release passed admission.

    This private record is deliberately stricter than a cache marker.  It
    captures the actual verification instant and signer policy used by the
    updater.  Historic authentication may use that instant only after this
    record is cross-bound to installed state, a pending plan, or an accepted
    update receipt by the engine.
    """

    admission = deepcopy(dict(raw))
    expected = {
        "schema",
        "admissionId",
        "kind",
        "releaseId",
        "channel",
        "targetId",
        "releaseIndexDigest",
        "signedPayloadDigest",
        "sourceCommit",
        "verifiedAt",
        "trustMode",
        "verificationPolicy",
        "verificationPolicyDigest",
        "trustRootDigest",
        "verifiedSigners",
        "signatureProofs",
        "planDigest",
        "subject",
        "authority",
        "installationId",
        "admissionDigest",
    }
    if set(admission) != expected or admission.get("schema") != ADMISSION_SCHEMA:
        raise StoreError("admission_invalid", "release admission has an invalid shape")
    _safe_id(admission.get("admissionId"), "admission id")
    _safe_id(admission.get("releaseId"), "release id")
    if (
        not isinstance(admission.get("installationId"), str)
        or INSTALLATION_ID.fullmatch(admission["installationId"]) is None
    ):
        raise StoreError("admission_invalid", "release admission installation id is invalid")
    if admission.get("kind") not in {"installed-initialize", "update-apply"}:
        raise StoreError("admission_invalid", "release admission kind is invalid")
    if (
        not isinstance(admission.get("channel"), str)
        or not admission["channel"]
        or not isinstance(admission.get("targetId"), str)
        or not admission["targetId"]
    ):
        raise StoreError("admission_invalid", "release admission target is invalid")
    for field in (
        "releaseIndexDigest",
        "signedPayloadDigest",
        "verificationPolicyDigest",
        "trustRootDigest",
        "admissionDigest",
    ):
        if not isinstance(admission.get(field), str) or DIGEST.fullmatch(admission[field]) is None:
            raise StoreError("admission_invalid", f"release admission {field} is invalid")
    if (
        not isinstance(admission.get("sourceCommit"), str)
        or GIT_OBJECT.fullmatch(admission["sourceCommit"]) is None
    ):
        raise StoreError("admission_invalid", "release admission sourceCommit is invalid")
    plan_digest = admission.get("planDigest")
    if admission["kind"] == "installed-initialize":
        if plan_digest is not None:
            raise StoreError("admission_invalid", "initial admission cannot name an update plan")
    elif not isinstance(plan_digest, str) or DIGEST.fullmatch(plan_digest) is None:
        raise StoreError("admission_invalid", "update admission does not name an exact plan")
    subject = admission.get("subject")
    if not isinstance(subject, Mapping):
        raise StoreError("admission_invalid", "release admission subject is invalid")
    if admission["kind"] == "installed-initialize":
        if (
            set(subject) != {"type", "digest", "status"}
            or subject.get("type") != "installed-status"
        ):
            raise StoreError("admission_invalid", "initial admission subject is invalid")
        try:
            initial_status = validate_update_status(subject.get("status")).as_dict()
        except ReleaseContractError as exc:
            raise StoreError("admission_invalid", "initial admission status is invalid") from exc
        if (
            initial_status["sequence"] != 0
            or initial_status["current"] != initial_status["accepted"]
            or initial_status["current"]["releaseId"] != admission["releaseId"]
            or initial_status["current"]["signedPayloadDigest"] != admission["signedPayloadDigest"]
            or subject.get("digest") != canonical_digest(initial_status)
        ):
            raise StoreError(
                "admission_invalid",
                "initial admission is not bound to its exact initialized status",
            )
    elif dict(subject) != {"type": "update-plan", "digest": plan_digest}:
        raise StoreError("admission_invalid", "update admission subject is invalid")
    verified_at = admission.get("verifiedAt")
    if not isinstance(verified_at, str):
        raise StoreError("admission_invalid", "release admission time is invalid")
    try:
        parsed = datetime.fromisoformat(verified_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise StoreError("admission_invalid", "release admission time is invalid") from exc
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() != timezone.utc.utcoffset(parsed)
        or parsed.microsecond
        or parsed.isoformat().replace("+00:00", "Z") != verified_at
    ):
        raise StoreError("admission_invalid", "release admission time is invalid")

    policy = admission.get("verificationPolicy")
    policy_fields = {
        "expectedChannel",
        "expectedTarget",
        "updaterVersion",
        "acceptedSigners",
        "allowCandidate",
        "allowDeprecated",
        "requireTransparencyLog",
    }
    if not isinstance(policy, Mapping) or set(policy) != policy_fields:
        raise StoreError("admission_invalid", "release admission policy is invalid")
    if (
        policy["expectedChannel"] != admission["channel"]
        or policy["expectedTarget"] != admission["targetId"]
        or not isinstance(policy["updaterVersion"], str)
        or any(
            not isinstance(policy[field], bool)
            for field in ("allowCandidate", "allowDeprecated", "requireTransparencyLog")
        )
    ):
        raise StoreError("admission_invalid", "release admission policy does not bind its target")

    trust_mode = admission.get("trustMode")
    if trust_mode not in {"keyless", "pinned-public-key"}:
        raise StoreError("admission_invalid", "release admission trust mode is invalid")

    def validate_signers(value: object, label: str) -> list[dict[str, str]]:
        if not isinstance(value, list) or not value:
            raise StoreError("admission_invalid", f"release admission {label} is invalid")
        normalized: list[dict[str, str]] = []
        for signer in value:
            if not isinstance(signer, Mapping) or signer.get("mode") != trust_mode:
                raise StoreError("admission_invalid", f"release admission {label} is invalid")
            if trust_mode == "keyless":
                if set(signer) != {"mode", "certificateIdentity", "oidcIssuer"}:
                    raise StoreError("admission_invalid", f"release admission {label} is invalid")
                identity = signer.get("certificateIdentity")
                issuer = signer.get("oidcIssuer")
                if (
                    not isinstance(identity, str)
                    or not identity
                    or not isinstance(issuer, str)
                    or not issuer
                ):
                    raise StoreError("admission_invalid", f"release admission {label} is invalid")
                normalized.append(
                    {
                        "mode": "keyless",
                        "certificateIdentity": identity,
                        "oidcIssuer": issuer,
                    }
                )
            else:
                if set(signer) != {"mode", "keyId", "publicKeyDigest"}:
                    raise StoreError("admission_invalid", f"release admission {label} is invalid")
                key_id = signer.get("keyId")
                key_digest = signer.get("publicKeyDigest")
                if (
                    not isinstance(key_id, str)
                    or not key_id
                    or not isinstance(key_digest, str)
                    or DIGEST.fullmatch(key_digest) is None
                ):
                    raise StoreError("admission_invalid", f"release admission {label} is invalid")
                normalized.append(
                    {
                        "mode": "pinned-public-key",
                        "keyId": key_id,
                        "publicKeyDigest": key_digest,
                    }
                )
        signer_key = lambda item: tuple(str(value) for value in item.values())
        if normalized != sorted(normalized, key=signer_key):
            raise StoreError("admission_invalid", f"release admission {label} is not sorted")
        if len({canonical_digest(item) for item in normalized}) != len(normalized):
            raise StoreError("admission_invalid", f"release admission {label} is not unique")
        return normalized

    accepted = validate_signers(policy.get("acceptedSigners"), "accepted signers")
    verified = validate_signers(admission.get("verifiedSigners"), "verified signers")
    accepted_set = {canonical_digest(item) for item in accepted}
    if any(canonical_digest(item) not in accepted_set for item in verified):
        raise StoreError("admission_invalid", "verified signer was outside admission policy")
    if admission["verificationPolicyDigest"] != canonical_digest(
        {"verifiedAt": verified_at, "policy": dict(policy)}
    ):
        raise StoreError("admission_tampered", "release admission policy digest does not match")
    if admission["trustRootDigest"] != canonical_digest(
        {
            "acceptedSigners": accepted,
            "requireTransparencyLog": policy["requireTransparencyLog"],
        }
    ):
        raise StoreError("admission_tampered", "release admission trust root digest does not match")

    proofs = admission.get("signatureProofs")
    if not isinstance(proofs, list) or not proofs:
        raise StoreError("admission_invalid", "release admission signature proofs are invalid")
    proof_fields = {
        "trustMode",
        "scheme",
        "subjectKind",
        "subjectId",
        "subjectDigest",
        "bundleDigest",
        "signatureDescriptorDigest",
        "transparencyLog",
        "verificationState",
    } | (
        {"keyId", "publicKeyDigest"}
        if trust_mode == "pinned-public-key"
        else {"certificateIdentity", "oidcIssuer"}
    )
    for proof in proofs:
        if (
            not isinstance(proof, Mapping)
            or set(proof) != proof_fields
            or proof.get("trustMode") != trust_mode
            or proof.get("scheme") != "cosign-v3-bundle"
            or proof.get("subjectKind") not in {"release-index", "blob", "image"}
            or not isinstance(proof.get("subjectId"), str)
            or not proof["subjectId"]
            or not isinstance(proof.get("subjectDigest"), str)
            or DIGEST.fullmatch(proof["subjectDigest"]) is None
            or not isinstance(proof.get("bundleDigest"), str)
            or DIGEST.fullmatch(proof["bundleDigest"]) is None
            or not isinstance(proof.get("signatureDescriptorDigest"), str)
            or DIGEST.fullmatch(proof["signatureDescriptorDigest"]) is None
            or not isinstance(proof.get("transparencyLog"), str)
            or proof.get("verificationState") not in {"verified", "signed-index-declaration"}
        ):
            raise StoreError("admission_invalid", "release admission signature proof is invalid")
        if trust_mode == "pinned-public-key":
            if (
                not isinstance(proof.get("keyId"), str)
                or not proof["keyId"]
                or not isinstance(proof.get("publicKeyDigest"), str)
                or DIGEST.fullmatch(proof["publicKeyDigest"]) is None
                # A raw key can never claim keyless transparency authority.
                or proof["transparencyLog"] == "required-public-release"
            ):
                raise StoreError(
                    "admission_invalid", "release admission signature proof is invalid"
                )
        elif not isinstance(proof.get("certificateIdentity"), str) or not isinstance(
            proof.get("oidcIssuer"), str
        ):
            raise StoreError("admission_invalid", "release admission signature proof is invalid")
    if trust_mode == "pinned-public-key":
        proof_sort_key = lambda item: (
            item["keyId"],
            item["publicKeyDigest"],
            item["subjectKind"],
            item["subjectId"],
            item["bundleDigest"],
            item["signatureDescriptorDigest"],
        )
    else:
        proof_sort_key = lambda item: (
            item["certificateIdentity"],
            item["oidcIssuer"],
            item["subjectKind"],
            item["subjectId"],
            item["bundleDigest"],
            item["signatureDescriptorDigest"],
        )
    if proofs != sorted(proofs, key=proof_sort_key):
        raise StoreError("admission_invalid", "release admission signature proofs are not sorted")
    proof_signers = {
        canonical_digest(
            {
                "mode": "pinned-public-key",
                "keyId": item["keyId"],
                "publicKeyDigest": item["publicKeyDigest"],
            }
            if trust_mode == "pinned-public-key"
            else {
                "mode": "keyless",
                "certificateIdentity": item["certificateIdentity"],
                "oidcIssuer": item["oidcIssuer"],
            }
        )
        for item in proofs
    }
    verified_set = {canonical_digest(item) for item in verified}
    if proof_signers != verified_set:
        raise StoreError("admission_invalid", "signature proofs do not bind verified signers")
    if not any(
        item["subjectKind"] == "release-index" and item["verificationState"] == "verified"
        for item in proofs
    ):
        raise StoreError("admission_invalid", "release index has no verified signature proof")

    authority = admission.get("authority")
    authority_fields = {
        "kind",
        "requestId",
        "decisionDigest",
        "reservationDigest",
        "receiptId",
        "receiptDigest",
    }
    if not isinstance(authority, Mapping) or set(authority) != authority_fields:
        raise StoreError("admission_invalid", "release admission authority is invalid")
    if admission["kind"] == "installed-initialize":
        if authority != {
            "kind": "installer-status",
            "requestId": None,
            "decisionDigest": None,
            "reservationDigest": None,
            "receiptId": None,
            "receiptDigest": None,
        }:
            raise StoreError("admission_invalid", "initial admission authority is invalid")
    else:
        if authority.get("kind") != "update-reservation":
            raise StoreError("admission_invalid", "update admission authority is invalid")
        _safe_id(authority.get("requestId"), "authority request id")
        for field in ("decisionDigest", "reservationDigest"):
            if (
                not isinstance(authority.get(field), str)
                or DIGEST.fullmatch(authority[field]) is None
            ):
                raise StoreError("admission_invalid", "update admission authority is invalid")
        if authority.get("receiptId") is not None or authority.get("receiptDigest") is not None:
            raise StoreError(
                "admission_invalid", "pre-claim admission cannot name a terminal receipt"
            )
    body = {
        key: value
        for key, value in admission.items()
        if key not in {"admissionId", "admissionDigest"}
    }
    expected_digest = canonical_digest(body)
    if admission["admissionDigest"] != expected_digest:
        raise StoreError("admission_tampered", "release admission digest does not match")
    if (
        admission["admissionId"]
        != f"release_admission_{expected_digest.removeprefix('sha256:')[:32]}"
    ):
        raise StoreError("admission_tampered", "release admission identity does not match")
    return admission


def _validated_journal(raw: Mapping[str, Any]) -> dict[str, Any]:
    journal = dict(raw)
    expected = {
        "schema",
        "transactionId",
        "planId",
        "planDigest",
        "authority",
        "currentReleaseId",
        "successorReleaseId",
        "phase",
        "effectDisposition",
        "intent",
        "steps",
        "preparedReceipt",
        "preparedFailureEvidence",
        "canonicalAuthorityReceipt",
        "startedAt",
        "updatedAt",
        "journalDigest",
    }
    if set(journal) != expected or journal.get("schema") != JOURNAL_SCHEMA:
        raise StoreError("journal_invalid", "pending update journal has an invalid shape")
    for field in ("transactionId", "planId", "currentReleaseId", "successorReleaseId"):
        _safe_id(journal.get(field), field)
    if (
        not isinstance(journal.get("planDigest"), str)
        or DIGEST.fullmatch(journal["planDigest"]) is None
    ):
        raise StoreError("journal_invalid", "pending plan digest is invalid")
    suffix = journal["planDigest"].removeprefix("sha256:")[:32]
    if (
        journal["transactionId"] != f"update_txn_{suffix}"
        or journal["planId"] != f"update_plan_{suffix}"
        or journal["currentReleaseId"] == journal["successorReleaseId"]
    ):
        raise StoreError(
            "journal_invalid",
            "pending transaction identity does not derive from its exact plan",
        )
    authority = journal.get("authority")
    if not isinstance(authority, Mapping) or set(authority) != {
        "decision",
        "reservation",
        "claim",
    }:
        raise StoreError("journal_invalid", "pending authority binding is invalid")
    decision = authority.get("decision")
    reservation = authority.get("reservation")
    claim = authority.get("claim")
    if not all(isinstance(item, Mapping) for item in (decision, reservation)) or (
        claim is not None and not isinstance(claim, Mapping)
    ):
        raise StoreError("journal_invalid", "pending authority records are invalid")
    if (
        decision.get("decision") != "authorized"
        or decision.get("action") not in {"apply_update", "rollback_update"}
        or decision.get("scope", {}).get("runId") != journal["planDigest"]
        or reservation.get("decision") != decision
        or reservation.get("requestId") != decision.get("requestId")
    ):
        raise StoreError("journal_invalid", "authority scope does not bind the plan digest")
    if claim is not None and (
        claim.get("requestId") != decision.get("requestId")
        or claim.get("reservationId") != reservation.get("reservationId")
        or claim.get("reservationDigest") != reservation.get("reservationDigest")
        or claim.get("decisionDigest") != decision.get("decisionDigest")
    ):
        raise StoreError("journal_invalid", "authority claim does not bind its decision")
    phase = journal.get("phase")
    terminal_phases = {
        "reserved",
        "claimed",
        "claim_not_acquired",
        "failure_evidence_prepared",
        "retention_reconciliation_required",
        "cleanup_reconciliation_required",
        "receipt_prepared",
        "receipt_saved",
        "state_committed",
        "authority_finalization_pending",
        "authority_finalized",
        "link_saved",
        "completed",
        "reconciliation_required",
        "rollback_reconciliation_required",
    }
    allowed_phases = terminal_phases | JOURNAL_STEPS | {f"intent_{step}" for step in JOURNAL_STEPS}
    if not isinstance(phase, str) or phase not in allowed_phases:
        raise StoreError("journal_invalid", "pending update phase is invalid")
    if journal.get("effectDisposition") not in {
        "not_applied",
        "partial",
        "applied",
        "rolled_back",
        "unknown",
    }:
        raise StoreError("journal_invalid", "pending effect disposition is invalid")
    intent = journal.get("intent")
    if intent is not None:
        if not isinstance(intent, Mapping) or set(intent) != {"step", "effect", "recordedAt"}:
            raise StoreError("journal_invalid", "pending effect intent is invalid")
        if intent.get("step") not in JOURNAL_STEPS or intent.get("effect") not in {
            "not_applied",
            "partial",
            "applied",
        }:
            raise StoreError("journal_invalid", "pending effect intent is malformed")
        if phase not in {
            f"intent_{intent['step']}",
            "reconciliation_required",
            "rollback_reconciliation_required",
            "cleanup_reconciliation_required",
            "retention_reconciliation_required",
        }:
            raise StoreError("journal_invalid", "pending phase does not bind its effect intent")
        _utc_timestamp(intent.get("recordedAt"), "pending effect intent timestamp")
    steps = journal.get("steps")
    if not isinstance(steps, list) or len(steps) > 128:
        raise StoreError("journal_invalid", "pending update steps are invalid")
    step_names: list[str] = []
    step_times: list[datetime] = []
    for step in steps:
        if not isinstance(step, Mapping) or set(step) != {"step", "at", "evidence"}:
            raise StoreError("journal_invalid", "pending update step is invalid")
        if step.get("step") not in JOURNAL_STEPS or not isinstance(step.get("evidence"), Mapping):
            raise StoreError("journal_invalid", "pending update step evidence is invalid")
        step_names.append(str(step["step"]))
        step_times.append(_utc_timestamp(step.get("at"), "pending update step timestamp"))
    repeated = {
        name
        for name in step_names
        if name != "accepted-route-observation" and step_names.count(name) > 1
    }
    if repeated:
        raise StoreError("journal_invalid", "pending update steps repeat an effect or gate")
    prepared = journal.get("preparedReceipt")
    if prepared is not None:
        try:
            validate_update_receipt(prepared)
        except ReleaseContractError as exc:
            raise StoreError("journal_invalid", "prepared update receipt is invalid") from exc
        if (
            prepared["planId"] != journal["planId"]
            or prepared["planDigest"] != journal["planDigest"]
            or prepared["from"]["releaseId"] != journal["currentReleaseId"]
            or prepared["attempted"]["releaseId"] != journal["successorReleaseId"]
            or prepared["authority"]["requestId"] != decision.get("requestId")
            or prepared["authority"]["decisionDigest"] != decision.get("decisionDigest")
            or prepared["authority"]["reservationId"] != reservation.get("reservationId")
            or prepared["authority"]["reservationDigest"] != reservation.get("reservationDigest")
            or claim is None
            or prepared["authority"]["claimId"] != claim.get("claimId")
            or prepared["authority"]["claimDigest"] != claim.get("claimDigest")
            or "retain-predecessor" not in step_names
        ):
            raise StoreError(
                "journal_invalid",
                "prepared update receipt is not cross-bound to the pending transaction",
            )
    failure = journal.get("preparedFailureEvidence")
    if failure is not None:
        try:
            validate_update_failure_evidence(failure)
        except ReleaseContractError as exc:
            raise StoreError("journal_invalid", "prepared failure evidence is invalid") from exc
        if (
            failure["planId"] != journal["planId"]
            or failure["planDigest"] != journal["planDigest"]
            or failure["successor"]["releaseId"] != journal["successorReleaseId"]
        ):
            raise StoreError(
                "journal_invalid",
                "prepared failure evidence is not bound to the pending transaction",
            )
    if prepared is not None and ((prepared["result"] == "accepted") != (failure is None)):
        raise StoreError(
            "journal_invalid",
            "prepared receipt result does not match failure evidence state",
        )
    canonical = journal.get("canonicalAuthorityReceipt")
    if canonical is not None and not isinstance(canonical, Mapping):
        raise StoreError("journal_invalid", "canonical authority receipt is invalid")
    if canonical is not None:
        if prepared is None or claim is None:
            raise StoreError(
                "journal_invalid",
                "canonical authority receipt precedes the exact prepared outcome",
            )
        if (
            canonical.get("decisionDigest") != decision.get("decisionDigest")
            or canonical.get("claim", {}).get("claimId") != claim.get("claimId")
            or not isinstance(canonical.get("receiptId"), str)
            or not isinstance(canonical.get("receiptDigest"), str)
            or DIGEST.fullmatch(str(canonical.get("receiptDigest"))) is None
        ):
            raise StoreError(
                "journal_invalid",
                "canonical authority receipt is not bound to the exact claim",
            )
    started = _utc_timestamp(journal.get("startedAt"), "pending update start timestamp")
    updated = _utc_timestamp(journal.get("updatedAt"), "pending update update timestamp")
    if (
        started > updated
        or step_times != sorted(step_times)
        or any(observed < started or observed > updated for observed in step_times)
    ):
        raise StoreError("journal_invalid", "pending update timestamps are inconsistent")
    if intent is not None:
        recorded = _utc_timestamp(intent["recordedAt"], "pending effect intent timestamp")
        if recorded < started or recorded > updated:
            raise StoreError("journal_invalid", "pending effect intent timestamp is inconsistent")
    if journal.get("journalDigest") != _journal_digest(journal):
        raise StoreError("journal_tampered", "pending update journal digest does not match")
    return journal


def project_update_status(
    status: Mapping[str, Any],
    pending: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Purely project one coherent persisted-status/WAL snapshot for operators."""

    projected = deepcopy(dict(status))
    if pending is None:
        return projected
    intent = pending.get("intent")
    step = (
        str(intent["step"])
        if isinstance(intent, Mapping) and isinstance(intent.get("step"), str)
        else str(pending["phase"])
    )
    if step == "automatic-rollback" or "rollback" in step:
        phase = "rolling_back"
    elif step in {
        "switch",
        "health-accepted-route",
        "state-check-accepted-route",
        "accepted-route-observation",
        "reconciliation_required",
    }:
        phase = "switching"
    elif step == "pull":
        phase = "downloading"
    elif step == "stage":
        phase = "staged" if pending.get("intent") is None else "downloading"
    elif step in {
        "dry-run-migrations",
        "start-successor",
        "health-successor",
        "browser-successor",
        "studystate-successor",
        "state-check-successor",
        "retain-predecessor",
        "retention_reconciliation_required",
        "cleanup_reconciliation_required",
        "receipt_prepared",
        "receipt_saved",
        "state_committed",
        "authority_finalization_pending",
        "authority_finalized",
        "link_saved",
    }:
        phase = "validating"
    else:
        phase = "approved"
    projected["phase"] = phase
    projected["updatedAt"] = pending["updatedAt"]
    return projected


class UpdateStore:
    """Owner-private installed updater state with one cross-operation lock."""

    def __init__(self, root: Path | str, *, create: bool | None = None) -> None:
        if create is None:
            raise TypeError("use UpdateStore.create() or UpdateStore.open_existing()")
        candidate = Path(root).absolute()
        self.root = ensure_private_directory(candidate) if create else candidate
        self.plans = self.root / "plans"
        self.receipts = self.root / "receipts"
        self.failures = self.root / "failure-evidence"
        self.authority_links = self.root / "authority-links"
        self.admissions = self.root / "release-admissions"
        self.releases = self.root / "releases"
        self.journals = self.root / "journals"
        self.status_path = self.root / "status.json"
        self.pending_path = self.root / "pending.json"
        self.manifest_path = self.root / "manifest.json"
        self.lock_path = self.root / ".update.lock"
        self.operation_lock_path = self.root / ".operation.lock"
        if create:
            for directory in (
                self.plans,
                self.receipts,
                self.failures,
                self.authority_links,
                self.admissions,
                self.releases,
                self.journals,
            ):
                ensure_private_directory(directory)
            # Both lock identities are part of explicit store creation.  An
            # open-existing diagnostic or reconstructed process never creates
            # a path merely by attempting a read or acquiring a mutation lease.
            with exclusive_lock(self.lock_path):
                pass
            with exclusive_lock(self.operation_lock_path):
                pass
            self._ensure_manifest()

    def _ensure_manifest(self) -> None:
        """Create the installation identity once; never rewrite it afterwards."""

        if self.manifest_path.exists() or self.manifest_path.is_symlink():
            # Create is idempotent over an existing store, but the create-only
            # installation identity must validate and is never replaced.
            _validated_manifest(read_json(self.manifest_path, "updater store manifest"))
            return
        created = datetime.now(timezone.utc).replace(microsecond=0)
        create_json(
            self.manifest_path,
            {
                "schema": MANIFEST_SCHEMA,
                "installationId": secrets.token_hex(16),
                "createdAt": created.isoformat().replace("+00:00", "Z"),
            },
            "updater store manifest",
        )

    @property
    def installation_id(self) -> str:
        """The create-only identity that binds this store's updater authority."""

        try:
            manifest = read_json(self.manifest_path, "updater store manifest")
        except SafeIOError as exc:
            raise StoreError(exc.code, str(exc)) from exc
        return str(_validated_manifest(manifest)["installationId"])

    @classmethod
    def create(cls, root: Path | str) -> "UpdateStore":
        """Create one new/migrated state layout and its fixed lock identities."""

        return cls(root, create=True)

    @classmethod
    def open_existing(cls, root: Path | str) -> "UpdateStore":
        """Return a path-pure handle; no filesystem entry is created."""

        return cls(root, create=False)

    @contextmanager
    def transaction(self, *, timeout_seconds: float = 1.0) -> Iterator["UpdateSession"]:
        try:
            with exclusive_lock(
                self.lock_path,
                timeout_seconds=timeout_seconds,
                create=False,
            ):
                yield UpdateSession(self)
        except SafeIOError as exc:
            raise StoreError(exc.code, str(exc)) from exc

    @contextmanager
    def operation_lease(self, *, timeout_seconds: float = 1.0) -> Iterator[None]:
        """Serialize mutators without holding the short-lived state lock."""

        try:
            with exclusive_lock(
                self.operation_lock_path,
                timeout_seconds=timeout_seconds,
                create=False,
            ):
                yield
        except SafeIOError as exc:
            raise StoreError(exc.code, str(exc)) from exc

    def snapshot(self) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Read coherent status and pending WAL state under one short lock."""

        with self.transaction() as session:
            return session.load_status(), session.load_pending()

    def status(self) -> dict[str, Any]:
        with self.transaction() as session:
            return session.load_status()

    def load_plan(self, plan_id: str) -> dict[str, Any]:
        with self.transaction() as session:
            return session.load_plan(plan_id)

    def load_receipt(self, receipt_id: str) -> dict[str, Any]:
        with self.transaction() as session:
            return session.load_receipt(receipt_id)


class UpdateSession:
    """Methods valid while ``UpdateStore.transaction`` holds its lock."""

    def __init__(self, store: UpdateStore) -> None:
        self.store = store

    @staticmethod
    def _same_json_or_conflict(
        path: Path,
        value: Mapping[str, Any],
        label: str,
    ) -> bool:
        if not path.exists() and not path.is_symlink():
            return False
        existing = read_json(path, label)
        if existing != dict(value):
            raise StoreError(
                "immutable_record_conflict", f"{label} conflicts with an existing record"
            )
        return True

    def initialize_status(self, status: Mapping[str, Any]) -> dict[str, Any]:
        try:
            validated = validate_update_status(status).as_dict()
        except ReleaseContractError as exc:
            raise StoreError("status_invalid", str(exc)) from exc
        _check_installation(
            validated,
            installation_id=self.store.installation_id,
            code="status_invalid",
            label="update status",
        )
        if self.store.status_path.exists() or self.store.status_path.is_symlink():
            current = self.load_status()
            if current != validated:
                raise StoreError("already_initialized", "updater status already exists")
            return current
        create_json(self.store.status_path, validated, "update status")
        return deepcopy(validated)

    def status_exists(self) -> bool:
        """Return whether any status entry exists without following it."""

        return self.store.status_path.exists() or self.store.status_path.is_symlink()

    def load_status(self) -> dict[str, Any]:
        try:
            validated = validate_update_status(
                read_json(self.store.status_path, "update status")
            ).as_dict()
        except (SafeIOError, ReleaseContractError) as exc:
            code = exc.code if hasattr(exc, "code") else "status_invalid"
            raise StoreError(code, str(exc)) from exc
        _check_installation(
            validated,
            installation_id=self.store.installation_id,
            code="status_invalid",
            label="update status",
        )
        return validated

    def save_status(self, raw: Mapping[str, Any], *, timestamp: str) -> dict[str, Any]:
        status = dict(raw)
        previous = self.load_status()
        status["sequence"] = previous["sequence"] + 1
        status["updatedAt"] = timestamp
        try:
            validated = validate_update_status(status).as_dict()
        except ReleaseContractError as exc:
            raise StoreError("status_invalid", str(exc)) from exc
        _check_installation(
            validated,
            installation_id=self.store.installation_id,
            code="status_invalid",
            label="update status",
        )
        replace_json(self.store.status_path, validated, "update status")
        return deepcopy(validated)

    def save_release(self, envelope: UpdaterReleaseEnvelope) -> None:
        if not isinstance(envelope, UpdaterReleaseEnvelope):
            raise StoreError("release_invalid", "release is not a verified updater envelope")
        release = envelope.document.get("release")
        if not isinstance(release, Mapping):
            raise StoreError("release_invalid", "release envelope has no identity")
        self.save_release_index_bytes(
            release.get("releaseId"), envelope.canonical_index_bytes
        )

    def save_release_index_bytes(self, release_id: Any, payload: bytes) -> None:
        """Persist one canonical release index under its release identity.

        The successor predecessor chain must be durable in the installed
        store so ``check``/``plan`` can authenticate the exact predecessor
        index before it verifies a successor.  Genesis persists the current
        envelope through :meth:`save_release`; this writes an authenticated
        legacy predecessor index into the same immutable ``releases/`` slot.
        """

        release_key = _safe_id(release_id, "release id")
        path = self.store.releases / f"{release_key}.release-index.json"
        if path.exists() or path.is_symlink():
            if read_bytes(path, "canonical release index") != payload:
                raise StoreError(
                    "immutable_record_conflict",
                    "release identity conflicts with another canonical index",
                )
            return
        create_bytes(path, payload, "canonical release index")

    def save_admission(self, admission: Mapping[str, Any]) -> str:
        validated = _validated_admission(admission)
        _check_installation(
            validated,
            installation_id=self.store.installation_id,
            code="admission_invalid",
            label="release admission",
        )
        self._save_immutable(
            self.store.admissions,
            validated["admissionId"],
            validated,
            "release admission",
        )
        return str(validated["admissionDigest"])

    def list_admissions(self, release_id: str | None = None) -> list[dict[str, Any]]:
        expected_release_id = None if release_id is None else _safe_id(release_id, "release id")
        values: list[dict[str, Any]] = []
        for path in sorted(self.store.admissions.glob("*.json")):
            try:
                admission = _validated_admission(read_json(path, "release admission"))
            except SafeIOError as exc:
                raise StoreError(exc.code, str(exc)) from exc
            if path.stem != admission["admissionId"]:
                raise StoreError(
                    "admission_tampered",
                    "release admission filename does not match its immutable identity",
                )
            _check_installation(
                admission,
                installation_id=self.store.installation_id,
                code="admission_invalid",
                label="release admission",
            )
            if expected_release_id is None or admission["releaseId"] == expected_release_id:
                values.append(admission)
        return values

    def load_release_index_bytes(self, release_id: str) -> bytes:
        path = self.store.releases / f"{_safe_id(release_id, 'release id')}.release-index.json"
        try:
            return read_bytes(path, "canonical release index")
        except SafeIOError as exc:
            raise StoreError(exc.code, str(exc)) from exc

    def _save_immutable(
        self,
        directory: Path,
        identity: str,
        value: Mapping[str, Any],
        label: str,
    ) -> None:
        path = directory / f"{_safe_id(identity, label + ' id')}.json"
        if not self._same_json_or_conflict(path, value, label):
            create_json(path, value, label)

    def save_plan(self, plan: Mapping[str, Any]) -> None:
        try:
            validated = validate_contract_document(
                plan, expected_schema="stateport.update-plan/v1"
            ).as_dict()
        except ReleaseContractError as exc:
            raise StoreError("plan_invalid", str(exc)) from exc
        _check_installation(
            validated,
            installation_id=self.store.installation_id,
            code="plan_invalid",
            label="update plan",
        )
        self._save_immutable(self.store.plans, validated["planId"], validated, "update plan")

    def load_plan(self, plan_id: str) -> dict[str, Any]:
        path = self.store.plans / f"{_safe_id(plan_id, 'plan id')}.json"
        try:
            validated = validate_contract_document(
                read_json(path, "update plan"),
                expected_schema="stateport.update-plan/v1",
            ).as_dict()
        except (SafeIOError, ReleaseContractError) as exc:
            code = exc.code if hasattr(exc, "code") else "plan_invalid"
            raise StoreError(code, str(exc)) from exc
        _check_installation(
            validated,
            installation_id=self.store.installation_id,
            code="plan_invalid",
            label="update plan",
        )
        return validated

    def save_receipt(self, receipt: Mapping[str, Any]) -> str:
        try:
            validated = validate_update_receipt(receipt)
        except ReleaseContractError as exc:
            raise StoreError("receipt_invalid", str(exc)) from exc
        value = validated.as_dict()
        _check_installation(
            value,
            installation_id=self.store.installation_id,
            code="receipt_invalid",
            label="update receipt",
        )
        self._save_immutable(self.store.receipts, value["receiptId"], value, "update receipt")
        return validated.digest

    def load_receipt(self, receipt_id: str) -> dict[str, Any]:
        path = self.store.receipts / f"{_safe_id(receipt_id, 'receipt id')}.json"
        try:
            validated = validate_update_receipt(read_json(path, "update receipt")).as_dict()
        except (SafeIOError, ReleaseContractError) as exc:
            code = exc.code if hasattr(exc, "code") else "receipt_invalid"
            raise StoreError(code, str(exc)) from exc
        _check_installation(
            validated,
            installation_id=self.store.installation_id,
            code="receipt_invalid",
            label="update receipt",
        )
        return validated

    def list_receipts(self) -> list[dict[str, Any]]:
        values: list[dict[str, Any]] = []
        for path in sorted(self.store.receipts.glob("*.json")):
            try:
                receipt = validate_update_receipt(read_json(path, "update receipt")).as_dict()
            except (SafeIOError, ReleaseContractError) as exc:
                code = exc.code if hasattr(exc, "code") else "receipt_invalid"
                raise StoreError(code, str(exc)) from exc
            _check_installation(
                receipt,
                installation_id=self.store.installation_id,
                code="receipt_invalid",
                label="update receipt",
            )
            values.append(receipt)
        return values

    def list_failures(self) -> list[dict[str, Any]]:
        values: list[dict[str, Any]] = []
        for path in sorted(self.store.failures.glob("*.json")):
            try:
                values.append(
                    validate_update_failure_evidence(
                        read_json(path, "update failure evidence")
                    ).as_dict()
                )
            except (SafeIOError, ReleaseContractError) as exc:
                code = exc.code if hasattr(exc, "code") else "failure_invalid"
                raise StoreError(code, str(exc)) from exc
        return values

    def save_failure_evidence(self, failure: Mapping[str, Any]) -> str:
        try:
            validated = validate_update_failure_evidence(failure)
        except ReleaseContractError as exc:
            raise StoreError("failure_invalid", str(exc)) from exc
        value = validated.as_dict()
        self._save_immutable(
            self.store.failures,
            value["failureId"],
            value,
            "update failure evidence",
        )
        return validated.digest

    def save_authority_link(self, link: Mapping[str, Any]) -> str:
        try:
            validated = validate_update_authority_link(link)
        except ReleaseContractError as exc:
            raise StoreError("authority_link_invalid", str(exc)) from exc
        value = validated.as_dict()
        self._save_immutable(
            self.store.authority_links,
            value["linkId"],
            value,
            "update authority link",
        )
        return validated.digest

    def list_authority_links(self) -> list[dict[str, Any]]:
        values: list[dict[str, Any]] = []
        for path in sorted(self.store.authority_links.glob("*.json")):
            try:
                values.append(
                    validate_update_authority_link(
                        read_json(path, "update authority link")
                    ).as_dict()
                )
            except (SafeIOError, ReleaseContractError) as exc:
                code = exc.code if hasattr(exc, "code") else "authority_link_invalid"
                raise StoreError(code, str(exc)) from exc
        return values

    def load_pending(self) -> dict[str, Any] | None:
        if not self.store.pending_path.exists() and not self.store.pending_path.is_symlink():
            return None
        try:
            return _validated_journal(read_json(self.store.pending_path, "pending update journal"))
        except SafeIOError as exc:
            raise StoreError(exc.code, str(exc)) from exc

    def begin_journal(self, journal: Mapping[str, Any]) -> None:
        validated = _validated_journal(journal)
        if self.load_pending() is not None:
            raise StoreError("update_in_progress", "another update transaction is pending")
        create_json(self.store.pending_path, validated, "pending update journal")

    def save_journal(
        self,
        journal: Mapping[str, Any],
        *,
        expected_digest: str | None = None,
    ) -> None:
        validated = _validated_journal(journal)
        current = self.load_pending()
        if current is None:
            raise StoreError("journal_missing", "pending update journal is missing")
        if current.get("transactionId") != validated.get("transactionId"):
            raise StoreError("journal_conflict", "pending update journal identity changed")
        if expected_digest is not None and current.get("journalDigest") != expected_digest:
            raise StoreError(
                "journal_conflict",
                "pending update journal changed after the expected generation",
            )
        replace_json(self.store.pending_path, validated, "pending update journal")

    def archive_journal(
        self,
        journal: Mapping[str, Any],
        *,
        expected_digest: str | None = None,
    ) -> None:
        validated = _validated_journal(journal)
        transaction_id = _safe_id(validated.get("transactionId"), "transaction id")
        self._save_immutable(self.store.journals, transaction_id, validated, "update journal")
        current = self.load_pending()
        if current is None:
            return
        if expected_digest is not None and current.get("journalDigest") != expected_digest:
            raise StoreError(
                "journal_conflict",
                "pending update journal changed before terminal archival",
            )
        if current != validated:
            raise StoreError("journal_conflict", "pending update journal changed before archival")
        unlink_regular(self.store.pending_path, "pending update journal")


def journal_digest(journal: Mapping[str, Any]) -> str:
    """Public only within updater package so engine and store share one WAL digest."""

    return _journal_digest(journal)
