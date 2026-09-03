"""StatePort-owned staged update, rollback, and crash reconciliation engine."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import re
from typing import Any, Callable, Mapping, Protocol, Sequence

from stateport_release import (
    PinnedPublicKeyIdentity,
    ReleaseContractError,
    ReleaseVerificationPolicy,
    SignerIdentity,
    SignatureVerifier,
    UpdaterReleaseEnvelope,
    canonical_digest,
    embedded_predecessor_index,
    load_release_index,
    reverify_updater_release_envelope,
    to_updater_release_envelope,
    validate_contract_document,
    validate_update_plan,
    validate_update_receipt,
    verify_release_index,
)

from .authority import (
    UpdateAuthorityError,
    authority_reference,
    finalized_authority_reference,
)
from .models import ContractError, ReleaseFacts, UpdatePolicy, version_key
from .safe_io import read_json
from .store import (
    JOURNAL_SCHEMA,
    StoreError,
    UpdateSession,
    UpdateStore,
    _validated_admission,
    journal_digest,
    project_update_status,
)


UPDATER_VERSION = "0.1.1"
TARGET_ID = "linux-amd64-rootless-podman-quadlet"
WSL2_TARGET_ID = "wsl2-ubuntu2404-linux-amd64-rootless-podman-quadlet"
SUPPORTED_TARGET_IDS = frozenset({TARGET_ID, WSL2_TARGET_ID})
PLAN_TTL = timedelta(hours=24)
MAX_RECONCILIATION_OBSERVATIONS = 8
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
SAFE_EVIDENCE_KEY = re.compile(r"[A-Za-z][A-Za-z0-9]{0,63}\Z")
SENSITIVE_KEY = re.compile(r"(?i)(secret|token|password|credential|privatekey|authorization)")
SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")
ERROR_CODE = re.compile(r"[a-z][a-z0-9_]{0,127}\Z")

UPDATE_STEPS = (
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
    "record-receipt",
)
ROLLBACK_STEPS = (
    "verify",
    "backup",
    "stage",
    "start-successor",
    "health-successor",
    "browser-successor",
    "studystate-successor",
    "state-check-successor",
    "switch",
    "health-accepted-route",
    "state-check-accepted-route",
    "retain-predecessor",
    "record-receipt",
)


class UpdateError(ValueError):
    """A typed updater refusal or failed/reconciling transition."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: Mapping[str, Any] | None = None,
        receipt: Mapping[str, Any] | None = None,
    ) -> None:
        if not isinstance(code, str) or ERROR_CODE.fullmatch(code) is None:
            code = "updater_error"
        super().__init__(message)
        self.code = code
        self.details = dict(details or {})
        self.receipt = None if receipt is None else dict(receipt)


class UpdateHostError(UpdateError):
    """A host-adapter failure with an explicit side-effect disposition."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        effect: str = "not_applied",
        details: Mapping[str, Any] | None = None,
    ) -> None:
        if effect not in {"not_applied", "partial", "unknown", "applied"}:
            raise ValueError("invalid host failure effect")
        super().__init__(code, message, details=details)
        self.effect = effect


class UpdateHost(Protocol):
    """Bounded execution-host operations; no arbitrary shell text crosses it.

    Methods that may be called again during reconciliation are required to be
    idempotent for the exact plan digest.  Unknown effectful intents are never
    replayed automatically.
    """

    def preflight(self, release: ReleaseFacts) -> Mapping[str, Any]: ...

    def backup(self, plan: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def pull_images(self, plan: Mapping[str, Any], release: ReleaseFacts) -> Mapping[str, Any]: ...

    def stage(self, plan: Mapping[str, Any], release: ReleaseFacts) -> Mapping[str, Any]: ...

    def dry_run_migrations(self, plan: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def start_successor(self, plan: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def health_successor(self, plan: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def browser_successor(self, plan: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def studystate_successor(self, plan: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def state_check_successor(self, plan: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def switch(self, plan: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def health_accepted_route(self, plan: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def state_check_accepted_route(self, plan: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def observe_accepted_revision(self) -> Mapping[str, Any]: ...

    def discard_successor(self, plan: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def rollback_failed_switch(self, plan: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def observe_effect_receipt(self, *, plan_digest: str, step: str) -> Mapping[str, Any]: ...

    def enforce_retention(
        self,
        *,
        plan_digest: str,
        current_release_id: str,
        required_predecessor_ids: Sequence[str],
        required_failure_evidence_ids: Sequence[str],
        maximum_versions: int,
        maximum_age_days: int,
    ) -> Mapping[str, Any]: ...


class CanonicalUpdateAuthority(Protocol):
    def validate_reservation(
        self, plan: Mapping[str, Any], authorization: Mapping[str, Any]
    ) -> dict[str, Any]: ...

    def claim(self, binding: Mapping[str, Any]) -> dict[str, Any]: ...

    def recover_claim(self, request_id: str) -> dict[str, Any] | None: ...

    def terminal_receipt(self, request_id: str) -> dict[str, Any] | None: ...

    def finalize(
        self,
        binding: Mapping[str, Any],
        *,
        result_status: str,
        code: str | None,
        summary: str,
        resource: Mapping[str, Any],
        started_at: datetime,
    ) -> dict[str, Any]: ...


def _timestamp(clock: Callable[[], datetime]) -> str:
    value = clock().astimezone(timezone.utc).replace(microsecond=0)
    return value.isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise UpdateError("contract_invalid", f"{label} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise UpdateError("contract_invalid", f"{label} is invalid") from exc
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() != timezone.utc.utcoffset(parsed)
        or parsed.microsecond
        or parsed.isoformat().replace("+00:00", "Z") != value
    ):
        raise UpdateError("contract_invalid", f"{label} is invalid")
    return parsed


def _safe_evidence(value: object, label: str = "host evidence", *, depth: int = 0) -> Any:
    """Keep host-returned evidence bounded, path-free, and secret-free."""

    if depth > 16:
        raise UpdateError("host_evidence_invalid", f"{label} is too deeply nested")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > 2**63 - 1:
            raise UpdateError("host_evidence_invalid", f"{label} contains an out-of-range number")
        return value
    if isinstance(value, str):
        if len(value) > 2048 or "\x00" in value or value.startswith(("/", "~", "file:")):
            raise UpdateError("host_evidence_invalid", f"{label} contains an unsafe string")
        return value
    if isinstance(value, Mapping):
        if len(value) > 128:
            raise UpdateError("host_evidence_invalid", f"{label} contains too many fields")
        result: dict[str, Any] = {}
        for key, child in value.items():
            if (
                not isinstance(key, str)
                or SAFE_EVIDENCE_KEY.fullmatch(key) is None
                or SENSITIVE_KEY.search(key) is not None
            ):
                raise UpdateError("host_evidence_invalid", f"{label} contains an unsafe field")
            result[key] = _safe_evidence(child, f"{label}.{key}", depth=depth + 1)
        return result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if len(value) > 512:
            raise UpdateError("host_evidence_invalid", f"{label} contains too many items")
        return [_safe_evidence(child, label, depth=depth + 1) for child in value]
    raise UpdateError("host_evidence_invalid", f"{label} contains an unsupported value")


def _typed_mapping(
    value: object,
    *,
    schema: str,
    fields: set[str],
    label: str,
) -> dict[str, Any]:
    safe = _safe_evidence(value, label)
    expected = {"schema", *fields}
    if not isinstance(safe, dict) or set(safe) != expected or safe.get("schema") != schema:
        raise UpdateError(
            "host_evidence_invalid",
            f"{label} does not match {schema}",
        )
    return safe


def _evidence_id(value: object, label: str) -> str:
    if not isinstance(value, str) or SAFE_ID.fullmatch(value) is None:
        raise UpdateError("host_evidence_invalid", f"{label} is invalid")
    return value


def _evidence_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise UpdateError("host_evidence_invalid", f"{label} is invalid")
    return value


def historic_verification_policy(store: UpdateStore) -> ReleaseVerificationPolicy:
    """Rebuild the persisted trust policy that admitted the installed release."""

    with store.transaction() as session:
        status = session.load_status()
    release_id = status["current"]["releaseId"]
    admissions: list[dict[str, Any]] = []
    if store.admissions.is_dir():
        for path in sorted(store.admissions.glob("*.json")):
            admission = _validated_admission(read_json(path, "release admission"))
            if (
                admission["kind"] in {"installed-initialize", "update-apply"}
                and admission["releaseId"] == release_id
                and admission["installationId"] == store.installation_id
            ):
                admissions.append(admission)
    if not admissions:
        raise UpdateError(
            "historic_authentication_failed",
            "installed release has no exact durable admission",
        )
    admission = max(admissions, key=lambda item: str(item["verifiedAt"]))
    document = admission["verificationPolicy"]
    pinned = admission.get("trustMode") == "pinned-public-key"
    return ReleaseVerificationPolicy(
        expected_channel=str(document["expectedChannel"]),
        expected_target=str(document["expectedTarget"]),
        updater_version=str(document["updaterVersion"]),
        accepted_signers=frozenset(
            ()
            if pinned
            else (
                SignerIdentity(
                    certificate_identity=str(item["certificateIdentity"]),
                    oidc_issuer=str(item["oidcIssuer"]),
                )
                for item in document["acceptedSigners"]
            )
        ),
        accepted_public_keys=frozenset(
            (
                PinnedPublicKeyIdentity(
                    public_key_fingerprint=str(item["publicKeyDigest"]),
                    key_id=str(item["keyId"]),
                )
                for item in document["acceptedSigners"]
            )
            if pinned
            else ()
        ),
        expected_trust_mode="pinned-public-key" if pinned else "keyless-certificate",
        now=datetime.fromisoformat(str(admission["verifiedAt"])),
        allow_candidate=bool(document["allowCandidate"]),
        allow_deprecated=bool(document["allowDeprecated"]),
        require_transparency_log=bool(document["requireTransparencyLog"]),
    )


class UpdateEngine:
    """Coordinates signed releases, canonical authority, WAL, and host effects."""

    def __init__(
        self,
        store: UpdateStore,
        host: UpdateHost,
        authority: CanonicalUpdateAuthority,
        *,
        verification_policy: ReleaseVerificationPolicy,
        signature_verifier: SignatureVerifier,
        updater_version: str = UPDATER_VERSION,
        target_id: str = TARGET_ID,
        clock: Callable[[], datetime] | None = None,
        failpoint: Callable[[str], None] | None = None,
    ) -> None:
        version_key(updater_version)
        if verification_policy.expected_target != target_id:
            raise UpdateError("target_mismatch", "verification policy and updater target differ")
        self.store = store
        self.host = host
        self.authority = authority
        self.verification_policy = verification_policy
        self.signature_verifier = signature_verifier
        self.updater_version = updater_version
        self.target_id = target_id
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.failpoint = failpoint

    def _trip(self, phase: str) -> None:
        if self.failpoint is not None:
            self.failpoint(phase)

    def _now(self) -> datetime:
        return self.clock().astimezone(timezone.utc).replace(microsecond=0)

    def _policy_now(
        self,
        *,
        channel: str | None = None,
        at: datetime | None = None,
    ) -> ReleaseVerificationPolicy:
        return replace(
            self.verification_policy,
            expected_channel=channel or self.verification_policy.expected_channel,
            updater_version=self.updater_version,
            now=at or self._now(),
        )

    def _facts(
        self,
        envelope: UpdaterReleaseEnvelope,
        *,
        channel: str | None = None,
        verified_at: datetime | None = None,
    ) -> ReleaseFacts:
        """Reverify canonical bytes and derive facts from the rebound envelope."""

        try:
            verified = reverify_updater_release_envelope(
                envelope,
                policy=self._policy_now(channel=channel, at=verified_at),
                verifier=self.signature_verifier,
            )
            rebound = to_updater_release_envelope(verified)
        except ReleaseContractError as exc:
            raise UpdateError("release_verification_failed", str(exc)) from exc
        return ReleaseFacts.from_reverified(rebound, verified)

    @staticmethod
    def _signer_mapping(signer: SignerIdentity | PinnedPublicKeyIdentity) -> dict[str, str]:
        if isinstance(signer, PinnedPublicKeyIdentity):
            return {
                "mode": "pinned-public-key",
                "keyId": signer.key_id,
                "publicKeyDigest": signer.public_key_fingerprint,
            }
        return {
            "mode": "keyless",
            "certificateIdentity": signer.certificate_identity,
            "oidcIssuer": signer.oidc_issuer,
        }

    @staticmethod
    def _signer_sort_key(item: Mapping[str, str]) -> tuple[str, str]:
        if item["mode"] == "pinned-public-key":
            return (item["keyId"], item["publicKeyDigest"])
        return (item["certificateIdentity"], item["oidcIssuer"])

    @staticmethod
    def _signature_identity(signature: Mapping[str, Any]) -> dict[str, str]:
        """Signer fields of a verified signature descriptor, per trust mode."""

        if signature["trustMode"] == "pinned-public-key":
            return {
                "keyId": str(signature["publicKeyId"]),
                "publicKeyDigest": str(signature["publicKeyFingerprint"]),
            }
        return {
            "certificateIdentity": str(signature["certificateIdentity"]),
            "oidcIssuer": str(signature["certificateOidcIssuer"]),
        }

    def _signature_proofs(self, facts: ReleaseFacts) -> list[dict[str, str]]:
        trust_mode = (
            "pinned-public-key"
            if self.verification_policy.expected_trust_mode == "pinned-public-key"
            else "keyless"
        )
        verified_pairs = {
            self._signer_sort_key(self._signer_mapping(signer))
            for signer in facts.verified.verified_signers
        }
        descriptors = {
            (
                str(signature["subjectDigest"]),
                str(signature["bundle"]["digest"]),
            ): signature
            for signature in facts.verified.index.document["signatures"]
        }
        proofs: list[dict[str, str]] = []
        for proof in facts.verified.verification_proofs:
            signature = descriptors.get((proof.subject_digest, proof.bundle_digest))
            if signature is None:
                # The evolved contract also blob-verifies image signatures;
                # those proofs are persisted below as signed-index
                # declarations and are not release-index proofs.
                continue
            proofs.append(
                {
                    "trustMode": trust_mode,
                    **self._signature_identity(signature),
                    "scheme": str(signature["scheme"]),
                    "subjectKind": "release-index",
                    "subjectId": facts.release_id,
                    "subjectDigest": proof.subject_digest,
                    "bundleDigest": proof.bundle_digest,
                    "signatureDescriptorDigest": canonical_digest(signature),
                    "transparencyLog": str(signature["transparencyLog"]),
                    "verificationState": "verified",
                }
            )
        for image in facts.target_images:
            signature = image["signature"]
            signer = self._signer_sort_key(
                {"mode": trust_mode, **self._signature_identity(signature)}
            )
            if signer in verified_pairs:
                proofs.append(
                    {
                        "trustMode": trust_mode,
                        **self._signature_identity(signature),
                        "scheme": str(signature["scheme"]),
                        "subjectKind": "image",
                        "subjectId": str(image["imageId"]),
                        "subjectDigest": str(signature["subjectDigest"]),
                        "bundleDigest": str(signature["bundle"]["digest"]),
                        "signatureDescriptorDigest": canonical_digest(signature),
                        "transparencyLog": str(signature["transparencyLog"]),
                        # Current release-contract v1 authenticates this
                        # descriptor through the signed index but does not call
                        # the blob verifier.  Never mislabel it as blob-verified.
                        "verificationState": "signed-index-declaration",
                    }
                )
        return sorted(
            proofs,
            key=lambda item: (
                *self._signer_sort_key({"mode": item["trustMode"], **item}),
                item["subjectKind"],
                item["subjectId"],
                item["bundleDigest"],
                item["signatureDescriptorDigest"],
            ),
        )

    def _admission_record(
        self,
        facts: ReleaseFacts,
        *,
        kind: str,
        verified_at: datetime,
        subject: Mapping[str, Any],
        plan_digest: str | None,
        authority_binding: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        policy = self._policy_now(channel=facts.channel, at=verified_at)
        pinned = policy.expected_trust_mode == "pinned-public-key"
        accepted_signers = sorted(
            (
                self._signer_mapping(signer)
                for signer in (policy.accepted_public_keys if pinned else policy.accepted_signers)
            ),
            key=self._signer_sort_key,
        )
        verified_signers = sorted(
            (self._signer_mapping(signer) for signer in facts.verified.verified_signers),
            key=self._signer_sort_key,
        )
        signature_proofs = self._signature_proofs(facts)
        policy_document = {
            "expectedChannel": policy.expected_channel,
            "expectedTarget": policy.expected_target,
            "updaterVersion": policy.updater_version,
            "acceptedSigners": accepted_signers,
            "allowCandidate": policy.allow_candidate,
            "allowDeprecated": policy.allow_deprecated,
            "requireTransparencyLog": policy.require_transparency_log,
        }
        verified_at_text = verified_at.isoformat().replace("+00:00", "Z")
        body: dict[str, Any] = {
            "schema": "stateport.internal-release-admission/v1",
            "kind": kind,
            "releaseId": facts.release_id,
            "channel": facts.channel,
            "targetId": facts.target_id,
            "releaseIndexDigest": facts.index_digest,
            "signedPayloadDigest": facts.signed_digest,
            "sourceCommit": facts.source_commit,
            "verifiedAt": verified_at_text,
            "trustMode": "pinned-public-key" if pinned else "keyless",
            "verificationPolicy": policy_document,
            "verificationPolicyDigest": canonical_digest(
                {"verifiedAt": verified_at_text, "policy": policy_document}
            ),
            "trustRootDigest": canonical_digest(
                {
                    "acceptedSigners": accepted_signers,
                    "requireTransparencyLog": policy.require_transparency_log,
                }
            ),
            "verifiedSigners": verified_signers,
            "signatureProofs": signature_proofs,
            "planDigest": plan_digest,
            "subject": deepcopy(dict(subject)),
            "installationId": self.store.installation_id,
            "authority": (
                {
                    "kind": "installer-status",
                    "requestId": None,
                    "decisionDigest": None,
                    "reservationDigest": None,
                    "receiptId": None,
                    "receiptDigest": None,
                }
                if authority_binding is None
                else {
                    "kind": "update-reservation",
                    "requestId": authority_binding["decision"]["requestId"],
                    "decisionDigest": authority_binding["decision"]["decisionDigest"],
                    "reservationDigest": authority_binding["reservation"]["reservationDigest"],
                    "receiptId": None,
                    "receiptDigest": None,
                }
            ),
        }
        digest = canonical_digest(body)
        return {
            **body,
            "admissionId": f"release_admission_{digest.removeprefix('sha256:')[:32]}",
            "admissionDigest": digest,
        }

    @staticmethod
    def _receipt_accepts_admission(
        receipt: Mapping[str, Any], admission: Mapping[str, Any]
    ) -> bool:
        attempted = receipt.get("attempted")
        accepted = receipt.get("accepted")
        return bool(
            receipt.get("result") == "accepted"
            and receipt.get("installationId") == admission.get("installationId")
            and receipt.get("planDigest") == admission.get("planDigest")
            and receipt.get("releaseIndexDigest") == admission.get("releaseIndexDigest")
            and isinstance(attempted, Mapping)
            and isinstance(accepted, Mapping)
            and attempted.get("releaseId") == admission.get("releaseId")
            and accepted.get("releaseId") == admission.get("releaseId")
            and attempted.get("signedPayloadDigest") == admission.get("signedPayloadDigest")
            and accepted.get("signedPayloadDigest") == admission.get("signedPayloadDigest")
        )

    @staticmethod
    def _authority_link_accepts_admission(
        link: Mapping[str, Any],
        receipt: Mapping[str, Any],
        admission: Mapping[str, Any],
    ) -> bool:
        authority = link.get("authority")
        admitted_authority = admission.get("authority")
        return bool(
            isinstance(authority, Mapping)
            and isinstance(admitted_authority, Mapping)
            and link.get("planDigest") == admission.get("planDigest")
            and link.get("runId") == admission.get("planDigest")
            and link.get("updateReceiptId") == receipt.get("receiptId")
            and link.get("updateReceiptDigest") == canonical_digest(receipt)
            and authority.get("requestId") == admitted_authority.get("requestId")
            and authority.get("decisionDigest") == admitted_authority.get("decisionDigest")
            and authority.get("reservationDigest") == admitted_authority.get("reservationDigest")
            and isinstance(authority.get("receiptId"), str)
            and isinstance(authority.get("receiptDigest"), str)
        )

    def _canonical_terminal_accepts_link(
        self,
        link: Mapping[str, Any],
        receipt: Mapping[str, Any],
        admission: Mapping[str, Any],
    ) -> bool:
        authority = link.get("authority")
        if not isinstance(authority, Mapping):
            return False
        try:
            canonical = self.authority.terminal_receipt(str(authority.get("requestId")))
        except UpdateAuthorityError as exc:
            raise UpdateError(exc.code, str(exc), receipt=exc.receipt) from exc
        except Exception as exc:
            raise UpdateError(
                "authority_terminal_unavailable",
                "canonical terminal authority receipt could not be read",
            ) from exc
        if not isinstance(canonical, Mapping):
            return False
        result = canonical.get("result")
        resource = result.get("resource") if isinstance(result, Mapping) else None
        claim = canonical.get("claim")
        return bool(
            canonical.get("receiptId") == authority.get("receiptId")
            and canonical.get("receiptDigest") == authority.get("receiptDigest")
            and canonical.get("decisionDigest") == authority.get("decisionDigest")
            and isinstance(claim, Mapping)
            and claim.get("claimId") == authority.get("claimId")
            and isinstance(result, Mapping)
            and result.get("status") == "succeeded"
            and isinstance(resource, Mapping)
            and resource.get("updateReceiptId") == receipt.get("receiptId")
            and resource.get("updateReceiptDigest") == canonical_digest(receipt)
            and resource.get("planDigest") == admission.get("planDigest")
            and resource.get("acceptedReleaseId") == admission.get("releaseId")
        )

    def _select_admission(
        self,
        session: UpdateSession,
        release_id: str,
        *,
        required_plan_digest: str | None,
    ) -> dict[str, Any]:
        admissions = session.list_admissions(release_id)
        if required_plan_digest is not None:
            eligible = [
                item
                for item in admissions
                if item["kind"] == "update-apply"
                and item["planDigest"] == required_plan_digest
                and item["subject"] == {"type": "update-plan", "digest": required_plan_digest}
            ]
        else:
            receipts = session.list_receipts()
            authority_links = session.list_authority_links()
            durable_status = session.load_status() if session.status_exists() else None
            eligible = []
            for item in admissions:
                if item["kind"] == "installed-initialize":
                    # An installed-initialize admission is historic authority
                    # only while the durable status exists and still binds the
                    # admitted release as installed state; an orphan admission
                    # for a never-installed release proves nothing.
                    if durable_status is not None and any(
                        isinstance(identity, Mapping)
                        and identity.get("releaseId") == item["releaseId"]
                        and identity.get("signedPayloadDigest") == item["signedPayloadDigest"]
                        for identity in (
                            durable_status.get(field)
                            for field in (
                                "current",
                                "accepted",
                                "retainedPredecessor",
                                "stagedSuccessor",
                            )
                        )
                    ):
                        eligible.append(item)
                    continue
                accepted = False
                for receipt in receipts:
                    if not self._receipt_accepts_admission(receipt, item):
                        continue
                    for link in authority_links:
                        if self._authority_link_accepts_admission(
                            link, receipt, item
                        ) and self._canonical_terminal_accepts_link(link, receipt, item):
                            accepted = True
                            break
                    if accepted:
                        break
                if accepted:
                    eligible.append(item)
        if not eligible:
            raise UpdateError(
                "release_admission_missing",
                "historic release identity has no exact immutable admission proof",
            )
        return deepcopy(
            sorted(
                eligible,
                key=lambda item: (str(item["verifiedAt"]), str(item["admissionId"])),
            )[-1]
        )

    def _historic_facts(
        self,
        canonical_index_bytes: bytes,
        admission: Mapping[str, Any],
        *,
        channel: str,
    ) -> ReleaseFacts:
        """Re-authenticate exact bytes at a proven, create-only admission instant."""

        policy_document = admission["verificationPolicy"]
        if (
            admission["channel"] != channel
            or policy_document["expectedChannel"] != channel
            or policy_document["expectedTarget"] != self.target_id
        ):
            raise UpdateError(
                "historic_authentication_failed",
                "release admission policy does not match the requested channel and target",
            )
        pinned = admission.get("trustMode") == "pinned-public-key"
        historic_policy = ReleaseVerificationPolicy(
            expected_channel=str(policy_document["expectedChannel"]),
            expected_target=str(policy_document["expectedTarget"]),
            updater_version=str(policy_document["updaterVersion"]),
            accepted_signers=frozenset(
                ()
                if pinned
                else (
                    SignerIdentity(
                        certificate_identity=str(item["certificateIdentity"]),
                        oidc_issuer=str(item["oidcIssuer"]),
                    )
                    for item in policy_document["acceptedSigners"]
                )
            ),
            accepted_public_keys=frozenset(
                (
                    PinnedPublicKeyIdentity(
                        public_key_fingerprint=str(item["publicKeyDigest"]),
                        key_id=str(item["keyId"]),
                    )
                    for item in policy_document["acceptedSigners"]
                )
                if pinned
                else ()
            ),
            expected_trust_mode="pinned-public-key" if pinned else "keyless-certificate",
            now=_parse_timestamp(admission["verifiedAt"], "verifiedAt"),
            allow_candidate=bool(policy_document["allowCandidate"]),
            allow_deprecated=bool(policy_document["allowDeprecated"]),
            require_transparency_log=bool(policy_document["requireTransparencyLog"]),
        )
        try:
            index = load_release_index(canonical_index_bytes, legacy_predecessor=True)
            verified = verify_release_index(
                index,
                policy=historic_policy,
                verifier=self.signature_verifier,
                predecessor=embedded_predecessor_index(index),
                legacy_predecessor=True,
            )
            rebound = to_updater_release_envelope(verified)
        except ReleaseContractError as exc:
            raise UpdateError("historic_authentication_failed", str(exc)) from exc
        facts = ReleaseFacts.from_reverified(rebound, verified)
        verified_signers = sorted(
            (self._signer_mapping(signer) for signer in verified.verified_signers),
            key=self._signer_sort_key,
        )
        signature_proofs = self._signature_proofs(facts)
        if (
            facts.release_id != admission["releaseId"]
            or facts.channel != admission["channel"]
            or facts.target_id != admission["targetId"]
            or facts.index_digest != admission["releaseIndexDigest"]
            or facts.signed_digest != admission["signedPayloadDigest"]
            or facts.source_commit != admission["sourceCommit"]
            or verified_signers != admission["verifiedSigners"]
            or signature_proofs != admission["signatureProofs"]
        ):
            raise UpdateError(
                "historic_authentication_failed",
                "release bytes do not match their exact immutable admission proof",
            )
        return facts

    def _load_facts(
        self,
        session: UpdateSession,
        release_id: str,
        *,
        channel: str,
        required_plan_digest: str | None = None,
    ) -> ReleaseFacts:
        try:
            admission = self._select_admission(
                session,
                release_id,
                required_plan_digest=required_plan_digest,
            )
            payload = session.load_release_index_bytes(release_id)
        except StoreError as exc:
            raise UpdateError(exc.code, str(exc)) from exc
        return self._historic_facts(
            payload,
            admission,
            channel=channel,
        )

    def _adopt_torn_genesis(self, session: Any, facts: Any) -> dict[str, Any] | None:
        """Adopt the exact genesis admission left by a torn initialize.

        A crash between ``save_admission`` and ``initialize_status`` leaves a
        genesis admission whose wall-clock ``verifiedAt`` can never reproduce
        on a rerun.  The admission embeds the exact status it binds, so the
        rerun adopts both byte-identically instead of writing a second,
        divergent admission (which the installer would refuse as
        ``updater_genesis_conflict`` forever).
        """
        admissions = [
            item
            for item in session.list_admissions()
            if item.get("kind") == "installed-initialize"
        ]
        if not admissions:
            return None
        if len(admissions) != 1:
            raise UpdateError(
                "admission_conflict", "multiple genesis admissions claim this store"
            )
        admission = admissions[0]
        if (
            admission.get("releaseId") != facts.release_id
            or admission.get("signedPayloadDigest") != facts.signed_digest
            or admission.get("releaseIndexDigest") != facts.index_digest
        ):
            raise UpdateError(
                "admission_conflict", "the existing genesis admission binds another release"
            )
        subject = admission.get("subject")
        status = subject.get("status") if isinstance(subject, Mapping) else None
        current = status.get("current") if isinstance(status, Mapping) else None
        if not (
            isinstance(subject, Mapping)
            and subject.get("type") == "installed-status"
            and isinstance(status, Mapping)
            and canonical_digest(status) == subject.get("digest")
            and isinstance(current, Mapping)
            and current.get("releaseId") == facts.release_id
            and current.get("signedPayloadDigest") == facts.signed_digest
            and status.get("installationId") == self.store.installation_id
        ):
            # Structurally unadoptable remnant (for example re-issued for this
            # store with a foreign embedded status): fall back to the normal
            # path; the create-only writes converge on identical content or
            # refuse closed on drift.
            return None
        return deepcopy(dict(status))

    def initialize(
        self,
        release: UpdaterReleaseEnvelope,
        policy: UpdatePolicy,
    ) -> dict[str, Any]:
        # Repeat initialization must be a zero-write refusal.  In particular,
        # never persist a new release/admission and only then discover that an
        # installed status already exists.
        try:
            with self.store.transaction() as session:
                if session.status_exists():
                    session.load_status()
                    raise UpdateError(
                        "already_initialized",
                        "updater status already exists",
                    )
        except StoreError as exc:
            raise UpdateError(exc.code, str(exc)) from exc
        verified_at = self._now()
        facts = self._facts(
            release,
            channel=policy.channel,
            verified_at=verified_at,
        )
        self._check_static_release(facts, policy, current=None, operation="install")
        now = _timestamp(self.clock)
        status = {
            "schema": "stateport.update-status/v1",
            "sequence": 0,
            "phase": "idle",
            "installationId": self.store.installation_id,
            "policy": policy.to_mapping(),
            "current": facts.status_identity(),
            "accepted": facts.status_identity(),
            "retainedPredecessor": None,
            "stagedSuccessor": None,
            "failedSuccessorEvidence": None,
            "lastReceipt": None,
            "updatedAt": now,
        }
        with self.store.transaction() as session:
            if session.status_exists():
                session.load_status()
                raise UpdateError(
                    "already_initialized",
                    "updater status already exists",
                )
            adopted_status = self._adopt_torn_genesis(session, facts)
            session.save_release(facts.envelope)
            if adopted_status is not None:
                return session.initialize_status(adopted_status)
            session.save_admission(
                self._admission_record(
                    facts,
                    kind="installed-initialize",
                    verified_at=verified_at,
                    subject={
                        "type": "installed-status",
                        "digest": canonical_digest(status),
                        "status": deepcopy(status),
                    },
                    plan_digest=None,
                )
            )
            return session.initialize_status(status)

    def status(self) -> dict[str, Any]:
        try:
            status, pending = self.store.snapshot()
        except StoreError as exc:
            raise UpdateError(exc.code, str(exc)) from exc
        return project_update_status(status, pending)

    def _check_static_release(
        self,
        candidate: ReleaseFacts,
        policy: UpdatePolicy,
        *,
        current: ReleaseFacts | None,
        operation: str,
    ) -> None:
        if candidate.platform != "linux/amd64":
            raise UpdateError("architecture_mismatch", "only linux/amd64 is supported")
        if candidate.channel != policy.channel:
            raise UpdateError("channel_mismatch", "release channel does not match update policy")
        if version_key(candidate.minimum_updater_version) > version_key(self.updater_version):
            raise UpdateError("updater_too_old", "release requires a newer updater")
        if current is None:
            return
        if operation == "update":
            if version_key(candidate.version) <= version_key(current.version):
                raise UpdateError("downgrade_refused", "forward update must increase SemVer")
            predecessor = candidate.envelope.document["compatibility"]["predecessor"]
            if (
                predecessor is None
                or predecessor["releaseId"] != current.release_id
                or predecessor["signedPayloadDigest"] != current.signed_digest
            ):
                raise UpdateError(
                    "predecessor_mismatch", "release predecessor does not exactly match current"
                )
            current_shared = canonical_digest(
                current.verified.target.get("sharedWritableVolumes", ())
            )
            candidate_shared = canonical_digest(
                candidate.verified.target.get("sharedWritableVolumes", ())
            )
            if current_shared != candidate_shared:
                raise UpdateError(
                    "shared_volume_migration_required",
                    "release changes shared writable state without an accepted migration contract",
                )
        elif operation == "rollback":
            if version_key(candidate.version) >= version_key(current.version):
                raise UpdateError("rollback_target_invalid", "rollback target is not older")
            if not current.rollback_compatible:
                raise UpdateError("rollback_incompatible", "current release forbids rollback")
        else:
            raise UpdateError("plan_invalid", "update operation is invalid")
        if candidate.schema_version < current.schema_version and operation != "rollback":
            raise UpdateError("schema_downgrade_refused", "schema would move backwards")
        if (
            candidate.database_migration_version < current.database_migration_version
            and operation != "rollback"
        ):
            raise UpdateError(
                "migration_downgrade_refused", "database migration would move backwards"
            )
        if operation == "update" and not candidate.rollback_compatible:
            raise UpdateError("rollback_incompatible", "candidate lacks a safe rollback contract")

    def _preflight(
        self,
        release: ReleaseFacts,
    ) -> dict[str, Any]:
        try:
            evidence = _typed_mapping(
                self.host.preflight(release),
                schema="stateport.update-host-preflight/v1",
                fields={
                    "targetId",
                    "releaseId",
                    "availableBytes",
                    "requiredBytes",
                    "imageDigests",
                    "updaterCompatible",
                    "migrationCompatible",
                    "rollbackCompatible",
                },
                label="preflight evidence",
            )
        except UpdateError:
            raise
        except Exception as exc:
            raise UpdateHostError(
                "host_preflight_failed",
                "host preflight failed",
            ) from exc
        available = evidence.get("availableBytes")
        if (
            isinstance(available, bool)
            or not isinstance(available, int)
            or available < release.expected_pull_bytes
        ):
            raise UpdateError(
                "disk_full",
                "insufficient staging capacity for exact release images",
                details={
                    "requiredBytes": release.expected_pull_bytes,
                    "availableBytes": available,
                },
            )
        if (
            evidence["targetId"] != self.target_id
            or evidence["releaseId"] != release.release_id
            or evidence["requiredBytes"] != release.expected_pull_bytes
            or evidence["imageDigests"] != list(release.target_image_digests)
        ):
            raise UpdateError(
                "host_evidence_invalid",
                "preflight evidence is not bound to the exact target release images",
            )
        compatibility = {
            "updaterCompatible": evidence["updaterCompatible"],
            "migrationCompatible": evidence["migrationCompatible"],
            "rollbackCompatible": evidence["rollbackCompatible"],
        }
        if any(not isinstance(value, bool) for value in compatibility.values()):
            raise UpdateError(
                "host_evidence_invalid",
                "preflight compatibility evidence must be boolean",
            )
        if not all(compatibility.values()):
            raise UpdateError(
                "compatibility_refused",
                "host preflight refused updater, migration, or rollback compatibility",
                details=compatibility,
            )
        return evidence

    def _validate_step_evidence(
        self,
        step: str,
        value: object,
        *,
        plan: Mapping[str, Any],
        current: ReleaseFacts,
        successor: ReleaseFacts,
    ) -> dict[str, Any]:
        plan_digest = str(plan["planDigest"])
        if step == "backup":
            evidence = _typed_mapping(
                value,
                schema="stateport.update-host-backup/v1",
                fields={"planDigest", "receiptId", "backupDigest"},
                label="backup evidence",
            )
            if evidence["planDigest"] != plan_digest:
                raise UpdateError("host_evidence_invalid", "backup evidence names another plan")
            _evidence_id(evidence["receiptId"], "backup receipt")
            _evidence_digest(evidence["backupDigest"], "backup digest")
            return evidence
        if step == "pull":
            evidence = _typed_mapping(
                value,
                schema="stateport.update-host-pull/v1",
                fields={"releaseId", "imageDigests"},
                label="pull evidence",
            )
            if evidence["releaseId"] != successor.release_id or evidence["imageDigests"] != list(
                successor.target_image_digests
            ):
                raise UpdateError(
                    "host_evidence_invalid", "pull evidence is not the target image set"
                )
            return evidence
        if step == "stage":
            evidence = _typed_mapping(
                value,
                schema="stateport.update-host-stage/v1",
                fields={"releaseId", "slot", "bundleDigest"},
                label="stage evidence",
            )
            if (
                evidence["releaseId"] != successor.release_id
                or evidence["slot"] != "successor"
                or evidence["bundleDigest"] != successor.quadlet_bundle_digest
            ):
                raise UpdateError(
                    "host_evidence_invalid", "stage evidence is not the exact successor"
                )
            return evidence
        if step == "dry-run-migrations":
            evidence = _typed_mapping(
                value,
                schema="stateport.update-host-migration-dry-run/v1",
                fields={
                    "planDigest",
                    "status",
                    "schemaMigrationVersion",
                    "databaseMigrationVersion",
                    "dataCompatible",
                },
                label="migration dry-run evidence",
            )
            if (
                evidence["planDigest"] != plan_digest
                or evidence["status"] != "passed"
                or evidence["schemaMigrationVersion"] != successor.schema_version
                or evidence["databaseMigrationVersion"] != successor.database_migration_version
                or evidence["dataCompatible"] is not True
            ):
                raise UpdateError(
                    "migration_incompatible", "migration dry-run did not pass exactly"
                )
            return evidence
        if step in {"start-successor", "health-successor"}:
            schema = {
                "start-successor": "stateport.update-host-start/v1",
                "health-successor": "stateport.update-host-health/v1",
            }[step]
            extra = {"status"} if step == "start-successor" else {"healthy"}
            evidence = _typed_mapping(
                value,
                schema=schema,
                fields={"releaseId", "runtimeDigest", *extra},
                label=f"{step} evidence",
            )
            valid_result = (
                evidence.get("status") == "started"
                if step == "start-successor"
                else evidence.get("healthy") is True
            )
            if (
                evidence["releaseId"] != successor.release_id
                or evidence["runtimeDigest"] != successor.expected_revision_digest()
                or not valid_result
            ):
                raise UpdateError("host_evidence_invalid", f"{step} evidence is not exact")
            return evidence
        journey_schemas = {
            "browser-successor": "stateport.update-host-browser-check/v1",
            "studystate-successor": "stateport.update-host-studystate-check/v1",
            "state-check-successor": "stateport.update-host-state-check/v1",
        }
        if step in journey_schemas:
            evidence = _typed_mapping(
                value,
                schema=journey_schemas[step],
                fields={"releaseId", "status", "resultDigest"},
                label=f"{step} evidence",
            )
            if evidence["releaseId"] != successor.release_id or evidence["status"] != "passed":
                raise UpdateError("host_evidence_invalid", f"{step} did not pass")
            _evidence_digest(evidence["resultDigest"], f"{step} result digest")
            return evidence
        if step == "switch":
            evidence = _typed_mapping(
                value,
                schema="stateport.update-host-switch/v1",
                fields={"releaseId", "signedDigest", "runtimeDigest"},
                label="switch evidence",
            )
            if evidence != {
                "schema": "stateport.update-host-switch/v1",
                "releaseId": successor.release_id,
                "signedDigest": successor.signed_digest,
                "runtimeDigest": successor.expected_revision_digest(),
            }:
                raise UpdateError("host_evidence_invalid", "switch evidence is not exact successor")
            return evidence
        if step in {"health-accepted-route", "state-check-accepted-route"}:
            schema = {
                "health-accepted-route": "stateport.update-host-accepted-health/v1",
                "state-check-accepted-route": "stateport.update-host-accepted-state/v1",
            }[step]
            result_field = "healthy" if step == "health-accepted-route" else "status"
            evidence = _typed_mapping(
                value,
                schema=schema,
                fields={"releaseId", "runtimeDigest", result_field},
                label=f"{step} evidence",
            )
            if (
                evidence["releaseId"] != successor.release_id
                or evidence["runtimeDigest"] != successor.expected_revision_digest()
                or (
                    evidence[result_field] is not True
                    if result_field == "healthy"
                    else evidence[result_field] != "passed"
                )
            ):
                raise UpdateError(
                    "host_evidence_invalid", f"{step} did not bind accepted successor"
                )
            return evidence
        if step == "discard-successor":
            evidence = _typed_mapping(
                value,
                schema="stateport.update-host-discard/v1",
                fields={
                    "releaseId",
                    "status",
                    "retainedArtifactIds",
                    "removedRuntimeReleaseIds",
                    "inventoryDigest",
                },
                label="discard evidence",
            )
            retained = self._inventory_ids(
                evidence["retainedArtifactIds"], "discard retained artifact inventory"
            )
            removed = self._inventory_ids(
                evidence["removedRuntimeReleaseIds"], "discard removed runtime inventory"
            )
            inventory = {
                "retainedArtifactIds": retained,
                "removedRuntimeReleaseIds": removed,
            }
            if (
                evidence["releaseId"] != successor.release_id
                or evidence["status"] != "retained_for_evidence"
                or retained != [successor.release_id]
                or removed != [successor.release_id]
                or evidence["inventoryDigest"] != canonical_digest(inventory)
            ):
                raise UpdateError(
                    "host_evidence_invalid", "discard evidence is not exact successor"
                )
            return evidence
        if step == "automatic-rollback":
            evidence = _typed_mapping(
                value,
                schema="stateport.update-host-rollback/v1",
                fields={"releaseId", "signedDigest", "runtimeDigest", "status"},
                label="rollback evidence",
            )
            if evidence != {
                "schema": "stateport.update-host-rollback/v1",
                "releaseId": current.release_id,
                "signedDigest": current.signed_digest,
                "runtimeDigest": current.expected_revision_digest(),
                "status": "restored",
            }:
                raise UpdateError(
                    "host_evidence_invalid", "rollback evidence is not exact predecessor"
                )
            return evidence
        raise UpdateError("host_evidence_invalid", f"no typed evidence contract exists for {step}")

    @staticmethod
    def _inventory_ids(value: object, label: str) -> list[str]:
        if not isinstance(value, list) or len(value) > 64:
            raise UpdateError("retention_evidence_mismatch", f"{label} is invalid")
        normalized = [_evidence_id(item, label) for item in value]
        if normalized != sorted(set(normalized)):
            raise UpdateError(
                "retention_evidence_mismatch",
                f"{label} must be sorted and unique",
            )
        return normalized

    def _validate_retention_evidence(
        self,
        value: object,
        *,
        policy: UpdatePolicy,
        current_release_id: str | None = None,
        required_predecessor_ids: Sequence[str] = (),
        required_failure_evidence_ids: Sequence[str] = (),
    ) -> dict[str, Any]:
        evidence = _typed_mapping(
            value,
            schema="stateport.update-host-retention/v1",
            fields={
                "currentReleaseId",
                "retainedReleaseIds",
                "removedReleaseIds",
                "retainedFailureArtifactIds",
                "removedFailureArtifactIds",
                "inventoryDigest",
                "maximumVersions",
                "maximumAgeDays",
            },
            label="retention evidence",
        )
        current_id = _evidence_id(evidence["currentReleaseId"], "retention current release")
        retained_releases = self._inventory_ids(
            evidence["retainedReleaseIds"], "retained release inventory"
        )
        removed_releases = self._inventory_ids(
            evidence["removedReleaseIds"], "removed release inventory"
        )
        retained_failures = self._inventory_ids(
            evidence["retainedFailureArtifactIds"], "retained failure inventory"
        )
        removed_failures = self._inventory_ids(
            evidence["removedFailureArtifactIds"], "removed failure inventory"
        )
        inventory = {
            "currentReleaseId": current_id,
            "retainedReleaseIds": retained_releases,
            "removedReleaseIds": removed_releases,
            "retainedFailureArtifactIds": retained_failures,
            "removedFailureArtifactIds": removed_failures,
        }
        if (
            evidence["inventoryDigest"] != canonical_digest(inventory)
            or evidence["maximumVersions"] != policy.maximum_versions
            or evidence["maximumAgeDays"] != policy.maximum_age_days
            or len(retained_releases) > policy.maximum_versions
            or set(retained_releases) & set(removed_releases)
            or set(retained_failures) & set(removed_failures)
        ):
            raise UpdateError(
                "retention_evidence_mismatch",
                "host retention inventory is inconsistent",
            )
        if current_release_id is not None:
            required_releases = {current_release_id, *required_predecessor_ids}
            required_failures = set(required_failure_evidence_ids)
            if (
                current_id != current_release_id
                or not required_releases.issubset(retained_releases)
                or required_releases & set(removed_releases)
                or not required_failures.issubset(retained_failures)
                or required_failures & set(removed_failures)
            ):
                raise UpdateError(
                    "retention_evidence_mismatch",
                    "host retention inventory does not preserve required history",
                )
        return evidence

    def check(self, candidate: UpdaterReleaseEnvelope) -> dict[str, Any]:
        try:
            with self.store.operation_lease():
                with self.store.transaction() as session:
                    if session.load_pending() is not None:
                        raise UpdateError(
                            "interrupted_update_requires_reconciliation",
                            "a pending update must be reconciled",
                        )
                    status = session.load_status()
                    status_digest = canonical_digest(status)
                    policy = UpdatePolicy.from_mapping(status["policy"])
                    current = self._load_facts(
                        session,
                        status["current"]["releaseId"],
                        channel=policy.channel,
                    )
                facts = self._facts(candidate, channel=policy.channel)
                self._check_static_release(
                    facts,
                    policy,
                    current=current,
                    operation="update",
                )
                preflight = self._preflight(facts)
                # Read-only recheck: update check must never mutate durable
                # state, so the candidate release is not persisted here. The
                # plan operation re-verifies and persists it instead.
                with self.store.transaction() as session:
                    if (
                        session.load_pending() is not None
                        or canonical_digest(session.load_status()) != status_digest
                    ):
                        raise UpdateError(
                            "installed_state_changed",
                            "installed state changed during update check",
                        )
                return {
                    "checkedAt": _timestamp(self.clock),
                    "current": current.identity,
                    "successor": facts.identity,
                    "releaseIndexDigest": facts.index_digest,
                    "preflight": preflight,
                    "result": "update_available",
                }
        except StoreError as exc:
            raise UpdateError(exc.code, str(exc)) from exc

    def plan(
        self,
        candidate: UpdaterReleaseEnvelope | None = None,
        *,
        operation: str = "update",
        retain_candidate: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        if operation not in {"update", "rollback"}:
            raise UpdateError("plan_invalid", "update operation is invalid")
        try:
            with self.store.operation_lease():
                with self.store.transaction() as session:
                    if session.load_pending() is not None:
                        raise UpdateError(
                            "interrupted_update_requires_reconciliation",
                            "a pending update must be reconciled",
                        )
                    status = session.load_status()
                    status_digest = canonical_digest(status)
                    policy = UpdatePolicy.from_mapping(status["policy"])
                    current = self._load_facts(
                        session,
                        status["current"]["releaseId"],
                        channel=policy.channel,
                    )
                    if operation == "rollback":
                        retained = status.get("retainedPredecessor")
                        if not isinstance(retained, Mapping):
                            raise UpdateError(
                                "predecessor_unavailable",
                                "no retained predecessor exists",
                            )
                        facts = self._load_facts(
                            session,
                            retained["releaseId"],
                            channel=policy.channel,
                        )
                    else:
                        if candidate is None:
                            raise UpdateError(
                                "candidate_required",
                                "an exact verified candidate is required",
                            )
                        facts = self._facts(candidate, channel=policy.channel)
                self._check_static_release(
                    facts,
                    policy,
                    current=current,
                    operation=operation,
                )
                preflight = self._preflight(facts)
                if operation == "update" and retain_candidate is not None:
                    retain_candidate()
                created = self._now()
                steps = UPDATE_STEPS if operation == "update" else ROLLBACK_STEPS
                body: dict[str, Any] = {
                    "schema": "stateport.update-plan/v1",
                    "operation": operation,
                    "installationId": self.store.installation_id,
                    "current": dict(current.identity),
                    "successor": dict(facts.identity),
                    "releaseIndexDigest": facts.index_digest,
                    "signedPayloadDigest": facts.signed_digest,
                    "policy": policy.to_mapping(),
                    "estimatedPullBytes": facts.expected_pull_bytes,
                    "compatibility": {
                        "updaterCompatible": preflight["updaterCompatible"],
                        "migrationCompatible": preflight["migrationCompatible"],
                        "rollbackCompatible": preflight["rollbackCompatible"],
                        "downgrade": operation == "rollback",
                    },
                    "backupRequired": True,
                    "steps": list(steps),
                    "rollback": {
                        "automaticOnFailure": operation == "update",
                        "retainedPredecessor": True,
                        "dataCompatible": bool(
                            facts.envelope.document["compatibility"]["rollback"]["dataCompatible"]
                        ),
                    },
                    "authority": {
                        "action": ("apply_update" if operation == "update" else "rollback_update"),
                        "runId": "",
                        "status": "awaiting_authority_claim",
                    },
                    "createdAt": created.isoformat().replace("+00:00", "Z"),
                    "expiresAt": (created + PLAN_TTL).isoformat().replace("+00:00", "Z"),
                }
                # update_plan_digest excludes these digest-derived fields.
                from stateport_release import update_plan_digest

                digest = update_plan_digest(body)
                plan = {
                    **body,
                    "planId": f"update_plan_{digest.removeprefix('sha256:')[:32]}",
                    "planDigest": digest,
                    "authority": {**body["authority"], "runId": digest},
                }
                try:
                    plan = validate_update_plan(plan, now=self.clock()).as_dict()
                except ReleaseContractError as exc:
                    raise UpdateError("plan_invalid", str(exc)) from exc
                with self.store.transaction() as session:
                    if (
                        session.load_pending() is not None
                        or canonical_digest(session.load_status()) != status_digest
                    ):
                        raise UpdateError(
                            "installed_state_changed",
                            "installed state changed during update planning",
                        )
                    session.save_release(facts.envelope)
                    session.save_plan(plan)
                    status["phase"] = "planned"
                    status["stagedSuccessor"] = facts.status_identity()
                    session.save_status(status, timestamp=_timestamp(self.clock))
                return deepcopy(plan)
        except StoreError as exc:
            raise UpdateError(exc.code, str(exc)) from exc

    def _validated_plan(
        self,
        session: UpdateSession,
        plan_id: str,
        *,
        require_active: bool = True,
    ) -> dict[str, Any]:
        try:
            value = session.load_plan(plan_id)
            if require_active:
                return validate_update_plan(value, now=self.clock()).as_dict()
            return validate_contract_document(
                value,
                expected_schema="stateport.update-plan/v1",
            ).as_dict()
        except (ReleaseContractError, StoreError) as exc:
            code = exc.code if hasattr(exc, "code") else "plan_invalid"
            raise UpdateError(code, str(exc)) from exc

    def _plan_releases(
        self,
        session: UpdateSession,
        plan: Mapping[str, Any],
        *,
        successor_verified_at: datetime | None = None,
        require_successor_plan_admission: bool = False,
    ) -> tuple[ReleaseFacts, ReleaseFacts, UpdatePolicy]:
        policy = UpdatePolicy.from_mapping(plan["policy"])
        current = self._load_facts(session, plan["current"]["releaseId"], channel=policy.channel)
        if successor_verified_at is None:
            successor = self._load_facts(
                session,
                plan["successor"]["releaseId"],
                channel=policy.channel,
                required_plan_digest=(
                    str(plan["planDigest"]) if require_successor_plan_admission else None
                ),
            )
        else:
            try:
                index = load_release_index(
                    session.load_release_index_bytes(plan["successor"]["releaseId"])
                )
                predecessor_index = load_release_index(
                    session.load_release_index_bytes(plan["current"]["releaseId"]),
                    legacy_predecessor=True,
                )
                verified = verify_release_index(
                    index,
                    policy=self._policy_now(
                        channel=policy.channel,
                        at=successor_verified_at,
                    ),
                    verifier=self.signature_verifier,
                    predecessor=predecessor_index,
                )
                successor = ReleaseFacts.from_reverified(
                    to_updater_release_envelope(verified),
                    verified,
                )
            except ReleaseContractError as exc:
                raise UpdateError("release_verification_failed", str(exc)) from exc
        if (
            dict(current.identity) != plan["current"]
            or dict(successor.identity) != plan["successor"]
        ):
            raise UpdateError("release_identity_changed", "plan release identity changed")
        if successor.index_digest != plan["releaseIndexDigest"]:
            raise UpdateError("release_identity_changed", "plan release index changed")
        self._check_static_release(
            successor,
            policy,
            current=current,
            operation=str(plan["operation"]),
        )
        return current, successor, policy

    def _new_journal(
        self,
        plan: Mapping[str, Any],
        binding: Mapping[str, Any],
    ) -> dict[str, Any]:
        now = _timestamp(self.clock)
        journal: dict[str, Any] = {
            "schema": JOURNAL_SCHEMA,
            "transactionId": f"update_txn_{plan['planDigest'].removeprefix('sha256:')[:32]}",
            "planId": plan["planId"],
            "planDigest": plan["planDigest"],
            "authority": {
                "decision": deepcopy(binding["decision"]),
                "reservation": deepcopy(binding["reservation"]),
                "claim": None,
            },
            "currentReleaseId": plan["current"]["releaseId"],
            "successorReleaseId": plan["successor"]["releaseId"],
            "phase": "reserved",
            "effectDisposition": "not_applied",
            "intent": None,
            "steps": [],
            "preparedReceipt": None,
            "preparedFailureEvidence": None,
            "canonicalAuthorityReceipt": None,
            "startedAt": now,
            "updatedAt": now,
            "journalDigest": "",
        }
        journal["journalDigest"] = journal_digest(journal)
        return journal

    def _save_journal(self, session: UpdateSession, journal: dict[str, Any]) -> None:
        expected_digest = str(journal["journalDigest"])
        journal["updatedAt"] = _timestamp(self.clock)
        journal["journalDigest"] = journal_digest(journal)
        session.save_journal(journal, expected_digest=expected_digest)

    @staticmethod
    def _adopt_journal(target: dict[str, Any], source: Mapping[str, Any]) -> None:
        target.clear()
        target.update(deepcopy(dict(source)))

    def _with_current_journal(
        self,
        session: UpdateSession,
        journal: dict[str, Any],
    ) -> None:
        current = session.load_pending()
        if current is None or current.get("transactionId") != journal.get("transactionId"):
            raise UpdateError("journal_conflict", "pending updater transaction changed identity")
        if current.get("journalDigest") != journal.get("journalDigest"):
            raise UpdateError("journal_conflict", "pending updater transaction changed generation")
        self._adopt_journal(journal, current)

    def _set_journal_state(
        self,
        journal: dict[str, Any],
        *,
        phase: str | None = None,
        disposition: str | None = None,
    ) -> None:
        with self.store.transaction() as session:
            self._with_current_journal(session, journal)
            if phase is not None:
                journal["phase"] = phase
            if disposition is not None:
                journal["effectDisposition"] = disposition
            self._save_journal(session, journal)

    def _append_step(
        self,
        journal: dict[str, Any],
        step: str,
        evidence: Mapping[str, Any],
        *,
        disposition: str | None = None,
    ) -> None:
        with self.store.transaction() as session:
            self._with_current_journal(session, journal)
            journal["steps"] = [
                *journal["steps"],
                {
                    "step": step,
                    "at": _timestamp(self.clock),
                    "evidence": deepcopy(dict(evidence)),
                },
            ]
            journal["phase"] = step
            journal["intent"] = None
            if disposition is not None:
                journal["effectDisposition"] = disposition
            self._save_journal(session, journal)

    def _step(
        self,
        journal: dict[str, Any],
        current: ReleaseFacts,
        successor: ReleaseFacts,
        plan: Mapping[str, Any],
        step: str,
        operation: Callable[[ReleaseFacts], Mapping[str, Any]],
        *,
        effect: str,
    ) -> dict[str, Any]:
        with self.store.transaction() as session:
            self._with_current_journal(session, journal)
            journal["phase"] = f"intent_{step}"
            journal["intent"] = {
                "step": step,
                "effect": effect,
                "recordedAt": _timestamp(self.clock),
            }
            self._save_journal(session, journal)
        self._trip(f"before_effect_{step}")
        # The immutable facts were freshly admitted before claim, or restored
        # from an exact plan-bound admission during reconciliation.  Freshness
        # is never reinterpreted after an effect starts.
        rebound = successor
        try:
            evidence = self._validate_step_evidence(
                step,
                operation(rebound),
                plan=plan,
                current=current,
                successor=rebound,
            )
        except UpdateHostError:
            raise
        except UpdateError:
            raise
        except Exception as exc:
            raise UpdateHostError(
                f"{step.replace('-', '_')}_failed",
                f"host operation failed: {step}",
                effect=effect,
            ) from exc
        record = self._effect_record(
            plan=plan,
            step=step,
            evidence=evidence,
        )
        self._trip(f"after_effect_before_journal_{step}")
        disposition = "applied" if effect == "applied" else journal["effectDisposition"]
        self._append_step(
            journal,
            step,
            record,
            disposition=disposition,
        )
        self._trip(f"after_journal_{step}")
        return evidence

    def _completed_steps(self, journal: Mapping[str, Any]) -> set[str]:
        return {str(item["step"]) for item in journal["steps"]}

    def _validated_effect_receipt(
        self,
        value: object,
        *,
        plan: Mapping[str, Any],
        step: str,
        evidence: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        receipt = _typed_mapping(
            value,
            schema="stateport.update-host-effect-receipt/v1",
            fields={
                "receiptId",
                "planDigest",
                "step",
                "status",
                "evidence",
                "evidenceDigest",
            },
            label="execution-host effect receipt",
        )
        _evidence_id(receipt["receiptId"], "execution-host effect receipt id")
        if (
            receipt["planDigest"] != plan["planDigest"]
            or receipt["step"] != step
            or receipt["status"] != "observed"
        ):
            raise UpdateError(
                "host_effect_receipt_invalid",
                "execution-host effect receipt does not bind the exact plan step",
            )
        persisted_evidence = _safe_evidence(
            receipt["evidence"],
            "execution-host effect receipt evidence",
        )
        if not isinstance(persisted_evidence, dict):
            raise UpdateError(
                "host_effect_receipt_invalid",
                "execution-host effect receipt evidence is invalid",
            )
        expected_digest = canonical_digest(persisted_evidence)
        seed = canonical_digest(
            {
                "planDigest": receipt["planDigest"],
                "step": receipt["step"],
                "evidenceDigest": expected_digest,
            }
        )
        if (
            receipt["evidenceDigest"] != expected_digest
            or receipt["receiptId"] != f"host_effect_receipt_{seed.removeprefix('sha256:')[:32]}"
            or (evidence is not None and persisted_evidence != dict(evidence))
        ):
            raise UpdateError(
                "host_effect_receipt_invalid",
                "execution-host effect receipt does not bind its exact evidence",
            )
        return receipt

    def _effect_record(
        self,
        *,
        plan: Mapping[str, Any],
        step: str,
        evidence: Mapping[str, Any],
    ) -> dict[str, Any]:
        try:
            receipt = self._validated_effect_receipt(
                self.host.observe_effect_receipt(
                    plan_digest=str(plan["planDigest"]),
                    step=step,
                ),
                plan=plan,
                step=step,
                evidence=evidence,
            )
        except UpdateError:
            raise
        except Exception as exc:
            raise UpdateError(
                "host_effect_receipt_missing",
                "execution host did not persist exact effect evidence",
            ) from exc
        return {
            "schema": "stateport.internal-update-step-record/v1",
            "evidence": deepcopy(dict(evidence)),
            "hostReceipt": receipt,
        }

    def _validated_effect_record(
        self,
        value: object,
        *,
        plan: Mapping[str, Any],
        step: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        record = _typed_mapping(
            value,
            schema="stateport.internal-update-step-record/v1",
            fields={"evidence", "hostReceipt"},
            label="persisted execution-host step record",
        )
        evidence = _safe_evidence(record["evidence"], "persisted execution-host evidence")
        if not isinstance(evidence, dict):
            raise UpdateError(
                "journal_semantic_invalid",
                "persisted execution-host evidence is invalid",
            )
        receipt = self._validated_effect_receipt(
            record["hostReceipt"],
            plan=plan,
            step=step,
            evidence=evidence,
        )
        return evidence, receipt

    def _validated_observation_evidence(
        self,
        evidence: object,
        current: ReleaseFacts,
        successor: ReleaseFacts,
    ) -> str:
        safe = _safe_evidence(evidence, "persisted accepted revision observation")
        if isinstance(safe, dict) and set(safe) == {"status", "code"}:
            if safe["status"] != "unavailable":
                raise UpdateError(
                    "journal_semantic_invalid",
                    "persisted unavailable observation has an invalid status",
                )
            _evidence_id(safe["code"], "persisted observation code")
            return "ambiguous"
        observed = _typed_mapping(
            safe,
            schema="stateport.update-host-observation/v1",
            fields={"releaseId", "signedDigest", "runtimeDigest"},
            label="persisted accepted revision observation",
        )
        for label, release in (("current", current), ("successor", successor)):
            if observed == {
                "schema": "stateport.update-host-observation/v1",
                "releaseId": release.release_id,
                "signedDigest": release.signed_digest,
                "runtimeDigest": release.expected_revision_digest(),
            }:
                return label
        _evidence_id(observed["releaseId"], "persisted observed release id")
        _evidence_digest(observed["signedDigest"], "persisted observed signed digest")
        _evidence_digest(observed["runtimeDigest"], "persisted observed runtime digest")
        return "ambiguous"

    def _validate_journal_semantics(
        self,
        session: UpdateSession,
        plan: Mapping[str, Any],
        journal: Mapping[str, Any],
        current: ReleaseFacts,
        successor: ReleaseFacts,
        policy: UpdatePolicy,
    ) -> None:
        """Cross-bind mutable WAL state before any recovery decision.

        The WAL digest detects accidental byte changes; this validator proves
        that every persisted field still describes one possible execution of
        the exact plan.  A caller may recompute a self-digest, but cannot turn
        out-of-order or mismatched records into completed update gates.
        """

        suffix = str(plan["planDigest"]).removeprefix("sha256:")[:32]
        if (
            journal["transactionId"] != f"update_txn_{suffix}"
            or journal["planId"] != plan["planId"]
            or journal["planDigest"] != plan["planDigest"]
            or journal["currentReleaseId"] != current.release_id
            or journal["successorReleaseId"] != successor.release_id
            or dict(current.identity) != plan["current"]
            or dict(successor.identity) != plan["successor"]
        ):
            raise UpdateError(
                "journal_semantic_invalid",
                "pending journal does not bind the exact plan and releases",
            )

        authority = journal["authority"]
        try:
            rebound = self.authority.validate_reservation(
                plan,
                {
                    "decision": authority["decision"],
                    "reservation": authority["reservation"],
                },
            )
        except Exception as exc:
            raise UpdateError(
                "journal_authority_invalid",
                "pending journal authority reservation is not canonical",
            ) from exc
        if (
            rebound.get("decision") != authority["decision"]
            or rebound.get("reservation") != authority["reservation"]
        ):
            raise UpdateError(
                "journal_authority_invalid",
                "pending journal authority reservation changed",
            )

        operational = [
            str(step)
            for step in plan["steps"]
            if step not in {"retain-predecessor", "record-receipt"}
        ]
        next_operational = 0
        retain_seen = False
        observation_states: list[str] = []
        automatic_rollback_seen = False
        discard_seen = False
        completed: dict[str, Mapping[str, Any]] = {}
        if (
            sum(1 for item in journal["steps"] if item["step"] == "accepted-route-observation")
            > MAX_RECONCILIATION_OBSERVATIONS
        ):
            raise UpdateError(
                "journal_semantic_invalid",
                "pending journal exceeds its bounded observation history",
            )
        for item in journal["steps"]:
            step = str(item["step"])
            evidence = item["evidence"]
            if retain_seen:
                raise UpdateError(
                    "journal_semantic_invalid",
                    "persisted work appears after terminal retention evidence",
                )
            if step in operational:
                if next_operational >= len(operational) or operational[next_operational] != step:
                    raise UpdateError(
                        "journal_semantic_invalid",
                        "persisted update gates are missing or out of order",
                    )
                next_operational += 1
                if step == "verify":
                    if evidence != {
                        "releaseIndexDigest": successor.index_digest,
                        "signedPayloadDigest": successor.signed_digest,
                    }:
                        raise UpdateError(
                            "journal_semantic_invalid",
                            "persisted verification evidence does not bind the successor",
                        )
                    completed[step] = evidence
                else:
                    step_evidence, _host_receipt = self._validated_effect_record(
                        evidence,
                        plan=plan,
                        step=step,
                    )
                    self._validate_step_evidence(
                        step,
                        step_evidence,
                        plan=plan,
                        current=current,
                        successor=successor,
                    )
                    completed[step] = step_evidence
                continue
            if step == "accepted-route-observation":
                observation_states.append(
                    self._validated_observation_evidence(evidence, current, successor)
                )
                continue
            if step == "automatic-rollback":
                if not observation_states or observation_states[-1] != "successor":
                    raise UpdateError(
                        "journal_semantic_invalid",
                        "persisted rollback lacks exact successor observation",
                    )
                step_evidence, _host_receipt = self._validated_effect_record(
                    evidence,
                    plan=plan,
                    step=step,
                )
                self._validate_step_evidence(
                    step,
                    step_evidence,
                    plan=plan,
                    current=current,
                    successor=successor,
                )
                automatic_rollback_seen = True
                completed[step] = step_evidence
                continue
            if step == "discard-successor":
                if not observation_states or observation_states[-1] != "current":
                    raise UpdateError(
                        "journal_semantic_invalid",
                        "persisted cleanup lacks exact predecessor observation",
                    )
                step_evidence, _host_receipt = self._validated_effect_record(
                    evidence,
                    plan=plan,
                    step=step,
                )
                self._validate_step_evidence(
                    step,
                    step_evidence,
                    plan=plan,
                    current=current,
                    successor=successor,
                )
                discard_seen = True
                completed[step] = step_evidence
                continue
            if step == "retain-predecessor":
                step_evidence, _host_receipt = self._validated_effect_record(
                    evidence,
                    plan=plan,
                    step=step,
                )
                retained = self._validate_retention_evidence(
                    step_evidence,
                    policy=policy,
                )
                retain_seen = True
                completed[step] = retained
                continue
            raise UpdateError(
                "journal_semantic_invalid",
                f"unsupported persisted update step: {step}",
            )

        failure = journal.get("preparedFailureEvidence")
        if isinstance(failure, Mapping):
            if (
                failure["planId"] != plan["planId"]
                or failure["planDigest"] != plan["planDigest"]
                or failure["successor"] != successor.status_identity()
                or failure["failedStep"] not in plan["steps"]
                or failure["safeSummary"]
                != f"Update failed safely at {failure['failedStep']} ({failure['errorCode']})."
                or failure["artifacts"] != []
                or failure["retained"] is not True
            ):
                raise UpdateError(
                    "journal_semantic_invalid",
                    "prepared failure evidence does not describe this exact plan failure",
                )

        receipt = journal.get("preparedReceipt")
        result = None if not isinstance(receipt, Mapping) else str(receipt["result"])
        if result is not None:
            if not retain_seen:
                raise UpdateError(
                    "journal_semantic_invalid",
                    "prepared terminal outcome lacks exact retention evidence",
                )
            expected_accepted = successor.identity if result == "accepted" else current.identity
            expected_authority = authority_reference(
                authority,
                plan_digest=str(plan["planDigest"]),
            )
            checks = {
                step: ("passed" if step in completed else "not_run")
                for step in plan["steps"]
                if step != "record-receipt"
            }
            retention_digest = canonical_digest(completed["retain-predecessor"])
            checks[f"retention-evidence-{retention_digest.removeprefix('sha256:')}"] = "passed"
            if isinstance(failure, Mapping):
                checks[str(failure["failedStep"])] = "failed"
            backup = completed.get("backup", {})
            backup_receipt = (
                str(backup["receiptId"])
                if isinstance(backup, Mapping) and isinstance(backup.get("receiptId"), str)
                else "backup_not_created"
            )
            expected_rollback = {
                "attempted": result == "rolled_back",
                "succeeded": result == "rolled_back",
                "retainedFailureEvidence": failure is not None,
            }
            receipt_seed = canonical_digest(
                {
                    "planDigest": plan["planDigest"],
                    "result": result,
                    "accepted": expected_accepted["signedPayloadDigest"],
                }
            )
            if (
                receipt["receiptId"]
                != f"update_receipt_{receipt_seed.removeprefix('sha256:')[:32]}"
                or receipt["planId"] != plan["planId"]
                or receipt["planDigest"] != plan["planDigest"]
                or receipt["operation"] != plan["operation"]
                or receipt["from"] != current.identity
                or receipt["attempted"] != successor.identity
                or receipt["accepted"] != expected_accepted
                or receipt["releaseIndexDigest"] != successor.index_digest
                or receipt["backupReceipt"] != backup_receipt
                or receipt["checks"] != checks
                or receipt["rollback"] != expected_rollback
                or receipt["authority"] != expected_authority
                or receipt["startedAt"] != journal["startedAt"]
                or ((result == "accepted") != (failure is None))
                or (result == "accepted" and next_operational != len(operational))
                or (result == "rolled_back" and not automatic_rollback_seen)
                or (result == "failed_safe" and self._staged_or_later(journal) and not discard_seen)
                or not observation_states
                or observation_states[-1] != ("successor" if result == "accepted" else "current")
            ):
                raise UpdateError(
                    "journal_semantic_invalid",
                    "prepared update receipt does not derive from exact ordered evidence",
                )

            retained = completed["retain-predecessor"]
            failure_id = None if failure is None else str(failure["failureId"])
            predecessors, failures = self._retention_requirements(
                session,
                current,
                result=result,
                failure_id=failure_id,
                policy=policy,
            )
            expected_runtime = successor.release_id if result == "accepted" else current.release_id
            try:
                self._validate_retention_evidence(
                    retained,
                    policy=policy,
                    current_release_id=expected_runtime,
                    required_predecessor_ids=predecessors,
                    required_failure_evidence_ids=failures,
                )
            except UpdateError as exc:
                raise UpdateError(
                    "journal_semantic_invalid",
                    "persisted retention evidence does not match retained canonical records",
                ) from exc

        terminal_phases = {
            "receipt_saved",
            "state_committed",
            "authority_finalization_pending",
            "authority_finalized",
            "link_saved",
            "completed",
        }
        if journal["phase"] in terminal_phases and result is None:
            raise UpdateError(
                "journal_semantic_invalid",
                "terminal journal phase has no prepared update receipt",
            )
        if (
            journal["phase"]
            in {
                "authority_finalized",
                "link_saved",
                "completed",
            }
            and journal.get("canonicalAuthorityReceipt") is None
        ):
            raise UpdateError(
                "journal_semantic_invalid",
                "finalized journal phase has no canonical authority receipt",
            )
        if result is not None and journal["phase"] in {
            "receipt_saved",
            "state_committed",
            "authority_finalization_pending",
            "authority_finalized",
            "link_saved",
            "completed",
        }:
            try:
                persisted_receipt = session.load_receipt(str(receipt["receiptId"]))
            except StoreError as exc:
                raise UpdateError(
                    "journal_semantic_invalid",
                    "journal phase claims a receipt that is not durably stored",
                ) from exc
            if persisted_receipt != receipt:
                raise UpdateError(
                    "journal_semantic_invalid",
                    "durable update receipt differs from the journal outcome",
                )
        if result is not None and journal["phase"] in {
            "state_committed",
            "authority_finalization_pending",
            "authority_finalized",
            "link_saved",
            "completed",
        }:
            status = session.load_status()
            accepted_status = (
                successor.status_identity() if result == "accepted" else current.status_identity()
            )
            if (
                status["lastReceipt"] != receipt["receiptId"]
                or status["current"] != accepted_status
                or status["accepted"] != accepted_status
                or status["stagedSuccessor"] is not None
            ):
                raise UpdateError(
                    "journal_semantic_invalid",
                    "committed updater state does not match the prepared outcome",
                )
        if journal["phase"] in {"link_saved", "completed"}:
            canonical = journal["canonicalAuthorityReceipt"]
            links = session.list_authority_links()
            if not any(
                link["planDigest"] == plan["planDigest"]
                and link["updateReceiptId"] == receipt["receiptId"]
                and link["authority"]["receiptId"] == canonical["receiptId"]
                and link["authority"]["receiptDigest"] == canonical["receiptDigest"]
                for link in links
            ):
                raise UpdateError(
                    "journal_semantic_invalid",
                    "journal link phase lacks the exact durable authority link",
                )

    def _revalidate_persisted_effect_receipts(
        self,
        plan: Mapping[str, Any],
        journal: Mapping[str, Any],
    ) -> None:
        """Reread every persisted effect receipt from the execution host."""

        for item in journal["steps"]:
            step = str(item["step"])
            if step in {"verify", "accepted-route-observation"}:
                continue
            persisted_evidence, persisted_receipt = self._validated_effect_record(
                item["evidence"],
                plan=plan,
                step=step,
            )
            try:
                observed_receipt = self._validated_effect_receipt(
                    self.host.observe_effect_receipt(
                        plan_digest=str(plan["planDigest"]),
                        step=step,
                    ),
                    plan=plan,
                    step=step,
                    evidence=persisted_evidence,
                )
            except Exception as exc:
                raise UpdateError(
                    "journal_effect_revalidation_failed",
                    f"persisted host effect could not be independently revalidated: {step}",
                ) from exc
            if observed_receipt != persisted_receipt:
                raise UpdateError(
                    "journal_effect_revalidation_failed",
                    f"persisted host effect receipt changed during recovery: {step}",
                )

    def _revalidate_persisted_live_gates(
        self,
        plan: Mapping[str, Any],
        journal: Mapping[str, Any],
        current: ReleaseFacts,
        successor: ReleaseFacts,
    ) -> None:
        """Rerun completed read-only gates while their staged target is live."""

        operations: dict[str, Callable[[ReleaseFacts], Mapping[str, Any]]] = {
            "dry-run-migrations": lambda _release: self.host.dry_run_migrations(plan),
            "health-successor": lambda _release: self.host.health_successor(plan),
            "browser-successor": lambda _release: self.host.browser_successor(plan),
            "studystate-successor": lambda _release: self.host.studystate_successor(plan),
            "state-check-successor": lambda _release: self.host.state_check_successor(plan),
            "health-accepted-route": lambda _release: self.host.health_accepted_route(plan),
            "state-check-accepted-route": lambda _release: self.host.state_check_accepted_route(
                plan
            ),
        }
        for item in journal["steps"]:
            step = str(item["step"])
            operation = operations.get(step)
            if operation is None:
                continue
            persisted_evidence, _persisted_receipt = self._validated_effect_record(
                item["evidence"],
                plan=plan,
                step=step,
            )
            try:
                observed = self._validate_step_evidence(
                    step,
                    operation(successor),
                    plan=plan,
                    current=current,
                    successor=successor,
                )
            except Exception as exc:
                raise UpdateError(
                    "journal_gate_revalidation_failed",
                    f"persisted gate could not be independently revalidated: {step}",
                ) from exc
            if observed != persisted_evidence:
                raise UpdateError(
                    "journal_gate_revalidation_failed",
                    f"persisted gate evidence changed during recovery: {step}",
                )

    def _recover_unjournaled_terminal_effect(
        self,
        plan: Mapping[str, Any],
        journal: dict[str, Any],
        current: ReleaseFacts,
        successor: ReleaseFacts,
        step: str,
    ) -> bool:
        """Recover a cleanup/rollback receipt written before a WAL crash.

        These operations are never replayed merely because their WAL append
        was interrupted. The execution host must independently retain the
        exact receipt; otherwise only the matching explicit retry resolution
        may invoke the idempotent operation again.
        """

        try:
            raw_receipt = self.host.observe_effect_receipt(
                plan_digest=str(plan["planDigest"]),
                step=step,
            )
        except UpdateHostError as exc:
            if exc.code == "effect_receipt_missing":
                return False
            raise UpdateError(
                "journal_effect_revalidation_failed",
                f"interrupted host effect receipt could not be read: {step}",
            ) from exc
        except Exception as exc:
            raise UpdateError(
                "journal_effect_revalidation_failed",
                f"interrupted host effect receipt could not be read: {step}",
            ) from exc
        receipt = self._validated_effect_receipt(
            raw_receipt,
            plan=plan,
            step=step,
        )
        evidence = self._validate_step_evidence(
            step,
            receipt["evidence"],
            plan=plan,
            current=current,
            successor=successor,
        )
        record = {
            "schema": "stateport.internal-update-step-record/v1",
            "evidence": evidence,
            "hostReceipt": receipt,
        }
        self._append_step(
            journal,
            step,
            record,
            disposition=("applied" if step == "automatic-rollback" else "partial"),
        )
        return True

    def apply(
        self,
        plan_id: str,
        authorization: Mapping[str, Any],
    ) -> dict[str, Any]:
        try:
            lease = self.store.operation_lease()
            with lease:
                candidate_verified_at = self._now()
                with self.store.transaction() as session:
                    if session.load_pending() is not None:
                        raise UpdateError(
                            "interrupted_update_requires_reconciliation",
                            "a pending update must be reconciled before apply",
                        )
                    plan = self._validated_plan(session, plan_id)
                    current, successor, policy = self._plan_releases(
                        session,
                        plan,
                        successor_verified_at=(
                            candidate_verified_at if plan["operation"] == "update" else None
                        ),
                    )
                    status = session.load_status()
                    if status["current"] != current.status_identity():
                        raise UpdateError(
                            "installed_identity_changed",
                            "installed release changed after plan",
                        )
                    if status["policy"] != plan["policy"]:
                        raise UpdateError(
                            "update_policy_changed",
                            "update policy changed after the exact plan was created",
                        )

                # Effect-free compatibility is repeated immediately before
                # authority claim without holding the state lock.
                preflight = self._preflight(successor)
                for field in (
                    "updaterCompatible",
                    "migrationCompatible",
                    "rollbackCompatible",
                ):
                    if preflight[field] != plan["compatibility"][field]:
                        raise UpdateError(
                            "compatibility_changed",
                            "host compatibility changed after plan creation",
                        )
                try:
                    binding = self.authority.validate_reservation(plan, authorization)
                except UpdateAuthorityError as exc:
                    raise UpdateError(exc.code, str(exc), receipt=exc.receipt) from exc
                claim_verified_at = self._now()
                journal = self._new_journal(plan, binding)
                with self.store.transaction() as session:
                    final_plan = self._validated_plan(session, plan_id)
                    if final_plan != plan:
                        raise UpdateError(
                            "plan_changed",
                            "update plan changed before authority claim",
                        )
                    current, successor, policy = self._plan_releases(
                        session,
                        final_plan,
                        successor_verified_at=(
                            claim_verified_at if plan["operation"] == "update" else None
                        ),
                    )
                    latest = session.load_status()
                    if (
                        session.load_pending() is not None
                        or latest["current"] != current.status_identity()
                        or latest["policy"] != plan["policy"]
                    ):
                        raise UpdateError(
                            "installed_state_changed",
                            "installed identity or update policy changed before claim",
                        )
                    if plan["operation"] == "update":
                        session.save_admission(
                            self._admission_record(
                                successor,
                                kind="update-apply",
                                verified_at=claim_verified_at,
                                subject={
                                    "type": "update-plan",
                                    "digest": str(plan["planDigest"]),
                                },
                                plan_digest=str(plan["planDigest"]),
                                authority_binding=binding,
                            )
                        )
                    session.begin_journal(journal)
                self._trip("before_authority_claim")
                try:
                    # The plan and candidate may expire during a slow host
                    # preflight.  Recheck both after the last failpoint and
                    # immediately before acquiring effect authority.
                    validate_update_plan(plan, now=self.clock())
                    if plan["operation"] == "update":
                        rebound = self._facts(
                            successor.envelope,
                            channel=policy.channel,
                            verified_at=self._now(),
                        )
                        if (
                            dict(rebound.identity) != plan["successor"]
                            or rebound.index_digest != plan["releaseIndexDigest"]
                        ):
                            raise UpdateError(
                                "release_identity_changed",
                                "successor changed immediately before authority claim",
                            )
                    claim = self.authority.claim(binding)
                except ReleaseContractError as exc:
                    with self.store.transaction() as session:
                        self._with_current_journal(session, journal)
                        journal["phase"] = "claim_not_acquired"
                        journal["intent"] = None
                        self._save_journal(session, journal)
                        session.archive_journal(
                            journal,
                            expected_digest=journal["journalDigest"],
                        )
                    raise UpdateError("plan_invalid", str(exc)) from exc
                except UpdateError:
                    with self.store.transaction() as session:
                        self._with_current_journal(session, journal)
                        journal["phase"] = "claim_not_acquired"
                        journal["intent"] = None
                        self._save_journal(session, journal)
                        session.archive_journal(
                            journal,
                            expected_digest=journal["journalDigest"],
                        )
                    raise
                except UpdateAuthorityError as exc:
                    with self.store.transaction() as session:
                        self._with_current_journal(session, journal)
                        journal["phase"] = "claim_not_acquired"
                        journal["intent"] = None
                        self._save_journal(session, journal)
                        session.archive_journal(
                            journal,
                            expected_digest=journal["journalDigest"],
                        )
                    raise UpdateError(exc.code, str(exc), receipt=exc.receipt) from exc
                self._trip("after_authority_claim_before_journal")
                with self.store.transaction() as session:
                    self._with_current_journal(session, journal)
                    journal["authority"]["claim"] = deepcopy(claim)
                    journal["phase"] = "claimed"
                    self._save_journal(session, journal)
                    status = session.load_status()
                    status["phase"] = "approved"
                    status["stagedSuccessor"] = successor.status_identity()
                    session.save_status(status, timestamp=_timestamp(self.clock))
                return self._execute_remaining(
                    plan,
                    journal,
                    current,
                    successor,
                    policy,
                )
        except StoreError as exc:
            raise UpdateError(exc.code, str(exc)) from exc

    def _execute_remaining(
        self,
        plan: Mapping[str, Any],
        journal: dict[str, Any],
        current: ReleaseFacts,
        successor: ReleaseFacts,
        policy: UpdatePolicy,
    ) -> dict[str, Any]:
        completed = self._completed_steps(journal)
        if "verify" not in completed:
            self._append_step(
                journal,
                "verify",
                {
                    "releaseIndexDigest": successor.index_digest,
                    "signedPayloadDigest": successor.signed_digest,
                },
            )

        operations: list[tuple[str, Callable[[ReleaseFacts], Mapping[str, Any]], str]] = [
            ("backup", lambda _release: self.host.backup(plan), "not_applied"),
        ]
        if plan["operation"] == "update":
            operations.append(
                ("pull", lambda release: self.host.pull_images(plan, release), "partial")
            )
        operations.append(("stage", lambda release: self.host.stage(plan, release), "partial"))
        if plan["operation"] == "update":
            operations.append(
                (
                    "dry-run-migrations",
                    lambda _release: self.host.dry_run_migrations(plan),
                    "partial",
                )
            )
        operations.extend(
            [
                ("start-successor", lambda _release: self.host.start_successor(plan), "partial"),
                ("health-successor", lambda _release: self.host.health_successor(plan), "partial"),
                (
                    "browser-successor",
                    lambda _release: self.host.browser_successor(plan),
                    "partial",
                ),
                (
                    "studystate-successor",
                    lambda _release: self.host.studystate_successor(plan),
                    "partial",
                ),
                (
                    "state-check-successor",
                    lambda _release: self.host.state_check_successor(plan),
                    "partial",
                ),
                ("switch", lambda _release: self.host.switch(plan), "applied"),
                (
                    "health-accepted-route",
                    lambda _release: self.host.health_accepted_route(plan),
                    "applied",
                ),
                (
                    "state-check-accepted-route",
                    lambda _release: self.host.state_check_accepted_route(plan),
                    "applied",
                ),
            ]
        )
        try:
            for step, operation, effect in operations:
                if step in completed:
                    continue
                self._step(
                    journal,
                    current,
                    successor,
                    plan,
                    step,
                    operation,
                    effect=effect,
                )
                completed.add(step)
        except UpdateError as error:
            intent = journal.get("intent")
            if isinstance(intent, Mapping) and isinstance(intent.get("step"), str):
                error.details.setdefault("failedStep", intent["step"])
            if isinstance(error, UpdateHostError):
                self._set_journal_state(journal, disposition=error.effect)
            return self._handle_failure(
                plan,
                journal,
                current,
                successor,
                policy,
                error,
            )

        observed, observation = self._observe_accepted(current, successor)
        self._record_observation(journal, observation)
        if observed != "successor":
            return self._handle_failure(
                plan,
                journal,
                current,
                successor,
                policy,
                UpdateHostError(
                    "accepted_runtime_identity_mismatch",
                    "accepted route does not expose the exact signed successor runtime",
                    effect="unknown" if observed == "ambiguous" else "not_applied",
                ),
            )

        return self._prepare_and_commit_terminal(
            plan,
            journal,
            current,
            successor,
            policy,
            result="accepted",
            error=None,
            rollback_attempted=False,
            rollback_succeeded=False,
        )

    def _observe_accepted(
        self,
        current: ReleaseFacts,
        successor: ReleaseFacts,
    ) -> tuple[str, dict[str, Any]]:
        try:
            evidence = _typed_mapping(
                self.host.observe_accepted_revision(),
                schema="stateport.update-host-observation/v1",
                fields={"releaseId", "signedDigest", "runtimeDigest"},
                label="accepted revision observation",
            )
        except BaseException as exc:
            if not isinstance(exc, Exception):
                raise
            return "ambiguous", {
                "status": "unavailable",
                "code": (
                    exc.code
                    if isinstance(exc, UpdateError) and ERROR_CODE.fullmatch(exc.code)
                    else "observation_failed"
                ),
            }
        if (
            evidence["releaseId"] == current.release_id
            and evidence["signedDigest"] == current.signed_digest
            and evidence["runtimeDigest"] == current.expected_revision_digest()
        ):
            return "current", evidence
        if (
            evidence["releaseId"] == successor.release_id
            and evidence["signedDigest"] == successor.signed_digest
            and evidence["runtimeDigest"] == successor.expected_revision_digest()
        ):
            return "successor", evidence
        return "ambiguous", evidence

    def _record_observation(
        self,
        journal: dict[str, Any],
        evidence: Mapping[str, Any],
    ) -> None:
        # Repeated reconciliation replaces the unconsumed trailing observation
        # instead of growing the WAL until its 128-step safety bound makes
        # recovery impossible.  Observations consumed by a subsequent rollback
        # or cleanup effect remain immutable evidence.
        with self.store.transaction() as session:
            self._with_current_journal(session, journal)
            observed = {
                "step": "accepted-route-observation",
                "at": _timestamp(self.clock),
                "evidence": deepcopy(dict(evidence)),
            }
            if journal["steps"] and journal["steps"][-1]["step"] == observed["step"]:
                journal["steps"] = [*journal["steps"][:-1], observed]
            else:
                count = sum(
                    1 for item in journal["steps"] if item["step"] == "accepted-route-observation"
                )
                if count >= MAX_RECONCILIATION_OBSERVATIONS:
                    raise UpdateError(
                        "observation_history_exhausted",
                        "bounded reconciliation observation history is exhausted",
                    )
                journal["steps"] = [*journal["steps"], observed]
            # An accepted-route observation resolves only route identity. It
            # cannot prove that an interrupted stage, cleanup, or rollback
            # effect did or did not happen. Preserve that intent until an
            # exact host receipt, successful cleanup/rollback, or explicit
            # operator retry establishes its durable disposition.
            if journal["intent"] is None:
                journal["phase"] = "accepted-route-observation"
            self._save_journal(session, journal)

    @staticmethod
    def _staged_or_later(journal: Mapping[str, Any]) -> bool:
        completed = {str(item["step"]) for item in journal["steps"]}
        intent = journal.get("intent")
        failure = journal.get("preparedFailureEvidence")
        failed_step = failure.get("failedStep") if isinstance(failure, Mapping) else None
        possibly_staged = {
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
        }
        return (
            "stage" in completed
            or (
                isinstance(intent, Mapping)
                and intent.get("step") in {*possibly_staged, "discard-successor"}
            )
            or failed_step in possibly_staged
        )

    def _discard_staged_successor(
        self,
        plan: Mapping[str, Any],
        journal: dict[str, Any],
        current: ReleaseFacts,
        successor: ReleaseFacts,
    ) -> None:
        try:
            self._step(
                journal,
                current,
                successor,
                plan,
                "discard-successor",
                lambda _release: self.host.discard_successor(plan),
                effect="partial",
            )
        except BaseException as exc:
            if not isinstance(exc, Exception):
                raise
            with self.store.transaction() as session:
                self._with_current_journal(session, journal)
                journal["phase"] = "cleanup_reconciliation_required"
                journal["effectDisposition"] = "unknown"
                self._save_journal(session, journal)
                status = session.load_status()
                status["phase"] = "validating"
                status["stagedSuccessor"] = successor.status_identity()
                session.save_status(status, timestamp=_timestamp(self.clock))
            raise UpdateError(
                "cleanup_reconciliation_required",
                "failed successor cleanup lacks exact host evidence",
            ) from exc

    def _handle_failure(
        self,
        plan: Mapping[str, Any],
        journal: dict[str, Any],
        current: ReleaseFacts,
        successor: ReleaseFacts,
        policy: UpdatePolicy,
        error: UpdateError,
    ) -> dict[str, Any]:
        observed, observation = self._observe_accepted(current, successor)
        self._record_observation(journal, observation)
        if observed == "ambiguous":
            with self.store.transaction() as session:
                self._with_current_journal(session, journal)
                journal["phase"] = "reconciliation_required"
                journal["effectDisposition"] = "unknown"
                self._save_journal(session, journal)
                status = session.load_status()
                status["phase"] = (
                    "switching"
                    if journal["effectDisposition"] in {"applied", "unknown"}
                    else "validating"
                )
                status["stagedSuccessor"] = successor.status_identity()
                session.save_status(status, timestamp=_timestamp(self.clock))
            raise UpdateError(
                "reconciliation_required",
                "accepted runtime identity is ambiguous; no effect was replayed or finalized",
                details={"cause": error.code},
            )
        if observed == "successor":
            try:
                self._step(
                    journal,
                    current,
                    successor,
                    plan,
                    "automatic-rollback",
                    lambda _release: self.host.rollback_failed_switch(plan),
                    effect="applied",
                )
                after, after_evidence = self._observe_accepted(current, successor)
                self._record_observation(journal, after_evidence)
            except UpdateError:
                with self.store.transaction() as session:
                    self._with_current_journal(session, journal)
                    journal["phase"] = "rollback_reconciliation_required"
                    journal["effectDisposition"] = "unknown"
                    self._save_journal(session, journal)
                    status = session.load_status()
                    status["phase"] = "rolling_back"
                    session.save_status(status, timestamp=_timestamp(self.clock))
                raise UpdateError(
                    "rollback_reconciliation_required",
                    "automatic rollback outcome is ambiguous and was not replayed",
                )
            if after != "current":
                with self.store.transaction() as session:
                    self._with_current_journal(session, journal)
                    journal["phase"] = "rollback_reconciliation_required"
                    journal["effectDisposition"] = "unknown"
                    self._save_journal(session, journal)
                    status = session.load_status()
                    status["phase"] = "rolling_back"
                    session.save_status(status, timestamp=_timestamp(self.clock))
                raise UpdateError(
                    "rollback_reconciliation_required",
                    "automatic rollback did not produce exact predecessor observation",
                )
            self._set_journal_state(journal, disposition="rolled_back")
            return self._prepare_and_commit_terminal(
                plan,
                journal,
                current,
                successor,
                policy,
                result="rolled_back",
                error=error,
                rollback_attempted=True,
                rollback_succeeded=True,
            )

        # The accepted route remained exact predecessor.  Cleanup is meaningful
        # only once staging may have created successor resources; a refusal in
        # verify/backup/pull must not invent a discard side effect.
        if self._staged_or_later(journal):
            if journal.get("preparedFailureEvidence") is None:
                failure = self._make_failure_evidence(plan, successor, error, journal)
                with self.store.transaction() as session:
                    self._with_current_journal(session, journal)
                    session.save_failure_evidence(failure)
                    journal["preparedFailureEvidence"] = failure
                    journal["phase"] = "failure_evidence_prepared"
                    journal["intent"] = None
                    self._save_journal(session, journal)
            self._discard_staged_successor(
                plan,
                journal,
                current,
                successor,
            )
        self._set_journal_state(journal, disposition="not_applied")
        return self._prepare_and_commit_terminal(
            plan,
            journal,
            current,
            successor,
            policy,
            result="failed_safe",
            error=error,
            rollback_attempted=False,
            rollback_succeeded=False,
        )

    def _failure_step(
        self,
        journal: Mapping[str, Any],
        error: UpdateError | None = None,
    ) -> str:
        if error is not None and error.details.get("failedStep") in set(UPDATE_STEPS):
            return str(error.details["failedStep"])
        intent = journal.get("intent")
        if isinstance(intent, Mapping) and intent.get("step") in set(UPDATE_STEPS):
            return str(intent["step"])
        completed = [item["step"] for item in journal["steps"] if item["step"] in set(UPDATE_STEPS)]
        return str(completed[-1]) if completed else "verify"

    def _make_failure_evidence(
        self,
        plan: Mapping[str, Any],
        successor: ReleaseFacts,
        error: UpdateError,
        journal: Mapping[str, Any],
    ) -> dict[str, Any]:
        seed = canonical_digest(
            {
                "planDigest": plan["planDigest"],
                "errorCode": error.code,
                "journalDigest": journal["journalDigest"],
            }
        )
        return {
            "schema": "stateport.update-failure-evidence/v1",
            "failureId": f"update_failure_{seed.removeprefix('sha256:')[:32]}",
            "planId": plan["planId"],
            "planDigest": plan["planDigest"],
            "successor": successor.status_identity(),
            "failedStep": self._failure_step(journal, error),
            "errorCode": re.sub(r"[^a-z0-9_]", "_", error.code.lower())[:128],
            "safeSummary": f"Update failed safely at {self._failure_step(journal, error)} ({error.code}).",
            "artifacts": [],
            "retained": True,
            "observedAt": _timestamp(self.clock),
        }

    def _make_receipt(
        self,
        plan: Mapping[str, Any],
        journal: Mapping[str, Any],
        current: ReleaseFacts,
        successor: ReleaseFacts,
        *,
        result: str,
        error: UpdateError | None,
        rollback_attempted: bool,
        rollback_succeeded: bool,
    ) -> dict[str, Any]:
        binding = journal["authority"]
        reference = authority_reference(binding, plan_digest=plan["planDigest"])
        completed: dict[str, Mapping[str, Any]] = {}
        for item in journal["steps"]:
            step = str(item["step"])
            evidence = item["evidence"]
            if step in {"verify", "accepted-route-observation"}:
                completed[step] = evidence
            else:
                completed[step], _host_receipt = self._validated_effect_record(
                    evidence,
                    plan=plan,
                    step=step,
                )
        checks = {
            step: ("passed" if step in completed else "not_run")
            for step in plan["steps"]
            if step != "record-receipt"
        }
        retention = completed.get("retain-predecessor")
        if isinstance(retention, Mapping):
            retention_digest = canonical_digest(retention)
            checks[f"retention-evidence-{retention_digest.removeprefix('sha256:')}"] = "passed"
        if error is not None:
            checks[self._failure_step(journal, error)] = "failed"
        backup = completed.get("backup", {})
        backup_receipt = (
            str(backup["receiptId"])
            if isinstance(backup, Mapping) and isinstance(backup.get("receiptId"), str)
            else "backup_not_created"
        )
        accepted = successor.identity if result == "accepted" else current.identity
        seed = canonical_digest(
            {
                "planDigest": plan["planDigest"],
                "result": result,
                "accepted": accepted["signedPayloadDigest"],
            }
        )
        return {
            "schema": "stateport.update-receipt/v1",
            "receiptId": f"update_receipt_{seed.removeprefix('sha256:')[:32]}",
            "installationId": self.store.installation_id,
            "planId": plan["planId"],
            "planDigest": plan["planDigest"],
            "operation": plan["operation"],
            "from": dict(current.identity),
            "attempted": dict(successor.identity),
            "accepted": dict(accepted),
            "releaseIndexDigest": successor.index_digest,
            "backupReceipt": backup_receipt,
            "checks": checks,
            "rollback": {
                "attempted": rollback_attempted,
                "succeeded": rollback_succeeded,
                "retainedFailureEvidence": error is not None,
            },
            "authority": reference,
            "startedAt": journal["startedAt"],
            "finishedAt": _timestamp(self.clock),
            "result": result,
        }

    def _prepare_and_commit_terminal(
        self,
        plan: Mapping[str, Any],
        journal: dict[str, Any],
        current: ReleaseFacts,
        successor: ReleaseFacts,
        policy: UpdatePolicy,
        *,
        result: str,
        error: UpdateError | None,
        rollback_attempted: bool,
        rollback_succeeded: bool,
    ) -> dict[str, Any]:
        if journal["preparedReceipt"] is None:
            failure = journal.get("preparedFailureEvidence")
            if error is not None and failure is None:
                failure = self._make_failure_evidence(plan, successor, error, journal)
                with self.store.transaction() as session:
                    self._with_current_journal(session, journal)
                    session.save_failure_evidence(failure)
                    journal["preparedFailureEvidence"] = failure
                    journal["phase"] = "failure_evidence_prepared"
                    journal["intent"] = None
                    self._save_journal(session, journal)
            failure_id = None if failure is None else str(failure["failureId"])
            if "retain-predecessor" not in self._completed_steps(journal):
                self._enforce_retention(
                    plan,
                    journal,
                    current,
                    successor,
                    policy,
                    result=result,
                    failure_id=failure_id,
                )
            receipt = self._make_receipt(
                plan,
                journal,
                current,
                successor,
                result=result,
                error=error,
                rollback_attempted=rollback_attempted,
                rollback_succeeded=rollback_succeeded,
            )
            try:
                validate_update_receipt(receipt)
            except ReleaseContractError as exc:
                raise UpdateError("receipt_invalid", str(exc)) from exc
            with self.store.transaction() as session:
                self._with_current_journal(session, journal)
                journal["preparedReceipt"] = receipt
                journal["phase"] = "receipt_prepared"
                journal["intent"] = None
                self._save_journal(session, journal)
        return self._commit_prepared_terminal(
            plan,
            journal,
            current,
            successor,
            policy,
        )

    def _retention_requirements(
        self,
        session: UpdateSession,
        current: ReleaseFacts,
        *,
        result: str,
        failure_id: str | None,
        policy: UpdatePolicy,
    ) -> tuple[list[str], list[str]]:
        receipts = session.list_receipts()
        by_accepted = {
            str(receipt["accepted"]["releaseId"]): receipt
            for receipt in receipts
            if receipt["result"] == "accepted"
        }
        predecessors: list[str] = []
        cursor = current.release_id
        if result == "accepted":
            predecessors.append(cursor)
        while len(predecessors) < policy.accepted_predecessors:
            previous = by_accepted.get(cursor)
            if previous is None:
                break
            candidate = str(previous["from"]["releaseId"])
            if candidate in predecessors or candidate == cursor:
                break
            predecessors.append(candidate)
            cursor = candidate

        failures = sorted(
            session.list_failures(),
            key=lambda item: (str(item["observedAt"]), str(item["failureId"])),
            reverse=True,
        )
        failure_ids: list[str] = []
        if failure_id is not None:
            failure_ids.append(failure_id)
        for failure in failures:
            candidate = str(failure["failureId"])
            if candidate not in failure_ids:
                failure_ids.append(candidate)
            if len(failure_ids) >= policy.failed_successors:
                break
        return (
            predecessors[: policy.accepted_predecessors],
            failure_ids[: policy.failed_successors],
        )

    def _enforce_retention(
        self,
        plan: Mapping[str, Any],
        journal: dict[str, Any],
        current: ReleaseFacts,
        successor: ReleaseFacts,
        policy: UpdatePolicy,
        *,
        result: str,
        failure_id: str | None,
    ) -> dict[str, Any]:
        accepted = successor if result == "accepted" else current
        with self.store.transaction() as session:
            self._with_current_journal(session, journal)
            predecessors, failures = self._retention_requirements(
                session,
                current,
                result=result,
                failure_id=failure_id,
                policy=policy,
            )
            journal["phase"] = "intent_retain-predecessor"
            journal["intent"] = {
                "step": "retain-predecessor",
                "effect": "partial",
                "recordedAt": _timestamp(self.clock),
            }
            self._save_journal(session, journal)

        self._trip("before_retention")
        try:
            evidence = self._validate_retention_evidence(
                self.host.enforce_retention(
                    plan_digest=str(plan["planDigest"]),
                    current_release_id=accepted.release_id,
                    required_predecessor_ids=predecessors,
                    required_failure_evidence_ids=failures,
                    maximum_versions=policy.maximum_versions,
                    maximum_age_days=policy.maximum_age_days,
                ),
                policy=policy,
                current_release_id=accepted.release_id,
                required_predecessor_ids=predecessors,
                required_failure_evidence_ids=failures,
            )
            record = self._effect_record(
                plan=plan,
                step="retain-predecessor",
                evidence=evidence,
            )
            self._trip("after_retention_before_journal")
        except Exception as exc:
            with self.store.transaction() as session:
                self._with_current_journal(session, journal)
                journal["phase"] = "retention_reconciliation_required"
                journal["effectDisposition"] = "unknown"
                self._save_journal(session, journal)
                status = session.load_status()
                status["phase"] = "validating"
                session.save_status(status, timestamp=_timestamp(self.clock))
            raise UpdateError(
                "retention_reconciliation_required",
                "accepted runtime is exact but retention requires bounded reconciliation",
            ) from exc
        self._append_step(
            journal,
            "retain-predecessor",
            record,
            disposition=journal["effectDisposition"],
        )
        return evidence

    def _commit_prepared_terminal(
        self,
        plan: Mapping[str, Any],
        journal: dict[str, Any],
        current: ReleaseFacts,
        successor: ReleaseFacts,
        policy: UpdatePolicy,
    ) -> dict[str, Any]:
        del policy
        receipt = deepcopy(journal["preparedReceipt"])
        if not isinstance(receipt, dict):
            raise UpdateError("receipt_missing", "pending terminal receipt is missing")
        failure = journal.get("preparedFailureEvidence")
        failure_id: str | None = None
        with self.store.transaction() as session:
            self._with_current_journal(session, journal)
            if isinstance(failure, Mapping):
                session.save_failure_evidence(failure)
                failure_id = str(failure["failureId"])
            self._trip("before_receipt_save")
            receipt_digest = session.save_receipt(receipt)
            self._trip("after_receipt_save_before_journal")
            journal["phase"] = "receipt_saved"
            self._save_journal(session, journal)

        result = receipt["result"]
        accepted = successor if result == "accepted" else current
        with self.store.transaction() as session:
            self._with_current_journal(session, journal)
            latest = session.load_status()
            if latest["lastReceipt"] == receipt["receiptId"]:
                if latest["current"] != accepted.status_identity():
                    raise UpdateError(
                        "state_commit_conflict",
                        "terminal receipt exists but installed identity disagrees",
                    )
            else:
                if (
                    latest["current"] != current.status_identity()
                    or latest["accepted"] != current.status_identity()
                    or latest["stagedSuccessor"] != successor.status_identity()
                    or latest["policy"] != plan["policy"]
                ):
                    raise UpdateError(
                        "state_commit_conflict",
                        "installed state changed before terminal update commit",
                    )
                latest["current"] = accepted.status_identity()
                latest["accepted"] = accepted.status_identity()
                latest["retainedPredecessor"] = (
                    current.status_identity()
                    if result == "accepted"
                    else latest["retainedPredecessor"]
                )
                latest["stagedSuccessor"] = None
                latest["failedSuccessorEvidence"] = failure_id
                latest["lastReceipt"] = receipt["receiptId"]
                latest["phase"] = {
                    "accepted": "accepted",
                    "rolled_back": "rolled_back",
                    "failed_safe": "failed_safe",
                }[result]
                session.save_status(latest, timestamp=receipt["finishedAt"])
            self._trip("after_state_flip_before_journal")
            journal["phase"] = "state_committed"
            self._save_journal(session, journal)

        persisted_canonical = journal.get("canonicalAuthorityReceipt")
        binding = journal["authority"]
        resource = {
            "updateReceiptId": receipt["receiptId"],
            "updateReceiptDigest": receipt_digest,
            "planDigest": plan["planDigest"],
            "acceptedReleaseId": receipt["accepted"]["releaseId"],
            "retentionEvidenceDigest": canonical_digest(
                self._validated_effect_record(
                    next(
                        item["evidence"]
                        for item in journal["steps"]
                        if item["step"] == "retain-predecessor"
                    ),
                    plan=plan,
                    step="retain-predecessor",
                )[0]
            ),
        }
        if persisted_canonical is None:
            with self.store.transaction() as session:
                self._with_current_journal(session, journal)
                journal["phase"] = "authority_finalization_pending"
                self._save_journal(session, journal)
        try:
            # Always round-trip through canonical authority, even when the WAL
            # claims finalization already happened.  The mutable journal can
            # cache an exact receipt, but can never act as its authority.
            canonical = self.authority.finalize(
                binding,
                result_status=("succeeded" if result == "accepted" else "failed"),
                code=None if result == "accepted" else "update_failed_safe",
                summary=(
                    "StatePort accepted the exact verified successor"
                    if result == "accepted"
                    else "StatePort retained exact failure evidence and safe runtime"
                ),
                resource=resource,
                started_at=_parse_timestamp(journal["startedAt"], "startedAt"),
            )
        except Exception as exc:
            raise UpdateError(
                "authority_finalization_pending",
                "canonical authority outcome requires reconciliation",
                receipt=receipt,
            ) from exc
        if persisted_canonical is not None and persisted_canonical != canonical:
            raise UpdateError(
                "authority_receipt_conflict",
                "persisted authority receipt differs from canonical authority state",
                receipt=receipt,
            )
        if persisted_canonical is None:
            self._trip("after_authority_finalize_before_journal")
            with self.store.transaction() as session:
                self._with_current_journal(session, journal)
                journal["canonicalAuthorityReceipt"] = deepcopy(canonical)
                journal["phase"] = "authority_finalized"
                self._save_journal(session, journal)

        finalized = finalized_authority_reference(
            binding, canonical, plan_digest=plan["planDigest"]
        )
        link_seed = canonical_digest(
            {
                "planDigest": plan["planDigest"],
                "updateReceiptDigest": receipt_digest,
                "authorityReceiptDigest": canonical["receiptDigest"],
            }
        )
        try:
            linked_at_value = datetime.fromisoformat(
                str(canonical["completedAt"]).replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise UpdateError(
                "authority_receipt_invalid",
                "canonical authority receipt completion time is invalid",
            ) from exc
        if linked_at_value.tzinfo is None or linked_at_value.utcoffset() is None:
            raise UpdateError(
                "authority_receipt_invalid",
                "canonical authority receipt completion time has no timezone",
            )
        linked_at = (
            linked_at_value.astimezone(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
        link = {
            "schema": "stateport.update-authority-link/v1",
            "linkId": f"update_authority_link_{link_seed.removeprefix('sha256:')[:32]}",
            "planDigest": plan["planDigest"],
            "runId": plan["planDigest"],
            "updateReceiptId": receipt["receiptId"],
            "updateReceiptDigest": receipt_digest,
            "authority": finalized,
            "linkedAt": linked_at,
        }
        self._trip("after_authority_journal_before_link")
        with self.store.transaction() as session:
            self._with_current_journal(session, journal)
            session.save_authority_link(link)
            self._trip("after_link_before_journal")
            journal["phase"] = "link_saved"
            self._save_journal(session, journal)
            journal["phase"] = "completed"
            self._save_journal(session, journal)
            self._trip("before_archive")
            session.archive_journal(
                journal,
                expected_digest=journal["journalDigest"],
            )
        self._trip("after_archive")
        return receipt

    def reconcile(self, *, resolution: str = "observe") -> dict[str, Any]:
        """Reconcile one exact WAL without replaying an unknown effect.

        ``retry_rollback`` and ``retry_cleanup`` are the only explicit operator
        retries. Each is accepted only after the host proves the exact active
        revision; both adapters must be idempotent for the plan digest.
        """

        if resolution not in {
            "observe",
            "retry_cleanup",
            "retry_rollback",
            "accept_successor",
        }:
            raise UpdateError("resolution_invalid", "reconciliation resolution is invalid")
        try:
            with self.store.operation_lease():
                with self.store.transaction() as session:
                    journal = session.load_pending()
                    if journal is None:
                        return session.load_status()
                    # A claimed effect remains recoverable after its planning
                    # window.  Structural/digest validation still applies;
                    # live expiry is enforced below only for a genuinely new
                    # claim.
                    plan = self._validated_plan(
                        session,
                        journal["planId"],
                        require_active=False,
                    )
                    current, successor, policy = self._plan_releases(
                        session,
                        plan,
                        require_successor_plan_admission=plan["operation"] == "update",
                    )
                    self._validate_journal_semantics(
                        session,
                        plan,
                        journal,
                        current,
                        successor,
                        policy,
                    )

                request_id = journal["authority"]["decision"]["requestId"]
                persisted_claim = journal["authority"]["claim"]
                try:
                    canonical_claim = self.authority.recover_claim(request_id)
                except UpdateAuthorityError as exc:
                    raise UpdateError(exc.code, str(exc), receipt=exc.receipt) from exc
                if persisted_claim is not None:
                    if canonical_claim is None or canonical_claim != persisted_claim:
                        raise UpdateError(
                            "authority_claim_mismatch",
                            "persisted authority claim is absent or differs from canonical authority",
                        )
                else:
                    claim = canonical_claim
                    if claim is None:
                        # No effect authority exists yet.  This is a new claim,
                        # so both plan activity and candidate freshness must be
                        # re-established at the claim boundary.
                        try:
                            claim_verified_at = self._now()
                            with self.store.transaction() as session:
                                active_plan = self._validated_plan(
                                    session,
                                    journal["planId"],
                                )
                                if active_plan != plan:
                                    raise UpdateError(
                                        "plan_changed",
                                        "pending plan changed before authority claim",
                                    )
                                current, successor, policy = self._plan_releases(
                                    session,
                                    active_plan,
                                    successor_verified_at=(
                                        claim_verified_at if plan["operation"] == "update" else None
                                    ),
                                )
                            validate_update_plan(plan, now=self.clock())
                            claim = self.authority.claim(journal["authority"])
                        except (ReleaseContractError, UpdateError, UpdateAuthorityError) as exc:
                            with self.store.transaction() as session:
                                self._with_current_journal(session, journal)
                                journal["phase"] = "claim_not_acquired"
                                journal["intent"] = None
                                self._save_journal(session, journal)
                                session.archive_journal(
                                    journal,
                                    expected_digest=journal["journalDigest"],
                                )
                            code = getattr(exc, "code", "plan_invalid")
                            receipt = getattr(exc, "receipt", None)
                            raise UpdateError(
                                str(code),
                                "pending update did not acquire live effect authority",
                                receipt=receipt if isinstance(receipt, Mapping) else None,
                            ) from exc
                    try:
                        decision = journal["authority"]["decision"]
                        reservation = journal["authority"]["reservation"]
                        if (
                            claim.get("requestId") != decision.get("requestId")
                            or claim.get("reservationId") != reservation.get("reservationId")
                            or claim.get("reservationDigest")
                            != reservation.get("reservationDigest")
                            or claim.get("decisionDigest") != decision.get("decisionDigest")
                        ):
                            raise UpdateError(
                                "authority_claim_mismatch",
                                "recovered authority claim is not bound to the exact reservation",
                            )
                    except AttributeError as exc:
                        raise UpdateError(
                            "authority_claim_mismatch",
                            "canonical authority claim is malformed",
                        ) from exc
                    with self.store.transaction() as session:
                        self._with_current_journal(session, journal)
                        journal["authority"]["claim"] = deepcopy(claim)
                        journal["phase"] = "claimed"
                        self._save_journal(session, journal)

                # Every recovery path consumes the same independently
                # revalidated prefix. Retention, prepared-terminal, and
                # non-null-intent branches may not bypass host receipt reads.
                self._revalidate_persisted_effect_receipts(
                    plan,
                    journal,
                )

                if journal["preparedReceipt"] is not None:
                    if journal["preparedReceipt"]["result"] == "accepted":
                        self._revalidate_persisted_live_gates(
                            plan,
                            journal,
                            current,
                            successor,
                        )
                    return self._commit_prepared_terminal(
                        plan,
                        journal,
                        current,
                        successor,
                        policy,
                    )

                intent = journal.get("intent")
                if journal["phase"] == "retention_reconciliation_required" or (
                    isinstance(intent, Mapping) and intent.get("step") == "retain-predecessor"
                ):
                    failure = journal.get("preparedFailureEvidence")
                    error = None
                    result = "accepted"
                    rollback_attempted = False
                    rollback_succeeded = False
                    if isinstance(failure, Mapping):
                        error = UpdateError(
                            str(failure["errorCode"]),
                            str(failure["safeSummary"]),
                            details={"failedStep": failure["failedStep"]},
                        )
                        result = (
                            "rolled_back"
                            if journal["effectDisposition"] == "rolled_back"
                            else "failed_safe"
                        )
                        rollback_attempted = result == "rolled_back"
                        rollback_succeeded = result == "rolled_back"
                    return self._prepare_and_commit_terminal(
                        plan,
                        journal,
                        current,
                        successor,
                        policy,
                        result=result,
                        error=error,
                        rollback_attempted=rollback_attempted,
                        rollback_succeeded=rollback_succeeded,
                    )

                if intent is None and journal["phase"] not in {
                    "reconciliation_required",
                    "rollback_reconciliation_required",
                    "cleanup_reconciliation_required",
                }:
                    self._revalidate_persisted_live_gates(
                        plan,
                        journal,
                        current,
                        successor,
                    )
                    return self._execute_remaining(
                        plan,
                        journal,
                        current,
                        successor,
                        policy,
                    )

                intent_step = (
                    str(intent["step"])
                    if isinstance(intent, Mapping) and isinstance(intent.get("step"), str)
                    else None
                )
                if intent_step in {"discard-successor", "automatic-rollback"}:
                    self._recover_unjournaled_terminal_effect(
                        plan,
                        journal,
                        current,
                        successor,
                        intent_step,
                    )

                observed, evidence = self._observe_accepted(current, successor)
                self._record_observation(journal, evidence)
                if observed == "ambiguous":
                    with self.store.transaction() as session:
                        self._with_current_journal(session, journal)
                        journal["phase"] = "reconciliation_required"
                        journal["effectDisposition"] = "unknown"
                        self._save_journal(session, journal)
                        status = session.load_status()
                        status["phase"] = "switching"
                        session.save_status(status, timestamp=_timestamp(self.clock))
                    raise UpdateError(
                        "reconciliation_required",
                        "runtime identity remains ambiguous; no effect was replayed",
                    )
                if observed == "current":
                    result = (
                        "rolled_back"
                        if journal["phase"] == "rollback_reconciliation_required"
                        or intent_step == "automatic-rollback"
                        else "failed_safe"
                    )
                    failure = journal.get("preparedFailureEvidence")
                    if isinstance(failure, Mapping):
                        error = UpdateError(
                            str(failure["errorCode"]),
                            str(failure["safeSummary"]),
                            details={"failedStep": failure["failedStep"]},
                        )
                    else:
                        error = UpdateError(
                            "interrupted_update_reconciled",
                            "interrupted update resolved to exact predecessor",
                            details=(
                                {"failedStep": intent_step}
                                if intent_step in set(UPDATE_STEPS)
                                else None
                            ),
                        )
                    if (
                        result == "rolled_back"
                        and "automatic-rollback" not in self._completed_steps(journal)
                    ):
                        if resolution != "retry_rollback":
                            with self.store.transaction() as session:
                                self._with_current_journal(session, journal)
                                journal["phase"] = "rollback_reconciliation_required"
                                journal["effectDisposition"] = "unknown"
                                self._save_journal(session, journal)
                            raise UpdateError(
                                "operator_resolution_required",
                                "rollback outcome lacks a host receipt; choose retry_rollback after inspection",
                            )
                        self._step(
                            journal,
                            current,
                            successor,
                            plan,
                            "automatic-rollback",
                            lambda _release: self.host.rollback_failed_switch(plan),
                            effect="applied",
                        )
                        after, after_evidence = self._observe_accepted(current, successor)
                        self._record_observation(journal, after_evidence)
                        if after != "current":
                            raise UpdateError(
                                "rollback_reconciliation_required",
                                "explicit rollback retry lacks exact predecessor observation",
                            )
                    if (
                        result == "failed_safe"
                        and self._staged_or_later(journal)
                        and "discard-successor" not in self._completed_steps(journal)
                    ):
                        if not isinstance(failure, Mapping):
                            failure = self._make_failure_evidence(
                                plan,
                                successor,
                                error,
                                journal,
                            )
                            with self.store.transaction() as session:
                                self._with_current_journal(session, journal)
                                session.save_failure_evidence(failure)
                                journal["preparedFailureEvidence"] = failure
                                self._save_journal(session, journal)
                        cleanup_intent = (
                            intent_step == "discard-successor"
                            and "discard-successor" not in self._completed_steps(journal)
                        )
                        if cleanup_intent and resolution != "retry_cleanup":
                            with self.store.transaction() as session:
                                self._with_current_journal(session, journal)
                                journal["phase"] = "cleanup_reconciliation_required"
                                journal["effectDisposition"] = "unknown"
                                self._save_journal(session, journal)
                            raise UpdateError(
                                "operator_resolution_required",
                                "cleanup outcome is unknown; choose retry_cleanup only after inspection",
                            )
                        self._discard_staged_successor(
                            plan,
                            journal,
                            current,
                            successor,
                        )
                    self._set_journal_state(
                        journal,
                        disposition=("rolled_back" if result == "rolled_back" else "not_applied"),
                    )
                    return self._prepare_and_commit_terminal(
                        plan,
                        journal,
                        current,
                        successor,
                        policy,
                        result=result,
                        error=error,
                        rollback_attempted=result == "rolled_back",
                        rollback_succeeded=result == "rolled_back",
                    )

                rollback_was_unknown = journal["phase"] == "rollback_reconciliation_required" or (
                    isinstance(intent, Mapping) and intent.get("step") == "automatic-rollback"
                )
                if resolution == "accept_successor":
                    try:
                        completed = self._completed_steps(journal)
                        for step, operation in (
                            (
                                "health-accepted-route",
                                lambda _release: self.host.health_accepted_route(plan),
                            ),
                            (
                                "state-check-accepted-route",
                                lambda _release: self.host.state_check_accepted_route(plan),
                            ),
                        ):
                            if step not in completed:
                                self._step(
                                    journal,
                                    current,
                                    successor,
                                    plan,
                                    step,
                                    operation,
                                    effect="applied",
                                )
                    except UpdateError as exc:
                        raise UpdateError(
                            "successor_acceptance_refused",
                            "successor failed accepted-route validation",
                        ) from exc
                    return self._prepare_and_commit_terminal(
                        plan,
                        journal,
                        current,
                        successor,
                        policy,
                        result="accepted",
                        error=None,
                        rollback_attempted=False,
                        rollback_succeeded=False,
                    )
                if rollback_was_unknown and resolution != "retry_rollback":
                    with self.store.transaction() as session:
                        self._with_current_journal(session, journal)
                        journal["phase"] = "rollback_reconciliation_required"
                        self._save_journal(session, journal)
                    raise UpdateError(
                        "operator_resolution_required",
                        "successor is exact but prior rollback outcome was unknown; choose retry_rollback or accept_successor",
                    )

                try:
                    self._step(
                        journal,
                        current,
                        successor,
                        plan,
                        "automatic-rollback",
                        lambda _release: self.host.rollback_failed_switch(plan),
                        effect="applied",
                    )
                    after, after_evidence = self._observe_accepted(current, successor)
                    self._record_observation(journal, after_evidence)
                except UpdateError as exc:
                    with self.store.transaction() as session:
                        self._with_current_journal(session, journal)
                        journal["phase"] = "rollback_reconciliation_required"
                        journal["effectDisposition"] = "unknown"
                        self._save_journal(session, journal)
                        status = session.load_status()
                        status["phase"] = "rolling_back"
                        session.save_status(status, timestamp=_timestamp(self.clock))
                    raise UpdateError(
                        "rollback_reconciliation_required",
                        "rollback remains ambiguous and was not automatically replayed",
                    ) from exc
                if after != "current":
                    with self.store.transaction() as session:
                        self._with_current_journal(session, journal)
                        journal["phase"] = "rollback_reconciliation_required"
                        journal["effectDisposition"] = "unknown"
                        self._save_journal(session, journal)
                    raise UpdateError(
                        "rollback_reconciliation_required",
                        "rollback lacks exact predecessor observation",
                    )
                self._set_journal_state(journal, disposition="rolled_back")
                error = UpdateError(
                    "interrupted_update_rolled_back",
                    "interrupted successor was rolled back",
                )
                return self._prepare_and_commit_terminal(
                    plan,
                    journal,
                    current,
                    successor,
                    policy,
                    result="rolled_back",
                    error=error,
                    rollback_attempted=True,
                    rollback_succeeded=True,
                )
        except StoreError as exc:
            raise UpdateError(exc.code, str(exc)) from exc

    def set_policy(
        self,
        policy: UpdatePolicy,
        *,
        expected_status_digest: str,
        mutate: Callable[..., tuple[dict[str, Any], Mapping[str, Any]]],
    ) -> dict[str, Any]:
        """Modify policy only through the caller's canonical authority wrapper.

        The callback is normally ``AuthorityManagerAdapter.execute_scoped``
        partially bound to ``modify_update_policy``.  There is intentionally no
        caller-supplied actor identity.
        """

        if DIGEST.fullmatch(expected_status_digest) is None:
            raise UpdateError("approval_digest_mismatch", "status digest is invalid")

        def operation() -> dict[str, Any]:
            try:
                with self.store.operation_lease():
                    with self.store.transaction() as session:
                        if session.load_pending() is not None:
                            raise UpdateError(
                                "update_in_progress",
                                "policy cannot change during update",
                            )
                        status = session.load_status()
                        if canonical_digest(status) != expected_status_digest:
                            raise UpdateError(
                                "approval_digest_mismatch",
                                "status changed before policy mutation",
                            )
                        status["policy"] = policy.to_mapping()
                        return session.save_status(
                            status,
                            timestamp=_timestamp(self.clock),
                        )
            except StoreError as exc:
                raise UpdateError(exc.code, str(exc)) from exc

        changed, receipt = mutate(
            "modify_update_policy",
            run_id=expected_status_digest,
            operation=operation,
            resource_from_result=lambda result: {
                "policyDigest": result["policy"]["policyDigest"],
                "statusDigest": canonical_digest(result),
            },
        )
        return {**changed, "receipt": dict(receipt)}
