"""Ingress, provider-serialization, and model-return enforcement."""

from __future__ import annotations

from hashlib import sha256
import json
from typing import Iterable, Mapping

from .contracts import RedactionDecision, SanitizedContextReceipt, SensitiveDataPolicy, SensitiveFinding
from .scanner import DeterministicScanner


class GatewayFailure(RuntimeError):
    """The boundary could not classify content safely."""


class GatewayBlocked(GatewayFailure):
    def __init__(self, boundary: str, findings: tuple[SensitiveFinding, ...]) -> None:
        super().__init__(f"sensitive content blocked at {boundary}")
        self.boundary = boundary
        self.findings = findings


def _digest(value: str | bytes) -> str:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return "sha256:" + sha256(raw).hexdigest()


class SensitiveDataGateway:
    """Scan complete boundary payloads and return value-free receipts."""

    def __init__(self, scanner: DeterministicScanner, policy: SensitiveDataPolicy | None = None) -> None:
        self.scanner = scanner
        self.policy = policy or SensitiveDataPolicy()
        # This stable relationship map is process-local and never appears in
        # contracts, receipts, logs, or provider context.
        self._aliases: dict[tuple[str, str], str] = {}
        self._alias_counts: dict[str, int] = {}

    def _scan(self, text: str, source_kind: str, *, boundary: str) -> tuple[SensitiveFinding, ...]:
        try:
            return self.scanner.scan(text, source_kind=source_kind, policy=self.policy)
        except Exception as exc:
            if self.policy.strict:
                raise GatewayFailure(f"scanner unavailable at {boundary}; request failed closed") from exc
            raise

    def redact(self, text: str, *, source_kind: str) -> RedactionDecision:
        findings = self._scan(text, source_kind, boundary="ingress")
        placeholders: list[str] = []
        replacements: list[tuple[int, int, str]] = []
        blocked = False
        for finding in findings:
            if finding.action == "block":
                blocked = True
            elif finding.action not in {"redact", "review"}:
                continue
            matched_digest = sha256(text[finding.start:finding.end].encode("utf-8")).hexdigest()
            alias_key = (finding.category, matched_digest)
            placeholder = self._aliases.get(alias_key)
            if placeholder is None:
                self._alias_counts[finding.category] = self._alias_counts.get(finding.category, 0) + 1
                placeholder = f"[{finding.category.upper()}_{self._alias_counts[finding.category]}]"
                self._aliases[alias_key] = placeholder
            if placeholder not in placeholders:
                placeholders.append(placeholder)
            replacements.append((finding.start, finding.end, placeholder))
        sanitized = text
        for start, end, placeholder in reversed(replacements):
            sanitized = sanitized[:start] + placeholder + sanitized[end:]
        return RedactionDecision(sanitized, findings, tuple(placeholders), blocked)

    def sanitize_ingress(self, fragments: Mapping[str, str]) -> tuple[dict[str, str], tuple[SanitizedContextReceipt, ...]]:
        sanitized: dict[str, str] = {}
        receipts: list[SanitizedContextReceipt] = []
        for source_kind in sorted(fragments):
            text = fragments[source_kind]
            decision = self.redact(text, source_kind=source_kind)
            receipt = self._receipt("ingress", (source_kind,), text, decision.sanitized_text, decision.findings, "blocked" if decision.blocked else "sanitized")
            receipts.append(receipt)
            if decision.blocked:
                raise GatewayBlocked("ingress", decision.findings)
            sanitized[source_kind] = decision.sanitized_text
        return sanitized, tuple(receipts)

    def serialize_provider_payload(self, fragments: Mapping[str, str]) -> tuple[bytes, SanitizedContextReceipt]:
        """Assemble then scan the exact serialized body immediately before send."""

        body = json.dumps(dict(sorted(fragments.items())), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        decision = self.redact(body, source_kind="assembled_provider_payload")
        findings = decision.findings
        serialized = decision.sanitized_text
        blocked = decision.blocked or any(item.action == "review" for item in findings)
        receipt = self._receipt(
            "provider_serialization", tuple(sorted(fragments)), body,
            None if blocked else serialized, findings, "blocked" if blocked else "sanitized",
        )
        if receipt.outcome == "blocked":
            raise GatewayBlocked("provider_serialization", findings)
        return serialized.encode("utf-8"), receipt

    def sanitize_model_return(self, text: str, *, source_kind: str = "tool_output") -> tuple[str, SanitizedContextReceipt]:
        decision = self.redact(text, source_kind=source_kind)
        unsafe = decision.blocked or any(item.action == "review" for item in decision.findings)
        receipt = self._receipt(
            "model_return", (source_kind,), text, None if unsafe else decision.sanitized_text,
            decision.findings, "withheld" if unsafe else "sanitized",
        )
        if unsafe:
            raise GatewayBlocked("model_return", decision.findings)
        return decision.sanitized_text, receipt

    def _receipt(
        self,
        boundary: str,
        source_kinds: Iterable[str],
        original: str,
        sanitized: str | None,
        findings: tuple[SensitiveFinding, ...],
        outcome: str,
    ) -> SanitizedContextReceipt:
        source_tuple = tuple(source_kinds)
        identity = "|".join((boundary, _digest(original), outcome, *(item.finding_id for item in findings)))
        return SanitizedContextReceipt(
            receipt_id="scan." + sha256(identity.encode("utf-8")).hexdigest()[:24],
            boundary=boundary,
            source_kinds=source_tuple,
            input_digest=_digest(original),
            output_digest=None if sanitized is None else _digest(sanitized),
            finding_ids=tuple(item.finding_id for item in findings),
            outcome=outcome,
            scanner_version=self.scanner.VERSION,
            policy_id=self.policy.policy_id,
        )
