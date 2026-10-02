"""Strict contracts for bounded conversation compression and handoff.

These contracts classify continuity artifacts as ephemeral operational state.
They never authorize a canonical StateSpec write and never accept raw prompt,
provider configuration, or executable extension fields.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import re
import secrets
from types import MappingProxyType
from typing import Any, Mapping, Sequence


POLICY_FORMAT = "stateport.context-lifecycle/v1"
EFFECTIVE_POLICY_FORMAT = "stateport.context-lifecycle-effective/v1"
USAGE_FORMAT = "stateport.context-usage/v1"
CONTINUITY_FORMAT = "stateport.context-continuity/v1"
COMPRESSION_FORMAT = "stateport.context-compression/v1"
HANDOFF_FORMAT = "stateport.handoff-artifact/v1"
RECEIPT_FORMAT = "stateport.context-lifecycle-receipt/v1"
RESUME_DECISION_FORMAT = "stateport.context-resume-decision/v1"

PREFERENCE_MODES = ("faster", "balanced", "deeper")
POLICY_SCOPES = (
    "template", "instance", "operator", "user_preference", "backend", "budget",
)
LIFECYCLE_MODES = ("automatic", "manual", "disabled")
MODE_RESTRICTIVENESS = {"automatic": 0, "manual": 1, "disabled": 2}

CONTEXT_CATEGORY_ORDER = (
    "active_task",
    "requirements",
    "completed_work",
    "pending_work",
    "decisions",
    "approvals",
    "unresolved_risks",
    "exact_git_identities",
    "acceptance_criteria",
    "validation_state",
    "next_action",
    "relevant_state_references",
    "recent_receipts",
    "application_state",
    "conversation_summary",
    "tool_outcomes",
)
CONTEXT_CATEGORIES = frozenset(CONTEXT_CATEGORY_ORDER)
EXCLUDED_CATEGORY_ORDER = (
    "credentials",
    "raw_provider_prompt",
    "raw_provider_transcript",
    "raw_terminal_transcript",
    "private_unselected_data",
)
EXCLUDED_CATEGORIES = frozenset(EXCLUDED_CATEGORY_ORDER)
REQUIRED_PRESERVATION = (
    "active_task",
    "requirements",
    "decisions",
    "approvals",
    "unresolved_risks",
    "exact_git_identities",
    "acceptance_criteria",
    "validation_state",
    "next_action",
)
RESUME_GUARDS = (
    "same_instance",
    "same_workstream",
    "compatible_runtime_profile",
    "unchanged_base_snapshot",
    "fresh_context_manifest",
)

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40,64}$")
_BRANCH = re.compile(r"^(?:HEAD|[A-Za-z0-9][A-Za-z0-9._/-]{0,254})$")


class ContextLifecycleError(ValueError):
    """A bounded lifecycle request failed without exposing private content."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = _identifier(reason_code, "reason code")
        super().__init__(self.reason_code)


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


def canonical_digest(value: Any) -> str:
    if hasattr(value, "to_dict"):
        value = value.to_dict()
    return "sha256:" + sha256(_canonical(value)).hexdigest()


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _mapping(
    value: Any,
    label: str,
    required: set[str],
    *,
    optional: set[str] | None = None,
) -> Mapping[str, Any]:
    optional = optional or set()
    if (
        not isinstance(value, Mapping)
        or not required.issubset(value)
        or not set(value).issubset(required | optional)
    ):
        raise ValueError(f"{label} has an invalid shape")
    return value


def _text(value: Any, label: str, *, maximum: int = 4096) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > maximum
        or "\x00" in value
        or any(ord(character) < 32 and character not in "\n\t" for character in value)
    ):
        raise ValueError(f"{label} must be bounded text")
    return value


def _identifier(value: Any, label: str) -> str:
    value = _text(value, label, maximum=128)
    if _ID.fullmatch(value) is None:
        raise ValueError(f"{label} has invalid characters")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{label} must be a sha256 digest")
    return value


def _git_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or _GIT_SHA.fullmatch(value) is None:
        raise ValueError(f"{label} must be an immutable Git SHA")
    return value


def _integer(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{label} is outside policy bounds")
    return value


def _ratio(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a ratio")
    result = float(value)
    if not 0.1 <= result <= 0.99:
        raise ValueError(f"{label} must be between 0.1 and 0.99")
    return result


def _usage_ratio(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a ratio")
    result = float(value)
    if not 0 <= result <= 2_000:
        raise ValueError(f"{label} is outside accounting bounds")
    return result


def _timestamp(value: Any, label: str) -> str:
    value = _text(value, label, maximum=40)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return value


def _timestamp_value(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _strings(
    value: Any,
    label: str,
    *,
    allowed: frozenset[str] | None = None,
    maximum_items: int = 64,
    maximum_text: int = 2048,
    required: bool = False,
) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > maximum_items or (required and not value):
        raise ValueError(f"{label} must be a bounded list")
    result = tuple(_text(item, label, maximum=maximum_text) for item in value)
    if len(set(result)) != len(result):
        raise ValueError(f"{label} must not contain duplicates")
    if allowed is not None and any(item not in allowed for item in result):
        raise ValueError(f"{label} contains an unsupported category")
    return result


class _Contract:
    def __init__(self, value: Mapping[str, Any]) -> None:
        self._value = _freeze(value)

    def to_dict(self) -> dict[str, Any]:
        return _thaw(self._value)

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_dict())


class ContextLifecyclePolicy(_Contract):
    """One independently authoritative policy layer."""

    @classmethod
    def from_dict(cls, value: Any) -> "ContextLifecyclePolicy":
        data = _mapping(
            value,
            "context lifecycle policy",
            {
                "formatVersion", "policyId", "budget", "compression", "handoff",
                "session", "contextCategories",
            },
        )
        if data["formatVersion"] != POLICY_FORMAT:
            raise ValueError("context lifecycle policy has an invalid formatVersion")
        _identifier(data["policyId"], "policyId")
        budget = _mapping(
            data["budget"], "context budget", {"maximumInputTokens", "preferredInputTokens"},
        )
        maximum = _integer(
            budget["maximumInputTokens"], "maximumInputTokens", minimum=1_000, maximum=2_000_000,
        )
        preferred = _integer(
            budget["preferredInputTokens"], "preferredInputTokens", minimum=1_000, maximum=2_000_000,
        )
        if preferred > maximum:
            raise ValueError("preferredInputTokens may not exceed maximumInputTokens")
        compression = _mapping(
            data["compression"], "compression policy", {"mode", "triggerRatio", "preserve"},
        )
        if compression["mode"] not in LIFECYCLE_MODES:
            raise ValueError("compression mode is invalid")
        compression_ratio = _ratio(compression["triggerRatio"], "compression triggerRatio")
        preserve = _strings(
            compression["preserve"], "compression preserve", allowed=CONTEXT_CATEGORIES, required=True,
        )
        missing = set(REQUIRED_PRESERVATION) - set(preserve)
        if missing:
            raise ValueError("compression policy omits mandatory continuity categories")
        handoff = _mapping(
            data["handoff"], "handoff policy", {"mode", "triggerRatio", "createArtifact", "requireReceipt"},
        )
        if handoff["mode"] not in LIFECYCLE_MODES:
            raise ValueError("handoff mode is invalid")
        handoff_ratio = _ratio(handoff["triggerRatio"], "handoff triggerRatio")
        if handoff_ratio <= compression_ratio:
            raise ValueError("handoff triggerRatio must exceed compression triggerRatio")
        if not isinstance(handoff["createArtifact"], bool) or not isinstance(handoff["requireReceipt"], bool):
            raise ValueError("handoff artifact and receipt requirements must be boolean")
        session = _mapping(data["session"], "session policy", {"resumeOnlyWhen"})
        resume = _strings(
            session["resumeOnlyWhen"], "session resumeOnlyWhen",
            allowed=frozenset(RESUME_GUARDS), required=True,
        )
        categories = _mapping(
            data["contextCategories"], "context categories", {"included", "excluded"},
        )
        included = _strings(
            categories["included"], "included context categories", allowed=CONTEXT_CATEGORIES, required=True,
        )
        excluded = _strings(
            categories["excluded"], "excluded context categories", allowed=EXCLUDED_CATEGORIES,
        )
        if not set(preserve).issubset(included):
            raise ValueError("preserved categories must be included")
        normalized = {
            "formatVersion": POLICY_FORMAT,
            "policyId": data["policyId"],
            "budget": {"maximumInputTokens": maximum, "preferredInputTokens": preferred},
            "compression": {
                "mode": compression["mode"], "triggerRatio": compression_ratio,
                "preserve": list(preserve),
            },
            "handoff": {
                "mode": handoff["mode"], "triggerRatio": handoff_ratio,
                "createArtifact": handoff["createArtifact"], "requireReceipt": handoff["requireReceipt"],
            },
            "session": {"resumeOnlyWhen": list(resume)},
            "contextCategories": {"included": list(included), "excluded": list(excluded)},
        }
        return cls(normalized)

    @property
    def policy_id(self) -> str:
        return str(self._value["policyId"])


class EffectiveContextPolicy(_Contract):
    @property
    def maximum_input_tokens(self) -> int:
        return int(self._value["budget"]["maximumInputTokens"])

    @property
    def compression_mode(self) -> str:
        return str(self._value["compression"]["mode"])

    @property
    def compression_trigger_ratio(self) -> float:
        return float(self._value["compression"]["triggerRatio"])

    @property
    def handoff_mode(self) -> str:
        return str(self._value["handoff"]["mode"])

    @property
    def handoff_trigger_ratio(self) -> float:
        return float(self._value["handoff"]["triggerRatio"])


def resolve_effective_policy(
    layers: Sequence[tuple[str, ContextLifecyclePolicy]],
) -> EffectiveContextPolicy:
    """Resolve the most restrictive compatible value from every supplied layer."""

    if not layers or len(layers) > len(POLICY_SCOPES):
        raise ValueError("effective context policy requires bounded policy layers")
    scopes = [scope for scope, _ in layers]
    if len(set(scopes)) != len(scopes) or any(scope not in POLICY_SCOPES for scope in scopes):
        raise ValueError("context policy layer scopes must be unique and recognized")
    if any(not isinstance(policy, ContextLifecyclePolicy) for _, policy in layers):
        raise TypeError("context policy layers must contain validated policies")
    values = [(scope, policy.to_dict()) for scope, policy in layers]
    maximum = min(item["budget"]["maximumInputTokens"] for _, item in values)
    preferred = min(maximum, *(item["budget"]["preferredInputTokens"] for _, item in values))
    compression_mode = max(
        (item["compression"]["mode"] for _, item in values),
        key=lambda mode: MODE_RESTRICTIVENESS[mode],
    )
    handoff_mode = max(
        (item["handoff"]["mode"] for _, item in values),
        key=lambda mode: MODE_RESTRICTIVENESS[mode],
    )
    compression_ratio = min(item["compression"]["triggerRatio"] for _, item in values)
    handoff_ratio = min(item["handoff"]["triggerRatio"] for _, item in values)
    if handoff_ratio <= compression_ratio:
        handoff_ratio = min(0.99, round(compression_ratio + 0.01, 4))
    preserve = tuple(
        category for category in CONTEXT_CATEGORY_ORDER
        if any(category in item["compression"]["preserve"] for _, item in values)
    )
    included_sets = [set(item["contextCategories"]["included"]) for _, item in values]
    included = set.intersection(*included_sets)
    excluded = set().union(*(item["contextCategories"]["excluded"] for _, item in values))
    if not set(REQUIRED_PRESERVATION).issubset(included):
        raise ValueError("effective context policy would discard mandatory continuity")
    resume = tuple(
        guard for guard in RESUME_GUARDS
        if any(guard in item["session"]["resumeOnlyWhen"] for _, item in values)
    )

    def binding(path: tuple[str, str], selected: Any) -> list[str]:
        return [scope for scope, item in values if item[path[0]][path[1]] == selected]

    ordered_included = [category for category in CONTEXT_CATEGORY_ORDER if category in included]
    ordered_excluded = [category for category in EXCLUDED_CATEGORY_ORDER if category in excluded]
    preferred_reasons = binding(("budget", "preferredInputTokens"), preferred)
    if not preferred_reasons:
        preferred_reasons = binding(("budget", "maximumInputTokens"), maximum)
    handoff_ratio_reasons = binding(("handoff", "triggerRatio"), handoff_ratio)
    if not handoff_ratio_reasons:
        handoff_ratio_reasons = ["derived_compatibility_floor"]
    result = {
        "formatVersion": EFFECTIVE_POLICY_FORMAT,
        "sourcePolicies": [
            {"scope": scope, "policyId": policy.policy_id, "digest": policy.digest}
            for scope, policy in layers
        ],
        "unresolvedPolicyScopes": [scope for scope in POLICY_SCOPES if scope not in scopes],
        "budget": {"maximumInputTokens": maximum, "preferredInputTokens": preferred},
        "compression": {
            "mode": compression_mode, "triggerRatio": compression_ratio,
            "preserve": list(preserve),
        },
        "handoff": {
            "mode": handoff_mode,
            "triggerRatio": handoff_ratio,
            "createArtifact": all(item["handoff"]["createArtifact"] for _, item in values),
            "requireReceipt": any(item["handoff"]["requireReceipt"] for _, item in values),
        },
        "session": {"resumeOnlyWhen": list(resume)},
        "contextCategories": {"included": ordered_included, "excluded": ordered_excluded},
        "bindingReasons": {
            "budget.maximumInputTokens": binding(("budget", "maximumInputTokens"), maximum),
            "budget.preferredInputTokens": preferred_reasons,
            "compression.mode": binding(("compression", "mode"), compression_mode),
            "compression.triggerRatio": binding(("compression", "triggerRatio"), compression_ratio),
            "handoff.mode": binding(("handoff", "mode"), handoff_mode),
            "handoff.triggerRatio": handoff_ratio_reasons,
        },
        "authorityClassification": "operational_noncanonical",
        "canonicalStateMutation": False,
    }
    result["effectivePolicyDigest"] = canonical_digest(result)
    return EffectiveContextPolicy(result)


def preference_policy(base: ContextLifecyclePolicy, mode: str) -> ContextLifecyclePolicy:
    """Map understandable product modes to bounded candidate preferences."""

    if mode not in PREFERENCE_MODES:
        raise ValueError("context preference mode is invalid")
    value = base.to_dict()
    value["policyId"] = f"preference.{mode}"
    candidates = {
        "faster": {"maximum": 64_000, "preferred": 36_000, "compression": 0.62, "handoff": 0.82},
        "balanced": {
            "maximum": value["budget"]["maximumInputTokens"],
            "preferred": value["budget"]["preferredInputTokens"],
            "compression": value["compression"]["triggerRatio"],
            "handoff": value["handoff"]["triggerRatio"],
        },
        "deeper": {"maximum": 160_000, "preferred": 100_000, "compression": 0.80, "handoff": 0.92},
    }
    selected = candidates[mode]
    value["budget"] = {
        "maximumInputTokens": selected["maximum"],
        "preferredInputTokens": selected["preferred"],
    }
    value["compression"]["triggerRatio"] = selected["compression"]
    value["handoff"]["triggerRatio"] = selected["handoff"]
    return ContextLifecyclePolicy.from_dict(value)


@dataclass(frozen=True)
class TokenUsage:
    input_tokens: int | None
    quality: str
    source: str

    @classmethod
    def from_dict(cls, value: Any) -> "TokenUsage":
        data = _mapping(value, "context usage", {"formatVersion", "inputTokens", "quality", "source"})
        if data["formatVersion"] != USAGE_FORMAT:
            raise ValueError("context usage has an invalid formatVersion")
        if data["quality"] not in {"observed", "estimated", "unavailable"}:
            raise ValueError("context usage quality is invalid")
        source_by_quality = {
            "observed": "provider_reported",
            "estimated": "stateport_estimator",
            "unavailable": "unavailable",
        }
        if data["source"] != source_by_quality[data["quality"]]:
            raise ValueError("context usage source does not match accounting quality")
        if data["quality"] == "unavailable":
            if data["inputTokens"] is not None:
                raise ValueError("unavailable token usage may not claim a value")
            tokens = None
        else:
            tokens = _integer(data["inputTokens"], "inputTokens", minimum=0, maximum=2_000_000)
        return cls(tokens, data["quality"], data["source"])

    def to_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": USAGE_FORMAT,
            "inputTokens": self.input_tokens,
            "quality": self.quality,
            "source": self.source,
        }

    def ratio(self, maximum_input_tokens: int) -> float | None:
        if self.input_tokens is None:
            return None
        return self.input_tokens / maximum_input_tokens


class ContinuityState(_Contract):
    """The exact bounded facts which compression and handoff must preserve."""

    @classmethod
    def from_dict(cls, value: Any) -> "ContinuityState":
        required = {
            "formatVersion", "conversationId", "workstreamId", "instanceId",
            "runtimeProfile", "baseSha", "contextManifest", "activeTask",
            "requirements", "completedWork", "pendingWork", "decisions", "approvals",
            "unresolvedRisks", "exactGitIdentity", "acceptanceCriteria", "validationState",
            "relevantStateReferences", "recentReceipts", "nextAction",
        }
        data = _mapping(value, "continuity state", required)
        if data["formatVersion"] != CONTINUITY_FORMAT:
            raise ValueError("continuity state has an invalid formatVersion")
        for key in ("conversationId", "workstreamId", "instanceId"):
            _identifier(data[key], key)
        runtime = _mapping(data["runtimeProfile"], "runtime profile identity", {"id", "digest"})
        _identifier(runtime["id"], "runtime profile id")
        _digest(runtime["digest"], "runtime profile digest")
        base_sha = _git_sha(data["baseSha"], "baseSha")
        manifest = _mapping(
            data["contextManifest"], "context manifest identity",
            {"contextId", "digest", "compiledAt", "freshUntil", "provenanceDigest"},
        )
        _identifier(manifest["contextId"], "context manifest id")
        _digest(manifest["digest"], "context manifest digest")
        _digest(manifest["provenanceDigest"], "context manifest provenance digest")
        compiled_at = _timestamp(manifest["compiledAt"], "context compiledAt")
        fresh_until = _timestamp(manifest["freshUntil"], "context freshUntil")
        if _timestamp_value(fresh_until) <= _timestamp_value(compiled_at):
            raise ValueError("context manifest freshness window is invalid")
        git = _mapping(
            data["exactGitIdentity"], "exact Git identity",
            {"repositoryId", "branch", "baseSha", "headSha", "treeSha", "worktreeStatusDigest", "worktreeClean"},
        )
        _identifier(git["repositoryId"], "repository id")
        if not isinstance(git["branch"], str) or _BRANCH.fullmatch(git["branch"]) is None or ".." in git["branch"]:
            raise ValueError("Git branch identity is invalid")
        git_base = _git_sha(git["baseSha"], "Git base SHA")
        _git_sha(git["headSha"], "Git head SHA")
        _git_sha(git["treeSha"], "Git tree SHA")
        _digest(git["worktreeStatusDigest"], "worktree status digest")
        if not isinstance(git["worktreeClean"], bool):
            raise ValueError("worktreeClean must be boolean")
        if git_base != base_sha:
            raise ValueError("continuity base SHA and Git base SHA differ")
        state_references = data["relevantStateReferences"]
        if not isinstance(state_references, list) or len(state_references) > 64:
            raise ValueError("relevant state references must be bounded")
        normalized_references: list[dict[str, str]] = []
        for reference in state_references:
            item = _mapping(reference, "state reference", {"id", "digest", "authority"})
            _identifier(item["id"], "state reference id")
            _digest(item["digest"], "state reference digest")
            if item["authority"] not in {"canonical", "generated", "external"}:
                raise ValueError("state reference authority is invalid")
            normalized_references.append(dict(item))
        if len({item["id"] for item in normalized_references}) != len(normalized_references):
            raise ValueError("state reference ids must be unique")
        receipts = _strings(data["recentReceipts"], "recent receipts", maximum_text=71)
        for receipt in receipts:
            _digest(receipt, "recent receipt")
        normalized = {
            "formatVersion": CONTINUITY_FORMAT,
            "conversationId": data["conversationId"],
            "workstreamId": data["workstreamId"],
            "instanceId": data["instanceId"],
            "runtimeProfile": dict(runtime),
            "baseSha": base_sha,
            "contextManifest": {
                **dict(manifest), "compiledAt": compiled_at, "freshUntil": fresh_until,
            },
            "activeTask": _text(data["activeTask"], "active task"),
            "requirements": list(_strings(data["requirements"], "requirements", required=True)),
            "completedWork": list(_strings(data["completedWork"], "completed work")),
            "pendingWork": list(_strings(data["pendingWork"], "pending work")),
            "decisions": list(_strings(data["decisions"], "decisions")),
            "approvals": list(_strings(data["approvals"], "approvals")),
            "unresolvedRisks": list(_strings(data["unresolvedRisks"], "unresolved risks")),
            "exactGitIdentity": dict(git),
            "acceptanceCriteria": list(_strings(data["acceptanceCriteria"], "acceptance criteria", required=True)),
            "validationState": list(_strings(data["validationState"], "validation state", required=True)),
            "relevantStateReferences": normalized_references,
            "recentReceipts": list(receipts),
            "nextAction": _text(data["nextAction"], "next action"),
        }
        return cls(normalized)

    @property
    def conversation_id(self) -> str:
        return str(self._value["conversationId"])

    @property
    def workstream_id(self) -> str:
        return str(self._value["workstreamId"])

    @property
    def instance_id(self) -> str:
        return str(self._value["instanceId"])


def _integrity_contract(value: Any, label: str, format_version: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or value.get("formatVersion") != format_version:
        raise ValueError(f"{label} has an invalid formatVersion")
    if value.get("authorityClassification") != "ephemeral_noncanonical" or value.get("canonicalStateMutation") is not False:
        raise ValueError(f"{label} may not claim canonical authority")
    digest = _digest(value.get("artifactDigest"), f"{label} digest")
    unsigned = dict(value)
    unsigned.pop("artifactDigest", None)
    if canonical_digest(unsigned) != digest:
        raise ValueError(f"{label} digest does not match its payload")
    return value


class CompressionArtifact(_Contract):
    @classmethod
    def from_dict(cls, value: Any) -> "CompressionArtifact":
        data = _integrity_contract(value, "compression artifact", COMPRESSION_FORMAT)
        required = {
            "formatVersion", "artifactId", "artifactDigest", "conversationId", "workstreamId",
            "instanceId", "createdAt", "trigger", "usage", "policyDigest",
            "sourceContinuityDigest", "preserved", "authorityClassification", "canonicalStateMutation",
        }
        _mapping(data, "compression artifact", required)
        _identifier(data["artifactId"], "compression artifact id")
        for key in ("conversationId", "workstreamId", "instanceId"):
            _identifier(data[key], key)
        _timestamp(data["createdAt"], "compression createdAt")
        _digest(data["policyDigest"], "compression policy digest")
        _digest(data["sourceContinuityDigest"], "source continuity digest")
        continuity = ContinuityState.from_dict(data["preserved"])
        if (
            continuity.conversation_id != data["conversationId"]
            or continuity.workstream_id != data["workstreamId"]
            or continuity.instance_id != data["instanceId"]
            or continuity.digest != data["sourceContinuityDigest"]
        ):
            raise ValueError("compression identity does not match preserved continuity")
        trigger = _mapping(data["trigger"], "compression trigger", {"mode", "ratio", "threshold"})
        if trigger["mode"] not in {"automatic", "manual"}:
            raise ValueError("compression trigger mode is invalid")
        if trigger["ratio"] is not None:
            _usage_ratio(trigger["ratio"], "compression observed ratio")
        _ratio(trigger["threshold"], "compression threshold")
        TokenUsage.from_dict(data["usage"])
        return cls(dict(data))


class HandoffArtifact(_Contract):
    @classmethod
    def from_dict(cls, value: Any) -> "HandoffArtifact":
        data = _integrity_contract(value, "handoff artifact", HANDOFF_FORMAT)
        required = {
            "formatVersion", "artifactId", "artifactDigest", "conversationId", "workstreamId",
            "instanceId", "createdAt", "trigger", "usage", "policyDigest", "sourceContinuityDigest",
            "sourceCompressionDigest", "preserved", "providerSessionStrategy",
            "authorityClassification", "canonicalStateMutation",
        }
        _mapping(data, "handoff artifact", required)
        _identifier(data["artifactId"], "handoff artifact id")
        for key in ("conversationId", "workstreamId", "instanceId"):
            _identifier(data[key], key)
        _timestamp(data["createdAt"], "handoff createdAt")
        _digest(data["policyDigest"], "handoff policy digest")
        _digest(data["sourceContinuityDigest"], "source continuity digest")
        if data["sourceCompressionDigest"] is not None:
            _digest(data["sourceCompressionDigest"], "source compression digest")
        if data["providerSessionStrategy"] != "fresh_session_same_logical_conversation":
            raise ValueError("handoff provider session strategy is invalid")
        continuity = ContinuityState.from_dict(data["preserved"])
        if (
            continuity.conversation_id != data["conversationId"]
            or continuity.workstream_id != data["workstreamId"]
            or continuity.instance_id != data["instanceId"]
            or continuity.digest != data["sourceContinuityDigest"]
        ):
            raise ValueError("handoff identity does not match preserved continuity")
        trigger = _mapping(data["trigger"], "handoff trigger", {"mode", "ratio", "threshold"})
        if trigger["mode"] not in {"automatic", "manual"}:
            raise ValueError("handoff trigger mode is invalid")
        if trigger["ratio"] is not None:
            _usage_ratio(trigger["ratio"], "handoff observed ratio")
        _ratio(trigger["threshold"], "handoff threshold")
        TokenUsage.from_dict(data["usage"])
        return cls(dict(data))


def _artifact_payload(
    *,
    format_version: str,
    prefix: str,
    continuity: ContinuityState,
    usage: TokenUsage,
    policy: EffectiveContextPolicy,
    trigger: str,
    created_at: str,
    threshold: float,
) -> dict[str, Any]:
    if trigger not in {"automatic", "manual"}:
        raise ValueError("artifact trigger is invalid")
    _timestamp(created_at, "artifact createdAt")
    ratio = usage.ratio(policy.maximum_input_tokens)
    return {
        "formatVersion": format_version,
        "artifactId": f"{prefix}.{secrets.token_hex(24)}",
        "conversationId": continuity.conversation_id,
        "workstreamId": continuity.workstream_id,
        "instanceId": continuity.instance_id,
        "createdAt": created_at,
        "trigger": {"mode": trigger, "ratio": round(ratio, 6) if ratio is not None else None, "threshold": threshold},
        "usage": usage.to_dict(),
        "policyDigest": str(policy.to_dict()["effectivePolicyDigest"]),
        "sourceContinuityDigest": continuity.digest,
        "preserved": continuity.to_dict(),
        "authorityClassification": "ephemeral_noncanonical",
        "canonicalStateMutation": False,
    }


def build_compression_artifact(
    continuity: ContinuityState,
    usage: TokenUsage,
    policy: EffectiveContextPolicy,
    *,
    trigger: str,
    created_at: str,
) -> CompressionArtifact:
    value = _artifact_payload(
        format_version=COMPRESSION_FORMAT,
        prefix="compression",
        continuity=continuity,
        usage=usage,
        policy=policy,
        trigger=trigger,
        created_at=created_at,
        threshold=policy.compression_trigger_ratio,
    )
    value["artifactDigest"] = canonical_digest(value)
    return CompressionArtifact.from_dict(value)


def build_handoff_artifact(
    continuity: ContinuityState,
    usage: TokenUsage,
    policy: EffectiveContextPolicy,
    *,
    trigger: str,
    created_at: str,
    source_compression_digest: str | None = None,
) -> HandoffArtifact:
    if source_compression_digest is not None:
        _digest(source_compression_digest, "source compression digest")
    value = _artifact_payload(
        format_version=HANDOFF_FORMAT,
        prefix="handoff",
        continuity=continuity,
        usage=usage,
        policy=policy,
        trigger=trigger,
        created_at=created_at,
        threshold=policy.handoff_trigger_ratio,
    )
    value["sourceCompressionDigest"] = source_compression_digest
    value["providerSessionStrategy"] = "fresh_session_same_logical_conversation"
    value["artifactDigest"] = canonical_digest(value)
    return HandoffArtifact.from_dict(value)


def compression_due(usage: TokenUsage, policy: EffectiveContextPolicy) -> bool:
    ratio = usage.ratio(policy.maximum_input_tokens)
    return policy.compression_mode == "automatic" and ratio is not None and ratio >= policy.compression_trigger_ratio


def handoff_due(usage: TokenUsage, policy: EffectiveContextPolicy) -> bool:
    ratio = usage.ratio(policy.maximum_input_tokens)
    return policy.handoff_mode == "automatic" and ratio is not None and ratio >= policy.handoff_trigger_ratio


@dataclass(frozen=True)
class ResumeEnvironment:
    conversation_id: str
    workstream_id: str
    instance_id: str
    runtime_profile_id: str
    runtime_profile_digest: str
    base_sha: str
    head_sha: str
    tree_sha: str
    worktree_status_digest: str
    context_manifest_digest: str
    context_provenance_digest: str
    context_fresh_until: str
    observed_at: str

    @classmethod
    def from_dict(cls, value: Any) -> "ResumeEnvironment":
        required = {
            "conversationId", "workstreamId", "instanceId", "runtimeProfileId",
            "runtimeProfileDigest", "baseSha", "headSha", "treeSha", "worktreeStatusDigest",
            "contextManifestDigest", "contextProvenanceDigest", "contextFreshUntil", "observedAt",
        }
        data = _mapping(value, "resume environment", required)
        for key in ("conversationId", "workstreamId", "instanceId", "runtimeProfileId"):
            _identifier(data[key], key)
        for key in ("runtimeProfileDigest", "worktreeStatusDigest", "contextManifestDigest", "contextProvenanceDigest"):
            _digest(data[key], key)
        for key in ("baseSha", "headSha", "treeSha"):
            _git_sha(data[key], key)
        fresh = _timestamp(data["contextFreshUntil"], "contextFreshUntil")
        observed = _timestamp(data["observedAt"], "observedAt")
        return cls(
            data["conversationId"], data["workstreamId"], data["instanceId"],
            data["runtimeProfileId"], data["runtimeProfileDigest"], data["baseSha"],
            data["headSha"], data["treeSha"], data["worktreeStatusDigest"],
            data["contextManifestDigest"], data["contextProvenanceDigest"], fresh, observed,
        )


class ResumeDecision(_Contract):
    @property
    def allowed(self) -> bool:
        return bool(self._value["allowed"])


def evaluate_resume(
    artifact: HandoffArtifact,
    environment: ResumeEnvironment,
    policy: EffectiveContextPolicy,
) -> ResumeDecision:
    """Fail closed on any configured continuity guard or provenance drift."""

    handoff = artifact.to_dict()
    continuity = handoff["preserved"]
    git = continuity["exactGitIdentity"]
    manifest = continuity["contextManifest"]
    reasons: list[str] = []
    if environment.conversation_id != continuity["conversationId"]:
        reasons.append("logical_conversation_changed")
    guards = set(policy.to_dict()["session"]["resumeOnlyWhen"])
    if "same_instance" in guards and environment.instance_id != continuity["instanceId"]:
        reasons.append("instance_changed")
    if "same_workstream" in guards and environment.workstream_id != continuity["workstreamId"]:
        reasons.append("workstream_changed")
    if "compatible_runtime_profile" in guards and (
        environment.runtime_profile_id != continuity["runtimeProfile"]["id"]
        or environment.runtime_profile_digest != continuity["runtimeProfile"]["digest"]
    ):
        reasons.append("runtime_profile_incompatible")
    if "unchanged_base_snapshot" in guards and (
        environment.base_sha != continuity["baseSha"]
        or environment.head_sha != git["headSha"]
        or environment.tree_sha != git["treeSha"]
        or environment.worktree_status_digest != git["worktreeStatusDigest"]
    ):
        reasons.append("base_snapshot_changed")
    if "fresh_context_manifest" in guards:
        if (
            environment.context_manifest_digest != manifest["digest"]
            or environment.context_provenance_digest != manifest["provenanceDigest"]
        ):
            reasons.append("context_manifest_changed")
        if (
            _timestamp_value(environment.observed_at) >= _timestamp_value(environment.context_fresh_until)
            or _timestamp_value(environment.observed_at) >= _timestamp_value(manifest["freshUntil"])
        ):
            reasons.append("context_manifest_stale")
    value = {
        "formatVersion": RESUME_DECISION_FORMAT,
        "artifactDigest": handoff["artifactDigest"],
        "conversationId": continuity["conversationId"],
        "allowed": not reasons,
        "reasonCodes": reasons,
        "providerSessionAction": "resume" if not reasons else "fresh_context_required",
        "logicalConversationPreserved": environment.conversation_id == continuity["conversationId"],
        "canonicalStateMutation": False,
    }
    return ResumeDecision(value)


class ContextLifecycleReceipt(_Contract):
    @classmethod
    def create(
        cls,
        *,
        action: str,
        outcome: str,
        actor_id: str,
        instance_id: str,
        conversation_id: str,
        workstream_id: str,
        policy_digest: str,
        input_provenance_digest: str,
        artifact_digest: str | None,
        reason_codes: Sequence[str],
        occurred_at: str,
    ) -> "ContextLifecycleReceipt":
        if action not in {"compression", "handoff", "resume"}:
            raise ValueError("context lifecycle receipt action is invalid")
        if outcome not in {"completed", "refused"}:
            raise ValueError("context lifecycle receipt outcome is invalid")
        for value, label in (
            (actor_id, "actor id"), (instance_id, "instance id"),
            (conversation_id, "conversation id"), (workstream_id, "workstream id"),
        ):
            _identifier(value, label)
        _digest(policy_digest, "receipt policy digest")
        _digest(input_provenance_digest, "receipt input provenance digest")
        if artifact_digest is not None:
            _digest(artifact_digest, "receipt artifact digest")
        reasons = tuple(_identifier(item, "receipt reason code") for item in reason_codes)
        _timestamp(occurred_at, "receipt occurredAt")
        value = {
            "formatVersion": RECEIPT_FORMAT,
            "receiptId": f"context-receipt.{secrets.token_hex(24)}",
            "action": action,
            "outcome": outcome,
            "actorId": actor_id,
            "instanceId": instance_id,
            "conversationId": conversation_id,
            "workstreamId": workstream_id,
            "policyDigest": policy_digest,
            "inputProvenanceDigest": input_provenance_digest,
            "artifactDigest": artifact_digest,
            "reasonCodes": list(reasons),
            "occurredAt": occurred_at,
            "authorityClassification": "operational_noncanonical",
            "canonicalStateMutation": False,
            "transcriptRetained": False,
        }
        value["receiptDigest"] = canonical_digest(value)
        return cls(value)
