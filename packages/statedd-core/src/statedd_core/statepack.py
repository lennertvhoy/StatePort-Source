"""Deterministic, disposable StatePack context generation.

StatePack is derived working context.  It is deliberately not a source of
truth: the StateIR source identity and hashes are carried in every manifest so
that a caller can always relate a generated pack back to canonical state.
"""

from __future__ import annotations

import dataclasses
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence

from statedd_core.stateir import StateFact, StateIR


STATEPACK_FORMAT = "statepack/v1"
_PROFILES = {"human", "compact", "ultra", "audit", "task"}
_SELECTIONS = {"eager", "compact_context", "modular"}
_REQUIRED_MANIFEST_FIELDS = {
    "formatVersion",
    "instanceId",
    "sourceRevision",
    "sourceHashes",
    "generatedFor",
    "budgetTokens",
    "profile",
    "selection",
    "includedFiles",
    "excludedFiles",
    "includedFacts",
    "excludedFacts",
    "lossiness",
    "truncationStatus",
    "tokenMeasurement",
}
_WORD_RE = re.compile(r"[a-z0-9]+")
_METADATA_TERMS = {
    "created",
    "id",
    "identity",
    "instance",
    "kind",
    "metadata",
    "name",
    "owner",
    "revision",
    "source",
    "status",
    "template",
    "type",
    "version",
}
_MISSING = object()


class TokenCounter(Protocol):
    """Callable shape for model-specific token counters."""

    def __call__(self, text: str) -> int:
        """Return the number of tokens in ``text``."""


def _whitespace_token_counter(text: str) -> int:
    """Return a deterministic approximate whitespace token count.

    This is intentionally not presented as model tokenization.  It is a
    stable fallback for local inspection and tests when no model tokenizer is
    configured.
    """

    return len(text.split())


DEFAULT_TOKENIZER_ID = "whitespace-v1"


@dataclass(frozen=True)
class StatePack:
    """A generated task/model-specific context pack."""

    manifest: dict[str, Any]
    text: str

    def to_dict(self) -> dict[str, Any]:
        """Return the wire representation without changing the pack."""

        return {"manifest": self.manifest, "text": self.text}


@dataclass(frozen=True)
class _FactView:
    fact: StateFact
    path: str
    value: Any
    source_file: str | None
    order: int


def _read(value: Any, *names: str, default: Any = _MISSING) -> Any:
    if isinstance(value, Mapping):
        for name in names:
            if name in value:
                return value[name]
    else:
        for name in names:
            if hasattr(value, name):
                return getattr(value, name)
    if default is not _MISSING:
        return default
    joined = ", ".join(names)
    raise ValueError(f"missing required StateIR field: {joined}")


def _non_empty_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _canonical_value(value: Any) -> str:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        value = dataclasses.asdict(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _source_file(fact: Any) -> str | None:
    source = _read(
        fact,
        "source_file",
        "sourceFile",
        "source_path",
        "sourcePath",
        "file",
        default=None,
    )
    if source is None:
        source = _read(fact, "source", default=None)
        if isinstance(source, Mapping):
            source = _read(source, "file", "path", "source_file", default=None)
    if source is None:
        return None
    return str(source)


def _fact_provenance(view: _FactView) -> dict[str, Any]:
    """Return source metadata for one fact without copying its value.

    Values are intentionally absent: a StatePack already contains the selected
    value in its text, while the manifest only needs enough information to
    trace that value back to canonical StateDD source.
    """

    fact_id = _read(view.fact, "id", default=None)
    source = _read(view.fact, "source", default=None)
    if dataclasses.is_dataclass(source) and not isinstance(source, type):
        source = dataclasses.asdict(source)
    elif isinstance(source, Mapping):
        source = dict(source)
    return {
        "id": str(fact_id) if fact_id is not None else None,
        "path": view.path,
        "sourceFile": view.source_file,
        "sensitivity": _read(view.fact, "sensitivity", default=None),
        "lossiness": _read(view.fact, "lossiness", default=None),
        "source": source,
    }


def _fact_views(ir: StateIR) -> list[_FactView]:
    raw_facts = _read(ir, "facts", default=None)
    if raw_facts is None:
        raise ValueError("StateIR.facts is required")
    if isinstance(raw_facts, (str, bytes)):
        raise ValueError("StateIR.facts must be a sequence of StateFact values")

    views: list[_FactView] = []
    for order, fact in enumerate(raw_facts):
        path = _read(fact, "path", "key", "name", default=None)
        if path is None:
            raise ValueError("StateFact.path is required")
        value = _read(fact, "value", default=None)
        views.append(
            _FactView(
                fact=fact,
                path=str(path),
                value=value,
                source_file=_source_file(fact),
                order=order,
            )
        )
    return views


def _source_data(ir: StateIR) -> tuple[str, str, dict[str, Any]]:
    instance_id = _non_empty_string(
        _read(ir, "instance_id", "instanceId", "id"), "instanceId"
    )
    source_revision = _non_empty_string(
        _read(ir, "source_revision", "sourceRevision", "revision"),
        "sourceRevision",
    )
    source_hashes = _read(ir, "source_hashes", "sourceHashes", default={})
    if not isinstance(source_hashes, Mapping):
        raise ValueError("StateIR.source_hashes must be a mapping")
    normalized = {str(key): value for key, value in source_hashes.items()}
    return instance_id, source_revision, dict(sorted(normalized.items()))


def _all_source_files(ir: StateIR, facts: Sequence[_FactView], source_hashes: Mapping[str, Any]) -> list[str]:
    files: set[str] = set(str(path) for path in source_hashes)
    raw_files = _read(ir, "files", "source_files", "sourceFiles", default=[])
    if isinstance(raw_files, Mapping):
        files.update(str(path) for path in raw_files)
    elif not isinstance(raw_files, (str, bytes)):
        for raw_file in raw_files:
            if isinstance(raw_file, Mapping):
                path = _read(raw_file, "path", "file", "source_file", default=None)
            else:
                path = raw_file
            if path is not None:
                files.add(str(path))
    files.update(view.source_file for view in facts if view.source_file is not None)
    return sorted(files)


def _terms(value: Any) -> set[str]:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        value = dataclasses.asdict(value)
    if isinstance(value, Mapping):
        text = " ".join(f"{key} {item}" for key, item in value.items())
    elif isinstance(value, (list, tuple, set)):
        text = " ".join(str(item) for item in value)
    else:
        text = str(value)
    return set(_WORD_RE.findall(text.casefold()))


def _metadata_like(view: _FactView) -> bool:
    path_terms = _terms(view.path)
    return bool(path_terms & _METADATA_TERMS)


def _rank_task_facts(facts: Sequence[_FactView], task: str) -> list[_FactView]:
    task_terms = _terms(task)
    scored = []
    for view in facts:
        overlap = len(task_terms & (_terms(view.path) | _terms(view.value)))
        if overlap:
            scored.append((overlap, view))
    if not scored:
        scored = [(0, view) for view in facts if _metadata_like(view)]
    return [
        view
        for _, view in sorted(
            scored,
            key=lambda item: (-item[0], item[1].path, item[1].source_file or "", item[1].order),
        )
    ]


def _stable_fact_order(facts: Sequence[_FactView]) -> list[_FactView]:
    return sorted(facts, key=lambda view: (view.path, view.source_file or "", view.order))


def _render_fact(view: _FactView, profile: str) -> str:
    value = _canonical_value(view.value)
    if profile in {"human", "audit"}:
        return f"{view.path} = {value}"
    if profile == "ultra":
        return json.dumps(
            {"p": view.path, "v": view.value},
            ensure_ascii=False,
            sort_keys=False,
            separators=(",", ":"),
        )
    return json.dumps(
        {"path": view.path, "value": view.value},
        ensure_ascii=False,
        sort_keys=False,
        separators=(",", ":"),
    )


def _render(facts: Sequence[_FactView], profile: str) -> str:
    return "\n".join(_render_fact(view, profile) for view in facts)


def _bounded_facts(
    candidates: Sequence[_FactView],
    profile: str,
    budget_tokens: int,
    counter: TokenCounter,
) -> list[_FactView]:
    included: list[_FactView] = []
    for candidate in candidates:
        proposed = included + [candidate]
        if _measure_tokens(counter, _render(proposed, profile)) <= budget_tokens:
            included.append(candidate)
    return included


def _measure_tokens(counter: TokenCounter, text: str) -> int:
    """Call a tokenizer callback and fail closed on an invalid measurement."""

    count = counter(text)
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise ValueError("token_counter must return a non-negative integer")
    return count


def build_state_pack(
    ir: StateIR,
    task: str,
    model: str,
    budget_tokens: int,
    profile: str = "compact",
    selection: str = "eager",
    token_counter: TokenCounter | None = None,
    tokenizer_id: str | None = None,
) -> StatePack:
    """Compile exact StateIR facts into a deterministic disposable pack."""

    task = _non_empty_string(task, "task")
    model = _non_empty_string(model, "model")
    if isinstance(budget_tokens, bool) or not isinstance(budget_tokens, int) or budget_tokens <= 0:
        raise ValueError("budget_tokens must be a positive integer")
    if profile not in _PROFILES:
        raise ValueError(f"profile must be one of {sorted(_PROFILES)}")
    if selection not in _SELECTIONS:
        raise ValueError(f"selection must be one of {sorted(_SELECTIONS)}")
    if token_counter is not None and not tokenizer_id:
        raise ValueError("tokenizer_id is required when token_counter is supplied")
    if tokenizer_id is not None and (
        not isinstance(tokenizer_id, str) or not tokenizer_id.strip()
    ):
        raise ValueError("tokenizer_id must be a non-empty string")

    instance_id, source_revision, source_hashes = _source_data(ir)
    facts = _fact_views(ir)
    all_files = _all_source_files(ir, facts, source_hashes)

    if selection == "eager":
        candidates = _stable_fact_order(facts)
        selection_policy = "all-facts"
    else:
        candidates = _rank_task_facts(facts, task)
        selection_policy = "normalized-task-term-overlap-with-metadata-fallback"
    counter = token_counter or _whitespace_token_counter
    included = _bounded_facts(candidates, profile, budget_tokens, counter)
    included_ids = {id(view) for view in included}
    excluded = [view for view in facts if id(view) not in included_ids]
    budget_truncated = len(included) < len(candidates)
    text = _render(included, profile)
    token_count = _measure_tokens(counter, text)

    included_files = sorted(
        {view.source_file for view in included if view.source_file is not None}
    )
    excluded_files = sorted(set(all_files) - set(included_files))
    included_fact_names = [view.path for view in included]
    excluded_fact_names = [view.path for view in excluded]
    manifest: dict[str, Any] = {
        "formatVersion": STATEPACK_FORMAT,
        "instanceId": instance_id,
        "sourceRevision": source_revision,
        "sourceHashes": source_hashes,
        "sourceStale": bool(_read(ir, "stale", default=False)),
        "generatedFor": {"task": task, "model": model},
        "budgetTokens": budget_tokens,
        "profile": profile,
        "selection": selection,
        "selectionPolicy": selection_policy,
        "includedFiles": included_files,
        "excludedFiles": excluded_files,
        "includedFacts": included_fact_names,
        "excludedFacts": excluded_fact_names,
        "factProvenance": [_fact_provenance(view) for view in included],
        "lossiness": "lossless",
        "truncationStatus": {
            "truncated": budget_truncated,
            "reason": "budget" if budget_truncated else None,
            "selectedFactCount": len(candidates),
            "includedFactCount": len(included),
            "excludedFactCount": len(excluded),
        },
        "tokenMeasurement": {
            "tokenizerId": tokenizer_id or DEFAULT_TOKENIZER_ID,
            "tokenCount": token_count,
            "exact": token_counter is not None,
        },
    }
    return StatePack(manifest=manifest, text=text)


def _pack_parts(pack: StatePack | Mapping[str, Any]) -> tuple[Mapping[str, Any], str]:
    if isinstance(pack, StatePack):
        return pack.manifest, pack.text
    if not isinstance(pack, Mapping):
        raise TypeError("pack must be a StatePack or mapping")
    manifest = pack.get("manifest")
    text = pack.get("text")
    if not isinstance(manifest, Mapping) or not isinstance(text, str):
        raise ValueError("pack must contain a manifest mapping and text string")
    return manifest, text


def inspect_state_pack(pack: StatePack | Mapping[str, Any]) -> dict[str, Any]:
    """Validate the manifest shape without changing the supplied pack.

    A current StateIR is not an argument to this API, so source freshness is
    not re-hashed here.  ``stale`` therefore reports only the shape-level
    stale condition (a missing source revision); callers comparing against a
    current IR should compare source identities before using the pack.
    """

    try:
        manifest, text = _pack_parts(pack)
    except (TypeError, ValueError) as exc:
        return {"valid": False, "stale": True, "shape": "invalid", "errors": [str(exc)]}

    errors: list[str] = []
    missing = sorted(_REQUIRED_MANIFEST_FIELDS - set(manifest))
    if missing:
        errors.append(f"missing manifest fields: {', '.join(missing)}")
    if manifest.get("formatVersion") != STATEPACK_FORMAT:
        errors.append(f"formatVersion must be {STATEPACK_FORMAT!r}")
    for field in ("instanceId", "sourceRevision", "lossiness"):
        if field in manifest and (not isinstance(manifest[field], str) or not manifest[field]):
            errors.append(f"{field} must be a non-empty string")
    if "budgetTokens" in manifest and (
        isinstance(manifest["budgetTokens"], bool)
        or not isinstance(manifest["budgetTokens"], int)
        or manifest["budgetTokens"] <= 0
    ):
        errors.append("budgetTokens must be a positive integer")
    if "profile" in manifest and manifest["profile"] not in _PROFILES:
        errors.append("profile is not supported")
    if "selection" in manifest and manifest["selection"] not in _SELECTIONS:
        errors.append("selection is not supported")
    if "generatedFor" in manifest:
        generated_for = manifest["generatedFor"]
        if not isinstance(generated_for, Mapping) or not all(
            isinstance(generated_for.get(field), str) and generated_for.get(field).strip()
            for field in ("task", "model")
        ):
            errors.append("generatedFor must contain non-empty task and model")
    if "sourceHashes" in manifest and not isinstance(manifest["sourceHashes"], Mapping):
        errors.append("sourceHashes must be a mapping")
    for field in ("includedFiles", "excludedFiles", "includedFacts", "excludedFacts"):
        if field in manifest and (
            not isinstance(manifest[field], list)
            or any(not isinstance(item, str) for item in manifest[field])
        ):
            errors.append(f"{field} must be a list of strings")
    provenance = manifest.get("factProvenance")
    if provenance is not None and (
        not isinstance(provenance, list)
        or any(not isinstance(item, Mapping) for item in provenance)
    ):
        errors.append("factProvenance must be a list of mappings")
    measurement = manifest.get("tokenMeasurement")
    if not isinstance(measurement, Mapping):
        errors.append("tokenMeasurement must be a mapping")
    else:
        if not isinstance(measurement.get("tokenizerId"), str) or not measurement.get("tokenizerId"):
            errors.append("tokenMeasurement.tokenizerId must be a non-empty string")
        if isinstance(measurement.get("tokenCount"), bool) or not isinstance(
            measurement.get("tokenCount"), int
        ) or measurement.get("tokenCount") < 0:
            errors.append("tokenMeasurement.tokenCount must be a non-negative integer")
        if not isinstance(measurement.get("exact"), bool):
            errors.append("tokenMeasurement.exact must be a boolean")
    if not isinstance(manifest.get("truncationStatus"), Mapping):
        errors.append("truncationStatus must be a mapping")

    stale = bool(manifest.get("sourceStale")) or not isinstance(manifest.get("sourceRevision"), str) or not manifest.get("sourceRevision")
    return {
        "valid": not errors,
        "stale": stale,
        "shape": "valid" if not errors else "invalid",
        "errors": errors,
        "tokenCount": measurement.get("tokenCount") if isinstance(measurement, Mapping) else None,
        "textLength": len(text),
    }


def compare_state_packs(
    left: StatePack | Mapping[str, Any], right: StatePack | Mapping[str, Any]
) -> dict[str, Any]:
    """Compare the contract dimensions relevant to StatePack evaluation."""

    left_manifest, _ = _pack_parts(left)
    right_manifest, _ = _pack_parts(right)
    fields = (
        "instanceId",
        "sourceRevision",
        "sourceHashes",
        "sourceStale",
        "generatedFor",
        "budgetTokens",
        "profile",
        "selection",
        "selectionPolicy",
        "tokenizerId",
        "tokenExact",
        "tokenCount",
        "includedFacts",
        "excludedFacts",
        "includedFiles",
        "excludedFiles",
        "lossiness",
        "truncationStatus",
    )
    values: dict[str, dict[str, Any]] = {}
    differences: list[str] = []
    for field in fields:
        if field in {"tokenCount", "tokenizerId", "tokenExact"}:
            left_measurement = left_manifest.get("tokenMeasurement")
            right_measurement = right_manifest.get("tokenMeasurement")
            if not isinstance(left_measurement, Mapping):
                left_measurement = {}
            if not isinstance(right_measurement, Mapping):
                right_measurement = {}
            measurement_field = {
                "tokenCount": "tokenCount",
                "tokenizerId": "tokenizerId",
                "tokenExact": "exact",
            }[field]
            left_value = left_measurement.get(measurement_field)
            right_value = right_measurement.get(measurement_field)
        else:
            left_value = left_manifest.get(field)
            right_value = right_manifest.get(field)
        equal = left_value == right_value
        values[field] = {"left": left_value, "right": right_value, "equal": equal}
        if not equal:
            differences.append(field)
    return {"equal": not differences, "differences": differences, **values}


__all__ = [
    "DEFAULT_TOKENIZER_ID",
    "STATEPACK_FORMAT",
    "StatePack",
    "TokenCounter",
    "build_state_pack",
    "compare_state_packs",
    "inspect_state_pack",
]
