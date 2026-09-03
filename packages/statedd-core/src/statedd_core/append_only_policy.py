"""Fail-closed policy helpers for append-only instance state.

Append-only state is deliberately modelled as a transaction over an immutable
record prefix.  A caller may append one registered migration marker, but may
not rewrite, insert, remove, or reclassify an existing record.  The helpers
return data instead of writing files so a lifecycle transaction can stage the
result and keep the live instance untouched until validation succeeds.
"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Mapping, Sequence

from statedd_core.lifecycle_errors import LifecycleError


APPEND_ONLY_POLICY_FORMAT = "statedd.append-only-policy/v1"
MIGRATION_MARKER_FORMAT = "statedd.migration-marker/v1"
APPEND_ONLY_ROLLBACK_MODE = "transactional_snapshot"
MIGRATION_MARKER_TYPE = "migration_marker"
SENSITIVITIES = {"public", "internal", "private", "secret"}


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LifecycleError(f"{label} must be a non-empty string")
    return value


def _policy_path(value: Any) -> str:
    path = _string(value, "path")
    parsed = PurePosixPath(path)
    if (
        parsed.is_absolute()
        or "\\" in path
        or path != parsed.as_posix()
        or any(part in {"", ".", ".."} for part in parsed.parts)
        or parsed.parts[0] in {".git", ".statedd", ".stateport"}
    ):
        raise LifecycleError("append-only path must be a safe relative data path")
    return path


def _json_copy(value: Any, label: str) -> Any:
    """Copy JSON-shaped data and reject values with unstable representations."""
    try:
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise LifecycleError(f"{label} must contain JSON-compatible data") from exc
    return copy.deepcopy(value)


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class MigrationMarker:
    """One migration marker that an append-only policy explicitly permits."""

    marker_id: str
    source_schema: str
    target_schema: str
    sensitivity: str

    def __post_init__(self) -> None:
        _string(self.marker_id, "marker_id")
        _string(self.source_schema, "source_schema")
        _string(self.target_schema, "target_schema")
        if not isinstance(self.sensitivity, str) or self.sensitivity not in SENSITIVITIES:
            raise LifecycleError("marker sensitivity is invalid")
        if self.source_schema == self.target_schema:
            raise LifecycleError("migration marker must change schema")

    @property
    def record_id(self) -> str:
        return f"migration:{self.marker_id}"

    def as_record(self) -> dict[str, str]:
        """Return the canonical record appended for this registered marker."""
        return {
            "formatVersion": MIGRATION_MARKER_FORMAT,
            "recordId": self.record_id,
            "recordType": MIGRATION_MARKER_TYPE,
            "markerId": self.marker_id,
            "sourceSchema": self.source_schema,
            "targetSchema": self.target_schema,
            "sensitivity": self.sensitivity,
        }


@dataclass(frozen=True)
class AppendOnlyLifecyclePolicy:
    """Policy for one append-only instance file or logical record stream."""

    path: str
    sensitivity: str
    registered_markers: tuple[MigrationMarker, ...] = field(default_factory=tuple)
    rollback_mode: str = APPEND_ONLY_ROLLBACK_MODE

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _policy_path(self.path))
        if not isinstance(self.sensitivity, str) or self.sensitivity not in SENSITIVITIES:
            raise LifecycleError("append-only policy sensitivity is invalid")
        if self.rollback_mode != APPEND_ONLY_ROLLBACK_MODE:
            raise LifecycleError("append-only policy must use transactional snapshot rollback")
        if any(not isinstance(marker, MigrationMarker) for marker in self.registered_markers):
            raise LifecycleError("registered_markers must contain migration markers")
        object.__setattr__(self, "registered_markers", tuple(self.registered_markers))
        marker_ids = [marker.marker_id for marker in self.registered_markers]
        if len(marker_ids) != len(set(marker_ids)):
            raise LifecycleError("registered migration markers must be unique")
        for marker in self.registered_markers:
            if marker.sensitivity != self.sensitivity:
                raise LifecycleError(
                    f"marker {marker.marker_id!r} sensitivity does not match policy"
                )

    @classmethod
    def create(
        cls,
        path: str,
        *,
        sensitivity: str,
        registered_markers: Sequence[MigrationMarker] = (),
    ) -> "AppendOnlyLifecyclePolicy":
        """Construct a policy with an explicit, immutable marker registry."""
        return cls(
            path=path,
            sensitivity=sensitivity,
            registered_markers=tuple(registered_markers),
        )

    def marker(self, marker_id: str) -> MigrationMarker:
        """Resolve one marker from the policy registry, failing closed."""
        for marker in self.registered_markers:
            if marker.marker_id == marker_id:
                return marker
        raise LifecycleError(f"migration marker is not registered: {marker_id}")

    def as_dict(self) -> dict[str, Any]:
        """Return a deterministic machine-readable policy representation."""
        return {
            "formatVersion": APPEND_ONLY_POLICY_FORMAT,
            "path": self.path,
            "sensitivity": self.sensitivity,
            "rollback": self.rollback_mode,
            "registeredMarkers": [
                {
                    "id": marker.marker_id,
                    "sourceSchema": marker.source_schema,
                    "targetSchema": marker.target_schema,
                    "sensitivity": marker.sensitivity,
                }
                for marker in sorted(self.registered_markers, key=lambda item: item.marker_id)
            ],
        }


def _normalise_records(
    records: Sequence[Mapping[str, Any]], policy: AppendOnlyLifecyclePolicy
) -> tuple[dict[str, Any], ...]:
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes, bytearray)):
        raise LifecycleError("append-only records must be a sequence")
    normalised: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, raw in enumerate(records):
        if not isinstance(raw, Mapping):
            raise LifecycleError(f"append-only record {index} must be a mapping")
        record = _json_copy(dict(raw), f"append-only record {index}")
        record_id = _string(record.get("recordId"), f"append-only record {index}.recordId")
        if record_id in seen_ids:
            raise LifecycleError(f"append-only records contain duplicate recordId: {record_id}")
        seen_ids.add(record_id)
        if record.get("sensitivity") != policy.sensitivity:
            raise LifecycleError(
                f"append-only record {record_id!r} sensitivity does not match policy"
            )
        if record.get("recordType") == MIGRATION_MARKER_TYPE:
            marker_id = _string(record.get("markerId"), f"record {record_id}.markerId")
            marker = policy.marker(marker_id)
            if record != marker.as_record():
                raise LifecycleError(
                    f"registered migration marker {marker_id!r} was rewritten"
                )
        elif "markerId" in record or "sourceSchema" in record or "targetSchema" in record:
            raise LifecycleError(f"record {record_id!r} has unregistered migration fields")
        normalised.append(record)
    return tuple(normalised)


@dataclass(frozen=True)
class AppendOnlyUpdate:
    """A staged append with exact snapshots for optimistic apply and rollback."""

    _before: tuple[dict[str, Any], ...]
    _after: tuple[dict[str, Any], ...]
    marker: MigrationMarker
    policy_path: str
    sensitivity: str
    registered_markers: tuple[MigrationMarker, ...]
    update_digest: str

    @property
    def before(self) -> list[dict[str, Any]]:
        return copy.deepcopy(list(self._before))

    @property
    def after(self) -> list[dict[str, Any]]:
        return copy.deepcopy(list(self._after))

    @property
    def rollback_snapshot(self) -> list[dict[str, Any]]:
        """The exact pre-update state to restore if staged validation fails."""
        return self.before

    def as_dict(self) -> dict[str, Any]:
        return {
            "formatVersion": APPEND_ONLY_POLICY_FORMAT,
            "path": self.policy_path,
            "sensitivity": self.sensitivity,
            "marker": self.marker.as_record(),
            "beforeDigest": _canonical_digest(list(self._before)),
            "afterDigest": _canonical_digest(list(self._after)),
            "updateDigest": self.update_digest,
            "rollback": {"mode": APPEND_ONLY_ROLLBACK_MODE, "beforeIsImmutable": True},
        }


def plan_append_only_marker(
    records: Sequence[Mapping[str, Any]],
    marker: MigrationMarker,
    policy: AppendOnlyLifecyclePolicy,
) -> AppendOnlyUpdate:
    """Plan the only permitted mutation: one registered marker append."""
    if not isinstance(marker, MigrationMarker):
        raise LifecycleError("append-only migration marker has an invalid type")
    registered = policy.marker(marker.marker_id)
    if marker != registered:
        raise LifecycleError("migration marker does not match its registered definition")
    before = _normalise_records(records, policy)
    if any(record.get("recordType") == MIGRATION_MARKER_TYPE and record.get("markerId") == marker.marker_id for record in before):
        raise LifecycleError(f"migration marker is already present: {marker.marker_id}")
    after = before + (marker.as_record(),)
    update_payload = {
        "path": policy.path,
        "sensitivity": policy.sensitivity,
        "before": list(before),
        "after": list(after),
        "marker": marker.as_record(),
        "rollback": APPEND_ONLY_ROLLBACK_MODE,
    }
    return AppendOnlyUpdate(
        _before=before,
        _after=after,
        marker=marker,
        policy_path=policy.path,
        sensitivity=policy.sensitivity,
        registered_markers=policy.registered_markers,
        update_digest=_canonical_digest(update_payload),
    )


def _validate_update(update: AppendOnlyUpdate) -> None:
    """Validate the staged object itself, not only the live record prefix."""
    if not isinstance(update, AppendOnlyUpdate):
        raise LifecycleError("append-only update has an invalid type")
    policy = AppendOnlyLifecyclePolicy.create(
        update.policy_path,
        sensitivity=update.sensitivity,
        registered_markers=update.registered_markers,
    )
    marker = policy.marker(update.marker.marker_id)
    if marker != update.marker:
        raise LifecycleError("append-only update marker is not policy-bound")
    before = _normalise_records(update._before, policy)
    after = _normalise_records(update._after, policy)
    if before != update._before or after != update._after:
        raise LifecycleError("append-only update contains non-canonical records")
    if after != before + (marker.as_record(),):
        raise LifecycleError("append-only update may contain only one registered append")
    update_payload = {
        "path": policy.path,
        "sensitivity": policy.sensitivity,
        "before": list(before),
        "after": list(after),
        "marker": marker.as_record(),
        "rollback": APPEND_ONLY_ROLLBACK_MODE,
    }
    if update.update_digest != _canonical_digest(update_payload):
        raise LifecycleError("append-only update digest is invalid")


def apply_append_only_update(
    current_records: Sequence[Mapping[str, Any]],
    update: AppendOnlyUpdate,
) -> list[dict[str, Any]]:
    """Apply a staged append only when the live state is its exact base."""
    _validate_update(update)
    current = _normalise_records(
        current_records,
        AppendOnlyLifecyclePolicy.create(
            update.policy_path,
            sensitivity=update.sensitivity,
            registered_markers=update.registered_markers,
        ),
    )
    if current != update._before:
        raise LifecycleError("append-only update is stale; historical records must remain unchanged")
    return update.after


def rollback_append_only_update(
    current_records: Sequence[Mapping[str, Any]],
    update: AppendOnlyUpdate,
) -> list[dict[str, Any]]:
    """Restore the exact staged base, refusing to erase later history."""
    _validate_update(update)
    current = _normalise_records(
        current_records,
        AppendOnlyLifecyclePolicy.create(
            update.policy_path,
            sensitivity=update.sensitivity,
            registered_markers=update.registered_markers,
        ),
    )
    if current != update._after:
        raise LifecycleError(
            "append-only rollback would rewrite records added after this update"
        )
    return update.rollback_snapshot


__all__ = [
    "APPEND_ONLY_POLICY_FORMAT",
    "APPEND_ONLY_ROLLBACK_MODE",
    "MIGRATION_MARKER_FORMAT",
    "AppendOnlyLifecyclePolicy",
    "AppendOnlyUpdate",
    "MigrationMarker",
    "apply_append_only_update",
    "plan_append_only_marker",
    "rollback_append_only_update",
]
