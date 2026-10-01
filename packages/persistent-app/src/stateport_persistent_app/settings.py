"""Typed, durable StatePort settings projections and mutations.

Settings are operational metadata. They never become canonical application
state and every write creates a receipt that can be rolled back exactly.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Mapping


class SettingsError(ValueError):
    """Raised when a typed settings request cannot be accepted."""


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _atomic_write(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists() and path.is_symlink():
        raise SettingsError("settings file must not be a symlink")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


@dataclass(frozen=True)
class SettingsField:
    section: str
    field_id: str
    label: str
    value_type: str
    default: object
    options: tuple[object, ...] = ()
    editable: bool = True
    requires_approval: bool = False
    policy_source: str = "user preference"
    description: str = ""

    @property
    def key(self) -> str:
        return f"{self.section}.{self.field_id}"


FIELDS: tuple[SettingsField, ...] = (
    SettingsField("general", "defaultLandingView", "Default landing view", "select", "home", ("home", "catalog"), description="Where StatePort opens after a restart."),
    SettingsField("general", "appearance", "Appearance", "select", "system", ("system", "light", "dark"), description="Uses the browser preference when set to system."),
    SettingsField("notifications", "level", "Notification level", "select", "important", ("all", "important", "none"), description="Controls local attention notices."),
    SettingsField("conversation", "retention", "Conversation retention", "text", "Local transcript; manual export and clear", editable=False, policy_source="Conversation lifecycle", description="Automatic expiry is not enabled. Use Conversation → Export or Clear history for explicit transcript lifecycle actions; canonical application state is unaffected."),
    SettingsField("conversation", "channelMirrorPolicy", "Channel mirror policy", "text", "Fixed when the thread is created", editable=False, policy_source="Conversation thread", description="Delivery policy is bound to the durable thread identity; changing it here would be misleading."),
    SettingsField("conversation", "attachments", "Attachment handling", "text", "Allowlisted private uploads; context inclusion requires proposal", editable=False, policy_source="Conversation attachment policy", description="Text, Markdown, JSON, YAML, PNG, JPEG, and opaque PDF uploads are size- and retention-bounded. Uploading never adds content to model context automatically."),
    SettingsField("context", "mode", "Context loading", "text", "Use Application Settings → Context", editable=False, policy_source="Context Lifecycle service", description="Faster, Balanced, and Deeper are owned by the application Context Lifecycle contract."),
    SettingsField("runtime", "backendProfile", "Backend profile", "text", "local-approved", editable=False, requires_approval=True, policy_source="operator policy", description="The effective provider-neutral backend profile."),
    SettingsField("runtime", "networkPolicy", "Network policy", "text", "disabled", editable=False, requires_approval=True, policy_source="operator policy", description="Network access is disabled for the local beta profile."),
    SettingsField("runtime", "executionMode", "Execution mode", "text", "advisory", editable=False, requires_approval=True, policy_source="application and operator policy", description="Governed execution remains approval-bound."),
    SettingsField("permissions", "effective", "Effective permissions", "text", "application-declared intersection", editable=False, requires_approval=True, policy_source="effective policy", description="The most restrictive applicable policy wins."),
    SettingsField("channels", "web", "Web channel", "text", "loopback session", editable=False, policy_source="service boundary", description="The local web channel is bound to the loopback session."),
    SettingsField("channels", "telegram", "Telegram channel", "text", "not configured", editable=False, policy_source="channel configuration", description="A binding appears here only after an authenticated operator connection."),
    SettingsField("data", "export", "Export and deletion", "text", "available from application workspace", editable=False, policy_source="StatePort lifecycle", description="Export and deletion preserve canonical state boundaries and create receipts."),
    SettingsField("backup", "recovery", "Backup and recovery", "text", "verified backups available per application", editable=False, policy_source="StatePort lifecycle", description="Backups are application-scoped and verified before they are reported as complete."),
)


class SettingsStore:
    FORMAT = "stateport.settings-store/v1"
    RECEIPT_FORMAT = "stateport.settings-mutation-receipt/v1"
    _ID = re.compile(r"^[a-z][a-z0-9._-]{1,127}$")
    _RETIRED_FIELDS = frozenset({"conversation.retentionDays"})
    # These preferences are owned by the process-wide browser/session
    # experience.  Exposing writable copies in an application projection
    # would create settings that persist successfully but have no effect.
    _GLOBAL_ONLY_FIELDS = frozenset({
        "general.defaultLandingView",
        "general.appearance",
        "notifications.level",
    })

    def __init__(self, path: Path | str, *, scope: str, instance_id: str | None = None) -> None:
        self.path = Path(os.path.abspath(os.fspath(Path(path).expanduser())))
        self.scope = scope
        self.instance_id = instance_id
        self._validate_scope()
        loaded = self._load()
        self.revision = loaded["revision"]
        self.values = loaded["values"]
        self.receipts = loaded["receipts"]

    def _validate_scope(self) -> None:
        if self.scope not in {"global", "application"}:
            raise SettingsError("settings scope is unsupported")
        if self.scope == "application" and (not isinstance(self.instance_id, str) or not self._ID.fullmatch(self.instance_id)):
            raise SettingsError("application settings identity is invalid")

    def _fields(self) -> tuple[SettingsField, ...]:
        if self.scope == "global":
            return FIELDS
        return tuple(field for field in FIELDS if field.key not in self._GLOBAL_ONLY_FIELDS)

    def _defaults(self) -> dict[str, object]:
        result: dict[str, object] = {}
        for field in self._fields():
            result[field.key] = field.default
        return result

    def _load(self) -> dict[str, Any]:
        if self.path.parent.is_symlink():
            raise SettingsError("settings store parent must not be a symlink")
        if not self.path.exists():
            return {"revision": 0, "values": self._defaults(), "receipts": []}
        if self.path.is_symlink() or not self.path.is_file():
            raise SettingsError("settings store is not a regular file")
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise SettingsError("settings store is malformed") from exc
        if not isinstance(value, dict) or value.get("formatVersion") != self.FORMAT or value.get("scope") != self.scope or value.get("instanceId") != self.instance_id:
            raise SettingsError("settings store identity or format is invalid")
        revision = value.get("revision")
        values = value.get("values")
        receipts = value.get("receipts")
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0 or not isinstance(values, dict) or not isinstance(receipts, list) or len(receipts) > 200:
            raise SettingsError("settings store shape is invalid")
        for receipt in receipts:
            self._validate_receipt(receipt)
        defaults = self._defaults()
        for key, item in values.items():
            if key not in defaults:
                if key in self._RETIRED_FIELDS or (self.scope == "application" and key in self._GLOBAL_ONLY_FIELDS):
                    continue
                raise SettingsError("settings store contains an unknown field")
            self._validate_field(key, item)
            # Non-editable fields are projections owned by another policy or
            # service. Ignore stale historical values rather than displaying
            # them as if they were current effective truth.
            if self._field(key).editable:
                defaults[key] = item
        return {"revision": revision, "values": defaults, "receipts": receipts}

    def _validate_receipt(self, receipt: object) -> None:
        if not isinstance(receipt, dict):
            raise SettingsError("settings receipt is malformed")
        required = {"formatVersion", "receiptId", "scope", "instanceId", "action", "status", "revision", "changes", "previousValues", "effectivePolicy", "createdAt"}
        if set(receipt) != required or receipt.get("formatVersion") != self.RECEIPT_FORMAT:
            raise SettingsError("settings receipt is malformed")
        if (
            not isinstance(receipt.get("receiptId"), str)
            or not re.fullmatch(r"[a-f0-9]{24}", receipt["receiptId"])
            or receipt.get("scope") != self.scope
            or receipt.get("instanceId") != self.instance_id
            or not isinstance(receipt.get("action"), str)
            or not isinstance(receipt.get("status"), str)
            or not isinstance(receipt.get("revision"), int)
            or isinstance(receipt.get("revision"), bool)
            or receipt["revision"] < 1
            or not isinstance(receipt.get("changes"), dict)
            or not isinstance(receipt.get("previousValues"), dict)
            or not isinstance(receipt.get("effectivePolicy"), str)
            or not isinstance(receipt.get("createdAt"), str)
        ):
            raise SettingsError("settings receipt is malformed")
        for key, value in {**receipt["changes"], **receipt["previousValues"]}.items():
            if not isinstance(key, str):
                raise SettingsError("settings receipt contains an invalid field")
            # Receipts are historical evidence.  Validate their shape against
            # the complete contract even when a field is no longer exposed in
            # this scope; rollback below still refuses to mutate another
            # authority.
            field = next((candidate for candidate in FIELDS if candidate.key == key), None)
            if field is None:
                raise SettingsError("settings receipt contains an unknown field")
            self._validate_field_value(field, key, value)

    @contextmanager
    def _mutation_lock(self):
        lock_path = self.path.with_name(f".{self.path.name}.lock")
        if lock_path.parent.is_symlink() or lock_path.exists() and lock_path.is_symlink():
            raise SettingsError("settings lock path is unsafe")
        lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with lock_path.open("a+", encoding="utf-8") as lock:
            os.chmod(lock_path, 0o600)
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def _field(self, key: str) -> SettingsField:
        for field in self._fields():
            if field.key == key:
                return field
        raise SettingsError(f"unknown settings field: {key}")

    @staticmethod
    def _validate_field_value(field: SettingsField, key: str, value: object) -> None:
        if field.value_type == "number":
            if isinstance(value, bool) or not isinstance(value, int) or not field.options or not int(field.options[0]) <= value <= int(field.options[-1]):
                raise SettingsError(f"{key} must be within the supported numeric range")
        elif field.value_type == "select":
            if not isinstance(value, str) or value not in field.options:
                raise SettingsError(f"{key} must be one of the supported options")
        elif field.value_type == "text":
            if not isinstance(value, str) or not value or len(value) > 256:
                raise SettingsError(f"{key} must be a bounded string")
        else:
            raise SettingsError(f"{key} has an unsupported field type")

    def _validate_field(self, key: str, value: object) -> None:
        field = self._field(key)
        self._validate_field_value(field, key, value)

    def _write(self) -> None:
        _atomic_write(self.path, {
            "formatVersion": self.FORMAT,
            "scope": self.scope,
            "instanceId": self.instance_id,
            "revision": self.revision,
            "values": self.values,
            "receipts": self.receipts[-200:],
        })

    def _receipt(self, *, action: str, changes: Mapping[str, object], previous: Mapping[str, object], status: str = "applied") -> dict[str, object]:
        return {
            "formatVersion": self.RECEIPT_FORMAT,
            "receiptId": _digest({"scope": self.scope, "instanceId": self.instance_id, "revision": self.revision, "action": action, "changes": changes})[7:31],
            "scope": self.scope,
            "instanceId": self.instance_id,
            "action": action,
            "status": status,
            "revision": self.revision,
            "changes": dict(changes),
            "previousValues": dict(previous),
            "effectivePolicy": "platform → application → instance → operator → user → runtime; most restrictive rule wins",
            "createdAt": _now(),
        }

    def projection(self) -> dict[str, object]:
        grouped: dict[str, list[dict[str, object]]] = {}
        for field in self._fields():
            value = self.values[field.key]
            grouped.setdefault(field.section, []).append({
                "formatVersion": "stateport.settings-field/v1",
                "id": field.field_id,
                "key": field.key,
                "label": field.label,
                "type": field.value_type,
                "value": value,
                "requestedValue": value if field.editable else None,
                "effectiveValue": value,
                "default": field.default,
                "options": list(field.options),
                "editable": field.editable,
                "requiresApproval": field.requires_approval,
                "policySource": field.policy_source,
                "description": field.description,
            })
        return {
            "formatVersion": "stateport.settings-projection/v1",
            "scope": self.scope,
            "instanceId": self.instance_id,
            "revision": self.revision,
            "effectivePolicy": {"precedence": ["platform", "application", "instance", "operator", "user", "runtime"], "mostRestrictiveWins": True},
            "sections": [{"id": section, "label": section.replace("_", " ").title(), "fields": fields} for section, fields in grouped.items()],
            "recentReceipts": list(reversed(self.receipts[-10:])),
        }

    def preview(self, *, expected_revision: int, changes: Mapping[str, object]) -> dict[str, object]:
        self._validate_request(expected_revision, changes)
        proposed = dict(self.values)
        for key, value in changes.items():
            proposed[key] = value
        return {"formatVersion": "stateport.settings-preview/v1", "scope": self.scope, "revision": self.revision, "changes": dict(changes), "effectiveValues": proposed, "requiresApproval": False, "approvalReason": None}

    def _validate_request(self, expected_revision: int, changes: Mapping[str, object]) -> None:
        if isinstance(expected_revision, bool) or not isinstance(expected_revision, int) or expected_revision != self.revision:
            raise SettingsError("settings revision is stale; reload the effective projection")
        if not isinstance(changes, Mapping) or not changes or len(changes) > 16:
            raise SettingsError("settings patch must contain one to sixteen fields")
        for key, value in changes.items():
            if not isinstance(key, str):
                raise SettingsError("settings field keys must be strings")
            field = self._field(key)
            if not field.editable:
                raise SettingsError(f"{key} is controlled by {field.policy_source} and is not user-writable")
            self._validate_field(key, value)

    def patch(self, *, expected_revision: int, changes: Mapping[str, object]) -> dict[str, object]:
        with self._mutation_lock():
            loaded = self._load()
            self.revision, self.values, self.receipts = loaded["revision"], loaded["values"], loaded["receipts"]
            self._validate_request(expected_revision, changes)
            previous = {key: self.values[key] for key in changes}
            self.values.update(changes)
            self.revision += 1
            receipt = self._receipt(action="settings.patch", changes=changes, previous=previous)
            self.receipts.append(receipt)
            self._write()
            return {"projection": self.projection(), "receipt": receipt}

    def rollback(self, *, expected_revision: int, receipt_id: str) -> dict[str, object]:
        with self._mutation_lock():
            loaded = self._load()
            self.revision, self.values, self.receipts = loaded["revision"], loaded["values"], loaded["receipts"]
            if not isinstance(receipt_id, str) or not receipt_id:
                raise SettingsError("settings receipt identity is required")
            target = next((item for item in self.receipts if item.get("receiptId") == receipt_id), None)
            if not isinstance(target, dict):
                raise SettingsError("settings receipt was not found")
            previous = target.get("previousValues")
            changes = target.get("changes")
            if not isinstance(previous, dict) or not isinstance(changes, dict):
                raise SettingsError("settings receipt is not rollback-capable")
            # Older pre-contract receipts may contain fields that are now owned by
            # a dedicated service. Roll back only still-editable values; never
            # mutate a second authority from a historical receipt.
            rollback_values = {
                key: value for key, value in previous.items()
                if key in {field.key for field in self._fields()} and self._field(key).editable
            }
            self._validate_request(expected_revision, rollback_values)
            current = {key: self.values[key] for key in rollback_values}
            self.values.update(rollback_values)
            self.revision += 1
            receipt = self._receipt(action="settings.rollback", changes=rollback_values, previous=current)
            self.receipts.append(receipt)
            self._write()
            return {"projection": self.projection(), "receipt": receipt}
