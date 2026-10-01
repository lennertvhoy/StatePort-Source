"""Durable, application-scoped local activity and receipt projections.

This is an operational index, not canonical application state.  It projects
only facts already persisted by the local application boundary: inspection
state, recovery receipts, run history, and application-settings receipts.  Its own read and
acknowledgement records are local operational receipts and never assert that
the underlying application condition was repaired.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
from typing import Any, Mapping


class ActivityReceiptError(ValueError):
    """Raised when the bounded operational projection cannot be used safely."""


_IDENTIFIER = re.compile(r"^[a-z][a-z0-9._-]{1,127}$")
_RECEIPT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,127}$")
_ACTIONS = frozenset({"read", "acknowledge"})


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _canonical(value: object) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ActivityReceiptError("activity projection value is not JSON-safe") from exc


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _persistent_metadata_digest(value: object) -> str:
    """Match the canonical JSON-line digest used by the durable app store."""

    return "sha256:" + hashlib.sha256((_canonical(value) + "\n").encode("utf-8")).hexdigest()


def _bounded_text(value: object, field: str, maximum: int = 240) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ActivityReceiptError(f"{field} is invalid")
    return value


class ActivityReceiptStore:
    """A SQLite-backed view for one local StatePort state root."""

    FORMAT = "stateport.activity-receipts-projection/v1"
    RECEIPT_FORMAT = "stateport.activity-receipt/v1"

    def __init__(self, path: Path | str) -> None:
        self.path = self._safe_path(path)
        self._initialize()

    @staticmethod
    def _safe_path(value: Path | str) -> Path:
        path = Path(os.path.abspath(os.fspath(value)))
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise ActivityReceiptError("activity projection store path is unsafe")
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if path.parent.is_symlink() or path.is_symlink():
            raise ActivityReceiptError("activity projection store path is unsafe")
        return path

    def _connect(self) -> sqlite3.Connection:
        self._safe_path(self.path)
        try:
            connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        except sqlite3.Error as exc:
            raise ActivityReceiptError("activity projection store could not be opened") from exc
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        if self.path.is_symlink() or not self.path.is_file():
            connection.close()
            raise ActivityReceiptError("activity projection store changed during open")
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("CREATE TABLE IF NOT EXISTS activity_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            row = connection.execute("SELECT value FROM activity_metadata WHERE key = 'schema'").fetchone()
            if row is None:
                connection.execute("INSERT INTO activity_metadata(key, value) VALUES('schema', 'stateport.activity-receipts-schema/v1')")
            elif row["value"] != "stateport.activity-receipts-schema/v1":
                raise ActivityReceiptError("activity projection store schema is unsupported")
            connection.execute("""
                CREATE TABLE IF NOT EXISTS attention_items (
                    instance_id TEXT NOT NULL,
                    attention_id TEXT NOT NULL,
                    source_kind TEXT NOT NULL,
                    title TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('open', 'resolved')),
                    first_observed_at TEXT NOT NULL,
                    last_observed_at TEXT NOT NULL,
                    read_at TEXT,
                    acknowledged_at TEXT,
                    version INTEGER NOT NULL CHECK(version >= 1),
                    PRIMARY KEY(instance_id, attention_id)
                )
            """)
            connection.execute("""
                CREATE TABLE IF NOT EXISTS receipt_index (
                    instance_id TEXT NOT NULL,
                    receipt_id TEXT NOT NULL,
                    receipt_type TEXT NOT NULL,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    source_kind TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    payload_digest TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    PRIMARY KEY(instance_id, receipt_id)
                )
            """)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _instance_id(value: object) -> str:
        if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
            raise ActivityReceiptError("application instance identity is invalid")
        return value

    @staticmethod
    def _receipt_from_settings(instance_id: str, value: Mapping[str, object]) -> dict[str, object] | None:
        receipt_id = value.get("receiptId")
        action = value.get("action")
        status = value.get("status")
        created_at = value.get("createdAt")
        if not all(isinstance(item, str) for item in (receipt_id, action, status, created_at)):
            return None
        if not _RECEIPT_ID.fullmatch(receipt_id) or len(action) > 128 or len(status) > 64 or len(created_at) > 64:
            return None
        if value.get("instanceId") != instance_id:
            return None
        # Settings receipts are already a typed durable store; retain their
        # complete bounded payload so a detail request never reconstructs data.
        encoded = _canonical(dict(value))
        if len(encoded.encode("utf-8")) > 16_384:
            return None
        return {
            "receiptId": receipt_id,
            "receiptType": str(value.get("formatVersion", "stateport.settings-mutation-receipt/v1")),
            "action": action,
            "status": status,
            "createdAt": created_at,
            "sourceKind": "application_settings",
            "payload": dict(value),
        }

    @staticmethod
    def _receipt_from_backup(instance_id: str, inspection: Mapping[str, object]) -> dict[str, object] | None:
        recovery = inspection.get("recovery")
        latest = recovery.get("latest") if isinstance(recovery, Mapping) else None
        value = latest.get("backupReceipt") if isinstance(latest, Mapping) else None
        if not isinstance(value, Mapping):
            return None
        receipt_id = value.get("receiptId")
        action = value.get("action")
        status = value.get("status")
        created_at = value.get("createdAt")
        if not all(isinstance(item, str) for item in (receipt_id, action, status, created_at)):
            return None
        if not _RECEIPT_ID.fullmatch(receipt_id) or value.get("instanceId") != instance_id:
            return None
        payload = dict(value)
        if len(_canonical(payload).encode("utf-8")) > 16_384:
            return None
        return {
            "receiptId": receipt_id,
            "receiptType": str(value.get("formatVersion", "stateport.backup-receipt/v1")),
            "action": action,
            "status": status,
            "createdAt": created_at,
            "sourceKind": "application_backup",
            "payload": payload,
        }

    @staticmethod
    def _receipt_from_application_install(
        instance_id: str,
        value: object,
    ) -> dict[str, object] | None:
        """Project, but never replace, the durable application-install authority."""

        if value is None:
            return None
        if not isinstance(value, Mapping):
            raise ActivityReceiptError("application install receipt source is invalid")
        required = {
            "formatVersion", "receiptId", "operation", "applicationId",
            "instanceId", "actor", "descriptorIdentities", "source",
            "baseGit", "catalogIdentity", "consent", "createdAt",
        }
        receipt_id = value.get("receiptId")
        base_git = value.get("baseGit")
        created_at = value.get("createdAt")
        lifecycle_provenance = value.get("lifecycle")
        if (
            set(value) - required != ({"lifecycle"} if "lifecycle" in value else set())
            or value.get("formatVersion") != "stateport.application-install-receipt/v1"
            or value.get("operation") != "install_public_fixture"
            or value.get("instanceId") != instance_id
            or not isinstance(receipt_id, str)
            or not _RECEIPT_ID.fullmatch(receipt_id)
            or not isinstance(base_git, str)
            or not re.fullmatch(r"[0-9a-f]{40,64}", base_git)
            or receipt_id != f"application-install.{instance_id}.{base_git[:12]}"
            or not isinstance(created_at, str)
            or len(created_at) > 64
        ):
            raise ActivityReceiptError("application install receipt source identity is invalid")
        if lifecycle_provenance is not None and (
            not isinstance(lifecycle_provenance, Mapping)
            or set(lifecycle_provenance)
            != {"formatVersion", "templateId", "releaseVersion", "sourceRevision", "revisionId"}
            or lifecycle_provenance.get("formatVersion") != "statedd.lock/v1"
        ):
            raise ActivityReceiptError("application install receipt source identity is invalid")
        catalog_identity = value.get("catalogIdentity")
        descriptor_identities = value.get("descriptorIdentities")
        application_identity = (
            descriptor_identities.get("application")
            if isinstance(descriptor_identities, Mapping)
            else None
        )
        source = value.get("source")
        if (
            not isinstance(catalog_identity, Mapping)
            or catalog_identity.get("instanceId") != instance_id
            or catalog_identity.get("applicationId") != value.get("applicationId")
            or not isinstance(application_identity, Mapping)
            or application_identity.get("applicationId") != value.get("applicationId")
            or not re.fullmatch(
                r"sha256:[0-9a-f]{64}",
                str(application_identity.get("descriptorDigest", "")),
            )
            or not re.fullmatch(
                r"sha256:[0-9a-f]{64}",
                str(application_identity.get("packageDigest", "")),
            )
            or not isinstance(source, Mapping)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(source.get("digest", "")))
        ):
            raise ActivityReceiptError("application install receipt source binding is invalid")
        payload = dict(value)
        if len(_canonical(payload).encode("utf-8")) > 16_384:
            raise ActivityReceiptError("application install receipt source is too large")
        return {
            "receiptId": receipt_id,
            "receiptType": "stateport.application-install-receipt/v1",
            "action": "application.install.fixture",
            "status": "applied",
            "createdAt": created_at,
            "sourceKind": "application_install",
            "payload": payload,
            "payloadDigest": _persistent_metadata_digest(payload),
        }

    @staticmethod
    def _attention_facts(inspection: Mapping[str, object]) -> dict[str, dict[str, str]]:
        facts: dict[str, dict[str, str]] = {}
        health = inspection.get("health")
        if isinstance(health, str) and health != "valid":
            facts["application-health"] = {
                "sourceKind": "application_inspection",
                "title": "Application state needs inspection",
                "detail": f"Persisted inspection reported health: {health}.",
            }
        recovery = inspection.get("recovery")
        if isinstance(recovery, Mapping) and recovery.get("status") == "no_backup":
            facts["recovery-backup"] = {
                "sourceKind": "application_recovery",
                "title": "No verified backup recorded",
                "detail": "Create a backup before relying on recovery.",
            }
        restore = recovery.get("restore") if isinstance(recovery, Mapping) else None
        restore_inspection = (
            isinstance(restore, Mapping)
            and restore.get("operatorInspectionRequired") is True
        )
        if (
            isinstance(recovery, Mapping)
            and recovery.get("operatorInspectionRequired") is True
            or restore_inspection
        ):
            staging_retained = (
                isinstance(restore, Mapping)
                and restore.get("stagingRetained") is True
            )
            facts["recovery-operator-inspection"] = {
                "sourceKind": "application_recovery",
                "title": "Recovery requires operator inspection",
                "detail": (
                    "A failed restore retained staging data for operator review."
                    if staging_retained
                    else "The persisted recovery state requires an operator review."
                ),
            }
        return facts

    @staticmethod
    def _upsert_receipt(connection: sqlite3.Connection, instance_id: str, value: Mapping[str, object], observed_at: str) -> None:
        payload = value["payload"]
        payload_json = _canonical(payload)
        supplied_digest = value.get("payloadDigest")
        if supplied_digest is not None and (
            not isinstance(supplied_digest, str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", supplied_digest)
        ):
            raise ActivityReceiptError("operational receipt payload digest is invalid")
        payload_digest = supplied_digest or _digest(payload)
        connection.execute(
            """INSERT INTO receipt_index(
                instance_id, receipt_id, receipt_type, action, status, created_at,
                source_kind, payload_json, payload_digest, observed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(instance_id, receipt_id) DO UPDATE SET
                receipt_type = excluded.receipt_type, action = excluded.action,
                status = excluded.status, created_at = excluded.created_at,
                source_kind = excluded.source_kind, payload_json = excluded.payload_json,
                payload_digest = excluded.payload_digest, observed_at = excluded.observed_at
            """,
            (
                instance_id, value["receiptId"], value["receiptType"], value["action"],
                value["status"], value["createdAt"], value["sourceKind"], payload_json,
                payload_digest, observed_at,
            ),
        )

    @staticmethod
    def _receipt_from_application_rename(instance_id: str, value: object) -> dict[str, object]:
        keys = {"formatVersion", "receiptId", "instanceId", "oldName", "newName", "actorId", "actorRole", "createdAt"}
        if (
            not isinstance(value, Mapping) or set(value) != keys
            or value.get("formatVersion") != "stateport.application-rename-receipt/v1"
            or value.get("instanceId") != instance_id
            or not isinstance(value.get("receiptId"), str)
            or not re.fullmatch(r"rename_[a-f0-9]{32}", str(value.get("receiptId")))
            or value.get("actorRole") not in {"local_user", "platform_operator"}
        ):
            raise ActivityReceiptError("catalog rename receipt identity is invalid")
        for field, maximum in (("oldName", 120), ("newName", 120), ("actorId", 128), ("createdAt", 64)):
            text = _bounded_text(value.get(field), field, maximum)
            if text.strip() != text or any(ord(character) < 32 or ord(character) == 127 for character in text):
                raise ActivityReceiptError("catalog rename receipt text is invalid")
        return {
            "receiptId": value["receiptId"], "receiptType": value["formatVersion"],
            "action": "application.rename", "status": "applied", "createdAt": value["createdAt"],
            "sourceKind": "application_catalog", "payload": dict(value),
        }

    def refresh(
        self,
        *,
        instance_id: str,
        inspection: Mapping[str, object],
        settings_receipts: object,
        application_install_receipt: object = None,
        application_rename_receipts: object = None,
    ) -> None:
        instance = self._instance_id(instance_id)
        if not isinstance(inspection, Mapping) or not isinstance(settings_receipts, list):
            raise ActivityReceiptError("activity projection source facts are invalid")
        if application_rename_receipts is None:
            application_rename_receipts = []
        if not isinstance(application_rename_receipts, list):
            raise ActivityReceiptError("catalog rename receipt history is invalid")
        facts = self._attention_facts(inspection)
        now = _now()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute("SELECT attention_id, state FROM attention_items WHERE instance_id = ?", (instance,)).fetchall()
            current = {str(row["attention_id"]): str(row["state"]) for row in rows}
            for attention_id, fact in facts.items():
                connection.execute(
                    """INSERT INTO attention_items(
                        instance_id, attention_id, source_kind, title, detail, state,
                        first_observed_at, last_observed_at, read_at, acknowledged_at, version
                    ) VALUES (?, ?, ?, ?, ?, 'open', ?, ?, NULL, NULL, 1)
                    ON CONFLICT(instance_id, attention_id) DO UPDATE SET
                        source_kind = excluded.source_kind, title = excluded.title,
                        detail = excluded.detail, state = 'open', last_observed_at = excluded.last_observed_at,
                        version = CASE WHEN attention_items.state = 'resolved' THEN attention_items.version + 1 ELSE attention_items.version END
                    """,
                    (instance, attention_id, fact["sourceKind"], fact["title"], fact["detail"], now, now),
                )
            for attention_id, prior_state in current.items():
                if attention_id not in facts and prior_state == "open":
                    connection.execute(
                        "UPDATE attention_items SET state = 'resolved', last_observed_at = ?, version = version + 1 WHERE instance_id = ? AND attention_id = ?",
                        (now, instance, attention_id),
                    )
            for receipt in settings_receipts:
                if isinstance(receipt, Mapping):
                    projected = self._receipt_from_settings(instance, receipt)
                    if projected is not None:
                        self._upsert_receipt(connection, instance, projected, now)
            backup_receipt = self._receipt_from_backup(instance, inspection)
            if backup_receipt is not None:
                self._upsert_receipt(connection, instance, backup_receipt, now)
            install_receipt = self._receipt_from_application_install(
                instance,
                application_install_receipt,
            )
            if install_receipt is not None:
                self._upsert_receipt(connection, instance, install_receipt, now)
            for receipt in application_rename_receipts:
                self._upsert_receipt(connection, instance, self._receipt_from_application_rename(instance, receipt), now)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def record_receipt(self, *, instance_id: str, receipt: Mapping[str, object]) -> None:
        """Persist one already-validated operational receipt in the index."""

        instance = self._instance_id(instance_id)
        projected = {
            "receiptId": receipt.get("receiptId"),
            "receiptType": receipt.get("receiptType", receipt.get("formatVersion")),
            "action": receipt.get("action"),
            "status": receipt.get("status"),
            "createdAt": receipt.get("createdAt"),
            "sourceKind": receipt.get("sourceKind", "stateport_operation"),
            "payload": dict(receipt),
        }
        if (
            not isinstance(projected["receiptId"], str)
            or not _RECEIPT_ID.fullmatch(projected["receiptId"])
            or not all(isinstance(projected[key], str) and projected[key] for key in ("receiptType", "action", "status", "createdAt", "sourceKind"))
        ):
            raise ActivityReceiptError("operational receipt is malformed")
        if len(_canonical(projected["payload"]).encode("utf-8")) > 16_384:
            raise ActivityReceiptError("operational receipt is too large")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._upsert_receipt(connection, instance, projected, _now())
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _attention_row(row: sqlite3.Row) -> dict[str, object]:
        return {
            "attentionId": row["attention_id"], "sourceKind": row["source_kind"],
            "title": row["title"], "detail": row["detail"], "state": row["state"],
            "firstObservedAt": row["first_observed_at"], "lastObservedAt": row["last_observed_at"],
            "readAt": row["read_at"], "acknowledgedAt": row["acknowledged_at"], "version": row["version"],
        }

    @staticmethod
    def _receipt_row(row: sqlite3.Row) -> dict[str, object]:
        return {
            "receiptId": row["receipt_id"], "receiptType": row["receipt_type"],
            "action": row["action"], "status": row["status"], "createdAt": row["created_at"],
            "sourceKind": row["source_kind"], "payloadDigest": row["payload_digest"],
        }

    def activity(self, instance_id: str, *, notification_level: str = "important") -> dict[str, object]:
        instance = self._instance_id(instance_id)
        if notification_level not in {"all", "important", "none"}:
            raise ActivityReceiptError("notification level is unsupported")
        connection = self._connect()
        try:
            attention_rows = connection.execute(
                "SELECT * FROM attention_items WHERE instance_id = ? AND state = 'open' ORDER BY acknowledged_at IS NOT NULL, last_observed_at DESC, attention_id",
                (instance,),
            ).fetchall()
            receipts = connection.execute(
                "SELECT * FROM receipt_index WHERE instance_id = ? ORDER BY created_at DESC, receipt_id DESC LIMIT 10",
                (instance,),
            ).fetchall()
            return {
                "formatVersion": self.FORMAT, "instanceId": instance,
                "attention": [] if notification_level == "none" else [self._attention_row(row) for row in attention_rows],
                "recentActivity": [
                    {"kind": "receipt", "receiptId": row["receipt_id"], "action": row["action"], "status": row["status"], "occurredAt": row["created_at"]}
                    for row in receipts
                ],
            }
        finally:
            connection.close()

    def receipt_index(self, instance_id: str) -> dict[str, object]:
        instance = self._instance_id(instance_id)
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT * FROM receipt_index WHERE instance_id = ? ORDER BY created_at DESC, receipt_id DESC LIMIT 50", (instance,)
            ).fetchall()
            return {"formatVersion": self.FORMAT, "instanceId": instance, "receipts": [self._receipt_row(row) for row in rows]}
        finally:
            connection.close()

    def receipt_detail(self, instance_id: str, receipt_id: str) -> dict[str, object]:
        instance = self._instance_id(instance_id)
        if not isinstance(receipt_id, str) or not _RECEIPT_ID.fullmatch(receipt_id):
            raise ActivityReceiptError("receipt identity is invalid")
        connection = self._connect()
        try:
            row = connection.execute("SELECT * FROM receipt_index WHERE instance_id = ? AND receipt_id = ?", (instance, receipt_id)).fetchone()
            if row is None:
                raise ActivityReceiptError("receipt was not found")
            payload = json.loads(row["payload_json"])
            return {"formatVersion": self.FORMAT, "instanceId": instance, "receipt": {**self._receipt_row(row), "payload": payload}}
        except json.JSONDecodeError as exc:
            raise ActivityReceiptError("stored receipt detail is invalid") from exc
        finally:
            connection.close()

    def transition_attention(self, *, instance_id: str, attention_id: str, action: str, expected_version: object) -> dict[str, object]:
        instance = self._instance_id(instance_id)
        if not isinstance(attention_id, str) or not _IDENTIFIER.fullmatch(attention_id):
            raise ActivityReceiptError("attention identity is invalid")
        if action not in _ACTIONS:
            raise ActivityReceiptError("attention action is unsupported")
        if isinstance(expected_version, bool) or not isinstance(expected_version, int) or expected_version < 1:
            raise ActivityReceiptError("attention version is invalid")
        now = _now()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM attention_items WHERE instance_id = ? AND attention_id = ?", (instance, attention_id)).fetchone()
            if row is None or row["state"] != "open":
                raise ActivityReceiptError("attention item is no longer active")
            if row["version"] != expected_version:
                raise ActivityReceiptError("attention item changed; reload the activity view")
            column = "read_at" if action == "read" else "acknowledged_at"
            connection.execute(
                f"UPDATE attention_items SET {column} = ?, version = version + 1 WHERE instance_id = ? AND attention_id = ?",
                (now, instance, attention_id),
            )
            updated = connection.execute("SELECT * FROM attention_items WHERE instance_id = ? AND attention_id = ?", (instance, attention_id)).fetchone()
            assert updated is not None
            receipt_id = "attention-" + hashlib.sha256(f"{instance}:{attention_id}:{action}:{updated['version']}".encode("utf-8")).hexdigest()[:24]
            payload = {
                "formatVersion": self.RECEIPT_FORMAT, "receiptId": receipt_id,
                "instanceId": instance, "action": f"attention.{action}", "status": "applied",
                "attentionId": attention_id, "attentionVersion": updated["version"], "createdAt": now,
                "effect": "local_operational_attention_state_only",
            }
            self._upsert_receipt(connection, instance, {
                "receiptId": receipt_id, "receiptType": self.RECEIPT_FORMAT,
                "action": payload["action"], "status": "applied", "createdAt": now,
                "sourceKind": "activity_projection", "payload": payload,
            }, now)
            connection.commit()
            return {"attention": self._attention_row(updated), "receipt": payload}
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
