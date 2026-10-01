"""Confined, metadata-first storage for operational conversation attachments.

Attachments are deliberately not a context source.  This store preserves bytes
only for an authorized instance/conversation pair and records no raw byte
payload in its metadata or receipts.
"""

from __future__ import annotations

import base64
import binascii
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import tempfile
import threading
from typing import Mapping


class ConversationAttachmentError(ValueError):
    """A safe refusal at the attachment boundary."""


_IDENTIFIER = re.compile(r"^[a-z][a-z0-9._:-]{1,127}$")
_ATTACHMENT_ID = re.compile(r"^att-[a-f0-9]{32}$")
_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_BLOB_NAME = re.compile(r"^[0-9a-f]{64}$")
_STAGING_NAME = re.compile(r"^\.upload-([0-9a-f]{64})-[A-Za-z0-9_]+$")


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class ConversationAttachmentStore:
    """Content-addressed bytes with thread-confined metadata and receipts."""

    FORMAT = "stateport.conversation-attachment/v1"
    RECEIPT_FORMAT = "stateport.conversation-attachment-receipt/v1"
    MAX_BYTES = 2 * 1024 * 1024
    MAX_THREAD_BYTES = 8 * 1024 * 1024
    MAX_ATTACHMENTS_PER_THREAD = 24
    SENSITIVITY_LABELS = frozenset({"public", "internal", "private"})
    RETENTION_CLASSES = frozenset({"conversation_30_days", "conversation_90_days"})
    MEDIA_TYPES = frozenset({
        "text/plain", "text/markdown", "application/json", "text/yaml",
        "application/yaml", "application/x-yaml", "image/png", "image/jpeg",
        "application/pdf",
    })

    def __init__(self, root: Path | str):
        self.root = Path(os.path.abspath(os.fspath(root)))
        if self.root.exists() and self.root.is_symlink():
            raise ConversationAttachmentError("attachment store root is unsafe")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        root_resolved = self.root.resolve(strict=True)
        blobs_parent = self.root / "blobs"
        if blobs_parent.is_symlink() or (blobs_parent.exists() and not blobs_parent.is_dir()):
            raise ConversationAttachmentError("attachment blob parent is unsafe")
        blobs_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if blobs_parent.is_symlink():
            raise ConversationAttachmentError("attachment blob parent is unsafe")
        self.blobs_root = blobs_parent / "sha256"
        if self.blobs_root.is_symlink() or (self.blobs_root.exists() and not self.blobs_root.is_dir()):
            raise ConversationAttachmentError("attachment blob store is unsafe")
        self.blobs_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.blobs_root, 0o700)
        try:
            self.blobs_root.resolve(strict=True).relative_to(root_resolved)
        except ValueError as exc:
            raise ConversationAttachmentError("attachment blob store is outside the attachment root") from exc
        self.database = self.root / "attachments.sqlite3"
        self._mutex = threading.RLock()
        self._initialize()
        self.reconcile()

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS attachments (
                    attachment_id TEXT PRIMARY KEY,
                    instance_id TEXT NOT NULL,
                    conversation_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    media_type TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    digest TEXT NOT NULL,
                    storage_key TEXT NOT NULL,
                    sensitivity_label TEXT NOT NULL,
                    retention_class TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    deleted_at TEXT
                );
                CREATE INDEX IF NOT EXISTS attachment_scope ON attachments(instance_id, conversation_id, deleted_at);
                CREATE TABLE IF NOT EXISTS attachment_receipts (
                    receipt_id TEXT PRIMARY KEY,
                    attachment_id TEXT NOT NULL,
                    instance_id TEXT NOT NULL,
                    conversation_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload_digest TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS attachment_blob_gc (
                    digest TEXT PRIMARY KEY,
                    queued_at TEXT NOT NULL
                );
            """)
            connection.commit()
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        if self.database.exists() and self.database.is_symlink():
            raise ConversationAttachmentError("attachment metadata database is unsafe")
        connection = sqlite3.connect(self.database)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @staticmethod
    def _identity(value: object, field: str) -> str:
        if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
            raise ConversationAttachmentError(f"{field} is invalid")
        return value

    @staticmethod
    def _filename(value: object) -> str:
        if not isinstance(value, str) or not _FILENAME.fullmatch(value):
            raise ConversationAttachmentError("attachment filename is unsafe")
        if value in {".", ".."} or "/" in value or "\\" in value:
            raise ConversationAttachmentError("attachment filename is unsafe")
        return value

    @classmethod
    def _content(cls, value: object) -> bytes:
        if not isinstance(value, str) or not value or len(value) > ((cls.MAX_BYTES + 2) // 3) * 4 + 8:
            raise ConversationAttachmentError("attachment base64 payload is invalid")
        try:
            content = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ConversationAttachmentError("attachment base64 payload is invalid") from exc
        if not content or len(content) > cls.MAX_BYTES:
            raise ConversationAttachmentError("attachment exceeds the maximum byte size")
        return content

    @staticmethod
    def _reject_executable(content: bytes) -> None:
        if content.startswith((b"#!", b"\x7fELF", b"MZ", b"\xfe\xed\xfa", b"\xcf\xfa\xed\xfe", b"PK\x03\x04")):
            raise ConversationAttachmentError("executable or archive attachment content is refused")

    @classmethod
    def _verify_media_type(cls, media_type: object, content: bytes) -> str:
        if not isinstance(media_type, str) or media_type not in cls.MEDIA_TYPES:
            raise ConversationAttachmentError("attachment media type is not allowed")
        cls._reject_executable(content)
        if media_type == "image/png":
            if not content.startswith(b"\x89PNG\r\n\x1a\n"):
                raise ConversationAttachmentError("attachment media type does not match PNG bytes")
        elif media_type == "image/jpeg":
            if not (content.startswith(b"\xff\xd8\xff") and content.rstrip().endswith(b"\xff\xd9")):
                raise ConversationAttachmentError("attachment media type does not match JPEG bytes")
        elif media_type == "application/pdf":
            if not content.startswith(b"%PDF-"):
                raise ConversationAttachmentError("attachment media type does not match PDF bytes")
        else:
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ConversationAttachmentError("text attachment is not valid UTF-8") from exc
            if "\x00" in text:
                raise ConversationAttachmentError("text attachment contains NUL bytes")
            if media_type == "application/json":
                try:
                    json.loads(text)
                except json.JSONDecodeError as exc:
                    raise ConversationAttachmentError("attachment media type does not match JSON bytes") from exc
            elif media_type in {"text/yaml", "application/yaml", "application/x-yaml"}:
                try:
                    import yaml
                    yaml.safe_load(text)
                except Exception as exc:  # SafeLoader rejects unsafe constructors and malformed input.
                    raise ConversationAttachmentError("attachment media type does not match safe YAML bytes") from exc
        return media_type

    @classmethod
    def _policy(cls, sensitivity_label: object, retention_class: object) -> tuple[str, str]:
        sensitivity = "private" if sensitivity_label is None else sensitivity_label
        retention = "conversation_30_days" if retention_class is None else retention_class
        if sensitivity not in cls.SENSITIVITY_LABELS or retention not in cls.RETENTION_CLASSES:
            raise ConversationAttachmentError("attachment sensitivity or retention policy is unsupported")
        return str(sensitivity), str(retention)

    @staticmethod
    def _metadata(row: sqlite3.Row) -> dict[str, object]:
        return {
            "formatVersion": ConversationAttachmentStore.FORMAT,
            "attachmentId": row["attachment_id"], "name": row["name"],
            "mediaType": row["media_type"], "sizeBytes": row["size_bytes"],
            "digest": row["digest"], "storageKey": row["storage_key"],
            "sensitivityLabel": row["sensitivity_label"], "retentionClass": row["retention_class"],
            "createdAt": row["created_at"],
            "contextInclusion": {"status": "not_proposed", "automatic": False},
        }

    def _blob_path(self, digest: str) -> Path:
        if not _DIGEST.fullmatch(digest):
            raise ConversationAttachmentError("attachment digest is invalid")
        try:
            base = self.blobs_root.resolve(strict=True)
            base.relative_to(self.root.resolve(strict=True))
        except (OSError, ValueError) as exc:
            raise ConversationAttachmentError("attachment blob store is outside the attachment root") from exc
        target = base / digest.removeprefix("sha256:")
        if target.parent != base or target.is_symlink():
            raise ConversationAttachmentError("attachment storage path is unsafe")
        return target

    def _stage_blob(self, digest: str, content: bytes) -> tuple[str, str | None]:
        """Stage blob bytes under a temporary name in the blob store.

        The blob never reaches its final content-addressed location before the
        metadata insert commits; the caller moves the staged file into place
        after commit and removes it on rollback, so a failed insert leaves no
        orphaned blob.
        """
        target = self._blob_path(digest)
        if target.exists():
            if not target.is_file() or target.is_symlink() or target.read_bytes() != content:
                raise ConversationAttachmentError("attachment content address is unsafe")
            os.chmod(target, 0o600)
            return f"sha256/{digest.removeprefix('sha256:')}", None
        descriptor, staging = tempfile.mkstemp(prefix=f".upload-{digest.removeprefix('sha256:')}-", dir=self.blobs_root)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(staging, 0o600)
        except Exception:
            try:
                os.unlink(staging)
            except OSError:
                pass
            raise
        return f"sha256/{digest.removeprefix('sha256:')}", staging

    def _place_blob(self, staging: str | None, digest: str) -> None:
        """Move a staged blob into its final content-addressed location after commit."""
        if staging is None:
            return
        target = self._blob_path(digest)
        if target.exists() and target.is_file() and not target.is_symlink():
            os.unlink(staging)
            return
        os.replace(staging, target)

    def _receipt(self, connection: sqlite3.Connection, *, attachment_id: str, instance_id: str, conversation_id: str, action: str, metadata: Mapping[str, object]) -> dict[str, object]:
        created_at = _now()
        receipt_id = f"attachment-receipt-{secrets.token_hex(16)}"
        payload = {"attachmentId": attachment_id, "instanceId": instance_id, "conversationId": conversation_id, "action": action, "metadataDigest": "sha256:" + hashlib.sha256(_canonical(dict(metadata)).encode("utf-8")).hexdigest()}
        connection.execute(
            "INSERT INTO attachment_receipts(receipt_id, attachment_id, instance_id, conversation_id, action, created_at, payload_digest) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (receipt_id, attachment_id, instance_id, conversation_id, action, created_at, payload["metadataDigest"]),
        )
        return {"formatVersion": self.RECEIPT_FORMAT, "receiptId": receipt_id, "attachmentId": attachment_id, "action": action, "createdAt": created_at, "payloadDigest": payload["metadataDigest"], "rawBytesIncluded": False, "contextInclusion": "not_proposed"}

    def upload(self, *, instance_id: object, conversation_id: object, name: object, media_type: object, data_base64: object, sensitivity_label: object = None, retention_class: object = None) -> dict[str, object]:
        instance = self._identity(instance_id, "instance identity")
        conversation = self._identity(conversation_id, "conversation identity")
        filename = self._filename(name)
        content = self._content(data_base64)
        type_value = self._verify_media_type(media_type, content)
        sensitivity, retention = self._policy(sensitivity_label, retention_class)
        digest = "sha256:" + hashlib.sha256(content).hexdigest()
        attachment_id = f"att-{secrets.token_hex(16)}"
        with self._mutex:
            connection = self._connect()
            staging: str | None = None
            try:
                quota = connection.execute("SELECT COUNT(*) AS count, COALESCE(SUM(size_bytes), 0) AS total FROM attachments WHERE instance_id = ? AND conversation_id = ? AND deleted_at IS NULL", (instance, conversation)).fetchone()
                if quota is None or int(quota["count"]) >= self.MAX_ATTACHMENTS_PER_THREAD or int(quota["total"]) + len(content) > self.MAX_THREAD_BYTES:
                    raise ConversationAttachmentError("conversation attachment quota is exhausted")
                storage_key, staging = self._stage_blob(digest, content)
                created_at = _now()
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "INSERT INTO attachments(attachment_id, instance_id, conversation_id, name, media_type, size_bytes, digest, storage_key, sensitivity_label, retention_class, created_at, deleted_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                    (attachment_id, instance, conversation, filename, type_value, len(content), digest, storage_key, sensitivity, retention, created_at),
                )
                row = connection.execute("SELECT * FROM attachments WHERE attachment_id = ?", (attachment_id,)).fetchone()
                assert row is not None
                metadata = self._metadata(row)
                receipt = self._receipt(connection, attachment_id=attachment_id, instance_id=instance, conversation_id=conversation, action="upload", metadata=metadata)
                # A live reference now exists; cancel any queued byte deletion for this digest.
                connection.execute("DELETE FROM attachment_blob_gc WHERE digest = ?", (digest,))
                connection.commit()
                self._place_blob(staging, digest)
                staging = None
                return {"attachment": metadata, "receipt": receipt}
            except Exception:
                connection.rollback()
                raise
            finally:
                if staging is not None:
                    try:
                        os.unlink(staging)
                    except OSError:
                        pass
                connection.close()

    def _row(self, connection: sqlite3.Connection, instance_id: object, conversation_id: object, attachment_id: object, *, include_deleted: bool = False) -> sqlite3.Row:
        instance = self._identity(instance_id, "instance identity")
        conversation = self._identity(conversation_id, "conversation identity")
        if not isinstance(attachment_id, str) or not _ATTACHMENT_ID.fullmatch(attachment_id):
            raise ConversationAttachmentError("attachment identity is invalid")
        deleted = "" if include_deleted else " AND deleted_at IS NULL"
        row = connection.execute(f"SELECT * FROM attachments WHERE attachment_id = ? AND instance_id = ? AND conversation_id = ?{deleted}", (attachment_id, instance, conversation)).fetchone()
        if row is None:
            raise ConversationAttachmentError("attachment is not available for this application conversation")
        return row

    def list_metadata(self, *, instance_id: object, conversation_id: object) -> dict[str, object]:
        instance = self._identity(instance_id, "instance identity")
        conversation = self._identity(conversation_id, "conversation identity")
        connection = self._connect()
        try:
            rows = connection.execute("SELECT * FROM attachments WHERE instance_id = ? AND conversation_id = ? AND deleted_at IS NULL ORDER BY created_at, attachment_id", (instance, conversation)).fetchall()
            return {"formatVersion": "stateport.conversation-attachment-list/v1", "instanceId": instance, "conversationId": conversation, "attachments": [self._metadata(row) for row in rows]}
        finally:
            connection.close()

    def detail(self, *, instance_id: object, conversation_id: object, attachment_id: object) -> dict[str, object]:
        connection = self._connect()
        try:
            return {"attachment": self._metadata(self._row(connection, instance_id, conversation_id, attachment_id))}
        finally:
            connection.close()

    def conversation_reference(self, *, instance_id: object, conversation_id: object, attachment_id: object) -> dict[str, object]:
        detail = self.detail(instance_id=instance_id, conversation_id=conversation_id, attachment_id=attachment_id)["attachment"]
        assert isinstance(detail, dict)
        return {key: detail[key] for key in ("attachmentId", "name", "mediaType", "sizeBytes", "digest")}

    def _queue_blob_gc(self, connection: sqlite3.Connection, digest: str) -> bool:
        """Queue a content-addressed blob for byte deletion once no live attachment references it.

        The reference check and the queue insert happen inside the caller's
        BEGIN IMMEDIATE transaction under the store mutex, so an upload of the
        same content cannot race the decision.
        """
        if not _DIGEST.fullmatch(digest):
            return False
        count = connection.execute(
            "SELECT COUNT(*) AS count FROM attachments WHERE digest = ? AND deleted_at IS NULL",
            (digest,),
        ).fetchone()
        if count is not None and int(count["count"]) > 0:
            return False
        connection.execute(
            "INSERT OR IGNORE INTO attachment_blob_gc(digest, queued_at) VALUES (?, ?)",
            (digest, _now()),
        )
        return True

    def _drain_blob_gc(self) -> int:
        """Idempotently delete blobs whose queued GC entries still have no live references."""
        with self._mutex:
            connection = self._connect()
            try:
                rows = connection.execute("SELECT digest FROM attachment_blob_gc ORDER BY queued_at, digest").fetchall()
                connection.execute("BEGIN IMMEDIATE")
                removed = 0
                for row in rows:
                    digest = row["digest"]
                    if _DIGEST.fullmatch(digest):
                        count = connection.execute(
                            "SELECT COUNT(*) AS count FROM attachments WHERE digest = ? AND deleted_at IS NULL",
                            (digest,),
                        ).fetchone()
                        if count is not None and int(count["count"]) > 0:
                            connection.execute("DELETE FROM attachment_blob_gc WHERE digest = ?", (digest,))
                            continue
                        blob = self._blob_path(digest)
                        if blob.exists() and blob.is_file() and not blob.is_symlink():
                            blob.unlink()
                            removed += 1
                    connection.execute("DELETE FROM attachment_blob_gc WHERE digest = ?", (digest,))
                connection.commit()
                return removed
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise
            finally:
                connection.close()

    def delete(self, *, instance_id: object, conversation_id: object, attachment_id: object) -> dict[str, object]:
        with self._mutex:
            connection = self._connect()
            try:
                row = self._row(connection, instance_id, conversation_id, attachment_id)
                metadata = self._metadata(row)
                connection.execute("BEGIN IMMEDIATE")
                connection.execute("UPDATE attachments SET deleted_at = ? WHERE attachment_id = ?", (_now(), row["attachment_id"]))
                receipt = self._receipt(connection, attachment_id=row["attachment_id"], instance_id=row["instance_id"], conversation_id=row["conversation_id"], action="delete", metadata=metadata)
                self._queue_blob_gc(connection, row["digest"])
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
        # Byte deletion is post-commit only: the metadata tombstone is durable first.
        self._drain_blob_gc()
        return {"attachment": metadata, "receipt": receipt}

    def export(self, *, instance_id: object, conversation_id: object, attachment_id: object) -> dict[str, object]:
        connection = self._connect()
        try:
            row = self._row(connection, instance_id, conversation_id, attachment_id)
            metadata = self._metadata(row)
            content = self._blob_path(row["digest"]).read_bytes()
            if len(content) != row["size_bytes"] or "sha256:" + hashlib.sha256(content).hexdigest() != row["digest"]:
                raise ConversationAttachmentError("attachment content integrity check failed")
            connection.execute("BEGIN IMMEDIATE")
            receipt = self._receipt(connection, attachment_id=row["attachment_id"], instance_id=row["instance_id"], conversation_id=row["conversation_id"], action="export", metadata=metadata)
            connection.commit()
            return {"attachment": metadata, "dataBase64": base64.b64encode(content).decode("ascii"), "receipt": receipt}
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    _RETENTION_DAYS = {
        "conversation_30_days": 30,
        "conversation_90_days": 90,
    }

    def purge_deleted(self) -> dict[str, object]:
        """Queue and drain content-addressed blobs whose attachments are all soft-deleted."""
        with self._mutex:
            connection = self._connect()
            try:
                rows = connection.execute(
                    "SELECT DISTINCT digest FROM attachments WHERE deleted_at IS NOT NULL"
                ).fetchall()
                connection.execute("BEGIN IMMEDIATE")
                for row in rows:
                    self._queue_blob_gc(connection, row["digest"])
                connection.commit()
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise
            finally:
                connection.close()
        removed = self._drain_blob_gc()
        return {"formatVersion": "stateport.attachment-purge-deleted/v1", "blobsRemoved": removed}

    def purge_expired(self) -> dict[str, object]:
        """Soft-delete and queue blob removal for attachments whose retention period has elapsed."""
        with self._mutex:
            connection = self._connect()
            try:
                now = datetime.now(timezone.utc)
                expired: list[dict[str, object]] = []
                rows = connection.execute(
                    "SELECT * FROM attachments WHERE deleted_at IS NULL"
                ).fetchall()
                for row in rows:
                    retention = row["retention_class"]
                    days = self._RETENTION_DAYS.get(retention)
                    if days is None:
                        continue
                    created = datetime.fromisoformat(row["created_at"].replace("Z", "+00:00"))
                    if now - created < timedelta(days=days):
                        continue
                    expired.append({
                        "attachmentId": row["attachment_id"],
                        "digest": row["digest"],
                        "retentionClass": retention,
                        "createdAt": row["created_at"],
                    })
                if expired:
                    connection.execute("BEGIN IMMEDIATE")
                    for item in expired:
                        connection.execute(
                            "UPDATE attachments SET deleted_at = ? WHERE attachment_id = ?",
                            (_now(), item["attachmentId"]),
                        )
                    for item in expired:
                        self._queue_blob_gc(connection, str(item["digest"]))
                    connection.commit()
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise
            finally:
                connection.close()
        if expired:
            self._drain_blob_gc()
        return {
            "formatVersion": "stateport.attachment-purge-expired/v1",
            "expiredCount": len(expired),
            "expired": expired,
        }

    def reconcile(self) -> dict[str, object]:
        """Reconcile blob storage with metadata after a (re)start.

        Finishes queued byte deletions, restores staged uploads whose metadata
        committed but whose blob never reached its final location, removes
        stale staging files, and reclaims orphaned blobs that no live metadata
        references.
        """
        drained = self._drain_blob_gc()
        with self._mutex:
            connection = self._connect()
            try:
                rows = connection.execute("SELECT DISTINCT digest FROM attachments WHERE deleted_at IS NULL").fetchall()
            finally:
                connection.close()
            live = {row["digest"] for row in rows}
            restored = 0
            reclaimed = 0
            for entry in sorted(self.blobs_root.iterdir()):
                if not entry.is_file() or entry.is_symlink():
                    continue
                staging = _STAGING_NAME.fullmatch(entry.name)
                if staging is not None:
                    digest = "sha256:" + staging.group(1)
                    if digest in live and not self._blob_path(digest).exists():
                        os.replace(entry, self._blob_path(digest))
                        os.chmod(self._blob_path(digest), 0o600)
                        restored += 1
                    else:
                        entry.unlink()
                    continue
                if _BLOB_NAME.fullmatch(entry.name) and "sha256:" + entry.name not in live:
                    entry.unlink()
                    reclaimed += 1
            return {
                "formatVersion": "stateport.attachment-reconcile/v1",
                "queuedDeletionsCompleted": drained,
                "stagedUploadsRestored": restored,
                "orphanedBlobsReclaimed": reclaimed,
            }

    def export_all(self) -> dict[str, object]:
        """Export all non-deleted attachment metadata and content for privacy export."""
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT * FROM attachments WHERE deleted_at IS NULL ORDER BY created_at, attachment_id"
            ).fetchall()
            attachments: list[dict[str, object]] = []
            for row in rows:
                metadata = self._metadata(row)
                blob = self._blob_path(row["digest"])
                if blob.exists() and blob.is_file() and not blob.is_symlink():
                    content = blob.read_bytes()
                    if len(content) == row["size_bytes"] and "sha256:" + hashlib.sha256(content).hexdigest() == row["digest"]:
                        metadata["dataBase64"] = base64.b64encode(content).decode("ascii")
                attachments.append(metadata)
            return {
                "formatVersion": "stateport.attachment-export-all/v1",
                "exportedAt": _now(),
                "attachmentCount": len(attachments),
                "attachments": attachments,
            }
        finally:
            connection.close()
