from __future__ import annotations

import base64
import hashlib
from pathlib import Path
import sqlite3
import sys
import threading

import pytest

ROOT = Path(__file__).resolve().parents[1]
for relative in (
    "packages/statedd-core/src",
    "packages/template-validator/src",
    "packages/persistent-app/src",
    "packages/instance-backup/src",
    "packages/instance-catalog/src",
    "packages/diagnostics/src",
):
    path = ROOT / relative
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from stateport_persistent_app.conversation_attachments import (  # noqa: E402
    ConversationAttachmentError,
    ConversationAttachmentStore,
)


def encoded(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def test_upload_is_content_addressed_and_export_is_integrity_checked(tmp_path: Path) -> None:
    store = ConversationAttachmentStore(tmp_path / "attachments")
    content = b"# private notes\n"
    result = store.upload(
        instance_id="projectstate",
        conversation_id="thread-1",
        name="notes.md",
        media_type="text/markdown",
        data_base64=encoded(content),
    )
    attachment = result["attachment"]
    assert attachment["digest"] == "sha256:" + hashlib.sha256(content).hexdigest()
    assert attachment["storageKey"].startswith("sha256/")
    assert attachment["contextInclusion"] == {"status": "not_proposed", "automatic": False}
    exported = store.export(instance_id="projectstate", conversation_id="thread-1", attachment_id=attachment["attachmentId"])
    assert base64.b64decode(exported["dataBase64"]) == content
    assert exported["receipt"]["rawBytesIncluded"] is False


def test_upload_rejects_unsafe_names_magic_mismatches_and_executables(tmp_path: Path) -> None:
    store = ConversationAttachmentStore(tmp_path / "attachments")
    common = {"instance_id": "projectstate", "conversation_id": "thread-1", "sensitivity_label": "private", "retention_class": "conversation_30_days"}
    with pytest.raises(ConversationAttachmentError):
        store.upload(**common, name="../secret.md", media_type="text/markdown", data_base64=encoded(b"safe"))
    with pytest.raises(ConversationAttachmentError):
        store.upload(**common, name="image.png", media_type="image/png", data_base64=encoded(b"not a png"))
    with pytest.raises(ConversationAttachmentError):
        store.upload(**common, name="run.sh", media_type="text/plain", data_base64=encoded(b"#!/bin/sh\necho nope"))
    with pytest.raises(ConversationAttachmentError):
        store.upload(**common, name="data.json", media_type="application/json", data_base64=encoded(b"not json"))


def test_symlinked_blob_parents_fail_closed(tmp_path: Path) -> None:
    root = tmp_path / "attachments"
    root.mkdir()
    (root / "blobs").symlink_to(tmp_path / "outside", target_is_directory=True)
    with pytest.raises(ConversationAttachmentError):
        ConversationAttachmentStore(root)


def test_attachment_scope_delete_and_quota_are_application_bound(tmp_path: Path) -> None:
    store = ConversationAttachmentStore(tmp_path / "attachments")
    uploaded = store.upload(
        instance_id="projectstate",
        conversation_id="thread-1",
        name="data.json",
        media_type="application/json",
        data_base64=encoded(b'{"safe": true}'),
    )["attachment"]
    with pytest.raises(ConversationAttachmentError):
        store.detail(instance_id="studystate", conversation_id="thread-1", attachment_id=uploaded["attachmentId"])
    with pytest.raises(ConversationAttachmentError):
        store.conversation_reference(instance_id="projectstate", conversation_id="thread-2", attachment_id=uploaded["attachmentId"])
    deleted = store.delete(instance_id="projectstate", conversation_id="thread-1", attachment_id=uploaded["attachmentId"])
    assert deleted["receipt"]["action"] == "delete"
    with pytest.raises(ConversationAttachmentError):
        store.detail(instance_id="projectstate", conversation_id="thread-1", attachment_id=uploaded["attachmentId"])


def _blob_path(store: ConversationAttachmentStore, digest: str) -> Path:
    return store.blobs_root / digest.removeprefix("sha256:")


def _gc_rows(store: ConversationAttachmentStore) -> list[tuple]:
    connection = sqlite3.connect(store.database)
    try:
        return connection.execute("SELECT digest, queued_at FROM attachment_blob_gc").fetchall()
    finally:
        connection.close()


def _staging_files(store: ConversationAttachmentStore) -> list[Path]:
    return [entry for entry in store.blobs_root.iterdir() if entry.name.startswith(".upload-")]


def test_failed_upload_commit_leaves_no_metadata_and_no_orphaned_blob(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = ConversationAttachmentStore(tmp_path / "attachments")
    content = b'{"transactional": true}'
    digest = "sha256:" + hashlib.sha256(content).hexdigest()

    def broken_receipt(*args: object, **kwargs: object) -> dict[str, object]:
        raise sqlite3.OperationalError("simulated commit failure")

    monkeypatch.setattr(store, "_receipt", broken_receipt)
    with pytest.raises(sqlite3.OperationalError):
        store.upload(
            instance_id="projectstate",
            conversation_id="thread-1",
            name="data.json",
            media_type="application/json",
            data_base64=encoded(content),
        )
    # The insert rolled back: no active metadata exists at all.
    assert store.list_metadata(instance_id="projectstate", conversation_id="thread-1")["attachments"] == []
    # The staged blob was removed and never reached its final location: no orphan.
    assert not _blob_path(store, digest).exists()
    assert _staging_files(store) == []
    assert _gc_rows(store) == []


def test_failed_delete_commit_keeps_live_metadata_and_blob(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = ConversationAttachmentStore(tmp_path / "attachments")
    content = b'{"transactional": true}'
    digest = "sha256:" + hashlib.sha256(content).hexdigest()
    uploaded = store.upload(
        instance_id="projectstate",
        conversation_id="thread-1",
        name="data.json",
        media_type="application/json",
        data_base64=encoded(content),
    )["attachment"]

    def broken_receipt(*args: object, **kwargs: object) -> dict[str, object]:
        raise sqlite3.OperationalError("simulated commit failure")

    monkeypatch.setattr(store, "_receipt", broken_receipt)
    with pytest.raises(sqlite3.OperationalError):
        store.delete(instance_id="projectstate", conversation_id="thread-1", attachment_id=uploaded["attachmentId"])
    # Tombstone rolled back: metadata is still live and the blob is intact.
    assert store.detail(instance_id="projectstate", conversation_id="thread-1", attachment_id=uploaded["attachmentId"])["attachment"]["digest"] == digest
    assert _blob_path(store, digest).read_bytes() == content
    assert _gc_rows(store) == []


def test_restart_finishes_queued_deletion_after_crash_between_commit_and_byte_deletion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "attachments"
    store = ConversationAttachmentStore(root)
    content = b'{"crash": true}'
    digest = "sha256:" + hashlib.sha256(content).hexdigest()
    uploaded = store.upload(
        instance_id="projectstate",
        conversation_id="thread-1",
        name="data.json",
        media_type="application/json",
        data_base64=encoded(content),
    )["attachment"]
    # Simulate a crash after the tombstone commit but before byte deletion.
    monkeypatch.setattr(store, "_drain_blob_gc", lambda: 0)
    store.delete(instance_id="projectstate", conversation_id="thread-1", attachment_id=uploaded["attachmentId"])
    # The tombstone is durable and the bytes are still on disk awaiting GC.
    with pytest.raises(ConversationAttachmentError):
        store.detail(instance_id="projectstate", conversation_id="thread-1", attachment_id=uploaded["attachmentId"])
    assert _blob_path(store, digest).exists()
    assert [row[0] for row in _gc_rows(store)] == [digest]
    # Restart: the new store reconciles and finishes the queued deletion.
    restarted = ConversationAttachmentStore(root)
    assert not _blob_path(restarted, digest).exists()
    assert _gc_rows(restarted) == []


def test_restart_reclaims_orphaned_blobs_and_stale_staging_files(tmp_path: Path) -> None:
    root = tmp_path / "attachments"
    store = ConversationAttachmentStore(root)
    content = b'{"live": true}'
    live_digest = "sha256:" + hashlib.sha256(content).hexdigest()
    store.upload(
        instance_id="projectstate",
        conversation_id="thread-1",
        name="data.json",
        media_type="application/json",
        data_base64=encoded(content),
    )
    # An orphaned blob with no metadata reference (the pre-fix failure mode).
    orphan_digest = "sha256:" + hashlib.sha256(b"orphan").hexdigest()
    _blob_path(store, orphan_digest).write_bytes(b"orphan")
    # A stale staging file whose upload never committed.
    stale = store.blobs_root / f".upload-{hashlib.sha256(b'stale').hexdigest()}-abcdef"
    stale.write_bytes(b"stale")
    restarted = ConversationAttachmentStore(root)
    assert not _blob_path(restarted, orphan_digest).exists()
    assert _staging_files(restarted) == []
    # The live blob is untouched.
    assert _blob_path(restarted, live_digest).read_bytes() == content


def test_restart_restores_staged_upload_that_crashed_between_commit_and_placement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "attachments"
    store = ConversationAttachmentStore(root)
    content = b'{"staged": true}'
    digest = "sha256:" + hashlib.sha256(content).hexdigest()
    # Simulate a crash after the metadata commit but before the staged blob moved into place.
    monkeypatch.setattr(store, "_place_blob", lambda staging, digest_value: None)
    uploaded = store.upload(
        instance_id="projectstate",
        conversation_id="thread-1",
        name="data.json",
        media_type="application/json",
        data_base64=encoded(content),
    )["attachment"]
    assert uploaded["digest"] == digest
    assert not _blob_path(store, digest).exists()
    assert len(_staging_files(store)) == 1
    # Restart: reconciliation restores the staged bytes so live metadata never references missing content.
    restarted = ConversationAttachmentStore(root)
    assert _blob_path(restarted, digest).read_bytes() == content
    exported = restarted.export(instance_id="projectstate", conversation_id="thread-1", attachment_id=uploaded["attachmentId"])
    assert base64.b64decode(exported["dataBase64"]) == content


def test_shared_digest_blob_survives_until_last_reference_is_deleted(tmp_path: Path) -> None:
    store = ConversationAttachmentStore(tmp_path / "attachments")
    content = b'{"shared": true}'
    digest = "sha256:" + hashlib.sha256(content).hexdigest()
    first = store.upload(
        instance_id="projectstate",
        conversation_id="thread-1",
        name="one.json",
        media_type="application/json",
        data_base64=encoded(content),
    )["attachment"]
    second = store.upload(
        instance_id="projectstate",
        conversation_id="thread-1",
        name="two.json",
        media_type="application/json",
        data_base64=encoded(content),
    )["attachment"]
    store.delete(instance_id="projectstate", conversation_id="thread-1", attachment_id=first["attachmentId"])
    # One live reference remains: the blob must survive.
    assert _blob_path(store, digest).read_bytes() == content
    assert _gc_rows(store) == []
    store.delete(instance_id="projectstate", conversation_id="thread-1", attachment_id=second["attachmentId"])
    assert not _blob_path(store, digest).exists()
    assert _gc_rows(store) == []


def test_concurrent_upload_and_delete_of_same_digest_cannot_race(tmp_path: Path) -> None:
    store = ConversationAttachmentStore(tmp_path / "attachments")
    for round_index in range(8):
        content = f'{{"race": {round_index}}}'.encode("utf-8")
        digest = "sha256:" + hashlib.sha256(content).hexdigest()
        seed = store.upload(
            instance_id="projectstate",
            conversation_id="thread-1",
            name=f"race-{round_index}.json",
            media_type="application/json",
            data_base64=encoded(content),
        )["attachment"]
        errors: list[BaseException] = []

        def deleter() -> None:
            try:
                store.delete(instance_id="projectstate", conversation_id="thread-1", attachment_id=seed["attachmentId"])
            except BaseException as exc:  # noqa: BLE001 - collected and asserted on the main thread
                errors.append(exc)

        def uploader() -> None:
            try:
                store.upload(
                    instance_id="projectstate",
                    conversation_id="thread-1",
                    name=f"race-{round_index}-b.json",
                    media_type="application/json",
                    data_base64=encoded(content),
                )
            except BaseException as exc:  # noqa: BLE001 - collected and asserted on the main thread
                errors.append(exc)

        threads = [threading.Thread(target=deleter), threading.Thread(target=uploader)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert errors == []
        # Invariant in every interleaving: live metadata never references missing content,
        # and no queued deletion remains once the store is quiet.
        live = store.list_metadata(instance_id="projectstate", conversation_id="thread-1")["attachments"]
        assert any(item["digest"] == digest for item in live)
        assert _blob_path(store, digest).read_bytes() == content
        assert _gc_rows(store) == []
