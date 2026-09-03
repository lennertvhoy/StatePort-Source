#!/usr/bin/env python3
"""Focused tests for the durable assistant processor integration boundary."""

from __future__ import annotations

from dataclasses import dataclass
import json
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "conversation-service" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "execution-host" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "external-engine-runtime" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "codex-adapter" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "persistent-app" / "src"))

from external_engine_runtime import ProcessIdentity  # noqa: E402
from stateport_persistent_app.assistant_processor import AssistantProcessor  # noqa: E402
from stateport_persistent_app.assistant_reconciliation import (  # noqa: E402
    AssistantReconciliationState,
)
from stateport_persistent_app.assistant_work import (  # noqa: E402
    AssistantClaim,
    AssistantWorkStore,
)
from stateport_persistent_app.provider_router import ProviderInvocation  # noqa: E402


@dataclass
class Message:
    message_id: str
    conversation_id: str = "conv.study"
    application_id: str = "studystate"
    instance_id: str = "instance.study"
    sequence: int = 1
    kind: str = "user_message"
    body: str = "What should I study next?"


@dataclass
class Reply:
    message_id: str


class FakeConversations:
    def __init__(self) -> None:
        self.sent: list[dict[str, object]] = []
        self.messages: list[dict[str, object]] = [
            {
                "messageId": "msg.user",
                "conversationId": "conv.study",
                "applicationId": "studystate",
                "instanceId": "instance.study",
                "sequence": 1,
                "kind": "user_message",
                "body": "What should I study next?",
                "replyToMessageId": None,
            }
        ]
        self.binding = {
            "applicationId": "studystate",
            "instanceId": "instance.study",
        }

    def presentation(self, *, participant_id: str, conversation_id: str):
        assert participant_id == "local-operator:instance.study"
        assert conversation_id == "conv.study"
        return {
            "applicationBinding": dict(self.binding),
            "messages": [dict(item) for item in self.messages],
        }

    def send_internal(
        self,
        *,
        participant_id: str,
        conversation_id: str,
        body: str,
        kind: str,
        source_message_id: str,
    ) -> Reply:
        assert participant_id == "local-operator:instance.study"
        assert kind == "assistant_message"
        reply = {
            "messageId": f"msg.assistant.{len(self.sent) + 1}",
            "conversationId": conversation_id,
            "applicationId": "studystate",
            "instanceId": "instance.study",
            "sequence": len(self.messages) + 1,
            "kind": "assistant_message",
            "body": body,
            "replyToMessageId": source_message_id,
        }
        self.sent.append(reply)
        self.messages.append(reply)
        return Reply(str(reply["messageId"]))


class FakeRouter:
    def __init__(self) -> None:
        self.invocations = 0
        self.runtime_profile = {
            "formatVersion": "stateport.provider-router/v1",
            "profileDigest": "sha256:" + "a" * 64,
            "provider": {"id": "codex-local"},
            "model": {"id": "fixture"},
        }

    def invoke(self, **kwargs) -> ProviderInvocation:
        self.invocations += 1
        on_started = kwargs.get("on_started")
        if on_started:
            on_started(
                ProcessIdentity(
                    123,
                    123,
                    "1",
                    "generation." + "b" * 64,
                )
            )
        return ProviderInvocation(
            assistant_text="Review the weakest objective first.",
            runtime_profile=self.runtime_profile,
            adapter={"id": "codex-cli", "version": "fixture"},
            provider={"id": "codex-local"},
            model={"id": "fixture"},
            usage={"availability": "unavailable"},
            duration_ms=12,
            cleanup="not_required",
            normalized_events=(),
        )


def processor(
    root: Path,
    conversations: FakeConversations,
    router: FakeRouter,
) -> AssistantProcessor:
    return AssistantProcessor(
        conversations,  # type: ignore[arg-type]
        work_store=AssistantWorkStore(root / "assistant.sqlite3"),
        router=router,  # type: ignore[arg-type]
        staging_root=root / "staging",
        worker_id="assistant.test",
        conversation_store_path=None,
        reconciliation_state=AssistantReconciliationState(root / "reconciliation.json"),
    )


def test_processor_invocation_and_delivery_are_separate_durable_phases() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        conversations = FakeConversations()
        router = FakeRouter()
        current = processor(root, conversations, router)
        queued = current.enqueue(
            Message("msg.user"),  # type: ignore[arg-type]
            participant_id="local-operator:instance.study",
        )
        assert current.process_once()
        stored = AssistantWorkStore(root / "assistant.sqlite3").get(str(queued["workId"]))
        assert stored["state"] == "result_ready"
        assert stored["providerResult"]["assistantText"] == "Review the weakest objective first."
        assert conversations.sent == []
        assert router.invocations == 1

        restarted = processor(root, conversations, router)
        assert restarted.process_once()
        completed = AssistantWorkStore(root / "assistant.sqlite3").get(str(queued["workId"]))
        assert completed["state"] == "completed"
        assert completed["replyMessageId"] == "msg.assistant.1"
        assert len(conversations.sent) == 1
        assert router.invocations == 1


def test_restart_after_reply_persistence_does_not_duplicate_delivery() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        conversations = FakeConversations()
        router = FakeRouter()
        current = processor(root, conversations, router)
        queued = current.enqueue(
            Message("msg.user"),  # type: ignore[arg-type]
            participant_id="local-operator:instance.study",
        )
        assert current.process_once()
        conversations.messages.append(
            {
                "messageId": "msg.preexisting",
                "conversationId": "conv.study",
                "applicationId": "studystate",
                "instanceId": "instance.study",
                "sequence": 2,
                "kind": "assistant_message",
                "body": "Review the weakest objective first.",
                "replyToMessageId": "msg.user",
            }
        )
        restarted = processor(root, conversations, router)
        assert restarted.process_once()
        completed = AssistantWorkStore(root / "assistant.sqlite3").get(str(queued["workId"]))
        assert completed["state"] == "completed"
        assert completed["replyMessageId"] == "msg.preexisting"
        assert conversations.sent == []


def test_conversation_binding_drift_fails_without_model_invocation_or_fake_reply() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        conversations = FakeConversations()
        router = FakeRouter()
        current = processor(root, conversations, router)
        queued = current.enqueue(
            Message("msg.user"),  # type: ignore[arg-type]
            participant_id="local-operator:instance.study",
        )
        conversations.binding["instanceId"] = "instance.other"
        assert current.process_once()
        failed = AssistantWorkStore(root / "assistant.sqlite3").get(str(queued["workId"]))
        assert failed["state"] == "failed"
        assert failed["error"]["code"] == "assistant_invocation_failed"
        assert router.invocations == 0
        assert conversations.sent == []


def test_enqueue_rejects_non_user_messages() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        current = processor(root, FakeConversations(), FakeRouter())
        bad = Message("msg.assistant", kind="assistant_message")
        try:
            current.enqueue(
                bad,  # type: ignore[arg-type]
                participant_id="local-operator:instance.study",
            )
        except Exception as exc:
            assert "only user messages" in str(exc)
        else:
            raise AssertionError("assistant message was incorrectly queued as user work")


def test_activation_cursor_does_not_backfill_history_but_recovers_new_messages() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        conversation_db = root / "conversation.sqlite3"
        connection = sqlite3.connect(conversation_db)
        connection.executescript(
            """
            CREATE TABLE threads (conversation_id TEXT PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE messages (
                message_id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                payload TEXT NOT NULL
            );
            """
        )
        thread = {
            "conversationId": "conv.study",
            "applicationId": "studystate",
            "instanceId": "instance.study",
            "createdBy": "local-operator:instance.study",
        }
        historical = {
            "messageId": "msg.historical",
            "conversationId": "conv.study",
            "applicationId": "studystate",
            "instanceId": "instance.study",
            "sequence": 1,
            "kind": "user_message",
            "body": "Old prompt",
            "replyToMessageId": None,
        }
        connection.execute("INSERT INTO threads VALUES (?, ?)", ("conv.study", json.dumps(thread)))
        connection.execute(
            "INSERT INTO messages VALUES (?, ?, ?, ?)",
            ("msg.historical", "conv.study", 1, json.dumps(historical)),
        )
        connection.commit()

        conversations = FakeConversations()
        router = FakeRouter()
        current = AssistantProcessor(
            conversations,  # type: ignore[arg-type]
            work_store=AssistantWorkStore(root / "assistant.sqlite3"),
            router=router,  # type: ignore[arg-type]
            staging_root=root / "staging",
            conversation_store_path=conversation_db,
            reconciliation_state=AssistantReconciliationState(root / "reconciliation.json"),
            worker_id="assistant.test",
        )
        assert current.reconcile_messages() == 0
        assert AssistantWorkStore(root / "assistant.sqlite3").get_by_message("msg.historical") is None

        fresh = {
            **historical,
            "messageId": "msg.fresh",
            "sequence": 2,
            "body": "New prompt",
        }
        connection.execute(
            "INSERT INTO messages VALUES (?, ?, ?, ?)",
            ("msg.fresh", "conv.study", 2, json.dumps(fresh)),
        )
        connection.commit()
        connection.close()

        assert current.reconcile_messages() == 1
        assert current.reconcile_messages() == 0
        queued = AssistantWorkStore(root / "assistant.sqlite3").get_by_message("msg.fresh")
        assert queued is not None and queued["state"] == "queued"


def test_atm10_guide_context_prioritises_ledger_and_binds_the_rendered_prompt(
    monkeypatch,
) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        source_root = root / "atm10-speedrun-guide"
        (source_root / "state").mkdir(parents=True)
        (source_root / "guide").mkdir(parents=True)
        (source_root / "state" / "ATM_STAR_PROGRESS.yaml").write_text(
            "next_live_checks:\n- Verify RS Pattern Grid and Crafter\n",
            encoding="utf-8",
        )
        (source_root / "NEXT_ACTIONS.md").write_text(
            "# Active\nBL-010: build minimum Flux link before scaling\n",
            encoding="utf-8",
        )
        (source_root / "STATUS.md").write_text(
            "Reported foundation only; the live world is not verified.\n",
            encoding="utf-8",
        )
        (source_root / "PROJECT_STATE.yaml").write_text(
            "project: " + "state " * 5000,
            encoding="utf-8",
        )
        (source_root / "guide" / "ATM10_6.1_FLUX_NETWORKS_STARTER.md").write_text(
            "# Flux Networks Starter Card\n\n"
            "## Decision\n\nMinimum: one Plug plus one Point. Controller optional.\n\n"
            "## Exact minimum totals\n\n"
            "| Item | Need |\n|---|---:|\n| Flux Dust | 17 |\n| Obsidian | 12 |\n"
            "| Eye of Ender | 3 |\n\n## Done when\n\nRS Controller stays powered.\n",
            encoding="utf-8",
        )
        (source_root / "guide" / "ATM10_6.1_SPEEDRUN_RUNBOOK.md").write_text(
            "# Runbook\n\n" + "Broad reference material. " * 500,
            encoding="utf-8",
        )
        data_home = root / "data"
        catalog = data_home / "stateport" / "catalog" / "external-instances.json"
        catalog.parent.mkdir(parents=True)
        catalog.write_text(
            json.dumps(
                {
                    "entries": [
                        {
                            "formatVersion": "stateport.external-catalog-entry/v1",
                            "instanceId": "instance.study",
                            "applicationId": "atm10.speedrun-guide",
                            "path": str(source_root),
                            "status": "active",
                            "filesystem": {
                                "device": source_root.stat().st_dev,
                                "inode": source_root.stat().st_ino,
                                "kind": "directory",
                            },
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.setenv("XDG_DATA_HOME", str(data_home))

        conversations = FakeConversations()
        conversations.binding["applicationId"] = "atm10.speedrun-guide"
        conversations.messages[0]["applicationId"] = "atm10.speedrun-guide"
        conversations.messages[0]["body"] = "Give me the optimal next action."
        current = processor(root, conversations, FakeRouter())
        claim = AssistantClaim(
            work_id="assistant.atm",
            attempt_id="attempt.assistant.atm.1",
            phase="invoke",
            lease_token="lease",
            lease_expires_at="2099-01-01T00:00:00Z",
            instance_id="instance.study",
            application_id="atm10.speedrun-guide",
            conversation_id="conv.study",
            message_id="msg.user",
            participant_id="local-operator:instance.study",
            source_sequence=1,
            attempt_ordinal=1,
            provider_result=None,
        )

        objective, first_digest = current._conversation_objective(claim)
        assert objective.index("[STATUS.md]") < objective.index("[NEXT_ACTIONS.md]")
        assert objective.index("[NEXT_ACTIONS.md]") < objective.index(
            "[guide/ATM10_6.1_FLUX_NETWORKS_STARTER.md]"
        )
        assert "Flux Networks Starter Card" in objective
        assert "one Plug plus one Point" in objective
        assert "Lead with one decision" in objective
        assert len(objective.encode("utf-8")) <= 28 * 1024
        assert len(current._read_instance_context(claim).encode("utf-8")) <= 12 * 1024

        (source_root / "NEXT_ACTIONS.md").write_text(
            "# Active\nBL-010: record the RS result before any circuit lane\n",
            encoding="utf-8",
        )
        changed_objective, changed_digest = current._conversation_objective(claim)
        assert "record the RS result" in changed_objective
        assert changed_digest != first_digest

        conversations.messages[0]["body"] = "x" * 20_000
        bounded_objective, _bounded_digest = current._conversation_objective(claim)
        assert len(bounded_objective.encode("utf-8")) <= 28 * 1024


def test_atm10_guide_context_is_explicit_when_the_registered_source_is_unavailable(
    monkeypatch,
) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        monkeypatch.setenv("XDG_DATA_HOME", str(Path(tmp) / "empty-data"))
        claim = AssistantClaim(
            work_id="assistant.atm",
            attempt_id="attempt.assistant.atm.1",
            phase="invoke",
            lease_token="lease",
            lease_expires_at="2099-01-01T00:00:00Z",
            instance_id="instance.study",
            application_id="atm10.speedrun-guide",
            conversation_id="conv.study",
            message_id="msg.user",
            participant_id="local-operator:instance.study",
            source_sequence=1,
            attempt_ordinal=1,
            provider_result=None,
        )

        context = AssistantProcessor._read_instance_context(claim)

        assert "source context is unavailable" in context
        assert "registered guide files" in context
        assert "could not" in context


def test_atm10_guide_does_not_invoke_a_provider_without_registered_context(
    monkeypatch,
) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        monkeypatch.setenv("XDG_DATA_HOME", str(root / "empty-data"))
        conversations = FakeConversations()
        conversations.binding["applicationId"] = "atm10.speedrun-guide"
        conversations.messages[0]["applicationId"] = "atm10.speedrun-guide"
        router = FakeRouter()
        current = processor(root, conversations, router)
        queued = current.enqueue(
            Message("msg.user", application_id="atm10.speedrun-guide"),  # type: ignore[arg-type]
            participant_id="local-operator:instance.study",
        )

        assert current.process_once()

        failed = AssistantWorkStore(root / "assistant.sqlite3").get(str(queued["workId"]))
        assert failed["state"] == "failed"
        assert failed["error"]["code"] == "assistant_invocation_failed"
        assert router.invocations == 0
        assert conversations.sent == []


def _atm10_fixture(root: Path) -> Path:
    """Create a synthetic public-safe ATM10 instance fixture."""
    source = root / "atm10-source"
    (source / "state").mkdir(parents=True)
    (source / "guide").mkdir(parents=True)
    (source / "STATUS.md").write_text(
        "# Status\nReported: RS, wind power, Mekanism. "
        "No autocrafting or Flux yet.\n",
        encoding="utf-8",
    )
    (source / "NEXT_ACTIONS.md").write_text(
        "# Active\nBL-010: build minimum Flux link\n", encoding="utf-8",
    )
    (source / "guide" / "ATM10_6.1_FLUX_NETWORKS_STARTER.md").write_text(
        "# Flux Networks Starter Card\n\n"
        "## Decision\n\n"
        "Minimum: one Flux Plug plus one Flux Point. "
        "Controller is optional and postponed.\n\n"
        "## Recipe provenance\n\n"
        "Flux Core: 4 Flux Dust + 4 Obsidian + 1 Eye of Ender -> 4 Cores.\n"
        "Flux Block: 5 Flux Dust + 4 Flux Cores -> 1 Block.\n"
        "Flux Plug: 4 Flux Cores + 1 Flux Block -> 1 Plug.\n"
        "Flux Point: 4 Flux Cores + 1 Redstone Block -> 1 Point.\n\n"
        "## Exact minimum: one Plug + one Point\n\n"
        "| Item | Need | Crafts | Output | Surplus |\n"
        "|---|---:|---:|---:|---:|\n"
        "| Flux Core | 12 | 3 | 4 | 0 |\n"
        "| Flux Block | 1 | 1 | 1 | 0 |\n"
        "| Redstone Block | 1 | 1 | 1 | 0 |\n"
        "| Flux Plug | 1 | 1 | 1 | 0 |\n"
        "| Flux Point | 1 | 1 | 1 | 0 |\n\n"
        "### Raw recipe consumption\n\n"
        "| Raw input | Exact amount |\n|---|---:|\n"
        "| Flux Dust | 17 |\n| Obsidian | 12 |\n"
        "| Eye of Ender | 3 |\n| Redstone Dust | 9 |\n\n"
        "## Build and configure\n\n"
        "1. Craft Flux Cores, Block, Plug, Point.\n"
        "2. Place Plug on Energy Cube.\n"
        "3. Create private network MAIN.\n"
        "4. Place Point on RS Controller, select MAIN.\n\n"
        "## Done when\n\n"
        "- RS Controller powered with old Cable removed.\n"
        "- Energy Cube decreases under load and recovers.\n\n"
        "## Next action\n\n"
        "Build one RS autocrafting proof: Pattern Grid + Crafter + simple recipe.\n",
        encoding="utf-8",
    )
    (source / "state" / "ATM_STAR_PROGRESS.yaml").write_text(
        "capabilities:\n  rs_autocrafting: not_started\n"
        "  flux_networks: not_started\n",
        encoding="utf-8",
    )
    (source / "PROJECT_STATE.yaml").write_text(
        "project: ATM10\ncurrent_game_state:\n  confidence: reported\n",
        encoding="utf-8",
    )
    (source / "guide" / "ATM10_6.1_SPEEDRUN_RUNBOOK.md").write_text(
        "# Runbook\n\n" + "Broad reference material. " * 500,
        encoding="utf-8",
    )
    return source


def _register_atm10_instance(
    root: Path, source: Path, instance_id: str = "instance.study"
) -> Path:
    """Register a synthetic instance in the catalog."""
    data_home = root / "data"
    catalog = data_home / "stateport" / "catalog" / "external-instances.json"
    catalog.parent.mkdir(parents=True)
    catalog.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "formatVersion": "stateport.external-catalog-entry/v1",
                        "instanceId": instance_id,
                        "applicationId": "atm10.speedrun-guide",
                        "path": str(source),
                        "status": "active",
                        "filesystem": {
                            "device": source.stat().st_dev,
                            "inode": source.stat().st_ino,
                            "kind": "directory",
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return data_home


def _atm10_claim() -> AssistantClaim:
    return AssistantClaim(
        work_id="assistant.atm",
        attempt_id="attempt.assistant.atm.1",
        phase="invoke",
        lease_token="lease",
        lease_expires_at="2099-01-01T00:00:00Z",
        instance_id="instance.study",
        application_id="atm10.speedrun-guide",
        conversation_id="conv.study",
        message_id="msg.user",
        participant_id="local-operator:instance.study",
        source_sequence=1,
        attempt_ordinal=1,
        provider_result=None,
    )


def test_atm10_context_includes_flux_starter_card(monkeypatch) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        source = _atm10_fixture(root)
        data_home = _register_atm10_instance(root, source)
        monkeypatch.setenv("XDG_DATA_HOME", str(data_home))
        claim = _atm10_claim()
        context = AssistantProcessor._read_instance_context(claim)
        assert "Flux Networks Starter Card" in context
        assert "one Flux Plug plus one Flux Point" in context
        assert "Flux Dust" in context and "17" in context
        assert "Build and configure" in context
        assert "Done when" in context


def test_atm10_runbook_does_not_dominate_context_budget(monkeypatch) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        source = _atm10_fixture(root)
        data_home = _register_atm10_instance(root, source)
        monkeypatch.setenv("XDG_DATA_HOME", str(data_home))
        claim = _atm10_claim()
        context = AssistantProcessor._read_instance_context(claim)
        assert len(context.encode("utf-8")) <= 12 * 1024
        assert "Flux Networks Starter Card" in context
        flux_idx = context.find("Flux Networks Starter Card")
        runbook_idx = context.find("Broad reference material")
        if runbook_idx != -1:
            flux_size = len(
                context[flux_idx:runbook_idx].encode("utf-8")
            )
            runbook_size = len(
                context[runbook_idx:].encode("utf-8")
            )
            assert flux_size > 0
            assert runbook_size <= flux_size * 3, (
                f"runbook ({runbook_size}B) must not dominate the Flux card "
                f"({flux_size}B) in the context budget"
            )


def test_atm10_context_fails_closed_with_only_stale_runbook(monkeypatch) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        source = root / "stale-only"
        (source / "guide").mkdir(parents=True)
        (source / "guide" / "ATM10_6.1_SPEEDRUN_RUNBOOK.md").write_text(
            "# Stale Runbook\nFlux Controller required. Five Points needed.\n",
            encoding="utf-8",
        )
        data_home = _register_atm10_instance(root, source)
        monkeypatch.setenv("XDG_DATA_HOME", str(data_home))
        claim = _atm10_claim()
        context = AssistantProcessor._read_instance_context(claim)
        assert "source context is unavailable" in context or (
            "Flux Networks Starter Card" not in context
            and "STATUS" not in context
        ), "stale-only runbook must not present as authoritative context"


def test_atm10_objective_does_not_require_flux_controller(monkeypatch) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        source = _atm10_fixture(root)
        data_home = _register_atm10_instance(root, source)
        monkeypatch.setenv("XDG_DATA_HOME", str(data_home))
        conversations = FakeConversations()
        conversations.binding["applicationId"] = "atm10.speedrun-guide"
        conversations.messages[0]["applicationId"] = "atm10.speedrun-guide"
        conversations.messages[0]["body"] = "What should I do now?"
        current = processor(root, conversations, FakeRouter())
        objective, _ = current._conversation_objective(_atm10_claim())
        assert "Never require a Flux Controller" in objective
        assert "minimum transfer proof" in objective


def test_atm10_context_stale_catalog_fails_closed(monkeypatch) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        source = _atm10_fixture(root)
        data_home = _register_atm10_instance(root, source)
        monkeypatch.setenv("XDG_DATA_HOME", str(data_home))
        import shutil
        shutil.rmtree(source)
        source.mkdir()
        (source / "STATUS.md").write_text("different directory same path", encoding="utf-8")
        claim = _atm10_claim()
        context = AssistantProcessor._read_instance_context(claim)
        assert "source context is unavailable" in context


def test_atm10_context_has_no_attachment_bytes(monkeypatch) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        source = _atm10_fixture(root)
        (source / "attachment.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"X" * 200)
        data_home = _register_atm10_instance(root, source)
        monkeypatch.setenv("XDG_DATA_HOME", str(data_home))
        claim = _atm10_claim()
        context = AssistantProcessor._read_instance_context(claim)
        assert "\x89PNG" not in context
        assert "attachment.png" not in context
