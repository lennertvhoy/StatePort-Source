#!/usr/bin/env python3
"""Regression tests for per-work assistant cancellation and cleanup."""

from __future__ import annotations

from dataclasses import dataclass
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "conversation-service" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "execution-host" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "external-engine-runtime" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "codex-adapter" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "persistent-app" / "src"))

from external_engine_runtime import (  # noqa: E402
    ProcessSpec,
    filtered_environment,
    run_process,
)
from stateport_persistent_app.assistant_cancellable_runtime import (  # noqa: E402
    AssistantProcessor,
    CancellableAssistantWorkStore,
)
from stateport_persistent_app.assistant_reconciliation import (  # noqa: E402
    AssistantReconciliationState,
)
from stateport_persistent_app.provider_router import (  # noqa: E402
    ProviderInvocation,
    ProviderRouterError,
)


@dataclass
class Message:
    message_id: str = "msg.user"
    conversation_id: str = "conv.study"
    application_id: str = "studystate"
    instance_id: str = "instance.study"
    sequence: int = 1
    kind: str = "user_message"
    body: str = "What should I study next?"


class FakeConversations:
    def __init__(self) -> None:
        self.messages = [
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

    def presentation(self, *, participant_id: str, conversation_id: str):
        assert participant_id == "local-operator:instance.study"
        assert conversation_id == "conv.study"
        return {
            "applicationBinding": {
                "applicationId": "studystate",
                "instanceId": "instance.study",
            },
            "messages": [dict(item) for item in self.messages],
        }

    def send_internal(self, **_kwargs):
        raise AssertionError("cancelled work must not deliver an assistant reply")


class BlockingProcessRouter:
    def __init__(self) -> None:
        self.invocations = 0
        self.runtime_profile = {
            "formatVersion": "stateport.provider-router/v1",
            "profileDigest": "sha256:" + "a" * 64,
            "provider": {"id": "codex-local"},
            "model": {"id": "fixture"},
            "budgets": {"timeSeconds": 20},
        }

    def invoke(self, **kwargs) -> ProviderInvocation:
        self.invocations += 1
        staging = kwargs["staging_root"]
        command = (
            sys.executable,
            "-c",
            (
                "import subprocess,sys,time; "
                "subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']); "
                "print('provider-started', flush=True); time.sleep(30)"
            ),
        )
        result = run_process(
            ProcessSpec(
                command,
                staging,
                timeout_seconds=20,
                max_output_bytes=32 * 1024,
                environment=filtered_environment(),
                on_started=kwargs.get("on_started"),
                on_finished=kwargs.get("on_finished"),
                process_generation=(
                    "generation."
                    + "b" * 64
                ),
            ),
            cancel_event=kwargs.get("cancel_event"),
        )
        if result.cancelled:
            raise ProviderRouterError("provider_cancelled")
        return ProviderInvocation(
            assistant_text="unexpected",
            runtime_profile=self.runtime_profile,
            adapter={"id": "fixture", "version": "1"},
            provider={"id": "fixture"},
            model={"id": "fixture"},
            usage={"availability": "unavailable"},
            duration_ms=result.duration_ms,
            cleanup=result.cleanup,
            normalized_events=(),
        )


def processor(root: Path, router: BlockingProcessRouter) -> AssistantProcessor:
    return AssistantProcessor(
        FakeConversations(),  # type: ignore[arg-type]
        work_store=CancellableAssistantWorkStore(root / "assistant.sqlite3"),
        router=router,  # type: ignore[arg-type]
        staging_root=root / "staging",
        conversation_store_path=None,
        reconciliation_state=AssistantReconciliationState(
            root / "reconciliation.json"
        ),
        worker_id="assistant.cancel-test",
        poll_interval=0.05,
    )


def enqueue(current: AssistantProcessor) -> dict[str, object]:
    return current.enqueue(
        Message(),  # type: ignore[arg-type]
        participant_id="local-operator:instance.study",
    )


def test_queued_work_cancels_without_provider_invocation() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        router = BlockingProcessRouter()
        current = processor(root, router)
        queued = enqueue(current)

        outcome = current.cancel_message("msg.user")

        assert outcome["status"] == "cancelled"
        record = current.work_store.get(str(queued["workId"]))
        assert record["state"] == "cancelled"
        assert record["error"]["code"] == "user_cancelled"
        assert router.invocations == 0
        assert current.process_once() is False
        assert current.work_store.event_journal(str(queued["workId"]))[-1][
            "payload"
        ]["cancelled"] is True


def test_reattach_during_grace_prevents_disconnect_cancellation() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        current = processor(root, BlockingProcessRouter())
        queued = enqueue(current)
        first = current.attach_stream("msg.user")
        current.detach_stream(first, disconnected=True)
        time.sleep(0.2)
        replacement = current.attach_stream("msg.user")
        time.sleep(1.6)

        assert current.work_store.get(str(queued["workId"]))["state"] == "queued"
        current.detach_stream(replacement, disconnected=False)


def test_final_disconnect_reaps_process_group_and_never_reinvokes() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        router = BlockingProcessRouter()
        current = processor(root, router)
        queued = enqueue(current)
        stream = current.attach_stream("msg.user")
        worker = threading.Thread(target=current.process_once, daemon=True)
        worker.start()

        deadline = time.monotonic() + 5
        process_identity = None
        while time.monotonic() < deadline:
            record = current.work_store.get(str(queued["workId"]))
            attempts = record.get("attempts", [])
            if attempts and attempts[0].get("processIdentity"):
                process_identity = attempts[0]["processIdentity"]
                break
            time.sleep(0.02)
        assert process_identity is not None

        current.detach_stream(stream, disconnected=True)
        worker.join(timeout=6)
        assert not worker.is_alive()

        record = current.work_store.get(str(queued["workId"]))
        assert record["state"] == "cancelled"
        assert record["error"]["code"] == "stream_disconnected"
        attempt = record["attempts"][0]
        assert attempt["state"] == "interrupted"
        assert attempt["error"]["cleanup"] in {
            "terminated",
            "killed",
            "already_exited",
            "forced_kill",
            "finished_before_cancel",
        }
        assert router.invocations == 1

        restarted = processor(root, router)
        assert restarted.process_once() is False
        assert router.invocations == 1
        assert restarted.work_store.get(str(queued["workId"]))["state"] == "cancelled"
