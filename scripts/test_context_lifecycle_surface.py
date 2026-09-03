#!/usr/bin/env python3
"""Product-surface and real-service tests for app-attached context lifecycle."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest


ROOT = Path(__file__).resolve().parents[1]
for relative in (
    "packages/persistent-app/src",
    "packages/instance-backup/src",
    "packages/instance-catalog/src",
    "packages/diagnostics/src",
    "packages/statedd-core/src",
    "packages/template-validator/src",
    "apps/runner/src",
):
    sys.path.insert(0, str(ROOT / relative))

from stateport_persistent_app import LocalLayout, PersistentApp  # noqa: E402
from service_test_product import service_product_fixture  # noqa: E402


DIGEST_A = "sha256:" + "a" * 64


def _repository(path: Path) -> Path:
    path.mkdir()
    (path / "STATE.yaml").write_text("goal: remain canonical\n", encoding="utf-8")
    environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_AUTHOR_NAME": "StatePort test",
        "GIT_AUTHOR_EMAIL": "stateport@example.invalid",
        "GIT_COMMITTER_NAME": "StatePort test",
        "GIT_COMMITTER_EMAIL": "stateport@example.invalid",
    }
    for arguments in (
        ("init", "--initial-branch=main", "--template="),
        ("add", "--all"),
        ("-c", "commit.gpgSign=false", "commit", "-m", "fixture"),
    ):
        subprocess.run(
            ("/usr/bin/git", "-C", path.as_posix(), *arguments),
            check=True,
            capture_output=True,
            env=environment,
        )
    return path.resolve()


def _application_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if not path.is_file() or ".git" in path.relative_to(root).parts:
            continue
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()


def test_context_controls_are_progressively_disclosed_and_do_not_offer_raw_prompt_fields() -> None:
    types = (ROOT / "apps" / "web" / "src" / "client" / "types.ts").read_text(encoding="utf-8")
    mappers = (ROOT / "apps" / "web" / "src" / "client" / "http" / "mappers.ts").read_text(encoding="utf-8")
    execution = (ROOT / "apps" / "web" / "src" / "client" / "http" / "domainsExecution.ts").read_text(encoding="utf-8")
    app_settings = (ROOT / "apps" / "web" / "src" / "features" / "settings" / "AppSettingsView.tsx").read_text(encoding="utf-8")
    context_group = (ROOT / "apps" / "web" / "src" / "features" / "settings" / "ContextLifecycleGroup.tsx").read_text(encoding="utf-8")
    context_shell = (ROOT / "apps" / "web" / "src" / "shell" / "AppContextShell.tsx").read_text(encoding="utf-8")
    view_registry = (ROOT / "apps" / "web" / "src" / "features" / "application-experience" / "registry.ts").read_text(encoding="utf-8")
    # The context preference stays an explicit three-mode contract; compact
    # and handoff transitions stay bound to the exact continuity identity.
    assert "export type ContextPreference = 'faster' | 'balanced' | 'deeper'" in types
    assert "async updatePreference(" in execution
    assert "expectedPolicyDigest: input.expectedPolicyDigest," in execution
    assert "compact(instanceId: string, input: ContextTransitionBinding)" in execution
    assert "handoff(instanceId: string, input: ContextTransitionBinding)" in execution
    assert "compact/handoff must never claim" in execution
    # The application-scoped Settings route now consumes the real context
    # client. It exposes exact identity-bound preference/compact/handoff
    # controls and represents raw prompts as a read-only policy fact.
    assert "id: 'context'," in app_settings
    assert "return <ContextLifecycleGroup" in app_settings
    assert ".context.getLifecycle(instanceId)" in context_group
    assert ".context.updatePreference(instanceId" in context_group
    assert ".context.compact(instanceId, binding)" in context_group
    assert ".context.handoff(instanceId, binding)" in context_group
    assert 'data-testid="context-compact"' in context_group
    assert 'data-testid="context-handoff"' in context_group
    assert "Operational context, not application truth" in context_group
    # Raw prompt overrides stay impossible end to end: the strict projection
    # must carry the policy fact, and the surface renders that value through
    # ReadOnlyValue rather than an editable prompt field. Missing policy
    # evidence is rejected instead of silently defaulted.
    assert "rawPromptFieldsAllowed" in types
    assert "rawPromptFieldsAllowed: z.boolean()" in mappers
    assert "rawPromptFieldsAllowed: wire.preference.rawPromptFieldsAllowed" in mappers
    assert 'label="Raw prompt overrides"' in context_group
    assert "<ReadOnlyValue" in context_group
    assert "<textarea" not in context_group and "contentEditable=" not in context_group
    # Context controls remain progressively disclosed. Conversation label and
    # order come from the bound descriptor registry, while Settings remains a
    # late StatePort-owned shell contribution rather than package-injected
    # navigation or a global Context home.
    assert "applicationNavigation(instance)" in context_shell
    assert "component: 'conversation_thread'" in view_registry
    assert "label: contribution.label" in view_registry
    assert "order: contribution.order" in view_registry
    assert "left.order - right.order" in view_registry
    settings_contribution = view_registry.index("destination: 'settings'")
    assert view_registry.index("component: 'conversation_thread'") < settings_contribution
    assert "order: 1000" in view_registry[settings_contribution:]
    assert "source: 'stateport'" in view_registry[settings_contribution:]
    assert "label: 'Context lifecycle'" in app_settings


def test_real_service_exposes_policy_and_creates_noncanonical_receipted_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    instance = _repository(app.layout.instances_root / "project-one")
    app.catalog.register(
        instance,
        instance_id="project-one",
        name="Project One",
        source={
            "templateId": "stateport.development-reference",
            "resolvedCommit": "fixture:context-lifecycle",
            "resolvedTree": "context-lifecycle",
            "manifestDigest": DIGEST_A,
        },
    )
    before = _application_digest(instance)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])
    app.service_start(
        port=port,
        repo_root=service_product_fixture(tmp_path, ROOT),
    )
    try:
        unauthenticated = Request(
            f"http://127.0.0.1:{port}/v1/instances/project-one/context-lifecycle",
        )
        with pytest.raises(HTTPError) as denied:
            urlopen(unauthenticated)
        assert denied.value.code == 401

        with urlopen(f"http://127.0.0.1:{port}/session") as response:
            session = json.loads(response.read())["result"]
            cookie = response.headers["Set-Cookie"].split(";", 1)[0]

        def get(path: str) -> dict[str, object]:
            request = Request(f"http://127.0.0.1:{port}{path}", headers={"Cookie": cookie})
            with urlopen(request) as response:
                return json.loads(response.read())["result"]

        def post(path: str, payload: dict[str, object]) -> dict[str, object]:
            request = Request(
                f"http://127.0.0.1:{port}{path}",
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Cookie": cookie,
                    "Origin": f"http://127.0.0.1:{port}",
                    "X-StatePort-CSRF": session["csrfToken"],
                },
                method="POST",
            )
            with urlopen(request) as response:
                return json.loads(response.read())["result"]

        view = get("/v1/instances/project-one/context-lifecycle")
        assert view["preference"]["mode"] == "balanced"
        assert view["preference"]["rawPromptFieldsAllowed"] is False
        assert view["usage"] == {
            "formatVersion": "stateport.context-usage/v1",
            "inputTokens": None,
            "quality": "unavailable",
            "source": "unavailable",
        }
        assert view["continuity"]["available"] is False
        assert view["continuity"]["manualCompactAvailable"] is False

        message = post(
            "/v1/instances/project-one/conversation/messages",
            {
                "clientMessageId": "context-task-1",
                "text": "Prepare a truthful handoff for the current project slice.",
                "replyToExternalMessageId": None,
                "attachments": [],
            },
        )
        assert message["ingest"]["status"] == "accepted"
        view = get("/v1/instances/project-one/context-lifecycle")
        assert view["usage"]["quality"] == "estimated"
        assert view["usage"]["source"] == "stateport_estimator"
        assert view["continuity"]["available"] is True
        assert view["continuity"]["manualCompactAvailable"] is True
        assert view["continuity"]["manualHandoffAvailable"] is True
        assert view["continuity"]["continuityDigest"].startswith("sha256:")
        assert view["effectivePolicy"]["unresolvedPolicyScopes"] == ["template", "instance", "backend", "budget"]
        balanced_digest = view["effectivePolicy"]["effectivePolicyDigest"]
        raw_preference = Request(
            f"http://127.0.0.1:{port}/v1/instances/project-one/context-lifecycle/preference",
            data=json.dumps({
                "expectedInstanceId": "project-one",
                "expectedPolicyDigest": balanced_digest,
                "mode": "faster",
                "rawPrompt": "do not accept browser-supplied policy text",
            }).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Cookie": cookie,
                "Origin": f"http://127.0.0.1:{port}",
                "X-StatePort-CSRF": session["csrfToken"],
            },
            method="POST",
        )
        with pytest.raises(HTTPError) as raw_preference_refused:
            urlopen(raw_preference)
        assert raw_preference_refused.value.code == 400
        assert json.loads(raw_preference_refused.value.read())["error"]["code"] == "operation_failed"
        faster = post(
            "/v1/instances/project-one/context-lifecycle/preference",
            {
                "expectedInstanceId": "project-one",
                "expectedPolicyDigest": balanced_digest,
                "mode": "faster",
            },
        )
        assert faster["preference"]["mode"] == "faster"
        assert faster["effectivePolicy"]["budget"]["maximumInputTokens"] == 64000

        binding = {
            "expectedInstanceId": "project-one",
            "expectedBaseSha": faster["continuity"]["expectedBaseSha"],
            "expectedPolicyDigest": faster["continuity"]["expectedPolicyDigest"],
            "expectedContinuityDigest": faster["continuity"]["continuityDigest"],
        }
        missing_csrf = Request(
            f"http://127.0.0.1:{port}/v1/instances/project-one/context-lifecycle/compact",
            data=json.dumps(binding).encode("utf-8"),
            headers={"Content-Type": "application/json", "Cookie": cookie},
            method="POST",
        )
        with pytest.raises(HTTPError) as csrf_denied:
            urlopen(missing_csrf)
        assert csrf_denied.value.code == 403

        raw_continuity = Request(
            f"http://127.0.0.1:{port}/v1/instances/project-one/context-lifecycle/compact",
            data=json.dumps({**binding, "usage": {}}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Cookie": cookie,
                "Origin": f"http://127.0.0.1:{port}",
                "X-StatePort-CSRF": session["csrfToken"],
            },
            method="POST",
        )
        with pytest.raises(HTTPError) as raw_refused:
            urlopen(raw_continuity)
        assert raw_refused.value.code == 409
        assert json.loads(raw_refused.value.read())["error"]["code"] == "invalid_context_lifecycle_binding"

        browser_compact = post("/v1/instances/project-one/context-lifecycle/compact", binding)
        browser_handoff = post("/v1/instances/project-one/context-lifecycle/handoff", binding)
        assert browser_compact["receipt"]["action"] == "compression"
        assert browser_handoff["receipt"]["action"] == "handoff"
        assert browser_handoff["artifact"]["conversationId"] == faster["continuity"]["conversationId"]
        second_message = post(
            "/v1/instances/project-one/conversation/messages",
            {
                "clientMessageId": "context-task-2",
                "text": "Continue after the handoff without changing the logical workstream.",
                "replyToExternalMessageId": None,
                "attachments": [],
            },
        )
        assert second_message["ingest"]["status"] == "accepted"
        continued = get("/v1/instances/project-one/context-lifecycle")
        assert continued["continuity"]["conversationId"] == faster["continuity"]["conversationId"]
        assert continued["continuity"]["workstreamId"] == faster["continuity"]["workstreamId"]
        assert continued["continuity"]["continuityDigest"] != faster["continuity"]["continuityDigest"]

        stale_request = Request(
            f"http://127.0.0.1:{port}/v1/instances/project-one/context-lifecycle/preference",
            data=json.dumps({
                "expectedInstanceId": "project-one",
                "expectedPolicyDigest": balanced_digest,
                "mode": "deeper",
            }).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Cookie": cookie,
                "Origin": f"http://127.0.0.1:{port}",
                "X-StatePort-CSRF": session["csrfToken"],
            },
            method="POST",
        )
        with pytest.raises(HTTPError) as stale:
            urlopen(stale_request)
        assert stale.value.code == 409
        assert json.loads(stale.value.read())["error"]["code"] == "context_policy_changed"

        assert browser_compact["canonicalStateUnchanged"] is True
        assert browser_compact["receipt"]["transcriptRetained"] is False
        assert browser_handoff["artifact"]["providerSessionStrategy"] == "fresh_session_same_logical_conversation"
        assert browser_handoff["receipt"]["artifactDigest"] == browser_handoff["artifact"]["artifactDigest"]
        assert _application_digest(instance) == before
        records = tuple((app.layout.state_root / "context-lifecycle" / "records" / "project-one").glob("*.json"))
        assert len(records) == 2
        assert not tuple(instance.rglob("*context-lifecycle*"))
    finally:
        app.service_stop()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
