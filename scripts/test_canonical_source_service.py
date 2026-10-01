#!/usr/bin/env python3
"""Service and app-shell proofs for the canonical-source boundary."""

from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path
import sys
import threading
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
for relative in (
    "packages/persistent-app/src",
    "packages/portable-execution/src",
    "packages/application-experience/src",
    "packages/context-lifecycle/src",
    "packages/conversation-service/src",
    "packages/terminal-broker/src",
    "packages/file-workspace-broker/src",
    "packages/execution-host/src",
    "packages/external-engine-runtime/src",
    "packages/codex-adapter/src",
    "packages/run-bundle/src",
    "packages/statedd-core/src",
    "packages/template-validator/src",
    "packages/instance-backup/src",
    "packages/instance-catalog/src",
    "packages/diagnostics/src",
    "packages/statebench/src",
    "packages/governed-runner/src",
    "packages/sandbox-runtime/src",
):
    source = ROOT / relative
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from stateport_persistent_app import LocalLayout, PersistentApp  # noqa: E402
from stateport_persistent_app import service_process  # noqa: E402
from stateport_persistent_app.service_process import AppServer  # noqa: E402


CATALOG = ROOT / "sources" / "canonical" / "studydd.yaml"


def _request(
    port: int,
    path: str,
    *,
    cookie: str | None = None,
    csrf: str | None = None,
    body: dict[str, object] | None = None,
    origin: str | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, object]]:
    request_headers = {"Accept": "application/json", **(headers or {})}
    if cookie:
        request_headers["Cookie"] = cookie
    if body is not None:
        request_headers["Content-Type"] = "application/json"
        request_headers["Origin"] = origin or f"http://127.0.0.1:{port}"
    if csrf is not None:
        request_headers["X-StatePort-CSRF"] = csrf
    request = Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(body).encode("utf-8") if body is not None else None,
        headers=request_headers,
        method="POST" if body is not None else "GET",
    )
    try:
        with urlopen(request) as response:
            return response.status, json.loads(response.read())
    except HTTPError as error:
        return error.code, json.loads(error.read())


@contextmanager
def _service(
    layout: LocalLayout,
    *,
    actor_role: str,
    canonical_source_catalog: Path = CATALOG,
):
    if actor_role == "platform_operator":
        boundary = layout.config_root / "platform-operator-authority"
        boundary.write_text("test operator boundary\n", encoding="utf-8")
        boundary.chmod(0o600)
    server = AppServer(
        ("127.0.0.1", 0),
        layout,
        ROOT / "apps" / "web",
        actor_role=actor_role,
        canonical_source_catalog=canonical_source_catalog,
    )
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield server, int(server.server_address[1])
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()
        assert not thread.is_alive()


def _layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> LocalLayout:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    layout = LocalLayout.from_environment()
    layout.initialize()
    return layout


def _session(port: int) -> tuple[str, str]:
    with urlopen(f"http://127.0.0.1:{port}/session") as response:
        result = json.loads(response.read())["result"]
        cookie = response.headers["Set-Cookie"].split(";", 1)[0]
    return cookie, result["csrfToken"]


def _candidate_payload(view: dict[str, object]) -> dict[str, object]:
    candidate = view["developmentCandidate"]
    assert isinstance(candidate, dict)
    identity = candidate["identity"]
    action = candidate["verificationAction"]
    assert isinstance(identity, dict) and isinstance(action, dict)
    return {
        "sourceId": view["sourceId"],
        "sourceClass": candidate["sourceClass"],
        "expectedCommit": identity["commit"],
        "expectedTree": identity["tree"],
        "expectedManifestDigest": identity["manifestDigest"],
        "expectedSourceDigest": identity["sourceDigest"],
        "acknowledgement": action["acknowledgement"],
    }


def test_service_uses_one_long_lived_app_and_catalog_for_every_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = _layout(tmp_path, monkeypatch)
    with _service(layout, actor_role="local_user") as (server, port):
        app = server.source_app()
        assert app is server.execution.app
        assert server.source_app() is app
        assert server.source_app().catalog is app.catalog

        def unexpected_app(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("request constructed a second PersistentApp")

        monkeypatch.setattr(service_process, "PersistentApp", unexpected_app)
        cookie, _csrf = _session(port)
        status, payload = _request(port, "/v1/instances", cookie=cookie)
        assert status == 200
        assert payload["ok"] is True


def test_service_keeps_the_exact_source_authority_loaded_at_startup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = _layout(tmp_path, monkeypatch)
    catalog = tmp_path / "studydd.yaml"
    catalog.write_bytes(CATALOG.read_bytes())

    with _service(
        layout,
        actor_role="local_user",
        canonical_source_catalog=catalog,
    ) as (server, port):
        cookie, _csrf = _session(port)
        before_status, before = _request(port, "/v1/sources", cookie=cookie)
        assert before_status == 200

        catalog.write_text("invalid: [\n", encoding="utf-8")

        after_status, after = _request(port, "/v1/sources", cookie=cookie)
        assert after_status == 200
        assert after == before
        assert server.source_app() is server.execution.app


def test_public_registry_and_application_catalog_are_bounded_and_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = _layout(tmp_path, monkeypatch)
    with _service(layout, actor_role="local_user") as (_server, port):
        cookie, _csrf = _session(port)
        status, payload = _request(port, "/v1/sources", cookie=cookie)
        assert status == 200
        sources = payload["result"]["sources"]
        assert sources == [{
            "formatVersion": "stateport.canonical-source-public-view/v1",
            "sourceId": "stateport.source.studystate",
            "applicationId": "study-state",
            "publicName": "StudyState",
            "status": "awaiting_verified_release",
            "installable": False,
            "productionAction": {"action": "install_or_update", "enabled": False},
            "message": "Application source is awaiting a verified release.",
        }]
        serialized = json.dumps(sources)
        for forbidden in (
            "repository", "commit", "tree", "manifestDigest", "sourceDigest",
            "profile", "checkout", "mirror", "Traceback", str(ROOT),
        ):
            assert forbidden not in serialized

        app_status, applications = _request(port, "/v1/applications", cookie=cookie)
        assert app_status == 200
        study = next(
            item for item in applications["result"]["applications"]
            if item["applicationId"] == "studydd"
        )
        assert study["sourceStatus"] == sources[0]
        assert study["install"]["status"] == "unavailable"
        assert "canonical_source_unresolved" in study["install"]["reasons"]

        experience_status, experiences = _request(
            port, "/v1/application-experiences", cookie=cookie,
        )
        assert experience_status == 200
        study_experience = next(
            item for item in experiences["result"]["experiences"]
            if item["applicationId"] == "studydd"
        )
        assert study_experience["sourceStatus"] == sources[0]
        assert not any(
            item["id"] in {"workbench", "terminal", "editor", "cto_orchestration"}
            for item in study_experience["capabilities"]
        )


def test_operator_projection_is_permission_bound_exact_and_redacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = _layout(tmp_path, monkeypatch)
    source_path = "/v1/sources/stateport.source.studystate"
    with _service(layout, actor_role="local_user") as (_server, port):
        cookie, _csrf = _session(port)
        for path, headers in (
            (source_path, {}),
            (source_path + "?actor_role=platform_operator", {}),
            (source_path, {"X-StatePort-Actor-Role": "platform_operator"}),
        ):
            status, payload = _request(port, path, cookie=cookie, headers=headers)
            assert status == 403
            assert payload["error"]["code"] == "source_inspection_denied"

    with _service(layout, actor_role="platform_operator") as (_server, port):
        cookie, _csrf = _session(port)
        status, payload = _request(port, source_path, cookie=cookie)
        assert status == 200
        view = payload["result"]
        assert view["formatVersion"] == "stateport.canonical-source-operator-view/v1"
        assert view["canonicalRelease"] == {
            "sourceClass": "canonical_release",
            "identity": None,
            "status": "awaiting_verified_release",
            "trust": "development_only",
            "installable": False,
            "missingRequirement": "canonical_release_not_published",
            "requiredModules": [
                "studydd.core", "studydd.activities", "studydd.source-freshness", "studydd.fast-drill",
            ],
            "expectedSelfTests": [
                "core-health", "core-demo-replay", "core-cross-platform-paths", "activities-contract",
                "source-freshness-contract", "source-aware-routing", "fast-drill-checkpoint-contract",
                "fast-drill-settings-migration",
            ],
        }
        candidate = view["developmentCandidate"]
        assert candidate["sourceClass"] == "development_candidate"
        assert candidate["productionInstallAllowed"] is False
        assert candidate["identity"]["commit"] == "cffc45a2f69f8719b950abce37988667b1712830"
        assert candidate["identity"]["tree"] == "e518c185fab3dbd1624cf76d017f566e4aad317f"
        serialized = json.dumps(view)
        for forbidden in ("checkoutLocation", "sourceMirror", "credential", "password", str(layout.state_root)):
            assert forbidden not in serialized

        unknown_status, unknown = _request(
            port, "/v1/sources/StatePort.source.studystate", cookie=cookie,
        )
        assert unknown_status == 404 and unknown["error"]["code"] == "source_not_found"


def test_development_verification_requires_csrf_operator_and_exact_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = _layout(tmp_path, monkeypatch)
    source_id = "stateport.source.studystate"
    detail_path = f"/v1/sources/{source_id}"
    action_path = f"{detail_path}/development-resolve"

    with _service(layout, actor_role="platform_operator") as (_server, port):
        cookie, csrf = _session(port)
        detail_status, detail = _request(port, detail_path, cookie=cookie)
        assert detail_status == 200
        payload = _candidate_payload(detail["result"])

        denied_status, denied = _request(port, action_path, cookie=cookie, body=payload)
        assert denied_status == 403 and denied["error"]["code"] == "source_verification_denied"

        stale = dict(payload)
        stale["expectedCommit"] = "f" * 40
        stale_status, stale_result = _request(port, action_path, cookie=cookie, csrf=csrf, body=stale)
        assert stale_status == 409 and stale_result["error"]["code"] == "source_candidate_stale"

        unknown = {**payload, "unexpected": True}
        shape_status, shape = _request(port, action_path, cookie=cookie, csrf=csrf, body=unknown)
        assert shape_status == 400 and shape["error"]["code"] == "operation_failed"
        assert "Traceback" not in json.dumps(shape) and str(layout.state_root) not in json.dumps(shape)

        captured: dict[str, object] = {}

        def verified(self: PersistentApp, **kwargs: object) -> dict[str, object]:
            captured.update(kwargs)
            return {
                "formatVersion": "stateport.development-source-resolution/v1",
                "sourceId": source_id,
                "sourceClass": "development_candidate",
                "productionInstallAllowed": False,
                "receiptDigest": "sha256:" + "a" * 64,
            }

        monkeypatch.setattr(PersistentApp, "resolve_development_candidate", verified)
        accepted_status, accepted = _request(port, action_path, cookie=cookie, csrf=csrf, body=payload)
        assert accepted_status == 200
        assert accepted["result"]["sourceClass"] == "development_candidate"
        assert accepted["result"]["productionInstallAllowed"] is False
        assert captured == {"source_id": source_id, "operator_acknowledged": True}

    with _service(layout, actor_role="local_user") as (_server, port):
        cookie, csrf = _session(port)
        forbidden_status, forbidden = _request(port, action_path, cookie=cookie, csrf=csrf, body={})
        assert forbidden_status == 403
        assert forbidden["error"]["code"] == "source_verification_denied"


def test_shell_uses_safe_status_and_hides_candidate_action_from_normal_users() -> None:
    mappers = (ROOT / "apps" / "web" / "src" / "client" / "http" / "mappers.ts").read_text(encoding="utf-8")
    catalog = (ROOT / "apps" / "web" / "src" / "features" / "catalog" / "CatalogPage.tsx").read_text(encoding="utf-8")
    endpoints = (ROOT / "apps" / "web" / "src" / "client" / "http" / "endpoints.ts").read_text(encoding="utf-8")
    # An unresolved canonical source can never become an enabled production
    # action: install availability is computed from the service-provided
    # install contract bound to exact descriptor identities, and the catalog
    # renders the unavailable state with the explicit reason.
    assert "const installAvailable = wire.install?.status === 'available' && exactInstallIdentity" in mappers
    assert "installUnavailableReason" in mappers
    assert "entry.installAvailable === false ? 'Unavailable'" in catalog
    # Development-candidate verification remains a service permission gate.
    # The routed source surface consumes it only after the authenticated
    # status projection reports the platform-operator role; the backend
    # permission check remains independently authoritative.
    assert "sourceDevelopmentResolve" in endpoints and "development-resolve" in endpoints
    manifest = yaml.safe_load(
        (ROOT / "config" / "functionality-preservation.v1.yaml").read_text(encoding="utf-8")
    )
    control = next(
        item
        for item in manifest["userControls"]
        if item["id"] == "canonical-source-verify-candidate"
    )
    assert control["status"] == "foundation"
    source_surface = (
        ROOT / "apps" / "web" / "src" / "features" / "sources" / "SourceRegistryPage.tsx"
    ).read_text(encoding="utf-8")
    assert "status.actor?.role === 'platform_operator'" in source_surface
    assert "if (!operator || !selectedPublicSource) return" in source_surface
    assert 'data-testid="verify-development-candidate"' in source_surface
    gaps = (ROOT / "apps" / "web" / "docs" / "BACKEND_GAPS.md").read_text(encoding="utf-8")
    assert "platform StateBench is **operator-gated**" in gaps
    assert "resolve must never execute repository code" in gaps


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
