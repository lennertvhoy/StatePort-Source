#!/usr/bin/env python3
"""Browser onboarding and capability-aware shell regression tests."""

from __future__ import annotations

import json
from pathlib import Path
import socket
import stat
import sys
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest


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

from stateport_application_experience import ExperienceRegistry  # noqa: E402
from stateport_persistent_app import LocalLayout, PersistentApp  # noqa: E402


def _request(
    port: int,
    path: str,
    *,
    cookie: str | None = None,
    csrf: str | None = None,
    body: dict[str, object] | None = None,
) -> tuple[int, dict[str, object]]:
    headers = {"Accept": "application/json"}
    if cookie:
        headers["Cookie"] = cookie
    if body is not None:
        headers.update({"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{port}"})
    if csrf is not None:
        headers["X-StatePort-CSRF"] = csrf
    request = Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(body).encode("utf-8") if body is not None else None,
        headers=headers,
        method="POST" if body is not None else "GET",
    )
    try:
        with urlopen(request) as response:
            return response.status, json.loads(response.read())
    except HTTPError as error:
        return error.code, json.loads(error.read())


def test_checklist_experience_is_application_native_without_development_controls() -> None:
    registry = ExperienceRegistry(ROOT)
    descriptor = registry.get("checklistdd")
    assert descriptor is not None
    assert descriptor.display_name == "ChecklistState"
    assert {item.value for item in descriptor.capabilities} == {
        "conversation", "progress_dashboard", "goal_execution", "proactive_notifications",
    }
    assert {"workbench", "terminal", "editor", "cto_orchestration", "benchmark_evidence"}.isdisjoint(
        {item.value for item in descriptor.capabilities}
    )
    assert descriptor.platform_operations == ()
    assert registry.get("ChecklistDD") is descriptor


def test_browser_installs_exact_public_fixture_with_csrf_and_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])
    app.service_start(port=port)
    try:
        with urlopen(f"http://127.0.0.1:{port}/session") as response:
            session = json.loads(response.read())["result"]
            cookie = response.headers["Set-Cookie"].split(";", 1)[0]
            csp = response.headers["Content-Security-Policy"]
            assert "script-src 'self'" in csp
            assert "style-src-elem 'self' 'unsafe-inline'" in csp
            assert "style-src-attr 'unsafe-inline'" in csp
            assert "worker-src 'self' blob:" in csp
            assert "font-src 'self' data:" in csp
            assert "img-src 'self' blob:" in csp
            assert "object-src 'none'" in csp
            assert "frame-src 'none'" in csp
            assert "form-action 'none'" in csp
            assert "unsafe-eval" not in csp and "script-src 'self' 'unsafe-inline'" not in csp
            assert response.headers["X-Content-Type-Options"] == "nosniff"
            assert response.headers["X-Frame-Options"] == "DENY"
            assert response.headers["Referrer-Policy"] == "no-referrer"
            assert response.headers["Permissions-Policy"] == (
                "camera=(), geolocation=(), microphone=(), payment=(), usb=()"
            )
            assert response.headers["Cross-Origin-Resource-Policy"] == "same-origin"
            assert response.headers["Cross-Origin-Opener-Policy"] == "same-origin"
        status, catalog = _request(port, "/v1/applications", cookie=cookie)
        assert status == 200
        applications = catalog["result"]["applications"]
        checklist = next(item for item in applications if item["applicationId"] == "checklistdd")
        study = next(item for item in applications if item["applicationId"] == "studydd")
        study_sample = next(item for item in applications if item["applicationId"] == "studystate.sample")
        development = next(item for item in applications if item["applicationId"] == "stateport.development-reference")
        assert checklist["install"] == {
            "confirmationRequired": True,
            "networkPolicy": "disabled",
            "reasons": [],
            "receiptFormat": "stateport.application-install-receipt/v1",
            "requestedCapabilities": ["conversation", "goal_execution", "proactive_notifications", "progress_dashboard"],
            "sourceKind": "bundled_public_fixture",
            "status": "available",
        }
        assert study["install"]["status"] == "unavailable"
        assert study_sample["install"]["status"] == "available"
        assert study_sample["displayName"] == "StudyState Sample"
        assert development["install"]["status"] == "available"
        assert development["displayName"] == "ProjectState"
        assert {"workbench", "terminal", "editor", "cto_orchestration"} <= set(
            development["install"]["requestedCapabilities"]
        )
        assert "descriptorPath" not in json.dumps(applications)
        payload = {
            "applicationId": "checklistdd",
            "instanceId": "checklist-browser",
            "name": "ChecklistState",
            "applicationDescriptorDigest": checklist["applicationIdentity"]["descriptorDigest"],
            "applicationPackageDigest": checklist["applicationIdentity"]["packageDigest"],
            "experienceDescriptorDigest": checklist["experienceIdentity"]["descriptorDigest"],
        }

        denied, denial = _request(port, "/v1/application-fixtures/install", cookie=cookie, body=payload)
        assert denied == 403 and denial["error"]["code"] == "application_install_denied"
        stale_payload = dict(payload)
        stale_payload["applicationDescriptorDigest"] = "sha256:" + "0" * 64
        stale, stale_result = _request(
            port, "/v1/application-fixtures/install", cookie=cookie, csrf=session["csrfToken"], body=stale_payload,
        )
        assert stale == 409 and stale_result["error"]["code"] == "application_install_stale"
        stale_package_payload = dict(payload)
        stale_package_payload["applicationPackageDigest"] = "sha256:" + "0" * 64
        stale_package, stale_package_result = _request(
            port,
            "/v1/application-fixtures/install",
            cookie=cookie,
            csrf=session["csrfToken"],
            body=stale_package_payload,
        )
        assert stale_package == 409
        assert stale_package_result["error"]["code"] == "application_install_stale"

        # A descriptor-declared lifecycle template redirects install validation
        # to the declared revision's package digest; the catalog must advertise
        # exactly that digest or the browser journey refuses every install.
        study_sample_payload = {
            "applicationId": "studystate.sample",
            "instanceId": "studystate-browser",
            "name": "StudyState Sample",
            "applicationDescriptorDigest": study_sample["applicationIdentity"]["descriptorDigest"],
            "applicationPackageDigest": study_sample["applicationIdentity"]["packageDigest"],
            "experienceDescriptorDigest": study_sample["experienceIdentity"]["descriptorDigest"],
        }
        study_status, study_installed = _request(
            port,
            "/v1/application-fixtures/install",
            cookie=cookie,
            csrf=session["csrfToken"],
            body=study_sample_payload,
        )
        assert study_status == 200 and study_installed["ok"] is True
        assert study_installed["result"]["entry"]["instanceId"] == "studystate-browser"
        lifecycle = study_installed["result"]["lifecycle"]
        assert lifecycle is not None and lifecycle["revisionId"] == "v0001"
        assert lifecycle["formatVersion"] == "statedd.lock/v1"
        receipt_path = app.layout.operations_root / "application-installs" / "studystate-browser.json"
        assert json.loads(receipt_path.read_text(encoding="utf-8"))["consent"] == "explicit_browser_confirmation"

        installed_status, installed = _request(
            port, "/v1/application-fixtures/install", cookie=cookie, csrf=session["csrfToken"], body=payload,
        )
        assert installed_status == 200
        result = installed["result"]
        assert result["entry"]["instanceId"] == "checklist-browser"
        assert result["entry"]["applicationId"] == "checklistdd"
        assert {"path", "filesystem", "metadata"}.isdisjoint(result["entry"])
        assert result["receipt"]["formatVersion"] == "stateport.application-install-receipt/v1"
        assert result["receipt"]["receiptDigest"].startswith("sha256:")
        receipt_path = app.layout.operations_root / "application-installs" / "checklist-browser.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        assert stat.S_IMODE(receipt_path.stat().st_mode) == 0o600
        assert receipt["consent"] == "explicit_browser_confirmation"
        assert receipt["source"]["networkPolicy"] == "disabled"
        assert receipt["descriptorIdentities"]["application"]["packageDigest"] == payload["applicationPackageDigest"]
        assert str(app.layout.instances_root) not in json.dumps(receipt)
        catalog_entry = app.catalog.get("checklist-browser")
        capability_grant = catalog_entry["metadata"]["capabilityGrant"]
        assert capability_grant["formatVersion"] == "stateport.instance-capability-grant/v1"
        assert capability_grant["instanceId"] == "checklist-browser"
        assert capability_grant["adoptionMode"] == "registered"
        assert capability_grant["grantedCapabilities"] == capability_grant["requestedCapabilities"]
        assert capability_grant["grantDigest"].startswith("sha256:")

        receipt_id = result["receipt"]["receiptId"]
        receipt_status, receipt_index = _request(
            port,
            "/v1/instances/checklist-browser/receipts",
            cookie=cookie,
        )
        assert receipt_status == 200
        projected = next(
            item
            for item in receipt_index["result"]["receipts"]
            if item["receiptId"] == receipt_id
        )
        assert projected == {
            "receiptId": receipt_id,
            "receiptType": "stateport.application-install-receipt/v1",
            "action": "application.install.fixture",
            "status": "applied",
            "createdAt": receipt["createdAt"],
            "sourceKind": "application_install",
            "payloadDigest": result["receipt"]["receiptDigest"],
        }
        detail_status, receipt_detail = _request(
            port,
            f"/v1/instances/checklist-browser/receipts/{receipt_id}",
            cookie=cookie,
        )
        assert detail_status == 200
        assert receipt_detail["result"]["instanceId"] == "checklist-browser"
        assert receipt_detail["result"]["receipt"]["payload"] == receipt
        assert (
            receipt_detail["result"]["receipt"]["payloadDigest"]
            == result["receipt"]["receiptDigest"]
        )

        status, experience = _request(port, "/v1/instances/checklist-browser/experience", cookie=cookie)
        assert status == 200
        capabilities = {item["id"] for item in experience["result"]["capabilities"]}
        assert {"workbench", "terminal", "editor", "cto_orchestration", "benchmark_evidence"}.isdisjoint(capabilities)

        # The SQLite receipt view is never allowed to mask a corrupted durable
        # operations receipt. A later refresh re-reads the authority and fails
        # closed on its exact application/instance binding.
        receipt_path.write_text(
            json.dumps({**receipt, "instanceId": "different-instance"}),
            encoding="utf-8",
        )
        malformed_status, malformed = _request(
            port,
            "/v1/instances/checklist-browser/receipts",
            cookie=cookie,
        )
        assert malformed_status == 400
        assert malformed["error"]["code"] == "operation_failed"
    finally:
        app.service_stop()


def test_imported_instance_identity_cannot_inherit_application_capabilities(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    imported = app.layout.instances_root / "imported-development"
    imported.mkdir(parents=True)
    app.catalog.import_instance(
        imported,
        instance_id="imported-development",
        name="Imported development package",
        application_id="stateport.development-reference",
        source={"templateId": "stateport.development-reference", "sourceClass": "public_https_repository"},
    )
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])
    app.service_start(port=port)
    try:
        with urlopen(f"http://127.0.0.1:{port}/session") as response:
            cookie = response.headers["Set-Cookie"].split(";", 1)[0]
        status, payload = _request(port, "/v1/instances/imported-development/experience", cookie=cookie)
        assert status == 200
        resolved = payload["result"]
        assert resolved["instanceBinding"]["instanceId"] == "imported-development"
        statuses = {item["id"]: item["status"] for item in resolved["capabilities"]}
        assert statuses["workbench"] == "denied"
        assert statuses["terminal"] == "denied"
        assert statuses["file_viewer"] == "denied"
        assert resolved["instanceBinding"]["descriptorDigest"] == resolved["descriptorIdentity"]["descriptorDigest"]
    finally:
        app.service_stop()


def test_shell_keeps_install_primary_and_developer_tools_progressively_disclosed() -> None:
    catalog = (ROOT / "apps" / "web" / "src" / "features" / "catalog" / "CatalogPage.tsx").read_text(encoding="utf-8")
    review = (ROOT / "apps" / "web" / "src" / "features" / "catalog" / "InstallReview.tsx").read_text(encoding="utf-8")
    onboarding = (ROOT / "apps" / "web" / "src" / "features" / "applications" / "components" / "OnboardingStrip.tsx").read_text(encoding="utf-8")
    context_shell = (ROOT / "apps" / "web" / "src" / "shell" / "AppContextShell.tsx").read_text(encoding="utf-8")
    view_registry = (ROOT / "apps" / "web" / "src" / "features" / "application-experience" / "registry.ts").read_text(encoding="utf-8")
    workbench_shell = (ROOT / "apps" / "web" / "src" / "shell" / "WorkbenchShell.tsx").read_text(encoding="utf-8")
    commands = (ROOT / "apps" / "web" / "src" / "shell" / "commands.ts").read_text(encoding="utf-8")
    orchestration = (ROOT / "apps" / "web" / "src" / "features" / "orchestration" / "OrchestrationTool.tsx").read_text(encoding="utf-8")
    domains = (ROOT / "apps" / "web" / "src" / "client" / "http" / "domainsCore.ts").read_text(encoding="utf-8")
    transport = (ROOT / "apps" / "web" / "src" / "client" / "http" / "transport.ts").read_text(encoding="utf-8")
    # Reviewed installation is the primary path and always passes an explicit
    # identity-bound confirmation; the repository import stays a quiet
    # secondary path that never pretends to be the ordinary flow.
    assert "Install a reviewed sample" in onboarding
    assert "Installing this package requires your confirmation" in review
    assert 'data-testid="confirm-install"' in review
    assert "Quiet secondary path at the foot of the list" in catalog
    assert "Import a local repository" in catalog and "reviewed installation stays the ordinary path." in catalog
    assert "Installing a reviewed package is the supported starting point." in catalog
    assert "applicationDescriptorDigest" in domains and "applicationPackageDigest" in domains and "experienceDescriptorDigest" in domains
    # Developer tools stay progressively disclosed behind effective
    # capabilities: nav entries are filtered, the workbench deep-link
    # redirects with an honest note, and the palette lists only permitted
    # commands.
    assert "applicationNavigation(instance)" in context_shell
    assert "capabilityUsable(instance, capability)" in view_registry
    assert "component: 'development_workbench'" in view_registry
    assert "candidate.capability === view.capability" in view_registry
    assert "This application does not include" in workbench_shell
    assert "command.when ? command.when() : true" in commands and "availableCommands" in commands
    # Goal execution is honest when nothing is actionable and never advances
    # by itself.
    assert 'data-testid="orchestration-unavailable"' in orchestration
    assert "nothing runs until you approve it" in orchestration
    # Mutations stay CSRF-bound on the same-origin session, with no session
    # state in web storage.
    assert "credentials: 'same-origin'" in transport and "X-StatePort-CSRF" in transport
    assert "localStorage" not in transport and "sessionStorage" not in transport


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
