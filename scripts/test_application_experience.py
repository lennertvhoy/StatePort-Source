#!/usr/bin/env python3
"""Focused tests for the application-first shell and trusted UI boundary."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import socket
import struct
import sys
import xml.etree.ElementTree as ET
from urllib.request import Request, urlopen

import jsonschema
import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "packages" / "application-experience" / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))
for relative in (
    "packages/persistent-app/src",
    "packages/instance-backup/src",
    "packages/instance-catalog/src",
    "packages/diagnostics/src",
    "packages/statedd-core/src",
    "packages/template-validator/src",
    "apps/runner/src",
):
    path = ROOT / relative
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

from render_favicon import SIZES, render  # noqa: E402
from stateport_application_experience import (  # noqa: E402
    ApplicationExperienceDescriptor,
    ExperienceContractError,
    ExperienceRegistry,
    load_experience_policy,
    resolve_experience,
)
from validate_application_experience import validate  # noqa: E402
from stateport_persistent_app import LocalLayout, PersistentApp  # noqa: E402


def _source(name: str) -> dict[str, object]:
    value = yaml.safe_load((ROOT / "fixtures" / "application-experiences" / name).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_descriptors_are_strict_schema_valid_and_digest_bound() -> None:
    registry = ExperienceRegistry(ROOT)
    schema = json.loads((ROOT / "schemas" / "application-experience.v1.schema.json").read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    for value in registry.list():
        validator.validate(value)
        descriptor = ApplicationExperienceDescriptor.from_mapping(value)
        assert descriptor.identity()["descriptorDigest"].startswith("sha256:")
        assert len(descriptor.identity()["descriptorDigest"]) == 71


@pytest.mark.parametrize("field", ["html", "javascript", "css", "url", "command", "import", "path", "actorPermissions", "grantPermissions"])
def test_descriptor_rejects_executable_and_permission_injection_fields(field: str) -> None:
    value = _source("development-workspace.yaml")
    value[field] = "javascript:alert(1)"
    with pytest.raises(ExperienceContractError, match="unknown fields"):
        ApplicationExperienceDescriptor.from_mapping(value)


@pytest.mark.parametrize("route", ["https://example.invalid/workbench", "javascript:alert(1)", "//example.invalid", "/workbench/../platform", "/etc/passwd", "/workbench?code=1"])
def test_descriptor_rejects_unsafe_routes(route: str) -> None:
    value = _source("development-workspace.yaml")
    value["views"][0]["route"] = route
    with pytest.raises(ExperienceContractError, match="application view route"):
        ApplicationExperienceDescriptor.from_mapping(value)


@pytest.mark.parametrize("component", ["<script>alert(1)</script>", "https://example.invalid/widget.js", "custom_css", "shell_command", "dynamic_import", "../../component"])
def test_descriptor_allows_only_stateport_owned_components(component: str) -> None:
    value = _source("development-workspace.yaml")
    value["views"][0]["component"] = component
    with pytest.raises(ExperienceContractError, match="application view component"):
        ApplicationExperienceDescriptor.from_mapping(value)


@pytest.mark.parametrize("payload", ["<img src=x onerror=alert(1)>", "javascript:alert(1)", "https://example.invalid", "url(https://example.invalid/a.css)", "@import 'evil.css'"])
def test_descriptor_text_cannot_smuggle_markup_css_or_urls(payload: str) -> None:
    value = _source("development-workspace.yaml")
    value["description"] = payload
    with pytest.raises(ExperienceContractError, match="unsafe markup or URL content"):
        ApplicationExperienceDescriptor.from_mapping(value)


def test_package_platform_contribution_cannot_grant_actor_permission() -> None:
    value = _source("development-workspace.yaml")
    value["platformOperations"][0]["grantsActorPermissions"] = ["platform.statebench.read"]
    with pytest.raises(ExperienceContractError, match="unknown fields"):
        ApplicationExperienceDescriptor.from_mapping(value)

    descriptor = ApplicationExperienceDescriptor.from_mapping(_source("development-workspace.yaml"))
    requested = {item.value for item in descriptor.capabilities}
    runtime = {item: "available" for item in requested}
    denied = resolve_experience(descriptor, instance_grants=requested, operator_permits=requested, runtime_capabilities=runtime, actor_permissions=set())
    operation = denied["platformOperations"][0]
    assert operation["status"] == "denied"
    assert operation["visible"] is False
    assert "missing_actor_permission:platform.statebench.read" in operation["reasons"]
    accepted = resolve_experience(descriptor, instance_grants=requested, operator_permits=requested, runtime_capabilities=runtime, actor_permissions={"platform.statebench.read"})
    assert accepted["platformOperations"][0]["status"] == "available"


def test_most_restrictive_resolution_preserves_distinct_statuses_and_reasons() -> None:
    descriptor = ApplicationExperienceDescriptor.from_mapping(_source("development-workspace.yaml"))
    requested = {item.value for item in descriptor.capabilities}
    runtime: dict[str, str | dict[str, str]] = {item: "available" for item in requested}
    runtime["progress_dashboard"] = {"status": "degraded", "reason": "summary_only"}
    runtime["goal_execution"] = {"status": "environment_gated", "reason": "approval_backend_missing"}
    runtime["proactive_notifications"] = {"status": "unavailable", "reason": "delivery_adapter_missing"}
    grants = requested - {"file_viewer"}
    permits = requested - {"workbench"}
    result = resolve_experience(descriptor, instance_grants=grants, operator_permits=permits, runtime_capabilities=runtime, actor_permissions=set())
    statuses = {item["id"]: item for item in result["capabilities"]}
    assert statuses["conversation"]["status"] == "available"
    assert statuses["progress_dashboard"] == {"id": "progress_dashboard", "status": "degraded", "reasons": ["summary_only"]}
    assert statuses["goal_execution"]["status"] == "environment_gated"
    assert statuses["proactive_notifications"]["status"] == "unavailable"
    assert statuses["file_viewer"] == {"id": "file_viewer", "status": "denied", "reasons": ["not_granted_by_instance"]}
    assert statuses["workbench"] == {"id": "workbench", "status": "denied", "reasons": ["denied_by_operator_policy"]}
    assert {item["status"] for item in result["capabilities"]} >= {"available", "denied", "unavailable", "environment_gated", "degraded"}


def test_descriptor_tampering_changes_identity_and_install_projection_never_grants() -> None:
    first = ApplicationExperienceDescriptor.from_mapping(_source("study-state.yaml"))
    changed = _source("study-state.yaml")
    changed["description"] = changed["description"] + " Reviewed."
    second = ApplicationExperienceDescriptor.from_mapping(changed)
    assert first.descriptor_digest() != second.descriptor_digest()
    requested = {item.value for item in first.capabilities}
    result = resolve_experience(first, instance_grants=requested, operator_permits=requested, runtime_capabilities={item: "available" for item in requested}, actor_permissions=set())
    assert result["descriptorIdentity"]["descriptorDigest"] == first.descriptor_digest()
    assert result["installProjection"]["descriptorDigest"] == first.descriptor_digest()
    assert result["installProjection"]["applicationId"] == first.application_id
    assert result["installProjection"]["grantsCapabilities"] is False


def test_study_state_never_exposes_development_workbench_capabilities() -> None:
    registry = ExperienceRegistry(ROOT)
    policy = load_experience_policy(ROOT / "config" / "application-experience-policy.yaml")
    study = registry.get("studydd")
    development = registry.get("stateport.development-reference")
    assert study is not None and development is not None
    forbidden = {"workbench", "terminal", "editor", "cto_orchestration", "benchmark_evidence"}
    assert forbidden.isdisjoint({item.value for item in study.capabilities})
    assert forbidden.isdisjoint({item.capability.value for item in study.views})
    assert all(item.view_id != "project-workbench" for item in study.navigation)
    assert study.platform_operations == ()
    assert forbidden <= {item.value for item in development.capabilities}
    assert any(item.view_id == "project-workbench" for item in development.navigation)
    resolved = registry.resolve(
        development.application_id,
        instance_grants=policy.grants_for(development.application_id),
        operator_permits=policy.operator_permits,
        runtime_capabilities=policy.runtime_capabilities,
        actor_permissions=policy.permissions_for("local_user"),
    )
    assert resolved is not None
    assert next(item for item in resolved["capabilities"] if item["id"] == "workbench")["status"] == "available"
    assert registry.get("StudyDD") is study


def test_public_study_sample_uses_native_views_without_development_capabilities() -> None:
    registry = ExperienceRegistry(ROOT)
    policy = load_experience_policy(ROOT / "config" / "application-experience-policy.yaml")
    study = registry.get("studystate.sample")
    assert study is not None
    assert study.display_name == "StudyState Sample"
    assert {item.component for item in study.views} == {
        "progress_overview", "conversation_thread", "goal_actions", "notification_feed",
    }
    forbidden = {"workbench", "terminal", "editor", "cto_orchestration", "benchmark_evidence"}
    assert forbidden.isdisjoint({item.value for item in study.capabilities})
    resolved = registry.resolve(
        study.application_id,
        instance_grants=policy.grants_for(study.application_id),
        operator_permits=policy.operator_permits,
        runtime_capabilities=policy.runtime_capabilities,
        actor_permissions=policy.permissions_for("local_user"),
    )
    assert resolved is not None
    statuses = {item["id"]: item["status"] for item in resolved["capabilities"]}
    assert statuses == {
        "conversation": "available",
        "progress_dashboard": "available",
        "goal_execution": "degraded",
        "proactive_notifications": "degraded",
    }
    assert resolved["platformOperations"] == []


def test_application_conversation_is_stateport_owned_and_locally_available() -> None:
    registry = ExperienceRegistry(ROOT)
    policy = load_experience_policy(ROOT / "config" / "application-experience-policy.yaml")
    for application_id in ("studydd", "stateport.development-reference"):
        resolved = registry.resolve(
            application_id,
            instance_grants=policy.grants_for(application_id),
            operator_permits=policy.operator_permits,
            runtime_capabilities=policy.runtime_capabilities,
            actor_permissions=policy.permissions_for("local_user"),
        )
        assert resolved is not None
        assert resolved["conversation"]["enabled"] is True
        assert resolved["conversation"]["component"] == "conversation_thread"
        assert resolved["conversation"]["mode"] == "application_attached"


def test_atm10_guide_is_a_conversation_only_application() -> None:
    registry = ExperienceRegistry(ROOT)
    policy = load_experience_policy(ROOT / "config" / "application-experience-policy.yaml")
    guide = registry.get("atm10.speedrun-guide")
    assert guide is not None
    assert guide.display_name == "ATM10 6.1 Speedrun Guide"
    assert {item.value for item in guide.capabilities} == {
        "conversation",
        "progress_dashboard",
    }
    assert {item.component for item in guide.views} == {
        "application_home",
        "conversation_thread",
    }
    resolved = registry.resolve(
        guide.application_id,
        instance_grants=policy.grants_for(guide.application_id),
        operator_permits=policy.operator_permits,
        runtime_capabilities=policy.runtime_capabilities,
        actor_permissions=policy.permissions_for("local_user"),
    )
    assert resolved is not None
    assert {
        item["id"]: item["status"] for item in resolved["capabilities"]
    } == {"conversation": "available", "progress_dashboard": "available"}


def test_functionality_preservation_manifest_covers_routes_buttons_apis_and_aliases() -> None:
    counts = validate()
    assert counts == {
        "descriptors": 9,
        "routes": 17,
        "controls": 65,
        "apis": 145,
        "capabilities": 18,
        "aliases": 10,
        "dynamicControls": 15,
        "dynamicOperations": 10,
        "dynamicBehaviors": 10,
        "surfaceGaps": 1,
        "dynamicGaps": 0,
    }


def _frontend_sources() -> dict[str, str]:
    """Product sources of the typed React frontend, excluding tests and the dev-only mock adapter."""
    base = ROOT / "apps" / "web" / "src"
    sources: dict[str, str] = {}
    for path in sorted(base.rglob("*")):
        if path.suffix not in {".ts", ".tsx"} or not path.is_file():
            continue
        relative = path.relative_to(base).as_posix()
        if "__tests__" in relative or relative.startswith(("client/mock/", "test/")):
            continue
        sources[relative] = path.read_text(encoding="utf-8")
    return sources


def test_application_shell_is_app_first_and_platform_operations_are_permission_gated() -> None:
    app = (ROOT / "apps" / "web" / "src" / "App.tsx").read_text(encoding="utf-8")
    home = (ROOT / "apps" / "web" / "src" / "features" / "applications" / "ApplicationsPage.tsx").read_text(encoding="utf-8")
    onboarding = (ROOT / "apps" / "web" / "src" / "features" / "applications" / "components" / "OnboardingStrip.tsx").read_text(encoding="utf-8")
    sources = (ROOT / "apps" / "web" / "src" / "features" / "sources" / "SourceRegistryPage.tsx").read_text(encoding="utf-8")
    statebench = (ROOT / "apps" / "web" / "src" / "features" / "statebench" / "PlatformStateBenchPage.tsx").read_text(encoding="utf-8")
    legacy = (ROOT / "apps" / "web" / "src" / "legacyRoutes.ts").read_text(encoding="utf-8")
    transport = (ROOT / "apps" / "web" / "src" / "client" / "http" / "transport.ts").read_text(encoding="utf-8")
    # The default landing is the installed-application home, not a platform panel.
    assert '<Navigate to="/applications" replace' in app
    assert "Needs attention" in home and 'title="No applications yet"' in home
    readiness = (ROOT / "apps/web/src/shell/ReadinessSummary.tsx").read_text(encoding="utf-8")
    catalog = (ROOT / "apps/web/src/features/catalog/CatalogPage.tsx").read_text(encoding="utf-8")
    assert "<ReadinessSummary />" in onboarding
    assert "'/catalog'" in readiness and "<Link to={check.to}" in readiness
    assert 'data-testid={`install-${pkg.name}`}' in catalog
    assert "onClick={() => openInstall(pkg.id)}" in catalog
    # The legacy #platform entry remains a safe normal-user return to
    # Applications. Canonical source status has its own bounded global route,
    # while exact source evidence and verification are separately role-gated.
    assert "platform: '/applications'" in legacy
    assert 'path="sources"' in app
    assert 'path="statebench"' in app
    assert "status.actor?.role === 'platform_operator'" in sources
    assert "if (!operator || !selectedPublicSource) return" in sources
    assert "canInspectPlatformStateBench(status)" in statebench
    assert "client.platformStateBench.getMatrix(status)" in statebench
    assert "authoritativePerformanceClaim: false" in statebench
    manifest = yaml.safe_load((ROOT / "config" / "functionality-preservation.v1.yaml").read_text(encoding="utf-8"))
    platform_route = next(item for item in manifest["uiRoutes"] if item["id"] == "platform-route")
    assert platform_route["status"] == "foundation"
    # Session state stays in memory on the same-origin transport, never in web storage.
    assert "credentials: 'same-origin'" in transport
    assert "private csrfToken" in transport
    assert "localStorage" not in transport and "sessionStorage" not in transport
    # Compatibility identifiers stay out of the product surface.
    for relative, source in _frontend_sources().items():
        for legacy_name in ("StateDD", "StudyDD", "ClassDD"):
            assert legacy_name not in source, relative


def test_shell_dispatches_only_trusted_native_components_and_effective_capabilities() -> None:
    context_shell = (ROOT / "apps" / "web" / "src" / "shell" / "AppContextShell.tsx").read_text(encoding="utf-8")
    app = (ROOT / "apps" / "web" / "src" / "App.tsx").read_text(encoding="utf-8")
    view_registry = (ROOT / "apps" / "web" / "src" / "features" / "application-experience" / "registry.ts").read_text(encoding="utf-8")
    view_guard = (ROOT / "apps" / "web" / "src" / "features" / "application-experience" / "ApplicationViewGuard.tsx").read_text(encoding="utf-8")
    workbench_shell = (ROOT / "apps" / "web" / "src" / "shell" / "WorkbenchShell.tsx").read_text(encoding="utf-8")
    overview = (ROOT / "apps" / "web" / "src" / "features" / "app-overview" / "AppOverviewPage.tsx").read_text(encoding="utf-8")
    sources = _frontend_sources()
    # Descriptors select only exact reviewed component/capability/route tuples.
    # The static router and renderer imports stay StatePort-owned; package
    # values can neither register routes nor load executable frontend code.
    assert "applicationNavigation(instance)" in context_shell
    assert "component: 'conversation_thread'" in view_registry
    assert "component: 'development_workbench'" in view_registry
    assert "component: 'run_history'" in view_registry
    assert "controlId: 'project-runs'" in view_registry
    assert "controlId: 'nixos-runs'" in view_registry
    assert "candidate.controlId === control.controlId" in view_registry
    assert "candidate.component === view.component" in view_registry
    assert "candidate.capability === view.capability" in view_registry
    assert "candidate.declaredRoute === view.declaredRoute" in view_registry
    assert "capabilityUsable(instance, capability)" in view_registry
    assert "applicationNavigation(instance).some" in view_registry
    assert "import(" not in view_registry
    assert "ApplicationViewGuard" in app
    assert "applicationDestinationAvailable(instance, destination)" in view_guard
    assert "<StudySection" in overview and "<ChecklistSection" in overview and "<ProjectSection" in overview
    # Workbench tools are a static capability-gated registry; deep links into
    # an ungranted tool redirect with an honest note instead of rendering.
    assert "capabilities: ['file_viewer', 'editor']" in workbench_shell
    assert "capabilities: ['terminal']" in workbench_shell
    assert "toolAvailable" in workbench_shell and "hasCapability" in workbench_shell
    assert "This application does not include" in workbench_shell
    # No arbitrary markup or code injection anywhere in the product sources.
    # The unused chart helper that previously injected a generated <style>
    # block was removed together with its unused Recharts dependency.
    for relative, source in sources.items():
        assert "eval(" not in source and "innerHTML =" not in source, relative
    dangerous = {relative for relative, source in sources.items() if "dangerouslySetInnerHTML" in source}
    assert dangerous == set()


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_favicon_is_a_small_size_derivative_of_the_preserved_mascot() -> None:
    brand = ROOT / "apps" / "web" / "assets" / "brand"
    mascot = brand / "stateport-mascot.svg"
    favicon = brand / "favicon.svg"
    manifest = json.loads((brand / "favicon-asset-manifest.json").read_text(encoding="utf-8"))
    assert _sha(mascot) == "d0768716bed8391220cb4a87e52e00705bac92fed4fa16b870682ab5c392c803"
    assert manifest["mascotSource"]["sha256"] == _sha(mascot)
    assert manifest["favicon"]["sha256"] == _sha(favicon)
    namespace = {"svg": "http://www.w3.org/2000/svg"}
    mascot_root = ET.parse(mascot).getroot()
    favicon_root = ET.parse(favicon).getroot()
    mascot_logo = mascot_root.find("svg:g[@id='logo']", namespace)
    micro_mark = favicon_root.find("svg:g[@id='micro-mark']", namespace)
    assert mascot_logo is not None and micro_mark is not None
    assert favicon_root.attrib["viewBox"] == "0 0 16 16"
    background = favicon_root.find("svg:rect[@id='favicon-background']", namespace)
    assert background is not None
    assert background.attrib == {"id": "favicon-background", "width": "16", "height": "16", "rx": "4", "fill": "#2F7DFF"}
    assert micro_mark.find("svg:path[@id='cap']", namespace) is not None
    assert micro_mark.find("svg:circle[@id='left-eye']", namespace) is not None
    assert micro_mark.find("svg:circle[@id='right-eye']", namespace) is not None
    assert micro_mark.find("svg:path[@id='beak']", namespace) is not None
    assert manifest["favicon"]["strategy"] == "simplified_micro_mark"
    assert manifest["favicon"]["relationship"] == "small-size derivative of the preserved mascot"
    assert manifest["favicon"]["nativeSizeDesigned"] == 16
    assert manifest["favicon"]["mascotGeometryPreserved"] is False
    source = favicon.read_text(encoding="utf-8").lower()
    assert "<script" not in source and "foreignobject" not in source and "http://" not in source.replace("http://www.w3.org/2000/svg", "") and "https://" not in source


@pytest.mark.skipif(shutil.which("magick") is None, reason="ImageMagick is unavailable")
def test_favicon_renders_at_browser_sizes(tmp_path: Path) -> None:
    rendered = render(tmp_path)
    assert [path.name for path in rendered] == [f"favicon-{size}.png" for size in SIZES]
    for path, size in zip(rendered, SIZES, strict=True):
        data = path.read_bytes()
        assert data.startswith(b"\x89PNG\r\n\x1a\n")
        width, height = struct.unpack(">II", data[16:24])
        assert (width, height) == (size, size)


def test_instance_experience_projection_is_digest_bound_in_service() -> None:
    service = (ROOT / "packages" / "persistent-app" / "src" / "stateport_persistent_app" / "service_process.py").read_text(encoding="utf-8")
    assert 'parts[3] == "experience"' in service
    assert '"instanceBinding"' in service
    assert 'result["descriptorIdentity"]["descriptorDigest"]' in service


def test_real_local_service_binds_study_experience_without_workbench(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    app = PersistentApp(LocalLayout.from_environment())
    app.setup_init()
    instance = app.layout.instances_root / "study-one"
    instance.mkdir()
    app.catalog.register(instance, instance_id="study-one", name="StudyState One", source={"templateId": "studydd", "resolvedCommit": "fixture:study", "resolvedTree": "study", "manifestDigest": "sha256:" + "0" * 64})
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])
    app.service_start(port=port)
    try:
        with urlopen(f"http://127.0.0.1:{port}/session") as response:
            cookie = response.headers["Set-Cookie"].split(";", 1)[0]
        request = Request(f"http://127.0.0.1:{port}/v1/instances/study-one/experience", headers={"Cookie": cookie})
        with urlopen(request) as response:
            value = json.loads(response.read())["result"]
        assert value["descriptor"]["displayName"] == "StudyState"
        assert value["instanceBinding"] == {
            "instanceId": "study-one",
            "applicationId": "studydd",
            "descriptorDigest": value["descriptorIdentity"]["descriptorDigest"],
        }
        assert value["installProjection"]["grantsCapabilities"] is False
        assert not any(item["id"] in {"workbench", "terminal", "editor", "cto_orchestration", "benchmark_evidence"} for item in value["capabilities"])
        assert value["actor"]["platformOperationsAllowed"] is False
    finally:
        app.service_stop()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
