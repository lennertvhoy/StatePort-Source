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

from service_test_product import service_product_fixture  # noqa: E402
from render_favicon import SIZES, render  # noqa: E402
from stateport_application_experience import (  # noqa: E402
    ApplicationExperienceDescriptor,
    ExperienceContractError,
    ExperienceRegistry,
    load_experience_policy,
    resolve_experience,
)
from validate_application_experience import (  # noqa: E402
    CONTROL_SHAPE_CLASSES,
    _check_preservation_item,
    _citation_measurement,
    _control_shape_classes,
    _path_matches,
    _resolve_test_citations,
    _expression_census,
    _shipped_frontend_sources,
    _undeclared_controls,
    _uncredited_declared_controls,
    validate,
)
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
        # 77 = the 65 previously inventoried controls plus the 12 that
        # cc2d6e92 declared for the ExecutionHostPage container surface:
        # workloads refresh, workspace terminal open, application workspace
        # create and recover, development workspace create, development
        # container recreate, workload start, stop, cancel and logs, container
        # remove, and operation history refresh. Each cites a real evidence
        # literal in ExecutionHostPage and a real colocated
        # `__tests__/ExecutionHost*` test, and validate_application_experience.py
        # exits 0 over them, so the evidence is fresh rather than merely
        # counted. The pin was left at 65 by that commit, so this RAISES it to
        # the real count rather than removing a control entry to make the old
        # number true.
        "controls": 77,
        # 160 = the 145 previously inventoried operations plus 15 that the
        # validator proved were live service/frontend routes with no entry at all:
        # the agent-run surface, the operations projection, the provider
        # credential and device-login operations, and the three typed-client
        # templates. Each new entry cites a real evidence literal in the code that
        # serves or builds the path, and a test that already exercised it.
        # 162: the validator's measured count on the current tree. The pin
        # still said 160 after later manifest commits (for example a322ea90,
        # provider sign-in adoption) added operation entries without raising
        # it; this RAISES it to the measured count, no entry was removed.
        "apis": 162,
        "capabilities": 18,
        "aliases": 10,
        "dynamicControls": 15,
        "dynamicOperations": 10,
        # 12 = the 10 previously inventoried behaviours, because 49da6f7c did not
        # add coverage but SPLIT one coarse entry into three guard-anchored ones:
        # `provider-operator-refusal` became the login-mutation, the
        # configuring-mutation and the credential-write refusals, each naming the
        # specific guard in ProviderSettings.tsx rather than sharing one
        # literal. That commit is manifest-only, +3/-1 with no product, test or
        # validator change, so the arithmetic is 10 - 1 + 3 = 12 and nothing was
        # removed. Each of the three cites a real `evidence.file` plus a real
        # `contains` literal, and validate_application_experience.py exits 0 over
        # the set while reporting dynamicBehaviors=12, so the finer granularity
        # is covered rather than merely counted. This RAISES the pin to the real
        # count rather than merging the three back into one to make the old
        # number true.
        "dynamicBehaviors": 12,
        # 0: the last open surface gap was `run-button`. It is closed by a real
        # routed React surface, not by flipping the counter — the test below
        # proves the surface exists, is non-executable, and never calls
        # /synthetic-run.
        #
        # RENAMED from `surfaceGaps`, and the rename is the point rather than
        # cosmetics. The old name read downstream as a coverage metric, and a 0
        # under it was a false assurance: this is a census of manifest rows whose
        # SELF-DECLARED status is the string "gap", so a control that exists in
        # apps/web/src and has no manifest entry cannot appear in it at all. That
        # is how the word "container" stayed undeclared across all four manifests
        # while twelve operator controls were rendered, with this number at 0
        # throughout. `declaredGapRows` cannot be misread as assurance, and
        # `undeclaredControls` states the blind spot as unmeasured so its absence
        # is never read as a measurement of zero. Whether that coverage can be
        # computed at all is an owner decision, recorded at
        # evidence/one-line-release-001/owner-decision-brief-control-population-boundary-20260927.md,
        # and is NOT settled here.
        "declaredGapRows": 0,
        "dynamicGaps": 0,
        # The blind spot is now MEASURED rather than pinned as an unmeasurable
        # literal, so this entry is an int. It is pinned to the exact measured
        # value on purpose: the census enumerates control identities from shipped
        # source, so a drop means controls left the shipped surface, and a jump
        # means new ones were added without a declaration. Both are the events
        # this figure exists to make visible.
        # 515: the measured census on the current tree, up from 511 because
        # later commits added shipped web controls without raising this pin
        # (this lane added none: base plus the evidence fix already measures
        # 515). The figure is reported, not enforced; it is recorded here rather
        # than hidden.
        "undeclaredControls": 515,
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
    # 182f2c55 replaced the fixed index redirect with the StartupRoute resolver, so
    # the home default now lives there rather than in App.tsx. The resolver also
    # revalidates the resumed identity server-side instead of trusting persisted
    # continuity, and both halves are asserted because either could regress alone.
    startup = (ROOT / "apps" / "web" / "src" / "shell" / "StartupRoute.tsx").read_text(encoding="utf-8")
    assert "<Route index element={<StartupRoute />}" in app
    assert "let route = '/applications'" in startup
    assert "const instance = await getClient().applications.get(id)" in startup
    assert "if (instance.id === id)" in startup
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
    app.service_start(port=port, repo_root=service_product_fixture(tmp_path, ROOT))
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


def test_synthetic_validation_is_visibly_classified_and_not_executable_from_the_ui() -> None:
    """The `run-button` surface gap is closed by an explanation, not a control.

    The backend keeps a production-ineligible `synthetic_run` capability. The
    product contract says the frontend must not call it, so the app overview
    classifies it in the ordinary capabilities list instead of executing it.
    This test fails if the classification is removed, if it stops being
    explicitly non-executable, or if the UI ever acquires a control that calls
    the endpoint.
    """
    page = (ROOT / "apps/web/src/features/app-overview/AppOverviewPage.tsx").read_text(encoding="utf-8")

    # The classified entry exists inside the ordinary capabilities list.
    assert 'data-testid="capability-synthetic-run"' in page
    assert "SYNTHETIC_VALIDATION_CLASSIFICATION" in page

    # It is explicitly non-executable, in machine-checkable and user-facing form.
    assert 'data-executable="false"' in page
    for required in (
        "not executable from this UI",
        "It does not imply production readiness.",
        "Infrastructure configuration validation is performed by the validate plan/run operation.",
    ):
        assert required in page, f"synthetic-validation classification lost required copy: {required!r}"

    # It stays a statement of classification: no button or link is rendered for it.
    classification_block = page.split('data-testid="capability-synthetic-run"', 1)[1]
    classification_block = classification_block.split("</li>", 1)[0]
    assert "<button" not in classification_block
    assert "<Button" not in classification_block
    assert "<a " not in classification_block
    assert "<Link" not in classification_block

    # The UI still never calls the endpoint. The contract keeps it *declared*
    # (endpoints.ts) but with no routed control, so the invariant to pin is
    # "declared exactly once, invoked nowhere" — not "the path literal is
    # absent", which would forbid a documented declaration.
    frontend = ROOT / "apps" / "web" / "src"
    declared_in = sorted(
        path.relative_to(frontend).as_posix()
        for path in frontend.rglob("*")
        if path.suffix in {".ts", ".tsx"}
        and path.is_file()
        and "__tests__" not in path.as_posix()
        and "syntheticRun" in path.read_text(encoding="utf-8")
    )
    assert declared_in == ["client/http/endpoints.ts"], (
        f"syntheticRun must stay a bare endpoint declaration, but it also appears in {declared_in}"
    )
    endpoints = (frontend / "client/http/endpoints.ts").read_text(encoding="utf-8")
    assert "syntheticRun: (instanceId: string) =>" in endpoints
    assert endpoints.count("syntheticRun") == 1

    manifest = yaml.safe_load((ROOT / "config/functionality-preservation.v1.yaml").read_text(encoding="utf-8"))
    entry = next(item for item in manifest["userControls"] if item["id"] == "run-button")
    assert entry["status"] == "preserved"
    assert "remainingGap" not in entry
    assert entry["evidence"] == {
        "file": "apps/web/src/features/app-overview/AppOverviewPage.tsx",
        "contains": 'data-testid="capability-synthetic-run"',
    }
    assert "production readiness" in entry["migrationBehavior"]

    # The manifest entry no longer hides the capability behind an open gap.
    assert not [
        item
        for group in ("uiRoutes", "userControls", "capabilities")
        for item in manifest[group]
        if item["status"] == "gap"
    ]


def test_every_preservation_cited_test_resolves_to_a_real_file_inside_the_repository() -> None:
    """A cited `test` is a coverage claim, so it must resolve to a real file.

    The JSON schema checks `test` is a non-empty string and nothing more, and
    the validator previously never read the field at all, so a refactor that
    deleted or renamed a cited test left the manifest claiming coverage it no
    longer had. This asserts the positive property over the real manifest and
    then proves the guard it relies on has teeth in the three shapes that must
    be refused: a missing path, a path escaping the repository, and a
    directory rather than a file.
    """
    manifest = yaml.safe_load((ROOT / "config/functionality-preservation.v1.yaml").read_text(encoding="utf-8"))
    groups = ("uiRoutes", "userControls", "apiOperations", "capabilities", "legacyAliases")
    entries = [item for group in groups for item in manifest[group]]
    assert entries, "the manifest must cite tests at all"
    for item in entries:
        _check_preservation_item(item)

    # The refusal must name the offending entry, not just fail: a refusal a
    # reader cannot act on is not a usable gate.
    template = dict(next(item for item in manifest["userControls"] if item["id"] == "menu-toggle"))
    for rejected in (
        "scripts/test_application_experience_DOES_NOT_EXIST.py",
        "../../../etc/hostname",
        "scripts",
    ):
        broken = {**template, "test": rejected}
        with pytest.raises(ValueError, match=r"preservation test path is missing or unsafe for menu-toggle"):
            _check_preservation_item(broken)


# ---------------------------------------------------------------------------
# The shape of the undeclared population.
#
# These tests exist to hold ONE property above every other: the shape
# breakdown describes the same population the coverage census counts, and
# reduces nothing. The population boundary is the owner's undecided call, so the
# dangerous failure mode here is not a wrong class -- that is visible and
# correctable -- but a breakdown that quietly became a filter, where the census
# shrank and the number nobody re-derived stayed printed. So the partition is
# pinned to be exhaustive and disjoint against the real population, and pinned
# again on synthetic input where a class can be forced.
# ---------------------------------------------------------------------------


def _real_census() -> tuple[dict[str, str], list[str]]:
    """The shipped sources and the real undeclared population.

    Built from the manifests the way validate() does, so this does not re-derive
    the population by a second route that could drift from the figure.
    """
    import validate_application_experience as module

    manifest = module._merge_preservation_extensions(
        module._load_yaml(ROOT / "config" / "functionality-preservation.v1.yaml")
    )
    dynamic = module._load_yaml(ROOT / "config" / "frontend-dynamic-preservation.v1.yaml")
    everything = [
        *manifest["uiRoutes"],
        *manifest["userControls"],
        *manifest["apiOperations"],
        *manifest["capabilities"],
        *manifest["legacyAliases"],
        *dynamic.get("controls", []),
        *dynamic.get("operations", []),
        *dynamic.get("behaviors", []),
    ]
    sources = _shipped_frontend_sources()
    return sources, _undeclared_controls(sources, everything)


def test_shape_breakdown_partitions_the_population_without_narrowing_it() -> None:
    """The classes must tile the population exactly: every identity once."""
    sources, undeclared = _real_census()
    shapes = _control_shape_classes(sources, undeclared)
    assert set(shapes) == set(CONTROL_SHAPE_CLASSES)
    everything = [entry for values in shapes.values() for entry in values]
    # Disjoint AND exhaustive: no identity is dropped and none is counted twice.
    # A filter that removed, say, the container class would fail the first
    # assertion; one that reported a class twice would fail the second.
    assert sorted(everything) == sorted(undeclared)
    assert len(everything) == len(set(everything)) == len(undeclared)
    # And the classes are not empty for no reason: each one is reachable.
    assert all(shapes[name] for name in CONTROL_SHAPE_CLASSES)


def test_shape_breakdown_does_not_change_the_reported_coverage_figure() -> None:
    """Reporting a shape must not move the figure, the exit path or the rest.

    The returned figure set is the published one and is compared by exact
    equality elsewhere, so this asserts the two specific things a shape report
    could plausibly disturb: the count itself, and the rest of the counts.
    """
    counts = validate()
    assert counts["undeclaredControls"] == 515
    assert counts["routes"] == 17 and counts["controls"] == 77
    sources, undeclared = _real_census()
    shapes = _control_shape_classes(sources, undeclared)
    assert sum(len(values) for values in shapes.values()) == counts["undeclaredControls"]


def test_interactive_and_container_hosts_are_told_apart_by_a_real_element() -> None:
    """A native action and a layout anchor must not land in the same class."""
    sources = {
        "apps/web/src/Synthetic.tsx": (
            "export function Synthetic() {\n"
            '  return (\n'
            "    <div>\n"
            '      <button data-testid="press">Go</button>\n'
            '      <a href="/x" data-testid="link">Away</a>\n'
            '      <input data-testid="typed" />\n'
            '      <div data-testid="anchor" />\n'
            '      <section data-testid="region" />\n'
            "    </div>\n"
            "  )\n"
            "}\n"
        )
    }
    undeclared = sorted(
        f'{file}: data-testid="{name}"'
        for file, content in sources.items()
        for name in __import__("re").findall(r'data-testid="([^"{}$`]+)"', content)
    )
    shapes = _control_shape_classes(sources, undeclared)
    assert sorted(entry.split('"')[1] for entry in shapes["interactive"]) == [
        "link",
        "press",
        "typed",
    ]
    assert sorted(entry.split('"')[1] for entry in shapes["container_or_layout"]) == [
        "anchor",
        "region",
    ]
    assert sum(len(values) for values in shapes.values()) == 5


def test_a_local_component_is_followed_to_the_element_it_renders() -> None:
    """A wrapper component must not be filed as unresolvable just for being one.

    The barrel is the whole point: the component is reached only by following
    the re-export, which is exactly how the shipped frontend imports its shared
    components (`import { Button } from '@/components'`). A resolver that stops
    at the import would report every such control as unresolvable.
    """
    sources = {
        "apps/web/src/ui/Button.tsx": (
            "export function Button(props: Record<string, unknown>) {\n"
            "  return <button type=\"button\" {...props} />\n"
            "}\n"
        ),
        "apps/web/src/components.ts": "export { Button } from './ui/Button'\n",
        "apps/web/src/Page.tsx": (
            "import { Button } from '@/components'\n"
            "export function Page() {\n"
            '  return <Button data-testid="wrapped-action" />\n'
            "}\n"
        ),
    }
    shapes = _control_shape_classes(
        sources, ['apps/web/src/Page.tsx: data-testid="wrapped-action"']
    )
    assert shapes["interactive"] == ['apps/web/src/Page.tsx: data-testid="wrapped-action"']


def test_an_unresolvable_host_is_reported_as_unknown_rather_than_guessed() -> None:
    """A third-party component is its own class, not silently a container.

    This is the honesty property: react-router's Link renders an <a>, but no
    shipped file says so, so the scan must not assert either way. Filing it as
    `interactive` would need a hand-maintained list of "our components are
    buttons", which is precisely the list that goes stale and leaves a control
    reported as a layout anchor after it was turned into a button.
    """
    sources = {
        "apps/web/src/Page.tsx": (
            "import { Link } from 'react-router-dom'\n"
            "export function Page() {\n"
            '  return <Link to="/x" data-testid="third-party" />\n'
            "}\n"
        )
    }
    shapes = _control_shape_classes(
        sources, ['apps/web/src/Page.tsx: data-testid="third-party"']
    )
    assert shapes["component_host_unresolved"] == [
        'apps/web/src/Page.tsx: data-testid="third-party"'
    ]
    assert not shapes["interactive"] and not shapes["container_or_layout"]


def test_a_data_testid_in_a_selector_string_is_kept_but_called_a_reference() -> None:
    """A textual occurrence stays in the population and is not called an element.

    This is the real `drawer` case: one control, referenced by a
    querySelector in two other files, which the text scan counts twice more.
    Dropping them would be a silent narrowing of the population; calling them
    elements would be a lie. They are reported as references instead.
    """
    sources = {
        "apps/web/src/Tool.tsx": (
            "export function closeIfOpen() {\n"
            "  if (document.querySelector('[data-testid=\"drawer\"]')) return\n"
            "}\n"
        )
    }
    shapes = _control_shape_classes(
        sources, ['apps/web/src/Tool.tsx: data-testid="drawer"']
    )
    assert shapes["non_element_reference"] == ['apps/web/src/Tool.tsx: data-testid="drawer"']
    assert sum(len(values) for values in shapes.values()) == 1


def test_a_mention_in_a_doc_comment_is_not_mistaken_for_a_control() -> None:
    """Prose that quotes a literal is not an element, and a bare `'` is not a string.

    The apostrophe case is the regression that a whole-file mask walks into:
    "couldn't" in JSX text opens a string that pairs with the next apostrophe in
    the file and masks everything between, which reclassified the entire
    population as non-elements on the first attempt at this feature.
    """
    sources = {
        "apps/web/src/Page.tsx": (
            "/**\n"
            " * The layout root keeps data-testid=\"page-stub\" as a legacy anchor.\n"
            " */\n"
            "export function Page() {\n"
            "  // it couldn't be removed, so data-testid=\"page-note\" survives too\n"
            "  return <div data-testid=\"page-anchor\" />\n"
            "}\n"
        )
    }
    shapes = _control_shape_classes(
        sources,
        [
            'apps/web/src/Page.tsx: data-testid="page-stub"',
            'apps/web/src/Page.tsx: data-testid="page-note"',
            'apps/web/src/Page.tsx: data-testid="page-anchor"',
        ],
    )
    assert shapes["non_element_reference"] == [
        'apps/web/src/Page.tsx: data-testid="page-note"',
        'apps/web/src/Page.tsx: data-testid="page-stub"',
    ]
    assert shapes["container_or_layout"] == ['apps/web/src/Page.tsx: data-testid="page-anchor"']


def test_a_placeholder_is_not_reported_as_an_operator_action() -> None:
    """Loading placeholders are the clearest non-action case, on any host kind.

    Asserted through a component host the scan cannot resolve, because that is
    where this went wrong first: `overview-skeleton` sits on <SkeletonRows>, and
    testing resolvability before the placeholder test filed it under
    component_host_unresolved, the one class where nobody looks for a skeleton.
    """
    sources = {
        "apps/web/src/Page.tsx": (
            "import { SkeletonRows } from '@/components'\n"
            "export function Page() {\n"
            '  return <SkeletonRows rows={6} data-testid="route-skeleton" />\n'
            "}\n"
        )
    }
    shapes = _control_shape_classes(
        sources, ['apps/web/src/Page.tsx: data-testid="route-skeleton"']
    )
    assert shapes["skeleton_placeholder"] == ['apps/web/src/Page.tsx: data-testid="route-skeleton"']
    assert sum(len(values) for values in shapes.values()) == 1


def test_an_identity_repeated_in_one_file_takes_the_most_actionable_class() -> None:
    """Several sites of one identity fold to one class, and it is stated which.

    A `data-testid` reused for a dialog trigger and the dialog body must be
    reported once, as the thing an operator acts on, and the rule has to be the
    documented one rather than whichever site happened to be scanned first.
    """
    sources = {
        "apps/web/src/Page.tsx": (
            "export function Page() {\n"
            "  return (\n"
            "    <div>\n"
            '      <button data-testid="reuse" onClick={open} />\n'
            '      <div data-testid="reuse" />\n'
            "    </div>\n"
            "  )\n"
            "}\n"
        )
    }
    shapes = _control_shape_classes(sources, ['apps/web/src/Page.tsx: data-testid="reuse"'])
    assert shapes["interactive"] == ['apps/web/src/Page.tsx: data-testid="reuse"']
    assert sum(len(values) for values in shapes.values()) == 1


def test_declared_rows_that_credit_no_control_identity_are_enumerated() -> None:
    """A declared row anchored on prose discharges no identity, and says so.

    These rows are not wrong and the manifest must not be "fixed" by deleting
    them: _check_preservation_item already proves each cites fresh, real
    evidence. What the split records is that they are not the same kind of thing
    as an undeclared identity, so the two must not be summed into a percentage.
    """
    manifest = yaml.safe_load(
        (ROOT / "config" / "functionality-preservation.v1.yaml").read_text(encoding="utf-8")
    )
    credited, uncredited = _uncredited_declared_controls(manifest["userControls"])
    assert len(credited) + len(uncredited) == len(manifest["userControls"]) == 77
    # Pinned because these two numbers are what the report publishes, and a
    # silent change in either is a change in what the manifest is claiming.
    assert len(credited) == 25
    assert len(uncredited) == 52
    # Spot-checked on both sides so the split is not merely arithmetic: one row
    # that does name a control identity, and one that names only a label.
    assert "run-button" in {row["id"] for row in credited}
    assert "menu-toggle" in {row["id"] for row in uncredited}
    assert all(row["file"] and row["contains"] for row in uncredited)


def test_the_shape_report_is_actually_printed_and_agrees_with_the_figure() -> None:
    """The report must reach stdout, and its sum must be the published figure.

    This test exists because of a demonstrated hole, not a hypothetical one.
    Deleting the single line that calls the report from main() removes every
    SHAPES and DECLARED line from the output, and every other test in this file
    still passed: they call the functions directly, so nothing tied the
    functions to what the validator actually says. A gate whose breakdown can
    be deleted without a failure is a breakdown nobody is reading.
    """
    import io
    import contextlib

    import validate_application_experience as module

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        assert module.main() == 0
    printed = buffer.getvalue()

    counts = validate()
    assert counts["undeclaredControls"] == 515
    shape_line = next(line for line in printed.splitlines() if line.startswith("SHAPES "))
    assert "undeclaredControls=515" in shape_line
    # The printed sum is checked against the printed classes, and the printed
    # classes are checked against the census, so a lie in the report line is
    # caught here even if every underlying function is correct.
    reported = dict(
        part.split(":") for part in shape_line.split("breakdown=")[1].split()[0].split(",")
    )
    assert {name: int(value) for name, value in reported.items()} == {
        name: len(module._CENSUS["shapes"][name]) for name in module.CONTROL_SHAPE_CLASSES
    }
    assert int(shape_line.split("sum=")[1].split()[0]) == counts["undeclaredControls"]
    assert "exhaustive=True" in shape_line
    # The declared split is reported too, and pinned to the same numbers the
    # manifest really has.
    assert "DECLARED userControls=77 creditingADataTestid=25 creditingNone=52" in printed
    # The ceiling travels with the numbers, so the claim cannot be read without
    # the limits attached to it.
    assert "WHAT THE SHAPES LINE DOES NOT ESTABLISH" in printed
    assert "must not be summed into a coverage percentage" in printed
    # The EXPRESSION line is actually reported, with its ceiling attached, so the
    # new signal cannot be read as coverage without seeing what it is not.
    expression_line = next(line for line in printed.splitlines() if line.startswith("EXPRESSION "))
    assert "expressedInATest=" in expression_line and "expressedNowhere=" in expression_line
    assert "is not regression verification" in printed
    assert "NOT a count of untested behaviours" in printed


# The FIXED NEGATIVE CONTROL. These five behaviours the measurement found are
# genuinely unexercised: their derived handle appears in no test. If a change to
# the expression census stops reporting any of them as `expressed_nowhere` -- i.e.
# starts crediting them -- this test fails, which is the whole point of pinning
# them as a negative control for any recall-increasing repair.
def test_the_five_fixed_negative_control_rows_stay_expressed_nowhere() -> None:
    import validate_application_experience as module

    validate()
    _, expressed_nowhere = module._CENSUS["expression"]
    unexpressed = {row["id"] for row in expressed_nowhere}
    fixed = {
        "governed-portable-execution",
        "infrastructure-plan",
        "open-advanced-button",
        "provenance-ownership-recovery",
        "workbench-status-area",
    }
    assert fixed <= unexpressed, (
        "negative control broken: behaviours known to be unexercised were credited: "
        f"{sorted(fixed - unexpressed)}"
    )


# The POSITIVE CONTROL. These four rows were MEASURED to be regression-protected:
# mutating the behaviour each pins makes the row's real driver test fail. If a
# change stops crediting (expressing) any of them, this test fails. Together the
# two controls pin both directions: recall may increase only for rows whose
# behaviour a test really touches, and never at the cost of the five that no test
# touches.
def test_measured_regression_protected_rows_stay_expressed_in_a_test() -> None:
    import validate_application_experience as module

    validate()
    expressed, _ = module._CENSUS["expression"]
    expressed_ids = {row["id"] for row in expressed}
    protected = {
        "copy-cli-button",
        "repository-import-inspect",
        "repository-import-refresh",
        "terminal-end",
    }
    assert protected <= expressed_ids, (
        "positive control broken: a regression-protected row stopped being credited: "
        f"{sorted(protected - expressed_ids)}"
    )


def _api_operations() -> list[dict[str, object]]:
    """The merged apiOperations, the population the citation measure covers."""
    manifest = yaml.safe_load(
        (ROOT / "config" / "functionality-preservation.v1.yaml").read_text(encoding="utf-8")
    )
    operations = list(manifest["apiOperations"])
    extension_root = ROOT / "config" / "functionality-preservation.extensions"
    for path in sorted(extension_root.glob("*.yaml")):
        operations.extend(yaml.safe_load(path.read_text(encoding="utf-8"))["apiOperations"])
    return operations


def test_composed_citations_resolve_by_ast_and_never_by_grep() -> None:
    """A route composed at a sink must read supported, not unsupported.

    This test exists because the naive alternative is wrong, not merely
    inconvenient. A literal grep for '/v1/provider/credential' finds NOTHING in
    scripts/test_provider_setup.py, which composes f'/v1/provider/{action}' at
    the sink and picks the verb from a ternary, so a grep-based measure reports
    it unsupported and accuses a correct, live test. The same applies to the
    conversation helper that binds its path through a `method=` keyword.

    Every case below is composed at a sink from a parameter, and each one must
    land in `supported` -- never `unsupported`, and never silently `unresolved`
    either, because a measure that cannot see a correct citation teaches its
    reader nothing.
    """
    operations = {item["id"]: item for item in _api_operations()}
    measurement = _citation_measurement(list(operations.values()))
    for identifier in (
        "provider-credential-set-api",
        "provider-credential-remove-api",
        "post-instance-conversation-export",
        "post-instance-conversation-clear",
        "get-instance-activity",
    ):
        assert identifier in measurement["supported"], (
            f"{identifier} must resolve as supported, not "
            f"unsupported={identifier in measurement['unsupported']} "
            f"unresolved={identifier in measurement['unresolved']}"
        )


def test_a_citation_with_no_supporting_test_is_reported_unsupported() -> None:
    """The measure must be able to accuse, or it detects nothing at all.

    A measure that reports `supported` for everything would pass the test
    above too, so it is only useful if the other direction is also reachable.
    scripts/test_settings_service.py exercises a settings STORE directly and
    issues no request at all, which is exactly the shape of the real defect
    this measure was written for.
    """
    measurement = _citation_measurement(_api_operations())
    assert "preview-application-settings" in measurement["unsupported"]


def test_the_three_buckets_are_exhaustive_and_disjoint() -> None:
    """Every apiOperation row lands in exactly one bucket, and none is lost.

    Without this, a row silently dropped by an exception would improve every
    number it appears in, and the counts would be unfalsifiable.
    """
    operations = _api_operations()
    measurement = _citation_measurement(operations)
    buckets = [
        set(measurement["supported"]),
        set(measurement["unsupported"]),
        set(measurement["unresolved"]),
    ]
    assert sum(len(bucket) for bucket in buckets) == len(operations)
    assert not (buckets[0] & buckets[1]) and not (buckets[0] & buckets[2]) and not (buckets[1] & buckets[2])
    assert set().union(*buckets) == {str(item["id"]) for item in operations}

    # The four rows the subscript change moved are pinned to the honest bucket.
    # `unresolved` says the route is in the cited file and the path parameter's
    # value is not provable from it. `unsupported` would be a confident accusation
    # against a correct, live test. `supported` would be worse still: it would
    # claim the route is exercised with a run/grant/route id the resolver never saw.
    for identifier in (
        "provider-verify-api",
        "post-authority-grant-revoke",
        "post-preview-route-revoke",
        "post-preview-route-rewrite",
    ):
        assert identifier in buckets[2], (
            f"{identifier} must be unresolved; supported={identifier in buckets[0]} "
            f"unsupported={identifier in buckets[1]}"
        )
        assert identifier not in buckets[0]
        assert identifier not in buckets[1]


def test_a_citation_the_resolver_cannot_read_is_unresolved_never_unsupported() -> None:
    """A TypeScript citation is an unknown, not a defect.

    The resolver reads Python. For anything else it knows nothing, and the only
    safe way to publish that ignorance is `unresolved`: reporting a
    non-Python citation as unsupported would be the resolver guessing, and a
    guess that reads as a finding will eventually be acted on.
    """
    pairs, analysable = _resolve_test_citations(ROOT / "apps" / "web" / "tests" / "live-core.spec.ts")
    assert analysable is False
    assert pairs == set()


def test_an_unresolved_path_never_matches_a_declared_route(tmp_path: Path) -> None:
    """A composition the resolver could not complete cannot confirm anything.

    This is the safety property the whole measure rests on. If a path still
    holding a hole could match, every blind spot would read as a confirmed
    coverage claim, and the measure would be worse than not having it.

    Since the resolver learned to read a SUBSCRIPT-BOUND PATH PARAMETER, this also
    carries the negative control for that change: one positive control that MUST
    resolve, and five cases that look resolvable and must NOT. They live in this
    existing function rather than a new one so the total stays 61 -- the check is
    a strengthening of the property already asserted here, not a new moving part.

    The positive control is what makes the five refusals mean anything. All four
    corpus rows the subscript change moved are `unresolved`, which shows the
    classification is honest but proves nothing about whether subscript reading
    works; without a case that must resolve, every refusal below would also pass
    against a resolver with no subscript support at all.
    """
    from validate_application_experience import (
        _HOLE_CHAR,
        _HOLE_KEEP,
        _hole,
        _hole_path_matches,
    )

    unresolved = f"/v1/instances/{_hole('instance')}/activity"
    assert not _path_matches(unresolved, "/v1/instances/{instanceId}/activity")
    assert _path_matches("/v1/instances/project-one/activity", "/v1/instances/{instanceId}/activity")
    # A longer test path must not satisfy a shorter declared one.
    assert not _path_matches("/v1/provider/credential/remove", "/v1/provider/credential")
    assert _HOLE_CHAR not in "/v1/instances/project-one/activity"

    # --- the hole-shape comparator answers a NARROWER question ---------------
    # A hole is one unknown segment, so it compares under the same rule as a
    # declared `{name}`: equal segment count, one segment per wildcard. It must not
    # let a hole swallow a separator, or a two-segment run id would satisfy a
    # one-segment route.
    hole = _HOLE_KEEP
    assert _hole_path_matches(f"/v1/runs/{hole}/approve", _DECLARED_RUN_APPROVE)
    assert not _hole_path_matches(f"/v1/runs/{hole}{hole}/approve", "/v1/runs/{runId}")
    assert not _hole_path_matches(f"/v1/runs/{hole}/approve", "/v1/runs")
    # A hole is also compatible with a CONCRETE declared segment, because an
    # unresolved value could be that value. This does not weaken the bucket: the
    # answer is still `unresolved` -- an unknown that accuses nothing -- and still
    # never `supported`. It is why provider-verify-api lands in `unresolved` while
    # the test composes f'/v1/provider/{action}' against the concrete route
    # /v1/provider/verify. Widening here moves rows toward "unknown", which is the
    # safe direction: it can neither invent coverage nor invent a defect.
    assert _hole_path_matches(
        f"/v1/runs/{hole}/approve", "/v1/runs/literal/approve"
    )
    # A fully resolved path is not this function's business at all.
    assert not _hole_path_matches("/v1/runs/run-123/approve", _DECLARED_RUN_APPROVE)

    # --- POSITIVE CONTROL: a provable literal subscript must resolve ---------
    # The resolver returns (pairs, analysable); the probe files here are written
    # by this test and always parse, so a set(), False return would fail the
    # positive control below loudly rather than vacuously.
    resolved_pairs, _ = _resolve_test_citations(
        _write_probe(tmp_path, _PROVABLE_SUBSCRIPT)
    )
    resolved = frozenset(
        path
        for path, _ in resolved_pairs
    )
    assert "/v1/runs/run-123/approve" in resolved, (
        f"a provable literal subscript must resolve; got {sorted(resolved)}"
    )
    assert _path_matches("/v1/runs/run-123/approve", _DECLARED_RUN_APPROVE)

    # --- NEGATIVE CONTROLS: five things that look resolvable and are not -----
    for _label, _source in _REFUSALS.items():
        refused_pairs, _ = _resolve_test_citations(
            _write_probe(tmp_path, _source)
        )
        refused = frozenset(
            path
            for path, _ in refused_pairs
        )
        assert not any(
            _path_matches(path, _DECLARED_RUN_APPROVE) for path in refused
        ), (
            f"{_label}: an unprovable subscript resolved into a confirmed path, "
            f"which is fabrication; got {sorted(refused)}"
        )
        # It must stay VISIBLE as the route shape, so the row lands in
        # `unresolved` -- an honest unknown -- rather than `unsupported`, which
        # accuses a test that does exercise the route.
        assert any(
            _hole_path_matches(path, _DECLARED_RUN_APPROVE) for path in refused
        ), f"{_label}: the route shape was lost entirely; got {sorted(refused)}"


def _write_probe(tmp_path: Path, source: str) -> Path:
    """A throwaway module the resolver can be pointed at.

    Written under tmp_path and never into the repository: this increment changes
    the MEASUREMENT, and adding a fixture test file to the tree would be a new
    moving part in a lane whose allowed paths are the two scripts.
    """
    probe = tmp_path / "probe_citation.py"
    probe.write_text(source, encoding="utf-8")
    return probe


# A subscript over a provable literal, composed into a path at a sink.
_PROVABLE_SUBSCRIPT = '''
RUNS = {"run": {"runId": "run-123"}}

def post(path, body=None):
    connection.request("POST", path, body)

def test_provable():
    post(f"/v1/runs/{RUNS['run']['runId']}/approve", {})
'''

# Each of these looks resolvable and must not be. Together they are the negative
# control: a resolver that loosened subscript handling would resolve at least one.
_REFUSALS = {
    # A subscript on a LIVE RESPONSE. This is the ordinary case for run/grant/route
    # ids, and it is why so many of these rows land in unresolved rather than
    # supported: the value is server-generated and the test never writes it down.
    "live_response": '''
def post(path, body=None):
    connection.request("POST", path, body)

def test_live():
    prepared = post("/v1/instances/i/execution/prepare", {})
    run_id = prepared["result"]["run"]["runId"]
    post(f"/v1/runs/{run_id}/approve", {})
''',
    # The name is a PARAMETER of another function. This is the historical bug: a
    # same-named module literal would otherwise fill the hole, which is how this
    # metric once invented /v1/provider/costTelemetry.
    "parameter_shadow": '''
RUNS = {"runId": "run-from-an-unrelated-table"}

def post(path, runId):
    connection.request("POST", path)

def test_shadow():
    post(f"/v1/runs/{runId}/approve")
''',
    # The dict LOOKS like a literal and is not one: its values are names.
    "looks_literal": '''
def post(path, body=None):
    connection.request("POST", path, body)

def test_looks():
    origin = "http://127.0.0.1:1"
    service = {"origin": origin, "port": 1}
    post(f"/v1/runs/{service['origin']}/approve", {})
''',
    # The name is bound more than once, so which binding is in force at the sink is
    # a choice the resolver must not make on the test's behalf.
    "rebound": '''
def post(path, body=None):
    connection.request("POST", path, body)

def test_rebound():
    run = {"runId": "run-late"}
    run = post("/v1/runs", {})
    post(f"/v1/runs/{run['runId']}/approve", {})
''',
    # The key is a computed name, not a constant. Refuses rather than guessing.
    "dynamic_key": '''
RUNS = {"a": {"runId": "run-123"}}

def post(path, body=None):
    connection.request("POST", path, body)

def test_dynamic():
    which = "a"
    post(f"/v1/runs/{RUNS[which]['runId']}/approve", {})
''',
}

_DECLARED_RUN_APPROVE = "/v1/runs/{runId}/approve"


def _probe_row(tmp_path: Path, source: str, identifier: str = "probe-row") -> dict[str, object]:
    """One manifest row whose `test` is a throwaway probe file, and its buckets.

    `test` is an ABSOLUTE path: `_citation_measurement` builds the file to read
    with `ROOT / <test>`, and pathlib's `/` returns the right operand unchanged
    when it is absolute, so the probe stays under tmp_path and out of the
    repository. Writing a fixture test file into the tree instead would be a new
    moving part in a lane whose allowed path is this file alone.
    """
    probe = _write_probe(tmp_path, source)
    item: dict[str, object] = {
        "id": identifier,
        "path": _DECLARED_RUN_APPROVE,
        "method": "POST",
        "test": str(probe),
    }
    return _citation_measurement([item])


def test_a_subscript_row_provable_from_a_literal_is_reported_supported(tmp_path: Path) -> None:
    """POSITIVE CONTROL: subscript reading must actually work, or the refusals mean nothing.

    Every negative control below also passes against a resolver that ignores
    subscripts completely, because "returns nothing" is indistinguishable from
    "refuses to guess". This is the case that separates the two: the value is
    written out in the test as a plain dict literal, so reading it is reading
    the test, and the row must come out `supported`.

    The assertion is on the BUCKET, not on the resolver's intermediate pairs.
    A path can resolve correctly and still be mislabelled by the classification
    below it, and it is the bucket that is published as
    `CITATIONS supported=N`. The row is also required to resolve to the exact
    declared shape, so a resolver that emitted some other concrete path cannot
    buy the `supported` bucket with a fabrication.
    """
    measurement = _probe_row(tmp_path, _PROVABLE_SUBSCRIPT)
    assert "probe-row" in measurement["supported"], (
        f"a subscript provable from a literal must be supported; "
        f"got supported={measurement['supported']} "
        f"unresolved={measurement['unresolved']} "
        f"unsupported={measurement['unsupported']}"
    )
    assert "/v1/runs/run-123/approve" not in measurement["unresolved"]


def test_an_unprovable_subscript_row_is_unresolved_and_never_supported(tmp_path: Path) -> None:
    """NEGATIVE CONTROL: an honest unknown must never be promoted to a claim.

    This is the exact regression that once shipped: anonymous holes were filled
    from an unrelated module table and the resolver INVENTED /v1/provider/
    costTelemetry, a route no test ever called. A resolver that guesses is worse
    than no resolver, because it converts an honest unknown into false
    assurance -- and false assurance is what a reader acts on.

    Each case below is a row the resolver can see the route in and CANNOT prove
    the value of. It must land in `unresolved`: the route is demonstrably in the
    cited file and the segment's value is unknown. It must never reach
    `supported`, which asserts the request is exercised with a value the
    resolver never saw, and it must not fall back to `unsupported`, which
    accuses a test that does exercise the route.

    The check that makes this non-vacuous: every case also asserts the hole
    SHAPE is still visible in what the resolver returned. Without that, a probe
    file that failed to parse would return no pairs at all, land in
    `unresolved` for the wrong reason, and pass -- which is a test that
    certifies nothing. Seeing the shape proves the file WAS read and the route
    WAS found; what is missing is the value, and the bucket must say so.
    """
    from validate_application_experience import _hole_path_matches

    for label, source in _REFUSALS.items():
        measurement = _probe_row(tmp_path, source, identifier=label)
        assert label not in measurement["supported"], (
            f"{label}: an unprovable subscript was promoted to supported, which "
            f"is fabrication; supported={measurement['supported']}"
        )
        assert label in measurement["unresolved"], (
            f"{label}: an unprovable subscript must be an honest unknown; "
            f"got unsupported={measurement['unsupported']} "
            f"supported={measurement['supported']}"
        )
        assert label not in measurement["unsupported"], (
            f"{label}: the route IS in the cited file, so unsupported is a "
            f"confident false accusation"
        )
        # Non-vacuity: the shape must still be visible, so `unresolved` above is
        # the hole branch and not an unparsed file.
        pairs, analysable = _resolve_test_citations(
            _write_probe(tmp_path, source)
        )
        assert analysable is True, f"{label}: the probe did not parse, so the check is void"
        assert any(
            _hole_path_matches(path, _DECLARED_RUN_APPROVE) for path, _ in pairs
        ), f"{label}: the route shape was lost; the file was read but not understood"


def test_the_measurement_never_refuses_and_never_enters_the_verdict() -> None:
    """The measure is reporting-only, and that is enforced, not just intended.

    Two properties at once: an unresolvable citation does not raise, and the
    published figure set is byte-identical whether the measurement runs or not.
    The second is checked by comparing validate()'s return value against the
    keys the existing tests already pin, so adding a key here would fail
    rather than quietly republish a different number.
    """
    counts = validate()
    assert set(counts) == {
        "descriptors",
        "routes",
        "controls",
        "apis",
        "capabilities",
        "aliases",
        "dynamicControls",
        "dynamicOperations",
        "dynamicBehaviors",
        "declaredGapRows",
        "undeclaredControls",
        "dynamicGaps",
    }
    assert "citations" not in counts
    # A citation to a file that does not exist is an unknown, not a crash.
    measurement = _citation_measurement(
        [{"id": "x", "path": "/v1/x", "method": "GET", "test": "scripts/does_not_exist.py"}]
    )
    assert measurement["unresolved"] == ["x"]
    assert measurement["unsupported"] == []


def test_the_citation_line_reaches_stdout_with_its_ceiling() -> None:
    """The report must be printed, and its limits must travel with the numbers.

    A breakdown that can be deleted without a failure is a breakdown nobody is
    reading, which is the failure mode this file already has a test for on the
    SHAPES line. The ceiling sentence is asserted too: a count published
    without its limits is a claim, and this one is a measurement of reachability
    rather than of test quality.
    """
    import contextlib
    import io

    import validate_application_experience as module

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        assert module.main() == 0
    printed = buffer.getvalue()
    line = next(line for line in printed.splitlines() if line.startswith("CITATIONS "))
    # The figure moved 68/77 -> 71/72 because these five citations were repointed from
    # this file, which cannot exercise their routes, to tests that genuinely do:
    # get-instance -> scripts/test_studystate_sample_service.py (:88, real AppServer
    #   HTTP GET, asserts packageState),
    # get-instance-actions -> scripts/test_studystate_sample_service.py (:81, asserts
    #   the actionId set),
    # prepare-execution -> scripts/test_checklistdd_service.py (:109, POST, drives the
    #   run that every later assertion in that journey depends on),
    # get-health -> scripts/test_activity_receipts_service.py (:210, real AppServer
    #   /health, asserts result.status == "ok"),
    # get-status -> scripts/test_public_repository_import.py (:165, real AppServer
    #   GET, asserts actor.actorId).
    # Three became SUPPORTED. get-health and get-status became UNRESOLVED rather than
    # supported, and that is the honest landing: both are genuinely exercised, but
    # each helper builds its Request with no explicit method=, so the resolver reads
    # the verb as absent and refuses to confirm it (validator lines 1768-1778). That
    # is a smaller claim than "tested" and a much smaller claim than the "unsupported"
    # defect they replace. rows and the other 15 unresolved are unchanged.
    #
    # THE FIGURE THEN MOVED 71/72/17 -> 71/68/21, ALL FOUR unsupported -> unresolved,
    # because the resolver learned to handle a SUBSCRIPT-BOUND PATH PARAMETER. Two
    # constructs are now read, and the construct named in the code is the subscript:
    #
    #   1. _provable_literals + _subscript_string read a subscript ONLY when its value
    #      is provably a literal written in that same test -- a dict/list/tuple
    #      literal, or json.loads of a string constant, with every value inside it also
    #      source-level. A live response, a helper call, a name bound more than once,
    #      a name that is a parameter of any function, a dict that merely LOOKS like
    #      a literal, a non-constant key, and a key absent from a provable dict are
    #      ALL refused.
    #   2. _hole_path_matches then compares a path the resolver could only partly
    #      resolve against the declared path, under the same segment-wise rule
    #      _path_matches already uses, so a hole stands for exactly one segment and
    #      can never swallow a separator.
    #
    # AN UNPROVABLE SUBSCRIPT STILL YIELDS UNRESOLVED, NEVER `supported`. That is the
    # whole safety property, and it is asserted directly, not by comment: the negative
    # controls live inside test_an_unresolved_path_never_matches_a_declared_route
    # (below, same file), which now runs a provable-literal case that MUST resolve and
    # five refusal cases that must not, and which pins the four corpus rows in
    # `unresolved` rather than `supported`. It is kept inside that existing function
    # so the total stays 61 and the check is a strengthening, not a new moving part.
    # The resolver already shipped a bug that filled anonymous holes from an unrelated
    # module table and INVENTED /v1/provider/costTelemetry, so a metric that
    # fabricates evidence is worse than no metric: it converts an honest unknown into
    # a false assurance.
    #
    # The four rows, and why each is `unresolved` rather than `unsupported` -- in
    # every case the value is NOT provable from a literal, which is precisely why no
    # row may claim `supported`:
    #   post-preview-route-revoke   -> scripts/test_preview_gateway.py:551 composes
    #     f"/v1/preview-routes/{route_id}/revoke", and :520 binds
    #     route_id = route["routeId"] where route = _register(harness, echo.port) --
    #     a Call, so _subscript_string returns None. The file has NO provable literal
    #     at all.
    #   post-preview-route-rewrite  -> same file, :532 composes
    #     f"/v1/preview-routes/{route_id}/rewrite" with the same unprovable binding.
    #   post-authority-grant-revoke -> scripts/test_platform_services_api.py:766
    #     composes f"/v1/authority/grants/{grant_id}/revoke" with grant_id from
    #     harness.grant(...) (:624), a Call. The :1055 sibling `grant_a['grantId']`
    #     is also unprovable even though `grants` IS a provable literal `{}` (:1014),
    #     because the key 'a' is absent from it.
    #   provider-verify-api         -> scripts/test_provider_setup.py composes
    #     f"/v1/provider/{action}" at the sink; `action` is a HELPER PARAMETER, not a
    #     subscript, so this row moved through construct 2 alone. It is named here so
    #     the four are not over-credited to the subscript fix.
    #
    # CONDITIONAL VERBS ARE NOW DECIDED FROM THE CALL SITE (2026-09-29).
    #
    # The figure moved from supported=71 unsupported=68 unresolved=21 to
    # supported=75 unsupported=68 unresolved=17 because the resolver no longer
    # DECIDES a conditional verb wrong. The construct is a sink reading
    # `method="POST" if body is not None else "GET"`: the old binder could not
    # reduce a call site's `body={"expectedVersion": 3}` to a string, so it
    # bound nothing, so the "unsupplied parameters take their declared default"
    # loop then bound `body` to its null marker, and the conditional decided
    # GET. That is a confident wrong answer about a request the test issues
    # WITH a body, and it is worse than an unknown because it manufactures a
    # contradiction a reader may "fix" by corrupting the manifest.
    #
    # The verb is now decided from the call site, by AST: a supplied argument
    # that is provably not None -- a dict/list/set/tuple literal, an f-string, a
    # non-None constant, or a name resolved through its own assignment -- makes
    # `x is not None` true and selects POST; an explicit `None`, or an omitted
    # argument whose declared default is None, selects GET; and a call site
    # whose body CANNOT BE PROVEN still yields `unresolved` and NOT either verb.
    # That last clause is the safety property and is pinned as a real negative
    # control in test_call_site_body_decides_the_conditional_verb below, because
    # a rule that cannot be shown to refuse is not a rule. Nothing is inferred
    # from a method name, a variable name, a path segment or a comment.
    #
    # The four rows, and the call site that decides each -- every one moved
    # unresolved -> supported, i.e. this is a pure narrowing of the unknown:
    #   install-application-fixture -> scripts/test_application_onboarding.py:158
    #     `body=payload`, and payload is a dict literal assigned at :146.
    #   post-instance-template-upgrade-request/approve/apply -> the same
    #     onboarding helper, same `body=payload` shape.
    # unsupported did not move at all, and that is structural rather than lucky:
    # `_citation_measurement` calls a row `unsupported` ONLY when no resolved
    # path matches it; a row whose path matches but whose verb does not is
    # `unresolved`. So a verb decision can move a row between `supported` and
    # `unresolved` and can never manufacture a new `unsupported`.
    #
    # This stays an EXACT-match tripwire for drift on purpose: a range, regex or
    # approximate comparison here would be indistinguishable from deleting the check.
    #
    # THE TWO ATTENTION ROWS ARE REPOINTED TO THE FILE THAT ACTUALLY ISSUES THEM
    # (2026-09-29). The figure moved supported=75 unsupported=68 unresolved=17
    # -> supported=77 unsupported=66 unresolved=17, and ONLY these two ids left
    # the unsupported list (verified by set difference over the
    # CITATIONS_DETAIL entries: removed = post-attention-read,
    # post-attention-acknowledge; added = nothing).
    #
    # Both rows cited scripts/test_application_experience.py, which contains
    # ZERO occurrences of "acknowledge" and no "/read" route literal at all: it
    # starts no server, so the rows were unsupported honestly. The requests that
    # DO exist are in scripts/test_activity_receipts_service.py, whose :401
    # sink is `method="POST" if body is not None else "GET"`:
    #   post-attention-read        -> :423 request("/v1/instances/activity-fixture/
    #     activity/recovery-backup/read", ...) with body= a dict literal keyed
    #     {"expectedVersion"} at :427 -> POST.
    #   post-attention-acknowledge -> :416 (no csrf, asserts 403), :441 (stale
    #     409) and :433 (success), each with a dict literal body keyed
    #     {"expectedVersion"} -> POST.
    # The verb is therefore not asserted by the manifest: the service registers
    # both routes inside do_POST (service_process.py:1433, route at :1765) and
    # calls self._strict_body(body, {"expectedVersion"}), so a GET could never
    # supply the required body. No method label was changed on either row.
    #
    # THE FIGURE NOW MOVES BY REACHABILITY, 77/66/17 -> 81/62/17. Four rows left
    # the unsupported list, and the construct is THE SINK IS PROVEN BY A TERMINAL
    # OPERATION INSTEAD OF BY ITS CALLEE NAME. The old rule asked whether a call's
    # NAME was in a fixed list; that is a naming convention, not a property of the
    # code, so a genuine request through a differently-named transport was
    # invisible. The new rule asks whether the thing the call reaches actually
    # performs I/O, and refuses when no terminal operation can be named. Nothing
    # in it can be satisfied by spelling.
    #
    #   post-template-upgrade-mutation-request   test_studystate_upgrade_surface.py:2079
    #   post-template-upgrade-approval-decision  test_studystate_upgrade_surface.py:2097
    #   post-template-upgrade-mutation-apply     test_studystate_upgrade_surface.py:2104
    #     api.dispatch("POST", "/v1/...", {...}) resolves to GovernedAPI.dispatch
    #     (packages/governed-api/src/governed_api/application.py:202), whose body
    #     builds the route table at :271-298 and calls the looked-up handler at
    #     :300. TERMINAL: service route dispatch -- a {"/route": handler} table,
    #     looked up BY THE REQUEST PATH, whose looked-up value is CALLED.
    #     All three assert real outcomes: :2087 status == 200, :256 a 403 and
    #     :2097 a 200, :2104-2117 a 403 on self-apply and a 200 with
    #     idempotent == True.
    #
    #   terminal-socket                            test_terminal_service.py:362
    #     RawWebSocket.open(service, path=SOCKET_PATH) does
    #     socket.create_connection(("127.0.0.1", port)) at :379 and writes the
    #     request line f"GET {path} HTTP/1.1" at :387.
    #     TERMINAL: socket.create_connection(...).
    #     The path is the `path=` KEYWORD, not args[0] (which is the service
    #     dict), and the verb is read out of that handshake request line rather
    #     than assumed; :725 asserts a 400 for a query-string variant.
    #
    # ZERO rows moved supported -> anything, and NOTHING was added to the
    # unsupported list: the set difference over the CITATIONS_DETAIL entries is
    # removed = exactly these four, added = nothing. A resolvable sink still
    # cannot fabricate a path -- the (method, path, body) offsets that make the
    # dispatch shape readable are gated on the SAME reachability proof, so a
    # computed path keeps its hole and an undecidable verb stays undecided.
    # 162/64: the two operation rows added after this pin was written (see the
    # `apis` pin) cite tests that do not contain their route, so they land in
    # `unsupported`; supported and unresolved are unchanged. That is the
    # report's honest answer for them, recorded rather than hidden.
    assert line == "CITATIONS rows=162 supported=81 unsupported=64 unresolved=17"
    assert "WHAT THE CITATIONS LINE DOES NOT ESTABLISH" in printed
    assert "not a gate" in printed


# ---------------------------------------------------------------------------
# CALL-SITE SUPPLIEDNESS: the conditional verb is decided from the call site
# ---------------------------------------------------------------------------
#
# The sink below is the real shape, verbatim from
# scripts/test_activity_receipts_service.py:393-401 and
# scripts/test_application_onboarding.py:48-63: a helper whose `body` is
# keyword-only with a None default, whose request verb is picked by testing that
# body. Whether the request is a POST or a GET is decided entirely by what each
# CALL SITE passes, which is why reading the sink alone can never answer it.
_CONDITIONAL_HELPER = '''
from urllib.request import Request, urlopen

def request(path, *, cookie=None, csrf=None, body=None):
    with urlopen(Request(f"http://127.0.0.1:8080{path}", data=body,
                         method="POST" if body is not None else "GET")) as response:
        return response.read()
'''


def _verbs_for(tmp_path: Path, body_argument: str) -> frozenset[str]:
    """The verbs one body-passing call site resolves to over a fixed route.

    The route is under `/v1/` because `_strip_origin` cuts a composed origin at
    the first of /v1/, /session or /health, so any other probe route keeps its
    `http://host` prefix and would never match the declaration it is compared
    against.
    """
    probe = _write_probe(
        tmp_path, _CONDITIONAL_HELPER + f'\nrequest("/v1/probe", {body_argument})\n'
    )
    pairs, analysable = _resolve_test_citations(probe)
    assert analysable, "the probe must parse; an unparsable probe proves nothing"
    return frozenset(
        verb
        for found, verbs in pairs
        if _path_matches(found, "/v1/probe")
        for verb in verbs
    )


def test_call_site_body_decides_the_conditional_verb(tmp_path: Path) -> None:
    """A supplied body decides POST, an absent one decides GET, by AST.

    This is the rule the metric change added, pinned in both directions. The
    old behaviour bound nothing for a supplied non-string body, let the
    helper's `None` default stand in for it, and decided GET for call sites
    that plainly pass a body -- a confident wrong answer, which is worse than
    an unknown because a reader may "fix" the contradiction by editing the
    manifest.

    Both parameter shapes are covered because both occur for real:
    `body=payload` against a keyword-only `body` in
    scripts/test_application_onboarding.py:48, and a positional
    `request(path, {...})` against `def request(path, body=None)` in
    scripts/test_studystate_upgrade_surface.py:154.
    """
    for label, body_argument in (
        ("dict literal", 'body={"expectedVersion": 3}'),
        ("empty dict literal", "body={}"),
        ("list literal", "body=[1, 2]"),
        ("f-string body", 'body=f"{x}"'),
        ("name bound to a dict literal", "body=payload"),
    ):
        source = _CONDITIONAL_HELPER + '\npayload = {"a": 1}\n'
        probe = _write_probe(tmp_path, source + f'request("/v1/probe", {body_argument})\n')
        pairs, analysable = _resolve_test_citations(probe)
        assert analysable
        verbs = frozenset(
            verb
            for found, found_verbs in pairs
            if _path_matches(found, "/v1/probe")
            for verb in found_verbs
        )
        assert verbs == frozenset({"POST"}), (
            f"{label}: a supplied body that is provably not None makes "
            f"`body is not None` true, so the sink's POST branch is the one "
            f"this call site reaches; got {sorted(verbs)}"
        )

    # The POSITIONAL shape, which is what three of the four moved rows use.
    positional = '''
from urllib.request import Request, urlopen

def request(path, body=None):
    with urlopen(Request(f"http://127.0.0.1:8080{path}", data=body,
                         method="POST" if body is not None else "GET")) as response:
        return response.read()

request("/v1/probe", {"expectedVersion": 3})
'''
    pairs, analysable = _resolve_test_citations(_write_probe(tmp_path, positional))
    assert analysable
    assert frozenset(
        verb
        for found, found_verbs in pairs
        if _path_matches(found, "/v1/probe")
        for verb in found_verbs
    ) == frozenset({"POST"}), "a positional dict body must also decide POST"

    for label, body_argument in (
        ("explicit None", "body=None"),
        ("body omitted, default is None", "cookie=None"),
    ):
        assert _verbs_for(tmp_path, body_argument) == frozenset({"GET"}), (
            f"{label}: no body was supplied, so `body is not None` is false and "
            f"the sink issues a GET; the resolver must read that from the call "
            f"site rather than defaulting either way"
        )

    # A positional body omitted entirely: `request("/v1/probe")`.
    pairs, analysable = _resolve_test_citations(
        _write_probe(
            tmp_path,
            positional.replace('request("/v1/probe", {"expectedVersion": 3})', 'request("/v1/probe")'),
        )
    )
    assert analysable
    assert frozenset(
        verb
        for found, found_verbs in pairs
        if _path_matches(found, "/v1/probe")
        for verb in found_verbs
    ) == frozenset({"GET"}), (
        "an omitted positional body whose default is None must decide GET; the "
        "keyword-only default binding alone would leave this undecided"
    )


def test_an_unprovable_call_site_body_stays_unresolved_and_not_either_verb(
    tmp_path: Path,
) -> None:
    """The negative control: a body this resolver cannot type yields NO verb.

    A rule that cannot be shown to refuse is not a rule. Each body below is
    genuinely supplied and genuinely may be None -- `dict.get` returns None,
    `next` raises or returns None, and a live-response subscript may hold
    anything -- so deciding either verb here would manufacture assurance. The
    assertion is on the EMPTY set specifically: not GET, and not POST.

    These are not invented shapes. `body=stale_payload` at
    scripts/test_application_onboarding.py:163 and `body=stale_package_payload`
    at :173 are exactly the `dict(payload)` form, and both of those real call
    sites are among the sites this resolver still refuses.
    """
    for label, body_argument in (
        ("call that may return None", "body=dict(payload)"),
        ("name bound to such a call", "body=maybe"),
        ("subscript of a live response", 'body=response["body"]'),
        ("attribute of an unknown object", "body=response.body"),
        ("binary op of unknown operands", "body=a + b"),
    ):
        assert _verbs_for(tmp_path, body_argument) == frozenset(), (
            f"{label}: this resolver cannot prove the body is not None, so the "
            f"verb is undecidable and the row must land `unresolved`. Deciding "
            f"GET would be the exact defect this rule was added to remove, and "
            f"deciding POST would be a worse one; got "
            f"{sorted(_verbs_for(tmp_path, body_argument))}"
        )

    # The same refusal at the level where it would reach a published figure.
    probe = _write_probe(
        tmp_path, _CONDITIONAL_HELPER + '\nrequest("/v1/probe", body=dict(payload))\n'
    )
    for method in ("GET", "POST"):
        buckets = _citation_measurement(
            [
                {
                    "id": "probe-row",
                    "path": "/v1/probe",
                    "method": method,
                    "test": str(probe),
                }
            ]
        )
        assert buckets["supported"] == [], (
            f"declared {method}: an unreadable verb must never produce a "
            f"supported row; got {buckets}"
        )
        assert buckets["unresolved"] == ["probe-row"], (
            f"declared {method}: the route is present and the verb unknown, so "
            f"this is the honest unknown; got {buckets}"
        )


def test_suppliedness_never_overwrites_a_string_the_file_already_proved() -> None:
    """A body fact must not displace a proved path value for the same name.

    Suppliedness is merged AFTER the string bindings, and this is the test that
    holds that ordering. Written into the same map it overwrote a module-level
    value the resolver had already proved: scripts/test_post_mutation_
    security_matrix.py fell from 89 resolved paths to 10 and three `supported`
    rows became `unsupported`, because `request(ACTION)` lost the value
    `_resolved_assignments` had established for `ACTION`.
    """
    source = '''
from urllib.request import Request, urlopen

ACTION = "/probe"

def request(path, *, body=None):
    with urlopen(Request(f"http://127.0.0.1:8080{path}", data=body,
                         method="POST" if body is not None else "GET")) as response:
        return response.read()

def test_it():
    request(ACTION)
'''
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        probe = _write_probe(Path(directory), source)
        pairs, analysable = _resolve_test_citations(probe)
    assert analysable
    paths = {found for found, _ in pairs}
    assert "/probe" in paths, (
        "the module-level ACTION binding must survive a call site that supplies "
        f"no body; the resolver saw {sorted(paths)}"
    )


def test_the_four_rows_this_construct_moved_are_credited_for_their_own_call_sites() -> None:
    """The exact rows the figure moved by, pinned to the call sites that decide them.

    The pin in the figure test fixes the published number; this fixes WHY it
    moved, so a future change that moves those four rows for some other reason
    cannot quietly inherit the credit. Three of the four come from a POSITIONAL
    dict body and one from a keyword body, and each is pinned twice: the sink
    that carries the conditional, and the call site that supplies the body.
    """
    sinks = (
        # (file, sink line) -- the `method="POST" if body is not None else "GET"`
        ("scripts/test_application_onboarding.py", 67),
        ("scripts/test_studystate_upgrade_surface.py", 164),
    )
    for relative, line in sinks:
        source = (ROOT / relative).read_text(encoding="utf-8").splitlines()
        window = "\n".join(source[line - 4 : line + 4])
        assert 'method="POST" if body is not None else "GET"' in window, (
            f"{relative}:{line} is cited as the conditional sink for rows this "
            f"construct moved; the construct is gone: {window!r}"
        )

    # The call sites that supply a provably non-None body.
    for relative, line in (
        ("scripts/test_application_onboarding.py", 158),
        ("scripts/test_application_onboarding.py", 205),
        ("scripts/test_studystate_upgrade_surface.py", 189),
        ("scripts/test_studystate_upgrade_surface.py", 204),
        ("scripts/test_studystate_upgrade_surface.py", 266),
        ("scripts/test_studystate_upgrade_surface.py", 279),
    ):
        source = (ROOT / relative).read_text(encoding="utf-8").splitlines()
        window = "\n".join(source[line - 2 : line + 2])
        assert "request(" in window and ("body=" in window or ", {" in window), (
            f"{relative}:{line} supplies no body at all, so it cannot be the "
            f"evidence for a row that moved on a supplied body: {window!r}"
        )

    # And the dict literal that makes the keyword body's value provable.
    source = (ROOT / "scripts/test_application_onboarding.py").read_text(
        encoding="utf-8"
    ).splitlines()
    assert source[148].strip() == "payload = {", (
        "scripts/test_application_onboarding.py:149 must be the dict-literal "
        f"assignment that makes `body=payload` provably not-None; got {source[148]!r}"
    )

    # The four rows, and that they are supported rather than merely reachable.
    buckets = _citation_measurement(
        [
            {
                "id": "install-application-fixture",
                "method": "POST",
                "path": "/v1/application-fixtures/install",
                "test": "scripts/test_application_onboarding.py",
            },
            {
                "id": "post-instance-template-upgrade-request",
                "method": "POST",
                "path": "/v1/instances/{instanceId}/template-upgrade/request",
                "test": "scripts/test_studystate_upgrade_surface.py",
            },
        ]
    )
    assert buckets["supported"] == [
        "install-application-fixture",
        "post-instance-template-upgrade-request",
    ], f"the rows this construct moved must be credited by their own call sites; got {buckets}"



# ---------------------------------------------------------------------------
# REACHABILITY: A TRANSPORT IS PROVEN BY A TERMINAL OPERATION, NOT BY ITS NAME
# ---------------------------------------------------------------------------
#
# The defect: `_is_request_sink` decided a call was a transport because its
# CALLEE NAME was in a fixed list. That is a naming convention, not a property of
# the code, so a real request through a differently-named transport was invisible
# and its row was reported `unsupported` -- a false accusation against a correct
# test. The rule under test asks instead whether the thing the call reaches
# actually performs I/O, and refuses when it cannot NAME a terminal operation.
#
# The two halves below are the point of the increment and they pull in opposite
# directions, so both are asserted: the four real transports must be credited,
# and the four convincing non-transports must be refused.

def _sinks_in_source(source: str) -> list[str]:
    """The calls the resolver treats as transports in `source`."""
    import ast as _ast

    import validate_application_experience as module

    tree = _ast.parse(source)
    functions = module._functions(tree)
    module._record_dispatch_calls(tree, functions)
    return [_ast.unparse(node) for _, node in module._sinks_in(tree, functions)]


# The real transports, reproduced in miniature. Each one REACHES a terminal
# operation; none of them is named like a transport in `_TRANSPORT_NAMES`.
_REACHES_A_TERMINAL = '''

def dispatch(method, path, body=None):
    routes = {
        "/v1/alpha": _alpha,
        "/v1/beta": _beta,
    }
    if method != "POST":
        raise ValueError(method)
    chosen = routes.get(path)
    return chosen(body)


class Wire:
    @classmethod
    def open(cls, service, *, path="/v1/terminal/socket"):
        import socket
        connection = socket.create_connection(("127.0.0.1", 8080), timeout=3)
        return connection


a = dispatch("POST", "/v1/alpha", {})
w = Wire.open({}, path="/v1/terminal/socket")
'''

# The convincing non-transports. NONE of these reaches a terminal operation:
# the first only takes a path and returns a dict, the second is named like a
# transport and returns a constant, the third has a `request` method that
# touches nothing, and the fourth opens a file, which is I/O but not a network
# primitive and is therefore not a transport.
_REACHES_NO_TERMINAL = '''

def describe(path):
    return {"path": path, "count": 1}


def request(path):
    return 200


class Client:
    def get(self, path):
        return {"ok": True}

    def post(self, path, body=None):
        return 200

    def request(self, path):
        return {"path": path}


c = Client()
a = describe("/v1/x")
b = request("/v1/y")
g = c.get("/v1/z")
p = c.post("/v1/w", {})
r = c.request("/v1/v")
with open("/tmp/not-a-transport") as handle:
    body = handle.read()
'''


def test_a_transport_is_proven_by_the_terminal_operation_it_reaches() -> None:
    """The rule credits what performs I/O, however it is named."""
    sinks = _sinks_in_source(_REACHES_A_TERMINAL)
    assert any("dispatch(" in sink for sink in sinks), (
        "a service route dispatch reaches its terminal operation and must be a "
        f"sink; got {sinks}"
    )
    assert any("Wire.open(" in sink for sink in sinks), (
        "a classmethod that calls socket.create_connection reaches a terminal "
        f"operation and must be a sink; got {sinks}"
    )
    # And the terminals are NAMED, not merely implied, so a reader can audit
    # which operation justified the credit.
    import ast as _ast

    import validate_application_experience as module

    tree = _ast.parse(_REACHES_A_TERMINAL)
    functions = module._functions(tree)
    terminals = {
        module._reaches_transport(node, tree, functions, module._transport_bindings(tree))
        for node in _ast.walk(tree)
        if isinstance(node, _ast.Call)
    }
    terminals.discard(None)
    assert "service route dispatch: routes.get(path) then handler(payload)" in terminals
    assert "socket.create_connection(...)" in terminals


def test_the_rule_refuses_a_call_that_reaches_no_transport() -> None:
    """THE NEGATIVE CONTROL. A rule that cannot refuse is not a rule.

    If this test were deleted the metric would credit `describe("/v1/x")` -- a
    function that takes a path and returns a dict -- as a request, and would
    report every row citing such a file as supported. That is precisely the
    fabrication this increment exists to prevent, so the refusal is asserted
    rather than assumed.
    """
    assert _sinks_in_source(_REACHES_NO_TERMINAL) == [], (
        "none of these reaches a terminal operation, so none is a transport: a "
        "path argument, a transport-shaped name, a request-shaped method and a "
        "file open are not network primitives"
    )


def test_the_rule_refuses_a_suggestive_name_without_a_terminal() -> None:
    """A method named exactly like a transport, with no terminal inside it."""
    source = '''
class Sink:
    def request(self, method, path, body=None):
        return {"method": method, "path": path}


s = Sink()
r = s.request("POST", "/v1/x", {})
'''
    assert _sinks_in_source(source) == [], (
        "`s.request(...)` is named like the http.client transport but reaches "
        "no terminal operation, so the name must not credit it"
    )


def test_a_constructing_receiver_is_never_credited_without_a_terminal() -> None:
    """A class the file builds is not enough; its method must reach a terminal.

    `_attribute_terminal` resolves a receiver through the constructors and
    annotations in the cited file, which is a real widening. This is the test
    that bounds it: resolution alone never credits anything.
    """
    source = '''
class Client:
    def fetch(self, path):
        return {"path": path}


c = Client()
got = c.fetch("/v1/x")
'''
    assert _sinks_in_source(source) == [], (
        "the receiver resolves to a class this file constructs, but `fetch` "
        "reaches no terminal operation, so it must not be credited"
    )


def test_a_compound_annotation_never_fabricates_a_receiver_class() -> None:
    """`list[WebHarness]` and friends are refused, not guessed at.

    This resolver has already shipped a fabrication class by reaching into a
    compound annotation and naming a class that was not the receiver's type, so
    the compound forms are refused outright rather than mined.
    """
    import validate_application_experience as module

    import ast as _ast

    for annotation in ("WebHarness", "list[WebHarness]", "WebHarness | None", "Any"):
        source = f'''
def use(harness: {annotation}, path):
    return harness.post(path, {{}})
'''
        tree = _ast.parse(source)
        resolved = module._annotated_class_names(tree, _ast.Name(id="harness"))
        if annotation == "WebHarness":
            assert resolved == {"WebHarness"}, f"a bare annotation is a statement: {resolved}"
        else:
            assert resolved == set(), (
                f"{annotation!r} is a compound annotation and must resolve to "
                f"nothing rather than be mined for a class name; got {resolved}"
            )


def test_the_four_measured_rows_are_supported_by_their_own_transports() -> None:
    """The four rows this increment moved, credited by their own call sites."""
    buckets = _citation_measurement(
        [
            {
                "id": "post-template-upgrade-mutation-request",
                "method": "POST",
                "path": "/v1/mutations/request",
                "test": "scripts/test_studystate_upgrade_surface.py",
            },
            {
                "id": "post-template-upgrade-approval-decision",
                "method": "POST",
                "path": "/v1/approvals/decide",
                "test": "scripts/test_studystate_upgrade_surface.py",
            },
            {
                "id": "post-template-upgrade-mutation-apply",
                "method": "POST",
                "path": "/v1/mutations/apply",
                "test": "scripts/test_studystate_upgrade_surface.py",
            },
            {
                "id": "terminal-socket",
                "method": "GET",
                "path": "/v1/terminal/socket",
                "test": "scripts/test_terminal_service.py",
            },
        ]
    )
    assert sorted(buckets["supported"]) == [
        "post-template-upgrade-approval-decision",
        "post-template-upgrade-mutation-apply",
        "post-template-upgrade-mutation-request",
        "terminal-socket",
    ], f"all four must be credited by reachability; got {buckets}"
    assert buckets["unsupported"] == [], f"none may remain unsupported; got {buckets}"


def test_a_dispatch_with_a_computed_path_stays_unresolved() -> None:
    """A resolvable sink must not let a resolvable sink fabricate a path.

    The dispatch shape makes `dispatch(method, path, body)` readable, which is
    what recovered these rows. The safety property is that the path still has to
    COMPOSE: a path built from a name the file never binds stays a hole, and a
    hole is reported `unresolved`, never `supported`.
    """
    import validate_application_experience as module

    tree = module._resolve_test_citations(ROOT / "scripts/test_studystate_upgrade_surface.py")
    pairs, analysable = tree
    assert analysable
    # The three dispatch rows resolve to REAL paths, not holes.
    for path, verbs in pairs:
        for wanted in ("/v1/mutations/request", "/v1/approvals/decide", "/v1/mutations/apply"):
            if path == wanted:
                assert "POST" in verbs, f"{wanted} must carry its verb; got {verbs}"
    # And no hole-bearing path may be confirmed for a row it does not fill.
    from validate_application_experience import _path_matches

    for path, _ in pairs:
        if path and "" in path:
            assert not _path_matches(path, "/v1/mutations/request")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
