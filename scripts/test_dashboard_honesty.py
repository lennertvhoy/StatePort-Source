#!/usr/bin/env python3
"""Static contract checks for the honest local-alpha dashboard surface."""

from __future__ import annotations

from pathlib import Path
import re

import yaml


ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "apps" / "web"
SRC = WEB / "src"


def _read(relative: str) -> str:
    return (SRC / relative).read_text(encoding="utf-8")


def test_every_enabled_navigation_item_has_a_real_local_route() -> None:
    app = _read("App.tsx")
    sidebar = _read("shell/Sidebar.tsx")
    context_shell = _read("shell/AppContextShell.tsx")
    view_registry = _read("features/application-experience/registry.ts")
    legacy = _read("legacyRoutes.ts")
    routes = set(re.findall(r'path="([^"]+)"', app))
    # Every sidebar destination is a real router route, and Approvals is a
    # first-class destination that never aliases Settings.
    for target in re.findall(r"to: '(/[a-z]+)'", sidebar):
        assert target.lstrip("/") in routes, target
    assert "approvals" in routes and "settings" in routes
    # Every registered app-scoped destination resolves under the static
    # application router. Descriptor routes are evidence only and never enter
    # the router directly.
    assert "applicationNavigation(instance)" in context_shell
    assert "the frontend never navigates to it directly" in _read("client/types.ts")
    for target in re.findall(r"\n\s+to: '([a-z]*)',", view_registry):
        assert target in {"", "conversation", "runs", "workbench", "receipts", "settings"}, target
        if target:
            assert target in routes, target
    # Legacy hashes normalize onto real routes before the router renders.
    assert "home: '/applications'" in legacy and "catalog: '/catalog'" in legacy
    assert "approvals: '/approvals'" in legacy and "settings: '/settings'" in legacy
    assert "platform: '/applications'" in legacy


def test_unavailable_navigation_is_noninteractive_and_explicit() -> None:
    approvals = _read("features/approvals/ApprovalListPane.tsx")
    composer = _read("features/conversation/Composer.tsx")
    workbench_shell = _read("shell/WorkbenchShell.tsx")
    catalog = _read("features/catalog/CatalogPage.tsx")
    context_shell = _read("shell/AppContextShell.tsx")
    view_registry = _read("features/application-experience/registry.ts")
    view_guard = _read("features/application-experience/ApplicationViewGuard.tsx")
    readme = (WEB / "README.md").read_text(encoding="utf-8")
    assert "No pending approvals" in approvals
    # The composer stays disabled until there is something to send.
    assert "const canSend = text.trim().length > 0 || uploads.hasReady" in composer
    assert "disabled={!canSend}" in composer
    # Capability-gated surfaces disappear from navigation and deep links
    # redirect with an explicit reason instead of rendering dead ends.
    assert "applicationNavigation(instance)" in context_shell
    assert "capabilityUsable(instance, capability)" in view_registry
    assert "registeredView(view, contribution.placement)" in view_registry
    assert "applicationDestinationAvailable(instance, destination)" in view_guard
    assert "This application does not include" in workbench_shell
    # Unavailable installs are disabled with the reason, never silently active.
    assert "entry.installAvailable === false ? 'Unavailable'" in catalog
    assert "installUnavailableReason" in catalog
    assert "never falls back to mock data" in readme


def test_visible_buttons_have_real_actions_or_disabled_semantics() -> None:
    overview = _read("features/app-overview/AppOverviewPage.tsx")
    domains = _read("client/http/domainsCore.ts")
    detail = _read("features/approvals/ApprovalDetailPane.tsx")
    execution = _read("client/http/domainsExecution.ts")
    catalog = _read("features/catalog/CatalogPage.tsx")
    # Backup, catalog refresh, and approval decisions are wired to real
    # control-plane endpoints.
    assert "runBackup" in overview and "getClient().recovery.runBackup(instance.id)" in overview
    assert "endpoints.backup(instanceId)" in domains
    assert "endpoints.catalogRefresh" in domains
    assert 'data-testid="approve-button"' in detail and 'data-testid="confirm-reject"' in detail
    assert "runApprove" in execution and "runProposalReject" in execution
    # The repository-import secondary path is honest about its availability.
    assert "Import a local repository" in catalog
    assert "reviewed installation stays the ordinary path." in catalog


def test_dashboard_uses_existing_control_plane_contract_and_structured_errors() -> None:
    endpoints = _read("client/http/endpoints.ts")
    transport = _read("client/http/transport.ts")
    for route in ("/session", "/v1/status", "/v1/instances", "/v1/application-experiences", "/v1/approvals"):
        assert route in endpoints, route
    # Structured client errors instead of silent failure or fabricated data.
    assert "ClientError" in transport
    assert "NEVER falls back to mock data" in transport
    assert "credentials: 'same-origin'" in transport
    assert "localStorage" not in transport and "sessionStorage" not in transport


def test_preview_only_surfaces_are_not_presented_as_completed_controls() -> None:
    scenario = _read("shell/ScenarioLab.tsx")
    client_index = _read("client/index.ts")
    readme = (WEB / "README.md").read_text(encoding="utf-8")
    # The Scenario Lab and mock adapter are development-only and build-time
    # selected; production builds default to the HTTP adapter and cannot
    # silently fall back to mock data.
    assert "import.meta.env.DEV" in scenario
    assert "VITE_STATEPORT_ADAPTER" in client_index
    assert "import.meta.env.DEV ? 'mock' : 'http'" in client_index
    assert "never falls back to mock data" in readme
    # Runtime and policy truth stays in the platform configuration.
    policy = (ROOT / "config" / "application-experience-policy.yaml").read_text(encoding="utf-8")
    assert "  terminal:\n    status: available" in policy
    assert "application.terminal.use" in policy
    assert "conversation:\n    status: available" in policy
    # Canonical source status has a real bounded route, while exact source
    # evidence remains actor-gated. Platform StateBench has a strict
    # operator-only consumer and remains evidence rather than a mock success.
    manifest = yaml.safe_load(
        (ROOT / "config" / "functionality-preservation.v1.yaml").read_text(encoding="utf-8")
    )
    platform = next(item for item in manifest["uiRoutes"] if item["id"] == "platform-route")
    statebench = next(item for item in manifest["capabilities"] if item["id"] == "statebench-evidence")
    assert platform["status"] == "foundation"
    assert statebench["status"] == "foundation"
    source_surface = _read("features/sources/SourceRegistryPage.tsx")
    assert "status.actor?.role === 'platform_operator'" in source_surface
    assert "if (!operator || !selectedPublicSource) return" in source_surface
    statebench_surface = _read("features/statebench/PlatformStateBenchPage.tsx")
    assert "canInspectPlatformStateBench(status)" in statebench_surface
    assert "client.platformStateBench.getMatrix(status)" in statebench_surface
    assert "authoritativePerformanceClaim: false" in statebench_surface
    gaps = (WEB / "docs" / "BACKEND_GAPS.md").read_text(encoding="utf-8")
    assert "operator-only StateBench consumer" in gaps


if __name__ == "__main__":
    for function in (
        test_every_enabled_navigation_item_has_a_real_local_route,
        test_unavailable_navigation_is_noninteractive_and_explicit,
        test_visible_buttons_have_real_actions_or_disabled_semantics,
        test_dashboard_uses_existing_control_plane_contract_and_structured_errors,
        test_preview_only_surfaces_are_not_presented_as_completed_controls,
    ):
        function()
    print("PASS")
