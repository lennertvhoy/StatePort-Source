#!/usr/bin/env python3
"""Static contract checks for the honest local-alpha dashboard surface."""

from __future__ import annotations

from pathlib import Path
import re



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
        assert target in {"", "conversation", "runs", "receipts", "settings"}, target
        if target:
            assert target in routes, target
    # Legacy hashes normalize onto real routes before the router renders.
    assert "home: '/applications'" in legacy and "catalog: '/catalog'" in legacy
    assert "approvals: '/approvals'" in legacy and "settings: '/settings'" in legacy
    assert "platform: '/applications'" in legacy


def test_unavailable_navigation_is_noninteractive_and_explicit() -> None:
    approvals = _read("features/approvals/ApprovalListPane.tsx")
    composer = _read("features/conversation/Composer.tsx")
    catalog = _read("features/catalog/CatalogPage.tsx")
    catalog_model = _read("features/catalog/catalogModel.ts")
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
    # An entry that can never be installed here is not listed at all; one that
    # is already installed but not installable stays disabled with the reason.
    assert "listableCatalog(" in catalog and "entry.installAvailable !== false" in catalog_model
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
    # The entry label was deliberately consolidated at ce693db6 ("Expose public and
    # local repository import through consistent entry labels"); the visible
    # affordance is "Import a repository", used by both the dropdown item and the
    # empty-state action. This assertion keeps its teeth: it is a substring check
    # against the rendered source, so removing or renaming the affordance fails it.
    assert "Import a repository" in catalog
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
    app_shell = _read("shell/AppShell.tsx")
    client_index = _read("client/index.ts")
    main = _read("main.tsx")
    readme = (WEB / "README.md").read_text(encoding="utf-8")
    # The Scenario Lab and mock adapter are development-only and build-time
    # selected; production builds default to the HTTP adapter and cannot
    # silently fall back to mock data. The client boundary does not import the
    # mock at all: it is loaded through a dynamic import that a production
    # build folds away, and the Scenario Lab is loaded the same way.
    assert "import.meta.env.DEV" in scenario
    assert "import.meta.env.DEV ? lazy(() => import('./DevTools')) : null" in app_shell
    assert "VITE_STATEPORT_ADAPTER" in client_index
    assert "import.meta.env.DEV ? 'mock' : 'http'" in client_index
    assert "/mock/" not in client_index.replace("export type { ScenarioId } from './mock/scenarios'", "")
    assert "await import('./dev/installMock')" in main
    assert "never falls back to mock data" in readme
    # Runtime and policy truth stays in the platform configuration.
    policy = (ROOT / "config" / "application-experience-policy.yaml").read_text(encoding="utf-8")
    assert "  terminal:\n    status: available" in policy
    assert "application.terminal.use" in policy
    assert "conversation:\n    status: available" in policy
    # Surfaces that cannot work on the installed product are not routed (ADR-0007
    # section 5): the platform hub, the read-only execution host, and the
    # operator-only pages are what remains of the platform area.
    app = _read("App.tsx")
    for removed in ("sources", "statebench", "deployments", "preview-routes", "workbench"):
        assert f'path="{removed}' not in app, removed
    for kept in ("platform", "execution-host", "authority", "updater"):
        assert f'path="{kept}"' in app, kept
    execution_host = _read("features/execution-host/ExecutionHostPage.tsx")
    for mutation in ("startWorkload", "stopWorkload", "cancelWorkload", "removeWorkload", "createDefaultWorkload"):
        assert mutation not in execution_host, mutation
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
