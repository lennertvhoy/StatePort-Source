#!/usr/bin/env python3
"""Static acceptance checks for the native GUI vertical slice."""

from pathlib import Path
import hashlib
import re

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "apps" / "web"
SRC = WEB / "src"


def _read(relative: str) -> str:
    return (SRC / relative).read_text(encoding="utf-8")


def test_web_surface_has_application_first_navigation_and_api_boundary() -> None:
    app = _read("App.tsx")
    sidebar = _read("shell/Sidebar.tsx")
    context_shell = _read("shell/AppContextShell.tsx")
    view_registry = _read("features/application-experience/registry.ts")
    view_guard = _read("features/application-experience/ApplicationViewGuard.tsx")
    legacy = _read("legacyRoutes.ts")
    endpoints = _read("client/http/endpoints.ts")
    transport = _read("client/http/transport.ts")
    domains = _read("client/http/domainsCore.ts")
    conversation = _read("client/http/domainsConversation.ts")
    home = _read("features/applications/ApplicationsPage.tsx")
    workbench_shell = _read("shell/WorkbenchShell.tsx")
    tokens = _read("styles/tokens.css")
    # Application-first navigation: Applications, Catalog, Approvals, Settings.
    assert '<Navigate to="/applications" replace' in app
    assert "label: 'Applications'" in sidebar and "label: 'Catalog'" in sidebar
    assert "label: 'Approvals'" in sidebar and "label: 'Settings'" in sidebar
    assert "Needs attention" in home and 'title="No applications yet"' in home
    assert "/v1/status" in endpoints and "/v1/instances" in endpoints and "/v1/application-experiences" in endpoints
    assert "/conversation" in endpoints and "/conversation/messages" in endpoints
    # Legacy hashes normalize app-first; there is no platform surface route.
    assert "home: '/applications'" in legacy and "platform: '/applications'" in legacy
    assert "path.startsWith('app/')" in legacy
    assert "credentials: 'same-origin'" in transport
    assert "localStorage" not in transport and "sessionStorage" not in transport
    # Activity, attention, and receipts remain application-scoped surfaces.
    assert "/activity" in endpoints and "/receipts" in endpoints
    assert "acknowledge" in endpoints and "acknowledgeAttention" in home
    assert 'path="receipts/:receiptId"' in app
    # Conversation export and clear stay explicit, receipted operations.
    assert "/conversation/export" in endpoints and "/conversation/clear" in endpoints
    assert "confirmation: 'CLEAR_CONVERSATION'" in conversation
    # Settings rollback stays scoped: global and application settings each
    # keep their own rollback endpoint.
    assert "endpoints.settingsRollback" in domains and "appSettingsRollback" in endpoints
    # Capability-gated surfaces disappear rather than render dead controls.
    assert "toolAvailable" in workbench_shell and "This application does not include" in workbench_shell
    assert "applicationNavigation(instance)" in context_shell
    assert "capabilityUsable(instance, capability)" in view_registry
    assert "registeredView(view, contribution.placement)" in view_registry
    assert "applicationDestinationAvailable(instance, destination)" in view_guard
    assert "import(" not in view_registry
    # Accessibility tokens: reduced motion and coarse-pointer targets.
    assert '[data-motion="reduced"]' in tokens and "@media (pointer: coarse)" in tokens


def test_web_surface_uses_the_canonical_mascot_assets_same_origin() -> None:
    """The shipped shell uses the reviewed light/compact marks."""
    document = (WEB / "index.html").read_text(encoding="utf-8")
    vite = (WEB / "vite.config.ts").read_text(encoding="utf-8")
    brand = _read("components/Brand.tsx")
    assets = {
        "stateport-mascot-light-block-arch.svg": "32af9b36db5a7dafba0b85f3598806dc13b2d9a31e3fab5415ff65dd80462240",
        "stateport-mascot-dark-block-arch.svg": "62d1a8ee6a68aa025e7246f689cd4ed7e885d7f3d97fb78fe84c0d5f75cdf013",
        "stateport-favicon-block-arch.svg": "352fc98ed519f876d982049f33bc3441a86df8954f0547ec1558355c4c417b93",
    }
    for filename, expected in assets.items():
        path = WEB / "assets" / "brand" / filename
        assert path.is_file()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected
        lowered = path.read_text(encoding="utf-8").lower()
        # SVGs are static local artwork, never executable or remotely linked.
        assert re.search(r"<script\b", lowered) is None
        assert re.search(r"\bon[a-z][\w:-]*\s*=", lowered) is None
        assert "<foreignobject" not in lowered
        assert re.search(r"(?:href|xlink:href|src)\s*=\s*['\"](?:https?:|//|data:)", lowered) is None
        assert "url(" not in lowered

    assert 'viewBox="24 21 464 464"' in (WEB / "assets/brand/stateport-favicon-block-arch.svg").read_text()

    assert "../../assets/brand/stateport-mascot-light-block-arch.svg" in brand
    assert "../../assets/brand/stateport-mascot-dark-block-arch.svg" not in brand
    assert "../../assets/brand/stateport-favicon-block-arch.svg" in brand
    assert "data-brand-asset=\"dark\"" not in brand
    assert "stateport-mascot.svg" not in brand
    assert "stateport-mascot-v2" not in brand
    assert "export type BrandMarkSize = 16 | 20 | 24 | 32 | 40" in brand
    assert "<BrandMark size={40} />" in brand
    sidebar = _read("shell/Sidebar.tsx")
    assert '<BrandMark size={24} />' in sidebar
    assert "min-h-10 min-w-10 items-center justify-center" in sidebar
    assert 'href="/assets/brand/stateport-favicon-block-arch.svg"' in document
    assert "assetsInlineLimit: 0" in vite
    assert "closeBundle()" not in vite
    assert "http://" not in brand and "https://" not in brand and "data:image" not in brand

    import json

    manifest = json.loads((ROOT / "brand" / "source-manifest.json").read_text(encoding="utf-8"))
    canonical = {asset["path"]: asset for asset in manifest["canonicalAssets"]}
    provenance = {asset["path"]: asset for asset in manifest["provenanceAssets"]}
    assert canonical["apps/web/assets/brand/stateport-favicon-block-arch.svg"]["size"]["compact"] == [16, 20, 24, 32]
    assert canonical["apps/web/assets/brand/stateport-favicon-block-arch.svg"]["size"]["visualScale"] == 1.25
    assert canonical["apps/web/assets/brand/stateport-mascot-light-block-arch.svg"]["size"]["expandedLockup"] == 40
    assert canonical["apps/web/assets/brand/stateport-mascot-light-block-arch.svg"]["size"]["visualScale"] == 1.25
    assert provenance["apps/web/assets/brand/stateport-mascot-dark-block-arch.svg"]["disposition"] == "untouched_provenance_not_active_ui"


def test_web_surface_keeps_mascot_component_selectors_out_of_tokens() -> None:
    index_css = (SRC / "index.css").read_text(encoding="utf-8")
    tokens = _read("styles/tokens.css")
    brand = _read("components/Brand.tsx")
    assert ".brand-mascot-light" in index_css
    assert ".brand-mascot-dark" not in index_css
    assert "[data-theme='dark'] .brand-mascot-light" not in index_css
    assert ".brand-mascot-light" not in tokens and ".brand-mascot-dark" not in tokens
    assert "--brand-art-scale: 1.25" in tokens
    assert "brand-art-frame" in brand
    assert "overflow-hidden" not in brand
    assert ".brand-mark {\n    position: relative;" in index_css
    assert "width: calc(100% / var(--brand-art-scale));" in index_css
    assert "height: calc(100% / var(--brand-art-scale));" in index_css
    assert "transform: scale(var(--brand-art-scale))" in index_css


def test_private_mascot_derivative_remains_preserved_but_unwired() -> None:
    """Private supplied assets stay recoverable without entering the product."""
    import json
    import re

    brand = _read("components/Brand.tsx")
    master = WEB / "assets" / "brand" / "stateport-mascot.svg"
    derivative = WEB / "assets" / "brand" / "stateport-mascot-shell.svg"
    manifest = WEB / "assets" / "brand" / "shell-mark-asset-manifest.json"
    expected_master = "d0768716bed8391220cb4a87e52e00705bac92fed4fa16b870682ab5c392c803"
    expected_derivative = "85459d506c5e15f405a44b6604fecd1cdc64ff4fd6a2d42ddb68199fdfca2cf6"
    assert derivative.is_file() and manifest.is_file()
    # The master remains the byte-identical provenance source.
    assert hashlib.sha256(master.read_bytes()).hexdigest() == expected_master
    assert hashlib.sha256(derivative.read_bytes()).hexdigest() == expected_derivative
    record = json.loads(manifest.read_text(encoding="utf-8"))
    assert record["mascotSource"]["sha256"] == expected_master
    assert record["mascotSource"]["modified"] is False
    assert record["shellMark"]["sha256"] == expected_derivative
    assert record["shellMark"]["geometryPreserved"] is True
    master_text = master.read_text(encoding="utf-8")
    derivative_text = derivative.read_text(encoding="utf-8")
    # Identical vector geometry: every path and circle is preserved exactly.
    geometry = lambda text: sorted(re.findall(r'd="[^"]+"', text)) + sorted(re.findall(r"<circle[^/]*/>", text))
    assert geometry(master_text) == geometry(derivative_text)
    # The derivative tightens the canvas to the geometry bounds with a small
    # margin, so the visible mark occupies materially more of the viewBox.
    assert 'viewBox="0 0 1254 1254"' in master_text
    assert 'viewBox="207.5 180 845 845"' in derivative_text
    # The accepted bright-blue revision: identical v1 geometry, new fill only.
    assert "#2F7DFF" in derivative_text
    assert "#054CC6" not in derivative_text
    # Neither supplied asset is wired into the public-safe shell.
    assert "stateport-mascot-shell.svg" not in brand
    assert "stateport-mascot.svg" not in brand
    lowered = derivative_text.lower()
    assert "<script" not in lowered and "foreignobject" not in lowered


def test_web_surface_mascot_v2_remains_a_recorded_rejected_proposal() -> None:
    """The v2 family was proposed, adopted, then rejected by the owner on
    2026-07-19 in favour of the v1 geometry. It must stay recorded but
    unwired."""
    import json

    brand = _read("components/Brand.tsx")
    manifest = WEB / "assets" / "brand" / "mascot-v2-asset-manifest.json"
    master_v2 = WEB / "assets" / "brand" / "stateport-mascot-v2.svg"
    favicon_v2 = WEB / "assets" / "brand" / "stateport-mascot-v2-favicon.svg"
    assert manifest.is_file() and master_v2.is_file() and favicon_v2.is_file()
    record = json.loads(manifest.read_text(encoding="utf-8"))
    assert record["status"] == "rejected_superseded"
    assert hashlib.sha256(master_v2.read_bytes()).hexdigest() == record["v2Master"]["sha256"]
    assert hashlib.sha256(favicon_v2.read_bytes()).hexdigest() == record["v2Favicon"]["sha256"]
    # The private v1 and rejected v2 records remain untouched and unwired.
    assert record["v1Master"]["modified"] is False
    assert (WEB / "assets" / "brand" / "stateport-mascot.svg").is_file()
    assert "stateport-mascot-v2" not in brand
    assert "stateport-mascot.svg" not in brand
    for path in (master_v2, favicon_v2):
        lowered = path.read_text(encoding="utf-8").lower()
        assert "<script" not in lowered and "foreignobject" not in lowered


def test_web_surface_is_not_a_live_bot_or_fake_mutation_surface() -> None:
    readme = (WEB / "README.md").read_text(encoding="utf-8")
    transport = _read("client/http/transport.ts")
    dialog = _read("features/files/SavePreviewDialog.tsx")
    conversation = _read("client/http/domainsConversation.ts")
    surface = _read("features/conversation/ConversationSurface.tsx")
    client_index = _read("client/index.ts")
    lowered = readme.lower()
    # The adapter contract is honest: no silent mock fallback, no fabricated
    # data, and live-backend expectations are stated, not implied.
    assert "never falls back to mock data" in lowered
    assert "honest error" in lowered
    assert "mock adapter" in lowered and "vite_stateport_adapter" in lowered
    # Mutations are never faked locally: writes pass a governed confirmation
    # flow and conversation clear requires the explicit confirmation token.
    assert "NEVER falls back to mock data" in transport
    assert 'data-testid="confirm-save"' in dialog
    assert "confirmation: 'CLEAR_CONVERSATION'" in conversation
    assert "Clear conversation history" in surface and "This cannot be undone." in surface
    # The mock adapter is a build-time selection, never a runtime fallback.
    assert "VITE_STATEPORT_ADAPTER" in client_index
    assert "import.meta.env.DEV ? 'mock' : 'http'" in client_index


def test_web_surface_reconciles_stale_data_and_rejects_malformed_payloads() -> None:
    catalog = _read("features/catalog/CatalogPage.tsx")
    mappers = _read("client/http/mappers.ts")
    transport = _read("client/http/transport.ts")
    palette = _read("shell/CommandPalette.tsx")
    receipt = _read("features/receipts/ReceiptDetail.tsx")
    # Stale-while-revalidate honesty: the last verified copy stays visible
    # with an explicit stale marker instead of a fabricated refresh.
    assert "staleCache" in catalog
    assert "The catalog could not be refreshed — showing the last loaded copy." in catalog
    # Wire payloads are validated fail-closed against known format versions.
    assert "function failClosed(" in mappers
    assert "FORMAT.applicationExperienceResolution" in mappers
    assert "FORMAT.activityReceiptsProjection" in mappers
    assert "ClientError" in transport
    # Overlay surfaces close predictably with Escape.
    assert "Escape closes with focus restored" in palette
    assert "Escape/back both work" in receipt


def test_ui_foundation_is_bound_to_build_identity_and_first_class_routes() -> None:
    app = _read("App.tsx")
    main = _read("main.tsx")
    build_env = _read("build-env.d.ts")
    vite = (WEB / "vite.config.ts").read_text(encoding="utf-8")
    screenshots = (WEB / "tests" / "e2e" / "screenshots.spec.ts").read_text(encoding="utf-8")
    # Approvals is a first-class destination and never aliases Settings.
    assert 'path="approvals"' in app and 'path="approvals/:approvalId"' in app
    assert 'path="settings"' in app
    # Every served bundle is bound to its build identity, and the screenshot
    # matrix captures route × viewport × theme explicitly.
    assert "__BUILD_SHA__" in vite and "rootElement.dataset.buildSha = __BUILD_SHA__" in main
    assert "declare const __BUILD_SHA__: string" in build_env
    assert "viewport" in screenshots and "theme" in screenshots
    assert "for (const theme of ['light', 'dark'] as const)" in screenshots


def test_service_static_boundary_uses_only_the_reviewed_vite_manifest() -> None:
    service = (ROOT / "packages" / "persistent-app" / "src" / "stateport_persistent_app" / "service_process.py").read_text(encoding="utf-8")
    # Source fallback remains available to disposable test fixtures. The real
    # product dist must carry the exact production/HTTP build marker, and only
    # manifest-listed bounded assets are served from an accepted build.
    assert "selected_web_root = _select_web_root(" in service
    assert "expected_source_commit=expected_source_commit" in service
    assert "expected_source_tree=expected_source_tree" in service
    assert '_WEB_BUILD_IDENTITY_FILE = "stateport-build.json"' in service
    assert 'identity.get("formatVersion") != "stateport.web-build/v3"' in service
    assert 'identity.get("adapter") != "http"' in service
    assert 'identity.get("mode") != "production"' in service
    assert "_require_production_web_build_identity(built_web_root)" in service
    assert "_bounded_static" in service
    assert 'manifest_path = web_root / ".vite" / "manifest.json"' in service
    assert "if vite_asset in self.server.vite_asset_paths" in service
    assert "script-src 'self'" in service
    assert "worker-src 'self' blob:" in service


if __name__ == "__main__":
    test_web_surface_has_application_first_navigation_and_api_boundary()
    test_web_surface_uses_the_canonical_mascot_assets_same_origin()
    test_web_surface_keeps_mascot_component_selectors_out_of_tokens()
    test_private_mascot_derivative_remains_preserved_but_unwired()
    test_web_surface_mascot_v2_remains_a_recorded_rejected_proposal()
    test_web_surface_is_not_a_live_bot_or_fake_mutation_surface()
    test_web_surface_reconciles_stale_data_and_rejects_malformed_payloads()
    test_ui_foundation_is_bound_to_build_identity_and_first_class_routes()
    test_service_static_boundary_uses_only_the_reviewed_vite_manifest()
    print("PASS")
