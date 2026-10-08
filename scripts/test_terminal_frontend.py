#!/usr/bin/env python3
"""Static and unit-level checks for the optional xterm Workbench surface."""

from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess

import yaml


ROOT = Path(__file__).resolve().parents[1]
_ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def _plain_output(value: str) -> str:
    return _ANSI_ESCAPE.sub("", value)

WEB = ROOT / "apps" / "web"
TERMINAL = WEB / "src" / "features" / "terminal"

LOCKED = {
    "@xterm/xterm": "6.0.0",
    "@xterm/addon-fit": "0.11.0",
    "@xterm/addon-search": "0.16.0",
    "@xterm/addon-web-links": "0.12.0",
}


def _terminal_sources() -> dict[str, str]:
    return {
        path.relative_to(TERMINAL).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(TERMINAL.rglob("*"))
        if path.suffix in {".ts", ".tsx"} and "__tests__" not in path.as_posix()
    }


def test_xterm_dependencies_are_stable_self_hosted_and_lockfile_pinned() -> None:
    package = json.loads((WEB / "package.json").read_text(encoding="utf-8"))
    lock = json.loads((WEB / "package-lock.json").read_text(encoding="utf-8"))
    dependencies = package["dependencies"]
    for name in LOCKED:
        assert name in dependencies, name
        locked = lock["packages"][f"node_modules/{name}"]
        assert locked["version"] == LOCKED[name], name
        assert locked["integrity"].startswith("sha512-"), name
        assert "beta" not in locked["version"] and "latest" not in locked["version"]
    assert "node_modules/@xterm/addon-web-fonts" not in lock["packages"]
    # The paste guard is implemented natively; the clipboard addon was removed
    # during dependency cleanup and must not silently return.
    assert "@xterm/addon-clipboard" not in dependencies
    assert "node_modules/@xterm/addon-clipboard" not in lock["packages"]
    assert not (WEB / ".npmrc").exists()


def test_terminal_tool_is_lazy_and_only_reachable_from_a_permitted_workbench() -> None:
    app = (WEB / "src" / "App.tsx").read_text(encoding="utf-8")
    workbench_shell = (WEB / "src" / "shell" / "WorkbenchShell.tsx").read_text(encoding="utf-8")
    integrations = (WEB / "src" / "features" / "workbench" / "WorkbenchIntegrations.tsx").read_text(encoding="utf-8")
    study = yaml.safe_load((ROOT / "fixtures" / "application-experiences" / "study-state.yaml").read_text(encoding="utf-8"))
    assert "lazy(() => import('@/features/terminal/TerminalTool'))" in app
    assert "import TerminalTool" not in app
    assert "capabilities: ['terminal']" in workbench_shell
    assert "toolAvailable" in workbench_shell and "This application does not include" in workbench_shell
    assert "hasCapability('terminal')" in integrations
    assert {"terminal", "workbench", "editor", "cto_orchestration"}.isdisjoint(study["capabilities"])


def test_terminal_surface_uses_safe_browser_apis_and_explicit_connect() -> None:
    tool = (TERMINAL / "TerminalTool.tsx").read_text(encoding="utf-8")
    view = (TERMINAL / "TerminalView.tsx").read_text(encoding="utf-8")
    runtime = (TERMINAL / "sessionRuntime.ts").read_text(encoding="utf-8")
    links = (TERMINAL / "terminalLinks.ts").read_text(encoding="utf-8")
    sources = _terminal_sources()
    # Explicit connect, never auto-connect; input is refused before the
    # ready frame validates.
    assert "opening the tool NEVER auto-connects" in tool
    assert 'data-testid="terminal-connect"' in tool and 'data-testid="terminal-end"' in tool
    assert "import { FitAddon }" in runtime and "import { SearchAddon }" in runtime
    assert "import { WebLinksAddon }" in runtime
    assert "navigator.clipboard" in view and "PasteGuardDialog" in view
    # Terminal output is untrusted. Both the auto-open and confirmation paths
    # use one exact URL-parser boundary; only absolute HTTP(S) destinations can
    # open, unsupported/malformed links remain copy-only, and new windows are
    # isolated from their opener.
    assert "const decision = validateTerminalLink(uri)" in view
    assert "if (!decision.href || handling === 'confirm')" in view
    assert view.count("openTerminalLink(") == 2
    assert "parsed.protocol !== 'http:' && parsed.protocol !== 'https:'" in links
    assert "if (!decision.href) return false" in links
    assert "'noopener,noreferrer'" in links and "opened.opener = null" in links
    assert "This destination stays copy-only for manual review." in view
    assert "{linkRequest?.href ? (" in view
    combined = "\n".join(sources.values())
    for forbidden in ("innerHTML", "insertAdjacentHTML", "eval(", "new Function", "javascript:"):
        assert forbidden not in combined, forbidden
    for relative, source in sources.items():
        if relative == "terminalManager.ts":
            continue  # tab-session markers only; audited below
        assert "localStorage" not in source and "sessionStorage" not in source, relative


def test_terminal_socket_policy_keeps_the_one_use_token_out_of_the_url() -> None:
    socket = (WEB / "src" / "client" / "http" / "terminalSocket.ts").read_text(encoding="utf-8")
    terminal = (WEB / "src" / "client" / "http" / "terminal.ts").read_text(encoding="utf-8")
    endpoints = (WEB / "src" / "client" / "http" / "endpoints.ts").read_text(encoding="utf-8")
    assert "stateport.terminal-socket/v1" in socket
    assert "stateport.terminal.v1" in socket
    assert "one-use token" in socket and "NEVER placed in the URL" in socket
    assert "oneUseToken: ticket.oneUseToken" in socket
    assert "Input is never sent before the ready frame validates" in terminal
    assert "terminalPrepare" in endpoints and "'/v1/terminal/socket'" in endpoints
    service = (ROOT / "packages" / "persistent-app" / "src" / "stateport_persistent_app" / "service_process.py").read_text(encoding="utf-8")
    assert "terminal WebSocket origin is invalid" in service


def test_terminal_controls_accessibility_and_settings_are_present() -> None:
    tool = (TERMINAL / "TerminalTool.tsx").read_text(encoding="utf-8")
    view = (TERMINAL / "TerminalView.tsx").read_text(encoding="utf-8")
    find_bar = (TERMINAL / "FindBar.tsx").read_text(encoding="utf-8")
    settings = (WEB / "src" / "features" / "settings" / "GlobalGroups2.tsx").read_text(encoding="utf-8")
    tokens = (WEB / "src" / "styles" / "tokens.css").read_text(encoding="utf-8")
    assert 'data-testid="terminal-connect"' in tool and 'data-testid="terminal-end"' in tool
    assert 'aria-label="Previous match"' in find_bar and 'aria-label="Next match"' in find_bar
    assert "Copy selection" in view and "pasteFromClipboard" in view
    assert "applySettings()" in view and "settings/terminal" in tool
    assert 'data-testid="settings-group-terminal"' in settings
    # Screen-reader output stays a polite live region, never raw terminal
    # data dumped into the DOM.
    assert 'aria-live="polite"' in view and 'data-testid="terminal-sr-region"' in view
    assert 'data-testid="terminal-announce"' in tool
    assert '[data-motion="reduced"]' in tokens and "@media (pointer: coarse)" in tokens


def test_terminal_surface_never_embeds_server_paths_commands_or_secrets() -> None:
    sources = _terminal_sources()
    client = (WEB / "src" / "client" / "http" / "terminal.ts").read_text(encoding="utf-8")
    socket = (WEB / "src" / "client" / "http" / "terminalSocket.ts").read_text(encoding="utf-8")
    combined = "\n".join([*sources.values(), client, socket])
    for forbidden in (
        "SSH_AUTH_SOCK", "IdentityFile=", "UserKnownHostsFile=", "ProxyCommand=",
        '"/home/', "'/home/", "/tmp/stateport", "BEGIN OPENSSH PRIVATE KEY", "herdr socket URL",
    ):
        assert forbidden not in combined, forbidden
    assert "oneUseToken" in combined
    manager = sources["terminalManager.ts"]
    assert "localStorage" not in manager
    assert "sessionStorage" in manager and "MARKER_KEY" in manager


def test_terminal_store_and_session_guards_execute_in_vitest() -> None:
    result = subprocess.run(
        ["npm", "run", "test", "--", "src/features/terminal"],
        cwd=WEB,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    output = _plain_output(result.stdout)
    assert result.returncode == 0, output
    assert re.search(r"Tests\s+\d+\s+passed", output), output
    assert not re.search(r"(?:Test Files|Tests)\s+\d+\s+failed", output), output


if __name__ == "__main__":
    raise SystemExit(__import__("pytest").main([__file__]))
