#!/usr/bin/env python3
"""The terminal socket policy of the typed client (the web terminal surface itself is not shipped)."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "apps" / "web"


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
