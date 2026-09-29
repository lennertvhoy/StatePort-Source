#!/usr/bin/env python3
"""Tests for the HTTP-dispatch resolver, including the case a literal search cannot solve.

The load-bearing case is ``test_composing_helper_fragment_is_resolved``: the literal
``/v1/provider/credential`` appears in no test source, yet the endpoint is exercised through a helper
that builds the path from a fragment. A substring search therefore reports a guaranteed false
negative, and this file pins the behaviour that fixes it.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _module():
    spec = importlib.util.spec_from_file_location(
        "probe_preserved_paths", ROOT / "scripts" / "probe_preserved_paths.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


probe = _module()


def test_composing_helper_fragment_is_resolved() -> None:
    """A path built from a fragment must resolve, which is exactly what grep cannot do."""
    source = '''
def request(connection, headers, action, body=None):
    method = "GET" if action == "status" else "POST"
    connection.request(method, f"/v1/provider/{action}", None, headers)

request(connection, headers, "credential", {"apiKey": "x"})
request(connection, headers, "configure", {"model": "m"})
request(connection, headers, "status")
'''
    found = probe.dispatched_paths(source)
    assert "/v1/provider/credential" in found
    assert "/v1/provider/configure" in found
    assert "/v1/provider/status" in found


def test_the_real_suite_resolves_the_paths_grep_cannot_see() -> None:
    """The ground truth, read from the repository rather than asserted from memory.

    ``/v1/provider/credential`` has no literal in any test file, yet this test file exercises it
    through a composing helper. That is the whole reason the resolver exists.
    """
    target = ROOT / "scripts" / "test_provider_setup.py"
    text = target.read_text(encoding="utf-8")
    assert "/v1/provider/credential" not in text, (
        "the premise changed: the literal now exists, so this test no longer proves the resolver "
        "is doing anything a grep could not"
    )
    found = probe.dispatched_paths(text)
    assert "/v1/provider/credential" in found
    assert "/v1/provider/credential/remove" in found


def test_positional_binding_not_named_argument_matching() -> None:
    """The fragment is bound by the parameter's own index, not by an identifier match."""
    source = '''
def request(connection, headers, action, body=None):
    connection.request("POST", f"/v1/provider/{action}", body, headers)
request(connection, headers, "logout")
'''
    assert "/v1/provider/logout" in probe.dispatched_paths(source)


def test_two_helpers_of_the_same_name_do_not_collapse() -> None:
    """Same name, different signatures: a name-keyed dict would silently keep only the last."""
    source = '''
def request(method, path, body=None, headers=None):
    connection.request(method, path, body, headers)

def other(connection, headers, action, body=None):
    connection.request("POST", f"/v1/provider/{action}", body, headers)

request("GET", "/v1/plain/literal")
other(connection, headers, "credential")
'''
    found = probe.dispatched_paths(source)
    assert "/v1/plain/literal" in found
    assert "/v1/provider/credential" in found


def test_non_literal_fragment_yields_nothing_rather_than_a_guess() -> None:
    """A dynamic fragment must not become an invented path."""
    source = '''
def request(connection, headers, action, body=None):
    connection.request("POST", f"/v1/provider/{action}", body, headers)
request(connection, headers, some_variable)
'''
    assert "/v1/provider/some_variable" not in probe.dispatched_paths(source)


def test_dispatched_paths_is_deterministic() -> None:
    source = '''
def request(connection, headers, action):
    connection.request("POST", f"/v1/x/{action}", None, headers)
request(connection, headers, "one")
request(connection, headers, "two")
'''
    assert probe.dispatched_paths(source) == probe.dispatched_paths(source)
    assert len(probe.dispatched_paths(source)) == 2


def test_table_driven_dispatch_is_resolved() -> None:
    """The dominant shape: a table of cases looped into a dispatch helper.

    A call-site-only probe misses every one of these, which is why a whole-population run found so
    few paths while the service tests visibly contain the routes.
    """
    source = """
CASES = (
    ("/v1/execution-host/workloads", "execution_host_access_denied"),
    ("/v1/execution-host/workloads/start", "execution_host_access_denied"),
)

def _get(port, path):
    connection.request("GET", f"http://127.0.0.1:{port}{path}", None, {})

for path, expected in CASES:
    _get(port, path)
"""
    found = probe.dispatched_paths(source)
    assert "/v1/execution-host/workloads" in found
    assert "/v1/execution-host/workloads/start" in found


def test_local_wrapper_helpers_are_treated_as_sinks() -> None:
    """``_get``/``_post`` are not on any well-known list, but a forwarder is still a sink."""
    source = """
def _post(port, path, body):
    connection.request("POST", f"http://127.0.0.1:{port}{path}", body, {})

_post(port, "/v1/thing")
"""
    assert "/v1/thing" in probe.dispatched_paths(source)


def test_a_table_never_dispatched_is_not_claimed() -> None:
    """A path in a table that no loop feeds to a sink must NOT be reported as dispatched."""
    source = """
UNUSED = ("/v1/never/called",)
"""
    assert "/v1/never/called" not in probe.dispatched_paths(source)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
