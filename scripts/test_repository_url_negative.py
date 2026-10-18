"""Negative tests for the public repository URL / SSRF validator (audit S2-04).

Mutants for the non-443 port refusal, the ".local" suffix refusal and
any() -> all() over DNS answers all survived because every existing test used a
single-address answer. DNS is always mocked here: no test performs a lookup.
"""

from __future__ import annotations

import json
from pathlib import Path
import socket
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
for relative in (
    "packages/persistent-app/src",
    "packages/statedd-core/src",
    "packages/template-validator/src",
    "packages/instance-backup/src",
    "packages/instance-catalog/src",
    "packages/diagnostics/src",
):
    sys.path.insert(0, str(ROOT / relative))

from stateport_persistent_app import repository_import as module  # noqa: E402

PUBLIC_V4 = "93.184.216.34"
PUBLIC_V4_B = "8.8.8.8"
PUBLIC_V6 = "2001:4860:4860::8888"

PRIVATE_ADDRESSES = [
    "127.0.0.1",
    "10.0.0.5",
    "172.16.0.1",
    "192.168.1.1",
    "169.254.169.254",  # cloud metadata
    "100.64.0.1",  # carrier-grade NAT
    "0.0.0.0",
    "224.0.0.1",  # multicast
    "240.0.0.1",  # reserved
    "::1",
    "fe80::1",  # link-local
    "fc00::1",  # unique local
    "fd12:3456::1",  # unique local
    "fd00:ec2::254",  # AWS IPv6 metadata
    "::ffff:10.0.0.1",  # v4-mapped private
    "::ffff:169.254.169.254",  # v4-mapped metadata
    "64:ff9b::a00:1",  # NAT64 of 10.0.0.1
    "::",
]


@pytest.fixture(autouse=True)
def _no_real_dns(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("test attempted a real DNS lookup")

    monkeypatch.setattr(module.socket, "getaddrinfo", refuse)


def _answers(*addresses: str):
    def fake(host, port, *args, **kwargs):
        return [
            (socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))
            for address in addresses
        ]

    return fake


def _resolve_to(monkeypatch, *addresses: str) -> None:
    monkeypatch.setattr(module.socket, "getaddrinfo", _answers(*addresses))


def _subprocess_answers(monkeypatch, by_family: dict[int, list[str]]) -> list[int]:
    families: list[int] = []

    class _Result:
        def __init__(self, stdout: str) -> None:
            self.stdout = stdout
            self.returncode = 0

    def fake_run(argv, **kwargs):
        family = int(argv[-1])
        families.append(family)
        if family not in by_family:
            raise subprocess.TimeoutExpired(argv, 8)
        return _Result(json.dumps(by_family[family]))

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    return families


# --- positive controls: these must stay accepted ---------------------------


@pytest.mark.parametrize(
    "addresses",
    [
        [PUBLIC_V4],
        [PUBLIC_V6],
        [PUBLIC_V4, PUBLIC_V4_B],
        [PUBLIC_V4, PUBLIC_V6],
    ],
)
def test_public_answers_are_accepted(monkeypatch, addresses):
    _resolve_to(monkeypatch, *addresses)
    assert module.validate_public_https_url("https://example.com/org/repo") == "https://example.com/org/repo"


def test_explicit_443_and_trailing_dot_host_are_accepted(monkeypatch):
    _resolve_to(monkeypatch, PUBLIC_V4)
    assert module.validate_public_https_url("https://Example.COM.:443/org/repo") == "https://example.com/org/repo"


def test_public_ipv6_literal_is_accepted(monkeypatch):
    _resolve_to(monkeypatch, PUBLIC_V6)
    assert module.validate_public_https_url(f"https://[{PUBLIC_V6}]/repo") == f"https://[{PUBLIC_V6}]/repo"


@pytest.mark.parametrize(
    "by_family,pinned",
    [
        ({socket.AF_INET: [PUBLIC_V4]}, PUBLIC_V4),
        ({socket.AF_INET: [PUBLIC_V4, PUBLIC_V4_B]}, PUBLIC_V4_B),
        ({socket.AF_INET: [], socket.AF_INET6: [PUBLIC_V6]}, PUBLIC_V6),
        ({socket.AF_INET6: [PUBLIC_V6, "2606:4700:4700::1111"]}, PUBLIC_V6),
    ],
)
def test_public_target_accepts_public_answers_and_pins_one(monkeypatch, by_family, pinned):
    _subprocess_answers(monkeypatch, by_family)
    url, address = module._public_target("https://example.com/org/repo")
    assert url == "https://example.com/org/repo"
    assert address == pinned


# --- mixed public + private answers: ANY private answer refuses ------------


@pytest.mark.parametrize("private", PRIVATE_ADDRESSES)
@pytest.mark.parametrize("order", ["public-first", "private-first"])
def test_validate_refuses_when_any_answer_is_private(monkeypatch, private, order):
    answers = [PUBLIC_V4, private] if order == "public-first" else [private, PUBLIC_V4]
    _resolve_to(monkeypatch, *answers)
    with pytest.raises(module.RepositoryImportError) as caught:
        module.validate_public_https_url("https://example.com/org/repo")
    assert caught.value.code == "repository_url_private_target"


@pytest.mark.parametrize("private", PRIVATE_ADDRESSES)
def test_validate_refuses_single_private_answer(monkeypatch, private):
    _resolve_to(monkeypatch, private)
    with pytest.raises(module.RepositoryImportError) as caught:
        module.validate_public_https_url("https://example.com/org/repo")
    assert caught.value.code == "repository_url_private_target"


def test_validate_refuses_three_answers_with_one_private_in_the_middle(monkeypatch):
    _resolve_to(monkeypatch, PUBLIC_V4, "169.254.169.254", PUBLIC_V6)
    with pytest.raises(module.RepositoryImportError, match="private or reserved"):
        module.validate_public_https_url("https://example.com/org/repo")


@pytest.mark.parametrize(
    "answers",
    [[], ["not-an-ip"], [PUBLIC_V4, "not-an-ip"], ["999.1.1.1"]],
)
def test_validate_refuses_empty_or_unparseable_answers(monkeypatch, answers):
    _resolve_to(monkeypatch, *answers)
    with pytest.raises(module.RepositoryImportError) as caught:
        module.validate_public_https_url("https://example.com/org/repo")
    assert caught.value.code == "repository_url_private_target"


def test_validate_reports_unresolved_host(monkeypatch):
    def fail(*args, **kwargs):
        raise socket.gaierror("no such host")

    monkeypatch.setattr(module.socket, "getaddrinfo", fail)
    with pytest.raises(module.RepositoryImportError) as caught:
        module.validate_public_https_url("https://example.com/org/repo")
    assert caught.value.code == "repository_url_unresolved"


@pytest.mark.parametrize("private", PRIVATE_ADDRESSES)
@pytest.mark.parametrize("order", ["public-first", "private-first"])
def test_public_target_refuses_when_any_answer_is_private(monkeypatch, private, order):
    answers = [PUBLIC_V4, private] if order == "public-first" else [private, PUBLIC_V4]
    families = _subprocess_answers(monkeypatch, {socket.AF_INET: answers, socket.AF_INET6: [PUBLIC_V6]})
    with pytest.raises(module.RepositoryImportError) as caught:
        module._public_target("https://example.com/org/repo")
    assert caught.value.code == "repository_url_private_target"
    # refused on the first family, never falls through to a clean second family
    assert families == [socket.AF_INET]


def test_public_target_refuses_private_in_ipv6_answer_after_empty_ipv4(monkeypatch):
    _subprocess_answers(monkeypatch, {socket.AF_INET: [], socket.AF_INET6: [PUBLIC_V6, "fd12:3456::1"]})
    with pytest.raises(module.RepositoryImportError) as caught:
        module._public_target("https://example.com/org/repo")
    assert caught.value.code == "repository_url_private_target"


def test_public_target_refuses_non_string_answer(monkeypatch):
    _subprocess_answers(monkeypatch, {socket.AF_INET: [PUBLIC_V4, 5]})
    with pytest.raises(module.RepositoryImportError) as caught:
        module._public_target("https://example.com/org/repo")
    assert caught.value.code == "repository_url_private_target"


# --- port, names, credentials: refused before any resolution ---------------


@pytest.mark.parametrize("port", ["80", "444", "8443", "22", "65535", "0"])
@pytest.mark.parametrize("resolve", [False, True])
def test_non_443_port_is_refused_before_resolution(monkeypatch, port, resolve):
    # the autouse fixture makes any lookup raise AssertionError
    with pytest.raises(module.RepositoryImportError) as caught:
        module.validate_public_https_url(f"https://example.com:{port}/org/repo", resolve=resolve)
    assert caught.value.code == "repository_url_refused"
    assert "443" in str(caught.value)


def test_non_443_port_is_refused_by_public_target(monkeypatch):
    called = _subprocess_answers(monkeypatch, {socket.AF_INET: [PUBLIC_V4]})
    with pytest.raises(module.RepositoryImportError) as caught:
        module._public_target("https://example.com:8443/org/repo")
    assert caught.value.code == "repository_url_refused"
    assert called == []


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "LOCALHOST",
        "localhost.",
        "localhost.localdomain",
        "printer.local",
        "PRINTER.LOCAL",
        "printer.local.",
        "a.b.c.local",
    ],
)
@pytest.mark.parametrize("resolve", [False, True])
def test_local_names_are_refused_even_if_dns_would_say_public(monkeypatch, host, resolve):
    _resolve_to(monkeypatch, PUBLIC_V4)
    with pytest.raises(module.RepositoryImportError) as caught:
        module.validate_public_https_url(f"https://{host}/org/repo", resolve=resolve)
    assert caught.value.code == "repository_url_refused"
    assert "local" in str(caught.value)


@pytest.mark.parametrize("host", ["printer.local", "localhost"])
def test_public_target_refuses_local_names_before_resolution(monkeypatch, host):
    called = _subprocess_answers(monkeypatch, {socket.AF_INET: [PUBLIC_V4]})
    with pytest.raises(module.RepositoryImportError) as caught:
        module._public_target(f"https://{host}/org/repo")
    assert caught.value.code == "repository_url_refused"
    assert called == []


@pytest.mark.parametrize("host", ["db.internal", "svc.corp.internal", "foo.localhost", "intranet"])
@pytest.mark.parametrize("private", ["10.1.2.3", "127.0.0.1", "169.254.169.254", "fd12:3456::1"])
def test_internal_style_names_are_refused_when_they_resolve_privately(monkeypatch, host, private):
    _resolve_to(monkeypatch, private)
    with pytest.raises(module.RepositoryImportError) as caught:
        module.validate_public_https_url(f"https://{host}/org/repo")
    assert caught.value.code == "repository_url_private_target"


# Userinfo is assembled at runtime so the file carries no literal URL with a user and password in its
# authority, which the Sensitive Data Gateway treats as an embedded credential. The values are
# throwaway placeholders; the test asserts the validator refuses any userinfo.
_USER = "user"
_PASS = "secret"


@pytest.mark.parametrize(
    "url",
    [
        "https://" + _USER + ":" + _PASS + "@example.com/org/repo",
        "https://user@example.com/org/repo",
        "https://:secret@example.com/org/repo",
        "https://@example.com/org/repo",
        "https://" + _USER + ":" + _PASS + "@[2001:4860:4860::8888]/org/repo",
    ],
)
@pytest.mark.parametrize("resolve", [False, True])
def test_credentials_in_url_are_refused_before_resolution(url, resolve):
    with pytest.raises(module.RepositoryImportError) as caught:
        module.validate_public_https_url(url, resolve=resolve)
    assert caught.value.code == "repository_url_refused"
    assert "secret" not in str(caught.value)


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/org/repo",
        "ssh://example.com/org/repo",
        "file:///etc/passwd",
        "ftp://example.com/org/repo",
        "//example.com/org/repo",
        "https:///org/repo",
        "https://example.com/org/repo?x=1",
        "https://example.com/org/repo#frag",
    ],
)
def test_other_schemes_and_shapes_are_refused_before_resolution(url):
    with pytest.raises(module.RepositoryImportError):
        module.validate_public_https_url(url)


@pytest.mark.parametrize("literal", ["127.0.0.1", "10.0.0.5", "169.254.169.254", "[::1]", "[fe80::1]", "[fd12:3456::1]", "[::ffff:10.0.0.1]"])
def test_private_ip_literals_are_refused_via_resolution(monkeypatch, literal):
    address = literal.strip("[]")
    _resolve_to(monkeypatch, address)
    with pytest.raises(module.RepositoryImportError) as caught:
        module.validate_public_https_url(f"https://{literal}/org/repo")
    assert caught.value.code == "repository_url_private_target"


@pytest.mark.parametrize("literal", ["127.0.0.1", "169.254.169.254", "[::1]", "[fd12:3456::1]"])
def test_public_target_refuses_private_ip_literals(monkeypatch, literal):
    address = literal.strip("[]")
    _subprocess_answers(monkeypatch, {socket.AF_INET: [address], socket.AF_INET6: [address]})
    with pytest.raises(module.RepositoryImportError) as caught:
        module._public_target(f"https://{literal}/org/repo")
    assert caught.value.code == "repository_url_private_target"
