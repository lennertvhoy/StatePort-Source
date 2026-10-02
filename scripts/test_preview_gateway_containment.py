#!/usr/bin/env python3
"""Security containment proof: same-origin previews are disabled by default.

Contained defect: preview content is served from the StatePort origin, so
hostile preview JavaScript running in a preview frame could reach ``/session``,
authenticated ``/v1/*`` mutations, the operator cookie, StatePort
local/session storage, and terminal ticket creation. Header filtering is not
an acceptable fix; the only acceptable long-term shape is a
credential-isolated origin. Until that exists, the preview surface stays
unreachable and the API reports a typed, actionable unavailable state.

RE-ENABLE GATE: any future change that re-enables preview serving MUST keep
this test passing and extend it to prove — against the real serving path,
from whatever origin serves previews — that hostile preview JavaScript cannot
reach /session, a benign authenticated /v1 mutation, StatePort cookies,
StatePort local/session storage, or terminal ticket creation.
"""

from __future__ import annotations

import http.client
import json
from pathlib import Path
import sys
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
for source_root in sorted((ROOT / "packages").glob("*/src")):
    sys.path.insert(0, str(source_root))
for source_root in sorted((ROOT / "apps").glob("*/src")):
    sys.path.insert(0, str(source_root))

from stateport_preview_gateway import PreviewRouteRegistry  # noqa: E402

from test_platform_services_api import WebHarness  # noqa: E402


CAPSULE = "capsule:demo-classdd:001"
REVISION_A = "sha256:" + "a" * 64


@pytest.fixture()
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> WebHarness:
    # Default harness: previews are NOT enabled. Production services always
    # run in exactly this configuration.
    instance = WebHarness(tmp_path, monkeypatch)
    try:
        yield instance
    finally:
        instance.close()


def _raw(
    port: int,
    path: str,
    *,
    method: str = "GET",
    cookie: str | None = None,
    csrf: str | None = None,
    origin: str | None = None,
    upgrade: bool = False,
    body: dict[str, object] | None = None,
) -> tuple[int, dict[str, object]]:
    headers: dict[str, str] = {}
    if cookie is not None:
        headers["Cookie"] = cookie
    if csrf is not None:
        headers["X-StatePort-CSRF"] = csrf
    if origin is not None:
        headers["Origin"] = origin
    if upgrade:
        headers.update(
            {
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Version": "13",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            }
        )
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode("utf-8")
    request = Request(
        f"http://127.0.0.1:{port}{path}", data=data, headers=headers, method=method
    )
    try:
        with urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except HTTPError as error:
        return error.code, json.loads(error.read())


def test_preview_proxy_surface_is_unreachable_when_disabled(harness: WebHarness) -> None:
    """No preview document can ever be served from the StatePort origin."""

    # Unauthenticated, authenticated, POST, and WebSocket-upgrade attempts all
    # hit the same typed refusal before any upstream is contacted.
    for attempt in (
        lambda: _raw(harness.port, f"/preview/{CAPSULE}/web/"),
        lambda: _raw(harness.port, f"/preview/{CAPSULE}/web/index.html", cookie=harness.cookie),
        lambda: _raw(
            harness.port,
            f"/preview/{CAPSULE}/web/api",
            method="POST",
            cookie=harness.cookie,
            csrf=harness.csrf,
            origin=harness.origin,
            body={"hostile": "payload"},
        ),
        lambda: _raw(
            harness.port,
            f"/preview/{CAPSULE}/web/ws",
            cookie=harness.cookie,
            origin=harness.origin,
            upgrade=True,
        ),
    ):
        status, payload = attempt()
        assert status == 403, payload
        assert payload["error"]["code"] == "preview_disabled_same_origin"
        assert "credential-isolated origin" in payload["error"]["message"]


def test_preview_route_mutations_are_refused_when_disabled(harness: WebHarness) -> None:
    """Hostile content cannot be introduced through the receipted registry."""

    status, payload = harness.post(
        "/v1/preview-routes",
        {
            "capsuleId": CAPSULE,
            "serviceId": "web",
            "revisionDigest": REVISION_A,
            "upstreamPort": 9,
            "ttlSeconds": 3600,
        },
    )
    assert status == 409, payload
    assert payload["error"]["code"] == "preview_disabled_same_origin"

    for operation, body in (
        ("revoke", {"reason": "containment check"}),
        ("rewrite", {"revisionDigest": REVISION_A, "upstreamPort": 9}),
    ):
        status, payload = harness.post(f"/v1/preview-routes/route_any/{operation}", body)
        assert status == 409, payload
        assert payload["error"]["code"] == "preview_disabled_same_origin"


def test_preview_route_index_reports_typed_unavailable(harness: WebHarness) -> None:
    """The API tells the UI exactly why previews are unavailable and what next."""

    status, payload = harness.get("/v1/preview-routes")
    assert status == 200, payload
    availability = payload["result"]["availability"]
    assert availability["status"] == "disabled"
    assert availability["code"] == "preview_disabled_same_origin"
    assert "credential-isolated origin" in availability["message"]
    assert availability["nextAction"]
    assert payload["result"]["routes"] == []


def test_preregistered_route_still_cannot_be_served_when_disabled(
    harness: WebHarness, tmp_path: Path
) -> None:
    """Containment is at the serving layer, not only at registration.

    Even a route that already exists in the registry state — written by an
    older build, a restored backup, or direct state manipulation — cannot be
    resolved or proxied while previews are disabled.
    """

    registry = PreviewRouteRegistry(tmp_path / "preview-state")
    registry.register(
        capsule_id=CAPSULE,
        service_id="web",
        revision_digest=REVISION_A,
        upstream_port=9,
        ttl_seconds=3600,
        actor="containment-test",
    )
    harness.server._preview_route_registry = registry

    status, payload = _raw(harness.port, f"/preview/{CAPSULE}/web/", cookie=harness.cookie)
    assert status == 403, payload
    assert payload["error"]["code"] == "preview_disabled_same_origin"


def test_credential_targets_remain_guarded_while_previews_disabled(harness: WebHarness) -> None:
    """The assets hostile preview JS would want stay behind their guards.

    Since no preview document can be served, no script can run in the
    StatePort origin at all; these assertions pin the guards on the targets
    such a script would attack first.
    """

    # Terminal ticket creation requires the operator session.
    status, payload = _raw(
        harness.port,
        "/v1/instances/instance-one/terminal/prepare",
        method="POST",
        body={"expectedInstanceId": "instance-one", "columns": 80, "rows": 24},
    )
    assert status == 401, payload
    assert payload["error"]["code"] == "session_required"

    # A benign authenticated /v1 mutation still requires the CSRF token and
    # loopback Origin that cross-origin or injected content cannot mint.
    status, payload = _raw(
        harness.port,
        "/v1/preview-routes",
        method="POST",
        cookie=harness.cookie,
        body={
            "capsuleId": CAPSULE,
            "serviceId": "web",
            "revisionDigest": REVISION_A,
            "upstreamPort": 9,
            "ttlSeconds": 3600,
        },
    )
    assert status == 403, payload

    # The preview route index exposes no StatePort credential material.
    status, payload = harness.get("/v1/preview-routes")
    assert status == 200, payload
    serialized = json.dumps(payload)
    assert harness.cookie.split("=", 1)[1] not in serialized
    assert harness.csrf not in serialized


def _raw_with_headers(
    port: int, path: str
) -> tuple[int, dict[str, str], dict[str, object]]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        body = response.read()
        headers = {key.lower(): value for key, value in response.getheaders()}
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = {"raw": body.decode("utf-8", errors="replace")}
        return response.status, headers, payload
    finally:
        connection.close()


def test_session_endpoint_is_the_credential_mint_previews_could_reach(
    harness: WebHarness,
) -> None:
    """Pin exactly why same-origin previews stay disabled.

    ``GET /session`` is unauthenticated by design — it is how the StatePort
    SPA establishes its session — so it hands any JavaScript running on the
    StatePort origin the full operator credential bundle in one fetch: the
    session cookie plus the CSRF token that authorizes every ``/v1/*``
    mutation. A preview document served from this origin could do the same.
    This characterization must stay true and preview serving must stay off
    (or move to a credential-isolated origin) — never both same-origin and
    enabled.
    """

    status, headers, payload = _raw_with_headers(harness.port, "/session")
    assert status == 200, payload
    assert payload["result"]["csrfToken"] == harness.csrf
    set_cookie = headers.get("set-cookie", "")
    assert set_cookie.startswith("stateport_session=")
    assert "HttpOnly" in set_cookie


def test_preview_path_cannot_escape_to_session_or_v1(harness: WebHarness) -> None:
    """Traversal through the preview surface never yields credential material.

    While previews are disabled every ``/preview/`` request is refused, so no
    preview-serving path can be abused as a confused deputy to reach
    ``/session`` or ``/v1/*``. The assertions are origin-level (no CSRF token,
    no session cookie, no ``/v1`` result), so they must keep passing after any
    future re-enable from a credential-isolated origin.
    """

    attempts = (
        "/preview/../session",
        "/preview/%2e%2e/session",
        f"/preview/{CAPSULE}/web/../../session",
        f"/preview/{CAPSULE}/web/../../../v1/preview-routes",
        f"/preview/{CAPSULE}/web/..%2f..%2fsession",
    )
    for path in attempts:
        status, headers, payload = _raw_with_headers(harness.port, path)
        serialized = json.dumps(payload)
        assert harness.csrf not in serialized, (path, status, payload)
        assert "stateport_session=" not in headers.get("set-cookie", ""), (path, status)
        assert not (status == 200 and payload.get("ok") is True), (path, status, payload)
