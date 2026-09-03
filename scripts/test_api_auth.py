#!/usr/bin/env python3
"""Acceptance tests for bearer authentication and HTTP identity binding."""

from __future__ import annotations

import json
import io
import os
import shutil
import sys
import tempfile
import threading
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
for relative in ("packages/api-auth/src", "packages/governed-api/src", "packages/statedd-core/src", "packages/template-validator/src", "packages/approval-gate/src", "packages/quota-engine/src", "packages/audit-log/src", "packages/governed-runner/src", "packages/container-runner/src", "packages/observability/src", "apps/runner/src", "apps/api/src"):
    sys.path.insert(0, str(ROOT / relative))

from governed_api import GovernedAPI
from stateport_auth import AuthError, BearerAuthenticator
from statedd_core import create_instance
import stateport_api.http as http_adapter
from stateport_api.http import _Handler, serve
from http.server import ThreadingHTTPServer


def _request(url: str, body: dict[str, object] | None = None, token: str | None = None) -> tuple[int, dict[str, object]]:
    request = Request(url, method="POST" if body is not None else "GET")
    if body is not None:
        request.data = json.dumps(body).encode("utf-8")  # type: ignore[attr-defined]
        request.add_header("content-type", "application/json")
    if token is not None:
        request.add_header("authorization", f"Bearer {token}")
    try:
        with urlopen(request, timeout=3) as response:
            return response.status, json.loads(response.read())
    except HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_authenticator_is_fail_closed_and_does_not_expose_tokens() -> None:
    token = "auth-" + "A" * 20
    auth = BearerAuthenticator({"alice": token})
    assert auth.authenticate(f"Bearer {token}").actor == "alice"
    assert token not in repr(auth.authenticate(f"Bearer {token}"))
    for value in (None, "Basic nope", "Bearer wrong"):
        try:
            auth.authenticate(value)
        except AuthError:
            pass
        else:
            raise AssertionError("invalid bearer credential must fail")


def test_empty_token_mapping_is_not_configured() -> None:
    assert BearerAuthenticator.from_json_mapping({}).configured is False


def test_launcher_rejects_authorization_configuration_without_authentication() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        cases = (
            {"identities": {"alice": {"roles": ["user"], "instances": ["i1"]}}},
            {"operator_allowed_capabilities": ["read_state"]},
            {
                "identities": {"alice": {"roles": ["user"], "instances": ["i1"]}},
                "authenticator": BearerAuthenticator.from_json_mapping({}),
            },
        )
        for configured in cases:
            try:
                serve(tmpdir, port=0, **configured)
            except ValueError as exc:
                assert "require bearer authentication" in str(exc)
            else:
                raise AssertionError("authorization configuration without authentication must fail")


def test_main_preserves_unauthenticated_read_only_default_and_fails_closed() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        with patch.dict(os.environ, {}, clear=True), patch.object(http_adapter, "serve") as mocked_serve:
            assert http_adapter.main(["--workspace", tmpdir]) == 0
            kwargs = mocked_serve.call_args.kwargs
            assert kwargs["identities"] is None
            assert kwargs["operator_allowed_capabilities"] == []
            assert kwargs["authenticator"].configured is False

        unsafe_environments = (
            {"STATEPORT_IDENTITIES_JSON": json.dumps({"alice": {"roles": ["user"], "instances": ["i1"]}})},
            {"STATEPORT_OPERATOR_CAPABILITIES": "read_state"},
            {
                "STATEPORT_IDENTITIES_JSON": json.dumps({"alice": {"roles": ["user"], "instances": ["i1"]}}),
                "STATEPORT_AUTH_TOKENS_JSON": "{}",
            },
        )
        for environment in unsafe_environments:
            with patch.dict(os.environ, environment, clear=True), patch.object(http_adapter, "serve"):
                try:
                    with redirect_stderr(io.StringIO()):
                        http_adapter.main(["--workspace", tmpdir])
                except SystemExit as exc:
                    assert exc.code == 2
                else:
                    raise AssertionError("unsafe launcher configuration must fail")

        authenticated_environment = {
            "STATEPORT_IDENTITIES_JSON": json.dumps(
                {"alice": {"roles": ["user"], "instances": ["i1"]}}
            ),
            "STATEPORT_AUTH_TOKENS_JSON": json.dumps({"alice": "auth-" + "C" * 20}),
        }
        with patch.dict(os.environ, authenticated_environment, clear=True), patch.object(
            http_adapter, "serve"
        ) as mocked_serve:
            assert http_adapter.main(["--workspace", tmpdir]) == 0
            assert mocked_serve.call_args.kwargs["authenticator"].configured is True

        oidc_environment = {
            "STATEPORT_IDENTITIES_JSON": json.dumps(
                {"alice": {"roles": ["user"], "instances": ["i1"]}}
            ),
            "STATEPORT_OIDC_CONFIG_JSON": "{}",
        }
        pinned = BearerAuthenticator({"alice": "auth-" + "D" * 20})
        with patch.dict(os.environ, oidc_environment, clear=True), patch.object(
            http_adapter.OIDCAuthenticator,
            "from_mapping",
            return_value=pinned,
        ) as from_mapping, patch.object(http_adapter, "serve") as mocked_serve:
            assert http_adapter.main(["--workspace", tmpdir]) == 0
            from_mapping.assert_called_once_with({})
            assert mocked_serve.call_args.kwargs["authenticator"] is pinned

        with patch.dict(
            os.environ,
            {
                "STATEPORT_AUTH_TOKENS_JSON": "{}",
                "STATEPORT_OIDC_CONFIG_JSON": "{}",
            },
            clear=True,
        ), patch.object(http_adapter, "serve"):
            try:
                with redirect_stderr(io.StringIO()):
                    http_adapter.main(["--workspace", tmpdir])
            except SystemExit as exc:
                assert exc.code == 2
            else:
                raise AssertionError("local bearer and OIDC modes must not be combined")


def test_http_binds_authenticated_actor_and_rejects_mismatch() -> None:
    token = "auth-" + "B" * 20
    with tempfile.TemporaryDirectory() as tmpdir:
        api = GovernedAPI(tmpdir, identities={"alice": {"roles": ["user"], "instances": ["i1"]}})
        server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        server.governed_api = api  # type: ignore[attr-defined]
        server.authenticator = BearerAuthenticator({"alice": token})  # type: ignore[attr-defined]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            assert _request(url + "/health")[0] == 200
            assert _request(url + "/v1/identity/check", {"instanceId": "i1"})[0] == 401
            status, payload = _request(url + "/v1/identity/check", {"instanceId": "i1"}, token)
            assert status == 200 and payload["result"]["identity"]["id"] == "alice"
            assert _request(url + "/v1/identity/check", {"actor": "other"}, token)[0] == 403
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


def test_authenticated_operator_and_approver_complete_mutation_without_self_approval(
    tmp_path: Path,
) -> None:
    template = tmp_path / "template"
    shutil.copytree(ROOT / "templates" / "classdd", template)
    instance = tmp_path / "instance"
    create_instance(
        template,
        instance,
        instance_id="mutation-demo",
        name="Mutation demo",
        owner_name="Tester",
        owner_handle="@tester",
    )
    instance_yaml = instance / "instance.yaml"
    instance_yaml.write_text(
        instance_yaml.read_text(encoding="utf-8").replace(
            '  status: "draft"\n',
            '  status: "draft"\n  grantedCapabilities:\n    - "write_state"\n',
        ),
        encoding="utf-8",
    )
    (instance / ".statedd" / "lock.yaml").unlink()

    operator_token = "operator-" + "A" * 20
    approver_token = "approver-" + "B" * 20
    api = GovernedAPI(
        tmp_path,
        identities={
            "local-operator": {"roles": ["operator"], "instances": ["*"]},
            "local-approver": {"roles": ["approver"], "instances": ["*"]},
        },
        operator_allowed_capabilities=["write_state"],
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.governed_api = api  # type: ignore[attr-defined]
    server.authenticator = BearerAuthenticator(  # type: ignore[attr-defined]
        {
            "local-approver": approver_token,
            "local-operator": operator_token,
        }
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        status, requested = _request(
            url + "/v1/mutations/request",
            {
                "actor": "local-operator",
                "operation": "materialize-instance",
                "instancePath": "instance",
                "templatePath": "template",
            },
            operator_token,
        )
        assert status == 200
        approval_id = requested["result"]["approval"]["id"]  # type: ignore[index]
        status, self_approval = _request(
            url + "/v1/approvals/decide",
            {
                "actor": "local-operator",
                "approvalId": approval_id,
                "status": "approved",
            },
            operator_token,
        )
        assert status == 403
        assert self_approval["error"]["code"] == "self_approval_forbidden"  # type: ignore[index]
        status, _ = _request(
            url + "/v1/approvals/decide",
            {
                "actor": "local-approver",
                "approvalId": approval_id,
                "status": "approved",
            },
            approver_token,
        )
        assert status == 200
        status, applied = _request(
            url + "/v1/mutations/apply",
            {"actor": "local-operator", "approvalId": approval_id},
            operator_token,
        )
        assert status == 200 and applied["result"]["applied"] is True  # type: ignore[index]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


if __name__ == "__main__":
    test_authenticator_is_fail_closed_and_does_not_expose_tokens()
    test_empty_token_mapping_is_not_configured()
    test_launcher_rejects_authorization_configuration_without_authentication()
    test_main_preserves_unauthenticated_read_only_default_and_fails_closed()
    test_http_binds_authenticated_actor_and_rejects_mismatch()
    print("PASS")
