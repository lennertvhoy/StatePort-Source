#!/usr/bin/env python3
"""Verify the provider-free public-alpha catalog boundary.

This is deliberately a read-only check. Installing the fictional sample is a
separate browser confirmation and must not be represented as automatic user
consent by the source installer.
"""

from __future__ import annotations

import argparse
import json
from http.cookiejar import CookieJar
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPCookieProcessor, build_opener


APPLICATION_ID = "studystate.sample"
DISPLAY_NAME = "StudyState Sample"
EXPECTED_CAPABILITIES = {
    "conversation",
    "goal_execution",
    "proactive_notifications",
    "progress_dashboard",
}


class PreflightError(ValueError):
    """The running service does not satisfy the public-alpha contract."""


def validate_catalog(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return the exact sample entry or fail with an actionable explanation."""

    result = payload.get("result")
    applications = result.get("applications") if isinstance(result, Mapping) else None
    if not isinstance(applications, list):
        raise PreflightError("application catalog response has no result.applications list")
    matches = [
        item
        for item in applications
        if isinstance(item, Mapping) and item.get("applicationId") == APPLICATION_ID
    ]
    if len(matches) != 1:
        raise PreflightError(
            f"application catalog must contain exactly one {APPLICATION_ID!r} entry; found {len(matches)}"
        )
    entry = matches[0]
    if entry.get("displayName") != DISPLAY_NAME:
        raise PreflightError(
            f"{APPLICATION_ID} display name is not the expected fictional sample {DISPLAY_NAME!r}"
        )
    install = entry.get("install")
    if not isinstance(install, Mapping):
        raise PreflightError(f"{APPLICATION_ID} has no install contract")
    if install.get("status") != "available":
        reasons = install.get("reasons", [])
        raise PreflightError(f"{DISPLAY_NAME} is not installable: {reasons}")
    if install.get("sourceKind") != "bundled_public_fixture":
        raise PreflightError(f"{DISPLAY_NAME} is not identified as a bundled public fixture")
    if install.get("networkPolicy") != "disabled":
        raise PreflightError(f"{DISPLAY_NAME} does not declare networkPolicy=disabled")
    capabilities = install.get("requestedCapabilities")
    if not isinstance(capabilities, list) or set(capabilities) != EXPECTED_CAPABILITIES:
        raise PreflightError(f"{DISPLAY_NAME} requested capabilities do not match the public-alpha contract")
    if install.get("confirmationRequired") is not True:
        raise PreflightError(f"{DISPLAY_NAME} does not require explicit installation confirmation")
    return entry


def check_service(base_url: str, timeout: float = 10.0) -> Mapping[str, Any]:
    """Open a local session and validate its application catalog."""

    parsed = urlsplit(base_url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise PreflightError("base URL has an invalid port") from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost"}
        or port is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path.rstrip("/")
        or parsed.query
        or parsed.fragment
    ):
        raise PreflightError("base URL must be an origin-only loopback HTTP URL with an explicit port")
    base = f"http://{parsed.hostname}:{port}"
    opener = build_opener(HTTPCookieProcessor(CookieJar()))
    with opener.open(f"{base}/session", timeout=timeout) as response:
        session = json.load(response)
    if not isinstance(session, Mapping) or session.get("ok") is not True:
        raise PreflightError("StatePort session endpoint is not ready")
    with opener.open(f"{base}/v1/applications", timeout=timeout) as response:
        catalog = json.load(response)
    if not isinstance(catalog, Mapping):
        raise PreflightError("application catalog response is not an object")
    return validate_catalog(catalog)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args(argv)
    try:
        check_service(args.base_url, args.timeout)
    except (PreflightError, HTTPError, URLError, json.JSONDecodeError, TimeoutError) as exc:
        parser.exit(1, f"public-alpha preflight: error: {exc}\n")
    print(
        "public-alpha preflight: StudyState Sample is available as a "
        "provider-free bundled fixture; explicit browser confirmation remains required."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
