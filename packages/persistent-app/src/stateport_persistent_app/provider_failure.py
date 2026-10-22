"""Classify a failed provider invocation into one readable, public-safe cause.

The managed OpenCode process reports why a request failed in two places: a
run-level ``error`` event on stdout and, when started with diagnostic logging,
``level=ERROR`` lines on stderr. Neither is ever persisted or returned. This
module only reads them to pick one code out of a fixed vocabulary; the code is
the only thing that crosses the durable error boundary (see
``AssistantProcessor._failure_message``).

Precedence is deliberate: a quota, authentication or model cause found in the
diagnostics wins over a timeout, because opencode retries those internally and
the process then hits the time budget without the user learning the real cause.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

QUOTA = "provider_quota_exceeded"
AUTH_MISSING = "provider_authentication_missing"
AUTH_EXPIRED = "provider_authentication_expired"
AUTH_UNVERIFIED = "provider_authentication_unverified"
MODEL_UNAVAILABLE = "provider_model_unavailable"
UPSTREAM = "provider_upstream_unavailable"

#: Causes that must never be retried: the same request would fail again and a
#: retry only burns quota or hammers an endpoint that refused us.
NEVER_RETRY = frozenset({QUOTA, AUTH_MISSING, AUTH_EXPIRED, AUTH_UNVERIFIED, MODEL_UNAVAILABLE})
RETRYABLE = frozenset({UPSTREAM})

_SCAN_LIMIT = 96 * 1024

_QUOTA = re.compile(
    r"usage[ _-]?limit|rate[ _-]?limit|quota|insufficient[ _-]?(?:credit|balance|funds)"
    r"|credit balance|out of credits|billing|payment required|too many requests"
    r"|\b(?:status(?:code|_code)?\W{1,3}|http\W{0,6})(?:429|402)\b",
    re.I,
)
_AUTH_MISSING = re.compile(
    r"no (?:api[ _-]?key|credentials?|auth(?:entication)?)\b"
    r"|(?:api[ _-]?key|credentials?|token) (?:is |was )?(?:missing|required|not (?:set|found|configured))"
    r"|missing (?:api[ _-]?key|credentials?|token)|not (?:logged|signed)[ _-]?in|please (?:log|sign)[ _-]?in",
    re.I,
)
_AUTH_EXPIRED = re.compile(
    r"unauthori[sz]ed|invalid[ _-]?(?:api[ _-]?key|token|credentials?|x-api-key)"
    r"|(?:token|credentials?|session|api[ _-]?key) (?:has |is |was )?(?:expired|revoked|invalid)"
    r"|\b(?:status(?:code|_code)?\W{1,3}|http\W{0,6})401\b|authentication (?:failed|error)",
    re.I,
)
_MODEL = re.compile(
    r"model ?not ?found|\bmodel\b[ :'\"\w./+-]{0,60}?\b(?:not (?:available|supported|found|exist)|unavailable|deprecated|decommissioned|does not exist)"
    r"|unknown model|not available in your (?:country|region)|unsupported model"
    r"|\b(?:status(?:code|_code)?\W{1,3}|http\W{0,6})404\b",
    re.I,
)
_TRANSIENT = re.compile(
    r"unexpected server error|internal server error|bad gateway|service unavailable"
    r"|gateway time-?out|overloaded|temporarily unavailable|econnreset|etimedout|econnrefused"
    r"|socket hang up|fetch failed|connection (?:reset|refused|closed|error)|network error"
    r"|\b(?:status(?:code|_code)?\W{1,3}|http\W{0,6})(?:50\d|52\d)\b",
    re.I,
)


def _fragments(events: Iterable[dict[str, Any]], stderr: str) -> str:
    parts: list[str] = []
    for event in events:
        if event.get("type") != "error":
            continue
        error = event.get("error")
        if isinstance(error, dict):
            name = error.get("name")
            if isinstance(name, str):
                parts.append(name)
            data = error.get("data")
            if isinstance(data, dict):
                for key in ("message", "statusCode", "status"):
                    value = data.get(key)
                    if isinstance(value, (str, int)) and not isinstance(value, bool):
                        parts.append(f"{key}={value}" if key != "message" else str(value))
            message = error.get("message")
            if isinstance(message, str):
                parts.append(message)
    if isinstance(stderr, str) and stderr:
        parts.append(stderr[:_SCAN_LIMIT])
    return "\n".join(parts)


def _auth_named(events: Iterable[dict[str, Any]]) -> bool:
    for event in events:
        error = event.get("error") if event.get("type") == "error" else None
        name = error.get("name") if isinstance(error, dict) else None
        if isinstance(name, str) and "auth" in name.lower():
            return True
    return False


def classify_provider_failure(
    events: Iterable[dict[str, Any]] = (),
    stderr: str = "",
) -> str | None:
    """Return a fixed cause code, or None when the diagnostics say nothing known."""

    events = tuple(events)
    text = _fragments(events, stderr)
    if _QUOTA.search(text):
        return QUOTA
    if _auth_named(events):
        return AUTH_EXPIRED if _AUTH_EXPIRED.search(text) else (
            AUTH_MISSING if _AUTH_MISSING.search(text) else AUTH_UNVERIFIED
        )
    if _AUTH_MISSING.search(text):
        return AUTH_MISSING
    if _AUTH_EXPIRED.search(text):
        return AUTH_EXPIRED
    if _MODEL.search(text):
        return MODEL_UNAVAILABLE
    if _TRANSIENT.search(text):
        return UPSTREAM
    return None


__all__ = [
    "AUTH_EXPIRED", "AUTH_MISSING", "AUTH_UNVERIFIED", "MODEL_UNAVAILABLE", "NEVER_RETRY",
    "QUOTA", "RETRYABLE", "UPSTREAM", "classify_provider_failure",
]
