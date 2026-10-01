#!/usr/bin/env python3
"""Verify anonymous public image transport for one StatePort release candidate.

The tool is network-verifying but credential-free: it never reads an image
credential, never invokes Podman, and refuses to run when a credential-bearing
environment variable is present.  Every request is an anonymous registry
request answered through the standard GHCR bearer challenge
(``WWW-Authenticate: Bearer realm=...``); the exact token-URL parser is
imported from the reviewed assembler so quoted-comma scope values cannot be
split incorrectly.  Only the transport/redirect/budget/receipt layers are
implemented here, because the reviewed ``_registry_get`` hides the request
count, the 429 stop, the token cache and the redirect Authorization policy
that this verifier must record.

Probe plan
==========

Per expected image (consumer images from the release build receipt plus the
approved provider image from the producer build receipt), executed in order
and stopping at the first failed premise for that image:

P1  manifest-by-digest: body SHA-256 and ``Docker-Content-Digest`` equal the
    digest bound in the receipt.
P2  the release tag resolves to exactly the expected digest.
P3  index/platform recursion is bounded (<=2) and selects a unique linux/amd64
    leaf (not-applicable for a direct manifest).
P4  config and layer descriptors are well formed (digest, size, layers).
P5  the config blob is fully fetched with ``Range: bytes=0-<size-1>`` and its
    bytes hash to the declared config digest.
P6  every layer blob answers ``Range: bytes=0-0`` with an exact
    ``Content-Range: bytes 0-0/<size>``.
P7  the registry-observed digest equals both receipt references.
P8  release-authority ``configDigest``/``layerDigests`` (when present) equal the
    manifest descriptors.

Run level:

P9  a digest that cannot exist in the repository is not anonymously readable.
P10 a tag that cannot exist in the repository is not anonymously readable.
P11 every digest in the reviewed visibility list stays unreadable (0 bytes
    served, body never hashes to the reviewed digest).
P12 every reviewed private package denies an anonymous pull token.
P13 anonymous cross-repository blob mount is refused (never 201/202).
P14 request budget and minimum delay stay inside the declared bounds; a 429
    blocks the run without retry.
P15 the environment carried no credential and the receipt says so.
P16 tag-collision preflight is a push-side responsibility and is explicitly
    skipped here (recorded in ``skippedProbes``).
P17 the tool digest and version are recorded in the receipt.
P18 the receipt is created create-only with mode 0600 (the writer enforces it;
    the probe entry records that it is enforced out of band).

A private-review input declares the digests and packages whose non-readability
must be demonstrated.  The expected value of every negative is "the public
registry never serves those bytes to an anonymous caller"; a 200 for any of
them fails the run, while a token-endpoint denial, 401, 403 or 404 passes.

Fail-closed policy
==================

* Probe/premise failures (digest, header, tag, descriptor, blob, leak,
  cross-repo mount) collect per image and per negative and end in
  ``result: failed``.
* Infrastructure failures (unavailable transport, malformed challenge,
  unusable token endpoint, oversized response) abort the run and end in
  ``result: blocked``.
* Budget exhaustion and any 429 abort immediately without retry and end in
  ``result: blocked``.
* A credential-bearing environment refuses to run at all (exit 2, no
  receipt).
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time
from typing import Any, Callable, Mapping, Protocol
import urllib.error
import urllib.request
from urllib.parse import urlencode, urljoin, urlsplit


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import assemble_release_index as _assembler  # noqa: E402
from release_safe_io import sha256_file as _sha256_file  # noqa: E402


FORMAT_VERSION = "stateport-public-image-transport-verification/v1"
TOOL_VERSION = "1"
CONSUMER_RECEIPT_FORMAT = "stateport.release-image-build-receipt/v1"
PRODUCER_RECEIPT_FORMAT = "stateport.producer-build-receipt/v1"
VISIBILITY_REVIEW_FORMAT = "stateport.registry-visibility-review/v1"

REGISTRY_HOST = "ghcr.io"
STORAGE_HOSTS = frozenset({"pkg-containers.githubusercontent.com"})
REGISTRY_BASE = f"https://{REGISTRY_HOST}"

MANIFEST_ACCEPT = (
    "application/vnd.oci.image.index.v1+json, "
    "application/vnd.oci.image.manifest.v1+json, "
    "application/vnd.docker.distribution.manifest.list.v2+json, "
    "application/vnd.docker.distribution.manifest.v2+json"
)

DEFAULT_MAX_REQUESTS = 400
DEFAULT_MIN_DELAY_S = 1.0
REQUEST_TIMEOUT_S = 30
MAX_REDIRECTS = 4
MAX_INDEX_DEPTH = 2
MANIFEST_MAX_BYTES = 4 * 1024 * 1024
TOKEN_MAX_BYTES = 256 * 1024
BLOB_PROBE_BYTES = 1024
CONFIG_MAX_BYTES = 64 * 1024 * 1024
ERROR_BODY_MAX_BYTES = 64 * 1024

_IMAGE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")
_REPOSITORY_PATH = re.compile(r"^[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)*$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SINGLE_BYTE_CONTENT_RANGE = re.compile(r"^bytes 0-0/([1-9][0-9]*)$")

_CREDENTIAL_ENV_VARS = (
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GHCR_TOKEN",
    "GH_ENTERPRISE_TOKEN",
    "GH_AUTH_TOKEN",
    "GITHUB_PAT",
    "CR_PAT",
    "REGISTRY_AUTH_FILE",
    "DOCKER_CONFIG",
    "DOCKER_AUTH_CONFIG",
    "PODMAN_AUTH_FILE",
    "CONTAINERS_AUTH_FILE",
)
_PROXY_ENV_VARS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
)
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_ABSENT_STATUSES = frozenset({401, 403, 404})


class ProbeError(RuntimeError):
    """Base class for verifier failures."""


class InputError(ProbeError):
    """A premise input is missing, malformed or inconsistent (blocked)."""


class TransportBlocked(ProbeError):
    """The transport or registry infrastructure cannot be trusted (blocked)."""


class BudgetExhausted(TransportBlocked):
    """The declared request budget is exhausted or a 429 was observed."""


class CredentialEnvironmentError(ProbeError):
    """A credential-bearing environment variable is present (refuse to run)."""


class _ProbeFailure(ProbeError):
    """One named probe found a premise failure for one image or negative."""

    def __init__(self, probe_id: str, message: str) -> None:
        super().__init__(f"{probe_id}: {message}")
        self.probe_id = probe_id
        self.message = message


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes
    url: str


@dataclass(frozen=True)
class ProbeResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes
    url: str
    http_requests: int
    redirects: int
    authorization: str


@dataclass(frozen=True)
class ExpectedImage:
    image_id: str
    role: str
    repository: str
    tag: str
    manifest_digest: str
    config_digest: str | None
    layer_digests: tuple[str, ...] | None
    source_reference: str


@dataclass(frozen=True)
class VisibilityReview:
    path: Path
    sha256: str
    private_digests: tuple[tuple[str, str], ...]
    private_packages: tuple[str, ...]


@dataclass(frozen=True)
class RunConfig:
    repository: str
    tag: str
    expectations_path: Path
    producer_receipt_path: Path
    private_review_path: Path
    receipt_out: Path
    max_requests: int = DEFAULT_MAX_REQUESTS
    min_delay_s: float = DEFAULT_MIN_DELAY_S
    index_mode_path: Path | None = None


class Transport(Protocol):
    def send(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        max_bytes: int,
    ) -> HttpResponse: ...


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _lower_headers(headers: Any) -> dict[str, str]:
    if headers is None:
        return {}
    return {str(key).lower(): str(value) for key, value in headers.items()}


def _observed_digest(body: bytes) -> str:
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _checked_digest(value: Any, description: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise InputError(f"{description} is not a lowercase sha256 digest: {value!r}")
    return value


def _checked_image_id(value: Any, description: str) -> str:
    if not isinstance(value, str) or _IMAGE_ID.fullmatch(value) is None:
        raise InputError(f"{description} is not a safe image identifier: {value!r}")
    return value


def _checked_tag(value: Any, description: str) -> str:
    if not isinstance(value, str) or _TAG.fullmatch(value) is None:
        raise InputError(f"{description} is not a valid registry tag: {value!r}")
    return value


def validate_repository(value: str) -> str:
    """Return ``ghcr.io/<owner>/<prefix>`` after strict anonymous-path checks."""

    if not isinstance(value, str) or not value or "://" in value:
        raise InputError(f"repository must be given as ghcr.io/<owner>/<prefix>: {value!r}")
    parts = urlsplit("https://" + value)
    try:
        port = parts.port
    except ValueError as exc:
        raise InputError(f"repository has an invalid port: {value!r}") from exc
    if (
        parts.scheme != "https"
        or parts.hostname != REGISTRY_HOST
        or port is not None
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
    ):
        raise InputError(f"repository must be exactly {REGISTRY_HOST}/<owner>/<prefix>: {value!r}")
    path = parts.path.strip("/")
    if _REPOSITORY_PATH.fullmatch(path) is None or "%" in path:
        raise InputError(f"repository path is unsafe or not lowercase: {value!r}")
    return f"{REGISTRY_HOST}/{path}"


def registry_path(repository: str) -> str:
    if not repository.startswith(REGISTRY_HOST + "/"):
        raise InputError(f"repository is not on {REGISTRY_HOST}: {repository!r}")
    path = repository[len(REGISTRY_HOST) + 1 :]
    if _REPOSITORY_PATH.fullmatch(path) is None:
        raise InputError(f"repository path is unsafe: {repository!r}")
    return path


def manifest_url(repository: str, reference: str) -> str:
    if not isinstance(reference, str) or not reference or "/" in reference or "@" in reference:
        raise InputError(f"manifest reference is not a single path segment: {reference!r}")
    if _DIGEST.fullmatch(reference) is None and _TAG.fullmatch(reference) is None:
        raise InputError(f"manifest reference is neither digest nor tag: {reference!r}")
    return f"{REGISTRY_BASE}/v2/{registry_path(repository)}/manifests/{reference}"


def blob_url(repository: str, digest: str) -> str:
    _checked_digest(digest, "blob digest")
    return f"{REGISTRY_BASE}/v2/{registry_path(repository)}/blobs/{digest}"


def mount_url(repository: str, digest: str, *, source: str) -> str:
    _checked_digest(digest, "cross-repo mount digest")
    query = urlencode({"mount": digest, "from": registry_path(source)})
    return f"{REGISTRY_BASE}/v2/{registry_path(repository)}/blobs/uploads/?{query}"


def _safe_registry_url(url: str, allowed_hosts: frozenset[str] | set[str]) -> str:
    parts = urlsplit(url)
    try:
        port = parts.port
    except ValueError as exc:
        raise TransportBlocked(f"registry URL has an invalid port: {url}") from exc
    if (
        parts.scheme != "https"
        or parts.hostname not in allowed_hosts
        or port not in {None, 443}
        or parts.username is not None
        or parts.password is not None
        or parts.fragment
    ):
        raise TransportBlocked(f"registry URL is outside the approved HTTPS hosts: {url}")
    return url


def _allowed_hosts(*, storage: bool) -> set[str]:
    hosts = {REGISTRY_HOST}
    if storage:
        hosts.update(STORAGE_HOSTS)
    return hosts


class UrllibTransport:
    """One raw HTTP exchange with redirects disabled at the urllib layer."""

    def send(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        max_bytes: int,
    ) -> HttpResponse:
        request = urllib.request.Request(url, data=body, headers=dict(headers), method=method)

        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, response_headers, newurl):  # noqa: ANN001
                return None

        opener = urllib.request.build_opener(_NoRedirect())
        try:
            response = opener.open(request, timeout=REQUEST_TIMEOUT_S)
        except urllib.error.HTTPError as exc:
            try:
                payload = exc.read(max_bytes + 1)
            finally:
                exc.close()
            return HttpResponse(
                status=int(exc.code),
                headers=_lower_headers(exc.headers),
                body=payload,
                url=url,
            )
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise TransportBlocked(f"registry request unavailable: {url}") from exc
        with response:
            payload = response.read(max_bytes + 1)
            status = int(response.status)
            response_headers = _lower_headers(response.headers)
        return HttpResponse(status=status, headers=response_headers, body=payload, url=url)


class ProbeSession:
    """Anonymous GHCR session: budget, throttle, redirects, bearer challenge."""

    def __init__(
        self,
        *,
        transport: Transport,
        max_requests: int,
        min_delay_s: float,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if max_requests < 1:
            raise InputError("--max-requests must be at least 1")
        if min_delay_s < 0:
            raise InputError("--min-delay-s must not be negative")
        self.transport = transport
        self.max_requests = max_requests
        self.min_delay_s = min_delay_s
        self.clock = clock
        self.sleep = sleep
        self.requests_used = 0
        self.started_at = clock()
        self._last_send_at: float | None = None
        self._tokens: dict[str, tuple[str, float, int | None]] = {}
        self.tokens_acquired: list[dict[str, Any]] = []
        self.token_denials: list[dict[str, Any]] = []
        self.rate_limit_observations: list[dict[str, Any]] = []
        self.requests_by_host: dict[str, int] = {}
        self.requests_by_method: dict[str, int] = {}

    # -- low level ---------------------------------------------------------

    def _send_one(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        max_bytes: int,
    ) -> HttpResponse:
        if self.requests_used >= self.max_requests:
            raise BudgetExhausted(
                f"request budget exhausted at {self.max_requests} requests before {method} {url}"
            )
        now = self.clock()
        if self._last_send_at is not None and self.min_delay_s > 0:
            wait = self.min_delay_s - (now - self._last_send_at)
            if wait > 0:
                self.sleep(wait)
        self.requests_used += 1
        self._last_send_at = self.clock()
        host = urlsplit(url).hostname or ""
        self.requests_by_host[host] = self.requests_by_host.get(host, 0) + 1
        self.requests_by_method[method] = self.requests_by_method.get(method, 0) + 1
        response = self.transport.send(method, url, headers, body, max_bytes)
        if response.status == 429:
            observation = {
                "request": self.requests_used,
                "url": url,
                "retryAfter": response.headers.get("retry-after"),
            }
            self.rate_limit_observations.append(observation)
            raise BudgetExhausted(
                f"registry returned 429 at request {self.requests_used}; no retry is attempted"
            )
        if len(response.body) > max_bytes:
            raise TransportBlocked(f"registry response exceeded {max_bytes} bytes: {url}")
        return response

    def _send(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        max_bytes: int,
        token: str | None,
        *,
        storage: bool,
    ) -> tuple[HttpResponse, int, int]:
        current_url = url
        current_method = method
        current_body = body
        current_headers = dict(headers)
        if token is not None:
            current_headers["Authorization"] = "Bearer " + token
        sends = 0
        redirects = 0
        while True:
            _safe_registry_url(current_url, _allowed_hosts(storage=storage))
            response = self._send_one(
                current_method, current_url, current_headers, current_body, max_bytes
            )
            sends += 1
            if response.status not in _REDIRECT_STATUSES:
                return response, sends, redirects
            if redirects >= MAX_REDIRECTS:
                raise TransportBlocked(f"registry redirect chain is too long: {url}")
            location = response.headers.get("location")
            if not location:
                raise TransportBlocked(f"registry redirect without Location header: {current_url}")
            target = urlsplit(urljoin(current_url, location))
            _safe_registry_url(target.geturl(), _allowed_hosts(storage=storage))
            if target.hostname != urlsplit(current_url).hostname:
                current_headers = {
                    key: value
                    for key, value in current_headers.items()
                    if key.lower() != "authorization"
                }
            if response.status == 303 or (
                response.status in {301, 302} and current_method != "HEAD"
            ):
                current_method = "GET"
                current_body = None
            current_url = target.geturl()
            redirects += 1

    # -- bearer flow -------------------------------------------------------

    def _cached_token(self, scope_repository: str) -> str | None:
        cached = self._tokens.get(scope_repository)
        if cached is None:
            return None
        token, acquired_at, expires_in = cached
        if expires_in is not None and self.clock() - acquired_at > expires_in - 15:
            self._tokens.pop(scope_repository, None)
            return None
        return token

    def _acquire_token(
        self, challenge: str, scope_repository: str
    ) -> tuple[str | None, int | None]:
        try:
            token_url = _assembler._registry_token_url(challenge, repository=scope_repository)
        except _assembler.AssemblyError as exc:
            raise TransportBlocked(f"anonymous registry challenge is unusable: {exc}") from exc
        response, _sends, _redirects = self._send(
            "GET",
            token_url,
            {"Accept": "application/json"},
            None,
            TOKEN_MAX_BYTES,
            None,
            storage=False,
        )
        if response.status in {401, 403}:
            self.token_denials.append(
                {
                    "repository": scope_repository,
                    "status": response.status,
                    "atRequest": self.requests_used,
                }
            )
            return None, None
        if response.status != 200:
            raise TransportBlocked(
                f"anonymous token endpoint returned {response.status}: {token_url}"
            )
        try:
            document = json.loads(response.body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TransportBlocked("anonymous token response is malformed JSON") from exc
        if not isinstance(document, Mapping):
            raise TransportBlocked("anonymous token response is not a JSON object")
        token = document.get("token") or document.get("access_token")
        if not isinstance(token, str) or not token:
            raise TransportBlocked("anonymous token response has no bearer token")
        expires_in: int | None = None
        raw_expires = document.get("expires_in")
        if isinstance(raw_expires, bool) or not isinstance(raw_expires, int):
            if isinstance(raw_expires, str) and raw_expires.isdigit():
                expires_in = int(raw_expires)
            elif raw_expires is not None:
                raise TransportBlocked("anonymous token response has a malformed expires_in")
        else:
            expires_in = raw_expires
        if expires_in is not None and expires_in < 0:
            raise TransportBlocked("anonymous token response has a negative expires_in")
        self.tokens_acquired.append(
            {
                "repository": scope_repository,
                "expiresIn": expires_in,
                "atRequest": self.requests_used,
            }
        )
        if expires_in is not None and expires_in > 0:
            self._tokens[scope_repository] = (token, self.clock(), expires_in)
        return token, expires_in

    def request(
        self,
        method: str,
        url: str,
        *,
        scope_repository: str,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
        max_bytes: int = MANIFEST_MAX_BYTES,
        range_header: str | None = None,
    ) -> ProbeResponse:
        request_headers = dict(headers or {})
        if range_header is not None:
            request_headers["Range"] = range_header
        token = self._cached_token(scope_repository)
        response, sends, redirects = self._send(
            method, url, request_headers, body, max_bytes, token,
            storage=range_header is not None,
        )
        if response.status != 401:
            return ProbeResponse(
                status=response.status,
                headers=response.headers,
                body=response.body,
                url=response.url,
                http_requests=sends,
                redirects=redirects,
                authorization="bearer" if token else "none",
            )
        challenge = response.headers.get("www-authenticate")
        if not challenge:
            if token is not None:
                # The registry refused a token we already hold without issuing a
                # fresh challenge (for example an insufficient-scope refusal to a
                # cross-repository mount).  Surface the status; the caller decides.
                return ProbeResponse(
                    status=response.status,
                    headers=response.headers,
                    body=response.body,
                    url=response.url,
                    http_requests=sends,
                    redirects=redirects,
                    authorization="bearer",
                )
            raise TransportBlocked(
                "anonymous registry returned 401 without an auth challenge: " + url
            )
        self._tokens.pop(scope_repository, None)
        token, _expires = self._acquire_token(challenge, scope_repository)
        if token is None:
            return ProbeResponse(
                status=response.status,
                headers=response.headers,
                body=response.body,
                url=response.url,
                http_requests=sends,
                redirects=redirects,
                authorization="token-denied",
            )
        retry, retry_sends, retry_redirects = self._send(
            method, url, request_headers, body, max_bytes, token,
            storage=range_header is not None,
        )
        return ProbeResponse(
            status=retry.status,
            headers=retry.headers,
            body=retry.body,
            url=retry.url,
            http_requests=sends + retry_sends,
            redirects=redirects + retry_redirects,
            authorization="bearer",
        )

    def fetch_token_url(self, url: str) -> HttpResponse:
        """Read a token endpoint directly (anonymous; used for P12)."""

        response, _sends, _redirects = self._send(
            "GET", url, {"Accept": "application/json"}, None, TOKEN_MAX_BYTES, None,
            storage=False,
        )
        return response

    # -- snapshots ---------------------------------------------------------

    def budget_snapshot(self) -> dict[str, Any]:
        return {
            "maxRequests": self.max_requests,
            "minDelaySeconds": self.min_delay_s,
            "requestsUsed": self.requests_used,
            "elapsedSeconds": round(self.clock() - self.started_at, 3),
            "requestsByHost": dict(sorted(self.requests_by_host.items())),
            "requestsByMethod": dict(sorted(self.requests_by_method.items())),
            "any429": bool(self.rate_limit_observations),
        }

    def rate_limit_snapshot(self) -> dict[str, Any]:
        return {
            "any429": bool(self.rate_limit_observations),
            "observations": list(self.rate_limit_observations),
        }

    def authentication_snapshot(self) -> dict[str, Any]:
        return {
            "method": "anonymous-bearer-challenge-only",
            "tokensAcquired": list(self.tokens_acquired),
            "tokenDenials": list(self.token_denials),
        }


def _load_json_file(
    path: Path, *, description: str, maximum_bytes: int = 64 * 1024 * 1024
) -> Mapping[str, Any]:
    candidate = path.expanduser()
    if (
        candidate.is_symlink()
        or not candidate.is_file()
        or candidate.stat().st_size > maximum_bytes
    ):
        raise InputError(f"{description} is missing, unsafe or too large: {path}")
    try:
        value = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InputError(f"{description} is not valid UTF-8 JSON: {path}") from exc
    if not isinstance(value, Mapping):
        raise InputError(f"{description} is not a JSON object: {path}")
    return value


def _file_binding(path: Path) -> dict[str, Any]:
    candidate = path.expanduser().resolve()
    if candidate.is_symlink() or not candidate.is_file():
        raise InputError(f"input file is missing or unsafe: {path}")
    return {"path": str(candidate), "sha256": _sha256_file(candidate)}


def _accepted_reference_parts(reference: Any, description: str) -> tuple[str, str]:
    if not isinstance(reference, str):
        raise InputError(f"{description} is not a string: {reference!r}")
    name, separator, digest = reference.partition("@")
    if not separator or "/" not in name or _DIGEST.fullmatch(digest) is None:
        raise InputError(f"{description} is not an exact name@sha256 reference: {reference!r}")
    return name, digest


def load_consumer_images(
    document: Mapping[str, Any], *, repository: str, tag: str
) -> list[ExpectedImage]:
    if document.get("formatVersion") != CONSUMER_RECEIPT_FORMAT:
        raise InputError("expectations are not a stateport release image build receipt")
    identity = document.get("identity")
    if not isinstance(identity, Mapping) or identity.get("version") != tag:
        observed = identity.get("version") if isinstance(identity, Mapping) else None
        raise InputError(f"build receipt version {observed!r} does not match --tag {tag!r}")
    images = document.get("images")
    if not isinstance(images, Mapping) or not images:
        raise InputError("build receipt has no images")
    expected: list[ExpectedImage] = []
    for raw_id, image in images.items():
        image_id = _checked_image_id(raw_id, "build receipt image ID")
        if not isinstance(image, Mapping):
            raise InputError(f"build receipt image is malformed: {image_id}")
        authority = image.get("releaseAuthority")
        if not isinstance(authority, Mapping):
            raise InputError(f"build receipt image has no releaseAuthority: {image_id}")
        manifest_digest = _checked_digest(
            authority.get("manifestDigest"), f"{image_id} releaseAuthority manifestDigest"
        )
        accepted = image.get("acceptedReference")
        if accepted is not None:
            _name, accepted_digest = _accepted_reference_parts(
                accepted, f"{image_id} acceptedReference"
            )
            if accepted_digest != manifest_digest:
                raise InputError(
                    f"{image_id} acceptedReference digest disagrees with its releaseAuthority"
                )
        config_digest = authority.get("configDigest")
        if config_digest is not None:
            config_digest = _checked_digest(
                config_digest, f"{image_id} releaseAuthority configDigest"
            )
        raw_layers = authority.get("layerDigests")
        layer_digests: tuple[str, ...] | None = None
        if raw_layers is not None:
            if not isinstance(raw_layers, list) or not raw_layers:
                raise InputError(
                    f"{image_id} releaseAuthority layerDigests is not a non-empty list"
                )
            layer_digests = tuple(
                _checked_digest(item, f"{image_id} releaseAuthority layer digest")
                for item in raw_layers
            )
        expected.append(
            ExpectedImage(
                image_id=image_id,
                role="consumer",
                repository=f"{repository}/{image_id}",
                tag=tag,
                manifest_digest=manifest_digest,
                config_digest=config_digest,
                layer_digests=layer_digests,
                source_reference=(
                    str(accepted) if accepted is not None else f"{image_id}@{manifest_digest}"
                ),
            )
        )
    return expected


def load_producer_image(
    document: Mapping[str, Any], *, repository: str, tag: str
) -> ExpectedImage:
    if document.get("formatVersion") != PRODUCER_RECEIPT_FORMAT:
        raise InputError("producer receipt is not a stateport producer-build-receipt/v1")
    if document.get("result") != "succeeded":
        raise InputError("producer receipt did not succeed")
    name, digest = _accepted_reference_parts(
        document.get("acceptedReference"), "producer acceptedReference"
    )
    manifest_digest = _checked_digest(document.get("manifestDigest"), "producer manifestDigest")
    if manifest_digest != digest:
        raise InputError("producer manifestDigest disagrees with its acceptedReference")
    platform_digest = document.get("platformManifestDigest")
    if platform_digest is not None and platform_digest != manifest_digest:
        raise InputError("producer platformManifestDigest disagrees with its manifestDigest")
    image_id = _checked_image_id(name.rsplit("/", 1)[-1], "producer image ID")
    expected_repository = f"{repository}/{image_id}"
    if name.startswith(REGISTRY_HOST + "/") and name != expected_repository:
        raise InputError(
            f"producer acceptedReference is on {REGISTRY_HOST} but not at the reviewed path: {name}"
        )
    return ExpectedImage(
        image_id=image_id,
        role="provider",
        repository=expected_repository,
        tag=tag,
        manifest_digest=manifest_digest,
        config_digest=None,
        layer_digests=None,
        source_reference=name + "@" + digest,
    )


def load_visibility_review(path: Path, *, repository: str) -> VisibilityReview:
    document = _load_json_file(path, description="registry visibility review")
    if document.get("formatVersion") != VISIBILITY_REVIEW_FORMAT:
        raise InputError("visibility review does not declare the reviewed formatVersion")
    reviewed_repository = document.get("repository")
    if not isinstance(reviewed_repository, str) or not reviewed_repository:
        raise InputError("visibility review must declare the repository it is bound to")
    if reviewed_repository != repository:
        raise InputError("visibility review is bound to a different repository")
    raw_digests = document.get("privateDigests")
    if not isinstance(raw_digests, list) or not raw_digests:
        raise InputError("visibility review must declare a non-empty privateDigests list")
    private_digests: list[tuple[str, str]] = []
    for index, entry in enumerate(raw_digests):
        if not isinstance(entry, Mapping):
            raise InputError(f"privateDigests[{index}] is not an object")
        name, digest = _accepted_reference_parts(
            entry.get("reference"), f"privateDigests[{index}].reference"
        )
        if not name.startswith(REGISTRY_HOST + "/"):
            raise InputError(f"privateDigests[{index}] is not on {REGISTRY_HOST}")
        registry_path(f"{REGISTRY_HOST}/{name[len(REGISTRY_HOST) + 1:]}")
        private_digests.append((name, digest))
    raw_packages = document.get("privatePackages")
    if not isinstance(raw_packages, list) or not raw_packages:
        raise InputError("visibility review must declare a non-empty privatePackages list")
    private_packages: list[str] = []
    for index, entry in enumerate(raw_packages):
        if not isinstance(entry, Mapping):
            raise InputError(f"privatePackages[{index}] is not an object")
        package = entry.get("repository")
        if not isinstance(package, str) or not package.startswith(REGISTRY_HOST + "/"):
            raise InputError(f"privatePackages[{index}].repository is not a {REGISTRY_HOST} path")
        registry_path(package)
        private_packages.append(package)
    resolved = path.expanduser().resolve()
    return VisibilityReview(
        path=resolved,
        sha256=_sha256_file(resolved),
        private_digests=tuple(private_digests),
        private_packages=tuple(private_packages),
    )


def load_index_mode(path: Path) -> dict[str, Any]:
    """Record a lane-6 signed-index input without binding it yet."""

    binding = _file_binding(path)
    document = _load_json_file(path, description="signed release index")
    binding.update(
        {
            "formatVersion": document.get("formatVersion"),
            "bound": False,
            "note": (
                "lane-6 signed-index digest binding is not implemented; the file digest is "
                "recorded for continuity and the run does not treat it as authority"
            ),
        }
    )
    return binding


def _descriptor(entry: Any, description: str) -> tuple[str, int]:
    if not isinstance(entry, Mapping):
        raise _ProbeFailure("P4", f"{description} is not an object")
    digest = entry.get("digest")
    if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
        raise _ProbeFailure("P4", f"{description} has an invalid digest")
    size = entry.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or size < 1:
        raise _ProbeFailure("P4", f"{description} has an invalid size")
    media_type = entry.get("mediaType")
    if media_type is not None and not isinstance(media_type, str):
        raise _ProbeFailure("P4", f"{description} has an invalid mediaType")
    return digest, size


def _fetch_manifest_chain(
    session: ProbeSession, image: ExpectedImage
) -> tuple[Mapping[str, Any], int, str]:
    """Fetch the expected manifest, recursing through a bounded index."""

    digest = image.manifest_digest
    seen = {digest}
    depth = 0
    while True:
        response = session.request(
            "GET",
            manifest_url(image.repository, digest),
            scope_repository=registry_path(image.repository),
            headers={"Accept": MANIFEST_ACCEPT},
            max_bytes=MANIFEST_MAX_BYTES,
        )
        if response.status != 200:
            raise _ProbeFailure(
                "P1",
                f"manifest {digest} returned HTTP {response.status} "
                f"(authorization={response.authorization})",
            )
        body = response.body
        observed = _observed_digest(body)
        header = response.headers.get("docker-content-digest")
        if observed != digest or header != digest:
            raise _ProbeFailure(
                "P1",
                f"manifest digest disagrees: body {observed}, header {header!r}, "
                f"expected {digest}",
            )
        try:
            manifest = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _ProbeFailure("P1", "manifest is not valid JSON") from exc
        if not isinstance(manifest, Mapping) or manifest.get("schemaVersion") != 2:
            raise _ProbeFailure("P1", "manifest is not a schemaVersion 2 object")
        raw_index = manifest.get("manifests")
        if raw_index is None:
            return manifest, depth, digest
        if (
            not isinstance(raw_index, list)
            or not raw_index
            or not all(isinstance(item, Mapping) for item in raw_index)
        ):
            raise _ProbeFailure("P3", "manifest index contains malformed entries")
        candidates = [
            item
            for item in raw_index
            if isinstance(item.get("platform"), Mapping)
            and item["platform"].get("os") == "linux"
            and item["platform"].get("architecture") == "amd64"
        ]
        if len(candidates) != 1:
            raise _ProbeFailure("P3", "manifest index has no unique linux/amd64 manifest")
        nested = candidates[0].get("digest")
        if not isinstance(nested, str) or _DIGEST.fullmatch(nested) is None:
            raise _ProbeFailure("P3", "manifest index has an invalid nested digest")
        if depth + 1 > MAX_INDEX_DEPTH:
            raise _ProbeFailure("P3", f"manifest index nesting exceeds {MAX_INDEX_DEPTH}")
        if nested in seen:
            raise _ProbeFailure("P3", "manifest index repeats a digest")
        seen.add(nested)
        depth += 1
        digest = nested


def _probe_image(session: ProbeSession, image: ExpectedImage) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "imageId": image.image_id,
        "role": image.role,
        "repository": image.repository,
        "reference": f"{image.repository}@{image.manifest_digest}",
        "sourceReference": image.source_reference,
        "tag": image.tag,
        "expectedDigest": image.manifest_digest,
        "configDigest": image.config_digest,
        "layerDigests": list(image.layer_digests) if image.layer_digests is not None else None,
        "resolvedDigest": None,
        "resolvedTagDigest": None,
        "indexDepth": None,
        "platformLeafDigest": None,
        "config": None,
        "layers": [],
        "probes": [],
        "result": "passed",
        "failure": None,
    }

    def record(probe_id: str, status: str, detail: str) -> None:
        entry["probes"].append({"id": probe_id, "status": status, "detail": detail})

    try:
        manifest, depth, leaf_digest = _fetch_manifest_chain(session, image)
        entry["resolvedDigest"] = image.manifest_digest
        entry["indexDepth"] = depth
        entry["platformLeafDigest"] = leaf_digest if depth > 0 else None
        record(
            "P1",
            "passed",
            f"manifest {image.manifest_digest} readable; body hash and Docker-Content-Digest agree",
        )
        record("P3", "passed" if depth > 0 else "not-applicable", f"index recursion depth {depth}")
        record(
            "P7",
            "passed",
            f"registry digest equals receipt references ({image.source_reference})",
        )

        tag_response = session.request(
            "GET",
            manifest_url(image.repository, image.tag),
            scope_repository=registry_path(image.repository),
            headers={"Accept": MANIFEST_ACCEPT},
            max_bytes=MANIFEST_MAX_BYTES,
        )
        if tag_response.status != 200:
            raise _ProbeFailure(
                "P2", f"tag {image.tag} returned HTTP {tag_response.status}"
            )
        tag_observed = _observed_digest(tag_response.body)
        tag_header = tag_response.headers.get("docker-content-digest")
        if tag_observed != image.manifest_digest or tag_header != image.manifest_digest:
            raise _ProbeFailure(
                "P2",
                f"tag {image.tag} resolves to body {tag_observed}, header {tag_header!r}, "
                f"expected {image.manifest_digest}",
            )
        entry["resolvedTagDigest"] = tag_header
        record("P2", "passed", f"tag {image.tag} resolves to {tag_header}")

        config_digest, config_size = _descriptor(manifest.get("config"), "config descriptor")
        layers: list[dict[str, Any]] = []
        for index, raw_layer in enumerate(manifest.get("layers") or []):
            digest, size = _descriptor(raw_layer, f"layer descriptor #{index}")
            layers.append({"digest": digest, "size": size})
        if not layers:
            raise _ProbeFailure("P4", "manifest has no layers")
        record("P4", "passed", f"{len(layers)} layer descriptor(s) validated")

        if image.config_digest is not None and image.config_digest != config_digest:
            raise _ProbeFailure(
                "P8",
                f"releaseAuthority configDigest {image.config_digest} != manifest {config_digest}",
            )
        if image.layer_digests is not None:
            observed_layers = tuple(layer["digest"] for layer in layers)
            if observed_layers != image.layer_digests:
                raise _ProbeFailure(
                    "P8", "releaseAuthority layerDigests do not match the manifest layers"
                )
        record(
            "P8",
            "passed"
            if (image.config_digest is not None or image.layer_digests is not None)
            else "not-applicable",
            "releaseAuthority bindings agree"
            if (image.config_digest is not None or image.layer_digests is not None)
            else "receipt carries no config/layer digest bindings for this image",
        )

        if config_size > CONFIG_MAX_BYTES:
            raise _ProbeFailure(
                "P5", f"config size {config_size} exceeds the {CONFIG_MAX_BYTES}-byte bound"
            )
        config_response = session.request(
            "GET",
            blob_url(image.repository, config_digest),
            scope_repository=registry_path(image.repository),
            headers={"Accept": "application/octet-stream"},
            max_bytes=config_size + 1,
            range_header=f"bytes=0-{config_size - 1}",
        )
        if config_response.status not in {200, 206}:
            raise _ProbeFailure(
                "P5", f"config blob returned HTTP {config_response.status}"
            )
        if len(config_response.body) != config_size:
            raise _ProbeFailure(
                "P5",
                f"config blob served {len(config_response.body)} bytes, expected {config_size}",
            )
        observed_config = _observed_digest(config_response.body)
        if observed_config != config_digest:
            raise _ProbeFailure(
                "P5",
                f"config blob hashes to {observed_config}, expected {config_digest}",
            )
        if config_response.status == 206:
            expected_range = f"bytes 0-{config_size - 1}/{config_size}"
            if config_response.headers.get("content-range") != expected_range:
                raise _ProbeFailure(
                    "P5",
                    f"config Content-Range {config_response.headers.get('content-range')!r} "
                    f"!= {expected_range!r}",
                )
        entry["config"] = {
            "digest": config_digest,
            "size": config_size,
            "status": config_response.status,
            "bytesFetched": len(config_response.body),
            "digestVerified": True,
            "rangeHonored": config_response.status == 206,
            "requests": config_response.http_requests,
        }
        record(
            "P5",
            "passed",
            f"config blob {config_digest} digest-verified "
            f"({config_size} bytes, rangeHonored={config_response.status == 206})",
        )

        for layer in layers:
            response = session.request(
                "GET",
                blob_url(image.repository, layer["digest"]),
                scope_repository=registry_path(image.repository),
                range_header="bytes=0-0",
                max_bytes=BLOB_PROBE_BYTES,
            )
            entry["layers"].append(
                {
                    "digest": layer["digest"],
                    "size": layer["size"],
                    "status": response.status,
                    "contentRange": response.headers.get("content-range"),
                    "rangeHonored": response.status == 206,
                    "requests": response.http_requests,
                }
            )
            if response.status != 206:
                raise _ProbeFailure(
                    "P6",
                    f"layer {layer['digest']} Range probe returned HTTP {response.status}",
                )
            if len(response.body) != 1:
                raise _ProbeFailure(
                    "P6",
                    f"layer {layer['digest']} Range probe served {len(response.body)} bytes",
                )
            match = _SINGLE_BYTE_CONTENT_RANGE.fullmatch(
                response.headers.get("content-range", "")
            )
            if match is None or int(match.group(1)) != layer["size"]:
                raise _ProbeFailure(
                    "P6",
                    f"layer {layer['digest']} Content-Range is not bytes 0-0/{layer['size']}",
                )
        record("P6", "passed", f"{len(layers)} layer Range probe(s) exact")
    except _ProbeFailure as exc:
        record(exc.probe_id, "failed", exc.message)
        entry["result"] = "failed"
        entry["failure"] = str(exc)
    return entry


def _absent_seed(repository: str, tag: str, excluded: set[str]) -> str:
    seed = f"stateport-anonymous-absence-probe:{repository}:{tag}".encode("utf-8")
    counter = 0
    digest = _observed_digest(seed)
    while digest in excluded:
        counter += 1
        digest = _observed_digest(seed + str(counter).encode("ascii"))
    return digest


def _negative_outcome(entry: dict[str, Any], response: Any) -> dict[str, Any]:
    if response.status == 200:
        entry["result"] = "failed"
        entry["detail"] = "an anonymous caller received a 200 response"
    elif response.status not in _ABSENT_STATUSES:
        entry["result"] = "failed"
        entry["detail"] = f"unexpected HTTP {response.status} for a negative reference"
    return entry


def _probe_absent_digest(
    session: ProbeSession, repository: str, tag: str, excluded: set[str]
) -> dict[str, Any]:
    digest = _absent_seed(repository, tag, excluded)
    response = session.request(
        "GET",
        manifest_url(repository, digest),
        scope_repository=registry_path(repository),
        headers={"Accept": MANIFEST_ACCEPT},
        max_bytes=MANIFEST_MAX_BYTES,
    )
    served = len(response.body) if response.status == 200 else 0
    entry = {
        "digest": digest,
        "status": response.status,
        "authorization": response.authorization,
        "bytesServed": served,
        "bodyDigest": _observed_digest(response.body) if response.status == 200 else None,
        "result": "passed",
        "detail": None,
    }
    return _negative_outcome(entry, response)


def _probe_absent_tag(session: ProbeSession, repository: str, tag: str) -> dict[str, Any]:
    absent_tag = "stateport-absence-" + _observed_digest(
        f"stateport-anonymous-absence-tag:{repository}:{tag}".encode("utf-8")
    ).split(":", 1)[1][:12]
    response = session.request(
        "GET",
        manifest_url(repository, absent_tag),
        scope_repository=registry_path(repository),
        headers={"Accept": MANIFEST_ACCEPT},
        max_bytes=MANIFEST_MAX_BYTES,
    )
    served = len(response.body) if response.status == 200 else 0
    entry = {
        "tag": absent_tag,
        "status": response.status,
        "authorization": response.authorization,
        "bytesServed": served,
        "result": "passed",
        "detail": None,
    }
    return _negative_outcome(entry, response)


def _probe_private_digest(
    session: ProbeSession, name: str, digest: str
) -> dict[str, Any]:
    response = session.request(
        "GET",
        manifest_url(name, digest),
        scope_repository=registry_path(name),
        headers={"Accept": MANIFEST_ACCEPT},
        max_bytes=MANIFEST_MAX_BYTES,
    )
    served = len(response.body) if response.status == 200 else 0
    body_digest = _observed_digest(response.body) if response.status == 200 else None
    entry = {
        "reference": f"{name}@{digest}",
        "status": response.status,
        "authorization": response.authorization,
        "bytesServed": served,
        "bodyDigest": body_digest,
        "contentMatchesPrivateDigest": body_digest == digest,
        "result": "passed",
        "detail": None,
    }
    return _negative_outcome(entry, response)


def _private_package_token_url(package: str) -> str:
    challenge = (
        f'Bearer realm="https://{REGISTRY_HOST}/token",service="{REGISTRY_HOST}"'
    )
    try:
        return _assembler._registry_token_url(challenge, repository=registry_path(package))
    except _assembler.AssemblyError as exc:
        raise TransportBlocked(f"private package token URL is unusable: {exc}") from exc


def _probe_private_package(session: ProbeSession, package: str) -> dict[str, Any]:
    response = session.fetch_token_url(_private_package_token_url(package))
    entry: dict[str, Any] = {
        "repository": package,
        "status": response.status,
        "tokenGranted": False,
        "expiresIn": None,
        "result": "passed",
        "detail": None,
    }
    if response.status == 200:
        entry["tokenGranted"] = True
        entry["result"] = "failed"
        entry["detail"] = "an anonymous pull token was granted for a reviewed private package"
        try:
            document = json.loads(response.body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            document = None
        if isinstance(document, Mapping):
            expires = document.get("expires_in")
            if isinstance(expires, int) and not isinstance(expires, bool):
                entry["expiresIn"] = expires
    elif response.status not in {401, 403}:
        entry["result"] = "failed"
        entry["detail"] = f"unexpected HTTP {response.status} from the token endpoint"
    return entry


def _probe_cross_repo_mount(
    session: ProbeSession, images: list[Mapping[str, Any]]
) -> dict[str, Any]:
    with_layers = [entry for entry in images if entry.get("layers")]
    if len(with_layers) < 2:
        return {
            "result": "not-applicable",
            "detail": "fewer than two probed images carry layers",
            "targetRepository": None,
            "fromRepository": None,
            "digest": None,
            "status": None,
            "bytesServed": 0,
        }
    source, target = with_layers[0], with_layers[1]
    digest = source["layers"][0]["digest"]
    response = session.request(
        "POST",
        mount_url(target["repository"], digest, source=source["repository"]),
        scope_repository=registry_path(target["repository"]),
        max_bytes=ERROR_BODY_MAX_BYTES,
    )
    served = len(response.body) if response.status in {201, 202} else 0
    entry = {
        "targetRepository": target["repository"],
        "fromRepository": source["repository"],
        "digest": digest,
        "status": response.status,
        "authorization": response.authorization,
        "bytesServed": served,
        "uploadSessionCreated": response.status in {201, 202},
        "result": "passed",
        "detail": None,
    }
    if response.status in {201, 202}:
        entry["result"] = "failed"
        entry["detail"] = (
            "anonymous cross-repository mount was accepted "
            f"(HTTP {response.status}); no upload was finalized"
        )
    elif response.status not in {401, 403}:
        entry["result"] = "failed"
        entry["detail"] = f"unexpected HTTP {response.status} for a refused mount"
    return entry


def _credential_variables(environ: Mapping[str, Any]) -> list[str]:
    upper = {str(name).upper() for name in environ}
    return sorted({name for name in _CREDENTIAL_ENV_VARS if name in upper})


def _proxy_variables(environ: Mapping[str, Any]) -> list[str]:
    found: list[str] = []
    for name, value in environ.items():
        normalized = str(name).upper()
        if normalized in _PROXY_ENV_VARS and str(value):
            found.append(normalized)
    return sorted(set(found))


def _negative_probe_status(entry: Mapping[str, Any] | None, *, blocked: bool) -> str:
    if entry is None:
        return "blocked" if blocked else "not-run"
    result = str(entry.get("result"))
    if result == "not-applicable":
        return "not-applicable"
    return result


def run_verification(
    config: RunConfig,
    *,
    transport: Transport,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    environ: Mapping[str, Any] | None = None,
    tool_sha256: str | None = None,
) -> dict[str, Any]:
    """Run every probe and return the receipt document (never written here)."""

    environment = dict(os.environ) if environ is None else dict(environ)
    tool_path = Path(__file__).resolve()
    if tool_sha256 is None:
        tool_sha256 = _sha256_file(tool_path)
    try:
        tool_name = str(tool_path.relative_to(ROOT))
    except ValueError:
        tool_name = str(tool_path)

    receipt: dict[str, Any] = {
        "formatVersion": FORMAT_VERSION,
        "observedAt": _utc_now(),
        "version": config.tag,
        "repository": config.repository,
        "tool": {"path": tool_name, "version": TOOL_VERSION, "sha256": tool_sha256},
        "credentials": "none",
        "environment": {"credentialVariables": [], "proxyVariables": []},
        "expectations": {
            "buildReceipt": None,
            "producerBuildReceipt": None,
            "privateReview": None,
            "indexMode": None,
        },
        "budget": None,
        "images": [],
        "negatives": {
            "absentDigest": None,
            "absentTag": None,
            "privateDigests": [],
            "privateTokenDenials": [],
            "crossRepoMount": None,
        },
        "rateLimit": {"any429": False, "observations": []},
        "authentication": None,
        "probes": [],
        "skippedProbes": [
            {
                "id": "P16",
                "reason": (
                    "tag-absence preflight is a push-side responsibility; the authenticated "
                    "push path must prove the target tag was free before publication"
                ),
            }
        ],
        "failures": [],
        "result": "passed",
        "blockedReason": None,
    }

    session: ProbeSession | None = None
    credentials_cleared = False
    budget_blocked = False

    try:
        credential_names = _credential_variables(environment)
        if credential_names:
            raise CredentialEnvironmentError(
                "credential environment variables are set: " + ", ".join(credential_names)
            )
        proxy_names = _proxy_variables(environment)
        if proxy_names:
            raise InputError(
                "proxy environment variables are set ("
                + ", ".join(proxy_names)
                + "); anonymous direct transport cannot be proven"
            )
        credentials_cleared = True
        receipt["environment"] = {
            "credentialVariables": [],
            "proxyVariables": [],
        }

        receipt["expectations"]["buildReceipt"] = _file_binding(config.expectations_path)
        receipt["expectations"]["producerBuildReceipt"] = _file_binding(
            config.producer_receipt_path
        )
        receipt["expectations"]["privateReview"] = _file_binding(config.private_review_path)
        if config.index_mode_path is not None:
            receipt["expectations"]["indexMode"] = load_index_mode(config.index_mode_path)

        consumer_document = _load_json_file(
            config.expectations_path, description="build receipt"
        )
        images = load_consumer_images(
            consumer_document, repository=config.repository, tag=config.tag
        )
        producer_document = _load_json_file(
            config.producer_receipt_path, description="producer build receipt"
        )
        provider = load_producer_image(
            producer_document, repository=config.repository, tag=config.tag
        )
        if provider.image_id in {image.image_id for image in images}:
            raise InputError(
                f"producer image ID collides with a consumer image ID: {provider.image_id}"
            )
        review = load_visibility_review(config.private_review_path, repository=config.repository)

        session = ProbeSession(
            transport=transport,
            max_requests=config.max_requests,
            min_delay_s=config.min_delay_s,
            clock=clock,
            sleep=sleep,
        )
        expected_digests = {image.manifest_digest for image in images} | {
            provider.manifest_digest
        }

        for image in (*images, provider):
            entry = _probe_image(session, image)
            receipt["images"].append(entry)
            if entry["result"] != "passed":
                receipt["failures"].append(f"{image.image_id}: {entry['failure']}")

        digest_anchor = images[0].repository
        receipt["negatives"]["absentDigest"] = _probe_absent_digest(
            session, digest_anchor, config.tag, expected_digests
        )
        receipt["negatives"]["absentTag"] = _probe_absent_tag(
            session, digest_anchor, config.tag
        )
        receipt["negatives"]["privateDigests"] = [
            _probe_private_digest(session, name, digest)
            for name, digest in review.private_digests
        ]
        receipt["negatives"]["privateTokenDenials"] = [
            _probe_private_package(session, package) for package in review.private_packages
        ]
        receipt["negatives"]["crossRepoMount"] = _probe_cross_repo_mount(
            session, list(receipt["images"])
        )
    except CredentialEnvironmentError:
        raise
    except BudgetExhausted as exc:
        budget_blocked = True
        receipt["result"] = "blocked"
        receipt["blockedReason"] = str(exc)
    except (InputError, TransportBlocked) as exc:
        receipt["result"] = "blocked"
        receipt["blockedReason"] = str(exc)
    finally:
        if session is not None:
            receipt["budget"] = session.budget_snapshot()
            receipt["rateLimit"] = session.rate_limit_snapshot()
            receipt["authentication"] = session.authentication_snapshot()

    blocked = receipt["result"] == "blocked"
    negatives = receipt["negatives"]
    if not blocked:
        for index, entry in enumerate(negatives["privateDigests"]):
            if entry["result"] != "passed":
                receipt["failures"].append(
                    f"privateDigests[{index}] {entry['reference']}: {entry['detail']}"
                )
        for index, entry in enumerate(negatives["privateTokenDenials"]):
            if entry["result"] != "passed":
                receipt["failures"].append(
                    f"privateTokenDenials[{index}] {entry['repository']}: {entry['detail']}"
                )
        for name in ("absentDigest", "absentTag", "crossRepoMount"):
            entry = negatives[name]
            if entry is not None and entry["result"] not in {"passed", "not-applicable"}:
                receipt["failures"].append(f"{name}: {entry.get('detail')}")
        receipt["result"] = "failed" if receipt["failures"] else "passed"

    receipt["probes"] = [
        {
            "id": "P9",
            "status": _negative_probe_status(negatives["absentDigest"], blocked=blocked),
            "detail": "absent digest is not anonymously readable",
        },
        {
            "id": "P10",
            "status": _negative_probe_status(negatives["absentTag"], blocked=blocked),
            "detail": "absent tag is not anonymously readable",
        },
        {
            "id": "P11",
            "status": (
                "blocked"
                if blocked
                else (
                    "failed"
                    if any(item["result"] != "passed" for item in negatives["privateDigests"])
                    else "passed"
                )
            ),
            "detail": f"{len(negatives['privateDigests'])} reviewed private digest(s) stayed unreadable",
        },
        {
            "id": "P12",
            "status": (
                "blocked"
                if blocked
                else (
                    "failed"
                    if any(
                        item["result"] != "passed"
                        for item in negatives["privateTokenDenials"]
                    )
                    else "passed"
                )
            ),
            "detail": f"{len(negatives['privateTokenDenials'])} private package token denial(s)",
        },
        {
            "id": "P13",
            "status": _negative_probe_status(negatives["crossRepoMount"], blocked=blocked),
            "detail": "anonymous cross-repository mount refused",
        },
        {
            "id": "P14",
            "status": "blocked" if budget_blocked else ("passed" if session else "not-run"),
            "detail": (
                "budget or rate limit stopped the run"
                if budget_blocked
                else "request budget and minimum delay held"
            ),
        },
        {
            "id": "P15",
            "status": "passed" if credentials_cleared else "blocked",
            "detail": "no credential variable was present; receipt records credentials=none",
        },
        {
            "id": "P17",
            "status": "passed",
            "detail": f"tool sha256 {tool_sha256} and version {TOOL_VERSION} recorded",
        },
        {
            "id": "P18",
            "status": "not-evaluated-in-band",
            "detail": (
                "the writer enforces create-only mode 0600 with a same-directory temporary "
                "and an atomic no-clobber link; covered by the tool's unit tests"
            ),
        },
    ]
    return receipt


def write_receipt_create_only(path: Path, receipt: Mapping[str, Any]) -> Path:
    """Write one receipt without ever replacing an existing file."""

    target = path.expanduser()
    if not target.is_absolute():
        target = target.resolve()
    if target.is_symlink():
        raise InputError(f"receipt path is a symlink: {target}")
    parent = target.parent
    parent_descriptor = os.open(
        parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        try:
            os.stat(target.name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise InputError(f"receipt already exists; refusing to overwrite: {target}")
        payload = (
            json.dumps(receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("utf-8")
        temp_name = f".{target.name}.tmp-{os.getpid()}-{secrets.token_hex(6)}"
        descriptor = os.open(
            temp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_descriptor,
        )
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("receipt write made no progress")
                view = view[written:]
            os.fsync(descriptor)
            observed = os.fstat(descriptor)
            if not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1:
                raise OSError("receipt temporary is not a singly linked regular file")
        finally:
            os.close(descriptor)
        try:
            os.link(temp_name, target.name, src_dir_fd=parent_descriptor, dst_dir_fd=parent_descriptor)
        except FileExistsError as exc:
            raise InputError(
                f"receipt appeared concurrently; refusing to overwrite: {target}"
            ) from exc
        finally:
            try:
                os.unlink(temp_name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
        os.fsync(parent_descriptor)
        final = os.stat(target.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1:
            raise OSError("receipt is not a singly linked regular file")
        mode = stat.S_IMODE(final.st_mode)
        if mode != 0o600:
            raise OSError(f"receipt mode is {oct(mode)}, expected 0o600")
    finally:
        os.close(parent_descriptor)
    return target


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify anonymous public GHCR transport for one StatePort release candidate "
            "without any credential."
        )
    )
    parser.add_argument("--expectations", required=True, help="release image build receipt")
    parser.add_argument("--producer-receipt", required=True, help="producer build receipt")
    parser.add_argument("--repository", required=True, help="ghcr.io/<owner>/<prefix>")
    parser.add_argument("--tag", required=True, help="release version tag")
    parser.add_argument("--private-review", required=True, help="registry visibility review JSON")
    parser.add_argument("--receipt-out", required=True, help="create-only receipt output path")
    parser.add_argument("--max-requests", type=int, default=DEFAULT_MAX_REQUESTS)
    parser.add_argument("--min-delay-s", type=float, default=DEFAULT_MIN_DELAY_S)
    parser.add_argument(
        "--index-mode",
        default=None,
        help="optional signed release index (lane-6 binding; recorded, not yet bound)",
    )
    return parser.parse_args(argv)


def main(
    argv: list[str] | None = None,
    *,
    transport_factory: Callable[[], Transport] | None = None,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    environ: Mapping[str, Any] | None = None,
) -> int:
    args = _parse_args(argv)
    try:
        repository = validate_repository(args.repository)
        tag = _checked_tag(args.tag, "--tag")
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return 2
    config = RunConfig(
        repository=repository,
        tag=tag,
        expectations_path=Path(args.expectations),
        producer_receipt_path=Path(args.producer_receipt),
        private_review_path=Path(args.private_review),
        receipt_out=Path(args.receipt_out),
        max_requests=args.max_requests,
        min_delay_s=args.min_delay_s,
        index_mode_path=Path(args.index_mode) if args.index_mode else None,
    )
    factory = transport_factory if transport_factory is not None else (lambda: UrllibTransport())
    try:
        receipt = run_verification(
            config,
            transport=factory(),
            clock=clock,
            sleep=sleep,
            environ=environ,
        )
    except CredentialEnvironmentError as exc:
        print(f"refusing anonymous transport: {exc}", file=sys.stderr)
        return 2
    try:
        write_receipt_create_only(config.receipt_out, receipt)
    except (InputError, OSError) as exc:
        print(f"cannot write receipt: {exc}", file=sys.stderr)
        return 2
    budget = receipt.get("budget") or {}
    print(
        json.dumps(
            {
                "result": receipt["result"],
                "receipt": str(config.receipt_out.expanduser()),
                "requestsUsed": budget.get("requestsUsed"),
            }
        )
    )
    return {"passed": 0, "failed": 1, "blocked": 2}[receipt["result"]]


if __name__ == "__main__":
    raise SystemExit(main())




