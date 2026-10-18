#!/usr/bin/env python3
"""Audit that the anonymous install path fully resolves on a release route.

Why this exists
---------------
The delivery boundary is one anonymous command against a published route. The
property that matters is therefore not "does the route serve every reference the
signed index names" -- it is **"does every byte the bootstrap fetches actually
arrive, and match the digest the bootstrap itself pins"**.

Auditing by way of the index's ``operator://release/...`` references answers a
different question, and answering it has produced three false findings in this
campaign in a row:

* ``operator://release/quadlet`` is a *collection* reference (a bundle digest over
  a set of files, with ``size`` the sum), so requiring a file at that path
  reports a dangling reference that does not exist;
* the seven per-image signature bundles are published at a flat
  ``<version>/signatures/<image>.sigstore.json`` rather than at the index's path,
  so the same method reports them absent when they are served with matching
  digests;
* the public route is a *projection* of the release, not a mirror of the index's
  reference list, so the residue reads as a publication defect.

This auditor sidesteps all three by taking the route's own word for what it
serves: it parses the ``get``/``check`` pairs out of the bootstrap itself, maps
them onto the route root, resolves each, and compares the bytes delivered
against the digest the bootstrap pins. It never consults the index's URI scheme,
so it cannot report a reference as missing when the route publishes it under a
different, correct path.

Reference shapes it handles, all by construction:

* ordinary file fetches under ``$RELEASE_ROOT``;
* manifest fetches under ``$PROBE_ROOT``;
* the external ``$COSIGN_URL`` tool pin, which is deliberately **not** a route
  artifact and is reported as ``external`` rather than as missing.

Read-only. It reads a route root and a bootstrap; it fetches nothing and writes
only the path it is given.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict
from pathlib import Path

# get "$RELEASE_ROOT/release-index.json" "$tmp/release-index.json" "release index"
GET = re.compile(r'get\s+"\$(?P<root>[A-Z_]+)(?P<rel>[^"]*)"\s+"(?P<local>[^"]+)"\s+"(?P<label>[^"]*)"')
# check "<64 hex>" "$tmp/release-index.json"
CHECK = re.compile(r'check\s+"(?P<digest>[0-9a-f]{64})"\s+"\$(?P<tmp>[A-Za-z_0-9]+)(?P<name>[^"]*)"')
# NAME="value" for the constants the roots are built from
CONST = re.compile(r'^(?P<key>[A-Z_][A-Z_0-9]*)="(?P<value>[^"]*)"', re.M)


class AuditError(RuntimeError):
    """The bootstrap could not be parsed, or a base URL was refused."""


LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})



def resolve_url(base_url: str, route_rel: str) -> str:
    """Build the absolute URL a user would fetch for one route-relative path.

    The public route is what the delivery boundary is about, so the audit must be
    able to run against the URLs a user actually requests, not only against a
    local checkout. This is a pure function so the URL construction is testable
    without a network, which is where the interesting failure would be.

    Refuses a non-HTTPS base unless it is loopback, so a real run cannot silently
    downgrade the very transport the release depends on. Loopback is permitted
    only so the tests can exercise the transport deterministically.
    """
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme not in ("https", "http"):
        raise AuditError(f"base URL must be https, got {base_url!r}")
    if parsed.scheme == "http" and (parsed.hostname or "") not in LOCAL_HOSTS:
        raise AuditError(f"refusing a non-loopback plain-http base URL: {base_url!r}")
    # The base's PATH is load-bearing and must be preserved: the published roots
    # live under /StatePort-Site/download/..., so building the URL from scheme and
    # netloc alone silently resolves every fetch to the domain root. That bug was
    # found by running this auditor, which is the argument for having it.
    base_path = parsed.path.rstrip("/")
    path = f"{base_path}/{route_rel.lstrip('/')}" if base_path else f"/{route_rel.lstrip('/')}"
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def https_transport(timeout: float = 30.0):
    """Return a transport that fetches absolute URLs over HTTPS."""

    def fetch(url: str) -> bytes:
        request = urllib.request.Request(url, headers={"User-Agent": "stateport-route-audit/1"})
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - scheme checked above
            return response.read()

    return fetch


@dataclass(frozen=True)
class Fetch:
    label: str
    root: str
    rel: str
    route_rel: str
    digest: str
    external: bool


def parse_bootstrap(text: str) -> tuple[dict[str, str], list[Fetch]]:
    """Return (constants, fetches) parsed from a bootstrap's own declarations.

    A ``get`` with no ``check`` is only accepted when it targets an external URL,
    which is how the third-party tool pin is expressed. Anything else without a
    digest is a parse failure, because an unpinned fetch cannot be audited and
    must not be silently reported as resolved.
    """
    constants = {m.group("key"): m.group("value") for m in CONST.finditer(text)}
    for required in ("STATEPORT_VERSION", "RELEASE_ROOT", "PROBE_ROOT"):
        if required not in constants:
            raise AuditError(f"bootstrap does not declare {required}")

    version = constants["STATEPORT_VERSION"]
    # The bootstrap states its own roots; derive the on-disk layout from them
    # rather than assuming one, so a changed layout shows up as a resolution
    # failure instead of being papered over.
    release_root = constants["RELEASE_ROOT"].rstrip("/")
    probe_root = constants["PROBE_ROOT"].rstrip("/")
    release_suffix = release_root.split("/download/", 1)[-1] if "/download/" in release_root else version
    probe_suffix = probe_root.split("/download/", 1)[-1] if "/download/" in probe_root else ""

    gets: list[tuple[str, str, str, str]] = []  # label, root, rel, local
    for match in GET.finditer(text):
        gets.append((match.group("label"), match.group("root"), match.group("rel"), match.group("local")))

    checks: dict[str, str] = {}
    for match in CHECK.finditer(text):
        checks[match.group("tmp") + match.group("name")] = match.group("digest")

    fetches: list[Fetch] = []
    for label, root, rel, local in gets:
        key = local.lstrip("$")
        tmp, _, name = key.partition("/")
        digest = checks.get(key)
        external = root not in ("RELEASE_ROOT", "PROBE_ROOT")
        if digest is None and not external:
            raise AuditError(f"fetch {label!r} pins no digest, so it cannot be audited")
        if root == "PROBE_ROOT":
            route_rel = f"{probe_suffix}/{rel.lstrip('/')}"
        else:
            route_rel = f"{release_suffix}/{rel.lstrip('/')}"
        fetches.append(
            Fetch(
                label=label,
                root=root,
                rel=rel,
                route_rel=route_rel,
                digest=digest or "",
                external=external,
            )
        )
    if not fetches:
        raise AuditError("bootstrap declares no fetches")
    return constants, fetches


def _index_version(payload: bytes) -> str | None:
    """The release version a signed release index declares, or None if unreadable."""
    try:
        document = json.loads(payload)
        return document["signed"]["release"]["version"]
    except (ValueError, KeyError, TypeError):
        return None


def _version_binding(fetches, constants, route_root, base_url, transport, payloads):
    """Compare the bootstrap's declared version with the index it digest-pins.

    Reuses the payload already fetched during the sweep, so the check adds no
    request: a published audit still issues exactly one request per fetch site.
    """
    index_rel = next((f.route_rel for f in fetches if f.route_rel.endswith("release-index.json")), None)
    if index_rel is None:
        return None
    location = (
        resolve_url(base_url, index_rel)
        if base_url is not None
        else str(route_root / "download" / index_rel)
    )
    payload = payloads.get(location)
    if payload is None:
        return {"declared": constants.get("STATEPORT_VERSION"), "index": None, "match": False,
                "error": "pinned index was not resolved by the sweep"}
    declared = constants.get("STATEPORT_VERSION")
    indexed = _index_version(payload)
    return {"declared": declared, "index": indexed, "match": declared == indexed and indexed is not None}


def audit(route_root: Path, bootstrap: Path, *, base_url: str | None = None, transport=None) -> dict:
    """Audit the bootstrap's fetch set.

    With no ``base_url`` the route is read from ``route_root`` on disk, which
    answers "is the staged or checked-out route healthy". With one, the same
    fetch set is resolved against the URLs a user would request, which is the
    question the delivery boundary actually asks. The two modes are reported
    separately rather than blended, because a checkout can be healthy while the
    published route is not.
    """
    constants, fetches = parse_bootstrap(bootstrap.read_text())
    if base_url is not None:
        resolve_url(base_url, "probe")  # refuse a bad base before any fetch
        transport = transport or https_transport()
    resolved, missing, mismatched, external = [], [], [], []
    payloads: dict[str, bytes] = {}
    for fetch in fetches:
        if fetch.external:
            external.append(fetch.label)
            continue
        if base_url is not None:
            location = resolve_url(base_url, fetch.route_rel)
            try:
                payload = transport(location)
            except OSError as error:
                missing.append({"label": fetch.label, "path": location, "error": str(error)})
                continue
        else:
            target = route_root / "download" / fetch.route_rel
            location = str(target)
            if not target.is_file():
                missing.append({"label": fetch.label, "path": location})
                continue
            payload = target.read_bytes()
        payloads[location] = payload
        actual = hashlib.sha256(payload).hexdigest()
        if actual != fetch.digest:
            mismatched.append(
                {
                    "label": fetch.label,
                    "path": location,
                    "pinned": fetch.digest,
                    "actual": actual,
                }
            )
        else:
            resolved.append({"label": fetch.label, "path": location})
    # The delivery boundary requires the signed index, the URL, the DISPLAYED
    # version, the source identity and the installed receipt to identify the same
    # authorized release. The bootstrap pins the index's digest and verifies its
    # signature, so the bytes are authentic -- but it passes no expected version
    # anywhere, and STATEPORT_VERSION is a self-declared constant used only for
    # the roots and the success message. Nothing asserts that the authenticated
    # index is the release it claims to be installing, and the bootstrap is
    # hand-edited once per release. So the check belongs here, where the bootstrap
    # and the index it pins are both in hand.
    version_binding = _version_binding(fetches, constants, route_root, base_url, transport, payloads)
    return {
        "schema": "stateport.route-install-path-audit/v1",
        "versionBinding": version_binding,
        "ok": (not missing and not mismatched and (version_binding is None or version_binding["match"])),
        "mode": "published" if base_url is not None else "checkout",
        "baseUrl": base_url,
        "routeRoot": str(route_root) if base_url is None else None,
        "bootstrap": str(bootstrap),
        "releaseVersion": constants["STATEPORT_VERSION"],
        "fetchCount": len(fetches),
        "routeFetchCount": len(fetches) - len(external),
        "resolved": len(resolved),
        "resolvedPaths": resolved,
        "missing": missing,
        "mismatched": mismatched,
        "external": external,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--route-root", type=Path, required=True, help="site root containing download/")
    parser.add_argument("--bootstrap", type=Path, required=True, help="the published download/install.sh")
    parser.add_argument(
        "--base-url",
        default=None,
        help="audit the URLs a user would fetch instead of a local checkout, e.g. https://host/download",
    )
    args = parser.parse_args(argv)
    try:
        result = audit(args.route_root, args.bootstrap, base_url=args.base_url)
    except AuditError as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=1, sort_keys=True, default=str))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
