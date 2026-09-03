#!/usr/bin/env python3
"""Fail closed on high/critical web advisories with bounded exceptions.

The complete and production npm audits must agree. A clean audit needs and
consumes no exception. An exception is permitted only while it is active,
bounded, and evidence-backed: the React Router unstable-RSC advisory graph is
the only accepted shape, and only while the application contains none of the
affected RSC APIs and the dated exception remains live. Stale exceptions are
removed when an audit becomes clean; a clean audit never consumes an
exception.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
from typing import Mapping


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "config" / "web-dependency-audit-policy.v1.json"
WEB_ROOT = ROOT / "apps" / "web"
PACKAGE_LOCK_PATH = WEB_ROOT / "package-lock.json"
POLICY_SCHEMA = "stateport.web-dependency-audit-policy/v1"
ROUTER_ADVISORY = "GHSA-qwww-vcr4-c8h2"
ROUTER_GRAPH = {"react-router", "react-router-dom"}
COMMON_EXCEPTION_KEYS = {
    "advisoryId",
    "source",
    "package",
    "severity",
    "title",
    "url",
    "range",
    "expiresAt",
    "applicability",
    "reason",
}
ROUTER_EXCEPTION_KEYS = COMMON_EXCEPTION_KEYS | {
    "propagatedPackage",
    "scanRoot",
    "forbiddenMarkers",
}
BROWSER_DATA_KEYS = {"reviewedAt", "reviewExpiresAt", "minimumVersions"}
BROWSER_DATA_PACKAGES = {"baseline-browser-mapping", "caniuse-lite"}
TEXT_SUFFIXES = {".cjs", ".js", ".json", ".jsx", ".mjs", ".ts", ".tsx"}
EXCLUDED_DIRECTORIES = {
    ".git",
    "coverage",
    "dist",
    "dist-demo",
    "node_modules",
    "playwright-report",
    "test-results",
}


class WebDependencyAuditError(RuntimeError):
    """The audit report or its exception policy failed closed."""


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise WebDependencyAuditError(f"{label} must be an object")
    return value


def _nonempty_unique_strings(value: object, label: str) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
        or len(set(value)) != len(value)
    ):
        raise WebDependencyAuditError(f"{label} must be non-empty unique strings")
    return tuple(value)


def _utc_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise WebDependencyAuditError(f"{label} must be UTC")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise WebDependencyAuditError(f"{label} is invalid") from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise WebDependencyAuditError(f"{label} must be UTC")
    return parsed


def _expiry(value: object) -> datetime:
    return _utc_timestamp(value, "dependency-audit exception expiry")


def _load_policy(
    path: Path = POLICY_PATH,
) -> tuple[dict[str, Mapping[str, object]], Mapping[str, object]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise WebDependencyAuditError("web dependency audit policy is unreadable") from exc
    policy = _mapping(value, "policy")
    if set(policy) != {"schema", "browserData", "exceptions"} or policy.get("schema") != POLICY_SCHEMA:
        raise WebDependencyAuditError("web dependency audit policy has an invalid contract")
    browser_data = _mapping(policy.get("browserData"), "browser-data review")
    if set(browser_data) != BROWSER_DATA_KEYS:
        raise WebDependencyAuditError("browser-data review has an invalid contract")
    reviewed_at = _utc_timestamp(browser_data.get("reviewedAt"), "browser-data review time")
    review_expires_at = _utc_timestamp(
        browser_data.get("reviewExpiresAt"), "browser-data review expiry"
    )
    if reviewed_at >= review_expires_at:
        raise WebDependencyAuditError("browser-data review window is invalid")
    minimum_versions = _mapping(
        browser_data.get("minimumVersions"), "browser-data minimum versions"
    )
    if set(minimum_versions) != BROWSER_DATA_PACKAGES or any(
        not isinstance(version, str) or not version for version in minimum_versions.values()
    ):
        raise WebDependencyAuditError("browser-data minimum versions are invalid")
    raw_exceptions = policy.get("exceptions")
    if not isinstance(raw_exceptions, list) or len(raw_exceptions) > 1:
        raise WebDependencyAuditError("at most one current dependency-audit exception is permitted")
    if not raw_exceptions:
        return {}, browser_data
    router = _mapping(raw_exceptions[0], "React Router exception")
    if set(router) != ROUTER_EXCEPTION_KEYS or router.get("advisoryId") != ROUTER_ADVISORY:
        raise WebDependencyAuditError("React Router exception has an invalid shape or identity")
    expected = {
        "source": 1124282,
        "package": "react-router",
        "propagatedPackage": "react-router-dom",
        "severity": "high",
        "title": "React Router: RSC Mode CSRF Bypass Allows Action Execution Before 400 Response",
        "url": "https://github.com/advisories/GHSA-qwww-vcr4-c8h2",
        "range": ">=7.12.0 <8.3.0",
        "applicability": "not_applicable_unstable_rsc_apis_absent",
        "scanRoot": "apps/web",
    }
    for key, expected_value in expected.items():
        if router.get(key) != expected_value:
            raise WebDependencyAuditError(f"React Router exception {key} is invalid")
    _nonempty_unique_strings(router.get("forbiddenMarkers"), "React Router applicability markers")
    if not isinstance(router.get("reason"), str) or not str(router["reason"]).strip():
        raise WebDependencyAuditError("dependency-audit exception reason is required")
    _expiry(router.get("expiresAt"))
    return {ROUTER_ADVISORY: router}, browser_data


def _version_tuple(value: object, label: str) -> tuple[int, ...]:
    if not isinstance(value, str):
        raise WebDependencyAuditError(f"{label} version is invalid")
    parts = value.split(".")
    if len(parts) != 3 or any(not part.isdigit() for part in parts):
        raise WebDependencyAuditError(f"{label} version is invalid")
    return tuple(int(part) for part in parts)


def validate_browser_data_policy(
    *,
    now: datetime | None = None,
    policy_path: Path = POLICY_PATH,
    lock_path: Path = PACKAGE_LOCK_PATH,
) -> dict[str, str]:
    """Verify reviewed browser-compatibility data stays current and hash-locked."""

    _, browser_data = _load_policy(policy_path)
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise WebDependencyAuditError("browser-data validation clock must be timezone-aware")
    if current >= _utc_timestamp(
        browser_data["reviewExpiresAt"], "browser-data review expiry"
    ):
        raise WebDependencyAuditError("browser-data review has expired")
    try:
        lock = _mapping(
            json.loads(lock_path.read_text(encoding="utf-8")), "web package lock"
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise WebDependencyAuditError("web package lock is unreadable") from exc
    if lock.get("lockfileVersion") != 3:
        raise WebDependencyAuditError("web package lock version is unsupported")
    packages = _mapping(lock.get("packages"), "web package-lock packages")
    minimum_versions = _mapping(
        browser_data["minimumVersions"], "browser-data minimum versions"
    )
    observed: dict[str, str] = {}
    for package in sorted(BROWSER_DATA_PACKAGES):
        entry = _mapping(packages.get(f"node_modules/{package}"), f"{package} lock entry")
        version = entry.get("version")
        if _version_tuple(version, package) < _version_tuple(
            minimum_versions[package], f"{package} minimum"
        ):
            raise WebDependencyAuditError(f"{package} browser data is below the reviewed minimum")
        observed[package] = str(version)
    return observed


def _assert_router_applicability(exception: Mapping[str, object], *, root: Path = ROOT) -> None:
    scan_root = (root / str(exception["scanRoot"])).resolve()
    expected_root = (root / "apps" / "web").resolve()
    if scan_root != expected_root or not scan_root.is_dir() or scan_root.is_symlink():
        raise WebDependencyAuditError("dependency-audit applicability scan root is unsafe")
    markers = _nonempty_unique_strings(exception["forbiddenMarkers"], "React Router applicability markers")
    matches: list[str] = []
    for path in sorted(scan_root.rglob("*")):
        if not path.is_file() or path.is_symlink() or path.suffix not in TEXT_SUFFIXES:
            continue
        relative = path.relative_to(scan_root)
        if any(part in EXCLUDED_DIRECTORIES for part in relative.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise WebDependencyAuditError(f"could not inspect {relative.as_posix()}") from exc
        for marker in markers:
            if marker in text:
                matches.append(f"{relative.as_posix()}:{marker}")
    if matches:
        raise WebDependencyAuditError(
            "React Router RSC applicability marker found: " + ", ".join(matches[:5])
        )


def _report_vulnerabilities(report: Mapping[str, object]) -> Mapping[str, object]:
    if report.get("auditReportVersion") != 2:
        raise WebDependencyAuditError("npm audit report version is unsupported")
    vulnerabilities = _mapping(report.get("vulnerabilities"), "vulnerabilities")
    metadata = _mapping(report.get("metadata"), "metadata")
    counts = _mapping(metadata.get("vulnerabilities"), "metadata vulnerability counts")
    if counts.get("critical") != 0 or counts.get("high") != len(vulnerabilities) or counts.get("total") != len(vulnerabilities):
        raise WebDependencyAuditError("npm audit vulnerability counts changed")
    return vulnerabilities


def _assert_advisory(value: object, exception: Mapping[str, object]) -> None:
    advisory = _mapping(value, "react-router advisory")
    expected = {
        "source": exception["source"],
        "name": exception["package"],
        "dependency": exception["package"],
        "title": exception["title"],
        "url": exception["url"],
        "severity": exception["severity"],
        "cwe": ["CWE-352"],
        "range": exception["range"],
    }
    for key, expected_value in expected.items():
        if advisory.get(key) != expected_value:
            raise WebDependencyAuditError(f"react-router advisory {key} changed")


def _assert_router_group(vulnerabilities: Mapping[str, object], exception: Mapping[str, object]) -> None:
    if set(vulnerabilities) != ROUTER_GRAPH:
        raise WebDependencyAuditError("React Router advisory propagation set changed")
    router = _mapping(vulnerabilities["react-router"], "react-router vulnerability")
    if (
        router.get("name") != "react-router"
        or router.get("severity") != "high"
        or router.get("isDirect") is not False
        or router.get("effects") != ["react-router-dom"]
        or router.get("nodes") != ["node_modules/react-router"]
    ):
        raise WebDependencyAuditError("react-router advisory propagation shape changed")
    via = router.get("via")
    if not isinstance(via, list) or len(via) != 1:
        raise WebDependencyAuditError("react-router advisory sources changed")
    _assert_advisory(via[0], exception)
    propagated = _mapping(vulnerabilities["react-router-dom"], "react-router-dom vulnerability")
    if (
        propagated.get("name") != "react-router-dom"
        or propagated.get("severity") != "high"
        or propagated.get("isDirect") is not True
        or propagated.get("via") != ["react-router"]
        or propagated.get("effects") != []
        or propagated.get("nodes") != ["node_modules/react-router-dom"]
    ):
        raise WebDependencyAuditError("react-router-dom advisory propagation shape changed")


def validate_reports(
    full_report: Mapping[str, object],
    production_report: Mapping[str, object],
    *,
    now: datetime | None = None,
    root: Path = ROOT,
    policy_path: Path = POLICY_PATH,
) -> tuple[str, ...]:
    full = _report_vulnerabilities(full_report)
    production = _report_vulnerabilities(production_report)
    if not set(full).issubset(ROUTER_GRAPH) or not set(production).issubset(ROUTER_GRAPH):
        raise WebDependencyAuditError("npm audit contains an unapproved vulnerability set")
    if set(full) != set(production):
        raise WebDependencyAuditError("complete and production npm audits disagree")
    if full and set(full) != ROUTER_GRAPH:
        raise WebDependencyAuditError("React Router advisory graph is incomplete")
    policies, _ = _load_policy(policy_path)
    if not full:
        return ()
    if ROUTER_ADVISORY not in policies:
        raise WebDependencyAuditError(
            "React Router advisory reported without an active, bounded exception"
        )
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise WebDependencyAuditError("dependency-audit validation clock must be timezone-aware")
    router = policies[ROUTER_ADVISORY]
    if current >= _expiry(router["expiresAt"]):
        raise WebDependencyAuditError("React Router dependency-audit exception has expired")
    _assert_router_group(full, router)
    _assert_router_group(production, router)
    _assert_router_applicability(router, root=root)
    return (ROUTER_ADVISORY,)


def validate_report(
    report: Mapping[str, object],
    *,
    now: datetime | None = None,
    root: Path = ROOT,
    policy_path: Path = POLICY_PATH,
) -> str:
    accepted = validate_reports(report, report, now=now, root=root, policy_path=policy_path)
    return accepted[0] if accepted else "clean"


def _run_npm_audit(*, production_only: bool) -> tuple[int, Mapping[str, object]]:
    command = ["npm", "audit", "--json", "--audit-level=high"]
    if production_only:
        command.append("--omit=dev")
    completed = subprocess.run(
        command,
        cwd=WEB_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=240,
        shell=False,
    )
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise WebDependencyAuditError("npm audit did not return valid JSON") from exc
    return completed.returncode, _mapping(report, "npm audit report")


def _assert_returncode(returncode: int, report: Mapping[str, object], label: str) -> None:
    expected = 1 if _report_vulnerabilities(report) else 0
    if returncode != expected:
        raise WebDependencyAuditError(f"{label} npm audit returned an unexpected status")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate-policy-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        exceptions, browser_data = _load_policy()
        if exceptions:
            _assert_router_applicability(exceptions[ROUTER_ADVISORY])
        observed_browser_data = validate_browser_data_policy()
        if args.validate_policy_only:
            if exceptions:
                print(
                    "PASS: current web dependency exception, applicability boundary, "
                    f"and browser data are valid ({observed_browser_data}; review expires "
                    f"{browser_data['reviewExpiresAt']})"
                )
            else:
                print(
                    "PASS: no web dependency exception is active and browser data is "
                    f"valid ({observed_browser_data}; review expires "
                    f"{browser_data['reviewExpiresAt']})"
                )
            return 0
        full_code, full_report = _run_npm_audit(production_only=False)
        production_code, production_report = _run_npm_audit(production_only=True)
        _assert_returncode(full_code, full_report, "complete")
        _assert_returncode(production_code, production_report, "production")
        accepted = validate_reports(full_report, production_report)
        if not accepted:
            print("PASS: npm reports no high or critical dependency vulnerabilities")
            return 0
        expiry = exceptions[ROUTER_ADVISORY]["expiresAt"]
        print(
            "PASS: only the applicability-controlled React Router advisory remains "
            f"(expires {expiry}); browser data {observed_browser_data} is reviewed through "
            f"{browser_data['reviewExpiresAt']}"
        )
        return 0
    except (OSError, subprocess.SubprocessError, WebDependencyAuditError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
