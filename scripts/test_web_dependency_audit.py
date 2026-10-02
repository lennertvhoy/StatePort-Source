from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

from validate_web_dependency_audit import (  # noqa: E402
    POLICY_PATH,
    WebDependencyAuditError,
    validate_browser_data_policy,
    validate_report,
    validate_reports,
)


NOW = datetime(2026, 8, 1, 8, 0, tzinfo=timezone.utc)

# The exact bounded exception shape accepted while the React Router RSC
# advisory is live. The canonical policy currently carries no exception; this
# fixture proves the parser still honours an active, evidence-backed one.
ROUTER_EXCEPTION = {
    "advisoryId": "GHSA-qwww-vcr4-c8h2",
    "source": 1124282,
    "package": "react-router",
    "propagatedPackage": "react-router-dom",
    "severity": "high",
    "title": "React Router: RSC Mode CSRF Bypass Allows Action Execution Before 400 Response",
    "url": "https://github.com/advisories/GHSA-qwww-vcr4-c8h2",
    "range": ">=7.12.0 <8.3.0",
    "expiresAt": "2026-08-12T00:00:00Z",
    "applicability": "not_applicable_unstable_rsc_apis_absent",
    "scanRoot": "apps/web",
    "forbiddenMarkers": [
        "@vitejs/plugin-rsc",
        "@react-router/dev/vite",
        "react-router/dom",
        "unstable_reactRouterRSC",
        "unstable_RSCRouteConfig",
        "unstable_routeRSCServerRequest",
        "unstable_RSCStaticRouter",
        "unstable_matchRSCServerRequest",
        "unstable_createCallServer",
        "unstable_getRSCStream",
        "unstable_RSCHydratedRouter",
        "unstable_RSCPayload",
    ],
    "reason": "The upstream advisory explicitly applies only to unstable React Server Components APIs. StatePort is a client-side Vite application and the applicability scan fails if any RSC dependency, entry point, or unstable React Router RSC API appears.",
}


def _report() -> dict[str, object]:
    return {
        "auditReportVersion": 2,
        "vulnerabilities": {
            "react-router": {
                "name": "react-router",
                "severity": "high",
                "isDirect": False,
                "via": [{
                    "source": 1124282,
                    "name": "react-router",
                    "dependency": "react-router",
                    "title": "React Router: RSC Mode CSRF Bypass Allows Action Execution Before 400 Response",
                    "url": "https://github.com/advisories/GHSA-qwww-vcr4-c8h2",
                    "severity": "high",
                    "cwe": ["CWE-352"],
                    "cvss": {"score": 0, "vectorString": None},
                    "range": ">=7.12.0 <8.3.0",
                }],
                "effects": ["react-router-dom"],
                "range": "7.12.0 - 8.2.0",
                "nodes": ["node_modules/react-router"],
                "fixAvailable": {"name": "react-router-dom", "version": "7.11.0", "isSemVerMajor": True},
            },
            "react-router-dom": {
                "name": "react-router-dom",
                "severity": "high",
                "isDirect": True,
                "via": ["react-router"],
                "effects": [],
                "range": ">=7.12.0-pre.0",
                "nodes": ["node_modules/react-router-dom"],
                "fixAvailable": {"name": "react-router-dom", "version": "7.11.0", "isSemVerMajor": True},
            },
        },
        "metadata": {"vulnerabilities": {"info": 0, "low": 0, "moderate": 0, "high": 2, "critical": 0, "total": 2}},
    }


def _clean_report() -> dict[str, object]:
    return {
        "auditReportVersion": 2,
        "vulnerabilities": {},
        "metadata": {"vulnerabilities": {"info": 0, "low": 0, "moderate": 0, "high": 0, "critical": 0, "total": 0}},
    }


def _scan_root(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    web = root / "apps" / "web"
    (web / "src").mkdir(parents=True)
    (web / "src" / "App.tsx").write_text("import { HashRouter } from 'react-router-dom'\n", encoding="utf-8")
    (web / "package.json").write_text(json.dumps({"dependencies": {"react-router-dom": "^7.18.1"}}), encoding="utf-8")
    return root


def _browser_policy(tmp_path: Path) -> tuple[Path, Path]:
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    lock_path = tmp_path / "package-lock.json"
    lock_path.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/baseline-browser-mapping": {"version": "2.11.9"},
                    "node_modules/caniuse-lite": {"version": "1.0.30001806"},
                },
            }
        ),
        encoding="utf-8",
    )
    return policy_path, lock_path


def _router_policy(tmp_path: Path) -> Path:
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    policy["exceptions"] = [deepcopy(ROUTER_EXCEPTION)]
    policy_path = tmp_path / "router-policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    return policy_path


def test_exact_non_applicable_advisory_is_accepted_before_expiry(tmp_path: Path) -> None:
    assert (
        validate_report(_report(), now=NOW, root=_scan_root(tmp_path), policy_path=_router_policy(tmp_path))
        == "GHSA-qwww-vcr4-c8h2"
    )


def test_exception_expires_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(WebDependencyAuditError, match="expired"):
        validate_report(
            _report(),
            now=datetime(2026, 8, 12, tzinfo=timezone.utc),
            root=_scan_root(tmp_path),
            policy_path=_router_policy(tmp_path),
        )


def test_rsc_marker_makes_exception_inapplicable(tmp_path: Path) -> None:
    root = _scan_root(tmp_path)
    (root / "apps" / "web" / "src" / "entry.rsc.tsx").write_text(
        "import { unstable_matchRSCServerRequest } from 'react-router'\n", encoding="utf-8"
    )
    with pytest.raises(WebDependencyAuditError, match="applicability marker"):
        validate_report(_report(), now=NOW, root=root, policy_path=_router_policy(tmp_path))


def test_any_additional_or_stale_advisory_fails_closed(tmp_path: Path) -> None:
    report = _report()
    vulnerabilities = report["vulnerabilities"]
    assert isinstance(vulnerabilities, dict)
    vulnerabilities["brace-expansion"] = {
        "name": "brace-expansion", "severity": "high", "isDirect": False,
        "via": [], "effects": [], "nodes": ["node_modules/brace-expansion"],
    }
    counts = report["metadata"]["vulnerabilities"]  # type: ignore[index]
    counts["high"] = 3  # type: ignore[index]
    counts["total"] = 3  # type: ignore[index]
    with pytest.raises(WebDependencyAuditError, match="unapproved vulnerability set"):
        validate_report(report, now=NOW, root=_scan_root(tmp_path), policy_path=_router_policy(tmp_path))


def test_advisory_propagation_change_fails_closed(tmp_path: Path) -> None:
    report = deepcopy(_report())
    report["vulnerabilities"]["react-router"]["effects"] = ["react-router-dom", "another-package"]  # type: ignore[index]
    with pytest.raises(WebDependencyAuditError, match="propagation shape changed"):
        validate_report(report, now=NOW, root=_scan_root(tmp_path), policy_path=_router_policy(tmp_path))


def test_reported_advisory_without_active_exception_fails_closed(tmp_path: Path) -> None:
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    policy_path = tmp_path / "zero-exception-policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    with pytest.raises(WebDependencyAuditError, match="without an active, bounded exception"):
        validate_report(_report(), now=NOW, root=_scan_root(tmp_path), policy_path=policy_path)


def test_clean_report_does_not_consume_exception(tmp_path: Path) -> None:
    assert validate_report(_clean_report(), now=NOW, root=_scan_root(tmp_path)) == "clean"


def test_complete_and_production_audits_must_agree(tmp_path: Path) -> None:
    with pytest.raises(WebDependencyAuditError, match="disagree"):
        validate_reports(_report(), _clean_report(), now=NOW, root=_scan_root(tmp_path))


def test_canonical_policy_carries_no_stale_exception() -> None:
    # The audit is clean, so the policy must not consume or carry any
    # exception; a bounded exception is added back only while one is active.
    value = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    assert value["exceptions"] == []


def test_reviewed_browser_data_versions_are_accepted(tmp_path: Path) -> None:
    policy_path, lock_path = _browser_policy(tmp_path)
    assert validate_browser_data_policy(
        now=NOW, policy_path=policy_path, lock_path=lock_path
    ) == {
        "baseline-browser-mapping": "2.11.9",
        "caniuse-lite": "1.0.30001806",
    }


def test_stale_browser_data_version_fails_closed(tmp_path: Path) -> None:
    policy_path, lock_path = _browser_policy(tmp_path)
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    lock["packages"]["node_modules/caniuse-lite"]["version"] = "1.0.30001762"
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    with pytest.raises(WebDependencyAuditError, match="below the reviewed minimum"):
        validate_browser_data_policy(now=NOW, policy_path=policy_path, lock_path=lock_path)


def test_browser_data_review_expiry_fails_closed(tmp_path: Path) -> None:
    policy_path, lock_path = _browser_policy(tmp_path)
    with pytest.raises(WebDependencyAuditError, match="review has expired"):
        validate_browser_data_policy(
            now=datetime(2026, 11, 1, tzinfo=timezone.utc),
            policy_path=policy_path,
            lock_path=lock_path,
        )
