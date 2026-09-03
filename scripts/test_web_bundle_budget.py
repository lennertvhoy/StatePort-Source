from __future__ import annotations

import json
from pathlib import Path

import pytest

from validate_web_bundle_budget import BundleBudgetError, inspect_bundle, load_policy


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "config" / "web-bundle-budget.v1.json"


def _fixture(tmp_path: Path, *, javascript_bytes: int = 20) -> Path:
    repository = tmp_path / "repository"
    dist = repository / "apps/web/dist/assets"
    dist.mkdir(parents=True)
    (dist.parent / "stateport-build.json").write_text("{}\n", encoding="utf-8")
    (dist / "index.js").write_bytes(b"j" * javascript_bytes)
    (dist / "index.css").write_bytes(b"c" * 10)
    return repository


def test_current_production_bundle_stays_within_reviewed_budget() -> None:
    report = inspect_bundle(ROOT, POLICY)
    assert report["violations"] == []
    assert report["totalBytes"] > 0


def test_oversized_asset_fails_with_exact_observation(tmp_path: Path) -> None:
    repository = _fixture(tmp_path, javascript_bytes=901)
    value = load_policy(POLICY)
    value["maximumJavaScriptAssetBytes"] = 900
    policy = tmp_path / "budget.json"
    policy.write_text(json.dumps(value), encoding="utf-8")
    report = inspect_bundle(repository, policy)
    assert report["violations"] == [
        {"kind": "js", "asset": "assets/index.js", "observedBytes": 901, "limitBytes": 900}
    ]


def test_missing_marker_and_path_escape_fail_closed(tmp_path: Path) -> None:
    repository = _fixture(tmp_path)
    (repository / "apps/web/dist/stateport-build.json").unlink()
    with pytest.raises(BundleBudgetError, match="incomplete"):
        inspect_bundle(repository, POLICY)
    value = load_policy(POLICY)
    value["distRoot"] = "../outside"
    policy = tmp_path / "budget.json"
    policy.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(BundleBudgetError, match="repository-relative"):
        load_policy(policy)
