from __future__ import annotations

from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
for path in sorted((ROOT / "packages").glob("*/src")) + [ROOT / "apps/runner/src"]:
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from stateport_persistent_app.service_process import (  # noqa: E402
    _expected_web_source_identity,
)


COMMIT = "a" * 40
TREE = "b" * 40
OTHER_COMMIT = "c" * 40
OTHER_TREE = "d" * 40
REPO_ROOT = {"gitHead": COMMIT, "gitTree": TREE}


def test_source_checkout_binds_marker_to_product_root_git_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("STATEPORT_PACKAGED_PRODUCT", raising=False)
    assert _expected_web_source_identity(REPO_ROOT) == (COMMIT, TREE)


def test_packaged_image_binds_marker_to_baked_source_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STATEPORT_PACKAGED_PRODUCT", "1")
    monkeypatch.setenv("STATEPORT_BUILD_SOURCE_COMMIT", OTHER_COMMIT)
    monkeypatch.setenv("STATEPORT_BUILD_SOURCE_TREE", OTHER_TREE)
    assert _expected_web_source_identity(REPO_ROOT) == (OTHER_COMMIT, OTHER_TREE)


def test_packaged_image_without_baked_identity_stays_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STATEPORT_PACKAGED_PRODUCT", "1")
    monkeypatch.delenv("STATEPORT_BUILD_SOURCE_COMMIT", raising=False)
    monkeypatch.delenv("STATEPORT_BUILD_SOURCE_TREE", raising=False)
    assert _expected_web_source_identity(REPO_ROOT) == ("unknown", "unknown")


def test_packaged_image_refuses_half_unknown_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STATEPORT_PACKAGED_PRODUCT", "1")
    monkeypatch.setenv("STATEPORT_BUILD_SOURCE_COMMIT", OTHER_COMMIT)
    monkeypatch.delenv("STATEPORT_BUILD_SOURCE_TREE", raising=False)
    with pytest.raises(ValueError, match="both be exact or both be unknown"):
        _expected_web_source_identity(REPO_ROOT)


def test_packaged_image_refuses_non_exact_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STATEPORT_PACKAGED_PRODUCT", "1")
    monkeypatch.setenv("STATEPORT_BUILD_SOURCE_COMMIT", "main")
    monkeypatch.setenv("STATEPORT_BUILD_SOURCE_TREE", OTHER_TREE)
    with pytest.raises(ValueError, match="not exact"):
        _expected_web_source_identity(REPO_ROOT)
