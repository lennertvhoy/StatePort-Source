#!/usr/bin/env python3
"""Synthetic StateDD v5 compatibility adapter tests."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages/stateport-compat/src"))

from stateport_compat import CompatibilityError, load_statedd_assets, map_assets_to_stateport  # noqa: E402


def test_v2_maps_project_and_template_ownership_without_mutation() -> None:
    with tempfile.TemporaryDirectory(prefix="stateport-compat-") as raw:
        path = Path(raw) / "STATEDD_ASSETS.json"
        value = {
            "schema": "statedd.runtime_assets.v2",
            "template_version": "statedd-template-v5",
            "template_commit": "a" * 40,
            "profile": "solo",
            "managed_assets": [
                {"path": "README.md", "owner": "template", "merge_strategy": "replace-if-unmodified", "sensitivity": "public", "append_only": False},
                {"path": "WORKLOG.md", "owner": "project", "merge_strategy": "append-only", "sensitivity": "sensitive", "append_only": True},
            ],
            "retired_assets": [],
        }
        original = json.dumps(value, sort_keys=True)
        path.write_text(json.dumps(value), encoding="utf-8")
        result = map_assets_to_stateport(load_statedd_assets(path))
        assert [item["owner"] for item in result["files"]] == ["template", "instance"]
        assert result["files"][1]["merge"] == "append_only"
        assert json.dumps(json.loads(path.read_text()), sort_keys=True) == original


def test_malformed_or_unsafe_v5_payload_fails_closed() -> None:
    with tempfile.TemporaryDirectory(prefix="stateport-compat-") as raw:
        path = Path(raw) / "STATEDD_ASSETS.json"
        path.write_text(json.dumps({"schema": "unknown", "profile": "solo"}), encoding="utf-8")
        try:
            load_statedd_assets(path)
        except CompatibilityError:
            pass
        else:
            raise AssertionError("unknown StateDD schema accepted")

        path.write_text(
            json.dumps({"schema": "statedd.runtime_assets.v2", "template_version": "v5", "profile": "solo", "managed_assets": [{"path": "../secret", "owner": "template", "merge_strategy": "preserve", "sensitivity": "public", "append_only": False}]}),
            encoding="utf-8",
        )
        try:
            load_statedd_assets(path)
        except CompatibilityError:
            pass
        else:
            raise AssertionError("path traversal accepted")


if __name__ == "__main__":
    test_v2_maps_project_and_template_ownership_without_mutation()
    test_malformed_or_unsafe_v5_payload_fails_closed()
    print("PASS")
