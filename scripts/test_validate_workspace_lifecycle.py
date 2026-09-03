#!/usr/bin/env python3
"""Static integration tests for the workspace lifecycle control boundary."""

from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

from validate_workspace_lifecycle import validate_workspace_lifecycle  # noqa: E402


def test_repository_workspace_lifecycle_contract_is_complete() -> None:
    assert validate_workspace_lifecycle(ROOT) == []
