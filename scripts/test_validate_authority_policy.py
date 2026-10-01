#!/usr/bin/env python3
"""Repository-level regression for the bounded-delegation validator."""

from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

from validate_authority_policy import validate_authority_policy  # noqa: E402


def test_repository_authority_contract_is_complete() -> None:
    assert validate_authority_policy(ROOT) == []
