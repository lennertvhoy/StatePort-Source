#!/usr/bin/env python3
"""Operator CLI for signed-release execution-host provisioning."""

from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "release-contracts" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "updater" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "execution-host" / "src"))

from stateport_release.execution_host_provisioning import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
