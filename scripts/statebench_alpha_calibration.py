#!/usr/bin/env python3
"""Generate the deterministic, provider-free StateBench calibration report."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "statebench" / "src"))
sys.path.insert(0, str(ROOT / "packages" / "run-bundle" / "src"))

from statebench import generate_alpha_calibration  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = generate_alpha_calibration(args.output)
    print(f"{args.output / 'calibration.json'}")
    print(f"{args.output / 'calibration.md'}")
    print(f"cases={len(report.suite.cases)} results={len(report.results)} pairings={len(report.pairings)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
