#!/usr/bin/env python3
"""Run application-experience validation with one-line failure output."""

from __future__ import annotations

import sys

from validate_application_experience import validate


def main() -> int:
    try:
        counts = validate()
    except Exception as exc:  # noqa: BLE001 - diagnostic boundary
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print("PASS " + " ".join(f"{key}={value}" for key, value in counts.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
