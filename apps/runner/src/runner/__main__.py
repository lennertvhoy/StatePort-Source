"""Container-friendly CLI for the deterministic StatePort runner."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from runner import run_instance


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="stateport-runner")
    parser.add_argument(
        "instance",
        nargs="?",
        default=os.environ.get("STATEPORT_INSTANCE_PATH", "/stateport/instance"),
    )
    parser.add_argument(
        "--template",
        default=os.environ.get("STATEPORT_TEMPLATE_PATH"),
    )
    args = parser.parse_args(argv)
    result = run_instance(
        Path(args.instance),
        template_path_override=Path(args.template) if args.template else None,
    )
    print(
        json.dumps(
            {
                "ok": result.ok,
                "status": result.status,
                "logs": list(result.logs),
                "errors": list(result.errors),
            },
            sort_keys=True,
        )
    )
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
