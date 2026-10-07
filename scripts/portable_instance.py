from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
for relative in ("packages/portable-execution/src", "packages/instance-backup/src"):
    sys.path.insert(0, str(ROOT / relative))

from stateport_portable_execution import export_portable, import_portable, inspect_portable  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export or import a portable StatePort instance")
    sub = parser.add_subparsers(dest="command", required=True)
    export = sub.add_parser("export")
    export.add_argument("instance", type=Path)
    export.add_argument("archive", type=Path)
    inspect = sub.add_parser("inspect")
    inspect.add_argument("archive", type=Path)
    restore = sub.add_parser("import")
    restore.add_argument("archive", type=Path)
    restore.add_argument("destination", type=Path)
    restore.add_argument("--dry-run", action="store_true")
    restore.add_argument("--new-instance-id")
    args = parser.parse_args(argv)
    if args.command == "export":
        result = export_portable(args.instance, args.archive)
    elif args.command == "inspect":
        result = inspect_portable(args.archive)
    else:
        result = import_portable(args.archive, args.destination, dry_run=args.dry_run, new_instance_id=args.new_instance_id)
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
