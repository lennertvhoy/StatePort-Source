"""Verify complete preparation-context bytes, types, modes and safe links."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat


def inventory(root: Path) -> tuple[list, str]:
    rows = []

    def walk(path: Path) -> None:
        info = path.lstat()
        relative = path.relative_to(root).as_posix()
        # Bound separately by the caller's required receipt SHA-256. Including
        # the receipt in its own inventory would create a circular digest.
        if relative == 'consumer-context.json':
            return
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISDIR(info.st_mode):
            rows.append([relative, 'd', mode])
            for child in sorted(path.iterdir()):
                walk(child)
        elif stat.S_ISREG(info.st_mode):
            with path.open('rb') as stream:
                digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            rows.append([relative, 'f', mode, info.st_size, digest])
        elif stat.S_ISLNK(info.st_mode):
            target = os.readlink(path)
            if Path(target).is_absolute() or '..' in Path(target).parts:
                raise ValueError('escaping link: ' + relative)
            rows.append([relative, 'l', mode, target])
        else:
            raise ValueError('special file: ' + relative)

    walk(root)
    digest = hashlib.sha256(json.dumps(rows, separators=(',', ':')).encode()).hexdigest()
    return rows, digest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--sha', required=True)
    args = parser.parse_args()
    rows, digest = inventory(args.root)
    if digest != args.sha:
        raise SystemExit('context inventory mismatch')
    print(json.dumps({'inventoryDigest': digest, 'entries': len(rows)}))
