#!/usr/bin/env python3
"""Render the reviewed SVG favicon at browser sizes with ImageMagick."""

from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "apps" / "web" / "assets" / "brand" / "favicon.svg"
SIZES = (16, 32, 48)


def render(output: Path) -> list[Path]:
    executable = shutil.which("magick")
    if executable is None:
        raise RuntimeError("ImageMagick 'magick' is required to render favicon evidence")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    rendered: list[Path] = []
    for size in SIZES:
        target = output / f"favicon-{size}.png"
        subprocess.run(
            [executable, "-background", "none", str(SOURCE), "-resize", f"{size}x{size}", str(target)],
            cwd=ROOT,
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        rendered.append(target)
    return rendered


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="owned output directory for 16, 32, and 48px PNGs")
    args = parser.parse_args()
    for path in render(args.output):
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
