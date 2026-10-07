#!/usr/bin/env python3
"""Keep the installer's embedded OpenCode-adoption sources equal to their two sources.

The one-line install downloads only the signed ``stateport-installer`` file, so
the host-side adoption helper (``scripts/adopt_opencode_signin.py``) and the
standard-library module it loads (``provider_adoption.py``) cannot sit beside
it.  ``scripts/install_no_checkout.py`` therefore carries verbatim copies of
both files between the BEGIN/END markers below, inside the signed installer
bytes.  This script regenerates that block; ``--check`` exits 1 when it has
drifted.  Run it after every edit of either source:

    python3 scripts/generate_installer_adoption_embed.py
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "install_no_checkout.py"
HELPER = ROOT / "scripts" / "adopt_opencode_signin.py"
MODULE = ROOT / "packages" / "persistent-app" / "src" / "stateport_persistent_app" / "provider_adoption.py"

BEGIN = "# BEGIN GENERATED: embedded OpenCode adoption sources (scripts/generate_installer_adoption_embed.py)\n"
END = "# END GENERATED: embedded OpenCode adoption sources\n"


def _literal(name: str, source: Path) -> str:
    text = source.read_text(encoding="utf-8")
    if "'''" in text or text.endswith("\\") or "\r" in text:
        raise SystemExit(f"{source}: cannot be embedded as a raw triple-quoted string")
    return f"{name} = r'''{text}'''\n"


def render_block() -> str:
    return (
        BEGIN
        + "# Verbatim copies; edit the sources, never this block.\n"
        + _literal("_EMBEDDED_PROVIDER_ADOPTION_SOURCE", MODULE)
        + _literal("_EMBEDDED_ADOPTION_HELPER_SOURCE", HELPER)
        + END
    )


def apply(installer_text: str, block: str) -> str:
    start = installer_text.find(BEGIN)
    end = installer_text.find(END)
    if start < 0 or end < start:
        raise SystemExit(f"{INSTALLER}: embedded-adoption markers not found")
    return installer_text[:start] + block + installer_text[end + len(END):]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 instead of rewriting when drifted")
    args = parser.parse_args(argv)
    current = INSTALLER.read_text(encoding="utf-8")
    expected = apply(current, render_block())
    if expected == current:
        print("installer embedded adoption sources are current")
        return 0
    if args.check:
        print(
            "installer embedded adoption sources are stale; run "
            "python3 scripts/generate_installer_adoption_embed.py",
            file=sys.stderr,
        )
        return 1
    INSTALLER.write_text(expected, encoding="utf-8")
    print(f"rewrote the embedded adoption sources in {INSTALLER}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
