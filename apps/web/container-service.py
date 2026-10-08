#!/usr/bin/env python3
"""Start the canonical StatePort AppServer inside the web OCI image.

This wrapper only makes the repository's source-tree packages importable. It
does not implement HTTP, proxy, or static-serving behavior; the AppServer
remains the sole same-origin authority and the thin service entry adds durable
assistant events, refresh projection, per-work cancellation, and redelivery.
"""

from __future__ import annotations

import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]

for parent in (ROOT / "packages", ROOT / "apps"):
    for source in sorted(parent.glob("*/src")):
        if source.is_dir():
            sys.path.insert(0, str(source))

from stateport_persistent_app.service_resilient_entry import main  # noqa: E402


def _bootstrap_platform_operator_authority() -> None:
    """Create the private platform-operator authority boundary on first start.

    The web container runs as the platform operator so the governed
    deployment/authority surfaces are reachable.  The authority file must be
    owned by this container's uid with mode 0600; the product-data volume is
    rootless (``:rw,U``), so the running container owns it and can create the
    file exactly once.  A pre-existing file (for example from an operator
    upgrade) is never replaced.
    """

    config_root = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "stateport"
    boundary = config_root / "platform-operator-authority"
    try:
        boundary.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(boundary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
    except FileExistsError:
        return
    except OSError:
        # A read-only or otherwise unavailable config root must fail loudly:
        # starting without the operator boundary would silently hide every
        # platform surface behind 403s.
        raise
    try:
        if boundary.stat().st_uid != os.geteuid() or boundary.stat().st_mode & 0o077:
            boundary.unlink()
            raise RuntimeError("platform-operator-authority must be private to the container uid")
    except OSError:
        raise


if __name__ == "__main__":
    _bootstrap_platform_operator_authority()
    raise SystemExit(main())
