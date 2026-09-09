"""
QUARANTINED: opencode-adapter's run_opencode_in_container helper was found
during audit to pass '&&' as a literal script argument, attempt writes to
/read-only container paths (/etc/passwd, /etc/group, /home, /usr/local),
and skip verification of the inner command. The standalone container helper
now refuses every invocation before any process or filesystem mutation. The OpenCodeAdapter (non-container) path
is unaffected. Do not use run_opencode_in_container in production.
"""

from .adapter import OpenCodeProbe, OpenCodeAdapter, OpenCodeRunResult, opencode_probe

__all__ = ["OpenCodeProbe", "OpenCodeAdapter", "OpenCodeRunResult", "opencode_probe"]
