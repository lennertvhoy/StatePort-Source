"""StatePort's bounded Codex CLI adapter.

This package observes only the installed executable and supported help output.
It never reads credential files, copies auth state, or grants Codex authority
over a canonical instance.
"""

from .adapter import CodexAdapter, CodexProbe, codex_probe

__all__ = ["CodexAdapter", "CodexProbe", "codex_probe"]
