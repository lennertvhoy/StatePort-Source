"""Result types for the StatePort local runner."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class RunResult:
    """Outcome of running a StateSpec instance."""

    status: str
    logs: tuple[str, ...] = field(default_factory=tuple)
    errors: tuple[str, ...] = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        """True when the run produced no errors."""
        return not self.errors
