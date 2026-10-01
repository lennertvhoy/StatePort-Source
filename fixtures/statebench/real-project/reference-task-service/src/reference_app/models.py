"""Initial typed model boundary."""

from dataclasses import dataclass


@dataclass(frozen=True)
class TaskDraft:
    title: str
