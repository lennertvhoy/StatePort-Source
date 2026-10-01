"""Bounded process execution for replaceable external engines.

The runtime owns process lifetime, environment filtering, output limits and
temporary workspaces.  Engine adapters only translate their native protocol;
they never become the StatePort security boundary.
"""

from .runtime import (
    ProcessRuntimeError,
    ProcessResult,
    ProcessIdentity,
    ProcessSpec,
    TemporaryWorkspace,
    decode_jsonl,
    filtered_environment,
    probe_executable,
    run_process,
)

__all__ = [
    "ProcessRuntimeError",
    "ProcessResult",
    "ProcessIdentity",
    "ProcessSpec",
    "TemporaryWorkspace",
    "decode_jsonl",
    "filtered_environment",
    "probe_executable",
    "run_process",
]
