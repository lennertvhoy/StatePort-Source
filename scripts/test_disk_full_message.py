"""A full disk is reported as a full disk, not as a vague local-resource problem (found by the disk-full e2e row)."""
from __future__ import annotations

import errno
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for source_root in sorted((ROOT / "packages").glob("*/src")):
    sys.path.insert(0, str(source_root))

from stateport_persistent_app.service_process import _safe_operation_failure  # noqa: E402


def test_enospc_and_quota_name_the_full_disk_and_leak_no_path() -> None:
    for code in (errno.ENOSPC, errno.EDQUOT):
        cause, message = _safe_operation_failure(OSError(code, "No space left", "/private/host/path"))
        assert cause == "local_io_error"
        assert "disk" in message and "full" in message and "free some space" in message.lower()
        assert "/private" not in message


def test_other_io_errors_keep_the_generic_sentence() -> None:
    cause, message = _safe_operation_failure(OSError(errno.EACCES, "denied", "/x"))
    assert (cause, message) == ("local_io_error", "A local resource could not be accessed. Check service setup and try again.")
