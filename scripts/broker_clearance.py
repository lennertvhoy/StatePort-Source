"""Out-of-band secret broker clearance for unattended release signing.

Handles the case where the secret broker's interactive prompt cannot be
answered (owner away from the machine).  A pending request is not treated
as a failure; the short code is recorded, and a later request with that
code completes the handover without a dialog.

Exit codes
----------
 0  OK — credential delivered and consumer succeeded
10  NO_OPERATION_CONFIG
11  CONFIG_INVALID
12  UNKNOWN_OPERATION
20  SCENARIO_UNAVAILABLE
21  SCENARIO_BLOCKED
30  PROMPT_CANCELLED
31  PROMPT_TIMEOUT
32  PROMPT_FAILED
33  PROMPT_PENDING — request paused, waiting for owner approval (not a failure)
40  CONSUMER_FAILED
41  CONSUMER_TIMEOUT
50  APPROVAL_NOT_FOUND
51  APPROVAL_EXPIRED
52  APPROVAL_CONSUMED
53  APPROVAL_MISMATCH
54  APPROVAL_MISSING_PROVENANCE
130 CANCELLED
 1  unexpected error
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

BROKER = Path.home() / "machine-state/tools/opencode-secret-broker/secret_broker.py"
CLEARANCE_DIR = Path.home() / ".local/state/opencode-secret-broker/clearance"

EXIT_OK = 0
EXIT_PROMPT_PENDING = 33
EXIT_APPROVAL_NOT_FOUND = 50
EXIT_APPROVAL_EXPIRED = 51
EXIT_APPROVAL_CONSUMED = 52
EXIT_APPROVAL_MISMATCH = 53

PENDING_SUFFIX = ".pending.json"
APPROVED_SUFFIX = ".approved.json"


@dataclass(frozen=True)
class BrokerOutcome:
    """Result of a broker invocation."""

    status: str
    operation_id: str
    exit_code: int
    pending_code: str | None = None
    expires_at: float | None = None

    @property
    def is_pending(self) -> bool:
        return self.status == "PROMPT_PENDING"

    @property
    def is_ok(self) -> bool:
        return self.status == "OK"

    @property
    def is_failure(self) -> bool:
        return not self.is_pending and not self.is_ok


def run_broker_request(
    operation_id: str,
    *,
    broker: str | Path = BROKER,
    config_path: str | Path | None = None,
    clearance_code: str | None = None,
    timeout: int = 30,
) -> BrokerOutcome:
    """Invoke ``secret_broker.py request`` and parse the structured result.

    The broker prints ``STATUS OPERATION_ID`` on stdout.  When the status is
    ``PROMPT_PENDING`` it also prints ``  code=XXXXXX expires_at=…`` on the
    next line.  Exit code 33 maps to ``PROMPT_PENDING``.
    """

    cmd = [sys.executable, str(broker), "request", "--operation", operation_id]
    if clearance_code is not None:
        cmd.extend(["--clearance", clearance_code])
    if config_path is not None:
        cmd.extend(["--config", str(config_path)])

    try:
        completed = subprocess.run(
            cmd,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return BrokerOutcome("BROKER_TIMEOUT", operation_id, -1)
    except OSError as exc:
        return BrokerOutcome("BROKER_UNAVAILABLE", operation_id, -1)

    exit_code = completed.returncode
    stdout = completed.stdout.strip()

    status = "UNKNOWN"
    op_id = operation_id
    pending_code = None
    expires_at = None

    if stdout:
        parts = stdout.splitlines()[0].split()
        if len(parts) >= 1:
            status = parts[0]
        if len(parts) >= 2:
            op_id = parts[1]

        for line in stdout.splitlines()[1:]:
            line = line.strip()
            if line.startswith("code=") and "expires_at=" in line:
                for token in line.split():
                    if token.startswith("code="):
                        pending_code = token.split("=", 1)[1]
                    elif token.startswith("expires_at="):
                        try:
                            expires_at = float(token.split("=", 1)[1])
                        except ValueError:
                            pass

    return BrokerOutcome(
        status=status,
        operation_id=op_id,
        exit_code=exit_code,
        pending_code=pending_code,
        expires_at=expires_at,
    )


def check_pending_clearance(operation_id: str, clearance_dir: str | Path = CLEARANCE_DIR) -> dict | None:
    """Return the first unexpired pending clearance for *operation_id*, or None."""

    cdir = Path(clearance_dir)
    if not cdir.exists():
        return None

    import time

    now = time.time()
    for entry in sorted(cdir.iterdir()):
        if not entry.name.endswith(PENDING_SUFFIX):
            continue
        try:
            data = json.loads(entry.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(data, dict):
            continue
        if data.get("expires_at", 0) <= now:
            continue
        if data.get("operation_id") == operation_id:
            return data
    return None


def approval_exists(code: str, clearance_dir: str | Path = CLEARANCE_DIR) -> bool:
    """Check whether an unexpired, unconsumed approval file exists for *code*."""

    cdir = Path(clearance_dir)
    if not cdir.exists():
        return False

    import time

    now = time.time()
    for entry in cdir.iterdir():
        if not entry.name.endswith(APPROVED_SUFFIX):
            continue
        try:
            data = json.loads(entry.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(data, dict):
            continue
        if data.get("consumed", True):
            continue
        if data.get("expires_at", 0) <= now:
            continue
        if data.get("code") == code:
            return True
    return False


def request_with_clearance(
    operation_id: str,
    *,
    broker: str | Path = BROKER,
    config_path: str | Path | None = None,
    timeout: int = 60,
) -> BrokerOutcome:
    """First attempt: invoke the broker and return the parsed outcome.

    Exit code 33 (PROMPT_PENDING) is a valid intermediate result, not a
    failure.  The caller should record the ``pending_code`` from the
    outcome and present it to the owner for out-of-band approval.
    """

    return run_broker_request(
        operation_id,
        broker=broker,
        config_path=config_path,
        clearance_code=None,
        timeout=timeout,
    )


def resume_with_clearance(
    operation_id: str,
    clearance_code: str,
    *,
    broker: str | Path = BROKER,
    config_path: str | Path | None = None,
    timeout: int = 60,
) -> BrokerOutcome:
    """Second attempt: complete the handover using an approved clearance code.

    The broker skips the interactive prompt and delivers the credential
    directly to the consumer (if the approval is valid, unconsumed, and
    matches this exact request).
    """

    return run_broker_request(
        operation_id,
        broker=broker,
        config_path=config_path,
        clearance_code=clearance_code,
        timeout=timeout,
    )


def is_pending_exit(code: int) -> bool:
    """True when the exit code means 'paused, waiting for owner'."""

    return code == EXIT_PROMPT_PENDING
