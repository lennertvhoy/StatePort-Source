#!/usr/bin/env python3
"""Tests for broker_clearance.py — the out-of-band clearance wrapper.

Uses a stub broker script on PATH that simulates the real broker's
behaviour without GUI, network, or real secrets.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

# Ensure the scripts directory is importable.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import broker_clearance as bc

# ---------------------------------------------------------------------------
# Stub broker
# ---------------------------------------------------------------------------

STUB_BROKER_TEMPLATE = textwrap.dedent("""\
    #!/usr/bin/env python3
    \"\"\"Stub secret broker for testing broker_clearance.

    Behaviour is controlled by the STUB_BROKER_MODE env var:

    ok               — exit 0, "OK <op>"
    pending          — exit 33, "PROMPT_PENDING <op>\\n  code=STUB01 expires_at=<now+3600>"
    approval_not_found — exit 50, "APPROVAL_NOT_FOUND <op>"
    approval_mismatch  — exit 53, "APPROVAL_MISMATCH <op>"
    consumer_failed    — exit 40, "CONSUMER_FAILED <op>"
    \"\"\"
    import json, os, sys, time

    mode = os.environ.get("STUB_BROKER_MODE", "ok")

    args = sys.argv[1:]
    operation_id = "-"
    clearance_code = None

    i = 0
    while i < len(args):
        if args[i] == "--operation" and i + 1 < len(args):
            operation_id = args[i + 1]
            i += 2
        elif args[i] == "--clearance" and i + 1 < len(args):
            clearance_code = args[i + 1]
            i += 2
        else:
            i += 1

    if mode == "pending":
        expires = time.time() + 3600
        print(f"PROMPT_PENDING {operation_id}")
        print(f"  code=STUB01 expires_at={expires}")
        sys.exit(33)
    elif mode == "ok":
        print(f"OK {operation_id}")
        sys.exit(0)
    elif mode == "approval_not_found":
        print(f"APPROVAL_NOT_FOUND {operation_id}")
        sys.exit(50)
    elif mode == "approval_mismatch":
        print(f"APPROVAL_MISMATCH {operation_id}")
        sys.exit(53)
    elif mode == "consumer_failed":
        print(f"CONSUMER_FAILED {operation_id}")
        sys.exit(40)
    else:
        print(f"UNKNOWN {operation_id}")
        sys.exit(1)
""")


def _write_stub_broker(tmp: Path) -> Path:
    """Write the stub broker to *tmp* and make it executable."""

    stub = tmp / "stub_secret_broker.py"
    stub.write_text(STUB_BROKER_TEMPLATE, encoding="utf-8")
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return stub


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestBrokerOutcome(unittest.TestCase):
    def test_pending_is_not_failure(self):
        outcome = bc.BrokerOutcome(status="PROMPT_PENDING", operation_id="test-op", exit_code=33, pending_code="ABC123", expires_at=1.0)
        self.assertTrue(outcome.is_pending)
        self.assertFalse(outcome.is_ok)
        self.assertFalse(outcome.is_failure)

    def test_ok_is_not_failure(self):
        outcome = bc.BrokerOutcome(status="OK", operation_id="test-op", exit_code=0)
        self.assertTrue(outcome.is_ok)
        self.assertFalse(outcome.is_pending)
        self.assertFalse(outcome.is_failure)

    def test_other_statuses_are_failures(self):
        for status in ("PROMPT_TIMEOUT", "CONSUMER_FAILED", "SCENARIO_UNAVAILABLE", "UNKNOWN"):
            outcome = bc.BrokerOutcome(status=status, operation_id="test-op", exit_code=1)
            self.assertTrue(outcome.is_failure, f"{status} should be a failure")
            self.assertFalse(outcome.is_pending)
            self.assertFalse(outcome.is_ok)


class TestIsPendingExit(unittest.TestCase):
    def test_exit_33_is_pending(self):
        self.assertTrue(bc.is_pending_exit(33))

    def test_exit_0_is_not_pending(self):
        self.assertFalse(bc.is_pending_exit(0))

    def test_exit_1_is_not_pending(self):
        self.assertFalse(bc.is_pending_exit(1))

    def test_exit_50_is_not_pending(self):
        self.assertFalse(bc.is_pending_exit(50))


class TestRunBrokerRequest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._tmp_path = Path(self._tmp)
        self._stub = _write_stub_broker(self._tmp_path)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_ok_mode(self):
        os.environ["STUB_BROKER_MODE"] = "ok"
        try:
            outcome = bc.run_broker_request("test-op", broker=self._stub, timeout=5)
            self.assertTrue(outcome.is_ok)
            self.assertEqual(outcome.status, "OK")
            self.assertEqual(outcome.operation_id, "test-op")
            self.assertEqual(outcome.exit_code, 0)
            self.assertIsNone(outcome.pending_code)
        finally:
            os.environ.pop("STUB_BROKER_MODE", None)

    def test_pending_mode(self):
        os.environ["STUB_BROKER_MODE"] = "pending"
        try:
            outcome = bc.run_broker_request("test-op", broker=self._stub, timeout=5)
            self.assertTrue(outcome.is_pending)
            self.assertEqual(outcome.status, "PROMPT_PENDING")
            self.assertEqual(outcome.exit_code, 33)
            self.assertEqual(outcome.pending_code, "STUB01")
            self.assertIsNotNone(outcome.expires_at)
            self.assertGreater(outcome.expires_at, time.time())
        finally:
            os.environ.pop("STUB_BROKER_MODE", None)

    def test_consumer_failed_mode(self):
        os.environ["STUB_BROKER_MODE"] = "consumer_failed"
        try:
            outcome = bc.run_broker_request("test-op", broker=self._stub, timeout=5)
            self.assertTrue(outcome.is_failure)
            self.assertEqual(outcome.status, "CONSUMER_FAILED")
            self.assertEqual(outcome.exit_code, 40)
        finally:
            os.environ.pop("STUB_BROKER_MODE", None)

    def test_approval_not_found_mode(self):
        os.environ["STUB_BROKER_MODE"] = "approval_not_found"
        try:
            outcome = bc.run_broker_request("test-op", broker=self._stub, timeout=5)
            self.assertTrue(outcome.is_failure)
            self.assertEqual(outcome.status, "APPROVAL_NOT_FOUND")
            self.assertEqual(outcome.exit_code, 50)
        finally:
            os.environ.pop("STUB_BROKER_MODE", None)


class TestCheckPendingClearance(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        self._clearance_dir = self._tmp / "clearance"
        self._clearance_dir.mkdir()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _write_pending(self, operation_id: str, code: str = "TEST01", expires_in: int = 3600) -> Path:
        data = {
            "operation_id": operation_id,
            "argv": ["/usr/bin/test"],
            "request_digest": "a" * 64,
            "code": code,
            "created_at": time.time(),
            "expires_at": time.time() + expires_in,
            "uid": os.getuid(),
            "working_directory": "/tmp",
        }
        path = self._clearance_dir / f"{'a' * 64}.pending.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_finds_pending_for_matching_operation(self):
        self._write_pending("op-1")
        result = bc.check_pending_clearance("op-1", self._clearance_dir)
        self.assertIsNotNone(result)
        self.assertEqual(result["operation_id"], "op-1")
        self.assertEqual(result["code"], "TEST01")

    def test_returns_none_for_different_operation(self):
        self._write_pending("op-1")
        result = bc.check_pending_clearance("op-2", self._clearance_dir)
        self.assertIsNone(result)

    def test_returns_none_for_expired(self):
        self._write_pending("op-1", expires_in=-1)
        result = bc.check_pending_clearance("op-1", self._clearance_dir)
        self.assertIsNone(result)

    def test_returns_none_for_empty_dir(self):
        result = bc.check_pending_clearance("op-1", self._clearance_dir)
        self.assertIsNone(result)

    def test_returns_none_for_nonexistent_dir(self):
        result = bc.check_pending_clearance("op-1", self._tmp / "nonexistent")
        self.assertIsNone(result)


class TestApprovalExists(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        self._clearance_dir = self._tmp / "clearance"
        self._clearance_dir.mkdir()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _write_approval(self, code: str, consumed: bool = False, expires_in: int = 3600) -> Path:
        data = {
            "request_digest": "a" * 64,
            "code": code,
            "approval_timestamp": time.time(),
            "expires_at": time.time() + expires_in,
            "provenance": {"channel": "test", "message-id": "m1"},
            "consumed": consumed,
        }
        digest = "a" * 64 if not consumed else "b" * 64
        path = self._clearance_dir / f"{digest}.approved.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_finds_unconsumed_approval(self):
        self._write_approval("CODE1")
        self.assertTrue(bc.approval_exists("CODE1", self._clearance_dir))

    def test_rejects_consumed_approval(self):
        self._write_approval("CODE1", consumed=True)
        self.assertFalse(bc.approval_exists("CODE1", self._clearance_dir))

    def test_rejects_expired_approval(self):
        self._write_approval("CODE1", expires_in=-1)
        self.assertFalse(bc.approval_exists("CODE1", self._clearance_dir))

    def test_rejects_wrong_code(self):
        self._write_approval("CODE1")
        self.assertFalse(bc.approval_exists("CODE2", self._clearance_dir))

    def test_returns_false_for_empty_dir(self):
        self.assertFalse(bc.approval_exists("CODE1", self._clearance_dir))


class TestTwoStepFlow(unittest.TestCase):
    """End-to-end test of the two-step clearance flow using the stub broker."""

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        self._stub = _write_stub_broker(self._tmp)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_attempt1_pending_then_attempt2_ok(self):
        # Attempt 1: stub returns PROMPT_PENDING
        os.environ["STUB_BROKER_MODE"] = "pending"
        try:
            outcome1 = bc.request_with_clearance("sign-op", broker=self._stub, timeout=5)
            self.assertTrue(outcome1.is_pending)
            self.assertEqual(outcome1.pending_code, "STUB01")
            self.assertFalse(outcome1.is_failure)
        finally:
            os.environ.pop("STUB_BROKER_MODE", None)

        # Attempt 2: stub returns OK (simulates approved clearance)
        os.environ["STUB_BROKER_MODE"] = "ok"
        try:
            outcome2 = bc.resume_with_clearance("sign-op", "STUB01", broker=self._stub, timeout=5)
            self.assertTrue(outcome2.is_ok)
            self.assertFalse(outcome2.is_pending)
            self.assertFalse(outcome2.is_failure)
        finally:
            os.environ.pop("STUB_BROKER_MODE", None)

    def test_attempt1_pending_then_attempt2_approval_not_found(self):
        # Attempt 1: pending
        os.environ["STUB_BROKER_MODE"] = "pending"
        try:
            outcome1 = bc.request_with_clearance("sign-op", broker=self._stub, timeout=5)
            self.assertTrue(outcome1.is_pending)
        finally:
            os.environ.pop("STUB_BROKER_MODE", None)

        # Attempt 2: approval not found (expired or invalid)
        os.environ["STUB_BROKER_MODE"] = "approval_not_found"
        try:
            outcome2 = bc.resume_with_clearance("sign-op", "STALE", broker=self._stub, timeout=5)
            self.assertTrue(outcome2.is_failure)
            self.assertEqual(outcome2.status, "APPROVAL_NOT_FOUND")
        finally:
            os.environ.pop("STUB_BROKER_MODE", None)

    def test_pending_exit_code_distinct_from_failure(self):
        os.environ["STUB_BROKER_MODE"] = "pending"
        try:
            outcome = bc.request_with_clearance("sign-op", broker=self._stub, timeout=5)
            # Exit code 33 is NOT 0 (OK) and NOT 1 (generic failure)
            self.assertEqual(outcome.exit_code, 33)
            self.assertNotEqual(outcome.exit_code, 0)
            self.assertNotEqual(outcome.exit_code, 1)
            # is_pending is True, is_failure is False
            self.assertTrue(outcome.is_pending)
            self.assertFalse(outcome.is_failure)
        finally:
            os.environ.pop("STUB_BROKER_MODE", None)


class TestNoConsentWeakening(unittest.TestCase):
    """Verify that the module never bypasses the interactive prompt."""

    def test_request_with_clearance_passes_no_extra_flags(self):
        """The module must not add flags that skip the interactive prompt."""

        captured_cmd = []

        class FakeCompleted:
            returncode = 0
            stdout = "OK test-op\n"
            stderr = ""

        def fake_run(cmd, **kwargs):
            captured_cmd.extend(cmd)
            return FakeCompleted()

        import subprocess
        original_run = subprocess.run
        subprocess.run = fake_run
        try:
            os.environ["STUB_BROKER_MODE"] = "ok"
            try:
                bc.request_with_clearance("test-op", broker="/fake/broker", timeout=5)
            finally:
                os.environ.pop("STUB_BROKER_MODE", None)
        finally:
            subprocess.run = original_run

        # Must contain --operation but must NOT contain --clearance
        self.assertIn("--operation", captured_cmd)
        self.assertNotIn("--clearance", captured_cmd)
        # Must NOT contain any env-override flags
        for flag in ("--skip-prompt", "--force", "--yes", "--no-prompt", "--auto"):
            self.assertNotIn(flag, captured_cmd)

    def test_resume_with_clearance_passes_only_clearance(self):
        """The module passes --clearance but never --skip-prompt or similar."""

        captured_cmd = []

        class FakeCompleted:
            returncode = 0
            stdout = "OK test-op\n"
            stderr = ""

        def fake_run(cmd, **kwargs):
            captured_cmd.extend(cmd)
            return FakeCompleted()

        import subprocess
        original_run = subprocess.run
        subprocess.run = fake_run
        try:
            os.environ["STUB_BROKER_MODE"] = "ok"
            try:
                bc.resume_with_clearance("test-op", "CODE1", broker="/fake/broker", timeout=5)
            finally:
                os.environ.pop("STUB_BROKER_MODE", None)
        finally:
            subprocess.run = original_run

        self.assertIn("--clearance", captured_cmd)
        self.assertIn("CODE1", captured_cmd)
        for flag in ("--skip-prompt", "--force", "--yes", "--no-prompt", "--auto"):
            self.assertNotIn(flag, captured_cmd)


if __name__ == "__main__":
    unittest.main()
