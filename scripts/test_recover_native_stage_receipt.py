"""Tests for recover_native_stage_receipt.

Every guard here is proven to have teeth: each test that asserts a refusal also
asserts that the SAME input with the defect removed is accepted.  A test that
cannot fail is the defect this campaign has recorded twice, so each negative
case is paired with its positive twin.
"""

from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

# Loaded by explicit file path, NOT as ``from qualification import ...``.
# ``infra/qualification`` and ``scripts/qualification`` are two different
# packages with the same name, and a repo-root ``pytest -q`` -- which is what
# .github/workflows/validate.yml runs -- resolves the bare name to the infra one,
# so a test module living under ``scripts/qualification`` is itself named
# ``qualification.test_...`` and cannot be imported at all. This file therefore
# lives directly in ``scripts/`` and loads the module by path. See
# evidence/one-line-release-001/repo-root-pytest-collection-abort-20260926T2130Z.md.
_MODULE_PATH = ROOT / "scripts" / "qualification" / "recover_native_stage_receipt.py"
_spec = importlib.util.spec_from_file_location("recover_native_stage_receipt", _MODULE_PATH)
assert _spec is not None and _spec.loader is not None
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


def frame(payload: bytes, chunk: int = 700, declared: int | None = None) -> str:
    """Build a well-formed framed block exactly as the guest emits one."""
    b64 = base64.b64encode(payload).decode()
    total = -(-len(b64) // chunk)
    lines = [f"STATEPORT-R2 2026-09-14T14:07:00Z R2-RECEIPT-BEGIN chunks={total if declared is None else declared}"]
    for position in range(total):
        lines.append(
            "STATEPORT-R2 2026-09-14T14:07:00Z R2-RECEIPT "
            f"{position} {b64[position * chunk:(position + 1) * chunk]}"
        )
    lines.append("STATEPORT-R2 2026-09-14T14:07:06Z R2-RECEIPT-END")
    return "\n".join(lines) + "\n"


def test_recovers_a_single_receipt_byte_for_byte():
    payload = json.dumps({"result": "passed", "evidenceClass": "owner_path_qualification"}).encode()
    receipts = mod.recover(frame(payload))
    assert len(receipts) == 1
    assert receipts[0]["_raw"] == payload
    assert receipts[0]["declaredChunks"] == 1
    assert receipts[0]["bytes"] == len(payload)


def test_recovers_multiple_blocks_from_one_log():
    first = b'{"result":"passed"}'
    second = b'{"result":"failed"}'
    receipts = mod.recover(frame(first) + "unrelated serial noise\n" + frame(second))
    assert [r["_raw"] for r in receipts] == [first, second]


def test_multi_chunk_payload_survives_chunk_boundaries():
    # 700 is the guest's chunk width; a payload spanning several chunks is the
    # case that a naive single-line parse would silently truncate.
    payload = json.dumps({"facts": ["x" * 64] * 200}).encode()
    receipts = mod.recover(frame(payload))
    assert receipts[0]["declaredChunks"] > 1
    assert json.loads(receipts[0]["_raw"])["facts"] == ["x" * 64] * 200


def test_refuses_a_block_that_loses_its_end_marker():
    payload = b'{"result":"passed"}'
    truncated = frame(payload).replace("R2-RECEIPT-END", "")
    with pytest.raises(mod.RecoveryError, match="no R2-RECEIPT-END"):
        mod.recover(truncated)


def test_refuses_a_block_whose_declared_count_disagrees_with_its_chunks():
    payload = json.dumps({"facts": ["y" * 64] * 100}).encode()
    wrong = frame(payload, declared=99)
    with pytest.raises(mod.RecoveryError, match="declares 99 chunks but carries"):
        mod.recover(wrong)


def test_refuses_a_block_with_a_missing_chunk():
    payload = json.dumps({"facts": ["z" * 64] * 100}).encode()
    lines = [line for line in frame(payload).split("\n") if " R2-RECEIPT 1 " not in line]
    with pytest.raises(mod.RecoveryError, match="declares .* chunks but carries"):
        mod.recover("\n".join(lines) + "\n")


def test_refuses_out_of_order_chunks_even_when_the_count_matches():
    payload = json.dumps({"facts": ["q" * 64] * 100}).encode()
    lines = frame(payload).split("\n")
    chunk_lines = [i for i, line in enumerate(lines) if " R2-RECEIPT " in line]
    first, second = chunk_lines[0], chunk_lines[1]
    lines[first], lines[second] = lines[second], lines[first]
    with pytest.raises(mod.RecoveryError, match="not 0"):
        mod.recover("\n".join(lines) + "\n")


def test_refuses_a_block_that_is_not_base64():
    """The token stays one whitespace-free run, so the capture succeeds and the
    DECODE is what refuses.  An earlier draft of this test appended a space,
    which made the chunk line fail the pattern instead and produced the count
    error rather than the base64 error -- a passing-looking test of the wrong
    guard, which is the defect this file is written against."""
    good = frame(b'{"result":"passed"}')
    assert mod.recover(good), "the well-formed twin must be accepted"
    broken = good.replace("R2-RECEIPT 0 ", "R2-RECEIPT 0 not!base64!", 1)
    with pytest.raises(mod.RecoveryError, match="not valid base64"):
        mod.recover(broken)


def test_refuses_a_chunk_line_whose_payload_is_not_one_token():
    """A space inside the payload makes the line unparseable as a chunk at all."""
    good = frame(b'{"result":"passed"}')
    broken = good.replace("R2-RECEIPT 0 ", "R2-RECEIPT 0 two words ", 1)
    with pytest.raises(mod.RecoveryError, match="declares 1 chunks but carries 0"):
        mod.recover(broken)


def test_non_json_payload_is_recovered_and_marked_not_json():
    receipts = mod.recover(frame(b"\x00\x01binary not json"))
    assert receipts[0]["json"] is None
    view = mod.describe(receipts[0], None)
    assert view["schemaValidation"] == "not-run"
    assert view["json"] is None


def test_schema_validation_reports_failure_without_raising():
    """A legacy receipt must be REPORTED as failing, not crash the recovery."""
    validator = mod._schema(ROOT)
    assert validator is not None, "the repository receipt schema must be present"
    legacy = json.dumps({"result": "passed", "evidenceClass": "owner_path_qualification"}).encode()
    view = mod.describe(mod.recover(frame(legacy))[0], validator)
    assert view["schemaValidation"] == "fail"
    assert view["schemaValidationErrorCount"] > 0
    assert view["declared"]["result"] == "passed"


def test_main_exits_nonzero_when_the_log_has_no_framed_receipt(tmp_path, capsys):
    empty = tmp_path / "serial.log"
    empty.write_text("nothing to see here\n")
    assert mod.main([str(empty)]) == 1
    assert "no framed receipt found" in capsys.readouterr().err


def test_main_exits_two_on_an_untrustworthy_block(tmp_path, capsys):
    broken = tmp_path / "serial.log"
    broken.write_text(frame(b'{"result":"passed"}').replace("R2-RECEIPT-END", ""))
    assert mod.main([str(broken)]) == 2
    assert "no R2-RECEIPT-END" in capsys.readouterr().err


def test_main_writes_recovered_bytes_and_prints_a_summary(tmp_path, capsys):
    log = tmp_path / "serial.log"
    payload = b'{"result":"passed","stageId":"r3"}'
    log.write_text(frame(payload))
    out = tmp_path / "receipt.json"
    assert mod.main([str(log), "--out", str(out), "--root", str(ROOT)]) == 0
    written = sorted(tmp_path.glob("receipt-*.json"))
    assert len(written) == 1
    assert written[0].read_bytes() == payload
    summary = json.loads(capsys.readouterr().out)
    assert summary["recovered"] == 1
    assert summary["receipts"][0]["bytes"] == len(payload)
    assert summary["receipts"][0]["schemaValidation"] == "fail"
