#!/usr/bin/env python3
"""Recover guest qualification receipts that are base64-framed inside a serial log.

Why this exists
---------------
The native Windows 11 / WSL2 runner in this campaign transmits the guest's
qualification receipt to the host over the VM serial console, base64-framed in
700-character chunks between ``R2-RECEIPT-BEGIN`` and ``R2-RECEIPT-END``
markers.  It never writes those bytes to a file.  The receipt therefore exists
only inside ``serial.log``, and a reader who does not know the framing sees a
wall of base64 and concludes there is no receipt.

That is not hypothetical.  The 2026-09-14 native run was recorded ``failed``
(see ``native-harness-pass-condition-defect-20260926.md``) while a 73,840-byte
owner-path receipt sat undecoded in the serial log of the very same run.

What it does
------------
For each framed block it:

  * checks the declared chunk count against the number of chunks present and
    refuses a block with a missing, duplicated or out-of-order index,
  * concatenates and base64-decodes, strictly,
  * records the byte length and sha256 of each recovered receipt,
  * optionally validates each receipt against the project's own
    ``qualification-stage-receipt.v1`` schema and REPORTS the outcome.

A schema failure is reported, not raised.  Receipts minted before the current
contract legitimately do not satisfy it, and that fact is the interesting
result rather than an error in the decoder.

Read-only.  It reads one log and writes only the paths it is given.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import sys
from pathlib import Path

BEGIN = re.compile(r"R2-RECEIPT-BEGIN chunks=(\d+)")
CHUNK = re.compile(r"R2-RECEIPT (\d+) (\S+)\s*$")
END = "R2-RECEIPT-END"

SCHEMA_PATH = Path("infra/qualification/schemas/qualification-stage-receipt.v1.schema.json")


class RecoveryError(RuntimeError):
    """A framed block is present but cannot be trusted."""


def _schema(root: Path):
    try:
        import jsonschema
    except ImportError:  # pragma: no cover - the dependency is present in this repo
        return None
    path = root / SCHEMA_PATH
    if not path.exists():
        return None
    return jsonschema.Draft202012Validator(json.loads(path.read_text()))


def _blocks(text: str):
    """Yield (declared_chunks, [chunk_text, ...]) for each framed block."""
    lines = text.split("\n")
    index = 0
    while index < len(lines):
        begin = BEGIN.search(lines[index])
        if not begin:
            index += 1
            continue
        declared = int(begin.group(1))
        chunks: list[tuple[int, str]] = []
        cursor = index + 1
        closed = False
        while cursor < len(lines):
            if END in lines[cursor]:
                closed = True
                break
            match = CHUNK.search(lines[cursor])
            if match:
                chunks.append((int(match.group(1)), match.group(2)))
            cursor += 1
        if not closed:
            raise RecoveryError(
                f"R2-RECEIPT-BEGIN chunks={declared} at line {index + 1} has no R2-RECEIPT-END"
            )
        yield declared, chunks, index + 1
        index = cursor + 1


def recover(text: str) -> list[dict]:
    """Recover every framed receipt. Raises RecoveryError on any untrustworthy block."""
    receipts = []
    for declared, chunks, line_no in _blocks(text):
        if len(chunks) != declared:
            raise RecoveryError(
                f"block at line {line_no} declares {declared} chunks but carries {len(chunks)}"
            )
        seen = [position for position, _ in chunks]
        if seen != list(range(declared)):
            raise RecoveryError(
                f"block at line {line_no} chunk indices are not 0..{declared - 1} in order: {seen[:8]}"
            )
        joined = "".join(payload for _, payload in chunks)
        try:
            raw = base64.b64decode(joined, validate=True)
        except (binascii.Error, ValueError) as error:
            raise RecoveryError(f"block at line {line_no} is not valid base64: {error}") from error
        receipts.append(
            {
                "serialLine": line_no,
                "declaredChunks": declared,
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "json": _maybe_json(raw),
                "_raw": raw,
            }
        )
    return receipts


def _maybe_json(raw: bytes):
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def describe(receipt: dict, validator) -> dict:
    """Public, JSON-safe view of one recovered receipt."""
    view = {key: value for key, value in receipt.items() if not key.startswith("_")}
    payload = receipt.get("json")
    if validator is None:
        view["schemaValidation"] = "not-run"
    elif payload is None:
        view["schemaValidation"] = "not-applicable-not-json"
    else:
        errors = sorted(validator.iter_errors(payload), key=lambda e: list(e.path))
        view["schemaValidation"] = "pass" if not errors else "fail"
        view["schemaValidationErrors"] = [error.message[:300] for error in errors[:6]]
        view["schemaValidationErrorCount"] = len(errors)
    if isinstance(payload, dict):
        view["declared"] = {
            key: payload.get(key)
            for key in ("version", "mode", "result", "evidenceClass")
            if key in payload
        }
    return view


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("serial_log", type=Path, help="serial.log from a native run")
    parser.add_argument("--out", type=Path, help="write each recovered receipt as JSON, suffixed -1, -2, ...")
    parser.add_argument("--root", type=Path, default=Path("."), help="repository root for the receipt schema")
    args = parser.parse_args(argv)

    text = args.serial_log.read_text(errors="replace")
    try:
        receipts = recover(text)
    except RecoveryError as error:
        print(json.dumps({"error": str(error), "serialLog": str(args.serial_log)}), file=sys.stderr)
        return 2
    if not receipts:
        print(json.dumps({"error": "no framed receipt found", "serialLog": str(args.serial_log)}), file=sys.stderr)
        return 1

    validator = _schema(args.root)
    views = [describe(receipt, validator) for receipt in receipts]
    print(json.dumps({"serialLog": str(args.serial_log), "recovered": len(views), "receipts": views}, indent=1))

    if args.out:
        for position, receipt in enumerate(receipts, 1):
            target = args.out.with_name(f"{args.out.stem}-{position}{args.out.suffix}")
            target.write_bytes(receipt["_raw"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
