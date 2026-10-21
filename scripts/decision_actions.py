#!/usr/bin/env python3
"""Decision Log check actions.

Read-only, deterministic, standard library plus PyYAML. Each run prints exactly one
JSON object on stdout and exits 0, so that the verdict (not the exit status) carries
the result. ``--fail-on-invalid`` exists only for the template's validationCommand.

Verdicts:
  invalid  the state file is missing or unparseable, or an entry is malformed
  not_yet  something is overdue or incomplete
  passed   nothing to do
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any

import yaml


RESULT_FORMAT = "decision-log.action-result/v1"
ACTION_IDS = {
    "check": "decision-log.check/v1",
    "list-due": "decision-log.list-due/v1",
}
STATE_PATH = "state/DECISIONS.yaml"
RECORD_DIR = "decisions"
STATUSES = ("open", "decided", "superseded")
MAX_STATE_BYTES = 1024 * 1024
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class StateInvalid(Exception):
    """The state cannot be evaluated; carries findings for the invalid verdict."""

    def __init__(self, findings: list[dict[str, Any]]) -> None:
        super().__init__(findings[0]["message"] if findings else "invalid")
        self.findings = findings


def _finding(code: str, message: str, entry_id: str | None = None, **extra: Any) -> dict[str, Any]:
    value: dict[str, Any] = {"code": code, "entryId": entry_id, "message": message}
    value.update(extra)
    return value


def _as_date(value: Any) -> dt.date | None:
    if isinstance(value, dt.datetime):
        return value.date()
    if isinstance(value, dt.date):
        return value
    if isinstance(value, str) and _ISO_DATE.fullmatch(value):
        try:
            return dt.date.fromisoformat(value)
        except ValueError:
            return None
    return None


def _non_empty_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def load_entries(root: Path) -> list[dict[str, Any]]:
    """Return validated entries in file order, each with parsed dates under ``_dates``."""

    path = root / STATE_PATH
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        raise StateInvalid([_finding("state_missing", f"{STATE_PATH} does not exist")])
    except OSError:
        raise StateInvalid([_finding("state_unreadable", f"{STATE_PATH} cannot be read")])
    if not stat.S_ISREG(info.st_mode):
        raise StateInvalid([_finding("state_unreadable", f"{STATE_PATH} is not a regular file")])
    if info.st_size > MAX_STATE_BYTES:
        raise StateInvalid([_finding("state_too_large", f"{STATE_PATH} is larger than {MAX_STATE_BYTES} bytes")])
    try:
        value = yaml.safe_load(path.read_bytes().decode("utf-8"))
    except UnicodeDecodeError:
        raise StateInvalid([_finding("state_unparseable", f"{STATE_PATH} is not valid UTF-8")])
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" (line {mark.line + 1})" if mark is not None else ""
        raise StateInvalid([_finding("state_unparseable", f"{STATE_PATH} does not parse as YAML{where}")])
    except OSError:
        raise StateInvalid([_finding("state_unreadable", f"{STATE_PATH} cannot be read")])
    if not isinstance(value, dict) or not isinstance(value.get("decisions"), list):
        raise StateInvalid([_finding("state_shape", f"{STATE_PATH} must be a mapping with a `decisions` list")])

    findings: list[dict[str, Any]] = []
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(value["decisions"], start=1):
        label = f"entry {index}"
        if not isinstance(raw, dict):
            findings.append(_finding("entry_invalid", f"{label} is not a mapping"))
            continue
        entry_id = raw.get("id")
        if isinstance(entry_id, str) and _ID.fullmatch(entry_id):
            label = entry_id
        else:
            findings.append(_finding("entry_invalid", f"{label} needs an `id` of letters, digits, '.', '_' or '-'"))
            entry_id = None
        if entry_id is not None:
            if entry_id in seen:
                findings.append(_finding("entry_invalid", f"id {entry_id} is used more than once", entry_id))
            seen.add(entry_id)
        if not _non_empty_text(raw.get("title")):
            findings.append(_finding("entry_invalid", f"{label} needs a non-empty `title`", entry_id))
        if raw.get("status") not in STATUSES:
            findings.append(_finding("entry_invalid", f"{label} needs a `status` of open, decided or superseded", entry_id))
        dates: dict[str, dt.date] = {}
        for field, required in (("created", True), ("decideBy", False), ("decidedOn", False), ("reviewOn", False)):
            present = raw.get(field) is not None
            if not present:
                if required:
                    findings.append(_finding("entry_invalid", f"{label} needs a `{field}` date (YYYY-MM-DD)", entry_id))
                continue
            parsed = _as_date(raw[field])
            if parsed is None:
                findings.append(_finding("entry_invalid", f"{label} has a `{field}` that is not a YYYY-MM-DD date", entry_id))
            else:
                dates[field] = parsed
        entry = dict(raw)
        entry["_dates"] = dates
        entries.append(entry)
    if findings:
        raise StateInvalid(findings)
    return entries


def _has_record(root: Path, entry_id: str) -> bool:
    try:
        info = os.lstat(root / RECORD_DIR / f"{entry_id}.md")
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and info.st_size > 0


def _days(later: dt.date, earlier: dt.date) -> str:
    count = (later - earlier).days
    return f"{count} day" + ("" if count == 1 else "s")


def _overdue_questions(entries: list[dict[str, Any]], today: dt.date) -> list[dict[str, Any]]:
    found = []
    for entry in entries:
        decide_by = entry["_dates"].get("decideBy")
        if entry["status"] == "open" and decide_by is not None and today > decide_by:
            found.append(
                _finding(
                    "question_overdue",
                    f"Open question is {_days(today, decide_by)} past its decideBy date {decide_by.isoformat()}: {entry['title']}",
                    entry["id"],
                    date=decide_by.isoformat(),
                )
            )
    return found


def _reviews_due(entries: list[dict[str, Any]], today: dt.date) -> list[dict[str, Any]]:
    found = []
    for entry in entries:
        review_on = entry["_dates"].get("reviewOn")
        if entry["status"] == "decided" and review_on is not None and today > review_on:
            found.append(
                _finding(
                    "review_due",
                    f"Decision is {_days(today, review_on)} past its reviewOn date {review_on.isoformat()}: {entry['title']}",
                    entry["id"],
                    date=review_on.isoformat(),
                )
            )
    return found


def _counts(entries: list[dict[str, Any]]) -> str:
    return ", ".join(f"{sum(1 for e in entries if e['status'] == s)} {s}" for s in STATUSES)


def check(root: Path, today: dt.date) -> tuple[str, str, list[dict[str, Any]]]:
    entries = load_entries(root)
    findings = _overdue_questions(entries, today)
    incomplete = 0
    for entry in entries:
        if entry["status"] != "decided":
            continue
        missing = False
        if not _non_empty_text(entry.get("rationale")):
            findings.append(_finding("rationale_missing", f"Decided entry has no `rationale`: {entry['title']}", entry["id"]))
            missing = True
        if not _has_record(root, entry["id"]):
            findings.append(
                _finding("record_missing", f"Decided entry has no record at {RECORD_DIR}/{entry['id']}.md: {entry['title']}", entry["id"])
            )
            missing = True
        incomplete += missing
    if not findings:
        return "passed", f"The decision log is up to date ({len(entries)} entries: {_counts(entries)}).", []
    overdue = sum(1 for f in findings if f["code"] == "question_overdue")
    parts = []
    if overdue:
        parts.append(f"{overdue} open question(s) past decideBy")
    if incomplete:
        parts.append(f"{incomplete} decided entr{'y' if incomplete == 1 else 'ies'} without rationale or record")
    return "not_yet", f"{'; '.join(parts)} ({len(entries)} entries: {_counts(entries)}).", findings


def list_due(root: Path, today: dt.date) -> tuple[str, str, list[dict[str, Any]]]:
    entries = load_entries(root)
    order = {entry["id"]: index for index, entry in enumerate(entries)}
    findings = _overdue_questions(entries, today) + _reviews_due(entries, today)
    findings.sort(key=lambda f: (f["date"], order[f["entryId"]], f["code"]))
    if not findings:
        return "passed", "Nothing is due.", []
    questions = sum(1 for f in findings if f["code"] == "question_overdue")
    return "not_yet", f"{questions} open question(s) past decideBy, {len(findings) - questions} decision review(s) due.", findings


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # never exit(2): the verdict carries failures
        raise ValueError(message)


def _parse(argv: list[str]) -> argparse.Namespace:
    parser = _Parser(description="Decision Log check actions (read-only).", add_help=False, allow_abbrev=False)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--action", default="check")
    parser.add_argument("--inputs", default="{}")
    parser.add_argument("--today", default=None, help="YYYY-MM-DD; for tests, defaults to the local date")
    parser.add_argument("--fail-on-invalid", action="store_true")
    return parser.parse_args(argv)


def run(argv: list[str]) -> tuple[dict[str, Any], bool]:
    action_id = ACTION_IDS["check"]
    try:
        args = _parse(argv)
        if args.action not in ACTION_IDS:
            action_id = "decision-log.unknown/v1"
            raise ValueError(f"unknown action {args.action!r}; expected one of {', '.join(ACTION_IDS)}")
        action_id = ACTION_IDS[args.action]
        inputs = json.loads(args.inputs)
        if not isinstance(inputs, dict) or inputs:
            raise ValueError("this action takes no inputs")
        if args.today is None:
            today = dt.date.today()
        else:
            today = _as_date(args.today)
            if today is None:
                raise ValueError("--today must be a YYYY-MM-DD date")
        verdict, summary, findings = (check if args.action == "check" else list_due)(args.root, today)
    except StateInvalid as exc:
        verdict, summary, findings = "invalid", exc.findings[0]["message"] if len(exc.findings) == 1 else f"{len(exc.findings)} problems in {STATE_PATH}.", exc.findings
    except (ValueError, json.JSONDecodeError) as exc:
        verdict, summary, findings = "invalid", f"Bad invocation: {exc}", [_finding("bad_invocation", str(exc))]
    except Exception as exc:  # the contract is one JSON object and exit 0, whatever happens
        verdict, summary, findings = "invalid", f"Internal error: {type(exc).__name__}", [_finding("internal_error", type(exc).__name__)]
    result = {"formatVersion": RESULT_FORMAT, "actionId": action_id, "verdict": verdict, "summary": summary, "findings": findings}
    return result, verdict == "invalid" and "--fail-on-invalid" in argv


def main() -> int:
    result, fail = run(sys.argv[1:])
    print(json.dumps(result, sort_keys=True))
    return 1 if fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
