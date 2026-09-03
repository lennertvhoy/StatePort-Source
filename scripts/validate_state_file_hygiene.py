#!/usr/bin/env python3
"""Fail closed when live StatePort state files outgrow their current-state role.

Historical material belongs in ``docs/history/state``.  The live state files
are deliberately small navigation and authority surfaces, so a reviewer can
read current truth without reconstructing history from duplicated narratives.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_DIR = Path("docs/history/state")


@dataclass(frozen=True)
class StateFileRule:
    path: Path
    max_lines: int
    archive_prefix: str


STATE_FILE_RULES = (
    StateFileRule(Path("STATUS.md"), 120, "STATUS-"),
    StateFileRule(Path("NEXT_ACTIONS.md"), 120, "NEXT_ACTIONS-"),
    StateFileRule(Path("PROJECT_STATE.yaml"), 220, "PROJECT_STATE-"),
    StateFileRule(Path("WORKLOG.md"), 160, "WORKLOG-"),
    StateFileRule(Path("docs/EVIDENCE_LOG.md"), 160, "EVIDENCE_LOG-"),
)
ARCHIVE_NAME_RE = re.compile(r"^[A-Z_]+-\d{4}-\d{2}-\d{2}(?:[-.].+)?\.(?:md|yaml)$")


@dataclass(frozen=True)
class Finding:
    path: Path
    detail: str

    def render(self) -> str:
        return f"{self.path}: {self.detail}"


def validate_state_file_hygiene(root: Path) -> list[Finding]:
    """Return live-state size, archive, and linkage violations."""
    findings: list[Finding] = []
    archive_dir = root / ARCHIVE_DIR
    if not archive_dir.is_dir():
        return [Finding(ARCHIVE_DIR, "missing dated current-state archive directory")]

    for rule in STATE_FILE_RULES:
        live_path = root / rule.path
        if not live_path.is_file():
            findings.append(Finding(rule.path, "missing live state file"))
            continue
        text = live_path.read_text(encoding="utf-8")
        line_count = len(text.splitlines())
        if line_count > rule.max_lines:
            findings.append(
                Finding(rule.path, f"{line_count} lines exceeds {rule.max_lines}-line budget")
            )
        if "docs/history/state/" not in text:
            findings.append(
                Finding(rule.path, "missing link or pointer to docs/history/state/ archive")
            )
        archives = sorted(archive_dir.glob(f"{rule.archive_prefix}*"))
        if not archives:
            findings.append(
                Finding(rule.path, f"no dated archive matching {rule.archive_prefix}*"))
        elif not any(ARCHIVE_NAME_RE.fullmatch(path.name) for path in archives):
            findings.append(
                Finding(rule.path, "archive filename must include an ISO date and .md or .yaml suffix")
            )
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate StatePort current-state size and archive rotation hygiene"
    )
    parser.add_argument("root", nargs="?", default=str(REPO_ROOT))
    args = parser.parse_args(argv)
    findings = validate_state_file_hygiene(Path(args.root).resolve())
    if findings:
        for finding in findings:
            print(f"FAIL: {finding.render()}")
        print(f"FAILED: {len(findings)} state-file hygiene violation(s) found")
        return 1
    print("PASS: current-state line budgets and archive rotation checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
