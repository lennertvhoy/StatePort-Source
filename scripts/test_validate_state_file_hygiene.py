from pathlib import Path

import validate_state_file_hygiene as hygiene


def _write_valid_state(root: Path) -> None:
    archive = root / "docs/history/state"
    archive.mkdir(parents=True)
    for rule in hygiene.STATE_FILE_RULES:
        path = root / rule.path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("current: true\narchive: docs/history/state/\n", encoding="utf-8")
        suffix = ".yaml" if rule.path.suffix == ".yaml" else ".md"
        (archive / f"{rule.archive_prefix}2026-07-26{suffix}").write_text(
            "historical\n", encoding="utf-8"
        )


def test_live_repository_passes_hygiene_gate():
    assert hygiene.validate_state_file_hygiene(hygiene.REPO_ROOT) == []


def test_rejects_over_budget_live_file(tmp_path: Path):
    _write_valid_state(tmp_path)
    (tmp_path / "STATUS.md").write_text(
        "archive: docs/history/state/\n" * 121, encoding="utf-8"
    )
    findings = hygiene.validate_state_file_hygiene(tmp_path)
    assert any(f.path == Path("STATUS.md") and "budget" in f.detail for f in findings)


def test_rejects_missing_archive_pointer_and_rotation(tmp_path: Path):
    _write_valid_state(tmp_path)
    (tmp_path / "NEXT_ACTIONS.md").write_text("current: true\n", encoding="utf-8")
    (tmp_path / "docs/history/state/NEXT_ACTIONS-2026-07-26.md").unlink()
    findings = hygiene.validate_state_file_hygiene(tmp_path)
    details = [f.detail for f in findings if f.path == Path("NEXT_ACTIONS.md")]
    assert any("pointer" in detail for detail in details)
    assert any("no dated archive" in detail for detail in details)
