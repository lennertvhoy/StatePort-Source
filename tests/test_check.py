"""Tests for the Decision Log check actions (run with: python3 -m pytest tests)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "decision_actions.py"
TODAY = "2026-10-21"


def run(root: Path, action: str = "check", today: str = TODAY, *extra: str) -> tuple[dict, int, str]:
    proc = subprocess.run(
        [sys.executable, "-B", str(SCRIPT), "--root", str(root), "--action", action, "--today", today, *extra],
        capture_output=True,
        text=True,
        check=False,
    )
    lines = proc.stdout.strip().splitlines()
    assert len(lines) == 1, f"expected exactly one JSON line, got {proc.stdout!r}"
    return json.loads(lines[0]), proc.returncode, proc.stderr


def entry(id_: str, status: str = "open", **fields) -> dict:
    value = {"id": id_, "title": f"Title of {id_}", "status": status, "created": "2026-01-01"}
    value.update(fields)
    return value


def make_instance(tmp_path: Path, entries: list[dict], records: tuple[str, ...] = ()) -> Path:
    (tmp_path / "state").mkdir()
    (tmp_path / "decisions").mkdir()
    (tmp_path / "state" / "DECISIONS.yaml").write_text(
        yaml.safe_dump({"formatVersion": "decision-log.state/v1", "decisions": entries}, sort_keys=False)
    )
    for record in records:
        (tmp_path / "decisions" / f"{record}.md").write_text(f"# {record}\n")
    return tmp_path


def decided(id_: str, **fields) -> dict:
    return entry(id_, "decided", rationale="Because.", decidedOn="2026-01-05", **fields)


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file() and ".git" not in p.parts and "__pycache__" not in p.parts):
        digest.update(str(path.relative_to(root)).encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()


# --- the seeded template state --------------------------------------------------------------


def test_seed_is_not_yet_out_of_the_box():
    result, code, stderr = run(ROOT)
    assert code == 0 and stderr == ""
    assert result["formatVersion"] == "decision-log.action-result/v1"
    assert result["actionId"] == "decision-log.check/v1"
    assert result["verdict"] == "not_yet"
    assert [(f["code"], f["entryId"]) for f in result["findings"]] == [("question_overdue", "0002-meeting-cadence")]


def test_seed_passes_before_its_question_is_overdue():
    result, _, _ = run(ROOT, today="2026-09-01")
    assert result["verdict"] == "passed"
    assert result["findings"] == []


def test_seed_list_due_reports_question_and_review():
    result, code, _ = run(ROOT, "list-due")
    assert code == 0
    assert result["actionId"] == "decision-log.list-due/v1"
    assert result["verdict"] == "not_yet"
    assert [(f["code"], f["entryId"]) for f in result["findings"]] == [
        ("review_due", "0001-database-backup-approach"),
        ("question_overdue", "0002-meeting-cadence"),
    ]


# --- passed ---------------------------------------------------------------------------------


def test_empty_log_passes(tmp_path):
    result, code, _ = run(make_instance(tmp_path, []))
    assert (result["verdict"], code) == ("passed", 0)


def test_open_question_before_and_on_its_decide_by_date_passes(tmp_path):
    root = make_instance(tmp_path, [entry("a", decideBy="2026-10-21"), entry("b", decideBy="2026-12-01"), entry("c")])
    assert run(root)[0]["verdict"] == "passed"


def test_decided_with_rationale_and_record_passes(tmp_path):
    root = make_instance(tmp_path, [decided("a"), entry("old", "superseded", supersededBy="a")], records=("a",))
    result, _, _ = run(root)
    assert result["verdict"] == "passed"
    assert "2 entries" in result["summary"]


def test_quoted_string_dates_are_accepted(tmp_path):
    root = make_instance(tmp_path, [entry("a", created="2026-01-01", decideBy="2026-12-01")])
    assert run(root)[0]["verdict"] == "passed"


# --- not_yet --------------------------------------------------------------------------------


def test_open_question_past_decide_by_is_not_yet(tmp_path):
    root = make_instance(tmp_path, [entry("a", decideBy="2026-10-20")])
    result, _, _ = run(root)
    assert result["verdict"] == "not_yet"
    assert result["findings"][0]["code"] == "question_overdue"
    assert "1 day past" in result["findings"][0]["message"]


def test_decided_without_rationale_is_not_yet(tmp_path):
    bare = entry("a", "decided", decidedOn="2026-01-05")
    result, _, _ = run(make_instance(tmp_path, [bare], records=("a",)))
    assert result["verdict"] == "not_yet"
    assert [f["code"] for f in result["findings"]] == ["rationale_missing"]


def test_decided_with_blank_rationale_is_not_yet(tmp_path):
    root = make_instance(tmp_path, [entry("a", "decided", rationale="   ")], records=("a",))
    assert [f["code"] for f in run(root)[0]["findings"]] == ["rationale_missing"]


def test_decided_without_record_is_not_yet(tmp_path):
    result, _, _ = run(make_instance(tmp_path, [decided("a")]))
    assert result["verdict"] == "not_yet"
    assert [f["code"] for f in result["findings"]] == ["record_missing"]


def test_empty_record_does_not_count(tmp_path):
    root = make_instance(tmp_path, [decided("a")], records=("a",))
    (root / "decisions" / "a.md").write_text("")
    assert [f["code"] for f in run(root)[0]["findings"]] == ["record_missing"]


def test_record_symlink_does_not_count(tmp_path):
    root = make_instance(tmp_path, [decided("a")])
    outside = tmp_path.parent / f"{tmp_path.name}-outside.md"
    outside.write_text("# outside\n")
    (root / "decisions" / "a.md").symlink_to(outside)
    assert [f["code"] for f in run(root)[0]["findings"]] == ["record_missing"]


def test_all_problems_are_reported_in_file_order(tmp_path):
    root = make_instance(
        tmp_path,
        [entry("q", decideBy="2026-01-01"), entry("d", "decided"), entry("q2", decideBy="2026-02-01")],
    )
    result, _, _ = run(root)
    assert [(f["code"], f["entryId"]) for f in result["findings"]] == [
        ("question_overdue", "q"),
        ("question_overdue", "q2"),
        ("rationale_missing", "d"),
        ("record_missing", "d"),
    ]


def test_review_date_alone_does_not_fail_the_check(tmp_path):
    root = make_instance(tmp_path, [decided("a", reviewOn="2026-01-10")], records=("a",))
    assert run(root)[0]["verdict"] == "passed"
    due, _, _ = run(root, "list-due")
    assert [(f["code"], f["entryId"]) for f in due["findings"]] == [("review_due", "a")]


def test_list_due_is_oldest_first_and_passes_when_nothing_is_due(tmp_path):
    root = make_instance(
        tmp_path,
        [decided("late", reviewOn="2026-09-01"), entry("early", decideBy="2026-03-01"), entry("future", decideBy="2027-03-01")],
        records=("late",),
    )
    due, _, _ = run(root, "list-due")
    assert [f["entryId"] for f in due["findings"]] == ["early", "late"]
    assert run(root, "list-due", "2026-01-01")[0]["verdict"] == "passed"


# --- invalid --------------------------------------------------------------------------------


def write_state(root: Path, text: str) -> Path:
    (root / "state").mkdir(exist_ok=True)
    (root / "state" / "DECISIONS.yaml").write_text(text)
    return root


def test_missing_state_file_is_invalid(tmp_path):
    result, code, _ = run(tmp_path)
    assert (result["verdict"], code) == ("invalid", 0)
    assert result["findings"][0]["code"] == "state_missing"


def test_unparseable_yaml_is_invalid(tmp_path):
    result, code, _ = run(write_state(tmp_path, "decisions: [unclosed\n  - : :\n"))
    assert (result["verdict"], code) == ("invalid", 0)
    assert result["findings"][0]["code"] == "state_unparseable"


@pytest.mark.parametrize("text", ["", "- just\n- a list\n", "decisions: nope\n", "other: []\n"])
def test_wrong_shape_is_invalid(tmp_path, text):
    result, _, _ = run(write_state(tmp_path, text))
    assert result["verdict"] == "invalid"
    assert result["findings"][0]["code"] == "state_shape"


@pytest.mark.parametrize("missing", ["id", "title", "status", "created"])
def test_entry_missing_a_required_field_is_invalid(tmp_path, missing):
    bad = entry("a")
    del bad[missing]
    result, code, _ = run(make_instance(tmp_path, [bad]))
    assert (result["verdict"], code) == ("invalid", 0)
    assert result["findings"][0]["code"] == "entry_invalid"


def test_unknown_status_is_invalid(tmp_path):
    assert run(make_instance(tmp_path, [entry("a", "maybe")]))[0]["verdict"] == "invalid"


@pytest.mark.parametrize("field", ["created", "decideBy", "reviewOn", "decidedOn"])
def test_malformed_dates_are_invalid(tmp_path, field):
    root = make_instance(tmp_path, [entry("a", **{field: "next tuesday"})])
    result, _, _ = run(root)
    assert result["verdict"] == "invalid"
    assert field in result["findings"][0]["message"]


def test_calendar_impossible_date_is_invalid(tmp_path):
    assert run(make_instance(tmp_path, [entry("a", created="2026-02-30")]))[0]["verdict"] == "invalid"


@pytest.mark.parametrize("bad_id", ["../escape", "a/b", ".hidden", "", "x" * 200])
def test_unsafe_ids_are_invalid(tmp_path, bad_id):
    assert run(make_instance(tmp_path, [entry(bad_id)]))[0]["verdict"] == "invalid"


def test_duplicate_ids_are_invalid(tmp_path):
    result, _, _ = run(make_instance(tmp_path, [entry("a"), entry("a")]))
    assert result["verdict"] == "invalid"
    assert "more than once" in result["findings"][0]["message"]


def test_non_mapping_entry_is_invalid(tmp_path):
    assert run(write_state(tmp_path, "decisions:\n  - just a string\n"))[0]["verdict"] == "invalid"


def test_invalid_beats_not_yet(tmp_path):
    root = make_instance(tmp_path, [entry("late", decideBy="2026-01-01"), entry("broken", "maybe")])
    assert run(root)[0]["verdict"] == "invalid"


def test_list_due_on_invalid_state_is_invalid(tmp_path):
    result, _, _ = run(write_state(tmp_path, "{{{"), "list-due")
    assert result["verdict"] == "invalid"


# --- contract: one object, exit 0, read-only, deterministic -----------------------------------


def test_bad_invocations_still_print_one_object_and_exit_zero():
    for argv in (["--bogus"], ["--action", "nope"], ["--inputs", "not json"], ["--inputs", '{"x": 1}'], ["--today", "soon"]):
        proc = subprocess.run([sys.executable, "-B", str(SCRIPT), "--root", str(ROOT), *argv], capture_output=True, text=True)
        assert proc.returncode == 0, argv
        value = json.loads(proc.stdout)
        assert value["verdict"] == "invalid" and value["findings"][0]["code"] == "bad_invocation", argv


def test_fail_on_invalid_is_the_only_nonzero_exit(tmp_path):
    assert run(tmp_path, "check", TODAY, "--fail-on-invalid")[1] == 1
    assert run(ROOT, "check", TODAY, "--fail-on-invalid")[1] == 0  # not_yet is not invalid


def test_runs_do_not_modify_the_instance(tmp_path):
    root = tmp_path / "copy"
    shutil.copytree(ROOT, root, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache"))
    before = tree_digest(root)
    for action in ("check", "list-due"):
        run(root, action)
    assert tree_digest(root) == before


def test_output_is_deterministic():
    first = subprocess.run([sys.executable, "-B", str(SCRIPT), "--root", str(ROOT), "--today", TODAY], capture_output=True, text=True).stdout
    second = subprocess.run([sys.executable, "-B", str(SCRIPT), "--root", str(ROOT), "--today", TODAY], capture_output=True, text=True).stdout
    assert first == second


# --- descriptor consistency -------------------------------------------------------------------


def load(name: str) -> dict:
    return yaml.safe_load((ROOT / name).read_text())


def test_descriptor_matches_the_contract():
    app = load("application.yaml")
    assert app["formatVersion"] == "stateport.application/v1"
    assert app["applicationId"] == "decision-log"
    assert app["productionEligible"] is False and app["privacyClassification"] == "public_safe"
    assert app["stateLayout"]["canonical"] == ["state/DECISIONS.yaml", "decisions/"]
    assert app["stateLayout"]["ownership"] == {"state/DECISIONS.yaml": "instance", "decisions/": "instance"}
    assert app["actionsPath"] == "actions.yaml"
    assert (ROOT / app["executorCommand"]).is_file()
    assert app["evaluatorAction"] == "decision-log.check/v1"


def test_actions_match_the_contract():
    actions = {a["id"]: a for a in load("actions.yaml")["actions"]}
    assert set(actions) == {"decision-log.check/v1", "decision-log.list-due/v1", "decision-log.draft-decision/v1"}
    assert load("application.yaml")["evaluatorAction"] in actions
    for name in ("decision-log.check/v1", "decision-log.list-due/v1"):
        action = actions[name]
        assert (action["executorKind"], action["mutationPolicy"], action["networkPolicy"], action["toolPolicy"]) == (
            "script", "none", "disabled", "none"
        )
        assert (ROOT / action["executorCommand"]).is_file()
    draft = actions["decision-log.draft-decision/v1"]
    assert (draft["executorKind"], draft["mutationPolicy"], draft["networkPolicy"], draft["actionClass"]) == (
        "agent", "propose_only", "model_provider_only", "agent.edit-state"
    )
    assert draft["writablePaths"] == ["state/DECISIONS.yaml", "decisions/"]
    assert 0 < len(draft["instructions"]) <= 1500
    for action in actions.values():
        assert action["formatVersion"] == "decision-log.action/v1" and action["contextPolicy"]["id"]


def test_seed_record_exists_for_the_decided_entry():
    state = load("state/DECISIONS.yaml")
    decided_ids = [e["id"] for e in state["decisions"] if e["status"] == "decided"]
    assert decided_ids and all((ROOT / "decisions" / f"{i}.md").is_file() for i in decided_ids)
