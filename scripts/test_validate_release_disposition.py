#!/usr/bin/env python3
"""Regression tests for the release work disposition ledger validator."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "validate_release_disposition.py"
LEDGER_PATH = ROOT / "docs" / "release" / "RELEASE_WORK_DISPOSITION.yaml"

sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "packages" / "statedd-core" / "src"))

import validate_release_disposition as vrd

REAL_LEDGER = LEDGER_PATH.read_text(encoding="utf-8")


def write_ledger(tmp_path: Path, text: str) -> Path:
    """Write a ledger text into a minimal root layout and return the root."""
    root = tmp_path / "repo"
    ledger_dir = root / "docs" / "release"
    ledger_dir.mkdir(parents=True)
    (ledger_dir / "RELEASE_WORK_DISPOSITION.yaml").write_text(text, encoding="utf-8")
    return root


def mutated_root(tmp_path: Path, old: str, new: str, *, occurrences: int = 1) -> Path:
    """Copy the real ledger with exactly one text mutation applied."""
    found = REAL_LEDGER.count(old)
    assert found >= occurrences, f"anchor not found enough times ({found}): {old!r}"
    return write_ledger(tmp_path, REAL_LEDGER.replace(old, new, occurrences))


def findings_for(root: Path, git_root: Path = ROOT) -> list[vrd.Finding]:
    return vrd.validate_disposition(root, git_root=git_root)


def rule_ids(findings: list[vrd.Finding]) -> set[str]:
    return {finding.rule for finding in findings}


def _git(root: Path, *args: str, input_text: str | None = None) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=root,
        input=input_text,
        capture_output=True,
        text=True,
        check=True,
    )
    return completed.stdout.strip()


def make_object_repo(tmp_path: Path) -> tuple[Path, str, str]:
    """Create a tmp git repo holding one blob and one tree; return (root, blob, tree)."""
    root = tmp_path / "objects"
    root.mkdir(parents=True)
    _git(root, "init")
    blob = _git(root, "hash-object", "-w", "--stdin", input_text="not a commit\n")
    tree = _git(root, "mktree", input_text=f"100644 blob {blob}\tfile.txt\n")
    return root, blob, tree


# ---------------------------------------------------------------------------
# Pass cases
# ---------------------------------------------------------------------------


def test_real_ledger_passes() -> None:
    assert vrd.validate_disposition(ROOT) == []


def test_real_ledger_cli_passes() -> None:
    completed = subprocess.run(
        [sys.executable, str(VALIDATOR), str(ROOT)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "PASS" in completed.stdout


def test_carrier_prs_multi_attribution_allowed() -> None:
    """PRs 8, 10, 11 are carrier lines partitioned across multiple items."""
    findings = vrd.validate_disposition(ROOT)
    assert "pr-multi-attribution" not in rule_ids(findings), findings
    assert "pr-coverage-gap" not in rule_ids(findings), findings
    # Sanity: the documented carrier model is actually exercised.
    assert REAL_LEDGER.count("pr: 8\n") > 1
    assert REAL_LEDGER.count("pr: 10\n") > 1
    assert REAL_LEDGER.count("pr: 11\n") > 1


def test_commit_set_without_ref_head_passes() -> None:
    """The two commit_set items carry no ref/head and validate clean."""
    assert "kind: commit_set" in REAL_LEDGER
    findings = vrd.validate_disposition(ROOT)
    assert "source-ref-required" not in rule_ids(findings), findings
    assert "source-identity" not in rule_ids(findings), findings


# ---------------------------------------------------------------------------
# Fail cases (one mutation each against a tmp copy of the real ledger)
# ---------------------------------------------------------------------------


def test_duplicate_item_id(tmp_path: Path) -> None:
    root = mutated_root(
        tmp_path, "- id: public-evidence-redaction", "- id: legal-licensing-governance"
    )
    findings = findings_for(root)
    assert "duplicate-item-id" in rule_ids(findings), findings


def test_invalid_decision(tmp_path: Path) -> None:
    root = mutated_root(tmp_path, "    decision: unresolved\n", "    decision: maybe\n")
    findings = findings_for(root)
    assert "invalid-decision" in rule_ids(findings), findings


def test_short_commit_sha(tmp_path: Path) -> None:
    root = mutated_root(
        tmp_path,
        "- 9f215c66b0c50e26aa21b1dfb6670c092150235d",
        "- 9f215c6",
    )
    findings = findings_for(root)
    assert "commit-sha-format" in rule_ids(findings), findings


def test_unresolvable_commit_sha(tmp_path: Path) -> None:
    root = mutated_root(
        tmp_path,
        "7e43f2974636546b2758a565b7db6a6d5a80551f",
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    )
    findings = findings_for(root)
    assert "commit-is-commit" in rule_ids(findings), findings


def test_missing_decision_status(tmp_path: Path) -> None:
    root = mutated_root(tmp_path, "    decisionStatus: proposed\n", "")
    findings = findings_for(root)
    assert "decision-status" in rule_ids(findings), findings


def test_accepted_without_owner_metadata(tmp_path: Path) -> None:
    root = mutated_root(
        tmp_path, "    decisionStatus: proposed\n", "    decisionStatus: accepted\n"
    )
    findings = findings_for(root)
    assert "owner-acceptance-incomplete" in rule_ids(findings), findings


def test_port_with_blockers(tmp_path: Path) -> None:
    anchor = (
        "    decisionStatus: proposed\n"
        "    securityImplications: >\n"
        "      Supply-chain provenance; keeps Debian signature verification."
    )
    assert REAL_LEDGER.count(anchor) == 1
    root = mutated_root(
        tmp_path,
        anchor,
        "    decisionStatus: proposed\n"
        "    blockers:\n"
        "      - runner digest not re-resolved\n"
        "    securityImplications: >\n"
        "      Supply-chain provenance; keeps Debian signature verification.",
    )
    findings = findings_for(root)
    assert "port-with-blockers" in rule_ids(findings), findings


def test_decision_counts_mismatch(tmp_path: Path) -> None:
    assert REAL_LEDGER.count("    port: 16") == 1
    root = mutated_root(tmp_path, "    port: 16", "    port: 15")
    findings = findings_for(root)
    assert "decision-counts-mismatch" in rule_ids(findings), findings


def test_pr12_in_two_items(tmp_path: Path) -> None:
    anchor = "      pr: 13\n"
    assert REAL_LEDGER.count(anchor) == 1
    root = mutated_root(tmp_path, anchor, "      pr: 12\n")
    findings = findings_for(root)
    assert "pr-multi-attribution" in rule_ids(findings), findings
    assert any("PR 12" in f.message for f in findings if f.rule == "pr-multi-attribution")


def test_pr13_missing_from_all_items(tmp_path: Path) -> None:
    anchor = "      pr: 13\n"
    assert REAL_LEDGER.count(anchor) == 1
    # Re-attribute the PR #13 item to carrier PR 8 (multi allowed there),
    # leaving PR 13 covered by no item.
    root = mutated_root(tmp_path, anchor, "      pr: 8\n")
    findings = findings_for(root)
    assert "pr-coverage-gap" in rule_ids(findings), findings
    assert any("PR 13" in f.message for f in findings if f.rule == "pr-coverage-gap")


def test_pr_out_of_range(tmp_path: Path) -> None:
    anchor = "      pr: 21\n"
    assert REAL_LEDGER.count(anchor) == 1
    root = mutated_root(tmp_path, anchor, "      pr: 22\n")
    findings = findings_for(root)
    assert "pr-out-of-range" in rule_ids(findings), findings


def test_invalid_current_main_equivalent(tmp_path: Path) -> None:
    root = mutated_root(
        tmp_path, "    currentMainEquivalent: none\n", "    currentMainEquivalent: unknown\n"
    )
    findings = findings_for(root)
    assert "invalid-equivalence" in rule_ids(findings), findings


def test_dangling_superseded_by(tmp_path: Path) -> None:
    anchor = "supersededBy: release-bundle-v2-and-safe-publication"
    assert REAL_LEDGER.count(anchor) == 1
    root = mutated_root(tmp_path, anchor, "supersededBy: no-such-item")
    findings = findings_for(root)
    assert "dangling-reference" in rule_ids(findings), findings


def test_flow_style_list_regression(tmp_path: Path) -> None:
    anchor = (
        "    requiredTests:\n"
        "      - validate_repo passes\n"
        "      - public-release audit gate recognizes the files"
    )
    assert REAL_LEDGER.count(anchor) == 1
    root = mutated_root(tmp_path, anchor, "    requiredTests: [validate_repo passes]")
    findings = findings_for(root)
    assert "list-type-error" in rule_ids(findings), findings
    assert any(
        "flow-style" in f.message for f in findings if f.rule == "list-type-error"
    ), findings


# ---------------------------------------------------------------------------
# Git-binding fail cases (typed source contract)
# ---------------------------------------------------------------------------


def test_blob_sha_rejected_as_head(tmp_path: Path) -> None:
    objects, blob, _tree = make_object_repo(tmp_path)
    anchor = "      head: 27f957fa819289490852698c148f6b2eebddb4f9\n"
    assert REAL_LEDGER.count(anchor) >= 1
    root = mutated_root(tmp_path, anchor, f"      head: {blob}\n")
    findings = findings_for(root, git_root=objects)
    assert "head-is-commit" in rule_ids(findings), findings
    assert any(
        blob in f.message for f in findings if f.rule == "head-is-commit"
    ), findings


def test_tree_sha_rejected_as_commit(tmp_path: Path) -> None:
    objects, _blob, tree = make_object_repo(tmp_path)
    root = mutated_root(
        tmp_path,
        "- 9f215c66b0c50e26aa21b1dfb6670c092150235d",
        f"- {tree}",
    )
    findings = findings_for(root, git_root=objects)
    assert "commit-is-commit" in rule_ids(findings), findings
    assert any(
        tree in f.message for f in findings if f.rule == "commit-is-commit"
    ), findings


def test_unrelated_commit_rejected(tmp_path: Path) -> None:
    # 235d115f (PR #12 head) is not an ancestor of the archive tip the
    # legal-licensing item binds to.
    root = mutated_root(
        tmp_path,
        "- 9f215c66b0c50e26aa21b1dfb6670c092150235d",
        "- 235d115f970df77410df85999bc143032bd942b2",
    )
    findings = findings_for(root)
    assert "commit-reachable-from-head" in rule_ids(findings), findings


def test_ref_head_mismatch(tmp_path: Path) -> None:
    anchor = "      head: 27f957fa819289490852698c148f6b2eebddb4f9\n"
    assert REAL_LEDGER.count(anchor) >= 1
    # PR #8 head resolves and is a commit, but is not the archive branch tip.
    root = mutated_root(
        tmp_path, anchor, "      head: 3d22708b9b932fa6e361627c6e54bf95119a0e79\n"
    )
    findings = findings_for(root)
    assert "ref-matches-head" in rule_ids(findings), findings


def test_non_resolving_ref(tmp_path: Path) -> None:
    anchor = (
        "      ref: refs/remotes/origin/archive/reconciliation/2026-07-25/pr-21-head\n"
    )
    assert REAL_LEDGER.count(anchor) == 1
    root = mutated_root(
        tmp_path,
        anchor,
        "      ref: refs/remotes/origin/archive/reconciliation/2026-07-25/pr-99-head\n",
    )
    findings = findings_for(root)
    assert "ref-resolves" in rule_ids(findings), findings
    assert any(
        "ARCHIVE_REF_PLAN" in f.message for f in findings if f.rule == "ref-resolves"
    ), findings


def test_aggregated_sources_entry_mismatch(tmp_path: Path) -> None:
    anchor = (
        "        ref: refs/remotes/origin/archive/reconciliation/2026-07-25/pr-17-head\n"
        "        head: a49e3a8888d7a1f291fa341d107df1a79f050821\n"
    )
    assert REAL_LEDGER.count(anchor) == 1
    root = mutated_root(
        tmp_path,
        anchor,
        "        ref: refs/remotes/origin/archive/reconciliation/2026-07-25/pr-17-head\n"
        "        head: cdc911ea769cd7192c141339c45411045359f864\n",
    )
    findings = findings_for(root)
    assert "ref-matches-head" in rule_ids(findings), findings


# ---------------------------------------------------------------------------
# Typed extension fields (reviewClassification / ownerGate / implementation)
# ---------------------------------------------------------------------------

TYPED_EXTENSION_BLOCK = (
    "    reviewClassification:\n"
    "      decision: port_as_appropriate\n"
    "      approvalStatus: technically_approved\n"
    "    ownerGate:\n"
    "      type: licence_reconfirmation\n"
    "      status: satisfied\n"
    "      ownerIdentity: Lennert Van Hoyweghen\n"
    '      ownerDecisionDate: "2026-07-25"\n'
    "      decisionRecord: WORKLOG.md\n"
    "    implementation:\n"
    "      status: implemented_on_private_review_branch\n"
    "      branch: agent/alpha-public-legal-boundary-001\n"
    "      head: 1fc30ac637ada5a3741bc8cd575b3dc936481eb9\n"
    "      mergedToCanonical: false\n"
    "      headNote: >\n"
    "        names the branch head this record was last reconciled to; updated\n"
    "        at each Phase 1 closure commit on the branch\n"
)


def test_typed_extension_fields_present_and_valid() -> None:
    """The legal-licensing-governance item carries valid typed extensions."""
    assert TYPED_EXTENSION_BLOCK in REAL_LEDGER
    findings = vrd.validate_disposition(ROOT)
    assert "review-classification" not in rule_ids(findings), findings
    assert "owner-gate" not in rule_ids(findings), findings
    assert "implementation" not in rule_ids(findings), findings
    assert "implementation-head-unresolved" not in rule_ids(findings), findings


def test_ledger_without_typed_extensions_still_passes(tmp_path: Path) -> None:
    """The new fields are optional: a ledger without them validates clean."""
    root = mutated_root(tmp_path, TYPED_EXTENSION_BLOCK, "")
    findings = findings_for(root)
    assert findings == [], findings


def test_invalid_review_classification_decision(tmp_path: Path) -> None:
    root = mutated_root(
        tmp_path, "      decision: port_as_appropriate\n", "      decision: port_maybe\n"
    )
    findings = findings_for(root)
    assert "review-classification" in rule_ids(findings), findings


def test_invalid_review_classification_approval(tmp_path: Path) -> None:
    root = mutated_root(
        tmp_path,
        "      approvalStatus: technically_approved\n",
        "      approvalStatus: rubber_stamped\n",
    )
    findings = findings_for(root)
    assert "review-classification" in rule_ids(findings), findings


def test_invalid_owner_gate_status(tmp_path: Path) -> None:
    assert REAL_LEDGER.count("      status: satisfied\n") == 1
    root = mutated_root(tmp_path, "      status: satisfied\n", "      status: unknown\n")
    findings = findings_for(root)
    assert "owner-gate" in rule_ids(findings), findings


def test_invalid_owner_gate_date(tmp_path: Path) -> None:
    root = mutated_root(
        tmp_path,
        '      ownerDecisionDate: "2026-07-25"\n',
        '      ownerDecisionDate: "25-07-2026"\n',
    )
    findings = findings_for(root)
    assert "owner-gate" in rule_ids(findings), findings


def test_owner_gate_missing_field(tmp_path: Path) -> None:
    root = mutated_root(tmp_path, "      decisionRecord: WORKLOG.md\n", "")
    findings = findings_for(root)
    assert "owner-gate" in rule_ids(findings), findings


def test_invalid_implementation_status(tmp_path: Path) -> None:
    root = mutated_root(
        tmp_path,
        "      status: implemented_on_private_review_branch\n",
        "      status: shipped\n",
    )
    findings = findings_for(root)
    assert "implementation" in rule_ids(findings), findings


def test_implementation_missing_field(tmp_path: Path) -> None:
    root = mutated_root(
        tmp_path, "      branch: agent/alpha-public-legal-boundary-001\n", ""
    )
    findings = findings_for(root)
    assert "implementation" in rule_ids(findings), findings


def test_implementation_head_not_hex(tmp_path: Path) -> None:
    root = mutated_root(
        tmp_path,
        "      head: 1fc30ac637ada5a3741bc8cd575b3dc936481eb9\n",
        "      head: 7fb85b0\n",
    )
    findings = findings_for(root)
    assert "implementation" in rule_ids(findings), findings


def test_implementation_head_unresolved(tmp_path: Path) -> None:
    root = mutated_root(
        tmp_path,
        "      head: 1fc30ac637ada5a3741bc8cd575b3dc936481eb9\n",
        "      head: deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n",
    )
    findings = findings_for(root)
    assert "implementation-head-unresolved" in rule_ids(findings), findings


def test_implementation_merged_flag_not_boolean(tmp_path: Path) -> None:
    root = mutated_root(
        tmp_path,
        "      mergedToCanonical: false\n",
        "      mergedToCanonical: not_yet\n",
    )
    findings = findings_for(root)
    assert "implementation" in rule_ids(findings), findings


def test_cli_exit_codes(tmp_path: Path) -> None:
    ok = subprocess.run(
        [sys.executable, str(VALIDATOR), str(ROOT)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert ok.returncode == 0, ok.stdout + ok.stderr

    bad_root = mutated_root(tmp_path, "    decision: unresolved\n", "    decision: maybe\n")
    failed = subprocess.run(
        [sys.executable, str(VALIDATOR), str(bad_root), "--git-root", str(ROOT)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert failed.returncode == 1
    assert "invalid-decision" in failed.stdout


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
