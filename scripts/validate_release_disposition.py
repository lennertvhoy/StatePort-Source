#!/usr/bin/env python3
"""Validate the release work disposition ledger as machine-checked release authority.

The ledger (docs/release/RELEASE_WORK_DISPOSITION.yaml) dispositions all
release-engineering work on closed PRs #8-#21 and the retained archive
branch before any of it is ported into main. This validator makes the
ledger a gate: it checks the document against
schemas/release-disposition.v1.schema.json (via the repository's
lightweight JSON Schema subset checker) and then enforces the semantic
rules below, each with a stable rule id.

Rules (rule id in parentheses):

- formatVersion and required metadata fields, baseHead a 40-char SHA
  (format-version, metadata-field).
- Unique item ids (duplicate-item-id).
- decision in port | superseded | reject | unresolved | transient_carrier
  | validation_only (invalid-decision).
- decisionStatus in proposed | accepted | rejected (decision-status);
  accepted/rejected requires ownerIdentity and an ownerDecisionDate in
  YYYY-MM-DD form (owner-acceptance-incomplete).
- Typed source contract on every item: exactly one of source (a single
  typed source) or sources (an aggregated list) is present
  (source-identity); kind in pr_head | branch_tip | commit_set
  (source-kind-valid); pr is a required integer iff kind == pr_head and
  forbidden otherwise (source-pr-required); ref and head are required
  unless kind == commit_set and forbidden for commit_set
  (source-ref-required).
- Git binding (30s timeouts, fail closed as git-error): head names a
  commit — git rev-parse --verify --quiet <sha>^{commit}, so a blob or
  tree SHA fails (head-is-commit); ref resolves to a commit
  (ref-resolves, with an actionable fetch message); the resolved ref
  equals head (ref-matches-head); every commits entry is 40-char
  lowercase hex (commit-sha-format) and names a commit
  (commit-is-commit); every commits entry is an ancestor of head via
  git merge-base --is-ancestor (commit-reachable-from-head).
- Source identity for commit_set items: an item with no commits must
  carry provenance: provenance_missing (source-identity).
- Non-empty purpose and reason (empty-purpose, empty-reason).
- Typed equivalence: currentMainEquivalent is ``none`` or ``n/a``
  (optionally followed by an em-dash explanation), or starts with
  ``partial:`` or ``equivalent:`` (invalid-equivalence).
- requiredReview and requiredTests keys are present
  (missing-review-tests-keys) and are lists; any field that must be a
  list but parses as a string indicates a flow-style regression, because
  the strict statedd_core YAML parser reads flow collections as strings
  (list-type-error).
- An item with a non-empty blockers list must not have decision: port
  (port-with-blockers).
- metadata.decisionCounts matches the actual per-decision item counts
  (decision-counts-mismatch).
- PR coverage from the typed pr fields (source.pr / sources[].pr): every
  PR 8..21 appears in metadata.coveredPrs and in at least one item
  (pr-coverage-gap); PRs 9 and 12..21 appear in exactly one item
  (pr-multi-attribution); PRs 8, 10, 11 are carrier lines and may be
  partitioned across multiple items (documented model); no pr value
  outside 8..21 (pr-out-of-range).
- supersededBy / representedBy reference existing item ids
  (dangling-reference).
- Optional typed extension fields on items, fail-closed when present:
  reviewClassification.decision in unresolved | port_as_appropriate |
  superseded | rejected and .approvalStatus in technically_approved |
  pending | rejected, both required when the object is present
  (review-classification); ownerGate requires type (non-empty string),
  status in satisfied | pending | blocked, ownerIdentity (non-empty
  string), ownerDecisionDate in YYYY-MM-DD form, and decisionRecord
  (non-empty string) (owner-gate); implementation requires status in
  implemented_on_private_review_branch | not_started | in_progress |
  ported_to_canonical | superseded, a non-empty branch string, a 40-char
  lowercase hex head that resolves to a commit via git (no ancestry
  requirement — the named branch advances; resolving is enough), and a
  boolean mergedToCanonical, with headNote a non-empty string when
  present (implementation, implementation-head-unresolved).

Intentionally stdlib-only plus statedd_core.yaml.parse_yaml_text,
mirroring validate_state_consistency.py. Importable:
validate_disposition() returns findings; main() wraps the CLI.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

CORE_SRC = REPO_ROOT / "packages" / "statedd-core" / "src"
if str(CORE_SRC) not in sys.path:
    sys.path.insert(0, str(CORE_SRC))
if str(REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "scripts"))

from statedd_core.yaml import StateDDYamlError, parse_yaml_text
from statedd_validate_schema import validate_json_schema

LEDGER_FILE = "docs/release/RELEASE_WORK_DISPOSITION.yaml"
SCHEMA_FILE = "schemas/release-disposition.v1.schema.json"

FORMAT_VERSION = "stateport.release-disposition/v1"
ALLOWED_DECISIONS = (
    "port",
    "superseded",
    "reject",
    "unresolved",
    "transient_carrier",
    "validation_only",
)
DECISION_STATUSES = ("proposed", "accepted", "rejected")
SOURCE_KINDS = ("pr_head", "branch_tip", "commit_set")
REQUIRED_METADATA_FIELDS = ("baseHead", "phase", "coveredPrs", "decisionCounts", "status")
COVERED_PRS = tuple(range(8, 22))
# Carrier lines whose content is legitimately partitioned across multiple
# archive-sourced items; every other PR must map to exactly one item.
CARRIER_PRS = (8, 10, 11)
EXACTLY_ONCE_PRS = tuple(pr for pr in COVERED_PRS if pr not in CARRIER_PRS)

REVIEW_CLASSIFICATION_DECISIONS = ("unresolved", "port_as_appropriate", "superseded", "rejected")
REVIEW_CLASSIFICATION_APPROVALS = ("technically_approved", "pending", "rejected")
OWNER_GATE_STATUSES = ("satisfied", "pending", "blocked")
IMPLEMENTATION_STATUSES = (
    "implemented_on_private_review_branch",
    "not_started",
    "in_progress",
    "ported_to_canonical",
    "superseded",
)

SHA_RE = re.compile(r"[0-9a-f]{40}")
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
# Typed equivalence token: exactly "none"/"n/a", either bare or followed by
# an em-dash explanation, or a "partial:"/"equivalent:" prefixed description.
EQUIVALENCE_RE = re.compile(r"^(none|n/a)$|^(none|n/a) — |^partial:|^equivalent:")
GIT_TIMEOUT_SECONDS = 30

FETCH_HINT = (
    "the ledger binds durable archive branches under "
    "refs/remotes/origin/archive/reconciliation/2026-07-25/ "
    "(docs/release/ARCHIVE_REF_PLAN.yaml, pushed_verified); a normal clone's "
    "default fetch includes them — run git fetch origin and re-check"
)


@dataclass(frozen=True)
class Finding:
    """One ledger violation, addressed by item id (or ledger section)."""

    item: str
    rule: str
    message: str

    def render(self) -> str:
        return f"RULE {self.rule} [{self.item}]: {self.message}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _expect_list(
    findings: list[Finding], item: str, field: str, value: Any
) -> list | None:
    """Return value as a list, or record a list-type-error finding.

    A string here means someone reintroduced a flow-style collection
    (``field: [a, b]``), which the strict statedd_core parser reads as a
    plain string; the message says so explicitly.
    """
    if isinstance(value, str):
        findings.append(
            Finding(
                item,
                "list-type-error",
                f"{field} parsed as a string, not a list — flow-style "
                f"collections ({field}: [...]) are read as strings by the "
                "strict parser; use block-style '- entry' lists",
            )
        )
        return None
    if not isinstance(value, list):
        findings.append(
            Finding(
                item,
                "list-type-error",
                f"{field} must be a list, got {type(value).__name__}",
            )
        )
        return None
    return value


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _git_resolve_commit(git_root: Path, ref: str) -> str | None:
    """Resolve ref^{commit} to a SHA, or None on any failure (fail closed)."""
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
            cwd=git_root,
            capture_output=True,
            text=True,
            check=False,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    resolved = completed.stdout.strip()
    return resolved or None


def _git_is_ancestor(git_root: Path, commit: str, head: str) -> bool | None:
    """True/False for a definitive answer, None when git itself failed."""
    try:
        completed = subprocess.run(
            ["git", "merge-base", "--is-ancestor", commit, head],
            cwd=git_root,
            capture_output=True,
            text=True,
            check=False,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return completed.returncode == 0


# ---------------------------------------------------------------------------
# Rule checks
# ---------------------------------------------------------------------------


def check_schema(data: Any, schema: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for issue in validate_json_schema(data, schema):
        findings.append(Finding(issue.path, "schema-violation", issue.message))
    return findings


def check_metadata(data: dict, findings: list[Finding]) -> dict[str, int] | None:
    """Validate metadata; return the recorded decisionCounts mapping or None."""
    metadata = data.get("metadata")
    if not isinstance(metadata, dict):
        findings.append(Finding("metadata", "metadata-field", "metadata section is missing or not a mapping"))
        return None
    for field in REQUIRED_METADATA_FIELDS:
        if field not in metadata:
            findings.append(Finding("metadata", "metadata-field", f"required metadata field {field!r} is missing"))
    base_head = metadata.get("baseHead")
    if base_head is not None and not (isinstance(base_head, str) and SHA_RE.fullmatch(base_head)):
        findings.append(
            Finding("metadata", "metadata-field", f"baseHead must be a 40-char lowercase hex SHA, got {base_head!r}")
        )
    covered = metadata.get("coveredPrs")
    covered_list = _expect_list(findings, "metadata", "coveredPrs", covered) if covered is not None else None
    if covered_list is not None:
        for pr in COVERED_PRS:
            if pr not in covered_list:
                findings.append(
                    Finding("metadata", "pr-coverage-gap", f"PR {pr} is missing from metadata.coveredPrs")
                )
    decision_counts = metadata.get("decisionCounts")
    if decision_counts is not None and not isinstance(decision_counts, dict):
        findings.append(
            Finding("metadata", "metadata-field", "decisionCounts must be a mapping of decision to count")
        )
    return decision_counts if isinstance(decision_counts, dict) else None


def check_typed_source(
    entry: dict,
    item_id: str,
    label: str,
    git_root: Path,
    findings: list[Finding],
    pr_owners: dict[int, list[str]],
    provenance_missing: bool,
) -> None:
    """Validate one typed source block of an item."""
    kind = entry.get("kind")
    if kind not in SOURCE_KINDS:
        findings.append(
            Finding(item_id, "source-kind-valid", f"{label}: kind must be one of {SOURCE_KINDS}, got {kind!r}")
        )
        return

    pr = entry.get("pr")
    if kind == "pr_head":
        if not _is_int(pr):
            findings.append(
                Finding(item_id, "source-pr-required", f"{label}: kind pr_head requires an integer pr field, got {pr!r}")
            )
        elif pr not in COVERED_PRS:
            findings.append(
                Finding(item_id, "pr-out-of-range", f"{label}: pr value {pr} is outside the covered range 8..21")
            )
        else:
            pr_owners.setdefault(pr, []).append(item_id)
    elif pr is not None:
        findings.append(
            Finding(item_id, "source-pr-required", f"{label}: pr is only allowed when kind is pr_head (kind is {kind!r})")
        )

    ref = entry.get("ref")
    head = entry.get("head")
    if kind == "commit_set":
        if ref is not None or head is not None:
            findings.append(
                Finding(item_id, "source-ref-required", f"{label}: kind commit_set must not declare ref or head")
            )
    else:
        if not isinstance(ref, str) or not ref:
            findings.append(
                Finding(item_id, "source-ref-required", f"{label}: kind {kind} requires a non-empty ref field")
            )
        if not isinstance(head, str) or not SHA_RE.fullmatch(head):
            findings.append(
                Finding(item_id, "source-ref-required", f"{label}: kind {kind} requires head as a 40-char lowercase hex SHA, got {head!r}")
            )
        else:
            if _git_resolve_commit(git_root, head) is None:
                findings.append(
                    Finding(item_id, "head-is-commit", f"{label}: head {head} does not resolve to a commit (rev-parse {head}^{{commit}} failed; a blob or tree SHA is not a head)")
                )
        if isinstance(ref, str) and ref and isinstance(head, str) and SHA_RE.fullmatch(head):
            resolved = _git_resolve_commit(git_root, ref)
            if resolved is None:
                findings.append(
                    Finding(item_id, "ref-resolves", f"{label}: ref {ref!r} does not resolve to a commit; {FETCH_HINT}")
                )
            elif resolved != head:
                findings.append(
                    Finding(item_id, "ref-matches-head", f"{label}: ref {ref!r} resolves to {resolved}, not the recorded head {head}")
                )

    commits = _expect_list(findings, item_id, f"{label}.commits", entry.get("commits"))
    if commits is None:
        return
    head_usable = (
        kind != "commit_set"
        and isinstance(head, str)
        and SHA_RE.fullmatch(head)
        and _git_resolve_commit(git_root, head) is not None
    )
    for sha in commits:
        if not isinstance(sha, str) or not SHA_RE.fullmatch(sha):
            findings.append(
                Finding(item_id, "commit-sha-format", f"{label}: commits entry must be a 40-char lowercase hex SHA, got {sha!r}")
            )
            continue
        if _git_resolve_commit(git_root, sha) is None:
            findings.append(
                Finding(item_id, "commit-is-commit", f"{label}: commits entry {sha} does not resolve to a commit (a blob or tree SHA is not a commit)")
            )
            continue
        if head_usable:
            ancestor = _git_is_ancestor(git_root, sha, head)
            if ancestor is None:
                findings.append(
                    Finding(item_id, "git-error", f"{label}: git merge-base --is-ancestor {sha} {head} failed; failing closed")
                )
            elif not ancestor:
                findings.append(
                    Finding(item_id, "commit-reachable-from-head", f"{label}: commit {sha} is not an ancestor of head {head}")
                )

    if kind == "commit_set" and not commits and not provenance_missing:
        findings.append(
            Finding(
                item_id,
                "source-identity",
                f"{label}: commit_set with no commits requires provenance: provenance_missing on the item",
            )
        )


def check_typed_extensions(
    entry: dict, item_id: str, git_root: Path, findings: list[Finding]
) -> None:
    """Validate the optional typed extension objects on an item.

    All three objects are optional, but when present every rule fails
    closed on malformed values.
    """
    review = entry.get("reviewClassification")
    if review is not None:
        if not isinstance(review, dict):
            findings.append(
                Finding(item_id, "review-classification", f"reviewClassification must be a mapping, got {type(review).__name__}")
            )
        else:
            decision = review.get("decision")
            if decision not in REVIEW_CLASSIFICATION_DECISIONS:
                findings.append(
                    Finding(
                        item_id,
                        "review-classification",
                        f"reviewClassification.decision must be one of {REVIEW_CLASSIFICATION_DECISIONS}, got {decision!r}",
                    )
                )
            approval = review.get("approvalStatus")
            if approval not in REVIEW_CLASSIFICATION_APPROVALS:
                findings.append(
                    Finding(
                        item_id,
                        "review-classification",
                        f"reviewClassification.approvalStatus must be one of {REVIEW_CLASSIFICATION_APPROVALS}, got {approval!r}",
                    )
                )

    owner_gate = entry.get("ownerGate")
    if owner_gate is not None:
        if not isinstance(owner_gate, dict):
            findings.append(
                Finding(item_id, "owner-gate", f"ownerGate must be a mapping, got {type(owner_gate).__name__}")
            )
        else:
            for field in ("type", "status", "ownerIdentity", "ownerDecisionDate", "decisionRecord"):
                if field not in owner_gate:
                    findings.append(
                        Finding(item_id, "owner-gate", f"ownerGate is missing required field {field!r}")
                    )
            for field in ("type", "ownerIdentity", "decisionRecord"):
                value = owner_gate.get(field)
                if value is not None and (not isinstance(value, str) or not value.strip()):
                    findings.append(
                        Finding(item_id, "owner-gate", f"ownerGate.{field} must be a non-empty string, got {value!r}")
                    )
            status = owner_gate.get("status")
            if status is not None and status not in OWNER_GATE_STATUSES:
                findings.append(
                    Finding(item_id, "owner-gate", f"ownerGate.status must be one of {OWNER_GATE_STATUSES}, got {status!r}")
                )
            date = owner_gate.get("ownerDecisionDate")
            if date is not None and (not isinstance(date, str) or not DATE_RE.fullmatch(date)):
                findings.append(
                    Finding(item_id, "owner-gate", f"ownerGate.ownerDecisionDate must be in YYYY-MM-DD form, got {date!r}")
                )

    implementation = entry.get("implementation")
    if implementation is not None:
        if not isinstance(implementation, dict):
            findings.append(
                Finding(item_id, "implementation", f"implementation must be a mapping, got {type(implementation).__name__}")
            )
        else:
            for field in ("status", "branch", "head", "mergedToCanonical"):
                if field not in implementation:
                    findings.append(
                        Finding(item_id, "implementation", f"implementation is missing required field {field!r}")
                    )
            status = implementation.get("status")
            if status is not None and status not in IMPLEMENTATION_STATUSES:
                findings.append(
                    Finding(item_id, "implementation", f"implementation.status must be one of {IMPLEMENTATION_STATUSES}, got {status!r}")
                )
            branch = implementation.get("branch")
            if branch is not None and (not isinstance(branch, str) or not branch.strip()):
                findings.append(
                    Finding(item_id, "implementation", f"implementation.branch must be a non-empty string, got {branch!r}")
                )
            merged = implementation.get("mergedToCanonical")
            if merged is not None and not isinstance(merged, bool):
                findings.append(
                    Finding(item_id, "implementation", f"implementation.mergedToCanonical must be a boolean, got {merged!r}")
                )
            head_note = implementation.get("headNote")
            if head_note is not None and (not isinstance(head_note, str) or not head_note.strip()):
                findings.append(
                    Finding(item_id, "implementation", f"implementation.headNote must be a non-empty string when present, got {head_note!r}")
                )
            head = implementation.get("head")
            if head is not None:
                if not isinstance(head, str) or not SHA_RE.fullmatch(head):
                    findings.append(
                        Finding(item_id, "implementation", f"implementation.head must be a 40-char lowercase hex SHA, got {head!r}")
                    )
                elif _git_resolve_commit(git_root, head) is None:
                    findings.append(
                        Finding(
                            item_id,
                            "implementation-head-unresolved",
                            f"implementation.head {head} does not resolve to a commit "
                            "(rev-parse failed; the recorded reconciliation head must exist "
                            "in the repository — no ancestry to the branch tip is required "
                            "because the branch advances)",
                        )
                    )


def check_items(
    data: dict, git_root: Path, findings: list[Finding]
) -> dict[str, int]:
    """Validate items; return the actual per-decision counts."""
    counts = {decision: 0 for decision in ALLOWED_DECISIONS}
    items = data.get("items")
    if not isinstance(items, list):
        findings.append(Finding("items", "list-type-error", "items must be a list"))
        return counts

    ids: list[str] = [
        entry["id"] for entry in items if isinstance(entry, dict) and isinstance(entry.get("id"), str)
    ]
    id_set = set(ids)
    pr_owners: dict[int, list[str]] = {}

    for index, entry in enumerate(items):
        label = f"items[{index}]"
        if not isinstance(entry, dict):
            findings.append(Finding(label, "schema-violation", "item is not a mapping"))
            continue
        item_id = entry.get("id")
        if not isinstance(item_id, str) or not item_id:
            findings.append(Finding(label, "schema-violation", "item is missing a string id"))
            continue
        if ids.count(item_id) > 1 and ids.index(item_id) == index:
            findings.append(Finding(item_id, "duplicate-item-id", f"item id {item_id!r} appears more than once"))

        decision = entry.get("decision")
        if decision not in ALLOWED_DECISIONS:
            findings.append(
                Finding(item_id, "invalid-decision", f"decision must be one of {ALLOWED_DECISIONS}, got {decision!r}")
            )
        else:
            counts[decision] += 1

        status = entry.get("decisionStatus")
        if status is None:
            findings.append(Finding(item_id, "decision-status", "decisionStatus is missing"))
        elif status not in DECISION_STATUSES:
            findings.append(
                Finding(item_id, "decision-status", f"decisionStatus must be one of {DECISION_STATUSES}, got {status!r}")
            )
        elif status in {"accepted", "rejected"}:
            owner = entry.get("ownerIdentity")
            date = entry.get("ownerDecisionDate")
            if not isinstance(owner, str) or not owner.strip():
                findings.append(
                    Finding(
                        item_id,
                        "owner-acceptance-incomplete",
                        f"decisionStatus {status!r} requires a non-empty ownerIdentity field",
                    )
                )
            if not isinstance(date, str) or not DATE_RE.fullmatch(date):
                findings.append(
                    Finding(
                        item_id,
                        "owner-acceptance-incomplete",
                        f"decisionStatus {status!r} requires ownerDecisionDate in YYYY-MM-DD form, got {date!r}",
                    )
                )

        provenance_missing = entry.get("provenance") == "provenance_missing"
        source = entry.get("source")
        sources = entry.get("sources")
        if isinstance(source, dict) and sources is None:
            check_typed_source(source, item_id, "source", git_root, findings, pr_owners, provenance_missing)
        elif isinstance(sources, list) and source is None:
            if not sources:
                findings.append(Finding(item_id, "source-identity", "sources list is empty"))
            for source_index, sub in enumerate(sources):
                sub_label = f"sources[{source_index}]"
                if not isinstance(sub, dict):
                    findings.append(Finding(item_id, "schema-violation", f"{sub_label} is not a mapping"))
                    continue
                check_typed_source(sub, item_id, sub_label, git_root, findings, pr_owners, provenance_missing)
        else:
            findings.append(
                Finding(
                    item_id,
                    "source-identity",
                    "item must declare exactly one of source (typed source) or sources (aggregated typed sources)",
                )
            )

        purpose = entry.get("purpose")
        if not isinstance(purpose, str) or not purpose.strip():
            findings.append(Finding(item_id, "empty-purpose", "purpose must be a non-empty string"))
        reason = entry.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            findings.append(Finding(item_id, "empty-reason", "reason must be a non-empty string"))

        equivalence = entry.get("currentMainEquivalent")
        if not isinstance(equivalence, str) or not EQUIVALENCE_RE.search(equivalence):
            findings.append(
                Finding(
                    item_id,
                    "invalid-equivalence",
                    "currentMainEquivalent must be 'none' or 'n/a' (optionally with an "
                    "em-dash explanation), or start with 'partial:' or 'equivalent:', "
                    f"got {equivalence!r}",
                )
            )

        for field in ("requiredReview", "requiredTests"):
            if field not in entry:
                findings.append(Finding(item_id, "missing-review-tests-keys", f"required key {field!r} is missing"))
            else:
                _expect_list(findings, item_id, field, entry[field])

        blockers = entry.get("blockers")
        if blockers is not None:
            blocker_list = _expect_list(findings, item_id, "blockers", blockers)
            if blocker_list and decision == "port":
                findings.append(
                    Finding(
                        item_id,
                        "port-with-blockers",
                        f"decision is 'port' but blockers is non-empty: {blocker_list}",
                    )
                )

        check_typed_extensions(entry, item_id, git_root, findings)

        superseded_by = entry.get("supersededBy")
        if superseded_by is not None and superseded_by not in id_set:
            findings.append(
                Finding(item_id, "dangling-reference", f"supersededBy references unknown item id {superseded_by!r}")
            )
        represented_by = entry.get("representedBy")
        if represented_by is not None:
            represented_list = _expect_list(findings, item_id, "representedBy", represented_by)
            if represented_list is not None:
                for referenced in represented_list:
                    if referenced not in id_set:
                        findings.append(
                            Finding(item_id, "dangling-reference", f"representedBy references unknown item id {referenced!r}")
                        )

    # PR coverage across items (from typed source.pr / sources[].pr).
    for pr in COVERED_PRS:
        owners = pr_owners.get(pr, [])
        if not owners:
            findings.append(Finding(f"pr-{pr}", "pr-coverage-gap", f"PR {pr} appears in no item's source.pr"))
        elif pr in EXACTLY_ONCE_PRS and len(owners) > 1:
            findings.append(
                Finding(
                    f"pr-{pr}",
                    "pr-multi-attribution",
                    f"PR {pr} must map to exactly one item but appears in: {owners}",
                )
            )

    return counts


# ---------------------------------------------------------------------------
# Orchestration and CLI
# ---------------------------------------------------------------------------


def validate_disposition(root: Path, git_root: Path | None = None) -> list[Finding]:
    """Return all release-disposition ledger findings under root.

    ``root`` locates the ledger file; ``git_root`` locates the repository
    used to resolve refs and commit SHAs (defaults to ``root``). Tests
    pass a temporary ledger root together with the real repository as
    git_root.
    """
    git_root = git_root if git_root is not None else root
    findings: list[Finding] = []

    path = root / LEDGER_FILE
    if not path.is_file():
        return [Finding("ledger", "missing-ledger", f"{LEDGER_FILE} not found under {root}")]
    raw = path.read_text(encoding="utf-8")
    try:
        data = parse_yaml_text(raw)
    except StateDDYamlError as exc:
        return [Finding("ledger", "ledger-unparseable", str(exc))]
    if not isinstance(data, dict):
        return [Finding("ledger", "ledger-unparseable", "top-level YAML value is not a mapping")]

    if data.get("formatVersion") != FORMAT_VERSION:
        findings.append(
            Finding("metadata", "format-version", f"formatVersion must be {FORMAT_VERSION!r}, got {data.get('formatVersion')!r}")
        )

    schema_path = REPO_ROOT / SCHEMA_FILE
    if not schema_path.is_file():
        findings.append(Finding("schema", "missing-schema", f"{SCHEMA_FILE} not found in {REPO_ROOT}"))
    else:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        findings.extend(check_schema(data, schema))

    decision_counts = check_metadata(data, findings)
    actual_counts = check_items(data, git_root, findings)

    if decision_counts is not None:
        for decision in ALLOWED_DECISIONS:
            recorded = decision_counts.get(decision)
            actual = actual_counts.get(decision, 0)
            if recorded != actual:
                findings.append(
                    Finding(
                        "metadata",
                        "decision-counts-mismatch",
                        f"decisionCounts.{decision} is {recorded!r} but the items contain {actual} "
                        f"'{decision}' decision(s)",
                    )
                )
        unknown = set(decision_counts) - set(ALLOWED_DECISIONS)
        for key in sorted(unknown):
            findings.append(
                Finding("metadata", "metadata-field", f"decisionCounts contains unknown decision key {key!r}")
            )

    return findings


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate the StatePort release work disposition ledger"
    )
    parser.add_argument(
        "root",
        nargs="?",
        default=str(REPO_ROOT),
        help="Root containing docs/release/RELEASE_WORK_DISPOSITION.yaml (default: parent of scripts/)",
    )
    parser.add_argument(
        "--git-root",
        default=None,
        help="Repository used to resolve refs and commit SHAs (default: same as root)",
    )
    return parser.parse_args(argv[1:])


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv)
    root = Path(args.root).resolve()
    git_root = Path(args.git_root).resolve() if args.git_root else root
    findings = validate_disposition(root, git_root)
    if findings:
        for finding in findings:
            print(f"FAIL: {finding.render()}")
        print(f"FAILED: {len(findings)} release-disposition violation(s) found")
        return 1
    print(f"PASS: release disposition ledger passed ({LEDGER_FILE})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
