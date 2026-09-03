#!/usr/bin/env python3
"""Deterministic current-state contradiction validator for StatePort.

PROJECT_STATE.yaml is the sole canonical current-state source. STATUS.md and
NEXT_ACTIONS.md are deterministic, exact-byte projections. This validator
rejects projection drift and contradictions in the rendered projections.
Append-only history files
(WORKLOG.md, docs/EVIDENCE_LOG.md, HANDOFF_*.md) are never scanned.

Scope convention (must match the reconciled state files):

- STATUS.md: a ``##``/``###`` section whose heading contains "Historical"
  (case-insensitive) is historical through to the next heading of
  same-or-higher level; everything else is current scope. Historical
  content MUST live under such a heading: a current-scope paragraph or
  list item whose text begins with "Historical" is a violation.
- NEXT_ACTIONS.md: everything under the "## Completed since last update"
  heading is historical; everything above it is current scope. That
  heading must exist and must be the FINAL level-2 (##) section.
- PROJECT_STATE.yaml holds the anchor facts: ``workflow.release_freeze``,
  ``current_state.repository.canonicalBranch``, ``current_state.review.branch``,
  ``current_state.stateBinding``, and exactly one RELEASE-FREEZE incident
  record in ``incidents[]``. Rotated evidence must stay discoverable:
  ``current_state.priorWork.archivedPriorWork.archive`` names dated archive
  files committed under ``docs/history/state/``. ``metadata.updated_at`` must
  be a timezone-aware ISO-8601 UTC timestamp, and
  ``stateWorkflow.activeSlice.id`` must appear in ``active_problems[]`` so the
  execution queue and the recorded problem set cannot silently diverge.

FREEZE MODEL: ``workflow.release_freeze`` and the single RELEASE-FREEZE
incident record must exist and agree bidirectionally (true <-> open/active,
false <-> lifted/resolved; missing, duplicate, or unrecognized statuses fail
closed). Freeze-language text rules derive from the actual flag: claims that
the freeze is active are rejected when the flag is false, and claims that the
freeze is lifted or thawed are rejected when the flag is true; when the flag
is unreadable both directions are rejected (fail closed). Merge, branch, and
acceptance rules run regardless of the freeze state — an active freeze must
not disable them.

TYPED HEAD MODEL: a commit cannot contain its own SHA, so head identity is
split into typed fields instead of one false "Main HEAD":

- Canonical branch: STATUS.md ``**Canonical:**`` line and
  ``current_state.repository.canonicalBranch`` name the canonical branch
  (``main``) and nothing else. The exact canonical head derives from Git at
  validation time (``git rev-parse main`` / ``origin/main`` per the
  divergence rule below) and is NEVER persisted in current-state files: a
  persisted canonical SHA goes stale the moment canonical advances, which
  makes any such protocol unmergeable. When BOTH local ``main`` and
  ``origin/main`` exist they must be equal (``canonical-ref-divergence``);
  the local ref is used only when ``origin/main`` genuinely does not exist.
  A previously observed canonical SHA may remain only as a typed historical
  observation (``canonicalHeadObserved`` with ``classification:
  historical_observation``) and is never parsed as current truth. A
  feature-branch commit must never be recorded as the canonical head.
- Behavioural head: STATUS.md ``**Behavioural Head:**`` and
  ``current_state.stateBinding.behaviouralHead`` — the last product/runtime
  behaviour commit the state documents describe.
- Control head: STATUS.md ``**Control Head:**`` and
  ``current_state.stateBinding.controlHead`` — the last commit that changes
  this repository's typed-head policy or validator. The control head is
  optional only for legacy state records; once either file declares it,
  both files must declare the same full SHA.
- Both typed heads must resolve and be ancestors of HEAD. With the dual-head
  contract active, the behavioural-head commit must itself change a product
  path and the control-head commit must itself change a control path. This
  rejects a state-only reconciliation commit bound as either typed head.
  Since the behavioural head, only state/history and control paths may have
  changed; since the control head, only state/history and product paths may
  have changed. These complementary NET tree diffs (plus tracked worktree
  changes; untracked files are not authority and are ignored) ensure every
  newer product change rebinds the behavioural head and every newer protocol
  change rebinds the control head. State/history paths are the live state
  files, narrowly named dated archives under ``docs/history/state/``, and
  root-level ``HANDOFF*.md``. Runtime policy, release authority, schemas, and
  arbitrary documentation remain product paths and are not exempted.
  Squash/rebase rewrites break ancestry and fail closed: re-record the
  affected typed head as the rewritten commit.
- Review branch lifecycle: ``current_state.review.status`` is ``active`` or
  ``closed`` (absent means ``active``). ``active``: ``review.branch`` is
  required and its head derives from the branch ref at validation time
  (local ref, else ``origin/<branch>``), never from a persisted SHA in
  current state. ``closed``: the branch field is optional and no ref
  resolution is required, so canonical ``main`` keeps validating after a
  merged review branch is deleted.

Intentionally stdlib-only plus statedd_core.yaml.parse_yaml_text, mirroring
statedd_validate_schema.py. Importable: validate_repo_state() returns
findings; main() wraps the CLI.
"""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

CORE_SRC = REPO_ROOT / "packages" / "statedd-core" / "src"
if str(CORE_SRC) not in sys.path:
    sys.path.insert(0, str(CORE_SRC))

from statedd_core.yaml import StateDDYamlError, parse_yaml_text
from validate_state_file_hygiene import validate_state_file_hygiene

STATUS_FILE = "STATUS.md"
NEXT_ACTIONS_FILE = "NEXT_ACTIONS.md"
PROJECT_STATE_FILE = "PROJECT_STATE.yaml"
CANONICAL_STATE_PATHS = frozenset({STATUS_FILE, NEXT_ACTIONS_FILE, PROJECT_STATE_FILE})
STATE_WORKFLOW_FORMAT = "stateport.current-state-workflow/v1"
STATE_WORKFLOW_FACT = (
    "PROJECT_STATE.yaml is the sole canonical current-state source; STATUS.md "
    "and NEXT_ACTIONS.md must exactly match its deterministic projections, "
    "history remains separate, and a completed vertical slice has exactly one "
    "final state-only reconciliation commit"
)

FREEZE_INCIDENT_MARKER = "RELEASE-FREEZE"
EXPECTED_RECONCILIATION_POLICY = "state_only_descendant"
CANONICAL_BRANCH = "main"

FREEZE_FACT = (
    "PROJECT_STATE.yaml workflow.release_freeze is false and incident "
    "INC-2026-07-21-RELEASE-FREEZE-P0 is lifted (2026-07-25 product-owner "
    "directive); main is the single canonical version"
)
FREEZE_ACTIVE_FACT = (
    "PROJECT_STATE.yaml workflow.release_freeze is true and the "
    "RELEASE-FREEZE incident is active; current-scope text may not claim "
    "the freeze is lifted or thawed"
)
FREEZE_INCIDENT_FACT = (
    "exactly one RELEASE-FREEZE incident record must exist and its status "
    "must agree with workflow.release_freeze in both directions "
    "(true <-> open/active, false <-> lifted/resolved)"
)
MERGED_FACT = (
    "BL-AI-VERTICAL-002 is merged to canonical main via PR #7 at ed3055f "
    "(2026-07-25); branch agent/bl-ai-vertical-002 is deleted"
)
BRANCH_FACT = (
    "stale release-program branches were deleted 2026-07-25; content is "
    "preserved via closed-PR refs and main is canonical"
)
CANONICAL_FACT = (
    "the canonical branch is main and its exact head derives from Git refs "
    "at validation time (git rev-parse main / origin/main); state files "
    "record only the branch name as current truth — a persisted canonical "
    "SHA (STATUS.md 'branch `main` at `<sha>`' or repository.head) is "
    "forbidden, and observed SHAs may remain only as typed "
    "canonicalHeadObserved historical observations"
)
DIVERGENCE_FACT = (
    "local main and origin/main must name the same commit; run "
    "git fetch origin and reconcile the refs (fast-forward the stale side "
    "or push the missing commits) before state can be validated"
)
BEHAVIOURAL_FACT = (
    "stateBinding.behaviouralHead names the last product/runtime behaviour "
    "commit the state describes; with the dual-head contract active, only "
    "state/history and typed-head control files may change after it — "
    "re-record behaviouralHead as the newest product commit in a state-only "
    "commit"
)
CONTROL_FACT = (
    "stateBinding.controlHead names the last typed-head policy/validator "
    "commit the state describes; only state/history and product files may "
    "change after it — re-record controlHead as the newest typed-head "
    "control commit in a state-only commit"
)
REBIND_FACT = (
    "the named head must be an ancestor of HEAD; if the commit was "
    "rewritten (squash/rebase), rebind STATUS.md Behavioural Head and "
    "PROJECT_STATE.yaml stateBinding.behaviouralHead: re-record "
    "behaviouralHead as the rewritten (new) non-state commit in a "
    "state-only commit"
)
CONTROL_REBIND_FACT = (
    "the named control head must be an ancestor of HEAD; if the commit was "
    "rewritten (squash/rebase), rebind STATUS.md Control Head and "
    "PROJECT_STATE.yaml stateBinding.controlHead to the rewritten typed-head "
    "control commit in a state-only commit"
)
EXECUTION_CONTROL_FACT = (
    "every directive must enforce one sealed mission phase, resource-safe admission, mandatory "
    "phase-boundary handoff, protected-action guards, and prior-work lookup; executionControls "
    "must enforce material-delta-only "
    "investigation reruns, zero unknown-cause heavy retries, isolated proof before a heavy "
    "rerun, canonical evidence indexing before phase changes, latest-owner priority for "
    "reversible sequencing, one corrected tool invocation, exact-target public-command "
    "receipts before installer readiness, and dependency-edge proof before image rebuilds; "
    "current_state.priorWork must record whether its evidence index was loaded or recovered "
    "with gaps"
)
INSTALLER_READINESS_FACT = (
    "installerReady may be true only when current_state.release.exactTargetReceipt is a "
    "successful, non-staged, non-shimmed receipt from the anonymously served command on "
    "genuine Windows 11 + WSL2 + Ubuntu 24.04 and exactly binds the published version, "
    "release-index digest, signed payload, source commit/tree, and bootstrap digest"
)
UPDATED_AT_FACT = (
    "metadata.updated_at must be a timezone-aware ISO-8601 UTC timestamp (for "
    "example 2026-08-23T18:42:00Z); naive or unparseable timestamps fail closed"
)
PRIOR_WORK_ARCHIVE_FACT = (
    "rotated prior-work evidence must remain discoverable after context loss: "
    "current_state.priorWork.archivedPriorWork.archive must name dated archive "
    "file paths that are committed under docs/history/state/"
)
ACTIVE_SLICE_PROBLEM_FACT = (
    "stateWorkflow.activeSlice.id must appear in active_problems[] ids so the "
    "execution queue and the recorded problem set cannot silently diverge"
)
REQUIRED_EXECUTION_CONTROLS = {
    "priorWorkLookupRequired": True,
    "equivalentInvestigationRerunPolicy": "material_delta_only",
    "unknownCauseHeavyRetryLimit": 0,
    "heavyRerunRequiresIsolatedProof": True,
    "phaseTransitionRequiresEvidenceIndex": True,
    "latestOwnerPriorityWins": True,
    "toolInvocationCorrectionLimit": 1,
    "installerReadinessRequiresExactTargetPublicReceipt": True,
    "imageRebuildRequiresInvalidatedDependencyEdge": True,
}
REQUIRED_UNINTERRUPTED_EXECUTION_CONTROLS = {
    "ownerPromptPolicy": "human_only",
    "knownNextActionPolicy": "execute_bounded_local_milestone_without_scope_expansion",
    "technicalFailurePolicy": "one_bounded_correction_then_handoff",
    "resourcePressurePolicy": "throttle_or_stop_with_safe_handoff",
    "safeBoundaryHandoff": "required",
    "stateBeforeKnownAction": "required_at_phase_boundary",
    "stateReconciliationPolicy": "once_at_phase_boundary",
    "diagnosticRerunPolicy": "one_bounded_correction_only",
    "reportPolicy": "report_at_phase_boundary_or_human_only_gate",
    "swapOccupancyPolicy": "warning_only",
    "hostAuthenticationDependency": "forbidden_for_resource_admission",
    "maxHeavyOperationsConcurrent": 1,
}
REQUIRED_UNINTERRUPTED_AUTHORITY = {
    "reversibleLocalActions": "authorized",
    "localCommits": "authorized",
    "stateportPush": "authorized_for_validated_canonical_main_closure",
    "releaseImplementation": "authorized",
    "diagnosticHarnessChanges": "authorized",
    "diagnosticReruns": "authorized_after_a_material_precondition_change",
    "hostLocalGovernorChanges": "authorized",
    "imageRebuild": "authorized_when_candidate_controlled_bytes_change",
    "integratedQualification": "authorized",
    "releaseCandidateSigning": "authorized_when_prerequisites_pass",
    "publicationArtifacts": "authorized",
    "publicationAndDeployment": "prepare_only_until_human_acceptance",
    "ownerPrompts": "human_only",
    "humanAcceptance": "not_granted",
}
EXECUTION_CONTROL_PROJECTION_TEXT = {
    "ownerPromptPolicy": {
        "human_only": "Owner interaction: human-only.",
    },
    "knownNextActionPolicy": {
        "execute_bounded_local_milestone_without_scope_expansion": (
            "Only the current sealed phase executes automatically; scope expansion "
            "requires a new owner directive."
        ),
    },
    "resourcePressurePolicy": {
        "throttle_or_stop_with_safe_handoff": (
            "Resource pressure is handled by throttling or a safe handoff."
        ),
    },
    "swapOccupancyPolicy": {
        "warning_only": "Swap occupancy alone never blocks execution.",
    },
    "safeBoundaryHandoff": {
        "required": "A safe-boundary handoff is required after each bounded phase.",
    },
}

# State/history paths are deliberately narrow. Dated rotations use an exact
# basename/date/extension grammar so arbitrary files cannot gain state-only
# authority merely by being placed under docs/history/state/.
STATE_DOC_PATHS = frozenset(
    {
        STATUS_FILE,
        NEXT_ACTIONS_FILE,
        PROJECT_STATE_FILE,
        "WORKLOG.md",
        "docs/EVIDENCE_LOG.md",
    }
)
ROOT_HANDOFF_RE = re.compile(r"^HANDOFF[^/]*\.md$")
DATED_STATE_ARCHIVE_RE = re.compile(
    r"^docs/history/state/"
    r"(?:STATUS|NEXT_ACTIONS|PROJECT_STATE|WORKLOG|EVIDENCE_LOG)-"
    r"\d{4}-\d{2}-\d{2}(?:[-.][^/]+)?\.(?:md|yaml)$"
)

# This is intentionally an exact allowlist for executable repository-control
# protocols. Runtime product paths, release ledgers, unrelated schemas,
# general scripts, and arbitrary tests remain product paths. The workspace
# lifecycle entries were added under typed owner directive
# OD-2026-07-29-CONVERGENCE-CORRECTIVE. The standing-authority entries were
# added under OD-2026-07-29-BOUNDED-DELEGATION; any further expansion still
# requires owner review.
CONTROL_PATHS = frozenset(
    {
        "AGENTS.md",
        "PROJECT_DNA.yaml",
        "apps/admin-cli/src/admin_cli/main.py",
        "apps/admin-cli/src/admin_cli/authority.py",
        "apps/admin-cli/src/admin_cli/workspaces.py",
        "apps/web/package.json",
        "apps/web/playwright.config.ts",
        "config/authority-policy.v1.yaml",
        "config/agent-routing-policy.yaml",
        "config/context-lifecycle.v1.yaml",
        "config/mission-envelope.v1.yaml",
        "config/public-export-allowlist.v1.yaml",
        "config/workspace-lifecycle.v1.yaml",
        "infra/qualification/README.md",
        "docs/operations/authority.md",
        "docs/operations/workspace-lifecycle.md",
        "fixtures/statebench/workspace-lifecycle-incident-2026-07-29.yaml",
        "packages/governed-runner/README.md",
        "packages/governed-runner/src/governed_runner/__init__.py",
        "packages/governed-runner/src/governed_runner/authority.py",
        "packages/governed-runner/src/governed_runner/workspaces.py",
        "packages/statebench/src/statebench/devloop.py",
        "schemas/authority-action-receipt.v1.schema.json",
        "schemas/authority-grant.v1.schema.json",
        "schemas/authority-policy.v1.schema.json",
        "schemas/mission-envelope.v1.schema.json",
        "schemas/workspace-budget.v1.schema.json",
        "schemas/workspace-lease.v1.schema.json",
        "scripts/local_closure_gate.py",
        "scripts/run_web_e2e.py",
        "scripts/test_run_web_e2e.py",
        "scripts/test_authority_policy.py",
        "scripts/test_agent_routing_policy.py",
        "scripts/test_local_closure_gate.py",
        "scripts/test_validate_mission_envelope.py",
        "scripts/test_statebench_devloop.py",
        "scripts/validate_state_consistency.py",
        "scripts/test_validate_authority_policy.py",
        "scripts/test_validate_state_consistency.py",
        "scripts/test_validate_workspace_lifecycle.py",
        "scripts/test_workspace_authority_integration.py",
        "scripts/test_workspace_lifecycle.py",
        "scripts/validate_authority_policy.py",
        "scripts/validate_agent_routing_policy.py",
        "scripts/validate_mission_envelope.py",
        "scripts/public_snapshot_audit.py",
        "scripts/validate_repo.py",
        "scripts/validate_workspace_lifecycle.py",
        "config/release-scan-exceptions.v1.yaml",
    }
)
SHA40_RE = re.compile(r"[0-9a-f]{40}")


@dataclass(frozen=True)
class Rule:
    """A current-scope contradiction rule applied line by line."""

    id: str
    pattern: re.Pattern[str]
    fact: str
    # Optional second pattern that must also match the same line.
    also: re.Pattern[str] | None = None
    # Optional same-line exemption that suppresses the match.
    unless: re.Pattern[str] | None = None


# State-independent rules: merge/branch/acceptance contradictions run
# regardless of the freeze flag — an active freeze must not disable them.
TEXT_RULES: tuple[Rule, ...] = (
    Rule(
        id="vertical-unmerged",
        pattern=re.compile(r"\bunmerged\b"),
        also=re.compile(
            r"BL-AI-VERTICAL-002|bl-ai-vertical-002|AI vertical|AI application vertical",
            re.IGNORECASE,
        ),
        # Truthful retrospective lines ("previously unmerged ... now merged")
        # are not contradictions.
        unless=re.compile(r"now merged|merged to (the )?`?main", re.IGNORECASE),
        fact=MERGED_FACT,
    ),
    Rule(
        id="acceptance-not-merged",
        pattern=re.compile(r"No current result is [^.]*\bmerged\b", re.IGNORECASE),
        fact=MERGED_FACT,
    ),
)


def _freeze_rules(release_freeze: bool | None) -> tuple[Rule, ...]:
    """Freeze-language rules derived from the actual freeze flag.

    False: claims that the freeze is active are contradictions.
    True: claims that the freeze is lifted or thawed are contradictions.
    None (flag unreadable): both directions are rejected (fail closed).
    """
    active_claims = (
        Rule(
            id="freeze-active",
            pattern=re.compile(
                r"(P0\s+)?(platform\s+)?release freeze (remains|is) (still )?active",
                re.IGNORECASE,
            ),
            fact=FREEZE_FACT,
        ),
        Rule(
            id="frozen-main",
            pattern=re.compile(r"frozen `?main", re.IGNORECASE),
            fact=FREEZE_FACT,
        ),
        Rule(
            id="frozen-main",
            pattern=re.compile(r"main is frozen", re.IGNORECASE),
            fact=FREEZE_FACT,
        ),
        Rule(
            id="freeze-not-lifted",
            pattern=re.compile(
                r"does not lift the (P0\s+)?(platform\s+)?(release\s+)?freeze",
                re.IGNORECASE,
            ),
            fact=FREEZE_FACT,
        ),
    )
    lifted_claims = (
        Rule(
            id="freeze-lifted-claim",
            pattern=re.compile(
                r"(release\s+)?freeze\s+(is\s+|has\s+been\s+|was\s+|remains\s+)?(now\s+)?(lifted|thawed)\b",
                re.IGNORECASE,
            ),
            fact=FREEZE_ACTIVE_FACT,
        ),
        Rule(
            id="freeze-lifted-claim",
            pattern=re.compile(
                r"(lifted|thawed) the (P0\s+)?(platform\s+)?(release\s+)?freeze",
                re.IGNORECASE,
            ),
            fact=FREEZE_ACTIVE_FACT,
        ),
    )
    if release_freeze is True:
        return lifted_claims
    if release_freeze is False:
        return active_claims
    return active_claims + lifted_claims

# Branch references that are stale unless the enclosing line / list item /
# paragraph carries an explicit archival annotation.
STALE_BRANCH_RE = re.compile(
    r"agent/bl-ai-vertical-002|agent/kimi-frontend-integration|"
    r"agent/acceptance-sidebar-mascot|agent/public-release-closure-001"
)
BRANCH_ANNOTATION_RE = re.compile(
    r"deleted|merged|closed|historical|preserved|superseded", re.IGNORECASE
)

HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
LEVEL2_HEADING_RE = re.compile(r"^##\s+(?!#)(.*)$")
LIST_ITEM_RE = re.compile(r"^\s*(?:[-*+]|\d+\.)\s")
HISTORICAL_HEADING_RE = re.compile(r"historical", re.IGNORECASE)
COMPLETED_HEADING_RE = re.compile(r"^##\s+Completed since last update", re.IGNORECASE)
HISTORICAL_BLOCK_START_RE = re.compile(
    r"^\s*(?:[-*+]\s+|\d+\.\s+)?historical\b", re.IGNORECASE
)

CANONICAL_LINE_RE = re.compile(r"\*\*Canonical:\*\*\s*branch `([^`]+)`")
# Forbidden old form: the Canonical line binding the branch to an exact SHA
# as current truth ("branch `main` at `<short>` (<sha40>)").
CANONICAL_PERSISTED_STATUS_RE = re.compile(
    r"\*\*Canonical:\*\*[^\n]*\bat\s+`[0-9a-fA-F]{7,40}`\s*\([0-9a-fA-F]{40}\)"
)
BEHAVIOURAL_LINE_RE = re.compile(r"\*\*Behavioural Head:\*\*\s*`([0-9a-fA-F]+)`")
CONTROL_LINE_RE = re.compile(r"\*\*Control Head:\*\*\s*`([0-9a-fA-F]+)`")


@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    rule: str
    matched: str
    fact: str

    def render(self) -> str:
        return (
            f"{self.file}:{self.line}: RULE {self.rule}: "
            f"matched {self.matched!r} — contradicts canonical fact: {self.fact}"
        )


# ---------------------------------------------------------------------------
# Current-scope extraction
# ---------------------------------------------------------------------------


def status_current_lines(text: str) -> list[tuple[int, str]]:
    """Return (line_number, line) pairs in current (non-historical) scope."""
    current: list[tuple[int, str]] = []
    historical_level: int | None = None
    for lineno, line in enumerate(text.splitlines(), 1):
        heading = HEADING_RE.match(line)
        if heading:
            level = len(heading.group(1))
            title = heading.group(2)
            if historical_level is not None and level <= historical_level:
                historical_level = None
            if level >= 2 and HISTORICAL_HEADING_RE.search(title):
                historical_level = level
                continue
            if historical_level is not None:
                continue
            current.append((lineno, line))
            continue
        if historical_level is not None:
            continue
        current.append((lineno, line))
    return current


def next_actions_current_lines(text: str) -> list[tuple[int, str]]:
    """Return (line_number, line) pairs above the completed-history heading."""
    current: list[tuple[int, str]] = []
    historical = False
    for lineno, line in enumerate(text.splitlines(), 1):
        if not historical and COMPLETED_HEADING_RE.match(line):
            historical = True
        if historical:
            continue
        current.append((lineno, line))
    return current


def _blocks(scoped_lines: list[tuple[int, str]]) -> list[list[tuple[int, str]]]:
    """Group scoped lines into logical blocks.

    A block is a list item together with its continuation lines, or a
    paragraph of consecutive non-blank lines. Blank lines and headings start
    a new block. Branch annotations apply to the whole block so a wrapped
    line is excused by an annotation on its own logical statement.
    """
    blocks: list[list[tuple[int, str]]] = []
    current: list[tuple[int, str]] = []
    for lineno, line in scoped_lines:
        if not line.strip():
            if current:
                blocks.append(current)
                current = []
            continue
        if HEADING_RE.match(line) or LIST_ITEM_RE.match(line):
            if current:
                blocks.append(current)
            current = [(lineno, line)]
            continue
        current.append((lineno, line))
    if current:
        blocks.append(current)
    return blocks


# ---------------------------------------------------------------------------
# Rule checks
# ---------------------------------------------------------------------------


def check_text_rules(
    scoped: list[tuple[int, str]],
    filename: str,
    release_freeze: bool | None,
) -> list[Finding]:
    findings: list[Finding] = []
    rules = TEXT_RULES + _freeze_rules(release_freeze)
    for lineno, line in scoped:
        for rule in rules:
            match = rule.pattern.search(line)
            if not match:
                continue
            if rule.also is not None and not rule.also.search(line):
                continue
            if rule.unless is not None and rule.unless.search(line):
                continue
            findings.append(
                Finding(filename, lineno, rule.id, match.group(0), rule.fact)
            )
    for block in _blocks(scoped):
        block_text = "\n".join(line for _, line in block)
        if BRANCH_ANNOTATION_RE.search(block_text):
            continue
        for lineno, line in block:
            match = STALE_BRANCH_RE.search(line)
            if match:
                findings.append(
                    Finding(
                        filename,
                        lineno,
                        "stale-deleted-branch",
                        match.group(0),
                        BRANCH_FACT,
                    )
                )
                break
    return findings


def check_historical_block_placement(
    scoped: list[tuple[int, str]],
) -> list[Finding]:
    """Historical content must live under a heading containing 'Historical'."""
    findings: list[Finding] = []
    for lineno, line in scoped:
        if HEADING_RE.match(line):
            continue
        match = HISTORICAL_BLOCK_START_RE.match(line)
        if match:
            findings.append(
                Finding(
                    STATUS_FILE,
                    lineno,
                    "historical-outside-heading",
                    match.group(0).strip(),
                    "historical content must live under a STATUS.md heading "
                    "containing 'Historical'; current scope is current truth only",
                )
            )
    return findings


def check_next_actions_structure(text: str) -> list[Finding]:
    """'## Completed since last update' must exist and be the final ## section."""
    findings: list[Finding] = []
    completed_line: int | None = None
    trailing: list[tuple[int, str]] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if COMPLETED_HEADING_RE.match(line):
            completed_line = lineno
            continue
        if completed_line is not None and LEVEL2_HEADING_RE.match(line):
            trailing.append((lineno, line.strip()))
    if completed_line is None:
        findings.append(
            Finding(
                NEXT_ACTIONS_FILE,
                1,
                "completed-heading-missing",
                "## Completed since last update",
                "NEXT_ACTIONS.md must end with a '## Completed since last "
                "update' history section as its final level-2 section",
            )
        )
        return findings
    for lineno, heading in trailing:
        findings.append(
            Finding(
                NEXT_ACTIONS_FILE,
                lineno,
                "completed-not-final",
                heading,
                "'## Completed since last update' must be the final level-2 "
                "section of NEXT_ACTIONS.md; move this section above it",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# PROJECT_STATE.yaml anchor extraction
# ---------------------------------------------------------------------------


def _find_section(state: dict, key: str) -> dict | None:
    section = state.get(key)
    if isinstance(section, dict):
        return section
    current_state = state.get("current_state")
    if isinstance(current_state, dict) and isinstance(current_state.get(key), dict):
        return current_state[key]
    return None


def _find_incidents(state: dict) -> list:
    incidents = state.get("incidents")
    return incidents if isinstance(incidents, list) else []


def _required_mapping(parent: dict, key: str) -> dict:
    value = parent.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"{key} must be a mapping")
    return value


def _required_text(parent: dict, key: str) -> str:
    value = parent.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a non-empty string")
    return value.strip()


def _display(value: object) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    if value is None:
        return "not recorded"
    return str(value)


def _humanize(value: object) -> str:
    return _display(value).replace("_", " ")


def _execution_control_projection_lines(controls: dict) -> list[str]:
    lines: list[str] = []
    for key, text_by_value in EXECUTION_CONTROL_PROJECTION_TEXT.items():
        value = _required_text(controls, key)
        text = text_by_value.get(value)
        if text is None:
            raise ValueError(f"unsupported executionControls.{key} projection value {value!r}")
        lines.append(text)
    return lines


def render_current_state_projections(state: dict, state_raw: str) -> dict[str, str]:
    """Render the two human-facing current-state projections."""
    metadata = _required_mapping(state, "metadata")
    workflow = _required_mapping(state, "workflow")
    current = _required_mapping(state, "current_state")
    repository = _required_mapping(current, "repository")
    binding = _required_mapping(current, "stateBinding")
    release = _required_mapping(current, "release")
    evidence = _required_mapping(current, "evidence")
    directive = _required_mapping(state, "owner_directive")
    directive_scope = _required_mapping(directive, "scope")
    directive_authority = _required_mapping(directive, "authority")
    execution_controls = _required_mapping(current, "executionControls")
    state_workflow = _required_mapping(current, "stateWorkflow")
    projections = _required_mapping(state_workflow, "projections")
    active_slice = _required_mapping(state_workflow, "activeSlice")

    if state_workflow.get("formatVersion") != STATE_WORKFLOW_FORMAT:
        raise ValueError(f"stateWorkflow.formatVersion must be {STATE_WORKFLOW_FORMAT}")
    if state_workflow.get("canonicalCurrentState") != PROJECT_STATE_FILE:
        raise ValueError(f"stateWorkflow.canonicalCurrentState must be {PROJECT_STATE_FILE}")
    if projections != {"status": STATUS_FILE, "nextActions": NEXT_ACTIONS_FILE}:
        raise ValueError("stateWorkflow.projections must name STATUS.md and NEXT_ACTIONS.md")
    if state_workflow.get("history") != [
        "WORKLOG.md",
        "docs/EVIDENCE_LOG.md",
        "docs/history/state/",
    ]:
        raise ValueError("stateWorkflow.history must name only the canonical history surfaces")
    if state_workflow.get("status") != "enforced":
        raise ValueError("stateWorkflow.status must be enforced")
    if state_workflow.get("stateOnlyReconciliationBudget") != "one_per_completed_vertical_slice":
        raise ValueError("stateWorkflow.stateOnlyReconciliationBudget must cap completed slices at one")

    active = {
        key: _required_text(active_slice, key)
        for key in (
            "id",
            "priority",
            "title",
            "status",
            "authorityKey",
            "summary",
            "decision",
            "work",
            "exit",
        )
    }
    branch = _required_text(repository, "canonicalBranch")
    behavioural = _required_text(binding, "behaviouralHead")
    control = _required_text(binding, "controlHead")
    updated_at = _required_text(metadata, "updated_at")
    mode = _required_text(workflow, "statedd_mode")
    directive_id = _required_text(directive, "id")
    directive_status = _required_text(directive, "status")
    directive_objective = _required_text(directive, "objective")
    graph = _required_text(evidence, "releaseContract")
    release_contract_summary = _required_text(state_workflow, "releaseContractSummary")
    authority_value = directive_authority.get(active["authorityKey"])
    execution_lines = _execution_control_projection_lines(execution_controls)
    digest = hashlib.sha256(state_raw.encode("utf-8")).hexdigest()
    generated = (
        f"<!-- Generated from {PROJECT_STATE_FILE}; do not edit. "
        f"source-sha256: {digest} -->"
    )

    limits = state.get("known_limits")
    limit_lines = (
        [f"- Known limit: {_humanize(value)}." for value in limits]
        if isinstance(limits, list)
        else []
    )
    prohibited = directive_scope.get("prohibitedChanges")
    prohibited_text = (
        ", ".join(_humanize(value) for value in prohibited)
        if isinstance(prohibited, list)
        else "not recorded"
    )

    status_lines = [
        "# StatePort status",
        generated,
        f"**Updated At:** {updated_at}",
        f"**Execution Mode:** {mode}",
        f"**Release Freeze:** {'active' if workflow.get('release_freeze') is True else 'inactive'}; published/versioned signed bytes remain immutable.",
        f"**Release Status:** {_humanize(workflow.get('release_status'))}.",
        f"**Canonical:** branch `{branch}`; its exact head derives from Git at validation time.",
        f"**Behavioural Head:** `{behavioural}`",
        f"**Control Head:** `{control}`",
        f"**Phase:** {_humanize(state.get('project', {}).get('phase') if isinstance(state.get('project'), dict) else None)}; {active['summary']}",
        "",
        "## Current Truth",
        f"- Published release: `{_display(release.get('publishedVersion'))}`; support tier `{_display(release.get('supportTier'))}`; installer ready: `{_display(release.get('installerReady'))}`; owner accepted: `{_display(release.get('ownerAccepted'))}`.",
        f"- Signed target: `{_display(release.get('signedTargetId'))}`; source `{_display(release.get('canonicalSourceCommit'))}`; release-index SHA-256 `{_display(release.get('releaseIndexSha256'))}`.",
        f"- Owner install receipt: `{_display(release.get('ownerInstallReceipt'))}`; clean public one-command receipt: `{_display(release.get('cleanInstallReceipt'))}`.",
        f"- Private candidate status: `{_humanize(evidence.get('j1PrivateStatus', evidence.get('alpha9PrivateStatus')))}`.",
        f"- Complete release contract: `{graph}`. {release_contract_summary}",
        f"- Active slice `{active['id']}` (`{active['priority']}`): {active['decision']}",
        *limit_lines,
        "",
        "## Human On The Loop",
        *(f"- {line}" for line in execution_lines),
        f"- Directive `{directive_id}` is `{directive_status}`: {_humanize(directive_objective)}.",
        f"- Active-slice authority `{active['authorityKey']}`: `{_display(authority_value)}`; heavy operations: `{_display(directive_authority.get('heavyOperations'))}`.",
        f"- Prohibited in this slice: {prohibited_text}.",
        "",
        "## Exact Next Action",
        active["work"],
        "",
        "Older status history is archived under `docs/history/state/`.",
        "",
    ]
    next_lines = [
        "# NEXT_ACTIONS - active execution queue",
        generated,
        "",
        f"**Updated At:** {updated_at}",
        f"**Execution Mode:** {mode}",
        "**Max Items:** 1",
        "",
        f"## {active['priority']} [{active['id']}] {active['title']}",
        "",
        f"**Status:** {active['summary']}",
        "",
        f"**Decision:** {active['decision']}",
        "",
        f"**Work:** {active['work']}",
        "",
        f"**Exit:** {active['exit']}",
        "",
        *execution_lines,
        "",
        "History is recorded only in `WORKLOG.md`, `docs/EVIDENCE_LOG.md`, and `docs/history/state/`.",
        "",
    ]
    return {STATUS_FILE: "\n".join(status_lines), NEXT_ACTIONS_FILE: "\n".join(next_lines)}


def check_state_workflow(
    root: Path, state: dict | None, state_raw: str
) -> tuple[list[Finding], dict[str, str] | None]:
    findings: list[Finding] = []
    current = state.get("current_state") if isinstance(state, dict) else None
    workflow = current.get("stateWorkflow") if isinstance(current, dict) else None
    required = (root / "PROJECT_DNA.yaml").is_file()
    if not isinstance(workflow, dict):
        if required:
            findings.append(
                Finding(
                    PROJECT_STATE_FILE,
                    _line_of(state_raw, re.compile(r"^current_state:")),
                    "state-workflow-anchor",
                    "current_state.stateWorkflow is missing",
                    STATE_WORKFLOW_FACT,
                )
            )
        return findings, None
    try:
        rendered = render_current_state_projections(state, state_raw)
    except ValueError as exc:
        findings.append(
            Finding(
                PROJECT_STATE_FILE,
                _line_of(state_raw, re.compile(r"^  stateWorkflow:")),
                "state-workflow-contract",
                str(exc),
                STATE_WORKFLOW_FACT,
            )
        )
        return findings, None

    for filename, expected in rendered.items():
        path = root / filename
        if not path.is_file():
            findings.append(
                Finding(filename, 1, "projection-missing", filename, STATE_WORKFLOW_FACT)
            )
            continue
        actual = path.read_text(encoding="utf-8")
        if actual != expected:
            findings.append(
                Finding(
                    filename,
                    1,
                    "projection-drift",
                    f"actual sha256 {hashlib.sha256(actual.encode('utf-8')).hexdigest()} != expected sha256 {hashlib.sha256(expected.encode('utf-8')).hexdigest()}",
                    STATE_WORKFLOW_FACT,
                )
            )
    return findings, rendered


def materialize_current_state_projections(root: Path) -> tuple[str, ...]:
    """Stage both projections before replacing either generated file."""
    anchor_findings, _, state, state_raw = check_project_state_anchors(root)
    if anchor_findings or state is None:
        raise ValueError(anchor_findings[0].render() if anchor_findings else "state unavailable")
    rendered = render_current_state_projections(state, state_raw)
    prepared: list[tuple[str, Path, Path]] = []
    originals: dict[Path, bytes | None] = {}
    replaced: list[Path] = []
    try:
        for filename, content in rendered.items():
            path = root / filename
            originals[path] = path.read_bytes() if path.is_file() else None
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=path.parent,
                prefix=f".{path.name}.",
                delete=False,
            ) as handle:
                handle.write(content)
                prepared.append((filename, path, Path(handle.name)))
        try:
            for _, path, temporary in prepared:
                temporary.replace(path)
                replaced.append(path)
        except OSError:
            for path in reversed(replaced):
                original = originals[path]
                if original is None:
                    path.unlink(missing_ok=True)
                    continue
                with tempfile.NamedTemporaryFile(
                    "wb", dir=path.parent, prefix=f".{path.name}.rollback.", delete=False
                ) as handle:
                    handle.write(original)
                    rollback = Path(handle.name)
                rollback.replace(path)
            raise
        return tuple(filename for filename, _, _ in prepared)
    finally:
        for _, _, temporary in prepared:
            temporary.unlink(missing_ok=True)


def _match_line(text: str, pattern: re.Pattern[str], start: int = 0) -> int | None:
    """First 1-based line number matching pattern at or after start, or None."""
    for lineno, line in enumerate(text.splitlines(), 1):
        if lineno < start:
            continue
        if pattern.search(line):
            return lineno
    return None


def _line_of(text: str, pattern: re.Pattern[str], start: int = 0) -> int:
    """First 1-based line number matching pattern at or after start."""
    return _match_line(text, pattern, start) or 1


def _mapping_span(
    text: str, key: str
) -> tuple[int, int, list[tuple[int, str]]] | None:
    """Locate a YAML mapping key; return (key_line, indent, body_lines).

    body_lines holds (lineno, line) pairs for non-blank, non-comment lines
    indented deeper than the key — i.e. the mapping's own extent, so guards
    never match sibling or later sections.
    """
    lines = text.splitlines()
    key_re = re.compile(rf"^(\s*){re.escape(key)}:\s*(?:#.*)?$")
    for index, line in enumerate(lines):
        match = key_re.match(line)
        if not match:
            continue
        indent = len(match.group(1))
        body: list[tuple[int, str]] = []
        for body_index in range(index + 1, len(lines)):
            body_line = lines[body_index]
            if not body_line.strip() or body_line.lstrip().startswith("#"):
                continue
            if len(body_line) - len(body_line.lstrip()) <= indent:
                break
            body.append((body_index + 1, body_line))
        return index + 1, indent, body
    return None


def _problem_id(problem: object) -> str | None:
    """Extract an active_problems entry id from either supported form.

    statedd_core's restricted YAML parser renders flow mappings as their
    literal text (``{id: BL-X, status: open}``), so accept dict entries and
    that exact string shape alike.
    """
    if isinstance(problem, dict):
        value = problem.get("id")
        return str(value) if value is not None else None
    if isinstance(problem, str):
        match = re.match(r"^\{\s*id:\s*([^,}]+?)\s*(?:,.*)?\}$", problem.strip())
        if match:
            return match.group(1)
    return None


def check_project_state_anchors(
    root: Path,
) -> tuple[list[Finding], bool | None, dict | None, str]:
    """Load PROJECT_STATE.yaml and check the freeze anchors bidirectionally.

    Returns (findings, release_freeze, parsed_state, raw_text).
    release_freeze is None when it cannot be determined (fail closed).
    """
    findings: list[Finding] = []
    path = root / PROJECT_STATE_FILE
    if not path.is_file():
        findings.append(
            Finding(
                PROJECT_STATE_FILE,
                1,
                "missing-state-file",
                PROJECT_STATE_FILE,
                FREEZE_FACT,
            )
        )
        return findings, None, None, ""
    raw = path.read_text(encoding="utf-8")
    try:
        state = parse_yaml_text(raw)
    except StateDDYamlError as exc:
        findings.append(
            Finding(PROJECT_STATE_FILE, 1, "state-unparseable", str(exc), FREEZE_FACT)
        )
        return findings, None, None, raw
    if not isinstance(state, dict):
        findings.append(
            Finding(
                PROJECT_STATE_FILE,
                1,
                "state-unparseable",
                "top-level YAML value is not a mapping",
                FREEZE_FACT,
            )
        )
        return findings, None, None, raw

    metadata = state.get("metadata")
    if isinstance(metadata, dict) and metadata.get("updated_at") is not None:
        raw_updated = str(metadata["updated_at"])
        try:
            updated = datetime.fromisoformat(raw_updated.replace("Z", "+00:00"))
            if updated.tzinfo is None:
                raise ValueError("naive timestamp without UTC offset")
        except ValueError:
            findings.append(
                Finding(
                    PROJECT_STATE_FILE,
                    _line_of(raw, re.compile(r"^metadata:")),
                    "updated-at-format",
                    f"metadata.updated_at {raw_updated!r}",
                    UPDATED_AT_FACT,
                )
            )

    current_state = state.get("current_state")
    controls = (
        current_state.get("executionControls")
        if isinstance(current_state, dict)
        else None
    )
    controls_line = _line_of(raw, re.compile(r"^  executionControls:"))
    if not isinstance(controls, dict):
        findings.append(
            Finding(
                PROJECT_STATE_FILE,
                controls_line,
                "execution-control-anchor",
                "current_state.executionControls is missing or not a mapping",
                EXECUTION_CONTROL_FACT,
            )
        )
    else:
        active_priority = controls.get("activePriority")
        if not isinstance(active_priority, str) or not active_priority.strip():
            findings.append(
                Finding(
                    PROJECT_STATE_FILE,
                    controls_line,
                    "execution-control-anchor",
                    "executionControls.activePriority is missing or empty",
                    EXECUTION_CONTROL_FACT,
                )
            )
        for key, expected in {**REQUIRED_EXECUTION_CONTROLS, **REQUIRED_UNINTERRUPTED_EXECUTION_CONTROLS}.items():
            if controls.get(key) != expected:
                findings.append(
                    Finding(
                        PROJECT_STATE_FILE,
                        controls_line,
                        "execution-control-anchor",
                        f"executionControls.{key}={controls.get(key)!r}, expected {expected!r}",
                        EXECUTION_CONTROL_FACT,
                    )
                )

    directive = state.get("owner_directive")
    directive_line = _line_of(raw, re.compile(r"^owner_directive:"))
    directive_id = directive.get("id") if isinstance(directive, dict) else None
    directive_status = directive.get("status") if isinstance(directive, dict) else None
    public_release_active = (
        isinstance(directive_id, str)
        and directive_id.startswith("PUBLIC-RELEASE-")
        and isinstance(directive_status, str)
        and directive_status.startswith("active")
    )
    if public_release_active:
        for key, expected in REQUIRED_UNINTERRUPTED_EXECUTION_CONTROLS.items():
            if controls.get(key) != expected if isinstance(controls, dict) else True:
                findings.append(
                    Finding(
                        PROJECT_STATE_FILE,
                        controls_line,
                        "execution-control-anchor",
                        f"active public-release executionControls.{key}={controls.get(key) if isinstance(controls, dict) else None!r}, expected {expected!r}",
                        EXECUTION_CONTROL_FACT,
                    )
                )
        authority = directive.get("authority") if isinstance(directive, dict) else None
        for key, expected in REQUIRED_UNINTERRUPTED_AUTHORITY.items():
            if authority.get(key) != expected if isinstance(authority, dict) else True:
                findings.append(
                    Finding(
                        PROJECT_STATE_FILE,
                        directive_line,
                        "owner-directive-anchor",
                        f"active public-release authority.{key}={authority.get(key) if isinstance(authority, dict) else None!r}, expected {expected!r}",
                        EXECUTION_CONTROL_FACT,
                    )
                )
        expires_at = directive.get("limits", {}).get("expiresAt") if isinstance(directive, dict) and isinstance(directive.get("limits"), dict) else None
        try:
            expiry = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
            if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
                raise ValueError
        except (TypeError, ValueError):
            findings.append(
                Finding(
                    PROJECT_STATE_FILE,
                    directive_line,
                    "owner-directive-anchor",
                    "active public-release directive must have a future UTC limits.expiresAt",
                    EXECUTION_CONTROL_FACT,
                )
            )

    release = current_state.get("release") if isinstance(current_state, dict) else None
    release_line = _line_of(raw, re.compile(r"^  release:"))
    if isinstance(release, dict) and release.get("installation_enabled") is True:
        receipt = release.get("exactTargetReceipt")
        expected = {
            "status": "succeeded",
            "transport": "anonymous_public_command",
            "runtime": "windows11-wsl2-ubuntu2404",
            "staged": False,
            "shimmed": False,
            "version": release.get("publishedVersion"),
            "releaseIndexSha256": release.get("releaseIndexSha256"),
            "signedPayloadDigest": release.get("signedPayloadDigest"),
            "sourceCommit": release.get("canonicalSourceCommit"),
            "sourceTree": release.get("canonicalSourceTree"),
            "bootstrapSha256": (
                release.get("bootstrapSha256")
                if isinstance(release.get("bootstrapSha256"), str)
                else None
            ),
        }
        mismatches = (
            [key for key, value in expected.items() if receipt.get(key) != value]
            if isinstance(receipt, dict)
            else list(expected)
        )
        if mismatches or not isinstance(receipt, dict) or not isinstance(receipt.get("path"), str):
            findings.append(
                Finding(
                    PROJECT_STATE_FILE,
                    release_line,
                    "installer-readiness-receipt",
                    "exactTargetReceipt is missing or mismatched: " + ", ".join(mismatches),
                    INSTALLER_READINESS_FACT,
                )
            )

    prior_work = (
        current_state.get("priorWork") if isinstance(current_state, dict) else None
    )
    prior_work_line = _line_of(raw, re.compile(r"^  priorWork:"))
    if not isinstance(prior_work, dict) or prior_work.get("indexStatus") not in {
        "loaded",
        "recovered_with_gaps",
    } or not isinstance(prior_work.get("entries"), list):
        findings.append(
            Finding(
                PROJECT_STATE_FILE,
                prior_work_line,
                "prior-work-index-anchor",
                "current_state.priorWork must contain indexStatus loaded|recovered_with_gaps and an entries list",
                EXECUTION_CONTROL_FACT,
            )
        )

    if isinstance(prior_work, dict) and prior_work.get("archivedPriorWork") is not None:
        archived = prior_work["archivedPriorWork"]
        archive_value = archived.get("archive") if isinstance(archived, dict) else None
        archive_paths = (
            [archive_value]
            if isinstance(archive_value, str)
            else list(archive_value)
            if isinstance(archive_value, list)
            else None
        )
        malformed = (
            not archive_paths
            or any(
                not isinstance(value, str)
                or DATED_STATE_ARCHIVE_RE.fullmatch(value) is None
                for value in archive_paths
            )
        )
        if malformed:
            findings.append(
                Finding(
                    PROJECT_STATE_FILE,
                    prior_work_line,
                    "prior-work-archive-pointer",
                    "archivedPriorWork.archive must be a dated docs/history/state/ "
                    "file path or a list of them",
                    PRIOR_WORK_ARCHIVE_FACT,
                )
            )
        else:
            for value in archive_paths:
                tracked = _git(root, "ls-files", "--", value)
                if (
                    tracked is None
                    or tracked.returncode != 0
                    or not tracked.stdout.strip()
                    or not (root / value).is_file()
                ):
                    findings.append(
                        Finding(
                            PROJECT_STATE_FILE,
                            prior_work_line,
                            "prior-work-archive-pointer",
                            f"archivedPriorWork.archive {value} is missing or "
                            "uncommitted",
                            PRIOR_WORK_ARCHIVE_FACT,
                        )
                    )

    workflow_section = (
        current_state.get("stateWorkflow")
        if isinstance(current_state, dict)
        else None
    )
    problems = state.get("active_problems") if isinstance(state, dict) else None
    if re.search(r"^active_problems:\s*\[", raw, re.MULTILINE):
        findings.append(
            Finding(
                PROJECT_STATE_FILE,
                _line_of(raw, re.compile(r"^active_problems:")),
                "active-problems-encoding",
                "active_problems must use a block sequence compatible with the StateSpec loader",
                ACTIVE_SLICE_PROBLEM_FACT,
            )
        )
    if isinstance(workflow_section, dict) and isinstance(problems, list):
        slice_map = workflow_section.get("activeSlice")
        problem_ids = {
            problem_id
            for problem_id in (_problem_id(problem) for problem in problems)
            if problem_id is not None
        }
        if (
            isinstance(slice_map, dict)
            and isinstance(slice_map.get("id"), str)
            and slice_map["id"] not in problem_ids
        ):
            findings.append(
                Finding(
                    PROJECT_STATE_FILE,
                    _line_of(raw, re.compile(r"^  stateWorkflow:")),
                    "active-slice-problem-desync",
                    f"activeSlice.id {slice_map['id']!r} missing from "
                    f"active_problems ids {sorted(problem_ids)!r}",
                    ACTIVE_SLICE_PROBLEM_FACT,
                )
            )

    workflow = state.get("workflow")
    release_freeze: bool | None = None
    if isinstance(workflow, dict) and isinstance(workflow.get("release_freeze"), bool):
        release_freeze = workflow["release_freeze"]
    else:
        findings.append(
            Finding(
                PROJECT_STATE_FILE,
                _line_of(raw, re.compile(r"^workflow:")),
                "freeze-anchor-missing",
                "workflow.release_freeze",
                FREEZE_FACT,
            )
        )

    # Exactly one RELEASE-FREEZE incident record must exist, and the freeze
    # flag and the incident status must agree in both directions; an
    # unrecognized status fails closed.
    if release_freeze is not None:
        incidents_start = _line_of(raw, re.compile(r"^incidents:"))
        freeze_incidents = [
            incident
            for incident in _find_incidents(state)
            if isinstance(incident, dict)
            and FREEZE_INCIDENT_MARKER in str(incident.get("id", "")).upper()
        ]
        if not freeze_incidents:
            findings.append(
                Finding(
                    PROJECT_STATE_FILE,
                    incidents_start,
                    "freeze-incident-missing",
                    "no RELEASE-FREEZE incident record",
                    FREEZE_INCIDENT_FACT,
                )
            )
        elif len(freeze_incidents) > 1:
            findings.append(
                Finding(
                    PROJECT_STATE_FILE,
                    incidents_start,
                    "freeze-incident-duplicate",
                    f"{len(freeze_incidents)} RELEASE-FREEZE incident records",
                    FREEZE_INCIDENT_FACT,
                )
            )
        active_statuses = {"open", "active"}
        closed_statuses = {"lifted", "resolved"}
        for incident in freeze_incidents:
            incident_id = str(incident.get("id", ""))
            status = str(incident.get("status", "")).strip().lower()
            line = _line_of(
                raw, re.compile(re.escape(incident_id)), start=incidents_start
            )
            if release_freeze is False:
                if status in active_statuses:
                    findings.append(
                        Finding(
                            PROJECT_STATE_FILE,
                            line,
                            "freeze-incident-open",
                            f"id {incident_id} status {status} while release_freeze is false",
                            FREEZE_INCIDENT_FACT,
                        )
                    )
                elif status not in closed_statuses:
                    findings.append(
                        Finding(
                            PROJECT_STATE_FILE,
                            line,
                            "freeze-incident-status",
                            f"id {incident_id} has unrecognized status {status!r}",
                            FREEZE_INCIDENT_FACT,
                        )
                    )
            else:
                if status in closed_statuses:
                    findings.append(
                        Finding(
                            PROJECT_STATE_FILE,
                            line,
                            "freeze-incident-closed",
                            f"id {incident_id} status {status} while release_freeze is true",
                            FREEZE_INCIDENT_FACT,
                        )
                    )
                elif status not in active_statuses:
                    findings.append(
                        Finding(
                            PROJECT_STATE_FILE,
                            line,
                            "freeze-incident-status",
                            f"id {incident_id} has unrecognized status {status!r}",
                            FREEZE_INCIDENT_FACT,
                        )
                    )

    return findings, release_freeze, state, raw


# ---------------------------------------------------------------------------
# Git helpers (bounded; every failure path fails closed)
# ---------------------------------------------------------------------------

GIT_TIMEOUT_SECONDS = 30


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str] | None:
    """Run git bounded; None on timeout/OS error."""
    try:
        return subprocess.run(
            ["git", *args],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        # subprocess.TimeoutExpired is a SubprocessError subclass and lands
        # here, turning a timeout into the same fail-closed path as any
        # other git failure.
        return None


def _git_rev_parse(root: Path, ref: str) -> str | None:
    completed = _git(root, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
    if completed is None or completed.returncode != 0:
        return None
    return completed.stdout.strip() or None


def _git_is_ancestor(root: Path, ref: str) -> bool:
    completed = _git(root, "merge-base", "--is-ancestor", ref, "HEAD")
    return completed is not None and completed.returncode == 0


def _git_changed_paths(root: Path, ref: str) -> list[str] | None:
    """Net tree diff for the committed range plus tracked worktree changes.

    Untracked files are not authority and are ignored (e.g. intentionally
    untracked operator assets must not fail the gate).
    """
    changed: set[str] = set()
    for args in (("diff", "--name-only", f"{ref}..HEAD"), ("diff", "--name-only", ref)):
        completed = _git(root, *args)
        if completed is None or completed.returncode != 0:
            return None
        changed.update(line for line in completed.stdout.splitlines() if line.strip())
    return sorted(changed)


def _git_commit_paths(root: Path, ref: str) -> list[str] | None:
    """Return paths changed by one commit against all of its parents.

    ``--root`` covers a root commit and ``-m`` makes merge commits explicit.
    The union is sufficient for typed-head classification: a state-only
    merge cannot masquerade as product or protocol work.
    """
    completed = _git(
        root,
        "diff-tree",
        "--root",
        "-m",
        "--no-commit-id",
        "--name-only",
        "-r",
        ref,
    )
    if completed is None or completed.returncode != 0:
        return None
    return sorted(
        {line for line in completed.stdout.splitlines() if line.strip()}
    )


def _is_state_doc_path(path: str) -> bool:
    return (
        path in STATE_DOC_PATHS
        or ROOT_HANDOFF_RE.fullmatch(path) is not None
        or DATED_STATE_ARCHIVE_RE.fullmatch(path) is not None
    )


def _is_control_path(path: str) -> bool:
    return path in CONTROL_PATHS


def _is_product_path(path: str) -> bool:
    return not _is_state_doc_path(path) and not _is_control_path(path)


def _rebinds_different_heads(root: Path, older: str | None, newer: str) -> bool:
    """True when two adjacent state-only commits rebind different head lines."""
    if older is None:
        return False

    def _heads(commit: str) -> tuple[str, str] | None:
        show = _git(root, "show", f"{commit}:PROJECT_STATE.yaml")
        if show is None or show.returncode != 0:
            return None
        behavioural = control = None
        for line in show.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("behaviouralHead:"):
                behavioural = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("controlHead:"):
                control = stripped.split(":", 1)[1].strip()
        if behavioural is None or control is None:
            return None
        return behavioural, control

    older_heads = _heads(older)
    newer_heads = _heads(newer)
    if older_heads is None or newer_heads is None:
        return False
    return older_heads != newer_heads and (
        (older_heads[0] == newer_heads[0]) != (older_heads[1] == newer_heads[1])
    )


def _state_at_commit(root: Path, commit: str | None) -> dict | None:
    if commit is None:
        return None
    show = _git(root, "show", f"{commit}:PROJECT_STATE.yaml")
    if show is None or show.returncode != 0:
        return None
    try:
        state = parse_yaml_text(show.stdout)
    except StateDDYamlError:
        return None
    return state if isinstance(state, dict) else None


def _active_slice_is_in_flight(root: Path, commit: str | None) -> bool:
    """Identify an explicit non-completed active-slice checkpoint."""
    state = _state_at_commit(root, commit)
    if state is None:
        return False
    current = state.get("current_state")
    workflow = current.get("stateWorkflow") if isinstance(current, dict) else None
    active_slice = workflow.get("activeSlice") if isinstance(workflow, dict) else None
    status = active_slice.get("status") if isinstance(active_slice, dict) else None
    return isinstance(status, str) and ("_in_flight" in status or "-in-flight" in status)


def _is_evidence_indexed_phase_transition(
    root: Path, older: str | None, newer: str
) -> bool:
    """Recognize a completed evidence-only outcome without admitting state churn."""
    older_state = _state_at_commit(root, older)
    newer_state = _state_at_commit(root, newer)
    if older_state is None or newer_state is None:
        return False

    def _current_parts(
        state: dict,
    ) -> tuple[dict, dict, list[object]] | None:
        current = state.get("current_state")
        workflow = current.get("stateWorkflow") if isinstance(current, dict) else None
        active_slice = workflow.get("activeSlice") if isinstance(workflow, dict) else None
        prior_work = current.get("priorWork") if isinstance(current, dict) else None
        entries = prior_work.get("entries") if isinstance(prior_work, dict) else None
        if not isinstance(current, dict) or not isinstance(active_slice, dict) or not isinstance(entries, list):
            return None
        return current, active_slice, entries

    older_parts = _current_parts(older_state)
    newer_parts = _current_parts(newer_state)
    if older_parts is None or newer_parts is None:
        return False
    _, older_slice, older_entries = older_parts
    _, newer_slice, newer_entries = newer_parts

    slice_id = older_slice.get("id")
    if not isinstance(slice_id, str) or not slice_id or newer_slice.get("id") != slice_id:
        return False
    older_status = older_slice.get("status")
    newer_status = newer_slice.get("status")
    if not isinstance(older_status, str) or not isinstance(newer_status, str):
        return False
    if _active_slice_is_in_flight(root, older) or _active_slice_is_in_flight(root, newer):
        return False

    def _pending_gate(status: str) -> str | None:
        if "__" not in status:
            return None
        terminal = status.rsplit("__", 1)[-1]
        suffix = "_pending"
        if not terminal.endswith(suffix):
            return None
        gate = terminal[: -len(suffix)]
        return gate if re.fullmatch(r"[A-Za-z0-9]+(?:_[A-Za-z0-9]+)*", gate) else None

    older_gate = _pending_gate(older_status)
    newer_gate = _pending_gate(newer_status)
    if older_gate is None or newer_gate is None or older_gate.casefold() == newer_gate.casefold():
        return False
    for field in ("status", "decision", "work"):
        older_value = older_slice.get(field)
        newer_value = newer_slice.get(field)
        if (
            not isinstance(older_value, str)
            or not isinstance(newer_value, str)
            or not older_value
            or not newer_value
            or older_value == newer_value
        ):
            return False

    field_names = (
        "id",
        "question",
        "verdict",
        "evidence",
        "validity",
        "changedPrecondition",
        "missingArtifact",
    )
    flow_entry_pattern = re.compile(
        r"\{\s*id:\s*([^,{}\[\]]+),\s*"
        r"question:\s*([^,{}\[\]]+),\s*"
        r"verdict:\s*([^,{}\[\]]+),\s*"
        r"evidence:\s*\[([^{}\[\]]*)\],\s*"
        r"validity:\s*([^,{}\[\]]+),\s*"
        r"changedPrecondition:\s*([^,{}\[\]]+),\s*"
        r"missingArtifact:\s*([^,{}\[\]]+)\s*\}"
    )

    def _entry_fields(entry: object) -> dict[str, object] | None:
        if isinstance(entry, dict):
            return entry if set(entry) == set(field_names) else None
        if not isinstance(entry, str):
            return None
        match = flow_entry_pattern.fullmatch(entry)
        if match is None:
            return None
        values = [value.strip() for value in match.groups()]
        evidence = [item.strip() for item in values[3].split(",")]
        return {
            "id": values[0],
            "question": values[1],
            "verdict": values[2],
            "evidence": evidence,
            "validity": values[4],
            "changedPrecondition": values[5],
            "missingArtifact": values[6],
        }

    def _plain_scalar(value: object) -> bool:
        if not isinstance(value, str):
            return False
        text = value.strip()
        return bool(text) and text.casefold() not in {"null", "~"} and not any(
            quote in text for quote in ("'", '"')
        )

    def _identifier_words(value: str) -> list[str]:
        return [word.casefold() for word in re.findall(r"[A-Za-z0-9]+", value)]

    def _contains_words(words: list[str], phrase: list[str]) -> bool:
        return bool(phrase) and any(
            words[index : index + len(phrase)] == phrase
            for index in range(len(words) - len(phrase) + 1)
        )

    active_problem_pattern = re.compile(
        r"\{\s*id:\s*([^,{}]+),\s*status:\s*([^,{}]+)\s*}"
    )

    def _active_problem_fields(problem: object) -> tuple[str, str] | None:
        if isinstance(problem, dict):
            problem_id = problem.get("id")
            problem_status = problem.get("status")
            if (
                set(problem) != {"id", "status"}
                or not _plain_scalar(problem_id)
                or not _plain_scalar(problem_status)
            ):
                return None
            return str(problem_id).strip(), str(problem_status).strip()
        if not isinstance(problem, str):
            return None
        match = active_problem_pattern.fullmatch(problem)
        if match is None or not all(_plain_scalar(value) for value in match.groups()):
            return None
        return match.group(1).strip(), match.group(2).strip()

    def _active_problem_status(state: dict) -> str | None:
        problems = state.get("active_problems")
        if not isinstance(problems, list):
            return None
        matching: list[str] = []
        for problem in problems:
            fields = _active_problem_fields(problem)
            if fields is not None and fields[0] == slice_id:
                matching.append(fields[1])
            elif isinstance(problem, dict) and problem.get("id") == slice_id:
                return None
        return matching[0] if len(matching) == 1 else None

    if (
        _active_problem_status(older_state) is None
        or _active_problem_status(newer_state) is None
    ):
        return False

    if len(newer_entries) != len(older_entries) + 1:
        return False
    added_positions = [
        index
        for index in range(len(newer_entries))
        if newer_entries[:index] + newer_entries[index + 1 :] == older_entries
    ]
    if len(added_positions) != 1:
        return False
    added = _entry_fields(newer_entries[added_positions[0]])
    if added is None:
        return False

    def _entry_id(entry: object) -> str | None:
        if isinstance(entry, dict):
            entry_id = entry.get("id")
            return entry_id if isinstance(entry_id, str) and entry_id else None
        if not isinstance(entry, str):
            return None
        match = re.match(r"^\{\s*id:\s*([^,{}]+),", entry)
        return match.group(1).strip() if match is not None else None

    added_id = added.get("id")
    older_ids = [_entry_id(entry) for entry in older_entries]
    if (
        not _plain_scalar(added_id)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", str(added_id)) is None
        or any(entry_id is None for entry_id in older_ids)
        or added_id in older_ids
    ):
        return False
    required_text = ("question", "verdict", "validity", "changedPrecondition", "missingArtifact")
    if any(not _plain_scalar(added.get(field)) for field in required_text):
        return False
    evidence = added.get("evidence")
    if not isinstance(evidence, list) or not evidence or not all(
        _plain_scalar(item) for item in evidence
    ):
        return False
    question_words = _identifier_words(str(added["question"]))
    verdict_words = _identifier_words(str(added["verdict"]))
    precondition_words = _identifier_words(str(added["changedPrecondition"]))
    older_gate_words = _identifier_words(older_gate)
    if not (
        _contains_words(question_words, older_gate_words)
        or _contains_words(precondition_words, older_gate_words)
    ):
        return False
    if not verdict_words or verdict_words[0] not in {
        "yes",
        "passed",
        "succeeded",
        "verified",
        "resolved",
        "complete",
        "completed",
    }:
        return False
    if not set(precondition_words).intersection(
        {"closed", "passed", "succeeded", "verified", "resolved", "complete", "completed"}
    ) or set(precondition_words).intersection(
        {"no", "not", "failed", "failure", "refused", "bypassed", "incomplete", "unknown"}
    ):
        return False
    newer_gate_words = _identifier_words(newer_gate)
    for field in ("decision", "work"):
        value = newer_slice.get(field)
        if not isinstance(value, str) or not _contains_words(
            _identifier_words(value), newer_gate_words
        ):
            return False
    if not _contains_words(
        _identifier_words(str(added["missingArtifact"])), newer_gate_words
    ):
        return False

    def _without_phase_fields(state: dict) -> dict:
        normalized = copy.deepcopy(state)
        metadata = normalized.get("metadata")
        if isinstance(metadata, dict):
            metadata.pop("updated_at", None)
            metadata.pop("updated_by", None)
        workflow = normalized.get("workflow")
        if isinstance(workflow, dict):
            workflow.pop("release_status", None)
        current = normalized.get("current_state")
        state_workflow = current.get("stateWorkflow") if isinstance(current, dict) else None
        active_slice = (
            state_workflow.get("activeSlice") if isinstance(state_workflow, dict) else None
        )
        if isinstance(active_slice, dict):
            for field in (
                "status",
                "summary",
                "decision",
                "work",
                "firstFailure",
                "blocker",
            ):
                active_slice.pop(field, None)
        prior_work = current.get("priorWork") if isinstance(current, dict) else None
        if isinstance(prior_work, dict):
            prior_work.pop("entries", None)
        problems = normalized.get("active_problems")
        if isinstance(problems, list):
            for index, problem in enumerate(problems):
                fields = _active_problem_fields(problem)
                if fields is not None and fields[0] == slice_id:
                    problems[index] = {"id": slice_id}
        status = normalized.get("status")
        if isinstance(status, dict):
            status.pop("active_outcome", None)
        return normalized

    return _without_phase_fields(older_state) == _without_phase_fields(newer_state)


def check_reconciliation_budget(root: Path, state: dict | None) -> list[Finding]:
    """Require one final state-only commit for an enforced completed slice."""
    current = state.get("current_state") if isinstance(state, dict) else None
    workflow = current.get("stateWorkflow") if isinstance(current, dict) else None
    if not isinstance(workflow, dict) or workflow.get("status") != "enforced":
        return []
    binding = current.get("stateBinding") if isinstance(current, dict) else None
    if not isinstance(binding, dict):
        return []
    behavioural = binding.get("behaviouralHead")
    control = binding.get("controlHead")
    if not _sha40_ok(str(behavioural) if behavioural is not None else None) or not _sha40_ok(
        str(control) if control is not None else None
    ):
        return []

    # The slice base is the authority boundary, not the latest typed head.
    # The operating policy reconciles state once per completed vertical
    # outcome (``once_after_vertical_outcome``), so one directive may
    # legitimately close several slices. Consecutive state-only commits are
    # admitted only for dual-head sequencing, an explicit in-flight boundary,
    # or a new evidence-indexed phase transition that advances the active queue.
    directive = state.get("owner_directive") if isinstance(state, dict) else None
    directive_base = directive.get("base") if isinstance(directive, dict) else None
    slice_base = directive_base.get("stateportHead") if isinstance(directive_base, dict) else None
    if _sha40_ok(str(slice_base) if slice_base is not None else None):
        after_base = _git(root, "rev-list", "--reverse", "HEAD", f"^{slice_base}")
        if after_base is None or after_base.returncode != 0:
            return [
                Finding(
                    PROJECT_STATE_FILE,
                    1,
                    "reconciliation-unverifiable",
                    "git rev-list after owner directive base failed",
                    STATE_WORKFLOW_FACT,
                )
            ]
        previous_state_only_touches_canonical = False
        previous_commit = None
        for commit in (line for line in after_base.stdout.splitlines() if line.strip()):
            paths = _git_commit_paths(root, commit)
            if paths is None:
                continue
            is_state_only = bool(paths) and all(_is_state_doc_path(path) for path in paths)
            # Reconciliation churn means rewriting canonical current state
            # (PROJECT_STATE.yaml, STATUS.md, NEXT_ACTIONS.md) twice in a row.
            # State-doc commits that only append to the history ledgers
            # (WORKLOG.md, evidence log, dated archives) are the mandated
            # bookkeeping of every slice and never constitute a second
            # reconciliation, in any order relative to one rebind.
            touches_canonical = bool(CANONICAL_STATE_PATHS.intersection(paths))
            if is_state_only and previous_state_only_touches_canonical and touches_canonical:
                # The dual-head contract sometimes requires binding the two
                # head lines in immediate sequence when product and control
                # work land in separate commits.  Two adjacent state-only
                # commits are churn only when they rebind the SAME line;
                # sequential single-line rebinds of different heads are one
                # logical closure expressed across both contracts.
                in_flight_boundary = _active_slice_is_in_flight(
                    root, previous_commit
                ) != _active_slice_is_in_flight(root, commit)
                if not (
                    _rebinds_different_heads(root, previous_commit, commit)
                    or in_flight_boundary
                    or _is_evidence_indexed_phase_transition(root, previous_commit, commit)
                ):
                    return [
                        Finding(
                            PROJECT_STATE_FILE,
                            1,
                            "reconciliation-budget",
                            f"consecutive state-only reconciliation commits follow owner "
                            f"directive base {slice_base}: {commit[:7]}",
                            STATE_WORKFLOW_FACT,
                        )
                    ]
            previous_state_only_touches_canonical = is_state_only and touches_canonical
            previous_commit = commit

    completed = _git(
        root,
        "rev-list",
        "--reverse",
        "HEAD",
        f"^{behavioural}",
        f"^{control}",
    )
    if completed is None or completed.returncode != 0:
        return [
            Finding(
                PROJECT_STATE_FILE,
                1,
                "reconciliation-unverifiable",
                "git rev-list after typed heads failed",
                STATE_WORKFLOW_FACT,
            )
        ]
    commits = [line for line in completed.stdout.splitlines() if line.strip()]
    # Only commits that rewrite canonical current state count as
    # reconciliations; ledger-only bookkeeping (worklog/evidence/archive)
    # may trail the rebind without entering its budget.
    head = _git_rev_parse(root, "HEAD")

    def _touches_canonical_state(commit: str) -> bool:
        commit_paths = _git_commit_paths(root, commit)
        return bool(commit_paths) and bool(CANONICAL_STATE_PATHS.intersection(commit_paths))

    reconciliation_commits = [commit for commit in commits if _touches_canonical_state(commit)]
    # One logical state chain may include dual-head sequencing or consecutive
    # evidence-only phase closures that each advance the active queue.
    logical_reconciliations: list[list[str]] = []
    for commit in reconciliation_commits:
        if (
            logical_reconciliations
            and (
                _rebinds_different_heads(root, logical_reconciliations[-1][-1], commit)
                or _is_evidence_indexed_phase_transition(
                    root, logical_reconciliations[-1][-1], commit
                )
            )
        ):
            logical_reconciliations[-1].append(commit)
        else:
            logical_reconciliations.append([commit])
    if len(logical_reconciliations) != 1:
        return [
            Finding(
                PROJECT_STATE_FILE,
                1,
                "reconciliation-budget",
                f"{len(logical_reconciliations)} canonical-state reconciliation commits follow the latest behavioural/control heads"
                + (f" (plus {len(commits) - len(reconciliation_commits)} ledger-only)" if len(commits) != len(reconciliation_commits) else ""),
                STATE_WORKFLOW_FACT,
            )
        ]

    reconciliation = reconciliation_commits[-1]
    paths = _git_commit_paths(root, reconciliation)
    findings: list[Finding] = []
    trailing_ledger = [
        commit for commit in commits[commits.index(reconciliation) + 1 :]
        if not _touches_canonical_state(commit)
    ]
    allowed_head_candidates = {reconciliation, *trailing_ledger}
    if head not in allowed_head_candidates:
        # The final rebind must terminate the slice; only ledger-only
        # bookkeeping commits may follow it without reopening state.
        findings.append(
            Finding(
                PROJECT_STATE_FILE,
                1,
                "reconciliation-not-final",
                f"reconciliation {reconciliation} != HEAD {head}",
                STATE_WORKFLOW_FACT,
            )
        )
    if paths is None:
        findings.append(
            Finding(
                PROJECT_STATE_FILE,
                1,
                "reconciliation-unverifiable",
                f"git diff-tree {reconciliation} failed",
                STATE_WORKFLOW_FACT,
            )
        )
        return findings
    non_state = [path for path in paths if not _is_state_doc_path(path)]
    if non_state:
        findings.append(
            Finding(
                PROJECT_STATE_FILE,
                1,
                "reconciliation-not-state-only",
                ", ".join(non_state),
                STATE_WORKFLOW_FACT,
            )
        )
    required_paths = {PROJECT_STATE_FILE, STATUS_FILE, NEXT_ACTIONS_FILE}
    missing = sorted(required_paths - set(paths))
    if missing:
        findings.append(
            Finding(
                PROJECT_STATE_FILE,
                1,
                "reconciliation-incomplete",
                "missing " + ", ".join(missing),
                STATE_WORKFLOW_FACT,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Typed head model checks
# ---------------------------------------------------------------------------


@dataclass
class _HeadField:
    value: str | None
    line: int


def _extract_status_heads(
    scoped: list[tuple[int, str]],
) -> tuple[_HeadField, _HeadField, _HeadField]:
    branch = _HeadField(None, 1)
    behavioural = _HeadField(None, 1)
    control = _HeadField(None, 1)
    for lineno, line in scoped:
        canonical_match = CANONICAL_LINE_RE.search(line)
        if canonical_match and branch.value is None:
            branch = _HeadField(canonical_match.group(1), lineno)
        behavioural_match = BEHAVIOURAL_LINE_RE.search(line)
        if behavioural_match and behavioural.value is None:
            behavioural = _HeadField(behavioural_match.group(1), lineno)
        control_match = CONTROL_LINE_RE.search(line)
        if control_match and control.value is None:
            control = _HeadField(control_match.group(1), lineno)
    return branch, behavioural, control


def _sha40_ok(value: str | None) -> bool:
    return value is not None and SHA40_RE.fullmatch(value) is not None


def check_typed_heads(
    root: Path,
    status_scoped: list[tuple[int, str]],
    state: dict | None,
    state_raw: str,
) -> list[Finding]:
    findings: list[Finding] = []

    status_branch, status_behavioural, status_control = _extract_status_heads(
        status_scoped
    )

    repository = _find_section(state, "repository") if state else None
    review = _find_section(state, "review") if state else None
    binding = _find_section(state, "stateBinding") if state else None

    repo_branch = repository.get("canonicalBranch") if repository else None
    review_branch = review.get("branch") if review else None
    review_status_raw = review.get("status") if review else None
    # Absent status means active (backward compatible); anything other than
    # active | closed is a violation reported below.
    review_status = (
        str(review_status_raw).strip() if review_status_raw is not None else "active"
    )
    review_active = review_status == "active"
    binding_behavioural = (
        str(binding["behaviouralHead"]).strip()
        if binding and binding.get("behaviouralHead") is not None
        else None
    )
    binding_control = (
        str(binding["controlHead"]).strip()
        if binding and binding.get("controlHead") is not None
        else None
    )
    binding_policy = binding.get("reconciliationPolicy") if binding else None
    dual_heads = status_control.value is not None or binding_control is not None

    # --- persisted-head guards --------------------------------------------
    # An exact canonical or review head must never live in current-state
    # files; observed SHAs may remain only as typed historical observations
    # (e.g. canonicalHeadObserved with classification historical_observation).
    for lineno, line in status_scoped:
        if CANONICAL_PERSISTED_STATUS_RE.search(line):
            findings.append(
                Finding(
                    STATUS_FILE,
                    lineno,
                    "canonical-head-persisted",
                    line.strip(),
                    CANONICAL_FACT,
                )
            )
            break
    repository_map = _mapping_span(state_raw, "repository")
    if repository_map is not None:
        _, repo_indent, repo_body = repository_map
        repo_head_re = re.compile(
            rf"^\s{{{repo_indent + 2}}}head:\s*[0-9a-fA-F]{{7,40}}\s*$"
        )
        for lineno, line in repo_body:
            if repo_head_re.match(line):
                findings.append(
                    Finding(
                        PROJECT_STATE_FILE,
                        lineno,
                        "canonical-head-persisted",
                        "repository.head persists an exact canonical SHA as current truth",
                        CANONICAL_FACT,
                    )
                )
                break
    review_map = _mapping_span(state_raw, "review")
    if review_map is not None:
        _, review_indent, review_body = review_map
        review_observed_re = re.compile(rf"^\s{{{review_indent + 2}}}headObserved:")
        for lineno, line in review_body:
            if review_observed_re.match(line):
                findings.append(
                    Finding(
                        PROJECT_STATE_FILE,
                        lineno,
                        "review-head-persisted",
                        "review.headObserved persists an exact review head",
                        "the review-branch head derives from its ref at validation "
                        "time (local ref, else origin/<branch>) and must not be "
                        "persisted as current state",
                    )
                )
                break

    # --- anchors present -------------------------------------------------
    if review_status not in ("active", "closed"):
        findings.append(
            Finding(
                PROJECT_STATE_FILE,
                1,
                "review-status",
                f"review.status {review_status!r}",
                "current_state.review.status must be 'active' or 'closed' "
                "(absent means 'active'): 'active' requires review.branch to "
                "resolve; 'closed' makes the branch optional so canonical "
                "main validates after the review branch is deleted",
            )
        )
    missing: list[tuple[str, str]] = []
    if status_branch.value is None:
        missing.append((STATUS_FILE, "**Canonical:**"))
    if status_behavioural.value is None:
        missing.append((STATUS_FILE, "**Behavioural Head:**"))
    if dual_heads and status_control.value is None:
        missing.append((STATUS_FILE, "**Control Head:**"))
    if repo_branch is None:
        missing.append((PROJECT_STATE_FILE, "repository.canonicalBranch"))
    if binding_behavioural is None or binding_policy is None:
        missing.append((PROJECT_STATE_FILE, "stateBinding"))
    if dual_heads and binding_control is None:
        missing.append((PROJECT_STATE_FILE, "stateBinding.controlHead"))
    if review_branch is None and review_active:
        missing.append((PROJECT_STATE_FILE, "review.branch"))
    for filename, anchor in missing:
        findings.append(
            Finding(filename, 1, "head-anchor-missing", anchor, BEHAVIOURAL_FACT)
        )
    if missing:
        return findings

    # --- sha-format: formal SHA fields are full 40-char lowercase hex ----
    if not _sha40_ok(status_behavioural.value):
        findings.append(
            Finding(
                STATUS_FILE,
                status_behavioural.line,
                "sha-format",
                f"STATUS.md Behavioural Head = {status_behavioural.value!r}",
                "formal SHA fields must be full 40-character lowercase hex",
            )
        )
    if not _sha40_ok(binding_behavioural):
        findings.append(
            Finding(
                PROJECT_STATE_FILE,
                1,
                "sha-format",
                f"stateBinding.behaviouralHead = {binding_behavioural!r}",
                "formal SHA fields must be full 40-character lowercase hex",
            )
        )
    if dual_heads and not _sha40_ok(status_control.value):
        findings.append(
            Finding(
                STATUS_FILE,
                status_control.line,
                "sha-format",
                f"STATUS.md Control Head = {status_control.value!r}",
                "formal SHA fields must be full 40-character lowercase hex",
            )
        )
    if dual_heads and not _sha40_ok(binding_control):
        findings.append(
            Finding(
                PROJECT_STATE_FILE,
                1,
                "sha-format",
                f"stateBinding.controlHead = {binding_control!r}",
                "formal SHA fields must be full 40-character lowercase hex",
            )
        )

    # --- canonical branch: STATUS.md and state agree, and it is main -----
    if str(repo_branch) != str(status_branch.value):
        findings.append(
            Finding(
                PROJECT_STATE_FILE,
                1,
                "canonical-head-truth",
                f"repository.canonicalBranch {repo_branch!r} != STATUS.md canonical branch {status_branch.value!r}",
                CANONICAL_FACT,
            )
        )
    if str(status_branch.value) != CANONICAL_BRANCH:
        findings.append(
            Finding(
                STATUS_FILE,
                status_branch.line,
                "canonical-head-truth",
                f"canonical branch {status_branch.value!r} != {CANONICAL_BRANCH!r}",
                CANONICAL_FACT,
            )
        )

    # --- canonical head derives from git; local and remote must agree -----
    # When BOTH local main and origin/main exist they must be equal — a
    # stale local main must not mask a newer remote. The local ref is used
    # only when origin/main genuinely does not exist.
    branch_name = str(status_branch.value)
    local_ref = _git_rev_parse(root, branch_name)
    remote_ref = _git_rev_parse(root, f"origin/{branch_name}")
    if local_ref is not None and remote_ref is not None and local_ref != remote_ref:
        findings.append(
            Finding(
                PROJECT_STATE_FILE,
                1,
                "canonical-ref-divergence",
                f"local {branch_name} {local_ref} != origin/{branch_name} {remote_ref}",
                DIVERGENCE_FACT,
            )
        )
    if local_ref is None and remote_ref is None:
        findings.append(
            Finding(
                PROJECT_STATE_FILE,
                1,
                "head-unverifiable",
                f"git rev-parse {branch_name} and origin/{branch_name} both failed; failing closed",
                CANONICAL_FACT,
            )
        )

    # --- review branch: an active review requires a resolvable ref -------
    # Its head derives from the ref at validation time. A closed review
    # needs no ref: canonical main must keep validating after the merged
    # review branch is deleted.
    if review_active and review_branch is not None:
        review_ref = _git_rev_parse(root, str(review_branch))
        if review_ref is None:
            review_ref = _git_rev_parse(root, f"origin/{review_branch}")
        if review_ref is None:
            findings.append(
                Finding(
                    PROJECT_STATE_FILE,
                    1,
                    "review-head",
                    f"review.branch {review_branch}",
                    "the review-branch head derives from its ref at validation "
                    "time; the ref must resolve locally or as origin/<branch>",
                )
            )

    # --- cross-file behavioural head agreement ---------------------------
    if (
        _sha40_ok(status_behavioural.value)
        and _sha40_ok(binding_behavioural)
        and status_behavioural.value != binding_behavioural
    ):
        findings.append(
            Finding(
                PROJECT_STATE_FILE,
                1,
                "head-disagreement",
                f"STATUS.md Behavioural Head {status_behavioural.value!r} != stateBinding.behaviouralHead {binding_behavioural!r}",
                BEHAVIOURAL_FACT,
            )
        )

    # --- cross-file control head agreement -------------------------------
    if (
        dual_heads
        and _sha40_ok(status_control.value)
        and _sha40_ok(binding_control)
        and status_control.value != binding_control
    ):
        findings.append(
            Finding(
                PROJECT_STATE_FILE,
                1,
                "control-head-disagreement",
                f"STATUS.md Control Head {status_control.value!r} != stateBinding.controlHead {binding_control!r}",
                CONTROL_FACT,
            )
        )

    # --- reconciliation policy -------------------------------------------
    if binding_policy != EXPECTED_RECONCILIATION_POLICY:
        findings.append(
            Finding(
                PROJECT_STATE_FILE,
                1,
                "reconciliation-policy",
                f"reconciliationPolicy {binding_policy!r}",
                f"stateBinding.reconciliationPolicy must be {EXPECTED_RECONCILIATION_POLICY!r}",
            )
        )

    # --- behavioural head: resolves, typed commit, bounded net delta ------
    if _sha40_ok(binding_behavioural):
        if (
            _git_rev_parse(root, binding_behavioural) is None
            or not _git_is_ancestor(root, binding_behavioural)
        ):
            findings.append(
                Finding(
                    PROJECT_STATE_FILE,
                    1,
                    "head-not-ancestor",
                    f"stateBinding.behaviouralHead {binding_behavioural}",
                    REBIND_FACT,
                )
            )
        else:
            if dual_heads:
                commit_paths = _git_commit_paths(root, binding_behavioural)
                if commit_paths is None:
                    findings.append(
                        Finding(
                            PROJECT_STATE_FILE,
                            1,
                            "head-unverifiable",
                            f"git diff-tree {binding_behavioural} failed; failing closed",
                            BEHAVIOURAL_FACT,
                        )
                    )
                elif not any(_is_product_path(path) for path in commit_paths):
                    findings.append(
                        Finding(
                            STATUS_FILE,
                            status_behavioural.line,
                            "behavioural-head-type",
                            f"behaviouralHead {binding_behavioural[:7]} changed only state/control paths: {', '.join(commit_paths) or '(none)'}",
                            "with the dual-head contract active, behaviouralHead "
                            "must name a commit that itself changes at least one "
                            "product/runtime path; a state-only reconciliation "
                            "commit is not behavioural truth",
                        )
                    )
            changed = _git_changed_paths(root, binding_behavioural)
            if changed is None:
                findings.append(
                    Finding(
                        PROJECT_STATE_FILE,
                        1,
                        "head-unverifiable",
                        f"git diff --name-only {binding_behavioural}..HEAD failed; failing closed",
                        BEHAVIOURAL_FACT,
                    )
                )
            else:
                for path in changed:
                    allowed = _is_state_doc_path(path) or (
                        dual_heads and _is_control_path(path)
                    )
                    if not allowed:
                        findings.append(
                            Finding(
                                STATUS_FILE,
                                status_behavioural.line,
                                "stale-head",
                                f"{path} changed since behaviouralHead {binding_behavioural[:7]} without a state-only rebind",
                                BEHAVIOURAL_FACT,
                            )
                        )

    # --- control head: resolves, typed commit, bounded net delta ----------
    if dual_heads and _sha40_ok(binding_control):
        if (
            _git_rev_parse(root, binding_control) is None
            or not _git_is_ancestor(root, binding_control)
        ):
            findings.append(
                Finding(
                    PROJECT_STATE_FILE,
                    1,
                    "control-head-not-ancestor",
                    f"stateBinding.controlHead {binding_control}",
                    CONTROL_REBIND_FACT,
                )
            )
        else:
            commit_paths = _git_commit_paths(root, binding_control)
            if commit_paths is None:
                findings.append(
                    Finding(
                        PROJECT_STATE_FILE,
                        1,
                        "head-unverifiable",
                        f"git diff-tree {binding_control} failed; failing closed",
                        CONTROL_FACT,
                    )
                )
            elif not any(_is_control_path(path) for path in commit_paths):
                findings.append(
                    Finding(
                        STATUS_FILE,
                        status_control.line,
                        "control-head-type",
                        f"controlHead {binding_control[:7]} changed no typed-head control path: {', '.join(commit_paths) or '(none)'}",
                        "controlHead must name a commit that itself changes at "
                        "least one exact typed-head policy/validator path; a "
                        "state-only reconciliation commit is not control truth",
                    )
                )

            changed = _git_changed_paths(root, binding_control)
            if changed is None:
                findings.append(
                    Finding(
                        PROJECT_STATE_FILE,
                        1,
                        "head-unverifiable",
                        f"git diff --name-only {binding_control}..HEAD failed; failing closed",
                        CONTROL_FACT,
                    )
                )
            else:
                for path in changed:
                    if _is_control_path(path):
                        findings.append(
                            Finding(
                                STATUS_FILE,
                                status_control.line,
                                "stale-control-head",
                                f"{path} changed since controlHead {binding_control[:7]} without a state-only rebind",
                                CONTROL_FACT,
                            )
                        )

    return findings


# ---------------------------------------------------------------------------
# Orchestration and CLI
# ---------------------------------------------------------------------------


def validate_repo_state(root: Path) -> list[Finding]:
    """Return all current-state contradiction findings under root."""
    findings: list[Finding] = []

    anchor_findings, release_freeze, state, state_raw = check_project_state_anchors(
        root
    )
    findings.extend(anchor_findings)
    workflow_findings, rendered = check_state_workflow(root, state, state_raw)
    findings.extend(workflow_findings)

    scoped_by_file: dict[str, list[tuple[int, str]]] = {}
    raw_by_file: dict[str, str] = {}
    for filename, extractor in (
        (STATUS_FILE, status_current_lines),
        (NEXT_ACTIONS_FILE, next_actions_current_lines),
    ):
        path = root / filename
        if rendered is not None:
            raw_by_file[filename] = rendered[filename]
            scoped_by_file[filename] = extractor(rendered[filename])
            continue
        if not path.is_file():
            findings.append(
                Finding(filename, 1, "missing-state-file", filename, FREEZE_FACT)
            )
            scoped_by_file[filename] = []
            raw_by_file[filename] = ""
            continue
        raw_by_file[filename] = path.read_text(encoding="utf-8")
        scoped_by_file[filename] = extractor(raw_by_file[filename])

    # Text contradiction rules always run; historical scoping shields
    # point-in-time records. Freeze-language rules derive from the actual
    # release_freeze flag; merge/branch/acceptance rules run regardless.
    for filename, scoped in scoped_by_file.items():
        findings.extend(check_text_rules(scoped, filename, release_freeze))

    findings.extend(check_historical_block_placement(scoped_by_file[STATUS_FILE]))
    if rendered is None and raw_by_file[NEXT_ACTIONS_FILE]:
        findings.extend(check_next_actions_structure(raw_by_file[NEXT_ACTIONS_FILE]))

    findings.extend(
        check_typed_heads(root, scoped_by_file[STATUS_FILE], state, state_raw)
    )
    findings.extend(check_reconciliation_budget(root, state))
    return findings


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Reject known current-state contradictions in StatePort state files"
    )
    parser.add_argument(
        "root",
        nargs="?",
        default=str(REPO_ROOT),
        help="Repo root to validate (default: parent of scripts/)",
    )
    parser.add_argument(
        "--write-projections",
        action="store_true",
        help="regenerate STATUS.md and NEXT_ACTIONS.md from PROJECT_STATE.yaml",
    )
    return parser.parse_args(argv[1:])


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv)
    root = Path(args.root).resolve()
    if args.write_projections:
        try:
            written = materialize_current_state_projections(root)
        except (OSError, ValueError) as exc:
            print(f"FAIL: projection materialization refused: {exc}")
            return 1
        hygiene_findings = validate_state_file_hygiene(root)
        if hygiene_findings:
            for finding in hygiene_findings:
                print(f"FAIL: {finding.render()}")
            print(
                "FAILED: projections were written but current-state hygiene "
                "must pass before commit"
            )
            return 1
        print(
            "PASS: wrote current-state projections and state-file hygiene passed: "
            + ", ".join(written)
        )
        return 0
    findings = validate_repo_state(root)
    if findings:
        for finding in findings:
            print(f"FAIL: {finding.render()}")
        print(f"FAILED: {len(findings)} state-consistency violation(s) found")
        return 1
    print(
        "PASS: canonical PROJECT_STATE.yaml and current-state projections are consistent"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
