#!/usr/bin/env python3
"""Release journey J2 driver: durable mutation, restart, undo, upgrade, export.

Runs against one retained guest whose installed control plane matches the
exact candidate binding.  Every phase records typed evidence into the journey
receipt; any refusal fails the receipt with the shipped error code.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import secrets
import shlex
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from journey_common import (  # noqa: E402
    GuestJsonClient,
    JourneyReceipt,
    Refusal,
    SSH_PORT,
    boot_retained_vm,
    control_user_env,
    discover_services,
    log,
    restart_service,
    validate_retained_candidate_inputs,
    verify_installed_image_digests,
    wait_service_healthy,
)

RECORD_ACTION = "studystate.sample.record-evidence/v1"
UNDO_ACTION = "studystate.sample.undo-last-evidence/v1"
# The installed control plane separates request/apply from approval. Bearer
# authentication binds each body actor to its corresponding local identity.
GOVERNED_ACTOR = "local-operator"
GOVERNED_APPROVER = "local-approver"
QUALIFICATION_REGISTRY = "127.0.0.1:5443/stateport-alpha"
J2_REQUIRED_STEPS = (
    "input-preflight",
    "control-plane-bound-to-candidate",
    "web-session-handshake",
    "retained-journey-baseline-isolated",
    "fixture-install-browser-consent",
    "governed-mutation-applied",
    "state-survives-service-restart",
    "inspection-surface-readable",
    "gui-inspection-evidence",
    "undo-restores-prior-state",
    "undo-survives-second-restart",
    "control-plane-identities-separated",
    "template-revisions-shipped",
    "upgrade-preview-planned",
    "upgrade-plan-gui-inspected",
    "upgrade-authority-chain-bound",
    "template-upgrade-applied",
    "personal-state-intact-after-upgrade",
    "portable-export-verified",
    "portable-import-roundtrip",
)


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _control_user_command(*argv: str) -> str:
    """Build one quote-safe command in the installed control-user environment."""
    expect(bool(argv), "control-user command missing")
    inner = control_user_env() + "; run_control " + shlex.join(list(argv))
    return shlex.join(
        ["sudo", "runuser", "-u", "stateport-control", "--", "bash", "-c", inner]
    )


def _control_podman_exec_command(container: str, *argv: str) -> str:
    """Build one quote-safe command for podman exec as the control user."""
    expect(bool(container), "control container name missing")
    return _control_user_command("podman", "exec", "--", container, *argv)


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _object_digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _contract_digest(value: object) -> str:
    encoded = (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _study_state_snapshot(package_state: object) -> dict:
    expect(isinstance(package_state, dict), "StudyState package projection is missing")
    activities = package_state.get("activities")
    evidence = package_state.get("evidence")
    expect(isinstance(activities, list), "StudyState activity projection is missing")
    expect(isinstance(evidence, list), "StudyState evidence projection is missing")
    return {
        "kind": package_state.get("kind"),
        "goal": package_state.get("goal"),
        "goalProgressPercent": package_state.get("goalProgressPercent"),
        "planDigest": package_state.get("planDigest"),
        "activities": [
            {
                key: item.get(key)
                for key in ("id", "title", "reason", "state")
            }
            for item in activities
            if isinstance(item, dict)
        ],
        "evidence": [
            {key: item.get(key) for key in ("id", "title", "state")}
            for item in evidence
            if isinstance(item, dict)
        ],
    }


def _guided_mutation_binding(
    applied_run: object,
    baseline: object,
    after: object,
    expected_reflection: str,
) -> dict[str, str]:
    expect(isinstance(applied_run, dict), "guided mutation returned no applied run")
    expect(isinstance(baseline, dict), "guided mutation returned no baseline state")
    expect(isinstance(after, dict), "guided mutation returned no durable instance state")
    proposal = applied_run.get("proposal")
    operation = proposal.get("operation") if isinstance(proposal, dict) else None
    application_receipt = applied_run.get("receipt")
    closure_receipt = applied_run.get("closureReceipt")
    expect(
        applied_run.get("actionId") == RECORD_ACTION
        and isinstance(proposal, dict)
        and proposal.get("applicationAction") == RECORD_ACTION
        and isinstance(operation, dict)
        and operation.get("type") == "record_evidence"
        and operation.get("summary") == expected_reflection
        and operation.get("reflection") == expected_reflection,
        "guided mutation is not bound to the exact reviewed reflection proposal",
    )
    evidence_id = operation.get("evidenceId")
    activity_id = operation.get("activityId")
    proposal_id = proposal.get("proposalId")
    proposal_digest = applied_run.get("proposalDigest")
    baseline_package = baseline.get("packageState")
    package_state = after.get("packageState")
    expect(
        isinstance(baseline_package, dict) and isinstance(package_state, dict),
        "guided mutation durable package state is missing",
    )
    before_plan_digest = baseline_package.get("planDigest")
    after_plan_digest = package_state.get("planDigest")
    expect(
        all(isinstance(value, str) and value for value in (
            evidence_id,
            activity_id,
            proposal_id,
            proposal_digest,
            before_plan_digest,
            after_plan_digest,
        )),
        "guided mutation proposal identities are incomplete",
    )
    expect(
        proposal_digest == _contract_digest(proposal)
        and isinstance(application_receipt, dict)
        and application_receipt.get("proposalId") == proposal_id
        and application_receipt.get("preStateDigest")
        == proposal.get("preStateDigest")
        and application_receipt.get("postStateDigestAuthority")
        == "stateport_full_regular_tree_snapshot"
        and application_receipt.get("postStateDigest")
        == applied_run.get("canonicalStateAfter")
        and isinstance(closure_receipt, dict)
        and closure_receipt.get("proposalId") == proposal_id
        and closure_receipt.get("proposalDigest") == proposal_digest
        and closure_receipt.get("applicationReceiptDigest")
        == _contract_digest(application_receipt)
        and closure_receipt.get("canonicalStateBefore")
        == applied_run.get("canonicalStateBefore")
        and closure_receipt.get("canonicalStateAfter")
        == applied_run.get("canonicalStateAfter")
        and operation.get("beforePlanDigest") == before_plan_digest
        and operation.get("afterPlanDigest") == after_plan_digest,
        "guided mutation proposal digests do not bind the before and after state",
    )
    evidence = package_state.get("evidence")
    activities = package_state.get("activities")
    transition = package_state.get("lastTransition")
    expect(
        isinstance(evidence, list)
        and isinstance(activities, list)
        and isinstance(transition, dict),
        "guided mutation durable state is incomplete",
    )
    exact_evidence = [
        item
        for item in evidence
        if isinstance(item, dict) and item.get("id") == evidence_id
    ]
    activity = next(
        (
            item
            for item in activities
            if isinstance(item, dict) and item.get("id") == activity_id
        ),
        None,
    )
    expect(
        len(exact_evidence) == 1
        and exact_evidence[0].get("title") == expected_reflection
        and exact_evidence[0].get("state") == "self_reported"
        and isinstance(activity, dict)
        and activity.get("state") == "done"
        and transition.get("kind") == "evidence_applied"
        and transition.get("evidenceId") == evidence_id
        and transition.get("activityId") == activity_id
        and transition.get("proposalId") == proposal_id,
        "durable StudyState state is not bound to the exact reviewed reflection",
    )
    expect(
        transition.get("beforePlanDigest") == before_plan_digest
        and transition.get("afterPlanDigest") == after_plan_digest,
        "durable StudyState transition digests do not match the reviewed proposal",
    )
    return {
        "actionId": RECORD_ACTION,
        "proposalDigest": proposal_digest,
        "proposalId": proposal_id,
        "activityId": activity_id,
        "evidenceId": evidence_id,
        "reflectionSha256": "sha256:"
        + hashlib.sha256(expected_reflection.encode("utf-8")).hexdigest(),
        "beforePlanDigest": before_plan_digest,
        "planDigest": after_plan_digest,
    }


def _undo_restoration_binding(
    applied_run: object,
    *,
    reviewed_run: object,
    mutation_run: object,
    expected_review_run_id: object,
    expected_applied_run_id: object,
    expected_instance_id: object,
    expected_current_plan_digest: object,
    expected_restored_plan_digest: object,
    expected_semantic_state: object,
    actual_semantic_state: object,
) -> dict[str, str]:
    expect(isinstance(applied_run, dict), "undo returned no applied run")
    expect(isinstance(reviewed_run, dict), "undo returned no reviewed run")
    expect(isinstance(mutation_run, dict), "undo returned no original mutation run")
    expect(
        isinstance(expected_semantic_state, dict)
        and isinstance(actual_semantic_state, dict),
        "undo semantic state is missing",
    )
    proposal = applied_run.get("proposal")
    operation = proposal.get("operation") if isinstance(proposal, dict) else None
    application_receipt = applied_run.get("receipt")
    closure_receipt = applied_run.get("closureReceipt")
    proposal_id = proposal.get("proposalId") if isinstance(proposal, dict) else None
    proposal_digest = applied_run.get("proposalDigest")
    canonical_before = applied_run.get("canonicalStateBefore")
    canonical_after = applied_run.get("canonicalStateAfter")
    reviewed_proposal = reviewed_run.get("proposal")
    reviewed_canonical_before = reviewed_run.get("canonicalStateBefore")
    reviewed_canonical_after = reviewed_run.get("canonicalStateAfter")
    reviewed_result = reviewed_run.get("result")
    rejection = reviewed_run.get("rejection")
    mutation_proposal = mutation_run.get("proposal")
    mutation_operation = (
        mutation_proposal.get("operation")
        if isinstance(mutation_proposal, dict)
        else None
    )
    mutation_receipt = mutation_run.get("receipt")
    mutation_closure = mutation_run.get("closureReceipt")
    mutation_canonical_before = mutation_run.get("canonicalStateBefore")
    mutation_canonical_after = mutation_run.get("canonicalStateAfter")
    mutation_application_receipt = (
        mutation_receipt.get("applicationReceipt")
        if isinstance(mutation_receipt, dict)
        else None
    )
    expect(
        applied_run.get("actionId") == UNDO_ACTION
        and applied_run.get("applicationId") == "studystate.sample"
        and applied_run.get("runId") == expected_applied_run_id
        and applied_run.get("instanceId") == expected_instance_id
        and applied_run.get("status") == "applied"
        and applied_run.get("lifecycleState") == "CLOSED"
        and isinstance(proposal, dict)
        and proposal.get("applicationAction") == UNDO_ACTION
        and isinstance(operation, dict)
        and operation.get("type") == "undo_last_evidence",
        "undo is not bound to the reviewed action",
    )
    expect(
        all(
            isinstance(value, str) and value
            for value in (
                proposal_id,
                proposal_digest,
                canonical_before,
                canonical_after,
                reviewed_canonical_before,
                reviewed_canonical_after,
                expected_review_run_id,
                expected_applied_run_id,
                expected_instance_id,
                expected_current_plan_digest,
                expected_restored_plan_digest,
                mutation_canonical_before,
                mutation_canonical_after,
            )
        ),
        "undo proposal or state identities are incomplete",
    )
    # The GUI inspection surfaces may update governed instance metadata after
    # the mutation. Application-state continuity therefore links to the
    # mutation receipt, while full-tree continuity starts at the closed review.
    expect(
        reviewed_run.get("actionId") == UNDO_ACTION
        and reviewed_run.get("applicationId") == "studystate.sample"
        and reviewed_run.get("runId") == expected_review_run_id
        and reviewed_run.get("instanceId") == expected_instance_id
        and reviewed_run.get("status") == "state_change_rejected"
        and reviewed_run.get("lifecycleState") == "CLOSED"
        and reviewed_run.get("proposalDigest") == proposal_digest
        and reviewed_proposal == proposal
        and reviewed_canonical_before == reviewed_canonical_after
        and isinstance(reviewed_result, dict)
        and reviewed_result.get("canonicalStateUnchanged") is True
        and reviewed_result.get("canonicalStateDigest") == proposal.get("preStateDigest")
        and isinstance(rejection, dict)
        and rejection.get("operatorId") == GOVERNED_ACTOR,
        "undo does not match the closed GUI review",
    )
    expect(
        mutation_run.get("actionId") == RECORD_ACTION
        and mutation_run.get("applicationId") == "studystate.sample"
        and mutation_run.get("instanceId") == expected_instance_id
        and mutation_run.get("status") == "applied"
        and mutation_run.get("lifecycleState") == "CLOSED"
        and isinstance(mutation_proposal, dict)
        and mutation_proposal.get("applicationAction") == RECORD_ACTION
        and mutation_run.get("proposalDigest") == _contract_digest(mutation_proposal)
        and isinstance(mutation_operation, dict)
        and mutation_operation.get("afterPlanDigest") == expected_current_plan_digest
        and operation.get("appliedProposalId") == mutation_proposal.get("proposalId")
        and isinstance(mutation_application_receipt, dict)
        and proposal.get("preStateDigest")
        == mutation_application_receipt.get("postStateDigest")
        and isinstance(mutation_receipt, dict)
        and mutation_receipt.get("proposalId") == mutation_proposal.get("proposalId")
        and mutation_receipt.get("postStateDigest") == mutation_canonical_after
        and isinstance(reviewed_result, dict)
        and reviewed_result.get("canonicalStateDigest")
        == mutation_application_receipt.get("postStateDigest")
        and isinstance(mutation_closure, dict)
        and isinstance(mutation_closure.get("receiptId"), str)
        and bool(mutation_closure.get("receiptId"))
        and mutation_closure.get("runId") == mutation_run.get("runId")
        and mutation_closure.get("instanceId") == expected_instance_id
        and mutation_closure.get("applicationId") == "studystate.sample"
        and mutation_closure.get("actionId") == RECORD_ACTION
        and mutation_closure.get("proposalId") == mutation_proposal.get("proposalId")
        and mutation_closure.get("proposalDigest")
        == mutation_run.get("proposalDigest")
        and mutation_closure.get("canonicalStateBefore")
        == mutation_canonical_before
        and mutation_closure.get("canonicalStateAfter") == mutation_canonical_after
        and mutation_closure.get("applicationReceiptDigest")
        == _contract_digest(mutation_receipt),
        "undo does not bind the original reviewed mutation",
    )
    expect(
        proposal_digest == _contract_digest(proposal)
        and operation.get("expectedCurrentPlanDigest")
        == expected_current_plan_digest
        and operation.get("restoredPlanDigest") == expected_restored_plan_digest
        and isinstance(application_receipt, dict)
        and application_receipt.get("proposalId") == proposal_id
        and application_receipt.get("preStateDigest")
        == proposal.get("preStateDigest")
        and application_receipt.get("postStateDigestAuthority")
        == "stateport_full_regular_tree_snapshot"
        and application_receipt.get("postStateDigest") == canonical_after
        and isinstance(closure_receipt, dict)
        and isinstance(closure_receipt.get("receiptId"), str)
        and bool(closure_receipt.get("receiptId"))
        and closure_receipt.get("runId") == expected_applied_run_id
        and closure_receipt.get("instanceId") == expected_instance_id
        and closure_receipt.get("actionId") == UNDO_ACTION
        and closure_receipt.get("applicationId") == "studystate.sample"
        and closure_receipt.get("proposalId") == proposal_id
        and closure_receipt.get("proposalDigest") == proposal_digest
        and closure_receipt.get("applicationReceiptDigest")
        == _contract_digest(application_receipt)
        and closure_receipt.get("canonicalStateBefore") == canonical_before
        and closure_receipt.get("canonicalStateAfter") == canonical_after
        and canonical_before == reviewed_canonical_after
        and canonical_after != canonical_before,
        "undo receipts do not bind the approved canonical state transition",
    )
    expect(
        actual_semantic_state == expected_semantic_state
        and actual_semantic_state.get("planDigest") == expected_restored_plan_digest,
        "undo did not restore the evidence-bearing prior state",
    )
    return {
        "actionId": UNDO_ACTION,
        "appliedRunId": expected_applied_run_id,
        "proposalId": proposal_id,
        "proposalDigest": proposal_digest,
        "reviewRunId": expected_review_run_id,
        "reviewedCanonicalState": reviewed_canonical_after,
        "mutationProposalId": str(mutation_proposal.get("proposalId")),
        "mutationCanonicalStateAfter": mutation_canonical_after,
        "mutationClosureReceiptId": str(mutation_closure.get("receiptId")),
        "applicationReceiptDigest": _contract_digest(application_receipt),
        "closureReceiptId": str(closure_receipt.get("receiptId")),
        "canonicalStateBefore": canonical_before,
        "canonicalStateAfter": canonical_after,
        "restoredPlanDigest": expected_restored_plan_digest,
    }


def _required_step_failures(document: dict) -> list[str]:
    steps = document.get("steps")
    if not isinstance(steps, list):
        return ["steps:missing"]
    failures: list[str] = []
    for name in J2_REQUIRED_STEPS:
        matches = [step for step in steps if isinstance(step, dict) and step.get("name") == name]
        if not matches:
            failures.append(f"{name}:missing")
        elif len(matches) != 1:
            failures.append(f"{name}:duplicate")
        elif matches[0].get("ok") is not True:
            failures.append(f"{name}:failed")
    failures.extend(
        f"{step.get('name', 'unnamed')}:failed"
        for step in steps
        if isinstance(step, dict)
        and step.get("ok") is not True
        and step.get("name") not in J2_REQUIRED_STEPS
    )
    return failures


def _existing_study_instances(instance_index: object) -> list[dict[str, str]]:
    expect(isinstance(instance_index, dict), "installed instance index is malformed")
    instance_rows = instance_index.get("instances")
    expect(isinstance(instance_rows, list), "installed instance index is malformed")
    existing: list[dict[str, str]] = []
    for row in instance_rows:
        expect(isinstance(row, dict), "installed instance index row is malformed")
        application_id = row.get("applicationId")
        expect(
            isinstance(application_id, str)
            and re.fullmatch(
                r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?",
                application_id,
            )
            is not None,
            "installed instance application identity is malformed",
        )
        if application_id != "studystate.sample":
            continue
        instance_id = row.get("instanceId")
        instance_name = row.get("name")
        expect(
            isinstance(instance_id, str)
            and bool(instance_id)
            and isinstance(instance_name, str)
            and bool(instance_name),
            "installed StudyState instance identity is malformed",
        )
        existing.append({"instanceId": instance_id, "name": instance_name})
    return existing


def _ensure_qualification_registry(vm) -> None:
    probe = "curl -fsS -m 5 http://127.0.0.1:5443/v2/ >/dev/null"
    if vm.ssh(probe, check=False, timeout=30).returncode == 0:
        return
    start = (
        "test -x /usr/bin/docker-registry && "
        "test -f /etc/docker/registry/config.yml && "
        "setsid nohup /usr/bin/docker-registry serve /etc/docker/registry/config.yml "
        ">/var/log/stateport-qualification-registry.log 2>&1 </dev/null &"
    )
    vm.ssh(f"sudo sh -c {shlex.quote(start)}", check=False, timeout=30)
    for _ in range(30):
        if vm.ssh(probe, check=False, timeout=30).returncode == 0:
            return
        time.sleep(1)
    raise AssertionError("retained qualification registry did not become reachable")


def _gui_inspection_script(
    base_url: str,
    instance_id: str,
    approval_id: str,
    approval_digest: str,
    mutation_receipt_id: str,
    approve_after_capture: bool = False,
) -> str:
    script = r"""
const fs = require('fs');
const crypto = require('crypto');
const { chromium } = require('/opt/stateport-playwright/node_modules/playwright-core');
const baseUrl = __BASE_URL__;
const instanceId = __INSTANCE_ID__;
const approvalId = __APPROVAL_ID__;
const approvalTargetId = approvalId.split(':').slice(1).join(':');
const expectedApprovalDigest = __APPROVAL_DIGEST__;
const mutationReceiptId = __MUTATION_RECEIPT_ID__;
const approveAfterCapture = __APPROVE_AFTER_CAPTURE__;
const artifactRoot = '/artifacts';

function digest(value) {
  return 'sha256:' + crypto.createHash('sha256').update(value).digest('hex');
}

async function screenshot(page, name) {
  const path = `${artifactRoot}/${name}.jpg`;
  await page.screenshot({ path, type: 'jpeg', quality: 72, fullPage: false });
  return { file: `${name}.jpg`, sha256: digest(fs.readFileSync(path)) };
}

async function main() {
  fs.mkdirSync(artifactRoot, { recursive: true });
  const pageErrors = [];
  const failedResponses = [];
  const browser = await chromium.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-dev-shm-usage'],
  });
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  const page = await context.newPage();
  page.on('pageerror', (error) => pageErrors.push(String(error).slice(0, 300)));
  page.on('response', (response) => {
    const url = new URL(response.url());
    if (response.status() >= 400 && url.origin === new URL(baseUrl).origin && url.pathname.startsWith('/v1/')) {
      failedResponses.push({ status: response.status(), url: response.url() });
    }
  });
  const surfaces = {};

  await page.goto(`${baseUrl}/#/app/${encodeURIComponent(instanceId)}`, {
    waitUntil: 'domcontentloaded', timeout: 60000,
  });
  const history = page.locator('[data-testid="recent-activity-section"]');
  await history.waitFor({ state: 'visible', timeout: 60000 });
  const historyRows = await history.locator('li').count();
  if (historyRows < 1) throw new Error('history surface has no activity rows');
  const receiptBoundRows = history.locator('[data-receipt-id]');
  const historyReceiptIds = await receiptBoundRows.evaluateAll(
    (rows) => rows.map((row) => row.getAttribute('data-receipt-id')),
  );
  const mutationRowIndex = historyReceiptIds.indexOf(mutationReceiptId);
  if (mutationRowIndex < 0) throw new Error('history does not show the exact mutation receipt');
  const mutationHistoryText = await receiptBoundRows.nth(mutationRowIndex).innerText();
  const historyText = await history.innerText();
  surfaces.history = {
    selector: '[data-testid="recent-activity-section"]',
    rows: historyRows,
    mutationReceiptId,
    mutationVisibleTextSha256: digest(mutationHistoryText),
    visibleTextSha256: digest(historyText),
    screenshot: await screenshot(page, 'history'),
  };

  await page.goto(`${baseUrl}/#/approvals/${encodeURIComponent(approvalId)}`, {
    waitUntil: 'domcontentloaded', timeout: 60000,
  });
  await page.locator('[data-testid="approvals-stub"]').waitFor({ state: 'visible', timeout: 60000 });
  await page.locator('[data-testid="approval-row"]').first().waitFor({ state: 'visible', timeout: 60000 });
  const approvalDetail = page.locator('[data-testid="approval-detail"]');
  await approvalDetail.waitFor({ state: 'visible', timeout: 60000 });
  const approvalRows = await page.locator('[data-testid="approval-row"]').count();
  const approvalText = await approvalDetail.innerText();
  const approvalDigest = approvalDetail.locator('[data-testid="approval-plan-digest"]');
  await approvalDigest.waitFor({ state: 'visible', timeout: 60000 });
  const renderedApprovalDigest = await approvalDigest.getAttribute('data-digest');
  const accessibleApprovalDigest = await approvalDigest.getAttribute('aria-label');
  const expectedShortDigest = expectedApprovalDigest.length > 16
    ? `${expectedApprovalDigest.slice(0, 8)}…${expectedApprovalDigest.slice(-6)}`
    : expectedApprovalDigest;
  const visibleApprovalDigest = (await approvalDigest.innerText()).trim();
  if (approvalRows < 1) throw new Error('approvals surface has no rows');
  if (!approvalText.includes(approvalTargetId)) throw new Error('approval detail is not bound to the expected target');
  if (
    renderedApprovalDigest !== expectedApprovalDigest
    || accessibleApprovalDigest !== expectedApprovalDigest
    || visibleApprovalDigest !== expectedShortDigest
  ) {
    throw new Error('approval detail is not bound to the expected exact digest');
  }
  surfaces.approvals = {
    selector: '[data-testid="approval-detail"]',
    rows: approvalRows,
    approvalId,
    approvalDigest: expectedApprovalDigest,
    renderedApprovalDigest,
    visibleApprovalDigest,
    visibleTextSha256: digest(approvalText),
    screenshot: await screenshot(page, 'approvals'),
  };
  let approvalDecision = null;
  if (approveAfterCapture) {
    await page.locator('[data-testid="approve-button"]').click();
    const result = page.locator('[data-testid="decision-result"]');
    await result.waitFor({ state: 'visible', timeout: 60000 });
    const resultText = await result.innerText();
    if (!resultText.includes('Approved')) throw new Error('approval UI did not record approval');
    approvalDecision = 'approved';
  }

  await page.goto(`${baseUrl}/#/app/${encodeURIComponent(instanceId)}/receipts`, {
    waitUntil: 'domcontentloaded', timeout: 60000,
  });
  await page.locator('[data-testid="application-receipts-page"]').waitFor({ state: 'visible', timeout: 60000 });
  await page.locator('[data-receipt-id]').first().waitFor({ state: 'visible', timeout: 60000 });
  const receiptRows = await page.locator('[data-receipt-id]').count();
  const receiptIds = await page.locator('[data-receipt-id]').evaluateAll(
    (rows) => rows.map((row) => row.getAttribute('data-receipt-id')),
  );
  const receiptText = await page.locator('[data-testid="application-receipts-page"]').innerText();
  if (receiptRows < 1) throw new Error('receipts surface has no mutation receipts');
  if (!receiptIds.includes(mutationReceiptId)) throw new Error('expected mutation receipt is not visible');
  surfaces.receipts = {
    selector: '[data-testid="application-receipts-page"]',
    rows: receiptRows,
    receiptId: mutationReceiptId,
    visibleTextSha256: digest(receiptText),
    screenshot: await screenshot(page, 'receipts'),
  };

  await page.goto(`${baseUrl}/#/app/${encodeURIComponent(instanceId)}/settings?group=context`, {
    waitUntil: 'domcontentloaded', timeout: 60000,
  });
  const contextSurface = page.locator('[data-testid="app-settings-context-lifecycle"]');
  await contextSurface.waitFor({ state: 'visible', timeout: 60000 });
  const contextText = await contextSurface.innerText();
  if (!contextText.includes('Current estimated use') || !contextText.includes('Maximum input budget')) {
    throw new Error('context cost surface is incomplete');
  }
  surfaces.contextCost = {
    selector: '[data-testid="app-settings-context-lifecycle"]',
    rows: 1,
    visibleTextSha256: digest(contextText),
    screenshot: await screenshot(page, 'context-cost'),
  };

  await browser.close();
  if (pageErrors.length) throw new Error(`browser page errors: ${JSON.stringify(pageErrors)}`);
  if (failedResponses.length) throw new Error(`failed API responses: ${JSON.stringify(failedResponses)}`);
  process.stdout.write(JSON.stringify({
    formatVersion: 'stateport.j2-gui-inspection/v1',
    instanceId,
    surfaces,
    approvalDecision,
    failedResponses,
    pageErrors,
  }) + '\n');
}

main().catch((error) => {
  console.error(error && error.stack ? error.stack : String(error));
  process.exit(1);
});
"""
    return (
        script.replace("__BASE_URL__", json.dumps(base_url))
        .replace("__INSTANCE_ID__", json.dumps(instance_id))
        .replace("__APPROVAL_ID__", json.dumps(approval_id))
        .replace("__APPROVAL_DIGEST__", json.dumps(approval_digest))
        .replace("__MUTATION_RECEIPT_ID__", json.dumps(mutation_receipt_id))
        .replace("__APPROVE_AFTER_CAPTURE__", "true" if approve_after_capture else "false")
    )


def _guided_study_script(base_url: str, instance_name: str, reflection: str) -> str:
    script = r"""
const fs = require('fs');
const crypto = require('crypto');
const { chromium } = require('/opt/stateport-playwright/node_modules/playwright-core');
const baseUrl = __BASE_URL__;
const instanceName = __INSTANCE_NAME__;
const reflection = __REFLECTION__;
const artifactRoot = '/artifacts';

function digest(value) {
  return 'sha256:' + crypto.createHash('sha256').update(value).digest('hex');
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(',')}]`;
  }
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function contractDigest(value) {
  return digest(`${canonicalJson(value)}\n`);
}

async function screenshot(page, name) {
  const path = `${artifactRoot}/${name}.jpg`;
  await page.screenshot({ path, type: 'jpeg', quality: 72, fullPage: false });
  return { file: `${name}.jpg`, sha256: digest(fs.readFileSync(path)) };
}

async function readResult(page, path) {
  return await page.evaluate(async (requestPath) => {
    const response = await fetch(requestPath, { headers: { Accept: 'application/json' } });
    const body = await response.json();
    if (!response.ok || !body.ok || !body.result) {
      throw new Error(`verification read failed for ${requestPath}: ${JSON.stringify(body)}`);
    }
    return body.result;
  }, path);
}

async function main() {
  fs.mkdirSync(artifactRoot, { recursive: true });
  const pageErrors = [];
  const failedResponses = [];
  const browser = await chromium.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-dev-shm-usage'],
  });
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  const page = await context.newPage();
  page.on('pageerror', (error) => pageErrors.push(String(error).slice(0, 300)));
  page.on('response', (response) => {
    const url = new URL(response.url());
    if (response.status() >= 400 && url.origin === new URL(baseUrl).origin && url.pathname.startsWith('/v1/')) {
      failedResponses.push({ status: response.status(), url: response.url() });
    }
  });
  const surfaces = {};

  await page.goto(`${baseUrl}/#/catalog`, { waitUntil: 'domcontentloaded', timeout: 60000 });
  await page.locator('[data-testid="catalog-stub"]').waitFor({ state: 'visible', timeout: 60000 });
  const studyRow = page.locator('li').filter({ hasText: 'StudyState Sample' }).first();
  await studyRow.waitFor({ state: 'visible', timeout: 60000 });
  await studyRow.locator('[data-testid^="install-"]').click();
  const installReview = page.locator('[data-testid="install-review"]');
  await installReview.waitFor({ state: 'visible', timeout: 60000 });
  await page.locator('[data-testid="instance-name-input"]').fill(instanceName);
  const reviewText = await installReview.innerText();
  if (!reviewText.includes('requires your confirmation') || !reviewText.includes('Network')) {
    throw new Error('install review did not expose confirmation and permission scope');
  }
  surfaces.installReview = {
    selector: '[data-testid="install-review"]',
    visibleTextSha256: digest(reviewText),
    screenshot: await screenshot(page, 'install-review'),
  };

  const installResponsePromise = page.waitForResponse((response) => {
    const url = new URL(response.url());
    return response.request().method() === 'POST' && url.pathname === '/v1/application-fixtures/install';
  }, { timeout: 60000 });
  await page.locator('[data-testid="confirm-install"]').click();
  const installResponse = await installResponsePromise;
  const installBody = await installResponse.json();
  if (!installResponse.ok() || !installBody.ok || !installBody.result) {
    throw new Error(`browser installation failed: ${JSON.stringify(installBody)}`);
  }
  const installSuccess = page.locator('[data-testid="install-success"]');
  await installSuccess.waitFor({ state: 'visible', timeout: 60000 });
  const successText = await installSuccess.innerText();
  surfaces.installSuccess = {
    selector: '[data-testid="install-success"]',
    visibleTextSha256: digest(successText),
    screenshot: await screenshot(page, 'install-success'),
  };
  await page.locator('[data-testid="open-instance"]').click();
  await page.waitForURL(/#\/app\/[A-Za-z0-9._-]+$/, { timeout: 60000 });
  const hashParts = new URL(page.url()).hash.replace(/^#\//, '').split('/');
  const instanceId = decodeURIComponent(hashParts[1] || '');
  if (!/^[a-z][a-z0-9._-]{1,127}$/.test(instanceId)) {
    throw new Error(`browser generated an invalid instance identity: ${instanceId}`);
  }
  const journey = page.locator('[data-testid="study-native-journey"]');
  await journey.waitFor({ state: 'visible', timeout: 60000 });
  const baseline = await readResult(page, `/v1/instances/${encodeURIComponent(instanceId)}`);
  surfaces.studyBaseline = {
    selector: '[data-testid="study-native-journey"]',
    visibleTextSha256: digest(await journey.innerText()),
    screenshot: await screenshot(page, 'study-baseline'),
  };

  await page.locator('[data-testid="study-open-reflection"]').click();
  const reflectionInput = page.locator(`textarea[id="study-reflection-${instanceId}"]`);
  await reflectionInput.waitFor({ state: 'visible', timeout: 60000 });
  await reflectionInput.fill(reflection);
  await page.locator('[data-testid="study-review-change"]').click();
  const mutationReview = page.locator('[data-testid="study-change-preview"]');
  await mutationReview.waitFor({ state: 'visible', timeout: 60000 });
  const proposedReflection = await page.locator('[data-testid="study-review-reflection"]').innerText();
  if (proposedReflection !== reflection) {
    throw new Error('browser review did not bind the exact reflection');
  }
  surfaces.mutationReview = {
    selector: '[data-testid="study-change-preview"]',
    visibleTextSha256: digest(await mutationReview.innerText()),
    screenshot: await screenshot(page, 'mutation-review'),
  };

  const applyResponsePromise = page.waitForResponse((response) => {
    const url = new URL(response.url());
    return response.request().method() === 'POST' && /^\/v1\/runs\/[^/]+\/apply$/.test(url.pathname);
  }, { timeout: 60000 });
  await page.locator('[data-testid="study-approve-apply"]').click();
  const applyResponse = await applyResponsePromise;
  const applyBody = await applyResponse.json();
  if (!applyResponse.ok() || !applyBody.ok || !applyBody.result) {
    throw new Error(`browser mutation failed: ${JSON.stringify(applyBody)}`);
  }
  const appliedRun = applyBody.result.run || applyBody.result;
  const proposal = appliedRun.proposal;
  const operation = proposal && proposal.operation;
  const applicationReceipt = appliedRun.receipt;
  const closureReceipt = appliedRun.closureReceipt;
  const baselinePackageState = baseline && baseline.packageState;
  if (
    appliedRun.actionId !== 'studystate.sample.record-evidence/v1'
    || !proposal
    || proposal.applicationAction !== 'studystate.sample.record-evidence/v1'
    || !operation
    || operation.type !== 'record_evidence'
    || operation.reflection !== reflection
    || operation.summary !== reflection
    || typeof operation.evidenceId !== 'string'
    || appliedRun.proposalDigest !== contractDigest(proposal)
    || !applicationReceipt
    || applicationReceipt.proposalId !== proposal.proposalId
    || applicationReceipt.preStateDigest !== proposal.preStateDigest
    || applicationReceipt.postStateDigestAuthority !== 'stateport_full_regular_tree_snapshot'
    || applicationReceipt.postStateDigest !== appliedRun.canonicalStateAfter
    || !closureReceipt
    || closureReceipt.proposalId !== proposal.proposalId
    || closureReceipt.proposalDigest !== appliedRun.proposalDigest
    || closureReceipt.applicationReceiptDigest !== contractDigest(applicationReceipt)
    || closureReceipt.canonicalStateBefore !== appliedRun.canonicalStateBefore
    || closureReceipt.canonicalStateAfter !== appliedRun.canonicalStateAfter
    || !baselinePackageState
    || operation.beforePlanDigest !== baselinePackageState.planDigest
  ) {
    throw new Error('applied run is not bound to the exact reviewed reflection proposal');
  }
  const appliedSurface = page.locator('[data-testid="study-applied"]');
  await appliedSurface.waitFor({ state: 'visible', timeout: 60000 });
  const after = await readResult(page, `/v1/instances/${encodeURIComponent(instanceId)}`);
  const packageState = after.packageState;
  const durableEvidence = packageState && Array.isArray(packageState.evidence)
    ? packageState.evidence.filter((item) => item && item.id === operation.evidenceId)
    : [];
  const durableActivity = packageState && Array.isArray(packageState.activities)
    ? packageState.activities.find((item) => item && item.id === operation.activityId)
    : null;
  const transition = packageState && packageState.lastTransition;
  if (
    durableEvidence.length !== 1
    || durableEvidence[0].title !== reflection
    || durableEvidence[0].state !== 'self_reported'
    || !durableActivity
    || durableActivity.state !== 'done'
    || !transition
    || transition.kind !== 'evidence_applied'
    || transition.evidenceId !== operation.evidenceId
    || transition.activityId !== operation.activityId
    || transition.proposalId !== proposal.proposalId
    || operation.afterPlanDigest !== packageState.planDigest
    || transition.beforePlanDigest !== baselinePackageState.planDigest
    || transition.afterPlanDigest !== packageState.planDigest
  ) {
    throw new Error('durable StudyState state is not bound to the exact reviewed reflection');
  }
  surfaces.mutationApplied = {
    selector: '[data-testid="study-applied"]',
    visibleTextSha256: digest(await appliedSurface.innerText()),
    screenshot: await screenshot(page, 'mutation-applied'),
  };

  await browser.close();
  if (pageErrors.length) throw new Error(`browser page errors: ${JSON.stringify(pageErrors)}`);
  if (failedResponses.length) throw new Error(`failed API responses: ${JSON.stringify(failedResponses)}`);
  process.stdout.write(JSON.stringify({
    formatVersion: 'stateport.j2-guided-study/v1',
    instanceId,
    install: installBody.result,
    baseline,
    applied: appliedRun,
    after,
    mutationBinding: {
      actionId: appliedRun.actionId,
      proposalDigest: appliedRun.proposalDigest,
      proposalId: proposal.proposalId,
      activityId: operation.activityId,
      evidenceId: operation.evidenceId,
      reflectionSha256: digest(reflection),
      beforePlanDigest: baselinePackageState.planDigest,
      planDigest: packageState.planDigest,
    },
    surfaces,
    failedResponses,
    pageErrors,
  }) + '\n');
}

main().catch((error) => {
  console.error(error && error.stack ? error.stack : String(error));
  process.exit(1);
});
"""
    return (
        script.replace("__BASE_URL__", json.dumps(base_url))
        .replace("__INSTANCE_NAME__", json.dumps(instance_name))
        .replace("__REFLECTION__", json.dumps(reflection))
    )


def _copy_guest_evidence(vm, guest_path: str, host_path: Path) -> None:
    reader = r"""
import base64
import os
import pwd
import stat
import sys

path = sys.argv[1]
maximum = int(sys.argv[2])
parent, name = os.path.split(path)
parent_fd = os.open(parent, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        info = os.fstat(descriptor)
        expected_uid = pwd.getpwnam('stateport-control').pw_uid
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != expected_uid
            or info.st_size < 1
            or info.st_size > maximum
        ):
            raise SystemExit('unsafe GUI evidence file')
        chunks = []
        remaining = info.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise SystemExit('truncated GUI evidence file')
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise SystemExit('GUI evidence file grew during read')
        sys.stdout.write(base64.b64encode(b''.join(chunks)).decode('ascii'))
    finally:
        os.close(descriptor)
finally:
    os.close(parent_fd)
"""
    encoded = vm.ssh(
        shlex.join(["sudo", "python3", "-", guest_path, str(16 * 1024 * 1024)]),
        check=False,
        timeout=120,
        stdin_text=reader,
    )
    expect(encoded.returncode == 0, f"GUI evidence copy failed: {encoded.stderr[-300:]}")
    try:
        payload = base64.b64decode(encoded.stdout.strip(), validate=True)
    except ValueError as exc:
        raise AssertionError("GUI evidence was not valid base64") from exc
    expect(bool(payload), "GUI evidence screenshot is empty")
    host_path.write_bytes(payload)


def _capture_gui_inspection(
    vm,
    *,
    web_port: str,
    instance_id: str,
    approval_id: str,
    approval_digest: str,
    mutation_receipt_id: str,
    playwright_digest: str,
    receipt_path: Path,
    evidence_label: str = "mutation",
    approve_after_capture: bool = False,
) -> dict:
    _ensure_qualification_registry(vm)
    image = f"{QUALIFICATION_REGISTRY}/stateport-playwright@{playwright_digest}"
    observed = vm.ssh(
        "skopeo inspect --raw --tls-verify=false "
        + shlex.quote(f"docker://{image}")
        + " | sha256sum",
        check=False,
        timeout=180,
    )
    observed_digest = (
        "sha256:" + observed.stdout.split()[0]
        if observed.returncode == 0 and observed.stdout.strip()
        else ""
    )
    expect(observed_digest == playwright_digest, "qualification browser image digest mismatch")

    guest_artifacts = (
        "/var/lib/stateport-control/.local/state/stateport/qualification/J2/" + instance_id
    )
    created = vm.ssh(
        _control_user_command("install", "-d", "-m", "0700", guest_artifacts),
        check=False,
        timeout=60,
    )
    expect(created.returncode == 0, f"GUI evidence directory failed: {created.stderr[-300:]}")
    script = _gui_inspection_script(
        f"http://127.0.0.1:{web_port}",
        instance_id,
        approval_id,
        approval_digest,
        mutation_receipt_id,
        approve_after_capture,
    )
    browser = vm.ssh(
        _control_user_command(
            "podman",
            "run",
            "--rm",
            "--pull=always",
            "--tls-verify=false",
            "--network=host",
            "--userns=keep-id:uid=10001,gid=10001",
            "--read-only",
            "--tmpfs=/tmp:rw,nosuid,nodev,size=256m",
            "--shm-size=256m",
            "--security-opt=no-new-privileges",
            "--cap-drop=all",
            "--pids-limit=512",
            "--memory=1g",
            "--cpus=2",
            "--env=HOME=/tmp",
            "--volume",
            f"{guest_artifacts}:/artifacts:rw",
            image,
            "node",
            "-e",
            script,
        ),
        check=False,
        timeout=600,
    )
    expect(browser.returncode == 0, f"GUI inspection failed: {browser.stderr[-1000:]}")
    lines = [line for line in browser.stdout.splitlines() if line.strip()]
    expect(bool(lines), "GUI inspection emitted no result")
    try:
        evidence = json.loads(lines[-1])
    except json.JSONDecodeError as exc:
        raise AssertionError("GUI inspection result is not JSON") from exc
    expected_surfaces = {"history", "approvals", "receipts", "contextCost"}
    surfaces = evidence.get("surfaces") if isinstance(evidence, dict) else None
    expect(isinstance(surfaces, dict), "GUI inspection surfaces missing")
    expect(set(surfaces) == expected_surfaces, "GUI inspection surface set mismatch")
    expect(evidence.get("pageErrors") == [], "GUI inspection reported page errors")
    expect(evidence.get("failedResponses") == [], "GUI inspection reported failed API responses")

    artifact_dir = receipt_path.parent / f"{receipt_path.stem}-gui-{instance_id}-{evidence_label}"
    artifact_dir.mkdir(parents=True, exist_ok=False)
    for name, surface in surfaces.items():
        expect(isinstance(surface, dict), f"GUI surface {name} is malformed")
        screenshot = surface.get("screenshot")
        expect(isinstance(screenshot, dict), f"GUI surface {name} screenshot missing")
        filename = screenshot.get("file")
        expect(
            isinstance(filename, str) and Path(filename).name == filename,
            f"GUI surface {name} screenshot identity invalid",
        )
        host_path = artifact_dir / filename
        _copy_guest_evidence(vm, f"{guest_artifacts}/{filename}", host_path)
        expect(_sha256(host_path) == screenshot.get("sha256"), f"GUI surface {name} digest mismatch")
        screenshot["hostPath"] = str(host_path)
        screenshot["bytes"] = host_path.stat().st_size

    evidence["browserImage"] = image
    evidence["browserImageDigest"] = observed_digest
    manifest_path = artifact_dir / "inspection.json"
    manifest_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {
        "browserImage": image,
        "browserImageDigest": observed_digest,
        "manifest": str(manifest_path),
        "manifestSha256": _sha256(manifest_path),
        "surfaces": surfaces,
        "failedResponses": evidence.get("failedResponses", []),
        "approvalDecision": evidence.get("approvalDecision"),
    }


def _capture_guided_study_journey(
    vm,
    *,
    web_port: str,
    playwright_digest: str,
    receipt_path: Path,
    instance_name: str,
    reflection: str,
) -> dict:
    _ensure_qualification_registry(vm)
    image = f"{QUALIFICATION_REGISTRY}/stateport-playwright@{playwright_digest}"
    observed = vm.ssh(
        "skopeo inspect --raw --tls-verify=false "
        + shlex.quote(f"docker://{image}")
        + " | sha256sum",
        check=False,
        timeout=180,
    )
    observed_digest = (
        "sha256:" + observed.stdout.split()[0]
        if observed.returncode == 0 and observed.stdout.strip()
        else ""
    )
    expect(observed_digest == playwright_digest, "qualification browser image digest mismatch")
    guest_artifacts = (
        "/var/lib/stateport-control/.local/state/stateport/qualification/J2/guided-"
        + secrets.token_hex(6)
    )
    created = vm.ssh(
        _control_user_command("install", "-d", "-m", "0700", guest_artifacts),
        check=False,
        timeout=60,
    )
    expect(created.returncode == 0, f"guided evidence directory failed: {created.stderr[-300:]}")
    browser = vm.ssh(
        _control_user_command(
            "podman",
            "run",
            "--rm",
            "--pull=always",
            "--tls-verify=false",
            "--network=host",
            "--userns=keep-id:uid=10001,gid=10001",
            "--read-only",
            "--tmpfs=/tmp:rw,nosuid,nodev,size=256m",
            "--shm-size=256m",
            "--security-opt=no-new-privileges",
            "--cap-drop=all",
            "--pids-limit=512",
            "--memory=1g",
            "--cpus=2",
            "--env=HOME=/tmp",
            "--volume",
            f"{guest_artifacts}:/artifacts:rw",
            image,
            "node",
            "-e",
            _guided_study_script(
                f"http://127.0.0.1:{web_port}", instance_name, reflection
            ),
        ),
        check=False,
        timeout=600,
    )
    expect(browser.returncode == 0, f"guided browser journey failed: {browser.stderr[-1000:]}")
    lines = [line for line in browser.stdout.splitlines() if line.strip()]
    expect(bool(lines), "guided browser journey emitted no result")
    try:
        evidence = json.loads(lines[-1])
    except json.JSONDecodeError as exc:
        raise AssertionError("guided browser journey result is not JSON") from exc
    surfaces = evidence.get("surfaces") if isinstance(evidence, dict) else None
    expected_surfaces = {
        "installReview",
        "installSuccess",
        "studyBaseline",
        "mutationReview",
        "mutationApplied",
    }
    expect(isinstance(surfaces, dict) and set(surfaces) == expected_surfaces, "guided browser surfaces are incomplete")
    expect(evidence.get("pageErrors") == [], "guided browser reported page errors")
    expect(evidence.get("failedResponses") == [], "guided browser reported failed API responses")
    instance_id = evidence.get("instanceId")
    expect(isinstance(instance_id, str) and bool(instance_id), "guided browser returned no instance identity")
    artifact_dir = receipt_path.parent / f"{receipt_path.stem}-gui-{instance_id}-guided"
    artifact_dir.mkdir(parents=True, exist_ok=False)
    for name, surface in surfaces.items():
        expect(isinstance(surface, dict), f"guided surface {name} is malformed")
        screenshot = surface.get("screenshot")
        expect(isinstance(screenshot, dict), f"guided surface {name} screenshot missing")
        filename = screenshot.get("file")
        expect(
            isinstance(filename, str) and Path(filename).name == filename,
            f"guided surface {name} screenshot identity invalid",
        )
        host_path = artifact_dir / filename
        _copy_guest_evidence(vm, f"{guest_artifacts}/{filename}", host_path)
        expect(_sha256(host_path) == screenshot.get("sha256"), f"guided surface {name} digest mismatch")
        screenshot["hostPath"] = str(host_path)
        screenshot["bytes"] = host_path.stat().st_size
    evidence["browserImage"] = image
    evidence["browserImageDigest"] = observed_digest
    manifest_path = artifact_dir / "guided-study.json"
    manifest_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    evidence["manifest"] = str(manifest_path)
    evidence["manifestSha256"] = _sha256(manifest_path)
    return evidence


def _require_ssh_port_available() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind(("127.0.0.1", SSH_PORT))
        except OSError as exc:
            raise AssertionError(
                f"retained VM SSH port 127.0.0.1:{SSH_PORT} is already occupied"
            ) from exc


def governed_proposal(
    web: GuestJsonClient, instance_id: str, action_id: str, inputs: dict
) -> dict:
    prepare = web.request(
        "POST", f"/v1/instances/{instance_id}/execution/prepare",
        {"expectedInstanceId": instance_id, "actionId": action_id,
         "engineId": "synthetic", "inputs": inputs},
        csrf=True,
    )
    run = prepare["run"]
    run_id = run["runId"]
    revision = run["revision"]
    proposal_digest = None
    # Every run transition bumps the run revision; the next call must bind the
    # revision returned by the previous transition, not the prepare-time value.
    # Approve returns {revision}; execute returns {run: {revision, ...}}.
    for step in ("approve", "execute"):
        transitioned = web.request("POST", f"/v1/runs/{run_id}/{step}",
                                   {"expectedInstanceId": instance_id, "expectedRevision": revision},
                                   csrf=True)
        transitioned_run = transitioned.get("run") if isinstance(transitioned, dict) else None
        next_revision = (
            transitioned.get("revision")
            if isinstance(transitioned, dict) and isinstance(transitioned.get("revision"), int)
            else (transitioned_run.get("revision") if isinstance(transitioned_run, dict) and isinstance(transitioned_run.get("revision"), int) else None)
        )
        if next_revision is not None:
            revision = int(next_revision)
        transitioned_record = transitioned_run if isinstance(transitioned_run, dict) else transitioned
        if isinstance(transitioned_record, dict) and isinstance(
            transitioned_record.get("proposalDigest"), str
        ):
            proposal_digest = transitioned_record["proposalDigest"]
    expect(bool(proposal_digest), "governed execution produced no proposal digest")
    return {
        "runId": run_id,
        "revision": revision,
        "proposalDigest": proposal_digest,
    }


def governed_chain(
    web: GuestJsonClient, instance_id: str, action_id: str, inputs: dict
) -> dict:
    proposed = governed_proposal(web, instance_id, action_id, inputs)
    run_id = proposed["runId"]
    revision = proposed["revision"]
    proposal = web.request("POST", f"/v1/runs/{run_id}/proposal-approve",
                           {"expectedInstanceId": instance_id, "expectedRevision": revision},
                           csrf=True)
    if isinstance(proposal, dict) and isinstance(proposal.get("revision"), int):
        revision = int(proposal["revision"])
    applied_response = web.request(
        "POST",
        f"/v1/runs/{run_id}/apply",
        {"expectedInstanceId": instance_id, "expectedRevision": revision},
        csrf=True,
    )
    applied = applied_response.get("run") if isinstance(applied_response, dict) else None
    expect(isinstance(applied, dict), "governed apply returned no run record")
    expect(applied.get("runId") == run_id, "governed apply returned the wrong run")
    expect(applied.get("status") == "applied", "governed apply did not reach applied state")
    expect(applied.get("lifecycleState") == "CLOSED", "governed apply did not close")
    closure = applied.get("closureReceipt")
    expect(
        isinstance(closure, dict) and bool(closure.get("receiptId")),
        "governed apply returned no closure receipt",
    )
    return {
        "runId": run_id,
        "revision": revision,
        "proposalDigest": proposal.get("proposalDigest") if isinstance(proposal, dict) else None,
        "applied": applied,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt-out", type=Path, required=True)
    parser.add_argument("--vm-dir", type=Path, required=True)
    parser.add_argument("--candidate-dir", type=Path, required=True)
    parser.add_argument("--site-root", type=Path, required=True)
    parser.add_argument("--archive-root", type=Path, required=True)
    args = parser.parse_args()

    try:
        facts, prerequisite_evidence = validate_retained_candidate_inputs(
            args.candidate_dir, args.vm_dir, args.site_root, args.archive_root
        )
    except Exception as exc:  # noqa: BLE001 - preflight failure must be durable
        receipt = JourneyReceipt(
            "J2-durable-stateware-mutation-restart-inspect-undo",
            {
                "candidateDir": str(args.candidate_dir),
                "vmDir": str(args.vm_dir),
                "siteRoot": str(args.site_root),
                "archiveRoot": str(args.archive_root),
            },
        )
        receipt.out_path = args.receipt_out
        receipt.record("input-preflight", False, error=f"{type(exc).__name__}: {exc}")
        receipt.document["result"] = "failed"
        receipt.write(args.receipt_out)
        log(f"result: failed -> {args.receipt_out}")
        return 1
    receipt = JourneyReceipt("J2-durable-stateware-mutation-restart-inspect-undo",
                             {"candidate": facts, "prerequisites": prerequisite_evidence})
    receipt.out_path = args.receipt_out
    receipt.write(args.receipt_out)

    vm = None
    try:
        _require_ssh_port_available()
        receipt.record("input-preflight", True, **prerequisite_evidence)
        vm = boot_retained_vm(
            args.vm_dir, site_root=args.site_root, archive_root=args.archive_root
        )
        services = discover_services(vm)
        for service_id in ("stateport-web", "stateport-api", "stateport-worker"):
            wait_service_healthy(vm, services, service_id, deadline_s=420)
        digests = verify_installed_image_digests(vm, dict(facts["images"]))  # type: ignore[arg-type]
        receipt.record("control-plane-bound-to-candidate",
                        not digests["mismatches"], services=services)  # type: ignore[union-attr]
        expect(not digests["mismatches"], "installed control-plane image digest mismatch")  # type: ignore[union-attr]

        web = GuestJsonClient(vm, services["stateport-web"]["port"])
        session = web.request("GET", "/session")
        web.handshake()
        receipt.record("web-session-handshake", True, session={k: v for k, v in session.items() if k != "csrfToken"})

        existing_study_instances = _existing_study_instances(
            web.request("GET", "/v1/instances")
        )
        receipt.record(
            "retained-journey-baseline-isolated",
            not existing_study_instances,
            existingStudyInstances=existing_study_instances,
        )
        expect(
            not existing_study_instances,
            "retained VM already contains StudyState journey state; use a fresh post-J1 overlay",
        )

        catalog = web.request("GET", "/v1/applications")
        study = next(e for e in catalog["applications"] if e["applicationId"] == "studystate.sample")
        images = facts.get("images")
        playwright_digest = (
            images.get("stateport-playwright") if isinstance(images, dict) else None
        )
        expect(
            isinstance(playwright_digest, str) and playwright_digest.startswith("sha256:"),
            "candidate Playwright image digest missing",
        )
        reflection = "Governed durable mutation recorded during the J2 release journey."
        guided = _capture_guided_study_journey(
            vm,
            web_port=services["stateport-web"]["port"],
            playwright_digest=playwright_digest,
            receipt_path=args.receipt_out,
            instance_name=f"Release Journey StudyState {secrets.token_hex(4)}",
            reflection=reflection,
        )
        instance_id = guided["instanceId"]
        installed = guided.get("install") or {}
        lifecycle = installed.get("lifecycle") or {}
        source_kind = (study.get("install") or {}).get("sourceKind")
        fixture_installed = (
            lifecycle.get("revisionId") == "v0001"
            and source_kind == "bundled_public_fixture"
            and study.get("productionEligible") is False
            and guided.get("browserImageDigest") == playwright_digest
        )
        receipt.record(
            "fixture-install-browser-consent",
            fixture_installed,
            instanceId=instance_id,
            sourceKind=source_kind,
            productionEligible=study.get("productionEligible"),
            revisionId=lifecycle.get("revisionId"),
            releaseVersion=lifecycle.get("releaseVersion"),
            receiptId=(installed.get("receipt") or {}).get("receiptId"),
            browserManifest=guided.get("manifest"),
            browserManifestSha256=guided.get("manifestSha256"),
            surfaces=guided.get("surfaces"),
        )
        expect(fixture_installed, f"unexpected fixture install identity {installed}")

        baseline = guided.get("baseline") or {}
        expect(
            (baseline.get("instance") or {}).get("id") == instance_id,
            "guided baseline is not bound to the installed instance",
        )
        baseline_source = baseline.get("source")
        baseline_version = baseline.get("version")
        package_state = baseline.get("packageState") or {}
        baseline_snapshot = _study_state_snapshot(package_state)
        plan_digest_0 = package_state.get("planDigest")
        expect(bool(plan_digest_0), "baseline plan digest missing")

        applied_run = guided.get("applied") or {}
        mutation_binding = _guided_mutation_binding(
            applied_run, baseline, guided.get("after"), reflection
        )
        expect(
            guided.get("mutationBinding") == mutation_binding,
            "browser and verifier mutation bindings differ",
        )
        first = {
            "runId": applied_run.get("runId"),
            "proposalDigest": applied_run.get("proposalDigest"),
            "applied": applied_run,
        }
        after_first = web.request("GET", f"/v1/instances/{instance_id}")
        expect(after_first == guided.get("after"), "guided mutation result changed before verification")
        after_first_package = after_first.get("packageState") or {}
        after_first_snapshot = _study_state_snapshot(after_first_package)
        plan_digest_1 = after_first_package.get("planDigest")
        closure = (first["applied"].get("closureReceipt") or {})
        application_receipt = first["applied"].get("receipt") or {}
        mutation_applied = (
            bool(plan_digest_1 and plan_digest_1 != plan_digest_0)
            and isinstance(closure.get("receiptId"), str)
            and closure.get("runId") == first["runId"]
            and closure.get("instanceId") == instance_id
            and closure.get("proposalId")
            == (first["applied"].get("proposal") or {}).get("proposalId")
            and closure.get("proposalDigest") == first["proposalDigest"]
            and closure.get("applicationReceiptDigest")
            == _contract_digest(application_receipt)
            and closure.get("canonicalStateBefore")
            == first["applied"].get("canonicalStateBefore")
            and closure.get("canonicalStateAfter")
            == first["applied"].get("canonicalStateAfter")
            and application_receipt.get("preStateDigest")
            == (first["applied"].get("proposal") or {}).get("preStateDigest")
            and first["applied"].get("canonicalStateAfter")
            == application_receipt.get("postStateDigest")
            and len(after_first_snapshot["evidence"])
            == len(baseline_snapshot["evidence"]) + 1
        )
        receipt.record("governed-mutation-applied", mutation_applied,
                       runId=first["runId"], proposalDigest=first["proposalDigest"],
                       closureReceiptId=closure.get("receiptId"),
                       canonicalStateBefore=first["applied"].get("canonicalStateBefore"),
                       canonicalStateAfter=first["applied"].get("canonicalStateAfter"),
                       mutationBinding=mutation_binding,
                       studyStateBefore=_object_digest(baseline_snapshot),
                       studyStateAfter=_object_digest(after_first_snapshot),
                       planBefore=plan_digest_0, planAfter=plan_digest_1)
        expect(mutation_applied, "governed mutation receipt identity is incomplete")

        restart_service(vm, services["stateport-web"]["unit"])
        wait_service_healthy(vm, services, "stateport-web", deadline_s=300)
        web.handshake()
        persisted = web.request("GET", f"/v1/instances/{instance_id}")
        persisted_package = persisted.get("packageState") or {}
        persisted_snapshot = _study_state_snapshot(persisted_package)
        history = web.request("GET", f"/v1/instances/{instance_id}/execution/history")
        runs = [r.get("runId") for r in (history.get("runs") or [])] if isinstance(history, dict) else []
        receipt.record("state-survives-service-restart",
                       persisted_package == after_first_package
                       and first["runId"] in runs,
                       planDigest=plan_digest_1,
                       durableStateDigest=_object_digest(persisted_package),
                       semanticStateDigest=_object_digest(persisted_snapshot),
                       historyRunIds=runs)

        inspections = {
            "approvals-instance": f"/v1/instances/{instance_id}/approvals",
            "approvals-global": "/v1/approvals",
            "receipts": f"/v1/instances/{instance_id}/receipts",
            "activity": f"/v1/instances/{instance_id}/activity",
            "context-lifecycle": f"/v1/instances/{instance_id}/context-lifecycle",
        }
        inspection_results = {}
        for name, path in inspections.items():
            try:
                result = web.request("GET", path)
                size = len(json.dumps(result))
                inspection_results[name] = {"ok": True, "bytes": size}
            except Refusal as refusal:
                inspection_results[name] = {"ok": False, "code": refusal.code}
        receipt.record("inspection-surface-readable",
                       all(v["ok"] for v in inspection_results.values()),
                       results=inspection_results)

        approval_review = governed_proposal(
            web,
            instance_id,
            UNDO_ACTION,
            {"expectedPlanDigest": plan_digest_1},
        )
        gui_evidence = _capture_gui_inspection(
            vm,
            web_port=services["stateport-web"]["port"],
            instance_id=instance_id,
            approval_id=f"run_proposal:{approval_review['runId']}",
            approval_digest=approval_review["proposalDigest"],
            mutation_receipt_id=closure["receiptId"],
            playwright_digest=playwright_digest,
            receipt_path=args.receipt_out,
            evidence_label="mutation",
        )
        rejected_review = web.request(
            "POST",
            f"/v1/runs/{approval_review['runId']}/proposal-reject",
            {
                "expectedInstanceId": instance_id,
                "expectedRevision": approval_review["revision"],
            },
            csrf=True,
        )
        gui_surfaces = gui_evidence.get("surfaces")
        gui_ok = (
            gui_evidence.get("browserImageDigest") == playwright_digest
            and isinstance(gui_surfaces, dict)
            and set(gui_surfaces) == {"history", "approvals", "receipts", "contextCost"}
            and gui_evidence.get("failedResponses") == []
            and (gui_surfaces.get("approvals") or {}).get("approvalId")
            == f"run_proposal:{approval_review['runId']}"
            and (gui_surfaces.get("approvals") or {}).get("renderedApprovalDigest")
            == approval_review["proposalDigest"]
            and (gui_surfaces.get("history") or {}).get("mutationReceiptId")
            == closure["receiptId"]
            and (gui_surfaces.get("receipts") or {}).get("receiptId")
            == closure["receiptId"]
            and rejected_review.get("status") == "state_change_rejected"
            and rejected_review.get("lifecycleState") == "CLOSED"
            and all(
                isinstance(surface, dict)
                and isinstance(surface.get("rows"), int)
                and surface["rows"] > 0
                and isinstance(surface.get("screenshot"), dict)
                and bool(surface["screenshot"].get("hostPath"))
                for surface in gui_surfaces.values()
            )
        )
        gui_evidence["approvalReview"] = {
            "runId": approval_review["runId"],
            "proposalDigest": approval_review["proposalDigest"],
            "closureStatus": rejected_review.get("status"),
            "closureLifecycle": rejected_review.get("lifecycleState"),
        }
        receipt.record("gui-inspection-evidence", gui_ok, **gui_evidence)
        expect(gui_ok, "required J2 GUI inspection evidence is incomplete")

        undo = governed_chain(web, instance_id, UNDO_ACTION,
                              {"expectedPlanDigest": plan_digest_1})
        after_undo = web.request("GET", f"/v1/instances/{instance_id}")
        after_undo_snapshot = _study_state_snapshot(after_undo.get("packageState") or {})
        plan_digest_2 = after_undo_snapshot.get("planDigest")
        undo_binding = _undo_restoration_binding(
            undo["applied"],
            reviewed_run=rejected_review,
            mutation_run=first["applied"],
            expected_review_run_id=approval_review["runId"],
            expected_applied_run_id=undo["runId"],
            expected_instance_id=instance_id,
            expected_current_plan_digest=plan_digest_1,
            expected_restored_plan_digest=plan_digest_0,
            expected_semantic_state=baseline_snapshot,
            actual_semantic_state=after_undo_snapshot,
        )
        receipt.record("undo-restores-prior-state", True,
                       planAfterUndo=plan_digest_2,
                       expectedPrior=plan_digest_0,
                       semanticStateBefore=_object_digest(baseline_snapshot),
                       semanticStateAfter=_object_digest(after_undo_snapshot),
                       undoBinding=undo_binding)

        restart_service(vm, services["stateport-web"]["unit"])
        wait_service_healthy(vm, services, "stateport-web", deadline_s=300)
        web.handshake()
        undone_persisted = web.request("GET", f"/v1/instances/{instance_id}")
        after_undo_package = after_undo.get("packageState") or {}
        undone_persisted_package = undone_persisted.get("packageState") or {}
        undone_persisted_snapshot = _study_state_snapshot(
            undone_persisted_package
        )
        receipt.record("undo-survives-second-restart",
                       undone_persisted_package == after_undo_package,
                       durableStateDigest=_object_digest(undone_persisted_package),
                       semanticStateDigest=_object_digest(undone_persisted_snapshot))

        # Qualify the independently installed API bearer identities separately
        # from the web application's own upgrade authority chain.
        api = GuestJsonClient(vm, services["stateport-api"]["port"])
        token_doc = vm.ssh(
            "sudo cat $HOME/.local/state/stateport-install/control-plane-operator-token",
            check=False,
            timeout=60,
        )
        approver_token_doc = vm.ssh(
            "sudo cat $HOME/.local/state/stateport-install/control-plane-approver-token",
            check=False,
            timeout=60,
        )
        operator_token = token_doc.stdout.strip() if token_doc.returncode == 0 else ""
        approver_token = (
            approver_token_doc.stdout.strip()
            if approver_token_doc.returncode == 0
            else ""
        )
        expect(bool(operator_token), "control-plane operator token unreadable")
        expect(bool(approver_token), "control-plane approver token unreadable")
        operator_headers = {"Authorization": f"Bearer {operator_token}"}
        approver_headers = {"Authorization": f"Bearer {approver_token}"}
        operator_identity = api.request(
            "POST",
            "/v1/identity/check",
            {"actor": GOVERNED_ACTOR},
            headers=operator_headers,
        )["identity"]
        approver_identity = api.request(
            "POST",
            "/v1/identity/check",
            {"actor": GOVERNED_APPROVER},
            headers=approver_headers,
        )["identity"]
        identities_separated = (
            not secrets.compare_digest(operator_token, approver_token)
            and operator_identity.get("id") == GOVERNED_ACTOR
            and operator_identity.get("roles") == ["operator"]
            and approver_identity.get("id") == GOVERNED_APPROVER
            and approver_identity.get("roles") == ["approver"]
        )
        receipt.record(
            "control-plane-identities-separated",
            identities_separated,
            operator=operator_identity,
            approver=approver_identity,
        )
        expect(identities_separated, "installed control-plane identities are not separated")

        # The descriptor resolver and governed coordinator now run inside the
        # persistent application service. Only the declared revision crosses
        # this route; no caller-controlled instance or template path exists.
        requested = web.request(
            "POST",
            f"/v1/instances/{instance_id}/template-upgrade/request",
            {"expectedInstanceId": instance_id, "targetRevision": "v0002"},
            csrf=True,
        )
        upgrade_approval = requested.get("approval") or {}
        upgrade_plan = requested.get("plan") or {}
        target_binding = requested.get("targetBinding") or {}
        approval_id = upgrade_approval.get("id")
        plan_digest_upgrade = upgrade_plan.get("planDigest")
        template_ok = (
            target_binding.get("applicationId") == "studystate.sample"
            and target_binding.get("targetRevision") == "v0002"
            and isinstance(target_binding.get("templateDigest"), str)
            and target_binding["templateDigest"].startswith("sha256:")
            and (upgrade_plan.get("target") or {}).get("version") == "0.2.0"
        )
        receipt.record(
            "template-revisions-shipped",
            template_ok,
            instanceId=instance_id,
            targetBinding=target_binding,
        )
        expect(template_ok, "descriptor-declared v0002 template revision is unavailable")
        receipt.document["upgradePaths"] = {
            "instanceId": instance_id,
            "targetRevision": target_binding.get("targetRevision"),
            "templateDigest": target_binding.get("templateDigest"),
            "callerSuppliedPaths": False,
        }
        receipt.record(
            "upgrade-preview-planned",
            isinstance(approval_id, str)
            and isinstance(plan_digest_upgrade, str)
            and upgrade_approval.get("status") == "pending"
            and upgrade_plan.get("blocked") is False,
            approvalId=approval_id,
            blocked=upgrade_plan.get("blocked"),
            files=upgrade_plan.get("files"),
            planDigest=plan_digest_upgrade,
            current=upgrade_plan.get("current"),
            target=upgrade_plan.get("target"),
        )
        expect(isinstance(approval_id, str), "upgrade approval identity missing")
        expect(isinstance(plan_digest_upgrade, str), "upgrade preview plan digest missing")

        preapproval_refusal_code = None
        try:
            web.request(
                "POST",
                f"/v1/instances/{instance_id}/template-upgrade/apply",
                {"expectedInstanceId": instance_id,
                 "approvalId": approval_id,
                 "expectedPlanDigest": plan_digest_upgrade},
                csrf=True,
            )
        except Refusal as refusal:
            preapproval_refusal_code = refusal.code
            receipt.document.setdefault("refusals", []).append(
                {"step": "preapproval-apply-probe", "code": refusal.code})
        expect(preapproval_refusal_code == "approval_required", "upgrade applied before approval")

        upgrade_gui = _capture_gui_inspection(
            vm,
            web_port=services["stateport-web"]["port"],
            instance_id=instance_id,
            approval_id=f"template_upgrade:{approval_id}",
            approval_digest=plan_digest_upgrade,
            mutation_receipt_id=closure["receiptId"],
            playwright_digest=playwright_digest,
            receipt_path=args.receipt_out,
            evidence_label="upgrade",
            approve_after_capture=True,
        )
        upgrade_gui_surfaces = upgrade_gui.get("surfaces")
        upgrade_gui_ok = (
            upgrade_gui.get("approvalDecision") == "approved"
            and upgrade_gui.get("failedResponses") == []
            and isinstance(upgrade_gui_surfaces, dict)
            and (upgrade_gui_surfaces.get("approvals") or {}).get("approvalId")
            == f"template_upgrade:{approval_id}"
            and (upgrade_gui_surfaces.get("approvals") or {}).get("approvalDigest")
            == plan_digest_upgrade
            and (upgrade_gui_surfaces.get("approvals") or {}).get("renderedApprovalDigest")
            == plan_digest_upgrade
        )
        receipt.record("upgrade-plan-gui-inspected", upgrade_gui_ok, **upgrade_gui)
        expect(upgrade_gui_ok, "exact upgrade plan was not approved through the GUI")

        applied_upgrade = web.request(
            "POST",
            f"/v1/instances/{instance_id}/template-upgrade/apply",
            {"expectedInstanceId": instance_id,
             "approvalId": approval_id,
             "expectedPlanDigest": plan_digest_upgrade},
            csrf=True,
        )
        replay = web.request(
            "POST",
            f"/v1/instances/{instance_id}/template-upgrade/apply",
            {"expectedInstanceId": instance_id,
             "approvalId": approval_id,
             "expectedPlanDigest": plan_digest_upgrade},
            csrf=True,
        )
        upgrade_receipt = applied_upgrade.get("receipt") or {}
        upgrade_receipt_id = applied_upgrade.get("activityReceiptId")
        upgrade_authority = applied_upgrade.get("authority") or {}
        upgrade_authority_bindings = applied_upgrade.get("authorityBindings") or {}
        authority_bound = (
            upgrade_authority == {
            "requestedBy": "persistent-app-upgrade-requester",
            "approvedBy": "authenticated-platform_operator-approver",
            "appliedBy": "persistent-app-upgrade-operator",
            }
            and applied_upgrade.get("authorityModel")
            == "authenticated_session_with_internal_service_roles/v1"
            and upgrade_authority_bindings
            == {
                "requestedBy": {
                    "id": "persistent-app-upgrade-requester",
                    "principalType": "internal_service_role",
                },
                "approvedBy": {
                    "id": "authenticated-platform_operator-approver",
                    "principalType": "authenticated_operator_session",
                    "sessionActorId": "platform-operator",
                    "sessionActorRole": "platform_operator",
                },
                "appliedBy": {
                    "id": "persistent-app-upgrade-operator",
                    "principalType": "internal_service_role",
                },
            }
        )
        receipt.record(
            "upgrade-authority-chain-bound",
            authority_bound,
            authority=upgrade_authority,
            authorityModel=applied_upgrade.get("authorityModel"),
            authorityBindings=upgrade_authority_bindings,
        )
        upgrade_applied = (
            applied_upgrade.get("applied") is True
            and upgrade_receipt.get("status") == "applied"
            and upgrade_receipt.get("planDigest") == plan_digest_upgrade
            and upgrade_receipt.get("target", {}).get("version") == "0.2.0"
            and replay.get("idempotent") is True
            and replay.get("receipt", {}).get("planDigest") == plan_digest_upgrade
            and preapproval_refusal_code == "approval_required"
            and upgrade_receipt_id == f"template-upgrade:{approval_id}"
            and authority_bound
        )
        receipt.record(
            "template-upgrade-applied",
            upgrade_applied,
            approvalId=approval_id,
            preapprovalRefusalCode=preapproval_refusal_code,
            changedFiles=applied_upgrade.get("changedFiles"),
            replayIdempotent=replay.get("idempotent"),
            planDigest=plan_digest_upgrade,
            receiptId=upgrade_receipt_id,
        )
        expect(upgrade_applied, "same-instance template upgrade evidence is incomplete")

        restart_service(vm, services["stateport-web"]["unit"])
        wait_service_healthy(vm, services, "stateport-web", deadline_s=300)
        web.handshake()
        upgraded = web.request("GET", f"/v1/instances/{instance_id}")
        upgraded_package = upgraded.get("packageState") or {}
        upgraded_snapshot = _study_state_snapshot(upgraded_package)
        upgraded_history = web.request("GET", f"/v1/instances/{instance_id}/execution/history")
        upgraded_runs = [r.get("runId") for r in (upgraded_history.get("runs") or [])] if isinstance(upgraded_history, dict) else []
        upgraded_actions = web.request("GET", f"/v1/instances/{instance_id}/actions")
        upgraded_action_ids = {
            item.get("actionId")
            for item in upgraded_actions.get("actions", [])
            if isinstance(item, dict) and isinstance(item.get("actionId"), str)
        }
        receipt_index = web.request("GET", f"/v1/instances/{instance_id}/receipts")
        visible_receipt_ids = {
            item.get("receiptId")
            for item in receipt_index.get("receipts", [])
            if isinstance(item, dict) and isinstance(item.get("receiptId"), str)
        }
        personal_state_intact = (
            upgraded.get("instance", {}).get("id") == instance_id
            and upgraded_snapshot == after_undo_snapshot
            and upgraded.get("source") != baseline_source
            and upgraded.get("version") == "0.2.0"
            and baseline_version == "0.1.0"
            and first["runId"] in upgraded_runs
            and "studystate.sample.study-tip/v1" in upgraded_action_ids
            and upgrade_receipt_id in visible_receipt_ids
        )
        receipt.record("personal-state-intact-after-upgrade",
                       personal_state_intact,
                       planDigest=upgraded_package.get("planDigest"),
                       expectedPlanDigest=plan_digest_0,
                        studyStateDigest=_object_digest(upgraded_snapshot),
                       personalSource=upgraded.get("source"),
                       personalVersion=upgraded.get("version"),
                       actionIds=sorted(upgraded_action_ids),
                       upgradeReceiptId=upgrade_receipt_id,
                       visibleReceiptIds=sorted(str(item) for item in visible_receipt_ids))
        expect(personal_state_intact, "personal state or exact upgraded source did not survive")

        exported = web.request("POST", f"/v1/instances/{instance_id}/portable-export", {}, csrf=True)
        archive = exported.get("archive") if isinstance(exported, dict) else None
        archive_path = str(archive) if archive else None
        export_manifest = exported.get("manifest") if isinstance(exported, dict) else None
        file_digest = None
        if archive_path:
            web_container = services["stateport-web"]["container"]
            checksum = vm.ssh(
                _control_podman_exec_command(web_container, "sha256sum", archive_path),
                check=False,
                timeout=120,
            )
            file_digest = checksum.stdout.split()[0] if checksum.stdout.strip() else None
        expected_file_digest = str(exported.get("archiveFileDigest") or "").removeprefix(
            "sha256:"
        )
        export_identity_ok = (
            isinstance(export_manifest, dict)
            and export_manifest.get("formatVersion") == "stateport.instance-portable/v1"
            and export_manifest.get("instanceId") == instance_id
            and isinstance(export_manifest.get("sourceIdentity"), dict)
            and export_manifest.get("archiveDigest") == exported.get("archiveDigest")
            and isinstance(export_manifest.get("fileCount"), int)
            and export_manifest.get("fileCount", 0) > 0
            and (export_manifest.get("engineSessions") or {}).get("included") is False
            and (export_manifest.get("machinePaths") or {}).get("included") is False
        )
        export_ok = (
            bool(archive_path)
            and archive_path.startswith(
                "/var/lib/stateport/state/stateport/operations/portable/"
            )
            and file_digest is not None
            and file_digest == expected_file_digest
            and export_identity_ok
        )
        receipt.record("portable-export-verified",
                       export_ok,
                       archive=str(archive), archiveDigest=exported.get("archiveDigest"),
                       archiveFileDigest=exported.get("archiveFileDigest"),
                       observedFileDigest=file_digest,
                       sourceInstanceId=(export_manifest or {}).get("instanceId"),
                       sourceIdentity=(export_manifest or {}).get("sourceIdentity"),
                       fileCount=(export_manifest or {}).get("fileCount"))
        expect(export_ok, "portable export identity or archive bytes are incomplete")

        copy_instance = "j2copy-" + secrets.token_hex(4)
        destination_path = f"/var/lib/stateport/data/stateport/instances/{copy_instance}"
        preview_import = web.request(
            "POST", "/v1/portable-import/preview",
            {"archive": {"path": archive_path,
                         "archiveDigest": exported.get("archiveDigest"),
                         "archiveFileDigest": exported.get("archiveFileDigest")},
             "destination": {"path": destination_path, "instanceId": copy_instance},
             "identityPolicy": "reidentify"},
            csrf=True,
        )
        imported = web.request(
            "POST", "/v1/portable-import/apply",
            {"archive": {"path": archive_path,
                         "archiveDigest": exported.get("archiveDigest"),
                         "archiveFileDigest": exported.get("archiveFileDigest")},
             "destination": {"path": destination_path, "instanceId": copy_instance},
             "identityPolicy": "reidentify",
             "expectedPlanDigest": preview_import.get("planDigest"),
             "approval": {"decision": "approve",
                          "actorId": str(session.get("actorId") or "platform-operator"),
                          "actorRole": str(session.get("actorRole") or "platform_operator")}},
            csrf=True,
        )
        import_receipt = imported.get("receipt") if isinstance(imported, dict) else None
        preview_identity_ok = (
            isinstance(preview_import, dict)
            and preview_import.get("sourceInstanceId") == instance_id
            and preview_import.get("destinationInstanceId") == copy_instance
            and preview_import.get("sourceIdentity")
            == (export_manifest or {}).get("sourceIdentity")
            and preview_import.get("archiveDigest") == exported.get("archiveDigest")
            and preview_import.get("archiveFileDigest")
            == exported.get("archiveFileDigest")
        )
        import_identity_ok = (
            isinstance(import_receipt, dict)
            and import_receipt.get("status") == "applied"
            and import_receipt.get("sourceInstanceId") == instance_id
            and import_receipt.get("destinationInstanceId") == copy_instance
            and import_receipt.get("sourceIdentity")
            == (export_manifest or {}).get("sourceIdentity")
            and import_receipt.get("archiveDigest") == exported.get("archiveDigest")
            and import_receipt.get("archiveFileDigest")
            == exported.get("archiveFileDigest")
        )
        imported_instance = web.request("GET", f"/v1/instances/{copy_instance}")
        imported_snapshot = _study_state_snapshot(
            imported_instance.get("packageState") or {}
        )
        source_snapshot = _study_state_snapshot(upgraded_package)
        destination_state_ok = (
            imported_instance.get("version") == upgraded.get("version")
            and imported_instance.get("source") == upgraded.get("source")
            and imported_snapshot == source_snapshot
        )
        receipt.record("portable-import-roundtrip",
                        isinstance(imported, dict)
                        and imported.get("destinationMutated") is True
                        and preview_identity_ok
                        and import_identity_ok
                        and destination_state_ok,
                        destinationInstanceId=copy_instance,
                        importReceipt=(import_receipt or {}).get("receiptId"),
                        sourceStateDigest=_object_digest(source_snapshot),
                        destinationStateDigest=_object_digest(imported_snapshot),
                        result=imported if not isinstance(imported, dict) else {k: imported[k] for k in imported if k != "validation"})

        failed_steps = _required_step_failures(receipt.document)
        expect(not failed_steps, f"mandatory J2 steps failed: {failed_steps}")
        receipt.document["result"] = "passed"
    except Refusal as refusal:
        receipt.record("typed-refusal", False, code=refusal.code,
                       message=refusal.message, status=refusal.status)
        receipt.document["result"] = "failed"
    except SystemExit as exc:
        receipt.record("driver-error", False, error=f"SystemExit: {exc}")
        receipt.document["result"] = "failed"
    except Exception as exc:  # noqa: BLE001 - the receipt must carry the failure out
        receipt.record("driver-error", False, error=f"{type(exc).__name__}: {exc}")
        receipt.document["result"] = "failed"
    finally:
        if vm is not None:
            try:
                vm.teardown()
            except Exception as exc:  # noqa: BLE001 - teardown failure invalidates the journey
                receipt.record("teardown", False, error=f"{type(exc).__name__}: {exc}")
                receipt.document["result"] = "failed"
    receipt.write(args.receipt_out)
    log(f"result: {receipt.document['result']} -> {args.receipt_out}")
    return 0 if receipt.document["result"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
