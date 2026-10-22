/**
 * ADR-0007 action results, read from a governed run: the evaluator verdict of
 * a `check` action and the file proposal an `agent` action returns.
 *
 * These are the only places the web app reads the new run fields
 * (`result.evaluator`, `proposal.kind == "files"`, `proposal.patch`,
 * `proposal.evaluator.before/after`, the apply receipt's commit). The fields
 * arrive inside the run projection's untyped records, so each one is
 * validated here and anything unrecognised reads as "not recorded" rather
 * than as a pass.
 */
import { z } from 'zod'

import type { RunRecord } from './types'

export type EvaluatorVerdict = 'passed' | 'not_yet' | 'invalid'

export interface EvaluatorFinding {
  message: string
  path: string | null
  severity: string | null
}

export interface EvaluatorResult {
  verdict: EvaluatorVerdict
  summary: string | null
  findings: EvaluatorFinding[]
}

export type FileChangeKind = 'added' | 'modified' | 'deleted' | 'renamed'

/** A changed file as the proposal declares it (counts may be absent). */
export interface ProposedFileChange {
  path: string
  oldPath: string | null
  change: FileChangeKind
  additions: number | null
  deletions: number | null
  binary: boolean
}

export interface RouteUsed {
  model: string | null
  harness: string | null
  version: string | null
  label: string
}

export interface FileProposalView {
  proposalId: string | null
  baseCommit: string | null
  /** The exact unified diff (`git diff --binary` against the base). */
  patch: string
  /** Declared file list; empty when the service sent only the patch. */
  files: ProposedFileChange[]
  evaluatorBefore: EvaluatorResult | null
  evaluatorAfter: EvaluatorResult | null
  route: RouteUsed | null
  durationSeconds: number | null
  /** The agent's final text, bounded by the service. */
  agentSummary: string | null
}

export interface AppliedOutcome {
  /** The Git commit the apply created, from the apply receipt. */
  commit: string | null
  /** The evaluator re-run on the applied result, when one was recorded. */
  evaluator: EvaluatorResult | null
  /** The post-apply validation StatePort ran locally. */
  validation: { state: string; detail: string } | null
  receiptId: string | null
}

// ─────────────────────────────────────────────────────────────────────────────

const VERDICTS: Record<string, EvaluatorVerdict> = {
  passed: 'passed',
  pass: 'passed',
  not_yet: 'not_yet',
  'not-yet': 'not_yet',
  notyet: 'not_yet',
  notYet: 'not_yet',
  invalid: 'invalid',
}

const findingWire = z.union([
  z.string().min(1).transform((message) => ({ message, path: null, severity: null })),
  z
    .object({
      message: z.string().min(1).optional(),
      text: z.string().min(1).optional(),
      reason: z.string().min(1).optional(),
      path: z.string().min(1).nullish(),
      file: z.string().min(1).nullish(),
      severity: z.string().min(1).nullish(),
      level: z.string().min(1).nullish(),
    })
    .transform((finding) => ({
      message: finding.message ?? finding.text ?? finding.reason ?? '',
      path: finding.path ?? finding.file ?? null,
      severity: finding.severity ?? finding.level ?? null,
    })),
])

const verdictWire = z.object({
  verdict: z.string(),
  summary: z.string().nullish(),
  reason: z.string().nullish(),
  findings: z.array(z.unknown()).optional(),
})

function record(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined
}

function nonEmptyString(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value : null
}

function finiteNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null
}

/** `{verdict, summary|reason, findings}` → EvaluatorResult, or null when not a known verdict. */
export function mapEvaluatorResult(value: unknown): EvaluatorResult | null {
  const parsed = verdictWire.safeParse(value)
  if (!parsed.success) return null
  const verdict = VERDICTS[parsed.data.verdict]
  if (!verdict) return null
  return {
    verdict,
    summary: parsed.data.summary ?? parsed.data.reason ?? null,
    // A malformed finding is dropped; it never voids the verdict itself.
    findings: (parsed.data.findings ?? [])
      .map((entry) => findingWire.safeParse(entry))
      .flatMap((finding) => (finding.success && finding.data.message ? [finding.data] : [])),
  }
}

/** The verdict a `check` run recorded in its result, if any. */
export function checkVerdictOf(run: RunRecord): EvaluatorResult | null {
  const result = run.result
  if (!result) return null
  for (const candidate of [result.evaluation, result.evaluator, result.verdict, result]) {
    const mapped = mapEvaluatorResult(candidate)
    if (mapped) return mapped
  }
  return null
}

const CHANGE_KINDS: Record<string, FileChangeKind> = {
  added: 'added',
  add: 'added',
  A: 'added',
  new: 'added',
  modified: 'modified',
  modify: 'modified',
  M: 'modified',
  changed: 'modified',
  deleted: 'deleted',
  delete: 'deleted',
  removed: 'deleted',
  D: 'deleted',
  renamed: 'renamed',
  rename: 'renamed',
  R: 'renamed',
}

const fileWire = z.object({
  path: z.string().min(1),
  oldPath: z.string().min(1).nullish(),
  from: z.string().min(1).nullish(),
  change: z.string().optional(),
  status: z.string().optional(),
  additions: z.number().int().nonnegative().nullish(),
  deletions: z.number().int().nonnegative().nullish(),
  added: z.number().int().nonnegative().nullish(),
  removed: z.number().int().nonnegative().nullish(),
  binary: z.boolean().optional(),
})

function mapFiles(value: unknown): ProposedFileChange[] {
  if (!Array.isArray(value)) return []
  const files: ProposedFileChange[] = []
  for (const entry of value) {
    const parsed = typeof entry === 'string' ? fileWire.safeParse({ path: entry }) : fileWire.safeParse(entry)
    if (!parsed.success) continue
    const wire = parsed.data
    files.push({
      path: wire.path,
      oldPath: wire.oldPath ?? wire.from ?? null,
      change: CHANGE_KINDS[wire.change ?? wire.status ?? ''] ?? 'modified',
      additions: wire.additions ?? wire.added ?? null,
      deletions: wire.deletions ?? wire.removed ?? null,
      binary: wire.binary ?? false,
    })
  }
  return files
}

function mapRouteUsed(...candidates: unknown[]): RouteUsed | null {
  for (const candidate of candidates) {
    const asText = nonEmptyString(candidate)
    if (asText) return { model: asText, harness: null, version: null, label: asText }
    const value = record(candidate)
    if (!value) continue
    const model = nonEmptyString(value.model)
    const harness = nonEmptyString(value.harness)
    const version = nonEmptyString(value.version) ?? nonEmptyString(value.harnessVersion)
    if (!model && !harness) continue
    const via = harness ? ` via ${harness}${version ? ` ${version}` : ''}` : ''
    return { model, harness, version, label: `${model ?? 'unknown model'}${via}` }
  }
  return null
}

/**
 * The file proposal of an agent run, or null for any other proposal kind (e.g.
 * the study sample).
 *
 * The agent's own evidence travels with the run: the proposal's `producer`
 * names the route (`{harness, model, …}`) and the run result carries the
 * agent's duration and final text.
 */
export function fileProposalOf(run: RunRecord): FileProposalView | null {
  const proposal = run.proposal
  if (!proposal || proposal.kind !== 'files') return null
  const patch = typeof proposal.patch === 'string' ? proposal.patch : ''
  const evaluator = record(proposal.evaluator)
  const result = run.result ?? {}
  const agent = record(result.agent) ?? {}
  const producer = record(proposal.producer) ?? {}
  const latencyMs = finiteNumber(result.latencyMs)
  return {
    proposalId: nonEmptyString(proposal.proposalId) ?? nonEmptyString(proposal.id),
    baseCommit: nonEmptyString(proposal.baseCommit) ?? nonEmptyString(proposal.baseGit) ?? nonEmptyString(proposal.base),
    patch,
    files: mapFiles(proposal.files),
    evaluatorBefore: mapEvaluatorResult(evaluator?.before),
    evaluatorAfter: mapEvaluatorResult(evaluator?.after),
    route: mapRouteUsed(agent.route, producer.route, proposal.route, result.route, record(result.engineIdentity)),
    durationSeconds:
      finiteNumber(proposal.durationSeconds)
      ?? finiteNumber(agent.durationSeconds)
      ?? finiteNumber(result.durationSeconds)
      ?? (latencyMs === null ? null : latencyMs / 1000),
    agentSummary: nonEmptyString(proposal.summary) ?? nonEmptyString(agent.finalText) ?? nonEmptyString(result.summary),
  }
}

const GIT_REVISION = /^[0-9a-f]{7,64}$/

/**
 * The commit and the evidence of an applied file proposal.
 *
 * The apply receipt carries the commit as `{sha, parent, tree, author,
 * message, paths}` (a file proposal is applied as a Git commit); older
 * receipts carry only `finalGit`. The evaluator re-run is read from wherever
 * the run recorded it; when nothing was recorded the UI says so instead of
 * implying a check ran.
 */
export function appliedOutcomeOf(run: RunRecord): AppliedOutcome | null {
  if (run.status !== 'applied') return null
  const receipt = record(run.receipt)
  const closure = record(run.closureReceipt)
  const validation = record(run.postApplyValidation)
  const commitRecord = record(receipt?.commit)
  const commitCandidates = [
    commitRecord?.sha,
    receipt?.commit,
    receipt?.finalGit,
    closure?.finalGit,
  ]
  const commit = commitCandidates
    .map((value) => (typeof value === 'string' ? value : null))
    .find((value) => value !== null && GIT_REVISION.test(value)) ?? null
  const evaluatorCandidates = [
    record(receipt?.evaluator)?.after,
    receipt?.evaluatorAfter,
    validation?.evaluator,
    record(closure?.postApplyValidation)?.evaluator,
    record(closure?.evaluator)?.after,
  ]
  const evaluator = evaluatorCandidates.map(mapEvaluatorResult).find((value) => value !== null) ?? null
  const validationRecord = record(receipt?.validation) ?? record(closure?.validation)
  const validationState = nonEmptyString(validationRecord?.state)
    ?? (validation?.status === 'passed' ? 'validated' : nonEmptyString(validation?.status))
  const validationDetail = nonEmptyString(validationRecord?.detail)
    ?? (validation?.status === 'passed'
      ? 'StatePort ran its post-apply validation locally. Human acceptance is not recorded.'
      : null)
  return {
    commit,
    evaluator,
    validation: validationState ? { state: validationState, detail: validationDetail ?? '' } : null,
    receiptId: run.receiptId ?? null,
  }
}

/** A short, plain reason a run did not finish, from the fields the service records. */
export function runFailureReason(run: RunRecord): string | null {
  const result = run.result ?? {}
  const gate = run.executionGate ?? {}
  return (
    nonEmptyString(result.diagnostic)
    ?? nonEmptyString(result.error)
    ?? nonEmptyString(record(result.refusal)?.reason)
    ?? nonEmptyString(result.refusal)
    ?? nonEmptyString(gate.reason)
    ?? [...(run.events ?? [])].reverse().map((event) => nonEmptyString(event.reason)).find((value) => value !== null)
    ?? null
  )
}
