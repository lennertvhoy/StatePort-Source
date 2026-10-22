import { describe, expect, it } from 'vitest'

import { appliedOutcomeOf, checkVerdictOf, fileProposalOf, mapEvaluatorResult, runFailureReason } from '../proposals'
import type { RunRecord } from '../types'

function run(overrides: Partial<RunRecord>): RunRecord {
  return {
    id: 'run_1',
    instanceId: 'ins_1',
    actionId: 'projectstate.next-action/v1',
    engineId: 'opencode',
    state: 'proposed',
    status: 'state_change_proposed',
    revision: 4,
    inputs: {},
    createdAt: '2026-10-21T08:00:00Z',
    updatedAt: '2026-10-21T08:01:00Z',
    ...overrides,
  }
}

describe('evaluator verdicts', () => {
  it('normalises verdict spellings and findings, and refuses unknown verdicts', () => {
    expect(mapEvaluatorResult({ verdict: 'passed', summary: 'Gate is green.' })).toEqual({ verdict: 'passed', summary: 'Gate is green.', findings: [] })
    expect(mapEvaluatorResult({
      verdict: 'not-yet',
      reason: 'Two checks fail.',
      findings: ['STATE.yaml: next_action is empty', { path: 'PROJECT.md', message: 'Outcome missing', severity: 'high' }, { text: '' }],
    })).toEqual({
      verdict: 'not_yet',
      summary: 'Two checks fail.',
      findings: [
        { message: 'STATE.yaml: next_action is empty', path: null, severity: null },
        { message: 'Outcome missing', path: 'PROJECT.md', severity: 'high' },
      ],
    })
    expect(mapEvaluatorResult({ verdict: 'looks good to me' })).toBeNull()
    expect(mapEvaluatorResult('passed')).toBeNull()
  })

  it('reads a check verdict from the recorded run result only', () => {
    expect(checkVerdictOf(run({ result: { evaluator: { verdict: 'invalid', summary: 'STATE.yaml does not parse.' } } }))?.verdict).toBe('invalid')
    expect(checkVerdictOf(run({ result: { verdict: 'passed', summary: 'ok' } }))?.verdict).toBe('passed')
    expect(checkVerdictOf(run({ result: { canonicalStateUnchanged: true } }))).toBeNull()
    expect(checkVerdictOf(run({}))).toBeNull()
  })

  it('names the recorded failure reason', () => {
    expect(runFailureReason(run({ status: 'failed', result: { diagnostic: 'sandbox_unavailable: bubblewrap is missing' } }))).toBe('sandbox_unavailable: bubblewrap is missing')
    expect(runFailureReason(run({ status: 'failed', events: [{ type: 'state_transition', reason: 'route_not_consented' }] }))).toBe('route_not_consented')
  })
})

describe('file proposals', () => {
  const proposal = {
    kind: 'files',
    proposalId: 'proposal_1',
    baseGit: 'c'.repeat(40),
    patch: 'diff --git a/STATE.yaml b/STATE.yaml\n',
    files: [{ path: 'STATE.yaml', change: 'modified', additions: 2, deletions: 1 }, 'notes/new.md'],
    evaluator: { before: { verdict: 'not_yet', summary: 'next_action empty' }, after: { verdict: 'passed' } },
    producer: { kind: 'agent', engine: 'opencode', route: { harness: 'opencode', model: 'opencode/deepseek-v4.1-flash-free' } },
    summary: 'Filled in the next action.',
  }

  it('maps a files proposal and leaves semantic proposals to the existing view', () => {
    const view = fileProposalOf(run({ proposal }))
    expect(view).toMatchObject({
      proposalId: 'proposal_1',
      baseCommit: 'c'.repeat(40),
      agentSummary: 'Filled in the next action.',
      route: { model: 'opencode/deepseek-v4.1-flash-free', harness: 'opencode' },
      evaluatorBefore: { verdict: 'not_yet' },
      evaluatorAfter: { verdict: 'passed' },
    })
    expect(view?.files).toEqual([
      { path: 'STATE.yaml', oldPath: null, change: 'modified', additions: 2, deletions: 1, binary: false },
      { path: 'notes/new.md', oldPath: null, change: 'modified', additions: null, deletions: null, binary: false },
    ])
    expect(fileProposalOf(run({ proposal: { operations: [{ operation: 'replace' }] } }))).toBeNull()
  })

  it('reads the route and duration the agent recorded with the proposal', () => {
    const view = fileProposalOf(run({
      proposal,
      result: { agent: { route: { harness: 'opencode', model: 'opencode/beam-free' }, durationSeconds: 41.4, finalText: 'Filled in the next action.' } },
    }))
    expect(view?.route?.model).toBe('opencode/beam-free')
    expect(view?.durationSeconds).toBe(41.4)
  })
  it('falls back to the result engine identity and latency', () => {
    const view = fileProposalOf(run({
      proposal: { kind: 'files', patch: '' },
      result: { engineIdentity: { id: 'opencode', model: 'opencode/beam-free' }, latencyMs: 63000 },
    }))
    expect(view?.route?.model).toBe('opencode/beam-free')
    expect(view?.durationSeconds).toBe(63)
  })

  it('reads the commit and the evaluator re-run from the apply receipt', () => {
    const applied = run({
      status: 'applied',
      proposal,
      receiptId: 'governed-run.run_1.123456789abc',
      receipt: {
        commit: { sha: 'd'.repeat(40), parent: 'c'.repeat(40), tree: 'e'.repeat(40), author: 'StatePort', message: 'x', paths: ['STATE.yaml'] },
        evaluator: { after: { verdict: 'passed', summary: 'Gate is green.' } },
        validation: { state: 'validated', detail: 'Local validation passed.' },
      },
    })
    expect(appliedOutcomeOf(applied)).toEqual({
      commit: 'd'.repeat(40),
      evaluator: { verdict: 'passed', summary: 'Gate is green.', findings: [] },
      validation: { state: 'validated', detail: 'Local validation passed.' },
      receiptId: 'governed-run.run_1.123456789abc',
    })
    expect(appliedOutcomeOf(run({ proposal }))).toBeNull()
    expect(appliedOutcomeOf(run({ status: 'applied', receipt: { finalGit: 'not a sha' } }))?.commit).toBeNull()
  })

  it('says so when no post-apply validation was recorded', () => {
    const applied = run({ status: 'applied', proposal, receipt: { commit: { sha: 'd'.repeat(40) } } })
    expect(appliedOutcomeOf(applied)?.validation).toBeNull()
    expect(appliedOutcomeOf(applied)?.evaluator).toBeNull()
  })
})
