/**
 * Model routes API (keep-up-loop.md "API"): the wire mapper for the documented
 * `stateport.models-projection/v1` projection, the suite-run record, and the
 * HTTP client.
 *
 * The fixtures below are the shapes the backend actually sends
 * (`docs/API_CONTRACT_WEB.md` §"Model routes"); the mapper must fail closed
 * when a shape does not match.
 */
import { describe, expect, it } from 'vitest'

import { agentRouteReadiness, catalogueScore, proposalSentence, scoreLabel } from '../../models'
import { ClientError } from '../../types'
import { HttpModelsClient } from '../domainsModels'
import { HttpRunsClient } from '../domainsExecution'
import { mapEvaluateResponse, mapModelsView, mapSuiteRun } from '../modelsWire'
import { HttpTransport } from '../transport'
import { jsonResponse, makeFakeFetch } from './helpers'

const TERMS = 'During the free period, data sent to this model may be used to improve it.'
const TERMS_SHA = `sha256:${'f'.repeat(64)}`
const FREE = 'opencode/deepseek-v4.1-flash-free'
const OTHER_FREE = 'opencode/beam-free'

function viewPayload(overrides: Record<string, unknown> = {}) {
  return {
    formatVersion: 'stateport.models-projection/v1',
    status: {
      state: 'ready',
      detail: 'A consented free-model route and the pinned OpenCode executable are present.',
      harness: { id: 'opencode', present: true, version: '1.18.31' },
      readyClasses: ['agent.edit-state'],
    },
    consent: {
      destination: 'opencode-free',
      state: 'granted',
      grantedAt: '2026-10-21T08:30:00Z',
      grantedBy: 'owner',
      grantedTermsSha256: TERMS_SHA,
      terms: { provider: 'OpenCode Zen', url: 'https://opencode.ai/docs/zen', text: TERMS, sha256: TERMS_SHA },
    },
    catalogue: {
      observedAt: '2026-10-21T08:00:00Z',
      observations: 3,
      harness: { id: 'opencode', version: '1.18.31' },
      lastError: null,
      availabilityWindowSeconds: 604800,
      cache: null,
      models: [
        {
          id: FREE, free: true, destination: 'opencode-free', listedNow: true, usable: true,
          firstSeenAt: '2026-10-20T08:00:00Z', lastSeenAt: '2026-10-21T08:00:00Z', seenCount: 3,
          lastProbe: { status: 'ok', cause: null, at: '2026-10-21T08:00:05Z', seconds: 1.2, sandboxStatus: 'ok', refusal: null },
          latestResult: {
            runId: 'run-1', finishedAt: '2026-10-21T09:00:00Z', state: 'completed',
            available: true, complete: true, passed: 2, total: 4, medianSeconds: 63,
            suiteDigest: 'sha256:suite', current: true,
          },
        },
        {
          id: OTHER_FREE, free: true, destination: 'opencode-free', listedNow: false, usable: false,
          firstSeenAt: '2026-10-19T08:00:00Z', lastSeenAt: '2026-10-19T08:00:00Z', seenCount: 1,
          lastProbe: null, latestResult: null,
        },
      ],
    },
    alarms: [{ code: 'harness_misconfigured', model: null, at: '2026-10-21T08:00:00Z', detail: 'bwrap refused' }],
    routes: [
      {
        actionClass: 'agent.edit-state', model: FREE, pinned: true, setBy: 'owner',
        setAt: '2026-10-21T08:30:00Z', why: 'owner choice', ageSeconds: 600,
        score: { passed: 2, total: 4, medianSeconds: 63, runId: 'run-1', finishedAt: '2026-10-21T09:00:00Z', timeouts: 0 },
        usable: true, refusal: null,
      },
      {
        actionClass: 'chat', model: null, pinned: false, setBy: null, setAt: null, why: 'safe default',
        ageSeconds: null, score: null, usable: null,
        refusal: { code: 'route_not_configured', message: 'No model is chosen for chat yet.' },
      },
    ],
    lease: {
      enabled: true, state: 'active', grantedAt: '2026-10-21T08:00:00Z', expiresAt: '2999-11-20T08:00:00Z',
      maxSuiteRunsPerDay: 1, runsToday: 0, maxDays: 30, defaultDays: 30,
    },
    suite: {
      valid: true, id: 'model-suite', version: 'v1', digest: 'sha256:suite',
      taskCount: 4, taskTimeoutSeconds: 180,
      tasks: [{ id: 'plain-typo', title: 'Fix a typo', critical: true }],
    },
    evaluation: { activeRunId: null, maxModels: 3, lastRunId: 'run-1' },
    proposal: {
      id: 'proposal-abc', actionClass: 'agent.edit-state', from: FREE, to: OTHER_FREE,
      reason: 'Passes one more practice task.', why: 'the candidate passed more tasks',
      candidate: { passed: 3, total: 4, medianSeconds: 41, runId: 'run-2', finishedAt: '2026-10-21T10:00:00Z', timeouts: 0 },
      incumbent: { passed: 2, total: 4, medianSeconds: 63, runId: 'run-1', finishedAt: '2026-10-21T09:00:00Z', timeouts: 0 },
      suiteDigest: 'sha256:suite', createdAt: '2026-10-21T10:05:00Z', status: 'pending',
      summary: `Switch to ${OTHER_FREE}: 3/4 vs 2/4, 41 s vs 63 s`,
    },
    proposals: [],
    schedule: { running: true, intervalSeconds: 86400, nextTickAt: '2026-10-22T08:00:00Z' },
    receipts: [
      { receiptId: 'receipt-2', sequence: 2, type: 'route.changed', at: '2026-10-21T08:30:00Z', by: 'owner', from: null, to: FREE, why: 'owner choice' },
      { receiptId: 'receipt-1', sequence: 1, type: 'consent.granted', at: '2026-10-21T08:00:00Z', by: 'owner' },
    ],
    scoresNote: "Scores come from StatePort's practice tasks, not from your work.",
    ...overrides,
  }
}

describe('mapModelsView', () => {
  it('maps the documented projection onto the domain view', () => {
    const view = mapModelsView(viewPayload())
    expect(view.status).toMatchObject({ state: 'ready', readyClasses: ['agent.edit-state'] })
    expect(view.consent).toMatchObject({ destination: 'opencode-free', state: 'granted', grantedBy: 'owner' })
    expect(view.consent.terms.text).toBe(TERMS)
    expect(view.consent.terms.sha256).toBe(TERMS_SHA)
    expect(view.routes).toHaveLength(2)
    expect(view.routes[0]).toMatchObject({ actionClass: 'agent.edit-state', model: FREE, pinned: true, usable: true, ageSeconds: 600 })
    expect(view.routes[0].score).toMatchObject({ passed: 2, total: 4, medianSeconds: 63 })
    expect(view.routes[1]).toMatchObject({ actionClass: 'chat', model: null, pinned: false })
    expect(view.routes[1].refusal).toEqual({ code: 'route_not_configured', message: 'No model is chosen for chat yet.' })
    expect(view.catalogue.models.map((model) => [model.id, model.free, model.usable, model.listedNow])).toEqual([
      [FREE, true, true, true],
      [OTHER_FREE, true, false, false],
    ])
    expect(view.catalogue.models[0].lastProbe).toMatchObject({ status: 'ok', seconds: 1.2 })
    expect(catalogueScore(view.catalogue.models[0].latestResult)).toMatchObject({ passed: 2, total: 4 })
    expect(view.lease).toMatchObject({ enabled: true, state: 'active', defaultDays: 30 })
    expect(view.suite).toMatchObject({ valid: true, id: 'model-suite', taskCount: 4 })
    expect(view.evaluation).toMatchObject({ maxModels: 3, lastRunId: 'run-1' })
    expect(view.schedule).toMatchObject({ running: true, intervalSeconds: 86400 })
    expect(view.scoresNote).toContain('practice tasks')
    expect(view.alarms).toHaveLength(1)
    expect(view.receipts.map((receipt) => receipt.type)).toEqual(['route.changed', 'consent.granted'])
    expect(view.receipts[0].summary).toBe('Route set to opencode/deepseek-v4.1-flash-free: owner choice')
    expect(view.receipts[1].summary).toBe('Free-model terms accepted.')
  })

  it('uses the service’s own proposal summary', () => {
    const view = mapModelsView(viewPayload())
    expect(view.proposal && proposalSentence(view.proposal)).toBe(`Switch to ${OTHER_FREE}: 3/4 vs 2/4, 41 s vs 63 s`)
  })

  it('reads the frozen suite version the service publishes as a number', () => {
    // The service sends the suite version as a whole number; the projection must
    // still map (and the Models page must still load) instead of failing closed.
    const view = mapModelsView(viewPayload({
      suite: { valid: true, id: 'model-suite', version: 1, digest: 'sha256:suite', taskCount: 4, taskTimeoutSeconds: 180, tasks: [] },
    }))
    expect(view.suite).toMatchObject({ valid: true, id: 'model-suite', version: '1' })
  })

  it('requires consent before a free route counts as ready', () => {
    const notConsented = mapModelsView(viewPayload({
      consent: { ...(viewPayload().consent as Record<string, unknown>), state: 'not_granted', grantedAt: null },
    }))
    expect(agentRouteReadiness(notConsented)).toMatchObject({ ready: false, code: 'route_not_consented' })
    const consented = mapModelsView(viewPayload())
    expect(agentRouteReadiness(consented)).toMatchObject({ ready: true, model: FREE, destination: 'opencode-free' })
  })

  it('reports the refusal the service gave for a route without a model', () => {
    const view = mapModelsView(viewPayload({
      routes: [{ actionClass: 'agent.edit-state', model: null, pinned: false, setBy: null, setAt: null, why: null, ageSeconds: null, score: null, usable: null, refusal: { code: 'no_measured_route', message: 'no measured free model is available' } }],
    }))
    expect(agentRouteReadiness(view)).toMatchObject({ ready: false, code: 'no_measured_route' })
  })

  it('reads a stale consent as stale, not as granted', () => {
    const view = mapModelsView(viewPayload({
      consent: { ...(viewPayload().consent as Record<string, unknown>), state: 'stale' },
    }))
    expect(view.consent.state).toBe('stale')
    expect(agentRouteReadiness(view).ready).toBe(false)
  })

  it('does not count an agent action as ready when the model program is missing', () => {
    const view = mapModelsView(viewPayload({
      status: {
        state: 'harness_unavailable',
        detail: 'The pinned OpenCode executable is not available.',
        harness: { id: 'opencode', present: false, version: null },
      },
    }))
    expect(agentRouteReadiness(view)).toMatchObject({ ready: false, code: 'harness_unavailable' })
  })

  it('fails closed on a projection that does not match the contract', () => {
    for (const payload of [
      'not an object',
      {},
      viewPayload({ formatVersion: 'stateport.models-projection/v2' }),
      viewPayload({ status: { state: 'maybe', detail: '', harness: { id: 'opencode', present: true, version: null } } }),
      viewPayload({ consent: { destination: 'opencode-free', state: 'granted' } }),
      viewPayload({ routes: { 'agent.edit-state': FREE } }),
      viewPayload({ lease: { enabled: true } }),
      viewPayload({ suite: { valid: false } }),
      viewPayload({ receipts: [{ receiptId: 'r', type: 'consent.granted' }] }),
    ]) {
      expect(() => mapModelsView(payload)).toThrow(ClientError)
    }
  })

  it('fails closed on a contradictory score', () => {
    const payload = viewPayload()
    const routes = payload.routes as Array<Record<string, unknown>>
    routes[0] = { ...routes[0], score: { passed: 5, total: 4, medianSeconds: 1, runId: 'r', finishedAt: '2026-10-21T09:00:00Z', timeouts: 0 } }
    expect(() => mapModelsView(payload)).toThrow(ClientError)
  })
})

describe('mapSuiteRun', () => {
  const runPayload = {
    formatVersion: 'stateport.model-suite-run/v1',
    runId: 'run-9',
    sequence: 3,
    state: 'running',
    trigger: 'owner',
    by: 'owner',
    createdAt: '2026-10-21T09:00:00Z',
    startedAt: '2026-10-21T09:00:01Z',
    finishedAt: null,
    suite: { id: 'model-suite', version: 'v1', digest: 'sha256:suite' },
    harness: { id: 'opencode', version: '1.18.31' },
    requestedModels: [FREE],
    retryModels: [],
    progress: { completedTasks: 1, totalTasks: 4, currentModel: FREE, currentTask: 'plain-typo' },
    models: [
      {
        model: FREE,
        probe: { status: 'ok', cause: null, at: '2026-10-21T09:00:02Z', seconds: 1, sandboxStatus: 'ok', refusal: null },
        available: true,
        complete: false,
        isRetry: false,
        timeouts: 0,
        totals: null,
        tasks: [
          { taskId: 'plain-typo', passed: true, seconds: 12, reason: null, status: 'checked', failure: null, sandboxStatus: 'ok', exitCode: 0, tokens: 10, egressDenied: 0, hardTimeout: false },
          { taskId: 'projectstate-add-risk', passed: null, seconds: null, reason: null, status: 'not_run', failure: null, sandboxStatus: null, exitCode: null, tokens: null, egressDenied: 0, hardTimeout: false },
        ],
      },
    ],
  }

  it('maps the documented run record and binds it to the requested run', () => {
    const run = mapSuiteRun(runPayload, 'run-9')
    expect(run).toMatchObject({
      runId: 'run-9',
      state: 'running',
      trigger: 'owner',
      requestedModels: [FREE],
      progress: { completedTasks: 1, totalTasks: 4, currentModel: FREE, currentTask: 'plain-typo' },
    })
    expect(run.models[0].tasks[0]).toMatchObject({ taskId: 'plain-typo', passed: true, seconds: 12, status: 'checked' })
    expect(run.models[0].tasks[1]).toMatchObject({ taskId: 'projectstate-add-risk', passed: null, status: 'not_run' })
    expect(() => mapSuiteRun(runPayload, 'run-other')).toThrow(ClientError)
    expect(() => mapSuiteRun({ ...runPayload, state: 'exploded' }, 'run-9')).toThrow(ClientError)
  })

  it('maps a completed run with its totals', () => {
    const run = mapSuiteRun({
      ...runPayload,
      state: 'completed',
      finishedAt: '2026-10-21T09:05:00Z',
      models: [{
        ...runPayload.models[0],
        complete: true,
        totals: { passed: 3, total: 4, medianSeconds: 41 },
      }],
    }, 'run-9')
    expect(run.state).toBe('completed')
    expect(run.models[0].totals).toMatchObject({ passed: 3, total: 4, medianSeconds: 41 })
    expect(scoreLabel(run.models[0].totals)).toBe('3/4 · median 41 s')
  })

  it('reads the evaluation start answer', () => {
    expect(mapEvaluateResponse({ runId: 'run-9', state: 'queued' })).toEqual({ runId: 'run-9' })
    expect(() => mapEvaluateResponse({})).toThrow(ClientError)
  })
})

describe('HttpModelsClient', () => {
  function clientFor(routes: Parameters<typeof makeFakeFetch>[0]) {
    const fake = makeFakeFetch(routes)
    return { fake, models: new HttpModelsClient(new HttpTransport({ fetchFn: fake.fetchFn })) }
  }

  it('reads the view and sends every mutation with its exact body and CSRF header', async () => {
    const { fake, models } = clientFor([
      ['GET', '/v1/models', jsonResponse({ ok: true, result: viewPayload() })],
      ['POST', '/v1/models/consent', jsonResponse({ ok: true, result: viewPayload() })],
      ['DELETE', '/v1/models/consent', jsonResponse({ ok: true, result: viewPayload() })],
      ['POST', '/v1/models/observe', jsonResponse({ ok: true, result: viewPayload() })],
      ['POST', '/v1/models/evaluate', jsonResponse({ ok: true, result: { runId: 'run-1', state: 'queued' } })],
      ['GET', '/v1/models/runs/run-1', jsonResponse({ ok: true, result: {
        formatVersion: 'stateport.model-suite-run/v1', runId: 'run-1', sequence: 1, state: 'queued',
        trigger: 'owner', by: 'owner', createdAt: '2026-10-21T09:00:00Z', startedAt: null, finishedAt: null,
        suite: { id: 's', version: 'v1', digest: 'sha256:s' }, harness: { id: 'opencode', version: '1' },
        requestedModels: [FREE], retryModels: [],
        progress: { completedTasks: 0, totalTasks: 4, currentModel: null, currentTask: null },
        models: [],
      } })],
      ['POST', '/v1/models/route', jsonResponse({ ok: true, result: viewPayload() })],
      ['POST', '/v1/models/lease', jsonResponse({ ok: true, result: viewPayload() })],
      ['POST', '/v1/models/proposal/proposal-abc', jsonResponse({ ok: true, result: viewPayload() })],
    ])
    expect((await models.getView()).routes[0].model).toBe(FREE)
    await models.grantConsent({ destination: 'opencode-free', termsSha256: TERMS_SHA })
    await models.withdrawConsent('opencode-free')
    await models.observe()
    expect(await models.evaluate([FREE, FREE])).toEqual({ runId: 'run-1' })
    expect((await models.getRun('run-1')).state).toBe('queued')
    await models.setRoute({ actionClass: 'agent.edit-state', model: FREE, pin: true })
    await models.setRoute({ actionClass: 'agent.edit-state', model: null, pin: false })
    await models.setLease({ enabled: true, days: 30 })
    await models.decideProposal('proposal-abc', 'switch')

    const body = (method: string, path: string) => fake.calls.find((call) => call.method === method && call.url.endsWith(path))
    expect(body('POST', '/v1/models/consent')?.body).toEqual({ destination: 'opencode-free', termsSha256: TERMS_SHA })
    expect(body('POST', '/v1/models/consent')?.headers['x-stateport-csrf']).toBe('test-csrf')
    expect(body('DELETE', '/v1/models/consent')?.body).toEqual({ destination: 'opencode-free' })
    expect(body('POST', '/v1/models/evaluate')?.body).toEqual({ models: [FREE] })
    expect(body('POST', '/v1/models/route')?.body).toEqual({ actionClass: 'agent.edit-state', model: FREE, pin: true })
    expect(body('POST', '/v1/models/lease')?.body).toEqual({ enabled: true, days: 30 })
    expect(body('POST', '/v1/models/proposal/proposal-abc')?.body).toEqual({ decision: 'switch' })
  })

  it('refuses an empty or oversized evaluation before any request', async () => {
    const { fake, models } = clientFor([])
    await expect(models.evaluate([])).rejects.toMatchObject({ kind: 'validation' })
    await expect(models.evaluate(['a', 'b', 'c', 'd'])).rejects.toMatchObject({ kind: 'validation' })
    expect(fake.callsTo('/v1/models/evaluate')).toHaveLength(0)
  })

  it('surfaces a refused mutation as the service error', async () => {
    const { models } = clientFor([
      ['POST', '/v1/models/consent', jsonResponse({ ok: false, error: { code: 'terms_mismatch', message: 'The terms digest does not match the current terms text.' } }, 409)],
    ])
    await expect(models.grantConsent({ destination: 'opencode-free', termsSha256: TERMS_SHA })).rejects.toMatchObject({
      code: 'terms_mismatch',
      message: 'The terms digest does not match the current terms text.',
    })
  })
})

describe('governed actions and applied file proposals (ADR-0007 fields)', () => {
  const DIGEST_A = `sha256:${'a'.repeat(64)}`
  const DIGEST_B = `sha256:${'b'.repeat(64)}`
  const action = (extra: Record<string, unknown>) => ({
    formatVersion: 'stateport.application-action/v1',
    actionId: 'projectstate.gate/v1',
    displayName: 'Check the gate',
    purpose: 'Run the ProjectState gate.',
    ...extra,
  })

  it('maps check and agent kinds and ignores unknown kinds', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/instances/ins_1/actions', jsonResponse({ actions: [
        action({ kind: 'check' }),
        action({ actionId: 'projectstate.next-action/v1', kind: 'agent', actionClass: 'agent.edit-state' }),
        action({ actionId: 'legacy/v1', kind: 'typed' }),
      ] })],
    ])
    const runs = new HttpRunsClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const [check, agent, legacy] = await runs.listActions('ins_1')
    expect(check.kind).toBe('check')
    expect(agent).toMatchObject({ kind: 'agent', actionClass: 'agent.edit-state' })
    expect(legacy.kind).toBeUndefined()
  })

  function appliedRun(proposalKind: 'files' | undefined) {
    const baseGit = 'c'.repeat(40)
    const finalGit = 'd'.repeat(40)
    const receiptId = 'governed-run.run_1.123456789abc'
    return {
      formatVersion: 'stateport.governed-action-run/v1',
      runId: 'run_1',
      instanceId: 'ins_1',
      applicationId: 'projectstate',
      actionId: 'projectstate.next-action/v1',
      engine: { engineId: 'opencode' },
      status: 'applied',
      lifecycleState: 'CLOSED',
      revision: 13,
      requestedAt: '2026-10-21T08:00:00Z',
      runSpecDigest: DIGEST_A,
      descriptorDigest: DIGEST_A,
      actionContractDigest: DIGEST_B,
      proposalDigest: DIGEST_B,
      proposal: { proposalId: 'proposal_1', ...(proposalKind ? { kind: proposalKind, patch: 'diff' } : {}) },
      proposalApproval: { approvalDigest: DIGEST_A },
      canonicalStateBefore: DIGEST_A,
      canonicalStateAfter: DIGEST_B,
      baseGit,
      appliedRunBundle: { formatVersion: 'stateport.run-bundle/v1', runId: 'run_1', contentDigest: DIGEST_A },
      postApplyValidation: { status: 'passed', commandDigest: DIGEST_B },
      receipt: { proposalId: 'proposal_1', postStateDigest: DIGEST_B, baseGit, finalGit },
      receiptId,
      closureReceipt: {
        formatVersion: 'stateport.governed-run-closure-receipt/v1',
        receiptId,
        receiptType: 'stateport.governed-run-closure-receipt/v1',
        action: 'governed_run.apply',
        status: 'applied',
        createdAt: '2026-10-21T08:05:00Z',
        sourceKind: 'governed_run',
        actor: 'system',
        applicationId: 'projectstate',
        instanceId: 'ins_1',
        runId: 'run_1',
        actionId: 'projectstate.next-action/v1',
        engineId: 'opencode',
        runSpecDigest: DIGEST_A,
        descriptorDigest: DIGEST_A,
        actionContractDigest: DIGEST_B,
        sourceIdentityDigest: DIGEST_A,
        proposalId: 'proposal_1',
        proposalDigest: DIGEST_B,
        proposalApprovalDigest: DIGEST_A,
        baseGit,
        finalGit,
        canonicalStateBefore: DIGEST_A,
        canonicalStateAfter: DIGEST_B,
        applicationReceiptDigest: DIGEST_A,
        appliedRunBundleDigest: DIGEST_A,
        validation: { state: 'validated', detail: 'Local validation passed.' },
        postApplyValidation: { status: 'passed', commandDigest: DIGEST_B },
        claimState: { applied: true, locallyValidated: true, humanAccepted: false, remotelyAccepted: false },
        summary: 'Applied.',
        beforeSummary: 'Before.',
        afterSummary: 'After.',
      },
    }
  }

  it('accepts a new commit as the final revision only for an applied file proposal', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/instances/ins_1/execution/history', jsonResponse({ runs: [appliedRun('files')] })],
      ['GET', '/v1/instances/ins_2/execution/history', jsonResponse({ runs: [{ ...appliedRun(undefined), instanceId: 'ins_2', closureReceipt: { ...appliedRun(undefined).closureReceipt, instanceId: 'ins_2' } }] })],
    ])
    const runs = new HttpRunsClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const [run] = await runs.getHistory('ins_1')
    expect(run.status).toBe('applied')
    expect(run.receipt?.finalGit).toBe('d'.repeat(40))
    await expect(runs.getHistory('ins_2')).rejects.toMatchObject({ kind: 'validation' })
  })
})

describe('practice-suite run: why a model did not answer', () => {
  it('carries the probe cause, so the page can say the free usage limit was reached', () => {
    const run = mapSuiteRun({
      runId: 'run-1', state: 'completed', error: 'free_usage_limit', createdAt: null, startedAt: null, finishedAt: null,
      requestedModels: ['opencode/a-free'],
      progress: { completedTasks: 4, totalTasks: 4 },
      models: [{ model: 'opencode/a-free', probe: { status: 'unavailable', cause: 'free_usage_limit' }, available: false,
        complete: false, isRetry: false, tasks: [] }],
    }, 'run-1')
    expect(run.models[0].probeCause).toBe('free_usage_limit')
    expect(run.error).toBe('free_usage_limit')
  })
})
