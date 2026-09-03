import { describe, expect, it } from 'vitest'

import { HttpOrchestrationClient } from '../domainsExecution'
import { HttpTransport } from '../transport'
import { jsonResponse, makeFakeFetch } from './helpers'

const BASE_COMMIT = '1'.repeat(40)
const BASE_TREE = '2'.repeat(40)
const PLAN_DIGEST = `sha256:${'a'.repeat(64)}`
const RESULT_DIGEST = `sha256:${'b'.repeat(64)}`
const REVIEW_DIGEST = `sha256:${'c'.repeat(64)}`
const APPLICATION_ID = 'stateport.development-reference'

function projection(
  state: string,
  revision: number,
  extra: Record<string, unknown> = {},
) {
  return {
    formatVersion: 'stateport.goal-execution-view/v1',
    instanceId: 'ins_1',
    ...(state === 'not_prepared' ? {} : { applicationId: APPLICATION_ID }),
    state,
    mode: 'assisted',
    revision,
    recordedAt: `2026-07-18T12:00:0${Math.min(revision, 9)}Z`,
    currentIdentity: {
      baseCommit: BASE_COMMIT,
      baseTree: BASE_TREE,
      repositoryClean: true,
    },
    ...extra,
  }
}

describe('HttpOrchestrationClient — exact goal-execution transitions', () => {
  it('advertises only the review and lifecycle transitions the service implements', () => {
    const client = new HttpOrchestrationClient(new HttpTransport({ fetchFn: makeFakeFetch([]).fetchFn }))

    expect(client.canStop).toBe(false)
    expect(client.canRejectReview).toBe(false)
  })

  it('binds every transition to the current revision and digest identities', async () => {
    let current = projection('not_prepared', 0)
    const slice = {
      planId: 'plan_1',
      baseCommit: BASE_COMMIT,
      baseTree: BASE_TREE,
      requiredPermissions: ['repo.read'],
      maximumBudget: { token: 0, costMinor: 0, timeSeconds: 60, steps: 1 },
      networkPolicy: 'disabled',
      planDigest: PLAN_DIGEST,
    }
    const selectedItem = {
      objective: 'Inspect the exact public-safe project snapshot.',
      scope: ['README.md'],
      requiredPermissions: ['repo.read'],
    }
    const delegation = {
      implementerActor: 'stateport-bounded-inspector',
      reviewerActor: 'stateport-independent-reviewer',
      readScope: ['README.md'],
      writeScope: ['state/reports'],
    }
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/instances/ins_1/goal-execution',
        () => jsonResponse({ ok: true, result: current }),
      ],
      [
        'POST',
        '/v1/instances/ins_1/goal-execution/prepare',
        () => {
          current = projection('proposal_ready', 1, { slice, selectedItem, delegation })
          return jsonResponse({ ok: true, result: current })
        },
      ],
      [
        'POST',
        '/v1/instances/ins_1/goal-execution/approve',
        () => {
          current = projection('approved', 2, { slice, selectedItem, delegation })
          return jsonResponse({ ok: true, result: current })
        },
      ],
      [
        'POST',
        '/v1/instances/ins_1/goal-execution/execute',
        () => {
          current = projection('awaiting_independent_review', 3, {
            slice,
            selectedItem,
            delegation,
            executionResult: {
              executionResultDigest: RESULT_DIGEST,
              usedBudget: { token: 0, costMinor: 0, timeSeconds: 1, steps: 1 },
              testsPassed: true,
              repositoryClean: true,
            },
          })
          return jsonResponse({ ok: true, result: current })
        },
      ],
      [
        'POST',
        '/v1/instances/ins_1/goal-execution/review',
        () => {
          current = projection('independently_reviewed', 4, {
            slice,
            selectedItem,
            delegation,
            executionResult: { executionResultDigest: RESULT_DIGEST },
            review: {
              reviewDigest: REVIEW_DIGEST,
              disposition: 'accepted',
              reviewerActor: 'stateport-independent-reviewer',
            },
          })
          return jsonResponse({ ok: true, result: current })
        },
      ],
      [
        'POST',
        '/v1/instances/ins_1/goal-execution/close',
        () => {
          current = projection('closed', 5, {
            slice,
            selectedItem,
            delegation,
            review: { reviewDigest: REVIEW_DIGEST, disposition: 'accepted' },
            receipt: {
              formatVersion: 'stateport.goal-execution-receipt/v1',
              receiptId: 'goal-receipt-1',
              applicationId: 'stateport.development-reference',
              instanceId: 'ins_1',
              canonicalStateEffect: 'none',
            },
          })
          return jsonResponse({ ok: true, result: current })
        },
      ],
    ])
    const client = new HttpOrchestrationClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    expect(await client.getCurrent('ins_1')).toBeNull()
    const prepared = await client.prepareSlice('ins_1', {
      objective: 'Inspect README.md without changing canonical state.',
      mode: 'assisted',
    })
    expect(prepared).toMatchObject({
      stage: 'review_base',
      baseIdentity: { revision: BASE_COMMIT, clean: true },
      permissions: ['repo.read'],
      budget: { maxOperations: 1, maxMinutes: 1 },
    })
    expect(fake.callsTo('/goal-execution/prepare').at(-1)?.body).toEqual({
      expectedInstanceId: 'ins_1',
      expectedRevision: 0,
      expectedBaseCommit: BASE_COMMIT,
      mode: 'assisted',
      intent: 'Inspect README.md without changing canonical state.',
    })

    const approved = await client.approve(prepared.id)
    expect(approved.stage).toBe('run')
    expect(fake.callsTo('/goal-execution/approve').at(-1)?.body).toEqual({
      expectedInstanceId: 'ins_1',
      expectedRevision: 1,
      expectedPlanDigest: PLAN_DIGEST,
    })

    const events = []
    for await (const event of client.run(approved.id)) events.push(event)
    expect(events).toEqual([
      { type: 'state', planId: approved.id, state: 'running' },
      { type: 'state', planId: approved.id, state: 'completed_without_change' },
    ])
    expect(fake.callsTo('/goal-execution/execute').at(-1)?.body).toEqual({
      expectedInstanceId: 'ins_1',
      expectedRevision: 2,
      expectedPlanDigest: PLAN_DIGEST,
    })

    const reviewed = await client.submitReview(approved.id, { accepted: true })
    expect(reviewed.stage).toBe('close')
    expect(reviewed.state).toBe('validated')
    expect(reviewed.state).not.toBe('human_accepted')
    expect(reviewed.state).not.toBe('applied')
    expect(fake.callsTo('/goal-execution/review').at(-1)?.body).toEqual({
      expectedInstanceId: 'ins_1',
      expectedRevision: 3,
      expectedExecutionResultDigest: RESULT_DIGEST,
    })

    const closed = await client.close(approved.id)
    expect(closed.session).toMatchObject({
      stage: 'receipt',
      state: 'validated',
      receiptId: 'goal-receipt-1',
    })
    expect(closed.session.state).not.toBe('human_accepted')
    expect(closed.session.state).not.toBe('applied')
    expect(closed.receipt).toMatchObject({
      id: 'goal-receipt-1',
      result: 'completed_without_change',
      eventKind: 'goal_execution.closed',
    })
    expect(fake.callsTo('/goal-execution/close').at(-1)?.body).toEqual({
      expectedInstanceId: 'ins_1',
      expectedRevision: 4,
      expectedReviewDigest: REVIEW_DIGEST,
    })
  })

  it('does not fabricate a backend rejection transition', async () => {
    const current = projection('awaiting_independent_review', 3, {
      slice: {
        baseCommit: BASE_COMMIT,
        baseTree: BASE_TREE,
        planDigest: PLAN_DIGEST,
      },
      executionResult: { executionResultDigest: RESULT_DIGEST },
    })
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/instances/ins_1/goal-execution',
        jsonResponse({ ok: true, result: current }),
      ],
    ])
    const client = new HttpOrchestrationClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const session = await client.getCurrent('ins_1')
    await expect(client.submitReview(session!.id, { accepted: false, notes: 'No.' })).rejects.toMatchObject({
      kind: 'unavailable',
    })
    expect(fake.callsTo('/goal-execution/review')).toHaveLength(0)
  })

  it('retains backend identity and typed availability through the view mapping', async () => {
    const unavailable = projection('not_prepared', 0, {
      backendId: null,
      providerExecution: false,
      canonicalStateEffect: 'none',
      backendAvailability: {
        status: 'unavailable',
        code: 'goal_backend_unavailable',
        message: 'Governed execution is unavailable: no execution backend is configured on this host.',
        nextAction: 'Wait for a StatePort release that configures a governed execution backend.',
      },
    })
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/instances/ins_1/goal-execution',
        jsonResponse({ ok: true, result: unavailable }),
      ],
    ])
    const client = new HttpOrchestrationClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    const view = await client.getView('ins_1')
    expect(view.session).toBeNull()
    expect(view.backendId).toBeNull()
    expect(view.providerExecution).toBe(false)
    expect(view.canonicalStateEffect).toBe('none')
    expect(view.backendAvailability).toMatchObject({
      status: 'unavailable',
      code: 'goal_backend_unavailable',
    })
    expect(view.backendAvailability?.message).toContain('no execution backend is configured')
    expect(view.backendAvailability?.nextAction).toBeTruthy()
  })

  it('labels a test-only synthetic backend without inflating it to provider execution', async () => {
    const synthetic = projection('proposal_ready', 1, {
      backendId: 'fake',
      providerExecution: false,
      canonicalStateEffect: 'none',
      backendAvailability: { status: 'available', backendId: 'fake', testOnly: true },
      slice: { planId: 'plan_1', planDigest: PLAN_DIGEST },
    })
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/instances/ins_1/goal-execution',
        jsonResponse({ ok: true, result: synthetic }),
      ],
    ])
    const client = new HttpOrchestrationClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    const view = await client.getView('ins_1')
    expect(view.backendId).toBe('fake')
    expect(view.providerExecution).toBe(false)
    expect(view.backendAvailability).toMatchObject({
      status: 'available',
      backendId: 'fake',
      testOnly: true,
    })
  })

  it('rejects a GET projection for a different instance instead of relabelling it', async () => {
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/instances/ins_1/goal-execution',
        jsonResponse({
          ...projection('not_prepared', 0),
          instanceId: 'ins_other',
        }),
      ],
    ])
    const client = new HttpOrchestrationClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    await expect(client.getCurrent('ins_1')).rejects.toMatchObject({
      kind: 'validation',
    })
  })

  it('rejects a goal-execution projection without the current format identity', async () => {
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/instances/ins_1/goal-execution',
        jsonResponse({
          ...projection('not_prepared', 0),
          formatVersion: 'stateport.goal-execution-view/v0',
        }),
      ],
    ])
    const client = new HttpOrchestrationClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    await expect(client.getCurrent('ins_1')).rejects.toMatchObject({
      kind: 'validation',
    })
  })

  it('rejects an application identity change across governed transitions', async () => {
    const slice = {
      planId: 'plan_1',
      baseCommit: BASE_COMMIT,
      baseTree: BASE_TREE,
      planDigest: PLAN_DIGEST,
    }
    let current = projection('not_prepared', 0)
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/instances/ins_1/goal-execution',
        () => jsonResponse({ ok: true, result: current }),
      ],
      [
        'POST',
        '/v1/instances/ins_1/goal-execution/prepare',
        () => {
          current = projection('proposal_ready', 1, { slice })
          return jsonResponse({ ok: true, result: current })
        },
      ],
      [
        'POST',
        '/v1/instances/ins_1/goal-execution/approve',
        jsonResponse({
          ...projection('approved', 2, { slice }),
          applicationId: 'stateport.other-application',
        }),
      ],
    ])
    const client = new HttpOrchestrationClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const prepared = await client.prepareSlice('ins_1', {
      objective: 'Inspect one bounded slice.',
      mode: 'assisted',
    })

    await expect(client.approve(prepared.id)).rejects.toMatchObject({
      kind: 'validation',
    })
  })
})
