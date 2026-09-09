/**
 * Operation Center derivation tests: run-backed operations expose the
 * backend's idempotent cancel transition; infrastructure plans fail closed.
 */
import { describe, expect, it, vi } from 'vitest'

import { ClientError } from '../../types'
import type { RunRecord } from '../../types'
import type { InfrastructureClient, RunsClient } from '../../client'
import { HttpTransport } from '../transport'
import { HttpOperationsClient } from '../domainsCore'
import { jsonResponse, makeFakeFetch } from './helpers'

const RUN: RunRecord = {
  id: 'run_1',
  instanceId: 'ins_1',
  actionId: 'act_validate',
  engineId: 'eng_local',
  state: 'awaiting_approval',
  inputs: {},
  revision: 3,
  createdAt: '2026-07-04T08:00:00.000Z',
  updatedAt: '2026-07-04T08:00:00.000Z',
}

function makeOperations(runList: RunRecord[], transitionResult?: RunRecord) {
  const calls: { runId: string; operation: string; input: unknown }[] = []
  const fake = makeFakeFetch([
    ['GET', '/v1/operations', jsonResponse({ formatVersion: 'stateport.operations/v1',
      runs: runList.map((run) => ({ id: run.id, instanceId: run.instanceId, actionId: run.actionId,
        engineId: run.engineId, state: run.state, revision: run.revision, createdAt: run.createdAt, updatedAt: run.updatedAt })), infrastructureInstanceIds: [] })],
  ])
  const runs: Pick<RunsClient, 'getHistory' | 'transition'> = {
    getHistory: vi.fn(async () => runList),
    transition: async (runId, operation, input) => {
      calls.push({ runId, operation, input })
      return transitionResult ?? { ...RUN, state: 'cancelled', revision: RUN.revision + 1 }
    },
  }
  const infrastructure: Pick<InfrastructureClient, 'getTarget' | 'listPlans'> = {
    getTarget: async () => {
      throw new ClientError('unavailable', 'no infrastructure target')
    },
    listPlans: async () => [],
  }
  const operations = new HttpOperationsClient(new HttpTransport({ fetchFn: fake.fetchFn }), runs, infrastructure)
  return { operations, calls, runs }
}

describe('HttpOperationsClient — run cancel', () => {
  it('marks run-backed operations in cancellable states as cancellable', async () => {
    const { operations, runs } = makeOperations([RUN])
    const [record] = await operations.list()
    expect(record.kind).toBe('orchestration_run')
    expect(record.canCancel).toBe(true)
    expect(record.canPause).toBe(false)
    expect(runs.getHistory).not.toHaveBeenCalled()
  })

  it('does not offer cancel for terminal run states', async () => {
    const { operations } = makeOperations([{ ...RUN, state: 'validated' }])
    const [record] = await operations.list()
    expect(record.canCancel).toBe(false)
  })

  it('cancels through the run transition with exact identities', async () => {
    const { operations, calls } = makeOperations([RUN])
    const updated = await operations.cancel('op_run_1')
    expect(calls).toEqual([
      {
        runId: 'run_1',
        operation: 'cancel',
        input: { expectedInstanceId: 'ins_1', expectedRevision: 3 },
      },
    ])
    expect(updated.state).toBe('cancelled')
    expect(updated.canCancel).toBe(false)
  })

  it('refuses to cancel a run in a non-cancellable state', async () => {
    const { operations } = makeOperations([{ ...RUN, state: 'applied' }])
    const err = await operations.cancel('op_run_1').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ClientError)
  })
})


describe('fresh operation index', () => {
  it('observes new runs on the next read and surfaces server failures', async () => {
    let payload: unknown = { formatVersion: 'stateport.operations/v1', runs: [], infrastructureInstanceIds: [] }
    let failed = false
    const fetchFn = vi.fn(async () => failed ? jsonResponse({ error: 'unavailable' }, 503) : jsonResponse(payload))
    const infrastructure = { getTarget: vi.fn(), listPlans: vi.fn() }
    const runs = { getHistory: vi.fn(), transition: vi.fn() }
    const operations = new HttpOperationsClient(new HttpTransport({ fetchFn }), runs, infrastructure)
    expect(await operations.list()).toEqual([])
    payload = { formatVersion: 'stateport.operations/v1', runs: [{ runId: 'new-run', instanceId: 'new-app',
      actionId: 'validate', engineId: 'local', revision: 0, status: 'running', requestedAt: RUN.createdAt }],
      infrastructureInstanceIds: [] }
    expect((await operations.list())[0]).toMatchObject({ id: 'op_new-run', instanceId: 'new-app', state: 'running' })
    failed = true
    await expect(operations.list()).rejects.toBeInstanceOf(ClientError)
    expect(runs.getHistory).not.toHaveBeenCalled()
    expect(infrastructure.listPlans).not.toHaveBeenCalled()
    for (const [url] of fetchFn.mock.calls as unknown as [string][]) expect(['/session', '/v1/operations']).toContain(url)
  })

  it('projects stored plans and visible ownership refusals without target requests', async () => {
    let payload = { formatVersion: 'stateport.operations/v1', runs: [], infrastructureInstanceIds: ['infra', 'legacy'],
      infrastructurePlans: [{ id: 'plan-1', instanceId: 'infra', title: 'Start', state: 'completed',
        operation: 'start', createdAt: RUN.createdAt, updatedAt: RUN.updatedAt, receiptId: 'receipt-exact' }],
      observationErrors: [{ instanceId: 'legacy', code: 'operation_binding_unavailable', message: 'Legacy ownership cannot be confirmed' }] }
    const fetchFn = vi.fn(async () => jsonResponse(payload))
    const infrastructure = { getTarget: vi.fn(), listPlans: vi.fn() }
    const operations = new HttpOperationsClient(new HttpTransport({ fetchFn }),
      { getHistory: vi.fn(), transition: vi.fn() }, infrastructure)
    const records = await operations.list()
    expect(records[0]).toEqual({ id: 'observation_infrastructure_legacy_0', instanceId: 'legacy',
      kind: 'infrastructure_observation', title: 'Infrastructure operations unavailable',
      observationError: 'Legacy ownership cannot be confirmed' })
    expect(records[1]).toMatchObject({ id: 'op_plan-1', relatedPlanId: 'plan-1',
      relatedReceiptId: 'receipt-exact', state: 'completed', canCancel: false })
    await expect(operations.cancel(records[0].id)).rejects.toBeInstanceOf(ClientError)
    payload = { ...payload, infrastructurePlans: [], observationErrors: [] }
    expect(await operations.list()).toEqual([])
    expect(infrastructure.listPlans).not.toHaveBeenCalled()
    expect(infrastructure.getTarget).not.toHaveBeenCalled()
    for (const [url] of fetchFn.mock.calls as unknown as [string][]) expect(['/session', '/v1/operations']).toContain(url)
  })

  it('refuses missing infrastructure metadata explicitly instead of assuming no plans', async () => {
    const fake = makeFakeFetch([['GET', '/v1/operations', jsonResponse({ formatVersion: 'stateport.operations/v1',
      runs: [], infrastructureInstanceIds: ['infra'] })]])
    const infrastructure = { getTarget: vi.fn(), listPlans: vi.fn() }
    const operations = new HttpOperationsClient(new HttpTransport({ fetchFn: fake.fetchFn }),
      { getHistory: vi.fn(), transition: vi.fn() }, infrastructure)
    expect((await operations.list())[0]).toMatchObject({ kind: 'infrastructure_observation',
      observationError: expect.stringContaining('could not be confirmed') })
    expect(infrastructure.listPlans).not.toHaveBeenCalled()
  })
})
