/**
 * Operation Center derivation tests: run-backed operations expose the
 * backend's idempotent cancel transition; infrastructure plans fail closed.
 */
import { describe, expect, it } from 'vitest'

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
    ['GET', '/v1/instances', jsonResponse({ instances: [{ id: 'ins_1', instanceId: 'ins_1' }] })],
  ])
  const runs: Pick<RunsClient, 'getHistory' | 'transition'> = {
    getHistory: async () => runList,
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
  return { operations, calls }
}

describe('HttpOperationsClient — run cancel', () => {
  it('marks run-backed operations in cancellable states as cancellable', async () => {
    const { operations } = makeOperations([RUN])
    const [record] = await operations.list()
    expect(record.kind).toBe('orchestration_run')
    expect(record.canCancel).toBe(true)
    expect(record.canPause).toBe(false)
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
