/**
 * useInfrastructure — runPlan honesty: a backend `run_reconciliation_required`
 * refusal (the replay guard for a lost response or a concurrent run) must not
 * read as an execution failure, while a real execution failure still does.
 */
import { act, renderHook, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ClientError } from '@/client'
import type { InfrastructurePlan, InfrastructureTarget, PlanProgressEvent } from '@/client'

import { useInfrastructure } from '../useInfrastructure'

const getClientMock = vi.hoisted(() => vi.fn())

vi.mock('@/client', async (importOriginal) => {
  const original = await importOriginal<typeof import('@/client')>()
  return { ...original, getClient: getClientMock }
})

const INSTANCE = 'nixos-infrastructure'

const TARGET = {
  id: 'libvirt-persistent',
  instanceId: INSTANCE,
  name: 'Persistent local NixOS VM',
  kind: 'local_vm',
  available: true,
  repository: { name: 'nixos-homelab', branch: 'main', revision: '1'.repeat(40), clean: true },
  vm: { state: 'running' },
  ssh: { state: 'ready' },
  health: { state: 'healthy' },
} as unknown as InfrastructureTarget

const PLAN = {
  id: 'plan-1',
  instanceId: INSTANCE,
  targetId: 'libvirt-persistent',
  operation: 'start',
  state: 'approved',
} as unknown as InfrastructurePlan

function stubClient(runPlan: () => AsyncIterable<PlanProgressEvent>) {
  return {
    infrastructure: {
      getTarget: vi.fn(async () => TARGET),
      listPlans: vi.fn(async () => []),
      getAuthorization: vi.fn(async () => null),
      runPlan: vi.fn(runPlan),
    },
    receipts: { list: vi.fn(async () => []) },
  }
}

describe('useInfrastructure — run replay-guard honesty', () => {
  beforeEach(() => {
    getClientMock.mockReset()
  })

  it('surfaces run_reconciliation_required as in-progress, never as execution failure', async () => {
    const client = stubClient(async function* () {
      yield { type: 'state', planId: PLAN.id, state: 'running' } as PlanProgressEvent
      throw new ClientError(
        'http',
        'the infrastructure run may have started; inspect and reconcile it before any new execution',
        { code: 'run_reconciliation_required', status: 409 },
      )
    })
    getClientMock.mockReturnValue(client)

    const { result } = renderHook(() => useInfrastructure(INSTANCE))
    await waitFor(() => expect(result.current.loading).toBe(false))

    await act(async () => {
      await result.current.runPlan(PLAN)
    })

    expect(result.current.run?.receipt).toBeUndefined()
    expect(result.current.run?.error).toContain('Run already in progress — reconciliation required')
    expect(result.current.run?.error).toContain('not re-executed')
    // The projection is re-read after the refusal: the initial load plus the
    // post-run refresh must both observe the target.
    expect(client.infrastructure.getTarget.mock.calls.length).toBeGreaterThanOrEqual(2)
  })

  it('keeps surfacing a real execution failure as a failure', async () => {
    const client = stubClient(async function* () {
      yield { type: 'state', planId: PLAN.id, state: 'running' } as PlanProgressEvent
      throw new ClientError('http', 'the repository-owned infrastructure command failed', {
        code: 'operation_failed',
        status: 409,
      })
    })
    getClientMock.mockReturnValue(client)

    const { result } = renderHook(() => useInfrastructure(INSTANCE))
    await waitFor(() => expect(result.current.loading).toBe(false))

    await act(async () => {
      await result.current.runPlan(PLAN)
    })

    expect(result.current.run?.phase).toBe('failed')
    expect(result.current.run?.error).toBe('the repository-owned infrastructure command failed')
  })
})
