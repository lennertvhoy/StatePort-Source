import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import { ClientError } from '../types'
import { MockClient, resetMockState } from '../mock/adapter'
import { useScenarioStore } from '../mock/scenarios'

beforeEach(() => {
  resetMockState()
})

afterEach(() => {
  useScenarioStore.getState().setActive(null)
  resetMockState()
})

describe('approvals', () => {
  it('approving with the current plan digest succeeds and records a receipt', async () => {
    const client = new MockClient()
    const approval = await client.approvals.get('appr_0001')
    expect(approval.status).toBe('pending')

    const { approval: decided, receipt } = await client.approvals.approve('appr_0001', {
      expectedDigest: approval.planDigest.value,
    })
    expect(decided.status).toBe('approved')
    expect(decided.resultingReceiptId).toBe(receipt!.id)
    expect(receipt!.actionName).toBe('Infrastructure plan approved')

    const plan = await client.infrastructure.getPlan(decided.instanceId, 'plan_0001')
    expect(plan.state).toBe('approved')
  })

  it('persists the exact approved plan before an immediate client reload', async () => {
    const client = new MockClient()
    const approval = await client.approvals.get('appr_0001')
    const { approval: decided } = await client.approvals.approve(approval.id, {
      expectedDigest: approval.planDigest.value,
    })

    // Browser navigation constructs a new adapter immediately. The approval
    // promise must not resolve while durable mock truth still says pending.
    const reloaded = new MockClient()
    const persistedApproval = await reloaded.approvals.get(approval.id)
    const persistedPlan = await reloaded.infrastructure.getPlan(decided.instanceId, 'plan_0001')

    expect(persistedApproval.status).toBe('approved')
    expect(persistedApproval.planDigest.value).toBe(approval.planDigest.value)
    expect(persistedPlan.approvalId).toBe(approval.id)
    expect(persistedPlan.digest.value).toBe(approval.planDigest.value)
    expect(persistedPlan.state).toBe('approved')
  })

  it('rejects a digest mismatch (caller reviewed a different plan)', async () => {
    const client = new MockClient()
    await expect(
      client.approvals.approve('appr_0001', { expectedDigest: 'deadbeef'.repeat(8) }),
    ).rejects.toMatchObject({ kind: 'http', status: 409 })
  })

  it('rejects approval when the plan went stale, even with the recorded digest', async () => {
    const client = new MockClient()
    useScenarioStore.getState().setActive('approval_stale')
    const approval = await client.approvals.get('appr_0001')
    // Under the stale scenario the underlying digest moved away from planDigest.
    expect(approval.currentDigest?.value).not.toBe(approval.planDigest.value)

    const attempt = client.approvals.approve('appr_0001', {
      expectedDigest: approval.planDigest.value,
    })
    await expect(attempt).rejects.toBeInstanceOf(ClientError)
    await expect(attempt).rejects.toMatchObject({ status: 409 })
  })

  it('rejection records a human decision and a receipt', async () => {
    const client = new MockClient()
    const { approval, receipt } = await client.approvals.reject('appr_0001', {
      reason: 'Not before the maintenance window',
    })
    expect(approval.status).toBe('rejected')
    expect(approval.decisionReason).toBe('Not before the maintenance window')
    expect(receipt!.result).toBe('rejected')
  })
})
