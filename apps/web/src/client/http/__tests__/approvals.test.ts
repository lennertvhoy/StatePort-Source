/**
 * Approval-index contract tests: the fresh index carries the exact authority,
 * revision, and digest; decisions never infer their route from presentation.
 */
import { describe, expect, it } from 'vitest'

import { ClientError } from '../../types'
import { HttpApprovalsClient, HttpRunsClient } from '../domainsExecution'
import { HttpTransport } from '../transport'
import { jsonResponse, makeFakeFetch } from './helpers'

const RUN_SPEC_DIGEST = `sha256:${'aa'.repeat(32)}`
const PROPOSAL_DIGEST = `sha256:${'bb'.repeat(32)}`
const PLAN_DIGEST = `sha256:${'cc'.repeat(32)}`
const GRANT_DIGEST = `sha256:${'dd'.repeat(32)}`
const GOAL_DIGEST = `sha256:${'ee'.repeat(32)}`
const UPGRADE_DIGEST = `sha256:${'ff'.repeat(32)}`
const DECIDED_AT = '2026-07-19T10:00:00.000Z'

const INFRA_TARGET = {
  targetId: 'libvirt-persistent',
  targetType: 'local_libvirt',
  displayName: 'Persistent local NixOS VM',
  domain: 'ff-nixos-replica-vm-persistent',
  domainUuid: '33cff7f0-f59d-4da5-b47e-f030d2455e5b',
  connection: 'qemu:///session',
  ssh: { host: 'localhost', port: 2223, user: 'ff' },
}

const BASE_APPROVAL = {
  instanceId: 'ins_1',
  title: 'Review exact request',
  operationType: 'governed_action',
  risk: 'medium',
  status: 'pending',
  scope: ['Revision: 7'],
  beforeSummary: 'No governed change has happened.',
  afterSummary: 'Only the exact request will be approved.',
  whyRequired: 'The existing authority requires an exact decision.',
  requestedAt: '2026-07-19T08:00:00.000Z',
}

const ACTIVE_GRANT = {
  formatVersion: 'stateport.infrastructure-daily-driver-grant/v1',
  grantId: 'local-nix-daily-driver',
  instanceId: 'ins_1',
  applicationId: 'nixos-infrastructure',
  target: INFRA_TARGET,
  status: 'active',
  allowedOperations: ['repository.inspect', 'vm.observe', 'vm.health.read'],
  deniedOperations: ['vm.destroy'],
  createdAt: '2026-07-19T08:00:00.000Z',
  approvedAt: '2026-07-19T09:00:00.000Z',
  proposalDigest: GRANT_DIGEST,
  grantDigest: `sha256:${'12'.repeat(32)}`,
}

const GRANT_RECEIPT = {
  formatVersion: 'stateport.infrastructure-grant-receipt/v1',
  receiptType: 'infrastructure.grant.activate',
  receiptId: 'infra-grant-receipt-1',
  status: 'completed',
  instanceId: 'ins_1',
  target: INFRA_TARGET,
  createdAt: '2026-07-19T09:00:00.000Z',
  receiptDigest: `sha256:${'34'.repeat(32)}`,
}

function runApproval(
  decisionKind: 'run_approval' | 'run_proposal',
  digest: string,
) {
  return {
    ...BASE_APPROVAL,
    id: `${decisionKind}:run_7`,
    kind: 'orchestration_run',
    runId: 'run_7',
    planDigest: digest,
    decision: {
      kind: decisionKind,
      expectedInstanceId: 'ins_1',
      expectedRevision: 7,
      expectedDigest: digest,
    },
  }
}

function makeClient(approval: Record<string, unknown>) {
  let decided = false
  const fake = makeFakeFetch([
    [
      'GET',
      '/v1/approvals',
      () => jsonResponse({
        formatVersion: 'stateport.approval-index/v1',
        approvals: decided ? [] : [approval],
      }),
    ],
    ['POST', '/v1/runs/run_7/approve', () => { decided = true; return jsonResponse({ status: 'approved' }) }],
    ['POST', '/v1/runs/run_7/proposal-approve', () => { decided = true; return jsonResponse({ status: 'state_change_approved' }) }],
    ['POST', '/v1/runs/run_7/proposal-reject', () => { decided = true; return jsonResponse({ status: 'state_change_rejected' }) }],
    [
      'POST',
      '/v1/instances/ins_1/infrastructure/approve',
      () => {
        decided = true
        return jsonResponse({
          formatVersion: 'stateport.infrastructure-approval/v1',
          approvalId: 'approval-infra-1',
          instanceId: 'ins_1',
          planDigest: PLAN_DIGEST,
        })
      },
    ],
    [
      'POST',
      '/v1/instances/ins_1/infrastructure/grant/approve',
      () => {
        decided = true
        return jsonResponse({ ...ACTIVE_GRANT, receipt: GRANT_RECEIPT })
      },
    ],
    ['POST', '/v1/instances/ins_1/goal-execution/approve', () => { decided = true; return jsonResponse({ state: 'approved' }) }],
    ['POST', '/v1/instances/ins_1/template-upgrade/approve', () => {
      decided = true
      return jsonResponse({
        approval: {
          id: 'upgrade_7',
          instanceId: 'ins_1',
          status: 'approved',
          reason: '',
          metadata: {
            decision: { actor: 'authenticated-local_user-approver', status: 'approved', at: DECIDED_AT },
          },
        },
      })
    }],
    ['POST', '/v1/instances/ins_1/template-upgrade/reject', () => {
      decided = true
      return jsonResponse({
        approval: {
          id: 'upgrade_7',
          instanceId: 'ins_1',
          status: 'rejected',
          reason: 'Target needs revision',
          metadata: {
            decision: { actor: 'authenticated-local_user-approver', status: 'rejected', at: DECIDED_AT },
          },
        },
      })
    }],
  ])
  const transport = new HttpTransport({ fetchFn: fake.fetchFn })
  return { fake, client: new HttpApprovalsClient(transport, new HttpRunsClient(transport)) }
}

describe('HttpApprovalsClient — authoritative decision routing', () => {
  it('maps a fresh run-approval index with its exact discriminator and revision', async () => {
    const { client } = makeClient(runApproval('run_approval', RUN_SPEC_DIGEST))
    const [approval] = await client.list()

    expect(approval).toMatchObject({
      kind: 'orchestration_run',
      runId: 'run_7',
      expiresAt: undefined,
      decision: {
        kind: 'run_approval',
        expectedInstanceId: 'ins_1',
        expectedRevision: 7,
        expectedDigest: RUN_SPEC_DIGEST,
      },
    })
  })

  it('routes awaiting-run approval to /approve without a history lookup or invented receipt', async () => {
    const { fake, client } = makeClient(runApproval('run_approval', RUN_SPEC_DIGEST))
    const result = await client.approve('run_approval:run_7', { expectedDigest: RUN_SPEC_DIGEST })

    expect(fake.callsTo('/v1/runs/run_7/approve')[0].body).toEqual({
      expectedInstanceId: 'ins_1',
      expectedRevision: 7,
    })
    expect(fake.callsTo('/execution/history')).toHaveLength(0)
    expect(result.approval.status).toBe('approved')
    expect(result.receipt).toBeUndefined()
  })

  it('routes state-change proposal approval to /proposal-approve', async () => {
    const { fake, client } = makeClient(runApproval('run_proposal', PROPOSAL_DIGEST))
    await client.approve('run_proposal:run_7', { expectedDigest: PROPOSAL_DIGEST })

    expect(fake.callsTo('/v1/runs/run_7/proposal-approve')[0].body).toEqual({
      expectedInstanceId: 'ins_1',
      expectedRevision: 7,
    })
    expect(fake.callsTo('/v1/runs/run_7/approve')).toHaveLength(0)
  })

  it('routes a template upgrade decision with its exact operation and plan identities', async () => {
    const approval = {
      ...BASE_APPROVAL,
      id: 'template_upgrade:upgrade_7',
      kind: 'template_upgrade',
      targetId: 'upgrade_7',
      planDigest: UPGRADE_DIGEST,
      decision: {
        kind: 'template_upgrade',
        expectedInstanceId: 'ins_1',
        expectedDigest: UPGRADE_DIGEST,
      },
    }
    const { fake, client } = makeClient(approval)
    const result = await client.approve(approval.id, { expectedDigest: UPGRADE_DIGEST })

    expect(fake.callsTo('/v1/instances/ins_1/template-upgrade/approve')[0].body).toEqual({
      expectedInstanceId: 'ins_1',
      approvalId: 'upgrade_7',
      expectedPlanDigest: UPGRADE_DIGEST,
    })
    expect(result.approval).toMatchObject({
      status: 'approved',
      decidedAt: DECIDED_AT,
      decisionReason: undefined,
    })
  })

  it('retains the authoritative template upgrade rejection reason and time', async () => {
    const approval = {
      ...BASE_APPROVAL,
      id: 'template_upgrade:upgrade_7',
      kind: 'template_upgrade',
      targetId: 'upgrade_7',
      planDigest: UPGRADE_DIGEST,
      decision: {
        kind: 'template_upgrade',
        expectedInstanceId: 'ins_1',
        expectedDigest: UPGRADE_DIGEST,
      },
    }
    const { fake, client } = makeClient(approval)
    const result = await client.reject(approval.id, { reason: 'Target needs revision' })

    expect(fake.callsTo('/v1/instances/ins_1/template-upgrade/reject')[0].body).toEqual({
      expectedInstanceId: 'ins_1',
      approvalId: 'upgrade_7',
      expectedPlanDigest: UPGRADE_DIGEST,
      reason: 'Target needs revision',
    })
    expect(result.approval).toMatchObject({
      status: 'rejected',
      decidedAt: DECIDED_AT,
      decisionReason: 'Target needs revision',
    })
  })

  it('rejects a template upgrade index without an operation identity', async () => {
    const approval = {
      ...BASE_APPROVAL,
      id: 'template_upgrade:upgrade_7',
      kind: 'template_upgrade',
      planDigest: UPGRADE_DIGEST,
      decision: {
        kind: 'template_upgrade',
        expectedInstanceId: 'ins_1',
        expectedDigest: UPGRADE_DIGEST,
      },
    }
    const { client } = makeClient(approval)

    await expect(client.list()).rejects.toMatchObject({ kind: 'validation' })
  })

  it('rejects mismatched template presentation and decision authorities', async () => {
    const approval = {
      ...BASE_APPROVAL,
      id: 'template_upgrade:upgrade_7',
      kind: 'template_upgrade',
      targetId: 'upgrade_7',
      planDigest: UPGRADE_DIGEST,
      decision: {
        kind: 'goal_execution',
        expectedInstanceId: 'ins_1',
        expectedRevision: 4,
        expectedDigest: UPGRADE_DIGEST,
      },
    }
    const { client } = makeClient(approval)

    await expect(client.list()).rejects.toMatchObject({ kind: 'validation' })
  })

  it('routes only state-change proposal rejection to proposal-reject', async () => {
    const { fake, client } = makeClient(runApproval('run_proposal', PROPOSAL_DIGEST))
    await client.reject('run_proposal:run_7', {})

    expect(fake.callsTo('/v1/runs/run_7/proposal-reject')[0].body).toEqual({
      expectedInstanceId: 'ins_1',
      expectedRevision: 7,
    })
  })

  it('does not reinterpret an initial run approval as a proposal rejection', async () => {
    const { fake, client } = makeClient(runApproval('run_approval', RUN_SPEC_DIGEST))
    const error = await client.reject('run_approval:run_7', {}).catch((value: unknown) => value)

    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).kind).toBe('unavailable')
    expect(fake.callsTo('/v1/runs/run_7/proposal-reject')).toHaveLength(0)
  })

  it('does not claim to record a rejection reason unsupported by the endpoint', async () => {
    const { fake, client } = makeClient(runApproval('run_proposal', PROPOSAL_DIGEST))
    const error = await client
      .reject('run_proposal:run_7', { reason: 'Not now' })
      .catch((value: unknown) => value)

    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).kind).toBe('unavailable')
    expect(fake.callsTo('/v1/runs/run_7/proposal-reject')).toHaveLength(0)
  })

  it('routes an infrastructure plan with its exact digest and no fabricated receipt', async () => {
    const approval = {
      ...BASE_APPROVAL,
      id: `infrastructure_plan:${PLAN_DIGEST}`,
      kind: 'infrastructure_plan',
      planDigest: PLAN_DIGEST,
      decision: {
        kind: 'infrastructure_plan',
        expectedInstanceId: 'ins_1',
        expectedDigest: PLAN_DIGEST,
      },
    }
    const { fake, client } = makeClient(approval)
    const result = await client.approve(String(approval.id), { expectedDigest: PLAN_DIGEST })

    expect(fake.callsTo('/v1/instances/ins_1/infrastructure/approve')[0].body).toEqual({
      planDigest: PLAN_DIGEST,
    })
    expect(result.receipt).toBeUndefined()
  })

  it('routes a grant and preserves only the receipt actually returned by its authority', async () => {
    const approval = {
      ...BASE_APPROVAL,
      id: `authorization_grant:${GRANT_DIGEST}`,
      kind: 'authorization_grant',
      planDigest: GRANT_DIGEST,
      decision: {
        kind: 'authorization_grant',
        expectedInstanceId: 'ins_1',
        expectedDigest: GRANT_DIGEST,
      },
    }
    const { fake, client } = makeClient(approval)
    const result = await client.approve(String(approval.id), { expectedDigest: GRANT_DIGEST })

    expect(fake.callsTo('/v1/instances/ins_1/infrastructure/grant/approve')[0].body).toEqual({
      proposalDigest: GRANT_DIGEST,
    })
    expect(result.receipt?.id).toBe('infra-grant-receipt-1')
  })

  it('routes goal execution with exact instance, revision, and plan digest', async () => {
    const approval = {
      ...BASE_APPROVAL,
      id: `goal_execution:ins_1:${GOAL_DIGEST}`,
      kind: 'goal_execution',
      planDigest: GOAL_DIGEST,
      decision: {
        kind: 'goal_execution',
        expectedInstanceId: 'ins_1',
        expectedRevision: 11,
        expectedDigest: GOAL_DIGEST,
      },
    }
    const { fake, client } = makeClient(approval)
    await client.approve(String(approval.id), { expectedDigest: GOAL_DIGEST })

    expect(fake.callsTo('/v1/instances/ins_1/goal-execution/approve')[0].body).toEqual({
      expectedInstanceId: 'ins_1',
      expectedRevision: 11,
      expectedPlanDigest: GOAL_DIGEST,
    })
  })

  it('refuses a stale caller digest before sending a decision', async () => {
    const { fake, client } = makeClient(runApproval('run_approval', RUN_SPEC_DIGEST))
    const error = await client
      .approve('run_approval:run_7', { expectedDigest: PROPOSAL_DIGEST })
      .catch((value: unknown) => value)

    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).kind).toBe('validation')
    expect(fake.callsTo('/v1/runs/run_7/approve')).toHaveLength(0)
  })

  it('refuses indexed decision digest or instance drift at mapping time', async () => {
    const drifted = {
      ...runApproval('run_approval', RUN_SPEC_DIGEST),
      decision: {
        kind: 'run_approval',
        expectedInstanceId: 'ins_other',
        expectedRevision: 7,
        expectedDigest: PROPOSAL_DIGEST,
      },
    }
    const { client } = makeClient(drifted)
    const error = await client.list().catch((value: unknown) => value)

    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).kind).toBe('validation')
  })

  it('does not expose rejection for approval authorities without a reject endpoint', async () => {
    const approval = {
      ...BASE_APPROVAL,
      id: `infrastructure_plan:${PLAN_DIGEST}`,
      kind: 'infrastructure_plan',
      planDigest: PLAN_DIGEST,
      decision: {
        kind: 'infrastructure_plan',
        expectedInstanceId: 'ins_1',
        expectedDigest: PLAN_DIGEST,
      },
    }
    const { client } = makeClient(approval)
    const error = await client.reject(String(approval.id), {}).catch((value: unknown) => value)

    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).kind).toBe('unavailable')
  })
})
