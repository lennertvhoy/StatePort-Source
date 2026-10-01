/**
 * Platform surface HTTP client contract tests: deployments, standing
 * authority, installed updater, and preview routes.
 *
 * These pin the honesty rules:
 * - Reads validate the structural envelope and pass rich payloads through.
 * - Digest-bound mutations resolve the local actor from /v1/status and send
 *   `approval: {decision, actorId, proposalDigest}`.
 * - A `409 *_state_unavailable` surfaces as an honest ClientError (the UI must
 *   not fake a working control).
 * - Updater rollback plan carries `applyBoundary: 'installed-authority-cli'`.
 */
import { describe, expect, it } from 'vitest'

import { ClientError } from '../../types'
import { HttpTransport } from '../transport'
import {
  DigestApproval,
  HttpAuthorityClient,
  HttpPlatformDeploymentsClient,
  HttpPreviewRoutesClient,
  HttpUpdaterClient,
} from '../domainsPlatformSurface'
import { jsonResponse, makeFakeFetch, type RecordedCall } from './helpers'

const STATUS_OK = { ok: true, result: { state: 'connected', actor: { role: 'platform_operator', actorId: 'op-1' } } }

const SHA = `sha256:${'a'.repeat(64)}`
function authorityReceipt(options: {
  action?: string
  authorizedBy: { type: string; id: string; digest: string | null }
  applicationId: string | null
  resource: Record<string, unknown>
}) {
  return {
    schema: 'stateport.authority-action-receipt/v1',
    receiptId: 'authority_receipt_' + 'a'.repeat(32),
    requestId: 'authority_request_' + 'b'.repeat(32),
    action: options.action ?? 'authority_action',
    actorId: 'op-1',
    authorizedBy: options.authorizedBy,
    scope: { applicationId: options.applicationId },
    decision: 'authorized',
    result: { status: 'succeeded', resource: options.resource },
    decisionDigest: SHA,
    reservation: null,
    claim: null,
    receiptDigest: SHA,
  }
}

function deploymentAuthorityReceipt(action: string) {
  return authorityReceipt({
    action,
    authorizedBy: { type: 'grant', id: 'grant_daily', digest: SHA },
    applicationId: 'dep_web',
    resource: { deploymentId: 'dep_web' },
  })
}

/** Narrow a recorded call body to a record for field access in assertions. */
function bodyOf(call: RecordedCall): Record<string, unknown> {
  return (call.body ?? {}) as Record<string, unknown>
}

function deploymentIndex() {
  return {
    formatVersion: 'stateport.deployment-index/v1',
    deployments: [
      {
        deploymentId: 'dep_web',
        lifecycleState: 'healthy',
        driftStatus: 'aligned',
        desiredRevision: SHA,
        approvedPlanDigest: SHA,
        acceptedRevision: SHA,
        observedRevision: SHA,
        rollback: null,
        retainedDataState: { present: true },
        currentOperation: null,
        serviceHealth: { state: 'healthy' },
      },
    ],
  }
}

function updaterStatusPayload() {
  return {
    schema: 'stateport.update-status/v1',
    sequence: 1,
    phase: 'idle',
    installationId: 'installation-1',
    policy: { mode: 'manual', channel: 'stable' },
    current: { releaseId: 'release-current' },
    accepted: { releaseId: 'release-current' },
    retainedPredecessor: null,
    stagedSuccessor: null,
    failedSuccessorEvidence: null,
    lastReceipt: null,
    updatedAt: '2026-08-09T00:00:00Z',
    target: 'stateport-vm',
  }
}

function authorityIndexPayload() {
  return {
    schema: 'stateport.authority-index/v1',
    repository: { repositoryKey: 'repo', repositoryRoot: '/repo', origin: null },
    policy: {
      formatVersion: 'stateport.authority-profile-index/v1',
      schema: 'stateport.authority-policy/v1',
      defaultProfile: 'balanced',
      policyDigest: SHA,
      actionPolicies: {},
      profiles: {},
      hardDeny: [],
      mergeRequirements: [],
      subagentDefaultDeny: [],
      escalationConditions: [],
    },
    defaultProfile: 'balanced',
    policyDigest: SHA,
    control: { revision: 4, paused: true, controlDigest: SHA },
    activeGrants: [{ grantId: 'grant_active', grantDigest: SHA, status: 'active' }],
    inactiveGrants: [{ grantId: 'grant_old', grantDigest: SHA, status: 'revoked' }],
    revisions: { indexRevision: SHA, controlRevision: 4, grantRevisions: { grant_active: SHA, grant_old: SHA } },
    reviewableDigests: { indexDigest: SHA, controlDigest: SHA, grantDigests: { grant_active: SHA, grant_old: SHA } },
  }
}

describe('HttpPlatformDeploymentsClient', () => {
  it('lists deployments and validates the index envelope', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/deployments', jsonResponse({ ok: true, result: deploymentIndex() })],
    ])
    const client = new HttpPlatformDeploymentsClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const index = await client.list()
    expect(index.formatVersion).toBe('stateport.deployment-index/v1')
    expect(index.deployments).toHaveLength(1)
    expect(index.deployments[0].deploymentId).toBe('dep_web')
    expect(index.deployments[0].retainedDataState).toEqual({ present: true })
  })

  it('returns an empty index when no durable state exists', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/deployments', jsonResponse({ ok: true, result: { formatVersion: 'stateport.deployment-index/v1', deployments: [] } })],
    ])
    const client = new HttpPlatformDeploymentsClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const index = await client.list()
    expect(index.deployments).toHaveLength(0)
  })

  it('reads deployment detail as a passthrough state projection', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/deployments/dep_web', jsonResponse({ ok: true, result: { state: { deploymentId: 'dep_web', lifecycleState: 'degraded', extra: { ports: [8080] } } } })],
    ])
    const client = new HttpPlatformDeploymentsClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const detail = await client.get('dep_web')
    expect(detail.state.deploymentId).toBe('dep_web')
    expect(detail.state.extra).toEqual({ ports: [8080] })
  })

  it('plans a deployment with the exact body shape', async () => {
    const fake = makeFakeFetch([
      ['POST', '/v1/deployments/plan', (call) => jsonResponse({ ok: true, result: { planDigest: SHA, authorityReceipt: deploymentAuthorityReceipt('plan_deployment'), operation: 'apply', grantId: bodyOf(call).grantId } })],
    ])
    const client = new HttpPlatformDeploymentsClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const result = await client.plan({ project: '/workspace/stateport', deploymentId: 'dep_web', grantId: 'grant_daily', sliceId: 'slc_1' })
    expect((result as Record<string, unknown>).planDigest).toBe(SHA)
    const call = fake.callsTo('/v1/deployments/plan')[0]
    expect(call.body).toEqual({
      project: '/workspace/stateport',
      deploymentId: 'dep_web',
      grantId: 'grant_daily',
      sliceId: 'slc_1',
    })
    expect(call.headers['x-stateport-csrf']).toBe('test-csrf')
  })

  it('applies an accepted plan with digest-bound approval from /v1/status', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/status', jsonResponse(STATUS_OK)],
      ['POST', '/v1/deployments/dep_web/apply', (call) => jsonResponse({ ok: true, result: { state: { deploymentId: 'dep_web', lifecycleState: 'healthy' }, authorityReceipt: deploymentAuthorityReceipt('apply_deployment'), applied: true, acceptPlanDigest: bodyOf(call).acceptPlanDigest } })],
    ])
    const transport = new HttpTransport({ fetchFn: fake.fetchFn })
    const client = new HttpPlatformDeploymentsClient(transport)
    const result = await client.apply('dep_web', { acceptPlanDigest: SHA, grantId: 'grant_daily' })
    expect((result as Record<string, unknown>).state).toEqual({ deploymentId: 'dep_web', lifecycleState: 'healthy' })
    const call = fake.callsTo('/v1/deployments/dep_web/apply')[0]
    expect(bodyOf(call).approval).toEqual({ decision: 'approve', actorId: 'op-1', proposalDigest: SHA })
    expect(bodyOf(call).grantId).toBe('grant_daily')
    expect(bodyOf(call).acceptPlanDigest).toBe(SHA)
  })

  it('rejects a null deployment success payload', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/status', jsonResponse(STATUS_OK)],
      ['POST', '/v1/deployments/dep_web/apply', jsonResponse({ ok: true, result: null })],
    ])
    const client = new HttpPlatformDeploymentsClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const error = await client.apply('dep_web', { acceptPlanDigest: SHA, grantId: 'grant_daily' }).catch((value: unknown) => value)
    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).kind).toBe('validation')
  })

  it('rejects a deployment receipt bound to another grant', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/status', jsonResponse(STATUS_OK)],
      ['POST', '/v1/deployments/dep_web/apply', jsonResponse({ ok: true, result: {
        state: { deploymentId: 'dep_web', lifecycleState: 'healthy' },
        authorityReceipt: {
          ...deploymentAuthorityReceipt('apply_deployment'),
          authorizedBy: { type: 'grant', id: 'other-grant', digest: SHA },
        },
      } })],
    ])
    const client = new HttpPlatformDeploymentsClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const error = await client.apply('dep_web', { acceptPlanDigest: SHA, grantId: 'grant_daily' }).catch((value: unknown) => value)
    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).kind).toBe('validation')
  })

  it('rejects a failed authority receipt as a successful deployment result', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/status', jsonResponse(STATUS_OK)],
      ['POST', '/v1/deployments/dep_web/apply', jsonResponse({ ok: true, result: {
        state: { deploymentId: 'dep_web', lifecycleState: 'healthy' },
        authorityReceipt: {
          ...deploymentAuthorityReceipt('apply_deployment'),
          result: { status: 'failed', resource: { deploymentId: 'dep_web' } },
        },
      } })],
    ])
    const client = new HttpPlatformDeploymentsClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const error = await client.apply('dep_web', { acceptPlanDigest: SHA, grantId: 'grant_daily' }).catch((value: unknown) => value)
    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).kind).toBe('validation')
  })

  it('observes status and collects logs through the grant body', async () => {
    const fake = makeFakeFetch([
      ['POST', '/v1/deployments/dep_web/status', (call) => jsonResponse({ ok: true, result: { state: { deploymentId: 'dep_web', lifecycleState: 'healthy' }, authorityReceipt: deploymentAuthorityReceipt('observe_deployment'), observed: true, grantId: bodyOf(call).grantId } })],
      ['POST', '/v1/deployments/dep_web/logs', (call) => jsonResponse({ ok: true, result: { deploymentId: 'dep_web', logs: { web: 'hi\n' }, authorityReceipt: deploymentAuthorityReceipt('collect_deployment_logs'), tail: bodyOf(call).tail, serviceId: bodyOf(call).serviceId } })],
    ])
    const client = new HttpPlatformDeploymentsClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const status = await client.status('dep_web', { grantId: 'grant_daily' })
    expect((status as Record<string, unknown>).observed).toBe(true)
    const logs = await client.logs('dep_web', { grantId: 'grant_daily', serviceId: 'web', tail: 50 })
    expect((logs as Record<string, unknown>).logs).toEqual({ web: 'hi\n' })
    const logCall = fake.callsTo('/v1/deployments/dep_web/logs')[0]
    expect(logCall.body).toEqual({ grantId: 'grant_daily', serviceId: 'web', tail: 50 })
  })

  it('restart and remove carry the digest-bound approval member', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/status', jsonResponse(STATUS_OK)],
      ['POST', '/v1/deployments/dep_web/restart', (call) => jsonResponse({ ok: true, result: { state: { deploymentId: 'dep_web', lifecycleState: 'healthy' }, authorityReceipt: deploymentAuthorityReceipt('restart_deployment'), restarted: true, approvalActor: bodyOf(call).approval } })],
      ['POST', '/v1/deployments/dep_web/remove', (call) => jsonResponse({ ok: true, result: { state: { deploymentId: 'dep_web', lifecycleState: 'removed_runtime_data_retained' }, authorityReceipt: deploymentAuthorityReceipt('remove_deployment_runtime'), removed: true, approvalDecision: bodyOf(call).approval } })],
    ])
    const client = new HttpPlatformDeploymentsClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const restarted = await client.restart('dep_web', { grantId: 'grant_daily', proposalDigest: SHA })
    expect((restarted as Record<string, unknown>).restarted).toBe(true)
    const removed = await client.remove('dep_web', { grantId: 'grant_daily', proposalDigest: SHA })
    expect((removed as Record<string, unknown>).removed).toBe(true)
    expect(bodyOf(fake.callsTo('/v1/deployments/dep_web/restart')[0]).approval).toEqual({ decision: 'approve', actorId: 'op-1', proposalDigest: SHA })
  })

  it('plans retained-data purge', async () => {
    const fake = makeFakeFetch([
      ['POST', '/v1/deployments/dep_web/purge/plan', (call) => jsonResponse({ ok: true, result: { planDigest: SHA, authorityReceipt: deploymentAuthorityReceipt('plan_deployment'), operation: 'purge_data', grantId: bodyOf(call).grantId } })],
    ])
    const client = new HttpPlatformDeploymentsClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const result = await client.planPurge('dep_web', { grantId: 'grant_daily' })
    expect((result as Record<string, unknown>).operation).toBe('purge_data')
  })

  it('surfaces a 409 deployment_state_unavailable as an honest ClientError', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/deployments', jsonResponse({ ok: false, error: { code: 'deployment_state_unavailable', message: 'no durable state' } }, 409)],
    ])
    const client = new HttpPlatformDeploymentsClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const error = await client.list().catch((value: unknown) => value)
    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).code).toBe('deployment_state_unavailable')
  })
})

describe('HttpAuthorityClient', () => {
  it('parses the canonical authority index with active and inactive review state', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/authority/index', jsonResponse({ ok: true, result: {
        ...authorityIndexPayload(),
      } })],
    ])
    const client = new HttpAuthorityClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const index = await client.getIndex()
    expect(index.activeGrants[0].grantId).toBe('grant_active')
    expect(index.inactiveGrants[0].status).toBe('revoked')
    expect(index.reviewableDigests.controlDigest).toBe(SHA)
  })

  it('rejects an authority index whose grant digest is not reviewable', async () => {
    const payload = authorityIndexPayload()
    payload.activeGrants[0].grantDigest = `sha256:${'b'.repeat(64)}`
    const fake = makeFakeFetch([
      ['GET', '/v1/authority/index', jsonResponse({ ok: true, result: payload })],
    ])
    const client = new HttpAuthorityClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const error = await client.getIndex().catch((value: unknown) => value)
    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).kind).toBe('validation')
  })

  it('rejects duplicate or mispartitioned authority grants', async () => {
    const payload = authorityIndexPayload()
    payload.inactiveGrants[0].status = 'active'
    Object.assign(payload.revisions.grantRevisions, { extra: SHA })
    const fake = makeFakeFetch([
      ['GET', '/v1/authority/index', jsonResponse({ ok: true, result: payload })],
    ])
    const client = new HttpAuthorityClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const error = await client.getIndex().catch((value: unknown) => value)
    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).kind).toBe('validation')
  })

  it('lists profiles with the full envelope', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/authority/profiles', jsonResponse({ ok: true, result: {
        formatVersion: 'stateport.authority-profile-index/v1',
        schema: 'stateport.authority-policy/v1',
        defaultProfile: 'balanced',
        policyDigest: SHA,
        actionPolicies: { plan_deployment: { requireApproval: true } },
        profiles: { balanced: { name: 'balanced' } },
        hardDeny: ['deploy'],
        mergeRequirements: ['reviews'],
        subagentDefaultDeny: ['push'],
        escalationConditions: [{ when: 'destructive' }],
      } })],
    ])
    const client = new HttpAuthorityClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const profiles = await client.listProfiles()
    expect(profiles.defaultProfile).toBe('balanced')
    expect(profiles.hardDeny).toEqual(['deploy'])
    expect(profiles.actionPolicies.plan_deployment.requireApproval).toBe(true)
  })

  it('lists grants and resolves the pause control state', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/authority/grants', jsonResponse({ ok: true, result: {
        grants: [{ grantId: 'grant_daily', grantDigest: SHA, status: 'active', profile: 'balanced' }],
        paused: false,
        control: { controlDigest: SHA, paused: false },
      } })],
    ])
    const client = new HttpAuthorityClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const grants = await client.listGrants()
    expect(grants.grants[0].grantId).toBe('grant_daily')
    expect(grants.paused).toBe(false)
    expect((grants.control as Record<string, unknown>).controlDigest).toBe(SHA)
  })

  it('pauses with approval bound to the reviewed control digest', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/status', jsonResponse(STATUS_OK)],
      ['POST', '/v1/authority/pause', (call) => jsonResponse({ ok: true, result: {
        control: { paused: true, controlDigest: SHA, ownerDirectiveId: 'dir_1', actorId: 'op-1' },
        receipt: authorityReceipt({
          action: 'modify_authority_policy',
          authorizedBy: { type: 'owner_directive', id: 'dir_1', digest: null },
          applicationId: null,
          resource: { paused: true, controlDigest: SHA },
        }),
        receiptId: 'authority_receipt_' + 'a'.repeat(32),
        receiptDigest: SHA,
        sawApproval: 'approval' in bodyOf(call),
      } })],
    ])
    const client = new HttpAuthorityClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const result = await client.setPaused({ paused: true, ownerDirectiveId: 'dir_1', reason: 'maintenance', controlDigest: SHA })
    expect((result.control as Record<string, unknown>).paused).toBe(true)
    const call = fake.callsTo('/v1/authority/pause')[0]
    expect(bodyOf(call).paused).toBe(true)
    expect(bodyOf(call).approval).toEqual({ decision: 'approve', actorId: 'op-1', proposalDigest: SHA })
    expect(bodyOf(call).controlDigest).toBe(SHA)
    expect(bodyOf(call).ownerDirectiveId).toBe('dir_1')
  })

  it('unpauses with the control digest resolved from the grants projection', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/status', jsonResponse(STATUS_OK)],
      ['GET', '/v1/authority/grants', jsonResponse({ ok: true, result: {
        grants: [],
        paused: true,
        control: { controlDigest: SHA, paused: true },
      } })],
      ['POST', '/v1/authority/pause', (call) => jsonResponse({ ok: true, result: {
        control: { paused: false, controlDigest: SHA, ownerDirectiveId: 'dir_2', actorId: 'op-1' },
        receipt: authorityReceipt({
          action: 'modify_authority_policy',
          authorizedBy: { type: 'owner_directive', id: 'dir_2', digest: null },
          applicationId: null,
          resource: { paused: false, controlDigest: SHA },
        }),
        receiptId: 'authority_receipt_' + 'a'.repeat(32),
        receiptDigest: SHA,
        approval: bodyOf(call).approval,
      } })],
    ])
    const client = new HttpAuthorityClient(new HttpTransport({ fetchFn: fake.fetchFn }))
     const result = await client.setPaused({ paused: false, ownerDirectiveId: 'dir_2', reason: 'resume', controlDigest: SHA })
    expect((result.control as Record<string, unknown>).paused).toBe(false)
    const call = fake.callsTo('/v1/authority/pause')[0]
    expect(bodyOf(call).approval).toEqual({ decision: 'approve', actorId: 'op-1', proposalDigest: SHA })
  })

  it('revokes a grant with the digest resolved from the grant detail', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/status', jsonResponse(STATUS_OK)],
      ['GET', '/v1/authority/grants/grant_daily', jsonResponse({ ok: true, result: {
        grant: { grantId: 'grant_daily', grantDigest: SHA, status: 'active' },
        paused: false,
      } })],
      ['POST', '/v1/authority/grants/grant_daily/revoke', (call) => {
        const approval = bodyOf(call).approval as Record<string, unknown>
        return jsonResponse({ ok: true, result: {
          revocation: {
            schema: 'stateport.authority-revocation/v1',
            grantId: 'grant_daily',
            grantDigest: approval.proposalDigest,
            actorId: 'op-1',
            ownerDirectiveId: 'dir_3',
            reason: 'expired',
            revokedAt: '2026-08-09T00:00:00Z',
            revocationDigest: SHA,
          },
          revokedGrantDigest: approval.proposalDigest,
          receipt: authorityReceipt({
            action: 'modify_authority_policy',
            authorizedBy: { type: 'owner_directive', id: 'dir_3', digest: null },
            applicationId: null,
            resource: { grantId: 'grant_daily', revocationDigest: SHA },
          }),
          receiptId: 'authority_receipt_' + 'a'.repeat(32),
          receiptDigest: SHA,
        } })
      }],
    ])
    const client = new HttpAuthorityClient(new HttpTransport({ fetchFn: fake.fetchFn }))
     const result = await client.revokeGrant('grant_daily', { ownerDirectiveId: 'dir_3', reason: 'expired', grantDigest: SHA })
    expect(result.revokedGrantDigest).toBe(SHA)
    const call = fake.callsTo('/v1/authority/grants/grant_daily/revoke')[0]
    expect(bodyOf(call).approval).toEqual({ decision: 'approve', actorId: 'op-1', proposalDigest: SHA })
    expect(bodyOf(call).ownerDirectiveId).toBe('dir_3')
     expect(bodyOf(call).reason).toBe('expired')
    expect(bodyOf(call).grantDigest).toBe(SHA)
  })

  it('rejects a grants projection with a malformed digest', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/authority/grants', jsonResponse({ ok: true, result: {
        grants: [{ grantId: 'grant_daily', grantDigest: 'not-a-sha256-digest', status: 'active' }],
        paused: false,
      } })],
    ])
    const client = new HttpAuthorityClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const error = await client.listGrants().catch((value: unknown) => value)
    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).kind).toBe('validation')
  })

  it('rejects failed pause and revoke receipts', async () => {
    const failedPause = authorityReceipt({
      action: 'modify_authority_policy',
      authorizedBy: { type: 'owner_directive', id: 'dir_failed', digest: null },
      applicationId: null,
      resource: { paused: true, controlDigest: SHA },
    })
    failedPause.result.status = 'failed'
    const failedRevoke = authorityReceipt({
      action: 'modify_authority_policy',
      authorizedBy: { type: 'owner_directive', id: 'dir_failed', digest: null },
      applicationId: null,
      resource: { grantId: 'grant_daily', revocationDigest: SHA },
    })
    failedRevoke.result.status = 'failed'
    const fake = makeFakeFetch([
      ['GET', '/v1/status', jsonResponse(STATUS_OK)],
      ['POST', '/v1/authority/pause', jsonResponse({ ok: true, result: {
        control: { paused: true, controlDigest: SHA, ownerDirectiveId: 'dir_failed', actorId: 'op-1' },
        receipt: failedPause,
        receiptId: failedPause.receiptId,
        receiptDigest: failedPause.receiptDigest,
      } })],
      ['GET', '/v1/authority/grants/grant_daily', jsonResponse({ ok: true, result: {
        grant: { grantId: 'grant_daily', grantDigest: SHA, status: 'active' },
        paused: false,
      } })],
      ['POST', '/v1/authority/grants/grant_daily/revoke', jsonResponse({ ok: true, result: {
        revocation: {
          schema: 'stateport.authority-revocation/v1', grantId: 'grant_daily', grantDigest: SHA,
          actorId: 'op-1', ownerDirectiveId: 'dir_failed', reason: 'expired',
          revokedAt: '2026-08-09T00:00:00Z', revocationDigest: SHA,
        },
        revokedGrantDigest: SHA,
        receipt: failedRevoke,
        receiptId: failedRevoke.receiptId,
        receiptDigest: failedRevoke.receiptDigest,
      } })],
    ])
    const client = new HttpAuthorityClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const pauseError = await client.setPaused({ paused: true, ownerDirectiveId: 'dir_failed', reason: 'maintenance', controlDigest: SHA }).catch((value: unknown) => value)
    expect(pauseError).toBeInstanceOf(ClientError)
    const revokeError = await client.revokeGrant('grant_daily', { ownerDirectiveId: 'dir_failed', reason: 'expired', grantDigest: SHA }).catch((value: unknown) => value)
    expect(revokeError).toBeInstanceOf(ClientError)
  })

  it('rejects an authority mutation response missing its production receipt', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/status', jsonResponse(STATUS_OK)],
      ['POST', '/v1/authority/pause', jsonResponse({ ok: true, result: { control: { paused: true } } })],
    ])
    const client = new HttpAuthorityClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const error = await client.setPaused({ paused: true, ownerDirectiveId: 'dir_4', reason: 'maintenance', controlDigest: SHA }).catch((value: unknown) => value)
    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).kind).toBe('validation')
  })

  it('rejects an authority mutation response with inconsistent receipt fields', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/status', jsonResponse(STATUS_OK)],
      ['POST', '/v1/authority/pause', jsonResponse({ ok: true, result: {
        control: { paused: true },
        receipt: { receiptId: 'receipt_nested', receiptDigest: SHA },
        receiptId: 'receipt_top_level',
        receiptDigest: SHA,
      } })],
    ])
    const client = new HttpAuthorityClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const error = await client.setPaused({ paused: true, ownerDirectiveId: 'dir_5', reason: 'maintenance', controlDigest: SHA }).catch((value: unknown) => value)
    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).kind).toBe('validation')
  })

  it('surfaces a 404 grant_not_found honestly', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/authority/grants/missing', jsonResponse({ ok: false, error: { code: 'grant_not_found', message: 'no such grant' } }, 404)],
    ])
    const client = new HttpAuthorityClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const error = await client.getGrant('missing').catch((value: unknown) => value)
    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).code).toBe('grant_not_found')
  })
})

describe('HttpUpdaterClient', () => {
  it('reads the installed updater status as a passthrough projection', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/updater/status', jsonResponse({ ok: true, result: { ...updaterStatusPayload(), current: { version: '1.0.0' } } })],
    ])
    const client = new HttpUpdaterClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const status = await client.getStatus()
    expect(status.phase).toBe('idle')
    expect(status.target).toBe('stateport-vm')
  })

  it('reads policy and rollback projections with their envelopes', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/updater/policy', jsonResponse({ ok: true, result: {
        formatVersion: 'stateport.updater-policy/v1',
        policy: { channel: 'stable' },
        statusDigest: SHA,
      } })],
      ['GET', '/v1/updater/rollback', jsonResponse({ ok: true, result: {
        formatVersion: 'stateport.updater-rollback/v1',
        phase: 'idle',
        pendingPhase: null,
        retainedPredecessor: { version: '0.9.0', digest: SHA },
        rollbackAvailable: true,
        statusDigest: SHA,
      } })],
    ])
    const client = new HttpUpdaterClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const policy = await client.getPolicy()
    expect(policy.statusDigest).toBe(SHA)
    expect(policy.policy.channel).toBe('stable')
    const rollback = await client.getRollback()
    expect(rollback.rollbackAvailable).toBe(true)
    expect(rollback.retainedPredecessor).not.toBeNull()
  })

  it('mutates the policy with digest-bound approval', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/status', jsonResponse(STATUS_OK)],
      ['POST', '/v1/updater/policy', (call) => {
        const policy = bodyOf(call).policy as Record<string, unknown>
        return jsonResponse({ ok: true, result: {
          ...updaterStatusPayload(),
          policy,
          receipt: authorityReceipt({
            action: 'modify_update_policy',
            authorizedBy: { type: 'grant', id: 'grant_updater', digest: SHA },
            applicationId: null,
            resource: { policyDigest: SHA },
          }),
        } })
      }],
    ])
    const client = new HttpUpdaterClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const result = await client.setPolicy({ policy: { channel: 'beta' }, expectedStatusDigest: SHA })
    expect((result as Record<string, unknown>).policy).toEqual({ channel: 'beta' })
    expect((result as Record<string, unknown>).receipt).toBeDefined()
    const call = fake.callsTo('/v1/updater/policy')[0]
    expect(bodyOf(call).approval).toEqual({ decision: 'approve', actorId: 'op-1', proposalDigest: SHA })
    expect(bodyOf(call).policy).toEqual({ channel: 'beta' })
  })

  it('rejects a malformed updater success payload', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/status', jsonResponse(STATUS_OK)],
      ['POST', '/v1/updater/policy', jsonResponse({ ok: true, result: null })],
    ])
    const client = new HttpUpdaterClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const error = await client.setPolicy({ policy: { channel: 'beta' }, expectedStatusDigest: SHA }).catch((value: unknown) => value)
    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).kind).toBe('validation')
  })

  it('plans rollback with the apply boundary marker (never applies over HTTP)', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/status', jsonResponse(STATUS_OK)],
      ['POST', '/v1/updater/rollback', (call) => jsonResponse({ ok: true, result: {
        plan: { planId: 'update_plan_1', planDigest: SHA, operation: 'rollback', observedDigest: bodyOf(call).expectedStatusDigest },
        applyBoundary: 'installed-authority-cli',
        note: 'apply remains reserved to the installed updater authority boundary',
      } })],
    ])
    const client = new HttpUpdaterClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const result = await client.planRollback({ expectedStatusDigest: SHA })
    expect(result.applyBoundary).toBe('installed-authority-cli')
    expect(result.note).toContain('reserved')
    const call = fake.callsTo('/v1/updater/rollback')[0]
    expect(bodyOf(call).approval).toEqual({ decision: 'approve', actorId: 'op-1', proposalDigest: SHA })
  })

  it('surfaces updater_state_unavailable honestly when no host state exists', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/updater/status', jsonResponse({ ok: false, error: { code: 'updater_state_unavailable', message: 'no updater' } }, 409)],
    ])
    const client = new HttpUpdaterClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const error = await client.getStatus().catch((value: unknown) => value)
    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).code).toBe('updater_state_unavailable')
  })
})

describe('HttpPreviewRoutesClient', () => {
  const ROUTE = {
    schema: 'stateport.preview-route/v1',
    routeId: 'route_' + '0'.repeat(24),
    capsuleId: 'capsule_web',
    serviceId: 'web',
    revisionDigest: SHA,
    upstream: { host: '127.0.0.1', port: 8080 },
    createdAt: '2026-08-03T10:00:00Z',
    expiresAt: '2026-08-03T11:00:00Z',
    revokedAt: null,
    revocationReason: null,
    routeDigest: SHA,
    status: 'active' as const,
  }

  function previewReceipt(
    event: 'registered' | 'rewritten' | 'revoked',
    route: {
      routeId: string
      routeDigest: string
      revisionDigest: string
      upstream: { host: string; port: number }
      capsuleId: string
      serviceId: string
      expiresAt: string
      revokedAt: string | null
      revocationReason: string | null
    } = ROUTE,
  ) {
    return {
      schema: 'stateport.preview-route-receipt/v1',
      receiptId: 'receipt_' + 'c'.repeat(24),
      routeId: route.routeId,
      sequence: 1,
      event,
      actor: 'op-1',
      createdAt: '2026-08-03T10:00:00Z',
      data: {
        routeDigest: route.routeDigest,
        revisionDigest: route.revisionDigest,
        upstream: route.upstream,
        capsuleId: route.capsuleId,
        serviceId: route.serviceId,
        expiresAt: route.expiresAt,
        reason: 'rolled back',
      },
      previousReceiptDigest: null,
      receiptDigest: SHA,
    }
  }

  it('lists routes with derived status', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/preview-routes', jsonResponse({ ok: true, result: { routes: [ROUTE] } })],
    ])
    const client = new HttpPreviewRoutesClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const index = await client.list()
    expect(index.routes).toHaveLength(1)
    expect(index.routes[0].status).toBe('active')
    expect(index.routes[0].upstream.port).toBe(8080)
  })

  it('registers a route with the exact body shape', async () => {
    const fake = makeFakeFetch([
      ['POST', '/v1/preview-routes', (call) => {
        const body = bodyOf(call)
        const route = { ...ROUTE, upstream: { host: '127.0.0.1', port: body.upstreamPort as number } }
        return jsonResponse({ ok: true, result: { ...route, receipt: previewReceipt('registered', route) } })
      }],
    ])
    const client = new HttpPreviewRoutesClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const route = await client.register({ capsuleId: 'capsule_web', serviceId: 'web', revisionDigest: SHA, upstreamPort: 3000, ttlSeconds: 3600 })
    expect(route.upstream.port).toBe(3000)
    const call = fake.callsTo('/v1/preview-routes')[0]
    expect(call.body).toEqual({ capsuleId: 'capsule_web', serviceId: 'web', revisionDigest: SHA, upstreamPort: 3000, ttlSeconds: 3600 })
  })

  it('rejects a preview mutation receipt for the wrong route', async () => {
    const fake = makeFakeFetch([
      ['POST', '/v1/preview-routes', jsonResponse({ ok: true, result: {
        ...ROUTE,
        receipt: { ...previewReceipt('registered'), routeId: 'route_' + 'f'.repeat(24) },
      } })],
    ])
    const client = new HttpPreviewRoutesClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const error = await client.register({ capsuleId: 'capsule_web', serviceId: 'web', revisionDigest: SHA, upstreamPort: 3000, ttlSeconds: 3600 }).catch((value: unknown) => value)
    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).kind).toBe('validation')
  })

  it('rejects preview receipt data that does not bind digest and event fields', async () => {
    const fake = makeFakeFetch([
      ['POST', '/v1/preview-routes', jsonResponse({ ok: true, result: {
        ...ROUTE,
        receipt: {
          ...previewReceipt('registered'),
          data: { ...previewReceipt('registered').data, routeDigest: `sha256:${'b'.repeat(64)}`, revisionDigest: `sha256:${'c'.repeat(64)}` },
        },
      } })],
    ])
    const client = new HttpPreviewRoutesClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const error = await client.register({ capsuleId: 'capsule_web', serviceId: 'web', revisionDigest: SHA, upstreamPort: 3000, ttlSeconds: 3600 }).catch((value: unknown) => value)
    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).kind).toBe('validation')
  })

  it('revokes a route with a reason', async () => {
    const fake = makeFakeFetch([
      ['POST', '/v1/preview-routes/' + ROUTE.routeId + '/revoke', (call) => {
        const route = { ...ROUTE, revokedAt: '2026-08-03T12:00:00Z', revocationReason: bodyOf(call).reason as string, status: 'revoked' as const }
        return jsonResponse({ ok: true, result: { ...route, receipt: previewReceipt('revoked', route) } })
      }],
    ])
    const client = new HttpPreviewRoutesClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const route = await client.revoke(ROUTE.routeId, { reason: 'rolled back', expectedRouteDigest: ROUTE.routeDigest })
    expect(route.status).toBe('revoked')
    expect(route.revocationReason).toBe('rolled back')
    const call = fake.callsTo('/revoke')[0]
    expect(call.body).toEqual({ reason: 'rolled back', expectedRouteDigest: ROUTE.routeDigest })
  })

  it('atomically rewrites a route to a new revision and port', async () => {
    const newDigest = `sha256:${'b'.repeat(64)}`
    const fake = makeFakeFetch([
      ['POST', '/v1/preview-routes/' + ROUTE.routeId + '/rewrite', (call) => {
        const body = bodyOf(call)
        const route = { ...ROUTE, revisionDigest: body.revisionDigest as string, upstream: { host: '127.0.0.1', port: body.upstreamPort as number } }
        return jsonResponse({ ok: true, result: { ...route, receipt: previewReceipt('rewritten', route) } })
      }],
    ])
    const client = new HttpPreviewRoutesClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const route = await client.rewrite(ROUTE.routeId, { revisionDigest: newDigest, upstreamPort: 4000, expectedRouteDigest: ROUTE.routeDigest })
    expect(route.revisionDigest).toBe(newDigest)
    expect(route.upstream.port).toBe(4000)
    const call = fake.callsTo('/rewrite')[0]
    expect(call.body).toEqual({ revisionDigest: newDigest, upstreamPort: 4000, expectedRouteDigest: ROUTE.routeDigest })
  })

  it.each(['https://attacker.invalid/', '//attacker.invalid/', '/session', '/preview/other/web/'])('rejects unbound preview navigation %s', async (previewPath) => {
    const fake = makeFakeFetch([
      ['GET', '/v1/preview-routes', jsonResponse({ ok: true, result: { routes: [{ ...ROUTE, previewPath }] } })],
    ])
    const client = new HttpPreviewRoutesClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    await expect(client.list()).rejects.toBeInstanceOf(ClientError)
  })

  it('validates the route document (rejects an unknown schema)', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/preview-routes', jsonResponse({ ok: true, result: { routes: [{ ...ROUTE, schema: 'something.else/v9' }] } })],
    ])
    const client = new HttpPreviewRoutesClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const error = await client.list().catch((value: unknown) => value)
    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).kind).toBe('validation')
  })
})

describe('DigestApproval', () => {
  it('caches the actor identity across calls', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/status', jsonResponse(STATUS_OK)],
    ])
    const transport = new HttpTransport({ fetchFn: fake.fetchFn })
    const approval = new DigestApproval(transport)
    const a1 = await approval.build(SHA)
    const a2 = await approval.build(`sha256:${'b'.repeat(64)}`)
    expect(a1.actorId).toBe('op-1')
    expect(a2.actorId).toBe('op-1')
    expect(a2.proposalDigest).toBe(`sha256:${'b'.repeat(64)}`)
    // /v1/status fetched exactly once (cached).
    expect(fake.callsTo('/v1/status')).toHaveLength(1)
  })

  it('fails closed when the status projection carries no actor identity', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/status', jsonResponse({ ok: true, result: { state: 'connected' } })],
    ])
    const approval = new DigestApproval(new HttpTransport({ fetchFn: fake.fetchFn }))
    const error = await approval.build(SHA).catch((value: unknown) => value)
    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).kind).toBe('validation')
  })
})
