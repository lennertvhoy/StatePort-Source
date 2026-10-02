/**
 * HTTP domain clients — platform deployments, standing authority, installed
 * updater, and preview routes.
 *
 * These are operator-only host-state projections. Honesty rules:
 * - Every read validates the structural envelope (formatVersion + the fields
 *   the UI renders) and passes the rest through, so a richer backend stays
 *   visible without the client inventing a second authority.
 * - Digest-bound mutations (apply / restart / remove / revoke / pause / unpause /
 *   updater policy / updater rollback) resolve the local actor identity from
 *   `/v1/status` and send `approval: {decision, actorId, proposalDigest}`.
 * - A `409 *_state_unavailable` (no durable host state) and
 *   `409 approval_digest_mismatch` (stale review) surface as honest
 *   ClientErrors; the UI shows its real state instead of fake controls.
 * - Updater rollback *apply* is never exposed: the backend returns
 *   `applyBoundary: 'installed-authority-cli'` and the UI must show that as a
 *   limitation, not a working apply button.
 */
import { z } from 'zod'

import type {
  AuthorityClient,
  PlatformDeploymentsClient,
  PreviewRoutesClient,
  UpdaterClient,
} from '../client'
import type {
  AuthorityGrantDetail,
  AuthorityIndex,
  AuthorityGrantsIndex,
  AuthorityProfileIndex,
  PlatformDeploymentDetail,
  PlatformDeploymentIndex,
  PlatformDeploymentMutationResult,
  PlatformDeploymentPlanResult,
  PreviewRouteMutation,
  PreviewRouteIndex,
  UpdaterPolicyProjection,
  UpdaterRollbackPlanResult,
  UpdaterRollbackProjection,
  UpdaterStatus,
} from '../types'
import { ClientError } from '../types'
import { endpoints } from './endpoints'
import { HttpTransport } from './transport'

const unknownPayload = z.unknown()
const sha256Digest = z.string().regex(/^sha256:[0-9a-f]{64}$/)
const routeIdSchema = z.string().regex(/^route_[0-9a-f]{24}$/)

const authorityReceiptSchema = z
  .object({
    schema: z.literal('stateport.authority-action-receipt/v1'),
    receiptId: z.string().regex(/^authority_receipt_[0-9a-f]{32}$/),
    requestId: z.string().regex(/^authority_request_[0-9a-f]{32}$/),
    action: z.string().min(1),
    actorId: z.string().min(1),
    authorizedBy: z.object({
      type: z.string().min(1),
      id: z.string().min(1),
      digest: sha256Digest.nullable(),
    }),
    scope: z.object({ applicationId: z.string().nullable() }).passthrough(),
    decision: z.literal('authorized'),
    result: z.object({
      status: z.enum(['succeeded', 'failed']),
      resource: z.record(z.string(), z.unknown()),
    }).passthrough(),
    decisionDigest: sha256Digest,
    reservation: z.record(z.string(), z.unknown()).nullable(),
    claim: z.record(z.string(), z.unknown()).nullable(),
    receiptDigest: sha256Digest,
  })
  .passthrough()

function requiredSha256Digest(value: string, label: string): string {
  const parsed = sha256Digest.safeParse(value)
  if (!parsed.success) throw new ClientError('validation', `${label} must be sha256:<64hex>`)
  return parsed.data
}

function requiredRouteId(value: string): string {
  const parsed = routeIdSchema.safeParse(value)
  if (!parsed.success) throw new ClientError('validation', 'preview route id is invalid')
  return parsed.data
}

const deploymentSummary = z
  .object({
    deploymentId: z.string().min(1),
    lifecycleState: z.string().min(1),
    driftStatus: z.string().nullable(),
    desiredRevision: sha256Digest.nullable(),
    approvedPlanDigest: sha256Digest.nullable(),
    acceptedRevision: sha256Digest.nullable(),
    observedRevision: sha256Digest.nullable(),
    rollback: z.unknown(),
    retainedDataState: z.unknown(),
    currentOperation: z.string().nullable(),
    serviceHealth: z.unknown(),
  })
  .passthrough()

const deploymentIndexSchema = z
  .object({
    formatVersion: z.literal('stateport.deployment-index/v1'),
    deployments: z.array(deploymentSummary),
  })
  .passthrough()

const deploymentDetailSchema = z
  .object({
    state: z.record(z.string(), z.unknown()),
  })
  .passthrough()

const deploymentStateSchema = z
  .object({
    deploymentId: z.string().min(1),
    lifecycleState: z.string().min(1),
  })
  .passthrough()

const deploymentMutationSchema = z
  .object({
    state: deploymentStateSchema,
    authorityReceipt: authorityReceiptSchema.extend({
      result: z.object({
        status: z.literal('succeeded'),
        resource: z.record(z.string(), z.unknown()),
      }).passthrough(),
    }),
  })
  .passthrough()

const deploymentPlanSchema = z
  .object({
    planDigest: sha256Digest,
    authorityReceipt: authorityReceiptSchema.extend({
      result: z.object({
        status: z.literal('succeeded'),
        resource: z.record(z.string(), z.unknown()),
      }).passthrough(),
    }),
  })
  .passthrough()

const deploymentLogsSchema = z
  .object({
    deploymentId: z.string().min(1),
    logs: z.record(z.string(), z.string()),
    authorityReceipt: authorityReceiptSchema.extend({
      result: z.object({
        status: z.literal('succeeded'),
        resource: z.record(z.string(), z.unknown()),
      }).passthrough(),
    }),
  })
  .passthrough()

const updaterStatusSchema = z
  .object({
    schema: z.literal('stateport.update-status/v1'),
    sequence: z.number().int().nonnegative(),
    phase: z.string().min(1),
    installationId: z.string().min(1),
    policy: z.record(z.string(), z.unknown()),
    current: z.record(z.string(), z.unknown()),
    accepted: z.record(z.string(), z.unknown()),
    retainedPredecessor: z.record(z.string(), z.unknown()).nullable(),
    stagedSuccessor: z.record(z.string(), z.unknown()).nullable(),
    failedSuccessorEvidence: z.record(z.string(), z.unknown()).nullable(),
    lastReceipt: z.string().min(1).nullable(),
    updatedAt: z.string().min(1),
  })
  .passthrough()

const updaterPolicyMutationSchema = updaterStatusSchema.extend({
  receipt: authorityReceiptSchema.extend({
    result: z.object({
      status: z.literal('succeeded'),
      resource: z.record(z.string(), z.unknown()),
    }).passthrough(),
  }),
}).superRefine((value, ctx) => {
  if (value.receipt.action !== 'modify_update_policy') {
    ctx.addIssue({ code: 'custom', path: ['receipt', 'action'], message: 'updater policy receipt action is not bound' })
  }
})

const authorityProfileSchema = z
  .object({
    formatVersion: z.literal('stateport.authority-profile-index/v1'),
    schema: z.string().min(1),
    defaultProfile: z.string().min(1),
    policyDigest: sha256Digest,
    actionPolicies: z.record(z.string(), z.record(z.string(), z.unknown())),
    profiles: z.record(z.string(), z.record(z.string(), z.unknown())),
    hardDeny: z.array(z.string()),
    mergeRequirements: z.array(z.string()),
    subagentDefaultDeny: z.array(z.string()),
    escalationConditions: z.array(z.unknown()),
  })
  .passthrough()

const authorityGrantRow = z
  .object({
    grantId: z.string().min(1),
    grantDigest: sha256Digest,
    status: z.enum([
      'active',
      'revoked',
      'policy_unbound',
      'policy_changed',
      'parent_inactive',
      'expired',
      'consumed',
      'budget_exhausted',
    ]),
  })
  .passthrough()

const authorityGrantsSchema = z
  .object({
    grants: z.array(authorityGrantRow),
    paused: z.boolean(),
  })
  .passthrough()

const authorityGrantDetailSchema = z
  .object({
    grant: authorityGrantRow,
    paused: z.boolean(),
  })
  .passthrough()

const authorityIndexSchema = z
  .object({
    schema: z.literal('stateport.authority-index/v1'),
    repository: z.record(z.string(), z.unknown()),
    policy: authorityProfileSchema,
    defaultProfile: z.string().min(1),
    policyDigest: sha256Digest,
    control: z
      .object({
        paused: z.boolean(),
        controlDigest: sha256Digest,
        revision: z.number().int().nonnegative(),
      })
      .passthrough(),
    activeGrants: z.array(authorityGrantRow),
    inactiveGrants: z.array(authorityGrantRow),
    revisions: z
      .object({
        indexRevision: sha256Digest,
        controlRevision: z.number().int().nonnegative(),
        grantRevisions: z.record(z.string(), sha256Digest),
      })
      .passthrough(),
    reviewableDigests: z
      .object({
        indexDigest: sha256Digest,
        controlDigest: sha256Digest,
        grantDigests: z.record(z.string(), sha256Digest),
      })
      .passthrough(),
  })
  .passthrough()
  .superRefine((value, ctx) => {
    if (value.policy.policyDigest !== value.policyDigest) {
      ctx.addIssue({ code: 'custom', path: ['policyDigest'], message: 'policyDigest does not match policy' })
    }
    if (value.control.controlDigest !== value.reviewableDigests.controlDigest) {
      ctx.addIssue({ code: 'custom', path: ['reviewableDigests', 'controlDigest'], message: 'control digest is not reviewable' })
    }
    if (value.revisions.indexRevision !== value.reviewableDigests.indexDigest) {
      ctx.addIssue({ code: 'custom', path: ['reviewableDigests', 'indexDigest'], message: 'index digest is not reviewable' })
    }
    if (value.revisions.controlRevision !== value.control.revision) {
      ctx.addIssue({ code: 'custom', path: ['revisions', 'controlRevision'], message: 'control revision does not match control' })
    }
    for (const [group, grants] of Object.entries({
      activeGrants: value.activeGrants,
      inactiveGrants: value.inactiveGrants,
    })) {
      grants.forEach((grant, index) => {
        const reviewed = value.reviewableDigests.grantDigests[grant.grantId]
        const revision = value.revisions.grantRevisions[grant.grantId]
        if (reviewed !== grant.grantDigest) {
          ctx.addIssue({ code: 'custom', path: [group, index, 'grantDigest'], message: 'grant digest is not reviewable' })
        }
        if (revision !== grant.grantDigest) {
          ctx.addIssue({ code: 'custom', path: ['revisions', 'grantRevisions', grant.grantId], message: 'grant revision does not match grant' })
        }
      })
    }
    const activeIds = value.activeGrants.map((grant) => grant.grantId)
    const inactiveIds = value.inactiveGrants.map((grant) => grant.grantId)
    const allIds = [...activeIds, ...inactiveIds]
    if (new Set(allIds).size !== allIds.length) {
      ctx.addIssue({ code: 'custom', path: ['activeGrants'], message: 'authority grant ids must be unique across partitions' })
    }
    value.activeGrants.forEach((grant, index) => {
      if (grant.status !== 'active') {
        ctx.addIssue({ code: 'custom', path: ['activeGrants', index, 'status'], message: 'active grant partition contains an inactive grant' })
      }
    })
    value.inactiveGrants.forEach((grant, index) => {
      if (grant.status === 'active') {
        ctx.addIssue({ code: 'custom', path: ['inactiveGrants', index, 'status'], message: 'inactive grant partition contains an active grant' })
      }
    })
    for (const [label, mapping] of Object.entries({
      grantRevisions: value.revisions.grantRevisions,
      grantDigests: value.reviewableDigests.grantDigests,
    })) {
      if (Object.keys(mapping).some((grantId) => !allIds.includes(grantId)) || Object.keys(mapping).length !== allIds.length) {
        ctx.addIssue({ code: 'custom', path: [label], message: 'authority grant digest map keys must exactly match grant partitions' })
      }
    }
  })

const authorityRevocationSchema = z
  .object({
    schema: z.literal('stateport.authority-revocation/v1'),
    grantId: z.string().min(1),
    grantDigest: sha256Digest,
    actorId: z.string().min(1),
    ownerDirectiveId: z.string().min(1),
    reason: z.string().min(1),
    revokedAt: z.string().min(1),
    revocationDigest: sha256Digest,
  })
  .passthrough()

const authorityPauseMutationSchema = z
  .object({
    control: z.record(z.string(), z.unknown()),
    receipt: authorityReceiptSchema.extend({
      result: z.object({
        status: z.literal('succeeded'),
        resource: z.record(z.string(), z.unknown()),
      }).passthrough(),
    }),
    receiptId: z.string().min(1),
    receiptDigest: sha256Digest,
  })
  .passthrough()
  .superRefine((value, ctx) => {
    if (value.receipt.receiptId !== value.receiptId) {
      ctx.addIssue({ code: 'custom', path: ['receiptId'], message: 'receiptId does not match receipt' })
    }
    if (value.receipt.receiptDigest !== value.receiptDigest) {
      ctx.addIssue({ code: 'custom', path: ['receiptDigest'], message: 'receiptDigest does not match receipt' })
    }
    const resource = value.receipt.result.resource
    if (
      value.receipt.action !== 'modify_authority_policy'
      || value.receipt.actorId !== value.control.actorId
      || value.receipt.authorizedBy.type !== 'owner_directive'
      || value.receipt.authorizedBy.id !== value.control.ownerDirectiveId
    ) {
      ctx.addIssue({ code: 'custom', path: ['receipt', 'authorizedBy'], message: 'receipt authority does not match control directive' })
    }
    if (resource.paused !== value.control.paused || resource.controlDigest !== value.control.controlDigest) {
      ctx.addIssue({ code: 'custom', path: ['receipt', 'result', 'resource'], message: 'receipt resource does not match control' })
    }
  })

const authorityRevokeMutationSchema = z
  .object({
    revocation: authorityRevocationSchema,
    revokedGrantDigest: sha256Digest,
    receipt: authorityReceiptSchema.extend({
      result: z.object({
        status: z.literal('succeeded'),
        resource: z.record(z.string(), z.unknown()),
      }).passthrough(),
    }),
    receiptId: z.string().min(1),
    receiptDigest: sha256Digest,
  })
  .passthrough()
  .superRefine((value, ctx) => {
    if (value.receipt.receiptId !== value.receiptId) {
      ctx.addIssue({ code: 'custom', path: ['receiptId'], message: 'receiptId does not match receipt' })
    }
    if (value.receipt.receiptDigest !== value.receiptDigest) {
      ctx.addIssue({ code: 'custom', path: ['receiptDigest'], message: 'receiptDigest does not match receipt' })
    }
    const resource = value.receipt.result.resource
    if (
      value.receipt.action !== 'modify_authority_policy'
      || value.receipt.actorId !== value.revocation.actorId
      || value.receipt.authorizedBy.type !== 'owner_directive'
      || value.receipt.authorizedBy.id !== value.revocation.ownerDirectiveId
    ) {
      ctx.addIssue({ code: 'custom', path: ['receipt', 'authorizedBy'], message: 'receipt authority does not match revocation directive' })
    }
    if (resource.grantId !== value.revocation.grantId || resource.revocationDigest !== value.revocation.revocationDigest) {
      ctx.addIssue({ code: 'custom', path: ['receipt', 'result', 'resource'], message: 'receipt resource does not match revocation' })
    }
    if (value.revocation.grantDigest !== value.revokedGrantDigest) {
      ctx.addIssue({ code: 'custom', path: ['revokedGrantDigest'], message: 'revokedGrantDigest does not match revocation' })
    }
  })

const updaterPolicySchema = z
  .object({
    formatVersion: z.literal('stateport.updater-policy/v1'),
    policy: z.record(z.string(), z.unknown()),
    statusDigest: sha256Digest,
  })
  .passthrough()

const updaterRollbackSchema = z
  .object({
    formatVersion: z.literal('stateport.updater-rollback/v1'),
    phase: z.string().min(1),
    pendingPhase: z.string().nullable(),
    retainedPredecessor: z.record(z.string(), z.unknown()).nullable(),
    rollbackAvailable: z.boolean(),
    statusDigest: sha256Digest,
  })
  .passthrough()

const updaterRollbackPlanSchema = z
  .object({
    plan: z
      .object({
        planId: z.string().min(1),
        planDigest: sha256Digest,
        operation: z.string().min(1),
      })
      .passthrough(),
    applyBoundary: z.literal('installed-authority-cli'),
    note: z.string().min(1),
  })
  .passthrough()

const previewRouteSchema = z
  .object({
    schema: z.literal('stateport.preview-route/v1'),
    previewPath: z.string().nullable().optional(),
    routeId: routeIdSchema,
    capsuleId: z.string().min(1),
    serviceId: z.string().min(1),
    revisionDigest: sha256Digest,
    upstream: z.object({ host: z.string().min(1), port: z.number().int().min(1).max(65535) }),
    createdAt: z.string().min(1),
    expiresAt: z.string().min(1),
    revokedAt: z.string().nullable(),
    revocationReason: z.string().nullable(),
    routeDigest: sha256Digest,
    status: z.enum(['active', 'expired', 'revoked']),
  })
  .passthrough()

const previewRouteIndexSchema = z
  .object({
    routes: z.array(previewRouteSchema.superRefine((value, ctx) => {
      if (value.previewPath != null && (value.status !== 'active' || value.previewPath !== `/preview/${encodeURIComponent(value.capsuleId)}/${encodeURIComponent(value.serviceId)}/`)) {
        ctx.addIssue({ code: 'custom', path: ['previewPath'], message: 'preview path does not match gateway route' })
      }
    })),
  })
  .passthrough()

const previewReceiptSchema = z.object({
  schema: z.literal('stateport.preview-route-receipt/v1'),
  receiptId: z.string().regex(/^receipt_[0-9a-f]{24}$/),
  routeId: routeIdSchema,
  sequence: z.number().int().positive(),
  event: z.enum(['registered', 'rewritten', 'revoked']),
  actor: z.string().min(1),
  createdAt: z.string().min(1),
  data: z.record(z.string(), z.unknown()),
  previousReceiptDigest: sha256Digest.nullable(),
  receiptDigest: sha256Digest,
})

const previewMutationSchema = previewRouteSchema.extend({
  receipt: previewReceiptSchema,
}).superRefine((value, ctx) => {
  if (value.previewPath != null && (value.status !== 'active' || value.previewPath !== `/preview/${encodeURIComponent(value.capsuleId)}/${encodeURIComponent(value.serviceId)}/`)) {
    ctx.addIssue({ code: 'custom', path: ['previewPath'], message: 'preview path does not match gateway route' })
  }
  if (value.receipt.routeId !== value.routeId) {
    ctx.addIssue({ code: 'custom', path: ['receipt', 'routeId'], message: 'receipt route does not match route' })
  }
  if (value.receipt.data.routeDigest !== value.routeDigest) {
    ctx.addIssue({ code: 'custom', path: ['receipt', 'data', 'routeDigest'], message: 'receipt route digest does not match route' })
  }
  const dataUpstream = value.receipt.data.upstream
  if (value.receipt.event === 'registered' || value.receipt.event === 'rewritten') {
    if (value.receipt.data.revisionDigest !== value.revisionDigest) {
      ctx.addIssue({ code: 'custom', path: ['receipt', 'data', 'revisionDigest'], message: 'receipt revision does not match route' })
    }
    if (JSON.stringify(dataUpstream) !== JSON.stringify(value.upstream)) {
      ctx.addIssue({ code: 'custom', path: ['receipt', 'data', 'upstream'], message: 'receipt upstream does not match route' })
    }
  }
  if (value.receipt.event === 'registered' && (
    value.receipt.data.capsuleId !== value.capsuleId
    || value.receipt.data.serviceId !== value.serviceId
    || value.receipt.data.expiresAt !== value.expiresAt
  )) {
    ctx.addIssue({ code: 'custom', path: ['receipt', 'data'], message: 'registration receipt fields do not match route' })
  }
  if (value.receipt.event === 'revoked' && (
    value.revokedAt === null || value.receipt.data.reason !== value.revocationReason
  )) {
    ctx.addIssue({ code: 'custom', path: ['receipt', 'data', 'reason'], message: 'revocation receipt fields do not match route' })
  }
})

function bindDeploymentReceipt(
  payload: unknown,
  deploymentId: string,
  grantId: string,
  action: string,
): PlatformDeploymentMutationResult | PlatformDeploymentPlanResult {
  const value = payload as Record<string, unknown>
  const receipt = value.authorityReceipt as Record<string, unknown>
  const authorizedBy = receipt.authorizedBy as Record<string, unknown>
  const scope = receipt.scope as Record<string, unknown>
  if (
    receipt.action !== action
    || receipt.actorId === undefined
    || authorizedBy.type !== 'grant'
    || authorizedBy.id !== grantId
    || scope.applicationId !== deploymentId
    || receipt.decision !== 'authorized'
  ) {
    throw new ClientError('validation', 'authority receipt is not bound to the requested deployment and grant')
  }
  return payload as PlatformDeploymentMutationResult | PlatformDeploymentPlanResult
}

/**
 * Resolve the local operator actor identity from the status projection, then
 * build the exact digest-bound approval body member the contract requires.
 * The actor identity is cached for the life of the client (same as the
 * repository-import client).
 */
export class DigestApproval {
  private actorId: string | null = null
  private readonly transport: HttpTransport

  constructor(transport: HttpTransport) {
    this.transport = transport
  }

  async build(proposalDigest: string): Promise<{
    decision: 'approve'
    actorId: string
    proposalDigest: string
  }> {
    const digest = requiredSha256Digest(proposalDigest, 'proposal digest')
    const actorId = await this.currentActorId()
    return { decision: 'approve', actorId, proposalDigest: digest }
  }

  private async currentActorId(): Promise<string> {
    if (this.actorId) return this.actorId
    const payload = await this.transport.request(endpoints.status, { schema: unknownPayload })
    const wire = z
      .object({ actor: z.object({ actorId: z.string().optional() }).optional() })
      .passthrough()
      .parse(payload)
    const actorId = wire.actor?.actorId
    if (!actorId) {
      throw new ClientError('validation', 'The service status projection carried no actor identity')
    }
    this.actorId = actorId
    return actorId
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Platform deployments
// ─────────────────────────────────────────────────────────────────────────────

export class HttpPlatformDeploymentsClient implements PlatformDeploymentsClient {
  private readonly transport: HttpTransport
  private readonly approval: DigestApproval

  constructor(transport: HttpTransport, approval?: DigestApproval) {
    this.transport = transport
    this.approval = approval ?? new DigestApproval(transport)
  }

  async list(): Promise<PlatformDeploymentIndex> {
    const payload = await this.transport.request(endpoints.deployments, {
      schema: deploymentIndexSchema,
    })
    return payload as unknown as PlatformDeploymentIndex
  }

  async get(deploymentId: string): Promise<PlatformDeploymentDetail> {
    const payload = await this.transport.request(endpoints.deployment(deploymentId), {
      schema: deploymentDetailSchema,
    })
    return payload as unknown as PlatformDeploymentDetail
  }

  async plan(input: {
    project: string
    deploymentId: string
    grantId: string
    sliceId?: string
    rollbackOf?: string
  }): Promise<PlatformDeploymentPlanResult> {
    const body: Record<string, unknown> = {
      project: input.project,
      deploymentId: input.deploymentId,
      grantId: input.grantId,
    }
    if (input.sliceId !== undefined) body.sliceId = input.sliceId
    if (input.rollbackOf !== undefined) body.rollbackOf = requiredSha256Digest(input.rollbackOf, 'rollback revision digest')
    const payload = await this.transport.request(endpoints.deploymentPlan, {
      method: 'POST',
      body,
      schema: deploymentPlanSchema,
    })
    return bindDeploymentReceipt(payload, input.deploymentId, input.grantId, 'plan_deployment') as PlatformDeploymentPlanResult
  }

  async apply(
    deploymentId: string,
    input: { acceptPlanDigest: string; grantId: string; sliceId?: string },
  ): Promise<PlatformDeploymentMutationResult> {
    const acceptPlanDigest = requiredSha256Digest(input.acceptPlanDigest, 'accepted plan digest')
    const approval = await this.approval.build(acceptPlanDigest)
    const body: Record<string, unknown> = {
      acceptPlanDigest,
      grantId: input.grantId,
      approval,
    }
    if (input.sliceId !== undefined) body.sliceId = input.sliceId
    const payload = await this.transport.request(endpoints.deploymentApply(deploymentId), {
      method: 'POST',
      body,
      schema: deploymentMutationSchema,
    })
    return bindDeploymentReceipt(payload, deploymentId, input.grantId, 'apply_deployment') as PlatformDeploymentMutationResult
  }

  async status(
    deploymentId: string,
    input: { grantId: string; sliceId?: string },
  ): Promise<PlatformDeploymentMutationResult> {
    const payload = await this.governedRead(endpoints.deploymentStatus(deploymentId), input, deploymentMutationSchema)
    return bindDeploymentReceipt(payload, deploymentId, input.grantId, 'observe_deployment') as PlatformDeploymentMutationResult
  }

  async logs(
    deploymentId: string,
    input: { grantId: string; sliceId?: string; serviceId?: string; tail?: number },
  ): Promise<PlatformDeploymentMutationResult> {
    const body: Record<string, unknown> = { grantId: input.grantId }
    if (input.sliceId !== undefined) body.sliceId = input.sliceId
    if (input.serviceId !== undefined) body.serviceId = input.serviceId
    if (input.tail !== undefined) body.tail = input.tail
    const payload = await this.transport.request(endpoints.deploymentLogs(deploymentId), {
      method: 'POST',
      body,
      schema: deploymentLogsSchema,
    })
    return bindDeploymentReceipt(payload, deploymentId, input.grantId, 'collect_deployment_logs') as PlatformDeploymentMutationResult
  }

  async restart(
    deploymentId: string,
    input: { grantId: string; proposalDigest: string; sliceId?: string },
  ): Promise<PlatformDeploymentMutationResult> {
    const payload = await this.digestBoundRuntime(endpoints.deploymentRestart(deploymentId), input)
    return bindDeploymentReceipt(payload, deploymentId, input.grantId, 'restart_deployment') as PlatformDeploymentMutationResult
  }

  async remove(
    deploymentId: string,
    input: { grantId: string; proposalDigest: string; sliceId?: string },
  ): Promise<PlatformDeploymentMutationResult> {
    const payload = await this.digestBoundRuntime(endpoints.deploymentRemove(deploymentId), input)
    return bindDeploymentReceipt(payload, deploymentId, input.grantId, 'remove_deployment_runtime') as PlatformDeploymentMutationResult
  }

  async planPurge(
    deploymentId: string,
    input: { grantId: string; sliceId?: string },
  ): Promise<PlatformDeploymentPlanResult> {
    const payload = await this.governedRead(endpoints.deploymentPurgePlan(deploymentId), input, deploymentPlanSchema)
    return bindDeploymentReceipt(payload, deploymentId, input.grantId, 'plan_deployment') as PlatformDeploymentPlanResult
  }

  private async governedRead(
    path: string,
    input: { grantId: string; sliceId?: string },
    schema: z.ZodTypeAny,
  ): Promise<PlatformDeploymentMutationResult> {
    const body: Record<string, unknown> = { grantId: input.grantId }
    if (input.sliceId !== undefined) body.sliceId = input.sliceId
    return this.transport.request(path, {
      method: 'POST',
      body,
      schema,
    }) as Promise<PlatformDeploymentMutationResult>
  }

  /**
   * Restart/remove are digest-bound to the pending authority run id. The
   * server resolves the expected run id itself (`peek_authority_run_id`) and
   * binds the approval to that value; the client sends the canonical approval
   * member and the server re-checks the exact value. If no pending run exists
   * the server refuses typed, which surfaces as an honest ClientError.
   */
  private async digestBoundRuntime(
    path: string,
    input: { grantId: string; proposalDigest: string; sliceId?: string },
  ): Promise<PlatformDeploymentMutationResult> {
    const approval = await this.approval.build(input.proposalDigest)
    const body: Record<string, unknown> = { grantId: input.grantId, approval }
    if (input.sliceId !== undefined) body.sliceId = input.sliceId
    return this.transport.request(path, {
      method: 'POST',
      body,
      schema: deploymentMutationSchema,
    }) as Promise<PlatformDeploymentMutationResult>
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Standing authority
// ─────────────────────────────────────────────────────────────────────────────

export class HttpAuthorityClient implements AuthorityClient {
  private readonly transport: HttpTransport
  private readonly approval: DigestApproval

  constructor(transport: HttpTransport, approval?: DigestApproval) {
    this.transport = transport
    this.approval = approval ?? new DigestApproval(transport)
  }

  async getIndex(): Promise<AuthorityIndex> {
    const payload = await this.transport.request(endpoints.authorityIndex, {
      schema: authorityIndexSchema,
    })
    return payload as unknown as AuthorityIndex
  }

  async listProfiles(): Promise<AuthorityProfileIndex> {
    const payload = await this.transport.request(endpoints.authorityProfiles, {
      schema: authorityProfileSchema,
    })
    return payload as unknown as AuthorityProfileIndex
  }

  async listGrants(): Promise<AuthorityGrantsIndex> {
    const payload = await this.transport.request(endpoints.authorityGrants, {
      schema: authorityGrantsSchema,
    })
    return payload as unknown as AuthorityGrantsIndex
  }

  async getGrant(grantId: string): Promise<AuthorityGrantDetail> {
    const payload = await this.transport.request(endpoints.authorityGrant(grantId), {
      schema: authorityGrantDetailSchema,
    })
    return payload as unknown as AuthorityGrantDetail
  }

  async revokeGrant(
    grantId: string,
    input: { ownerDirectiveId: string; reason: string; grantDigest: string },
  ): Promise<{ revocation: unknown; revokedGrantDigest: string; receiptId: string; receiptDigest: string }> {
    const grantDigest = requiredSha256Digest(input.grantDigest, 'authority grant digest')
    const approval = await this.approval.build(grantDigest)
    const payload = await this.transport.request(endpoints.authorityGrantRevoke(grantId), {
      method: 'POST',
      body: {
        ownerDirectiveId: input.ownerDirectiveId,
        reason: input.reason,
        grantDigest,
        approval,
      },
      schema: authorityRevokeMutationSchema,
    })
    return payload as unknown as { revocation: unknown; revokedGrantDigest: string; receiptId: string; receiptDigest: string }
  }

  async setPaused(input: {
    paused: boolean
    ownerDirectiveId: string
    reason: string
    controlDigest: string
  }): Promise<{ control: unknown; receiptId: string; receiptDigest: string }> {
    const controlDigest = requiredSha256Digest(input.controlDigest, 'authority control digest')
    const body: Record<string, unknown> = {
      paused: input.paused,
      ownerDirectiveId: input.ownerDirectiveId,
      reason: input.reason,
      controlDigest,
    }
    // Every pause transition is an authority mutation and requires approval.
    body.approval = await this.approval.build(controlDigest)
    const payload = await this.transport.request(endpoints.authorityPause, {
      method: 'POST',
      body,
      schema: authorityPauseMutationSchema,
    })
    return payload as unknown as { control: unknown; receiptId: string; receiptDigest: string }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Installed updater
// ─────────────────────────────────────────────────────────────────────────────

export class HttpUpdaterClient implements UpdaterClient {
  private readonly transport: HttpTransport
  private readonly approval: DigestApproval

  constructor(transport: HttpTransport, approval?: DigestApproval) {
    this.transport = transport
    this.approval = approval ?? new DigestApproval(transport)
  }

  async getStatus(): Promise<UpdaterStatus> {
    return this.transport.request(endpoints.updaterStatus, {
      schema: updaterStatusSchema,
    }) as Promise<UpdaterStatus>
  }

  async getPolicy(): Promise<UpdaterPolicyProjection> {
    const payload = await this.transport.request(endpoints.updaterPolicy, {
      schema: updaterPolicySchema,
    })
    return payload as unknown as UpdaterPolicyProjection
  }

  async getRollback(): Promise<UpdaterRollbackProjection> {
    const payload = await this.transport.request(endpoints.updaterRollback, {
      schema: updaterRollbackSchema,
    })
    return payload as unknown as UpdaterRollbackProjection
  }

  async setPolicy(input: {
    policy: Record<string, unknown>
    expectedStatusDigest: string
  }): Promise<UpdaterStatus> {
    const expectedStatusDigest = requiredSha256Digest(input.expectedStatusDigest, 'expected status digest')
    const approval = await this.approval.build(expectedStatusDigest)
    const payload = await this.transport.request(endpoints.updaterPolicy, {
      method: 'POST',
      body: {
        policy: input.policy,
        expectedStatusDigest,
        approval,
      },
      schema: updaterPolicyMutationSchema,
    })
    if ((payload as UpdaterStatus & { receipt: { actorId: string } }).receipt.actorId !== approval.actorId) {
      throw new ClientError('validation', 'updater policy receipt actor is not bound to approval')
    }
    return payload as UpdaterStatus
  }

  async planRollback(input: { expectedStatusDigest: string }): Promise<UpdaterRollbackPlanResult> {
    const expectedStatusDigest = requiredSha256Digest(input.expectedStatusDigest, 'expected status digest')
    const approval = await this.approval.build(expectedStatusDigest)
    const payload = await this.transport.request(endpoints.updaterRollback, {
      method: 'POST',
      body: {
        expectedStatusDigest,
        approval,
      },
      schema: updaterRollbackPlanSchema,
    })
    return payload as unknown as UpdaterRollbackPlanResult
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Preview routes
// ─────────────────────────────────────────────────────────────────────────────

export class HttpPreviewRoutesClient implements PreviewRoutesClient {
  private readonly transport: HttpTransport

  constructor(transport: HttpTransport) {
    this.transport = transport
  }

  async list(): Promise<PreviewRouteIndex> {
    const payload = await this.transport.request(endpoints.previewRoutes, {
      schema: previewRouteIndexSchema,
    })
    return payload as unknown as PreviewRouteIndex
  }

  async register(input: {
    capsuleId: string
    serviceId: string
    revisionDigest: string
    upstreamPort: number
    ttlSeconds: number
  }): Promise<PreviewRouteMutation> {
    const revisionDigest = requiredSha256Digest(input.revisionDigest, 'preview revision digest')
    const payload = await this.transport.request(endpoints.previewRoutes, {
      method: 'POST',
      body: {
        capsuleId: input.capsuleId,
        serviceId: input.serviceId,
        revisionDigest,
        upstreamPort: input.upstreamPort,
        ttlSeconds: input.ttlSeconds,
      },
      schema: previewMutationSchema,
    })
    if ((payload as PreviewRouteMutation).receipt.event !== 'registered') {
      throw new ClientError('validation', 'preview registration receipt event is invalid')
    }
    return payload as unknown as PreviewRouteMutation
  }

  async revoke(routeId: string, input: { reason: string; expectedRouteDigest: string }): Promise<PreviewRouteMutation> {
    routeId = requiredRouteId(routeId)
    const payload = await this.transport.request(endpoints.previewRouteRevoke(routeId), {
      method: 'POST',
      body: { reason: input.reason, expectedRouteDigest: requiredSha256Digest(input.expectedRouteDigest, 'expected preview route digest') },
      schema: previewMutationSchema,
    })
    if ((payload as PreviewRouteMutation).receipt.event !== 'revoked') {
      throw new ClientError('validation', 'preview revocation receipt event is invalid')
    }
    return payload as unknown as PreviewRouteMutation
  }

  async rewrite(
    routeId: string,
    input: { revisionDigest: string; upstreamPort: number; expectedRouteDigest: string },
  ): Promise<PreviewRouteMutation> {
    routeId = requiredRouteId(routeId)
    const revisionDigest = requiredSha256Digest(input.revisionDigest, 'preview revision digest')
    const payload = await this.transport.request(endpoints.previewRouteRewrite(routeId), {
      method: 'POST',
      body: {
        revisionDigest,
        upstreamPort: input.upstreamPort,
        expectedRouteDigest: requiredSha256Digest(input.expectedRouteDigest, 'expected preview route digest'),
      },
      schema: previewMutationSchema,
    })
    if ((payload as PreviewRouteMutation).receipt.event !== 'rewritten') {
      throw new ClientError('validation', 'preview rewrite receipt event is invalid')
    }
    return payload as unknown as PreviewRouteMutation
  }
}
