/**
 * HTTP domain client — sanctioned execution-host control-plane proxy.
 *
 * This is the ONLY browser path to the confined execution-host daemon.  The
 * backend proxy validates session + CSRF (mutations), the grant binding, and
 * the daemon receipt; this client only renders the bounded result.  No
 * socket path, container id, or host identity is ever surfaced to the UI
 * beyond the bounded daemon receipt fields.
 */
import { z } from 'zod'

import type {
  ExecutionHostClient,
  ExecutionHostReceiptIndex,
  ExecutionHostResult,
  ExecutionHostStatus,
  WorkspaceAuthorityProjection,
  WorkspaceAuthorityPreparation,
  WorkspaceAuthorityRequestInput,
} from '../client'
import { ClientError } from '../types'
import { endpoints } from './endpoints'
import { HttpTransport } from './transport'

const unknownPayload = z.unknown()

function unavailable(what: string, detail: string): ClientError {
  return new ClientError('unavailable', what, { detail })
}

function asResult(payload: unknown): ExecutionHostResult {
  const record = (payload ?? {}) as {
    accepted?: boolean
    result?: Record<string, unknown> | unknown[] | null
    observed?: Record<string, unknown>
    refusal?: { reason?: string; detail?: string }
    receipt?: ExecutionHostResult['receipt']
    operationId?: string
  }
  return {
    operationId: typeof record.operationId === 'string' ? record.operationId : undefined,
    accepted: record.accepted === true,
    result: record.result ?? undefined,
    observed: record.observed ?? undefined,
    refusal: record.refusal ?? undefined,
    receipt: record.receipt ?? undefined,
  }
}

function asStatus(payload: unknown): ExecutionHostStatus {
  const record = (payload ?? {}) as { executionHost?: unknown }
  const host = (record.executionHost ?? payload ?? {}) as Record<string, unknown>
  const status = host.status === 'available' ? 'available' : 'unavailable'
  return {
    status,
    reason: typeof host.reason === 'string' ? host.reason : undefined,
    detail: typeof host.detail === 'string' ? host.detail : undefined,
    contractVersion:
      typeof host.contractVersion === 'number' ? host.contractVersion : undefined,
    engine: typeof host.engine === 'string' ? host.engine : null,
    engineVersion: typeof host.engineVersion === 'string' ? host.engineVersion : null,
    peerIdentity:
      host.peerIdentity && typeof host.peerIdentity === 'object'
        ? (host.peerIdentity as ExecutionHostStatus['peerIdentity'])
        : undefined,
    workloadKinds:
      Array.isArray(host.workloadKinds) && host.workloadKinds.every((k) => typeof k === 'string')
        ? (host.workloadKinds as string[])
        : undefined,
    grantId: typeof host.grantId === 'string' ? host.grantId : undefined,
    grantBound: host.grantBound === true,
  }
}

const digest = z.string().regex(/^sha256:[a-f0-9]{64}$/)
const timestamp = z.string().datetime()
const sourceInventoryEntry = z.object({
  path: z.string().min(1).max(4096),
  mode: z.enum(['100644', '100755']),
  contentDigest: digest,
}).strict().superRefine((entry, context) => {
  if (entry.path.includes('\\') || entry.path.includes('\x00') || entry.path.startsWith('/')
    || entry.path.split('/').includes('.git')
    || entry.path.split('/').some(part => part === '' || part === '.' || part === '..')
    || new TextEncoder().encode(entry.path).byteLength > 4096) {
    context.addIssue({ code: 'custom', message: 'Source inventory path is unsafe' })
  }
})
const sourceArchive = z.object({
  formatVersion: z.literal('stateport.deployment-context-archive/v1'),
  archiveDigest: digest,
  archiveBytes: z.number().int().positive().max(576 * 1024 * 1024),
  contextDigest: digest,
  fileCount: z.number().int().positive().max(10_000),
}).strict()
const workspaceAuthoritySource = z.object({
  baseRevision: z.string().regex(/^[a-f0-9]{40}$/),
  // The reviewed commit witness is carried as bounded base64; its digest is
  // authenticated by the server and is deliberately not recomputed here.
  commitObject: z.string().regex(/^[A-Za-z0-9+/]+={0,2}$/).max(87_384).refine(value => {
    try {
      const decoded = atob(value)
      return decoded.length > 0 && decoded.length <= 65_536 && btoa(decoded) === value
    } catch {
      return false
    }
  }, 'Commit object witness must be canonical base64 within its decoded bound'),
  sourceInventory: z.array(sourceInventoryEntry).min(1).max(10_000),
  sourceArchive,
  descriptorDigest: digest,
}).strict().superRefine((source, context) => {
  if (source.sourceArchive.fileCount !== source.sourceInventory.length) {
    context.addIssue({ code: 'custom', message: 'Source archive file count differs from inventory' })
  }
  const paths = new Set(source.sourceInventory.map(entry => entry.path))
  if (paths.size !== source.sourceInventory.length) context.addIssue({ code: 'custom', message: 'Source inventory contains duplicate paths' })
  for (const path of paths) {
    const parts = path.split('/')
    for (let index = 1; index < parts.length; index += 1) {
      if (paths.has(parts.slice(0, index).join('/'))) context.addIssue({ code: 'custom', message: 'Source inventory contains a file-directory collision' })
    }
  }
  if (JSON.stringify(source).length > 1024 * 1024) context.addIssue({ code: 'custom', message: 'Reviewed source exceeds its bound' })
})
const profile = z.object({
  image: z.object({ reference: z.string().regex(/@sha256:[a-f0-9]{64}$/) }),
  parameters: z.object({ cpuQuotaPercent: z.number().int().positive(), diskMaxBytes: z.number().int().positive(), networkMode: z.literal('none'), shell: z.tuple([z.literal('/bin/sh')]).optional() }),
  resources: z.object({ memoryMaxBytes: z.number().int().positive(), pidsMax: z.number().int().positive() }),
  timeoutSeconds: z.number().int().positive(), outputByteBound: z.number().int().positive(),
})
const issuerCommon = {
  issuerContextDigest: digest,
  profileDigest: digest,
  grantExpiresAtLimit: timestamp,
  operations: z.array(z.string()).max(32).optional(),
  profile,
}
const emptyIssuer = z.object({
  ...issuerCommon,
  profileId: z.enum(['stateport.empty-workspace/v1', 'stateport.empty-workspace-terminal/v1']),
  sourceMode: z.literal('empty'),
}).strict()
const reviewedIssuer = z.object({
  ...issuerCommon,
  profileId: z.literal('stateport.reviewed-source-workspace-terminal/v1'),
  sourceMode: z.literal('reviewed-commit'),
}).strict()
const authorityProjection = z.object({
  instanceId: z.string().min(1), applicationId: z.string().min(1), displayName: z.string(),
  catalogIdentityDigest: digest, status: z.enum(['available', 'issued', 'unavailable']),
  refusal: z.object({ reason: z.string(), detail: z.string() }).optional(),
  issuer: z.union([emptyIssuer, reviewedIssuer]).optional(),
  issued: z.record(z.string(), z.unknown()).optional(),
}).superRefine((value, context) => {
  const issuer = value.issuer
  if (!issuer) return
  const terminalOps = ['cancel', 'closeTerminal', 'createWorkload', 'execWorkload', 'listWorkloads', 'logs', 'openTerminal', 'removeWorkload', 'resizeTerminal', 'signalTerminal', 'start', 'status', 'stop']
  if (issuer.profileId === 'stateport.empty-workspace-terminal/v1') {
    if (!issuer.operations || JSON.stringify([...issuer.operations].sort()) !== JSON.stringify(terminalOps)
      || JSON.stringify(issuer.profile.parameters.shell) !== JSON.stringify(['/bin/sh'])) context.addIssue({ code: 'custom', message: 'The explicit terminal profile is incomplete' })
  } else if (issuer.profileId === 'stateport.reviewed-source-workspace-terminal/v1') {
    if (issuer.sourceMode !== 'reviewed-commit'
      || !issuer.operations || JSON.stringify([...issuer.operations].sort()) !== JSON.stringify(terminalOps)
      || JSON.stringify(issuer.profile.parameters.shell) !== JSON.stringify(['/bin/sh'])) {
      context.addIssue({ code: 'custom', message: 'The reviewed source terminal profile is incomplete' })
    }
  } else if (issuer.operations !== undefined) context.addIssue({ code: 'custom', message: 'Legacy workspace profiles cannot imply terminal authority' })
})
const authorityRequestV1 = z.object({
  formatVersion: z.literal('stateport.workspace-authority-request/v1'),
  instanceId: z.string().min(1), applicationId: z.string().min(1), catalogIdentityDigest: digest,
  issuerContextDigest: digest, profileDigest: digest, sourceMode: z.literal('empty'),
  createdAt: timestamp, expiresAt: timestamp, grantExpiresAt: timestamp, requestDigest: digest,
}).strict()
const authorityRequestV2 = z.object({
  formatVersion: z.literal('stateport.workspace-authority-request/v2'),
  instanceId: z.string().min(1), applicationId: z.string().min(1), catalogIdentityDigest: digest,
  issuerContextDigest: digest, profileDigest: digest, sourceMode: z.literal('reviewed-commit'),
  source: workspaceAuthoritySource, sourceDigest: digest,
  createdAt: timestamp, expiresAt: timestamp, grantExpiresAt: timestamp, requestDigest: digest,
}).strict()
const authorityRequest = z.discriminatedUnion('formatVersion', [authorityRequestV1, authorityRequestV2])

export class HttpExecutionHostClient implements ExecutionHostClient {
  private readonly transport: HttpTransport

  constructor(transport: HttpTransport) {
    this.transport = transport
  }

  async workspaceAuthority(instanceId: string): Promise<WorkspaceAuthorityProjection> {
    const result = await this.transport.request(`/v1/execution-host/workspaces/${encodeURIComponent(instanceId)}/authority`, { schema: authorityProjection })
    if (result.instanceId !== instanceId) throw unavailable('Workspace authority identity changed', 'Refresh the exact application.')
    return result
  }

  async prepareWorkspaceAuthority(instanceId: string, request: WorkspaceAuthorityRequestInput): Promise<WorkspaceAuthorityPreparation> {
    const result = await this.transport.request(`/v1/execution-host/workspaces/${encodeURIComponent(instanceId)}/authority/prepare`, {
      method: 'POST', body: request, schema: z.object({ request: authorityRequest, review: authorityProjection }),
    })
    if (result.request.instanceId !== instanceId || result.review.instanceId !== instanceId
      || result.request.profileDigest !== request.profileDigest || result.request.sourceMode !== request.sourceMode
      || result.request.grantExpiresAt !== request.grantExpiresAt
      || result.request.catalogIdentityDigest !== result.review.catalogIdentityDigest
      || result.request.applicationId !== result.review.applicationId
      || result.request.issuerContextDigest !== result.review.issuer?.issuerContextDigest
      || result.request.profileDigest !== result.review.issuer?.profileDigest) {
      throw unavailable('Workspace authority review changed', 'Refresh and prepare a new request.')
    }
    if (request.sourceMode === 'empty') {
      if (result.request.formatVersion !== 'stateport.workspace-authority-request/v1' || result.review.issuer?.sourceMode !== 'empty') {
        throw unavailable('Workspace authority review changed', 'Refresh and prepare a new request.')
      }
    } else if (result.request.formatVersion !== 'stateport.workspace-authority-request/v2'
      || result.review.issuer?.sourceMode !== 'reviewed-commit'
      || result.request.source === undefined
      || typeof result.request.sourceDigest !== 'string') {
      throw unavailable('Workspace source review changed', 'Refresh and prepare a new request.')
    }
    return result
  }

  async status(): Promise<ExecutionHostStatus> {
    const payload = await this.transport.request(endpoints.executionHost, {
      schema: unknownPayload,
    })
    return asStatus(payload)
  }

  async listWorkloads(): Promise<ExecutionHostResult> {
    const payload = await this.transport.request(endpoints.executionHostWorkloads, {
      schema: unknownPayload,
    })
    return asResult(payload)
  }

  async listReceipts(): Promise<ExecutionHostReceiptIndex> {
    const payload = await this.transport.request(endpoints.executionHostReceipts, {
      schema: unknownPayload,
    })
    return z.object({
      receipts: z.array(z.object({
        receiptId: z.string().min(1), receiptType: z.string().min(1),
        action: z.string().min(1), status: z.string().min(1),
        createdAt: z.string().min(1), sourceKind: z.string().min(1),
        payloadDigest: z.string().min(1),
      })).max(50),
    }).parse(payload)
  }

  async workloadStatus(workloadId: string): Promise<ExecutionHostResult> {
    const payload = await this.transport.request(
      endpoints.executionHostWorkloadStatus(workloadId),
      { schema: unknownPayload },
    )
    return asResult(payload)
  }

  async workloadLogs(workloadId: string): Promise<ExecutionHostResult> {
    const payload = await this.transport.request(
      endpoints.executionHostWorkloadLogs(workloadId),
      { schema: unknownPayload },
    )
    return asResult(payload)
  }

  private async mutate(path: string, workloadId: string, argv?: string[]): Promise<ExecutionHostResult> {
    const payload = await this.transport.request(path, {
      method: 'POST',
      body: argv === undefined ? { workloadId } : { workloadId, argv },
      schema: unknownPayload,
    })
    const result = asResult(payload)
    if (!result.accepted && !result.refusal) {
      throw unavailable(
        'The execution host refused the operation',
        'The sanctioned proxy returned no accepted receipt.',
      )
    }
    return result
  }

  async createDefaultWorkload(instanceId?: string, sourceReviewDigest?: string): Promise<ExecutionHostResult> {
    const payload = await this.transport.request(endpoints.executionHostWorkloads, {
      method: 'POST',
      body: instanceId ? { instanceId, ...(sourceReviewDigest ? { sourceReviewDigest } : {}) } : {},
      schema: unknownPayload,
    })
    return asResult(payload)
  }

  startWorkload(workloadId: string): Promise<ExecutionHostResult> {
    return this.mutate(endpoints.executionHostWorkloadStart, workloadId)
  }

  stopWorkload(workloadId: string): Promise<ExecutionHostResult> {
    return this.mutate(endpoints.executionHostWorkloadStop, workloadId)
  }

  cancelWorkload(workloadId: string): Promise<ExecutionHostResult> {
    return this.mutate(endpoints.executionHostWorkloadCancel, workloadId)
  }

  removeWorkload(workloadId: string): Promise<ExecutionHostResult> {
    return this.mutate(endpoints.executionHostWorkloadRemove, workloadId)
  }

  execWorkload(workloadId: string, argv: string[]): Promise<ExecutionHostResult> {
    return this.mutate(endpoints.executionHostWorkloadExec, workloadId, argv)
  }
}
