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

export class HttpExecutionHostClient implements ExecutionHostClient {
  private readonly transport: HttpTransport

  constructor(transport: HttpTransport) {
    this.transport = transport
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
    const record = (payload ?? {}) as { receipts?: unknown }
    return {
      receipts: Array.isArray(record.receipts)
        ? (record.receipts as ExecutionHostReceiptIndex['receipts'])
        : [],
    }
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

  async createDefaultWorkload(): Promise<ExecutionHostResult> {
    const payload = await this.transport.request(endpoints.executionHostWorkloads, {
      method: 'POST',
      body: {},
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
