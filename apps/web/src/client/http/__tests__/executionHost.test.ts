/**
 * Fail-old/pass-new tests for the sanctioned execution-host HTTP client.
 *
 * Fail-old: no browser client existed for the execution-host surface; the
 * GUI could not render real daemon state. Pass-new: the client renders the
 * bounded daemon receipts (health, workload lifecycle, logs) through the
 * same-origin /v1/execution-host surface and never fabricates container
 * state.
 */
import { describe, expect, it, vi } from 'vitest'

import { HttpExecutionHostClient } from '../domainsExecutionHost'
import { HttpTransport } from '../transport'
import type { WorkspaceAuthoritySource } from '../../client'

function fakeFetch(fn: (url: string, init?: RequestInit) => Promise<unknown>) {
  const calls: Array<{ url: string; init?: RequestInit }> = []
  const fetchFn = async (url: string | URL | Request, init?: RequestInit) => {
    const raw = typeof url === 'string' ? url : url.toString()
    calls.push({ url: raw, init })
    const payload = await fn(raw, init)
    return new Response(JSON.stringify(payload), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })
  }
  return { calls, fetchFn }
}

function jsonResponse(value: unknown) {
  return () => Promise.resolve(value)
}

describe('HttpExecutionHostClient', () => {
  it('renders execution-host availability from the sanctioned proxy', async () => {
    const { fetchFn } = fakeFetch(
      jsonResponse({
        ok: true,
        result: {
          executionHost: {
            status: 'available',
            contractVersion: 1,
            engine: 'podman',
            engineVersion: '4.9.3',
            peerIdentity: { mechanism: 'SO_PEERCRED' },
            grantId: 'control-plane-default',
            grantBound: true,
          },
        },
      }),
    )
    const client = new HttpExecutionHostClient(new HttpTransport({ fetchFn }))
    const status = await client.status()
    expect(status.status).toBe('available')
    expect(status.contractVersion).toBe(1)
    expect(status.engine).toBe('podman')
    expect(status.grantBound).toBe(true)
  })

  it('reports unavailable without fabricating state when the proxy has no daemon', async () => {
    const { fetchFn } = fakeFetch(
      jsonResponse({
        ok: true,
        result: {
          executionHost: {
            status: 'unavailable',
            reason: 'execution_socket_not_configured',
            grantBound: false,
          },
        },
      }),
    )
    const client = new HttpExecutionHostClient(new HttpTransport({ fetchFn }))
    const status = await client.status()
    expect(status.status).toBe('unavailable')
    expect(status.reason).toBe('execution_socket_not_configured')
    expect(status.grantBound).toBe(false)
  })

  it('renders a real workload lifecycle receipt without leaking socket paths', async () => {
    const { fetchFn } = fakeFetch(
      jsonResponse({
        ok: true,
        result: {
          operationId: 'op-1234',
          accepted: true,
          result: { workloadId: 'default-dev', state: 'running', engineStatus: 'running' },
          observed: {
            engine: 'podman',
            imageDigest: 'sha256:' + '0'.repeat(64),
            startedAt: '2026-08-18T00:00:00Z',
          },
        },
      }),
    )
    const client = new HttpExecutionHostClient(new HttpTransport({ fetchFn }))
    const result = await client.workloadStatus('default-dev')
    expect(result.accepted).toBe(true)
    expect((result.result as Record<string, unknown>)?.state).toBe('running')
    expect(result.observed?.imageDigest).toBe('sha256:' + '0'.repeat(64))
    expect(JSON.stringify(result)).not.toContain('control.sock')
  })

  it('surfaces a bounded daemon refusal for a mutation', async () => {
    const { fetchFn } = fakeFetch(
      jsonResponse({
        ok: true,
        result: {
          operationId: 'op-5678',
          accepted: false,
          refusal: { reason: 'grant-expired', detail: 'the grant expired' },
        },
      }),
    )
    const client = new HttpExecutionHostClient(new HttpTransport({ fetchFn }))
    const result = await client.stopWorkload('default-dev')
    expect(result.accepted).toBe(false)
    expect(result.refusal?.reason).toBe('grant-expired')
  })

  it('creates only the server-owned default workspace with an empty body and CSRF', async () => {
    const { calls, fetchFn } = fakeFetch(async (url) => {
      if (url === '/session') {
        return { ok: true, result: { csrfToken: 'csrf-fixture' } }
      }
      return {
        ok: true,
        result: {
          operationId: 'op-create',
          accepted: true,
          result: { workloadId: 'default-dev', state: 'created' },
          receipt: {
            receiptId: 'execution-host-op-create',
            receiptType: 'stateport.execution-host-operation-receipt/v1',
            action: 'execution_host.createWorkload',
            status: 'accepted',
            createdAt: '2026-08-20T00:00:00Z',
            sourceKind: 'execution_host',
            operationId: 'op-create',
            requestDigest: `sha256:${'1'.repeat(64)}`,
            resultDigest: `sha256:${'2'.repeat(64)}`,
            workloadId: 'default-dev',
          },
        },
      }
    })
    const client = new HttpExecutionHostClient(new HttpTransport({ fetchFn }))

    const result = await client.createDefaultWorkload()

    expect(result.result).toEqual({ workloadId: 'default-dev', state: 'created' })
    expect(result.receipt?.action).toBe('execution_host.createWorkload')
    expect(calls.at(-1)?.url).toBe('/v1/execution-host/workloads')
    expect(calls.at(-1)?.init?.method).toBe('POST')
    expect(calls.at(-1)?.init?.body).toBe('{}')
    expect(new Headers(calls.at(-1)?.init?.headers).get('X-StatePort-CSRF')).toBe(
      'csrf-fixture',
    )
  })

  it('loads persisted execution receipts without inventing missing entries', async () => {
    const { fetchFn } = fakeFetch(
      jsonResponse({
        ok: true,
        result: {
          receipts: [
            {
              receiptId: 'execution-host-op-create',
              receiptType: 'stateport.execution-host-operation-receipt/v1',
              action: 'execution_host.createWorkload',
              status: 'accepted',
              createdAt: '2026-08-20T00:00:00Z',
              sourceKind: 'execution_host',
              payloadDigest: `sha256:${'3'.repeat(64)}`,
            },
          ],
        },
      }),
    )
    const client = new HttpExecutionHostClient(new HttpTransport({ fetchFn }))

    const index = await client.listReceipts()

    expect(index.receipts).toHaveLength(1)
    expect(index.receipts[0]?.action).toBe('execution_host.createWorkload')
  })
})

it('refuses malformed receipt indexes instead of presenting an empty history', async () => {
  const fetchFn = vi.fn().mockResolvedValue(new Response(JSON.stringify({ ok: true, result: { unexpected: [] } }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
  const client = new HttpExecutionHostClient(new HttpTransport({ fetchFn }))
  await expect(client.listReceipts()).rejects.toThrow()
})

const authorityDigest = `sha256:${'a'.repeat(64)}`
const authorityReview = {
  instanceId: 'study-one', applicationId: 'studystate', displayName: 'Study', catalogIdentityDigest: authorityDigest, status: 'available',
  issuer: { issuerContextDigest: authorityDigest, profileId: 'stateport.empty-workspace/v1', profileDigest: authorityDigest, sourceMode: 'empty', grantExpiresAtLimit: '2099-01-01T00:00:00Z',
    profile: { image: { reference: `registry/workspace@${authorityDigest}` }, parameters: { cpuQuotaPercent: 100, diskMaxBytes: 256, networkMode: 'none' }, resources: { memoryMaxBytes: 256, pidsMax: 12 }, timeoutSeconds: 3600, outputByteBound: 64 } },
}
const authorityRequest = { formatVersion: 'stateport.workspace-authority-request/v1', instanceId: 'study-one', applicationId: 'studystate', catalogIdentityDigest: authorityDigest, issuerContextDigest: authorityDigest, profileDigest: authorityDigest, sourceMode: 'empty', createdAt: '2098-01-01T00:00:00Z', expiresAt: '2098-01-01T00:15:00Z', grantExpiresAt: '2099-01-01T00:00:00Z', requestDigest: authorityDigest }
const reviewedSource: WorkspaceAuthoritySource = {
  baseRevision: 'b'.repeat(40), commitObject: 'dHJlZSBhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhCmF1dGhvciB0ZXN0Cg==',
  sourceInventory: [{ path: 'application.yaml', mode: '100644', contentDigest: authorityDigest }],
  sourceArchive: { formatVersion: 'stateport.deployment-context-archive/v1', archiveDigest: authorityDigest, archiveBytes: 1024, contextDigest: authorityDigest, fileCount: 1 },
  descriptorDigest: authorityDigest,
}
const reviewedAuthorityReview = {
  ...authorityReview,
  issuer: { ...authorityReview.issuer, profileId: 'stateport.reviewed-source-workspace-terminal/v1', sourceMode: 'reviewed-commit', operations: ['createWorkload', 'listWorkloads', 'status', 'logs', 'start', 'stop', 'cancel', 'removeWorkload', 'execWorkload', 'openTerminal', 'resizeTerminal', 'signalTerminal', 'closeTerminal'], profile: { ...authorityReview.issuer.profile, parameters: { ...authorityReview.issuer.profile.parameters, shell: ['/bin/sh'] } } },
}
it('reads only the exact application authority and rejects foreign projections', async () => {
  const { fetchFn, calls } = fakeFetch(jsonResponse({ ok: true, result: authorityReview }))
  const client = new HttpExecutionHostClient(new HttpTransport({ fetchFn }))
  expect((await client.workspaceAuthority('study-one')).instanceId).toBe('study-one')
  expect(calls.some(call => call.url === '/v1/execution-host/workspaces/study-one/authority')).toBe(true)
  await expect(client.workspaceAuthority('other-one')).rejects.toThrow()
})
it('prepares exact review fields through HTTP POST and rejects mismatched catalog response', async () => {
  let payload = { request: authorityRequest, review: authorityReview }
  const { fetchFn, calls } = fakeFetch(async url => url.endsWith('/session') ? { ok: true, result: { csrfToken: 'fixture-token' } } : { ok: true, result: payload })
  const client = new HttpExecutionHostClient(new HttpTransport({ fetchFn }))
  const input = { profileDigest: authorityDigest, sourceMode: 'empty' as const, grantExpiresAt: authorityRequest.grantExpiresAt }
  expect((await client.prepareWorkspaceAuthority('study-one', input)).request).toEqual(authorityRequest)
  const post = calls.find(call => call.init?.method === 'POST')!
  expect(post.url).toContain('/v1/execution-host/workspaces/study-one/authority/prepare')
  expect(JSON.parse(post.init!.body as string)).toEqual(input)
  payload = { ...payload, request: { ...authorityRequest, catalogIdentityDigest: `sha256:${'b'.repeat(64)}` } }
  await expect(client.prepareWorkspaceAuthority('study-one', input)).rejects.toThrow()
})
it('prepares the reviewed-commit v2 request with the exact bounded source witness', async () => {
  const request = { formatVersion: 'stateport.workspace-authority-request/v2', instanceId: 'study-one', applicationId: 'studystate', catalogIdentityDigest: authorityDigest, issuerContextDigest: authorityDigest, profileDigest: authorityDigest, sourceMode: 'reviewed-commit', source: reviewedSource, sourceDigest: authorityDigest, createdAt: '2098-01-01T00:00:00Z', expiresAt: '2098-01-01T00:15:00Z', grantExpiresAt: '2099-01-01T00:00:00Z', requestDigest: authorityDigest }
  let payload = { request, review: reviewedAuthorityReview }
  const { fetchFn, calls } = fakeFetch(async url => url.endsWith('/session') ? { ok: true, result: { csrfToken: 'fixture-token' } } : { ok: true, result: payload })
  const client = new HttpExecutionHostClient(new HttpTransport({ fetchFn }))
  const input = { profileDigest: authorityDigest, sourceMode: 'reviewed-commit' as const, grantExpiresAt: request.grantExpiresAt }
  expect((await client.prepareWorkspaceAuthority('study-one', input)).request).toEqual(request)
  const post = calls.find(call => call.init?.method === 'POST')!
  expect(JSON.parse(post.init!.body as string)).toEqual(input)
  payload = { ...payload, request: { ...request, source: undefined as never } }
  await expect(client.prepareWorkspaceAuthority('study-one', input)).rejects.toThrow()
})
it('rejects a reviewed projection with an unsafe or inconsistent source witness', async () => {
  const { fetchFn } = fakeFetch(jsonResponse({ ok: true, result: { ...reviewedAuthorityReview, issuer: { ...reviewedAuthorityReview.issuer, source: { ...reviewedSource, sourceInventory: [{ ...reviewedSource.sourceInventory[0], path: '../application.yaml' }] } } } }))
  const client = new HttpExecutionHostClient(new HttpTransport({ fetchFn }))
  await expect(client.workspaceAuthority('study-one')).rejects.toThrow()
})
it('rejects an unsafe profile projection instead of offering arbitrary images or network', async () => {
  const { fetchFn } = fakeFetch(jsonResponse({ ok: true, result: { ...authorityReview, issuer: { ...authorityReview.issuer, profile: { ...authorityReview.issuer.profile, parameters: { ...authorityReview.issuer.profile.parameters, networkMode: 'host' } } } } }))
  const client = new HttpExecutionHostClient(new HttpTransport({ fetchFn }))
  await expect(client.workspaceAuthority('study-one')).rejects.toThrow()
})

it('accepts only the complete fixed terminal profile and refuses partial or legacy-implied terminal operations', async () => {
  const operations = ['createWorkload', 'listWorkloads', 'status', 'logs', 'start', 'stop', 'cancel', 'removeWorkload', 'execWorkload', 'openTerminal', 'resizeTerminal', 'signalTerminal', 'closeTerminal']
  let payload = { ...authorityReview, issuer: { ...authorityReview.issuer, profileId: 'stateport.empty-workspace-terminal/v1', operations, profile: { ...authorityReview.issuer.profile, parameters: { ...authorityReview.issuer.profile.parameters, shell: ['/bin/sh'] } } } }
  const { fetchFn } = fakeFetch(async () => ({ ok: true, result: payload }))
  const client = new HttpExecutionHostClient(new HttpTransport({ fetchFn }))
  expect((await client.workspaceAuthority('study-one')).issuer?.operations).toEqual(operations)
  payload = { ...payload, issuer: { ...payload.issuer, operations: operations.filter(operation => operation !== 'closeTerminal') } }
  await expect(client.workspaceAuthority('study-one')).rejects.toThrow()
  payload = { ...payload, issuer: { ...payload.issuer, operations, profileId: 'stateport.empty-workspace/v1' } }
  await expect(client.workspaceAuthority('study-one')).rejects.toThrow()
})
