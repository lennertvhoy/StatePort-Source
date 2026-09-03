/**
 * Fail-old/pass-new tests for the sanctioned execution-host HTTP client.
 *
 * Fail-old: no browser client existed for the execution-host surface; the
 * GUI could not render real daemon state. Pass-new: the client renders the
 * bounded daemon receipts (health, workload lifecycle, logs) through the
 * same-origin /v1/execution-host surface and never fabricates container
 * state.
 */
import { describe, expect, it } from 'vitest'

import { HttpExecutionHostClient } from '../domainsExecutionHost'
import { HttpTransport } from '../transport'

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
