/**
 * Transport contract tests (binding doc §13): envelope normalization, CSRF,
 * the single 401 refresh+retry, malformed payloads, and schema validation.
 */
import { describe, expect, it } from 'vitest'
import { z } from 'zod'

import { ClientError } from '../../types'
import { HttpTransport, voidSchema } from '../transport'
import { jsonResponse, makeFakeFetch, withCsrf } from './helpers'

describe('HttpTransport — envelope normalization', () => {
  const schema = z.object({ id: z.string() })

  it('unwraps { ok: true, result }', async () => {
    const fake = makeFakeFetch([['GET', '/v1/thing', jsonResponse({ ok: true, result: { id: 'a' } })]])
    const transport = new HttpTransport({ fetchFn: fake.fetchFn })
    await expect(transport.request('/v1/thing', { schema })).resolves.toEqual({ id: 'a' })
  })

  it('accepts a direct result object', async () => {
    const fake = makeFakeFetch([['GET', '/v1/thing', jsonResponse({ id: 'b' })]])
    const transport = new HttpTransport({ fetchFn: fake.fetchFn })
    await expect(transport.request('/v1/thing', { schema })).resolves.toEqual({ id: 'b' })
  })

  it('treats { ok: false, error } as an error with code + message preserved', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/thing', jsonResponse({ ok: false, error: { code: 'conflict', message: 'Digest mismatch' } }, 409)],
    ])
    const transport = new HttpTransport({ fetchFn: fake.fetchFn })
    const err = await transport.request('/v1/thing', { schema }).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ClientError)
    expect((err as ClientError).kind).toBe('http')
    expect((err as ClientError).status).toBe(409)
    expect((err as ClientError).message).toBe('Digest mismatch')
    expect((err as ClientError).code).toBe('conflict')
  })

  it('treats { ok: false, error } with HTTP 200 as an error too', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/thing', jsonResponse({ ok: false, error: { code: 'bad', message: 'Nope' } })],
    ])
    const transport = new HttpTransport({ fetchFn: fake.fetchFn })
    const err = await transport.request('/v1/thing', { schema }).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ClientError)
    expect((err as ClientError).message).toBe('Nope')
  })

  it('falls back to the documented error detail when no message is present', async () => {
    const fake = makeFakeFetch([
      ['POST', '/v1/thing', jsonResponse({ ok: false, error: { code: 'agent_run_refused', detail: 'Workspace authority is missing.' } }, 409)],
    ])
    const transport = new HttpTransport({ fetchFn: fake.fetchFn })
    const err = await transport.request('/v1/thing', { method: 'POST', schema }).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ClientError)
    expect((err as ClientError).message).toBe('Workspace authority is missing.')
    expect((err as ClientError).code).toBe('agent_run_refused')
    expect((err as ClientError).status).toBe(409)
  })

  it('accepts 204 No Content with a void schema', async () => {
    const fake = makeFakeFetch([['POST', '/v1/void', new Response(null, { status: 204 })]])
    const transport = new HttpTransport({ fetchFn: fake.fetchFn })
    await expect(transport.request('/v1/void', { method: 'POST', schema: voidSchema })).resolves.toBeUndefined()
  })
})

describe('HttpTransport — CSRF', () => {
  it('primes from GET /session and sends X-StatePort-CSRF on every mutation', async () => {
    const fake = makeFakeFetch([
      ['POST', '/v1/mutate', jsonResponse({ ok: true, result: { done: true } })],
      ['GET', '/v1/mutate', jsonResponse({ ok: true, result: { done: true } })],
    ])
    const transport = new HttpTransport({ fetchFn: fake.fetchFn })

    // The authenticated local API requires the browser session for reads too.
    await transport.request('/v1/mutate', { schema: z.unknown() })
    expect(fake.callsTo('/session')).toHaveLength(1)

    await transport.request('/v1/mutate', { method: 'POST', schema: z.unknown() })
    expect(fake.callsTo('/session')).toHaveLength(1)
    const mutation = fake.callsTo('/v1/mutate').find((c) => c.method === 'POST')!
    expect(mutation.headers['x-stateport-csrf']).toBe('test-csrf')

    // Second mutation reuses the primed token (no second /session fetch).
    await transport.request('/v1/mutate', { method: 'POST', schema: z.unknown() })
    expect(fake.callsTo('/session')).toHaveLength(1)
  })

  it('sends credentials: same-origin on every request', async () => {
    const seen: RequestCredentials[] = []
    const fetchFn: typeof fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      seen.push(init?.credentials as RequestCredentials)
      return jsonResponse({ ok: true })
    }) as typeof fetch
    const transport = new HttpTransport({ fetchFn })
    await transport.request('/session', { schema: z.unknown() })
    await transport.request('/v1/x', { method: 'POST', schema: z.unknown() })
    expect(seen.length).toBeGreaterThan(0)
    expect(seen.every((c) => c === 'same-origin')).toBe(true)
  })
})

describe('HttpTransport — 401 handling', () => {
  it('refreshes /session ONCE and retries the original ONCE, then gives up', async () => {
    let dataCalls = 0
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/data',
        () => {
          dataCalls += 1
          return jsonResponse({ error: 'expired' }, 401)
        },
      ],
    ])
    const transport = new HttpTransport({ fetchFn: fake.fetchFn })
    const err = await transport.request('/v1/data', { schema: z.unknown() }).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ClientError)
    expect((err as ClientError).kind).toBe('http')
    expect((err as ClientError).status).toBe(401)
    // Exactly one retry — never an endless loop.
    expect(dataCalls).toBe(2)
    // One initial session prime plus one refresh for the retry.
    expect(fake.callsTo('/session')).toHaveLength(2)
  })
})

describe('HttpTransport — malformed responses fail closed', () => {
  it('rejects non-JSON success bodies as validation errors', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/broken', new Response('<html>nope</html>', { status: 200 })],
    ])
    const transport = new HttpTransport({ fetchFn: fake.fetchFn })
    const err = await transport.request('/v1/broken', { schema: z.unknown() }).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ClientError)
    expect((err as ClientError).kind).toBe('validation')
  })

  it('rejects schema-mismatched payloads as validation errors', async () => {
    const fake = makeFakeFetch([['GET', '/v1/thing', jsonResponse({ ok: true, result: { nope: 1 } })]])
    const transport = new HttpTransport({ fetchFn: fake.fetchFn })
    const err = await transport
      .request('/v1/thing', { schema: z.object({ id: z.string() }) })
      .catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ClientError)
    expect((err as ClientError).kind).toBe('validation')
    expect((err as ClientError).detail).toContain('id')
  })

  it('maps fetch failures to network errors', async () => {
    const transport = new HttpTransport({
      fetchFn: (() => Promise.reject(new Error('connection refused'))) as typeof fetch,
    })
    const err = await transport.request('/v1/thing', { schema: z.unknown() }).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ClientError)
    expect((err as ClientError).kind).toBe('network')
  })
})

describe('HttpTransport — stale CSRF after a service restart', () => {
  /**
   * A tiny stand-in for the AppServer: the browser cookie jar is shared by every
   * transport in the page, while each transport caches its own CSRF token.  A
   * restarted service has a new session and a new token.  A stale token with a
   * valid session is a 403 (not a 401) with the stable code `csrf_token_invalid`,
   * exactly like the service's `_mutation_security`.
   */
  function makeRestartableService() {
    let generation = 1
    let cookieGeneration = 1
    const executed: string[] = []
    const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = new URL(String(input), 'http://stateport.test').pathname
      const method = (init?.method ?? 'GET').toUpperCase()
      if (path === '/session') {
        cookieGeneration = generation
        return withCsrf(jsonResponse({ ok: true, result: { session: 'local' } }), `csrf-${generation}`)
      }
      if (cookieGeneration !== generation) return jsonResponse({ ok: false, error: { code: 'session_required' } }, 401)
      if (method === 'POST') {
        const token = new Headers(init?.headers).get('x-stateport-csrf')
        if (token !== `csrf-${generation}`) {
          return jsonResponse({ ok: false, error: { code: 'csrf_token_invalid', message: 'the request could not be authorized' } }, 403)
        }
        executed.push(path)
      }
      return jsonResponse({ ok: true, result: { done: true } })
    }) as typeof fetch
    return { fetchFn, executed, restart: () => { generation += 1 } }
  }

  it('a transport holding a pre-restart token recovers instead of failing every mutation', async () => {
    const service = makeRestartableService()
    const pageTransport = new HttpTransport({ fetchFn: service.fetchFn })
    const providerTransport = new HttpTransport({ fetchFn: service.fetchFn })
    await pageTransport.request('/v1/status', { schema: z.unknown() })
    await providerTransport.request('/v1/provider/verify', { method: 'POST', schema: z.unknown() })

    service.restart()
    // The page's own transport notices the restart (401) and re-primes the shared cookie jar.
    await pageTransport.request('/v1/status', { schema: z.unknown() })
    await pageTransport.request('/v1/backup', { method: 'POST', schema: z.unknown() })
    // The second transport still holds the old token; its first mutation is a 403 on the wire.
    await providerTransport.request('/v1/provider/verify', { method: 'POST', schema: z.unknown() })

    expect(service.executed).toEqual(['/v1/provider/verify', '/v1/backup', '/v1/provider/verify'])
  })

  it('a CSRF refusal is retried exactly once with a fresh token and then reported', async () => {
    let posts = 0
    const fake = makeFakeFetch([
      ['POST', '/v1/stale', () => {
        posts += 1
        return jsonResponse({ ok: false, error: { code: 'csrf_token_invalid', message: 'refresh and retry' } }, 403)
      }],
    ])
    const transport = new HttpTransport({ fetchFn: fake.fetchFn })
    const err = await transport.request('/v1/stale', { method: 'POST', schema: z.unknown() }).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ClientError)
    expect((err as ClientError).status).toBe(403)
    expect((err as ClientError).code).toBe('csrf_token_invalid')
    expect(posts).toBe(2)
    expect(fake.callsTo('/session')).toHaveLength(2)
  })

  it.each([
    ['provider_action_denied'], ['execution_access_denied'], ['restore_access_denied'], ['file_workspace_access_denied'],
  ])('a route-specific 403 (%s) is never replayed: the mutation could already have had effects', async (code) => {
    let posts = 0
    const fake = makeFakeFetch([
      ['POST', '/v1/denied', () => {
        posts += 1
        return jsonResponse({ ok: false, error: { code, message: 'denied' } }, 403)
      }],
    ])
    const transport = new HttpTransport({ fetchFn: fake.fetchFn })
    const err = await transport.request('/v1/denied', { method: 'POST', schema: z.unknown() }).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ClientError)
    expect((err as ClientError).status).toBe(403)
    expect((err as ClientError).code).toBe(code)
    expect(posts).toBe(1)
    expect(fake.callsTo('/session')).toHaveLength(1)
  })

  it('a 403 without a JSON error body is not retried either', async () => {
    let posts = 0
    const fake = makeFakeFetch([
      ['POST', '/v1/opaque', () => {
        posts += 1
        return new Response('forbidden', { status: 403 })
      }],
    ])
    const transport = new HttpTransport({ fetchFn: fake.fetchFn })
    await transport.request('/v1/opaque', { method: 'POST', schema: z.unknown() }).catch(() => undefined)
    expect(posts).toBe(1)
  })

  it('never retries a 403 on a read (no token was involved)', async () => {
    let gets = 0
    const fake = makeFakeFetch([
      ['GET', '/v1/denied', () => {
        gets += 1
        return jsonResponse({ ok: false, error: { code: 'authority_access_denied', message: 'denied' } }, 403)
      }],
    ])
    const transport = new HttpTransport({ fetchFn: fake.fetchFn })
    await transport.request('/v1/denied', { schema: z.unknown() }).catch(() => undefined)
    expect(gets).toBe(1)
  })
})
