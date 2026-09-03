/**
 * Transport contract tests (binding doc §13): envelope normalization, CSRF,
 * the single 401 refresh+retry, malformed payloads, and schema validation.
 */
import { describe, expect, it } from 'vitest'
import { z } from 'zod'

import { ClientError } from '../../types'
import { HttpTransport, voidSchema } from '../transport'
import { jsonResponse, makeFakeFetch } from './helpers'

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
