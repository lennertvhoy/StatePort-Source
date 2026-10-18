import { describe, expect, it, vi } from 'vitest'

import { HttpTransport } from '../http/adapter'
import { ClientError } from '../types'
import { z } from 'zod'

const sessionResponse = () =>
  new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { 'X-StatePort-CSRF': 'csrf-token-1' },
  })

const jsonResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

describe('http transport', () => {
  it('sends the CSRF header on mutations after priming the session', async () => {
    const fetchFn = vi.fn<typeof fetch>(async (input, init) => {
      const url = String(input)
      if (url.endsWith('/session')) return sessionResponse()
      if (url.endsWith('/api/things')) {
        expect((init?.headers as Record<string, string>)['X-StatePort-CSRF']).toBe('csrf-token-1')
        expect(init?.credentials ?? 'same-origin').toBe('same-origin')
        return jsonResponse({ id: 'thing_1' })
      }
      return jsonResponse({}, 404)
    })
    const transport = new HttpTransport({ fetchFn })
    const result = await transport.request('/api/things', {
      method: 'POST',
      body: { name: 'x' },
      schema: z.object({ id: z.string() }),
    })
    expect(result.id).toBe('thing_1')
    expect(fetchFn).toHaveBeenCalledTimes(2)
  })

  it('does one session refresh and one retry after a 401', async () => {
    let calls = 0
    const fetchFn = vi.fn<typeof fetch>(async (input) => {
      const url = String(input)
      if (url.endsWith('/session')) return sessionResponse()
      calls += 1
      if (calls === 1) return jsonResponse({ error: 'expired' }, 401)
      return jsonResponse({ ok: true })
    })
    const transport = new HttpTransport({ fetchFn })
    const result = await transport.request('/api/data', { schema: z.object({ ok: z.boolean() }) })
    expect(result.ok).toBe(true)
    expect(calls).toBe(2)
  })

  it('normalizes http errors with status', async () => {
    const fetchFn = vi.fn<typeof fetch>(async (input) =>
      String(input).endsWith('/session') ? sessionResponse() : jsonResponse({ error: 'nope' }, 500),
    )
    const transport = new HttpTransport({ fetchFn })
    const attempt = transport.request('/api/data', { schema: z.object({ ok: z.boolean() }) })
    await expect(attempt).rejects.toBeInstanceOf(ClientError)
    await expect(attempt).rejects.toMatchObject({ kind: 'http', status: 500 })
  })

  it('normalizes schema drift as a validation error', async () => {
    const fetchFn = vi.fn<typeof fetch>(async () => jsonResponse({ wrong: true }))
    const transport = new HttpTransport({ fetchFn })
    await expect(
      transport.request('/api/data', { schema: z.object({ ok: z.boolean() }) }),
    ).rejects.toMatchObject({ kind: 'validation' })
  })

  it('normalizes connection failure as a network error', async () => {
    const fetchFn = vi.fn<typeof fetch>(async () => {
      throw new TypeError('fetch failed')
    })
    const transport = new HttpTransport({ fetchFn })
    await expect(
      transport.request('/api/data', { schema: z.object({ ok: z.boolean() }) }),
    ).rejects.toMatchObject({ kind: 'network' })
  })
})
