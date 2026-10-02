import { describe, expect, it, vi } from 'vitest'

import { HttpApplicationsClient } from '../domainsCore'
import { HttpTransport } from '../transport'
import { jsonResponse, makeFakeFetch } from './helpers'

const KEY = 'stateport.http.ui-overlay.v1'
const INSTANCE = { id: 'ins_1', name: 'Project', applicationId: 'projectstate', health: 'ready' }

function setup(unavailable = false) {
  const fake = makeFakeFetch([
    ['GET', '/v1/instances', jsonResponse({ instances: [INSTANCE] })],
    ['GET', '/v1/instances/ins_1/experience', jsonResponse({ ok: true, result: { capabilities: [] } })],
    ['GET', '/v1/instances/ins_1', unavailable
      ? jsonResponse({ ok: false, error: { code: 'unavailable', message: 'Offline' } }, 503)
      : jsonResponse({ ok: true, result: INSTANCE })],
  ])
  const transport = new HttpTransport({ fetchFn: fake.fetchFn })
  return { fake, client: new HttpApplicationsClient(transport), transport }
}

describe('durable browser-owned application pins', () => {
  it('reports storage refusal instead of falsely confirming a pin', async () => {
    const { client } = setup()
    const before = window.localStorage.getItem(KEY)
    vi.spyOn(window.localStorage, 'setItem').mockImplementation(() => {
      throw new DOMException('Quota exceeded', 'QuotaExceededError')
    })
    await expect(client.setPinned('ins_1', true)).rejects.toMatchObject({ kind: 'unavailable' })
    expect(window.localStorage.getItem(KEY)).toBe(before)
  })

  it('does not change a pin when the instance cannot be read', async () => {
    const { client } = setup(true)
    await expect(client.setPinned('ins_1', true)).rejects.toMatchObject({ status: 503 })
    expect(window.localStorage.getItem(KEY)).toBeNull()
  })

  it('returns the persisted pin without a second service read, and retains it in a fresh client', async () => {
    const { client, fake, transport } = setup()
    expect((await client.setPinned('ins_1', true)).pinned).toBe(true)
    expect(fake.calls.filter((call) => call.url.endsWith('/v1/instances/ins_1'))).toHaveLength(1)
    expect((await new HttpApplicationsClient(transport).get('ins_1')).pinned).toBe(true)
    expect((await client.setPinned('ins_1', false)).pinned).toBe(false)
    expect((await new HttpApplicationsClient(transport).get('ins_1')).pinned).toBe(false)
    expect(fake.calls.every((call) => call.method === 'GET')).toBe(true)
  })
})
