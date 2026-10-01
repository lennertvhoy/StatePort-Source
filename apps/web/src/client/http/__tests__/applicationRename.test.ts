import { expect, it } from 'vitest'

import { HttpApplicationsClient } from '../domainsCore'
import { HttpTransport } from '../transport'
import { jsonResponse, makeFakeFetch } from './helpers'

function setup({ stale = false, mismatched = false, failReadback = false } = {}) {
  const instance = { id: 'ins_1', name: 'First', applicationId: 'projectstate', health: 'ready' }
  let renameRequests = 0
  let readbackFailed = false
  const fake = makeFakeFetch([
    ['GET', '/v1/instances', () => jsonResponse({ instances: [instance] })],
    ['GET', '/v1/instances/ins_1', () => {
      if (failReadback && renameRequests > 0 && !readbackFailed) {
        readbackFailed = true
        return jsonResponse({ ok: false, error: { code: 'offline', message: 'Readback unavailable' } }, 503)
      }
      return jsonResponse({ ok: true, result: instance })
    }],
    ['GET', '/v1/instances/ins_1/experience', jsonResponse({ ok: true, result: { capabilities: [] } })],
    ['POST', '/v1/instances/ins_1/rename', () => {
      renameRequests += 1
      if (stale) return jsonResponse({ ok: false, error: { code: 'rename_conflict', message: 'Reload before renaming' } }, 409)
      instance.name = 'Renamed'
      return jsonResponse({ ok: true, result: {
        formatVersion: 'stateport.application-rename-result/v1', instanceId: instance.id, name: instance.name, replayed: renameRequests > 1,
        receipt: {
          formatVersion: 'stateport.application-rename-receipt/v1', receiptId: 'rename_1',
          instanceId: mismatched ? 'different-app' : instance.id, oldName: 'First', newName: instance.name,
          actorId: 'local-user', actorRole: 'local_user', createdAt: '2026-09-05T20:00:00Z',
        },
      } })
    }],
  ])
  return { fake, client: new HttpApplicationsClient(new HttpTransport({ fetchFn: fake.fetchFn })) }
}

it('binds the reviewed name and confirms the durable renamed projection', async () => {
  const { fake, client } = setup()
  expect((await client.rename('ins_1', 'Renamed', 'First')).name).toBe('Renamed')
  expect(fake.callsTo('/rename')[0].body).toEqual({ name: 'Renamed', expectedName: 'First' })
  expect(fake.calls.filter((call) => call.url.endsWith('/v1/instances/ins_1'))).toHaveLength(1)
})

it('preserves the user-reviewed name on a stale refusal without retrying a mutation', async () => {
  const { fake, client } = setup({ stale: true })
  await expect(client.rename('ins_1', 'Renamed', 'Old reviewed name')).rejects.toMatchObject({ status: 409 })
  expect(fake.callsTo('/rename')).toHaveLength(1)
  expect(fake.callsTo('/rename')[0].body).toEqual({ name: 'Renamed', expectedName: 'Old reviewed name' })
})

it('refuses a receipt for a different application after the mutation', async () => {
  const { client } = setup({ mismatched: true })
  await expect(client.rename('ins_1', 'Renamed', 'First')).rejects.toMatchObject({ kind: 'validation' })
})

it('keeps a completed rename unconfirmed after readback failure and retries only the same reviewed request', async () => {
  const { client, fake } = setup({ failReadback: true })
  await expect(client.rename('ins_1', 'Renamed', 'First')).rejects.toMatchObject({ status: 503 })
  expect(fake.callsTo('/rename')).toHaveLength(1)
  expect((await client.rename('ins_1', 'Renamed', 'First')).name).toBe('Renamed')
  expect(fake.callsTo('/rename').map((call) => call.body)).toEqual([
    { name: 'Renamed', expectedName: 'First' }, { name: 'Renamed', expectedName: 'First' },
  ])
})
