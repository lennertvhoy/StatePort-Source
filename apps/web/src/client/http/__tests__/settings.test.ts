/**
 * Settings contract tests: updates carry the current revision for optimistic
 * concurrency; rollback sends expectedRevision + receiptId.
 */
import { beforeEach, describe, expect, it } from 'vitest'

import { HttpTransport } from '../transport'
import { HttpAppSettingsClient, HttpGlobalSettingsClient } from '../domainsCore'
import { jsonResponse, makeFakeFetch } from './helpers'

const SETTINGS_PROJECTION = {
  formatVersion: 'stateport.settings-projection/v1',
  scope: 'global',
  instanceId: null,
  revision: 7,
  recentReceipts: [],
  sections: [
    {
      id: 'general',
      label: 'General',
      fields: [
        {
          id: 'appearance',
          key: 'general.appearance',
          label: 'Appearance',
          value: 'dark',
          effectiveValue: 'dark',
        },
      ],
    },
  ],
}

function settingsReceipt(
  revision: number,
  action: 'settings.patch' | 'settings.rollback',
  scope: 'global' | 'application' = 'global',
  instanceId: string | null = null,
) {
  const receiptId = revision.toString(16).padStart(24, '0')
  return {
    formatVersion: 'stateport.settings-mutation-receipt/v1',
    receiptId,
    scope,
    instanceId,
    action,
    status: 'applied',
    revision,
    changes: { 'general.appearance': 'dark' },
    previousValues: { 'general.appearance': 'light' },
    effectivePolicy: 'platform → application → instance → operator → user → runtime',
    createdAt: `2026-07-${String(revision).padStart(2, '0')}T10:00:00Z`,
  }
}

describe('HttpGlobalSettingsClient', () => {
  beforeEach(() => localStorage.clear())

  it('update sends the expectedRevision from the last projection', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/settings', jsonResponse({ ok: true, result: SETTINGS_PROJECTION })],
      ['POST', '/v1/settings', jsonResponse({
        ok: true,
        result: {
          projection: {
            ...SETTINGS_PROJECTION,
            revision: 8,
            recentReceipts: [settingsReceipt(8, 'settings.patch')],
            sections: [{
              ...SETTINGS_PROJECTION.sections[0],
              fields: [{ ...SETTINGS_PROJECTION.sections[0].fields[0], value: 'light', effectiveValue: 'light' }],
            }],
          },
          receipt: settingsReceipt(8, 'settings.patch'),
        },
      })],
      ['POST', '/v1/settings', jsonResponse({
        ok: true,
        result: {
          projection: {
            ...SETTINGS_PROJECTION,
            revision: 9,
            recentReceipts: [settingsReceipt(9, 'settings.patch')],
          },
          receipt: settingsReceipt(9, 'settings.patch'),
        },
      })],
    ])
    const client = new HttpGlobalSettingsClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    await client.get()
    const updated = await client.update({ appearance: { theme: 'light', density: 'comfortable' } })
    expect(updated.appearance.theme).toBe('light')
    const post = fake.callsTo('/v1/settings').find((c) => c.method === 'POST')!
    expect(post.body).toEqual({
      expectedRevision: 7,
      changes: { 'general.appearance': 'light' },
    })
    // A follow-up update uses the NEW revision (8).
    await client.update({ appearance: { theme: 'dark', density: 'comfortable' } })
    const posts = fake.callsTo('/v1/settings').filter((c) => c.method === 'POST')
    expect(posts[1].body).toMatchObject({ expectedRevision: 8 })
  })

  it('update fetches the projection first when no revision is known', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/settings', jsonResponse(SETTINGS_PROJECTION)],
      ['POST', '/v1/settings', jsonResponse({
        projection: {
          ...SETTINGS_PROJECTION,
          revision: 8,
          recentReceipts: [settingsReceipt(8, 'settings.patch')],
        },
        receipt: settingsReceipt(8, 'settings.patch'),
      })],
    ])
    const client = new HttpGlobalSettingsClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    await client.update({ appearance: { theme: 'light', density: 'compact' } })
    const posts = fake.callsTo('/v1/settings').filter((c) => c.method === 'POST')
    expect(posts[0].body).toEqual({ expectedRevision: 7, changes: { 'general.appearance': 'light' } })
  })

  it('rollback sends expectedRevision + receiptId to /v1/settings/rollback', async () => {
    const fake = makeFakeFetch([
      ['POST', '/v1/settings/rollback', jsonResponse({
        projection: {
          ...SETTINGS_PROJECTION,
          revision: 9,
          recentReceipts: [settingsReceipt(9, 'settings.rollback')],
        },
        receipt: settingsReceipt(9, 'settings.rollback'),
      })],
    ])
    const client = new HttpGlobalSettingsClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    await client.rollback({ expectedRevision: 8, receiptId: 'rcpt_55' })
    const call = fake.callsTo('/v1/settings/rollback')[0]
    expect(call.body).toEqual({ expectedRevision: 8, receiptId: 'rcpt_55' })
    expect(call.headers['x-stateport-csrf']).toBe('test-csrf')
  })

  it('exposes the exact bounded rollback history from the current projection', async () => {
    const first = settingsReceipt(6, 'settings.patch')
    const second = settingsReceipt(7, 'settings.rollback')
    const fake = makeFakeFetch([
      ['GET', '/v1/settings', jsonResponse({
        ...SETTINGS_PROJECTION,
        recentReceipts: [second, first],
      })],
    ])
    const client = new HttpGlobalSettingsClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    await expect(client.getRollbackHistory()).resolves.toEqual({
      currentRevision: 7,
      targets: [
        {
          receiptId: second.receiptId,
          revision: 7,
          action: 'settings.rollback',
          createdAt: second.createdAt,
          changes: second.changes,
          previousValues: second.previousValues,
        },
        {
          receiptId: first.receiptId,
          revision: 6,
          action: 'settings.patch',
          createdAt: first.createdAt,
          changes: first.changes,
          previousValues: first.previousValues,
        },
      ],
    })
  })

  it.each([
    ['wrong scope', { ...settingsReceipt(7, 'settings.patch'), scope: 'application', instanceId: 'ins_1' }],
    ['future revision', settingsReceipt(8, 'settings.patch')],
    ['extra receipt field', { ...settingsReceipt(7, 'settings.patch'), invented: true }],
    ['different field sets', {
      ...settingsReceipt(7, 'settings.patch'),
      previousValues: { 'notifications.level': 'important' },
    }],
  ])('fails closed for %s in rollback history', async (_label, receipt) => {
    const fake = makeFakeFetch([
      ['GET', '/v1/settings', jsonResponse({
        ...SETTINGS_PROJECTION,
        recentReceipts: [receipt],
      })],
    ])
    const client = new HttpGlobalSettingsClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    await expect(client.getRollbackHistory()).rejects.toMatchObject({ kind: 'validation' })
  })

  it('fails closed when a mutation receipt does not match the returned projection', async () => {
    const fake = makeFakeFetch([
      ['POST', '/v1/settings/rollback', jsonResponse({
        projection: {
          ...SETTINGS_PROJECTION,
          revision: 9,
          recentReceipts: [settingsReceipt(9, 'settings.rollback')],
        },
        receipt: settingsReceipt(8, 'settings.rollback'),
      })],
    ])
    const client = new HttpGlobalSettingsClient(
      new HttpTransport({ fetchFn: fake.fetchFn }),
    )

    await expect(
      client.rollback({ expectedRevision: 8, receiptId: '000000000000000000000008' }),
    ).rejects.toMatchObject({ kind: 'validation' })
  })

  it('fails closed when rollback returns a patch receipt', async () => {
    const fake = makeFakeFetch([
      ['POST', '/v1/settings/rollback', jsonResponse({
        projection: {
          ...SETTINGS_PROJECTION,
          revision: 9,
          recentReceipts: [settingsReceipt(9, 'settings.patch')],
        },
        receipt: settingsReceipt(9, 'settings.patch'),
      })],
    ])
    const client = new HttpGlobalSettingsClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    await expect(
      client.rollback({ expectedRevision: 8, receiptId: '000000000000000000000008' }),
    ).rejects.toMatchObject({ kind: 'validation' })
  })
})

describe('HttpAppSettingsClient', () => {
  beforeEach(() => localStorage.clear())

  it('keeps browser-only preferences local and uses the real per-instance rollback endpoint', async () => {
    const appProjection = {
      ...SETTINGS_PROJECTION,
      scope: 'application',
      instanceId: 'ins_1',
      revision: 3,
    }
    const fake = makeFakeFetch([
      ['GET', '/v1/instances/ins_1/settings', jsonResponse(appProjection)],
      ['POST', '/v1/instances/ins_1/settings-rollback', jsonResponse({
        projection: {
          ...appProjection,
          revision: 5,
          recentReceipts: [
            settingsReceipt(5, 'settings.rollback', 'application', 'ins_1'),
          ],
        },
        receipt: settingsReceipt(
          5,
          'settings.rollback',
          'application',
          'ins_1',
        ),
      })],
    ])
    const client = new HttpAppSettingsClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    await client.get('ins_1')
    await client.update('ins_1', { notificationLevel: 'all' })
    expect(fake.callsTo('/v1/instances/ins_1/settings').filter((c) => c.method === 'POST')).toHaveLength(0)
    await expect(client.get('ins_1')).resolves.toMatchObject({ notificationLevel: 'all' })

    await client.rollback('ins_1', { expectedRevision: 4, receiptId: 'rcpt_9' })
    const rollback = fake.callsTo('/v1/instances/ins_1/settings-rollback')[0]
    expect(rollback.body).toEqual({ expectedRevision: 4, receiptId: 'rcpt_9' })
  })
})
