import { describe, expect, it } from 'vitest'

import { ClientError } from '../../types'
import { HttpActivityClient } from '../domainsCore'
import { mapActivityItem } from '../mappers'
import { HttpTransport } from '../transport'
import { jsonResponse, makeFakeFetch } from './helpers'

const ATTENTION = {
  attentionId: 'recovery-backup',
  sourceKind: 'application_recovery',
  title: 'No verified backup recorded',
  detail: 'Create a backup before relying on recovery.',
  state: 'open',
  firstObservedAt: '2026-07-18T10:00:00Z',
  lastObservedAt: '2026-07-18T10:01:00Z',
  readAt: null,
  acknowledgedAt: null,
  version: 3,
}

const PROJECTION = {
  formatVersion: 'stateport.activity-receipts-projection/v1',
  instanceId: 'ins_1',
  attention: [ATTENTION],
  recentActivity: [
    {
      kind: 'receipt',
      receiptId: 'receipt-1',
      action: 'settings.patch',
      status: 'applied',
      occurredAt: '2026-07-18T09:00:00Z',
    },
  ],
}

describe('mapActivityItem titles', () => {
  it('humanizes a raw machine action instead of rendering it verbatim', () => {
    const item = mapActivityItem(
      {
        kind: 'receipt',
        receiptId: 'receipt-9',
        action: 'governed_run.apply',
        status: 'applied',
        occurredAt: '2026-07-18T09:00:00Z',
      },
      'ins_1',
    )
    expect(item.title).toBe('Application changes applied')
  })

  it('humanizes unknown action identifiers rather than leaking underscores', () => {
    const item = mapActivityItem(
      { kind: 'receipt', action: 'studystate.sample.undo-last-evidence/v1', occurredAt: '2026-07-18T09:00:00Z' },
      'ins_1',
    )
    expect(item.title).not.toContain('_')
    expect(item.title).not.toBe('studystate.sample.undo-last-evidence/v1')
  })

  it('prefers an explicit backend title over the humanized action', () => {
    const item = mapActivityItem(
      { kind: 'receipt', action: 'governed_run.apply', title: 'Plan updated', occurredAt: '2026-07-18T09:00:00Z' },
      'ins_1',
    )
    expect(item.title).toBe('Plan updated')
  })
})

describe('HttpActivityClient notifications', () => {
  it('projects backend attention as notifications and keeps receipts as history', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/instances', jsonResponse({ ok: true, result: [{ instanceId: 'ins_1' }] })],
      [
        'GET',
        '/v1/instances/ins_1/activity',
        jsonResponse({ ok: true, result: PROJECTION }),
      ],
    ])
    const client = new HttpActivityClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    const notifications = await client.listNotifications()

    expect(notifications).toEqual([
      {
        id: 'recovery-backup',
        instanceId: 'ins_1',
        title: 'No verified backup recorded',
        body: 'Create a backup before relying on recovery.',
        importance: 'important',
        createdAt: '2026-07-18T10:00:00Z',
        read: false,
        acknowledged: false,
        route: undefined,
        snoozedUntil: undefined,
      },
    ])
    expect(notifications.some((item) => item.id === 'receipt-1')).toBe(false)
  })

  it('marks the exact attention version read and accepts the returned transition', async () => {
    const readAttention = {
      ...ATTENTION,
      readAt: '2026-07-18T10:02:00Z',
      version: 4,
    }
    const fake = makeFakeFetch([
      ['GET', '/v1/instances', jsonResponse({ ok: true, result: [{ instanceId: 'ins_1' }] })],
      [
        'GET',
        '/v1/instances/ins_1/activity',
        jsonResponse({ ok: true, result: PROJECTION }),
      ],
      [
        'POST',
        '/v1/instances/ins_1/activity/recovery-backup/read',
        jsonResponse({ ok: true, result: { attention: readAttention } }),
      ],
    ])
    const client = new HttpActivityClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    await client.listNotifications()
    await client.markNotificationRead('recovery-backup')

    const call =
      fake.callsTo('/v1/instances/ins_1/activity/recovery-backup/read')[0]
    expect(call.body).toEqual({ expectedVersion: 3 })
    expect(call.headers['x-stateport-csrf']).toBe('test-csrf')
  })

  it('acknowledges the exact attention version and preserves the returned state', async () => {
    const acknowledgedAttention = {
      ...ATTENTION,
      acknowledgedAt: '2026-07-18T10:03:00Z',
      version: 4,
    }
    const fake = makeFakeFetch([
      ['GET', '/v1/instances', jsonResponse({ ok: true, result: [{ instanceId: 'ins_1' }] })],
      [
        'GET',
        '/v1/instances/ins_1/activity',
        jsonResponse({ ok: true, result: PROJECTION }),
      ],
      [
        'POST',
        '/v1/instances/ins_1/activity/recovery-backup/acknowledge',
        jsonResponse({ ok: true, result: { attention: acknowledgedAttention } }),
      ],
    ])
    const client = new HttpActivityClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    await client.listAttention()
    const result = await client.acknowledgeAttention('recovery-backup')

    const call =
      fake.callsTo('/v1/instances/ins_1/activity/recovery-backup/acknowledge')[0]
    expect(call.body).toEqual({ expectedVersion: 3 })
    expect(call.headers['x-stateport-csrf']).toBe('test-csrf')
    expect(result).toMatchObject({ id: 'recovery-backup', read: true, acknowledged: true })
  })

  it.each([
    ['read', '/v1/instances/ins_1/activity/recovery-backup/read'],
    ['acknowledge', '/v1/instances/ins_1/activity/recovery-backup/acknowledge'],
  ])('fails closed when no projection supplied an expected version for %s', async (operation, path) => {
    const fake = makeFakeFetch([])
    const client = new HttpActivityClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    const error =
      operation === 'read'
        ? await client
            .markNotificationRead('recovery-backup', { instanceId: 'ins_1' })
            .catch((caught: unknown) => caught)
        : await client
            .acknowledgeAttention('recovery-backup', { instanceId: 'ins_1' })
            .catch((caught: unknown) => caught)

    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).kind).toBe('unavailable')
    expect(fake.callsTo(path)).toHaveLength(0)
  })

  it('does not invent version zero when the backend omits an attention version', async () => {
    const withoutVersion = { ...ATTENTION } as Record<string, unknown>
    delete withoutVersion.version
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/instances/ins_1/activity',
        jsonResponse({ ok: true, result: { ...PROJECTION, attention: [withoutVersion] } }),
      ],
    ])
    const client = new HttpActivityClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    await client.listAttention('ins_1')
    const error = await client
      .acknowledgeAttention('recovery-backup')
      .catch((caught: unknown) => caught)

    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).kind).toBe('unavailable')
    expect(
      fake.callsTo('/v1/instances/ins_1/activity/recovery-backup/acknowledge'),
    ).toHaveLength(0)
  })

  it('rejects a projection explicitly bound to a different application instance', async () => {
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/instances/ins_1/activity',
        jsonResponse({
          ok: true,
          result: { ...PROJECTION, instanceId: 'ins_other' },
        }),
      ],
    ])
    const client = new HttpActivityClient(
      new HttpTransport({ fetchFn: fake.fetchFn }),
    )

    const error = await client
      .listAttention('ins_1')
      .catch((caught: unknown) => caught)
    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).kind).toBe('validation')
  })
})
