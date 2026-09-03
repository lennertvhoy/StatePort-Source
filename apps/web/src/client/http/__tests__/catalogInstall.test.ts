/**
 * Browser fixture installation is an identity-bound mutation. The generated
 * destination identity remains authoritative after the POST; a response may
 * confirm it, but may not redirect the client to a different application.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'

import { HttpCatalogClient } from '../domainsCore'
import { HttpTransport } from '../transport'
import { jsonResponse, makeFakeFetch } from './helpers'

const APPLICATION_ID = 'checklistdd'
const APPLICATION_DESCRIPTOR_DIGEST = `sha256:${'a'.repeat(64)}`
const PACKAGE_DIGEST = `sha256:${'b'.repeat(64)}`
const EXPERIENCE_DESCRIPTOR_DIGEST = `sha256:${'c'.repeat(64)}`
const INSTANCE_ID = 'ins_0101010101010101'
const RECEIPT_DIGEST = `sha256:${'d'.repeat(64)}`

const CATALOG_ENTRY = {
  formatVersion: 'stateport.application-catalog-entry/v1',
  applicationId: APPLICATION_ID,
  displayName: 'ChecklistState',
  description: 'A reviewed public fixture.',
  applicationIdentity: {
    descriptorDigest: APPLICATION_DESCRIPTOR_DIGEST,
    packageDigest: PACKAGE_DIGEST,
  },
  experienceIdentity: {
    descriptorDigest: EXPERIENCE_DESCRIPTOR_DIGEST,
  },
  install: {
    status: 'available',
    confirmationRequired: true,
    sourceKind: 'bundled_public_fixture',
    requestedCapabilities: ['conversation', 'goal_execution'],
    networkPolicy: 'disabled',
  },
}

describe('HttpCatalogClient fixture installation', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('returns the exact durable receipt reference after exact-identity read-back', async () => {
    vi.spyOn(globalThis.crypto, 'getRandomValues').mockImplementation((array) => {
      new Uint8Array(array.buffer, array.byteOffset, array.byteLength).fill(1)
      return array
    })
    const instance = {
      id: INSTANCE_ID,
      instanceId: INSTANCE_ID,
      name: 'My checklist',
      applicationId: APPLICATION_ID,
      health: 'ready',
      createdAt: '2026-07-19T00:00:00.000Z',
    }
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/applications',
        jsonResponse({ ok: true, result: { applications: [CATALOG_ENTRY] } }),
      ],
      [
        'POST',
        '/v1/application-fixtures/install',
        jsonResponse({
          ok: true,
          result: {
            entry: {
              applicationId: APPLICATION_ID,
              instanceId: INSTANCE_ID,
              status: 'active',
            },
            receipt: {
              formatVersion: 'stateport.application-install-receipt/v1',
              receiptId: `application-install.${INSTANCE_ID}.abc123abc123`,
              receiptDigest: RECEIPT_DIGEST,
            },
          },
        }),
      ],
      ['GET', `/v1/instances/${INSTANCE_ID}`, jsonResponse({ ok: true, result: instance })],
      [
        'GET',
        `/v1/instances/${INSTANCE_ID}/experience`,
        jsonResponse({ ok: true, result: { capabilities: [] } }),
      ],
      ['GET', '/v1/instances', jsonResponse({ ok: true, result: { instances: [instance] } })],
    ])
    const client = new HttpCatalogClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    await expect(
      client.createInstance(APPLICATION_ID, { name: 'My checklist' }),
    ).resolves.toEqual({
      instance: expect.objectContaining({
        id: INSTANCE_ID,
        name: 'My checklist',
      }),
      receipt: {
        id: `application-install.${INSTANCE_ID}.abc123abc123`,
        digest: { algorithm: 'sha256', value: RECEIPT_DIGEST },
      },
    })
    expect(fake.callsTo('/v1/application-fixtures/install')).toHaveLength(1)
    expect(fake.callsTo(`/v1/instances/${INSTANCE_ID}`)).not.toHaveLength(0)
  })

  it('fails closed before reading or navigating when the result changes the generated instance identity', async () => {
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/applications',
        jsonResponse({ ok: true, result: { applications: [CATALOG_ENTRY] } }),
      ],
      [
        'POST',
        '/v1/application-fixtures/install',
        (call) => {
          const body = call.body as { instanceId: string }
          return jsonResponse({
            ok: true,
            result: {
              entry: {
                applicationId: APPLICATION_ID,
                instanceId: `${body.instanceId}-mismatch`,
                status: 'active',
              },
              receipt: {
                formatVersion: 'stateport.application-install-receipt/v1',
                receiptId: `application-install.${body.instanceId}.abc123abc123`,
                receiptDigest: RECEIPT_DIGEST,
              },
            },
          })
        },
      ],
    ])
    const client = new HttpCatalogClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    await expect(client.createInstance(APPLICATION_ID, { name: 'My checklist' })).rejects.toMatchObject({
      kind: 'validation',
      message: expect.stringContaining('application installation instance identity'),
    })

    const install = fake.callsTo('/v1/application-fixtures/install')[0]
    expect(String((install.body as { instanceId: string }).instanceId)).toMatch(/^ins_[0-9a-f]{16}$/)
    expect(
      fake.calls.filter((call) =>
        new URL(call.url, 'http://stateport.test').pathname.startsWith('/v1/instances/'),
      ),
    ).toHaveLength(0)
    // The non-idempotent mutation is never retried after a response was
    // received, even though that response fails exact-identity validation.
    expect(fake.callsTo('/v1/application-fixtures/install')).toHaveLength(1)
  })
})
