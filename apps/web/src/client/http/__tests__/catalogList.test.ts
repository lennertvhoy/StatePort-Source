/**
 * Catalog list honesty: installed counts are derived from the real instances
 * index. When that index cannot be loaded, the list must fail honestly with
 * the transport error — never silently present degraded or zero counts as
 * truth.
 */
import { describe, expect, it } from 'vitest'

import { ClientError } from '../../types'
import { HttpCatalogClient } from '../domainsCore'
import { HttpTransport } from '../transport'
import { jsonResponse, makeFakeFetch } from './helpers'

const CATALOG_ENTRY = {
  formatVersion: 'stateport.application-catalog-entry/v1',
  applicationId: 'checklistdd',
  displayName: 'ChecklistState',
  description: 'A reviewed public fixture.',
  applicationIdentity: {
    descriptorDigest: `sha256:${'a'.repeat(64)}`,
    packageDigest: `sha256:${'b'.repeat(64)}`,
  },
  experienceIdentity: {
    descriptorDigest: `sha256:${'c'.repeat(64)}`,
  },
  install: {
    status: 'available',
    confirmationRequired: true,
    sourceKind: 'bundled_public_fixture',
    requestedCapabilities: ['conversation', 'goal_execution'],
    networkPolicy: 'disabled',
  },
}

const INSTANCE = {
  id: 'ins-aaaabbbbccccdddd',
  instanceId: 'ins-aaaabbbbccccdddd',
  name: 'My checklist',
  applicationId: 'checklistdd',
  health: 'ready',
  createdAt: '2026-07-19T00:00:00.000Z',
}

describe('HttpCatalogClient.list', () => {
  it('derives installed counts from the real instances index', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/applications', jsonResponse({ ok: true, result: { applications: [CATALOG_ENTRY] } })],
      ['GET', '/v1/instances', jsonResponse({ ok: true, result: { instances: [INSTANCE] } })],
    ])
    const client = new HttpCatalogClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    const catalog = await client.list()

    expect(catalog).toHaveLength(1)
    expect(catalog[0].pkg.id).toBe('checklistdd')
    expect(catalog[0].installedInstanceCount).toBe(1)
  })

  it('fails honestly when the instances index cannot be loaded', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/applications', jsonResponse({ ok: true, result: { applications: [CATALOG_ENTRY] } })],
      [
        'GET',
        '/v1/instances',
        jsonResponse(
          { ok: false, error: { code: 'instances_unavailable', message: 'The instances index is unavailable' } },
          503,
        ),
      ],
    ])
    const client = new HttpCatalogClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    const err = await client.list().catch((e: unknown) => e)

    // The failure surfaces as an honest ClientError; the caller is never
    // handed a catalog whose zero counts are silently fabricated.
    expect(err).toBeInstanceOf(ClientError)
    expect((err as ClientError).kind).toBe('http')
    expect((err as ClientError).status).toBe(503)
  })
})
