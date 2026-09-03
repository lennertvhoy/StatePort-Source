import { describe, expect, it } from 'vitest'

import type { LocalServiceStatus, PlatformStateBenchView } from '@/client'
import { HttpPlatformStateBenchClient } from '@/client/http/domainsPlatform'
import { mapPlatformStateBench } from '@/client/http/mappers'
import { HttpTransport } from '@/client/http/transport'

import { jsonResponse, makeFakeFetch } from './helpers'

const LOCAL_USER: LocalServiceStatus = {
  state: 'connected',
  endpoint: '/v1/status',
  actor: {
    role: 'local_user',
    actorId: 'local-user',
    platformOperationsAllowed: false,
    statebenchInspectionAllowed: false,
  },
}

const OPERATOR: LocalServiceStatus = {
  state: 'connected',
  endpoint: '/v1/status',
  actor: {
    role: 'platform_operator',
    actorId: 'platform-operator',
    platformOperationsAllowed: true,
    statebenchInspectionAllowed: true,
  },
}

const MATRIX: PlatformStateBenchView = {
  formatVersion: 'stateport.platform-statebench-view/v1',
  rows: [
    {
      formatVersion: 'statebench.run-bundle-row/v1',
      integrityStatus: 'verified',
      authoritative: false,
      producerClaimsTrusted: false,
      bundleDigest: `sha256:${'b'.repeat(64)}`,
      runId: 'operator-matrix-proof',
      applicationId: 'stateport.synthetic-reference',
      engineId: 'synthetic',
      adapterId: 'synthetic-action',
      status: 'completed',
      statePreserved: true,
      capabilityDegradations: [{ id: 'terminal.sandbox', status: 'unsupported' }],
      acceptedRun: true,
      usageAvailable: null,
      latencyMs: 12,
      unauthorizedMutations: 0,
      bundleFileCount: 6,
    },
  ],
  verifiedRowCount: 1,
  rejectedOrUnverifiedCount: 2,
  truncated: false,
  hardOutcomeOnly: true,
  authoritativePerformanceClaim: false,
  calibrationMeaning: 'Harness behavior only; comparative performance is not established.',
}

describe('platform StateBench HTTP client', () => {
  it('refuses a normal user before the operator endpoint is requested', async () => {
    const fake = makeFakeFetch([])
    const client = new HttpPlatformStateBenchClient(
      new HttpTransport({ fetchFn: fake.fetchFn }),
    )

    await expect(client.getMatrix(LOCAL_USER)).rejects.toMatchObject({
      kind: 'unavailable',
    })
    expect(fake.callsTo('/v1/platform/statebench')).toHaveLength(0)
  })

  it('loads and maps the exact closed operator projection', async () => {
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/platform/statebench',
        jsonResponse({ ok: true, result: MATRIX }),
      ],
    ])
    const client = new HttpPlatformStateBenchClient(
      new HttpTransport({ fetchFn: fake.fetchFn }),
    )

    await expect(client.getMatrix(OPERATOR)).resolves.toEqual(MATRIX)
    expect(fake.callsTo('/v1/platform/statebench')).toHaveLength(1)
  })

  it('fails closed on extra fields and contradictory count metadata', () => {
    expect(() =>
      mapPlatformStateBench({
        ...MATRIX,
        rows: [{ ...MATRIX.rows[0], path: '/tmp/private' }],
      }),
    ).toThrow()
    expect(() =>
      mapPlatformStateBench({
        ...MATRIX,
        verifiedRowCount: 0,
      }),
    ).toThrow(/verified-row count/)
    expect(() =>
      mapPlatformStateBench({
        ...MATRIX,
        authoritativePerformanceClaim: true,
      }),
    ).toThrow()
  })
})
