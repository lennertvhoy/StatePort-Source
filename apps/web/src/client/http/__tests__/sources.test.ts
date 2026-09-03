/**
 * Canonical-source contract tests: public reads remain bounded, operator
 * detail is exact and permission-shaped, and development verification binds
 * every immutable candidate field plus CSRF.
 */
import { describe, expect, it } from 'vitest'

import { ClientError } from '../../types'
import { HttpSessionClient } from '../domainsCore'
import { HttpSourcesClient } from '../domainsSources'
import { HttpTransport } from '../transport'
import { jsonResponse, makeFakeFetch } from './helpers'

const SOURCE_ID = 'stateport.source.studystate'
const REPOSITORY = 'https://github.com/example/studystate.git'
const COMMIT = '7b8a6449361578264952f985d70655233e870b4e'
const TREE = '3ade73c663dcb48fb4992138a0a135e5640959ba'
const MANIFEST_DIGEST = `sha256:${'4'.repeat(64)}`
const SOURCE_DIGEST = `sha256:${'6'.repeat(64)}`
const ACKNOWLEDGEMENT = `sha256:${'a'.repeat(64)}`

const PUBLIC_SOURCE = {
  formatVersion: 'stateport.canonical-source-public-view/v1',
  sourceId: SOURCE_ID,
  applicationId: 'study-state',
  publicName: 'StudyState',
  status: 'awaiting_verified_release',
  installable: false,
  productionAction: { action: 'install_or_update', enabled: false },
  message: 'Application source is awaiting a verified release.',
}

const IDENTITY = {
  repository: REPOSITORY,
  commit: COMMIT,
  tree: TREE,
  manifestDigest: MANIFEST_DIGEST,
  sourceDigest: SOURCE_DIGEST,
}

const OPERATOR_SOURCE = {
  formatVersion: 'stateport.canonical-source-operator-view/v1',
  sourceId: SOURCE_ID,
  application: {
    id: 'study-state',
    publicName: 'StudyState',
    legacyIdentifiers: ['studydd', 'StudyDD_Template'],
  },
  authority: {
    repository: REPOSITORY,
    canonicalRefPolicy: 'immutable_release_tag',
    manifestPath: '.statedd/manifest.yaml',
    manifestContract: 'statedd.template-manifest/v2',
  },
  canonicalRelease: {
    sourceClass: 'canonical_release',
    identity: null,
    status: 'awaiting_verified_release',
    trust: 'development_only',
    installable: false,
    missingRequirement: 'canonical_release_not_published',
    requiredModules: ['studydd.core'],
    expectedSelfTests: ['core-health'],
  },
  developmentCandidate: {
    sourceClass: 'development_candidate',
    releaseStatus: 'candidate',
    testingAllowed: true,
    productionInstallAllowed: false,
    identity: IDENTITY,
    verifiedModules: ['studydd.core'],
    verifiedSelfTests: ['core-health'],
    verificationAction: {
      enabled: true,
      acknowledgement: ACKNOWLEDGEMENT,
      purpose: 'isolated_development_verification_only',
    },
  },
  message: 'Application source is awaiting a verified release.',
}

const RESOLUTION = {
  formatVersion: 'stateport.development-source-resolution/v1',
  sourceId: SOURCE_ID,
  applicationId: 'study-state',
  sourceClass: 'development_candidate',
  identity: IDENTITY,
  releaseStatus: 'candidate',
  trust: 'development_only',
  productionInstallAllowed: false,
  verifiedModules: ['studydd.core'],
  requiredSelfTests: ['core-health'],
  selfTestDeclarationsMatched: true,
  selfTestsExecutedByThisOperation: false,
  verifiedAt: '2026-07-18T12:00:00+00:00',
  receiptDigest: `sha256:${'b'.repeat(64)}`,
}

describe('HttpSourcesClient', () => {
  it('maps only the bounded public registry projection', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/sources', jsonResponse({ ok: true, result: { sources: [PUBLIC_SOURCE] } })],
    ])
    const client = new HttpSourcesClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    await expect(client.list()).resolves.toEqual([PUBLIC_SOURCE])
  })

  it('fails closed when the public projection contains operator evidence', async () => {
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/sources',
        jsonResponse({
          ok: true,
          result: {
            sources: [{ ...PUBLIC_SOURCE, repository: REPOSITORY }],
          },
        }),
      ],
    ])
    const client = new HttpSourcesClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const error = await client.list().catch((reason: unknown) => reason)
    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).kind).toBe('validation')
  })

  it('reads the exact redacted operator projection and rejects identity substitution', async () => {
    const fake = makeFakeFetch([
      [
        'GET',
        `/v1/sources/${SOURCE_ID}`,
        jsonResponse({ ok: true, result: OPERATOR_SOURCE }),
      ],
    ])
    const client = new HttpSourcesClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    await expect(client.getOperatorDetail(SOURCE_ID)).resolves.toEqual(OPERATOR_SOURCE)
    await expect(client.getOperatorDetail('stateport.source.other')).rejects.toMatchObject({
      kind: 'http',
      status: 404,
    })
  })

  it('sends the exact candidate identity with CSRF and validates its receipt', async () => {
    const fake = makeFakeFetch([
      [
        'POST',
        `/v1/sources/${SOURCE_ID}/development-resolve`,
        jsonResponse({ ok: true, result: RESOLUTION }),
      ],
    ])
    const client = new HttpSourcesClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const input = {
      sourceId: SOURCE_ID,
      sourceClass: 'development_candidate' as const,
      expectedCommit: COMMIT,
      expectedTree: TREE,
      expectedManifestDigest: MANIFEST_DIGEST,
      expectedSourceDigest: SOURCE_DIGEST,
      acknowledgement: ACKNOWLEDGEMENT,
    }
    await expect(client.verifyDevelopmentCandidate(input)).resolves.toEqual(RESOLUTION)
    const call = fake.callsTo(`/v1/sources/${SOURCE_ID}/development-resolve`)[0]
    expect(call.body).toEqual(input)
    expect(call.headers['x-stateport-csrf']).toBe('test-csrf')
  })

  it('rejects a verification receipt for a different immutable identity', async () => {
    const fake = makeFakeFetch([
      [
        'POST',
        `/v1/sources/${SOURCE_ID}/development-resolve`,
        jsonResponse({
          ok: true,
          result: {
            ...RESOLUTION,
            identity: { ...IDENTITY, commit: 'f'.repeat(40) },
          },
        }),
      ],
    ])
    const client = new HttpSourcesClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    await expect(
      client.verifyDevelopmentCandidate({
        sourceId: SOURCE_ID,
        sourceClass: 'development_candidate',
        expectedCommit: COMMIT,
        expectedTree: TREE,
        expectedManifestDigest: MANIFEST_DIGEST,
        expectedSourceDigest: SOURCE_DIGEST,
        acknowledgement: ACKNOWLEDGEMENT,
      }),
    ).rejects.toMatchObject({ kind: 'validation' })
  })
})

describe('service actor projection', () => {
  it('preserves the backend actor role used to gate operator UI', async () => {
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/status',
        jsonResponse({
          ok: true,
          result: {
            state: 'connected',
            actor: {
              role: 'platform_operator',
              actorId: 'platform-operator',
              platformOperationsAllowed: true,
              statebenchInspectionAllowed: true,
            },
          },
        }),
      ],
    ])
    const client = new HttpSessionClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const status = await client.getLocalServiceStatus()
    expect(status.actor).toEqual({
      role: 'platform_operator',
      actorId: 'platform-operator',
      platformOperationsAllowed: true,
      statebenchInspectionAllowed: true,
    })
  })
})

describe('service execution runtime projection', () => {
  it('surfaces the execution-host socket truth as unavailable with reason', async () => {
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/status',
        jsonResponse({
          ok: true,
          result: {
            state: 'connected',
            runtime: {
              status: 'unavailable',
              reason: 'execution_socket_unreachable',
              detail: 'Execution host control socket is not reachable from this service; container execution cannot start.',
              socketPath: '/run/stateport-execution/control.sock',
              socketPresent: false,
              peerPolicy: 'unix-peer-credentials-required',
              workerExecutionEnabled: false,
            },
          },
        }),
      ],
    ])
    const client = new HttpSessionClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const status = await client.getLocalServiceStatus()
    expect(status.runtime).toEqual({
      status: 'unavailable',
      reason: 'execution_socket_unreachable',
      detail: 'Execution host control socket is not reachable from this service; container execution cannot start.',
      socketPath: '/run/stateport-execution/control.sock',
      socketPresent: false,
      peerPolicy: 'unix-peer-credentials-required',
      workerExecutionEnabled: false,
    })
  })

  it('maps an available runtime without inventing fields', async () => {
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/status',
        jsonResponse({
          ok: true,
          result: {
            state: 'connected',
            runtime: { status: 'available', socketPresent: true, workerExecutionEnabled: true },
          },
        }),
      ],
    ])
    const client = new HttpSessionClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const status = await client.getLocalServiceStatus()
    expect(status.runtime?.status).toBe('available')
    expect(status.runtime?.socketPresent).toBe(true)
    expect(status.runtime?.workerExecutionEnabled).toBe(true)
    expect(status.runtime?.reason).toBeUndefined()
  })

  it('tolerates a status payload without a runtime field', async () => {
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/status',
        jsonResponse({ ok: true, result: { state: 'connected' } }),
      ],
    ])
    const client = new HttpSessionClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const status = await client.getLocalServiceStatus()
    expect(status.runtime).toBeUndefined()
    expect(status.state).toBe('connected')
  })
})
