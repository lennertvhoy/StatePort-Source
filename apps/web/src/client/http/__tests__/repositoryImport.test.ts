/**
 * Repository import contract tests: discovery maps allowlisted candidates,
 * inspection binds the candidate identity, and registration sends the exact
 * inspected digest, the instance identity derived deterministically from that
 * digest (idempotent across retries), and the actor's approval.
 */
import { describe, expect, it } from 'vitest'

import { ClientError } from '../../types'
import { HttpTransport } from '../transport'
import { HttpRepositoryImportClient } from '../domainsCore'
import { mapRepositoryInspection } from '../mappers'
import { jsonResponse, makeFakeFetch } from './helpers'

const CANDIDATES = {
  candidates: [
    {
      candidateId: 'cand_alpha',
      displayName: 'alpha-project',
      relativeLocation: 'projects/alpha-project',
      inspection: { inspectionDigest: 'x'.repeat(64) },
    },
  ],
  policy: { allowlistedRoots: ['projects'] },
}

const INSPECTION = {
  formatVersion: 'stateport.repository-inspection/v1',
  sourceKind: 'local',
  source: 'projects/alpha-project',
  candidateId: 'cand_alpha',
  sourceIdentity: {
    branch: 'main',
    headCommit: 'c'.repeat(40),
    dirty: false,
  },
  stateSpec: { classification: 'application-shaped' },
  safetyFindings: [
    { code: 'symlinks_present', severity: 'warning', message: 'Symlink entries are present and will not be followed during materialization.' },
  ],
  inspectionDigest: 'd'.repeat(64),
  mutated: false,
}

const STATUS = { ok: true, result: { state: 'connected', actor: { role: 'local_user', actorId: 'local-user' } } }

const TEMPLATE_INSPECTION = {
  ...INSPECTION,
  inspectionDigest: `sha256:${'d'.repeat(64)}`,
  template: {
    formatVersion: 'stateport.template-adapter-match/v1',
    adapterId: 'projectstate-v6',
    applicationId: 'stateport.template.projectstate',
    displayName: 'ProjectState',
    description: 'An isolated ProjectState workspace.',
    templateKind: 'projectstate_v6',
    declaredTemplateId: 'projectstate',
    declaredVersion: 'projectstate-template-v6',
    markerFiles: ['PROJECT.md', 'STATE.yaml'],
    requestedCapabilities: ['conversation', 'progress_dashboard'],
    trustedActionIds: ['stateport.template.projectstate.inspect/v1'],
    executionTrust: 'stateport_owned_adapter_only',
    repositoryCommandsExecuted: false,
    validation: { status: 'passed', issues: [] },
  },
}

type RegistrationMismatch =
  | 'entry-instance'
  | 'inspection-candidate'
  | 'inspection-digest'
  | 'approval-digest'
  | 'receipt-instance'
  | 'receipt-digest'

function registrationResult(
  body: {
    candidateId: string
    inspectionDigest: string
    instanceId: string
  },
  mismatch?: RegistrationMismatch,
) {
  const result = {
    entry: {
      applicationId: 'nixos-infrastructure',
      instanceId: body.instanceId,
      status: 'active',
    },
    inspection: {
      ...INSPECTION,
      candidateId: body.candidateId,
      inspectionDigest: body.inspectionDigest,
    },
    conversationId: 'conv_1',
    receipt: {
      formatVersion: 'stateport.repository-import-receipt/v1',
      receiptId: 'repository-import-abc',
      instanceId: body.instanceId,
      inspectionDigest: body.inspectionDigest,
      approval: {
        actorId: 'local-user',
        proposalDigest: body.inspectionDigest,
      },
    },
  }
  if (mismatch === 'entry-instance') result.entry.instanceId = 'ins_other'
  if (mismatch === 'inspection-candidate') result.inspection.candidateId = 'cand_other'
  if (mismatch === 'inspection-digest') result.inspection.inspectionDigest = 'e'.repeat(64)
  if (mismatch === 'approval-digest') result.receipt.approval.proposalDigest = 'e'.repeat(64)
  if (mismatch === 'receipt-instance') result.receipt.instanceId = 'ins_other'
  if (mismatch === 'receipt-digest') result.receipt.inspectionDigest = 'e'.repeat(64)
  return result
}

describe('HttpRepositoryImportClient', () => {
  it.each([{ issues: [] }, { issues: [{ code: 'statespec_template_invalid', message: 'spec is required' }] }])(
    'keeps failed template validation blocking for $issues', ({ issues }) => {
      const inspection = mapRepositoryInspection({
        ...INSPECTION,
        template: { validation: { status: 'failed', issues }, repositoryCommandsExecuted: false },
      })
      expect(inspection.template).toBeUndefined()
      expect(inspection.findings.some((finding) => finding.severity === 'error')).toBe(true)
      if (issues.length) expect(inspection.findings).toContainEqual({ ...issues[0], severity: 'error' })
    },
  )

  it('maps allowlisted local candidates', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/repository-import/local-candidates', jsonResponse({ ok: true, result: CANDIDATES })],
    ])
    const client = new HttpRepositoryImportClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const candidates = await client.listLocalCandidates()
    expect(candidates).toEqual([
      {
        candidateId: 'cand_alpha',
        displayName: 'alpha-project',
        relativeLocation: 'projects/alpha-project',
        suggestedPackageId: undefined,
      },
    ])
  })

  it('inspects by candidate identity, never by raw path', async () => {
    const fake = makeFakeFetch([
      ['POST', '/v1/repository-import/inspect', jsonResponse({ ok: true, result: INSPECTION })],
    ])
    const client = new HttpRepositoryImportClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const inspection = await client.inspect('cand_alpha')
    expect(fake.callsTo('/v1/repository-import/inspect')[0].body).toEqual({ candidateId: 'cand_alpha' })
    expect(inspection.inspectionDigest).toBe('d'.repeat(64))
    expect(inspection.branch).toBe('main')
    expect(inspection.dirty).toBe(false)
    expect(inspection.mutated).toBe(false)
    expect(inspection.findings).toHaveLength(1)
  })

  it('plans and installs a detected template as an isolated managed copy', async () => {
    const planDigest = `sha256:${'a'.repeat(64)}`
    const receiptDigest = `sha256:${'b'.repeat(64)}`
    const fake = makeFakeFetch([
      ['GET', '/v1/status', jsonResponse(STATUS)],
      [
        'POST',
        '/v1/template-import/plan',
        (call) => {
          const body = call.body as Record<string, string>
          return jsonResponse({
            ok: true,
            result: {
              formatVersion: 'stateport.template-import-plan/v1',
              operation: 'template-import',
              candidateId: body.candidateId,
              inspectionDigest: body.inspectionDigest,
              instanceId: body.instanceId,
              name: body.name,
              template: TEMPLATE_INSPECTION.template,
              planDigest,
            },
          })
        },
      ],
      [
        'POST',
        '/v1/template-import/install',
        (call) => {
          const body = call.body as { plan: Record<string, string> }
          return jsonResponse({
            ok: true,
            result: {
              formatVersion: 'stateport.template-install-result/v1',
              instanceId: body.plan.instanceId,
              applicationId: 'stateport.template.projectstate',
              conversationId: 'conv_template',
              receiptId: 'template-import-abc',
              receiptDigest,
              sourceRepositoryMutated: false,
              managedCopyCreated: true,
            },
          })
        },
      ],
    ])
    const client = new HttpRepositoryImportClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const inspection = mapRepositoryInspection(TEMPLATE_INSPECTION)
    const result = await client.installTemplate({
      candidateId: 'cand_alpha',
      name: 'My ProjectState',
      inspection,
      approved: true,
    })

    const planCall = fake.callsTo('/v1/template-import/plan')[0]
    const planned = planCall.body as Record<string, string>
    expect(planned.instanceId).toMatch(/^template-[0-9a-f]{16}$/)
    expect(planned.inspectionDigest).toBe(TEMPLATE_INSPECTION.inspectionDigest)
    const installCall = fake.callsTo('/v1/template-import/install')[0]
    expect((installCall.body as { approval: object }).approval).toEqual({
      decision: 'approve',
      actorId: 'local-user',
      planDigest,
    })
    expect(result).toEqual({
      instanceId: planned.instanceId,
      conversationId: 'conv_template',
      receiptId: 'template-import-abc',
    })
  })

  it('preserves a missing mutation claim as unknown', async () => {
    const withoutMutationClaim = Object.fromEntries(
      Object.entries(INSPECTION).filter(([key]) => key !== 'mutated'),
    )
    const fake = makeFakeFetch([
      ['POST', '/v1/repository-import/inspect', jsonResponse({ ok: true, result: withoutMutationClaim })],
    ])
    const client = new HttpRepositoryImportClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    const inspection = await client.inspect('cand_alpha')
    expect(inspection.mutated).toBeUndefined()
  })

  it('fails closed when inspection returns a different candidate identity', async () => {
    const fake = makeFakeFetch([
      [
        'POST',
        '/v1/repository-import/inspect',
        jsonResponse({ ok: true, result: { ...INSPECTION, candidateId: 'cand_other' } }),
      ],
    ])
    const client = new HttpRepositoryImportClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    await expect(client.inspect('cand_alpha')).rejects.toMatchObject({
      kind: 'validation',
      message: 'Repository inspection returned a mismatched candidate identity',
    })
  })

  it('fails closed when the inspection carries no digest', async () => {
    const fake = makeFakeFetch([
      ['POST', '/v1/repository-import/inspect', jsonResponse({ ok: true, result: { source: 'x' } })],
    ])
    const client = new HttpRepositoryImportClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const err = await client.inspect('cand_alpha').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ClientError)
    expect((err as ClientError).kind).toBe('validation')
  })

  it('registers with exact digest, deterministic instance identity, and actor approval', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/status', jsonResponse(STATUS)],
      [
        'POST',
        '/v1/repository-import/register',
        (call) => jsonResponse({
          ok: true,
          result: registrationResult(call.body as {
            candidateId: string
            inspectionDigest: string
            instanceId: string
          }),
        }),
      ],
    ])
    const client = new HttpRepositoryImportClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const result = await client.register({
      candidateId: 'cand_alpha',
      name: 'Alpha Project',
      inspectionDigest: 'd'.repeat(64),
      approved: true,
    })
    const call = fake.callsTo('/v1/repository-import/register')[0]
    const body = call.body as Record<string, unknown>
    expect(body.candidateId).toBe('cand_alpha')
    expect(body.inspectionDigest).toBe('d'.repeat(64))
    // SHA-256 truncation of `stateport:external-instance:<inspectionDigest>`.
    expect(body.instanceId).toBe('ins-0ca56219647a4b74')
    expect(String(body.instanceId)).toMatch(/^ins-[0-9a-f]{16}$/)
    expect(body.name).toBe('Alpha Project')
    expect(body.approval).toEqual({ decision: 'approve', actorId: 'local-user', proposalDigest: 'd'.repeat(64) })
    expect(call.headers['x-stateport-csrf']).toBe('test-csrf')
    expect(result).toEqual({
      instanceId: body.instanceId,
      conversationId: 'conv_1',
      receiptId: 'repository-import-abc',
    })
  })

  it('re-sends the same instance identity on a retry of the same inspection', async () => {
    // Simulates a retry after a lost/ambiguous response: the backend's
    // idempotency path returns the existing registration for the same
    // instanceId + resolved path instead of a duplicate-instance error.
    const fake = makeFakeFetch([
      ['GET', '/v1/status', jsonResponse(STATUS)],
      [
        'POST',
        '/v1/repository-import/register',
        (call) => jsonResponse({
          ok: true,
          result: registrationResult(call.body as {
            candidateId: string
            inspectionDigest: string
            instanceId: string
          }),
        }),
      ],
    ])
    const client = new HttpRepositoryImportClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const input = {
      candidateId: 'cand_alpha',
      name: 'Alpha Project',
      inspectionDigest: 'd'.repeat(64),
      approved: true,
    }

    const first = await client.register(input)
    const second = await client.register(input)

    const calls = fake.callsTo('/v1/repository-import/register')
    expect(calls).toHaveLength(2)
    const firstId = (calls[0].body as { instanceId: string }).instanceId
    const secondId = (calls[1].body as { instanceId: string }).instanceId
    expect(secondId).toBe(firstId)
    // The idempotent retry resolves to the same registration.
    expect(second).toEqual(first)
  })

  it('derives different instance identities for different inspections', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/status', jsonResponse(STATUS)],
      [
        'POST',
        '/v1/repository-import/register',
        (call) => jsonResponse({
          ok: true,
          result: registrationResult(call.body as {
            candidateId: string
            inspectionDigest: string
            instanceId: string
          }),
        }),
      ],
    ])
    const client = new HttpRepositoryImportClient(new HttpTransport({ fetchFn: fake.fetchFn }))

    await client.register({
      candidateId: 'cand_alpha',
      name: 'Alpha Project',
      inspectionDigest: 'd'.repeat(64),
      approved: true,
    })
    await client.register({
      candidateId: 'cand_alpha',
      name: 'Alpha Project',
      inspectionDigest: 'e'.repeat(64),
      approved: true,
    })

    const calls = fake.callsTo('/v1/repository-import/register')
    const ids = calls.map((call) => (call.body as { instanceId: string }).instanceId)
    expect(ids[0]).toBe('ins-0ca56219647a4b74')
    expect(ids[1]).toBe('ins-647af544367b5793')
    expect(new Set(ids).size).toBe(2)
  })

  it.each([
    'entry-instance',
    'inspection-candidate',
    'inspection-digest',
    'approval-digest',
    'receipt-instance',
    'receipt-digest',
  ] satisfies RegistrationMismatch[])(
    'fails closed when registration returns a mismatched %s binding',
    async (mismatch) => {
      const fake = makeFakeFetch([
        ['GET', '/v1/status', jsonResponse(STATUS)],
        [
          'POST',
          '/v1/repository-import/register',
          (call) => jsonResponse({
            ok: true,
            result: registrationResult(
              call.body as {
                candidateId: string
                inspectionDigest: string
                instanceId: string
              },
              mismatch,
            ),
          }),
        ],
      ])
      const client = new HttpRepositoryImportClient(new HttpTransport({ fetchFn: fake.fetchFn }))

      await expect(client.register({
        candidateId: 'cand_alpha',
        name: 'Alpha Project',
        inspectionDigest: 'd'.repeat(64),
        approved: true,
      })).rejects.toMatchObject({ kind: 'validation' })
    },
  )

  it('refuses to register without explicit approval before any request', async () => {
    const fake = makeFakeFetch([])
    const client = new HttpRepositoryImportClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const err = await client
      .register({ candidateId: 'cand_alpha', name: 'x', inspectionDigest: 'd'.repeat(64), approved: false })
      .catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ClientError)
    expect((err as ClientError).kind).toBe('validation')
    expect(fake.callsTo('/v1/repository-import/register')).toHaveLength(0)
  })
})
