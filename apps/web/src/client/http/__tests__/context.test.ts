/**
 * Context lifecycle contract tests: the view maps the real backend
 * projection, preference updates bind exact policy identity, and manual
 * compact/handoff bind the full continuity identity set.
 */
import { describe, expect, it } from 'vitest'

import { ClientError } from '../../types'
import { HttpTransport } from '../transport'
import { HttpContextClient } from '../domainsExecution'
import { jsonResponse, makeFakeFetch } from './helpers'

const POLICY_DIGEST = `sha256:${'a'.repeat(64)}`
const CONTINUITY_DIGEST = `sha256:${'b'.repeat(64)}`
const WORKTREE_DIGEST = `sha256:${'d'.repeat(64)}`

const VIEW = {
  formatVersion: 'stateport.context-lifecycle-view/v1',
  instanceId: 'ins_1',
  preference: {
    mode: 'balanced',
    availableModes: [
      { id: 'faster', label: 'Faster', description: 'Compact earlier.' },
      { id: 'balanced', label: 'Balanced', description: 'Default thresholds.' },
      { id: 'deeper', label: 'Deeper', description: 'Keep more context.' },
    ],
    rawPromptFieldsAllowed: false,
  },
  effectivePolicy: {
    formatVersion: 'stateport.context-lifecycle-effective/v1',
    sourcePolicies: [
      { scope: 'platform', policyId: 'platform.default', digest: POLICY_DIGEST },
    ],
    unresolvedPolicyScopes: ['template', 'instance', 'backend', 'budget'],
    budget: { maximumInputTokens: 128000, preferredInputTokens: 72000 },
    compression: {
      mode: 'automatic',
      triggerRatio: 0.72,
      preserve: ['active_task', 'requirements', 'exact_git_identity'],
    },
    handoff: {
      mode: 'automatic',
      triggerRatio: 0.9,
      createArtifact: true,
      requireReceipt: true,
    },
    session: {
      resumeOnlyWhen: ['instance_identity_matches', 'base_sha_matches'],
    },
    contextCategories: {
      included: ['active_task', 'requirements', 'exact_git_identity'],
      excluded: ['provider_credentials', 'raw_terminal_transcript'],
    },
    bindingReasons: {
      'budget.maximumInputTokens': ['platform'],
      'budget.preferredInputTokens': ['platform'],
      'compression.mode': ['platform'],
      'compression.triggerRatio': ['platform'],
      'handoff.mode': ['platform'],
      'handoff.triggerRatio': ['platform'],
    },
    authorityClassification: 'operational_noncanonical',
    canonicalStateMutation: false,
    effectivePolicyDigest: POLICY_DIGEST,
  },
  usage: {
    formatVersion: 'stateport.context-usage/v1',
    inputTokens: 3340,
    quality: 'estimated',
    source: 'stateport_estimator',
  },
  usageDisplay: 'Approximately 3340 input tokens from the StatePort estimator; provider accounting is unavailable.',
  gitIdentity: {
    repositoryId: 'repository.1234567890abcdef1234567890abcdef',
    branch: 'main',
    baseSha: 'c'.repeat(40),
    headSha: 'c'.repeat(40),
    treeSha: 'e'.repeat(40),
    worktreeStatusDigest: WORKTREE_DIGEST,
    worktreeClean: true,
  },
  gitIdentityReason: null,
  continuity: {
    available: true,
    reasonCode: null,
    manualCompactAvailable: true,
    manualHandoffAvailable: true,
    continuityDigest: CONTINUITY_DIGEST,
    conversationId: 'conv_1',
    workstreamId: null,
    expectedBaseSha: 'c'.repeat(40),
    expectedPolicyDigest: POLICY_DIGEST,
  },
  storedRecordCount: 2,
  defaultsEvidence: 'candidate_not_benchmarked',
  authorityClassification: 'operational_noncanonical',
  canonicalStateMutation: false,
}

const BINDING = {
  expectedBaseSha: 'c'.repeat(40),
  expectedPolicyDigest: POLICY_DIGEST,
  expectedContinuityDigest: CONTINUITY_DIGEST,
}

describe('HttpContextClient — lifecycle view', () => {
  it('maps the real backend projection honestly', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/instances/ins_1/context-lifecycle', jsonResponse({ ok: true, result: VIEW })],
    ])
    const context = new HttpContextClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const lifecycle = await context.getLifecycle('ins_1')
    expect(lifecycle.preference).toBe('balanced')
    expect(lifecycle.availableModes).toHaveLength(3)
    expect(lifecycle.rawPromptFieldsAllowed).toBe(false)
    expect(lifecycle.policyDigest.value).toBe(POLICY_DIGEST)
    expect(lifecycle.usageDisplay).toMatch(/3340/)
    expect(lifecycle.usage).toMatchObject({
      inputTokens: 3340,
      quality: 'estimated',
      source: 'stateport_estimator',
    })
    expect(lifecycle.effectivePolicy.contextCategories.excluded).toContain('provider_credentials')
    expect(lifecycle.gitIdentity?.headSha).toBe('c'.repeat(40))
    expect(lifecycle.storedRecordCount).toBe(2)
    expect(lifecycle.authorityClassification).toBe('operational_noncanonical')
    expect(lifecycle.canonicalStateMutation).toBe(false)
    expect(lifecycle.continuity.available).toBe(true)
    expect(lifecycle.continuity.continuityDigest).toBe(CONTINUITY_DIGEST)
    expect(lifecycle.continuity.expectedBaseSha).toBe('c'.repeat(40))
    expect(lifecycle.segments).toEqual([])
  })

  it('fails closed on an unknown preference mode', async () => {
    const fake = makeFakeFetch([
      ['GET', '/v1/instances/ins_1/context-lifecycle', jsonResponse({ ok: true, result: { ...VIEW, preference: { mode: 'unlimited' } } })],
    ])
    const context = new HttpContextClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const err = await context.getLifecycle('ins_1').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ClientError)
    expect((err as ClientError).kind).toBe('validation')
  })

  it.each([
    ['missing policy identity', { effectivePolicy: { ...VIEW.effectivePolicy, effectivePolicyDigest: undefined } }],
    ['mismatched instance identity', { instanceId: 'ins_other' }],
    ['canonical mutation claim', { canonicalStateMutation: true }],
    ['wrong authority classification', { authorityClassification: 'canonical' }],
    [
      'continuity policy mismatch',
      {
        continuity: {
          ...VIEW.continuity,
          expectedPolicyDigest: `sha256:${'f'.repeat(64)}`,
        },
      },
    ],
  ])('fails closed on %s', async (_label, override) => {
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/instances/ins_1/context-lifecycle',
        jsonResponse({ ok: true, result: { ...VIEW, ...override } }),
      ],
    ])
    const context = new HttpContextClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const err = await context.getLifecycle('ins_1').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ClientError)
    expect((err as ClientError).kind).toBe('validation')
  })
})

describe('HttpContextClient — preference update', () => {
  it('sends exact instance and policy identities with the mode', async () => {
    const fake = makeFakeFetch([
      ['POST', '/v1/instances/ins_1/context-lifecycle/preference', jsonResponse({ ok: true, result: { ...VIEW, preference: { ...VIEW.preference, mode: 'deeper' } } })],
    ])
    const context = new HttpContextClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const lifecycle = await context.updatePreference('ins_1', { expectedPolicyDigest: POLICY_DIGEST, mode: 'deeper' })
    expect(lifecycle.preference).toBe('deeper')
    const call = fake.callsTo('/v1/instances/ins_1/context-lifecycle/preference')[0]
    expect(call.body).toEqual({
      expectedInstanceId: 'ins_1',
      expectedPolicyDigest: POLICY_DIGEST,
      mode: 'deeper',
    })
    expect(call.headers['x-stateport-csrf']).toBe('test-csrf')
  })
})

describe('HttpContextClient — manual transitions', () => {
  const ARTIFACT_DIGEST = `sha256:${'c'.repeat(64)}`
  const RECEIPT_DIGEST = `sha256:${'e'.repeat(64)}`

  function transitionResponse(
    action: 'compression' | 'handoff',
    receiptId: string,
  ) {
    return {
      artifact: {
        formatVersion:
          action === 'compression'
            ? 'stateport.context-compression/v1'
            : 'stateport.handoff-artifact/v1',
        artifactId: `${action}.artifact`,
        artifactDigest: ARTIFACT_DIGEST,
        instanceId: 'ins_1',
        policyDigest: POLICY_DIGEST,
        sourceContinuityDigest: CONTINUITY_DIGEST,
        authorityClassification: 'ephemeral_noncanonical',
        canonicalStateMutation: false,
      },
      receipt: {
        formatVersion: 'stateport.context-lifecycle-receipt/v1',
        receiptId,
        action,
        outcome: 'completed',
        instanceId: 'ins_1',
        policyDigest: POLICY_DIGEST,
        inputProvenanceDigest: CONTINUITY_DIGEST,
        artifactDigest: ARTIFACT_DIGEST,
        authorityClassification: 'operational_noncanonical',
        canonicalStateMutation: false,
        transcriptRetained: false,
        receiptDigest: RECEIPT_DIGEST,
      },
      canonicalStateUnchanged: true,
    }
  }

  it('compact binds the full continuity identity set and re-reads the view', async () => {
    const fake = makeFakeFetch([
      ['POST', '/v1/instances/ins_1/context-lifecycle/compact', jsonResponse({ ok: true, result: transitionResponse('compression', 'context-receipt.abc123') })],
      ['GET', '/v1/instances/ins_1/context-lifecycle', jsonResponse({ ok: true, result: VIEW })],
    ])
    const context = new HttpContextClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const result = await context.compact('ins_1', BINDING)
    const call = fake.callsTo('/v1/instances/ins_1/context-lifecycle/compact')[0]
    expect(call.body).toEqual({ expectedInstanceId: 'ins_1', ...BINDING })
    expect(result.receiptId).toBe('context-receipt.abc123')
    expect(result.summary).toMatch(/canonical application state is unchanged/)
    expect(result.lifecycle.instanceId).toBe('ins_1')
  })

  it('handoff binds the full continuity identity set', async () => {
    const fake = makeFakeFetch([
      ['POST', '/v1/instances/ins_1/context-lifecycle/handoff', jsonResponse({ ok: true, result: transitionResponse('handoff', 'context-receipt.def456') })],
      ['GET', '/v1/instances/ins_1/context-lifecycle', jsonResponse({ ok: true, result: VIEW })],
    ])
    const context = new HttpContextClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const result = await context.handoff('ins_1', BINDING)
    expect(fake.callsTo('/v1/instances/ins_1/context-lifecycle/handoff')[0].body).toEqual({ expectedInstanceId: 'ins_1', ...BINDING })
    expect(result.receiptId).toBe('context-receipt.def456')
  })

  it('fails closed when the transition returns no receipt identity', async () => {
    const fake = makeFakeFetch([
      ['POST', '/v1/instances/ins_1/context-lifecycle/compact', jsonResponse({ ok: true, result: { artifact: {}, canonicalStateUnchanged: true } })],
    ])
    const context = new HttpContextClient(new HttpTransport({ fetchFn: fake.fetchFn }))
    const err = await context.compact('ins_1', BINDING).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ClientError)
    expect((err as ClientError).kind).toBe('validation')
  })

  it.each([
    [
      'canonical state changed',
      { canonicalStateUnchanged: false },
    ],
    [
      'wrong action',
      { receipt: { action: 'handoff' } },
    ],
    [
      'wrong instance',
      { receipt: { instanceId: 'ins_other' } },
    ],
    [
      'wrong policy',
      { artifact: { policyDigest: `sha256:${'f'.repeat(64)}` } },
    ],
    [
      'wrong continuity',
      {
        receipt: {
          inputProvenanceDigest: `sha256:${'f'.repeat(64)}`,
        },
      },
    ],
    [
      'canonical receipt authority',
      {
        receipt: {
          authorityClassification: 'canonical',
        },
      },
    ],
  ])('fails closed when the transition reports %s', async (_label, patch) => {
    const valid = transitionResponse('compression', 'context-receipt.abc123')
    const result = {
      ...valid,
      ...patch,
      artifact: { ...valid.artifact, ...('artifact' in patch ? patch.artifact : {}) },
      receipt: { ...valid.receipt, ...('receipt' in patch ? patch.receipt : {}) },
    }
    const fake = makeFakeFetch([
      [
        'POST',
        '/v1/instances/ins_1/context-lifecycle/compact',
        jsonResponse({ ok: true, result }),
      ],
    ])
    const context = new HttpContextClient(
      new HttpTransport({ fetchFn: fake.fetchFn }),
    )

    await expect(context.compact('ins_1', BINDING)).rejects.toMatchObject({
      kind: 'validation',
    })
    expect(fake.callsTo('/v1/instances/ins_1/context-lifecycle')).toHaveLength(1)
  })
})
