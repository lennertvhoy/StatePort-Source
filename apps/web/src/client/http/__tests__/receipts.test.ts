/**
 * Receipt claim-state contract tests. Fixtures mirror the persistent
 * activity/receipt projection: operation status and validation evidence are
 * independent, and unsupported or contradictory claims fail closed.
 */
import { describe, expect, it } from 'vitest'

import { ClientError } from '../../types'
import { HttpReceiptsClient } from '../domainsCore'
import { mapReceipt, mapReceiptIndex } from '../mappers'
import { HttpTransport } from '../transport'
import { jsonResponse, makeFakeFetch } from './helpers'

const INSTANCE = 'activity-fixture'
const CREATED_AT = '2026-07-16T12:00:00.000Z'

function indexEntry(overrides: Record<string, unknown>) {
  return {
    receiptId: 'settings-receipt-1',
    receiptType: 'stateport.settings-mutation-receipt/v1',
    action: 'settings.patch',
    status: 'applied',
    createdAt: CREATED_AT,
    sourceKind: 'application_settings',
    payloadDigest: `sha256:${'1'.repeat(64)}`,
    ...overrides,
  }
}

function expectValidationFailure(payload: unknown) {
  expect(() => mapReceipt(payload, INSTANCE)).toThrowError(
    expect.objectContaining({ kind: 'validation' }) as ClientError,
  )
}

describe('receipt claim-state mapping', () => {
  it('keeps an applied settings mutation separate from validation', () => {
    const [receipt] = mapReceiptIndex(
      {
        formatVersion: 'stateport.activity-receipts-projection/v1',
        instanceId: INSTANCE,
        receipts: [indexEntry({})],
      },
      INSTANCE,
    )

    expect(receipt).toMatchObject({
      id: 'settings-receipt-1',
      result: 'applied',
      validation: {
        state: 'not_recorded',
        detail: 'No validation evidence was recorded for this receipt.',
      },
    })
  })

  it.each([
    ['executed', 'executed'],
    ['completed', 'completed'],
  ] as const)('keeps backend status %s non-validated', (status, expected) => {
    const receipt = mapReceipt(
      indexEntry({
        receiptId: `operation-${status}`,
        receiptType: 'stateport.infrastructure-receipt/v1',
        action: 'libvirt.start',
        status,
        sourceKind: 'infrastructure',
      }),
      INSTANCE,
    )

    expect(receipt.result).toBe(expected)
    expect(receipt.validation.state).toBe('not_recorded')
  })

  it('treats the backend backup status verified as explicit validation evidence', () => {
    const receipt = mapReceipt(
      indexEntry({
        receiptId: 'backup-123456789012345678901234',
        receiptType: 'stateport.backup-receipt/v1',
        action: 'backup.create',
        status: 'verified',
        sourceKind: 'application_backup',
      }),
      INSTANCE,
    )

    expect(receipt.result).toBe('validated')
    expect(receipt.validation).toEqual({
      state: 'validated',
      detail: 'The receipt result explicitly records successful validation.',
    })
  })

  it('preserves applied as the operation result when validation evidence passed', () => {
    const receipt = mapReceipt(
      {
        receiptId: 'file-receipt-1',
        instanceId: INSTANCE,
        applicationId: 'stateport.development-reference',
        operation: 'commitWrite',
        result: 'applied',
        validation: 'passed',
        completedAt: CREATED_AT,
      },
      INSTANCE,
    )

    expect(receipt.result).toBe('applied')
    expect(receipt.validation.state).toBe('validated')
  })

  it('does not infer validation from human acceptance', () => {
    const receipt = mapReceipt(
      {
        receiptId: 'orchestration-closure-1',
        instanceId: INSTANCE,
        action: 'orchestration.close',
        status: 'human_accepted',
        createdAt: CREATED_AT,
      },
      INSTANCE,
    )

    expect(receipt.result).toBe('human_accepted')
    expect(receipt.validation.state).toBe('not_recorded')
  })

  it('reads validation evidence from the exact detail payload without changing its result', () => {
    const receipt = mapReceipt(
      {
        ...indexEntry({
          receiptId: 'settings-receipt-validated',
          status: 'applied',
        }),
        payload: {
          receiptId: 'settings-receipt-validated',
          instanceId: INSTANCE,
          status: 'applied',
          validation: {
            status: 'passed',
            detail: 'The expected revision matched after the mutation.',
          },
        },
      },
      INSTANCE,
    )

    expect(receipt.result).toBe('applied')
    expect(receipt.validation).toEqual({
      state: 'validated',
      detail: 'The expected revision matched after the mutation.',
    })
  })

  it('preserves an exact plan digest from the authority receipt payload', () => {
    const planDigest = `sha256:${'7'.repeat(64)}`
    const receipt = mapReceipt(
      {
        ...indexEntry({
          receiptId: 'infra-receipt-plan-bound',
          action: 'libvirt.start',
          status: 'completed',
        }),
        payload: {
          receiptId: 'infra-receipt-plan-bound',
          instanceId: INSTANCE,
          action: 'libvirt.start',
          status: 'completed',
          planDigest,
        },
      },
      INSTANCE,
    )

    expect(receipt.planDigest?.value).toBe(planDigest)
  })

  it('fails closed when indexed and authority receipt plan digests disagree', () => {
    expectValidationFailure({
      ...indexEntry({
        receiptId: 'infra-receipt-plan-mismatch',
        action: 'libvirt.start',
        status: 'completed',
        planDigest: `sha256:${'7'.repeat(64)}`,
      }),
      payload: {
        receiptId: 'infra-receipt-plan-mismatch',
        instanceId: INSTANCE,
        action: 'libvirt.start',
        status: 'completed',
        planDigest: `sha256:${'8'.repeat(64)}`,
      },
    })
  })

  it('maps an indexed governed-run closure as applied and locally validated only', () => {
    const receiptId = 'governed-run.run-0123456789abcdef0123.123456789abc'
    const receipt = mapReceipt(
      {
        receiptId,
        receiptType: 'stateport.governed-run-closure-receipt/v1',
        action: 'governed_run.apply',
        status: 'applied',
        createdAt: CREATED_AT,
        sourceKind: 'governed_run',
        payloadDigest: `sha256:${'4'.repeat(64)}`,
        payload: {
          formatVersion: 'stateport.governed-run-closure-receipt/v1',
          receiptId,
          receiptType: 'stateport.governed-run-closure-receipt/v1',
          action: 'governed_run.apply',
          status: 'applied',
          createdAt: CREATED_AT,
          sourceKind: 'governed_run',
          actor: 'system',
          applicationId: 'checklistdd',
          instanceId: INSTANCE,
          runId: 'run-0123456789abcdef0123',
          validation: {
            state: 'validated',
            detail: 'Local validation passed; human acceptance is not recorded.',
          },
          claimState: {
            applied: true,
            locallyValidated: true,
            humanAccepted: false,
            remotelyAccepted: false,
          },
        },
      },
      INSTANCE,
    )

    expect(receipt).toMatchObject({
      id: receiptId,
      instanceId: INSTANCE,
      packageId: 'checklistdd',
      actionName: 'Application changes applied',
      eventKind: 'governed_run.apply',
      summary: 'Application changes applied.',
      result: 'applied',
      validation: {
        state: 'validated',
        detail: 'Local validation passed; human acceptance is not recorded.',
      },
    })
    expect(JSON.parse(receipt.rawJson).payload.claimState).toEqual({
      applied: true,
      locallyValidated: true,
      humanAccepted: false,
      remotelyAccepted: false,
    })
  })

  it.each([
    ['settings.patch', 'Settings saved'],
    ['backup.create', 'Backup created'],
    ['file_workspace.commitWrite', 'File change saved'],
    ['conversation.export', 'Conversation exported'],
    ['repository.import', 'Repository registered'],
    ['goal_execution.close', 'Orchestration item closed'],
    ['libvirt.start', 'Virtual machine started'],
  ])('keeps raw action %s exact while presenting a human label', (action, label) => {
    const receipt = mapReceipt(
      indexEntry({
        receiptId: `human-${action.replaceAll('.', '-')}`,
        action,
      }),
      INSTANCE,
    )

    expect(receipt.eventKind).toBe(action)
    expect(receipt.actionName).toBe(label)
    expect(receipt.summary).toBe(`${label}.`)
    expect(JSON.parse(receipt.rawJson).action).toBe(action)
  })

  it('maps an indexed conversation lifecycle projection without upgrading its noncanonical claim', () => {
    const lifecycleReceipt = {
      formatVersion: 'stateport.transcript-lifecycle-receipt/v1',
      receiptId: 'transcript-receipt-clear',
      requestId: 'web-clear-0123456789abcdef01234567',
      operation: 'clear',
      applicationId: 'stateport.development-reference',
      instanceId: INSTANCE,
      conversationId: 'conversation-one',
      performedBy: 'local-user',
      occurredAt: CREATED_AT,
      threadIdentity: 'preserved',
      bindingPolicy: 'preserved',
      removed: {
        messages: 2,
        deliveries: 0,
        deduplicationEntries: 2,
        proposals: 0,
        echoGuards: 0,
      },
      authority: 'operational_noncanonical',
      canonicalStateEffect: 'none',
    }
    const receipt = mapReceipt(
      {
        receiptId: lifecycleReceipt.receiptId,
        receiptType: lifecycleReceipt.formatVersion,
        action: 'conversation.clear',
        status: 'completed_without_change',
        createdAt: CREATED_AT,
        sourceKind: 'conversation_lifecycle',
        payloadDigest: `sha256:${'2'.repeat(64)}`,
        payload: {
          receiptId: lifecycleReceipt.receiptId,
          receiptType: lifecycleReceipt.formatVersion,
          action: 'conversation.clear',
          status: 'completed_without_change',
          createdAt: CREATED_AT,
          sourceKind: 'conversation_lifecycle',
          instanceId: INSTANCE,
          applicationId: lifecycleReceipt.applicationId,
          relatedConversationId: lifecycleReceipt.conversationId,
          canonicalStateEffect: 'none',
          lifecycleReceipt,
        },
      },
      INSTANCE,
    )

    expect(receipt).toMatchObject({
      id: lifecycleReceipt.receiptId,
      instanceId: INSTANCE,
      actionName: 'Conversation cleared',
      eventKind: 'conversation.clear',
      summary: 'Conversation cleared.',
      result: 'completed_without_change',
      validation: { state: 'not_recorded' },
    })
    expect(JSON.parse(receipt.rawJson).payload.lifecycleReceipt).toEqual(lifecycleReceipt)
  })

  it.each([
    {
      label: 'file mutation',
      receiptId: 'file-receipt.0123456789abcdef0123456789abcdef',
      receiptType: 'stateport.file-workspace/v1',
      action: 'file_workspace.commitWrite',
      status: 'applied',
      sourceKind: 'file_workspace',
      nestedKey: 'fileMutationReceipt',
      authorityReceipt: {
        formatVersion: 'stateport.file-workspace/v1',
        receiptId: 'file-receipt.0123456789abcdef0123456789abcdef',
        operation: 'commitWrite',
        instanceId: INSTANCE,
      },
      expectedResult: 'applied',
    },
    {
      label: 'goal execution closure',
      receiptId: 'receipt-0123456789abcdef01234567',
      receiptType: 'stateport.goal-execution-receipt/v1',
      action: 'goal_execution.close',
      status: 'completed_without_change',
      sourceKind: 'goal_execution',
      nestedKey: 'goalExecutionReceipt',
      authorityReceipt: {
        formatVersion: 'stateport.goal-execution-receipt/v1',
        receiptId: 'receipt-0123456789abcdef01234567',
        instanceId: INSTANCE,
        canonicalStateEffect: 'none',
      },
      expectedResult: 'completed_without_change',
    },
  ] as const)(
    'maps indexed $label evidence and preserves the authority receipt',
    ({
      receiptId,
      receiptType,
      action,
      status,
      sourceKind,
      nestedKey,
      authorityReceipt,
      expectedResult,
    }) => {
      const receipt = mapReceipt(
        {
          receiptId,
          receiptType,
          action,
          status,
          createdAt: CREATED_AT,
          sourceKind,
          payload: {
            receiptId,
            receiptType,
            action,
            status,
            createdAt: CREATED_AT,
            sourceKind,
            instanceId: INSTANCE,
            [nestedKey]: authorityReceipt,
          },
        },
        INSTANCE,
      )

      expect(receipt.result).toBe(expectedResult)
      expect(receipt.validation.state).toBe('not_recorded')
      expect(JSON.parse(receipt.rawJson).payload[nestedKey]).toEqual(authorityReceipt)
    },
  )

  it('fails closed on contradictory outcome claims', () => {
    expectValidationFailure({
      ...indexEntry({}),
      result: 'validated',
      status: 'applied',
    })
  })

  it('fails closed when a validated outcome carries failed validation evidence', () => {
    expectValidationFailure({
      ...indexEntry({}),
      status: 'validated',
      validation: { state: 'failed', detail: 'Validator exited non-zero.' },
    })
  })

  it.each(['success', 'succeeded', 'passed', 'healthy'])(
    'fails closed on unsupported generic success status %s',
    (status) => {
      expectValidationFailure(indexEntry({ status }))
    },
  )

  it('fails closed on mismatched detail identities and statuses', () => {
    expectValidationFailure({
      ...indexEntry({}),
      payload: {
        receiptId: 'different-receipt',
        instanceId: INSTANCE,
        status: 'applied',
      },
    })
    expectValidationFailure({
      ...indexEntry({}),
      payload: {
        receiptId: 'settings-receipt-1',
        instanceId: INSTANCE,
        status: 'completed',
      },
    })
  })

  it('fails closed when an explicit receipt or projection instance conflicts with the scoped request', () => {
    expectValidationFailure({
      ...indexEntry({}),
      instanceId: 'different-instance',
    })
    expect(() =>
      mapReceiptIndex(
        {
          formatVersion: 'stateport.activity-receipts-projection/v1',
          instanceId: 'different-instance',
          receipts: [indexEntry({})],
        },
        INSTANCE,
      ),
    ).toThrowError(expect.objectContaining({ kind: 'validation' }) as ClientError)
  })

  it('fails closed on unsupported validation shapes', () => {
    expectValidationFailure({
      ...indexEntry({}),
      validation: { valid: true, issues: [] },
    })
  })
})

describe('receipt application scoping', () => {
  function detail(instanceId: string) {
    return {
      formatVersion: 'stateport.activity-receipts-projection/v1',
      instanceId,
      receipt: {
        ...indexEntry({ receiptId: 'shared-receipt' }),
        instanceId,
      },
    }
  }

  it('keeps duplicate receipt IDs distinct across application instances', async () => {
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/instances/instance-a/receipts/shared-receipt',
        jsonResponse({ ok: true, result: detail('instance-a') }),
      ],
      [
        'GET',
        '/v1/instances/instance-b/receipts/shared-receipt',
        jsonResponse({ ok: true, result: detail('instance-b') }),
      ],
    ])
    const client = new HttpReceiptsClient(
      new HttpTransport({ fetchFn: fake.fetchFn }),
    )

    const first = await client.get('shared-receipt', 'instance-a')
    const second = await client.get('shared-receipt', 'instance-b')

    expect(first.instanceId).toBe('instance-a')
    expect(second.instanceId).toBe('instance-b')
    expect(fake.callsTo('/receipts/shared-receipt')).toHaveLength(2)
  })

  it('rejects a receipt detail envelope for a different application', async () => {
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/instances/instance-a/receipts/shared-receipt',
        jsonResponse({ ok: true, result: detail('instance-b') }),
      ],
    ])
    const client = new HttpReceiptsClient(
      new HttpTransport({ fetchFn: fake.fetchFn }),
    )

    const error = await client
      .get('shared-receipt', 'instance-a')
      .catch((caught: unknown) => caught)
    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).kind).toBe('validation')
  })

  it('rejects a receipt detail response with a different receipt identity', async () => {
    const fake = makeFakeFetch([
      [
        'GET',
        '/v1/instances/instance-a/receipts/requested-receipt',
        jsonResponse({ ok: true, result: detail('instance-a').receipt }),
      ],
    ])
    const client = new HttpReceiptsClient(
      new HttpTransport({ fetchFn: fake.fetchFn }),
    )

    const error = await client
      .get('requested-receipt', 'instance-a')
      .catch((caught: unknown) => caught)
    expect(error).toBeInstanceOf(ClientError)
    expect((error as ClientError).kind).toBe('validation')
    expect((error as ClientError).detail).toContain('expected requested-receipt')
  })
})

describe('goal-execution fan-out', () => {
  const receiptsProjection = {
    formatVersion: 'stateport.activity-receipts-projection/v1',
    instanceId: INSTANCE,
    receipts: [],
  }

  it('does not poll goal-execution when the caller knows the capability is absent', async () => {
    const fake = makeFakeFetch([
      [
        'GET',
        `/v1/instances/${INSTANCE}/receipts`,
        jsonResponse({ ok: true, result: receiptsProjection }),
      ],
    ])
    const client = new HttpReceiptsClient(
      new HttpTransport({ fetchFn: fake.fetchFn }),
    )

    const items = await client.list({ instanceId: INSTANCE, goalExecution: false })

    expect(items).toEqual([])
    expect(fake.callsTo(`/v1/instances/${INSTANCE}/receipts`)).toHaveLength(1)
    expect(fake.callsTo('/goal-execution')).toHaveLength(0)
  })

  it('polls goal-execution by default and tolerates the fail-closed 403', async () => {
    const fake = makeFakeFetch([
      [
        'GET',
        `/v1/instances/${INSTANCE}/receipts`,
        jsonResponse({ ok: true, result: receiptsProjection }),
      ],
      [
        'GET',
        `/v1/instances/${INSTANCE}/goal-execution`,
        jsonResponse(
          { ok: false, error: { code: 'goal_execution_access_denied', message: 'goal execution access denied' } },
          403,
        ),
      ],
    ])
    const client = new HttpReceiptsClient(
      new HttpTransport({ fetchFn: fake.fetchFn }),
    )

    const items = await client.list({ instanceId: INSTANCE })

    expect(items).toEqual([])
    expect(fake.callsTo(`/v1/instances/${INSTANCE}/goal-execution`)).toHaveLength(1)
  })
})
