/**
 * Unit tests for the pure receipts model: filtering, store mapping, day
 * grouping, related clustering, and export serialization.
 */
import { describe, expect, it } from 'vitest'

import type { Receipt } from '@/client'

import {
  DEFAULT_RECEIPTS_FILTER,
  actionKindGroupId,
  activeFilterCount,
  actorLabel,
  applyReceiptsFilter,
  connectedReceiptIds,
  dayLabel,
  defaultFilter,
  fromStoredFilter,
  groupReceiptsByDay,
  isPresetActive,
  normalizeReceiptDigest,
  parseReceiptDigest,
  RECEIPT_FILTER_PRESETS,
  receiptsToCsv,
  receiptsToJson,
  toStoredFilter,
} from '../receiptsModel'

function makeReceipt(overrides: Partial<Receipt> & { id: string }): Receipt {
  return {
    instanceId: 'ins_test',
    packageId: 'pkg_test',
    actionName: 'File change saved',
    eventKind: 'file.write',
    actor: 'user',
    result: 'validated',
    createdAt: '2025-01-10T12:00:00.000Z',
    validation: { state: 'validated', detail: 'ok' },
    summary: 'A thing happened.',
    rawJson: '{}',
    ...overrides,
  }
}

const NOW = new Date('2025-01-10T15:00:00.000Z').getTime()

describe('filter store mapping', () => {
  it('round-trips the view filter through the stored ReceiptFilter shape', () => {
    const filter = {
      ...DEFAULT_RECEIPTS_FILTER,
      query: 'backup',
      result: 'failed' as const,
      actionKind: 'file',
      actor: 'assistant' as const,
      dateRange: 'week' as const,
      view: 'timeline' as const,
      groupRelated: false,
      sort: 'oldest' as const,
    }
    const restored = fromStoredFilter(toStoredFilter(filter), false)
    expect(restored).toEqual(filter)
  })

  it('omits empty query / all-result from the client-contract fields', () => {
    const stored = toStoredFilter(DEFAULT_RECEIPTS_FILTER)
    expect(stored.query).toBeUndefined()
    expect(stored.result).toBeUndefined()
  })

  it('defaults to timeline on mobile and table on desktop when nothing stored', () => {
    expect(defaultFilter(true).view).toBe('timeline')
    expect(defaultFilter(false).view).toBe('table')
    expect(fromStoredFilter(undefined, true).view).toBe('timeline')
  })

  it('ignores malformed stored extras', () => {
    const restored = fromStoredFilter(
      { query: 'x', view: 'banana', actor: 'nobody', dateRange: 'century' } as never,
      false,
    )
    expect(restored.query).toBe('x')
    expect(restored.view).toBe('table')
    expect(restored.actor).toBe('all')
    expect(restored.dateRange).toBe('all')
  })
})

describe('receipt digest parsing', () => {
  it('accepts only a prefixed lowercase sha256 digest and preserves the prefix', () => {
    const digest = `sha256:${'a'.repeat(64)}`
    expect(parseReceiptDigest(digest)).toBe(digest)
    expect(normalizeReceiptDigest(digest)).toBe('a'.repeat(64))
  })

  it.each([
    'a'.repeat(64),
    `sha256:${'a'.repeat(63)}`,
    `sha256:${'A'.repeat(64)}`,
    `sha512:${'a'.repeat(64)}`,
  ])('rejects malformed digest %s', (value) => {
    expect(parseReceiptDigest(value)).toBeNull()
  })
})

describe('applyReceiptsFilter', () => {
  const receipts: Receipt[] = [
    makeReceipt({ id: 'rcpt_1', actionName: 'File change saved', eventKind: 'file.write', createdAt: '2025-01-10T10:00:00.000Z' }),
    makeReceipt({
      id: 'rcpt_2',
      actionName: 'Virtual machine started',
      eventKind: 'infrastructure.start',
      actor: 'assistant',
      result: 'failed',
      createdAt: '2025-01-09T10:00:00.000Z',
    }),
    makeReceipt({
      id: 'rcpt_3',
      actionName: 'Daily-driver authorization granted',
      eventKind: 'authorization.grant',
      actor: 'system',
      createdAt: '2025-01-01T10:00:00.000Z',
    }),
  ]

  it('matches human action names, not only raw event kinds', () => {
    const out = applyReceiptsFilter(receipts, { ...DEFAULT_RECEIPTS_FILTER, query: 'virtual machine' }, NOW)
    expect(out.map((r) => r.id)).toEqual(['rcpt_2'])
  })

  it('filters by action-kind group across event-kind prefixes', () => {
    const out = applyReceiptsFilter(receipts, { ...DEFAULT_RECEIPTS_FILTER, actionKind: 'approval' }, NOW)
    expect(out.map((r) => r.id)).toEqual(['rcpt_3'])
    expect(actionKindGroupId('authorization.grant')).toBe('approval')
    expect(actionKindGroupId('file_workspace.commitWrite')).toBe('file')
    expect(actionKindGroupId('libvirt.start')).toBe('infrastructure')
    expect(actionKindGroupId('nix.validation')).toBe('infrastructure')
    expect(actionKindGroupId('application.install.fixture')).toBe('application')
    expect(actionKindGroupId('repository.import')).toBe('application')
    expect(actionKindGroupId('settings.patch')).toBe('settings')
    expect(actionKindGroupId('governed_run.apply')).toBe('runs')
    expect(actionKindGroupId('goal_execution.close')).toBe('orchestration')
  })

  it('filters by result and actor', () => {
    const failed = applyReceiptsFilter(receipts, { ...DEFAULT_RECEIPTS_FILTER, result: 'failed' }, NOW)
    expect(failed.map((r) => r.id)).toEqual(['rcpt_2'])
    const system = applyReceiptsFilter(receipts, { ...DEFAULT_RECEIPTS_FILTER, actor: 'system' }, NOW)
    expect(system.map((r) => r.id)).toEqual(['rcpt_3'])
  })

  it('filters by date range relative to now', () => {
    const day = applyReceiptsFilter(receipts, { ...DEFAULT_RECEIPTS_FILTER, dateRange: 'day' }, NOW)
    expect(day.map((r) => r.id)).toEqual(['rcpt_1'])
    const week = applyReceiptsFilter(receipts, { ...DEFAULT_RECEIPTS_FILTER, dateRange: 'week' }, NOW)
    expect(week.map((r) => r.id).sort()).toEqual(['rcpt_1', 'rcpt_2'])
  })

  it('sorts newest first by default and oldest on request', () => {
    const newest = applyReceiptsFilter(receipts, DEFAULT_RECEIPTS_FILTER, NOW)
    expect(newest.map((r) => r.id)).toEqual(['rcpt_1', 'rcpt_2', 'rcpt_3'])
    const oldest = applyReceiptsFilter(receipts, { ...DEFAULT_RECEIPTS_FILTER, sort: 'oldest' }, NOW)
    expect(oldest.map((r) => r.id)).toEqual(['rcpt_3', 'rcpt_2', 'rcpt_1'])
  })

  it('counts only active facets', () => {
    expect(activeFilterCount(DEFAULT_RECEIPTS_FILTER)).toBe(0)
    expect(activeFilterCount({ ...DEFAULT_RECEIPTS_FILTER, result: 'failed', actor: 'user', view: 'timeline' })).toBe(2)
  })
})

describe('presets', () => {
  it('All is active only when unfiltered', () => {
    const all = RECEIPT_FILTER_PRESETS.find((p) => p.id === 'all')!
    expect(isPresetActive(all, DEFAULT_RECEIPTS_FILTER)).toBe(true)
    expect(isPresetActive(all, { ...DEFAULT_RECEIPTS_FILTER, query: 'x' })).toBe(false)
  })

  it('Failures activates on result=failed', () => {
    const failures = RECEIPT_FILTER_PRESETS.find((p) => p.id === 'failures')!
    expect(isPresetActive(failures, { ...DEFAULT_RECEIPTS_FILTER, result: 'failed' })).toBe(true)
    expect(isPresetActive(failures, DEFAULT_RECEIPTS_FILTER)).toBe(false)
  })
})

describe('timeline grouping', () => {
  it('groups by day, newest day first, chronological within a day', () => {
    const receipts = [
      makeReceipt({ id: 'b', createdAt: '2025-01-10T14:00:00.000Z' }),
      makeReceipt({ id: 'a', createdAt: '2025-01-10T09:00:00.000Z' }),
      makeReceipt({ id: 'c', createdAt: '2025-01-09T09:00:00.000Z' }),
    ]
    const groups = groupReceiptsByDay(receipts, new Date(NOW))
    expect(groups.map((g) => g.dayKey)).toEqual(['2025-01-10', '2025-01-09'])
    expect(groups[0].items.map((r) => r.id)).toEqual(['a', 'b'])
    expect(groups[0].label).toBe('Today')
    expect(groups[1].label).toBe('Yesterday')
  })

  it('labels arbitrary days with a full date', () => {
    expect(dayLabel('2025-01-01', new Date(NOW))).toContain('2025')
  })

  it('connects only receipts sharing a relation key', () => {
    const items = [
      makeReceipt({ id: 'one', relatedApprovalId: 'appr_1' }),
      makeReceipt({ id: 'two', relatedApprovalId: 'appr_1' }),
      makeReceipt({ id: 'three', relatedApprovalId: 'appr_2' }),
      makeReceipt({ id: 'four' }),
    ]
    const connected = connectedReceiptIds(items)
    expect(connected.has('one')).toBe(true)
    expect(connected.has('two')).toBe(true)
    expect(connected.has('three')).toBe(false)
    expect(connected.has('four')).toBe(false)
  })
})

describe('export serialization', () => {
  const receipts = [
    makeReceipt({ id: 'rcpt_1', actionName: 'File change, saved', summary: 'quoted "summary"' }),
    makeReceipt({ id: 'rcpt_2', actor: 'assistant' }),
  ]

  it('produces parseable JSON of the given (filtered) set', () => {
    const parsed = JSON.parse(receiptsToJson(receipts)) as Receipt[]
    expect(parsed).toHaveLength(2)
    expect(parsed[0].id).toBe('rcpt_1')
  })

  it('produces CSV with a header and escaped cells', () => {
    const csv = receiptsToCsv(receipts)
    const lines = csv.split('\n')
    expect(lines[0]).toBe('id,action,result,actor,time,event_kind,summary')
    expect(lines[1]).toContain('"File change, saved"')
    expect(lines[1]).toContain('"quoted ""summary"""')
    expect(lines[2]).toContain('Assistant')
  })

  it('neutralizes spreadsheet formulas in untrusted receipt fields', () => {
    const malicious = {
      ...receipts[0],
      actionName: '=HYPERLINK("https://attacker.invalid")',
      summary: '@SUM(1+1)',
    }
    const csv = receiptsToCsv([malicious])
    expect(csv).toContain(`"'=HYPERLINK(""https://attacker.invalid"")"`)
    expect(csv).toContain(`'@SUM(1+1)`)
    expect(csv).not.toContain(',=HYPERLINK')
    expect(csv).not.toContain(',@SUM')
  })
})

describe('actor labels', () => {
  it('maps actors to human labels', () => {
    expect(actorLabel('user')).toBe('You')
    expect(actorLabel('assistant')).toBe('Assistant')
    expect(actorLabel('system')).toBe('System')
  })
})
