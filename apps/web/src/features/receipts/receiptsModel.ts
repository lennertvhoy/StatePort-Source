/**
 * Receipts model — the pure, testable core of the Receipts surface
 * (design/receipts.md). No React here: filtering, grouping, presets,
 * export serialization, and the workspace-store filter mapping.
 *
 * Human-facing in the list, exact on demand in the detail: the list model
 * works with `actionName`, `result`, `actor`, `createdAt`; raw fields
 * (event kind, digests, revisions) stay in the detail drawer.
 */
import {
  Bell,
  DatabaseBackup,
  FilePenLine,
  KeyRound,
  LayoutGrid,
  ListChecks,
  MessageSquare,
  Receipt as ReceiptIcon,
  Server,
  Settings,
  ShieldCheck,
  Workflow,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

import type { ActorKind, Receipt, ReceiptFilter, ReceiptResult } from '@/client'

// ─────────────────────────────────────────────────────────────────────────────
// View filter (persisted per instance in the workspace store)
// ─────────────────────────────────────────────────────────────────────────────

export type ReceiptsViewMode = 'table' | 'timeline'
export type ReceiptDateRange = 'all' | 'day' | 'week' | 'month'
export type ReceiptActorFilter = 'all' | ActorKind
export type ReceiptSort = 'newest' | 'oldest'

export interface ReceiptsViewFilter {
  query: string
  result: ReceiptResult | 'all'
  /** 'all' or an ACTION_KIND_GROUPS id (matched by event-kind prefix). */
  actionKind: string
  actor: ReceiptActorFilter
  dateRange: ReceiptDateRange
  view: ReceiptsViewMode
  groupRelated: boolean
  sort: ReceiptSort
}

export const DEFAULT_RECEIPTS_FILTER: ReceiptsViewFilter = {
  query: '',
  result: 'all',
  actionKind: 'all',
  actor: 'all',
  dateRange: 'all',
  view: 'table',
  groupRelated: true,
  sort: 'newest',
}

/** Mobile default: timeline scans better narrow (receipts.md). */
export function defaultFilter(isMobile: boolean): ReceiptsViewFilter {
  return { ...DEFAULT_RECEIPTS_FILTER, view: isMobile ? 'timeline' : 'table' }
}

/**
 * The workspace store persists a `ReceiptFilter` (client contract). The view
 * filter is a structural superset — extra fields ride along in the persisted
 * JSON and are read back defensively. Server-relevant fields (query, result)
 * stay in sync with the client contract.
 */
export type StoredReceiptFilter = ReceiptFilter &
  Partial<{
    actionKind: string
    actor: ReceiptActorFilter
    dateRange: ReceiptDateRange
    view: ReceiptsViewMode
    groupRelated: boolean
    sort: ReceiptSort
  }>

export function toStoredFilter(filter: ReceiptsViewFilter): StoredReceiptFilter {
  return {
    query: filter.query || undefined,
    result: filter.result === 'all' ? undefined : filter.result,
    actionKind: filter.actionKind,
    actor: filter.actor,
    dateRange: filter.dateRange,
    view: filter.view,
    groupRelated: filter.groupRelated,
    sort: filter.sort,
  }
}

export function fromStoredFilter(stored: ReceiptFilter | undefined, isMobile: boolean): ReceiptsViewFilter {
  const base = defaultFilter(isMobile)
  if (!stored) return base
  const extra = stored as StoredReceiptFilter
  return {
    query: stored.query ?? base.query,
    result: stored.result ?? base.result,
    actionKind: typeof extra.actionKind === 'string' ? extra.actionKind : base.actionKind,
    actor: extra.actor === 'user' || extra.actor === 'assistant' || extra.actor === 'system' ? extra.actor : base.actor,
    dateRange:
      extra.dateRange === 'day' || extra.dateRange === 'week' || extra.dateRange === 'month' ? extra.dateRange : base.dateRange,
    view: extra.view === 'timeline' || extra.view === 'table' ? extra.view : base.view,
    groupRelated: typeof extra.groupRelated === 'boolean' ? extra.groupRelated : base.groupRelated,
    sort: extra.sort === 'oldest' || extra.sort === 'newest' ? extra.sort : base.sort,
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Action-kind groups (human-facing categories over raw event-kind prefixes)
// ─────────────────────────────────────────────────────────────────────────────

export interface ActionKindGroup {
  id: string
  label: string
  match: (eventKind: string) => boolean
}

export const ACTION_KIND_GROUPS: readonly ActionKindGroup[] = [
  {
    id: 'file',
    label: 'File changes',
    match: (k) => k.startsWith('file.') || k.startsWith('file_workspace.'),
  },
  {
    id: 'infrastructure',
    label: 'Infrastructure',
    match: (k) =>
      k.startsWith('infrastructure.') ||
      k.startsWith('libvirt.') ||
      k.startsWith('nix.'),
  },
  {
    id: 'approval',
    label: 'Approvals & grants',
    match: (k) => k.startsWith('approval.') || k.startsWith('authorization.'),
  },
  { id: 'conversation', label: 'Conversation', match: (k) => k.startsWith('conversation.') },
  { id: 'recovery', label: 'Backups & recovery', match: (k) => k.startsWith('recovery.') || k.startsWith('backup.') },
  { id: 'attention', label: 'Attention & activity', match: (k) => k.startsWith('attention.') || k.startsWith('activity.') },
  {
    id: 'application',
    label: 'Applications & sources',
    match: (k) => k.startsWith('application.') || k.startsWith('repository.'),
  },
  { id: 'settings', label: 'Settings', match: (k) => k.startsWith('settings.') },
  {
    id: 'runs',
    label: 'Governed runs',
    match: (k) => k.startsWith('governed_run.') || k.startsWith('run.'),
  },
  {
    id: 'orchestration',
    label: 'Orchestration',
    match: (k) => k.startsWith('orchestration.') || k.startsWith('goal_execution.'),
  },
]

export function actionKindGroupId(eventKind: string): string {
  return ACTION_KIND_GROUPS.find((g) => g.match(eventKind))?.id ?? 'other'
}

/** Small kind icon for list rows (never a raw event-kind string). */
export function actionKindIcon(eventKind: string): LucideIcon {
  switch (actionKindGroupId(eventKind)) {
    case 'file':
      return FilePenLine
    case 'infrastructure':
      return Server
    case 'approval':
      return eventKind.startsWith('authorization.') ? KeyRound : ShieldCheck
    case 'conversation':
      return MessageSquare
    case 'recovery':
      return DatabaseBackup
    case 'attention':
      return Bell
    case 'application':
      return LayoutGrid
    case 'settings':
      return Settings
    case 'orchestration':
    case 'runs':
      return Workflow
    default:
      return eventKind.startsWith('checklist.') ? ListChecks : ReceiptIcon
  }
}

export function actorLabel(actor: ActorKind): string {
  switch (actor) {
    case 'user':
      return 'You'
    case 'assistant':
      return 'Assistant'
    case 'system':
      return 'System'
  }
}

export function normalizeReceiptDigest(value: string): string {
  return value.replace(/^sha256:/, '')
}

export function parseReceiptDigest(value: string): string | null {
  return /^sha256:[0-9a-f]{64}$/.test(value) ? value : null
}

// ─────────────────────────────────────────────────────────────────────────────
// Filtering (all client-side; the mock list per instance is bounded)
// ─────────────────────────────────────────────────────────────────────────────

const RANGE_MS: Record<Exclude<ReceiptDateRange, 'all'>, number> = {
  day: 24 * 60 * 60 * 1000,
  week: 7 * 24 * 60 * 60 * 1000,
  month: 30 * 24 * 60 * 60 * 1000,
}

export function applyReceiptsFilter(receipts: readonly Receipt[], filter: ReceiptsViewFilter, now = Date.now()): Receipt[] {
  const query = filter.query.trim().toLowerCase()
  let items = receipts.filter((receipt) => {
    if (filter.result !== 'all' && receipt.result !== filter.result) return false
    if (filter.actionKind !== 'all') {
      const group = ACTION_KIND_GROUPS.find((g) => g.id === filter.actionKind)
      if (group ? !group.match(receipt.eventKind) : actionKindGroupId(receipt.eventKind) !== filter.actionKind) return false
    }
    if (filter.actor !== 'all' && receipt.actor !== filter.actor) return false
    if (filter.dateRange !== 'all') {
      const age = now - new Date(receipt.createdAt).getTime()
      if (Number.isNaN(age) || age > RANGE_MS[filter.dateRange]) return false
    }
    if (query) {
      const haystack = `${receipt.actionName}\n${receipt.summary}\n${receipt.id}\n${receipt.eventKind}`.toLowerCase()
      if (!haystack.includes(query)) return false
    }
    return true
  })
  items = [...items].sort((a, b) =>
    filter.sort === 'newest' ? b.createdAt.localeCompare(a.createdAt) : a.createdAt.localeCompare(b.createdAt),
  )
  return items
}

/** Count of facets that differ from the default view (mobile Filter badge). */
export function activeFilterCount(filter: ReceiptsViewFilter): number {
  let count = 0
  if (filter.query.trim()) count += 1
  if (filter.result !== 'all') count += 1
  if (filter.actionKind !== 'all') count += 1
  if (filter.actor !== 'all') count += 1
  if (filter.dateRange !== 'all') count += 1
  return count
}

// ─────────────────────────────────────────────────────────────────────────────
// Nav-panel presets (receipts.md: saved filters panel)
// ─────────────────────────────────────────────────────────────────────────────

export interface ReceiptFilterPreset {
  id: string
  label: string
  patch: Partial<ReceiptsViewFilter>
}

export const RECEIPT_FILTER_PRESETS: readonly ReceiptFilterPreset[] = [
  { id: 'all', label: 'All', patch: { ...DEFAULT_RECEIPTS_FILTER } },
  { id: 'week', label: 'This week', patch: { dateRange: 'week' } },
  { id: 'file', label: 'File changes', patch: { actionKind: 'file' } },
  { id: 'infrastructure', label: 'Infrastructure', patch: { actionKind: 'infrastructure' } },
  { id: 'approvals', label: 'Approvals & grants', patch: { actionKind: 'approval' } },
  { id: 'conversation', label: 'Conversation', patch: { actionKind: 'conversation' } },
  { id: 'failures', label: 'Failures', patch: { result: 'failed' } },
]

/** A preset is active when every patched field matches the current filter. */
export function isPresetActive(preset: ReceiptFilterPreset, filter: ReceiptsViewFilter): boolean {
  return Object.entries(preset.patch).every(([key, value]) => {
    const field = key as keyof ReceiptsViewFilter
    if (preset.id === 'all') {
      // "All" is active only when nothing is filtered (view/sort prefs ignored).
      return (
        filter.query === '' &&
        filter.result === 'all' &&
        filter.actionKind === 'all' &&
        filter.actor === 'all' &&
        filter.dateRange === 'all'
      )
    }
    return filter[field] === value
  })
}

// ─────────────────────────────────────────────────────────────────────────────
// Timeline grouping (grouped by day; related receipts cluster)
// ─────────────────────────────────────────────────────────────────────────────

export interface ReceiptDayGroup {
  /** YYYY-MM-DD (local). */
  dayKey: string
  label: string
  items: Receipt[]
}

export function dayKeyOf(iso: string): string {
  const d = new Date(iso)
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
}

export function dayLabel(dayKey: string, now = new Date()): string {
  const today = dayKeyOf(now.toISOString())
  const yesterdayDate = new Date(now.getTime() - 24 * 60 * 60 * 1000)
  const yesterday = dayKeyOf(yesterdayDate.toISOString())
  if (dayKey === today) return 'Today'
  if (dayKey === yesterday) return 'Yesterday'
  const [y, m, d] = dayKey.split('-').map(Number)
  return new Date(y, m - 1, d).toLocaleDateString(undefined, { weekday: 'short', month: 'short', day: 'numeric', year: 'numeric' })
}

/**
 * Group by calendar day — newest day first; entries within a day in
 * chronological order so approval → run → validate chains read downward.
 */
export function groupReceiptsByDay(receipts: readonly Receipt[], now = new Date()): ReceiptDayGroup[] {
  const byDay = new Map<string, Receipt[]>()
  for (const receipt of receipts) {
    const key = dayKeyOf(receipt.createdAt)
    const list = byDay.get(key) ?? []
    list.push(receipt)
    byDay.set(key, list)
  }
  return [...byDay.entries()]
    .sort(([a], [b]) => b.localeCompare(a))
    .map(([dayKey, items]) => ({
      dayKey,
      label: dayLabel(dayKey, now),
      items: [...items].sort((a, b) => a.createdAt.localeCompare(b.createdAt)),
    }))
}

/** The relation that visually chains receipts (approval → run → validate …). */
export function relationKey(receipt: Receipt): string | null {
  return (
    receipt.relatedApprovalId ??
    receipt.relatedPlanId ??
    receipt.relatedOperationId ??
    receipt.relatedConversationId ??
    null
  )
}

/**
 * Mark receipts that share a relation key with at least one sibling in the
 * same day group. Returns a set of receipt ids that render connected.
 */
export function connectedReceiptIds(items: readonly Receipt[]): Set<string> {
  const byKey = new Map<string, Receipt[]>()
  for (const receipt of items) {
    const key = relationKey(receipt)
    if (!key) continue
    const list = byKey.get(key) ?? []
    list.push(receipt)
    byKey.set(key, list)
  }
  const connected = new Set<string>()
  for (const group of byKey.values()) {
    if (group.length < 2) continue
    for (const receipt of group) connected.add(receipt.id)
  }
  return connected
}

// ─────────────────────────────────────────────────────────────────────────────
// Export serialization (the filtered set; download wiring lives in the tool)
// ─────────────────────────────────────────────────────────────────────────────

export function receiptsToJson(receipts: readonly Receipt[]): string {
  return JSON.stringify(receipts, null, 2)
}

function csvCell(value: string): string {
  // Receipt labels and summaries can originate outside the browser. Prefix
  // spreadsheet formula sigils so opening the export cannot execute them.
  const neutralized = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value
  return /[",\n]/.test(neutralized)
    ? `"${neutralized.replace(/"/g, '""')}"`
    : neutralized
}

export function receiptsToCsv(receipts: readonly Receipt[]): string {
  const header = 'id,action,result,actor,time,event_kind,summary'
  const rows = receipts.map((r) =>
    [r.id, r.actionName, r.result, actorLabel(r.actor), r.createdAt, r.eventKind, r.summary].map(csvCell).join(','),
  )
  return [header, ...rows].join('\n')
}

// ─────────────────────────────────────────────────────────────────────────────
// Detail helpers
// ─────────────────────────────────────────────────────────────────────────────

/** The one, quiet caveat — rendered once in the detail footer, never per row. */
export const RECEIPT_CAVEAT =
  'A receipt records what StatePort accepted and applied. It doesn’t by itself prove an external system’s later state.'

export const RECEIPTS_EMPTY_TITLE = 'No receipts yet'
export const RECEIPTS_EMPTY_BODY =
  'When you approve, run, save, or export something in this application, the record will appear here.'
export const RECEIPTS_NO_MATCH_TITLE = 'No receipts match these filters'

export const VERIFY_OK_MESSAGE = 'Verified — content matches the recorded digests'
