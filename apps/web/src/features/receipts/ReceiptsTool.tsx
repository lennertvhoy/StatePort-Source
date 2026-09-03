/**
 * ReceiptsTool — the audit trail (design/receipts.md). Human-facing list
 * (action · result · actor · time), exact-on-demand detail drawer, table ⇄
 * timeline views, search + persisted filters, group-related chaining,
 * mock-only integrity verification, and JSON/CSV export of the filtered set.
 *
 * Routes: `#/app/:instanceId/workbench/receipts[`:receiptId`] — the detail
 * drawer is a route; deep links open it, Back/Escape close it.
 *
 * Keyboard (scope): ↑/↓ rows · Enter open · Esc close drawer · f search ·
 * v table/timeline · Ctrl/Cmd+C on a row copies its receipt ID (toast).
 *
 * `data-testid="receipts-stub"` is kept on the root: the shell route-smoke
 * test (out of this feature's scope) looks it up on this route.
 */
import { Receipt } from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef } from 'react'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'

import { getClient, type Receipt as ReceiptType } from '@/client'
import { copyText, EmptyState, ErrorState, Skeleton } from '@/components'
import { sendToBridge } from '@/features/bridge/bridgeStore'
import type { ShellCommand } from '@/shell/commands'
import { useRegisterCommands } from '@/shell/commands'
import { useIsMobile, isEditableTarget } from '@/shell/platform'
import { WorkbenchToolHeader } from '@/shell/workbench/ToolHeader'
import { useRegisterToolPanel } from '@/shell/workbench/WorkbenchSlots'
import { useSessionStore, useWorkspaceStore } from '@/state'

import { requestReceiptVerify } from './detailActions'
import { ReceiptDetail } from './ReceiptDetail'
import { ReceiptsFilterBar } from './ReceiptsFilterBar'
import {
  applyReceiptsFilter,
  fromStoredFilter,
  groupReceiptsByDay,
  RECEIPTS_EMPTY_BODY,
  RECEIPTS_EMPTY_TITLE,
  RECEIPTS_NO_MATCH_TITLE,
  receiptsToCsv,
  receiptsToJson,
  toStoredFilter,
} from './receiptsModel'
import type { ReceiptsViewFilter } from './receiptsModel'
import { ReceiptsNavPanel } from './ReceiptsNavPanel'
import { ReceiptsTable } from './ReceiptsTable'
import { ReceiptsTimeline } from './ReceiptsTimeline'
import { useReceiptListKeyboard } from './useReceiptListKeyboard'
import { useReceipts } from './useReceipts'

/** Download a text file; returns false when the platform can't (tests). */
function downloadText(filename: string, text: string, mime: string): boolean {
  try {
    if (typeof URL.createObjectURL !== 'function') return false
    const blob = new Blob([text], { type: mime })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = filename
    document.body.appendChild(anchor)
    anchor.click()
    anchor.remove()
    window.setTimeout(() => URL.revokeObjectURL(url), 1000)
    return true
  } catch {
    return false
  }
}

/** Loading skeleton: icon bone + text bones, row-faithful (receipts.md). */
function ReceiptsSkeleton() {
  return (
    <div className="flex flex-col gap-1 p-3" role="status" aria-label="Loading receipts…" data-testid="receipts-skeleton">
      {Array.from({ length: 8 }, (_, i) => (
        <div key={i} className="flex h-8 items-center gap-2">
          <Skeleton className="size-4 shrink-0" />
          <Skeleton className="h-3.5 w-1/3" />
          <Skeleton className="h-4 w-16" />
          <span className="flex-1" />
          <Skeleton className="h-3.5 w-14" />
        </div>
      ))}
    </div>
  )
}

export default function ReceiptsTool() {
  const { instanceId = '', receiptId } = useParams<{ instanceId: string; receiptId: string }>()
  const canVerifyIntegrity = getClient().adapter === 'mock'
  const navigate = useNavigate()
  const isMobile = useIsMobile()
  const [searchParams, setSearchParams] = useSearchParams()
  const pushToast = useSessionStore((s) => s.pushToast)

  // ── Filter state (persisted per instance in the workspace store) ─────────
  const storedFilter = useWorkspaceStore((s) => s.receiptFilters[instanceId])
  const setReceiptFilter = useWorkspaceStore((s) => s.setReceiptFilter)
  const filter = useMemo(() => fromStoredFilter(storedFilter, isMobile), [storedFilter, isMobile])

  const patchFilter = useCallback(
    (patch: Partial<ReceiptsViewFilter>) => {
      const current = fromStoredFilter(useWorkspaceStore.getState().receiptFilters[instanceId], isMobile)
      setReceiptFilter(instanceId, toStoredFilter({ ...current, ...patch }))
    },
    [instanceId, isMobile, setReceiptFilter],
  )
  const clearFilters = useCallback(
    () =>
      patchFilter({ query: '', result: 'all', actionKind: 'all', actor: 'all', dateRange: 'all' }),
    [patchFilter],
  )

  // ── Data + derived views ──────────────────────────────────────────────────
  const { receipts, loading, error, refresh, newIds } = useReceipts(instanceId)
  const filtered = useMemo(() => applyReceiptsFilter(receipts, filter), [receipts, filter])
  const groups = useMemo(() => groupReceiptsByDay(filtered), [filtered])

  // ── Navigation actions ────────────────────────────────────────────────────
  const listRoute = `/app/${instanceId}/workbench/receipts`
  const openReceipt = useCallback((receipt: ReceiptType) => navigate(`${listRoute}/${receipt.id}`), [navigate, listRoute])
  const closeReceipt = useCallback(() => navigate(listRoute), [navigate, listRoute])

  const copyReceiptId = useCallback(
    (receipt: ReceiptType) => {
      void copyText(receipt.id).then((ok) => {
        if (ok) pushToast({ kind: 'success', title: 'Receipt ID copied', body: receipt.id })
      })
    },
    [pushToast],
  )

  const openRelated = useCallback(
    (receipt: ReceiptType) => {
      if (receipt.relatedApprovalId) void navigate(`/approvals/${receipt.relatedApprovalId}`)
      else if (receipt.relatedOperationId || receipt.relatedPlanId) void navigate(`/app/${instanceId}/workbench/deployments`)
      else if (receipt.relatedConversationId) {
        sendToBridge({ kind: 'receipt', instanceId, receiptId: receipt.id })
        void navigate(`/app/${instanceId}/conversation`)
      }
    },
    [instanceId, navigate],
  )

  const keyboard = useReceiptListKeyboard(filtered, { onOpen: openReceipt, onCopyId: copyReceiptId })

  // ── Export (the filtered set) ─────────────────────────────────────────────
  // Latest-list ref for the export callback — updated in an effect, never
  // during render.
  const filteredRef = useRef(filtered)
  useEffect(() => {
    filteredRef.current = filtered
  })
  const exportSet = useCallback(
    (format: 'json' | 'csv') => {
      const set = filteredRef.current
      const stamp = new Date().toISOString().slice(0, 10)
      const ok =
        format === 'json'
          ? downloadText(`receipts-${instanceId}-${stamp}.json`, receiptsToJson(set), 'application/json')
          : downloadText(`receipts-${instanceId}-${stamp}.csv`, receiptsToCsv(set), 'text/csv')
      if (ok) {
        pushToast({ kind: 'success', title: 'Receipts exported', body: `${set.length} receipt${set.length === 1 ? '' : 's'} (${format.toUpperCase()})` })
      } else {
        pushToast({ kind: 'error', title: 'Export failed', body: 'This environment could not create the download.' })
      }
    },
    [instanceId, pushToast],
  )

  // ── Tool-scoped keys: f focus search · v toggle view ─────────────────────
  const searchInputRef = useRef<HTMLInputElement | null>(null)
  const toolRootRef = useRef<HTMLDivElement | null>(null)
  // The tool root is an event scope, not an interactive element — the hotkey
  // listener attaches imperatively (keys work wherever focus sits inside).
  useEffect(() => {
    const el = toolRootRef.current
    if (!el) return
    const onToolKeyDown = (e: KeyboardEvent) => {
      if (isEditableTarget(e.target) || e.metaKey || e.ctrlKey || e.altKey) return
      if (e.key.toLowerCase() === 'f') {
        e.preventDefault()
        searchInputRef.current?.focus()
      } else if (e.key.toLowerCase() === 'v') {
        e.preventDefault()
        patchFilter({ view: filter.view === 'table' ? 'timeline' : 'table' })
      }
    }
    el.addEventListener('keydown', onToolKeyDown)
    return () => el.removeEventListener('keydown', onToolKeyDown)
  }, [filter.view, patchFilter])

  // ── Palette commands ──────────────────────────────────────────────────────
  const receiptIdRef = useRef(receiptId)
  useEffect(() => {
    receiptIdRef.current = receiptId
  })
  const commands = useMemo<ShellCommand[]>(
    () => [
      {
        id: 'receipts.search',
        title: 'Search receipts',
        group: 'Actions',
        icon: Receipt,
        shortcut: 'f',
        keywords: ['receipts', 'audit', 'find'],
        run: () => searchInputRef.current?.focus(),
      },
      {
        id: 'receipts.toggle_view',
        title: filter.view === 'table' ? 'Receipts: switch to timeline view' : 'Receipts: switch to table view',
        group: 'Actions',
        icon: Receipt,
        shortcut: 'v',
        keywords: ['timeline', 'table', 'receipts'],
        run: () => patchFilter({ view: filter.view === 'table' ? 'timeline' : 'table' }),
      },
      {
        id: 'receipts.toggle_group',
        title: filter.groupRelated ? 'Receipts: ungroup related' : 'Receipts: group related',
        group: 'Actions',
        icon: Receipt,
        keywords: ['chain', 'approval', 'timeline'],
        run: () => patchFilter({ groupRelated: !filter.groupRelated }),
      },
      ...(canVerifyIntegrity
        ? [
            {
              id: 'receipts.verify',
              title: 'Verify receipt integrity',
              group: 'Actions' as const,
              icon: Receipt,
              keywords: ['digest', 'audit', 'integrity'],
              when: () => Boolean(receiptIdRef.current),
              run: () => {
                requestReceiptVerify()
              },
            },
          ]
        : []),
      {
        id: 'receipts.copy_id',
        title: 'Copy receipt ID',
        group: 'Actions',
        icon: Receipt,
        keywords: ['clipboard', 'receipt'],
        run: () => {
          const target =
            filteredRef.current.find((r) => r.id === receiptIdRef.current) ?? filteredRef.current[keyboard.activeIndex]
          if (target) copyReceiptId(target)
        },
      },
      {
        id: 'receipts.export_json',
        title: 'Export receipts (JSON)',
        group: 'Actions',
        icon: Receipt,
        keywords: ['download', 'audit'],
        run: () => exportSet('json'),
      },
      {
        id: 'receipts.export_csv',
        title: 'Export receipts (CSV)',
        group: 'Actions',
        icon: Receipt,
        keywords: ['download', 'audit'],
        run: () => exportSet('csv'),
      },
    ],
    [canVerifyIntegrity, filter.view, filter.groupRelated, patchFilter, exportSet, copyReceiptId, keyboard.activeIndex],
  )
  useRegisterCommands(commands)

  // ── Nav panel (saved filters) ─────────────────────────────────────────────
  useRegisterToolPanel('receipts', ReceiptsNavPanel)

  // ── Render ────────────────────────────────────────────────────────────────
  const filteredOut = !loading && !error && receipts.length > 0 && filtered.length === 0
  const maximize = useCallback(() => {
    const next = new URLSearchParams(searchParams)
    next.set('focus', '1')
    setSearchParams(next)
  }, [searchParams, setSearchParams])

  return (
    <div
      ref={toolRootRef}
      className="flex h-full flex-col bg-app outline-none"
      data-testid="receipts-stub"
    >
      <WorkbenchToolHeader
        name="Receipts"
        icon={Receipt}
        state={
          !loading && !error ? (
            <span className="text-xs text-foreground-tertiary" data-testid="receipts-count">
              {filtered.length === receipts.length ? `${receipts.length}` : `${filtered.length} of ${receipts.length}`}{' '}
              {receipts.length === 1 ? 'receipt' : 'receipts'}
            </span>
          ) : undefined
        }
        onMaximize={maximize}
      />

      <ReceiptsFilterBar
        filter={filter}
        onFilterChange={patchFilter}
        onClearFilters={clearFilters}
        onExport={exportSet}
        exportDisabled={filtered.length === 0}
        searchInputRef={searchInputRef}
        isMobile={isMobile}
      />

      {loading ? (
        <ReceiptsSkeleton />
      ) : error ? (
        <ErrorState
          title="Receipts couldn't be loaded"
          error={error}
          preservedNote="Your filters are unchanged."
          onRetry={refresh}
        />
      ) : receipts.length === 0 ? (
        <EmptyState icon={Receipt} title={RECEIPTS_EMPTY_TITLE} description={RECEIPTS_EMPTY_BODY} />
      ) : filteredOut ? (
        <EmptyState
          icon={Receipt}
          title={RECEIPTS_NO_MATCH_TITLE}
          description="Try a different search, or clear the active filters."
          action={{ label: 'Clear filters', onClick: clearFilters }}
        />
      ) : filter.view === 'timeline' ? (
        <ReceiptsTimeline
          groups={groups}
          groupRelated={filter.groupRelated}
          receipts={filtered}
          keyboard={keyboard}
          onOpen={openReceipt}
          onOpenRelated={openRelated}
          newIds={newIds}
        />
      ) : (
        <ReceiptsTable
          receipts={filtered}
          keyboard={keyboard}
          onOpen={openReceipt}
          onOpenRelated={openRelated}
          newIds={newIds}
          sort={filter.sort}
          onToggleSort={() => patchFilter({ sort: filter.sort === 'newest' ? 'oldest' : 'newest' })}
          compact={isMobile}
        />
      )}

      {/* Screen-reader summary of the visible set. */}
      <span className="sr-only" aria-live="polite">
        {filtered.length} receipts shown
      </span>

      {receiptId ? <ReceiptDetail instanceId={instanceId} receiptId={receiptId} onClose={closeReceipt} /> : null}
    </div>
  )
}
