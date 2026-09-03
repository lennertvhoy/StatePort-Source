/**
 * ApprovalsPage (`#/approvals`, `#/approvals/:approvalId`) — the global
 * approvals inbox (approvals.md): a first-class destination for consequential
 * decisions. Split list + detail on ≥ 900 px; route-driven list→detail below.
 *
 * Keyboard: ↑/↓ or J/K move between requests · Enter opens the focused row ·
 * A focuses Approve · R focuses Reject (activation is always explicit — there
 * is no one-key approve) · Esc returns to the list.
 *
 * No bulk approval of destructive actions; routine batch approve is
 * deliberately omitted (every decision is made from its own review pane).
 */
import { ArrowDown, ArrowUp, OctagonAlert, ShieldCheck, ShieldQuestion, TriangleAlert } from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'

import type { ApplicationInstance, Approval, RiskLevel } from '@/client'
import { getClient } from '@/client'
import { cn } from '@/lib/utils'
import { useSessionStore } from '@/state'
import { useRegisterCommands } from '@/shell/commands'
import { isEditableTarget } from '@/shell/platform'

import { ApprovalDetailPane } from './ApprovalDetailPane'
import { ApprovalListPane } from './ApprovalListPane'
import { approvalRowDomId } from './approvalsModel'
import { EMPTY_APPROVAL_FILTERS, filterApprovals, sortApprovals } from './approvalsModel'
import type { ApprovalFilters, ApprovalSort } from './approvalsModel'

const NO_APPROVALS: Approval[] = []
const NO_INSTANCES: ApplicationInstance[] = []

/** rAF with a setTimeout fallback (jsdom without pretendToBeVisual). */
function nextFrame(cb: () => void): void {
  if (typeof window.requestAnimationFrame === 'function') window.requestAnimationFrame(() => cb())
  else window.setTimeout(cb, 0)
}

export default function ApprovalsPage() {
  const { approvalId } = useParams<{ approvalId: string }>()
  const navigate = useNavigate()
  const activeScenario = useSessionStore((s) => s.activeScenario)

  // Keyed fetch result: all/instances/loading/error derive from whether the
  // in-flight key has landed, so the effect never sets state synchronously.
  const [result, setResult] = useState<{
    key: string
    all: Approval[]
    instances: ApplicationInstance[]
    error: unknown
  } | null>(null)
  const [nonce, setNonce] = useState(0)
  const [filters, setFilters] = useState<ApprovalFilters>(EMPTY_APPROVAL_FILTERS)
  const [sort, setSort] = useState<ApprovalSort>('newest')
  const [now, setNow] = useState(() => Date.now())

  // Expiry text stays honest over time.
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 60_000)
    return () => window.clearInterval(timer)
  }, [])

  // ── Data ─────────────────────────────────────────────────────────────────
  const refresh = useCallback(() => setNonce((n) => n + 1), [])
  const requestKey = `${nonce}#${activeScenario ?? ''}`

  useEffect(() => {
    let cancelled = false
    Promise.all([getClient().approvals.list(), getClient().applications.list()])
      .then(([approvals, instanceList]) => {
        if (cancelled) return
        setResult({ key: requestKey, all: approvals, instances: instanceList, error: null })
      })
      .catch((err) => {
        if (cancelled) return
        setResult((prev) => ({ key: requestKey, all: prev?.all ?? [], instances: prev?.instances ?? [], error: err }))
      })
    return () => {
      cancelled = true
    }
  }, [nonce, activeScenario, requestKey])

  const landed = result && result.key === requestKey ? result : null
  const all = landed?.all ?? NO_APPROVALS
  const instances = landed?.instances ?? NO_INSTANCES
  const error = landed?.error ?? null
  const loading = !landed

  const instanceNameById = useMemo(() => {
    const map = new Map<string, string>()
    for (const instance of instances) map.set(instance.id, instance.name)
    return map
  }, [instances])
  const instanceName = useCallback((id: string) => instanceNameById.get(id), [instanceNameById])

  const pendingCount = useMemo(() => all.filter((a) => a.status === 'pending').length, [all])
  const decidedCount = all.length - pendingCount

  const visible = useMemo(
    () => sortApprovals(filterApprovals(all, filters, instanceName, now), sort),
    [all, filters, instanceName, now, sort],
  )

  // Keep the live list in a ref for keyboard/command handlers (no stale
  // closures) — updated in an effect, never during render.
  const visibleRef = useRef(visible)
  useEffect(() => {
    visibleRef.current = visible
  })

  // ── Selection movement (j/k, arrows, next/prev commands) ────────────────
  const moveSelection = useCallback(
    (delta: number) => {
      const list = visibleRef.current
      if (list.length === 0) return
      const idx = list.findIndex((a) => a.id === approvalId)
      const nextIndex =
        idx < 0 ? (delta > 0 ? 0 : list.length - 1) : Math.min(list.length - 1, Math.max(0, idx + delta))
      const target = list[nextIndex]
      navigate(`/approvals/${target.id}`)
      nextFrame(() => {
        document.getElementById(approvalRowDomId(target.id))?.focus()
      })
    },
    [approvalId, navigate],
  )

  const toggleRisk = useCallback((level: RiskLevel) => {
    setFilters((f) => ({ ...f, risks: f.risks.includes(level) ? [] : [level] }))
  }, [])

  // ── After a decision: refresh the inbox, move DOM focus to the next pending row ──
  const handleDecided = useCallback(
    // The receipt travels to the receipts surface; the inbox only needs the approval.
    (decided: Approval) => {
      const nextPending = visibleRef.current.find((a) => a.id !== decided.id && a.status === 'pending')
      refresh()
      nextFrame(() => {
        if (nextPending) document.getElementById(approvalRowDomId(nextPending.id))?.focus()
      })
    },
    [refresh],
  )

  // ── Commands ──────────────────────────────────────────────────────────────
  const commands = useMemo(
    () => [
      {
        id: 'approvals.open',
        title: 'Open approvals inbox',
        group: 'Navigation' as const,
        icon: ShieldQuestion,
        run: () => navigate('/approvals'),
        when: () => typeof window !== 'undefined' && !window.location.hash.startsWith('#/approvals'),
      },
      {
        id: 'approvals.next',
        title: 'Next approval',
        group: 'Navigation' as const,
        icon: ArrowDown,
        run: () => moveSelection(1),
        when: () => visibleRef.current.length > 0,
      },
      {
        id: 'approvals.previous',
        title: 'Previous approval',
        group: 'Navigation' as const,
        icon: ArrowUp,
        run: () => moveSelection(-1),
        when: () => visibleRef.current.length > 0,
      },
      {
        id: 'approvals.filter_routine',
        title: 'Approvals: filter to routine risk',
        group: 'Actions' as const,
        icon: ShieldCheck,
        run: () => toggleRisk('low'),
      },
      {
        id: 'approvals.filter_elevated',
        title: 'Approvals: filter to elevated risk',
        group: 'Actions' as const,
        icon: TriangleAlert,
        run: () => toggleRisk('medium'),
      },
      {
        id: 'approvals.filter_destructive',
        title: 'Approvals: filter to destructive risk',
        group: 'Actions' as const,
        icon: OctagonAlert,
        run: () => toggleRisk('high'),
      },
    ],
    [navigate, moveSelection, toggleRisk],
  )
  useRegisterCommands(commands)

  // ── Page keyboard ─────────────────────────────────────────────────────────
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.isComposing || e.metaKey || e.ctrlKey || e.altKey) return
      if (isEditableTarget(e.target)) return
      // Overlays (confirm dialog, drawers, palette) own their own keys.
      if (document.querySelector('[role="dialog"], [data-testid="drawer"][data-state="open"]')) return
      if (e.key === 'j' || e.key === 'J' || e.key === 'ArrowDown') {
        e.preventDefault()
        moveSelection(1)
      } else if (e.key === 'k' || e.key === 'K' || e.key === 'ArrowUp') {
        e.preventDefault()
        moveSelection(-1)
      } else if (e.key === 'a' || e.key === 'A') {
        const button = document.getElementById('approve-button')
        if (button) {
          e.preventDefault()
          button.focus()
        }
      } else if (e.key === 'r' || e.key === 'R') {
        const button = document.getElementById('reject-button')
        if (button) {
          e.preventDefault()
          button.focus()
        }
      } else if (e.key === 'Escape' && approvalId) {
        // Back to the list (mobile pattern; clears selection on desktop).
        navigate('/approvals')
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [moveSelection, approvalId, navigate])

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    // Legacy hook: the shell route-smoke test (src/shell/__tests__/routes.test.tsx,
    // orchestrator-owned) still selects `approvals-stub`; keep it on the real surface.
    <div className="flex h-full min-h-0 flex-col bg-app" data-testid="approvals-stub">
      <header className="flex items-baseline gap-3 border-b border-border px-4 py-3">
        <h1 className="text-xl text-foreground">Approvals</h1>
        <p className="text-xs text-foreground-secondary" data-testid="pending-count">
          {pendingCount === 1 ? '1 pending' : `${pendingCount} pending`}
        </p>
      </header>

      <div className="flex min-h-0 flex-1">
        {/* List column */}
        <aside
          className={cn(
            'w-full min-w-0 flex-col min-[900px]:w-[320px] min-[900px]:shrink-0 min-[900px]:border-r min-[900px]:border-border xl:w-[380px]',
            approvalId ? 'hidden min-[900px]:flex' : 'flex',
          )}
          aria-label="Approval requests"
        >
          <ApprovalListPane
            approvals={visible}
            facetSource={all}
            loading={loading}
            error={error}
            onRetry={refresh}
            filters={filters}
            onFiltersChange={setFilters}
            sort={sort}
            onSortChange={setSort}
            instances={instances}
            pendingCount={pendingCount}
            decidedCount={decidedCount}
            selectedId={approvalId}
            onSelect={(id) => navigate(`/approvals/${id}`)}
            now={now}
          />
        </aside>

        {/* Detail column */}
        <section
          className={cn(
            'min-w-0 flex-1 flex-col bg-surface',
            approvalId ? 'flex' : 'hidden min-[900px]:flex',
          )}
          aria-label="Approval detail"
        >
          {approvalId ? (
            <ApprovalDetailPane
              key={approvalId}
              approvalId={approvalId}
              instanceName={instanceName}
              onDecided={handleDecided}
              onBack={() => navigate('/approvals')}
              now={now}
            />
          ) : (
            <div className="flex h-full flex-col items-center justify-center gap-2 px-6 text-center">
              <ShieldQuestion className="size-5 text-foreground-tertiary" aria-hidden="true" />
              <p className="text-sm text-foreground-secondary">
                Select a request to review its exact scope before deciding.
              </p>
            </div>
          )}
        </section>
      </div>
    </div>
  )
}
