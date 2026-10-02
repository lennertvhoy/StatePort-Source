/**
 * ScenarioLab (scenario-lab.md) — development-only overlay making every
 * important state reachable. Access: palette command "Open Scenario Lab" or
 * `?scenario=lab`. Never appears in production (panel, palette command, and
 * URL param are inert and stripped).
 *
 * While a scenario is active, a slim 24 px ribbon reads
 * "Scenario: <id> · mock adapter" with Exit / Open lab — it can never be
 * mistaken for product UI.
 */
import { Copy, FlaskConical, RotateCcw, Trash2, X } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'

import type { ScenarioId } from '@/client'
import { getClient, SCENARIO_GROUPS, SCENARIOS } from '@/client'
import { ConfirmDialog, Disclosure, copyText } from '@/components'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { useSessionStore } from '@/state'

import { useEscapeLayer } from './escape'

interface ScenarioRow {
  id: ScenarioId
  label: string
  group: string
  effect: string
}

/** Structural view of a scenario behavior (SCENARIOS entries are const-narrowed). */
interface BehaviorFlags {
  latencyMultiplier?: number
  serviceState?: string
  failRequests?: { status: number; message: string }
  hideApplications?: boolean
  degradeInstances?: boolean
  approvals?: string
  conversation?: string
  attachmentUploadFails?: boolean
  files?: string
  terminal?: string
  targetUnavailable?: boolean
  vm?: string
  repoDirty?: boolean
  infraPlan?: string
  orchestration?: string
  receipts?: string
  backupDue?: boolean
  authorization?: string
}

/** One-line effect description derived from the behavior flags. */
function describeBehavior(id: ScenarioId): string {
  const def = SCENARIOS.find((s) => s.id === id)
  if (!def) return ''
  const b = def.behavior as BehaviorFlags
  const parts: string[] = []
  if (b.latencyMultiplier) parts.push(`adds ${b.latencyMultiplier}× latency`)
  if (b.serviceState) parts.push(`service = ${b.serviceState}`)
  if (b.failRequests) parts.push('every request fails')
  if (b.hideApplications) parts.push('application list is empty')
  if (b.degradeInstances) parts.push('instances report degraded')
  if (b.approvals) parts.push(`approvals = ${b.approvals}`)
  if (b.conversation) parts.push(`conversation = ${b.conversation}`)
  if (b.attachmentUploadFails) parts.push('attachment upload fails')
  if (b.files) parts.push(`files = ${b.files.replace('_', ' ')}`)
  if (b.terminal) parts.push(`terminal = ${b.terminal}`)
  if (b.targetUnavailable) parts.push('target unavailable')
  if (b.vm) parts.push(`vm = ${b.vm.replace('_', ' ')}`)
  if (b.repoDirty) parts.push('repository dirty')
  if (b.infraPlan) parts.push(`plan = ${b.infraPlan.replace('_', ' ')}`)
  if (b.orchestration) parts.push(`orchestration = ${b.orchestration.replace('_', ' ')}`)
  if (b.receipts) parts.push(`receipts = ${b.receipts}`)
  if (b.backupDue) parts.push('backup due')
  if (b.authorization) parts.push(`authorization = ${b.authorization}`)
  return parts.length > 0 ? parts.join('; ') : 'seeded baseline'
}

function ScenarioLabPanel() {
  const setLabOpen = useSessionStore((s) => s.setScenarioLabOpen)
  const activeScenario = useSessionStore((s) => s.activeScenario)
  const setActiveScenario = useSessionStore((s) => s.setActiveScenario)
  const pushToast = useSessionStore((s) => s.pushToast)
  const [resetOpen, setResetOpen] = useState(false)
  const [announcement, setAnnouncement] = useState('')

  useEscapeLayer(true, () => setLabOpen(false), { id: 'scenario-lab', priority: 10 })

  const groups = useMemo(() => {
    const rows: ScenarioRow[] = SCENARIOS.map((s) => ({
      id: s.id,
      label: s.label,
      group: s.group,
      effect: describeBehavior(s.id),
    }))
    return SCENARIO_GROUPS.map((group) => ({
      group,
      rows: rows.filter((r) => r.group === group),
    })).filter((g) => g.rows.length > 0)
  }, [])

  const apply = (id: ScenarioId | null) => {
    setActiveScenario(id)
    const label = id ? (SCENARIOS.find((s) => s.id === id)?.label ?? id) : null
    setAnnouncement(label ? `Scenario applied: ${label}` : 'Scenario cleared')
  }

  return (
    <aside
      className="fixed inset-y-0 right-0 z-drawer flex w-[380px] max-w-[92vw] flex-col border-l border-border bg-surface shadow-2"
      aria-label="Scenario Lab"
      data-testid="scenario-lab"
    >
      <div aria-live="polite" className="sr-only">
        {announcement}
      </div>
      <div className="flex items-center justify-between gap-2 border-b border-border px-3 py-2">
        <div className="flex items-center gap-2">
          <FlaskConical className="size-4 text-foreground-secondary" aria-hidden="true" />
          <h2 className="text-xl text-foreground">Scenario Lab</h2>
        </div>
        <button
          type="button"
          aria-label="Close Scenario Lab"
          onClick={() => setLabOpen(false)}
          className="inline-flex min-h-8 min-w-8 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
        >
          <X className="size-4" aria-hidden="true" />
        </button>
      </div>
      <p className="border-b border-border px-3 py-1.5 text-xs text-foreground-secondary">
        Development only. One scenario active at a time; unsaved changes are discarded on switch.
      </p>

      <div className="min-h-0 flex-1 overflow-y-auto px-2 py-2">
        {groups.map(({ group, rows }) => (
          <Disclosure
            key={group}
            title={
              <span>
                {group} <span className="tnum font-normal text-foreground-tertiary">({rows.length})</span>
              </span>
            }
            defaultOpen={rows.some((r) => r.id === activeScenario)}
          >
            <ul className="flex flex-col pb-2" role="radiogroup" aria-label={`${group} scenarios`}>
              {rows.map((row) => {
                const active = row.id === activeScenario
                return (
                  <li key={row.id}>
                    <button
                      type="button"
                      role="radio"
                      aria-checked={active}
                      onClick={() => apply(active ? null : row.id)}
                      className={cn(
                        'flex w-full items-start gap-2 rounded-sm px-2 py-1.5 text-left transition-colors duration-instant hover:bg-hover',
                        active && 'bg-accent-soft',
                      )}
                    >
                      <span
                        className={cn(
                          'mt-1 inline-flex size-3 shrink-0 items-center justify-center rounded-full border',
                          active ? 'border-accent bg-accent' : 'border-border-strong',
                        )}
                        aria-hidden="true"
                      />
                      <span className="min-w-0 flex-1">
                        <span className={cn('block truncate text-sm', active ? 'font-medium text-accent-soft-text' : 'text-foreground')}>
                          {row.label}
                        </span>
                        <span className="block truncate text-xs text-foreground-secondary">
                          {row.effect} · affects {row.group}
                        </span>
                        <span className="tnum block font-mono text-xs text-foreground-tertiary">{row.id}</span>
                      </span>
                    </button>
                  </li>
                )
              })}
            </ul>
          </Disclosure>
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-2 border-t border-border px-3 py-2">
        <Button size="sm" variant="ghost" onClick={() => apply(null)} disabled={!activeScenario}>
          <RotateCcw aria-hidden="true" />
          Reset all scenarios
        </Button>
        <Button size="sm" variant="ghost" onClick={() => setResetOpen(true)}>
          <Trash2 aria-hidden="true" />
          Reset mock data
        </Button>
        <Button
          size="sm"
          variant="ghost"
          onClick={async () => {
            const ok = await copyText(window.location.href)
            if (ok) pushToast({ kind: 'success', title: 'Scenario URL copied' })
          }}
        >
          <Copy aria-hidden="true" />
          Copy scenario URL
        </Button>
      </div>

      <ConfirmDialog
        open={resetOpen}
        onOpenChange={setResetOpen}
        title="Reset mock data"
        description="Wipes persisted mock state and reseeds the deterministic baseline."
        target="mock state"
        effect="All mock instances, receipts, and scenario overrides return to the seeded baseline."
        reversibility="Not reversible — unsaved mock edits are lost."
        destructive
        requireTypedConfirmation="reset"
        confirmLabel="Reset mock data"
        onConfirm={async () => {
          await getClient().scenario.resetMockState()
          setActiveScenario(null)
          pushToast({ kind: 'success', title: 'Mock data reset', body: 'The seeded baseline was restored.' })
        }}
      />
    </aside>
  )
}

/** Slim 24 px ribbon while a scenario is active (stacks below the status bar). */
export function ScenarioRibbon() {
  const activeScenario = useSessionStore((s) => s.activeScenario)
  const setActiveScenario = useSessionStore((s) => s.setActiveScenario)
  const setLabOpen = useSessionStore((s) => s.setScenarioLabOpen)

  if (!import.meta.env.DEV || !activeScenario) return null
  return (
    <div
      className="flex h-6 shrink-0 items-center justify-center gap-3 border-t border-border bg-active px-3 font-mono text-xs text-foreground-secondary"
      data-testid="scenario-ribbon"
    >
      <span className="flex items-center gap-1.5">
        <FlaskConical className="size-3" aria-hidden="true" />
        Scenario: {activeScenario} · mock adapter
      </span>
      <button type="button" className="rounded-sm px-1 text-foreground hover:bg-hover" onClick={() => setActiveScenario(null)}>
        Exit scenario
      </button>
      <button type="button" className="rounded-sm px-1 text-foreground hover:bg-hover" onClick={() => setLabOpen(true)}>
        Open lab
      </button>
    </div>
  )
}

/** Dev-only panel + production param stripping. Renders nothing in prod. */
export function ScenarioLab() {
  const labOpen = useSessionStore((s) => s.scenarioLabOpen)
  const setLabOpen = useSessionStore((s) => s.setScenarioLabOpen)

  // Production: the URL param is inert — strip it on load (scenario-lab.md).
  useEffect(() => {
    if (import.meta.env.DEV) return
    if (typeof window === 'undefined') return
    const params = new URLSearchParams(window.location.search)
    if (params.has('scenario')) {
      params.delete('scenario')
      const query = params.toString()
      window.history.replaceState(null, '', `${window.location.pathname}${query ? `?${query}` : ''}${window.location.hash}`)
    }
    setLabOpen(false)
  }, [setLabOpen])

  if (!import.meta.env.DEV || !labOpen) return null
  return <ScenarioLabPanel />
}
