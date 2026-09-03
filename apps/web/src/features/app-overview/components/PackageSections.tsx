/**
 * Package-driven overview sections (app-overview.md): the overview is
 * capability-driven — a study package surfaces learning truth, a checklist
 * package surfaces list truth, a project/infrastructure package surfaces
 * repository + target truth. Sections render only for their package kind and
 * never restate the dominant badge or the facts strip.
 *
 * Contract gaps (reported, UI stays honest):
 * - Checklist item toggles persist optimistically in the applications prefs
 *   store — the client boundary has no `toggleChecklistItem` yet, so no new
 *   receipt is produced for toggles (the "last receipt" lines still read the
 *   real receipt list).
 * - Study goal edits persist the same way (no `updateStudyGoal` contract).
 */
import {
  BadgeCheck,
  Circle,
  CircleCheck,
  CircleDashed,
  CircleDot,
  CirclePause,
  FileDiff,
  KeyRound,
  PenLine,
  Server,
  SquareTerminal,
} from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'

import type { ApplicationInstance, CapabilityId, InfrastructureTarget, OperationRecord, Receipt } from '@/client'
import type { SemanticPresentation } from '@/semantic'
import {
  healthStatePresentation,
  repositoryCleanPresentation,
  sshStatePresentation,
  vmStatePresentation,
} from '@/semantic'
import { OperationStateLabel, SectionHeader, TimeAgo, Tooltip } from '@/components'
import { Checkbox } from '@/components/ui/checkbox'
import { cn } from '@/lib/utils'
import { LIVE_OP_STATES } from '@/features/applications/lib/dominantStatus'
import { useApplicationsPrefs } from '@/features/applications/lib/prefsStore'
import { StudyJourney } from './StudyJourney'

const STATE_TEXT: Record<string, string> = {
  success: 'text-status-success',
  neutral: 'text-foreground-secondary',
  attention: 'text-status-attention',
  waiting: 'text-status-waiting',
  blocked: 'text-status-blocked',
  danger: 'text-status-danger',
  informational: 'text-status-informational',
}

function SectionShell({
  title,
  testId,
  children,
}: {
  title: string
  testId: string
  children: React.ReactNode
}) {
  return (
    <section aria-label={title} data-testid={testId}>
      <SectionHeader title={title} className="mb-2" />
      <div className="rounded-md border border-border bg-surface px-3 py-2.5">{children}</div>
    </section>
  )
}

/** Thin 2 px determinate progress bar (design: progress is a thin bar + count). */
function ProgressBar({ value, total, label }: { value: number; total: number; label: string }) {
  const percent = total > 0 ? Math.round((value / total) * 100) : 0
  return (
    <div className="flex items-center gap-2" role="progressbar" aria-valuenow={value} aria-valuemin={0} aria-valuemax={total} aria-label={label}>
      <div className="h-0.5 min-w-16 flex-1 rounded-full bg-active">
        <div className="h-full rounded-full bg-status-success transition-[width] duration-fast" style={{ width: `${percent}%` }} />
      </div>
      <span className="shrink-0 text-xs text-foreground-secondary tnum">{label}</span>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// StudyState
// ─────────────────────────────────────────────────────────────────────────────

const STUDY_ACTIVITY_ICON = {
  done: { icon: CircleCheck, className: 'text-status-success', label: 'Done' },
  in_progress: { icon: CircleDot, className: 'text-status-informational', label: 'In progress' },
  paused: { icon: CirclePause, className: 'text-foreground-secondary', label: 'Paused' },
  not_started: { icon: Circle, className: 'text-foreground-tertiary', label: 'Not started' },
} as const

const STUDY_EVIDENCE_LABEL = {
  verified: { icon: BadgeCheck, className: 'text-status-success', label: 'Verified' },
  self_reported: { icon: PenLine, className: 'text-foreground-secondary', label: 'Self-reported' },
  draft: { icon: PenLine, className: 'text-foreground-secondary', label: 'Draft' },
  missing: { icon: CircleDashed, className: 'text-foreground-tertiary', label: 'Missing' },
} as const

export function StudySection({
  instance,
  receipts,
  onDurableStateChanged,
}: {
  instance: ApplicationInstance
  receipts: Receipt[]
  onDurableStateChanged: () => Promise<void> | void
}) {
  const study = instance.packageState?.kind === 'study-state' ? instance.packageState : null
  const override = useApplicationsPrefs((s) => s.studyGoalOverrides[instance.id])
  const setStudyGoal = useApplicationsPrefs((s) => s.setStudyGoal)
  const resetStudyGoal = useApplicationsPrefs((s) => s.resetStudyGoal)
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState('')
  if (!study) return null

  const goal = override ?? study.goal
  const verified = study.evidence.filter((e) => e.state === 'verified').length
  const reviewReceipt = receipts.find((r) => /review/i.test(r.summary) || /review/i.test(r.actionName))

  return (
    <SectionShell title="Learning goal" testId="study-section">
      <div className="flex flex-col gap-2.5">
        <StudyJourney instance={instance} study={study} onDurableStateChanged={onDurableStateChanged} />

        {/* Current learning goal — one sentence. Edits are browser-local
            drafts only: no backend goal-update contract exists yet, so the
            UI must never present them as canonical application state. */}
        <div data-testid="study-goal">
          {editing ? (
            <form
              className="flex items-center gap-2"
              onSubmit={(e) => {
                e.preventDefault()
                const next = draft.trim()
                if (next) setStudyGoal(instance.id, next)
                setEditing(false)
              }}
            >
              <input
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                aria-label="Edit learning goal"
                className="h-control min-w-0 flex-1 rounded-sm border border-input bg-surface px-2 text-sm text-foreground"
              />
              <button type="submit" className="min-h-10 rounded-sm border border-border px-2.5 text-xs font-medium text-accent hover:bg-hover md:min-h-8">
                Save local draft
              </button>
              <button
                type="button"
                onClick={() => setEditing(false)}
                className="min-h-10 rounded-sm px-2 text-xs text-foreground-secondary hover:bg-hover md:min-h-8"
              >
                Cancel
              </button>
            </form>
          ) : (
            <p className="text-sm text-foreground">
              {goal}
              <Tooltip content="Edit learning goal (browser-local draft)">
                <button
                  type="button"
                  aria-label="Edit learning goal"
                  onClick={() => {
                    setDraft(goal)
                    setEditing(true)
                  }}
                  className="ml-2 inline-flex min-h-6 min-w-6 items-center justify-center rounded-sm align-middle text-foreground-tertiary transition-colors duration-instant hover:bg-hover hover:text-foreground"
                >
                  <PenLine className="size-3.5" aria-hidden="true" />
                </button>
              </Tooltip>
            </p>
          )}
          <p className="text-xs text-foreground-tertiary tnum">{study.goalProgressPercent}% toward goal</p>
          {override !== undefined ? (
            <p className="mt-1 text-xs text-status-attention" data-testid="study-goal-local-draft">
              Local draft in this browser — the application goal is unchanged.{' '}
              <button
                type="button"
                onClick={() => resetStudyGoal(instance.id)}
                className="underline underline-offset-2 hover:text-foreground"
              >
                Reset to application goal
              </button>
            </p>
          ) : null}
        </div>

        {/* Today's activity */}
        {study.activities.length > 0 ? (
          <ul aria-label="Study activities" className="flex flex-col gap-1">
            {study.activities.map((activity) => {
              const meta = STUDY_ACTIVITY_ICON[activity.state]
              return (
                <li key={activity.id} className="flex min-w-0 items-center gap-2 text-sm">
                  <meta.icon className={cn('size-3.5 shrink-0', meta.className)} aria-hidden="true" />
                  <span className={cn('min-w-0 flex-1 truncate', activity.state === 'done' ? 'text-foreground-secondary' : 'text-foreground')}>
                    {activity.title}
                  </span>
                  <span className="shrink-0 text-xs text-foreground-tertiary">{meta.label}</span>
                </li>
              )
            })}
          </ul>
        ) : null}

        {/* Evidence progress */}
        <div data-testid="study-evidence">
          <ProgressBar
            value={verified}
            total={study.evidence.length}
            label={`${verified} of ${study.evidence.length} evidence items verified`}
          />
          <ul aria-label="Evidence items" className="mt-1.5 flex flex-col gap-1">
            {study.evidence.map((item) => {
              const meta = STUDY_EVIDENCE_LABEL[item.state]
              return (
                <li key={item.id} className="flex min-w-0 items-center gap-2 text-xs">
                  <meta.icon className={cn('size-3.5 shrink-0', meta.className)} aria-hidden="true" />
                  <span className="min-w-0 flex-1 truncate text-foreground-secondary">{item.title}</span>
                  <span className="shrink-0 text-foreground-tertiary">{meta.label}</span>
                </li>
              )
            })}
          </ul>
        </div>

        {/* Review + reminders (honest: derived from the real receipt stream). */}
        <p className="text-xs text-foreground-tertiary">
          {reviewReceipt ? (
            <>
              Weekly review — last reminder{' '}
              <TimeAgo date={reviewReceipt.createdAt} className="inline" />
              {' · '}
            </>
          ) : null}
          Reminders arrive as notifications.
        </p>
      </div>
    </SectionShell>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// ChecklistState
// ─────────────────────────────────────────────────────────────────────────────

export function ChecklistSection({ instance, receipts }: { instance: ApplicationInstance; receipts: Receipt[] }) {
  const checklist = instance.packageState?.kind === 'checklist-state' ? instance.packageState : null
  const overrides = useApplicationsPrefs((s) => s.checklistDoneOverrides)
  const setChecklistDone = useApplicationsPrefs((s) => s.setChecklistDone)
  const resetChecklist = useApplicationsPrefs((s) => s.resetChecklist)
  if (!checklist) return null

  const hasOverrides = Object.keys(overrides).some((key) => key.startsWith(`${instance.id}:`))
  const items = checklist.items.map((item) => ({
    ...item,
    done: overrides[`${instance.id}:${item.id}`] ?? item.done,
  }))
  const doneCount = items.filter((i) => i.done).length
  const nextItem = items.find((i) => !i.done)
  const lastReceipt = receipts.find((r) => r.eventKind.startsWith('checklist')) ?? receipts[0] ?? null

  return (
    <SectionShell title="Checklist" testId="checklist-section">
      <div className="flex flex-col gap-2.5">
        <ProgressBar value={doneCount} total={items.length} label={`${doneCount} of ${items.length} complete`} />
        <ul aria-label="Checklist items" className="flex flex-col">
          {items.map((item) => (
            <li key={item.id} className="flex min-h-10 items-center gap-2 md:min-h-8" data-testid={`checklist-item-${item.id}`}>
              <Checkbox
                id={`checklist-${instance.id}-${item.id}`}
                checked={item.done}
                onCheckedChange={(checked) => setChecklistDone(instance.id, item.id, checked === true)}
                aria-label={item.title}
              />
              <label
                htmlFor={`checklist-${instance.id}-${item.id}`}
                className={cn('min-w-0 flex-1 cursor-pointer truncate text-sm', item.done ? 'text-foreground-secondary line-through' : 'text-foreground')}
              >
                {item.title}
              </label>
              <TimeAgo date={item.updatedAt} className="shrink-0" />
            </li>
          ))}
        </ul>
        <p className="text-xs text-foreground-tertiary">
          {nextItem ? (
            <>
              Next up: <span className="text-foreground-secondary">{nextItem.title}</span>
              {' · '}
            </>
          ) : (
            'All items complete · '
          )}
          {lastReceipt ? (
            <>
              Last receipt: {lastReceipt.actionName} <TimeAgo date={lastReceipt.createdAt} className="inline" />
            </>
          ) : (
            'No receipts yet'
          )}
        </p>
        {hasOverrides ? (
          <p className="text-xs text-status-attention" data-testid="checklist-local-draft">
            Checks marked here are stored in this browser only — no checklist completion is recorded in the
            application.{' '}
            <button
              type="button"
              onClick={() => resetChecklist(instance.id)}
              className="underline underline-offset-2 hover:text-foreground"
            >
              Reset to application state
            </button>
          </p>
        ) : null}
      </div>
    </SectionShell>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// ProjectState / infrastructure-backed packages
// ─────────────────────────────────────────────────────────────────────────────

function MiniLabel({ label, presentation, testId }: { label: string; presentation: SemanticPresentation; testId?: string }) {
  const Icon = presentation.icon
  return (
    <span className="inline-flex min-w-0 items-center gap-1 text-xs" data-testid={testId}>
      <span className="shrink-0 text-foreground-tertiary">{label}</span>
      <span className={cn('inline-flex items-center gap-1 font-medium', STATE_TEXT[presentation.state])} data-state={presentation.state}>
        <Icon className={cn('size-3.5', presentation.spin && 'icon-spin')} aria-hidden="true" />
        {presentation.label}
      </span>
    </span>
  )
}

export function ProjectSection({
  instance,
  operations,
  infraTarget,
  hasWorkbench,
}: {
  instance: ApplicationInstance
  operations: OperationRecord[]
  infraTarget: InfrastructureTarget | null
  hasWorkbench: boolean
}) {
  const live = operations.find((o) => LIVE_OP_STATES.includes(o.state))
  const repo = instance.repository
  const clean = repo ? repositoryCleanPresentation(repo.clean) : null

  if (!live && !repo && !infraTarget) return null

  return (
    <SectionShell title="Project" testId="project-section">
      <div className="flex flex-col gap-2.5">
        {live ? (
          <div className="flex min-w-0 items-center gap-2">
            <OperationStateLabel state={live.state} startedAt={live.startedAt} />
            <span className="min-w-0 flex-1 truncate text-sm text-foreground">{live.title}</span>
            {typeof live.progressPercent === 'number' ? (
              <span className="tnum shrink-0 text-xs text-foreground-tertiary">{live.progressPercent}%</span>
            ) : null}
            {hasWorkbench ? (
              <Link
                to={`/app/${instance.id}/workbench`}
                className="inline-flex min-h-8 shrink-0 items-center rounded-sm border border-border px-2 text-xs font-medium text-accent hover:bg-hover"
              >
                Open
              </Link>
            ) : null}
          </div>
        ) : null}

        {repo && clean ? (
          <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 text-xs">
            <span className="inline-flex min-w-0 items-center gap-1.5">
              <FileDiff className="size-3.5 shrink-0 text-foreground-tertiary" aria-hidden="true" />
              <span className="truncate font-mono text-foreground">{repo.name}</span>
            </span>
            <span className="inline-flex items-center gap-1">
              <span className="text-foreground-tertiary">branch</span>
              <span className="font-mono text-foreground">{repo.branch}</span>
            </span>
            <span className="font-mono text-foreground-tertiary">@{repo.revision.slice(0, 7) || '—'}</span>
            <MiniLabel label="" presentation={clean} />
          </div>
        ) : null}

        {infraTarget ? (
          <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 text-xs" data-testid="target-summary">
            <span className="inline-flex items-center gap-1.5">
              <Server className="size-3.5 shrink-0 text-foreground-tertiary" aria-hidden="true" />
              <span className="truncate text-foreground">{infraTarget.name}</span>
            </span>
            <MiniLabel label="VM" presentation={vmStatePresentation(infraTarget.vm.state)} testId="target-vm" />
            <MiniLabel label="SSH" presentation={sshStatePresentation(infraTarget.ssh.state)} testId="target-ssh" />
            <MiniLabel label="Health" presentation={healthStatePresentation(infraTarget.health.state)} testId="target-health" />
          </div>
        ) : null}
      </div>
    </SectionShell>
  )
}

/** Capability-gated quick links for application actions (app-overview.md "pinned actions"). */
export function QuickLinks({
  instance,
  has,
  hasWorkbench,
  canOpenReceipts,
}: {
  instance: ApplicationInstance
  has: (id: CapabilityId) => boolean
  hasWorkbench: boolean
  canOpenReceipts: boolean
}) {
  const links: { to: string; label: string; icon: typeof SquareTerminal }[] = []
  if (hasWorkbench && (has('file_viewer') || has('editor'))) {
    links.push({ to: `/app/${instance.id}/workbench/files`, label: 'Files', icon: FileDiff })
  }
  if (hasWorkbench && has('terminal')) {
    links.push({ to: `/app/${instance.id}/workbench/terminal`, label: 'Terminal', icon: SquareTerminal })
  }
  if (hasWorkbench && has('infrastructure')) {
    links.push({ to: `/app/${instance.id}/workbench/deployments`, label: 'Deployments', icon: Server })
  }
  if (canOpenReceipts) links.push({ to: `/app/${instance.id}/receipts`, label: 'Receipts', icon: KeyRound })
  if (links.length === 0) return null
  return (
    <nav aria-label="Quick links" className="flex flex-wrap items-center gap-1.5" data-testid="quick-links">
      {links.map((link) => (
        <Link
          key={link.to}
          to={link.to}
          className="inline-flex min-h-10 items-center gap-1.5 rounded-sm border border-border bg-surface px-2.5 text-xs font-medium text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground md:min-h-8"
        >
          <link.icon className="size-3.5" aria-hidden="true" />
          {link.label}
        </Link>
      ))}
    </nav>
  )
}
