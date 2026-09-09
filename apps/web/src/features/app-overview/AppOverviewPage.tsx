/**
 * App overview (`#/app/:instanceId`) — the front door to an application
 * (app-overview.md). Answers in order: what is this / is it ready / what
 * should I do next / is anything blocked / what changed recently / is
 * anything awaiting approval / does anything need attention / is recovery
 * current.
 *
 * Composition: identity header (one dominant badge) → facts strip (state
 * surfaces exactly once) → Needs attention → package-driven sections
 * (Study / Checklist / Project) → Recent activity → Capabilities → Recovery.
 * On mobile, Recent activity / Capabilities / Recovery collapse into
 * disclosures (design Mobile). Workbench actions never render without the
 * workbench capability.
 *
 * data-testid="app-overview-stub" is kept on the layout root as a legacy
 * alias for the shell route-smoke test (new id: app-overview-page).
 */
import {
  Activity as ActivityIcon,
  BookOpen,
  DatabaseBackup,
  FileDiff,
  LayoutGrid,
  ListChecks,
  MessageSquare,
  Pin,
  PinOff,
  Server,
  Settings,
  ShieldCheck,
  ShieldQuestion,
  SquareTerminal,
} from 'lucide-react'
import { createElement, useCallback, useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'

import type { ActivityItem, ApplicationInstance, AttentionItem } from '@/client'
import { getClient } from '@/client'
import { CapabilityDot, Disclosure, InlineNotice, SectionHeader, TimeAgo, Tooltip } from '@/components'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import type { ShellCommand } from '@/shell/commands'
import { useRegisterCommands } from '@/shell/commands'
import { invalidateInstanceCache } from '@/shell/data'
import { useCurrentInstance } from '@/shell/currentInstance'
import { useIsMobile } from '@/hooks/use-mobile'
import { useSessionStore } from '@/state'

import { AttentionFeed } from '@/features/applications/components/AttentionFeed'
import { buildAttentionFeed } from '@/features/applications/lib/attentionFeed'
import { resumeTargetFor, useWorkspaceContinuity } from '@/features/applications/lib/continuity'
import { RenameDialog } from '@/features/applications/components/RenameDialog'
import { useServiceOffline } from '@/features/applications/lib/dashboardData'
import { dominantInstanceStatus } from '@/features/applications/lib/dominantStatus'
import { RECOVERY_PRESENTATION } from '@/features/applications/lib/recoveryPresentation'
import { applicationDestinationAvailable } from '@/features/application-experience/registry'

import { FactsStrip } from './components/FactsStrip'
import { ImportedTemplateJourney } from './components/ImportedTemplateJourney'
import { OverviewHeader } from './components/OverviewHeader'
import { ChecklistSection, ProjectSection, QuickLinks, StudySection } from './components/PackageSections'
import { ProvenanceOwnershipSection } from './components/ProvenanceOwnershipSection'
import { useOverviewData } from './lib/overviewData'

const MAX_ACTIVITY_ROWS = 8
const OVERVIEW_SOURCE_LABELS: Record<string, string> = {
  activity: 'Activity',
  approvals: 'Approvals',
  operations: 'Operations',
  receipts: 'Receipts',
  infrastructure: 'Infrastructure',
  package: 'Package metadata',
}

const CAPABILITY_LABELS: Record<string, string> = {
  conversation: 'Conversation',
  workbench: 'Workbench',
  file_viewer: 'Files',
  editor: 'Editor',
  terminal: 'Terminal',
  progress_dashboard: 'Progress',
  goal_execution: 'Goals',
  cto_orchestration: 'Orchestration',
  benchmark_evidence: 'Evidence',
  proactive_notifications: 'Notifications',
  backup: 'Backup',
  infrastructure: 'Deployments',
  receipts: 'Receipts',
}

const ACTIVITY_KIND_ICONS: Record<string, typeof ActivityIcon> = {
  approval: ShieldQuestion,
  file: FileDiff,
  infrastructure: Server,
  recovery: DatabaseBackup,
  conversation: MessageSquare,
  instance: LayoutGrid,
  study: BookOpen,
  checklist: ListChecks,
  settings: Settings,
  terminal: SquareTerminal,
}

function activityIcon(kind: string): typeof ActivityIcon {
  const prefix = kind.split('.')[0]
  return ACTIVITY_KIND_ICONS[prefix] ?? ActivityIcon
}

export default function AppOverviewPage() {
  const { instance, hasCapability, refresh } = useCurrentInstance()
  const navigate = useNavigate()
  const pushToast = useSessionStore((s) => s.pushToast)
  const serviceOffline = useServiceOffline()
  const readOnly = serviceOffline
  const isMobile = useIsMobile()
  const continuity = useWorkspaceContinuity()

  const [renameOpen, setRenameOpen] = useState(false)
  const [backupBusy, setBackupBusy] = useState(false)
  const [activityExpanded, setActivityExpanded] = useState(false)

  const data = useOverviewData(instance)
  const refreshData = data.refresh
  const hasWorkbench = instance ? hasCapability('workbench') : false
  const hasReceipts = instance ? applicationDestinationAvailable(instance, 'receipts') : false

  // ── Continue: resume the last view/tool; fall back to the honest primary ──
  const continueAction = useMemo(() => {
    if (!instance) return { route: '', label: 'Continue' }
    const target = resumeTargetFor(instance, continuity)
    const isLast = continuity.lastInstanceId === instance.id
    if (isLast && target.viewLabel !== 'Overview') {
      return { route: target.route, label: `Continue in ${target.viewLabel}` }
    }
    if (hasWorkbench) {
      return {
        route: `/app/${instance.id}/workbench`,
        label: isLast ? 'Continue in Workbench' : 'Open Workbench',
      }
    }
    return { route: `/app/${instance.id}/conversation`, label: 'Open Conversation' }
  }, [instance, continuity, hasWorkbench])

  const currentViewLabel = useMemo(() => {
    if (!instance) return 'Overview'
    if (continuity.lastInstanceId !== instance.id) return 'Overview'
    return resumeTargetFor(instance, continuity).viewLabel
  }, [instance, continuity])

  const status = useMemo(
    () =>
      instance
        ? dominantInstanceStatus(
            {
              instance,
              pendingApprovals: data.pendingApprovals.length,
              operations: data.operations,
              capabilityDegraded: instance.capabilities.some((c) => c.status === 'degraded'),
            },
            { quiet: 'ready', dataState: data.sourceState },
          )
        : null,
    [instance, data.pendingApprovals.length, data.operations, data.sourceState],
  )

  const feed = useMemo(
    () =>
      instance
        ? buildAttentionFeed({
            instances: [instance],
            pendingApprovals: data.pendingApprovals,
            operations: data.operations,
            instanceId: instance.id,
          })
        : [],
    [instance, data.pendingApprovals, data.operations],
  )

  // ── mutations (all through the client boundary; then refresh) ─────────────
  const togglePin = useCallback(async () => {
    if (!instance) return
    const next = !instance.pinned
    try {
      await getClient().applications.setPinned(instance.id, next)
      invalidateInstanceCache(instance.id)
      pushToast({
        kind: 'success',
        title: next ? `Pinned ${instance.name}` : `Unpinned ${instance.name}`,
        body: next ? 'Unpin anytime from the overview menu.' : undefined,
      })
    } catch {
      pushToast({ kind: 'error', title: `Couldn't ${next ? 'pin' : 'unpin'} ${instance.name}`, body: 'Nothing changed.' })
    } finally {
      refresh()
    }
  }, [instance, pushToast, refresh])

  const acknowledge = useCallback(
    async (item: AttentionItem) => {
      if (!instance) return
      try {
        await getClient().activity.acknowledgeAttention(item.id)
        invalidateInstanceCache(instance.id)
      } catch {
        pushToast({ kind: 'error', title: `Couldn't acknowledge “${item.title}”`, body: 'Nothing changed.' })
      } finally {
        refresh()
        refreshData()
      }
    },
    [instance, pushToast, refresh, refreshData],
  )

  const runBackup = useCallback(async () => {
    if (!instance || backupBusy) return
    setBackupBusy(true)
    try {
      const { receipt } = await getClient().recovery.runBackup(instance.id)
      invalidateInstanceCache(instance.id)
      pushToast({
        kind: 'success',
        title: 'Backup completed',
        body: `Validated receipt ${receipt.id} was recorded.`,
        route: hasReceipts ? `/app/${instance.id}/receipts/${receipt.id}` : undefined,
      })
    } catch {
      pushToast({
        kind: 'error',
        title: 'Backup not confirmed',
        body:
          'No validated receipt was received. The outcome may be unknown; refresh Recovery or Receipts before retrying.',
      })
    } finally {
      setBackupBusy(false)
      refresh()
      refreshData()
    }
  }, [instance, backupBusy, hasReceipts, pushToast, refresh, refreshData])

  // ── palette commands: pin/unpin · approvals for this app · run backup ─────
  const commands = useMemo<ShellCommand[]>(() => {
    if (!instance) return []
    const list: ShellCommand[] = [
      {
        id: 'app.toggle_pin',
        title: instance.pinned ? `Unpin ${instance.name}` : `Pin ${instance.name}`,
        group: 'Applications',
        icon: instance.pinned ? PinOff : Pin,
        keywords: ['pin', 'favorite'],
        run: () => void togglePin(),
      },
    ]
    if (data.pendingApprovals.length > 0) {
      list.push({
        id: 'app.open_approvals',
        title: `Open approvals for ${instance.name} (${data.pendingApprovals.length} pending)`,
        group: 'Applications',
        icon: ShieldQuestion,
        keywords: ['approval', 'review'],
        run: () => void navigate('/approvals'),
      })
    }
    if (hasCapability('backup') && instance.recovery.state !== 'not_configured' && !readOnly) {
      list.push({
        id: 'app.run_backup',
        title: `Run backup for ${instance.name}`,
        group: 'Applications',
        icon: DatabaseBackup,
        keywords: ['backup', 'recovery'],
        run: () => void runBackup(),
      })
    }
    return list
  }, [instance, data.pendingApprovals.length, hasCapability, readOnly, togglePin, runBackup, navigate])
  useRegisterCommands(commands)

  if (!instance || !status) return null

  const lastReceipt = data.receipts[0] ?? null
  const visibleActivity = activityExpanded ? data.activity : data.activity.slice(0, MAX_ACTIVITY_ROWS)
  const recovery = RECOVERY_PRESENTATION[instance.recovery.state]
  const RecoveryIcon = recovery.icon
  const canBackup = hasCapability('backup') && instance.recovery.state !== 'not_configured'

  const activitySection = data.activity.length > 0 ? (
    <div data-testid="recent-activity-section">
      <ul aria-label="Recent activity" className="divide-y divide-border">
        {visibleActivity.map((item) => (
          <ActivityRow key={item.id} item={item} instance={instance} hasReceipts={hasReceipts} />
        ))}
      </ul>
      {!activityExpanded && data.activity.length > MAX_ACTIVITY_ROWS ? (
        <button
          type="button"
          onClick={() => setActivityExpanded(true)}
          className="mt-1.5 text-xs font-medium text-accent hover:underline"
        >
          View all activity ({data.activity.length})
        </button>
      ) : null}
    </div>
  ) : null

  const capabilitiesSection = (
    <div data-testid="capabilities-section">
      <CapabilitiesBody instance={instance} />
    </div>
  )

  const recoverySection = (
    <div data-testid="recovery-section">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
        <span className={cn('inline-flex items-center gap-1 font-medium', RECOVERY_TEXT[recovery.state])} data-testid="recovery-state" data-state={recovery.state}>
          <RecoveryIcon className={cn('size-3.5', recovery.spin && 'icon-spin')} aria-hidden="true" />
          {recovery.label}
        </span>
        {instance.recovery.lastBackupAt ? (
          <span className="text-foreground-tertiary">
            Last backup <TimeAgo date={instance.recovery.lastBackupAt} className="inline" />
          </span>
        ) : null}
        {instance.recovery.nextDueAt ? (
          <span className="text-foreground-tertiary">
            Next due <TimeAgo date={instance.recovery.nextDueAt} className="inline" />
          </span>
        ) : null}
        {instance.recovery.detail ? <span className="text-foreground-secondary">{instance.recovery.detail}</span> : null}
        {instance.recovery.state === 'due' && !instance.recovery.detail ? (
          <span className="text-foreground-secondary">
            No current verified backup — without one, this application's state cannot be restored after data loss.
          </span>
        ) : null}
        {instance.recovery.lastReceiptId && hasReceipts ? (
          <Link
            to={`/app/${instance.id}/receipts/${instance.recovery.lastReceiptId}`}
            className="font-medium text-accent hover:underline"
          >
            Backup receipt
          </Link>
        ) : null}
        {canBackup && !readOnly ? (
          <Button size="sm" variant="outline" onClick={() => void runBackup()} disabled={backupBusy} className="ml-auto min-h-10 md:min-h-8">
            <DatabaseBackup aria-hidden="true" />
            {backupBusy ? 'Backing up…' : 'Back up now'}
          </Button>
        ) : null}
      </div>
    </div>
  )

  const provenanceSection = instance.provenance ? (
    <ProvenanceOwnershipSection provenance={instance.provenance} />
  ) : null

  const unavailableSources = Object.entries(data.sourceStates)
    .filter(([, sourceState]) => sourceState === 'unavailable')
    .map(([source]) => OVERVIEW_SOURCE_LABELS[source] ?? source)
  const staleSources = Object.entries(data.sourceStates)
    .filter(([, sourceState]) => sourceState === 'stale')
    .map(([source]) => OVERVIEW_SOURCE_LABELS[source] ?? source)

  return (
    <div className="h-full overflow-y-auto bg-app" data-testid="app-overview-page">
      {/* Legacy alias for the shell route-smoke test (kept until the shell suite migrates). */}
      <div className="mx-auto flex w-full max-w-[880px] flex-col gap-6 p-4 md:p-6" data-testid="app-overview-stub">
        <OverviewHeader
          instance={instance}
          status={status}
          packageVersion={data.packageVersion}
          continueAction={continueAction}
          hasWorkbench={hasWorkbench}
          readOnly={readOnly}
          onContinue={() => void navigate(continueAction.route)}
          onOpenConversation={() => void navigate(`/app/${instance.id}/conversation`)}
          onOpenWorkbench={() => void navigate(`/app/${instance.id}/workbench`)}
          onOpenSettings={() => void navigate(`/app/${instance.id}/settings`)}
          onTogglePin={() => void togglePin()}
          showContinueAction={instance.packageState?.kind !== 'study-state'}
          onRename={getClient().applications.canRename ? () => setRenameOpen(true) : undefined}
        />

        {!data.loading && unavailableSources.length > 0 ? (
          <InlineNotice tone="blocked" title="Some overview data is unavailable" data-testid="overview-data-unavailable">
            {unavailableSources.join(', ')} could not be read. The status above is not Ready; retry to refresh these sources.
          </InlineNotice>
        ) : !data.loading && staleSources.length > 0 ? (
          <InlineNotice tone="attention" title="Showing last known overview data" data-testid="overview-data-stale">
            {staleSources.join(', ')} could not be refreshed. Values shown below may be stale.
          </InlineNotice>
        ) : null}

        <FactsStrip instance={instance} currentViewLabel={currentViewLabel} lastReceipt={lastReceipt} hasReceipts={hasReceipts} />
        <ImportedTemplateJourney instance={instance} />

        {!data.loading && feed.length > 0 ? (
          <section aria-label="Needs attention" data-testid="overview-attention-section">
            <SectionHeader title="Needs attention" className="mb-2" />
            <div className="rounded-md border border-border bg-surface px-1">
              <AttentionFeed items={feed} readOnly={readOnly} onAcknowledge={acknowledge} />
            </div>
          </section>
        ) : null}

        {/* Package-driven sections (capability truth, not generic widgets). */}
        <StudySection
          instance={instance}
          receipts={data.receipts}
          onDurableStateChanged={async () => {
            invalidateInstanceCache(instance.id)
            await Promise.resolve(refresh())
            refreshData()
          }}
        />
        <ChecklistSection instance={instance} receipts={data.receipts} />
        <ProjectSection instance={instance} operations={data.operations} infraTarget={data.infraTarget} hasWorkbench={hasWorkbench} />
        {hasWorkbench || hasReceipts ? (
          <QuickLinks
            instance={instance}
            has={hasCapability}
            hasWorkbench={hasWorkbench}
            canOpenReceipts={hasReceipts}
          />
        ) : null}

        {isMobile ? (
          <div className="flex flex-col gap-2">
            {activitySection ? (
              <div className="rounded-md border border-border bg-surface px-1 py-1">
                <Disclosure title="Recent activity" defaultOpen={false}>
                  <div className="px-1 pb-1">{activitySection}</div>
                </Disclosure>
              </div>
            ) : null}
            <div className="rounded-md border border-border bg-surface px-1 py-1">
              <Disclosure title="Capabilities" defaultOpen={false}>
                <div className="px-2 pb-2">{capabilitiesSection}</div>
              </Disclosure>
            </div>
            {provenanceSection}
            <div className="rounded-md border border-border bg-surface px-1 py-1">
              <Disclosure title="Recovery" defaultOpen={false}>
                <div className="px-2 pb-2">{recoverySection}</div>
              </Disclosure>
            </div>
          </div>
        ) : (
          <>
            {activitySection ? (
              <section aria-label="Recent activity">
                <SectionHeader title="Recent activity" className="mb-2" />
                <div className="rounded-md border border-border bg-surface px-3 py-2">{activitySection}</div>
              </section>
            ) : null}
            <section aria-label="Capabilities">
              <SectionHeader title="Capabilities" className="mb-2" />
              <div className="rounded-md border border-border bg-surface px-3 py-2">{capabilitiesSection}</div>
            </section>
            {provenanceSection}
            <section aria-label="Recovery">
              <SectionHeader title="Recovery" className="mb-2" />
              <div className="rounded-md border border-border bg-surface px-3 py-2">{recoverySection}</div>
            </section>
          </>
        )}
      </div>

      {getClient().applications.canRename ? (
        <RenameDialog
          open={renameOpen}
          currentName={instance.name}
          onOpenChange={setRenameOpen}
          onSubmit={async (name) => {
            await getClient().applications.rename(instance.id, name, instance.name)
            invalidateInstanceCache(instance.id)
            pushToast({ kind: 'success', title: `Renamed to ${name}` })
            refresh()
          }}
        />
      ) : null}
    </div>
  )
}

const RECOVERY_TEXT: Record<string, string> = {
  success: 'text-status-success',
  neutral: 'text-foreground-secondary',
  attention: 'text-status-attention',
  waiting: 'text-status-waiting',
  blocked: 'text-status-blocked',
  danger: 'text-status-danger',
  informational: 'text-status-informational',
}

function ActivityRow({ item, instance, hasReceipts }: { item: ActivityItem; instance: ApplicationInstance; hasReceipts: boolean }) {
  return (
    <li
      className="flex min-h-row items-center gap-2 py-1.5"
      data-activity-id={item.id}
      data-receipt-id={item.relatedReceiptId}
    >
      {/* Dynamic kind→icon lookup: createElement keeps it out of component-alias form. */}
      {createElement(activityIcon(item.kind), { className: 'size-4 shrink-0 text-foreground-tertiary', 'aria-hidden': true })}
      <span className="min-w-0 flex-1 truncate text-sm text-foreground">{item.title}</span>
      <TimeAgo date={item.createdAt} className="shrink-0" />
      {item.relatedReceiptId && hasReceipts ? (
        <Tooltip content="Open receipt">
          <Link
            to={`/app/${instance.id}/receipts/${item.relatedReceiptId}`}
            aria-label={`Open receipt for “${item.title}”`}
            className="inline-flex min-h-8 min-w-8 shrink-0 items-center justify-center rounded-sm text-foreground-secondary transition-colors duration-instant hover:bg-hover hover:text-foreground"
          >
            <ShieldCheck className="size-3.5" aria-hidden="true" />
          </Link>
        </Tooltip>
      ) : null}
    </li>
  )
}

function CapabilitiesBody({ instance }: { instance: ApplicationInstance }) {
  const available = instance.capabilities.filter((c) => c.status === 'available')
  const gated = instance.capabilities.filter((c) => c.status !== 'available')
  const summary = `${available.map((c) => CAPABILITY_LABELS[c.id] ?? c.id).join(' · ')} available${
    gated.length > 0 ? ` — ${gated.length} unavailable` : ''
  }`
  return (
    <Disclosure title={<span className="text-xs font-normal text-foreground-secondary">{summary}</span>} defaultOpen={false}>
      <ul className="mt-1 flex flex-col gap-1 pl-2">
        {instance.capabilities.map((c) => (
          <li key={c.id} className="flex min-h-6 items-center gap-2 text-xs">
            {c.status === 'available' ? (
              <span className="text-foreground-secondary">{CAPABILITY_LABELS[c.id] ?? c.id}</span>
            ) : (
              <>
                <CapabilityDot status={c.status} reason={c.reason} />
                <span className="text-foreground-secondary">{CAPABILITY_LABELS[c.id] ?? c.id}</span>
                {c.reason ? <span className="truncate text-foreground-tertiary">— {c.reason}</span> : null}
              </>
            )}
          </li>
        ))}
      </ul>
    </Disclosure>
  )
}
