/**
 * WorkbenchOverviewTool — the workbench's operational summary (workbench.md
 * §"Workbench Overview tool"): a tool launcher + current-state summary, not
 * a marketing page. Rows per available tool with honest one-line statuses
 * (unavailable tools are omitted, never disabled ghosts), active work,
 * recent receipts and activity, the layout preset with change/reset, a
 * backup-due nudge, and capability reasons where they exist.
 *
 * `data-testid="workbench-overview-stub"` stays on the root: the shell
 * route-smoke test (out of scope) looks it up on this route.
 */
import {
  ArrowRight,
  Check,
  ChevronRight,
  CircleAlert,
  FilePenLine,
  LayoutGrid,
  PanelsTopLeft,
  RotateCcw,
} from 'lucide-react'
import type { ComponentType, ReactNode } from 'react'
import { useCallback, useMemo } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'

import type { CapabilityId, OperationRecord, WorkbenchToolId } from '@/client'
import {
  CapabilityDot,
  ErrorState,
  InlineNotice,
  OperationStateLabel,
  SectionHeader,
  SkeletonRows,
  StatusDotFrom,
  TimeAgo,
  Tooltip,
} from '@/components'
import { CONDITION_PRESENTATIONS } from '@/semantic'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { useCurrentInstance } from '@/shell/currentInstance'
import { useRegisterToolPanel } from '@/shell/workbench/WorkbenchSlots'
import { WorkbenchToolHeader } from '@/shell/workbench/ToolHeader'
import { DEFAULT_LAYOUT, useWorkspaceStore } from '@/state'
import type { LayoutPreset } from '@/state'

import {
  CAPABILITY_LABELS,
  deploymentsToolStatus,
  filesToolStatus,
  orchestrationToolStatus,
  OVERVIEW_TOOL_LINKS,
  PRESET_LABELS,
  PRESET_ORDER,
  presetLayoutPatch,
  receiptsToolStatus,
  terminalToolStatus,
} from './overviewModel'
import type { ToolStatus } from './overviewModel'
import { useWorkbenchSummary } from './useWorkbenchSummary'

// ─────────────────────────────────────────────────────────────────────────────
// Row primitives (rows separated by hairlines — no card wall)
// ─────────────────────────────────────────────────────────────────────────────

function Section({ id, title, description, actions, children }: { id: string; title: string; description?: string; actions?: ReactNode; children: ReactNode }) {
  return (
    <section id={id} aria-label={title} className="scroll-mt-2">
      <SectionHeader title={title} description={description} actions={actions} className="mb-1" />
      <div className="border-t border-border">{children}</div>
    </section>
  )
}

function LinkRow({
  to,
  icon: Icon,
  title,
  detail,
  trailing,
  testId,
}: {
  to: string
  icon?: ComponentType<{ className?: string }>
  title: ReactNode
  detail?: ReactNode
  trailing?: ReactNode
  testId?: string
}) {
  return (
    <Link
      to={to}
      className="flex min-h-10 items-center gap-3 border-b border-border/60 px-1 py-1 transition-colors duration-instant hover:bg-hover"
      data-testid={testId}
    >
      {Icon ? <Icon className="size-5 shrink-0 text-foreground-secondary" aria-hidden="true" /> : null}
      <span className="min-w-0 flex-1">
        <span className="block truncate text-sm font-medium text-foreground">{title}</span>
        {detail ? <span className="block truncate text-xs text-foreground-tertiary">{detail}</span> : null}
      </span>
      {trailing}
      <ArrowRight className="size-4 shrink-0 text-foreground-tertiary" aria-hidden="true" />
    </Link>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Section-index nav panel (workbench.md: "Overview → section index")
// ─────────────────────────────────────────────────────────────────────────────

const SECTION_INDEX = [
  { id: 'overview-active', label: 'Active work' },
  { id: 'overview-tools', label: 'Tools' },
  { id: 'overview-receipts', label: 'Recent receipts' },
  { id: 'overview-activity', label: 'Recent activity' },
  { id: 'overview-capabilities', label: 'Capabilities' },
  { id: 'overview-layout', label: 'Layout' },
] as const

function OverviewNavPanel() {
  return (
    <nav aria-label="Overview sections" className="flex flex-col py-1" data-testid="overview-nav-panel">
      {SECTION_INDEX.map((section) => (
        <button
          key={section.id}
          type="button"
          onClick={() => document.getElementById(section.id)?.scrollIntoView({ block: 'start' })}
          className="flex min-h-7 items-center px-3 text-left text-sm text-foreground transition-colors duration-instant hover:bg-hover"
        >
          {section.label}
        </button>
      ))}
    </nav>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// The tool
// ─────────────────────────────────────────────────────────────────────────────

export default function WorkbenchOverviewTool() {
  const { instanceId = '' } = useParams<{ instanceId: string }>()
  const { instance, hasCapability, capability } = useCurrentInstance()
  const [searchParams, setSearchParams] = useSearchParams()

  const layout = useWorkspaceStore((s) => s.layouts[instanceId] ?? DEFAULT_LAYOUT)
  const setLayout = useWorkspaceStore((s) => s.setLayout)
  const resetLayout = useWorkspaceStore((s) => s.resetLayout)
  const openFiles = useWorkspaceStore((s) => s.openFiles[instanceId])
  const openFileCount = openFiles?.length ?? 0

  const summary = useWorkbenchSummary(instance, hasCapability)

  useRegisterToolPanel('overview', OverviewNavPanel)

  const maximize = useCallback(() => {
    const next = new URLSearchParams(searchParams)
    next.set('focus', '1')
    setSearchParams(next)
  }, [searchParams, setSearchParams])

  const applyPreset = useCallback(
    (preset: LayoutPreset) => setLayout(instanceId, presetLayoutPatch(preset)),
    [instanceId, setLayout],
  )

  const toolStatuses = useMemo<Record<WorkbenchToolId, ToolStatus>>(
    () => ({
      overview: { text: '' },
      files: filesToolStatus(openFileCount),
      terminal: terminalToolStatus(summary.terminalSession),
      deployments: deploymentsToolStatus(summary.infraTarget),
      orchestration: orchestrationToolStatus(summary.orchestration),
      receipts: receiptsToolStatus(summary.receiptCount),
    }),
    [openFileCount, summary.terminalSession, summary.infraTarget, summary.orchestration, summary.receiptCount],
  )

  if (!instance) return null

  const base = `/app/${instanceId}/workbench`
  const availableTools = OVERVIEW_TOOL_LINKS.filter((link) => link.capabilities.some((c) => hasCapability(c)))
  const capabilityFor = (caps: CapabilityId[]) => caps.map((c) => capability(c)).find((c) => c && c.status !== 'available')
  const nonAvailableCapabilities = instance.capabilities.filter((c) => c.status !== 'available')
  const availableCapabilityCount = instance.capabilities.length - nonAvailableCapabilities.length
  const backupDue = instance.recovery.state === 'due' || instance.recovery.state === 'failed'
  const hasActiveWork = summary.operations.length > 0 || summary.pendingApprovals.length > 0 || openFileCount > 0

  const operationRoute = (op: OperationRecord): string => {
    if (op.kind === 'infrastructure_plan') return `${base}/deployments`
    if (op.kind === 'orchestration_run') return `${base}/orchestration`
    return `/app/${instanceId}`
  }

  return (
    <div className="flex h-full flex-col bg-app" data-testid="workbench-overview-stub">
      <WorkbenchToolHeader
        name="Overview"
        icon={PanelsTopLeft}
        state={<span className="text-xs text-foreground-tertiary">{instance.name}</span>}
        onMaximize={maximize}
      />

      <div className="min-h-0 flex-1 overflow-y-auto">
        <div className="mx-auto flex max-w-3xl flex-col gap-6 px-4 py-4">
          {backupDue ? (
            <InlineNotice
              tone="attention"
              title={instance.recovery.state === 'failed' ? 'The last backup failed' : 'Backup due'}
              action={
                <Link
                  to={`/app/${instanceId}`}
                  className="shrink-0 rounded-sm border border-current px-2 py-0.5 text-xs font-medium transition-colors duration-instant hover:opacity-80"
                  data-testid="overview-backup-action"
                >
                  Open application
                </Link>
              }
            >
              {instance.recovery.detail ?? 'This application is due for a backup.'}
              {instance.recovery.lastBackupAt ? (
                <>
                  {' '}
                  Last backup <TimeAgo date={instance.recovery.lastBackupAt} className="text-current" />.
                </>
              ) : null}
            </InlineNotice>
          ) : null}

          {summary.loading ? (
            <SkeletonRows rows={6} data-testid="overview-skeleton" />
          ) : summary.error ? (
            <ErrorState
              title="The workbench summary couldn't be loaded"
              error={summary.error}
              onRetry={summary.refresh}
            />
          ) : (
            <>
              {hasActiveWork ? (
                <Section id="overview-active" title="Active work">
                  {summary.operations.map((op) => (
                    <LinkRow
                      key={op.id}
                      to={operationRoute(op)}
                      title={<OperationStateLabel state={op.state} startedAt={op.startedAt} />}
                      detail={op.title}
                      testId="overview-operation"
                    />
                  ))}
                  {summary.pendingApprovals.map((approval) => (
                    <LinkRow
                      key={approval.id}
                      to={`/approvals/${approval.id}`}
                      icon={CircleAlert}
                      title={approval.title}
                      detail={
                        <>
                          Waiting <TimeAgo date={approval.requestedAt} /> — review required
                        </>
                      }
                      trailing={
                        <span className="shrink-0 rounded-sm border border-accent/40 px-2 py-0.5 text-xs font-medium text-accent">
                          Review
                        </span>
                      }
                      testId="overview-approval"
                    />
                  ))}
                  {openFileCount > 0 ? (
                    <LinkRow
                      to={`${base}/files`}
                      icon={FilePenLine}
                      title={`${openFileCount} file${openFileCount === 1 ? '' : 's'} open in the editor`}
                      detail="Continue where you left off"
                      testId="overview-open-files"
                    />
                  ) : null}
                </Section>
              ) : null}

              <Section id="overview-tools" title="Tools" description="Available in this workbench">
                {availableTools.map((link) => {
                  const status = toolStatuses[link.tool]
                  const cap = capabilityFor(link.capabilities)
                  return (
                    <LinkRow
                      key={link.tool}
                      to={`${base}/${link.route}`}
                      icon={link.icon}
                      title={
                        <span className="flex items-center gap-1.5">
                          {link.label}
                          {cap ? (
                            <CapabilityDot status={cap.status} reason={cap.reason} />
                          ) : null}
                        </span>
                      }
                      detail={
                        <>
                          {status.text}
                          {cap?.reason ? ` — ${cap.reason}` : ''}
                        </>
                      }
                      testId={`overview-tool-${link.tool}`}
                    />
                  )
                })}
              </Section>

              <Section
                id="overview-receipts"
                title="Recent receipts"
                actions={
                  <Link
                    to={`${base}/receipts`}
                    className="flex items-center gap-0.5 text-xs font-medium text-accent transition-colors duration-instant hover:text-accent-hover"
                    data-testid="overview-receipts-link"
                  >
                    All receipts
                    <ChevronRight className="size-3.5" aria-hidden="true" />
                  </Link>
                }
              >
                {summary.receipts.length === 0 ? (
                  <p className="py-2 text-sm text-foreground-tertiary">
                    Nothing recorded yet — approved, run, saved, or exported work will appear here.
                  </p>
                ) : (
                  summary.receipts.map((receipt) => (
                    <LinkRow
                      key={receipt.id}
                      to={`${base}/receipts/${receipt.id}`}
                      title={receipt.actionName}
                      detail={receipt.summary}
                      trailing={<TimeAgo date={receipt.createdAt} />}
                      testId="overview-receipt"
                    />
                  ))
                )}
              </Section>

              <Section id="overview-activity" title="Recent activity" description={`In ${instance.name}`}>
                {summary.activity.length === 0 ? (
                  <p className="py-2 text-sm text-foreground-tertiary">No activity recorded for this application yet.</p>
                ) : (
                  summary.activity.map((item) => {
                    const to = item.route ?? (item.relatedReceiptId ? `${base}/receipts/${item.relatedReceiptId}` : null)
                    const inner = (
                      <>
                        <span className="min-w-0 flex-1">
                          <span className="block truncate text-sm text-foreground">{item.title}</span>
                          {item.detail ? <span className="block truncate text-xs text-foreground-tertiary">{item.detail}</span> : null}
                        </span>
                        <TimeAgo date={item.createdAt} />
                      </>
                    )
                    return to ? (
                      <Link
                        key={item.id}
                        to={to}
                        className="flex min-h-9 items-center gap-2 border-b border-border/60 px-1 py-1 transition-colors duration-instant hover:bg-hover"
                        data-testid="overview-activity"
                      >
                        {inner}
                      </Link>
                    ) : (
                      <div key={item.id} className="flex min-h-9 items-center gap-2 border-b border-border/60 px-1 py-1" data-testid="overview-activity">
                        {inner}
                      </div>
                    )
                  })
                )}
              </Section>

              <Section id="overview-capabilities" title="Capabilities">
                {nonAvailableCapabilities.length === 0 ? (
                  <p className="flex items-center gap-2 py-2 text-sm text-foreground-secondary">
                    <StatusDotFrom presentation={CONDITION_PRESENTATIONS.verified} />
                    All {instance.capabilities.length} capabilities available.
                  </p>
                ) : (
                  <>
                    {nonAvailableCapabilities.map((cap) => (
                      <div key={cap.id} className="flex min-h-9 items-center gap-2 border-b border-border/60 px-1 py-1" data-testid="overview-capability">
                        <CapabilityDot status={cap.status} reason={cap.reason} />
                        <span className="flex-1 truncate text-sm text-foreground">{CAPABILITY_LABELS[cap.id] ?? cap.id}</span>
                        <span className="truncate text-xs text-foreground-tertiary">{cap.reason}</span>
                      </div>
                    ))}
                    <p className="py-2 text-xs text-foreground-tertiary">
                      {availableCapabilityCount} other capabilit{availableCapabilityCount === 1 ? 'y is' : 'ies are'} available.
                    </p>
                  </>
                )}
              </Section>

              <Section id="overview-layout" title="Layout" description="How the workbench regions are arranged">
                <div className="flex min-h-11 flex-wrap items-center gap-2 px-1 py-1" data-testid="overview-layout-row">
                  <LayoutGrid className="size-4 text-foreground-secondary" aria-hidden="true" />
                  <span className="text-sm text-foreground">
                    Preset: <span className="font-medium" data-testid="overview-preset">{PRESET_LABELS[layout.preset]}</span>
                  </span>
                  <span className="flex-1" />
                  <DropdownMenu>
                    <DropdownMenuTrigger
                      className="inline-flex h-7 items-center rounded-sm border border-input px-2 text-xs font-medium text-foreground transition-colors duration-instant hover:bg-hover"
                      data-testid="overview-preset-menu"
                    >
                      Change
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end" className="bg-surface">
                      <DropdownMenuLabel>Layout presets</DropdownMenuLabel>
                      {PRESET_ORDER.map((preset) => (
                        <DropdownMenuItem key={preset} onSelect={() => applyPreset(preset)}>
                          <span className="flex-1">{PRESET_LABELS[preset]}</span>
                          {layout.preset === preset ? <Check className="size-4 text-accent" aria-hidden="true" /> : null}
                        </DropdownMenuItem>
                      ))}
                    </DropdownMenuContent>
                  </DropdownMenu>
                  <Tooltip content="Restore preset defaults and panel sizes">
                    <button
                      type="button"
                      onClick={() => resetLayout(instanceId)}
                      className="inline-flex h-7 items-center gap-1 rounded-sm border border-input px-2 text-xs font-medium text-foreground transition-colors duration-instant hover:bg-hover"
                      data-testid="overview-layout-reset"
                    >
                      <RotateCcw className="size-3.5" aria-hidden="true" />
                      Reset
                    </button>
                  </Tooltip>
                </div>
              </Section>
            </>
          )}
        </div>
      </div>
    </div>
  )
}

